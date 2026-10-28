//! Tiny target pairs and invariant harnesses. No fixture is executed on the
//! host: runtime checks, compilation and both variants go through the CLI.
use std::path::Path;
use std::process::{Command, Output};

fn cli(home: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_omgs"));
    if let Ok(executor) = omgs::sandbox::locate_executor() {
        command.env("OMGS_MXC_EXEC", executor.path);
    }
    command
        .env("OMGS_HOME", home)
        .env("RUSTUP_AUTO_INSTALL", "0")
        .args(args)
        .output()
        .unwrap()
}
fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}
fn ready() -> bool {
    let executor = match omgs::sandbox::locate_executor() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("skipping recipes: {e}");
            return false;
        }
    };
    #[cfg(windows)]
    if let Err(e) = omgs::sandbox::windows_policy(omgs::sandbox::windows_probe(&executor.path)) {
        eprintln!("skipping recipes: {e}");
        return false;
    }
    // Give child CLIs the same pinned executor, even with a throwaway home.
    // locate_executor already uses the inherited override or the real home.
    let _ = executor;
    true
}
struct Recipe {
    runtime: &'static str,
    source: &'static str,
    vulnerable: &'static str,
    fixed: &'static str,
    test: &'static str,
    harness: &'static str,
    command: &'static str,
}
fn check(recipe: Recipe) {
    if !ready() {
        return;
    }
    let d = std::env::temp_dir().join(format!(
        "omgs-recipe-{}-{}",
        recipe.runtime,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    let target = d.join("target");
    std::fs::create_dir_all(&target).unwrap();
    let home = d.join("home");
    let probe = cli(
        &home,
        &[
            "prove",
            "--cmd",
            &if recipe.runtime == "sh" {
                "sh -c 'exit 0'".into()
            } else {
                format!("{} --version", recipe.runtime)
            },
        ],
    );
    if !probe.status.success() {
        eprintln!(
            "skipping: {} not reachable inside the sandbox\n{}",
            recipe.runtime,
            text(&probe)
        );
        std::fs::remove_dir_all(d).unwrap();
        return;
    }
    std::fs::write(target.join(recipe.test), recipe.harness).unwrap();
    for (variant, source, exit) in [
        ("vulnerable", recipe.vulnerable, 1),
        ("fixed", recipe.fixed, 0),
    ] {
        std::fs::write(target.join(recipe.source), source).unwrap();
        let out = cli(
            &home,
            &[
                "prove",
                "--target",
                target.to_str().unwrap(),
                "--test",
                recipe.test,
                "--cmd",
                recipe.command,
            ],
        );
        let output = text(&out);
        assert_eq!(
            out.status.code(),
            Some(exit),
            "{} {variant}: {output}",
            recipe.runtime
        );
        assert!(output.contains("AUTHORIZED_CONTROL_OK"), "{output}");
        assert!(
            output.contains(if exit == 1 {
                "BOUNDARY_ASSERTION_FAILED"
            } else {
                "BOUNDARY_ASSERTION_OK"
            }),
            "{output}"
        );
        // Validate runner completion, rather than accepting an unrelated exit 1.
        let record_path = output
            .lines()
            .find_map(|s| s.strip_prefix("proof record: "))
            .unwrap()
            .split(" (not linked")
            .next()
            .unwrap();
        let record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(record_path).unwrap()).unwrap();
        for key in [
            "capture_complete",
            "cleanup_complete",
            "command_started",
            "command_finished",
        ] {
            assert_eq!(record[key], true, "{record}");
        }
        for key in ["timed_out", "executor_error", "killed", "interrupted"] {
            assert_eq!(record[key], false, "{record}");
        }
        assert_eq!(record["survivors"], serde_json::json!([]), "{record}");
        assert_eq!(record["exit_code"], exit, "{record}");
        assert_eq!(record["test_reachable"], true, "{record}");
        eprintln!("{} {variant}: clean=true, inner exit {exit}, authorized control and boundary assertion reached", recipe.runtime);
    }
    std::fs::remove_dir_all(d).unwrap();
}
#[cfg(unix)]
#[test]
fn shell_recipe() {
    check(Recipe {
        runtime: "sh", source: "target.sh", test: "test.sh", command: "sh test.sh",
        vulnerable: "can_read() { return 0; }\n",
        fixed: "can_read() { [ \"$1\" = \"$2\" ]; }\n",
        harness: ". ./target.sh\ncan_read owner owner || exit 2\necho AUTHORIZED_CONTROL_OK\nif can_read intruder owner; then echo BOUNDARY_ASSERTION_FAILED; exit 1; fi\necho BOUNDARY_ASSERTION_OK\n",
    });
}
#[cfg(unix)]
#[test]
fn python_recipe() {
    check(Recipe {
        runtime: "python3", source: "target.py", test: "test.py", command: "python3 -I test.py",
        vulnerable: "def can_read(actor, owner):\n    return True\n",
        fixed: "def can_read(actor, owner):\n    return actor == owner\n",
        harness: "import runpy\ncan_read = runpy.run_path('./target.py')['can_read']\nassert can_read('owner', 'owner'), 'AUTHORIZED_CONTROL_FAILED'\nprint('AUTHORIZED_CONTROL_OK', flush=True)\nassert not can_read('intruder', 'owner'), 'BOUNDARY_ASSERTION_FAILED'\nprint('BOUNDARY_ASSERTION_OK')\n",
    });
}
#[test]
fn node_recipe() {
    check(Recipe {
        runtime: "node", source: "target.cjs", test: "test.cjs", command: "node test.cjs",
        vulnerable: "exports.canRead = (actor, owner) => true;\n",
        fixed: "exports.canRead = (actor, owner) => actor === owner;\n",
        harness: "const assert = require('node:assert/strict');\nconst {canRead} = require('./target.cjs');\nassert.equal(canRead('owner', 'owner'), true, 'AUTHORIZED_CONTROL_FAILED');\nconsole.log('AUTHORIZED_CONTROL_OK');\nassert.equal(canRead('intruder', 'owner'), false, 'BOUNDARY_ASSERTION_FAILED');\nconsole.log('BOUNDARY_ASSERTION_OK');\n",
    });
}
#[test]
fn powershell_recipe() {
    check(Recipe {
        runtime: "pwsh", source: "target.ps1", test: "test.ps1", command: "pwsh -NoProfile -NonInteractive -File test.ps1",
        vulnerable: "function Test-CanRead($Actor, $Owner) { return $true }\n",
        fixed: "function Test-CanRead($Actor, $Owner) { return $Actor -ceq $Owner }\n",
        harness: "$ErrorActionPreference = 'Stop'\n. ./target.ps1\nif (-not (Test-CanRead 'owner' 'owner')) { throw 'AUTHORIZED_CONTROL_FAILED' }\nWrite-Output 'AUTHORIZED_CONTROL_OK'\nif (Test-CanRead 'intruder' 'owner') { Write-Output 'BOUNDARY_ASSERTION_FAILED'; exit 1 }\nWrite-Output 'BOUNDARY_ASSERTION_OK'\nexit 0\n",
    });
}
#[cfg(unix)]
#[test]
fn swift_recipe() {
    check(Recipe {
        runtime: "swiftc", source: "target.swift", test: "main.swift", command: "swiftc target.swift main.swift -o fixture && ./fixture",
        vulnerable: "func canRead(_ actor: String, _ owner: String) -> Bool { true }\n",
        fixed: "func canRead(_ actor: String, _ owner: String) -> Bool { actor == owner }\n",
        harness: "#if canImport(Darwin)\nimport Darwin\n#else\nimport Glibc\n#endif\nguard canRead(\"owner\", \"owner\") else { exit(2) }\nprint(\"AUTHORIZED_CONTROL_OK\")\nif canRead(\"intruder\", \"owner\") { print(\"BOUNDARY_ASSERTION_FAILED\"); exit(1) }\nprint(\"BOUNDARY_ASSERTION_OK\")\n",
    });
}
#[cfg(windows)]
#[test]
fn windows_toolchains_launch_inside_mxc() {
    if !ready() {
        return;
    }
    let d = std::env::temp_dir().join(format!("omgs-windows-tools-{}", std::process::id()));
    for (name, command, expected) in [
        ("cargo", "cargo --version", "cargo "),
        (
            "node",
            "node -e \"console.log('NODE_REACHABLE')\"",
            "NODE_REACHABLE",
        ),
        (
            "pwsh",
            "pwsh -NoProfile -NonInteractive -Command \"Write-Output PWSH_REACHABLE\"",
            "PWSH_REACHABLE",
        ),
    ] {
        if omgs::platform::which(name).is_none() {
            eprintln!("skipping: {name} not reachable inside the sandbox (not on host PATH)");
            continue;
        }
        let out = cli(&d, &["prove", "--cmd", command]);
        assert!(out.status.success(), "{name}: {}", text(&out));
        assert!(text(&out).contains(expected), "{}", text(&out));
        eprintln!("{name}: real omgs prove launch passed");
    }
    let out = cli(&d, &["doctor", "--live"]);
    assert!(out.status.success(), "{}", text(&out));
    let output = text(&out);
    let reachable = output
        .lines()
        .find(|s| s.starts_with("toolchains reachable inside the sandbox:"))
        .unwrap();
    for name in ["cargo", "node", "pwsh"] {
        if omgs::platform::which(name).is_some() {
            assert!(reachable.contains(name), "{output}");
        }
    }
    eprintln!("{reachable}");
    std::fs::remove_dir_all(d).unwrap();
}
