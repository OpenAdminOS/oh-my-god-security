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
fn required(runtime: &str, list: &str) -> bool {
    list.split(',').any(|s| s.trim() == runtime)
}
fn skip(runtime: &str, reason: &str) {
    skip_with_requirements(
        runtime,
        reason,
        &std::env::var("OMGS_REQUIRE_RECIPES").unwrap_or_default(),
    );
}
fn skip_with_requirements(runtime: &str, reason: &str, list: &str) {
    assert!(
        !required(runtime, list),
        "required recipe {runtime} skipped: {reason}"
    );
    eprintln!("recipe {runtime}: skipped ({reason})");
}
fn ready(runtime: &str) -> bool {
    let executor = match omgs::sandbox::locate_executor() {
        Ok(e) => e,
        Err(e) if e.contains("executor") && e.contains("not found.") => {
            skip(runtime, &e);
            return false;
        }
        Err(e) => panic!("recipe executor readiness failed: {e}"),
    };
    #[cfg(windows)]
    if let Err(e) = omgs::sandbox::windows_policy(omgs::sandbox::windows_probe(&executor.path)) {
        assert!(
            e.contains("MXC 1.0.1 leaves changed ACEs on granted folders"),
            "{e}"
        );
        let d = std::env::temp_dir().join(format!("omgs-recipe-refusal-{}", std::process::id()));
        for args in [vec!["prove", "--cmd", "exit 0"], vec!["doctor", "--live"]] {
            let out = cli(&d, &args);
            assert_eq!(out.status.code(), Some(3), "{}", text(&out));
            assert!(
                text(&out).contains("MXC 1.0.1 leaves changed ACEs on granted folders"),
                "{}",
                text(&out)
            );
        }
        let _ = std::fs::remove_dir_all(d);
        skip(runtime, &e);
        return false;
    }
    let _ = executor;
    if omgs::platform::which(runtime).is_none() {
        skip(runtime, &format!("{runtime} not on host PATH"));
        return false;
    }
    true
}
fn record(out: &Output, expected: i32, test: bool) {
    let output = text(out);
    assert_eq!(
        out.status.code(),
        Some(i32::from(expected != 0)),
        "{output}"
    );
    let path = output
        .lines()
        .find_map(|s| s.strip_prefix("proof record: "))
        .unwrap_or_else(|| panic!("missing proof record: {output}"))
        .split(" (not linked")
        .next()
        .unwrap();
    let record: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
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
    assert_eq!(record["exit_code"], expected, "{record}");
    if test {
        assert_eq!(record["test_reachable"], true, "{record}");
    }
}
struct Recipe {
    runtime: &'static str,
    source: &'static str,
    vulnerable: &'static str,
    fixed: &'static str,
    test: &'static str,
    harness: &'static str,
    command: &'static str,
    broken: &'static str,
    control_failure: &'static str,
}
fn check(recipe: Recipe) -> bool {
    if !ready(recipe.runtime) {
        return false;
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
    record(&probe, 0, false);
    std::fs::write(target.join(recipe.test), recipe.harness).unwrap();
    for (variant, source, exit) in [
        ("vulnerable", recipe.vulnerable, 1),
        ("fixed", recipe.fixed, 0),
        ("import failure", recipe.broken, 2),
        ("control failure", recipe.control_failure, 2),
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
            Some(i32::from(exit != 0)),
            "{} {variant}: {output}",
            recipe.runtime
        );
        record(&out, exit, true);
        if exit != 2 {
            assert!(
                output.lines().any(|s| s == "AUTHORIZED_CONTROL_OK"),
                "{output}"
            );
            assert!(
                output.lines().any(|s| s
                    == if exit == 1 {
                        "BOUNDARY_ASSERTION_FAILED"
                    } else {
                        "BOUNDARY_ASSERTION_OK"
                    }),
                "{output}"
            );
        } else {
            assert!(
                !output.lines().any(|s| s == "BOUNDARY_ASSERTION_FAILED"),
                "{output}"
            );
        }
        eprintln!(
            "{} {variant}: clean=true, inner exit {exit}, fixture classified",
            recipe.runtime
        );
    }
    std::fs::remove_dir_all(d).unwrap();
    true
}
#[cfg(unix)]
fn shell_recipe() -> Recipe {
    Recipe {
        runtime: "sh", source: "target.sh", test: "test.sh", command: "sh test.sh",
        vulnerable: "can_read() { return 0; }\n",
        fixed: "can_read() { [ \"$1\" = \"$2\" ]; }\n",
        broken: "exit 2\n", control_failure: "can_read() { return 1; }\n",
        harness: ". ./target.sh || exit 2\ncan_read owner owner || exit 2\necho AUTHORIZED_CONTROL_OK\nif can_read intruder owner; then echo BOUNDARY_ASSERTION_FAILED; exit 1; fi\necho BOUNDARY_ASSERTION_OK\n",
    }
}
#[cfg(unix)]
fn python_recipe() -> Recipe {
    Recipe {
        runtime: "python3", source: "target.py", test: "test.py", command: "python3 -I test.py",
        vulnerable: "def can_read(actor, owner):\n    return True\n",
        fixed: "def can_read(actor, owner):\n    return actor == owner\n",
        broken: "raise ImportError('missing target dependency')\n", control_failure: "def can_read(actor, owner):\n    return False\n",
        harness: "import sys\ntry:\n    import runpy\n    can_read = runpy.run_path('./target.py')['can_read']\n    if not can_read('owner', 'owner'):\n        raise RuntimeError('AUTHORIZED_CONTROL_FAILED')\n    print('AUTHORIZED_CONTROL_OK', flush=True)\n    forbidden = can_read('intruder', 'owner')\nexcept Exception as error:\n    print(error, file=sys.stderr)\n    sys.exit(2)\nif forbidden:\n    print('BOUNDARY_ASSERTION_FAILED', flush=True)\n    sys.exit(1)\nprint('BOUNDARY_ASSERTION_OK')\n",
    }
}
fn node_recipe() -> Recipe {
    Recipe {
        runtime: "node", source: "target.cjs", test: "test.cjs", command: "node test.cjs",
        vulnerable: "exports.canRead = (actor, owner) => true;\n",
        fixed: "exports.canRead = (actor, owner) => actor === owner;\n",
        broken: "require('./missing-dependency.cjs');\n", control_failure: "exports.canRead = () => false;\n",
        harness: "let forbidden;\ntry {\n  const {canRead} = require('./target.cjs');\n  if (canRead('owner', 'owner') !== true) throw new Error('AUTHORIZED_CONTROL_FAILED');\n  console.log('AUTHORIZED_CONTROL_OK');\n  forbidden = canRead('intruder', 'owner');\n} catch (error) { console.error(error); process.exit(2); }\nif (forbidden !== false) { console.log('BOUNDARY_ASSERTION_FAILED'); process.exit(1); }\nconsole.log('BOUNDARY_ASSERTION_OK');\n",
    }
}
fn powershell_recipe() -> Recipe {
    Recipe {
        runtime: "pwsh", source: "target.ps1", test: "test.ps1", command: "pwsh -NoProfile -NonInteractive -File test.ps1",
        vulnerable: "function Test-CanRead($Actor, $Owner) { return $true }\n",
        fixed: "function Test-CanRead($Actor, $Owner) { return $Actor -ceq $Owner }\n",
        broken: "throw 'missing target module'\n", control_failure: "function Test-CanRead($Actor, $Owner) { return $false }\n",
        harness: "$ErrorActionPreference = 'Stop'\ntry {\n  . ./target.ps1\n  if (-not (Test-CanRead 'owner' 'owner')) { throw 'AUTHORIZED_CONTROL_FAILED' }\n  Write-Output 'AUTHORIZED_CONTROL_OK'\n  $forbidden = Test-CanRead 'intruder' 'owner'\n} catch { Write-Error -ErrorAction Continue $_; exit 2 }\nif ($forbidden) { Write-Output 'BOUNDARY_ASSERTION_FAILED'; exit 1 }\nWrite-Output 'BOUNDARY_ASSERTION_OK'\nexit 0\n",
    }
}
#[cfg(unix)]
fn swift_recipe() -> Recipe {
    Recipe {
        runtime: "swiftc", source: "target.swift", test: "main.swift", command: "swiftc target.swift main.swift -o fixture || exit 2; ./fixture",
        broken: "import MissingTargetModule\n", control_failure: "func canRead(_ actor: String, _ owner: String) -> Bool { false }\n",
        vulnerable: "func canRead(_ actor: String, _ owner: String) -> Bool { true }\n",
        fixed: "func canRead(_ actor: String, _ owner: String) -> Bool { actor == owner }\n",
        harness: "#if canImport(Darwin)\nimport Darwin\n#else\nimport Glibc\n#endif\nguard canRead(\"owner\", \"owner\") else { exit(2) }\nprint(\"AUTHORIZED_CONTROL_OK\")\nif canRead(\"intruder\", \"owner\") { print(\"BOUNDARY_ASSERTION_FAILED\"); exit(1) }\nprint(\"BOUNDARY_ASSERTION_OK\")\n",
    }
}
#[cfg(windows)]
#[test]
fn windows_toolchains_launch_inside_mxc() {
    if !ready("cargo") {
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
            skip(name, &format!("{name} not on host PATH"));
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

#[test]
fn strict_recipe_list_matches_whole_runtime_names() {
    assert!(required("node", "sh, node,python3"));
    assert!(!required("node", "nodejs,python3"));
    assert!(!required("pwsh", ""));
}

#[test]
fn recipes() {
    #[cfg(unix)]
    let all = vec![
        shell_recipe(),
        python_recipe(),
        node_recipe(),
        powershell_recipe(),
        swift_recipe(),
    ];
    #[cfg(windows)]
    let all = vec![node_recipe(), powershell_recipe()];
    let total = all.len();
    let executed = all.into_iter().map(check).filter(|ran| *ran).count();
    eprintln!(
        "recipes summary: executed={executed}, skipped={}",
        total - executed
    );
}

#[test]
fn required_skip_and_failed_probe_are_fatal() {
    assert!(
        std::panic::catch_unwind(|| skip_with_requirements("node", "missing", "node")).is_err()
    );
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(windows)]
    use std::os::windows::process::ExitStatusExt;
    // Neither blocked prove, launch failure nor an incomplete successful CLI
    // response may become an absence skip. A clean record is mandatory.
    for code in [0, 3, 127] {
        #[cfg(unix)]
        let status = std::process::ExitStatus::from_raw(code << 8);
        #[cfg(windows)]
        let status = std::process::ExitStatus::from_raw(code as u32);
        let out = Output {
            status,
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        assert!(std::panic::catch_unwind(|| record(&out, 0, false)).is_err());
    }
}
