//! Tiny target pairs and invariant harnesses. No fixture is executed on the
//! host: runtime checks, compilation and both variants go through the CLI.
use serde_json::json;
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
        let d = omgs::platform::temp_root()
            .unwrap()
            .join(format!("omgs-recipe-refusal-{}", std::process::id()));
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
fn node_typescript_version(version: &str) -> bool {
    let parts: Vec<_> = version.trim().trim_start_matches('v').split('.').collect();
    let (Some(major), Some(minor)) = (
        parts.first().and_then(|s| s.parse::<u32>().ok()),
        parts.get(1).and_then(|s| s.parse::<u32>().ok()),
    ) else {
        return false;
    };
    major > 23 || (major == 23 && minor >= 6) || (major == 22 && minor >= 18)
}
fn typescript_ready() -> bool {
    let Some(node) = omgs::platform::which("node") else {
        return false;
    };
    let available = Command::new(node).args(["--eval", "if (typeof require('node:module').registerHooks !== 'function') process.exit(1); console.log(process.version)"])
        .output().is_ok_and(|out| out.status.success() && node_typescript_version(&String::from_utf8_lossy(&out.stdout)));
    if !available {
        skip("node", "TypeScript recipe requires Node 22.18+ (22.x), 23.6+ (23.x), or 24+, with registerHooks and unflagged type stripping");
    }
    available
}
#[test]
fn typescript_runtime_version_boundaries() {
    for version in ["v20.19.0", "v22.17.0", "v23.5.0", "invalid"] {
        assert!(!node_typescript_version(version), "{version}");
    }
    for version in ["v22.18.0", "v23.6.0", "v24.0.0", "v26.7.0\n"] {
        assert!(node_typescript_version(version), "{version}");
    }
}
fn record(out: &Output, expected: i32, test: bool) {
    let output = text(out);

    let path = output
        .lines()
        .find_map(|s| s.strip_prefix("proof record: "))
        .unwrap_or_else(|| panic!("missing proof record: {output}"))
        .split(" (")
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
    let parsed: omgs::proof::ProofRecord = serde_json::from_value(record.clone()).unwrap();
    assert_eq!(
        out.status.code(),
        Some(i32::from(omgs::proof::outer_exit(&parsed))),
        "{output}"
    );
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
    dependency_failure: &'static str,
}
fn check(recipe: Recipe) -> bool {
    if !ready(recipe.runtime) || (recipe.source == "target.ts" && !typescript_ready()) {
        return false;
    }
    let d = omgs::platform::temp_root().unwrap().join(format!(
        "omgs-recipe-{}-{}",
        recipe.runtime,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    omgs::platform::create_private_dir(&d).unwrap();
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
    let run = d.join("run");
    let init = cli(
        &home,
        &[
            "audit",
            "init",
            "--target",
            target.to_str().unwrap(),
            "--out",
            run.to_str().unwrap(),
            "--no-sensors",
            "--budget",
            "20",
        ],
    );
    assert!(init.status.success(), "{}", text(&init));
    let fp = omgs::fingerprint("missing_authz", "can_read", "resource", "owner");
    let findings_path = run.join("findings.json");
    let mut n = 0;
    for (variant, source, exit) in [
        ("vulnerable", recipe.vulnerable, 1),
        ("fixed", recipe.fixed, 0),
        ("import failure", recipe.broken, 2),
        ("control failure", recipe.control_failure, 2),
        (
            "unauthorized dependency failure",
            recipe.dependency_failure,
            2,
        ),
        ("fixed marker collision", recipe.vulnerable, 1),
        ("wrong nonce collision", recipe.vulnerable, 1),
        ("missing marker", recipe.vulnerable, 1),
        ("missing control marker", recipe.vulnerable, 1),
        ("marker beyond cap", recipe.vulnerable, 1),
        ("queued output flood", recipe.vulnerable, 1),
    ] {
        let spoof = match variant {
            "fixed marker collision" => Some((
                "AUTHORIZED_CONTROL_OK".to_string(),
                "BOUNDARY_ASSERTION_FAILED".to_string(),
            )),
            "wrong nonce collision" => Some((
                omgs::proof::control_marker(&"0".repeat(64)),
                omgs::proof::boundary_marker("BOUNDARY_ASSERTION_FAILED", &"0".repeat(64)),
            )),
            _ => None,
        };
        let malicious = spoof.map(|(control, boundary)| match recipe.runtime {
            "sh" => format!("echo {control}\necho {boundary}\nexit 1\n"),
            "python3" => format!("print('{control}', flush=True)\nprint('{boundary}', flush=True)\nraise SystemExit(1)\n"),
            "node" => format!("console.log('{control}'); console.log('{boundary}'); process.exit(1);\n"),
            "pwsh" => format!("Write-Output '{control}'\nWrite-Output '{boundary}'\n[Environment]::Exit(1)\n"),
            "swiftc" => format!("import Foundation\nfunc canRead(_ a: String, _ b: String) throws -> Bool {{ print(\"{control}\"); print(\"{boundary}\"); exit(1) }}\n"),
            _ => unreachable!(),
        });
        std::fs::write(
            target.join(recipe.source),
            malicious.as_deref().unwrap_or(source),
        )
        .unwrap();
        n += 1;
        let harness = match variant {
            "missing marker" => recipe
                .harness
                .replace("OMGS_BOUNDARY_", "BOUNDARY_MARKER_OMITTED_"),
            "missing control marker" => recipe
                .harness
                .replace("OMGS_CONTROL_", "CONTROL_MARKER_OMITTED_"),
            _ => recipe.harness.into(),
        };
        let harness = if variant == "queued output flood" {
            // Output still queued in the runtime when the harness finishes
            // must not cost the markers; Node pipe writes are asynchronous.
            let flood = match recipe.runtime {
                "node" => "process.stdout.write('y'.repeat(300000) + '\\n');\n",
                _ => "",
            };
            format!("{flood}{harness}")
        } else if variant == "marker beyond cap" {
            let flood = match recipe.runtime {
                "sh" => "i=0; while [ $i -lt 3000 ]; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\\n'; i=$((i+1)); done\n",
                "python3" => "print('x' * 300000, flush=True)\n",
                "node" => "require('node:fs').writeSync(1, 'x'.repeat(300000) + '\\n');\n",
                "pwsh" => "Write-Output ('x' * 300000)\n",
                "swiftc" => "print(String(repeating: \"x\", count: 300000))\n",
                _ => unreachable!(),
            };
            format!("{flood}{harness}")
        } else {
            harness
        };
        std::fs::write(target.join(recipe.test), harness).unwrap();
        let findings = serde_json::json!({"findings": [{
            "fingerprint": fp, "title": "Unauthorized resource access", "verdict": "confirmed",
            "severity": "high", "proof_tier": "test_proven", "attack_class": "missing_authz",
            "entry_point": "can_read", "sink": "resource", "boundary": "owner",
            "location": {"path": recipe.source, "line": 1},
            "evidence": "Real target invocation with synthetic owner and intruder.",
            "hunted_by": "red-1", "verified_by": "blue-1",
            "proof_ref": format!("proofs/{n}.json")
        }]});
        std::fs::write(&findings_path, findings.to_string()).unwrap();
        let out = cli(
            &home,
            &[
                "prove",
                "--run",
                run.to_str().unwrap(),
                "--finding",
                &fp,
                "--expect-marker",
                "BOUNDARY_ASSERTION_FAILED",
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
            Some(if exit == 0 {
                0
            } else if exit == 1
                && !variant.ends_with("collision")
                && !matches!(variant, "missing marker" | "missing control marker")
            {
                1
            } else {
                2
            }),
            "{} {variant}: {output}",
            recipe.runtime
        );
        record(&out, exit, true);
        let collision = variant.ends_with("collision");
        let supports = exit == 1
            && !collision
            && !matches!(variant, "missing marker" | "missing control marker");
        assert!(
            output.contains(&format!(
                "proof support for test_proven: {}",
                if supports { "yes" } else { "no" }
            )),
            "{output}"
        );
        let proof = omgs::proof::load(&run, &format!("proofs/{n}.json")).unwrap();
        assert_eq!(
            proof.contract.expect_marker(),
            Some("BOUNDARY_ASSERTION_FAILED")
        );
        assert_eq!(
            proof.contract.evidence().0,
            exit == 1 && !collision && variant != "missing marker",
            "{variant}"
        );
        assert_eq!(
            proof.contract.evidence().1,
            !collision
                && !matches!(
                    variant,
                    "import failure" | "control failure" | "missing control marker"
                ),
            "{variant}"
        );
        if variant == "marker beyond cap" {
            assert!(proof.output_bytes_total > 256 * 1024);
            assert!(!proof.output.contains("OMGS_BOUNDARY_"));
            assert!(!proof.output.contains("OMGS_CONTROL_"));
        }
        let validated = cli(
            &home,
            &["validate", "--findings", findings_path.to_str().unwrap()],
        );
        assert_eq!(
            validated.status.success(),
            supports,
            "{} {variant}: {}",
            recipe.runtime,
            text(&validated)
        );
        if exit != 2 && !variant.ends_with("cap") && variant != "queued output flood" && !collision
        {
            let control = omgs::proof::control_marker(&proof.marker_nonce);
            let boundary =
                omgs::proof::boundary_marker("BOUNDARY_ASSERTION_FAILED", &proof.marker_nonce);
            assert!(
                output.lines().any(|s| s
                    == if variant == "missing control marker" {
                        control.replace("OMGS_CONTROL_", "CONTROL_MARKER_OMITTED_")
                    } else {
                        control.clone()
                    }),
                "{output}"
            );
            assert!(
                output.lines().any(|s| s
                    == if variant == "missing marker" {
                        boundary.replace("OMGS_BOUNDARY_", "BOUNDARY_MARKER_OMITTED_")
                    } else if exit == 1 {
                        boundary.clone()
                    } else {
                        "BOUNDARY_ASSERTION_OK".into()
                    }),
                "{output}"
            );
        }
        eprintln!(
            "{} {variant}: clean=true, inner exit {exit}, fixture classified",
            recipe.runtime
        );
    }
    let replay = cli(
        &home,
        &[
            "prove",
            "--run",
            run.to_str().unwrap(),
            "--replay",
            &n.to_string(),
        ],
    );
    assert!(replay.status.success(), "{}", text(&replay));
    let replayed = omgs::proof::load(&run, &format!("proofs/{}.json", n + 1)).unwrap();
    assert_eq!(
        replayed.contract.expect_marker(),
        Some("BOUNDARY_ASSERTION_FAILED")
    );
    assert!(replayed.clean() && replayed.contract.evidence().0 && replayed.contract.evidence().1);
    assert_eq!(replayed.exit_code, Some(1));
    let original = omgs::proof::load(&run, &format!("proofs/{n}.json")).unwrap();
    assert!(omgs::proof::reproduces(&original, &replayed));
    let final_findings =
        omgs::shape::findings(&std::fs::read_to_string(&findings_path).unwrap()).unwrap();
    let eval_path = run.join("evaluation.json");
    let mut evaluation = json!({"evaluator":"independent-replay-context","source_ref":"synthetic",
        "decisions":[{"fingerprint":fp,"decision":"uphold","reason":"reconstructed invariant",
            "evidence":[],"required_changes":[]}],"gaps":["fixture-only reachability"]});
    std::fs::write(&eval_path, evaluation.to_string()).unwrap();
    assert!(omgs::adjudication::check(&run, &final_findings)
        .unwrap()
        .iter()
        .any(|g| g.contains("no reproduced replay")));
    evaluation["decisions"][0]["evidence"] = json!([format!("proofs/{}.json", n + 1)]);
    std::fs::write(&eval_path, evaluation.to_string()).unwrap();
    assert!(!omgs::adjudication::check(&run, &final_findings)
        .unwrap()
        .iter()
        .any(|g| g.contains("no reproduced replay")));
    let mut replay_as_original = final_findings.clone();
    replay_as_original.findings[0].proof_ref = Some(format!("proofs/{}.json", n + 1));
    assert!(omgs::proof::validate_proofs(&replay_as_original, &run)
        .iter()
        .any(|e| e.contains("not a replay")));
    let mut mismatch = replayed.clone();
    mismatch.command_sha256 = "f".repeat(64);
    assert!(!omgs::proof::reproduces(&original, &mismatch));
    mismatch = replayed.clone();
    mismatch.exit_code = Some(2);
    assert!(!omgs::proof::reproduces(&original, &mismatch));
    assert_ne!(replayed.marker_nonce, original.marker_nonce);
    assert!(text(&replay).contains("proof support for test_proven: yes"));
    assert!(text(&replay).contains(": reproduced"), "{}", text(&replay));
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
        dependency_failure: "can_read() { if [ \"$1\" = intruder ]; then command omgs_missing_dependency; else return 0; fi; }\n",
        harness: ". ./target.sh || exit 2\ncan_read owner owner || exit 2\necho \"OMGS_CONTROL_${OMGS_PROOF_NONCE:?}\"\ncan_read intruder owner\nstatus=$?\ncase $status in\n  0) echo \"OMGS_BOUNDARY_${OMGS_PROOF_NONCE:?}_${OMGS_PROOF_CONTRACT:?}\"; exit 1 ;;\n  1) echo BOUNDARY_ASSERTION_OK; exit 0 ;;\n  *) exit 2 ;;\nesac\n",
    }
}
#[cfg(unix)]
fn python_recipe() -> Recipe {
    Recipe {
        runtime: "python3", source: "target.py", test: "test.py", command: "python3 -I test.py",
        vulnerable: "def can_read(actor, owner):\n    return True\n",
        fixed: "def can_read(actor, owner):\n    return actor == owner\n",
        broken: "raise ImportError('missing target dependency')\n", control_failure: "def can_read(actor, owner):\n    return False\n",
        dependency_failure: "def can_read(actor, owner):\n    if actor != owner:\n        import omgs_missing_dependency\n    return True\n",
        harness: "import os, sys\nnonce = os.environ['OMGS_PROOF_NONCE']\nmarker = os.environ['OMGS_PROOF_CONTRACT']\ntry:\n    import runpy\n    can_read = runpy.run_path('./target.py')['can_read']\n    if not can_read('owner', 'owner'):\n        raise RuntimeError('AUTHORIZED_CONTROL_FAILED')\n    print(f'OMGS_CONTROL_{nonce}', flush=True)\n    forbidden = can_read('intruder', 'owner')\n    if type(forbidden) is not bool:\n        raise RuntimeError('INVALID_TARGET_RESULT')\nexcept Exception as error:\n    print(error, file=sys.stderr)\n    sys.exit(2)\nif forbidden:\n    print(f'OMGS_BOUNDARY_{nonce}_{marker}', flush=True)\n    sys.exit(1)\nprint('BOUNDARY_ASSERTION_OK')\n",
    }
}
fn node_recipe() -> Recipe {
    Recipe {
        runtime: "node", source: "target.cjs", test: "test.cjs", command: "node test.cjs",
        vulnerable: "exports.canRead = (actor, owner) => true;\n",
        fixed: "exports.canRead = (actor, owner) => actor === owner;\n",
        broken: "require('./missing-dependency.cjs');\n", control_failure: "exports.canRead = () => false;\n",
        dependency_failure: "exports.canRead = (actor, owner) => { if (actor !== owner) require('./missing-dependency.cjs'); return true; };\n",
        harness: "function check() {\n  let forbidden;\n  try {\n    const {canRead} = require('./target.cjs');\n    if (canRead('owner', 'owner') !== true) throw new Error('AUTHORIZED_CONTROL_FAILED');\n    console.log('OMGS_CONTROL_' + process.env.OMGS_PROOF_NONCE);\n    forbidden = canRead('intruder', 'owner');\n  } catch (error) { console.error(error); return 2; }\n  if (typeof forbidden !== 'boolean') return 2;\n  if (forbidden) { console.log('OMGS_BOUNDARY_' + process.env.OMGS_PROOF_NONCE + '_' + process.env.OMGS_PROOF_CONTRACT); return 1; }\n  console.log('BOUNDARY_ASSERTION_OK');\n  return 0;\n}\n// process.exit() can drop queued pipe writes; exitCode lets them drain.\nprocess.exitCode = check();\n",
    }
}
fn typescript_recipe() -> Recipe {
    Recipe {
        runtime: "node", source: "target.ts", test: "test.cjs", command: "node test.cjs",
        vulnerable: "export function canRead(actor: string, owner: string): boolean { return true; }\n",
        fixed: "export function canRead(actor: string, owner: string): boolean { return actor === owner; }\n",
        broken: "import './missing-enforcement.ts';\n",
        control_failure: "export function canRead(actor: string, owner: string): boolean { return false; }\n",
        dependency_failure: "export function canRead(actor: string, owner: string): boolean { if (actor !== owner) throw new Error('missing enforcement dependency'); return true; }\n",
        harness: r#"async function check() {
  let forbidden;
  try {
    const {registerHooks} = require('node:module');
    const {pathToFileURL} = require('node:url');
    const root = pathToFileURL(__dirname + '/');
    registerHooks({resolve(specifier, context, nextResolve) {
      if (!specifier.startsWith('@/')) return nextResolve(specifier, context);
      const suffix = specifier.slice(2);
      if (!suffix.endsWith('.ts') || suffix.split('/').some(p => !p || p === '..' || p === '.')) throw new Error('UNSUPPORTED_ALIAS');
      const resolved = new URL(suffix, root);
      if (!resolved.href.startsWith(root.href)) throw new Error('ALIAS_ESCAPE');
      return nextResolve(resolved.href, context);
    }});
    const {canRead} = await import('@/target.ts');
    if (canRead('owner', 'owner') !== true) throw new Error('AUTHORIZED_CONTROL_FAILED');
    console.log('OMGS_CONTROL_' + process.env.OMGS_PROOF_NONCE);
    forbidden = canRead('intruder', 'owner');
  } catch (error) { console.error(error); return 2; }
  if (typeof forbidden !== 'boolean') return 2;
  if (forbidden) { console.log('OMGS_BOUNDARY_' + process.env.OMGS_PROOF_NONCE + '_' + process.env.OMGS_PROOF_CONTRACT); return 1; }
  console.log('BOUNDARY_ASSERTION_OK');
  return 0;
}
check().then(code => { process.exitCode = code; }, error => { console.error(error); process.exitCode = 2; });
"#,
    }
}
fn powershell_recipe() -> Recipe {
    Recipe {
        runtime: "pwsh", source: "target.ps1", test: "test.ps1", command: "pwsh -NoProfile -NonInteractive -File test.ps1",
        vulnerable: "function Test-CanRead($Actor, $Owner) { return $true }\n",
        fixed: "function Test-CanRead($Actor, $Owner) { return $Actor -ceq $Owner }\n",
        broken: "throw 'missing target module'\n", control_failure: "function Test-CanRead($Actor, $Owner) { return $false }\n",
        dependency_failure: "function Test-CanRead($Actor, $Owner) { if ($Actor -cne $Owner) { throw 'missing dependency' }; return $true }\n",
        harness: "$ErrorActionPreference = 'Stop'\ntry {\n  . ./target.ps1\n  if (-not (Test-CanRead 'owner' 'owner')) { throw 'AUTHORIZED_CONTROL_FAILED' }\n  Write-Output \"OMGS_CONTROL_$env:OMGS_PROOF_NONCE\"\n  $forbidden = Test-CanRead 'intruder' 'owner'\n  if ($forbidden -isnot [bool]) { throw 'INVALID_TARGET_RESULT' }\n} catch { Write-Error -ErrorAction Continue $_; exit 2 }\nif ($forbidden) { Write-Output \"OMGS_BOUNDARY_$($env:OMGS_PROOF_NONCE)_$($env:OMGS_PROOF_CONTRACT)\"; exit 1 }\nWrite-Output 'BOUNDARY_ASSERTION_OK'\nexit 0\n",
    }
}
#[cfg(unix)]
fn swift_recipe() -> Recipe {
    Recipe {
        runtime: "swiftc", source: "target.swift", test: "main.swift", command: "swiftc target.swift main.swift -o fixture || exit 2; ./fixture",
        broken: "import MissingTargetModule\n", control_failure: "func canRead(_ actor: String, _ owner: String) throws -> Bool { false }\n",
        vulnerable: "func canRead(_ actor: String, _ owner: String) throws -> Bool { DiagnosticLog.record(); return true }\n",
        fixed: "func canRead(_ actor: String, _ owner: String) throws -> Bool { DiagnosticLog.record(); return actor == owner }\n",
        dependency_failure: "enum DependencyError: Error { case missing }\nfunc canRead(_ actor: String, _ owner: String) throws -> Bool { if actor != owner { throw DependencyError.missing }; return true }\n",
        harness: "// Unrelated logging stub only; real authorization stays in target.swift.\nenum DiagnosticLog { static func record() {} }\nimport Foundation\nlet nonce = ProcessInfo.processInfo.environment[\"OMGS_PROOF_NONCE\"]!\nlet marker = ProcessInfo.processInfo.environment[\"OMGS_PROOF_CONTRACT\"]!\n#if canImport(Darwin)\nimport Darwin\n#else\nimport Glibc\n#endif\ndo {\n  guard try canRead(\"owner\", \"owner\") else { exit(2) }\n  print(\"OMGS_CONTROL_\\(nonce)\")\n  if try canRead(\"intruder\", \"owner\") { print(\"OMGS_BOUNDARY_\\(nonce)_\\(marker)\"); exit(1) }\n  print(\"BOUNDARY_ASSERTION_OK\")\n} catch { exit(2) }\n",
    }
}
#[cfg(windows)]
#[test]
fn windows_toolchains_launch_inside_mxc() {
    if !ready("cargo") {
        return;
    }
    let d = omgs::platform::temp_root()
        .unwrap()
        .join(format!("omgs-windows-tools-{}", std::process::id()));
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
        typescript_recipe(),
        powershell_recipe(),
        swift_recipe(),
    ];
    #[cfg(windows)]
    let all = vec![node_recipe(), typescript_recipe(), powershell_recipe()];
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

#[test]
fn t50_t69_typescript_and_swift_dependency_boundaries_are_documented() {
    let recipe = include_str!("../skill/PROOF-RECIPES.md");
    for text in [
        "registerHooks",
        "await import('./src/decision.ts')",
        "UNSUPPORTED_ALIAS",
        "minimal real source set",
        "Evaluators reject replaced enforcement",
        "No installation",
        "Missing Next.js",
    ] {
        assert!(recipe.contains(text), "{text}");
    }
}
