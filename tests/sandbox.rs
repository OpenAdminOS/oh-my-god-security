//! End to end proofs through the real MXC executor. Each test that needs MXC
//! skips with a printed reason when no pinned executor is found; CI installs
//! one so they run there.

use std::path::{Path, PathBuf};
use std::process::Output;

// Valid storage fixtures must have the same owner and ACL as runtime files,
// including when the Windows test process has an elevated token.
fn write_private_fixture(
    path: impl AsRef<std::path::Path>,
    bytes: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    omgs::runmeta::write_atomic_bytes(path.as_ref(), bytes.as_ref())
}

fn scratch(name: &str) -> PathBuf {
    let base = std::env::temp_dir()
        .canonicalize()
        .unwrap_or_else(|_| std::env::temp_dir());
    static BASE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    let base = BASE.get_or_init(|| {
        let base = base.join(format!("omgs-private-fixtures-{}", std::process::id()));
        omgs::platform::create_private_tree(&base).unwrap();
        base
    });
    let d = base.join(format!("omgs-sbx-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    omgs::platform::private_dir(&d).unwrap();
    d
}

/// Runs the CLI with a throwaway data directory, handing it the executor
/// this test process found so both agree on what is installed.
fn omgs(home: &Path, args: &[&str]) -> Output {
    let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"));
    c.args(args).env("OMGS_HOME", home);
    if let Ok(l) = omgs::sandbox::locate_executor() {
        c.env("OMGS_MXC_EXEC", l.path);
    }
    c.output().unwrap()
}

#[track_caller]
fn mxc_ready() -> bool {
    match omgs::sandbox::locate_executor() {
        Ok(located) => {
            #[cfg(windows)]
            {
                let probe = omgs::sandbox::windows_probe(&located.path).unwrap();
                if probe.needs_dacl_augmentation == Some(true) {
                    assert_augmented_tier_refusal(
                        probe.tier.as_deref().unwrap(),
                        std::panic::Location::caller().line(),
                    );
                    return false;
                }
            }
            #[cfg(not(windows))]
            let _ = located;
            true
        }
        Err(e) => {
            eprintln!("skipping: {e}");
            false
        }
    }
}

// On augmentation hosts every real-proof test using mxc_ready executes this
// refusal contract instead. Safe Windows tiers retain their real proof runs.
#[cfg(windows)]
fn assert_augmented_tier_refusal(tier: &str, caller: u32) {
    use omgs::sandbox::{prove, ProveOutcome, ProveRequest, Tier};
    use std::process::Command;
    let d = scratch(&format!("augmentation-refusal-{caller}"));
    let target = d.join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("evidence.txt"), "untouched").unwrap();
    let roots: Vec<_> = std::iter::once(target.clone())
        .chain(
            omgs::sandbox::toolchain_roots("windows", omgs::platform::home().as_deref())
                .into_iter()
                .filter(|p| p.exists()),
        )
        .map(|p| p.canonicalize().unwrap())
        .collect();
    let acls = || {
        roots
            .iter()
            .map(|p| {
                let output = Command::new("icacls.exe")
                    .arg(p)
                    .arg("/l")
                    .output()
                    .unwrap();
                assert!(output.status.success(), "{output:?}");
                output.stdout
            })
            .collect::<Vec<_>>()
    };
    let before = acls();
    let check = |message: &str| {
        assert!(message.contains(tier), "{message}");
        assert!(
            message.contains(
                "MXC 1.0.1 leaves changed ACEs on granted folders even after a successful run"
            ),
            "{message}"
        );
        assert!(
            message.contains("Windows 11") && message.contains("needsDaclAugmentation=false"),
            "{message}"
        );
    };
    let lib_dir = d.join("library-proof");
    let request = ProveRequest {
        expect_marker: None,
        command: "echo REFUSAL_WORKLOAD_RAN".into(),
        test: None,
        target: Some(target.clone()),
        run_dir: lib_dir.clone(),
        timeout_ms: 1000,
        tier: Tier::Test,
        stage: None,
        expected_tree_sha256: None,
    };
    let ProveOutcome::Blocked { reason } = prove(&request) else {
        panic!("augmentation tier executed");
    };
    check(&reason);
    assert!(
        !lib_dir.exists(),
        "refusal must precede staging and config creation"
    );
    let home = d.join("home");
    for args in [
        vec![
            "prove",
            "--target",
            target.to_str().unwrap(),
            "--cmd",
            "echo REFUSAL_WORKLOAD_RAN",
        ],
        vec!["doctor", "--live"],
    ] {
        let out = omgs(&home, &args);
        assert_eq!(out.status.code(), Some(3), "{}", text(&out));
        check(&text(&out));
        assert!(!text(&out).contains("REFUSAL_WORKLOAD_RAN"));
    }
    fn no_config(path: &Path) {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            assert_ne!(entry.file_name(), "mxc-config.json");
            if entry.file_type().unwrap().is_dir() {
                no_config(&entry.path());
            }
        }
    }
    // Blocked cleanup removes run directories, so the absence of configs is
    // only a sanity check. The evidence that no config reached MXC is the
    // unchanged ACLs on toolchain roots MXC would have augmented.
    no_config(&d);
    assert_eq!(acls(), before, "refusal changed granted folder ACLs");
    assert_eq!(
        std::fs::read_to_string(target.join("evidence.txt")).unwrap(),
        "untouched"
    );
    std::fs::remove_dir_all(d).unwrap();
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn prove_refuses_an_executor_that_does_not_match_the_pin() {
    let d = scratch("pin");
    let fake = d.join("fake-exec");
    std::fs::write(&fake, b"#!/bin/sh\necho ran\n").unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args(["prove", "--cmd", "echo hi"])
        .env("OMGS_HOME", d.join("home"))
        .env("OMGS_MXC_EXEC", &fake)
        .env("PATH", &d)
        .output()
        .unwrap();
    let t = text(&out);
    if omgs::sandbox::this_executor().is_err() {
        assert_eq!(out.status.code(), Some(3), "{t}");
        return;
    }
    assert_eq!(out.status.code(), Some(3), "{t}");
    assert!(t.contains("refusing to run"), "{t}");
    assert!(t.contains("target code was not executed"), "{t}");
    assert!(!t.lines().any(|l| l.trim() == "ran"), "{t}");
    let _ = std::fs::remove_dir_all(&d);
}

#[cfg(unix)]
#[test]
fn blocked_reason_escapes_terminal_controls() {
    let d = scratch("blocked-controls");
    let fake = d.join("fake\x1b[31m\r\nexecutor");
    std::fs::write(&fake, b"not a pinned executor").unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args(["prove", "--cmd", "echo hi"])
        .env("OMGS_HOME", d.join("home"))
        .env("OMGS_MXC_EXEC", &fake)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains('\x1b') && !stderr.contains('\r'),
        "{stderr:?}"
    );
    assert!(
        stderr.contains("fake\\u{1b}[31m\\r\\nexecutor"),
        "{stderr:?}"
    );
    std::fs::remove_dir_all(d).unwrap();
}

#[cfg(unix)]
#[test]
fn denials_hold_and_the_target_is_untouched() {
    if !mxc_ready() {
        return;
    }
    let d = scratch("deny");
    let home = d.join("home");
    let target = d.join("target");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("app.txt"), b"original").unwrap();
    let outside = d.join("outside.txt");
    std::fs::write(&outside, b"outside-secret-value").unwrap();
    let real_home = omgs::platform::home().unwrap();
    let home_probe = std::fs::read_dir(&real_home)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.is_file() && std::fs::File::open(p).is_ok());
    let home_check = home_probe
        .map(|p| format!("cat '{}' >/dev/null 2>&1 && echo READ_HOME;", p.display()))
        .unwrap_or_default();
    // A host loopback service answering HTTP, reachable from the test itself
    // (positive control) and expected unreachable from inside.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            use std::io::Write;
            let _ = c.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 6\r\n\r\nHOSTOK");
        }
    });
    let host_curl = std::process::Command::new("curl")
        .args(["-sm3", &format!("http://127.0.0.1:{port}/")])
        .output();
    let curl_works = host_curl.is_ok_and(|o| String::from_utf8_lossy(&o.stdout) == "HOSTOK");
    // Linux shows synthetic mount ancestors when scratch is beneath HOME.
    let mount_parent = d
        .strip_prefix(&real_home)
        .ok()
        .and_then(|p| p.components().next())
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .unwrap_or_default();
    let cmd = format!(
        "cat '{o}' 2>/dev/null && echo READ_OUTSIDE; \
         [ -n \"$(ls -A '{h}' 2>/dev/null | grep -vx -e .cargo -e .rustup -e '{mount_parent}')\" ] && echo LIST_HOME; \
         {home_check} \
         touch '{d}/escape' 2>/dev/null; \
         curl --version >/dev/null 2>&1 && echo CURL_EXISTS; \
         curl -sm3 https://example.com >/dev/null 2>&1 && echo NETWORK; \
         curl -sm3 http://127.0.0.1:{port}/ 2>/dev/null; \
         echo changed > app.txt && cat app.txt",
        o = outside.display(),
        h = real_home.display(),
        d = d.display()
    );
    let out = omgs(
        &home,
        &["prove", "--target", target.to_str().unwrap(), "--cmd", &cmd],
    );
    let t = text(&out);
    assert!(curl_works, "host loopback positive control must answer");
    assert!(
        t.lines().any(|line| line == "CURL_EXISTS"),
        "sandbox curl must exist: {t}"
    );
    for leak in [
        "READ_OUTSIDE",
        "outside-secret-value",
        "READ_HOME",
        "LIST_HOME",
        "NETWORK",
        "HOSTOK",
    ] {
        assert!(!t.contains(leak), "{leak} must be denied: {t}");
    }
    assert!(t.contains("changed"), "workspace must be writable: {t}");
    assert!(!d.join("escape").exists());
    assert_eq!(std::fs::read(target.join("app.txt")).unwrap(), b"original");
    let _ = std::fs::remove_dir_all(&d);
}

#[cfg(unix)]
#[test]
fn timeout_kills_the_tree_and_fails_the_run() {
    if !mxc_ready() {
        return;
    }
    let d = scratch("timeout");
    let started = std::time::Instant::now();
    let out = omgs(
        &d,
        &[
            "prove",
            "--timeout-ms",
            "2000",
            "--cmd",
            "sleep 120 & sleep 120",
        ],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(started.elapsed().as_secs() < 60);
    let _ = std::fs::remove_dir_all(&d);
}

#[cfg(target_os = "macos")]
#[test]
fn setsid_escape_is_killed_reported_and_fails_the_run() {
    if !mxc_ready() {
        return;
    }
    let Some(py) = omgs::platform::which("python3") else {
        eprintln!("skipping: python3 not found");
        return;
    };
    let d = scratch("setsid");
    let cmd = format!(
        "'{}' -I -c 'import os,time\nif os.fork()==0:\n    os.setsid()\n    if os.fork()==0:\n        time.sleep(300)\n    os._exit(0)\nprint(\"parent done\")'",
        py.display()
    );
    let out = omgs(&d, &["prove", "--cmd", &cmd]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("survivor killed"), "{t}");
    let record = record_from(&t);
    assert!(
        !record["survivors"].as_array().unwrap().is_empty(),
        "{record}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// The unlinked record a prove run printed the path of.
fn record_from(output: &str) -> serde_json::Value {
    let line = output
        .lines()
        .find_map(|l| l.strip_prefix("proof record: "))
        .expect("prove prints its record path");
    let path = line.split(" (").next().unwrap();
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn tier2_is_refused_without_linux_or_approval() {
    let d = scratch("tier2-refuse");
    let target = d.join("target");
    std::fs::create_dir_all(&target).unwrap();
    let out = omgs(
        &d.join("home"),
        &[
            "prove",
            "--tier",
            "2",
            "--target",
            target.to_str().unwrap(),
            "--cmd",
            "true",
        ],
    );
    let t = text(&out);
    assert_eq!(out.status.code(), Some(3), "{t}");
    if cfg!(target_os = "linux") {
        assert!(t.contains("one-time human approval"), "{t}");
    } else {
        assert!(t.contains("tier 2 runs only on Linux"), "{t}");
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn proof_records_back_confirmed_findings() {
    if !mxc_ready() {
        return;
    }
    let d = scratch("record");
    let home = d.join("home");
    let target = d.join("target");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("check.txt"), b"vulnerable").unwrap();
    std::fs::create_dir_all(target.join("tests/security")).unwrap();
    // A proof test that fails on the vulnerable target.
    let (x_test, failing, x_body): (&str, &str, &[u8]) = if cfg!(windows) {
        (
            "tests/security/x.test.cmd",
            "cmd.exe /d /c tests\\security\\x.test.cmd",
            b"@echo off\r\nset \"omgs_value=\"\r\nset /p omgs_value=<check.txt\r\nif not defined omgs_value exit /b 126\r\nif \"%omgs_value%\"==\"vulnerable\" exit /b 1\r\nexit /b 0\r\n",
        )
    } else {
        (
            "tests/security/x.test.sh",
            "sh tests/security/x.test.sh",
            b"grep -q vulnerable check.txt && exit 1; exit 0",
        )
    };
    std::fs::write(target.join(x_test), x_body).unwrap();
    let run = d.join("run");
    let init = omgs(
        &home,
        &[
            "audit",
            "init",
            "--target",
            target.to_str().unwrap(),
            "--out",
            run.to_str().unwrap(),
            "--no-sensors",
        ],
    );
    assert!(init.status.success(), "{}", text(&init));
    let fp = omgs::fingerprint("missing_authz", "GET /x", "db.x", "tenant");
    let out = omgs(
        &home,
        &[
            "prove",
            "--run",
            run.to_str().unwrap(),
            "--finding",
            &fp,
            "--test",
            x_test,
            "--cmd",
            failing,
            "--timeout-ms",
            "17000",
        ],
    );
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("proof_ref proofs/1.json"), "{t}");
    assert!(t.contains("proof support for test_proven: yes"), "{t}");
    let record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(run.join("proofs/1.json")).unwrap()).unwrap();
    assert_eq!(record["finding"], fp.as_str());
    assert_eq!(record["tier"], "test");
    assert_eq!(record["exit_code"], 1);
    assert_eq!(record["test_reachable"], true);
    assert_eq!(record["mxc_version"], omgs::sandbox::MXC_VERSION);
    assert!(!record["enforced"].as_array().unwrap().is_empty());
    assert_eq!(record["config_sha256"].as_str().unwrap().len(), 64);
    assert!(run.join("proofs/1/mxc-config.json").is_file());
    assert!(!run.join("proofs/1/workspace").exists());

    let finding = |proof_ref: Option<&str>| {
        let mut f = serde_json::json!({
            "fingerprint": fp,
            "title": "Unauthorized read",
            "verdict": "confirmed",
            "severity": "high",
            "proof_tier": "test_proven",
            "attack_class": "missing_authz",
            "entry_point": "GET /x",
            "sink": "db.x",
            "boundary": "tenant",
            "location": {"path": "app/x.ts", "line": 3},
            "evidence": "Proof test fails on the target.",
            "hunted_by": "red-1",
            "verified_by": "blue-1"
        });
        if let Some(r) = proof_ref {
            f["proof_ref"] = serde_json::json!(r);
        }
        serde_json::json!({ "findings": [f] }).to_string()
    };
    let findings = run.join("findings.json");
    std::fs::write(&findings, finding(Some("proofs/1.json"))).unwrap();
    let ok = omgs(
        &home,
        &["validate", "--findings", findings.to_str().unwrap()],
    );
    assert!(ok.status.success(), "{}", text(&ok));
    std::fs::write(&findings, finding(None)).unwrap();
    let missing = omgs(
        &home,
        &["validate", "--findings", findings.to_str().unwrap()],
    );
    assert_eq!(missing.status.code(), Some(1));
    assert!(text(&missing).contains("requires proof_ref"));
    std::fs::write(&findings, finding(Some("proofs/7.json"))).unwrap();
    let dangling = omgs(
        &home,
        &["validate", "--findings", findings.to_str().unwrap()],
    );
    assert_eq!(dangling.status.code(), Some(1));

    // A draft kept outside the target is staged into the workspace copy only.
    let (draft_name, staged_rel, staged_cmd, body): (&str, &str, &str, &[u8]) = if cfg!(windows) {
        (
            "draft.test.cmd",
            "tests/security/new.test.cmd",
            "cmd.exe /d /c tests\\security\\new.test.cmd",
            b"@echo off\r\nset \"omgs_value=\"\r\nset /p omgs_value=<check.txt\r\nif not defined omgs_value exit /b 126\r\nif \"%omgs_value%\"==\"vulnerable\" exit /b 1\r\nexit /b 0\r\n",
        )
    } else {
        (
            "draft.test.sh",
            "tests/security/new.test.sh",
            "sh tests/security/new.test.sh",
            b"grep -q vulnerable check.txt && exit 1; exit 0",
        )
    };
    let draft = d.join(draft_name);
    std::fs::write(&draft, body).unwrap();
    let staged = omgs(
        &home,
        &[
            "prove",
            "--run",
            run.to_str().unwrap(),
            "--finding",
            &fp,
            "--test",
            staged_rel,
            "--test-from",
            draft.to_str().unwrap(),
            "--cmd",
            staged_cmd,
        ],
    );
    assert_eq!(staged.status.code(), Some(1), "{}", text(&staged));
    assert!(!target.join(staged_rel).exists());
    let staged_record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(run.join("proofs/2.json")).unwrap()).unwrap();
    assert_eq!(staged_record["exit_code"], 1);
    assert_eq!(staged_record["test_reachable"], true);
    assert_eq!(staged_record["executor_error"], false);
    assert!(staged_record["test_from"]
        .as_str()
        .unwrap()
        .ends_with(draft_name));

    // An independent replay of the recorded proof reproduces it.
    let replay = omgs(
        &home,
        &["prove", "--run", run.to_str().unwrap(), "--replay", "1"],
    );
    assert!(replay.status.success(), "{}", text(&replay));
    assert!(text(&replay).contains("reproduced"));
    let replayed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(run.join("proofs/3.json")).unwrap()).unwrap();
    assert_eq!(replayed["replays"], 1);
    assert_eq!(replayed["timeout_ms"], 17000);
    let config: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(run.join("proofs/3/mxc-config.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        config["process"]["timeout"],
        omgs::sandbox::executor_timeout_ms(std::env::consts::OS, 17000)
    );

    // A replay never takes a host path from an edited record.
    let original = std::fs::read_to_string(run.join("proofs/1.json")).unwrap();
    let mut edited: serde_json::Value = serde_json::from_str(&original).unwrap();
    edited["target"] = serde_json::json!(d.to_str().unwrap());
    std::fs::write(run.join("proofs/1.json"), edited.to_string()).unwrap();
    let redirected = omgs(
        &home,
        &["prove", "--run", run.to_str().unwrap(), "--replay", "1"],
    );
    assert_eq!(redirected.status.code(), Some(2), "{}", text(&redirected));
    assert!(text(&redirected).contains("not this run's target"));
    std::fs::write(run.join("proofs/1.json"), original).unwrap();

    // Dirty content and commit changes refuse replay without spending budget.
    let used = || {
        omgs::runmeta::read(&run).unwrap()["proof_runs_used"]
            .as_u64()
            .unwrap()
    };
    let before = used();
    std::fs::write(target.join("check.txt"), b"dirty").unwrap();
    let dirty = omgs(
        &home,
        &["prove", "--run", run.to_str().unwrap(), "--replay", "1"],
    );
    assert_eq!(dirty.status.code(), Some(3), "{}", text(&dirty));
    assert!(
        text(&dirty).contains("snapshot differs"),
        "{}",
        text(&dirty)
    );
    assert_eq!(used(), before);
    std::fs::write(target.join("check.txt"), b"vulnerable").unwrap();
    std::fs::create_dir_all(target.join(".git")).unwrap();
    std::fs::write(target.join(".git/HEAD"), "a".repeat(40)).unwrap();
    let commit = omgs(
        &home,
        &["prove", "--run", run.to_str().unwrap(), "--replay", "1"],
    );
    assert_eq!(commit.status.code(), Some(2), "{}", text(&commit));
    assert!(
        text(&commit).contains("target commit differs"),
        "{}",
        text(&commit)
    );
    assert_eq!(used(), before);
    std::fs::remove_dir_all(target.join(".git")).unwrap();

    // A rejected record may rest on a control test that passes.
    std::fs::write(target.join("check.txt"), b"fixed").unwrap();
    let control = omgs(
        &home,
        &[
            "prove",
            "--run",
            run.to_str().unwrap(),
            "--finding",
            &fp,
            "--test",
            x_test,
            "--cmd",
            failing,
        ],
    );
    assert!(control.status.success(), "{}", text(&control));
    let n = text(&control)
        .lines()
        .find_map(|l| l.split("proof_ref ").nth(1))
        .map(|r| r.trim_end_matches(')').to_string())
        .unwrap();
    let mut rejected: serde_json::Value = serde_json::from_str(&finding(Some(&n))).unwrap();
    rejected["findings"][0]["verdict"] = "rejected".into();
    rejected["findings"][0]["severity"] = serde_json::Value::Null;
    std::fs::write(&findings, rejected.to_string()).unwrap();
    let ok_rejected = omgs(
        &home,
        &["validate", "--findings", findings.to_str().unwrap()],
    );
    assert!(ok_rejected.status.success(), "{}", text(&ok_rejected));
    std::fs::write(target.join("check.txt"), b"vulnerable").unwrap();

    // A command that never ran (127) is not a failing proof test.
    let broken = omgs(
        &home,
        &[
            "prove",
            "--run",
            run.to_str().unwrap(),
            "--finding",
            &fp,
            "--test",
            x_test,
            "--cmd",
            &format!("omgs-no-such-command-xyz {x_test}"),
        ],
    );
    assert!(
        text(&broken).contains("proof_ref proofs/5.json"),
        "{}",
        text(&broken)
    );
    std::fs::write(&findings, finding(Some("proofs/5.json"))).unwrap();
    let never_ran = omgs(
        &home,
        &["validate", "--findings", findings.to_str().unwrap()],
    );
    assert_eq!(never_ran.status.code(), Some(1));
    assert!(
        text(&never_ran).contains("proof support requires assertion exit"),
        "{}",
        text(&never_ran)
    );
    assert!(
        text(&broken).contains("proof support for test_proven: no"),
        "{}",
        text(&broken)
    );
    // Equal inner exits cannot reproduce an originally unclean record.
    let mut original = omgs::proof::load(&run, "proofs/1.json").unwrap();
    original.command_finished = false;
    omgs::proof::write(&run, &original).unwrap();
    let unclean = omgs(
        &home,
        &["prove", "--run", run.to_str().unwrap(), "--replay", "1"],
    );
    assert_eq!(unclean.status.code(), Some(1), "{}", text(&unclean));
    assert!(
        text(&unclean).contains("NOT reproduced"),
        "{}",
        text(&unclean)
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[cfg(target_os = "macos")]
#[test]
fn posix_spawn_setsid_escape_is_killed_and_fails_the_run() {
    if !mxc_ready() {
        return;
    }
    let Some(py) = omgs::platform::which("python3") else {
        eprintln!("skipping: python3 not found");
        return;
    };
    let d = scratch("spawn-setsid");
    let cmd = format!(
        "'{}' -I -c 'import os\nos.posix_spawn(\"/bin/sleep\", [\"sleep\", \"300\"], {{}}, setsid=True)\nprint(\"spawned\")'",
        py.display()
    );
    let out = omgs(&d, &["prove", "--cmd", &cmd]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("survivor killed"), "{t}");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn concurrent_or_repeated_proofs_cannot_overspend_the_budget() {
    // Without MXC nothing runs and the charge is given back, so this needs it.
    if !mxc_ready() {
        return;
    }
    let d = scratch("budget");
    let home = d.join("home");
    let target = d.join("target");
    std::fs::create_dir_all(&target).unwrap();
    let run = d.join("run");
    let init = omgs(
        &home,
        &[
            "audit",
            "init",
            "--target",
            target.to_str().unwrap(),
            "--out",
            run.to_str().unwrap(),
            "--budget",
            "1",
            "--no-sensors",
        ],
    );
    assert!(init.status.success(), "{}", text(&init));
    let executor = omgs::sandbox::locate_executor().unwrap();
    let mut children = Vec::new();
    for _ in 0..6 {
        children.push(
            std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
                .args([
                    "prove",
                    "--run",
                    run.to_str().unwrap(),
                    "--cmd",
                    "echo budget-proof-ran",
                ])
                .env("OMGS_HOME", &home)
                .env("OMGS_MXC_EXEC", &executor.path)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    let outputs: Vec<_> = children
        .into_iter()
        .map(|c| c.wait_with_output().unwrap())
        .collect();
    assert_eq!(
        outputs
            .iter()
            .filter(|o| o.status.success() && text(o).contains("budget-proof-ran"))
            .count(),
        1,
        "{:?}",
        outputs.iter().map(text).collect::<Vec<_>>()
    );
    assert_eq!(
        outputs
            .iter()
            .filter(|o| o.status.code() == Some(3) && text(o).contains("budget exhausted"))
            .count(),
        5
    );
    assert_eq!(omgs::runmeta::read(&run).unwrap()["proof_runs_used"], 1);
    assert_eq!(
        std::fs::read_dir(run.join("proofs"))
            .unwrap()
            .filter(|e| e
                .as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|s| s == "json"))
            .count(),
        1
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[cfg(target_os = "macos")]
#[test]
fn installer_trust_fixture_fails_vulnerable_and_passes_fixed() {
    if !mxc_ready() {
        return;
    }
    if omgs::platform::which("swiftc").is_none() {
        eprintln!("skipping: swiftc not found");
        return;
    }
    let d = scratch("swift");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("benchmark/fixtures/installer-trust");
    let run = |variant: &str| {
        omgs(
            &d,
            &[
                "prove",
                "--target",
                fixture.to_str().unwrap(),
                "--test",
                "main.swift",
                "--expect-marker",
                "BOUNDARY_ASSERTION_FAILED",
                "--cmd",
                &format!(
                    "swiftc main.swift {variant}/Verifier.swift -o \"$TMPDIR/probe\" || exit 2; \"$TMPDIR/probe\""
                ),
            ],
        )
    };
    let vulnerable = run("vulnerable");
    assert_eq!(vulnerable.status.code(), Some(1), "{}", text(&vulnerable));
    assert!(text(&vulnerable).contains("INVARIANTS VIOLATED"));
    let fixed = run("fixed");
    assert!(fixed.status.success(), "{}", text(&fixed));
    assert!(text(&fixed).contains("BOUNDARY_ASSERTION_OK"));
    assert!(text(&vulnerable).contains("OMGS_BOUNDARY_"));
    for out in [&vulnerable, &fixed] {
        assert!(text(out).contains("OMGS_CONTROL_"));
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn an_mxc_timeout_is_never_a_proof() {
    if !mxc_ready() {
        return;
    }
    let d = scratch("mxc-timeout");
    let home = d.join("home");
    let target = d.join("target");
    std::fs::create_dir_all(target.join("tests")).unwrap();
    let (test, cmd): (&str, &str) = if cfg!(windows) {
        ("tests/slow.cmd", "cmd.exe /d /c tests\\slow.cmd")
    } else {
        ("tests/slow.sh", "sh tests/slow.sh")
    };
    let body: &[u8] = if cfg!(windows) {
        b"@for /l %%i in (1,1,2000000000) do @rem\r\n"
    } else {
        b"sleep 30"
    };
    std::fs::write(target.join(test), body).unwrap();
    let run = d.join("run");
    let init = omgs(
        &home,
        &[
            "audit",
            "init",
            "--target",
            target.to_str().unwrap(),
            "--out",
            run.to_str().unwrap(),
            "--no-sensors",
        ],
    );
    assert!(init.status.success(), "{}", text(&init));
    let fp = omgs::fingerprint("missing_authz", "GET /t", "db.t", "tenant");
    let out = omgs(
        &home,
        &[
            "prove",
            "--run",
            run.to_str().unwrap(),
            "--finding",
            &fp,
            "--test",
            test,
            "--timeout-ms",
            "2000",
            "--cmd",
            cmd,
        ],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(run.join("proofs/1.json")).unwrap()).unwrap();
    assert_eq!(record["timed_out"], true, "{record}");
    if cfg!(windows) {
        let config: serde_json::Value =
            serde_json::from_slice(&std::fs::read(run.join("proofs/1/mxc-config.json")).unwrap())
                .unwrap();
        assert_eq!(config["process"]["timeout"], 0);
        assert!(record["enforced"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("wall_clock=2000ms")));
        assert!(!record["output"]
            .as_str()
            .unwrap()
            .contains("script timed out"));
        if record["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| gap.as_str().unwrap().starts_with("Windows ACL cleanup:"))
        {
            assert_eq!(record["cleanup_complete"], false);
        }
    }
    let findings = run.join("findings.json");
    std::fs::write(
        &findings,
        serde_json::json!({"findings": [{
            "fingerprint": fp, "title": "t", "verdict": "confirmed", "severity": "high",
            "proof_tier": "test_proven", "attack_class": "missing_authz", "entry_point": "GET /t",
            "sink": "db.t", "boundary": "tenant", "location": {"path": "a.ts", "line": 1},
            "evidence": "e", "hunted_by": "red-1", "verified_by": "blue-1",
            "proof_ref": "proofs/1.json"
        }]})
        .to_string(),
    )
    .unwrap();
    let v = omgs(
        &home,
        &["validate", "--findings", findings.to_str().unwrap()],
    );
    assert_eq!(v.status.code(), Some(1), "{}", text(&v));
    assert!(text(&v).contains("did not finish cleanly"), "{}", text(&v));
    let _ = std::fs::remove_dir_all(&d);
}

#[cfg(windows)]
#[test]
fn windows_denials_hold_and_the_target_is_untouched() {
    if !mxc_ready() {
        return;
    }
    let d = scratch("deny-win");
    let target = d.join("target");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("app.txt"), b"original").unwrap();
    let outside = d.join("outside.txt");
    std::fs::write(&outside, b"outside-secret-value").unwrap();
    let cmd = format!(
        "cmd.exe /d /c type \"{}\" & echo changed> app.txt & type app.txt",
        outside.display()
    );
    let out = omgs(
        &d.join("home"),
        &["prove", "--target", target.to_str().unwrap(), "--cmd", &cmd],
    );
    let t = text(&out);
    assert!(!t.contains("outside-secret-value"), "{t}");
    assert!(t.contains("changed"), "{t}");
    assert_eq!(std::fs::read(target.join("app.txt")).unwrap(), b"original");
    let _ = std::fs::remove_dir_all(&d);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_tier2_has_a_private_loopback() {
    if !mxc_ready() {
        return;
    }
    let Some(py) = omgs::platform::which("python3") else {
        eprintln!("skipping: python3 not found");
        return;
    };
    let d = scratch("tier2");
    let home = d.join("home");
    let target = d.join("target");
    std::fs::create_dir_all(&target).unwrap();
    // A service on the host loopback the app under test must not reach.
    let host = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let host_port = host.local_addr().unwrap().port();
    std::fs::write(
        target.join("app.py"),
        format!(
            "import socket\ns=socket.socket();s.bind(('127.0.0.1',0));s.listen()\nc=socket.create_connection(s.getsockname());a,_=s.accept();c.send(b'hi');print('INSIDE',a.recv(2))\ntry:\n    socket.create_connection(('127.0.0.1',{host_port}),timeout=2);print('HOST_REACHED')\nexcept OSError:\n    print('host unreachable')\n"
        ),
    )
    .unwrap();
    // The approval is a person's step; the test seeds it as that person would.
    let canonical = target.canonicalize().unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join("tier2-approvals.json"),
        serde_json::json!({"approvals": [{"target": canonical, "approved_at_ms": 0}]}).to_string(),
    )
    .unwrap();
    let out = omgs(
        &home,
        &[
            "prove",
            "--tier",
            "2",
            "--target",
            target.to_str().unwrap(),
            "--cmd",
            &format!("{} -I app.py", py.display()),
        ],
    );
    let t = text(&out);
    assert!(t.contains("INSIDE b'hi'"), "{t}");
    assert!(
        t.contains("host unreachable") && !t.contains("HOST_REACHED"),
        "{t}"
    );
    drop(host);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn invalid_proof_inputs_and_failed_reservation_do_not_spend_budget() {
    let d = scratch("invalid-budget");
    let home = d.join("home");
    let target = d.join("target");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("test.txt"), b"proof").unwrap();
    let run = d.join("run");
    let init = omgs(
        &home,
        &[
            "audit",
            "init",
            "--target",
            target.to_str().unwrap(),
            "--out",
            run.to_str().unwrap(),
            "--no-sensors",
        ],
    );
    assert!(init.status.success(), "{}", text(&init));
    let fp = omgs::fingerprint("x", "x", "x", "x");
    let base = ["prove", "--run", run.to_str().unwrap()];
    for extra in [
        vec!["--cmd", " "],
        vec!["--cmd", "echo ok", "--timeout-ms", "0"],
        vec!["--cmd", "echo ok", "--timeout-ms", "4294967296"],
        vec!["--cmd", "echo ok", "--finding", &fp],
        vec![
            "--cmd",
            "echo wrong-test.txt",
            "--finding",
            &fp,
            "--test",
            "test.txt",
        ],
    ] {
        let out = omgs(&home, &[base.as_slice(), &extra].concat());
        assert_eq!(out.status.code(), Some(2), "{}", text(&out));
        assert_eq!(
            omgs::runmeta::read(&run)
                .unwrap()
                .get("proof_runs_used")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            0
        );
        assert!(!run.join("proofs").exists());
    }
    std::fs::write(run.join("proofs"), b"cannot reserve a directory").unwrap();
    let out = omgs(&home, &[base.as_slice(), &["--cmd", "echo ok"]].concat());
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert_eq!(omgs::runmeta::read(&run).unwrap()["proof_runs_used"], 0);
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn markers_survive_a_real_mxc_output_flood() {
    if !mxc_ready() {
        return;
    }
    let d = scratch("marker-flood");
    let cmd = if cfg!(windows) {
        "for /l %i in (1,1,20000) do @echo 0123456789abcdef0123456789abcdef"
    } else {
        "i=0; while [ $i -lt 20000 ]; do echo 0123456789abcdef0123456789abcdef; i=$((i+1)); done; exit 17"
    };
    let out = omgs(&d, &["prove", "--cmd", cmd]);
    let record = record_from(&text(&out));
    assert_eq!(record["command_started"], true, "{record}");
    assert_eq!(record["command_finished"], true, "{record}");
    assert_eq!(record["executor_error"], false, "{record}");
    assert_eq!(record["timed_out"], false, "{record}");
    assert_eq!(record["exit_code"], if cfg!(windows) { 0 } else { 17 });
    assert!(record["output_bytes_total"].as_u64().unwrap() > 256 * 1024);
    let _ = std::fs::remove_dir_all(d);
}

#[cfg(unix)]
#[test]
fn sensors_execute_resolved_paths_even_with_a_poisoned_current_directory() {
    use std::os::unix::fs::PermissionsExt;
    if !mxc_ready() {
        return;
    }
    let d = scratch("sensor-paths");
    let safe = d.join("safe");
    let poisoned = d.join("poisoned");
    let target = d.join("target");
    for dir in [&safe, &poisoned, &target] {
        std::fs::create_dir_all(dir).unwrap();
    }
    for tool in ["gitleaks", "semgrep"] {
        let output = if tool == "gitleaks" {
            "[]"
        } else {
            r#"{"results":[],"errors":[]}"#
        };
        let script = format!(
            "#!/bin/sh\n[ \"$0\" = '{}' ] || exit 77\nprintf '%s' '{}'\n",
            safe.join(tool).display(),
            output
        );
        std::fs::write(safe.join(tool), script).unwrap();
        std::fs::set_permissions(safe.join(tool), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            poisoned.join(tool),
            format!(
                "#!/bin/sh\necho poisoned > '{}'\n",
                d.join("poisoned-ran").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(poisoned.join(tool), std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }
    let rules = d.join("rules.yaml");
    std::fs::write(&rules, "rules: []").unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args([
            "check",
            "--target",
            target.to_str().unwrap(),
            "--out",
            d.join("reports").to_str().unwrap(),
        ])
        .env("PATH", format!(".:{}:/usr/bin:/bin", safe.display()))
        .env("OMGS_SEMGREP_CONFIG", rules)
        .env(
            "OMGS_MXC_EXEC",
            omgs::sandbox::locate_executor().unwrap().path,
        )
        .current_dir(poisoned)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    assert!(!d.join("poisoned-ran").exists());
    let report = std::fs::read_to_string(d.join("reports/sensors.json")).unwrap();
    let report: serde_json::Value = serde_json::from_str(&report).unwrap();
    for tool in ["gitleaks", "semgrep"] {
        assert!(
            report["tools_run"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!(tool)),
            "{report}"
        );
    }
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn a_relative_executor_override_runs_the_verified_file() {
    if !mxc_ready() {
        return;
    }
    let executor = omgs::sandbox::locate_executor().unwrap().path;
    let d = scratch("relative-executor");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args(["doctor", "--live"])
        .current_dir(executor.parent().unwrap())
        .env("OMGS_HOME", &d)
        .env("OMGS_MXC_EXEC", executor.file_name().unwrap())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn doctor_discloses_planned_controls_and_gaps_without_an_executor() {
    let d = scratch("doctor-missing");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .arg("doctor")
        .env("OMGS_HOME", &d)
        .env("PATH", "")
        .env("OMGS_MXC_EXEC", d.join("missing"))
        .output()
        .unwrap();
    let t = text(&out);
    assert!(!out.status.success());
    assert!(
        t.contains("planned proof controls if a verified MXC executor becomes available"),
        "{t}"
    );
    for runtime in ["sh", "node", "pwsh", "python3", "swiftc"] {
        assert!(t.contains(&format!("{runtime} not on host PATH")), "{t}");
    }
    for gap in [
        "readable toolchain roots",
        "no total disk quota",
        "hardlinked",
        "memory and task limits",
    ] {
        assert!(t.contains(gap), "{gap}: {t}");
    }
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn target_mismatch_and_invalid_metadata_never_charge_budget() {
    let d = scratch("strict-meta");
    let target = d.join("target");
    let other = d.join("other");
    let run = d.join("run");
    for path in [&target, &other, &run] {
        omgs::platform::private_dir(path).unwrap();
    }
    let meta = serde_json::json!({"target": target, "budget_agent_calls": 1});
    let meta_path = run.join(omgs::runmeta::FILE);
    write_private_fixture(&meta_path, meta.to_string()).unwrap();
    let mismatch = omgs(
        &d.join("home"),
        &[
            "prove",
            "--run",
            run.to_str().unwrap(),
            "--target",
            other.to_str().unwrap(),
            "--cmd",
            "echo ran",
        ],
    );
    assert_eq!(mismatch.status.code(), Some(2), "{}", text(&mismatch));
    assert!(text(&mismatch).contains("must match this run's target"));
    assert_eq!(
        std::fs::read_to_string(&meta_path).unwrap(),
        meta.to_string()
    );
    for key in ["budget_agent_calls", "agent_calls_used", "proof_runs_used"] {
        for value in [
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!("1"),
            serde_json::json!(null),
            serde_json::json!(false),
            serde_json::json!([]),
        ] {
            let mut invalid = meta.clone();
            invalid[key] = value;
            let saved = invalid.to_string();
            write_private_fixture(&meta_path, &saved).unwrap();
            let out = omgs(
                &d.join("home"),
                &["prove", "--run", run.to_str().unwrap(), "--cmd", "echo ran"],
            );
            assert_eq!(out.status.code(), Some(2), "{}", text(&out));
            assert!(text(&out).contains(key));
            assert_eq!(std::fs::read_to_string(&meta_path).unwrap(), saved);
        }
    }
    assert!(!run.join("proofs").exists());
    std::fs::remove_dir_all(d).unwrap();
}

#[cfg(not(target_os = "linux"))]
#[test]
fn approve_refuses_tier2_before_prompting_or_writing() {
    let d = scratch("approve-refuse");
    let out = omgs(
        &d.join("home"),
        &["approve", "--target", d.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(3), "{}", text(&out));
    assert!(text(&out).contains("tier 2 runs only on Linux"));
    assert!(text(&out).contains("target code was not executed"));
    assert!(!d.join("home/tier2-approvals.json").exists());
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn proof_test_paths_are_counted_on_every_os() {
    let d = scratch("check-paths");
    let target = d.join("target");
    std::fs::create_dir_all(target.join("tests/security")).unwrap();
    for rel in [
        "tests/security/test.rs",
        "a.security.test.js",
        "b.security.spec.ts",
    ] {
        std::fs::write(target.join(rel), b"text only").unwrap();
    }
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args([
            "check",
            "--target",
            target.to_str().unwrap(),
            "--out",
            d.join("out").to_str().unwrap(),
        ])
        .env("OMGS_HOME", d.join("home"))
        .env("PATH", "")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("committed proof tests found: 3"));
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn doctor_and_proofs_list_memory_and_task_gap_once() {
    #[cfg(windows)]
    if !mxc_ready() {
        return;
    }
    let d = scratch("unique-gaps");
    let doctor = omgs(&d, &["doctor"]);
    let needle = if cfg!(target_os = "linux") {
        "memory and task limits conditional"
    } else {
        "memory and task limits not applied"
    };
    assert_eq!(
        text(&doctor).matches(needle).count(),
        1,
        "{}",
        text(&doctor)
    );
    if mxc_ready() {
        let out = omgs(&d, &["prove", "--cmd", "echo ok"]);
        let record = record_from(&text(&out));
        assert_eq!(
            record["gaps"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|g| g.as_str().unwrap().contains(needle))
                .count(),
            1
        );
        assert_eq!(text(&out).matches(needle).count(), 1, "{}", text(&out));
    }
    std::fs::remove_dir_all(d).unwrap();
}

#[cfg(unix)]
#[test]
fn concurrent_proofs_do_not_sweep_each_others_processes() {
    if !mxc_ready() {
        return;
    }
    let d = scratch("concurrent-sweep");
    let home = d.join("home");
    let run = d.join("held");
    omgs::platform::private_dir(&run).unwrap();
    write_private_fixture(run.join(omgs::runmeta::FILE), "{}").unwrap();
    let executor = omgs::sandbox::locate_executor().unwrap();

    struct HeldProof {
        child: Option<std::process::Child>,
        release: PathBuf,
    }
    impl Drop for HeldProof {
        fn drop(&mut self) {
            // Release the workload on assertion failure as well, so its own
            // supervisor can finish cleanup and reap the executor.
            let _ = std::fs::write(&self.release, b"release");
            if let Some(child) = &mut self.child {
                let _ = child.wait();
            }
        }
    }
    let workspace = run.join("proofs/1/workspace");
    let mut held = HeldProof {
        release: workspace.join("release"),
        child: Some(
            std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
                .args([
                    "prove",
                    "--run",
                    run.to_str().unwrap(),
                    "--cmd",
                    "echo ready > ready; while [ ! -f release ]; do /bin/sleep 0.02; done",
                ])
                .env("OMGS_HOME", &home)
                .env("OMGS_MXC_EXEC", executor.path)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        ),
    };
    let start = std::time::Instant::now();
    while !workspace.join("ready").exists() {
        assert!(held.child.as_mut().unwrap().try_wait().unwrap().is_none());
        assert!(start.elapsed().as_secs() < 20, "held proof did not start");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    for _ in 0..8 {
        let out = omgs(&home, &["prove", "--cmd", "echo concurrent-proof"]);
        assert!(out.status.success(), "{}", text(&out));
        let record = record_from(&text(&out));
        assert_eq!(record["survivors"], serde_json::json!([]));
        assert!(held.child.as_mut().unwrap().try_wait().unwrap().is_none());
    }
    std::fs::write(&held.release, b"release").unwrap();
    let out = held.child.take().unwrap().wait_with_output().unwrap();
    assert!(out.status.success(), "{}", text(&out));
    let record = omgs::proof::load(&run, "proofs/1.json").unwrap();
    assert!(record.clean() && record.survivors.is_empty(), "{record:?}");
    std::fs::remove_dir_all(d).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn narrowed_homebrew_roots_support_python_node_and_cargo() {
    if !mxc_ready() {
        return;
    }
    let d = scratch("build-tools");
    let target = d.join("target");
    std::fs::create_dir_all(target.join("src")).unwrap();
    std::fs::write(
        target.join("Cargo.toml"),
        "[package]\nname='sandbox-probe'\nversion='0.1.0'\nedition='2021'\n",
    )
    .unwrap();
    std::fs::write(
        target.join("src/main.rs"),
        "fn main() { println!(\"cargo-ok\"); }",
    )
    .unwrap();
    let out = omgs(&d.join("home"), &["prove", "--target", target.to_str().unwrap(), "--cmd", "python3 -I -c 'print(\"python-ok\")' && node -e 'console.log(\"node-ok\")' && cargo run --offline"]);
    assert!(out.status.success(), "{}", text(&out));
    for tool in ["python-ok", "node-ok", "cargo-ok"] {
        assert!(text(&out).contains(tool), "{}", text(&out));
    }
    std::fs::remove_dir_all(d).unwrap();
}

#[cfg(unix)]
#[test]
fn interrupting_prove_cleans_the_executor_group_and_marks_the_record_unclean() {
    if !mxc_ready() {
        return;
    }
    for number in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        let d = scratch(&format!("signal-{number}"));
        let run = d.join("run");
        omgs::platform::private_dir(&run).unwrap();
        write_private_fixture(run.join(omgs::runmeta::FILE), "{}").unwrap();
        // The detached child also exercises the macOS survivor sweep.
        let command = if cfg!(target_os = "macos") {
            "python3 -I -c 'import os,time\npid=os.fork()\nif pid==0:\n os.setsid()\n open(\"ready\",\"w\").write(str(os.getpid()))\n time.sleep(120)\n os._exit(0)\ntime.sleep(120)'"
        } else {
            "sleep 120 & echo $! > ready; wait"
        };
        let executor = omgs::sandbox::locate_executor().unwrap();
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
            .args(["prove", "--run", run.to_str().unwrap(), "--cmd", command])
            .env("OMGS_HOME", d.join("home"))
            .env("OMGS_MXC_EXEC", executor.path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let ready = run.join("proofs/1/workspace/ready");
        let start = std::time::Instant::now();
        let pid = loop {
            if let Ok(text) = std::fs::read_to_string(&ready) {
                if let Ok(pid) = text.trim().parse::<i32>() {
                    break pid;
                }
            }
            if start.elapsed().as_secs() >= 20 || child.try_wait().unwrap().is_some() {
                let _ = child.kill();
                let out = child.wait_with_output().unwrap();
                panic!("proof never became ready: {}", text(&out));
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        assert_eq!(unsafe { libc::kill(child.id() as i32, number) }, 0);
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(1), "{}", text(&out));
        let record = omgs::proof::load(&run, "proofs/1.json").unwrap();
        assert!(
            record.interrupted && record.killed && !record.clean(),
            "{record:?}"
        );
        assert!(!record.timed_out && !record.executor_error, "{record:?}");
        assert!(record.cleanup_complete, "{record:?}");
        assert!(text(&out).contains(", killed"), "{}", text(&out));
        assert!(!text(&out).contains(", timed out"), "{}", text(&out));
        if cfg!(target_os = "macos") {
            assert!(record.survivors.iter().any(|s| s.pid == pid), "{record:?}");
        }
        #[cfg(target_os = "macos")]
        {
            let gone = std::time::Instant::now();
            while unsafe { libc::kill(pid, 0) } == 0 && gone.elapsed().as_secs() < 3 {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            assert_ne!(unsafe { libc::kill(pid, 0) }, 0, "pid {pid} survived");
        }
        // On Linux pid belongs to MXC's namespace, not the host. The separate
        // new-session tests check host-visible command markers after teardown.
        std::fs::remove_dir_all(d).unwrap();
    }
}

#[test]
fn unreachable_tests_never_run_the_command() {
    use omgs::sandbox::{prove, ProveOutcome, ProveRequest, Tier};
    if !mxc_ready() {
        return;
    }
    let d = scratch("unreachable-test");
    let target = d.join("target");
    std::fs::create_dir_all(target.join("directory")).unwrap();
    for (n, test) in ["missing test's file", "directory"].iter().enumerate() {
        let request = ProveRequest {
            expect_marker: None,
            command: "echo UNREACHABLE_COMMAND_RAN".into(),
            test: Some((*test).into()),
            target: Some(target.clone()),
            run_dir: d.join(n.to_string()),
            timeout_ms: 10000,
            tier: Tier::Test,
            stage: None,
            expected_tree_sha256: None,
        };
        let ProveOutcome::Ran(result) = prove(&request) else {
            panic!("the wrapper must run with the real executor");
        };
        assert_eq!(result.run.test_reachable, Some(false), "{:?}", result.run);
        assert_eq!(result.run.exit_code, Some(126), "{:?}", result.run);
        assert!(result.run.command_started && result.run.command_finished);
        assert!(!result.run.success);
        assert!(!result.run.output.contains("UNREACHABLE_COMMAND_RAN"));
    }
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn a_test_readable_only_on_the_host_is_not_a_clean_record() {
    if !mxc_ready() {
        return;
    }
    let d = scratch("host-only-test");
    let target = d.join("target");
    let outside = d.join("outside");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("proof.txt"), "host-only-test").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, target.join("tests")).unwrap();
    #[cfg(windows)]
    {
        let link = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(target.join("tests"))
            .arg(&outside)
            .output()
            .unwrap();
        assert!(link.status.success(), "{}", text(&link));
    }
    // The command would pass without the wrapper's in-sandbox check.
    let out = omgs(
        &d.join("home"),
        &[
            "prove",
            "--target",
            target.to_str().unwrap(),
            "--test",
            "tests/proof.txt",
            "--cmd",
            "echo tests/proof.txt COMMAND_SHOULD_NOT_RUN",
        ],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let record = record_from(&text(&out));
    assert_eq!(record["test_reachable"], false, "{record}");
    assert_eq!(record["exit_code"], 126, "{record}");
    let record: omgs::proof::ProofRecord = serde_json::from_value(record).unwrap();
    assert!(!record.clean());
    assert!(!record.output.contains("COMMAND_SHOULD_NOT_RUN"));
    let _ = std::fs::remove_dir_all(d);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_new_session_descendants_die_with_the_pid_namespace() {
    if !mxc_ready() {
        return;
    }
    let py = omgs::platform::which("python3").expect("Linux escape probes need python3");
    for method in ["setsid", "spawn"] {
        let d = scratch(&format!("linux-escape-{method}"));
        let run = d.join("run");
        omgs::platform::private_dir(&run).unwrap();
        write_private_fixture(run.join(omgs::runmeta::FILE), "{}").unwrap();
        let marker = format!("omgs-r4-{method}-{}", std::process::id());
        let args = format!(
            "[\"{}\",\"-I\",\"-c\",\"import time; time.sleep(120)\",\"{marker}\"]",
            py.display()
        );
        let launch = if method == "spawn" {
            format!(
                "os.posix_spawn(\"{}\", {args}, {{}}, setsid=True)",
                py.display()
            )
        } else {
            format!("if os.fork()==0:\n os.setsid()\n if os.fork()==0:\n  os.execv(\"{}\", {args})\n os._exit(0)", py.display())
        };
        let command = format!("'{}' -I -c 'import os,time\nopen(\"ready\",\"w\").close()\n{launch}\nwhile not os.path.exists(\"release\"):\n time.sleep(0.01)\nprint(\"escape positive control observed\")'", py.display());
        let executor = omgs::sandbox::locate_executor().unwrap();
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
            .args([
                "prove",
                "--run",
                run.to_str().unwrap(),
                "--cmd",
                &command,
                "--timeout-ms",
                "10000",
            ])
            .env("OMGS_HOME", &d)
            .env("OMGS_MXC_EXEC", executor.path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let visible = || {
            std::fs::read_dir("/proc").unwrap().flatten().any(|entry| {
                entry.file_name().to_string_lossy().parse::<u32>().is_ok()
                    && std::fs::read(entry.path().join("cmdline")).is_ok_and(|bytes| {
                        bytes.split(|b| *b == 0).any(|arg| arg == marker.as_bytes())
                    })
            })
        };
        // Staging and executor startup are separate from observing a launched
        // descendant. Heavy parallelism must not spend the observation budget
        // before Python has even started running the fixture.
        let ready_path = run.join("proofs/1/workspace/ready");
        let readiness_start = std::time::Instant::now();
        while !ready_path.exists()
            && readiness_start.elapsed().as_secs() < 30
            && child.try_wait().unwrap().is_none()
        {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let ready = ready_path.exists();
        let observation_start = std::time::Instant::now();
        while ready
            && !visible()
            && observation_start.elapsed().as_secs() < 8
            && child.try_wait().unwrap().is_none()
        {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let observed = ready && visible();
        if observed {
            std::fs::write(run.join("proofs/1/workspace/release"), b"go").unwrap();
        }
        let out = child.wait_with_output().unwrap();
        assert!(
            ready,
            "readiness phase: Python fixture did not signal startup for {method}: {}",
            text(&out)
        );
        assert!(
            observed,
            "observation phase: host did not see the detached descendant within eight seconds after readiness for {method}: {}",
            text(&out)
        );
        assert!(
            out.status.success(),
            "release phase: proof failed for {method}: {}",
            text(&out)
        );
        assert!(
            !visible(),
            "teardown phase: detached descendant survived namespace teardown for {method}"
        );
        let record = omgs::proof::load(&run, "proofs/1.json").unwrap();
        assert!(record.clean(), "{record:?}");
        assert!(record
            .enforced
            .iter()
            .any(|e| e == "MXC PID namespace teardown kills descendants, including new sessions"));
        std::fs::remove_dir_all(d).unwrap();
    }
}

#[test]
fn doctor_rejects_unknown_arguments_with_usage_hint() {
    let d = scratch("doctor-args");
    for args in [
        vec!["doctor", "--bogus"],
        vec!["doctor", "--bogus", "value"],
        vec!["doctor", "oops"],
        vec!["doctor", "--yes"],
        vec!["doctor", "--bogus", "--help"],
    ] {
        let out = omgs(&d, &args);
        assert_eq!(out.status.code(), Some(2), "{}", text(&out));
        assert!(
            text(&out).contains("run omgs --help for usage"),
            "{}",
            text(&out)
        );
    }
    std::fs::remove_dir_all(d).unwrap();
}

#[cfg(unix)]
#[test]
fn executable_drafts_keep_their_mode_and_commands_are_redacted() {
    use std::os::unix::fs::PermissionsExt;
    if !mxc_ready() {
        return;
    }
    let d = scratch("exec-draft");
    let target = d.join("target");
    let run = d.join("run");
    std::fs::create_dir_all(&target).unwrap();
    omgs::platform::private_dir(&run).unwrap();
    write_private_fixture(
        run.join(omgs::runmeta::FILE),
        serde_json::json!({"target": target}).to_string(),
    )
    .unwrap();
    let draft = d.join("draft.sh");
    std::fs::write(&draft, "#!/bin/sh\necho executable-draft\n").unwrap();
    std::fs::set_permissions(&draft, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = omgs(
        &d,
        &[
            "prove",
            "--run",
            run.to_str().unwrap(),
            "--target",
            target.to_str().unwrap(),
            "--test",
            "tests/x.sh",
            "--test-from",
            draft.to_str().unwrap(),
            "--cmd",
            "./tests/x.sh --access-token private-value \"--password=public SECRET_SUFFIX\" visible-argument && echo tool --secret-key=inline-private --client_secret following-private",
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
    for value in [
        "private-value",
        "inline-private",
        "following-private",
        "SECRET_SUFFIX",
    ] {
        assert!(!text(&out).contains(value), "{}", text(&out));
    }
    let record = omgs::proof::load(&run, "proofs/1.json").unwrap();
    assert!(record.output.contains("executable-draft"));
    assert!(!record.command.contains("private-value"));
    assert!(!record.command.contains("SECRET_SUFFIX"));
    assert!(record.command.contains("visible-argument"));
    assert!(omgs::proof::runner_evidence(&run, &record).is_empty());
    let replay = omgs(
        &d,
        &["prove", "--run", run.to_str().unwrap(), "--replay", "1"],
    );
    assert!(replay.status.success(), "{}", text(&replay));
    let conflict = omgs(
        &d,
        &[
            "prove",
            "--run",
            run.to_str().unwrap(),
            "--replay",
            "1",
            "--timeout-ms",
            "1",
        ],
    );
    assert_eq!(conflict.status.code(), Some(2));
    assert!(text(&conflict).contains("drop --timeout-ms"));
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn cli_rejects_unknown_and_duplicate_options_before_charging_budget() {
    let d = scratch("cli-options");
    let run = d.join("run");
    omgs::platform::private_dir(&run).unwrap();
    let meta = serde_json::json!({"budget_agent_calls": 1, "proof_runs_used": 0});
    let bytes = serde_json::to_vec(&meta).unwrap();
    write_private_fixture(run.join(omgs::runmeta::FILE), &bytes).unwrap();
    for tail in [
        vec!["--cmd", "exit 0", "--timeot-ms", "1"],
        vec!["--cmd", "exit 0", "--cmd", "exit 1"],
        vec!["--cmd", "exit 0", "--tier", "1", "--tier", "2"],
        vec!["--cmd", "exit 0", "--timeout-ms", "1", "--timeout-ms", "2"],
        vec!["--cmd", "exit 0", "unexpected"],
        vec!["--cmd", "--timeout-ms=5000"],
        vec!["--cmd", "--timeout-ms=5000 trailing text"],
        vec!["--cmd", "--tier"],
        vec!["--cmd", "--run"],
    ] {
        let mut args = vec!["prove", "--run", run.to_str().unwrap()];
        args.extend(tail);
        let out = omgs(&d.join("home"), &args);
        assert_eq!(out.status.code(), Some(2), "{}", text(&out));
        assert!(
            text(&out).contains("run omgs --help for usage"),
            "{}",
            text(&out)
        );
        assert_eq!(std::fs::read(run.join(omgs::runmeta::FILE)).unwrap(), bytes);
        assert!(!run.join("proofs").exists());
    }
    for args in [
        vec!["doctor", "--live", "--live"],
        vec!["setup", "--yes", "--yes"],
        vec!["audit", "init", "--target", "x", "--typo", "y"],
        vec!["validate", "--findings", "x", "--findings", "y"],
        vec!["status", "--run", "x", "--run", "y"],
        vec!["intent", "list", "--stack", "x", "--stack", "y"],
    ] {
        let out = omgs(&d.join("home"), &args);
        assert_eq!(out.status.code(), Some(2), "{}", text(&out));
        assert!(text(&out).contains("run omgs --help for usage"));
    }
    std::fs::remove_dir_all(d).unwrap();
}

#[cfg(unix)]
#[test]
fn symlinked_executor_and_proof_test_run_with_private_artifacts() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    if !mxc_ready() {
        return;
    }
    let d = scratch("content-links");
    let target = d.join("target");
    let run = d.join("run");
    std::fs::create_dir_all(&target).unwrap();
    omgs::platform::private_dir(&run).unwrap();
    std::fs::write(target.join("real.sh"), "exit 1\n").unwrap();
    symlink("real.sh", target.join("proof.sh")).unwrap();
    let executor = d.join("executor-link");
    symlink(omgs::sandbox::locate_executor().unwrap().path, &executor).unwrap();
    write_private_fixture(
        run.join(omgs::runmeta::FILE),
        serde_json::json!({"target": target}).to_string(),
    )
    .unwrap();
    for linked in [true, false] {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"));
        cmd.args([
            "prove",
            "--target",
            target.to_str().unwrap(),
            "--test",
            "proof.sh",
            "--cmd",
            "sh proof.sh; exit 1",
        ])
        .env("OMGS_HOME", d.join("home"))
        .env("OMGS_MXC_EXEC", &executor);
        if linked {
            cmd.args(["--run", run.to_str().unwrap()]);
        }
        let out = cmd.output().unwrap();
        let t = text(&out);
        assert_eq!(out.status.code(), Some(1), "{t}");
        assert!(t.contains("symlink to"), "{t}");
        let record = if linked {
            serde_json::to_value(omgs::proof::load(&run, "proofs/1.json").unwrap()).unwrap()
        } else {
            record_from(&t)
        };
        assert_eq!(record["command_finished"], true, "{record}");
        assert_eq!(record["test_reachable"], true, "{record}");
        let proof_dir = Path::new(record["proof_dir"].as_str().unwrap());
        assert_eq!(
            std::fs::metadata(proof_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for file in ["command.txt", "mxc-config.json"] {
            assert_eq!(
                std::fs::metadata(proof_dir.join(file))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600,
                "{file}"
            );
        }
    }
    std::fs::remove_dir_all(d).unwrap();
}

#[cfg(unix)]
#[test]
fn preparation_signals_release_the_reservation_and_remove_the_workspace() {
    if !mxc_ready() {
        return;
    }
    let executor = omgs::sandbox::locate_executor().unwrap();
    for number in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        let d = scratch(&format!("prepare-signal-{number}"));
        let target = d.join("target");
        let run = d.join("run");
        std::fs::create_dir_all(&target).unwrap();
        omgs::platform::private_dir(&run).unwrap();
        // Copy finishes quickly; hashing leaves a deterministic preparation window.
        std::fs::File::create(target.join("large"))
            .unwrap()
            .set_len(64 << 20)
            .unwrap();
        write_private_fixture(
            run.join(omgs::runmeta::FILE),
            serde_json::json!({"target": target, "proof_runs_used": 0}).to_string(),
        )
        .unwrap();
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
            .args([
                "prove",
                "--run",
                run.to_str().unwrap(),
                "--cmd",
                "echo TARGET_RAN",
            ])
            .env("OMGS_HOME", d.join("home"))
            .env("OMGS_MXC_EXEC", &executor.path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let start = std::time::Instant::now();
        while !run.join("proofs/1/workspace/large").exists() {
            if child.try_wait().unwrap().is_some() || start.elapsed().as_secs() > 20 {
                let _ = child.kill();
                panic!(
                    "preparation never started: {}",
                    text(&child.wait_with_output().unwrap())
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(unsafe { libc::kill(child.id() as i32, number) }, 0);
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(3), "{}", text(&out));
        assert!(text(&out).contains("interrupted"), "{}", text(&out));
        assert!(!text(&out).contains("TARGET_RAN"), "{}", text(&out));
        assert!(!run.join("proofs/1").exists());
        assert!(!run.join("proofs/1.json").exists());
        assert_eq!(omgs::runmeta::read(&run).unwrap()["proof_runs_used"], 0);
        std::fs::remove_dir_all(d).unwrap();
    }
}

#[test]
fn missing_executor_is_explicit_in_live_doctor_and_free_text_prove() {
    let d = scratch("no-executor");
    let run = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
            .args(args)
            .env("OMGS_HOME", &d)
            .env("OMGS_MXC_EXEC", d.join("missing-executor"))
            .output()
            .unwrap()
    };
    let out = run(&["doctor", "--live"]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out));
    assert!(!text(&out).contains("run omgs --help"));
    assert!(text(&out).contains("live check: not run, no verified executor"));
    for args in [
        vec!["prove", "--cmd", "--version"],
        vec!["prove", "--cmd=--version"],
    ] {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(3), "{}", text(&out));
        assert!(text(&out).contains("target code was not executed"));
    }
    std::fs::remove_dir_all(d).unwrap();
}

#[cfg(unix)]
#[test]
fn socket_and_fifo_gaps_survive_validation_and_replay() {
    use std::os::unix::ffi::OsStrExt;
    if !mxc_ready() {
        return;
    }
    let d = PathBuf::from("/tmp").join(format!("omgs-s-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    omgs::platform::create_private_dir(&d).unwrap();
    let target = d.join("t");
    std::fs::create_dir_all(&target).unwrap();
    let socket = std::os::unix::net::UnixListener::bind(target.join("socket")).unwrap();
    let fifo = std::ffi::CString::new(target.join("pipe").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    std::fs::write(
        target.join("proof.sh"),
        "test ! -e socket && test ! -e pipe\n",
    )
    .unwrap();
    let run = d.join("run");
    let home = d.join("home");
    let out = omgs(
        &home,
        &[
            "audit",
            "init",
            "--target",
            target.to_str().unwrap(),
            "--out",
            run.to_str().unwrap(),
            "--no-sensors",
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
    let out = omgs(
        &home,
        &[
            "prove",
            "--run",
            run.to_str().unwrap(),
            "--test",
            "proof.sh",
            "--cmd",
            "sh proof.sh",
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
    for n in [1, 2] {
        if n == 2 {
            let out = omgs(
                &home,
                &["prove", "--run", run.to_str().unwrap(), "--replay", "1"],
            );
            assert!(out.status.success(), "{}", text(&out));
            assert!(text(&out).contains("reproduced"));
        }
        let record = omgs::proof::load(&run, &format!("proofs/{n}.json")).unwrap();
        assert!(omgs::proof::runner_evidence(&run, &record).is_empty());
        assert_eq!(
            record.target_sha256.as_deref(),
            Some(omgs::proof::tree_digest(&target).unwrap().as_str())
        );
        for path in ["socket", "pipe"] {
            assert!(
                record
                    .gaps
                    .iter()
                    .any(|g| g == &format!("skipped target socket or FIFO: {path}")),
                "{:?}",
                record.gaps
            );
        }
    }
    drop(socket);
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn approve_refuses_filesystem_roots_before_prompting() {
    let d = scratch("approve-root");
    let canonical = std::fs::canonicalize(&d).unwrap();
    let root = canonical.ancestors().last().unwrap();
    let home = d.join("home");
    let out = omgs(&home, &["approve", "--target", root.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(text(&out).contains("filesystem roots cannot be approved"));
    assert!(!text(&out).contains("Type the folder name"));
    assert!(!home.exists());
    std::fs::remove_dir_all(d).unwrap();
}

#[cfg(unix)]
#[test]
fn symlink_proofs_replay_when_sockets_appear_or_disappear() {
    use std::os::unix::fs::symlink;
    if !mxc_ready() {
        return;
    }
    let d = PathBuf::from("/tmp").join(format!("omgs-sl-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    omgs::platform::create_private_dir(&d).unwrap();
    let target = d.join("target");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(
        target.join("real.sh"),
        "test -L proof.sh && test ! -e socket\n",
    )
    .unwrap();
    symlink("real.sh", target.join("proof.sh")).unwrap();
    for with_socket in [true, false] {
        let home = d.join(format!("home-{with_socket}"));
        let run = d.join(format!("run-{with_socket}"));
        let mut socket = with_socket
            .then(|| std::os::unix::net::UnixListener::bind(target.join("socket")).unwrap());
        let out = omgs(
            &home,
            &[
                "audit",
                "init",
                "--target",
                target.to_str().unwrap(),
                "--out",
                run.to_str().unwrap(),
                "--no-sensors",
            ],
        );
        assert!(out.status.success(), "{}", text(&out));
        let out = omgs(
            &home,
            &[
                "prove",
                "--run",
                run.to_str().unwrap(),
                "--test",
                "proof.sh",
                "--cmd",
                "sh proof.sh",
            ],
        );
        assert!(out.status.success(), "{}", text(&out));
        if with_socket {
            drop(socket.take());
            std::fs::remove_file(target.join("socket")).unwrap();
        } else {
            socket = Some(std::os::unix::net::UnixListener::bind(target.join("socket")).unwrap());
        }
        let out = omgs(
            &home,
            &["prove", "--run", run.to_str().unwrap(), "--replay", "1"],
        );
        assert!(out.status.success(), "{}", text(&out));
        assert!(text(&out).contains("reproduced"));
        let mut digests = Vec::new();
        for n in [1, 2] {
            let record = omgs::proof::load(&run, &format!("proofs/{n}.json")).unwrap();
            assert!(omgs::proof::runner_evidence(&run, &record).is_empty());
            digests.push(record.target_sha256);
        }
        assert_eq!(digests[0], digests[1]);
        drop(socket);
        if target.join("socket").exists() {
            std::fs::remove_file(target.join("socket")).unwrap();
        }
    }
    std::fs::remove_dir_all(d).unwrap();
}

#[cfg(unix)]
#[test]
fn gap_paths_escape_terminal_controls_but_records_keep_the_path() {
    use std::os::unix::ffi::OsStrExt;
    if !mxc_ready() {
        return;
    }
    let d = scratch("gap-controls");
    let target = d.join("target");
    std::fs::create_dir_all(&target).unwrap();
    let name = "pipe\nforged\r\t\u{1b}[31m";
    let fifo = std::ffi::CString::new(target.join(name).as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let out = omgs(
        &d.join("home"),
        &[
            "prove",
            "--target",
            target.to_str().unwrap(),
            "--cmd",
            "echo ran",
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains(name));
    assert!(
        stderr.contains("pipe\\nforged\\r\\t\\u{1b}[31m"),
        "{stderr}"
    );
    let record = record_from(&text(&out));
    assert!(record["gaps"].as_array().unwrap().iter().any(|g| {
        g.as_str() == Some(format!("skipped target socket or FIFO: {name}").as_str())
    }));
    std::fs::remove_dir_all(d).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_records_bind_probe_selection_to_the_saved_config() {
    if !mxc_ready() {
        return;
    }
    let d = scratch("windows-probe-config");
    let out = omgs(&d.join("home"), &["prove", "--cmd", "echo ran"]);
    assert!(out.status.success(), "{}", text(&out));
    let record = record_from(&text(&out));
    let notes: Vec<_> = record["notes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap())
        .collect();
    let gaps: Vec<_> = record["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap())
        .collect();
    assert!(notes.iter().any(|n| n.starts_with("Windows OS build")));
    assert!(!gaps
        .iter()
        .any(|n| n.starts_with("Windows OS build") || n.starts_with("Windows MXC probe:")));
    let probe =
        omgs::sandbox::windows_probe(&omgs::sandbox::locate_executor().unwrap().path).unwrap();
    assert!(notes
        .iter()
        .any(|n| n.contains("Windows capability selection: probe;")));
    assert!(notes
        .iter()
        .any(|n| n.contains(&format!("tier={}", probe.tier.as_deref().unwrap()))));
    assert_eq!(probe.needs_dacl_augmentation, Some(false));
    let config: serde_json::Value = serde_json::from_slice(
        &std::fs::read(Path::new(record["proof_dir"].as_str().unwrap()).join("mxc-config.json"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        !config["processContainer"]["filesystem"]["enumeratePaths"].is_null(),
        probe.probes.base_container_supports_enumerate_paths
    );
    assert!(record["enforced"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e.as_str().unwrap().contains("--dry-run")));
    std::fs::remove_dir_all(d).unwrap();
}
