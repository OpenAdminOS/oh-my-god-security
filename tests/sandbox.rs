//! End to end proofs through the real MXC executor. Each test that needs MXC
//! skips with a printed reason when no pinned executor is found; CI installs
//! one so they run there.

use std::path::{Path, PathBuf};
use std::process::Output;

fn scratch(name: &str) -> PathBuf {
    let base = std::env::temp_dir()
        .canonicalize()
        .unwrap_or_else(|_| std::env::temp_dir());
    let d = base.join(format!("omgs-sbx-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
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

fn mxc_ready() -> bool {
    match omgs::sandbox::locate_executor() {
        Ok(_) => true,
        Err(e) => {
            eprintln!("skipping: {e}");
            false
        }
    }
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
    assert!(t.contains("pinned digest"), "{t}");
    assert!(t.contains("target code was not executed"), "{t}");
    assert!(!t.contains("ran"), "{t}");
    let _ = std::fs::remove_dir_all(&d);
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
    let cmd = format!(
        "cat '{o}' 2>/dev/null && echo READ_OUTSIDE; \
         [ -n \"$(ls -A '{h}' 2>/dev/null | grep -vx -e .cargo -e .rustup)\" ] && echo LIST_HOME; \
         cat '{h}/.ssh/known_hosts' >/dev/null 2>&1 && echo READ_SSH; \
         touch '{d}/escape' 2>/dev/null; \
         curl -sm3 https://example.com >/dev/null 2>&1 && echo NETWORK; \
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
    for leak in [
        "READ_OUTSIDE",
        "outside-secret-value",
        "LIST_HOME",
        "READ_SSH",
        "NETWORK",
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
    // A proof test that fails on the vulnerable target.
    let failing = if cfg!(windows) {
        "cmd.exe /d /c findstr vulnerable check.txt && exit 1"
    } else {
        "grep -q vulnerable check.txt && exit 1"
    };
    let out = omgs(
        &home,
        &[
            "prove",
            "--run",
            run.to_str().unwrap(),
            "--finding",
            &fp,
            "--test",
            "tests/security/x.test.sh",
            "--cmd",
            failing,
        ],
    );
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("proof_ref proofs/1.json"), "{t}");
    let record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(run.join("proofs/1.json")).unwrap()).unwrap();
    assert_eq!(record["finding"], fp.as_str());
    assert_eq!(record["tier"], "test");
    assert_eq!(record["exit_code"], 1);
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
                "--cmd",
                &format!(
                    "swiftc main.swift {variant}/Verifier.swift -o \"$TMPDIR/probe\" && \"$TMPDIR/probe\""
                ),
            ],
        )
    };
    let vulnerable = run("vulnerable");
    assert_eq!(vulnerable.status.code(), Some(1), "{}", text(&vulnerable));
    assert!(text(&vulnerable).contains("INVARIANTS VIOLATED"));
    let fixed = run("fixed");
    assert!(fixed.status.success(), "{}", text(&fixed));
    assert!(text(&fixed).contains("INVARIANTS HOLD"));
    let _ = std::fs::remove_dir_all(&d);
}
