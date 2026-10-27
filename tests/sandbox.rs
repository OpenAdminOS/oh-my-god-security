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
    assert!(t.contains("refusing to run"), "{t}");
    assert!(t.contains("target code was not executed"), "{t}");
    assert!(!t.lines().any(|l| l.trim() == "ran"), "{t}");
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
    // A real file in the real home, so a denied read is not just a missing file.
    let home_probe = real_home.join(format!(".omgs-sbx-probe-{}", std::process::id()));
    std::fs::write(&home_probe, b"home-secret-value").unwrap();
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
    let cmd = format!(
        "cat '{o}' 2>/dev/null && echo READ_OUTSIDE; \
         [ -n \"$(ls -A '{h}' 2>/dev/null | grep -vx -e .cargo -e .rustup)\" ] && echo LIST_HOME; \
         cat '{hp}' 2>/dev/null; \
         cat '{h}/.ssh/known_hosts' >/dev/null 2>&1 && echo READ_SSH; \
         touch '{d}/escape' 2>/dev/null; \
         curl -sm3 https://example.com >/dev/null 2>&1 && echo NETWORK; \
         curl -sm3 http://127.0.0.1:{port}/ 2>/dev/null; \
         echo changed > app.txt && cat app.txt",
        o = outside.display(),
        h = real_home.display(),
        hp = home_probe.display(),
        d = d.display()
    );
    let out = omgs(
        &home,
        &["prove", "--target", target.to_str().unwrap(), "--cmd", &cmd],
    );
    let t = text(&out);
    let _ = std::fs::remove_file(&home_probe);
    if !curl_works {
        eprintln!("note: curl unavailable on the host, loopback denial not checked");
    }
    for leak in [
        "READ_OUTSIDE",
        "outside-secret-value",
        "home-secret-value",
        "LIST_HOME",
        "READ_SSH",
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
#[cfg(target_os = "macos")]
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
            b"@findstr /m vulnerable check.txt >nul && exit /b 1\r\n@exit /b 0\r\n",
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

    // A draft kept outside the target is staged into the workspace copy only.
    let (draft_name, staged_rel, staged_cmd, body): (&str, &str, &str, &[u8]) = if cfg!(windows) {
        (
            "draft.test.cmd",
            "tests/security/new.test.cmd",
            "cmd.exe /d /c tests\\security\\new.test.cmd",
            b"@findstr /m vulnerable check.txt >nul && exit /b 1\r\n@exit /b 0\r\n",
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
        text(&never_ran).contains("never ran"),
        "{}",
        text(&never_ran)
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
    // The charge lands before anything runs: the first proof spends the
    // budget, the second is refused with exit 3 because nothing ran.
    let prove = || {
        omgs(
            &home,
            &["prove", "--run", run.to_str().unwrap(), "--cmd", "true"],
        )
    };
    let first = prove();
    assert_ne!(first.status.code(), Some(2), "{}", text(&first));
    let second = prove();
    assert_eq!(second.status.code(), Some(3), "{}", text(&second));
    assert!(text(&second).contains("budget exhausted"));
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
