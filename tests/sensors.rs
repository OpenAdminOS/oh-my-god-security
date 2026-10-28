use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Fixture {
    root: PathBuf,
    bin: PathBuf,
    target: PathBuf,
    db: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "omgs-sensors-{}",
            &omgs::platform::random_nonce().unwrap()[..16]
        ));
        omgs::platform::create_private_tree(&root).unwrap();
        let bin = root.join("bin");
        let target = root.join("target");
        let db = root.join("db");
        omgs::platform::create_private_dir_new(&root.join("temp")).unwrap();
        std::fs::write(root.join("rules.yaml"), "rules: []").unwrap();
        for path in [&bin, &target, &db] {
            std::fs::create_dir(path).unwrap();
        }
        for name in [
            "src/main.rs",
            "tests/example.rs",
            "docs/README.md",
            "vendor/lib.rs",
            "Cargo.lock",
        ] {
            let path = target.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "fixture").unwrap();
        }
        std::fs::write(target.join("large.csv"), vec![b'x'; 1 << 20]).unwrap();
        std::fs::write(root.join("outside"), "external dependency secret").unwrap();
        std::fs::write(target.join("requirements.txt"), "-r ../outside").unwrap();
        std::fs::write(
            target.join("osv-scanner.toml"),
            "[[PackageOverrides]]\nignore = true\n",
        )
        .unwrap();
        std::fs::write(target.join(".gitignore"), "*\n").unwrap();
        std::fs::write(target.join(".semgrepignore"), "*\n").unwrap();
        std::fs::write(target.join("src/.semgrepignore"), "*\n").unwrap();
        std::fs::write(
            target.join("src/main.rs"),
            "secret // trufflehog:ignore // nosemgrep",
        )
        .unwrap();
        Self {
            root,
            bin,
            target,
            db,
        }
    }
    fn database(&self) {
        let dir = self.db.join("osv-scanner/crates.io");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("all.zip"), "fake database for fake scanner").unwrap();
    }
    fn tool(&self, tool: &str, output: &str, exit: i32) {
        static LAUNCHER: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        let launcher = LAUNCHER.get_or_init(|| {
            let dir =
                std::env::temp_dir().join(format!("omgs-sensor-fixture-{}", std::process::id()));
            omgs::platform::create_private_dir(&dir).unwrap();
            let source = dir.join("sensor.rs");
            std::fs::write(&source, include_str!("fixtures/sensor.rs")).unwrap();
            let exe = dir.join(if cfg!(windows) {
                "sensor.exe"
            } else {
                "sensor"
            });
            let status = Command::new(omgs::platform::which("rustc").unwrap())
                .env("RUSTUP_AUTO_INSTALL", "0")
                .arg(&source)
                .arg("-o")
                .arg(&exe)
                .status()
                .unwrap();
            assert!(status.success());
            exe
        });
        std::fs::write(
            self.bin.join(format!("{tool}.outside")),
            self.root.join("outside").to_str().unwrap(),
        )
        .unwrap();
        let path = self.bin.join(if cfg!(windows) {
            format!("{tool}.exe")
        } else {
            tool.into()
        });
        std::fs::copy(launcher, path).unwrap();
        std::fs::write(self.bin.join(format!("{tool}.json")), output).unwrap();
        std::fs::write(self.bin.join(format!("{tool}.mode")), exit.to_string()).unwrap();
    }
    fn cli(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_omgs"))
            .args(args)
            .env(
                "PATH",
                if cfg!(target_os = "linux") {
                    format!("{}:/usr/bin:/bin", self.bin.display())
                } else {
                    self.bin.display().to_string()
                },
            )
            .env("PATHEXT", ".EXE;.COM;.CMD;.BAT")
            .env("OMGS_OSV_DB", &self.db)
            .env("OMGS_SEMGREP_CONFIG", self.root.join("rules.yaml"))
            .env("TMPDIR", self.root.join("temp"))
            .env("TEMP", self.root.join("temp"))
            .env("TMP", self.root.join("temp"))
            .env("OMGS_TEST_SECRET", "must-not-be-inherited")
            .env("OMGS_HOME", self.root.join("home"))
            .env(
                "OMGS_MXC_EXEC",
                omgs::sandbox::locate_executor()
                    .map(|l| l.path)
                    .unwrap_or_else(|_| self.root.join("missing-mxc")),
            )
            .output()
            .unwrap()
    }
    fn init(&self, name: &str) -> PathBuf {
        let run = self.root.join(name);
        let temp = self.root.join("temp");
        omgs::platform::create_private_dir(&temp).unwrap();
        let out = self.cli(&[
            "audit",
            "init",
            "--target",
            self.target.to_str().unwrap(),
            "--out",
            run.to_str().unwrap(),
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            std::fs::read_dir(temp).unwrap().next().is_none(),
            "leftover scanner scratch"
        );
        run
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn read(path: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn truffle(file: &str) -> Value {
    json!({"DetectorName":"FixtureDetector", "Raw":"raw-secret-must-never-be-stored", "RawV2":"raw-v2-distinct-sentinel", "ExtraData":{"secret":"extra-data-distinct-sentinel"}, "Redacted":"raw-secret-must-never-be-stored", "SourceMetadata":{"Data":{"Filesystem":{"file":file,"line":7}}}})
}
fn osv() -> Value {
    json!({"results":[{"source":{"path":"Cargo.lock","type":"lockfile"},"packages":[{"package":{"name":"fixture","version":"1.0","ecosystem":"crates.io"},"vulnerabilities":[{"id":"OSV-fixture","details":"raw-secret-must-never-be-stored"}]}]}]})
}

fn ready() -> bool {
    let Ok(located) = omgs::sandbox::locate_executor() else {
        assert!(
            std::env::var_os("OMGS_REQUIRE_SENSORS").is_none(),
            "required sensor executor missing"
        );
        return false;
    };
    if cfg!(windows) {
        if let Err(reason) =
            omgs::sandbox::windows_policy(omgs::sandbox::windows_probe(&located.path))
        {
            assert!(reason.contains("requires DACL augmentation"), "{reason}");
            let f = Fixture::new();
            f.tool("trufflehog", &truffle("src/main.rs").to_string(), 0);
            let run = f.init("refusal");
            let r = read(&run.join("sensors.json"));
            assert!(r["tools_run"].as_array().unwrap().is_empty());
            assert!(r["gaps"].to_string().contains("requires DACL augmentation"));
            return false;
        }
    }
    true
}

#[test]
fn offline_tools_feed_redacted_artifacts_reports_and_critic() {
    if !ready() {
        return;
    }
    let f = Fixture::new();
    f.database();
    let output = [
        "src/main.rs",
        "tests/example.rs",
        "docs/README.md",
        "vendor/lib.rs",
        "large.csv",
    ]
    .map(|p| truffle(p).to_string())
    .join("\n");
    f.tool("trufflehog", &output, 0);
    f.tool("osv-scanner", &osv().to_string(), 1);
    let run = f.init("run");
    #[cfg(target_os = "linux")]
    if std::env::var_os("OMGS_REQUIRE_SENSORS").is_some() {
        let summary = read(&run.join("sensors.json"));
        assert!(
            !summary["gaps"]
                .to_string()
                .contains("memory and task limits not applied"),
            "{summary}"
        );
    }
    let hits = read(&run.join("sensor-hits.json"));
    assert_eq!(
        hits.as_array().unwrap().len(),
        6,
        "{}",
        read(&run.join("sensors.json"))
    );
    for class in ["code", "test", "docs", "vendored", "data"] {
        assert!(hits.as_array().unwrap().iter().any(|h| h["class"] == class));
    }
    let mut ledger = read(&run.join("coverage-ledger.json"));
    let units = ledger["units"].as_array_mut().unwrap();
    assert_eq!(
        units
            .iter()
            .filter(|u| u["id"].as_str().unwrap().starts_with("sensor:"))
            .count(),
        2
    );
    // Close unrelated inventory units to isolate the sensor requirement.
    for u in units
        .iter_mut()
        .filter(|u| !u["id"].as_str().unwrap().starts_with("sensor:"))
    {
        u["status"] = json!("covered");
        u["evidence"] = json!(["reviewed source"]);
    }
    std::fs::write(run.join("coverage-ledger.json"), ledger.to_string()).unwrap();
    std::fs::write(run.join("candidates-empty.json"), r#"{"candidates":[]}"#).unwrap();
    let critic = omgs::critic::critique_run(&run).unwrap();
    assert!(!critic.passed());
    assert_eq!(critic.gaps.len(), 2, "{:?}", critic.gaps);
    for u in ledger["units"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .filter(|u| u["id"].as_str().unwrap().starts_with("sensor:"))
    {
        u["status"] = json!("out_of_scope");
        u["note"] = json!("Reviewed fixture, no reachable production effect");
    }
    std::fs::write(run.join("coverage-ledger.json"), ledger.to_string()).unwrap();
    assert!(omgs::critic::critique_run(&run).unwrap().passed());
    // Removing a hit's unit cannot bypass reconciliation.
    let mut removed = ledger.clone();
    removed["units"]
        .as_array_mut()
        .unwrap()
        .retain(|u| !u["id"].as_str().unwrap().starts_with("sensor:trufflehog:"));
    std::fs::write(run.join("coverage-ledger.json"), removed.to_string()).unwrap();
    assert!(!omgs::critic::critique_run(&run).unwrap().passed());
    std::fs::write(run.join("coverage-ledger.json"), ledger.to_string()).unwrap();
    let out = f.cli(&[
        "report",
        "--findings",
        run.join("findings.json").to_str().unwrap(),
        "--out",
        run.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for name in ["REPORT.md", "REPORT.html"] {
        let content = std::fs::read_to_string(run.join(name)).unwrap();
        assert!(content.contains("FixtureDetector"));
        assert!(content.contains("OSV-fixture"));
        assert!(content.contains("docs/README.md"));
    }
    fn check_no_secret(path: &Path) {
        for e in std::fs::read_dir(path).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                check_no_secret(&p);
            } else {
                let bytes = std::fs::read(&p).unwrap();
                let content = String::from_utf8_lossy(&bytes);
                for sentinel in [
                    "raw-secret-must-never-be-stored",
                    "raw-v2-distinct-sentinel",
                    "extra-data-distinct-sentinel",
                ] {
                    assert!(
                        !content.contains(sentinel),
                        "{} leaked {sentinel}",
                        p.display()
                    );
                }
            }
        }
    }
    check_no_secret(&run);
}

#[test]
fn absent_database_skips_osv_and_missing_tools_are_explicit() {
    let f = Fixture::new();
    f.tool("osv-scanner", &osv().to_string(), 0);
    let run = f.init("run");
    let report = read(&run.join("sensors.json"));
    assert!(report["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g.as_str().unwrap().contains("osv database not present")));
    assert!(
        !f.root.join("osv-scanner.args").exists(),
        "scanner must not run without a database"
    );
    assert!(report["tools_unavailable"]
        .as_array()
        .unwrap()
        .contains(&json!("trufflehog")));
    assert!(report["tools_run"].as_array().unwrap().is_empty());
}

#[test]
fn malformed_output_is_a_gap_without_persisting_partial_hits_or_secrets() {
    if !ready() {
        return;
    }
    let f = Fixture::new();
    f.database();
    f.tool(
        "trufflehog",
        &format!(
            "{}\n{{\"Raw\":\"raw-secret-must-never-be-stored\"}}",
            truffle("src/main.rs")
        ),
        0,
    );
    f.tool(
        "osv-scanner",
        r#"{"results":[{"source":{"path":"Cargo.lock"}}]}"#,
        0,
    );
    let run = f.init("run");
    let report = read(&run.join("sensors.json"));
    assert!(report["hits"].as_array().unwrap().is_empty());
    assert!(report["tools_run"].as_array().unwrap().is_empty());
    for tool in ["trufflehog", "osv-scanner"] {
        assert!(report["gaps"].as_array().unwrap().iter().any(|g| g
            .as_str()
            .unwrap()
            .starts_with(&format!("{tool}: malformed"))));
    }
    assert!(!report
        .to_string()
        .contains("raw-secret-must-never-be-stored"));
}

#[test]
fn capped_and_failed_scans_are_gaps_not_zero_hit_successes() {
    if !ready() {
        return;
    }
    let f = Fixture::new();
    f.database();
    f.tool("trufflehog", &"x".repeat(4 * 1024 * 1024 + 1), 0);
    f.tool("osv-scanner", &osv().to_string(), 2);
    let run = f.init("run");
    let report = read(&run.join("sensors.json"));
    assert!(report["hits"].as_array().unwrap().is_empty());
    assert!(report["tools_run"].as_array().unwrap().is_empty());
    for tool in ["trufflehog", "osv-scanner"] {
        assert!(report["gaps"].as_array().unwrap().iter().any(|g| g
            .as_str()
            .unwrap()
            .starts_with(&format!("{tool}: scan failed"))));
    }
}

#[test]
fn semgrep_suppressions_are_disabled_and_skips_are_accountable() {
    if !ready() {
        return;
    }
    let f = Fixture::new();
    f.tool("semgrep", r#"{"results":[{"check_id":"fixture-rule","path":"src/main.rs","start":{"line":1},"extra":{"lines":"raw-secret-must-never-be-stored"}}],"errors":[],"paths":{"skipped":[{"path":"large.csv","reason":"size limit"}]}}"#, 0);
    let run = f.init("semgrep-run");
    let report = read(&run.join("sensors.json"));
    assert_eq!(report["hits"].as_array().unwrap().len(), 1, "{report}");
    assert!(report["gaps"].to_string().contains("paths.skipped"));
    assert!(f.target.join(".semgrepignore").exists());
    assert!(f.target.join("src/.semgrepignore").exists());
}

#[test]
fn osv_versions_are_distinct_accountable_units() {
    if !ready() {
        return;
    }
    let f = Fixture::new();
    f.database();
    let mut output = osv();
    let mut second = output["results"][0]["packages"][0].clone();
    second["package"]["version"] = json!("2.0");
    output["results"][0]["packages"]
        .as_array_mut()
        .unwrap()
        .push(second);
    f.tool("osv-scanner", &output.to_string(), 1);
    let run = f.init("versions");
    let report = omgs::sensors::read_report(&run).unwrap().unwrap();
    assert_eq!(report.hits.len(), 2);
    assert_ne!(report.hits[0].fingerprint, report.hits[1].fingerprint);
    let mut ledger = omgs::ledger::Ledger::default();
    omgs::sensors::seed_units(&report, &mut ledger);
    assert_eq!(ledger.units.len(), 2);
    ledger.units[0].status = "out_of_scope".into();
    assert_eq!(ledger.units[1].status, "candidate");
    ledger.units.pop();
    assert_eq!(omgs::sensors::reconcile(&report, &ledger).len(), 1);
    for html in [false, true] {
        let section = omgs::report::sensor_section(Some(&report), html);
        for text in ["fixture", "1.0", "2.0", "crates.io"] {
            assert!(section.contains(text));
        }
    }
}

// Run the helper in a child process so its private OS temp directory can be
// selected without racing the environment of other tests.
#[test]
fn forced_timeout_removes_scratch() {
    if !ready() {
        return;
    }
    let f = Fixture::new();
    f.tool("trufflehog", "", 0);
    std::fs::write(f.bin.join("trufflehog.mode"), "timeout").unwrap();
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "sensor_timeout_child", "--nocapture"])
        .env("OMGS_TIMEOUT_FIXTURE", &f.root)
        .env("TMPDIR", f.root.join("temp"))
        .env("TEMP", f.root.join("temp"))
        .env("TMP", f.root.join("temp"))
        .env(
            "OMGS_MXC_EXEC",
            omgs::sandbox::locate_executor().unwrap().path,
        )
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(std::fs::read_dir(f.root.join("temp"))
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn sensor_timeout_child() {
    let Some(root) = std::env::var_os("OMGS_TIMEOUT_FIXTURE") else {
        return;
    };
    let root = PathBuf::from(root);
    let executable = root.join(if cfg!(windows) {
        "bin/trufflehog.exe"
    } else {
        "bin/trufflehog"
    });
    let start = std::time::Instant::now();
    let result = omgs::sandbox::run_sensor(omgs::sandbox::SensorRequest {
        executable: &executable,
        args: [
            "filesystem",
            "--no-verification",
            "--no-update",
            "--json",
            "--no-ignore-tag",
            "{target}",
        ]
        .map(str::to_string)
        .to_vec(),
        target: &root.join("target"),
        readonly: vec![],
        env: vec![],
        semgrep: false,
        config: "",
        limits: omgs::supervise::Limits {
            wall_ms: 500,
            cpu_secs: Some(5),
            file_size_bytes: Some(1 << 20),
            open_files: Some(256),
            memory_bytes: Some(2 << 30),
            tasks: Some(128),
            output_cap_bytes: 4 << 20,
        },
    });
    let error = result.unwrap_err();
    assert!(error.contains("timeout=true, started=true"), "{error}");
    assert!(start.elapsed().as_secs() < 25);
}

#[test]
fn unavailable_mxc_never_runs_a_sensor() {
    let f = Fixture::new();
    f.tool("trufflehog", &truffle("src/main.rs").to_string(), 0);
    let out = Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args([
            "audit",
            "init",
            "--target",
            f.target.to_str().unwrap(),
            "--out",
            f.root.join("no-mxc").to_str().unwrap(),
        ])
        .env("PATH", &f.bin)
        .env("OMGS_MXC_EXEC", f.root.join("missing-mxc"))
        .output()
        .unwrap();
    assert!(out.status.success());
    let r = read(&f.root.join("no-mxc/sensors.json"));
    assert!(r["tools_run"].as_array().unwrap().is_empty());
    assert!(r["gaps"]
        .to_string()
        .contains("pinned MXC unavailable; sensor not run"));
}

#[test]
fn oversized_and_linked_inputs_remain_explicit_gaps() {
    if !ready() {
        return;
    }
    let f = Fixture::new();
    let file = std::fs::File::create(f.target.join("oversized.bin")).unwrap();
    file.set_len((16 << 20) + 1).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(f.root.join("outside"), f.target.join("outside-link")).unwrap();
    f.tool("trufflehog", &truffle("src/main.rs").to_string(), 0);
    let run = f.init("bounded-input");
    let r = read(&run.join("sensors.json"));
    assert!(
        r["gaps"].to_string().contains("input entries skipped"),
        "{r}"
    );
    assert_eq!(r["hits"].as_array().unwrap().len(), 1, "{r}");
}
