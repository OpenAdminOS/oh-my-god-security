// Valid run evidence uses the same ownership and ACL as runtime writers.
fn write_private_fixture(
    path: impl AsRef<std::path::Path>,
    bytes: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    omgs::runmeta::write_atomic_bytes(path.as_ref(), bytes.as_ref())
}

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixture_parent() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(std::env::var_os("USERPROFILE").unwrap())
    } else {
        omgs::platform::temp_root().unwrap()
    }
}
fn assert_no_scratch(data: &Path) {
    if data.exists() {
        assert!(!std::fs::read_dir(data).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("omgs-sensor-")));
    }
}

struct Fixture {
    root: PathBuf,
    bin: PathBuf,
    target: PathBuf,
    db: PathBuf,
    listener: std::net::TcpListener,
}
impl Fixture {
    fn new() -> Self {
        let root = fixture_parent().join(format!(
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
            omgs::platform::create_private_dir_new(path).unwrap();
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
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        Self {
            listener,
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
            let dir = fixture_parent().join(format!("omgs-sensor-fixture-{}", std::process::id()));
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
        let data = self.target.join(".sensor-fixture");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(
            data.join(format!("{tool}.outside")),
            self.root.join("outside").to_str().unwrap(),
        )
        .unwrap();
        std::fs::write(
            data.join(format!("{tool}.port")),
            self.listener.local_addr().unwrap().to_string(),
        )
        .unwrap();
        let path = self.bin.join(if cfg!(windows) {
            format!("{tool}.exe")
        } else {
            tool.into()
        });
        std::fs::copy(launcher, path).unwrap();
        std::fs::write(data.join(format!("{tool}.json")), output).unwrap();
        std::fs::write(data.join(format!("{tool}.mode")), exit.to_string()).unwrap();
    }
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_omgs"));
        command
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
            );
        command
    }
    fn cli(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
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
        assert_no_scratch(&self.root.join("home"));
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
    #[cfg(not(target_os = "linux"))]
    assert!(!read(&run.join("sensors.json"))["gaps"]
        .to_string()
        .contains("Linux cgroup"));
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
    // Preserve all broad parent classes when closing the inventory fixture.
    let mapped_classes: std::collections::BTreeSet<_> = units
        .iter()
        .filter(|u| {
            u["id"].as_str().unwrap().starts_with("stack:")
                || u["id"].as_str().unwrap().starts_with("project:")
        })
        .flat_map(|u| u["attack_classes"].as_array().unwrap().iter())
        .map(|class| class.as_str().unwrap().to_string())
        .collect();
    // Close unrelated inventory units to isolate the sensor requirement.
    for u in units
        .iter_mut()
        .filter(|u| !u["id"].as_str().unwrap().starts_with("sensor:"))
    {
        u["status"] = json!("covered");
        u["evidence"] = json!(["reviewed source"]);
        if u["id"].as_str().unwrap().starts_with("stack:")
            || u["id"].as_str().unwrap().starts_with("project:")
        {
            u["child_units"] = json!(["mapped:source"]);
        }
    }
    units.push(json!({"id":"mapped:source","surface":"src/main.rs","attack_classes":mapped_classes,"status":"covered","evidence":["src/main.rs"],"scope_paths":["src/main.rs"]}));
    write_private_fixture(run.join("coverage-ledger.json"), ledger.to_string()).unwrap();
    write_private_fixture(run.join("candidates-empty.json"), r#"{"candidates":[]}"#).unwrap();
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
    write_private_fixture(run.join("coverage-ledger.json"), ledger.to_string()).unwrap();
    assert!(omgs::critic::critique_run(&run).unwrap().passed());
    // Removing a hit's unit cannot bypass reconciliation.
    let mut removed = ledger.clone();
    removed["units"]
        .as_array_mut()
        .unwrap()
        .retain(|u| !u["id"].as_str().unwrap().starts_with("sensor:trufflehog:"));
    write_private_fixture(run.join("coverage-ledger.json"), removed.to_string()).unwrap();
    assert!(!omgs::critic::critique_run(&run).unwrap().passed());
    write_private_fixture(run.join("coverage-ledger.json"), ledger.to_string()).unwrap();
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

// Run the helper in a child process so its private data directory can be
// selected without racing the environment of other tests.
#[test]
fn forced_timeout_removes_scratch() {
    if !ready() {
        return;
    }
    let f = Fixture::new();
    f.tool("trufflehog", "", 0);
    std::fs::write(f.target.join(".sensor-fixture/trufflehog.mode"), "timeout").unwrap();
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "sensor_timeout_child", "--nocapture"])
        .env("OMGS_TIMEOUT_FIXTURE", &f.root)
        .env("OMGS_HOME", f.root.join("home"))
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
    assert_no_scratch(&f.root.join("home"));
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
        artifacts: &root.join("artifacts"),
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
        .env("OMGS_HOME", f.root.join("home"))
        .env("OMGS_MXC_EXEC", f.root.join("missing-mxc"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
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
        r["gaps"]
            .to_string()
            .contains("input entries/subtrees skipped"),
        "{r}"
    );
    assert!(r["gaps"].to_string().contains("oversized.bin"));
    assert!(r["gaps"].to_string().contains("file byte limit"));
    let ledger = read(&run.join("coverage-ledger.json"));
    assert!(ledger["units"].as_array().unwrap().iter().any(|u| u["id"]
        .as_str()
        .unwrap()
        .starts_with("inventory:sensor-input:")
        && u["status"] == "blocked"));
    assert_eq!(r["hits"].as_array().unwrap().len(), 1, "{r}");
}

#[test]
fn scratch_inside_target_is_refused_before_creation() {
    if !ready() {
        return;
    }
    let f = Fixture::new();
    f.tool("trufflehog", &truffle("src/main.rs").to_string(), 0);
    let out = Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args([
            "check",
            "--target",
            f.target.to_str().unwrap(),
            "--out",
            f.root.join("overlap").to_str().unwrap(),
        ])
        .env("PATH", &f.bin)
        .env(
            "OMGS_MXC_EXEC",
            omgs::sandbox::locate_executor().unwrap().path,
        )
        .env("OMGS_HOME", &f.target)
        .env("TMPDIR", &f.target)
        .env("TEMP", &f.target)
        .env("TMP", &f.target)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = read(&f.root.join("overlap/sensors.json"));
    assert!(
        report["gaps"]
            .to_string()
            .contains("scratch overlaps target"),
        "{report}"
    );
    assert!(report["tools_run"].as_array().unwrap().is_empty());
    assert!(!std::fs::read_dir(&f.target).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("omgs-sensor-")));
}

#[test]
fn scanner_directly_in_home_cannot_read_private_sibling() {
    if !ready() {
        return;
    }
    let f = Fixture::new();
    let private = f.bin.join("private-key");
    std::fs::write(&private, "synthetic private key").unwrap();
    f.tool("trufflehog", &truffle("src/main.rs").to_string(), 0);
    // The native fixture attempts this read and exits 38 if it succeeds.
    std::fs::write(
        f.target.join(".sensor-fixture/trufflehog.outside"),
        private.to_string_lossy().as_bytes(),
    )
    .unwrap();
    let run = f.root.join("home-boundary");
    let out = f
        .command(&[
            "audit",
            "init",
            "--target",
            f.target.to_str().unwrap(),
            "--out",
            run.to_str().unwrap(),
        ])
        .env("HOME", &f.bin)
        .env("USERPROFILE", &f.bin)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = read(&run.join("sensors.json"));
    assert_eq!(report["hits"].as_array().unwrap().len(), 1, "{report}");
    assert!(
        report["tools_run"]
            .as_array()
            .unwrap()
            .contains(&json!("trufflehog")),
        "{report}"
    );
}

#[test]
fn scratch_inside_artifacts_is_refused_before_creation() {
    if !ready() {
        return;
    }
    for command in [vec!["audit", "init"], vec!["check"]] {
        let f = Fixture::new();
        f.tool("trufflehog", &truffle("src/main.rs").to_string(), 0);
        let run = f.root.join("artifact-overlap");
        omgs::platform::create_private_dir_new(&run).unwrap();
        let audit = command[0] == "audit";
        let mut args = command;
        args.extend([
            "--target",
            f.target.to_str().unwrap(),
            "--out",
            run.to_str().unwrap(),
        ]);
        let out = f
            .command(&args)
            .env("OMGS_HOME", &run)
            .env("TMPDIR", &run)
            .env("TEMP", &run)
            .env("TMP", &run)
            .output()
            .unwrap();
        if audit {
            // Policy provenance must reject this data/run overlap even before sensors.
            assert!(!out.status.success());
            assert!(String::from_utf8_lossy(&out.stderr)
                .contains("trusted policy store must live outside the run directory"));
            assert_no_scratch(&run);
            continue;
        }
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let report = read(&run.join("sensors.json"));
        assert!(
            report["gaps"]
                .to_string()
                .contains("scratch overlaps artifacts"),
            "{report}"
        );
        assert!(report["tools_run"].as_array().unwrap().is_empty());
        for e in std::fs::read_dir(&run).unwrap() {
            let p = e.unwrap().path();
            assert!(!p.is_dir(), "scratch created in artifacts: {}", p.display());
            assert!(!std::fs::read_to_string(&p)
                .unwrap()
                .contains("raw-secret-must-never-be-stored"));
        }
    }
}

#[test]
fn semgrep_size_omissions_are_gaps_even_without_reported_skips() {
    if !ready() {
        return;
    }
    let f = Fixture::new();
    std::fs::File::create(f.target.join("two-mib.rs"))
        .unwrap()
        .set_len(2 << 20)
        .unwrap();
    f.tool(
        "semgrep",
        r#"{"results":[],"errors":[],"paths":{"scanned":[],"skipped":[]}}"#,
        0,
    );
    let run = f.init("semgrep-size");
    let report = read(&run.join("sensors.json"));
    assert!(
        report["tools_run"]
            .as_array()
            .unwrap()
            .contains(&json!("semgrep")),
        "{report}"
    );
    assert!(
        report["gaps"]
            .to_string()
            .contains("2 input files exceed Semgrep's 1000000 byte target limit"),
        "{report}"
    );
}

#[cfg(unix)]
#[test]
fn hostile_filenames_are_escaped_in_artifacts_ledger_cli_and_reports() {
    if !ready() {
        return;
    }
    let f = Fixture::new();
    let name = "src/new\nline\r\x1b[31m`<img src=x onerror=alert(1)>.rs";
    std::fs::write(f.target.join(name), "fixture").unwrap();
    f.tool("trufflehog", &truffle(name).to_string(), 0);
    let run = f.init("hostile-path");
    let expected = omgs::platform::escape_controls(&omgs::paths::display(Path::new(name)));
    let report = read(&run.join("sensors.json"));
    assert_eq!(report["hits"][0]["file"], expected, "{report}");
    let hits = read(&run.join("sensor-hits.json"));
    assert_eq!(hits[0]["file"], expected);
    let ledger = read(&run.join("coverage-ledger.json"));
    assert!(ledger["units"]
        .as_array()
        .unwrap()
        .iter()
        .any(|u| u["surface"] == expected));
    let cli = f.cli(&[
        "check",
        "--target",
        f.target.to_str().unwrap(),
        "--out",
        f.root.join("check-path").to_str().unwrap(),
    ]);
    assert!(cli.status.success());
    let stdout = String::from_utf8(cli.stdout).unwrap();
    assert!(stdout.contains(&expected), "{stdout}");
    assert!(!stdout.contains(['\r', '\x1b']));
    assert!(!stdout.contains(name));
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
    let markdown = std::fs::read_to_string(run.join("REPORT.md")).unwrap();
    let section = markdown.split("## Sensor hits and gaps").nth(1).unwrap();
    assert!(!section.contains(['\r', '\x1b']));
    assert!(section
        .lines()
        .any(|line| line.starts_with("- `` trufflehog:")
            && line.ends_with(" ``")
            && line.contains("new\\nline\\r\\u{1b}[31m")
            && line.contains("<img")));
    let html = std::fs::read_to_string(run.join("REPORT.html")).unwrap();
    assert!(!html.contains("<img src=x"));
}

#[test]
fn scratch_inside_readable_rules_is_refused_before_creation() {
    if !ready() {
        return;
    }
    let f = Fixture::new();
    f.tool("semgrep", r#"{"results":[]}"#, 0);
    let run = f.root.join("grant-overlap");
    let temp = f.root.join("temp");
    let out = f
        .command(&[
            "audit",
            "init",
            "--target",
            f.target.to_str().unwrap(),
            "--out",
            run.to_str().unwrap(),
        ])
        .env("OMGS_HOME", &temp)
        .env("OMGS_SEMGREP_CONFIG", &temp)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = read(&run.join("sensors.json"));
    assert!(
        report["gaps"]
            .to_string()
            .contains("scratch overlaps a readable grant"),
        "{report}"
    );
    assert!(report["tools_run"].as_array().unwrap().is_empty());
    assert_no_scratch(&temp);
}

#[cfg(target_os = "linux")]
#[test]
fn missing_linux_cgroup_scope_records_prove_gap() {
    if !ready() {
        return;
    }
    let f = Fixture::new();
    f.tool("trufflehog", &truffle("src/main.rs").to_string(), 0);
    let run = f.root.join("no-cgroup");
    // Keep systemd-run off PATH without changing executor discovery.
    let out = f
        .command(&[
            "check",
            "--target",
            f.target.to_str().unwrap(),
            "--out",
            run.to_str().unwrap(),
        ])
        .env("PATH", &f.bin)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = read(&run.join("sensors.json"));
    assert!(
        report["tools_run"]
            .as_array()
            .unwrap()
            .contains(&json!("trufflehog")),
        "{report}"
    );
    assert!(
        report["gaps"].as_array().unwrap().contains(&json!(
            "trufflehog: memory and task limits not applied: Linux cgroups required"
        )),
        "{report}"
    );
}

#[test]
fn native_private_adjacent_library_failure_is_a_gap() {
    if !ready() {
        return;
    }
    let f = Fixture::new();
    f.tool("trufflehog", "", 0);
    std::fs::write(
        f.bin.join(if cfg!(windows) {
            "private.dll"
        } else if cfg!(target_os = "macos") {
            "libprivate.dylib"
        } else {
            "libprivate.so"
        }),
        "fake private library",
    )
    .unwrap();
    std::fs::write(
        f.target.join(".sensor-fixture/trufflehog.mode"),
        "private-library",
    )
    .unwrap();
    let run = f.init("native-library");
    let report = read(&run.join("sensors.json"));
    assert!(
        report["tools_run"].as_array().unwrap().is_empty(),
        "{report}"
    );
    assert!(report["hits"].as_array().unwrap().is_empty(), "{report}");
    assert!(
        report["gaps"]
            .to_string()
            .contains("trufflehog: scan failed, timed out, or output incomplete (exit=42)"),
        "{report}"
    );
}

#[cfg(unix)]
#[test]
fn python_user_install_cannot_expose_shared_private_data() {
    use std::os::unix::fs::PermissionsExt;
    if !ready() {
        return;
    }
    let f = Fixture::new();
    let home = f.root.join("profile");
    let bin = home.join(".local/bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(home.join(".local/lib/python3.13/site-packages/semgrep")).unwrap();
    std::fs::create_dir_all(home.join(".local/share")).unwrap();
    let private = home.join(".local/share/private");
    std::fs::write(&private, "private application data").unwrap();
    // A deliberately unsupported fake Python cannot prove its real prefix.
    // Its bootstrap executes only in MXC and the entry script must be refused.
    let python = bin.join("python3");
    std::fs::write(&python, "#!/bin/sh\nexit 77\n").unwrap();
    std::fs::set_permissions(&python, std::fs::Permissions::from_mode(0o755)).unwrap();
    let scanner = bin.join("semgrep");
    std::fs::write(
        &scanner,
        format!("#!{}\n{}\n", python.display(), private.display()),
    )
    .unwrap();
    std::fs::set_permissions(&scanner, std::fs::Permissions::from_mode(0o755)).unwrap();
    let run = f.root.join("python-user");
    let out = f
        .command(&[
            "audit",
            "init",
            "--target",
            f.target.to_str().unwrap(),
            "--out",
            run.to_str().unwrap(),
        ])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("PATH", &bin)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = read(&run.join("sensors.json"));
    assert!(
        report["tools_run"].as_array().unwrap().is_empty(),
        "{report}"
    );
    assert!(report["gaps"].to_string().contains("semgrep: Python runtime not proven: file-only MXC introspection failed; sensor not run"), "{report}");
    assert!(!report.to_string().contains("private application data"));

    // A supported fake interpreter proves its prefix inside MXC. The installed
    // package is readable, while the sibling application data remains denied.
    let base = f.root.join("python-runtime");
    std::fs::create_dir(&base).unwrap();
    let site = home.join(".local/lib/python3.13/site-packages");
    std::fs::write(site.join("semgrep/__init__.py"), "fake package").unwrap();
    f.tool("python3", "", 0);
    std::fs::copy(f.bin.join("python3"), &python).unwrap();
    let run = f.root.join("python-proven");
    let out = f
        .command(&[
            "audit",
            "init",
            "--target",
            f.target.to_str().unwrap(),
            "--out",
            run.to_str().unwrap(),
        ])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("PATH", &bin)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = read(&run.join("sensors.json"));
    assert!(
        report["tools_run"]
            .as_array()
            .unwrap()
            .contains(&json!("semgrep")),
        "{report}"
    );
    assert!(!report.to_string().contains("private application data"));

    // Independently exercise the same file-only grants through MXC: the native
    // fake succeeds only when its attempt to read the private file is denied.
    f.tool("trufflehog", &truffle("src/main.rs").to_string(), 0);
    std::fs::write(
        f.target.join(".sensor-fixture/trufflehog.outside"),
        private.to_str().unwrap(),
    )
    .unwrap();
    let out = f
        .command(&[
            "audit",
            "init",
            "--target",
            f.target.to_str().unwrap(),
            "--out",
            f.root.join("python-boundary").to_str().unwrap(),
        ])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = read(&f.root.join("python-boundary/sensors.json"));
    assert!(
        report["tools_run"]
            .as_array()
            .unwrap()
            .contains(&json!("trufflehog")),
        "{report}"
    );
}

#[test]
fn scratch_overrun_stops_scanner_before_deadline_and_discards_output() {
    if !ready() {
        return;
    }
    let f = Fixture::new();
    f.tool("trufflehog", "raw-secret-must-be-discarded", 0);
    std::fs::write(
        f.target.join(".sensor-fixture/trufflehog.mode"),
        "scratch-overrun",
    )
    .unwrap();
    let start = std::time::Instant::now();
    let run = f.init("scratch-overrun");
    // Includes discovery, preflight and Windows graceful cleanup. Half of the
    // scanner's 120-second deadline still rejects waiting for that deadline,
    // while allowing a slower host to write the real 1 GiB fixture first.
    assert!(
        start.elapsed() < std::time::Duration::from_secs(60),
        "writer was not stopped promptly: {:?}",
        start.elapsed()
    );
    let report = read(&run.join("sensors.json"));
    assert!(report["hits"].as_array().unwrap().is_empty(), "{report}");
    assert!(
        report["gaps"]
            .to_string()
            .contains("writable sensor scratch byte limit exceeded (limit 1073741824 bytes)"),
        "{report}"
    );
    assert_no_scratch(&f.root.join("home"));
    assert!(!std::fs::read_to_string(run.join("sensors.json"))
        .unwrap()
        .contains("raw-secret-must-be-discarded"));
}

#[test]
fn deep_scanner_writes_are_cancelled_and_fully_removed() {
    if !ready() {
        return;
    }
    let f = Fixture::new();
    f.tool("trufflehog", "raw-secret-must-be-discarded", 0);
    std::fs::write(
        f.target.join(".sensor-fixture/trufflehog.mode"),
        "scratch-deep",
    )
    .unwrap();
    let start = std::time::Instant::now();
    let run = f.init("scratch-deep");
    assert!(start.elapsed() < std::time::Duration::from_secs(60));
    let report = read(&run.join("sensors.json"));
    assert!(report["hits"].as_array().unwrap().is_empty(), "{report}");
    assert!(
        report["gaps"]
            .to_string()
            .contains("scratch depth exceeded"),
        "{report}"
    );
    assert!(
        !report["gaps"]
            .to_string()
            .contains("scratch cleanup failed"),
        "{report}"
    );
    assert_no_scratch(&f.root.join("home"));
    assert!(!std::fs::read_to_string(run.join("sensors.json"))
        .unwrap()
        .contains("raw-secret-must-be-discarded"));
}

#[cfg(target_os = "macos")]
#[test]
fn sensor_output_near_its_cap_survives_launchd_result_transport() {
    if !ready() {
        return;
    }
    let f = Fixture::new();
    f.tool("gitleaks", "[]", 0);
    let baseline = omgs::sensors::read_report(&f.init("small-output"))
        .unwrap()
        .unwrap();
    assert!(baseline.tools_run.contains(&"gitleaks".into()));
    // Exercise the real sensor limits, including its existing deadline. The
    // wrapper adds a leading newline, START line, separator and END line.
    let overhead = 1 + "OMGS_START_".len() + 64 + 1 + 1 + "OMGS_END_".len() + 64 + 2 + 1;
    let cap = 4 * 1024 * 1024;
    for total in [1024 * 1024, cap - 1, cap, cap + 1] {
        let output = format!("[]{}", " ".repeat(total - overhead - 2));
        f.tool("gitleaks", &output, 0);
        let report = omgs::sensors::read_report(&f.init(&format!("output-{total}")))
            .unwrap()
            .unwrap();
        if total <= cap {
            assert_eq!(report, baseline, "total={total}");
        } else {
            assert!(!report.tools_run.contains(&"gitleaks".into()));
            assert!(
                report
                    .gaps
                    .iter()
                    .any(|gap| gap.starts_with("gitleaks:") && gap.contains("output incomplete")),
                "{:?}",
                report.gaps
            );
        }
    }
}

#[test]
fn additional_b_repeated_gitleaks_hits_have_one_identity_and_bounded_provenance() {
    if !ready() {
        return;
    }
    let f = Fixture::new();
    let hit = json!({"RuleID":"fixture-rule","File":"src/main.rs","StartLine":1,
        "Secret":"duplicate-match-sentinel-never-store"});
    f.tool(
        "gitleaks",
        &json!([hit.clone(), hit.clone(), hit]).to_string(),
        1,
    );
    let run = f.init("deduplicated-hits");
    let report = read(&run.join("sensors.json"));
    let hits = read(&run.join("sensor-hits.json"));
    assert_eq!(report["hits"].as_array().unwrap().len(), 1);
    assert_eq!(hits.as_array().unwrap().len(), 1);
    assert_eq!(hits[0]["duplicate_sources"]["first_source_index"], 0);
    assert_eq!(hits[0]["duplicate_sources"]["count"], 2);
    assert_eq!(
        hits[0]["duplicate_sources"]["source_indexes"],
        json!([1, 2])
    );
    assert_eq!(hits[0]["duplicate_sources"]["omitted"], 0);
    assert!(!report
        .to_string()
        .contains("duplicate-match-sentinel-never-store"));
    let one: omgs::sensors::SensorHit = serde_json::from_value(hits[0].clone()).unwrap();
    let mut clean = one.clone();
    clean.duplicate_sources = None;
    let mut repeated = vec![clean.clone(); 401];
    omgs::sensors::deduplicate_hits(&mut repeated);
    assert_eq!(repeated.len(), 1);
    let sources = repeated[0].duplicate_sources.as_ref().unwrap();
    assert_eq!(sources.count, 400);
    assert_eq!(sources.source_indexes.len(), 128);
    assert_eq!(sources.omitted, 272);
    let before = repeated.clone();
    omgs::sensors::deduplicate_hits(&mut repeated);
    assert_eq!(before, repeated);
    let mut groups = vec![clean.clone(); 201];
    let mut other = clean.clone();
    other.line = Some(3);
    groups.extend(vec![other; 201]);
    omgs::sensors::deduplicate_hits(&mut groups);
    assert_eq!(groups.len(), 2);
    assert_eq!(
        groups
            .iter()
            .map(|h| h.duplicate_sources.as_ref().unwrap().source_indexes.len())
            .sum::<usize>(),
        128
    );
    assert_eq!(
        groups
            .iter()
            .map(|h| h.duplicate_sources.as_ref().unwrap().omitted)
            .sum::<u64>(),
        272
    );
    let mut distinct = clean.clone();
    distinct.line = Some(2);
    let mut input = vec![clean.clone(), clean, distinct];
    omgs::sensors::deduplicate_hits(&mut input);
    assert_eq!(input.len(), 2);
    let mut legacy = report.clone();
    legacy["hits"] = json!([one.clone(), one]);
    let parsed = omgs::shape::sensors(&legacy.to_string()).unwrap();
    assert_eq!(parsed.hits.len(), 1);
    let l: omgs::ledger::Ledger =
        serde_json::from_value(read(&run.join("coverage-ledger.json"))).unwrap();
    assert_eq!(
        l.units
            .iter()
            .filter(|u| u.id.starts_with("sensor:gitleaks:"))
            .count(),
        1
    );
    assert!(!omgs::critic::critique(&l, 1, &[], &Default::default()).passed());
}

#[test]
fn short_secret_guesses_cannot_be_confirmed_from_persisted_artifacts() {
    if !ready() {
        return;
    }
    let f = Fixture::new();
    // No column forces the ephemeral keyed fallback.
    let mut hit = json!({"RuleID":"fixture-rule", "File":"src/main.rs", "StartLine":1,
        "Secret":"0427"});
    f.tool(
        "gitleaks",
        &json!([hit.clone(), hit.clone()]).to_string(),
        1,
    );
    let run = f.init("short-secret");
    let first = read(&run.join("sensor-hits.json"));
    assert_eq!(first.as_array().unwrap().len(), 1);
    assert_eq!(first[0]["duplicate_sources"]["count"], 1);
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
    fn collect(path: &Path, bytes: &mut Vec<u8>) {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(&path, bytes);
            } else {
                bytes.extend(std::fs::read(path).unwrap());
                bytes.push(b'\n');
            }
        }
    }
    let mut bytes = Vec::new();
    collect(&run, &mut bytes);
    bytes.extend(out.stdout);
    bytes.extend(out.stderr);
    let saved = String::from_utf8_lossy(&bytes);
    assert!(!saved.contains("\"Secret\":\"0427\""));
    for guess in 0..10_000 {
        hit["Secret"] = json!(format!("{guess:04}"));
        let digest = omgs::sha256::digest(&serde_json::to_vec(&hit).unwrap());
        assert!(
            !saved.contains(&digest),
            "guess {guess} has a persisted oracle"
        );
        let old_fingerprint = omgs::sha256::digest(
            &serde_json::to_vec(&(
                "occurrence-v1",
                "gitleaks",
                "fixture-rule",
                "src/main.rs",
                Some(1u64),
                &digest,
            ))
            .unwrap(),
        );
        assert!(!saved.contains(&old_fingerprint));
    }
    let second = f.init("short-secret-again");
    assert_ne!(
        first[0]["occurrence"],
        read(&second.join("sensor-hits.json"))[0]["occurrence"]
    );
}
