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
            omgs::platform::random_nonce().unwrap()
        ));
        omgs::platform::create_private_tree(&root).unwrap();
        let bin = root.join("bin");
        let target = root.join("target");
        let db = root.join("db");
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
        let response = self.root.join(format!("{tool}.json"));
        std::fs::write(&response, output).unwrap();
        let calls = self.root.join(format!("{tool}.args"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let script = format!("#!/bin/sh\n[ -z \"$OMGS_TEST_SECRET\" ] || exit 17\nprintf '%s\\n' \"$@\" > '{}'\n/bin/cat '{}'\nexit {exit}\n", calls.display(), response.display());
            let path = self.bin.join(tool);
            std::fs::write(&path, script).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        #[cfg(windows)]
        {
            // PATH lookup intentionally accepts only native executables. This
            // tiny launcher runs our PowerShell fixture, never a target file.
            static LAUNCHER: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
            let launcher = LAUNCHER.get_or_init(|| {
                let dir = self.root.parent().unwrap().join(format!("omgs-sensor-launcher-{}", std::process::id()));
                std::fs::create_dir_all(&dir).unwrap();
                let source = dir.join("launcher.rs");
                std::fs::write(&source, r#"fn main() {
                    let exe = std::env::current_exe().unwrap();
                    let shell = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32/WindowsPowerShell/v1.0/powershell.exe");
                    let status = std::process::Command::new(shell).args(["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"]).arg(exe.with_extension("ps1")).args(std::env::args_os().skip(1)).status().unwrap();
                    std::process::exit(status.code().unwrap_or(18));
                }"#).unwrap();
                let exe = dir.join("launcher.exe");
                let status = Command::new(omgs::platform::which("rustc").unwrap()).env("RUSTUP_AUTO_INSTALL", "0").arg(&source).arg("-o").arg(&exe).status().unwrap();
                assert!(status.success());
                exe
            });
            std::fs::copy(launcher, self.bin.join(format!("{tool}.exe"))).unwrap();
            let quote = |p: &Path| p.to_string_lossy().replace('\'', "''");
            let script = format!("if ($env:OMGS_TEST_SECRET) {{ exit 17 }}\n[IO.File]::WriteAllLines('{}', [string[]]$args)\n[Console]::Out.Write([IO.File]::ReadAllText('{}'))\nexit {exit}\n", quote(&calls), quote(&response));
            std::fs::write(self.bin.join(format!("{tool}.ps1")), script).unwrap();
        }
    }
    fn cli(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_omgs"))
            .args(args)
            .env("PATH", &self.bin)
            .env("PATHEXT", ".EXE;.COM;.CMD;.BAT")
            .env("OMGS_OSV_DB", &self.db)
            .env("OMGS_TEST_SECRET", "must-not-be-inherited")
            .env("OMGS_HOME", self.root.join("home"))
            .output()
            .unwrap()
    }
    fn init(&self, name: &str) -> PathBuf {
        let run = self.root.join(name);
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
    json!({"DetectorName":"FixtureDetector", "Raw":"raw-secret-must-never-be-stored", "Redacted":"raw-secret-must-never-be-stored", "SourceMetadata":{"Data":{"Filesystem":{"file":file,"line":7}}}})
}
fn osv() -> Value {
    json!({"results":[{"source":{"path":"Cargo.lock","type":"lockfile"},"packages":[{"package":{"name":"fixture","version":"1.0","ecosystem":"crates.io"},"vulnerabilities":[{"id":"OSV-fixture","details":"raw-secret-must-never-be-stored"}]}]}]})
}

#[test]
fn offline_tools_feed_redacted_artifacts_reports_and_critic() {
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
    let hits = read(&run.join("sensor-hits.json"));
    assert_eq!(hits.as_array().unwrap().len(), 6);
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
                assert!(
                    !std::fs::read_to_string(&p)
                        .unwrap()
                        .contains("raw-secret-must-never-be-stored"),
                    "{} leaked",
                    p.display()
                );
            }
        }
    }
    check_no_secret(&run);
    let args = std::fs::read_to_string(f.root.join("trufflehog.args")).unwrap();
    for flag in ["filesystem", "--no-verification", "--no-update", "--json"] {
        assert!(args.lines().any(|a| a == flag), "{args}");
    }
    let args = std::fs::read_to_string(f.root.join("osv-scanner.args")).unwrap();
    for flag in [
        "--offline",
        "--offline-vulnerabilities",
        "--format=json",
        "--no-call-analysis",
        "--no-resolve",
    ] {
        assert!(args.lines().any(|a| a == flag), "{args}");
    }
    assert!(!args.contains("download"));
    assert!(!args.contains("update"));
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
