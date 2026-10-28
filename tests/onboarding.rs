use std::process::Command;

#[test]
fn readme_has_newcomer_headings() {
    let readme = include_str!("../README.md");
    for heading in [
        "What happens when you run it",
        "What the binary does and never does",
        "Why target code only runs in a sandbox",
        "Handing results to an agent",
        "Known limitations",
    ] {
        assert!(
            readme.lines().any(|line| line == format!("## {heading}")),
            "{heading}"
        );
    }
}

#[test]
fn every_subcommand_has_help_without_initializing_state() {
    for command in [
        "setup",
        "review",
        "audit",
        "audit init",
        "batch",
        "batch init",
        "batch index",
        "bench",
        "bench score",
        "budget",
        "validate",
        "fingerprint",
        "prove",
        "approve",
        "report",
        "architecture",
        "ledger",
        "ledger list",
        "ledger add",
        "ledger set",
        "critic",
        "status",
        "watch",
        "route",
        "intent",
        "intent list",
        "intent answer",
        "check",
        "doctor",
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_omgs"))
            .args(command.split_whitespace())
            .arg("--help")
            .output()
            .unwrap();
        assert!(out.status.success(), "{command}: {out:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("Usage:"));
    }
}

#[test]
fn route_without_configuration_uses_host_and_records_refusal() {
    let home = omgs::platform::temp_root()
        .unwrap()
        .join(format!("omgs-route-default-{}", std::process::id()));
    let run = home.join("run");
    omgs::platform::create_private_tree(&run).unwrap();
    omgs::runmeta::write_atomic(&run.join("run-metadata.json"), "{}").unwrap();
    let route = || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_omgs"));
        cmd.env("OMGS_HOME", &home)
            .args(["route", "--run"])
            .arg(&run)
            .args(["--role", "hunter"]);
        cmd
    };
    let out = route().output().unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "host-default");
    let out = route()
        .args(["--refused", "host-default", "--reason", "declined"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let meta: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(run.join("run-metadata.json")).unwrap())
            .unwrap();
    assert_eq!(meta["reroutes"][0]["from"], "host-default");
    assert!(meta["blockers"].as_array().unwrap().len() == 1);
    let out = route()
        .arg("--models")
        .arg(home.join("missing.json"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn skill_version_and_executor_pins_match_the_binary() {
    assert_eq!(
        include_str!("../skill/VERSION").trim(),
        env!("CARGO_PKG_VERSION")
    );
    let rows: Vec<_> = include_str!("../skill/mxc-pins.txt")
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .collect();
    assert_eq!(rows.len(), 5);
    for row in rows {
        let fields: Vec<_> = row.split_whitespace().collect();
        assert_eq!(fields.len(), 4);
        let (os, arch) = match fields[0] {
            "Darwin/arm64" => ("macos", "aarch64"),
            "Linux/aarch64" => ("linux", "aarch64"),
            "Linux/x86_64" => ("linux", "x86_64"),
            "Windows/ARM64" => ("windows", "aarch64"),
            "Windows/AMD64" => ("windows", "x86_64"),
            other => panic!("unexpected platform {other}"),
        };
        let executor = omgs::sandbox::executor_for(os, arch).unwrap();
        assert_eq!(executor.file, fields[1].split('/').next_back().unwrap());
        assert_eq!(executor.sha256, fields[3]);
    }
}

#[test]
fn literal_environment_reads_are_documented() {
    let readme = include_str!("../README.md");
    for source in [
        include_str!("../src/platform.rs"),
        include_str!("../src/sensors.rs"),
        include_str!("../src/sandbox.rs"),
        include_str!("../src/supervise.rs"),
        include_str!("../src/sandbox/preflight.rs"),
    ] {
        for prefix in ["env::var(\"", "env::var_os(\""] {
            for part in source.split(prefix).skip(1) {
                let name = part.split('"').next().unwrap();
                assert!(
                    readme.contains(&format!("`{name}`")),
                    "undocumented: {name}"
                );
            }
        }
    }
}
