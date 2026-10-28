use omgs::policy::{self, Mode, Policy};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("omgs-policy-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    omgs::platform::create_private_tree(&path).unwrap();
    std::fs::canonicalize(path).unwrap()
}
fn cli(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("OMGS_HOME", home.join("omgs-data"))
        .env("RUSTUP_AUTO_INSTALL", "0")
        .output()
        .unwrap()
}
fn output(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}
fn git(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(repo)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", output(&out));
    String::from_utf8(out.stdout).unwrap().trim().into()
}
fn check_patch(repo: &Path, patch: &Path) {
    use std::io::Write;
    use std::process::Stdio;
    // Git for Windows does not accept Rust's extended canonical paths as
    // patch arguments. Feed exact bytes through stdin on every platform.
    let mut child = Command::new("git")
        .current_dir(repo)
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "apply",
            "--check",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&std::fs::read(patch).unwrap())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", output(&out));
}
fn read(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
fn write(path: &Path, value: &Value) {
    omgs::runmeta::write_atomic(path, &serde_json::to_string_pretty(value).unwrap()).unwrap();
}
fn init(root: &Path, target: &Path, run: &Path, base: Option<&str>) -> Output {
    let mut args = vec![
        "audit",
        "init",
        "--target",
        target.to_str().unwrap(),
        "--out",
        run.to_str().unwrap(),
        "--no-sensors",
    ];
    if let Some(base) = base {
        args.extend(["--base", base]);
    }
    cli(&root.join("home"), &args)
}
fn repo(root: &Path) -> PathBuf {
    let repo = root.join("repo");
    std::fs::create_dir(&repo).unwrap();
    git(&repo, &["init"]);
    std::fs::write(repo.join("main.rs"), "fn main() {}\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-m", "Base"]);
    repo
}
fn commit_policy(repo: &Path, p: &Policy) -> String {
    std::fs::create_dir_all(repo.join(".omgs")).unwrap();
    std::fs::write(repo.join(policy::PATH), policy::text(p).unwrap()).unwrap();
    git(repo, &["add", "."]);
    git(repo, &["commit", "--allow-empty", "-m", "Policy"]);
    git(repo, &["rev-parse", "HEAD"])
}
fn gate(root: &Path, repo: &Path, base: &str, head: &str, run: Option<&Path>, code: i32) -> Output {
    let mut args = vec![
        "gate",
        "--target",
        repo.to_str().unwrap(),
        "--base",
        base,
        "--head",
        head,
    ];
    if let Some(run) = run {
        args.extend(["--run", run.to_str().unwrap()]);
    }
    let o = cli(&root.join("home"), &args);
    assert_eq!(o.status.code(), Some(code), "{}", output(&o));
    o
}
fn registered() -> policy::GateTest {
    policy::GateTest {
        id: "boundary-test".into(),
        test: if cfg!(windows) {
            "security.cmd"
        } else {
            "security.sh"
        }
        .into(),
        command: if cfg!(windows) {
            "call security.cmd"
        } else {
            "sh security.sh"
        }
        .into(),
        expect_marker: "BOUNDARY".into(),
        severity: omgs::model::Severity::High,
        timeout_ms: 10_000,
        fingerprint: Some("omgs-0123456789abcdef".into()),
    }
}
fn test_source(failing: bool) -> &'static str {
    match (cfg!(windows), failing) {
        (true, true) => "@echo off\r\necho OMGS_CONTROL_%OMGS_PROOF_NONCE%\r\necho OMGS_BOUNDARY_%OMGS_PROOF_NONCE%_BOUNDARY\r\nexit /b 1\r\n",
        (true, false) => "@exit /b 0\r\n",
        (false, true) => "printf 'OMGS_CONTROL_%s\\nOMGS_BOUNDARY_%s_BOUNDARY\\n' \"$OMGS_PROOF_NONCE\" \"$OMGS_PROOF_NONCE\"\nexit 1\n",
        (false, false) => "exit 0\n",
    }
}
fn mxc_ready(root: &Path) -> bool {
    let o = cli(&root.join("home"), &["doctor", "--live"]);
    if o.status.success() {
        true
    } else {
        eprintln!("SKIP live gate tests: {}", output(&o));
        false
    }
}

/// An archived, internally consistent runner fixture. It needs no installed
/// executor and never executes a target. Live runner coverage remains in sandbox.rs.
fn evidence(run: &Path, target: &Path) {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("benchmark/fixtures/score/run-1/positive");
    omgs::platform::private_dir(&run.join("proofs/1")).unwrap();
    for name in [
        "1.json",
        "1/command.txt",
        "1/mxc-config.json",
        "1/test-draft",
    ] {
        let bytes = std::fs::read(fixture.join("proofs").join(name)).unwrap();
        omgs::runmeta::write_atomic_bytes(&run.join("proofs").join(name), &bytes).unwrap();
    }
    let mut proof = read(&run.join("proofs/1.json"));
    proof["target"] = json!(target);
    proof["target_sha256"] = json!("a".repeat(64));
    write(&run.join("proofs/1.json"), &proof);
    let findings = json!({"findings":[{
        "fingerprint": proof["finding"], "title":"Boundary read", "verdict":"confirmed", "severity":"high",
        "proof_tier":"test_proven", "attack_class":"idor", "entry_point":"GET /x", "sink":"db.x", "boundary":"tenant",
        "location":{"path":"main.rs","line":1}, "evidence":"Assertion failed after authorized control",
        "hunted_by":"red", "verified_by":"blue", "proof_ref":"proofs/1.json"
    }]});
    // Fixture identity uses its original semantic tuple; recover it from the
    // accompanying findings instead of inventing a different identity.
    let original = read(&fixture.join("findings.json"));
    let mut findings = findings;
    for key in ["attack_class", "entry_point", "sink", "boundary"] {
        findings["findings"][0][key] = original["findings"][0][key].clone();
    }
    write(&run.join("findings.json"), &findings);
    let file = omgs::shape::findings(&findings.to_string()).unwrap();
    assert!(omgs::model::validate(&file).is_empty());
    assert!(
        omgs::proof::validate_proofs(&file, run).is_empty(),
        "{:?}",
        omgs::proof::validate_proofs(&file, run)
    );
}

#[test]
fn registered_gate_executes_immutable_head_and_ignores_advisory_artifacts() {
    let root = scratch("gate-live");
    if !mxc_ready(&root) {
        std::fs::remove_dir_all(root).unwrap();
        return;
    }
    let repo = repo(&root);
    let t = registered();
    std::fs::write(repo.join(&t.test), test_source(true)).unwrap();
    let p = Policy {
        mode: Mode::Gate,
        gate_tests: vec![t.clone()],
        ..Default::default()
    };
    let base = commit_policy(&repo, &p);
    gate(&root, &repo, &base, &base, None, 1);
    let run = root.join("run");
    assert!(init(&root, &repo, &run, Some(&base)).status.success());
    evidence(&run, &repo); // A different, unregistered confirmed finding is advisory.
    let advisory = gate(&root, &repo, &base, &base, Some(&run), 1);
    assert!(output(&advisory).contains("not yet a registered gate test"));
    std::fs::write(run.join("findings.json"), "corrupt").unwrap();
    std::fs::write(run.join("run-metadata.json"), "corrupt").unwrap();
    std::fs::remove_dir_all(run.join("proofs")).unwrap();
    // A dirty fixed test also cannot bypass the committed failure.
    std::fs::write(repo.join(&t.test), test_source(false)).unwrap();
    gate(&root, &repo, &base, &base, Some(&run), 1);
    std::fs::write(repo.join(&t.test), test_source(true)).unwrap();
    let unavailable = Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args([
            "gate",
            "--target",
            repo.to_str().unwrap(),
            "--base",
            &base,
            "--head",
            &base,
        ])
        .env("OMGS_MXC_EXEC", root.join("missing-executor"))
        .output()
        .unwrap();
    assert_eq!(
        unavailable.status.code(),
        Some(3),
        "{}",
        output(&unavailable)
    );
    let head = commit_policy(&repo, &Policy::default());
    gate(&root, &repo, &base, &head, Some(&run), 1); // Head-only policy cannot disable gate.
    std::fs::write(repo.join(&t.test), test_source(false)).unwrap();
    let fixed = commit_policy(&repo, &Policy::default());
    gate(&root, &repo, &base, &fixed, None, 0);
    // A failing draft exists only in run storage and cannot add a gate test.
    std::fs::write(run.join("draft"), test_source(true)).unwrap();
    gate(&root, &repo, &base, &fixed, Some(&run), 0);
    gate(&root, &repo, &base, &head, None, 3);
    std::fs::remove_file(repo.join(&t.test)).unwrap();
    let missing = commit_policy(&repo, &Policy::default());
    gate(&root, &repo, &base, &missing, None, 3);
    std::fs::write(repo.join(&t.test), test_source(true)).unwrap();
    let mut suppressed = p.clone();
    suppressed.suppressions.push(policy::Suppression {
        fingerprint: t.fingerprint.unwrap(),
        reason: "Accepted until fix".into(),
        expires_unix: omgs::runmeta::now_unix() + 3600,
    });
    let suppressed = commit_policy(&repo, &suppressed);
    gate(&root, &repo, &suppressed, &suppressed, None, 0);
    let mut below = p.clone();
    below.severity_threshold = omgs::model::Severity::Critical;
    let below = commit_policy(&repo, &below);
    gate(&root, &repo, &below, &below, None, 0);
    for source in [
        if cfg!(windows) {
            "@exit /b 1\r\n"
        } else {
            "exit 1\n"
        },
        if cfg!(windows) {
            "@exit /b 2\r\n"
        } else {
            "exit 2\n"
        },
    ] {
        std::fs::write(repo.join(&t.test), source).unwrap();
        let invalid_contract = commit_policy(&repo, &p);
        gate(&root, &repo, &invalid_contract, &invalid_contract, None, 3);
    }
    std::fs::write(repo.join(&t.test), test_source(true)).unwrap();
    let mut advisory = p;
    advisory.mode = Mode::Advisory;
    let advisory = commit_policy(&repo, &advisory);
    assert!(output(&gate(&root, &repo, &advisory, &advisory, None, 0)).contains("would block"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn gate_missing_test_wrong_head_invalid_policy_and_unregistered_draft_without_mxc() {
    let root = scratch("gate-static");
    let repo = repo(&root);
    let base = commit_policy(
        &repo,
        &Policy {
            mode: Mode::Gate,
            gate_tests: vec![registered()],
            ..Default::default()
        },
    );
    assert!(output(&gate(&root, &repo, &base, &base, None, 3)).contains("missing"));
    // Case-insensitive host filesystems cannot satisfy a different committed path.
    std::fs::write(
        repo.join(if cfg!(windows) {
            "Security.cmd"
        } else {
            "Security.sh"
        }),
        test_source(false),
    )
    .unwrap();
    let case_head = commit_policy(
        &repo,
        &Policy {
            mode: Mode::Gate,
            gate_tests: vec![registered()],
            ..Default::default()
        },
    );
    assert!(output(&gate(&root, &repo, &case_head, &case_head, None, 3)).contains("missing"));
    let head = commit_policy(&repo, &Policy::default());
    assert!(output(&gate(&root, &repo, &base, &base, None, 3)).contains("does not match"));
    let base = commit_policy(
        &repo,
        &Policy {
            mode: Mode::Gate,
            ..Default::default()
        },
    );
    let run = root.join("run");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::write(run.join("draft"), test_source(true)).unwrap();
    std::fs::write(run.join("findings.json"), "corrupt").unwrap();
    gate(&root, &repo, &base, &base, Some(&run), 0);
    std::fs::write(repo.join(policy::PATH), "invalid").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-m", "Invalid policy"]);
    let invalid = git(&repo, &["rev-parse", "HEAD"]);
    gate(&root, &repo, &invalid, &invalid, None, 3);
    let advisory = commit_policy(
        &repo,
        &Policy {
            gate_tests: vec![registered()],
            ..Default::default()
        },
    );
    gate(&root, &repo, &advisory, &advisory, None, 0);
    gate(&root, &repo, &advisory, &head, None, 0);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn suppression_expiry_is_required_bounded_and_anchored_to_policy_change() {
    let root = scratch("expiry");
    let repo = repo(&root);
    let mut p: Value = serde_json::from_str(&policy::text(&Policy::default()).unwrap()).unwrap();
    p["suppressions"] = json!([{"fingerprint":"omgs-0123456789abcdef", "reason":"accepted"}]);
    assert!(policy::parse(&p.to_string()).is_err());
    for expiry in [
        json!(null),
        json!(-1),
        json!(u64::MAX),
        json!(policy::MAX_EXPIRY + 1),
    ] {
        p["suppressions"][0]["expires_unix"] = expiry;
        assert!(policy::parse(&p.to_string()).is_err());
    }
    p["suppressions"][0]["expires_unix"] =
        json!(omgs::runmeta::now_unix() + policy::MAX_SUPPRESSION_SECONDS + 86400);
    let p = policy::parse(&p.to_string()).unwrap();
    let base = commit_policy(&repo, &p);
    assert!(policy::load_base(&repo, Some(&base))
        .unwrap_err()
        .contains("365 days"));
    // Unrelated commits must not reset the policy's maximum lifetime.
    std::fs::write(repo.join("later"), "later").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-m", "Later"]);
    let head = git(&repo, &["rev-parse", "HEAD"]);
    assert!(policy::load_base(&repo, Some(&head)).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn strict_policy_rejects_required_unknown_duplicate_and_nested_keys() {
    let default: Value = serde_json::from_str(&policy::text(&Policy::default()).unwrap()).unwrap();
    assert!(policy::parse(&default.to_string()).is_ok());
    for key in default.as_object().unwrap().keys() {
        let mut p = default.clone();
        p.as_object_mut().unwrap().remove(key);
        assert!(policy::parse(&p.to_string()).is_err(), "{key}");
    }
    let mut p = default.clone();
    p["typo"] = json!(true);
    assert!(policy::parse(&p.to_string()).is_err());
    assert!(policy::parse(&default.to_string().replacen('{', "{\"mode\":\"gate\",", 1)).is_err());
    for key in ["mode", "severity_threshold"] {
        let mut p = default.clone();
        p[key] = if key == "mode" {
            json!({"gate":null})
        } else {
            json!({"high":null})
        };
        assert!(policy::parse(&p.to_string()).is_err());
    }
    let answer = json!({"id":omgs::intent::library().questions[0].id,"answer":"yes","scope":"repo","source":"owner"});
    let suppression =
        json!({"fingerprint":"omgs-0123456789abcdef","reason":"accepted","expires_unix":1234});
    for (container, record) in [("accepted_intent", answer), ("suppressions", suppression)] {
        for key in record.as_object().unwrap().keys() {
            let mut bad = record.clone();
            bad.as_object_mut().unwrap().remove(key);
            let mut p = default.clone();
            p[container] = json!([bad]);
            assert!(policy::parse(&p.to_string()).is_err());
        }
        let mut bad = record.clone();
        bad["unknown"] = json!(true);
        let mut p = default.clone();
        p[container] = json!([bad]);
        assert!(policy::parse(&p.to_string()).is_err());
        p[container] = json!([record.as_object().unwrap().values().collect::<Vec<_>>()]);
        assert!(policy::parse(&p.to_string()).is_err());
    }
    let contract = serde_json::to_value(registered()).unwrap();
    for key in [
        "id",
        "test",
        "command",
        "expect_marker",
        "severity",
        "timeout_ms",
    ] {
        let mut bad = contract.clone();
        bad.as_object_mut().unwrap().remove(key);
        let mut p = default.clone();
        p["gate_tests"] = json!([bad]);
        assert!(policy::parse(&p.to_string()).is_err(), "{key}");
    }
    for (key, value) in [
        ("severity", json!({"high":null})),
        ("fingerprint", json!(null)),
        ("test", json!("../outside")),
        ("command", json!("sh other-test.sh")),
        ("expect_marker", json!("OMGS_RESERVED")),
        ("timeout_ms", json!(0)),
    ] {
        let mut bad = contract.clone();
        bad[key] = value;
        let mut p = default.clone();
        p["gate_tests"] = json!([bad]);
        assert!(policy::parse(&p.to_string()).is_err(), "{key}");
    }
    let mut duplicates = default.clone();
    duplicates["gate_tests"] = json!([contract, contract]);
    assert!(policy::parse(&duplicates.to_string()).is_err());
    for path in ["../src", "/src", "a/../src", "a\\src", "a//b", "a/", "."] {
        let mut p = default.clone();
        p["excluded_paths"] = json!([path]);
        assert!(policy::parse(&p.to_string()).is_err(), "{path}");
    }
}

#[test]
fn hostile_git_config_never_executes_during_policy_read() {
    let root = scratch("hostile");
    let repo = repo(&root);
    let base = commit_policy(&repo, &Policy::default());
    let marker = root.join("EXECUTED");
    let malicious = format!("touch '{}'", marker.to_string_lossy().replace('\\', "/"));
    // git config only stores the value, it does not run it. No target git
    // command after this point except the production object-only policy reader.
    git(&repo, &["config", "core.fsmonitor", &malicious]);
    git(&repo, &["config", "diff.external", &malicious]);
    git(&repo, &["config", "diff.policy.textconv", &malicious]);
    std::fs::write(
        repo.join(".gitattributes"),
        ".omgs/policy.json diff=policy filter=policy\n",
    )
    .unwrap();
    git(&repo, &["config", "filter.policy.smudge", &malicious]);
    let loaded = policy::load_base(&repo, Some(&base)).unwrap();
    assert_eq!(loaded.policy.mode, Mode::Advisory);
    assert!(!marker.exists());
    // Exercise init too, including its source identity read and inventory.
    let out = init(&root, &repo, &root.join("run"), Some(&base));
    assert!(out.status.success(), "{}", output(&out));
    assert!(!marker.exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn setup_detects_only_existing_agents_and_writes_policy_only_on_request() {
    let root = scratch("setup");
    let home = root.join("home");
    for dir in [".claude", ".codex"] {
        std::fs::create_dir_all(home.join(dir)).unwrap();
    }
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("skill");
    let dry = cli(
        &home,
        &["setup", "--dry-run", "--from", source.to_str().unwrap()],
    );
    assert!(dry.status.success(), "{}", output(&dry));
    let display = output(&dry);
    assert!(display.contains(".claude") && display.contains(".codex"));
    for absent in [
        ".agents", ".cursor", ".gemini", ".copilot", "opencode", "windsurf",
    ] {
        assert!(!display.contains(absent));
    }
    assert!(!home.join(".codex/skills").exists());
    let repo = repo(&root);
    let install = cli(
        &home,
        &[
            "setup",
            "--install-skills",
            "--from",
            source.to_str().unwrap(),
        ],
    );
    assert!(install.status.success(), "{}", output(&install));
    assert!(!repo.join(policy::PATH).exists());
    let install = cli(
        &home,
        &[
            "setup",
            "--install-skills",
            "--from",
            source.to_str().unwrap(),
            "--write-policy",
            repo.to_str().unwrap(),
            "--mode",
            "gate",
        ],
    );
    assert!(install.status.success(), "{}", output(&install));
    for dir in [".claude", ".codex"] {
        let installed = home.join(dir).join("skills").join(omgs::setup::SKILL_NAME);
        assert_eq!(
            std::fs::read(installed.join("SKILL.md")).unwrap(),
            std::fs::read(source.join("SKILL.md")).unwrap()
        );
        assert!(installed.join("schemas/policy.schema.json").is_file());
    }
    assert!(!home.join(".agents").exists());
    assert!(!home.join(".cursor").exists());
    assert_eq!(
        policy::parse(&std::fs::read_to_string(repo.join(policy::PATH)).unwrap())
            .unwrap()
            .mode,
        Mode::Gate
    );
    let refused = cli(
        &home,
        &[
            "setup",
            "--write-policy",
            repo.to_str().unwrap(),
            "--mode",
            "advisory",
        ],
    );
    assert!(!refused.status.success());
    assert_eq!(read(&repo.join(policy::PATH))["mode"], "gate");
    let bootstrap = root.join("bootstrap");
    std::fs::create_dir_all(bootstrap.join("bin")).unwrap();
    let executable = bootstrap
        .join("bin")
        .join(if cfg!(windows) { "omgs.exe" } else { "omgs" });
    std::fs::copy(env!("CARGO_BIN_EXE_omgs"), &executable).unwrap();
    // Actual bootstrap layout: only the verified binary, launched from elsewhere.
    let launched = Command::new(&executable)
        .current_dir(&root)
        .args(["setup", "--install-skills"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    assert!(launched.status.success(), "{}", output(&launched));
    assert!(output(&launched).contains("already installed"));
    let installed = home.join(".codex/skills").join(omgs::setup::SKILL_NAME);
    std::fs::write(installed.join("SKILL.md"), "Owner changes").unwrap();
    std::fs::write(installed.join("custom.txt"), "keep in backup").unwrap();
    let refused = cli(&home, &["setup", "--install-skills"]);
    assert!(!refused.status.success());
    assert!(output(&refused).contains("SKILL.md") && output(&refused).contains("custom.txt"));
    assert_eq!(
        std::fs::read_to_string(installed.join("SKILL.md")).unwrap(),
        "Owner changes"
    );
    let replaced = cli(&home, &["setup", "--install-skills", "--replace"]);
    assert!(replaced.status.success(), "{}", output(&replaced));
    assert!(!installed.join("custom.txt").exists());
    assert_eq!(
        std::fs::read(installed.join("SKILL.md")).unwrap(),
        std::fs::read(source.join("SKILL.md")).unwrap()
    );
    let backup = std::fs::read_dir(installed.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .contains(".backup-")
        })
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(backup.join("custom.txt")).unwrap(),
        "keep in backup"
    );
    let bad = root.join("bad-source");
    std::fs::create_dir_all(&bad).unwrap();
    std::fs::write(bad.join("SKILL.md"), "invalid name").unwrap();
    assert!(omgs::setup::install(Some(&bad), std::slice::from_ref(&installed), true).is_err());
    assert_eq!(
        std::fs::read(installed.join("SKILL.md")).unwrap(),
        std::fs::read(source.join("SKILL.md")).unwrap()
    );
    let missing = Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args(["setup", "--verify-mxc"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("OMGS_HOME", home.join("omgs-data"))
        .env("OMGS_MXC_EXEC", root.join("missing-executor"))
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(3), "{}", output(&missing));
    assert!(output(&missing).contains("live check: not run"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn intent_proposal_is_reviewable_and_exclusions_remain_accountable() {
    let root = scratch("proposal");
    let repo = repo(&root);
    std::fs::create_dir_all(repo.join("excluded")).unwrap();
    std::fs::write(repo.join("excluded/service.rs"), "pub fn service() {}\n").unwrap();
    let mut p = Policy::default();
    p.excluded_paths.push("excluded".into());
    let base = commit_policy(&repo, &p);
    let before = std::fs::read(repo.join(policy::PATH)).unwrap();
    let run = root.join("run");
    assert!(init(&root, &repo, &run, Some(&base)).status.success());
    let ledger = read(&run.join("coverage-ledger.json"));
    let unit = ledger["units"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["id"] == "policy:excluded:excluded")
        .unwrap();
    assert_eq!(unit["status"], "planned");
    assert_eq!(unit["excluded_count"], 1);
    assert_eq!(unit["excluded_paths"], json!(["excluded/service.rs"]));
    assert_eq!(unit["excluded_source_count"], 1);
    let id = &omgs::intent::library().questions[0].id;
    let answer = cli(
        &root.join("home"),
        &[
            "intent",
            "answer",
            "--target",
            repo.to_str().unwrap(),
            "--id",
            id,
            "--answer",
            "Owner confirmed",
            "--source",
            "owner",
        ],
    );
    assert!(answer.status.success(), "{}", output(&answer));
    let proposal = cli(
        &root.join("home"),
        &["intent", "propose", "--run", run.to_str().unwrap()],
    );
    assert!(proposal.status.success(), "{}", output(&proposal));
    assert_eq!(before, std::fs::read(repo.join(policy::PATH)).unwrap());
    let patch = std::fs::read_to_string(run.join("policy.patch")).unwrap();
    assert!(patch.contains("Owner confirmed") && patch.contains("--- a/.omgs/policy.json"));
    check_patch(&repo, &run.join("policy.patch"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn accepted_base_intent_seeds_answers_and_missing_policy_proposes_a_new_file() {
    let root = scratch("accepted");
    let repo = repo(&root);
    let missing_base = git(&repo, &["rev-parse", "HEAD"]);
    let mut p = Policy::default();
    p.accepted_intent.push(policy::AcceptedIntent {
        id: omgs::intent::library().questions[0].id.clone(),
        answer: "Owner approved behavior".into(),
        scope: "repo".into(),
        source: "maintainer".into(),
    });
    let base = commit_policy(&repo, &p);
    let run = root.join("accepted-run");
    assert!(init(&root, &repo, &run, Some(&base)).status.success());
    let saved = read(&run.join("intent-answers.json"));
    assert_eq!(saved["answers"][0]["answer"], "Owner approved behavior");
    let proposal = cli(
        &root.join("home"),
        &["intent", "propose", "--run", run.to_str().unwrap()],
    );
    assert!(proposal.status.success(), "{}", output(&proposal));
    assert!(std::fs::read(run.join("policy.patch")).unwrap().is_empty());
    let empty = root.join("no-policy-run");
    assert!(init(&root, &repo, &empty, Some(&missing_base))
        .status
        .success());
    let proposal = cli(
        &root.join("home"),
        &["intent", "propose", "--run", empty.to_str().unwrap()],
    );
    assert!(proposal.status.success(), "{}", output(&proposal));
    let patch = std::fs::read_to_string(empty.join("policy.patch")).unwrap();
    assert!(patch.contains("--- /dev/null") && patch.contains("@@ -0,0 +1,"));
    std::fs::remove_file(repo.join(policy::PATH)).unwrap();
    check_patch(&repo, &empty.join("policy.patch"));
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
fn fifo(path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: path is a valid NUL-terminated path; no writer is ever started.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
}
#[cfg(unix)]
fn bounded_gate(repo: &Path, base: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args([
            "gate",
            "--target",
            repo.to_str().unwrap(),
            "--base",
            base,
            "--head",
            base,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let start = std::time::Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if start.elapsed().as_secs() >= 12 {
            let _ = child.kill();
            let _ = child.wait();
            panic!("gate exceeded outer fixture deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}
#[cfg(unix)]
#[test]
fn fifo_config_includes_are_rejected_and_git_object_reads_have_a_deadline() {
    let root = scratch("git-fifo");
    let repo = repo(&root);
    let base = commit_policy(
        &repo,
        &Policy {
            mode: Mode::Gate,
            ..Default::default()
        },
    );
    let pipe = root.join("include-fifo");
    fifo(&pipe);
    let config = repo.join(".git/config");
    let original = std::fs::read_to_string(&config).unwrap();
    for section in ["include", "includeIf \"gitdir:**\""] {
        std::fs::write(
            &config,
            format!("{original}\n[{section}]\npath = {}\n", pipe.display()),
        )
        .unwrap();
        let o = bounded_gate(&repo, &base);
        assert_eq!(o.status.code(), Some(3), "{}", output(&o));
        assert!(output(&o).contains("includes are blocked"));
    }
    std::fs::write(&config, &original).unwrap();
    std::fs::write(
        repo.join(".git/config.worktree"),
        format!("[include]\npath = {}\n", pipe.display()),
    )
    .unwrap();
    assert_eq!(bounded_gate(&repo, &base).status.code(), Some(3));
    std::fs::remove_file(repo.join(".git/config.worktree")).unwrap();
    let head_ref = std::fs::read_to_string(repo.join(".git/HEAD")).unwrap();
    let reference = repo
        .join(".git")
        .join(head_ref.trim().strip_prefix("ref: ").unwrap());
    std::fs::remove_file(&reference).unwrap();
    fifo(&reference);
    let start = std::time::Instant::now();
    let o = bounded_gate(&repo, &base);
    assert_eq!(o.status.code(), Some(3), "{}", output(&o));
    assert!(output(&o).contains("deadline"), "{}", output(&o));
    assert!(start.elapsed().as_secs() < 12);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn redirected_git_directory_is_blocked() {
    let root = scratch("redirect");
    let repo = repo(&root);
    let base = commit_policy(
        &repo,
        &Policy {
            mode: Mode::Gate,
            ..Default::default()
        },
    );
    std::fs::rename(repo.join(".git"), root.join("outside.git")).unwrap();
    std::fs::write(
        repo.join(".git"),
        format!("gitdir: {}\n", root.join("outside.git").display()),
    )
    .unwrap();
    assert!(output(&gate(&root, &repo, &base, &base, None, 3)).contains("redirected"));
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn stage_and_intent_propose_patch_validated_tests_and_registry_together() {
    let root = scratch("test-proposal");
    let repo = repo(&root);
    let base = commit_policy(&repo, &Policy::default());
    let run = root.join("run");
    assert!(init(&root, &repo, &run, Some(&base)).status.success());
    evidence(&run, &repo);
    for args in [
        vec!["stage", "--run", run.to_str().unwrap()],
        vec!["intent", "propose", "--run", run.to_str().unwrap()],
    ] {
        let o = cli(&root.join("home"), &args);
        assert!(o.status.success(), "{}", output(&o));
        let patch = std::fs::read_to_string(run.join("policy.patch")).unwrap();
        assert!(
            patch.contains("tests/security/x.test.ts")
                && patch.contains("gate_tests")
                && patch.contains("FIXTURE_BOUNDARY")
        );
        check_patch(&repo, &run.join("policy.patch"));
    }
    let mut proof = read(&run.join("proofs/1.json"));
    proof["cleanup_complete"] = json!(false);
    write(&run.join("proofs/1.json"), &proof);
    assert!(!cli(
        &root.join("home"),
        &["stage", "--run", run.to_str().unwrap()]
    )
    .status
    .success());
    std::fs::remove_dir_all(root).unwrap();
}
