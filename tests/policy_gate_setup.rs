use omgs::policy::{self, Mode, Policy};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn scratch(name: &str) -> PathBuf {
    let parent = if cfg!(windows) {
        PathBuf::from(std::env::var_os("USERPROFILE").unwrap())
    } else {
        omgs::platform::temp_root().unwrap()
    };
    let path = parent.join(format!("omgs-policy-{}-{name}", std::process::id()));
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
// Linux can briefly retain a copied executable's write handle in another
// thread's fork child, even after fs::copy closes the parent's handle. Retry
// only ETXTBSY before exec; never retry a started program or hide its status.
fn copied_binary_output(command: &mut Command) -> Output {
    #[cfg(target_os = "linux")]
    {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match command.output() {
                Err(error)
                    if error.raw_os_error() == Some(libc::ETXTBSY)
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                result => return result.expect("could not execute copied fixture binary"),
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    command.output().unwrap()
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
    apply_patch(repo, patch, true);
}
fn apply_patch(repo: &Path, patch: &Path, check: bool) {
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
        ])
        .args(if check {
            vec!["--check", "-"]
        } else {
            vec!["-"]
        })
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
    let data = root.join("home/omgs-data");
    if data.exists() {
        assert!(!std::fs::read_dir(data).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("omgs-gate-")));
    }
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
    completed_verifier_fixture(run, "blue");
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
        "hunted_by":"red", "verified_by":"blue", "verification":{"state":"final","attempt":"fixture-verifier"}, "proof_ref":"proofs/1.json"
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

#[cfg(unix)]
#[test]
fn symlinked_os_temp_supports_gate_and_run_storage() {
    let root = scratch("temp-alias");
    let physical = root.join("physical");
    omgs::platform::create_private_dir_new(&physical).unwrap();
    let alias = root.join("alias");
    std::os::unix::fs::symlink(&physical, &alias).unwrap();
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "registered_gate_executes_immutable_head_and_ignores_advisory_artifacts",
            "--nocapture",
        ])
        .env("TMPDIR", &alias)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", output(&out));
    // Installation and explicit run destinations retain strict admission.
    assert!(omgs::platform::create_private_tree(&alias.join("explicit-run")).is_err());
    std::fs::remove_dir_all(root).unwrap();
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
    let original = read(&run.join("findings.json"));
    let mut draft = original.clone();
    draft["findings"][0]["verification"]["state"] = json!("draft");
    write(&run.join("findings.json"), &draft);
    let advisory = gate(&root, &repo, &base, &base, Some(&run), 1);
    assert!(!output(&advisory).contains("advisory: confirmed finding"));
    write(&run.join("findings.json"), &original);
    omgs::attempts::append(
        &run,
        omgs::attempts::Event::Stop {
            id: "fixture-verifier".into(),
            actor: "host".into(),
            kind: "policy".into(),
            reason: "Observed stop".into(),
            artifacts: vec!["findings.json".into()],
            disposition: "quarantined".into(),
        },
    )
    .unwrap();
    let advisory = gate(&root, &repo, &base, &base, Some(&run), 1);
    assert!(!output(&advisory).contains("advisory: confirmed finding"));
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
    let modified = gate(&root, &repo, &base, &fixed, None, 0);
    assert!(output(&modified).contains(&format!(
        "registered gate test modified in head: {} {}",
        t.id, t.test
    )));
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
        for name in [
            "PIPELINE.md",
            "PROOF-CONTRACT.md",
            "PROOF-RECIPES.md",
            "POLICY-AND-GATE.md",
            "BUDGETS-AND-ROUTING.md",
            "EXECUTION-SAFETY.md",
            "SETUP.md",
            "HANDOFF-AND-PROGRESS.md",
            "DECISION-RULES.md",
        ] {
            assert_eq!(
                std::fs::read(installed.join(name)).unwrap(),
                std::fs::read(source.join(name)).unwrap(),
                "{name}"
            );
        }
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
    let launched = copied_binary_output(
        Command::new(&executable)
            .current_dir(&root)
            .args(["setup", "--install-skills"])
            .env("HOME", &home)
            .env("USERPROFILE", &home),
    );
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
        .env("OMGS_HOME", repo.parent().unwrap().join("data"))
        .env("RUSTUP_AUTO_INSTALL", "0")
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
        assert!(
            output(&o).contains("includes are blocked"),
            "{}",
            output(&o)
        );
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
    let excluded = cli(
        &root.join("home"),
        &["stage", "--run", run.to_str().unwrap()],
    );
    assert!(excluded.status.success(), "{}", output(&excluded));
    assert!(output(&excluded).contains("excluded omgs-"));
    assert!(std::fs::read(run.join("proposed-tests.patch"))
        .unwrap()
        .is_empty());
    assert!(std::fs::read(run.join("policy.patch")).unwrap().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn changed_registered_test_is_visible_before_sandbox_in_both_modes() {
    let root = scratch("changed-test-warning");
    let repo = repo(&root);
    let t = registered();
    for mode in [Mode::Gate, Mode::Advisory] {
        std::fs::write(repo.join(&t.test), test_source(true)).unwrap();
        let base = commit_policy(
            &repo,
            &Policy {
                mode,
                gate_tests: vec![t.clone()],
                ..Default::default()
            },
        );
        std::fs::write(repo.join(&t.test), test_source(false)).unwrap();
        let head = commit_policy(&repo, &Policy::default());
        let run_gate = |head: &str| {
            Command::new(env!("CARGO_BIN_EXE_omgs"))
                .args([
                    "gate",
                    "--target",
                    repo.to_str().unwrap(),
                    "--base",
                    &base,
                    "--head",
                    head,
                ])
                .env("OMGS_HOME", root.join("data"))
                // Internal scratch must not consult ambient OS temp settings.
                .env("TMPDIR", root.join("missing-temp"))
                .env("TEMP", root.join("missing-temp"))
                .env("TMP", root.join("missing-temp"))
                .env("OMGS_MXC_EXEC", root.join("missing-executor"))
                .output()
                .unwrap()
        };
        let warning = format!("registered gate test modified in head: {} {}", t.id, t.test);
        let changed = run_gate(&head);
        assert!(output(&changed).contains(&warning), "{}", output(&changed));
        assert_eq!(
            changed.status.code(),
            Some(if mode == Mode::Gate { 3 } else { 0 })
        );
        std::fs::remove_file(repo.join(&t.test)).unwrap();
        let deleted = commit_policy(&repo, &Policy::default());
        let deleted = run_gate(&deleted);
        assert!(output(&deleted).contains(&warning), "{}", output(&deleted));
        assert!(output(&deleted).contains("registered test missing from head"));
        assert_eq!(
            deleted.status.code(),
            Some(if mode == Mode::Gate { 3 } else { 0 })
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn pre_policy_run_cannot_seed_a_fix_run() {
    let root = scratch("legacy-fix");
    let repo = repo(&root);
    let legacy = root.join("legacy");
    omgs::platform::private_dir(&legacy).unwrap();
    let mut metadata: Value =
        serde_json::from_str(include_str!("fixtures/pre-policy-run.json")).unwrap();
    metadata["target"] = json!(repo.to_str().unwrap());
    omgs::runmeta::write_atomic(&legacy.join("run-metadata.json"), &metadata.to_string()).unwrap();
    let before = std::fs::read(legacy.join("run-metadata.json")).unwrap();
    let child = root.join("fix");
    let result = cli(
        &root,
        &[
            "audit",
            "init",
            "--target",
            repo.to_str().unwrap(),
            "--out",
            child.to_str().unwrap(),
            "--fix-of",
            legacy.to_str().unwrap(),
            "--no-sensors",
        ],
    );
    assert_eq!(result.status.code(), Some(2), "{}", output(&result));
    assert!(output(&result).contains("trusted policy record unavailable"));
    assert!(output(&result).contains("docs/policy-workflow.md#pre-policy-runs"));
    assert!(!child.exists());
    assert_eq!(
        std::fs::read(legacy.join("run-metadata.json")).unwrap(),
        before
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn bundle_build_rejects_literal_backslashes_and_linked_root() {
    use std::os::unix::fs::symlink;
    let root = scratch("bundle-build-paths");
    let builder = root.join("bundle-builder");
    let built = Command::new("rustc")
        .args(["--edition=2021", "build.rs", "-o"])
        .arg(&builder)
        .env("RUSTUP_AUTO_INSTALL", "0")
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", output(&built));
    let skill = root.join("skill");
    std::fs::create_dir(&skill).unwrap();
    let build = || {
        Command::new(&builder)
            .env("CARGO_MANIFEST_DIR", &root)
            .env("OUT_DIR", &root)
            .output()
            .unwrap()
    };
    for name in ["a\\b", "..\\escape", "C:prefix"] {
        let path = skill.join(name);
        std::fs::write(&path, "content").unwrap();
        assert!(!build().status.success());
        assert!(!root.join("skill.rs").exists());
        std::fs::remove_file(path).unwrap();
    }
    std::fs::rename(&skill, root.join("real-skill")).unwrap();
    symlink(root.join("real-skill"), &skill).unwrap();
    assert!(!build().status.success());
    assert!(!root.join("skill.rs").exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn default_setup_ignores_adjacent_and_checkout_sidecars() {
    let root = scratch("embedded-sidecars");
    let home = root.join("home");
    std::fs::create_dir_all(home.join(".agents")).unwrap();
    let binary_dir = root.join("bin");
    let checkout = root.join("checkout");
    for dir in [&binary_dir, &checkout] {
        std::fs::create_dir_all(dir.join("skill")).unwrap();
        std::fs::write(dir.join("skill/SKILL.md"), "sidecar content").unwrap();
    }
    let binary = binary_dir.join(if cfg!(windows) { "omgs.exe" } else { "omgs" });
    std::fs::copy(env!("CARGO_BIN_EXE_omgs"), &binary).unwrap();
    let result = copied_binary_output(
        Command::new(&binary)
            .args(["setup", "--install-skills"])
            .current_dir(&checkout)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("RUSTUP_AUTO_INSTALL", "0"),
    );
    assert!(result.status.success(), "{}", output(&result));
    let installed = home.join(".agents/skills").join(omgs::setup::SKILL_NAME);
    assert!(installed.join("HANDOFF-AND-PROGRESS.md").is_file());
    assert!(!installed.join("HANDOFF.md").exists());
    for (path, bytes) in omgs::setup::BUNDLED {
        assert_eq!(std::fs::read(installed.join(path)).unwrap(), *bytes);
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn policy_stage_admits_valid_proof_and_reports_invalid_proof_once() {
    let root = scratch("partial-policy-stage");
    let repo = repo(&root);
    let base = commit_policy(&repo, &Policy::default());
    let run = root.join("run");
    assert!(init(&root, &repo, &run, Some(&base)).status.success());
    evidence(&run, &repo);
    let mut findings = read(&run.join("findings.json"));
    let mut invalid = findings["findings"][0].clone();
    invalid["entry_point"] = json!("GET /invalid");
    invalid["fingerprint"] = json!(omgs::fingerprint(
        invalid["attack_class"].as_str().unwrap(),
        invalid["entry_point"].as_str().unwrap(),
        invalid["sink"].as_str().unwrap(),
        invalid["boundary"].as_str().unwrap(),
    ));
    invalid["proof_ref"] = json!("proofs/2.json");
    let invalid_id = invalid["fingerprint"].as_str().unwrap().to_owned();
    let mut invalid_proof = read(&run.join("proofs/1.json"));
    invalid_proof["n"] = json!(2);
    invalid_proof["finding"] = invalid["fingerprint"].clone();
    invalid_proof["test"] = json!("tests/security/invalid.ts");
    invalid_proof["cleanup_complete"] = json!(false);
    write(&run.join("proofs/2.json"), &invalid_proof);
    findings["findings"].as_array_mut().unwrap().push(invalid);
    write(&run.join("findings.json"), &findings);
    assert!(
        omgs::model::validate(&omgs::shape::findings(&findings.to_string()).unwrap()).is_empty()
    );
    let staged = cli(
        &root.join("home"),
        &["stage", "--run", run.to_str().unwrap()],
    );
    assert!(staged.status.success(), "{}", output(&staged));
    assert_eq!(
        output(&staged)
            .matches(&format!("excluded {invalid_id}:"))
            .count(),
        1
    );
    assert!(output(&staged).contains("did not finish cleanly"));
    let tests = std::fs::read_to_string(run.join("proposed-tests.patch")).unwrap();
    let policy = std::fs::read_to_string(run.join("policy.patch")).unwrap();
    assert!(policy.ends_with(&tests));
    for patch in [&tests, &policy] {
        assert_eq!(
            patch
                .matches("diff --git \"a/tests/security/x.test.ts\"")
                .count(),
            1
        );
        assert!(!patch.contains(&invalid_id));
        assert!(!patch.contains("GET /invalid"));
        assert!(!patch.contains("tests/security/invalid.ts"));
    }
    for name in ["proposed-tests.patch", "policy.patch"] {
        check_patch(&repo, &run.join(name));
    }
    std::fs::remove_dir_all(root).unwrap();
}

fn proposal_preserves_draft(name: &str, crlf_policy: bool, executable: bool) {
    let root = scratch(name);
    let repo = repo(&root);
    git(&repo, &["config", "core.autocrlf", "false"]);
    let p = Policy::default();
    let mut base = commit_policy(&repo, &p);
    if crlf_policy {
        std::fs::write(
            repo.join(policy::PATH),
            policy::text(&p).unwrap().replace("\n", "\r\n"),
        )
        .unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-m", "Retain CRLF policy"]);
        base = git(&repo, &["rev-parse", "HEAD"]);
    }
    let original_policy = std::fs::read(repo.join(policy::PATH)).unwrap();
    let run = root.join("run");
    assert!(init(&root, &repo, &run, Some(&base)).status.success());
    evidence(&run, &repo);
    let draft = run.join("proofs/1/test-draft");
    let bytes = if executable {
        b"#!/bin/sh\nprintf 'fixture boundary failure\\n'\nexit 1\n".to_vec()
    } else {
        b"throw new Error('fixture boundary failure');\r\n// retained CRLF\r\n".to_vec()
    };
    std::fs::write(&draft, &bytes).unwrap();
    #[cfg(unix)]
    if executable {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&draft, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut proof = read(&run.join("proofs/1.json"));
    proof["test_sha256"] = json!(omgs::sha256::digest(&bytes));
    write(&run.join("proofs/1.json"), &proof);
    let staged = cli(
        &root.join("home"),
        &["stage", "--run", run.to_str().unwrap()],
    );
    assert!(staged.status.success(), "{}", output(&staged));
    assert!(!output(&staged).contains("excluded"), "{}", output(&staged));
    let test = proof["test"].as_str().unwrap();
    // Apply each export to a separate copy, keeping the audited target untouched.
    for name in ["proposed-tests.patch", "policy.patch"] {
        let copy = root.join(name);
        std::fs::create_dir_all(copy.join(".omgs")).unwrap();
        git(&copy, &["init"]);
        git(&copy, &["config", "core.autocrlf", "false"]);
        std::fs::write(copy.join(policy::PATH), &original_policy).unwrap();
        let patch = run.join(name);
        check_patch(&copy, &patch);
        apply_patch(&copy, &patch, false);
        let applied = std::fs::read(copy.join(test)).unwrap();
        assert_eq!(applied, bytes);
        assert_eq!(
            omgs::sha256::digest(&applied),
            proof["test_sha256"].as_str().unwrap()
        );
        if name == "policy.patch" {
            let mut expected = p.clone();
            expected.gate_tests =
                policy::parse(&std::fs::read_to_string(copy.join(policy::PATH)).unwrap())
                    .unwrap()
                    .gate_tests;
            assert_eq!(expected.gate_tests.len(), 1);
            assert_eq!(
                std::fs::read(copy.join(policy::PATH)).unwrap(),
                policy::text(&expected).unwrap().as_bytes()
            );
        }
        #[cfg(unix)]
        if executable {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(copy.join(test))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111,
                0o111
            );
            assert!(std::fs::read_to_string(&patch)
                .unwrap()
                .contains("new file mode 100755"));
        }
    }
    assert_eq!(
        std::fs::read(repo.join(policy::PATH)).unwrap(),
        original_policy
    );
    assert!(!repo.join(test).exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn policy_proposal_preserves_crlf_test_bytes_and_digest() {
    proposal_preserves_draft("crlf-test-proposal", false, false);
}

#[test]
fn policy_proposal_applies_over_existing_crlf_policy() {
    proposal_preserves_draft("crlf-policy-proposal", true, false);
}

#[cfg(unix)]
#[test]
fn policy_proposal_retains_executable_draft_mode() {
    proposal_preserves_draft("executable-proposal", false, true);
}

fn report_intent(root: &Path, run: &Path) -> (Output, String) {
    let out = cli(
        &root.join("home"),
        &[
            "report",
            "--findings",
            run.join("findings.json").to_str().unwrap(),
            "--out",
            run.to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "{}", output(&out));
    let text = std::fs::read_to_string(run.join("REPORT.md")).unwrap();
    (out, text)
}

#[test]
fn report_intent_uses_committed_policy_and_rejects_untrusted_provenance() {
    let root = scratch("report-intent-trust");
    let repo = repo(&root);
    let mut p = Policy::default();
    p.accepted_intent.push(policy::AcceptedIntent {
        id: omgs::intent::library().questions[0].id.clone(),
        answer: "GENUINE OWNER ACCEPTANCE".into(),
        scope: "repo".into(),
        source: "maintainer".into(),
    });
    let base = commit_policy(&repo, &p);
    let run = root.join("run");
    let initialized = init(&root, &repo, &run, Some(&base));
    assert!(initialized.status.success(), "{}", output(&initialized));
    write(
        &run.join("findings.json"),
        &json!({"findings": [{
            "title": "Intent trust fixture", "verdict": "needs_validation",
            "fingerprint": omgs::fingerprint("access", "GET /x", "resource", "owner"),
            "hunted_by": "reviewer", "verified_by": "verifier",
            "proof_tier": "traced", "attack_class": "access",
            "entry_point": "GET /x", "sink": "resource", "boundary": "owner",
            "location": {"path": "main.rs", "line": 1},
            "intent_id": p.accepted_intent[0].id
        }]}),
    );
    let original = read(&run.join(omgs::runmeta::FILE));
    let answers = read(&run.join("intent-answers.json"));
    // There are no independently recorded answers. Trusted base acceptance renders.
    let (_, text) = report_intent(&root, &run);
    assert!(text.contains("GENUINE OWNER ACCEPTANCE"));

    // Change every internally checked snapshot field, including its digest.
    // A self-consistent run-local snapshot still cannot authorize an answer.
    let mut fabricated = p.accepted_intent[0].clone();
    fabricated.answer = "FABRICATED OWNER ACCEPTANCE".into();
    fabricated.scope = "main.rs".into();
    p.accepted_intent.push(fabricated);
    let raw = policy::text(&p).unwrap();
    let mut forged = original.clone();
    forged["policy"]["policy"] = serde_json::to_value(&p).unwrap();
    forged["policy"]["original"] = json!(raw);
    forged["policy"]["sha256"] = json!(omgs::sha256::digest(raw.as_bytes()));
    write(&run.join(omgs::runmeta::FILE), &forged);
    let mut forged_answers = answers.clone();
    let mut fabricated_answer = answers["answers"][0].clone();
    fabricated_answer["answer"] = json!("FABRICATED OWNER ACCEPTANCE");
    fabricated_answer["scope"] = json!("main.rs");
    forged_answers["answers"]
        .as_array_mut()
        .unwrap()
        .push(fabricated_answer);
    write(&run.join("intent-answers.json"), &forged_answers);
    let (out, text) = report_intent(&root, &run);
    assert!(!text.contains("FABRICATED OWNER ACCEPTANCE"));
    assert!(text.contains("GENUINE OWNER ACCEPTANCE"));
    assert!(output(&out).contains("ignoring snapshot"));

    // A real, different commit and its matching digest cannot replace the
    // reviewer-selected base, even if the entire snapshot is self-consistent.
    let substituted = commit_policy(&repo, &p);
    forged["policy"] =
        serde_json::to_value(policy::load_base(&repo, Some(&substituted)).unwrap()).unwrap();
    write(&run.join(omgs::runmeta::FILE), &forged);
    let (out, text) = report_intent(&root, &run);
    assert!(!text.contains("FABRICATED OWNER ACCEPTANCE"));
    assert!(text.contains("GENUINE OWNER ACCEPTANCE"));
    assert!(output(&out).contains("ignoring snapshot"));

    // Editing policy contents alone cannot change the base-derived answers.
    forged["policy"]["sha256"] = original["policy"]["sha256"].clone();
    write(&run.join(omgs::runmeta::FILE), &forged);
    let (_, text) = report_intent(&root, &run);
    assert!(!text.contains("FABRICATED OWNER ACCEPTANCE"));

    write(&run.join("intent-answers.json"), &answers);
    let mut broken = original.clone();
    broken["policy"]["base_commit"] = json!("0000000000000000000000000000000000000000");
    write(&run.join(omgs::runmeta::FILE), &broken);
    let (out, text) = report_intent(&root, &run);
    assert!(text.contains("GENUINE OWNER ACCEPTANCE"));
    assert!(output(&out).contains("ignoring snapshot"));

    // A later init against another base cannot retarget this run's record.
    let later = root.join("later-run");
    assert!(init(&root, &repo, &later, Some(&substituted))
        .status
        .success());
    let (_, text) = report_intent(&root, &run);
    assert!(!text.contains("FABRICATED OWNER ACCEPTANCE"));

    write(&run.join(omgs::runmeta::FILE), &original);
    let store = omgs::intent::answers_file(&root.join("home/omgs-data"), &repo);
    std::fs::create_dir_all(store.parent().unwrap()).unwrap();
    for target in ["", root.to_str().unwrap()] {
        let mut invalid = answers.clone();
        invalid["target"] = json!(target);
        write(&store, &invalid);
        let (out, text) = report_intent(&root, &run);
        assert!(!text.contains("GENUINE OWNER ACCEPTANCE"));
        assert!(output(&out).contains("store for this path belongs to another target"));
    }
    std::fs::remove_dir_all(root).unwrap();
}

fn fix_init(root: &Path, repo: &Path, parent: &Path, child: &Path) -> Output {
    cli(
        &root.join("home"),
        &[
            "audit",
            "init",
            "--target",
            repo.to_str().unwrap(),
            "--out",
            child.to_str().unwrap(),
            "--fix-of",
            parent.to_str().unwrap(),
            "--no-sensors",
        ],
    )
}

#[test]
fn fix_runs_ignore_edited_parent_policy_and_rederive_all_settings() {
    let root = scratch("fix-policy-trust");
    let repo = repo(&root);
    let mut p = Policy {
        mode: Mode::Gate,
        persona: Some("inheritor".into()),
        excluded_paths: vec!["excluded".into()],
        ..Policy::default()
    };
    p.suppressions.push(policy::Suppression {
        fingerprint: omgs::fingerprint("access", "GET /x", "resource", "owner"),
        reason: "Owner reviewed".into(),
        expires_unix: omgs::runmeta::now_unix() + 3600,
    });
    p.gate_tests.push(registered());
    let base = commit_policy(&repo, &p);
    let run = root.join("run");
    assert!(init(&root, &repo, &run, Some(&base)).status.success());
    let original = read(&run.join(omgs::runmeta::FILE));
    for (i, (key, value)) in [
        ("excluded_paths", json!(["main.rs"])),
        ("mode", json!("advisory")),
        ("persona", json!("builder")),
    ]
    .into_iter()
    .enumerate()
    {
        // Preserve family registration between children, editing only policy.
        let mut edited = read(&run.join(omgs::runmeta::FILE));
        edited["policy"]["policy"][key] = value;
        let forged = edited["policy"]["policy"].to_string();
        edited["policy"]["original"] = json!(forged);
        edited["policy"]["sha256"] = json!(omgs::sha256::digest(forged.as_bytes()));
        write(&run.join(omgs::runmeta::FILE), &edited);
        let child = root.join(format!("fix-{i}"));
        let out = fix_init(&root, &repo, &run, &child);
        assert!(out.status.success(), "{}", output(&out));
        assert!(output(&out).contains("ignoring snapshot"));
        let inherited = read(&child.join(omgs::runmeta::FILE));
        assert_eq!(inherited["policy"], original["policy"]);
        assert_eq!(inherited["mode"], "gate");
        assert_eq!(inherited["persona"], "inheritor");
        assert_eq!(
            inherited["files_first_party"],
            original["files_first_party"]
        );
        let ledger = read(&child.join("coverage-ledger.json"));
        assert!(!ledger.to_string().contains("policy:excluded:main.rs"));
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn no_base_cli_settings_survive_authenticated_fix_inheritance() {
    let root = scratch("fix-no-base-settings");
    let repo = repo(&root);
    // Cover no --base as well as a base commit without a policy blob.
    let base = git(&repo, &["rev-parse", "HEAD"]);
    for (i, base) in [None, Some(base.as_str())].into_iter().enumerate() {
        let run = root.join(format!("run-{i}"));
        let mut args = vec![
            "audit",
            "init",
            "--target",
            repo.to_str().unwrap(),
            "--out",
            run.to_str().unwrap(),
            "--no-sensors",
            "--mode",
            "gate",
            "--persona",
            "team",
            "--budget",
            "37",
        ];
        if let Some(base) = base {
            args.extend(["--base", base]);
        }
        let out = cli(&root.join("home"), &args);
        assert!(out.status.success(), "{}", output(&out));
        let original = read(&run.join(omgs::runmeta::FILE));
        let mut edited = original.clone();
        edited["policy"] = json!({"base_commit": "HEAD", "policy": {"persona": "builder"}});
        write(&run.join(omgs::runmeta::FILE), &edited);
        let child = root.join(format!("fix-{i}"));
        let out = fix_init(&root, &repo, &run, &child);
        assert!(out.status.success(), "{}", output(&out));
        let inherited = read(&child.join(omgs::runmeta::FILE));
        assert_eq!(inherited["policy"], original["policy"]);
        assert_eq!(inherited["mode"], "gate");
        assert_eq!(inherited["persona"], "team");
        assert_eq!(inherited["budget_agent_calls"], 37);
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn policy_patch_ignores_fabricated_snapshot_and_applies_to_real_base() {
    let root = scratch("proposal-trusted-base");
    let repo = repo(&root);
    let p = Policy::default();
    let base = commit_policy(&repo, &p);
    let run = root.join("run");
    assert!(init(&root, &repo, &run, Some(&base)).status.success());
    let answer = cli(
        &root.join("home"),
        &[
            "intent",
            "answer",
            "--target",
            repo.to_str().unwrap(),
            "--id",
            &omgs::intent::library().questions[0].id,
            "--answer",
            "Owner confirmed",
            "--source",
            "owner",
        ],
    );
    assert!(answer.status.success(), "{}", output(&answer));
    let propose = || {
        cli(
            &root.join("home"),
            &["intent", "propose", "--run", run.to_str().unwrap()],
        )
    };
    let out = propose();
    assert!(out.status.success(), "{}", output(&out));
    let expected = std::fs::read(run.join("policy.patch")).unwrap();
    let mut forged = p.clone();
    forged.mode = Mode::Gate;
    forged.excluded_paths.push("main.rs".into());
    let other = commit_policy(&repo, &forged);
    let mut edited = read(&run.join(omgs::runmeta::FILE));
    edited["policy"] =
        serde_json::to_value(policy::load_base(&repo, Some(&other)).unwrap()).unwrap();
    write(&run.join(omgs::runmeta::FILE), &edited);
    let out = propose();
    assert!(out.status.success(), "{}", output(&out));
    assert!(output(&out).contains("ignoring snapshot"));
    assert_eq!(std::fs::read(run.join("policy.patch")).unwrap(), expected);
    git(&repo, &["checkout", &base]);
    check_patch(&repo, &run.join("policy.patch"));
    apply_patch(&repo, &run.join("policy.patch"), false);
    let applied = read(&repo.join(policy::PATH));
    assert_eq!(applied["mode"], "advisory");
    assert_eq!(applied["excluded_paths"], json!([]));
    assert_eq!(applied["accepted_intent"][0]["answer"], "Owner confirmed");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn trusted_policy_requires_immutable_base_and_matching_run_target_and_digest() {
    let root = scratch("policy-provenance-validation");
    let repo = repo(&root);
    let base = commit_policy(&repo, &Policy::default());
    let run = root.join("run");
    assert!(init(&root, &repo, &run, Some(&base)).status.success());
    let store = root.join("home/omgs-data/intent");
    let entries: Vec<_> = std::fs::read_dir(&store)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(entries.len(), 1);
    let record_path = &entries[0];
    assert!(!record_path.starts_with(&run));
    assert!(!record_path.starts_with(&repo));
    let original = read(record_path);
    assert_eq!(original["base_commit"], base);
    assert_eq!(
        original["sha256"],
        omgs::sha256::digest(&std::fs::read(repo.join(policy::PATH)).unwrap())
    );
    for (i, (key, value, reason)) in [
        ("base_commit", json!("HEAD"), "full immutable commit SHA"),
        (
            "base_commit",
            json!(&base[..12]),
            "full immutable commit SHA",
        ),
        (
            "sha256",
            json!("0".repeat(64)),
            "differs from trusted record",
        ),
        ("target", json!(root), "another target or run"),
        ("run", json!(root), "another target or run"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut edited = original.clone();
        edited[key] = value;
        write(record_path, &edited);
        let child = root.join(format!("refused-{i}"));
        let out = fix_init(&root, &repo, &run, &child);
        assert!(!out.status.success(), "{}", output(&out));
        assert!(output(&out).contains(reason), "{}", output(&out));
        assert!(!child.exists());
    }
    std::fs::remove_file(record_path).unwrap();
    // A fully intact run snapshot cannot substitute for absent trusted provenance.
    let child = root.join("missing-provenance");
    let out = fix_init(&root, &repo, &run, &child);
    assert!(!out.status.success());
    assert!(output(&out).contains("trusted policy record unavailable"));
    assert!(!child.exists());
    std::fs::remove_dir_all(root).unwrap();
}

fn provenance_record(root: &Path) -> PathBuf {
    let entries: Vec<_> = std::fs::read_dir(root.join("home/omgs-data/intent"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(entries.len(), 1);
    entries[0].clone()
}

#[test]
fn provenance_is_exclusive_and_new_output_paths_have_fresh_generations() {
    let root = scratch("exclusive-provenance");
    let repo = repo(&root);
    let base = commit_policy(&repo, &Policy::default());
    let run = root.join("run");
    assert!(init(&root, &repo, &run, Some(&base)).status.success());
    let path = provenance_record(&root);
    let record = std::fs::read(&path).unwrap();
    let mut changed = Policy::default();
    changed.excluded_paths.push("main.rs".into());
    let other = commit_policy(&repo, &changed);
    // Empty the run without retiring its trusted record, keeping its inode.
    for entry in std::fs::read_dir(&run).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            std::fs::remove_dir_all(path).unwrap();
        } else {
            std::fs::remove_file(path).unwrap();
        }
    }
    let out = init(&root, &repo, &run, Some(&other));
    assert!(!out.status.success(), "{}", output(&out));
    assert!(
        output(&out).contains("re-initialize into a new output path"),
        "{}",
        output(&out)
    );
    assert_eq!(std::fs::read(&path).unwrap(), record);
    let fresh = root.join("fresh");
    let out = init(&root, &repo, &fresh, Some(&other));
    assert!(out.status.success(), "{}", output(&out));
    assert_ne!(
        std::fs::read(run.join(".omgs-claim")).unwrap(),
        std::fs::read(fresh.join(".omgs-claim")).unwrap()
    );
    assert_eq!(
        read(&fresh.join(omgs::runmeta::FILE))["policy"]["base_commit"],
        other
    );
    let out = fix_init(&root, &repo, &fresh, &root.join("fresh-child"));
    assert!(out.status.success(), "{}", output(&out));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn provenance_refuses_replaced_directory_even_with_copied_run_identity() {
    let root = scratch("replacement-provenance");
    let repo = repo(&root);
    let base = commit_policy(&repo, &Policy::default());
    let run = root.join("run");
    assert!(init(&root, &repo, &run, Some(&base)).status.success());
    let metadata = read(&run.join(omgs::runmeta::FILE));
    let generation = std::fs::read(run.join(".omgs-claim")).unwrap();
    let moved = root.join("moved");
    std::fs::rename(&run, &moved).unwrap();
    omgs::platform::create_private_dir(&run).unwrap();
    write(&run.join(omgs::runmeta::FILE), &metadata);
    for claim in ["0".repeat(64).into_bytes(), generation] {
        omgs::runmeta::write_atomic_bytes(&run.join(".omgs-claim"), &claim).unwrap();
        let out = fix_init(&root, &repo, &run, &root.join("child"));
        assert!(!out.status.success(), "{}", output(&out));
        assert!(
            output(&out).contains("generation or directory identity mismatch"),
            "{}",
            output(&out)
        );
        assert!(!root.join("child").exists());
    }
    std::fs::remove_dir_all(&run).unwrap();
    std::fs::rename(&moved, &run).unwrap();
    let out = fix_init(&root, &repo, &run, &root.join("child"));
    assert!(out.status.success(), "{}", output(&out));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn fix_budget_uses_trusted_family_cap_despite_edited_parent_metadata() {
    let root = scratch("trusted-family-cap");
    let repo = repo(&root);
    let base = commit_policy(
        &repo,
        &Policy {
            budget: Some(10),
            ..Policy::default()
        },
    );
    for (i, base) in [Some(base.as_str()), None].into_iter().enumerate() {
        let run = root.join(format!("run-{i}"));
        let out = cli(
            &root.join("home"),
            &[
                "audit",
                "init",
                "--target",
                repo.to_str().unwrap(),
                "--out",
                run.to_str().unwrap(),
                "--no-sensors",
                "--budget",
                "10",
            ]
            .into_iter()
            .chain(base.into_iter().flat_map(|b| ["--base", b]))
            .collect::<Vec<_>>(),
        );
        assert!(out.status.success(), "{}", output(&out));
        for (j, cap) in [json!(1000), json!(1), Value::Null].into_iter().enumerate() {
            let mut edited = read(&run.join(omgs::runmeta::FILE));
            if cap.is_null() {
                edited.as_object_mut().unwrap().remove("budget_agent_calls");
            } else {
                edited["budget_agent_calls"] = cap;
            }
            edited["agent_calls_used"] = json!(3);
            write(&run.join(omgs::runmeta::FILE), &edited);
            let child = root.join(format!("fix-{i}-{j}"));
            let out = fix_init(&root, &repo, &run, &child);
            assert!(out.status.success(), "{}", output(&out));
            let meta = read(&child.join(omgs::runmeta::FILE));
            assert_eq!(meta["budget_agent_calls"], 7);
            if base.is_none() {
                assert_eq!(meta["policy"]["policy"]["budget"], 7);
            }
            // Descendants still use the original family's authenticated cap.
            let out = fix_init(&root, &repo, &child, &root.join(format!("next-{i}-{j}")));
            assert!(out.status.success(), "{}", output(&out));
        }
    }
    let run = root.join("uncapped");
    assert!(init(&root, &repo, &run, None).status.success());
    let mut edited = read(&run.join(omgs::runmeta::FILE));
    edited["budget_agent_calls"] = json!(1000);
    write(&run.join(omgs::runmeta::FILE), &edited);
    let child = root.join("uncapped-child");
    let out = fix_init(&root, &repo, &run, &child);
    assert!(out.status.success(), "{}", output(&out));
    let meta = read(&child.join(omgs::runmeta::FILE));
    assert!(meta.get("budget_agent_calls").is_none());
    assert!(meta["policy"]["policy"]["budget"].is_null());
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(windows)]
fn icacls(path: &Path, args: &[&str]) {
    let out = Command::new("icacls.exe")
        .arg(path)
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", output(&out));
}

#[cfg(windows)]
#[test]
fn provenance_refuses_writable_store_on_creation_and_use() {
    let root = scratch("provenance-store-dacl");
    let repo = repo(&root);
    let run = root.join("run");
    let store = root.join("home/omgs-data/intent");
    omgs::platform::create_private_tree(&store).unwrap();
    icacls(&store, &["/grant", "*S-1-1-0:(OI)(CI)(W)"]);
    let out = init(&root, &repo, &run, None);
    assert!(!out.status.success(), "{}", output(&out));
    assert!(
        output(&out).contains("writable by another principal"),
        "{}",
        output(&out)
    );
    assert!(!run.exists());
    icacls(&store, &["/remove:g", "*S-1-1-0"]);
    assert!(init(&root, &repo, &run, None).status.success());
    icacls(&store, &["/grant", "*S-1-1-0:(W)"]);
    let out = fix_init(&root, &repo, &run, &root.join("child"));
    assert!(!out.status.success(), "{}", output(&out));
    assert!(
        output(&out).contains("owner-private intent store"),
        "{}",
        output(&out)
    );
    assert!(!root.join("child").exists());
    assert!(omgs::platform::check_private_dir(&store).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(windows)]
#[test]
fn provenance_refuses_record_with_unsafe_dacl_on_every_read() {
    let root = scratch("provenance-record-dacl");
    let repo = repo(&root);
    let run = root.join("run");
    assert!(init(&root, &repo, &run, None).status.success());
    let record = provenance_record(&root);
    for sid in ["*S-1-1-0:(W)", "*S-1-5-32-545:(W)"] {
        icacls(&record, &["/grant", sid]);
        let out = fix_init(&root, &repo, &run, &root.join("child"));
        assert!(!out.status.success(), "{}", output(&out));
        assert!(
            output(&out).contains("writable by another principal"),
            "{}",
            output(&out)
        );
        assert!(!root.join("child").exists());
        icacls(&record, &["/remove:g", sid.split(':').next().unwrap()]);
    }
    assert!(fix_init(&root, &repo, &run, &root.join("child"))
        .status
        .success());
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(windows)]
#[test]
fn provenance_refuses_foreign_owned_record_on_every_read() {
    let root = scratch("provenance-record-owner");
    let repo = repo(&root);
    let run = root.join("run");
    assert!(init(&root, &repo, &run, None).status.success());
    let record = provenance_record(&root);
    let user = Command::new("whoami.exe").output().unwrap();
    assert!(user.status.success());
    let user = String::from_utf8(user.stdout).unwrap();
    // Administrators is an assignable owner for these elevated Windows test hosts,
    // but it is not the current user's SID. Keep the private DACL intact.
    icacls(&record, &["/setowner", "*S-1-5-32-544"]);
    let out = fix_init(&root, &repo, &run, &root.join("child"));
    icacls(&record, &["/setowner", user.trim()]);
    assert!(!out.status.success(), "{}", output(&out));
    assert!(
        output(&out).contains("owned by the current user"),
        "{}",
        output(&out)
    );
    assert!(!root.join("child").exists());
    assert!(fix_init(&root, &repo, &run, &root.join("child"))
        .status
        .success());
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn interrupted_gate_export_cleans_scratch_for_sigint_and_sigterm() {
    use std::time::{Duration, Instant};
    for signal in [libc::SIGINT, libc::SIGTERM] {
        let root = scratch(&format!("export-interrupt-{signal}"));
        let repo = repo(&root);
        // Many immutable paths give the parent a deterministic observation
        // window while export is still in progress, without running target code.
        for n in 0..500 {
            std::fs::write(repo.join(format!("file-{n:04}")), vec![b'x'; 1024]).unwrap();
        }
        let head = commit_policy(
            &repo,
            &Policy {
                mode: Mode::Gate,
                gate_tests: vec![registered()],
                ..Policy::default()
            },
        );
        let data = root.join("data");
        let mut child = Command::new(env!("CARGO_BIN_EXE_omgs"))
            .args([
                "gate",
                "--target",
                repo.to_str().unwrap(),
                "--base",
                &head,
                "--head",
                &head,
            ])
            .env("OMGS_HOME", &data)
            .env("RUSTUP_AUTO_INSTALL", "0")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let start = Instant::now();
        loop {
            let exporting = std::fs::read_dir(&data).ok().is_some_and(|mut dirs| {
                dirs.any(|e| {
                    let path = e.unwrap().path().join("payload/head");
                    // At least one materialized blob proves interruption occurs
                    // after the guard and scratch creation, during HEAD export.
                    std::fs::read_dir(path).is_ok_and(|mut files| files.next().is_some())
                })
            });
            if exporting {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(15),
                "export did not start"
            );
            assert!(
                child.try_wait().unwrap().is_none(),
                "gate exited before export"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        // SAFETY: send only the requested signal to this test's live child.
        assert_eq!(unsafe { libc::kill(child.id() as i32, signal) }, 0);
        let start = Instant::now();
        while child.try_wait().unwrap().is_none() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "interrupted gate did not exit"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(3), "{}", output(&out));
        assert!(output(&out).contains("interrupted"), "{}", output(&out));
        assert!(!std::fs::read_dir(data).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("omgs-gate-")));
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn repeated_blob_export_cap_blocks_with_exit_three_without_expanding_data() {
    use std::io::Write;
    use std::process::Stdio;
    let root = scratch("repeated-blob-export-cap");
    let repo = repo(&root);
    let base = commit_policy(
        &repo,
        &Policy {
            mode: Mode::Gate,
            gate_tests: vec![registered()],
            ..Policy::default()
        },
    );
    std::fs::write(repo.join("blob"), vec![b'x'; 1 << 20]).unwrap();
    git(&repo, &["add", "blob"]);
    let blob = git(&repo, &["rev-parse", ":blob"]);
    // Thousands of index entries share one object. No expanded 4 GiB fixture
    // is written to the checkout or scratch.
    let mut child = Command::new("git")
        .current_dir(&repo)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "update-index",
            "--index-info",
        ])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    for n in 0..4097 {
        writeln!(input, "100644 {blob}\tfile-{n:04}").unwrap();
    }
    drop(input);
    assert!(child.wait().unwrap().success());
    let tree = git(&repo, &["write-tree"]);
    let head = git(
        &repo,
        &["commit-tree", &tree, "-p", &base, "-m", "Repeated fixture"],
    );
    git(&repo, &["update-ref", "HEAD", &head]);
    let out = gate(&root, &repo, &base, &head, None, 3);
    assert!(
        output(&out).contains("gate export byte cap exceeded (limit 4294967296 bytes)"),
        "{}",
        output(&out)
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn recovery_storage_failure_obeys_valid_base_advisory_mode() {
    let root = scratch("recovery-advisory");
    let repo = repo(&root);
    let advisory = commit_policy(&repo, &Policy::default());
    let unavailable = root.join("unavailable");
    std::fs::write(&unavailable, b"not a directory").unwrap();
    let invoke = |base: &str| {
        Command::new(env!("CARGO_BIN_EXE_omgs"))
            .args(["gate", "--target"])
            .arg(&repo)
            .args(["--base", base, "--head", base])
            .env("OMGS_HOME", &unavailable)
            .env("RUSTUP_AUTO_INSTALL", "0")
            .output()
            .unwrap()
    };
    let out = invoke(&advisory);
    assert_eq!(out.status.code(), Some(0), "{}", output(&out));
    assert!(output(&out).contains("advisory: would block (infrastructure)"));
    let strict = commit_policy(
        &repo,
        &Policy {
            mode: Mode::Gate,
            ..Default::default()
        },
    );
    let out = invoke(&strict);
    assert_eq!(out.status.code(), Some(3), "{}", output(&out));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn gate_export_caps_are_bounded_and_only_base_policy_can_raise_them() {
    let root = scratch("gate-limits");
    let repo = repo(&root);
    let mut p = Policy {
        mode: Mode::Gate,
        gate_tests: vec![registered()],
        gate_limits: Some(policy::GateLimits {
            bytes: 1,
            entries: 200_000,
        }),
        ..Default::default()
    };
    std::fs::write(repo.join(&p.gate_tests[0].test), test_source(false)).unwrap();
    let base = commit_policy(&repo, &p);
    p.gate_limits = Some(policy::GateLimits {
        bytes: 8 << 30,
        entries: 300_000,
    });
    let head = commit_policy(&repo, &p);
    let out = gate(&root, &repo, &base, &head, None, 3);
    assert!(
        output(&out).contains("byte cap exceeded (limit 1 bytes)"),
        "{}",
        output(&out)
    );
    let parsed = policy::parse(&policy::text(&p).unwrap()).unwrap();
    assert_eq!(parsed.gate_limits.unwrap().bytes, 8 << 30);
    for (bytes, entries) in [
        (0, 1),
        (policy::GateLimits::MAX_BYTES + 1, 1),
        (1, 0),
        (1, policy::GateLimits::MAX_ENTRIES + 1),
    ] {
        p.gate_limits = Some(policy::GateLimits { bytes, entries });
        assert!(policy::text(&p)
            .unwrap_err()
            .contains("gate_limits requires"));
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn deep_gate_exports_are_cleaned_and_unsupported_depth_exits_three() {
    let root = scratch("deep-gate-export");
    let repo = repo(&root);
    let base = commit_policy(
        &repo,
        &Policy {
            mode: Mode::Gate,
            gate_tests: vec![registered()],
            ..Policy::default()
        },
    );
    let blob = git(&repo, &["rev-parse", "HEAD:main.rs"]);
    for depth in [
        130,
        omgs::scratch::GATE_EXPORT_DEPTH,
        omgs::scratch::GATE_EXPORT_DEPTH + 1,
    ] {
        git(&repo, &["read-tree", &base]);
        let path = format!("{}raw", "d/".repeat(depth));
        git(
            &repo,
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                "100644",
                &blob,
                &path,
            ],
        );
        let tree = git(&repo, &["write-tree"]);
        let head = git(
            &repo,
            &["commit-tree", &tree, "-p", &base, "-m", "Deep fixture"],
        );
        git(&repo, &["update-ref", "HEAD", &head]);
        let out = gate(&root, &repo, &base, &head, None, 3);
        if depth <= omgs::scratch::GATE_EXPORT_DEPTH {
            // This check runs only after all blobs have been exported. The
            // deliberately missing registration avoids needing a sandbox here.
            assert!(
                output(&out).contains("registered test missing from head"),
                "{}",
                output(&out)
            );
        } else {
            assert!(
                output(&out).contains("gate export depth cap exceeded (limit 256 directories)"),
                "{}",
                output(&out)
            );
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

fn completed_verifier_fixture(run: &std::path::Path, identity: &str) {
    for value in [
        serde_json::json!({"event":"start","id":"fixture-verifier","role":"verifier","identity":identity,"context":"fixture-context","inputs":["synthetic-input"],"outputs":["findings.json"],"isolation":"procedural"}),
        serde_json::json!({"event":"complete","id":"fixture-verifier","actor":"fixture-host","reason":"Synthetic completion fixture"}),
    ] {
        omgs::attempts::append(run, serde_json::from_value(value).unwrap()).unwrap();
    }
}
