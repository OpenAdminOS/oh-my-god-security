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
fn gate(root: &Path, run: &Path, code: i32) -> Output {
    let o = cli(
        &root.join("home"),
        &["gate", "--run", run.to_str().unwrap()],
    );
    assert_eq!(o.status.code(), Some(code), "{}", output(&o));
    o
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
fn base_policy_controls_gate_despite_head_and_worktree_changes() {
    let root = scratch("base");
    let repo = repo(&root);
    let p = Policy {
        mode: Mode::Gate,
        ..Default::default()
    };
    let base = commit_policy(&repo, &p);
    let mut head = p.clone();
    head.mode = Mode::Advisory;
    head.severity_threshold = omgs::model::Severity::Critical;
    commit_policy(&repo, &head);
    let run = root.join("run");
    let out = init(&root, &repo, &run, Some(&base));
    assert!(out.status.success(), "{}", output(&out));
    evidence(&run, &repo);
    gate(&root, &run, 1);
    let m = read(&run.join("run-metadata.json"));
    assert_eq!(m["policy"]["base_commit"], base);
    assert_eq!(m["policy"]["source"], format!("{base}:.omgs/policy.json"));
    assert_eq!(
        m["policy"]["sha256"],
        omgs::sha256::digest(policy::text(&p).unwrap().as_bytes())
    );
    std::fs::write(repo.join(policy::PATH), "malformed head").unwrap();
    gate(&root, &run, 1);
    let out = cli(
        &root.join("home"),
        &[
            "audit",
            "init",
            "--target",
            repo.to_str().unwrap(),
            "--base",
            &base,
            "--mode",
            "advisory",
            "--out",
            root.join("override").to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
    assert!(!root.join("override").exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn head_only_policy_is_ignored_and_defaults_are_recorded() {
    let root = scratch("absent");
    let repo = repo(&root);
    let base = git(&repo, &["rev-parse", "HEAD"]);
    commit_policy(
        &repo,
        &Policy {
            mode: Mode::Gate,
            ..Default::default()
        },
    );
    let run = root.join("run");
    assert!(init(&root, &repo, &run, Some(&base)).status.success());
    evidence(&run, &repo);
    assert!(output(&gate(&root, &run, 0)).contains("would block"));
    assert_eq!(
        read(&run.join("run-metadata.json"))["policy"]["source"],
        "defaults:no-base-policy"
    );
    assert!(
        !init(&root, &repo, &root.join("missing"), Some("does-not-exist"))
            .status
            .success()
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn gate_exit_codes_threshold_suppression_contracts_and_invalid_runs() {
    let root = scratch("exits");
    let repo = repo(&root);
    let fp = "omgs-d7c7756a1f68ec92";
    for (name, mode, severity, suppress, expiry, code) in [
        ("at", Mode::Gate, "high", false, None, 1),
        ("above", Mode::Gate, "critical", false, None, 1),
        ("below", Mode::Gate, "medium", false, None, 0),
        ("suppressed", Mode::Gate, "high", true, None, 0),
        ("future", Mode::Gate, "high", true, Some(u64::MAX), 0),
        ("expired", Mode::Gate, "high", true, Some(0), 1),
        ("advisory", Mode::Advisory, "high", false, None, 0),
    ] {
        let mut p = Policy {
            mode,
            ..Default::default()
        };
        if suppress {
            p.suppressions.push(policy::Suppression {
                fingerprint: fp.into(),
                reason: "Owner accepted".into(),
                expires_unix: expiry,
            });
        }
        let base = commit_policy(&repo, &p);
        let run = root.join(name);
        assert!(init(&root, &repo, &run, Some(&base)).status.success());
        evidence(&run, &repo);
        let mut findings = read(&run.join("findings.json"));
        findings["findings"][0]["severity"] = json!(severity);
        write(&run.join("findings.json"), &findings);
        let out = gate(&root, &run, code);
        if mode == Mode::Advisory {
            assert!(output(&out).contains("would block"));
        }
    }
    let run = root.join("at");
    let proof_path = run.join("proofs/1.json");
    let proof = read(&proof_path);
    for pointer in [
        "/contract/boundary_marker_seen",
        "/contract/authorized_control_seen",
        "/command_started",
        "/command_finished",
        "/cleanup_complete",
    ] {
        let mut bad = proof.clone();
        *bad.pointer_mut(pointer).unwrap() = json!(false);
        write(&proof_path, &bad);
        assert!(output(&gate(&root, &run, 0)).contains("ineligible"));
    }
    let mut bad = proof.clone();
    bad["schema"] = json!("omgs-proof/1");
    write(&proof_path, &bad);
    gate(&root, &run, 0);
    std::fs::remove_file(&proof_path).unwrap();
    gate(&root, &run, 0);
    let mut findings = read(&run.join("findings.json"));
    findings["findings"][0]
        .as_object_mut()
        .unwrap()
        .remove("proof_ref");
    write(&run.join("findings.json"), &findings);
    gate(&root, &run, 0);
    std::fs::write(run.join("findings.json"), "{}").unwrap();
    gate(&root, &run, 3);
    let mut m = read(&run.join("run-metadata.json"));
    m["policy"]["sha256"] = json!("0".repeat(64));
    write(&run.join("run-metadata.json"), &m);
    gate(&root, &run, 3);
    gate(&root, &root.join("missing-run"), 3);
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
    let suppression = json!({"fingerprint":"omgs-0123456789abcdef","reason":"accepted"});
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
    std::fs::create_dir_all(bootstrap.join("skill")).unwrap();
    std::fs::write(bootstrap.join("skill/SKILL.md"), "bundled").unwrap();
    assert_eq!(
        omgs::setup::source(None, &bootstrap.join("omgs"), &root).unwrap(),
        bootstrap.join("skill")
    );
    std::fs::create_dir_all(bootstrap.join("bin")).unwrap();
    assert_eq!(
        omgs::setup::source(None, &bootstrap.join("bin/omgs"), &root).unwrap(),
        bootstrap.join("skill")
    );
    let executable = bootstrap.join(if cfg!(windows) { "omgs.exe" } else { "omgs" });
    std::fs::copy(env!("CARGO_BIN_EXE_omgs"), &executable).unwrap();
    std::fs::copy(source.join("SKILL.md"), bootstrap.join("skill/SKILL.md")).unwrap();
    let launched = Command::new(executable)
        .current_dir(&root)
        .args(["setup", "--install-skills"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    assert!(launched.status.success(), "{}", output(&launched));
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
