//! Synthetic regression cases for field workflow failures. No campaign inputs.
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Fixture {
    root: PathBuf,
    run: PathBuf,
    target: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = omgs::platform::temp_root().unwrap().join(format!(
            "omgs-pilot-{}",
            omgs::platform::random_nonce().unwrap()
        ));
        omgs::platform::create_private_tree(&root).unwrap();
        let target = root.join("target");
        omgs::platform::create_private_dir(&target).unwrap();
        std::fs::write(
            target.join("sample.ps1"),
            "function Get-Dummy { param($InputValue) $InputValue }",
        )
        .unwrap();
        let run = root.join("run");
        let f = Self { root, run, target };
        let out = f.cli(&[
            "audit",
            "init",
            "--target",
            f.target.to_str().unwrap(),
            "--out",
            f.run.to_str().unwrap(),
            "--persona",
            "inheritor",
            "--budget",
            "12",
            "--no-sensors",
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        f
    }
    fn cli(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_omgs"))
            .env("OMGS_HOME", self.root.join("state"))
            .env("RUSTUP_AUTO_INSTALL", "0")
            .args(args)
            .output()
            .unwrap()
    }
    fn put(&self, name: &str, v: Value) {
        omgs::runmeta::write_atomic(&self.run.join(name), &v.to_string()).unwrap();
    }
    fn run_str(&self) -> &str {
        self.run.to_str().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn read(path: impl AsRef<Path>) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn refusal_without_models_survives_report_metadata_and_index() {
    let f = Fixture::new();
    let out = f.cli(&[
        "route",
        "--run",
        f.run_str(),
        "--role",
        "verifier",
        "--refused",
        "fixed-test-provider",
        "--reason",
        "provider eligibility block",
    ]);
    assert_eq!(out.status.code(), Some(1));
    let m = read(f.run.join("run-metadata.json"));
    assert_eq!(m["reroutes"][0]["from"], "fixed-test-provider");
    assert!(m["blocker_events"][0]["reason"]
        .as_str()
        .unwrap()
        .contains("provider eligibility block"));
    let out = f.cli(&[
        "report",
        "--findings",
        f.run.join("findings.json").to_str().unwrap(),
        "--out",
        f.run_str(),
        "--model",
        "verifier=fixed-test-provider",
        "--model",
        "hunter=other-test-provider",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for name in ["REPORT.md", "REPORT.html"] {
        let text = std::fs::read_to_string(f.run.join(name)).unwrap();
        assert!(text.contains("provider eligibility block"));
        assert!(text.contains("fixed-test-provider"));
        assert!(text.contains("other-test-provider"));
    }
    assert_eq!(
        read(f.run.join("run-metadata.json"))["run_status"],
        "partial"
    );
    assert!(!omgs::runmeta::is_complete(&f.run));
    let summary = omgs::batch::summarize(
        &omgs::batch::BatchRun {
            url: "https://example.com/team/synthetic".into(),
            run_dir: Some(f.run_str().into()),
            ..Default::default()
        },
        &f.root,
    )
    .unwrap();
    for text in [
        omgs::batch::render_index_markdown(std::slice::from_ref(&summary)),
        omgs::batch::render_index_html(&[summary]),
    ] {
        assert!(text.contains("provider eligibility block"));
    }
}
#[test]
fn call_charging_budget_handoff_and_status_are_consistent() {
    let f = Fixture::new();
    let out = f.cli(&["budget", "--run", f.run_str(), "--charge-calls", "5"]);
    assert!(out.status.success());
    let a: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(a["calls_and_proofs_used"], 5);
    assert_eq!(a["remaining"], 7);
    assert!(!f
        .cli(&["budget", "--run", f.run_str(), "--charge-calls", "8"])
        .status
        .success());
    let out = f.cli(&[
        "status",
        "--run",
        f.run_str(),
        "--stage",
        "extra",
        "--state",
        "done",
    ]);
    assert!(out.status.success());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("unknown"));
    let progress = read(f.run.join("pipeline-status.json"));
    let stage = progress["stages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "extra")
        .unwrap();
    assert!(stage.get("started_ms").is_none());
    let handoff = omgs::handoff::build(&f.run, &Default::default(), None).unwrap();
    assert!(omgs::handoff::markdown(&handoff).contains("5 used of 12; 7 remaining"));
    let out = f.cli(&[
        "report",
        "--findings",
        f.run.join("findings.json").to_str().unwrap(),
        "--out",
        f.run_str(),
        "--agent-calls",
        "4",
    ]);
    assert!(!out.status.success());
}
#[test]
fn strict_role_handoffs_and_atomic_disposition_ingest() {
    let f = Fixture::new();
    f.put("coverage-ledger.json", json!({"units":[{"id":"function:dummy","surface":"sample.ps1:Get-Dummy","attack_classes":["credential_handling"],"status":"planned"}]}));
    f.put("dispositions-test.json", json!({"hunter":"test-hunter", "units":[{"unit_id":"function:dummy", "disposition":"candidate", "evidence":["synthetic-fingerprint"], "note":"handed to verification"}]}));
    let input = f.run.join("dispositions-test.json");
    assert!(f
        .cli(&["validate", "--dispositions", input.to_str().unwrap()])
        .status
        .success());
    assert!(f
        .cli(&[
            "ledger",
            "ingest",
            "--ledger",
            f.run.join("coverage-ledger.json").to_str().unwrap(),
            "--dispositions",
            input.to_str().unwrap()
        ])
        .status
        .success());
    assert_eq!(
        read(f.run.join("coverage-ledger.json"))["units"][0]["status"],
        "covered"
    );
    assert!(
        omgs::adjudication::dispositions(r#"{"hunter":"x","units":[["id","covered",[],""]]}"#)
            .is_err()
    );
    assert!(omgs::adjudication::candidates(r#"{"candidates":[]}"#).is_ok());
    assert!(omgs::adjudication::candidates(
        r#"{"candidates":[{"fingerprint":"omgs-0000000000000000"}]}"#
    )
    .is_err());
    assert!(omgs::adjudication::parse(
        r#"{"evaluator":"x","source_ref":"a","decisions":[],"gaps":[],"gaps":[]}"#
    )
    .is_err());
    assert!(omgs::adjudication::parse(
        r#"{"evaluator":"x","source_ref":"a","decisions":[[]],"gaps":[]}"#
    )
    .is_err());
}
#[test]
fn evaluator_missing_verdict_independence_and_report_limits() {
    let f = Fixture::new();
    let mut findings =
        omgs::shape::findings(include_str!("fixtures/report-run/findings.json")).unwrap();
    for (i, r) in findings.findings.iter_mut().enumerate() {
        r.fingerprint = format!("omgs-{i:016x}");
    }
    assert!(omgs::adjudication::check(&f.run, &findings)
        .unwrap()
        .iter()
        .any(|s| s.contains("missing")));
    let source = read(f.run.join("run-metadata.json"))["source_ref"].clone();
    f.put("evaluation.json", json!({"evaluator":"independent-test-context","source_ref":source,"decisions":[],"gaps":["synthetic transport not tested"]}));
    let gaps = omgs::adjudication::check(&f.run, &findings).unwrap();
    assert_eq!(
        gaps.iter()
            .filter(|g| g.contains("verdict missing"))
            .count(),
        findings.findings.len()
    );
    let decisions: Vec<_> = findings.findings.iter().map(|r| json!({"fingerprint":r.fingerprint,"decision":"uphold","reason":"independent trace","evidence":[],"required_changes":[]})).collect();
    f.put("evaluation.json", json!({"evaluator":"red-1","source_ref":source,"decisions":decisions,"gaps":["synthetic transport not tested"]}));
    assert!(omgs::adjudication::check(&f.run, &findings)
        .unwrap()
        .iter()
        .any(|g| g.contains("independent")));
    let mut a = read(f.run.join("architecture.json"));
    a["unexamined"] = json!(["synthetic external boundary"]);
    f.put("architecture.json", a);
    let lines = omgs::adjudication::report_lines(&f.run, &findings).unwrap();
    for html in [false, true] {
        let text = omgs::adjudication::render_lines(&lines, html);
        assert!(text.contains("synthetic transport not tested"));
        assert!(text.contains("synthetic external boundary"));
        assert!(text.contains("red-1"));
    }
}
#[test]
fn evaluator_identity_uses_unicode_normalization_and_bounded_reads() {
    let f = Fixture::new();
    let mut findings =
        omgs::shape::findings(include_str!("fixtures/report-run/findings.json")).unwrap();
    for (i, r) in findings.findings.iter_mut().enumerate() {
        r.fingerprint = format!("omgs-{i:016x}");
        r.verified_by = Some("VÉRIFIER".into());
    }
    let source = read(f.run.join("run-metadata.json"))["source_ref"].clone();
    let decisions: Vec<_> = findings.findings.iter().map(|r| json!({"fingerprint":r.fingerprint,"decision":"uphold","reason":"independent trace","evidence":[],"required_changes":[]})).collect();
    let evaluation =
        json!({"evaluator":" vérifier ","source_ref":source,"decisions":decisions,"gaps":[]});
    f.put("evaluation.json", evaluation.clone());
    assert!(omgs::adjudication::check(&f.run, &findings)
        .unwrap()
        .iter()
        .any(|g| g.contains("independent")));
    let path = f.run.join("evaluation.json");
    // Oversized evidence is refused rather than read without a bound.
    std::fs::write(&path, " ".repeat((8 << 20) + 1)).unwrap();
    assert!(omgs::adjudication::check(&f.run, &findings).is_err());
    #[cfg(unix)]
    {
        // A link to an outside evaluation is not adjudication evidence.
        let outside = f.run.parent().unwrap().join("outside-evaluation.json");
        std::fs::write(&outside, evaluation.to_string()).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&outside, &path).unwrap();
        assert!(omgs::adjudication::check(&f.run, &findings).is_err());
        // A dangling link is an error, not an absent evaluation.
        std::fs::remove_file(&outside).unwrap();
        assert!(omgs::adjudication::check(&f.run, &findings).is_err());
        // A FIFO must fail instead of blocking forever without a writer.
        std::fs::remove_file(&path).unwrap();
        let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(omgs::adjudication::check(&f.run, &findings).is_err());
        std::fs::remove_file(&path).unwrap();
    }
}

#[test]
fn command_help_and_intent_aliases_are_actionable() {
    let f = Fixture::new();
    for cmd in [
        "review", "batch", "prove", "critic", "validate", "route", "budget",
    ] {
        let o = f.cli(&[cmd, "--help"]);
        assert!(o.status.success());
        let text = String::from_utf8_lossy(&o.stderr);
        assert!(text.contains(&format!("omgs {cmd}")));
        assert!(!text.contains("omgs doctor"));
    }
    let one = f.cli(&["intent", "list", "--attack-class", "identity-binding"]);
    let two = f.cli(&["intent", "list", "--attack-class", "identity_binding"]);
    assert_eq!(one.stdout, two.stdout);
    assert!(!one.stdout.is_empty());
    assert_eq!(
        f.cli(&["intent", "list", "--attack-class", "not-a-class"])
            .status
            .code(),
        Some(2)
    );
}
#[test]
fn sensor_zero_hits_discloses_coverage_and_deduplicates_gaps() {
    let sensors = omgs::shape::sensors(&json!({"tools_run":["gitleaks"],"tools_unavailable":["semgrep"],"hits":[],"gaps":["semgrep: not present on PATH"]}).to_string()).unwrap();
    for html in [false, true] {
        let text = omgs::report::sensor_section(Some(&sensors), html);
        assert!(text.contains("Zero hits"));
        assert!(text.contains("no history scan"));
        assert_eq!(text.matches("semgrep:").count(), 1);
    }
    assert!(omgs::sensors::GITLEAKS_CONFIG.contains("omgs-azure-functions-url-key"));
    assert!(omgs::sensors::GITLEAKS_CONFIG.contains("useDefault = true"));
}

fn repo(path: &Path, origin: Option<&str>) {
    for args in [
        vec!["init"],
        vec!["add", "."],
        vec![
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-m",
            "Synthetic fixture",
        ],
    ] {
        let output = Command::new("git")
            .arg("-C")
            .arg(path)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    if let Some(origin) = origin {
        assert!(Command::new("git")
            .arg("-C")
            .arg(path)
            .args(["remote", "add", "origin", origin])
            .status()
            .unwrap()
            .success());
    }
}
#[test]
fn review_and_batch_reuse_explicit_clone_root_with_persona_and_exact_commit() {
    let f = Fixture::new();
    let clones = f.root.join("clones");
    let target = clones.join("example.com/team/synthetic");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("code.ps1"), "function Get-Dummy { 'fixture' }").unwrap();
    repo(&target, Some("https://example.com/team/synthetic"));
    let out_dir = f.root.join("explicit-run");
    let out = f.cli(&[
        "review",
        "--repo-url",
        "https://example.com/team/synthetic",
        "--clone-root",
        clones.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
        "--persona",
        "inheritor",
        "--no-sensors",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta = read(out_dir.join("run-metadata.json"));
    assert_eq!(meta["persona"], "inheritor");
    assert_eq!(meta["budget_profile"], "deep");
    assert!(meta.get("profile").is_none());
    assert_eq!(meta["execution_profile"], "standard");
    assert!(
        read(out_dir.join("coverage-ledger.json"))["units"][0]["note"]
            .as_str()
            .unwrap()
            .contains("Mapping placeholder")
    );
    assert_eq!(meta["source_ref"].as_str().unwrap().len(), 40);
    assert_eq!(
        read(out_dir.join("architecture.json"))["source_ref"],
        meta["source_ref"]
    );
    let list = f.root.join("repos.txt");
    std::fs::write(&list, "https://example.com/team/synthetic\n").unwrap();
    let batch = f.root.join("batch");
    let out = f.cli(&[
        "batch",
        "init",
        "--list",
        list.to_str().unwrap(),
        "--out",
        batch.to_str().unwrap(),
        "--clone-root",
        clones.to_str().unwrap(),
        "--persona",
        "builder",
        "--no-sensors",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        read(batch.join("example.com/team/synthetic/run-metadata.json"))["persona"],
        "builder"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(batch.join(".omgs-batch-claim"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(out_dir.join(".omgs-claim"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn gitleaks_rule_matches_synthetic_plain_and_encoded_url_keys_when_available() {
    let Some(exe) = omgs::platform::which("gitleaks") else {
        eprintln!("gitleaks not installed; rule configuration is checked separately");
        return;
    };
    let f = Fixture::new();
    let source = f.root.join("secret-fixtures");
    std::fs::create_dir(&source).unwrap();
    let dummy = "AbCd0123456789_test_dummy_key_never_issued_0123456789";
    std::fs::write(
        source.join("plain.ps1"),
        format!("$u='https://synthetic.azurewebsites.net/api/test?code={dummy}=='\n"),
    )
    .unwrap();
    std::fs::write(
        source.join("encoded.ps1"),
        format!("$u='https://synthetic.azurewebsites.net/api/test?a=b&code={dummy}%3D%3D'\n"),
    )
    .unwrap();
    let config = f.root.join("gitleaks.toml");
    std::fs::write(&config, omgs::sensors::GITLEAKS_CONFIG).unwrap();
    let report = f.root.join("gitleaks.json");
    let out = Command::new(exe)
        .args(["detect", "--no-git", "--source"])
        .arg(&source)
        .arg("--config")
        .arg(&config)
        .args(["--report-format", "json", "--report-path"])
        .arg(&report)
        .arg("--redact")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let hits = read(report);
    let hits = hits.as_array().unwrap();
    for name in ["plain.ps1", "encoded.ps1"] {
        assert!(hits
            .iter()
            .any(|h| h["RuleID"] == "omgs-azure-functions-url-key"
                && h["File"].as_str().unwrap().ends_with(name)));
    }
}

#[test]
fn guidance_preserves_probe_and_artifact_rules() {
    for (guide, phrase) in [
        (
            include_str!("../skill/HUNTING.md"),
            "Hunters must not execute any probe",
        ),
        (include_str!("../skill/EXECUTION-SAFETY.md"), "umask 077"),
        (
            include_str!("../skill/PROOF-CONTRACT.md"),
            "record.exit_code: 1",
        ),
        (
            include_str!("../skill/RECONNAISSANCE.md"),
            "FunctionsToExport",
        ),
        (
            include_str!("../skill/PROOF-RECIPES.md"),
            "CertificateRequest.Create",
        ),
        (
            include_str!("../skill/POLICY-AND-GATE.md"),
            "owner-review `policy.patch`",
        ),
    ] {
        assert!(guide.contains(phrase), "missing {phrase}");
    }
}

#[test]
fn unresolved_evaluator_leads_keep_delivery_partial() {
    let f = Fixture::new();
    for (id, role, identity) in [
        ("verifier-round", "verifier", "verifier"),
        ("evaluation-round", "evaluator", "independent"),
    ] {
        for event in [
            json!({"event":"start","id":id,"role":role,"identity":identity,"context":id,"inputs":["synthetic-input"],"outputs":["synthetic-output"],"isolation":"procedural"}),
            json!({"event":"complete","id":id,"actor":"fixture-host","reason":"Synthetic finished review"}),
        ] {
            omgs::attempts::append(&f.run, serde_json::from_value(event).unwrap()).unwrap();
        }
    }
    let source = read(f.run.join("run-metadata.json"))["source_ref"].clone();
    let mut ledger = read(f.run.join("coverage-ledger.json"));
    for u in ledger["units"].as_array_mut().unwrap() {
        u["status"] = "covered".into();
        u["evidence"] = json!(["sample.ps1"]);
    }
    let parent_classes = ledger["units"][0]["attack_classes"].clone();
    ledger["units"][0]["child_units"] = json!(["function:dummy"]);
    ledger["units"].as_array_mut().unwrap().push(json!({"id":"function:dummy","surface":"sample.ps1:Get-Dummy","attack_classes":parent_classes,"status":"covered","evidence":["sample.ps1"],"scope_paths":[{"path":"sample.ps1","operation":"Get-Dummy"}]}));
    ledger["units"].as_array_mut().unwrap().push(json!({"id":"late-lead","surface":"sample.ps1","attack_classes":[],"status":"blocked","note":"provider block"}));
    f.put("coverage-ledger.json", ledger.clone());
    f.put("candidates-empty.json", json!({"candidates":[]}));
    f.put("evaluation.json",json!({"evaluator":"independent","attempt":"evaluation-round","source_ref":source,"decisions":[],"gaps":[],"leads":[{"unit_id":"late-lead","reason":"new boundary"}]}));
    for status in ["blocked", "deferred"] {
        ledger["units"].as_array_mut().unwrap().last_mut().unwrap()["status"] = status.into();
        f.put("coverage-ledger.json", ledger.clone());
        let critic = omgs::critic::critique_run(&f.run).unwrap();
        assert!(critic
            .gaps
            .iter()
            .any(|g| g.contains(&format!("late-lead remains {status}"))));
        let out = f.cli(&[
            "report",
            "--findings",
            f.run.join("findings.json").to_str().unwrap(),
            "--out",
            f.run_str(),
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            read(f.run.join("run-metadata.json"))["run_status"],
            "partial"
        );
    }
    let lead = ledger["units"].as_array_mut().unwrap().last_mut().unwrap();
    lead["status"] = "out_of_scope".into();
    lead["note"] = "Outside the reviewed source revision".into();
    f.put("coverage-ledger.json", ledger.clone());
    assert!(omgs::critic::critique_run(&f.run)
        .unwrap()
        .gaps
        .iter()
        .any(|g| g.contains("requires scope evidence")));
    ledger["units"].as_array_mut().unwrap().last_mut().unwrap()["evidence"] = json!(["sample.ps1"]);
    f.put("coverage-ledger.json", ledger);
    assert!(omgs::critic::critique_run(&f.run).unwrap().passed());
}

#[test]
fn successful_fallback_keeps_refusal_details_in_both_indexes() {
    let f = Fixture::new();
    let models = f.root.join("models.json");
    omgs::runmeta::write_atomic(
        &models,
        &json!({"roles":{"verifier":["primarytest","fallbacktest"]}}).to_string(),
    )
    .unwrap();
    let out = f.cli(&[
        "route",
        "--run",
        f.run_str(),
        "--role",
        "verifier",
        "--refused",
        "primarytest",
        "--reason",
        "synthetic eligibility block",
        "--models",
        models.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let summary = omgs::batch::summarize(
        &omgs::batch::BatchRun {
            url: "https://example.com/team/synthetic".into(),
            run_dir: Some(f.run_str().into()),
            ..Default::default()
        },
        &f.root,
    )
    .unwrap();
    assert!(!summary.blockers.iter().any(|b| b.contains("eligibility")));
    assert_eq!(summary.refusal_events[0].from, "primarytest");
    for text in [
        omgs::batch::render_index_markdown(std::slice::from_ref(&summary)),
        omgs::batch::render_index_html(&[summary]),
    ] {
        for expected in [
            "primarytest",
            "fallbacktest",
            "synthetic eligibility block",
            "verifier",
        ] {
            assert!(text.contains(expected), "{text}");
        }
    }
}

#[test]
fn batch_accepts_a_fresh_relative_clone_root_before_attempting_git() {
    let f = Fixture::new();
    let list = f.root.join("relative-repos.txt");
    std::fs::write(&list, "https://example.com/team/synthetic\n").unwrap();
    let empty_bin = f.root.join("empty-bin");
    std::fs::create_dir(&empty_bin).unwrap();
    let out_dir = f.root.join("relative-runs");
    let out = Command::new(env!("CARGO_BIN_EXE_omgs"))
        .current_dir(&f.root)
        .env("OMGS_HOME", f.root.join("state"))
        .env("PATH", empty_bin)
        .args([
            "batch",
            "init",
            "--list",
            list.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
            "--clone-root",
            "fresh-clones",
            "--no-sensors",
        ])
        .output()
        .unwrap();
    // Git is deliberately absent so this reaches clone handling without network.
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let batch = read(out_dir.join("batch.json"));
    let target = Path::new(batch["runs"][0]["target"].as_str().unwrap());
    assert!(target.is_absolute());
    assert!(target.ends_with(Path::new("fresh-clones").join("example.com/team/synthetic")));
    assert!(batch["runs"][0]["error"]
        .as_str()
        .unwrap()
        .contains("git not found"));
    assert!(!f.root.join("fresh-clones").exists());
}

#[test]
fn hostile_saved_text_is_inert_at_terminal_and_report_boundaries() {
    let f = Fixture::new();
    let hostile = "hostile\u{1b}[2J\n::error::forged <img src=x onerror=alert(1)> [x](javascript:alert(1)) @mention";
    let check_terminal = |out: &Output| {
        for bytes in [&out.stdout, &out.stderr] {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains('\u{1b}'), "{text:?}");
            assert!(
                !text.lines().any(|l| l.starts_with("::error::")),
                "{text:?}"
            );
        }
    };
    let models = f.root.join("models.json");
    omgs::runmeta::write_atomic(&models, &json!({"roles":{hostile:["test"]}}).to_string()).unwrap();
    let out = f.cli(&[
        "route",
        "--run",
        f.run_str(),
        "--role",
        "verifier",
        "--models",
        models.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("hostile"));
    check_terminal(&out);

    let ledger = f.run.join("coverage-ledger.json");
    for args in [
        vec![
            "ledger",
            "add",
            "--ledger",
            ledger.to_str().unwrap(),
            "--unit",
            hostile,
            "--surface",
            "sample.ps1",
            "--note",
            hostile,
        ],
        vec![
            "ledger",
            "set",
            "--ledger",
            ledger.to_str().unwrap(),
            "--unit",
            hostile,
            "--status",
            "planned",
            "--note",
            hostile,
        ],
        vec!["ledger", "list", "--ledger", ledger.to_str().unwrap()],
    ] {
        let out = f.cli(&args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("hostile"));
        check_terminal(&out);
    }

    let summary = omgs::batch::RunSummary {
        url: hostile.into(),
        report_href: Some(format!("javascript:{hostile}/REPORT.html")),
        state: hostile.into(),
        budget: Some(hostile.into()),
        blockers: vec![hostile.into()],
        ..Default::default()
    };
    for text in [
        omgs::batch::render_index_markdown(std::slice::from_ref(&summary)),
        omgs::batch::render_index_html(&[summary]),
    ] {
        assert!(!text.contains('\u{1b}'));
        assert!(!text.lines().any(|l| l.starts_with("::error::")));
        assert!(!text.contains("<img src=x"));
        assert!(!text.contains("href=\"javascript:"));
    }

    let mut findings: Value =
        serde_json::from_str(include_str!("fixtures/report-run/findings.json")).unwrap();
    findings["findings"].as_array_mut().unwrap().truncate(1);
    findings["findings"][0]["title"] = hostile.into();
    findings["findings"][0]["fingerprint"] =
        omgs::fingerprint("export_scope", "GET /orders/:id", "orders.load", "tenant").into();
    let input = f.root.join("findings.json");
    omgs::runmeta::write_atomic(&input, &findings.to_string()).unwrap();
    let report = f.root.join("report");
    let out = f.cli(&[
        "report",
        "--findings",
        input.to_str().unwrap(),
        "--out",
        report.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    check_terminal(&out);
    for name in [
        "REPORT.md",
        "REPORT.html",
        "HANDOFF.md",
        "handoff.json",
        "findings.sarif.json",
    ] {
        let text = std::fs::read_to_string(report.join(name)).unwrap();
        assert!(!text.contains('\u{1b}'), "{name}");
        assert!(!text.lines().any(|l| l.starts_with("::error::")), "{name}");
        if name.ends_with(".json") {
            // JSON retains data faithfully, never creates HTML or Markdown nodes.
            serde_json::from_str::<Value>(&text).unwrap();
        } else {
            assert!(!text.contains("<img src=x"), "{name}");
            assert!(!text.contains("href=\"javascript:"), "{name}");
            if name.ends_with(".md") {
                assert!(!text.contains("[x](javascript:"), "{name}");
                assert!(!text.contains(" @mention"), "{name}");
            }
        }
    }
}

#[test]
fn terminal_controls_are_escaped_for_every_class() {
    let f = Fixture::new();
    let controls = "\u{1}\u{85}\u{202e}\u{2066}\u{2067}\u{2068}\u{2069}\u{200b}\u{200c}\u{200d}\u{200e}\u{200f}\u{feff}\u{2028}\u{2029}\u{e0001}";
    for c in controls.chars() {
        assert!(!omgs::platform::escape_controls(&c.to_string()).contains(c));
        let models = f.root.join("models.json");
        std::fs::write(
            &models,
            json!({"roles":{format!("hostile{c}"):["test"]}}).to_string(),
        )
        .unwrap();
        let out = f.cli(&[
            "route",
            "--run",
            f.run_str(),
            "--role",
            "verifier",
            "--models",
            models.to_str().unwrap(),
        ]);
        assert_eq!(out.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&out.stderr).contains(c));
        assert!(String::from_utf8_lossy(&out.stderr).contains("hostile"));
    }
}

#[test]
fn failed_stage_preserves_existing_proposal_and_policy_directory() {
    let f = Fixture::new();
    let proposal = f.run.join("proposed-tests.patch");
    std::fs::write(&proposal, "previous proposal\n").unwrap();
    let policy = f.run.join("policy.patch");
    std::fs::create_dir(&policy).unwrap();
    std::fs::write(policy.join("retained"), "previous policy").unwrap();
    let meta = std::fs::read(f.run.join("run-metadata.json")).unwrap();
    let out = f.cli(&["stage", "--run", f.run_str()]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(proposal).unwrap(),
        "previous proposal\n"
    );
    assert!(policy.is_dir());
    assert_eq!(
        std::fs::read_to_string(policy.join("retained")).unwrap(),
        "previous policy"
    );
    assert_eq!(
        std::fs::read(f.run.join("run-metadata.json")).unwrap(),
        meta
    );
}

#[test]
fn output_paths_reject_controls_before_creating_artifacts() {
    let f = Fixture::new();
    for c in ['\t', '\u{85}', '\u{202e}', '\u{2028}', '\u{2029}'] {
        let out_path = f.root.join(format!("new{c}run"));
        let out = f.cli(&[
            "audit",
            "init",
            "--target",
            f.target.to_str().unwrap(),
            "--out",
            out_path.to_str().unwrap(),
            "--no-sensors",
        ]);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("output paths must not contain"));
        assert!(out.stdout.is_empty());
        assert!(!out_path.exists());
    }
}

#[test]
fn paired_exports_preserve_markdown_when_html_destination_is_a_directory() {
    let f = Fixture::new();
    let batch = f.root.join("batch.json");
    std::fs::write(&batch, json!({"runs":[]}).to_string()).unwrap();
    let architecture = f.run.join("architecture.json");
    omgs::runmeta::write_atomic(
        &architecture,
        include_str!("../examples/architecture.sample.json"),
    )
    .unwrap();
    for (name, args) in [
        (
            "ARCHITECTURE",
            vec!["architecture", "--in", architecture.to_str().unwrap()],
        ),
        (
            "INDEX",
            vec!["batch", "index", "--batch", batch.to_str().unwrap()],
        ),
    ] {
        let out_dir = f.root.join(name);
        omgs::platform::create_private_dir(&out_dir).unwrap();
        let md = out_dir.join(format!("{name}.md"));
        let html = out_dir.join(format!("{name}.html"));
        omgs::runmeta::write_atomic(&md, "retained markdown").unwrap();
        omgs::platform::create_private_dir(&html).unwrap();
        std::fs::write(html.join("retained"), "retained html").unwrap();
        let mut args = args;
        args.extend(["--out", out_dir.to_str().unwrap()]);
        let result = f.cli(&args);
        assert_eq!(
            result.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stderr).contains("destination is a directory"));
        assert_eq!(std::fs::read_to_string(md).unwrap(), "retained markdown");
        assert_eq!(
            std::fs::read_to_string(html.join("retained")).unwrap(),
            "retained html"
        );
        assert_eq!(std::fs::read_dir(out_dir).unwrap().count(), 2);
    }
}

// Parallel verifiers each write their own findings file; the host merges
// them into the single findings.json without losing or silently replacing
// records.
#[test]
fn per_verifier_findings_files_merge_into_one() {
    let f = Fixture::new();
    let mut all = omgs::shape::findings(include_str!("fixtures/report-run/findings.json")).unwrap();
    for r in &mut all.findings {
        r.fingerprint = omgs::fingerprint(&r.attack_class, &r.entry_point, &r.sink, &r.boundary);
    }
    assert!(all.findings.len() >= 2);
    let (first, second) = all.findings.split_at(1);
    let write = |name: &str, findings: &[omgs::model::Finding]| {
        let path = f.run.join(name);
        let file = omgs::model::FindingsFile {
            findings: findings.to_vec(),
        };
        std::fs::write(&path, serde_json::to_string(&file).unwrap()).unwrap();
        path
    };
    let a = write("findings-blue-1.json", first);
    let b = write("findings-blue-2.json", second);
    let merge = |sources: &[&Path]| {
        let mut args = vec!["findings", "merge", "--run", f.run_str()];
        for s in sources {
            args.push("--from");
            args.push(s.to_str().unwrap());
        }
        f.cli(&args)
    };
    let out = merge(&[&a, &b]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let merged =
        omgs::shape::findings(&std::fs::read_to_string(f.run.join("findings.json")).unwrap())
            .unwrap();
    assert_eq!(
        serde_json::to_value(&merged).unwrap(),
        serde_json::to_value(&all).unwrap()
    );
    // Re-merging identical records is a no-op.
    assert!(merge(&[&a]).status.success());
    // The same fingerprint with different content is refused and nothing changes.
    let mut changed = first.to_vec();
    changed[0].evidence = "a different account".into();
    let c = write("findings-blue-3.json", &changed);
    let before = std::fs::read(f.run.join("findings.json")).unwrap();
    let out = merge(&[&c]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("reconcile"));
    assert_eq!(std::fs::read(f.run.join("findings.json")).unwrap(), before);
    // A record whose fingerprint is not its computed identity is refused.
    let mut invalid = second.to_vec();
    invalid[0].fingerprint = "omgs-00000000000000ff".into();
    let d = write("findings-blue-4.json", &invalid);
    let out = merge(&[&d]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(f.run.join("findings.json")).unwrap(), before);
    // Inputs that fit alone but not together are refused, leaving the file.
    let big = |name: &str, salt: &str| {
        let mut r = first[0].clone();
        r.entry_point = format!("{} {salt}", r.entry_point);
        r.fingerprint = omgs::fingerprint(&r.attack_class, &r.entry_point, &r.sink, &r.boundary);
        r.evidence = "x".repeat(9 << 20);
        write(name, &[r])
    };
    let (e, g) = (
        big("findings-big-1.json", "one"),
        big("findings-big-2.json", "two"),
    );
    let out = merge(&[&e, &g]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("byte limit"));
    assert_eq!(std::fs::read(f.run.join("findings.json")).unwrap(), before);
}
