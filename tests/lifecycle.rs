//! Non-executing lifecycle regressions. No reviewed code runs in these tests.
use omgs::attempts::{self, Event};
use omgs::model::{FindingsFile, Verdict};
use serde_json::{json, Value};
use std::path::PathBuf;

struct Run(PathBuf);
impl Run {
    fn new() -> Self {
        let path = omgs::platform::temp_root().unwrap().join(format!(
            "omgs-lifecycle-{}",
            omgs::platform::random_nonce().unwrap()
        ));
        omgs::platform::create_private_dir(&path).unwrap();
        omgs::runmeta::write_atomic(&path.join(omgs::runmeta::FILE), "{}").unwrap();
        Self(path)
    }
    fn put(&self, name: &str, value: Value) {
        omgs::runmeta::write_atomic(&self.0.join(name), &value.to_string()).unwrap();
    }
    fn event(&self, value: Value) -> Result<(), String> {
        attempts::append(&self.0, serde_json::from_value(value).unwrap()).map(|_| ())
    }
    fn meta(&self) -> serde_json::Map<String, Value> {
        omgs::runmeta::read(&self.0).unwrap()
    }
}
impl Drop for Run {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn start(id: &str, role: &str) -> Value {
    json!({"event":"start","id":id,"role":role,"identity":id,"context":format!("context-{id}"),"inputs":["claims.json"],"outputs":["decisions.json"],"isolation":"procedural"})
}
fn complete(id: &str) -> Value {
    json!({"event":"complete","id":id,"actor":"host","reason":"Inspected finished output and transcript"})
}
fn stop(id: &str, kind: &str) -> Value {
    json!({"event":"stop","id":id,"actor":"host","kind":kind,"reason":"Observed stop","artifacts":["decisions.json"],"disposition":"quarantined"})
}
fn resolve(id: &str, replacement: &str) -> Value {
    json!({"event":"resolve","id":id,"actor":"owner","authority":"user","reason":"Authorized replacement after review","replacement":replacement})
}
fn finding() -> FindingsFile {
    let fingerprint = omgs::fingerprint("input_validation", "entry", "sink", "boundary");
    omgs::shape::findings(&json!({"findings":[{"fingerprint":fingerprint,"title":"Synthetic claim","verdict":"rejected","proof_tier":"traced","attack_class":"input_validation","entry_point":"entry","sink":"sink","boundary":"boundary","location":{"path":"source.rs"},"evidence":"Decisive counterevidence","hunted_by":"red","verified_by":"blue"}]}).to_string()).unwrap()
}
fn stage(
    run: &Run,
    id: &str,
    parent: Option<&str>,
    state: &str,
    label: Option<&str>,
) -> Result<(), String> {
    omgs::status::apply(
        &run.0,
        &omgs::status::Update {
            stage: id,
            parent,
            state,
            label,
            detail: Some("round detail"),
            counters: &[],
            log: Some("progress"),
        },
    )
}
fn cli(run: &Run, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .env("OMGS_HOME", run.0.join("state"))
        .args(args)
        .arg("--run")
        .arg(&run.0)
        .output()
        .unwrap()
}
#[test]
fn t19_manifests_disclose_procedural_isolation_and_context_limits() {
    let run = Run::new();
    run.event(start("blue", "verifier")).unwrap();
    let h = attempts::history(&run.meta()).unwrap();
    let Event::Start {
        inputs,
        outputs,
        isolation,
        context,
        ..
    } = &h[0].record
    else {
        panic!()
    };
    assert_eq!(inputs, &["claims.json"]);
    assert_eq!(outputs, &["decisions.json"]);
    assert_eq!(isolation, "procedural");
    assert_eq!(context, "context-blue");
    let mut invalid = start("other", "hunter");
    invalid["inputs"] = json!([]);
    assert!(run.event(invalid).is_err());
    assert!(include_str!("../skill/BUDGETS-AND-ROUTING.md")
        .contains("Shared directories provide procedural context"));
    assert!(include_str!("../skill/agents/blue-verifier.md").contains("Do not infer"));
}
#[test]
fn t54_scaffold_identity_is_not_completion_and_stopped_final_is_invalid() {
    let run = Run::new();
    let mut f = finding();
    assert!(omgs::model::validate(&f)
        .iter()
        .any(|s| s.contains("verification requires")));
    run.event(start("blue", "verifier")).unwrap();
    f.findings[0].verification = Some(omgs::model::Verification {
        state: "final".into(),
        attempt: "blue".into(),
    });
    assert!(!attempts::finding_gaps(&run.0, &f).unwrap().is_empty());
    run.event(complete("blue")).unwrap();
    assert!(attempts::finding_gaps(&run.0, &f).unwrap().is_empty());
    assert!(attempts::final_for(&run.meta(), "blue", "verifier", "other").is_err());
    run.event(stop("blue", "policy")).unwrap();
    assert!(!attempts::finding_gaps(&run.0, &f).unwrap().is_empty());
    assert!(run.event(complete("blue")).is_err());
    let published = attempts::publication(&run.0, &f).unwrap();
    assert_eq!(published.findings[0].verdict, Verdict::NeedsValidation);
    assert!(published.findings[0].verification.is_none());
    assert_eq!(f.findings[0].verdict, Verdict::Rejected);
}
#[test]
fn t57_markdown_and_html_lead_with_incomplete_or_blocked_work() {
    let file = FindingsFile::default();
    let mut meta = omgs::report::ReportMeta::default();
    for html in [false, true] {
        let render = |m: &omgs::report::ReportMeta| {
            if html {
                omgs::report::render_html(&file, m)
            } else {
                omgs::report::render_markdown(&file, m)
            }
        };
        let text = render(&meta);
        assert!(text.contains("Incomplete review"));
        assert!(!text.contains("Nothing to fix"));
        meta.review_limits = vec!["attempt blue: stopped".into()];
        assert!(render(&meta).contains("Blocked review"));
        meta.review_limits.clear();
    }
}
#[test]
fn t58_logs_and_timeline_retain_date_and_utc_across_midnight() {
    assert_eq!(omgs::runmeta::timestamp(0), "1970-01-01T00:00:00Z");
    assert_eq!(omgs::runmeta::timestamp(86_400_000), "1970-01-02T00:00:00Z");
    assert_eq!(
        omgs::runmeta::timestamp(951_782_400_000),
        "2000-02-29T00:00:00Z"
    );
    let run = Run::new();
    stage(&run, "verify", None, "active", None).unwrap();
    let value: Value =
        serde_json::from_str(&std::fs::read_to_string(run.0.join(omgs::status::FILE)).unwrap())
            .unwrap();
    let ts = value["log"][0]["ts"].as_str().unwrap();
    assert_eq!(ts.len(), 20);
    assert!(ts.ends_with('Z'));
    assert!(omgs::report::timeline(&run.0).unwrap()[0]
        .started
        .ends_with('Z'));
}
#[test]
fn t59_resolving_blockers_preserves_refusal_history_and_requires_replacement() {
    let run = Run::new();
    omgs::runmeta::update(&run.0, |m| {
        m.insert("blockers".into(), json!(["Historical refusal"]));
        m.insert(
            "reroutes".into(),
            json!([{"role":"verifier","from":"configured","to":null,"reason":"refused"}]),
        );
        Ok(())
    })
    .unwrap();
    assert!(
        cli(
            &run,
            &[
                "attempt",
                "--resolve-blocker",
                "legacy-0",
                "--actor",
                "owner",
                "--reason",
                "Recovered",
                "--replacement",
                "missing"
            ]
        )
        .status
        .code()
            == Some(2)
    );
    run.event(start("replacement", "verifier")).unwrap();
    assert!(cli(
        &run,
        &[
            "attempt",
            "--resolve-blocker",
            "legacy-0",
            "--actor",
            "owner",
            "--reason",
            "Recovered",
            "--replacement",
            "replacement"
        ]
    )
    .status
    .success());
    let meta = run.meta();
    assert!(attempts::active_blockers(&meta).unwrap().is_empty());
    assert_eq!(meta["blockers"], json!(["Historical refusal"]));
    assert_eq!(meta["reroutes"].as_array().unwrap().len(), 1);
    assert_eq!(meta["blocker_events"][0]["state"], "resolved");
}
#[test]
fn t61_rounds_retain_identity_and_windows_with_fresh_labels() {
    let run = Run::new();
    stage(&run, "verify", None, "active", Some("first identity")).unwrap();
    stage(&run, "verify", None, "failed", None).unwrap();
    let before = omgs::report::timeline(&run.0).unwrap();
    stage(&run, "verify", None, "active", None).unwrap();
    assert_eq!(omgs::report::timeline(&run.0).unwrap()[1].label, "verify");
    stage(&run, "verify", None, "done", Some("second identity")).unwrap();
    let after = omgs::report::timeline(&run.0).unwrap();
    assert_eq!(after.len(), 2);
    assert_eq!(after[0].label, "first identity");
    assert_eq!(after[0].started, before[0].started);
    assert_eq!(after[0].ended, before[0].ended);
    assert_eq!(after[1].label, "second identity");
    let value: Value =
        serde_json::from_str(&std::fs::read_to_string(run.0.join(omgs::status::FILE)).unwrap())
            .unwrap();
    assert_eq!(value["stages"][0]["attempt_id"], "verify:2");
    assert_eq!(value["stages"][0]["history"][0]["attempt_id"], "verify:1");
}
#[test]
fn t63_publication_labels_survive_rerender_without_changing_evidence_identity() {
    let run = Run::new();
    run.put("findings.json", json!({"findings":[]}));
    omgs::runmeta::update(&run.0, |m| {
        m.insert("source_ref".into(), json!("original-evidence-ref"));
        Ok(())
    })
    .unwrap();
    let render = |extra: &[&str]| {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"));
        cmd.arg("report")
            .arg("--findings")
            .arg(run.0.join("findings.json"))
            .arg("--out")
            .arg(&run.0)
            .args(extra);
        let result = cmd.output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    };
    render(&[
        "--repo",
        "reviewed/repository",
        "--ref",
        "publication-ref",
        "--sandbox",
        "Recorded sandbox label",
    ]);
    render(&[]);
    let text = std::fs::read_to_string(run.0.join("REPORT.md")).unwrap();
    assert!(text.contains("reviewed/repository at publication-ref"));
    assert!(text.contains("Recorded sandbox label"));
    assert_eq!(run.meta()["source_ref"], "original-evidence-ref");
}
#[test]
fn t64_usage_retains_unknown_attempts_and_replaces_cumulative_continuations() {
    let run = Run::new();
    run.event(start("blue", "verifier")).unwrap();
    run.event(start("other", "verifier")).unwrap();
    for total in [100, 150] {
        let usage =
            omgs::accounting::parse(&[format!("blue-verifier@blue={total},unknown,50")]).unwrap();
        omgs::runmeta::update(&run.0, |m| {
            let mut saved = omgs::accounting::read(m)?;
            saved.extend(usage);
            m.insert("accounting".into(), serde_json::to_value(saved).unwrap());
            Ok(())
        })
        .unwrap();
    }
    let lines = omgs::accounting::lines(&omgs::accounting::read(&run.meta()).unwrap()).join("\n");
    assert!(
        lines.contains("tokens known subtotal 150, 1 unknown attempt(s)"),
        "{lines}"
    );
    assert!(lines.contains("Aggregate incomplete"));
    assert!(!lines.contains("subtotal 250"));
}
#[test]
fn t66_parentless_child_updates_uniquely_and_ambiguity_is_atomic() {
    let run = Run::new();
    stage(&run, "child", Some("hunt"), "active", None).unwrap();
    stage(&run, "child", None, "done", None).unwrap();
    let text = std::fs::read_to_string(run.0.join(omgs::status::FILE)).unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["stages"].as_array().unwrap().len(), 1);
    assert_eq!(v["stages"][0]["children"][0]["status"], "done");
    stage(&run, "child", Some("other"), "active", None).unwrap();
    let before = std::fs::read(run.0.join(omgs::status::FILE)).unwrap();
    assert!(stage(&run, "child", None, "done", None)
        .unwrap_err()
        .contains("ambiguous"));
    assert_eq!(
        before,
        std::fs::read(run.0.join(omgs::status::FILE)).unwrap()
    );
}
#[test]
fn t70_stops_are_per_attempt_and_resume_never_finalizes_stopped_output() {
    let run = Run::new();
    run.event(start("one", "hunter")).unwrap();
    run.event(start("two", "hunter")).unwrap();
    run.event(stop("one", "provider")).unwrap();
    run.event(complete("two")).unwrap();
    assert!(run.event(resolve("one", "missing")).is_err());
    run.event(start("replacement", "hunter")).unwrap();
    let mut unauthorized = resolve("one", "replacement");
    unauthorized["authority"] = json!("worker");
    assert!(run.event(unauthorized).is_err());
    run.event(resolve("one", "replacement")).unwrap();
    let states = attempts::states(&attempts::history(&run.meta()).unwrap()).unwrap();
    assert_eq!(states["one"].state, "stopped");
    assert_eq!(states["two"].state, "complete");
    assert_eq!(states["replacement"].state, "active");
    assert!(run.event(complete("one")).is_err());
    run.event(complete("replacement")).unwrap();
    assert!(attempts::gaps(&run.meta()).unwrap().is_empty());
    assert!(
        include_str!("../skill/BUDGETS-AND-ROUTING.md").contains("Do not retry a blocked action")
    );
}
#[test]
fn t74_recovery_requires_reconciliation_of_attempt_and_blocker_dispositions() {
    let run = Run::new();
    run.event(start("blue", "verifier")).unwrap();
    run.event(stop("blue", "policy")).unwrap();
    let mut unit = omgs::ledger::Unit::new("surface", "source", &["input_validation"], "blocked");
    unit.note = Some("Stopped".into());
    unit.extra.insert("attempt_ref".into(), json!("blue"));
    let mut ledger = omgs::ledger::Ledger {
        units: vec![unit],
        ..Default::default()
    };
    assert!(attempts::ledger_gaps(&run.0, &ledger).unwrap().is_empty());
    run.event(start("next", "verifier")).unwrap();
    run.event(resolve("blue", "next")).unwrap();
    assert!(attempts::ledger_gaps(&run.0, &ledger).unwrap()[0].contains("reconcile stale"));
    ledger.units[0].extra.clear();
    ledger.units[0].status = "deferred".into();
    ledger.units[0].note = Some("Bounded scope deferred".into());
    assert!(attempts::ledger_gaps(&run.0, &ledger).unwrap().is_empty());
}
#[test]
fn event_cli_rejects_unknown_fields_without_mutating_history() {
    let run = Run::new();
    let mut event = start("blue", "verifier");
    event["untrusted_extra"] = json!(true);
    run.put("event.json", event);
    let out = cli(
        &run,
        &[
            "attempt",
            "--event",
            run.0.join("event.json").to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(!run.meta().contains_key("attempts"));
    let schema: Value =
        serde_json::from_str(include_str!("../skill/schemas/attempt-event.schema.json")).unwrap();
    assert_eq!(schema["oneOf"].as_array().unwrap().len(), 5);
}

#[test]
fn scaffold_cli_cannot_validate_or_pass_critic_and_publishes_as_incomplete() {
    let run = Run::new();
    let file = finding();
    run.put("findings.json", serde_json::to_value(&file).unwrap());
    run.put("coverage-ledger.json", json!({"units":[]}));
    let validate = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .arg("validate")
        .arg("--findings")
        .arg(run.0.join("findings.json"))
        .output()
        .unwrap();
    assert_eq!(validate.status.code(), Some(1));
    assert_eq!(cli(&run, &["critic"]).status.code(), Some(1));
    let report = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .arg("report")
        .arg("--findings")
        .arg(run.0.join("findings.json"))
        .arg("--out")
        .arg(&run.0)
        .output()
        .unwrap();
    assert!(
        report.status.success(),
        "{}",
        String::from_utf8_lossy(&report.stderr)
    );
    let text = std::fs::read_to_string(run.0.join("REPORT.md")).unwrap();
    assert!(text.contains("Incomplete review"));
    assert!(text.contains("Rejected after verification: 0"));
    assert_eq!(run.meta()["run_status"], "partial");
    run.put("findings.json", json!({"findings":[]}));
    assert_eq!(cli(&run, &["critic"]).status.code(), Some(1));
}
#[test]
fn resolved_blocker_disposition_is_stale_until_host_reconciles_it() {
    let run = Run::new();
    omgs::runmeta::update(&run.0, |m| {
        attempts::blocker(m, "blocked-route", "active", "host", "Unavailable", None)
    })
    .unwrap();
    let mut unit = omgs::ledger::Unit::new("surface", "source", &["input_validation"], "deferred");
    unit.note = Some("Unavailable".into());
    unit.extra
        .insert("blocker_ref".into(), json!("blocked-route"));
    let ledger = omgs::ledger::Ledger {
        units: vec![unit],
        ..Default::default()
    };
    assert!(attempts::ledger_gaps(&run.0, &ledger).unwrap().is_empty());
    run.event(start("next", "verifier")).unwrap();
    omgs::runmeta::update(&run.0, |m| {
        attempts::blocker(
            m,
            "blocked-route",
            "resolved",
            "host",
            "Recovered",
            Some("next"),
        )
    })
    .unwrap();
    assert!(attempts::ledger_gaps(&run.0, &ledger).unwrap()[0].contains("reconcile resolved"));
    assert!(omgs::runmeta::update(&run.0, |m| attempts::blocker(
        m,
        "blocked-route",
        "active",
        "host",
        "New cause",
        None
    ))
    .is_err());
}

#[test]
fn draft_publication_never_filters_errors_using_untrusted_titles() {
    let mut file = finding();
    file.findings[0].title = "verification requires final state".into();
    file.findings[0].severity = Some(omgs::model::Severity::High);
    assert!(omgs::model::validate_drafts(&file)
        .iter()
        .any(|s| s.contains("must not carry severity")));
    file.findings[0].verification = Some(omgs::model::Verification {
        state: "invented".into(),
        attempt: "blue".into(),
    });
    assert!(omgs::model::validate_drafts(&file)
        .iter()
        .any(|s| s.contains("verification needs draft or final")));
}

#[test]
fn verification_and_evaluation_attempts_reject_positional_or_null_shapes() {
    let mut value = serde_json::to_value(finding()).unwrap();
    for malformed in [json!(["final", "blue"]), Value::Null] {
        value["findings"][0]["verification"] = malformed;
        assert!(omgs::shape::findings(&value.to_string()).is_err());
    }
    let evaluation = json!({"evaluator":"independent","attempt":null,"source_ref":"synthetic","decisions":[],"gaps":[]});
    assert!(omgs::adjudication::parse(&evaluation.to_string()).is_err());
}

#[test]
fn pending_reopens_a_round_without_losing_the_completed_window() {
    let run = Run::new();
    stage(&run, "verify", None, "active", Some("first")).unwrap();
    stage(&run, "verify", None, "done", None).unwrap();
    stage(&run, "verify", None, "pending", None).unwrap();
    stage(&run, "verify", None, "active", Some("next")).unwrap();
    let timeline = omgs::report::timeline(&run.0).unwrap();
    assert_eq!(timeline.len(), 2);
    assert_eq!(timeline[0].label, "first");
    assert_eq!(timeline[0].state, "done");
    assert_ne!(timeline[0].ended, "not recorded");
    assert_eq!(timeline[1].label, "next");
}
#[test]
fn historical_role_totals_remain_visible_without_double_counting_attempts() {
    let values = omgs::accounting::parse(&[
        "blue-verifier=700,1,100".into(),
        "blue-verifier@known=150,unknown,50".into(),
        "blue-verifier@stopped=unknown,unknown,unknown".into(),
    ])
    .unwrap();
    let lines = omgs::accounting::lines(&values).join("\n");
    assert!(lines.contains("historical role total; excluded from attempt aggregate): tokens 700"));
    assert!(lines.contains("tokens known subtotal 150, 1 unknown attempt(s)"));
    assert!(!lines.contains("subtotal 850"));
}

#[test]
fn additional_a_repeated_status_logs_render_in_both_reports() {
    let run = Run::new();
    run.put("findings.json", json!({"findings":[]}));
    let status = cli(
        &run,
        &[
            "status",
            "--stage",
            "hunt",
            "--state",
            "failed",
            "--log",
            "First disclosure",
            "--log",
            "Second disclosure <span>untrusted</span>",
        ],
    );
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let saved: Value =
        serde_json::from_str(&std::fs::read_to_string(run.0.join(omgs::status::FILE)).unwrap())
            .unwrap();
    assert_eq!(saved["log"].as_array().unwrap().len(), 2);
    let report = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .arg("report")
        .arg("--findings")
        .arg(run.0.join("findings.json"))
        .arg("--out")
        .arg(&run.0)
        .output()
        .unwrap();
    assert!(
        report.status.success(),
        "{}",
        String::from_utf8_lossy(&report.stderr)
    );
    for file in ["REPORT.md", "REPORT.html"] {
        let text = std::fs::read_to_string(run.0.join(file)).unwrap();
        assert!(text.contains("First disclosure"));
        assert!(text.contains("Second disclosure"));
        assert!(!text.contains("<span>untrusted</span>"));
    }
}
#[test]
fn additional_b_host_and_role_labels_are_recordable_before_reporting() {
    let run = Run::new();
    for (role, label) in [
        ("host", "host-runtime"),
        ("hunter", "hunter-runtime"),
        ("verifier", "verifier-runtime"),
        ("evaluator", "evaluator-runtime"),
        ("guard", "guard-runtime"),
    ] {
        let out = cli(&run, &["route", "--role", role, "--model", label]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(run.meta()["models"][role], label);
        let selected = cli(&run, &["route", "--role", role]);
        assert!(selected.status.success());
        assert_eq!(String::from_utf8_lossy(&selected.stdout).trim(), label);
        assert_eq!(run.meta()["models"][role], label);
    }
    let error = omgs::route::parse_identities(&["unknown=label".into()]).unwrap_err();
    for role in omgs::route::ROLES {
        assert!(error.contains(role), "{error}");
    }
    let labels = omgs::route::parse_identities(&[
        "host=host-runtime".into(),
        "verifier=verifier-runtime".into(),
    ])
    .unwrap();
    assert_eq!(labels["host"], "host-runtime");
    run.put("findings.json", json!({"findings":[]}));
    let report = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .arg("report")
        .arg("--findings")
        .arg(run.0.join("findings.json"))
        .arg("--out")
        .arg(&run.0)
        .args(["--model", "host=observed-host"])
        .output()
        .unwrap();
    assert!(
        report.status.success(),
        "{}",
        String::from_utf8_lossy(&report.stderr)
    );
    assert_eq!(run.meta()["models"]["host"], "observed-host");
}
#[test]
fn additional_c_continuation_turns_are_recorded_and_charged_exactly_once() {
    let run = Run::new();
    run.put(omgs::runmeta::FILE, json!({"budget_agent_calls":2}));
    run.event(start("blue", "verifier")).unwrap();
    let dispatch = |turn: &str| json!({"event":"dispatch","id":"blue","turn":turn,"actor":"host","reason":"Authorized review turn"});
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let value = dispatch("first");
            let run = &run;
            scope.spawn(move || run.event(value).unwrap());
        }
    });
    assert_eq!(run.meta()["agent_calls_used"], 1);
    assert_eq!(
        attempts::append(&run.0, serde_json::from_value(dispatch("first")).unwrap()).unwrap(),
        attempts::AppendOutcome::AlreadyRecorded
    );
    let mut conflicting = dispatch("first");
    conflicting["reason"] = json!("Different request");
    assert!(run.event(conflicting).is_err());
    run.event(complete("blue")).unwrap();
    run.event(dispatch("continuation")).unwrap();
    run.event(dispatch("continuation")).unwrap();
    assert_eq!(run.meta()["agent_calls_used"], 2);
    assert!(attempts::final_for(&run.meta(), "blue", "verifier", "blue").is_err());
    let before = run.meta();
    assert!(run.event(dispatch("exhausted")).is_err());
    assert_eq!(run.meta(), before);
    run.event(stop("blue", "policy")).unwrap();
    assert!(run.event(dispatch("continuation")).is_err());
    assert_eq!(run.meta()["agent_calls_used"], 2);
}
#[test]
fn additional_c_host_safety_stop_requires_an_authorized_fresh_attempt() {
    let run = Run::new();
    run.event(start("host-first", "host")).unwrap();
    run.event(stop("host-first", "policy")).unwrap();
    assert!(run.event(complete("host-first")).is_err());
    run.event(start("host-next", "host")).unwrap();
    run.event(resolve("host-first", "host-next")).unwrap();
    run.event(json!({"event":"dispatch","id":"host-next","turn":"approved-replacement","actor":"owner","reason":"Authorized replacement work"})).unwrap();
    assert_eq!(run.meta()["agent_calls_used"], 1);
    assert!(run.meta()["accounting"].get("host@host-next").is_some());
}
#[test]
fn additional_d_critic_reconciliation_discloses_incomplete_coverage_counts() {
    let file = FindingsFile::default();
    let meta = omgs::report::ReportMeta {
        coverage: vec!["blocked: unavailable".into(), "deferred: later".into()],
        critic: Some(omgs::critic::CriticReport::default()),
        ..Default::default()
    };
    for text in [
        omgs::report::render_markdown(&file, &meta),
        omgs::report::render_html(&file, &meta),
    ] {
        assert!(text.contains("Incomplete coverage: 1 blocked unit(s), 1 deferred unit(s)"));
        assert!(text.contains("blocked units: 1; deferred units: 1"));
        assert!(text.contains("Reconciliation does not establish complete coverage"));
    }
}
#[test]
fn additional_e_each_reused_proof_stage_round_remains_visible() {
    let run = Run::new();
    for i in 1..=5 {
        let label = format!("proof round {i}");
        stage(&run, "prove", None, "active", Some(&label)).unwrap();
        stage(&run, "prove", None, "done", None).unwrap();
    }
    let timeline = omgs::report::timeline(&run.0).unwrap();
    assert_eq!(timeline.len(), 5);
    for (i, row) in timeline.iter().enumerate() {
        assert_eq!(row.label, format!("proof round {}", i + 1));
        assert_eq!(row.state, "done");
        assert_ne!(row.started, "not recorded");
        assert_ne!(row.ended, "not recorded");
    }
}
#[test]
fn additional_f_persona_defaults_and_custom_combined_allowances_are_explicit() {
    let root = Run::new();
    let target = root.0.join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("source.rs"), "pub fn sample() {}\n").unwrap();
    for (name, extra, cap, profile) in [
        ("default", None, 64, "deep"),
        ("custom", Some("40"), 40, "custom"),
    ] {
        let run = root.0.join(name);
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"));
        cmd.args(["audit", "init", "--target"])
            .arg(&target)
            .arg("--out")
            .arg(&run)
            .args(["--persona", "inheritor", "--no-sensors"]);
        if let Some(budget) = extra {
            cmd.args(["--budget", budget]);
        }
        let result = cmd.output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let meta = omgs::runmeta::read(&run).unwrap();
        assert_eq!(meta["budget_agent_calls"], cap);
        assert_eq!(meta["budget_profile"], profile);
        assert_eq!(meta["persona_budget_default"], 64);
        assert_eq!(meta["persona_budget_profile"], "deep");
        assert_eq!(meta["budget_semantics"], "combined_calls_proofs_replays");
        omgs::runmeta::update(&run, |m| {
            m.insert("agent_calls_used".into(), json!(2));
            m.insert("proof_runs_used".into(), json!(3));
            Ok(())
        })
        .unwrap();
        let allowance = omgs::budget::allowance(&run).unwrap();
        assert_eq!(allowance.calls_and_proofs_used, 5);
        assert_eq!(allowance.remaining, Some(cap - 5));
        assert_eq!(allowance.budget_semantics, "combined_calls_proofs_replays");
    }
    assert!(include_str!("../skill/PIPELINE.md").contains("one shared pool"));
}
