//! Non-executing lifecycle regressions. No reviewed code runs in these tests.
use omgs::attempts::{self, Event};
use omgs::model::{FindingsFile, Verdict};
use serde_json::{json, Value};
use std::path::PathBuf;

struct Run(PathBuf, PathBuf);
impl Run {
    fn new() -> Self {
        let root = omgs::platform::temp_root().unwrap().join(format!(
            "omgs-lifecycle-{}",
            omgs::platform::random_nonce().unwrap()
        ));
        // Run writes admit their parent as private storage. The OS temp root
        // can be shared or have a different owner, including on Windows.
        omgs::platform::create_private_tree(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let path = root.join("run");
        omgs::platform::create_private_dir(&path).unwrap();
        omgs::runmeta::write_atomic(&path.join(omgs::runmeta::FILE), "{}").unwrap();
        // Exercise the same admission and locking path as later mutations so
        // a negative CLI assertion cannot pass because storage was rejected.
        omgs::runmeta::update(&path, |_| Ok(())).unwrap();
        Self(path, root)
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
        std::fs::remove_dir_all(&self.1).unwrap();
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
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .env("OMGS_HOME", run.0.join("state"))
        .args(args)
        .arg("--run")
        .arg(&run.0)
        .output()
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("storage-migration"),
        "CLI failed storage admission: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
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
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown field"));
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
    assert!(String::from_utf8_lossy(&validate.stderr).contains("verification requires"));
    let critic = cli(&run, &["critic"]);
    assert_eq!(critic.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&critic.stderr).contains("verification requires"));
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
    omgs::platform::create_private_dir(&target).unwrap();
    omgs::runmeta::write_atomic_bytes(&target.join("source.rs"), b"pub fn sample() {}\n").unwrap();
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

#[test]
fn evaluator_sampling_gap_prevents_completion_after_passing_reconciliation() {
    let run = Run::new();
    for (id, role) in [
        ("red", "hunter"),
        ("blue", "verifier"),
        ("independent", "evaluator"),
    ] {
        run.event(start(id, role)).unwrap();
        run.event(complete(id)).unwrap();
    }
    run.put("findings.json", json!({"findings":[]}));
    run.put("candidates-red.json", json!({"candidates":[]}));
    run.put("coverage-ledger.json", json!({"units":[{"id":"surface","surface":"source","attack_classes":["input_validation"],"status":"covered","evidence":["source.rs"]}]}));
    let evaluation = json!({"evaluator":"independent","attempt":"independent","source_ref":"synthetic","decisions":[],"gaps":[]});
    run.put("evaluation.json", evaluation.clone());
    let file = FindingsFile::default();
    let reconciliation = omgs::critic::critique_dir(&run.0, &file).unwrap();
    assert!(reconciliation.passed(), "{:?}", reconciliation.gaps);
    let mut evaluation = evaluation;
    evaluation["gaps"] = json!(["Sampling unfinished"]);
    run.put("evaluation.json", evaluation);
    let critic = omgs::critic::critique_dir(&run.0, &file).unwrap();
    assert!(critic
        .gaps
        .iter()
        .any(|g| g.contains("Sampling unfinished")));
    assert_eq!(cli(&run, &["critic"]).status.code(), Some(1));
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .arg("report")
        .arg("--findings")
        .arg(run.0.join("findings.json"))
        .arg("--out")
        .arg(&run.0)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    for name in ["REPORT.md", "REPORT.html"] {
        let text = std::fs::read_to_string(run.0.join(name)).unwrap();
        assert!(text.contains("Incomplete review"));
        assert!(!text.contains("Completed review: no confirmed findings"));
    }
    assert_eq!(run.meta()["run_status"], "partial");
    // A legacy saved completion cannot override the current evaluator gap.
    omgs::runmeta::update(&run.0, |m| {
        m.insert("run_status".into(), json!("complete"));
        Ok(())
    })
    .unwrap();
    let summary = omgs::batch::summarize(
        &omgs::batch::BatchRun {
            run_dir: Some(run.0.to_str().unwrap().into()),
            ..Default::default()
        },
        &run.0,
    )
    .unwrap();
    assert_eq!(summary.state, "partial");
}

#[test]
fn cumulative_usage_covers_only_the_submitted_turn_even_after_safety_stop() {
    let run = Run::new();
    run.event(start("blue", "verifier")).unwrap();
    let dispatch = |turn| json!({"event":"dispatch","id":"blue","turn":turn,"actor":"host","reason":"Authorized turn"});
    run.event(dispatch("one")).unwrap();
    assert!(cli(
        &run,
        &[
            "status",
            "--stage",
            "verify",
            "--state",
            "done",
            "--accounting",
            "blue-verifier@blue=100,1,50"
        ]
    )
    .status
    .success());
    assert_eq!(
        run.meta()["accounting"]["blue-verifier@blue"]["covered_turn"],
        "one"
    );
    let lines =
        || omgs::accounting::lines(&omgs::accounting::read(&run.meta()).unwrap()).join("\n");
    assert!(lines().contains("Aggregate complete"));
    run.event(complete("blue")).unwrap();
    run.event(dispatch("two")).unwrap();
    for stopped in [false, true] {
        if stopped {
            run.event(stop("blue", "policy")).unwrap();
        }
        let text = lines();
        assert!(
            text.contains("tokens known subtotal 100, 1 unknown attempt(s)"),
            "{text}"
        );
        assert!(text.contains("later turn usage unknown"));
        assert!(text.contains("Aggregate incomplete"));
        assert!(!text.contains("Aggregate complete"));
    }
}

#[test]
fn cumulative_usage_refresh_replaces_subtotal_and_covers_the_latest_turn() {
    let run = Run::new();
    run.event(start("blue", "verifier")).unwrap();
    for (turn, total) in [("one", "100"), ("two", "150")] {
        run.event(json!({"event":"dispatch","id":"blue","turn":turn,"actor":"host","reason":"Authorized turn"})).unwrap();
        assert!(cli(
            &run,
            &[
                "status",
                "--stage",
                "verify",
                "--state",
                "done",
                "--accounting",
                &format!("blue-verifier@blue={total},1,50")
            ]
        )
        .status
        .success());
    }
    let text = omgs::accounting::lines(&omgs::accounting::read(&run.meta()).unwrap()).join("\n");
    assert!(text.contains("tokens known subtotal 150, 0 unknown attempt(s)"));
    assert!(text.contains("Aggregate complete"));
    assert!(!text.contains("subtotal 250"));
}

#[test]
fn parent_round_archives_its_failed_children_before_successful_replacement() {
    let run = Run::new();
    stage(&run, "hunt", None, "active", Some("wave one")).unwrap();
    stage(&run, "child", Some("hunt"), "failed", Some("failed child")).unwrap();
    stage(&run, "hunt", None, "done", None).unwrap();
    stage(&run, "hunt", None, "active", Some("wave two")).unwrap();
    stage(
        &run,
        "child",
        Some("hunt"),
        "active",
        Some("replacement child"),
    )
    .unwrap();
    stage(&run, "child", Some("hunt"), "done", None).unwrap();
    stage(&run, "hunt", None, "done", None).unwrap();
    // A later mutation validates the archived children as well.
    stage(&run, "report", None, "done", None).unwrap();
    let rows = omgs::report::timeline(&run.0).unwrap();
    let old = rows
        .iter()
        .find(|r| r.label == "wave one / failed child")
        .unwrap();
    assert!(old.historical);
    assert_eq!(old.state, "failed");
    let current = rows
        .iter()
        .find(|r| r.label == "wave two / replacement child")
        .unwrap();
    assert!(!current.historical);
    assert_eq!(current.state, "done");
    let meta = omgs::report::ReportMeta {
        timeline: rows,
        critic: Some(Default::default()),
        ..Default::default()
    };
    assert!(omgs::report::review_state(&FindingsFile::default(), &meta).is_none());
}

#[test]
fn draft_and_stopped_verdicts_are_pending_in_publications_and_batch_counts() {
    for stopped in [false, true] {
        let run = Run::new();
        run.event(start("blue", "verifier")).unwrap();
        if stopped {
            run.event(stop("blue", "policy")).unwrap();
        }
        let mut file = finding();
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("benchmark")
            .join("fixtures")
            .join("score")
            .join("run-1")
            .join("positive");
        let archived =
            omgs::shape::findings(&std::fs::read_to_string(fixture.join("findings.json")).unwrap())
                .unwrap();
        let mut confirmed = archived.findings[0].clone();
        confirmed.verified_by = Some("blue".into());
        omgs::platform::create_private_tree(&run.0.join("proofs").join("1")).unwrap();
        for name in [
            "1.json",
            "1/command.txt",
            "1/mxc-config.json",
            "1/test-draft",
        ] {
            omgs::runmeta::write_atomic_bytes(
                &run.0.join("proofs").join(name),
                &std::fs::read(fixture.join("proofs").join(name)).unwrap(),
            )
            .unwrap();
        }
        confirmed.fix_brief = Some("Retained draft fix".into());
        file.findings.push(confirmed);
        for f in &mut file.findings {
            f.verification = Some(omgs::model::Verification {
                state: if stopped { "final" } else { "draft" }.into(),
                attempt: "blue".into(),
            });
        }
        run.put("findings.json", serde_json::to_value(&file).unwrap());
        let published = attempts::publication(&run.0, &file).unwrap();
        assert!(published
            .findings
            .iter()
            .all(|f| f.verdict == Verdict::NeedsValidation && f.fix_brief.is_none()));
        let handoff = omgs::handoff::build(&run.0, &file, None).unwrap();
        assert_eq!(handoff.review_state, "incomplete");
        assert!(handoff
            .records
            .iter()
            .all(|r| r.verdict == Verdict::NeedsValidation));
        let summary = omgs::batch::summarize(
            &omgs::batch::BatchRun {
                run_dir: Some(run.0.to_str().unwrap().into()),
                ..Default::default()
            },
            &run.0,
        )
        .unwrap();
        assert_eq!(
            (
                summary.confirmed,
                summary.rejected,
                summary.needs_validation
            ),
            (0, 0, 2)
        );
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
            .arg("report")
            .arg("--findings")
            .arg(run.0.join("findings.json"))
            .arg("--out")
            .arg(&run.0)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        for name in ["REPORT.md", "REPORT.html"] {
            let text = std::fs::read_to_string(run.0.join(name)).unwrap();
            assert!(text.contains("0 confirmed finding(s)"));
            assert!(!text.contains("Retained draft fix"));
        }
        let sarif: Value = serde_json::from_str(
            &std::fs::read_to_string(run.0.join("findings.sarif.json")).unwrap(),
        )
        .unwrap();
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r["level"] == "note"
            && r["properties"]["verdict"] == "needs_validation"
            && r["properties"]["proof_ref"].is_null()));
        let handoff: Value =
            serde_json::from_str(&std::fs::read_to_string(run.0.join("handoff.json")).unwrap())
                .unwrap();
        assert!(handoff["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["verdict"] == "needs_validation"));
    }
}

#[test]
fn batch_completion_matches_report_for_reopened_work_and_reasoned_deferrals() {
    let run = Run::new();
    for (id, role) in [
        ("red", "hunter"),
        ("blue", "verifier"),
        ("independent", "evaluator"),
    ] {
        run.event(start(id, role)).unwrap();
        run.event(complete(id)).unwrap();
    }
    let file = FindingsFile::default();
    run.put("findings.json", json!({"findings":[]}));
    run.put("candidates-red.json", json!({"candidates":[]}));
    run.put("coverage-ledger.json", json!({"units":[{"id":"surface","surface":"source","attack_classes":["input_validation"],"status":"covered","evidence":["source.rs"]}]}));
    run.put("evaluation.json", json!({"evaluator":"independent","attempt":"independent","source_ref":"synthetic","decisions":[],"gaps":[]}));
    let report = || {
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
            .arg("report")
            .arg("--findings")
            .arg(run.0.join("findings.json"))
            .arg("--out")
            .arg(&run.0)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    };
    let summary = || {
        omgs::batch::summarize(
            &omgs::batch::BatchRun {
                run_dir: Some(run.0.to_str().unwrap().into()),
                ..Default::default()
            },
            &run.0,
        )
        .unwrap()
    };
    report();
    assert_eq!(run.meta()["run_status"], "complete");
    assert_eq!(summary().state, "complete");
    assert!(omgs::report::run_review_state(&run.0, &file)
        .unwrap()
        .is_none());
    stage(&run, "hunt", None, "active", None).unwrap();
    assert_eq!(run.meta()["run_status"], "in_progress");
    // Even a stale external completion flag cannot override the current stage.
    omgs::runmeta::update(&run.0, |m| {
        m.insert("run_status".into(), json!("complete"));
        Ok(())
    })
    .unwrap();
    assert_eq!(summary().state, "partial");
    assert!(omgs::report::run_review_state(&run.0, &file)
        .unwrap()
        .is_some());
    report();
    assert_eq!(run.meta()["run_status"], "partial");
    stage(&run, "hunt", None, "done", None).unwrap();
    report();
    assert_eq!(summary().state, "complete");
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args(["ledger", "set", "--ledger"])
        .arg(run.0.join("coverage-ledger.json"))
        .args([
            "--unit",
            "surface",
            "--status",
            "deferred",
            "--note",
            "Review in next authorized scope",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(run.meta()["run_status"], "in_progress");
    assert!(!omgs::critic::critique_dir(&run.0, &file).unwrap().passed());
    omgs::runmeta::update(&run.0, |m| {
        m.insert("run_status".into(), json!("complete"));
        Ok(())
    })
    .unwrap();
    assert_eq!(summary().state, "partial");
    assert!(omgs::report::run_review_state(&run.0, &file)
        .unwrap()
        .unwrap()
        .contains("1 deferred"));
    report();
    assert_eq!(run.meta()["run_status"], "partial");
}

fn finished_review() -> Run {
    let run = Run::new();
    for (id, role) in [("blue", "verifier"), ("independent", "evaluator")] {
        run.event(start(id, role)).unwrap();
        run.event(complete(id)).unwrap();
    }
    run.put("findings.json", json!({"findings":[]}));
    run.put("candidates-empty.json", json!({"candidates":[]}));
    run.put("coverage-ledger.json", json!({"units":[{"id":"surface","surface":"source.rs","attack_classes":[],"status":"covered","evidence":["source.rs"]}]}));
    run.put("evaluation.json", json!({"evaluator":"independent","attempt":"independent","source_ref":"synthetic","decisions":[],"gaps":[]}));
    stage(&run, "report", None, "done", None).unwrap();
    run
}

#[test]
fn publication_rechecks_reopened_stages_and_deferred_coverage_under_lock() {
    for change in ["stage", "coverage", "stop", "finding"] {
        let run = finished_review();
        assert!(omgs::review::View::load(&run.0).unwrap().complete());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let worker = omgs::runmeta::with_lock(&run.0, || {
            let path = run.0.clone();
            let ready = barrier.clone();
            let worker = std::thread::spawn(move || {
                ready.wait();
                std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
                    .args(["report", "--findings"]).arg(path.join("findings.json"))
                    .arg("--out").arg(&path).output().unwrap()
            });
            barrier.wait();
            // The publisher cannot acquire this lock before the mutation.
            if change == "stage" {
                omgs::status::apply_with_logs_locked(&run.0, &omgs::status::Update {
                    stage: "hunt", label: None, parent: None, state: "active", detail: None, counters: &[], log: None,
                }, &[])?;
            } else if change == "coverage" {
                run.put("coverage-ledger.json", json!({"units":[{"id":"surface","surface":"source.rs","attack_classes":[],"status":"deferred","note":"Awaiting authorized review"}]}));
            } else if change == "finding" {
                let mut file = finding();
                file.findings[0].verification = Some(omgs::model::Verification { state:"draft".into(), attempt:"blue".into() });
                run.put("findings.json", json!(file));
            } else {
                let mut meta = run.meta();
                meta["attempts"].as_array_mut().unwrap().push(json!({"at":"2026-01-01T00:00:00Z","record":stop("blue", "policy")}));
                omgs::runmeta::check_numeric_fields(&meta)?;
                run.put("run-metadata.json", json!(meta));
            }
            Ok(worker)
        }).unwrap();
        let result = worker.join().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_published_partial(&run, change);
    }
}

#[test]
fn publication_holds_the_lock_from_complete_view_through_artifact_commit() {
    use std::sync::{mpsc, Arc, Barrier};
    use std::time::Duration;
    let run = finished_review();
    let mut mutation = None;
    omgs::report::publish(
        Some(&run.0),
        None,
        &Default::default(),
        &Default::default(),
        |_| {
            let view = omgs::review::View::load_locked(&run.0)?;
            assert!(view.complete());
            let path = run.0.clone();
            let barrier = Arc::new(Barrier::new(2));
            let writer_barrier = barrier.clone();
            let (send, receive) = mpsc::channel();
            mutation = Some(std::thread::spawn(move || {
                writer_barrier.wait();
                let lock = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path.join(".omgs-run.lock"))
                    .unwrap();
                let blocked = matches!(lock.try_lock(), Err(std::fs::TryLockError::WouldBlock));
                drop(lock);
                send.send(blocked).unwrap();
                omgs::runmeta::with_lock(&path, || {
                    // This checkpoint is after publication and before the reopen.
                    // Every actual artifact must describe the metadata saved here.
                    assert_eq!(omgs::runmeta::read(&path)?["run_status"], "complete");
                    for name in ["REPORT.md", "REPORT.html"] {
                        let report = std::fs::read_to_string(path.join(name)).unwrap();
                        assert!(
                            report.contains("Completed review: no confirmed findings."),
                            "{name}"
                        );
                    }
                    let handoff: Value =
                        serde_json::from_slice(&std::fs::read(path.join("handoff.json")).unwrap())
                            .unwrap();
                    assert_eq!(handoff["review_state"], "complete");
                    assert!(std::fs::read_to_string(path.join("HANDOFF.md"))
                        .unwrap()
                        .contains("complete"));
                    let sarif: Value = serde_json::from_slice(
                        &std::fs::read(path.join("findings.sarif.json")).unwrap(),
                    )
                    .unwrap();
                    assert_eq!(
                        sarif["runs"][0]["invocations"][0]["executionSuccessful"],
                        true
                    );
                    omgs::status::apply_with_logs_locked(
                        &path,
                        &omgs::status::Update {
                            stage: "hunt",
                            label: None,
                            parent: None,
                            state: "active",
                            detail: None,
                            counters: &[],
                            log: None,
                        },
                        &[],
                    )
                })
                .unwrap();
            }));
            barrier.wait();
            assert!(
                receive.recv_timeout(Duration::from_secs(10)).unwrap(),
                "competing mutation acquired the lock during rendering"
            );
            let handoff = omgs::handoff::build_view(&run.0, &view, None)?;
            for (name, text) in [
                (
                    "REPORT.md",
                    omgs::report::render_markdown(&view.findings, &view.meta),
                ),
                (
                    "REPORT.html",
                    omgs::report::render_html(&view.findings, &view.meta),
                ),
                (
                    "findings.sarif.json",
                    omgs::report::render_sarif(&view.findings, &view.meta),
                ),
                ("HANDOFF.md", omgs::handoff::markdown(&handoff)),
                ("handoff.json", serde_json::to_string(&handoff).unwrap()),
            ] {
                omgs::runmeta::write_atomic(&run.0.join(name), &text)?;
            }
            Ok(omgs::report::Completion {
                hunters: None,
                verifier: None,
                complete: view.complete(),
            })
        },
    )
    .unwrap();
    mutation.unwrap().join().unwrap();
    assert!(!omgs::review::View::load(&run.0).unwrap().complete());
    assert_eq!(run.meta()["run_status"], "in_progress");
}

fn assert_published_partial(run: &Run, change: &str) {
    assert_eq!(run.meta()["run_status"], "partial", "{change}");
    for name in ["REPORT.md", "REPORT.html", "HANDOFF.md"] {
        let text = std::fs::read_to_string(run.0.join(name)).unwrap();
        assert!(
            !text.contains("Completed review: no confirmed findings."),
            "{change}: {name}"
        );
        assert!(
            text.to_lowercase().contains("incomplete") || text.to_lowercase().contains("blocked"),
            "{change}: {name}"
        );
    }
    let handoff: Value =
        serde_json::from_str(&std::fs::read_to_string(run.0.join("handoff.json")).unwrap())
            .unwrap();
    assert_ne!(handoff["review_state"], "complete", "{change}");
    let sarif: Value =
        serde_json::from_str(&std::fs::read_to_string(run.0.join("findings.sarif.json")).unwrap())
            .unwrap();
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["executionSuccessful"], false,
        "{change}"
    );
}

#[test]
fn published_consumers_agree_on_review_matrix() {
    for confirmed in [false, true] {
        for scenario in [
            "complete",
            "active",
            "stopped",
            "deferred",
            "evaluator_gap",
            "reopened",
            "zero",
            "draft",
        ] {
            let run = finished_review();
            if scenario != "zero" {
                let mut file = if confirmed {
                    confirmed_fixture(&run)
                } else {
                    finding()
                };
                file.findings[0].verification = Some(omgs::model::Verification {
                    state: if scenario == "draft" {
                        "draft"
                    } else {
                        "final"
                    }
                    .into(),
                    attempt: "blue".into(),
                });
                let fp = file.findings[0].fingerprint.clone();
                run.put("findings.json", serde_json::to_value(&file).unwrap());
                run.put("candidates-red.json", json!({"candidates":[{"hunter":"red","unit_ids":["surface"],"source_ref":"synthetic","title":"Synthetic claim","attack_class":file.findings[0].attack_class,"entry_point":file.findings[0].entry_point,"sink":file.findings[0].sink,"boundary":file.findings[0].boundary,"location":file.findings[0].location,"attacker_capability":"untrusted input","trace":"entry to sink","concrete_result":"counterexample","counterevidence":"boundary enforced","proof_plan":"inspect boundary","fingerprint":fp}]}));
                run.put("coverage-ledger.json", json!({"units":[{"id":"surface","surface":"source.rs","attack_classes":[],"status":"covered","evidence":["source.rs",fp]}]}));
                run.put("evaluation.json", json!({"evaluator":"independent","attempt":"independent","source_ref":"synthetic","decisions":[{"fingerprint":fp,"decision":"uphold","reason":"Reviewed counterevidence","evidence":if confirmed { json!(["source.rs","proofs/2.json"]) } else { json!(["source.rs"]) },"required_changes":[]}],"gaps":if scenario == "evaluator_gap" {json!(["Unresolved boundary"])} else {json!([])}}));
            }
            match scenario {
                "active" => {
                    run.event(json!({"event":"dispatch","id":"blue","turn":"continued","actor":"host","reason":"Authorized continuation"})).unwrap();
                }
                "stopped" => {
                    run.event(stop("blue", "policy")).unwrap();
                }
                "deferred" => {
                    let mut ledger: Value = serde_json::from_str(
                        &std::fs::read_to_string(run.0.join("coverage-ledger.json")).unwrap(),
                    )
                    .unwrap();
                    ledger["units"][0]["status"] = json!("deferred");
                    ledger["units"][0]["note"] = json!("Awaiting review");
                    run.put("coverage-ledger.json", ledger);
                }
                "reopened" => stage(&run, "hunt", None, "active", None).unwrap(),
                _ => {}
            }
            // Legacy counters and completion flags must never override evidence.
            let mut progress: Value = serde_json::from_str(
                &std::fs::read_to_string(run.0.join("pipeline-status.json")).unwrap(),
            )
            .unwrap();
            progress["counters"] = json!({"confirmed":99,"rejected":99,"needs_validation":0});
            run.put("pipeline-status.json", progress);
            omgs::runmeta::update(&run.0, |m| {
                m.insert("run_status".into(), json!("complete"));
                Ok(())
            })
            .unwrap();
            let view = omgs::review::View::load(&run.0).unwrap();
            let complete = matches!(scenario, "complete" | "zero");
            assert_eq!(view.complete(), complete, "{scenario}: {:?}", view.state);
            let pending = matches!(scenario, "active" | "stopped" | "draft");
            let expected_confirmed = usize::from(confirmed && !pending && scenario != "zero");
            assert_eq!(view.confirmed, expected_confirmed);
            assert_eq!(view.needs_validation, usize::from(pending));
            assert_eq!(
                view.rejected,
                usize::from(!confirmed && !pending && scenario != "zero")
            );
            assert_eq!(omgs::runmeta::is_complete(&run.0), complete);
            let gate = omgs::policy::advisory_lines(&run.0, &Default::default()).unwrap();
            assert_eq!(
                gate.iter()
                    .any(|line| line.starts_with("advisory: Incomplete")
                        || line.starts_with("advisory: Blocked")),
                !complete
            );
            assert_eq!(
                gate.iter()
                    .any(|line| line.contains("advisory: confirmed finding")),
                expected_confirmed > 0
            );
            let mut registered = omgs::policy::Policy::default();
            if expected_confirmed > 0 {
                registered.gate_tests.push(omgs::policy::GateTest {
                    id: "registered".into(),
                    test: "tests/boundary.rs".into(),
                    command: "test".into(),
                    expect_marker: "BOUNDARY".into(),
                    severity: omgs::model::Severity::High,
                    timeout_ms: 1000,
                    fingerprint: Some(view.findings.findings[0].fingerprint.clone()),
                });
            }
            assert!(!omgs::policy::advisory_lines(&run.0, &registered)
                .unwrap()
                .iter()
                .any(|line| line.contains("advisory: confirmed finding")));
            assert_eq!(
                omgs::critic::critique_run(&run.0).unwrap().passed(),
                complete
            );
            let raw = omgs::shape::findings(
                &std::fs::read_to_string(run.0.join("findings.json")).unwrap(),
            )
            .unwrap();
            let handoff = omgs::handoff::build(&run.0, &raw, None).unwrap();
            assert_eq!(handoff.review_state == "complete", complete);
            assert_eq!(
                handoff.records.len(),
                usize::from(pending) + expected_confirmed
            );
            let summary = omgs::batch::summarize(
                &omgs::batch::BatchRun {
                    run_dir: Some(run.0.to_string_lossy().into()),
                    ..Default::default()
                },
                &run.0,
            )
            .unwrap();
            assert_eq!(summary.state == "complete", complete);
            assert_eq!(
                (
                    summary.confirmed,
                    summary.needs_validation,
                    summary.rejected
                ),
                (view.confirmed, view.needs_validation, view.rejected)
            );
            let response = omgs::watch::respond(
                "GET /pipeline-status.json HTTP/1.1\r\nHost: localhost:4000\r\n\r\n",
                4000,
                &run.0,
            );
            assert_eq!(response.status, 200);
            let dashboard: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(dashboard["review_complete"], complete);
            assert_eq!(dashboard["counters"]["confirmed"], expected_confirmed);
            assert_dashboard_render(&dashboard);
            assert_eq!(
                dashboard["counters"]["needs_validation"],
                view.needs_validation
            );
            assert_eq!(dashboard["counters"]["rejected"], view.rejected);
            let result = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
                .args(["report", "--findings"])
                .arg(run.0.join("findings.json"))
                .arg("--out")
                .arg(&run.0)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{scenario}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(run.meta()["run_status"] == "complete", complete);
            for name in ["REPORT.md", "REPORT.html"] {
                let report = std::fs::read_to_string(run.0.join(name)).unwrap();
                assert_eq!(
                    report.contains("Completed review: no confirmed findings."),
                    complete && expected_confirmed == 0,
                    "{scenario}: {name}"
                );
            }
            let sarif: Value = serde_json::from_str(
                &std::fs::read_to_string(run.0.join("findings.sarif.json")).unwrap(),
            )
            .unwrap();
            let invocation = &sarif["runs"][0]["invocations"][0];
            assert_eq!(invocation["executionSuccessful"], complete, "{scenario}");
            assert_eq!(
                invocation["toolExecutionNotifications"]
                    .as_array()
                    .unwrap()
                    .is_empty(),
                complete
            );
            let validation = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
                .args(["validate", "--findings"])
                .arg(run.0.join("findings.json"))
                .output()
                .unwrap();
            if matches!(scenario, "active" | "stopped" | "draft") {
                assert!(!validation.status.success());
            } else {
                assert!(
                    validation.status.success(),
                    "{scenario}: {}",
                    String::from_utf8_lossy(&validation.stderr)
                );
                assert_eq!(
                    String::from_utf8_lossy(&validation.stdout).contains("review complete"),
                    complete
                );
            }
            let status = cli(&run, &["status", "--stage", "report", "--state", "done"]);
            assert!(status.status.success());
            assert_eq!(
                String::from_utf8_lossy(&status.stdout).contains("review complete"),
                complete
            );
            let out = cli(&run, &["handoff"]);
            assert!(
                out.status.success(),
                "{scenario}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let saved_handoff: Value =
                serde_json::from_str(&std::fs::read_to_string(run.0.join("handoff.json")).unwrap())
                    .unwrap();
            assert_eq!(saved_handoff["review_state"] == "complete", complete);
            assert_eq!(
                saved_handoff["records"].as_array().unwrap().len(),
                handoff.records.len()
            );
            let md = std::fs::read_to_string(run.0.join("HANDOFF.md")).unwrap();
            assert!(md.contains(if complete { "complete" } else { "incomplete" }));
        }
    }
}

#[test]
fn zero_finding_sarif_preserves_active_stopped_and_deferred_review_state() {
    for state in ["active", "stopped", "deferred"] {
        let run = finished_review();
        if state == "deferred" {
            run.put("coverage-ledger.json", json!({"units":[{"id":"surface","surface":"source.rs","attack_classes":[],"status":"deferred","note":"Awaiting review"}]}));
        } else {
            run.event(start("next", "hunter")).unwrap();
            if state == "stopped" {
                run.event(stop("next", "policy")).unwrap();
            }
        }
        let view = omgs::review::View::load(&run.0).unwrap();
        let sarif: Value =
            serde_json::from_str(&omgs::report::render_sarif(&view.findings, &view.meta)).unwrap();
        assert!(sarif["runs"][0]["results"].as_array().unwrap().is_empty());
        assert_eq!(
            sarif["runs"][0]["invocations"][0]["executionSuccessful"],
            false
        );
        assert!(
            sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]["message"]["text"]
                .as_str()
                .unwrap()
                .contains(state)
        );
    }
}

#[test]
fn status_publishes_view_counts_and_dashboard_requires_its_completion_verdict() {
    let run = finished_review();
    omgs::status::apply(
        &run.0,
        &omgs::status::Update {
            stage: "verify",
            label: None,
            parent: None,
            state: "failed",
            detail: None,
            counters: &[("confirmed".into(), 99)],
            log: None,
        },
    )
    .unwrap();
    let status: Value =
        serde_json::from_str(&std::fs::read_to_string(run.0.join("pipeline-status.json")).unwrap())
            .unwrap();
    assert_eq!(status["counters"]["confirmed"], 0);
    assert_eq!(status["review_complete"], false);
    assert_dashboard_render(&status);
}

fn confirmed_fixture(run: &Run) -> FindingsFile {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("benchmark")
        .join("fixtures")
        .join("score")
        .join("run-1")
        .join("positive");
    let mut file =
        omgs::shape::findings(&std::fs::read_to_string(fixture.join("findings.json")).unwrap())
            .unwrap();
    file.findings.truncate(1);
    file.findings[0].verified_by = Some("blue".into());
    file.findings[0].hunted_by = Some("red".into());
    omgs::platform::create_private_tree(&run.0.join("proofs").join("1")).unwrap();
    for name in [
        "1.json",
        "1/command.txt",
        "1/mxc-config.json",
        "1/test-draft",
    ] {
        omgs::runmeta::write_atomic_bytes(
            &run.0.join("proofs").join(name),
            &std::fs::read(fixture.join("proofs").join(name)).unwrap(),
        )
        .unwrap();
    }
    omgs::platform::create_private_tree(&run.0.join("proofs").join("2")).unwrap();
    for name in ["command.txt", "mxc-config.json", "test-draft"] {
        omgs::runmeta::write_atomic_bytes(
            &run.0.join("proofs").join("2").join(name),
            &std::fs::read(fixture.join("proofs").join("1").join(name)).unwrap(),
        )
        .unwrap();
    }
    let mut replay: Value =
        serde_json::from_slice(&std::fs::read(fixture.join("proofs").join("1.json")).unwrap())
            .unwrap();
    replay["n"] = json!(2);
    replay["replays"] = json!(1);
    replay["proof_dir"] = json!("/omgs-fixture/positive/proofs/2");
    let config = std::fs::read_to_string(fixture.join("proofs").join("1").join("mxc-config.json"))
        .unwrap()
        .replace("/proofs/1/", "/proofs/2/");
    omgs::runmeta::write_atomic(
        &run.0.join("proofs").join("2").join("mxc-config.json"),
        &config,
    )
    .unwrap();
    replay["config_sha256"] = json!(omgs::sha256::digest(config.as_bytes()));
    run.put("proofs/2.json", replay);
    let replay = omgs::proof::load(&run.0, "proofs/2.json").unwrap();
    assert!(
        omgs::proof::runner_evidence(&run.0, &replay).is_empty(),
        "{:?}",
        omgs::proof::runner_evidence(&run.0, &replay)
    );
    file
}

fn assert_dashboard_render(data: &Value) {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let script = include_str!("../skill/progress/dashboard.html")
        .split_once("<script>")
        .unwrap()
        .1
        .split_once("</script>")
        .unwrap()
        .0;
    let harness = r#"
const fs=require('fs'), vm=require('vm');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
const elements={};
const element=()=>({textContent:'',innerHTML:'',classList:{toggle(){},add(){}},querySelector(){return element()}});
const context={document:{getElementById(id){return elements[id]??=element()}},Date,setInterval(){},fetch(){return new Promise(()=>{})}};
vm.createContext(context);vm.runInContext(input.script,context);
context.render(input.data);
console.log(JSON.stringify(elements));
"#;
    let mut child = Command::new("node")
        .args(["-e", harness])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Node is required to exercise dashboard rendering");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(json!({"script":script,"data":data}).to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let rendered: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        rendered["c-conf"]["textContent"],
        data["counters"]["confirmed"]
    );
    assert_eq!(
        rendered["c-needs"]["textContent"],
        data["counters"]["needs_validation"]
    );
    let headline = rendered["happening"]["textContent"].as_str().unwrap();
    assert_eq!(
        headline.contains("report is ready"),
        data["review_complete"] == true
    );
    if data["review_complete"] == false {
        assert_eq!(headline, data["review_state"].as_str().unwrap());
    }
}

#[test]
fn stale_usage_submissions_cannot_cover_continuations_or_replace_newer_totals() {
    for newer in ["turn", "submission"] {
        let run = finished_review();
        let entries = vec!["blue-verifier@blue=100,1,50".to_string()];
        let stale = omgs::accounting::Submission::observe(
            &run.meta(),
            omgs::accounting::parse(&entries).unwrap(),
        )
        .unwrap();
        if newer == "turn" {
            run.event(json!({"event":"dispatch","id":"blue","turn":"next","actor":"host","reason":"Authorized continuation"})).unwrap();
        } else {
            let fresh = omgs::accounting::Submission::observe(
                &run.meta(),
                omgs::accounting::parse(&["blue-verifier@blue=200,2,100".into()]).unwrap(),
            )
            .unwrap();
            omgs::runmeta::update(&run.0, |m| fresh.apply(m)).unwrap();
        }
        let expected = run.meta();
        let err = omgs::report::publish(
            Some(&run.0),
            None,
            &Default::default(),
            &Default::default(),
            |m| {
                stale.apply(m)?;
                panic!("stale submissions must be rejected before rendering");
            },
        )
        .unwrap_err();
        assert!(err.contains("stale"));
        assert_eq!(run.meta(), expected);
        let view = omgs::review::View::load(&run.0).unwrap();
        if newer == "turn" {
            assert!(view.accounting["blue-verifier@blue"].unreported);
            assert_eq!(view.accounting["blue-verifier@blue"].tokens, None);
        } else {
            assert_eq!(view.accounting["blue-verifier@blue"].tokens, Some(200));
        }
    }
}

#[test]
fn standalone_report_keeps_supplied_usage_in_its_publication_view() {
    let run = finished_review();
    std::fs::remove_file(run.0.join(omgs::runmeta::FILE)).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args(["report", "--findings"])
        .arg(run.0.join("findings.json"))
        .arg("--out")
        .arg(&run.0)
        .args(["--accounting", "host=7,0.5,9"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = std::fs::read_to_string(run.0.join("REPORT.md")).unwrap();
    assert!(report.contains("host: tokens 7, cost USD 0.5, duration ms 9"));
}

#[test]
fn standalone_handoff_cli_reads_findings_after_competing_stop() {
    let run = finished_review();
    let worker = omgs::runmeta::with_lock(&run.0, || {
        let path = run.0.clone();
        let worker = std::thread::spawn(move || {
            std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
                .arg("handoff")
                .arg("--run")
                .arg(path)
                .output()
                .unwrap()
        });
        // Replace findings as part of the competing stop transaction. A
        // publisher must not retain findings read before acquiring this lock.
        let mut file = confirmed_fixture(&run);
        file.findings[0].verification = Some(omgs::model::Verification {
            state: "final".into(),
            attempt: "blue".into(),
        });
        run.put("findings.json", json!(file));
        let mut meta = run.meta();
        meta["attempts"].as_array_mut().unwrap().push(json!({
            "at":"2026-01-01T00:00:00Z", "record":stop("blue", "policy")
        }));
        meta.insert("run_status".into(), json!("partial"));
        run.put("run-metadata.json", json!(meta));
        Ok(worker)
    })
    .unwrap();
    let result = worker.join().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let h: Value =
        serde_json::from_slice(&std::fs::read(run.0.join("handoff.json")).unwrap()).unwrap();
    assert_eq!(h["review_state"], "incomplete");
    assert_eq!(h["records"].as_array().unwrap().len(), 1);
    assert_eq!(h["records"][0]["verdict"], "needs_validation");
    assert!(!std::fs::read_to_string(run.0.join("HANDOFF.md"))
        .unwrap()
        .contains("## Confirmed"));
}

#[test]
fn standalone_handoff_holds_family_and_run_locks_through_both_writes() {
    use std::sync::mpsc;
    let run = finished_review();
    let root = run.1.join("original");
    omgs::platform::create_private_dir(&root).unwrap();
    omgs::runmeta::write_atomic(
        &root.join(omgs::runmeta::FILE),
        &json!({
            "run_id":"original", "fix_runs":[{"path":run.0,"run_id":"child"}]
        })
        .to_string(),
    )
    .unwrap();
    omgs::runmeta::update(&run.0, |m| {
        m.insert("run_id".into(), json!("child"));
        m.insert("budget_parent".into(), json!(root));
        m.insert("budget_parent_id".into(), json!("original"));
        Ok(())
    })
    .unwrap();
    run.put("stop.json", stop("blue", "policy"));
    let mut worker = None;
    omgs::handoff::publish(&run.0, None, |h| {
        assert_eq!(h.review_state, "complete");
        let path = run.0.clone();
        let parent = root.clone();
        let (send, receive) = mpsc::channel();
        worker = Some(std::thread::spawn(move || {
            for dir in [&parent, &path] {
                let lock = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(dir.join(".omgs-run.lock"))
                    .unwrap();
                assert!(matches!(
                    lock.try_lock(),
                    Err(std::fs::TryLockError::WouldBlock)
                ));
            }
            send.send(()).unwrap();
            // This is a real competing CLI stop, with no timing-only barrier.
            let output = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
                .arg("attempt")
                .arg("--run")
                .arg(&path)
                .arg("--event")
                .arg(path.join("stop.json"))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }));
        receive
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        omgs::runmeta::write_atomic(&run.0.join("HANDOFF.md"), &omgs::handoff::markdown(h))?;
        omgs::runmeta::write_atomic(
            &run.0.join("handoff.json"),
            &serde_json::to_string(h).unwrap(),
        )?;
        assert!(omgs::review::View::load_locked(&run.0)?.complete());
        Ok(())
    })
    .unwrap();
    worker.unwrap().join().unwrap();
    let result = cli(&run, &["handoff"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let h: Value =
        serde_json::from_slice(&std::fs::read(run.0.join("handoff.json")).unwrap()).unwrap();
    assert_eq!(h["review_state"], "incomplete");
}

#[test]
fn competing_publishers_keep_labels_and_saved_identity_in_one_transaction() {
    use std::sync::mpsc;
    let run = finished_review();
    let labels = std::collections::BTreeMap::from([
        ("repo", "publication-A".into()),
        ("source_ref", "ref-A".into()),
        ("sandbox", "sandbox-A".into()),
    ]);
    let mut worker = None;
    omgs::report::publish(Some(&run.0), None, &Default::default(), &labels, |m| {
        for (key, value) in &labels {
            assert_eq!(m["publication"][key], value.as_str());
        }
        let path = run.0.clone();
        let (send, receive) = mpsc::channel();
        worker = Some(std::thread::spawn(move || {
            let lock = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path.join(".omgs-run.lock"))
                .unwrap();
            send.send(matches!(
                lock.try_lock(),
                Err(std::fs::TryLockError::WouldBlock)
            ))
            .unwrap();
            drop(lock);
            // Inspect A's committed artifacts and identity at the first
            // available transaction boundary, then publish B through the CLI.
            omgs::runmeta::with_lock(&path, || {
                assert_eq!(
                    omgs::runmeta::read(&path)?["publication"]["source_ref"],
                    "ref-A"
                );
                for name in ["REPORT.md", "REPORT.html"] {
                    assert!(std::fs::read_to_string(path.join(name))
                        .unwrap()
                        .contains("ref-A"));
                }
                Ok(())
            })
            .unwrap();
            std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
                .arg("report")
                .arg("--findings")
                .arg(path.join("findings.json"))
                .arg("--out")
                .arg(path)
                .args([
                    "--repo",
                    "publication-B",
                    "--ref",
                    "ref-B",
                    "--sandbox",
                    "sandbox-B",
                ])
                .output()
                .unwrap()
        }));
        assert!(receive
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap());
        let mut view = omgs::review::View::load_locked(&run.0)?;
        let meta = &mut view.meta;
        meta.repo = m["publication"]["repo"].as_str().unwrap().into();
        meta.source_ref = m["publication"]["source_ref"].as_str().unwrap().into();
        meta.sandbox = m["publication"]["sandbox"].as_str().unwrap().into();
        omgs::runmeta::write_atomic(
            &run.0.join("REPORT.md"),
            &omgs::report::render_markdown(&view.findings, meta),
        )?;
        omgs::runmeta::write_atomic(
            &run.0.join("REPORT.html"),
            &omgs::report::render_html(&view.findings, meta),
        )?;
        Ok(omgs::report::Completion {
            hunters: None,
            verifier: None,
            complete: view.complete(),
        })
    })
    .unwrap();
    let result = worker.unwrap().join().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    for key in ["repo", "source_ref", "sandbox"] {
        let meta = run.meta();
        let label = meta["publication"][key].as_str().unwrap();
        assert!(label.ends_with('B'));
        for name in ["REPORT.md", "REPORT.html"] {
            assert!(std::fs::read_to_string(run.0.join(name))
                .unwrap()
                .contains(label));
        }
    }
}

#[test]
fn batch_publication_pins_all_inputs_through_both_index_writes() {
    let a = finished_review();
    let b = finished_review();
    let paths = vec![b.0.clone(), a.0.clone(), b.0.clone()];
    let mut mutation = None;
    omgs::runmeta::with_run_locks(&paths, false, || {
        let runs = [&a, &b]
            .iter()
            .map(|run| {
                omgs::batch::summarize_locked(
                    &omgs::batch::BatchRun {
                        run_dir: Some(run.0.to_string_lossy().into()),
                        ..Default::default()
                    },
                    &a.1,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert!(runs.iter().all(|run| run.state == "complete"));
        let (send, receive) = std::sync::mpsc::channel();
        let path = a.0.clone();
        mutation = Some(std::thread::spawn(move || {
            let lock = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path.join(".omgs-run.lock"))
                .unwrap();
            send.send(matches!(
                lock.try_lock(),
                Err(std::fs::TryLockError::WouldBlock)
            ))
            .unwrap();
            drop(lock);
            attempts::append(
                &path,
                serde_json::from_value(stop("blue", "policy")).unwrap(),
            )
            .unwrap();
        }));
        assert!(receive
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap());
        omgs::runmeta::write_atomic(
            &a.1.join("INDEX.md"),
            &omgs::batch::render_index_markdown(&runs),
        )?;
        omgs::runmeta::write_atomic(
            &a.1.join("INDEX.html"),
            &omgs::batch::render_index_html(&runs),
        )?;
        assert!(omgs::review::View::load_locked(&a.0)?.complete());
        Ok(())
    })
    .unwrap();
    mutation.unwrap().join().unwrap();
    assert!(!omgs::review::View::load(&a.0).unwrap().complete());
}
