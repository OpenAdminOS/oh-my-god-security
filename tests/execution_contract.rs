//! Contract failures must prevent spending calls or accepting pilot credit.
use omgs::{
    attempts::{self, Event},
    contract,
};
use serde_json::json;
use std::path::PathBuf;
struct Run(PathBuf);
impl Run {
    fn new() -> Self {
        let p = omgs::platform::temp_root().unwrap().join(format!(
            "omgs-contract-{}",
            omgs::platform::random_nonce().unwrap()
        ));
        omgs::platform::create_private_tree(&p).unwrap();
        omgs::runmeta::write_atomic(
            &p.join(omgs::runmeta::FILE),
            &json!({"source_ref":"abc", "budget_agent_calls":12}).to_string(),
        )
        .unwrap();
        Self(p)
    }
    fn contract(&self) -> contract::Contract {
        contract::decode(json!({"version":1,"source_ref":"abc","scope":["source"],"exclusions":["Windows runtime"],"roles":{"hunter":{"provider":"ollama","model":"local","location":"mini"},"verifier":{"provider":"ollama","model":"local","location":"mini"},"evaluator":{"provider":"ollama","model":"local","location":"mini"}},"verification":"source_only","retention":"reports_only","pilot_call_limit":3,"accepted_by":"owner"})).unwrap()
    }
    fn ready(&self) {
        let checks = ["model", "storage", "source", "validation", "cleanup"]
            .into_iter()
            .map(|k| {
                (
                    k.to_string(),
                    contract::Check {
                        state: "passed".into(),
                        evidence: "host checked".into(),
                    },
                )
            })
            .collect();
        contract::readiness(
            &self.0,
            contract::Readiness {
                source_ref: "abc".into(),
                checks,
            },
        )
        .unwrap();
    }
    fn start(&self, id: &str, role: &str, phase: &str) {
        attempts::append(
            &self.0,
            Event::Start {
                id: id.into(),
                role: role.into(),
                identity: id.into(),
                context: id.into(),
                inputs: vec!["scope".into()],
                outputs: vec!["result".into()],
                isolation: "procedural".into(),
            },
        )
        .unwrap();
        contract::bind(
            &self.0,
            contract::Binding {
                attempt: id.into(),
                execution: self.contract().roles[role].clone(),
                phase: phase.into(),
                boundary: "input to storage".into(),
                actor: "user".into(),
                entry: "input".into(),
                effect: "storage".into(),
                invariant: "authorized writes".into(),
            },
        )
        .unwrap();
    }
    fn dispatch(&self, id: &str, turn: &str) -> Result<attempts::AppendOutcome, String> {
        attempts::append(
            &self.0,
            Event::Dispatch {
                id: id.into(),
                turn: turn.into(),
                actor: "host".into(),
                reason: "review".into(),
            },
        )
    }
}
impl Drop for Run {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn locked_execution_requires_readiness_pilot_and_preserves_budget_on_rejection() {
    let r = Run::new();
    contract::lock(&r.0, r.contract()).unwrap();
    let mut changed = r.contract();
    changed.roles.get_mut("hunter").unwrap().model = "cloud".into();
    assert!(contract::lock(&r.0, changed)
        .unwrap_err()
        .contains("immutable"));
    r.start("hunt", "hunter", "review");
    assert!(r.dispatch("hunt", "1").unwrap_err().contains("readiness"));
    r.ready();
    assert!(r.dispatch("hunt", "1").unwrap_err().contains("pilot"));
    let m = omgs::runmeta::read(&r.0).unwrap();
    assert!(m.get("agent_calls_used").is_none());
    assert!(contract::check_model(&m, "hunter", "cloud").is_err());
}
#[test]
fn pilot_limit_is_charged_once_and_stop_prevents_new_dispatch() {
    let r = Run::new();
    contract::lock(&r.0, r.contract()).unwrap();
    r.ready();
    r.start("pilot", "hunter", "pilot");
    r.dispatch("pilot", "1").unwrap();
    let mut changed: contract::Readiness =
        contract::decode(omgs::runmeta::read(&r.0).unwrap()["readiness"].clone()).unwrap();
    changed.checks.get_mut("model").unwrap().evidence = "different backend".into();
    assert!(contract::readiness(&r.0, changed)
        .unwrap_err()
        .contains("immutable after dispatch"));
    assert_eq!(
        r.dispatch("pilot", "1").unwrap(),
        attempts::AppendOutcome::AlreadyRecorded
    );
    r.dispatch("pilot", "2").unwrap();
    r.dispatch("pilot", "3").unwrap();
    assert!(r.dispatch("pilot", "4").unwrap_err().contains("limit"));
    assert_eq!(
        omgs::runmeta::read(&r.0).unwrap()["agent_calls_used"],
        json!(3)
    );
    attempts::append(
        &r.0,
        Event::Stop {
            id: "pilot".into(),
            actor: "host".into(),
            kind: "provider".into(),
            reason: "refused".into(),
            artifacts: vec![],
            disposition: "discarded".into(),
        },
    )
    .unwrap();
    r.start("other", "verifier", "pilot");
    assert!(r
        .dispatch("other", "1")
        .unwrap_err()
        .contains("safety stop"));
}
#[test]
fn completed_undispatched_roles_cannot_grant_pilot_credit() {
    let r = Run::new();
    contract::lock(&r.0, r.contract()).unwrap();
    r.ready();
    for role in ["hunter", "verifier", "evaluator"] {
        r.start(role, role, "pilot");
        attempts::append(
            &r.0,
            Event::Complete {
                id: role.into(),
                actor: "host".into(),
                reason: "done".into(),
            },
        )
        .unwrap();
    }
    omgs::runmeta::write_atomic(&r.0.join("result.json"), "{}").unwrap();
    let p = contract::Pilot {
        hunter: "hunter".into(),
        verifier: "verifier".into(),
        evaluator: "evaluator".into(),
        source_accuracy: true,
        counterevidence: true,
        structured_output: true,
        evidence: vec!["result.json".into()],
        proof_ref: None,
    };
    assert!(contract::accept_pilot(&r.0, p)
        .unwrap_err()
        .contains("charged dispatch"));
}

#[test]
fn successful_pilot_allows_review_until_cleanup_closes_it() {
    let r = Run::new();
    contract::lock(&r.0, r.contract()).unwrap();
    r.ready();
    for role in ["hunter", "verifier", "evaluator"] {
        r.start(role, role, "pilot");
        r.dispatch(role, "1").unwrap();
        attempts::append(
            &r.0,
            Event::Complete {
                id: role.into(),
                actor: "host".into(),
                reason: "done".into(),
            },
        )
        .unwrap();
    }
    omgs::runmeta::write_atomic(&r.0.join("result.json"), "{}").unwrap();
    let p = contract::Pilot {
        hunter: "hunter".into(),
        verifier: "verifier".into(),
        evaluator: "evaluator".into(),
        source_accuracy: true,
        counterevidence: true,
        structured_output: true,
        evidence: vec!["result.json".into()],
        proof_ref: None,
    };
    contract::accept_pilot(&r.0, p).unwrap();
    assert!(contract::check_proof(&omgs::runmeta::read(&r.0).unwrap())
        .unwrap_err()
        .contains("source-only"));
    r.start("review", "hunter", "review");
    r.dispatch("review", "1").unwrap();
    assert!(omgs::cleanup::begin(&r.0).unwrap_err().contains("active"));
    attempts::append(
        &r.0,
        Event::Complete {
            id: "review".into(),
            actor: "host".into(),
            reason: "done".into(),
        },
    )
    .unwrap();
    omgs::cleanup::register(
        &r.0,
        omgs::cleanup::Resource {
            id: "checkout".into(),
            kind: "checkout".into(),
            location: "mini".into(),
            owner: "run".into(),
            locator: "private directory".into(),
        },
    )
    .unwrap();
    omgs::cleanup::begin(&r.0).unwrap();
    assert!(r.dispatch("review", "2").unwrap_err().contains("closing"));
    assert!(omgs::cleanup::finish(&r.0).is_err());
    omgs::cleanup::release(
        &r.0,
        omgs::cleanup::Release {
            id: "checkout".into(),
            actor: "host".into(),
            evidence: "observed absent".into(),
        },
    )
    .unwrap();
    omgs::cleanup::finish(&r.0).unwrap();
    omgs::cleanup::finish(&r.0).unwrap();
    assert_eq!(
        omgs::cleanup::show(&r.0).unwrap()["receipt"]["assurance"],
        json!("host_attested")
    );
}

#[test]
fn cli_route_refusal_records_blocker_without_fallback() {
    let r = Run::new();
    contract::lock(&r.0, r.contract()).unwrap();
    r.ready();
    let call = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
            .args(args)
            .arg("--run")
            .arg(&r.0)
            .output()
            .unwrap()
    };
    let selected = call(&["route", "--role", "hunter"]);
    assert!(
        selected.status.success(),
        "{}",
        String::from_utf8_lossy(&selected.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&selected.stdout).trim(), "local");
    let refused = call(&[
        "route",
        "--role",
        "hunter",
        "--refused",
        "local",
        "--reason",
        "provider stop",
    ]);
    assert_eq!(refused.status.code(), Some(1));
    r.start("blocked", "hunter", "pilot");
    assert!(r.dispatch("blocked", "1").unwrap_err().contains("blocker"));
    assert!(!call(&["route", "--role", "hunter", "--model", "cloud"])
        .status
        .success());
    assert!(call(&["contract", "show"]).status.success());
}
