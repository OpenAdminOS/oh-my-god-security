//! Contract failures must prevent spending calls or accepting pilot credit.
use omgs::{
    attempts::{self, Event},
    contract,
};
use serde_json::json;
use std::path::PathBuf;
struct Run(PathBuf, PathBuf);
impl Run {
    fn new() -> Self {
        let p = omgs::platform::temp_root().unwrap().join(format!(
            "omgs-contract-{}",
            omgs::platform::random_nonce().unwrap()
        ));
        omgs::platform::create_private_tree(&p).unwrap();
        let root = p;
        let p = root.join("run");
        omgs::platform::create_private_dir(&p).unwrap();
        omgs::runmeta::write_atomic(
            &p.join(omgs::runmeta::FILE),
            &json!({"source_ref":"abc", "budget_agent_calls":12}).to_string(),
        )
        .unwrap();
        Self(p, root)
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
                source_ref: omgs::runmeta::read(&self.0).unwrap()["source_ref"]
                    .as_str()
                    .unwrap()
                    .into(),
                checks,
            },
        )
        .unwrap();
    }
    fn start(&self, id: &str, role: &str, phase: &str) {
        self.start_as(id, role, phase, id);
    }
    fn start_as(&self, id: &str, role: &str, phase: &str, identity: &str) {
        attempts::append(
            &self.0,
            Event::Start {
                id: id.into(),
                role: role.into(),
                identity: identity.into(),
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
        let _ = std::fs::remove_dir_all(&self.1);
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
    omgs::runmeta::update(&r.0, |m| {
        m.insert("proof_runs_used".into(), json!(6));
        Ok(())
    })
    .unwrap();
    assert!(r.dispatch("review", "1").unwrap_err().contains("reserved"));
    assert_eq!(
        omgs::runmeta::read(&r.0).unwrap()["agent_calls_used"],
        json!(3)
    );
    // Restore the synthetic fixture to exercise the ordinary successful path too.
    omgs::runmeta::update(&r.0, |m| {
        m.insert("proof_runs_used".into(), json!(0));
        Ok(())
    })
    .unwrap();
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
    assert_eq!(
        r.dispatch("review", "1").unwrap(),
        attempts::AppendOutcome::AlreadyRecorded
    );
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
    let before = omgs::runmeta::read(&r.0).unwrap()["blocker_events"].clone();
    assert!(!call(&["route", "--role", "hunter"]).status.success());
    assert_eq!(omgs::runmeta::read(&r.0).unwrap()["blocker_events"], before);
}

#[test]
fn failed_pilot_is_durable_and_cannot_be_reaccepted() {
    let r = Run::new();
    let mut c = r.contract();
    c.pilot_call_limit = 6;
    contract::lock(&r.0, c).unwrap();
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
    omgs::runmeta::write_atomic(&r.0.join("quality.json"), "{}").unwrap();
    let mut p = contract::Pilot {
        hunter: "hunter".into(),
        verifier: "verifier".into(),
        evaluator: "evaluator".into(),
        source_accuracy: true,
        counterevidence: true,
        structured_output: true,
        evidence: vec!["quality.json".into()],
        proof_ref: None,
    };
    contract::accept_pilot(&r.0, p.clone()).unwrap();
    p.source_accuracy = false;
    assert!(contract::accept_pilot(&r.0, p.clone())
        .unwrap_err()
        .contains("persisted"));
    let m = omgs::runmeta::read(&r.0).unwrap();
    assert!(m.get("pilot").is_none());
    assert!(m.get("pilot_failure").is_some());
    r.start("pilot", "hunter", "pilot");
    assert!(r
        .dispatch("pilot", "1")
        .unwrap_err()
        .contains("pilot failed"));
    r.start("scaled", "hunter", "review");
    assert!(r
        .dispatch("scaled", "1")
        .unwrap_err()
        .contains("pilot failed"));
    p.source_accuracy = true;
    assert!(contract::accept_pilot(&r.0, p)
        .unwrap_err()
        .contains("cannot be overwritten"));
}

#[test]
fn proof_admission_rechecks_stop_and_revision_and_holds_cleanup_closed() {
    let r = Run::new();
    let target = r.0.join("target");
    std::fs::create_dir(&target).unwrap();
    let git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(&target)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&[
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "--allow-empty",
        "-qm",
        "A",
    ]);
    let a = omgs::proof::git_head(&target).unwrap();
    omgs::runmeta::update(&r.0, |m| {
        m.insert("source_ref".into(), json!(a));
        Ok(())
    })
    .unwrap();
    let mut c = r.contract();
    c.source_ref = a.clone();
    c.verification = "sandbox_tests".into();
    contract::lock(&r.0, c).unwrap();
    r.ready();
    let admission = omgs::budget::ProofAdmission::admit(&r.0, Some(&target), Some(&a)).unwrap();
    assert!(omgs::cleanup::begin(&r.0)
        .unwrap_err()
        .contains("active proofs"));
    omgs::runmeta::update(&r.0, |m| {
        m.insert("blockers".into(), json!(["safety stop during preparation"]));
        Ok(())
    })
    .unwrap();
    assert!(admission
        .start(Some(&target))
        .unwrap_err()
        .contains("blocker"));
    drop(admission);
    assert!(omgs::runmeta::read(&r.0).unwrap()["active_proofs"]
        .as_object()
        .unwrap()
        .is_empty());
    omgs::runmeta::update(&r.0, |m| {
        m.remove("blockers");
        Ok(())
    })
    .unwrap();
    let admission = omgs::budget::ProofAdmission::admit(&r.0, Some(&target), Some(&a)).unwrap();
    git(&[
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "--allow-empty",
        "-qm",
        "B",
    ]);
    assert!(admission
        .start(Some(&target))
        .unwrap_err()
        .contains("revision"));
    assert!(
        omgs::budget::ProofAdmission::admit(&r.0, Some(&target), Some(&a))
            .err()
            .unwrap()
            .contains("revision")
    );
    drop(admission);
    git(&["checkout", "-q", &a]);
    let admission = omgs::budget::ProofAdmission::admit(&r.0, Some(&target), Some(&a)).unwrap();
    admission.start(Some(&target)).unwrap();
    drop(admission); // Uncertain cleanup must remain active, never be silently certified by Drop.
    assert!(omgs::cleanup::begin(&r.0)
        .unwrap_err()
        .contains("active proofs"));
}

#[test]
fn cleanup_closes_atomic_proof_admission_without_spending() {
    let r = Run::new();
    let proof = omgs::budget::ProofAdmission::admit(&r.0, None, None).unwrap();
    proof.start(None).unwrap();
    proof.finish().unwrap();
    omgs::cleanup::begin(&r.0).unwrap();
    let before = omgs::runmeta::read(&r.0).unwrap();
    assert!(omgs::budget::ProofAdmission::admit(&r.0, None, None)
        .err()
        .unwrap()
        .contains("closing"));
    assert_eq!(
        omgs::runmeta::read(&r.0).unwrap()["proof_runs_used"],
        before["proof_runs_used"]
    );
    assert!(omgs::runmeta::read(&r.0).unwrap()["active_proofs"]
        .as_object()
        .unwrap()
        .is_empty());
}

#[test]
fn lock_rejects_spent_calls_and_existing_proof_artifacts() {
    let r = Run::new();
    omgs::runmeta::update(&r.0, |m| {
        m.insert("agent_calls_used".into(), json!(3));
        Ok(())
    })
    .unwrap();
    assert!(contract::lock(&r.0, r.contract())
        .unwrap_err()
        .contains("before spending"));
    omgs::runmeta::update(&r.0, |m| {
        m.insert("agent_calls_used".into(), json!(0));
        Ok(())
    })
    .unwrap();
    omgs::platform::create_private_dir(&r.0.join("proofs")).unwrap();
    omgs::runmeta::write_atomic(&r.0.join("proofs/1.json"), "{}").unwrap();
    assert!(contract::lock(&r.0, r.contract())
        .unwrap_err()
        .contains("proof artifacts"));
}

#[test]
fn required_contract_marker_blocks_unlocked_new_workflow_runs() {
    let r = Run::new();
    let target = r.1.join("source");
    std::fs::create_dir(&target).unwrap();
    let run = r.1.join("newrun");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args([
            "audit",
            "init",
            "--require-contract",
            "--no-sensors",
            "--target",
        ])
        .arg(&target)
        .arg("--out")
        .arg(&run)
        .env("OMGS_HOME", r.1.join("home"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let m = omgs::runmeta::read(&run).unwrap();
    assert_eq!(m["contract_required"], json!(true));
    assert!(contract::check_dispatch(&run, &m, "missing")
        .unwrap_err()
        .contains("requires a locked"));
    assert!(contract::check_proof(&m)
        .unwrap_err()
        .contains("requires a locked"));
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args(["route", "--role", "hunter", "--run"])
        .arg(&run)
        .env("OMGS_HOME", r.1.join("home"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("requires a locked"));
    assert!(!contract::gaps(&m).unwrap().is_empty());
}

#[test]
fn empty_cleanup_receipt_covers_no_resources() {
    let r = Run::new();
    omgs::cleanup::begin(&r.0).unwrap();
    omgs::cleanup::finish(&r.0).unwrap();
    let receipt = omgs::cleanup::show(&r.0).unwrap();
    assert!(receipt["receipt"]["resources"]
        .as_object()
        .unwrap()
        .is_empty());
    assert_eq!(receipt["receipt"]["assurance"], json!("host_attested"));
}

#[test]
fn source_only_view_refuses_imported_runtime_credit() {
    let r = Run::new();
    contract::lock(&r.0, r.contract()).unwrap();
    let mut findings: omgs::model::FindingsFile =
        serde_json::from_str(include_str!("fixtures/report-run/findings.json")).unwrap();
    findings.findings[0].proof_tier = omgs::model::ProofTier::TestProven;
    let view = omgs::review::View::with_findings(&r.0, &findings).unwrap();
    assert!(view
        .decision_errors
        .values()
        .flatten()
        .any(|e| e.contains("source-only contract cannot credit runtime proof")));
}

fn initialize_linked_fix(run: &std::path::Path) -> Result<PathBuf, String> {
    initialize_named_fix(run, "fix")
}
fn initialize_named_fix(run: &std::path::Path, name: &str) -> Result<PathBuf, String> {
    omgs::budget::init_fix(
        run,
        |_| Ok(Some(12)),
        |root, _, _| {
            let child = root.parent().unwrap().join(name);
            omgs::platform::create_private_dir(&child).map_err(|e| e.to_string())?;
            omgs::runmeta::write_atomic(
                &child.join(omgs::runmeta::FILE),
                &json!({"run_id":name,"source_ref":"changed","budget_agent_calls":12}).to_string(),
            )?;
            Ok(child)
        },
    )
}
#[test]
fn linked_fixes_refuse_failed_stopped_closing_or_source_only_parents() {
    for state in ["pilot", "stop", "cleanup", "source_only"] {
        let r = Run::new();
        omgs::runmeta::update(&r.0, |m| {
            m.insert("run_id".into(), json!("root"));
            Ok(())
        })
        .unwrap();
        let mut c = r.contract();
        if state != "source_only" {
            c.verification = "sandbox_tests".into();
        }
        contract::lock(&r.0, c).unwrap();
        match state {
            "pilot" => omgs::runmeta::update(&r.0, |m| {
                m.insert("pilot_failure".into(), json!({"source_accuracy":false}));
                Ok(())
            })
            .unwrap(),
            "stop" => {
                r.start("stopped", "hunter", "pilot");
                attempts::append(
                    &r.0,
                    Event::Stop {
                        id: "stopped".into(),
                        actor: "host".into(),
                        kind: "provider".into(),
                        reason: "safety stop".into(),
                        artifacts: vec![],
                        disposition: "discarded".into(),
                    },
                )
                .unwrap();
            }
            "cleanup" => omgs::cleanup::begin(&r.0).unwrap(),
            _ => {}
        }
        assert!(
            initialize_linked_fix(&r.0)
                .unwrap_err()
                .contains("fix run refused"),
            "{state}"
        );
        assert!(!r.1.join("fix").exists());
    }
}
#[test]
fn protected_fix_is_marked_and_later_parent_stop_blocks_it() {
    let r = Run::new();
    omgs::runmeta::update(&r.0, |m| {
        m.insert("run_id".into(), json!("root"));
        Ok(())
    })
    .unwrap();
    let mut c = r.contract();
    c.verification = "sandbox_tests".into();
    contract::lock(&r.0, c.clone()).unwrap();
    let child = initialize_linked_fix(&r.0).unwrap();
    let meta = omgs::runmeta::read(&child).unwrap();
    assert_eq!(meta["contract_required"], json!(true));
    assert!(contract::check_dispatch(&child, &meta, "none")
        .unwrap_err()
        .contains("own locked"));
    assert!(omgs::budget::ProofAdmission::admit(&child, None, None)
        .err()
        .unwrap()
        .contains("own locked"));
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args(["route", "--role", "hunter", "--run"])
        .arg(&child)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("own locked"));
    c.source_ref = "changed".into();
    contract::lock(&child, c).unwrap();
    omgs::runmeta::update(&r.0, |m| {
        m.insert("pilot_failure".into(), json!({"source_accuracy":false}));
        Ok(())
    })
    .unwrap();
    let meta = omgs::runmeta::read(&child).unwrap();
    assert!(contract::check_dispatch(&child, &meta, "none")
        .unwrap_err()
        .contains("parent pilot failed"));
    assert!(omgs::budget::ProofAdmission::admit(&child, None, None)
        .err()
        .unwrap()
        .contains("parent pilot failed"));
}
#[test]
fn stranded_proof_recovery_is_host_attested_and_closes_dispatch() {
    let r = Run::new();
    let proof = omgs::budget::ProofAdmission::admit(&r.0, None, None).unwrap();
    proof.start(None).unwrap();
    drop(proof);
    let state = omgs::cleanup::show(&r.0).unwrap();
    let token = state["active_proofs"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();
    let mut resolution = omgs::cleanup::ProofResolution {
        token,
        actor: "operator".into(),
        evidence: "coordinator and owned descendants inspected and stopped".into(),
        processes_stopped: false,
    };
    assert!(omgs::cleanup::resolve_proof(&r.0, resolution.clone()).is_err());
    resolution.processes_stopped = true;
    omgs::cleanup::resolve_proof(&r.0, resolution.clone()).unwrap();
    assert!(omgs::cleanup::resolve_proof(&r.0, resolution).is_err());
    assert!(omgs::budget::ProofAdmission::admit(&r.0, None, None)
        .err()
        .unwrap()
        .contains("closing"));
    omgs::cleanup::finish(&r.0).unwrap();
    let receipt = omgs::cleanup::show(&r.0).unwrap();
    assert_eq!(
        receipt["receipt"]["proof_resolutions"][0]["assurance"],
        json!("host_attested")
    );
}

#[test]
fn nested_fix_preserves_its_intermediate_parents_stop() {
    let r = Run::new();
    omgs::runmeta::update(&r.0, |m| {
        m.insert("run_id".into(), json!("root"));
        Ok(())
    })
    .unwrap();
    let mut c = r.contract();
    c.verification = "sandbox_tests".into();
    contract::lock(&r.0, c.clone()).unwrap();
    let child = initialize_linked_fix(&r.0).unwrap();
    c.source_ref = "changed".into();
    contract::lock(&child, c.clone()).unwrap();
    let nested = initialize_named_fix(&child, "nested").unwrap();
    contract::lock(&nested, c).unwrap();
    omgs::runmeta::update(&child, |m| {
        m.insert("pilot_failure".into(), json!({"source_accuracy":false}));
        Ok(())
    })
    .unwrap();
    assert!(
        contract::check_dispatch(&nested, &omgs::runmeta::read(&nested).unwrap(), "none")
            .unwrap_err()
            .contains("parent pilot failed")
    );
    assert!(omgs::budget::ProofAdmission::admit(&nested, None, None)
        .err()
        .unwrap()
        .contains("parent pilot failed"));
    assert!(initialize_named_fix(&nested, "third")
        .unwrap_err()
        .contains("parent pilot failed"));
    assert!(!r.1.join("third").exists());
}

#[test]
fn pilot_hunter_preserves_proof_inclusive_reserve() {
    let r = Run::new();
    omgs::runmeta::update(&r.0, |m| {
        m.insert("budget_agent_calls".into(), json!(6));
        Ok(())
    })
    .unwrap();
    let mut c = r.contract();
    c.verification = "sandbox_tests".into();
    contract::lock(&r.0, c).unwrap();
    r.ready();
    for _ in 0..3 {
        omgs::budget::charge_proof(&r.0).unwrap();
    }
    r.start("hunter", "hunter", "pilot");
    assert!(r.dispatch("hunter", "1").unwrap_err().contains("reserved"));
    assert_eq!(omgs::budget::allowance(&r.0).unwrap().remaining, Some(3));
    r.start("verifier", "verifier", "pilot");
    r.dispatch("verifier", "1").unwrap();
}

#[test]
fn cleanup_checks_running_and_uncertain_proofs_across_nested_family() {
    let r = Run::new();
    omgs::runmeta::update(&r.0, |m| {
        m.insert("run_id".into(), json!("root"));
        Ok(())
    })
    .unwrap();
    let child = initialize_linked_fix(&r.0).unwrap();
    let nested = initialize_named_fix(&child, "nested").unwrap();
    let proof = omgs::budget::ProofAdmission::admit(&nested, None, None).unwrap();
    proof.start(None).unwrap();
    for path in [&r.0, &child] {
        assert!(omgs::cleanup::begin(path)
            .unwrap_err()
            .contains("active proofs"));
    }
    drop(proof); // A started proof remains uncertain until host resolution.
    for path in [&r.0, &child] {
        assert!(omgs::cleanup::begin(path)
            .unwrap_err()
            .contains("active proofs"));
        assert!(omgs::cleanup::finish(path)
            .unwrap_err()
            .contains("active proofs"));
        assert!(omgs::runmeta::read(path)
            .unwrap()
            .get("cleanup_receipt")
            .is_none());
    }
    let state = omgs::runmeta::read(&nested).unwrap();
    let token = state["active_proofs"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();
    omgs::cleanup::resolve_proof(
        &nested,
        omgs::cleanup::ProofResolution {
            token,
            actor: "host".into(),
            evidence: "verified no surviving processes".into(),
            processes_stopped: true,
        },
    )
    .unwrap();
    omgs::cleanup::begin(&r.0).unwrap();
    omgs::cleanup::finish(&r.0).unwrap();
}

#[test]
fn legacy_parent_blockers_do_not_disable_fix_execution() {
    let r = Run::new();
    omgs::runmeta::update(&r.0, |m| {
        m.insert("run_id".into(), json!("root"));
        m.insert("blockers".into(), json!(["hunter refused"]));
        Ok(())
    })
    .unwrap();
    let child = initialize_linked_fix(&r.0).unwrap();
    let meta = omgs::runmeta::read(&child).unwrap();
    assert!(meta.get("contract_required").is_none());
    contract::check_dispatch(&child, &meta, "legacy").unwrap();
    omgs::budget::charge_proof(&child).unwrap();
    omgs::runmeta::update(&r.0, |m| {
        m.insert("blockers".into(), json!(["later refusal"]));
        Ok(())
    })
    .unwrap();
    let admission = omgs::budget::ProofAdmission::admit(&child, None, None).unwrap();
    admission.start(None).unwrap();
    admission.finish().unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args(["route", "--role", "hunter", "--run"])
        .arg(&child)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    omgs::cleanup::begin(&r.0).unwrap();
    assert!(omgs::budget::charge_proof(&child)
        .unwrap_err()
        .contains("cleanup"));
}

#[test]
fn cleanup_refuses_active_agent_attempts_in_nested_fix() {
    let r = Run::new();
    omgs::runmeta::update(&r.0, |m| {
        m.insert("run_id".into(), json!("root"));
        Ok(())
    })
    .unwrap();
    let child = initialize_linked_fix(&r.0).unwrap();
    let nested = initialize_named_fix(&child, "nested").unwrap();
    attempts::append(
        &nested,
        Event::Start {
            id: "hunter".into(),
            role: "hunter".into(),
            identity: "h".into(),
            context: "h".into(),
            inputs: vec!["scope".into()],
            outputs: vec!["result".into()],
            isolation: "procedural".into(),
        },
    )
    .unwrap();
    for path in [&r.0, &child] {
        assert!(omgs::cleanup::begin(path)
            .unwrap_err()
            .contains("active attempts"));
        assert!(omgs::cleanup::finish(path)
            .unwrap_err()
            .contains("active attempts"));
    }
}

#[test]
fn cleanup_of_any_member_closes_all_family_admission() {
    for closing in 0..4 {
        let r = Run::new();
        omgs::runmeta::update(&r.0, |m| {
            m.insert("run_id".into(), json!("root"));
            Ok(())
        })
        .unwrap();
        let child = initialize_linked_fix(&r.0).unwrap();
        let sibling = initialize_named_fix(&r.0, "sibling").unwrap();
        let nested = initialize_named_fix(&child, "nested").unwrap();
        let family = [&r.0, &child, &sibling, &nested];
        omgs::cleanup::begin(family[closing]).unwrap();
        for path in family {
            let err = attempts::append(
                path,
                Event::Start {
                    id: "new".into(),
                    role: "hunter".into(),
                    identity: "h".into(),
                    context: "h".into(),
                    inputs: vec!["scope".into()],
                    outputs: vec!["result".into()],
                    isolation: "procedural".into(),
                },
            )
            .unwrap_err();
            assert!(err.contains("closing"), "{err}");
            let meta = omgs::runmeta::read(path).unwrap();
            assert!(contract::check_dispatch(path, &meta, "new")
                .unwrap_err()
                .contains("closing"));
            assert!(omgs::budget::ProofAdmission::admit(path, None, None)
                .err()
                .unwrap()
                .contains("closing"));
            assert!(initialize_named_fix(path, "forbidden").is_err());
        }
        assert!(!r.1.join("forbidden").exists());
        omgs::cleanup::finish(family[closing]).unwrap();
    }
}

#[test]
fn proof_launch_rechecks_sibling_recovery_barrier() {
    let r = Run::new();
    omgs::runmeta::update(&r.0, |m| {
        m.insert("run_id".into(), json!("root"));
        Ok(())
    })
    .unwrap();
    let child = initialize_linked_fix(&r.0).unwrap();
    let pending = omgs::budget::ProofAdmission::admit(&r.0, None, None).unwrap();
    let stranded = omgs::budget::ProofAdmission::admit(&child, None, None).unwrap();
    stranded.start(None).unwrap();
    drop(stranded);
    let state = omgs::runmeta::read(&child).unwrap();
    let token = state["active_proofs"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();
    omgs::cleanup::resolve_proof(
        &child,
        omgs::cleanup::ProofResolution {
            token,
            actor: "host".into(),
            evidence: "verified child termination".into(),
            processes_stopped: true,
        },
    )
    .unwrap();
    assert!(pending.start(None).unwrap_err().contains("closing"));
    drop(pending);
    omgs::cleanup::finish(&child).unwrap();
}

#[test]
fn pilot_rejects_case_and_whitespace_identity_aliases() {
    for alias in ["Reviewer", " reviewer "] {
        let r = Run::new();
        contract::lock(&r.0, r.contract()).unwrap();
        r.ready();
        for (role, identity) in [
            ("hunter", "reviewer"),
            ("verifier", alias),
            ("evaluator", "third"),
        ] {
            r.start_as(role, role, "pilot", identity);
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
        let err = contract::accept_pilot(
            &r.0,
            contract::Pilot {
                hunter: "hunter".into(),
                verifier: "verifier".into(),
                evaluator: "evaluator".into(),
                source_accuracy: true,
                counterevidence: true,
                structured_output: true,
                evidence: vec!["result.json".into()],
                proof_ref: None,
            },
        )
        .unwrap_err();
        assert!(
            err.contains("independent role identities"),
            "{alias}: {err}"
        );
        assert!(omgs::runmeta::read(&r.0).unwrap().get("pilot").is_none());
        r.start("review", "hunter", "review");
        assert!(r
            .dispatch("review", "1")
            .unwrap_err()
            .contains("pilot has not passed"));
    }
}

#[test]
fn lock_reconciles_preexisting_route_labels_atomically() {
    for model in ["cloud", "local"] {
        let r = Run::new();
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
            .args(["route", "--role", "hunter", "--model", model, "--run"])
            .arg(&r.0)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let result = contract::lock(&r.0, r.contract());
        let meta = omgs::runmeta::read(&r.0).unwrap();
        assert_eq!(meta["models"]["hunter"], json!(model));
        if model == "cloud" {
            assert!(result.unwrap_err().contains("model label/route differs"));
            assert!(meta.get("execution_contract").is_none());
            assert!(meta.get("contract_locked_at").is_none());
        } else {
            result.unwrap();
            assert!(meta.get("execution_contract").is_some());
        }
    }
}
