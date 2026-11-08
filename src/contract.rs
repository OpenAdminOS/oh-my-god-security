//! A host-declared execution agreement. Enforces CLI dispatch, not a network sandbox.
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{collections::BTreeMap, path::Path};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    pub provider: String,
    pub model: String,
    pub location: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    pub version: u8,
    pub source_ref: String,
    pub scope: Vec<String>,
    pub exclusions: Vec<String>,
    pub roles: BTreeMap<String, Execution>,
    pub verification: String,
    pub retention: String,
    pub pilot_call_limit: u32,
    pub accepted_by: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Readiness {
    pub source_ref: String,
    pub checks: BTreeMap<String, Check>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub state: String,
    pub evidence: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub attempt: String,
    pub execution: Execution,
    pub phase: String,
    pub boundary: String,
    pub actor: String,
    pub entry: String,
    pub effect: String,
    pub invariant: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pilot {
    pub hunter: String,
    pub verifier: String,
    pub evaluator: String,
    pub source_accuracy: bool,
    pub counterevidence: bool,
    pub structured_output: bool,
    pub evidence: Vec<String>,
    pub proof_ref: Option<String>,
}
fn nonblank(s: &str) -> Result<(), String> {
    if s.trim().is_empty() || s.chars().any(char::is_control) {
        Err("contract values must be nonblank and contain no control characters".into())
    } else {
        Ok(())
    }
}
pub fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, String> {
    serde_json::from_value(value).map_err(|e| e.to_string())
}
pub fn load(meta: &Map<String, Value>) -> Result<Option<Contract>, String> {
    meta.get("execution_contract")
        .cloned()
        .map(decode)
        .transpose()
}
fn require(meta: &Map<String, Value>) -> Result<Contract, String> {
    load(meta)?.ok_or("lock an execution contract first".into())
}
pub fn lock(run: &Path, c: Contract) -> Result<(), String> {
    if c.version != 1
        || !["source_only", "sandbox_tests"].contains(&c.verification.as_str())
        || !["reports_only", "evidence"].contains(&c.retention.as_str())
        || !(3..=12).contains(&c.pilot_call_limit)
        || c.scope.is_empty()
    {
        return Err(
            "invalid contract version, verification, retention, scope or pilot limit (3..12)"
                .into(),
        );
    }
    for s in [&c.source_ref, &c.accepted_by]
        .into_iter()
        .chain(&c.scope)
        .chain(&c.exclusions)
    {
        nonblank(s)?;
    }
    for role in ["hunter", "verifier", "evaluator"] {
        if !c.roles.contains_key(role) {
            return Err(format!("contract missing {role} execution"));
        }
    }
    for (role, e) in &c.roles {
        if !crate::route::ROLES.contains(&role.as_str()) {
            return Err(format!("unknown contract role {role}"));
        }
        for s in [&e.provider, &e.model, &e.location] {
            nonblank(s)?;
        }
    }
    crate::runmeta::update(run, |m| {
        if let Some(old) = load(m)? {
            return if old == c {
                Ok(())
            } else {
                Err("execution contract is immutable; make a separately authorized run to change it".into())
            };
        }
        if !crate::attempts::history(m)?.is_empty() {
            return Err("lock contract before registering attempts".into());
        }
        if m.get("source_ref").and_then(Value::as_str) != Some(&c.source_ref) {
            return Err("contract source_ref must match initialized run".into());
        }
        if m.get("budget_agent_calls")
            .and_then(Value::as_u64)
            .is_some_and(|n| n < u64::from(c.pilot_call_limit) + 3)
        {
            return Err(
                "budget cannot fund pilot plus three reserved verification/reporting calls".into(),
            );
        }
        m.insert(
            "execution_contract".into(),
            serde_json::to_value(c).map_err(|e| e.to_string())?,
        );
        m.insert(
            "contract_locked_at".into(),
            json!(crate::runmeta::timestamp(crate::runmeta::now_ms())),
        );
        Ok(())
    })
}
pub fn readiness(run: &Path, r: Readiness) -> Result<(), String> {
    crate::runmeta::update(run, |m| {
        let c = require(m)?;
        if c.source_ref != r.source_ref {
            return Err("readiness source does not match contract".into());
        }
        for name in ["model", "storage", "source", "validation", "cleanup"] {
            if !r.checks.contains_key(name) {
                return Err(format!("readiness missing {name} check"));
            }
        }
        for (name, check) in &r.checks {
            nonblank(name)?;
            nonblank(&check.evidence)?;
            if !["passed", "blocked"].contains(&check.state.as_str()) {
                return Err("readiness state must be passed or blocked".into());
            }
        }
        // Requalification cannot reset the consumed pilot allowance.
        let value = serde_json::to_value(r).map_err(|e| e.to_string())?;
        if m.get("readiness") != Some(&value) {
            if crate::attempts::history(m)?
                .iter()
                .any(|r| matches!(r.record, crate::attempts::Event::Dispatch { .. }))
            {
                return Err("readiness is immutable after dispatch; stop changed infrastructure and request a new authorized run".into());
            }
            m.remove("pilot");
            if m.contains_key("readiness") {
                m.remove("execution_bindings");
            }
        }
        m.insert("readiness".into(), value);
        Ok(())
    })
}
fn ready(m: &Map<String, Value>) -> Result<(), String> {
    let c = require(m)?;
    let r: Readiness = decode(
        m.get("readiness")
            .cloned()
            .ok_or("readiness has not been recorded")?,
    )?;
    if r.source_ref != c.source_ref
        || ["model", "storage", "source", "validation", "cleanup"]
            .iter()
            .any(|k| !r.checks.contains_key(*k))
        || r.checks.values().any(|v| v.state != "passed")
    {
        return Err("readiness is blocked; do not dispatch or silently change the scope".into());
    }
    Ok(())
}
pub fn bind(run: &Path, b: Binding) -> Result<(), String> {
    for s in [
        &b.attempt,
        &b.boundary,
        &b.actor,
        &b.entry,
        &b.effect,
        &b.invariant,
    ] {
        nonblank(s)?;
    }
    if !["pilot", "review"].contains(&b.phase.as_str()) {
        return Err("binding phase must be pilot or review".into());
    }
    crate::runmeta::update(run, |m| {
        let c = require(m)?;
        let states = crate::attempts::states(&crate::attempts::history(m)?)?;
        let a = states
            .get(&b.attempt)
            .ok_or("register attempt before binding its execution")?;
        if a.state != "active" || c.roles.get(&a.role) != Some(&b.execution) {
            return Err(
                "attempt execution differs from locked role/provider/model/location".into(),
            );
        }
        let bindings = m
            .entry("execution_bindings")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or("bindings must be an object")?;
        let value = serde_json::to_value(&b).map_err(|e| e.to_string())?;
        if bindings.get(&b.attempt).is_some_and(|old| old != &value) {
            return Err("attempt binding is immutable".into());
        }
        bindings.insert(b.attempt, value);
        Ok(())
    })
}
pub fn check_dispatch(run: &Path, m: &Map<String, Value>, id: &str) -> Result<(), String> {
    let Some(c) = load(m)? else {
        return Ok(());
    }; // Legacy runs remain readable/usable.
    if m.contains_key("cleanup_started_at") {
        return Err("run is closing; new dispatch refused".into());
    }
    ready(m)?;
    if m.contains_key("pilot_failure") {
        return Err("pilot failed; further calls require a new authorized run".into());
    }
    if !crate::attempts::active_blockers(m)?.is_empty() {
        return Err("active blocker prevents dispatch".into());
    }
    let h = crate::attempts::history(m)?;
    let states = crate::attempts::states(&h)?;
    let a = states.get(id).ok_or("unknown dispatch attempt")?;
    let b: Binding = decode(
        m.get("execution_bindings")
            .and_then(|v| v.get(id))
            .cloned()
            .ok_or("dispatch needs an execution binding")?,
    )?;
    if b.attempt != id
        || !["pilot", "review"].contains(&b.phase.as_str())
        || c.roles.get(&a.role) != Some(&b.execution)
    {
        return Err("dispatch execution violates contract".into());
    }
    // A refusal never selects another model. Recovery remains a separate host-policy decision.
    if states
        .values()
        .any(|a| a.state == "stopped" && a.replacement.is_none())
    {
        return Err(
            "unresolved safety stop: dispatch blocked; no automatic retry or fallback".into(),
        );
    }
    if b.phase == "pilot" {
        let used = h.iter().filter(|r| matches!(&r.record, crate::attempts::Event::Dispatch { id, .. } if m.get("execution_bindings").and_then(|v| v.get(id)).and_then(|v|v.get("phase")).and_then(Value::as_str)==Some("pilot"))).count();
        if used >= c.pilot_call_limit as usize {
            return Err("pilot call limit exhausted".into());
        }
    } else {
        let _: Pilot = decode(
            m.get("pilot")
                .cloned()
                .ok_or("pilot has not passed; scaled dispatch refused")?,
        )?;
        if a.role == "hunter"
            && crate::budget::remaining_locked(run, m)?.is_some_and(|remaining| remaining <= 3)
        {
            return Err("remaining calls reserved for verification and reporting".into());
        }
    }
    Ok(())
}
pub fn accept_pilot(run: &Path, p: Pilot) -> Result<(), String> {
    if !(p.source_accuracy && p.counterevidence && p.structured_output) || p.evidence.is_empty() {
        crate::runmeta::update(run, |m| {
            require(m)?;
            m.remove("pilot");
            m.insert("run_status".into(), json!("partial"));
            m.insert("pilot_failure".into(), json!({"decision":p,"recorded_at":crate::runmeta::timestamp(crate::runmeta::now_ms())}));
            Ok(())
        })?;
        return Err(
            "pilot failed quality checks; stop persisted; new authorization/run required".into(),
        );
    }
    for e in &p.evidence {
        crate::run_artifact::check_containment(run, Path::new(e))?;
    }
    crate::runmeta::update(run, |m| {
        let c = require(m)?;
        ready(m)?;
        if m.contains_key("pilot_failure") {
            return Err("failed pilot cannot be overwritten; new authorized run required".into());
        }
        if !crate::attempts::active_blockers(m)?.is_empty() {
            return Err("active blocker prevents pilot acceptance".into());
        }
        let history = crate::attempts::history(m)?;
        let states = crate::attempts::states(&history)?;
        let mut identities = std::collections::BTreeSet::new();
        let mut contexts = std::collections::BTreeSet::new();
        for (id, role) in [
            (&p.hunter, "hunter"),
            (&p.verifier, "verifier"),
            (&p.evaluator, "evaluator"),
        ] {
            let a = states.get(id).ok_or("pilot attempt missing")?;
            if a.role != role || a.state != "complete" || !identities.insert(&a.identity) {
                return Err("pilot requires three completed independent role identities".into());
            }
            let context = history
                .iter()
                .find_map(|r| match &r.record {
                    crate::attempts::Event::Start {
                        id: started,
                        context,
                        ..
                    } if started == id => Some(context),
                    _ => None,
                })
                .ok_or("pilot context missing")?;
            if !contexts.insert(context) {
                return Err("pilot roles must use distinct contexts".into());
            }
            if !history.iter().any(|r| matches!(&r.record, crate::attempts::Event::Dispatch { id: dispatched, .. } if dispatched == id)) { return Err("pilot role has no charged dispatch".into()); }
            if m.get("execution_bindings")
                .and_then(|v| v.get(id))
                .and_then(|v| v.get("phase"))
                .and_then(Value::as_str)
                != Some("pilot")
            {
                return Err("pilot decision names a non-pilot attempt".into());
            }
        }
        if c.verification == "sandbox_tests" {
            let reference = p
                .proof_ref
                .as_deref()
                .ok_or("sandbox-tests pilot requires real runner evidence")?;
            let record = crate::proof::load(run, reference)?;
            if record.target_head.as_deref() != Some(&c.source_ref)
                || crate::proof::outer_exit(&record) > 1
                || !crate::proof::runner_evidence(run, &record).is_empty()
            {
                return Err("pilot proof is not clean runner evidence for this source".into());
            }
        }
        if states
            .values()
            .any(|a| a.state == "stopped" && a.replacement.is_none())
        {
            return Err("unresolved safety stop prevents pilot acceptance".into());
        }
        m.insert(
            "pilot".into(),
            serde_json::to_value(p).map_err(|e| e.to_string())?,
        );
        Ok(())
    })
}
pub fn check_model(m: &Map<String, Value>, role: &str, model: &str) -> Result<(), String> {
    if let Some(c) = load(m)? {
        if c.roles.get(role).is_none_or(|e| e.model != model) {
            return Err("model label/route differs from locked execution contract".into());
        }
    }
    Ok(())
}
pub fn gaps(m: &Map<String, Value>) -> Result<Vec<String>, String> {
    let Some(c) = load(m)? else {
        return Ok(vec![]);
    };
    let mut gaps = vec![];
    if let Err(e) = ready(m) {
        gaps.push(format!("Readiness: {e}"));
    }
    if m.contains_key("pilot_failure") {
        gaps.push("Pilot failed; further calls are stopped".into());
    }
    if !m.contains_key("pilot") {
        gaps.push("Pilot quality/validation gate has not passed".into());
    }
    if c.verification == "source_only" {
        gaps.push("Contract scope is source-only; runtime validation was not authorized".into());
    }
    Ok(gaps)
}
pub fn describe(m: &Map<String, Value>) -> Result<Vec<String>, String> {
    let Some(c) = load(m)? else {
        return Ok(vec![]);
    };
    let mut lines = vec![format!(
        "Contract: verification={}, retention={}, scope={}, exclusions={}",
        c.verification,
        c.retention,
        c.scope.join("; "),
        c.exclusions.join("; ")
    )];
    for (role, e) in c.roles {
        lines.push(format!(
            "{role}: {} / {} on {}",
            e.provider, e.model, e.location
        ));
    }
    Ok(lines)
}

/// Proofs cannot expand a source-only contract or resume a closing/stopped run.
pub fn check_proof(m: &Map<String, Value>) -> Result<(), String> {
    if m.contains_key("cleanup_started_at") {
        return Err("run is closing; proof refused".into());
    }
    if let Some(c) = load(m)? {
        if m.contains_key("pilot_failure") {
            return Err("failed pilot prevents proof".into());
        }
        if c.verification != "sandbox_tests" {
            return Err("source-only contract excludes target execution".into());
        }
        ready(m)?;
        if !crate::attempts::active_blockers(m)?.is_empty() {
            return Err("active blocker prevents proof".into());
        }
        if crate::attempts::states(&crate::attempts::history(m)?)?
            .values()
            .any(|a| a.state == "stopped" && a.replacement.is_none())
        {
            return Err("unresolved safety stop prevents proof".into());
        }
    }
    Ok(())
}

/// Validate both the prepared request identity and the current checkout at admission.
pub fn check_proof_target(
    m: &Map<String, Value>,
    target: Option<&Path>,
    expected_head: Option<&str>,
) -> Result<(), String> {
    check_proof(m)?;
    if let Some(c) = load(m)? {
        let head = target.and_then(crate::proof::git_head);
        if expected_head != Some(c.source_ref.as_str())
            || head.as_deref() != Some(c.source_ref.as_str())
        {
            return Err("proof target revision differs from locked source_ref".into());
        }
    }
    Ok(())
}
