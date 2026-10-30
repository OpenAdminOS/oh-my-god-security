//! Host-recorded attempt history. Records disclose authority, not authentication.
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    Start {
        id: String,
        role: String,
        identity: String,
        context: String,
        inputs: Vec<String>,
        outputs: Vec<String>,
        isolation: String,
    },
    Dispatch {
        id: String,
        turn: String,
        actor: String,
        reason: String,
    },
    Complete {
        id: String,
        actor: String,
        reason: String,
    },
    Stop {
        id: String,
        actor: String,
        kind: String,
        reason: String,
        artifacts: Vec<String>,
        disposition: String,
    },
    Resolve {
        id: String,
        actor: String,
        authority: String,
        reason: String,
        replacement: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub at: String,
    pub record: Event,
}
#[derive(Clone, Debug)]
pub struct Attempt {
    pub role: String,
    pub identity: String,
    pub state: String,
    pub replacement: Option<String>,
}
fn text(s: &str) -> Result<(), String> {
    if s.trim().is_empty() {
        Err("attempt fields must not be blank".into())
    } else {
        Ok(())
    }
}
pub fn history(meta: &Map<String, Value>) -> Result<Vec<Record>, String> {
    let records: Vec<Record> = meta
        .get("attempts")
        .map(|v| serde_json::from_value(v.clone()).map_err(|e| format!("attempts: {e}")))
        .transpose()?
        .unwrap_or_default();
    states(&records)?;
    Ok(records)
}
pub fn states(records: &[Record]) -> Result<BTreeMap<String, Attempt>, String> {
    let mut out: BTreeMap<String, Attempt> = BTreeMap::new();
    let mut turns = BTreeSet::new();
    for r in records {
        text(&r.at)?;
        match &r.record {
            Event::Start {
                id,
                role,
                identity,
                context,
                inputs,
                outputs,
                isolation,
            } => {
                for s in [id, role, identity, context, isolation]
                    .into_iter()
                    .chain(inputs)
                    .chain(outputs)
                {
                    text(s)?;
                }
                if !crate::route::ROLES.contains(&role.as_str())
                    || !["procedural", "host_enforced"].contains(&isolation.as_str())
                    || inputs.is_empty()
                    || outputs.is_empty()
                    || out.contains_key(id)
                {
                    return Err("start needs a unique id, role, isolation and nonempty input/output manifests".into());
                }
                out.insert(
                    id.clone(),
                    Attempt {
                        role: role.clone(),
                        identity: identity.clone(),
                        state: "active".into(),
                        replacement: None,
                    },
                );
            }
            Event::Dispatch {
                id,
                turn,
                actor,
                reason,
            } => {
                for value in [id, turn, actor, reason] {
                    text(value)?;
                }
                let attempt = out.get_mut(id).ok_or("unknown dispatch attempt")?;
                if attempt.state == "stopped" || !turns.insert((id.clone(), turn.clone())) {
                    return Err("dispatch needs an unstopped attempt and a unique turn id".into());
                }
                attempt.state = "active".into();
            }
            Event::Complete { id, actor, reason } => {
                text(actor)?;
                text(reason)?;
                let a = out.get_mut(id).ok_or("unknown attempt")?;
                if a.state != "active" {
                    return Err(
                        "only an active attempt can complete; stopped output cannot be finalized"
                            .into(),
                    );
                }
                a.state = "complete".into();
            }
            Event::Stop {
                id,
                actor,
                kind,
                reason,
                artifacts,
                disposition,
            } => {
                for s in [actor, kind, reason, disposition]
                    .into_iter()
                    .chain(artifacts)
                {
                    text(s)?;
                }
                if !["provider", "policy"].contains(&kind.as_str())
                    || !["quarantined", "discarded", "pending_review"]
                        .contains(&disposition.as_str())
                {
                    return Err("invalid stop kind or artifact disposition".into());
                }
                let a = out.get_mut(id).ok_or("unknown attempt")?;
                if a.state == "stopped" || a.replacement.is_some() {
                    return Err("attempt already stopped".into());
                }
                a.state = "stopped".into();
            }
            Event::Resolve {
                id,
                actor,
                authority,
                reason,
                replacement,
            } => {
                for s in [actor, authority, reason, replacement] {
                    text(s)?;
                }
                if !["host", "user"].contains(&authority.as_str()) {
                    return Err("resume needs existing host or user authority".into());
                }
                let old = out.get(id).ok_or("unknown stopped attempt")?;
                let new = out
                    .get(replacement)
                    .ok_or("replacement attempt must be started first")?;
                if id == replacement
                    || old.state != "stopped"
                    || old.replacement.is_some()
                    || new.state != "active"
                    || old.role != new.role
                {
                    return Err("resolve needs a stopped attempt and a fresh active replacement of the same role".into());
                }
                out.get_mut(id).unwrap().replacement = Some(replacement.clone());
            }
        }
    }
    Ok(out)
}
#[derive(Debug, PartialEq, Eq)]
pub enum AppendOutcome {
    Recorded,
    AlreadyRecorded,
}

pub fn append(run: &Path, event: Event) -> Result<AppendOutcome, String> {
    crate::runmeta::update(run, |m| {
        let mut h = history(m)?;
        if let Event::Dispatch { id, turn, .. } = &event {
            if let Some(previous) = h.iter().find(|r| matches!(&r.record, Event::Dispatch { id: old_id, turn: old_turn, .. } if old_id == id && old_turn == turn)) {
                let state = states(&h)?;
                if state.get(id).is_some_and(|a| a.state == "stopped") { return Err("stopped attempts cannot dispatch again".into()); }
                if previous.record != event { return Err("turn id is already recorded with different dispatch details".into()); }
                return Ok(AppendOutcome::AlreadyRecorded);
            }
        }
        let dispatch = matches!(&event, Event::Dispatch { .. });
        h.push(Record {
            at: crate::runmeta::timestamp(crate::runmeta::now_ms()),
            record: event,
        });
        states(&h)?;
        if dispatch {
            crate::budget::charge_calls_locked(run, m, 1)?;
        }
        if let Some(Record {
            record: Event::Start { id, role, .. },
            ..
        }) = h.last()
        {
            let role = match role.as_str() {
                "hunter" => "red-hunter",
                "verifier" => "blue-verifier",
                "guard" => "green-fixer",
                other => other,
            };
            m.entry("accounting")
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .ok_or("accounting must be an object")?
                .insert(
                    format!("{role}@{id}"),
                    json!({"tokens":null,"cost_usd":null,"duration_ms":null}),
                );
        }
        let stopped = matches!(h.last().map(|r| &r.record), Some(Event::Stop { .. }));
        m.insert(
            "run_status".into(),
            json!(if stopped { "partial" } else { "in_progress" }),
        );
        m.insert(
            "attempts".into(),
            serde_json::to_value(h).map_err(|e| e.to_string())?,
        );
        if dispatch {
            let usage = crate::accounting::read(m)?;
            m.insert(
                "accounting".into(),
                serde_json::to_value(usage).map_err(|e| e.to_string())?,
            );
        }
        Ok(AppendOutcome::Recorded)
    })
}
pub fn final_for(
    meta: &Map<String, Value>,
    id: &str,
    role: &str,
    identity: &str,
) -> Result<(), String> {
    let attempts = states(&history(meta)?)?;
    let a = attempts
        .get(id)
        .ok_or("final decision has no recorded attempt")?;
    if a.state != "complete"
        || a.role != role
        || crate::model::identity(&Some(a.identity.clone()))
            != crate::model::identity(&Some(identity.into()))
    {
        return Err(
            "final decision requires its completed attempt and matching role identity".into(),
        );
    }
    Ok(())
}
pub fn gaps(meta: &Map<String, Value>) -> Result<Vec<String>, String> {
    let mut gaps = Vec::new();
    for (id, a) in states(&history(meta)?)? {
        if a.state == "active" || (a.state == "stopped" && a.replacement.is_none()) {
            gaps.push(format!("attempt {id}: {}", a.state));
        }
    }
    gaps.extend(active_blockers(meta)?);
    Ok(gaps)
}

// Blocker events are append-only; legacy strings remain visible until explicitly resolved.
pub fn active_blockers(meta: &Map<String, Value>) -> Result<Vec<String>, String> {
    let mut active: BTreeMap<String, String> = BTreeMap::new();
    if let Some(v) = meta.get("blockers") {
        for (i, s) in v
            .as_array()
            .ok_or("blockers must be an array")?
            .iter()
            .enumerate()
        {
            active.insert(
                format!("legacy-{i}"),
                s.as_str().ok_or("blocker must be a string")?.into(),
            );
        }
    }
    let mut seen: BTreeSet<String> = active.keys().cloned().collect();
    if let Some(v) = meta.get("blocker_events") {
        for e in v.as_array().ok_or("blocker_events must be an array")? {
            let field = |k: &str| {
                e.get(k)
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                    .ok_or_else(|| format!("blocker event needs {k}"))
            };
            let id = field("id")?;
            field("actor")?;
            field("reason")?;
            field("at")?;
            match field("state")? {
                "active" => {
                    if !seen.insert(id.into()) {
                        return Err("blocker id must never be reused".into());
                    }
                    if active.insert(id.into(), field("reason")?.into()).is_some() {
                        return Err("duplicate active blocker".into());
                    }
                }
                "resolved" => {
                    if active.remove(id).is_none() {
                        return Err("cannot resolve inactive blocker".into());
                    }
                    let replacement = field("replacement")?;
                    if !states(&history(meta)?)?.contains_key(replacement) {
                        return Err("blocker resolution needs recorded replacement attempt".into());
                    }
                }
                _ => return Err("invalid blocker state".into()),
            }
        }
    }
    Ok(active
        .into_iter()
        .map(|(id, reason)| format!("blocker {id}: {reason}"))
        .collect())
}
pub fn blocker(
    meta: &mut Map<String, Value>,
    id: &str,
    state: &str,
    actor: &str,
    reason: &str,
    replacement: Option<&str>,
) -> Result<(), String> {
    let e = json!({"id":id,"state":state,"actor":actor,"reason":reason,"replacement":replacement,"at":crate::runmeta::timestamp(crate::runmeta::now_ms())});
    meta.entry("blocker_events")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or("blocker_events must be an array")?
        .push(e);
    active_blockers(meta)?;
    if state == "active" {
        meta.insert("run_status".into(), json!("partial"));
    }
    Ok(())
}

pub fn finding_gaps(
    run: &Path,
    findings: &crate::model::FindingsFile,
) -> Result<Vec<String>, String> {
    let meta = crate::runmeta::read_optional(run)?.unwrap_or_default();
    finding_gaps_for(&meta, findings)
}

pub(crate) fn finding_gaps_for(
    meta: &Map<String, Value>,
    findings: &crate::model::FindingsFile,
) -> Result<Vec<String>, String> {
    let mut gaps = Vec::new();
    for f in &findings.findings {
        if let Some(v) = &f.verification {
            if let Err(e) = final_for(
                meta,
                &v.attempt,
                "verifier",
                f.verified_by.as_deref().unwrap_or(""),
            ) {
                gaps.push(format!("{}: {e}", f.fingerprint));
            }
        }
    }
    Ok(gaps)
}

/// Dispositions retain their source attempt until the host reconciles them.
pub fn ledger_gaps(run: &Path, ledger: &crate::ledger::Ledger) -> Result<Vec<String>, String> {
    let meta = crate::runmeta::read_optional(run)?.unwrap_or_default();
    let attempts = states(&history(&meta)?)?;
    let active = active_blockers(&meta)?;
    let mut gaps = Vec::new();
    for unit in &ledger.units {
        let attempt = unit.extra.get("attempt_ref");
        let blocker = unit.extra.get("blocker_ref");
        if unit.status == "blocked" && attempt.is_none() && blocker.is_none() {
            gaps.push(format!(
                "unit {}: blocked disposition needs attempt_ref or blocker_ref",
                unit.id
            ));
        }
        if let Some(value) = attempt {
            let current = value.as_str().and_then(|id| attempts.get(id));
            if current.is_none_or(|a| a.state == "complete" || a.replacement.is_some()) {
                gaps.push(format!(
                    "unit {}: reconcile stale or unknown attempt_ref",
                    unit.id
                ));
            }
        }
        if let Some(value) = blocker {
            if !value.as_str().is_some_and(|id| {
                active
                    .iter()
                    .any(|s| s.starts_with(&format!("blocker {id}:")))
            }) {
                gaps.push(format!(
                    "unit {}: reconcile resolved or unknown blocker_ref",
                    unit.id
                ));
            }
        }
    }
    Ok(gaps)
}

/// Drafts and stopped output are retained as pending work, never published decisions.
pub fn publication(
    run: &Path,
    file: &crate::model::FindingsFile,
) -> Result<crate::model::FindingsFile, String> {
    Ok(crate::review::View::with_findings(run, file)?.findings)
}

pub(crate) fn project(
    meta: &Map<String, Value>,
    file: &crate::model::FindingsFile,
) -> crate::model::FindingsFile {
    let mut out = file.clone();
    for f in &mut out.findings {
        let finalized = f.verification.as_ref().is_some_and(|v| {
            v.state == "final"
                && final_for(
                    meta,
                    &v.attempt,
                    "verifier",
                    f.verified_by.as_deref().unwrap_or(""),
                )
                .is_ok()
        });
        if !finalized {
            f.verdict = crate::model::Verdict::NeedsValidation;
            f.severity = None;
            f.fix_brief = None;
            f.proof_tier = crate::model::ProofTier::Traced;
            f.proof_ref = None;
            f.verification = None;
            const DRAFT: &str =
                "Verification incomplete. Retained draft, not a finalized decision. ";
            if !f.evidence.starts_with(DRAFT) {
                f.evidence = format!("{DRAFT}{}", f.evidence);
            }
        }
    }
    out
}
