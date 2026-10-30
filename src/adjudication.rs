//! Strict role handoffs and mechanical adjudication accountability.
use crate::model::{FindingsFile, Verdict};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evaluation {
    pub evaluator: String,
    #[serde(default)]
    pub attempt: Option<String>,
    pub source_ref: String,
    pub decisions: Vec<Decision>,
    pub gaps: Vec<String>,
    #[serde(default)]
    pub leads: Vec<Lead>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub fingerprint: String,
    pub decision: String,
    pub reason: String,
    pub evidence: Vec<String>,
    pub required_changes: Vec<String>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lead {
    pub unit_id: String,
    pub reason: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dispositions {
    pub hunter: String,
    pub units: Vec<Disposition>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Disposition {
    pub unit_id: String,
    pub disposition: String,
    pub evidence: Vec<String>,
    pub note: String,
    #[serde(default)]
    pub attempt_ref: Option<String>,
    #[serde(default)]
    pub blocker_ref: Option<String>,
}

fn document(text: &str, list: &str) -> Result<Value, String> {
    let v = crate::shape::strict_json(text)?;
    if !v.is_object()
        || !v
            .get(list)
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().all(Value::is_object))
    {
        return Err(format!(
            "document must be an object with a {list} array of objects"
        ));
    }
    Ok(v)
}
fn nonblank(value: &str, key: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{key} must not be empty"))
    } else {
        Ok(())
    }
}
pub fn parse(text: &str) -> Result<Evaluation, String> {
    let v = document(text, "decisions")?;
    if v.get("leads")
        .is_some_and(|l| !l.as_array().is_some_and(|a| a.iter().all(Value::is_object)))
    {
        return Err("leads must be an array of objects".into());
    }
    if v.get("attempt")
        .is_some_and(|a| !a.as_str().is_some_and(|s| !s.trim().is_empty()))
    {
        return Err("attempt must be a nonblank string when present".into());
    }
    let e: Evaluation = serde_json::from_value(v).map_err(|e| e.to_string())?;
    nonblank(&e.evaluator, "evaluator")?;
    nonblank(&e.source_ref, "source_ref")?;
    let mut seen = BTreeSet::new();
    for d in &e.decisions {
        if !crate::model::is_fingerprint(&d.fingerprint) || !seen.insert(&d.fingerprint) {
            return Err("decision fingerprints must be valid and unique".into());
        }
        if !["uphold", "adjust", "overturn"].contains(&d.decision.as_str()) {
            return Err("decision must be uphold, adjust or overturn".into());
        }
        nonblank(&d.reason, "reason")?;
        if d.evidence
            .iter()
            .chain(&d.required_changes)
            .any(|s| s.trim().is_empty())
        {
            return Err("evidence and required_changes entries must not be blank".into());
        }
        if d.decision != "uphold" && d.required_changes.is_empty() {
            return Err("adjust and overturn require required_changes".into());
        }
    }
    for lead in &e.leads {
        nonblank(&lead.unit_id, "lead.unit_id")?;
        nonblank(&lead.reason, "lead.reason")?;
    }
    Ok(e)
}
pub fn dispositions(text: &str) -> Result<Dispositions, String> {
    let value = document(text, "units")?;
    for unit in value["units"].as_array().unwrap() {
        for key in ["attempt_ref", "blocker_ref"] {
            if unit
                .get(key)
                .is_some_and(|v| !v.as_str().is_some_and(|s| !s.trim().is_empty()))
            {
                return Err(format!("{key} must be a nonblank string when present"));
            }
        }
    }
    let d: Dispositions = serde_json::from_value(value).map_err(|e| e.to_string())?;
    nonblank(&d.hunter, "hunter")?;
    let mut seen = BTreeSet::new();
    for u in &d.units {
        nonblank(&u.unit_id, "unit_id")?;
        if !seen.insert(&u.unit_id)
            || ![
                "candidate",
                "covered",
                "blocked",
                "deferred",
                "out_of_scope",
            ]
            .contains(&u.disposition.as_str())
        {
            return Err(
                "unit ids must be unique and dispositions must use documented values".into(),
            );
        }
        if u.evidence.iter().any(|e| e.trim().is_empty()) {
            return Err("disposition evidence entries must not be blank".into());
        }
        if ["candidate", "covered"].contains(&u.disposition.as_str())
            && u.evidence.iter().all(|s| s.trim().is_empty())
        {
            return Err("candidate and covered dispositions require evidence".into());
        }
        if ["blocked", "deferred", "out_of_scope"].contains(&u.disposition.as_str()) {
            nonblank(&u.note, "note")?;
        }
    }
    Ok(d)
}
pub fn candidates(text: &str) -> Result<crate::critic::CandidatesFile, String> {
    let c = crate::shape::candidates(text)?;
    let errors: Vec<_> = c
        .candidates
        .iter()
        .enumerate()
        .flat_map(|(i, candidate)| {
            crate::critic::validate_candidate(candidate)
                .into_iter()
                .map(move |e| format!("candidates[{i}]: {e}"))
        })
        .collect();
    if errors.is_empty() {
        Ok(c)
    } else {
        Err(errors.join("; "))
    }
}

pub fn load(run: &Path) -> Result<Option<Evaluation>, String> {
    // Bounded, single-link and no-follow, like other run evidence. Only a
    // genuinely missing entry is optional; links and special files fail.
    match crate::run_artifact::read(
        run,
        Path::new("evaluation.json"),
        crate::run_artifact::EVALUATION_BYTES,
    ) {
        Ok(bytes) => {
            let s = String::from_utf8(bytes)
                .map_err(|_| "evaluation.json: not valid UTF-8".to_string())?;
            parse(&s)
                .map(Some)
                .map_err(|e| format!("evaluation.json: {e}"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("read evaluation.json: {e}")),
    }
}

/// Same normalization as every other separation check.
fn same_agent(a: &str, b: &str) -> bool {
    let id = |v: &str| crate::model::identity(&Some(v.to_string()));
    id(a).is_some() && id(a) == id(b)
}

pub fn check(run: &Path, findings: &FindingsFile) -> Result<Vec<String>, String> {
    let Some(e) = load(run)? else {
        return Ok(if findings.findings.is_empty() {
            vec![]
        } else {
            vec![
                "evaluation.json missing; finalized records require independent adjudication"
                    .into(),
            ]
        });
    };
    let mut gaps: Vec<String> = e
        .gaps
        .iter()
        .map(|gap| format!("Evaluator gap: {gap}"))
        .collect();
    let meta = if crate::run_artifact::optional_text(
        run,
        Path::new(crate::runmeta::FILE),
        crate::run_artifact::METADATA_BYTES,
    )?
    .is_some()
    {
        crate::runmeta::read(run)?
    } else {
        Default::default()
    };
    if meta
        .get("source_ref")
        .and_then(Value::as_str)
        .is_some_and(|r| r != e.source_ref)
    {
        gaps.push("evaluation source_ref differs from run".into());
    }
    match e.attempt.as_deref() {
        Some(id) => {
            if let Err(error) = crate::attempts::final_for(&meta, id, "evaluator", &e.evaluator) {
                gaps.push(error);
            }
        }
        None => gaps.push("evaluation requires a completed attempt".into()),
    }
    for f in &findings.findings {
        let Some(d) = e.decisions.iter().find(|d| d.fingerprint == f.fingerprint) else {
            gaps.push(format!(
                "{}: evaluator verdict missing ({:?})",
                f.fingerprint, f.verdict
            ));
            continue;
        };
        if [&f.hunted_by, &f.verified_by]
            .iter()
            .filter_map(|s| s.as_deref())
            .any(|id| same_agent(id, &e.evaluator))
        {
            gaps.push(format!(
                "{}: evaluator must be independent of hunter and verifier",
                f.fingerprint
            ));
        }
        if d.decision != "uphold" || !d.required_changes.is_empty() {
            gaps.push(format!("{}: evaluator changes unresolved", f.fingerprint));
        }
        if d.decision == "uphold" {
            if let Some(reference) = &f.proof_ref {
                let original = crate::proof::load(run, reference)?;
                let replayed = d
                    .evidence
                    .iter()
                    .filter(|r| r.starts_with("proofs/") && r.ends_with(".json"))
                    .any(|r| {
                        let Ok(replay) = crate::proof::load(run, r) else {
                            return false;
                        };
                        crate::proof::reproduces(&original, &replay)
                            && crate::proof::runner_evidence(run, &replay).is_empty()
                    });
                if !replayed {
                    gaps.push(format!("{}: upheld proof {reference} has no reproduced replay in evaluator evidence", f.fingerprint));
                }
            } else if f.verdict == Verdict::Confirmed {
                gaps.push(format!("{}: confirmed without proof", f.fingerprint));
            }
        }
    }
    for d in &e.decisions {
        if !findings
            .findings
            .iter()
            .any(|f| f.fingerprint == d.fingerprint)
        {
            gaps.push(format!(
                "evaluation references unknown finding {}",
                d.fingerprint
            ));
        }
    }
    if !e.leads.is_empty() {
        let ledger = crate::shape::ledger(&crate::run_artifact::text(
            run,
            Path::new("coverage-ledger.json"),
            crate::run_artifact::LEDGER_BYTES,
        )?)?;
        for lead in &e.leads {
            if let Some(unit) = ledger.units.iter().find(|u| u.id == lead.unit_id) {
                if unit.status == "out_of_scope"
                    && unit.evidence.iter().all(|e| e.trim().is_empty())
                {
                    gaps.push(format!(
                        "evaluator lead {} requires scope evidence before exclusion",
                        lead.unit_id
                    ));
                }
                if !["covered", "out_of_scope"].contains(&unit.status.as_str()) {
                    gaps.push(format!(
                        "evaluator lead {} remains {}; partial handoff only",
                        lead.unit_id, unit.status
                    ));
                }
            } else {
                gaps.push(format!(
                    "evaluator lead {} has no ledger disposition",
                    lead.unit_id
                ));
            }
        }
    }
    Ok(gaps)
}

pub fn report_lines(run: &Path, findings: &FindingsFile) -> Result<Vec<String>, String> {
    report_lines_inner(run, findings, false)
}

/// Caller holds the family and run locks through artifact publication.
pub fn report_lines_locked(run: &Path, findings: &FindingsFile) -> Result<Vec<String>, String> {
    report_lines_inner(run, findings, true)
}

fn report_lines_inner(
    run: &Path,
    findings: &FindingsFile,
    locked: bool,
) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    if let Some(e) = load(run)? {
        lines.push(format!(
            "Evaluator: {}. Artifact: evaluation.json. Source: {}",
            e.evaluator, e.source_ref
        ));
        for d in e.decisions {
            lines.push(format!(
                "Evaluation {}: {}. {}. Evidence/replays: {}. Required changes: {}",
                d.fingerprint,
                d.decision,
                d.reason,
                d.evidence.join(", "),
                d.required_changes.join("; ")
            ));
        }
        for gap in e.gaps {
            lines.push(format!("Evaluator gap: {gap}"));
        }
        for lead in e.leads {
            lines.push(format!("Evaluator lead {}: {}", lead.unit_id, lead.reason));
        }
    } else {
        lines.push("Evaluator: not recorded; adjudication not established".into());
    }
    lines.extend(
        check(run, findings)?
            .into_iter()
            .map(|g| format!("Adjudication gap: {g}")),
    );
    if crate::run_artifact::optional_text(
        run,
        Path::new(crate::runmeta::FILE),
        crate::run_artifact::METADATA_BYTES,
    )?
    .is_some()
    {
        let meta = crate::runmeta::read(run)?;
        lines.extend(crate::attempts::active_blockers(&meta)?);
        if let Some(events) = meta.get("blocker_events").and_then(Value::as_array) {
            for event in events {
                lines.push(format!("Blocker history: {event}"));
            }
        }
        for event in crate::attempts::history(&meta)? {
            lines.push(format!("Attempt history {}: {:?}", event.at, event.record));
        }
        lines.push("Context isolation is procedural unless the host enforces private views. Separate identities do not attest separate contexts. The same model across roles limits adversarial independence.".into());
        lines.push(if locked {
            crate::budget::summary_locked(run)?
        } else {
            crate::budget::summary(run)?
        });
    }
    if let Some(text) = crate::run_artifact::optional_text(
        run,
        Path::new(crate::status::FILE),
        crate::run_artifact::STATUS_BYTES,
    )? {
        let status = crate::shape::strict_json(&text)?;
        crate::status::check_document(
            status
                .as_object()
                .ok_or("pipeline status must be an object")?,
        )?;
        if let Some(log) = status.get("log").and_then(Value::as_array) {
            for entry in log {
                lines.push(format!(
                    "Status log {} [{}]: {}",
                    entry
                        .get("ts")
                        .and_then(Value::as_str)
                        .unwrap_or("time not recorded"),
                    entry
                        .get("kind")
                        .and_then(Value::as_str)
                        .unwrap_or("kind not recorded"),
                    entry["m"].as_str().unwrap()
                ));
            }
        }
    }
    if let Some(text) = crate::run_artifact::optional_text(
        run,
        Path::new("architecture.json"),
        crate::run_artifact::ARCHITECTURE_BYTES,
    )? {
        let a: crate::architecture::ArchitectureFile =
            serde_json::from_value(crate::shape::strict_json(&text)?).map_err(|e| e.to_string())?;
        for gap in a.unexamined {
            lines.push(format!("Unexamined: {gap}"));
        }
    }
    lines.push("Covered means examined with a disposition, including pending validation; it does not mean safe or fixed. A proven behavior can remain needs_validation when intent or production reachability is unresolved.".into());
    Ok(lines)
}
pub fn render_lines(lines: &[String], html: bool) -> String {
    if html {
        format!("<section class=\"wrap\"><h2>Adjudication and evidence limits</h2><ul>{}</ul></section>", lines.iter().map(|s| format!("<li>{}</li>", crate::html_escape(&crate::handoff::display_text(s)))).collect::<String>())
    } else {
        format!(
            "\n## Adjudication and evidence limits\n\n{}",
            lines
                .iter()
                .map(|s| format!("- {}\n", crate::handoff::markdown_inline(s)))
                .collect::<String>()
        )
    }
}
