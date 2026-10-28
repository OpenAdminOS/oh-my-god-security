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
    let d: Dispositions =
        serde_json::from_value(document(text, "units")?).map_err(|e| e.to_string())?;
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
    let units = c
        .candidates
        .iter()
        .flat_map(|c| c.unit_ids.iter())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|id| {
            let mut u = crate::ledger::Unit::new(id, ".", &[], "covered");
            u.evidence.push("synthetic-validation-context".into());
            u
        })
        .collect();
    let report = crate::critic::critique(
        &crate::ledger::Ledger {
            units,
            ..Default::default()
        },
        1,
        &c.candidates
            .iter()
            .cloned()
            .map(|candidate| crate::critic::SourcedCandidate {
                file: "input".into(),
                candidate,
            })
            .collect::<Vec<_>>(),
        &FindingsFile::default(),
    );
    let errors: Vec<_> = report
        .gaps
        .into_iter()
        .filter(|g| !g.contains("was never verified"))
        .collect();
    if errors.is_empty() {
        Ok(c)
    } else {
        Err(errors.join("; "))
    }
}
pub fn load(run: &Path) -> Result<Option<Evaluation>, String> {
    let path = run.join("evaluation.json");
    match std::fs::read_to_string(&path) {
        Ok(s) => parse(&s)
            .map(Some)
            .map_err(|e| format!("evaluation.json: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("read evaluation.json: {e}")),
    }
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
    let mut gaps = Vec::new();
    let meta = if run.join(crate::runmeta::FILE).exists() {
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
            .any(|id| id.trim().eq_ignore_ascii_case(e.evaluator.trim()))
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
        let ledger = crate::shape::ledger(
            &std::fs::read_to_string(run.join("coverage-ledger.json"))
                .map_err(|e| e.to_string())?,
        )?;
        for lead in &e.leads {
            if !ledger.units.iter().any(|u| u.id == lead.unit_id) {
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
    if run.join(crate::runmeta::FILE).is_file() {
        let meta = crate::runmeta::read(run)?;
        if let Some(blockers) = meta.get("blockers").and_then(Value::as_array) {
            for b in blockers {
                lines.push(format!("Blocker: {}", b.as_str().unwrap_or("malformed")));
            }
        }
        lines.push(crate::budget::summary(run)?);
    }
    if run.join("architecture.json").is_file() {
        let a: crate::architecture::ArchitectureFile =
            serde_json::from_value(crate::shape::strict_json(
                &std::fs::read_to_string(run.join("architecture.json"))
                    .map_err(|e| e.to_string())?,
            )?)
            .map_err(|e| e.to_string())?;
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
