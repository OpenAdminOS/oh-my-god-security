//! Coverage critic: reconciles the ledger, the hunters' candidate files, and
//! the verified findings of one run, so nothing a hunter raised is silently
//! dropped and no record is certified by the hunter that produced it.

use crate::ledger::{validate_ledger, Ledger};
use crate::model::{identity, is_fingerprint, validate, FindingsFile};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// One hunter candidate, matching `skill/schemas/candidates.schema.json`:
/// every required field is required here too, unknown fields are rejected,
/// and wrong types fail to parse, so a malformed handoff is an error rather
/// than a candidate the critic could pass.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub hunter: String,
    pub unit_ids: Vec<String>,
    pub source_ref: String,
    pub title: String,
    pub attack_class: String,
    pub entry_point: String,
    pub sink: String,
    pub boundary: String,
    pub location: CandidateLocation,
    pub attacker_capability: String,
    pub trace: String,
    pub concrete_result: String,
    pub counterevidence: String,
    #[serde(default)]
    pub missing_fact: Option<String>,
    #[serde(default)]
    pub intent_question: Option<String>,
    pub proof_plan: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateLocation {
    pub path: String,
    #[serde(default)]
    pub line: Option<u32>,
}

/// A hunter's handoff file. `candidates` is required, so a misspelled key
/// fails to parse instead of reading as an empty handoff; a hunter that found
/// nothing writes `{"candidates": []}`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidatesFile {
    pub candidates: Vec<Candidate>,
}

/// A candidate together with the file it came from, for messages.
#[derive(Debug, Clone)]
pub struct SourcedCandidate {
    pub file: String,
    pub candidate: Candidate,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CriticReport {
    pub gaps: Vec<String>,
    pub units: usize,
    pub candidates: usize,
    pub findings: usize,
}

impl CriticReport {
    pub fn passed(&self) -> bool {
        self.gaps.is_empty()
    }

    /// One line summary, for example "pass (4 units, 6 candidates, 3 findings)".
    pub fn summary(&self) -> String {
        format!(
            "{} (inspected: {} units, {} candidates, {} findings)",
            if self.passed() {
                "pass".to_string()
            } else {
                format!("{} gap(s)", self.gaps.len())
            },
            self.units,
            self.candidates,
            self.findings
        )
    }
}

/// Validate candidate fields without filtering target-derived diagnostics.
pub fn validate_candidate(c: &Candidate) -> Vec<String> {
    let mut errors = Vec::new();
    let expected = crate::fingerprint(&c.attack_class, &c.entry_point, &c.sink, &c.boundary);
    for (name, value) in [
        ("source_ref", &c.source_ref),
        ("title", &c.title),
        ("attack_class", &c.attack_class),
        ("entry_point", &c.entry_point),
        ("sink", &c.sink),
        ("boundary", &c.boundary),
        ("location.path", &c.location.path),
        ("attacker_capability", &c.attacker_capability),
        ("trace", &c.trace),
        ("concrete_result", &c.concrete_result),
        ("counterevidence", &c.counterevidence),
        ("proof_plan", &c.proof_plan),
    ] {
        if value.trim().is_empty() {
            errors.push(format!("{name} is empty"));
        }
    }
    if c.location.line == Some(0) {
        errors.push("location.line must be one-based".into());
    }
    if !is_fingerprint(&c.fingerprint) {
        errors.push(format!(
            "fingerprint '{}' is not an omgs fingerprint",
            c.fingerprint
        ));
    }
    if c.fingerprint != expected {
        errors.push(format!(
            "fingerprint {} does not match computed identity {expected}",
            c.fingerprint
        ));
    }
    if identity(&Some(c.hunter.clone())).is_none() {
        errors.push("hunter is not recorded".into());
    }
    if c.unit_ids.is_empty() {
        errors.push("names no ledger unit".into());
    }
    errors
}

/// Reconcile one run. `candidate_files` counts the candidates files found,
/// so a run where no hunter wrote anything is reported as a gap.
pub fn critique(
    ledger: &Ledger,
    candidate_files: usize,
    candidates: &[SourcedCandidate],
    findings: &FindingsFile,
) -> CriticReport {
    let mut gaps = Vec::new();
    for e in validate(findings) {
        gaps.push(format!("findings {e}"));
    }
    for e in validate_ledger(ledger) {
        gaps.push(format!("ledger {e}"));
    }
    for u in &ledger.units {
        if u.status == "planned"
            || u.status == "candidate"
            || ((crate::ledger::is_exclusion(u) || crate::ledger::is_inventory_gap(u))
                && !["covered", "out_of_scope"].contains(&u.status.as_str()))
        {
            gaps.push(format!(
                "unit '{}' is still {}, examine it or record why it was not",
                u.id, u.status
            ));
        }
    }
    let unit_ids: BTreeSet<&str> = ledger.units.iter().map(|u| u.id.as_str()).collect();
    if candidate_files == 0 {
        gaps.push(
            "no candidates*.json file in the run directory, each hunter writes one (an empty list when it found nothing)"
                .into(),
        );
    }

    // Hunters per candidate fingerprint, across every candidates file.
    let mut hunters: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for sc in candidates {
        let c = &sc.candidate;
        let at = format!("{} candidate '{}'", sc.file, c.title);
        gaps.extend(
            validate_candidate(c)
                .into_iter()
                .map(|e| format!("{at}: {e}")),
        );
        if is_fingerprint(&c.fingerprint) {
            if let Some(h) = identity(&Some(c.hunter.clone())) {
                hunters.entry(c.fingerprint.as_str()).or_default().insert(h);
            }
        }
        for id in &c.unit_ids {
            if !unit_ids.contains(id.as_str()) {
                gaps.push(format!("{at}: unit '{id}' is not in the ledger"));
            }
        }
    }

    let mut accounted: BTreeSet<&str> = BTreeSet::new();
    let referenced: BTreeSet<&str> = ledger
        .units
        .iter()
        .flat_map(|u| u.evidence.iter().map(|e| e.trim()))
        .collect();
    for (i, f) in findings.findings.iter().enumerate() {
        let at = format!("findings[{i}] '{}'", f.title);
        let mut absorbed_hunters: BTreeSet<String> = BTreeSet::new();
        let mut traced = false;
        for fp in std::iter::once(&f.fingerprint).chain(&f.candidates) {
            match hunters.get(fp.as_str()) {
                Some(set) => {
                    traced = true;
                    accounted.insert(fp.as_str());
                    absorbed_hunters.extend(set.iter().cloned());
                }
                None if fp != &f.fingerprint => {
                    gaps.push(format!(
                        "{at}: merged candidate {fp} is not in any candidates file"
                    ));
                }
                None => {}
            }
        }
        if !traced {
            gaps.push(format!(
                "{at}: traces to no hunter candidate, its fingerprint and merged candidates match none"
            ));
        }
        if let Some(h) = identity(&f.hunted_by) {
            if traced && !absorbed_hunters.contains(&h) {
                gaps.push(format!(
                    "{at}: hunted_by '{h}' is not the hunter of any candidate this record absorbed"
                ));
            }
        }
        if let Some(v) = identity(&f.verified_by) {
            if absorbed_hunters.contains(&v) {
                gaps.push(format!(
                    "{at}: verified_by '{v}' hunted a candidate this record absorbed, verification must be independent"
                ));
            }
        }
        if !referenced.contains(f.fingerprint.as_str()) {
            gaps.push(format!(
                "{at}: no ledger unit cites {} as evidence; candidate unit_ids: {}",
                f.fingerprint,
                candidates
                    .iter()
                    .filter(|c| c.candidate.fingerprint == f.fingerprint
                        || f.candidates.contains(&c.candidate.fingerprint))
                    .flat_map(|c| c.candidate.unit_ids.iter().cloned())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    for fp in hunters.keys() {
        if !accounted.contains(fp) {
            let title = candidates
                .iter()
                .find(|sc| sc.candidate.fingerprint == *fp)
                .map(|sc| sc.candidate.title.as_str())
                .unwrap_or_default();
            gaps.push(format!(
                "candidate {fp} '{title}' was never verified, no finding records it"
            ));
        }
    }
    CriticReport {
        gaps,
        units: ledger.units.len(),
        candidates: candidates.len(),
        findings: findings.findings.len(),
    }
}

/// Load a run directory's `findings.json` and critique it together with the
/// ledger and candidates beside it.
pub fn critique_run(dir: &Path) -> Result<CriticReport, String> {
    let findings = crate::shape::findings(&crate::run_artifact::text(
        dir,
        Path::new("findings.json"),
        crate::run_artifact::FINDINGS_BYTES,
    )?)
    .map_err(|e| format!("parse findings.json: {e}"))?;
    critique_dir(dir, &findings)
}

/// Critique the given findings against the ledger and every
/// `candidates*.json` in `dir`. Used by `omgs report`, so the critic result
/// always describes the exact findings being rendered.
pub fn critique_dir(dir: &Path, findings: &FindingsFile) -> Result<CriticReport, String> {
    critique_dir_inner(
        dir,
        findings,
        #[cfg(test)]
        || {},
    )
}

fn critique_dir_inner(
    dir: &Path,
    findings: &FindingsFile,
    #[cfg(test)] before_read: impl FnOnce(),
) -> Result<CriticReport, String> {
    let ledger: Ledger = crate::shape::ledger(&crate::run_artifact::text(
        dir,
        Path::new("coverage-ledger.json"),
        crate::run_artifact::LEDGER_BYTES,
    )?)
    .map_err(|e| format!("parse coverage-ledger.json: {e}"))?;
    // Every candidates*.json must be a readable regular file: a symlink, a
    // directory, or an unreadable entry is an error, never silently skipped,
    // so no hunter handoff can disappear from reconciliation.
    let mut names: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| format!("read {}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| format!("read {}: {e}", dir.display()))?;
        let Ok(name) = entry.file_name().into_string() else {
            let lossy = entry.file_name().to_string_lossy().to_string();
            if lossy.starts_with("candidates") {
                return Err(format!("{lossy} has a non-UTF-8 name; rename it"));
            }
            continue;
        };
        if !(name.starts_with("candidates") && name.ends_with(".json")) {
            continue;
        }
        names.push(name);
    }
    names.sort();
    #[cfg(test)]
    before_read();
    let mut candidates = Vec::new();
    for name in &names {
        let file: CandidatesFile = crate::shape::candidates(&crate::run_artifact::text(
            dir,
            Path::new(name),
            crate::run_artifact::CANDIDATES_BYTES,
        )?)
        .map_err(|e| format!("parse {name}: {e}"))?;
        candidates.extend(
            file.candidates
                .into_iter()
                .map(|candidate| SourcedCandidate {
                    file: name.clone(),
                    candidate,
                }),
        );
    }
    let mut report = critique(&ledger, names.len(), &candidates, findings);
    report
        .gaps
        .extend(crate::attempts::finding_gaps(dir, findings)?);
    report
        .gaps
        .extend(crate::attempts::ledger_gaps(dir, &ledger)?);
    let meta = crate::runmeta::read_optional(dir)?.unwrap_or_default();
    let attempts = crate::attempts::states(&crate::attempts::history(&meta)?)?;
    for role in ["verifier", "evaluator"] {
        if !attempts
            .values()
            .any(|a| a.role == role && a.state == "complete")
        {
            report.gaps.push(format!("{role} completion not recorded"));
        }
    }
    if let Some(sensors) = crate::sensors::read_report(dir)? {
        report
            .gaps
            .extend(crate::sensors::reconcile(&sensors, &ledger));
    }
    for e in crate::proof::validate_proofs(findings, dir) {
        report.gaps.push(format!("findings {e}"));
    }
    report
        .gaps
        .extend(crate::adjudication::check(dir, findings)?);
    if let Some(evaluation) = crate::adjudication::load(dir)? {
        for decision in &evaluation.decisions {
            if let Some(f) = findings
                .findings
                .iter()
                .find(|f| f.fingerprint == decision.fingerprint)
            {
                for candidate in candidates.iter().filter(|c| {
                    c.candidate.fingerprint == f.fingerprint
                        || f.candidates.contains(&c.candidate.fingerprint)
                }) {
                    let id = |v: &str| crate::model::identity(&Some(v.to_string()));
                    if id(&candidate.candidate.hunter).is_some()
                        && id(&candidate.candidate.hunter) == id(&evaluation.evaluator)
                    {
                        report.gaps.push(format!("{}: evaluator hunted absorbed candidate {}; independent adjudication required", f.fingerprint, candidate.candidate.fingerprint));
                    }
                }
            }
        }
    }
    Ok(report)
}

#[cfg(all(test, unix))]
mod replacement_tests {
    #[test]
    fn candidate_replacement_after_enumeration_is_refused() {
        let run = crate::platform::temp_root().unwrap().join(format!(
            "omgs-candidate-replace-{}",
            crate::platform::random_nonce().unwrap()
        ));
        crate::platform::create_private_tree(&run).unwrap();
        crate::runmeta::write_atomic(&run.join("coverage-ledger.json"), r#"{"units":[]}"#).unwrap();
        let candidate = run.join("candidates-1.json");
        crate::runmeta::write_atomic(&candidate, r#"{"hunter":"one","candidates":[]}"#).unwrap();
        let outside = run.join("outside.json");
        crate::runmeta::write_atomic(&outside, r#"{"hunter":"one","candidates":[]}"#).unwrap();
        let error = super::critique_dir_inner(&run, &Default::default(), || {
            std::fs::remove_file(&candidate).unwrap();
            std::os::unix::fs::symlink(&outside, &candidate).unwrap();
        })
        .expect_err("replacement must fail");
        assert!(error.contains("candidates-1.json"), "{error}");
        assert!(error.contains("run artifact"), "{error}");
        std::fs::remove_dir_all(run).unwrap();
    }
}
