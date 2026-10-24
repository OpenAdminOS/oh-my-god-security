//! Coverage critic: reconciles the ledger, the hunters' candidate files, and
//! the verified findings of one run, so nothing a hunter raised is silently
//! dropped and no record is certified by the hunter that produced it.

use crate::ledger::{validate_ledger, Ledger};
use crate::model::{identity, is_fingerprint, FindingsFile};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The fields of a hunter candidate the critic reads. Everything else in the
/// candidates schema is prose for the verifier.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Candidate {
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub hunter: Option<String>,
    #[serde(default)]
    pub unit_ids: Vec<String>,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub attack_class: String,
    #[serde(default)]
    pub entry_point: String,
    #[serde(default)]
    pub sink: String,
    #[serde(default)]
    pub boundary: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CandidatesFile {
    #[serde(default)]
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
            "{} ({} units, {} candidates, {} findings)",
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

/// Reconcile one run. `candidate_files` counts the candidates files found,
/// so a run where no hunter wrote anything is reported as a gap.
pub fn critique(
    ledger: &Ledger,
    candidate_files: usize,
    candidates: &[SourcedCandidate],
    findings: &FindingsFile,
) -> CriticReport {
    let mut gaps = Vec::new();
    for e in validate_ledger(ledger) {
        gaps.push(format!("ledger {e}"));
    }
    for u in &ledger.units {
        if u.status == "planned" || u.status == "candidate" {
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
        let expected = crate::fingerprint(&c.attack_class, &c.entry_point, &c.sink, &c.boundary);
        if !is_fingerprint(&c.fingerprint) {
            gaps.push(format!(
                "{at}: fingerprint '{}' is not an omgs fingerprint",
                c.fingerprint
            ));
            continue;
        }
        if c.fingerprint != expected {
            gaps.push(format!(
                "{at}: fingerprint {} does not match computed identity {expected}",
                c.fingerprint
            ));
        }
        match identity(&c.hunter) {
            Some(h) => {
                hunters.entry(c.fingerprint.as_str()).or_default().insert(h);
            }
            None => gaps.push(format!("{at}: hunter is not recorded")),
        }
        if c.unit_ids.is_empty() {
            gaps.push(format!("{at}: names no ledger unit"));
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
                "{at}: no ledger unit cites {} as evidence",
                f.fingerprint
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

/// Load a run directory and critique it. The ledger and findings must exist;
/// candidates are read from every `candidates*.json` in the directory.
pub fn critique_run(dir: &Path) -> Result<CriticReport, String> {
    let read = |name: &str| {
        let path = dir.join(name);
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))
    };
    let ledger: Ledger = serde_json::from_str(&read("coverage-ledger.json")?)
        .map_err(|e| format!("parse coverage-ledger.json: {e}"))?;
    let findings: FindingsFile = serde_json::from_str(&read("findings.json")?)
        .map_err(|e| format!("parse findings.json: {e}"))?;
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map_err(|e| format!("read {}: {e}", dir.display()))?
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with("candidates") && n.ends_with(".json"))
        .collect();
    names.sort();
    let mut candidates = Vec::new();
    for name in &names {
        let file: CandidatesFile =
            serde_json::from_str(&read(name)?).map_err(|e| format!("parse {name}: {e}"))?;
        candidates.extend(
            file.candidates
                .into_iter()
                .map(|candidate| SourcedCandidate {
                    file: name.clone(),
                    candidate,
                }),
        );
    }
    Ok(critique(&ledger, names.len(), &candidates, &findings))
}
