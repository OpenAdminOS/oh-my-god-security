//! The sole publication projection of a run. All inputs are read under its lock.
use crate::model::{FindingsFile, Verdict};
use crate::report::ReportMeta;
use serde_json::{json, Value};
use std::path::Path;

pub struct View {
    pub findings: FindingsFile,
    pub saved: serde_json::Map<String, Value>,
    pub budget: Option<String>,
    pub accounting: crate::accounting::Accounting,
    pub meta: ReportMeta,
    pub state: Option<String>,
    pub reasons: Vec<String>,
    pub progress: Value,
    pub attempts: std::collections::BTreeMap<String, crate::attempts::Attempt>,
    pub confirmed: usize,
    pub needs_validation: usize,
    pub rejected: usize,
    pub strict_errors: Vec<String>,
    pub proof_errors: Vec<String>,
    pub attempt_gaps: Vec<String>,
    pub adjudication_gaps: Vec<String>,
    pub decision_errors: std::collections::BTreeMap<String, Vec<String>>,
}

impl View {
    pub fn load(run: &Path) -> Result<Self, String> {
        crate::runmeta::with_lock(run, || Self::load_locked(run))
    }

    pub fn with_findings(run: &Path, findings: &FindingsFile) -> Result<Self, String> {
        crate::runmeta::with_lock(run, || Self::build_locked(run, Some(findings), false))
    }

    /// Caller holds the metadata lock, including through publication.
    pub fn load_locked(run: &Path) -> Result<Self, String> {
        Self::build_options(run, None, false, None, None, true, None)
    }

    /// Strict diagnostic commands must preserve malformed-input errors.
    /// Caller holds the run lock through the diagnostic.
    pub fn load_strict_locked(run: &Path) -> Result<Self, String> {
        Self::build_locked(run, None, false)
    }

    /// Caller holds every archive input lock through output publication.
    pub fn load_archive_locked(run: &Path) -> Result<Self, String> {
        Self::build_locked(run, None, true)
    }

    /// Use the metadata transaction that will be saved with these artifacts.
    /// Caller holds the family/run locks and has read findings under that lock.
    pub fn for_publication_locked(
        run: &Path,
        findings: &FindingsFile,
        saved: &serde_json::Map<String, Value>,
    ) -> Result<Self, String> {
        Self::build_options(run, Some(findings), false, Some(saved), None, false, None)
    }

    pub fn with_progress_locked(
        run: &Path,
        saved: &serde_json::Map<String, Value>,
        progress: &Value,
        tolerant: bool,
    ) -> Result<Self, String> {
        Self::build_options(
            run,
            None,
            false,
            Some(saved),
            Some(progress),
            tolerant,
            None,
        )
    }

    pub fn for_report_locked(
        run: &Path,
        findings: &FindingsFile,
        saved: &serde_json::Map<String, Value>,
        progress: Option<&Value>,
    ) -> Result<Self, String> {
        Self::build_options(
            run,
            Some(findings),
            false,
            Some(saved),
            progress,
            false,
            None,
        )
    }

    pub fn for_sensors_locked(
        run: &Path,
        saved: &serde_json::Map<String, Value>,
        progress: &Value,
        sensors: &crate::sensors::SensorsReport,
    ) -> Result<Self, String> {
        Self::build_options(
            run,
            None,
            false,
            Some(saved),
            Some(progress),
            true,
            Some(sensors),
        )
    }

    fn build_locked(
        run: &Path,
        supplied: Option<&FindingsFile>,
        archive: bool,
    ) -> Result<Self, String> {
        Self::build_options(run, supplied, archive, None, None, false, None)
    }

    fn build_options(
        run: &Path,
        supplied: Option<&FindingsFile>,
        archive: bool,
        proposed: Option<&serde_json::Map<String, Value>>,
        progress: Option<&Value>,
        tolerant: bool,
        sensors: Option<&crate::sensors::SensorsReport>,
    ) -> Result<Self, String> {
        fn read<T: Default>(
            result: Result<T, String>,
            name: &str,
            tolerant: bool,
            errors: &mut Vec<String>,
        ) -> Result<T, String> {
            match result {
                Ok(value) => Ok(value),
                Err(error) if tolerant => {
                    errors.push(format!("artifact unreadable: {name}: {error}"));
                    Ok(T::default())
                }
                Err(error) => Err(format!("{name}: {error}")),
            }
        }
        let mut unreadable = Vec::new();
        let saved = match proposed {
            Some(m) => m.clone(),
            None => crate::runmeta::read_optional(run)?.unwrap_or_default(),
        };
        let stored = read(
            crate::run_artifact::optional_text(
                run,
                Path::new("findings.json"),
                crate::run_artifact::FINDINGS_BYTES,
            ),
            "findings.json",
            tolerant,
            &mut unreadable,
        )?;
        let raw = match supplied {
            Some(file) => file.clone(),
            None => read(
                stored.as_deref().map(crate::shape::findings).transpose(),
                "findings.json",
                tolerant,
                &mut unreadable,
            )?
            .unwrap_or_default(),
        };
        let mut progress = match progress {
            Some(value) => value.clone(),
            None => read(
                (|| {
                    let text = crate::run_artifact::optional_text(
                        run,
                        Path::new(crate::status::FILE),
                        crate::run_artifact::STATUS_BYTES,
                    )?;
                    text.as_deref().map(crate::shape::strict_json).transpose()
                })(),
                crate::status::FILE,
                tolerant,
                &mut unreadable,
            )?
            .unwrap_or_else(|| json!({"stages":[],"updated_ms":0})),
        };
        if !progress.is_object() {
            progress = json!({"stages":[]});
            unreadable.push("artifact unreadable: pipeline-status.json: expected object".into());
        }
        let strict_errors = crate::model::validate(&raw);
        let mut proof_errors = Vec::new();
        let mut decision_errors = std::collections::BTreeMap::new();
        for finding in &raw.findings {
            let one = FindingsFile {
                findings: vec![finding.clone()],
            };
            let mut errors = crate::attempts::finding_gaps_for(&saved, &one)?;
            let proofs = crate::proof::validate_proofs(&one, run);
            proof_errors.extend(proofs.clone());
            errors.extend(proofs);
            decision_errors.insert(finding.fingerprint.clone(), errors);
        }
        let findings = crate::attempts::project(&saved, &raw);
        let attempts = crate::attempts::states(&crate::attempts::history(&saved)?)?;
        let mut coverage_reasons = Vec::new();
        let attempt_gaps = crate::attempts::gaps(&saved)?;
        let mut meta = ReportMeta {
            review_limits: attempt_gaps.clone(),
            timeline: read(
                crate::report::timeline_document(&progress),
                crate::status::FILE,
                tolerant,
                &mut unreadable,
            )?,
            ..Default::default()
        };
        meta.review_limits
            .extend(crate::model::validate_drafts(&raw));
        meta.review_limits
            .extend(decision_errors.values().flatten().cloned());
        if stored.is_none() && supplied.is_none() {
            meta.review_limits.push("findings.json missing".into());
        }
        let ledger = read(
            (|| {
                crate::run_artifact::optional_text(
                    run,
                    Path::new("coverage-ledger.json"),
                    crate::run_artifact::LEDGER_BYTES,
                )?
                .as_deref()
                .map(crate::shape::ledger)
                .transpose()
            })(),
            "coverage-ledger.json",
            tolerant,
            &mut unreadable,
        )?;
        if let Some(ledger) = ledger {
            coverage_reasons.extend(
                ledger
                    .units
                    .iter()
                    .filter(|u| u.status == "blocked")
                    .map(|u| format!("blocked unit {}", u.id)),
            );
            meta.coverage = crate::ledger::coverage_lines(&ledger);
            meta.critic = read(
                crate::critic::critique_projection(run, &findings, sensors),
                "coverage critic",
                tolerant,
                &mut unreadable,
            )?;
        }
        let adjudication_gaps = read(
            crate::adjudication::check(run, &findings),
            "evaluation.json",
            tolerant,
            &mut unreadable,
        )?;
        meta.review_limits.extend(
            adjudication_gaps
                .iter()
                .map(|gap| format!("Adjudication gap: {gap}")),
        );
        let architecture = read(
            (|| {
                crate::run_artifact::optional_text(
                    run,
                    Path::new("architecture.json"),
                    crate::run_artifact::ARCHITECTURE_BYTES,
                )?
                .map(|text| {
                    serde_json::from_value::<crate::architecture::ArchitectureFile>(
                        crate::shape::strict_json(&text)?,
                    )
                    .map_err(|e| e.to_string())
                })
                .transpose()
            })(),
            "architecture.json",
            tolerant,
            &mut unreadable,
        )?;
        if let Some(architecture) = architecture {
            meta.review_limits.extend(
                architecture
                    .unexamined
                    .into_iter()
                    .map(|gap| format!("Unexamined: {gap}")),
            );
        }
        for finding in &raw.findings {
            if finding.verdict == Verdict::Confirmed && finding.verification.is_none() {
                meta.review_limits.push(format!("Legacy confirmed finding {} demoted: final verification and its completed attempt were not recorded; reverify before confirming", finding.fingerprint));
            }
        }
        meta.review_limits.extend(unreadable);
        if let Some(critic) = &meta.critic {
            meta.review_limits.extend(critic.gaps.clone());
        }
        let mut seen = std::collections::BTreeSet::new();
        meta.review_limits.retain(|gap| seen.insert(gap.clone()));
        let state = completion_state(&findings, &meta);
        let mut reasons = meta.review_limits.clone();
        if let Some(critic) = &meta.critic {
            if !critic.passed() {
                reasons.push(format!("critic: {}", critic.summary()));
            }
        } else {
            reasons.push("coverage-ledger.json missing".into());
        }
        reasons.extend(coverage_reasons);
        reasons.extend(
            meta.timeline
                .iter()
                .filter(|row| !row.historical && row.state != "done")
                .map(|row| format!("stage {}: {}", row.label, row.state)),
        );
        reasons.extend(state.clone());
        let count = |verdict| {
            findings
                .findings
                .iter()
                .filter(|f| f.verdict == verdict)
                .count()
        };
        let confirmed = count(Verdict::Confirmed);
        let needs_validation = count(Verdict::NeedsValidation);
        let rejected = count(Verdict::Rejected);
        if !progress.get("counters").is_some_and(Value::is_object) {
            progress["counters"] = json!({});
        }
        progress["counters"]["confirmed"] = json!(confirmed);
        progress["counters"]["needs_validation"] = json!(needs_validation);
        progress["counters"]["rejected"] = json!(rejected);
        progress["review_state"] = json!(state.as_deref().unwrap_or("complete"));
        progress["review_complete"] = json!(state.is_none());
        let accounting = crate::accounting::read(&saved)?;
        meta.accounting = accounting.clone();
        let budget = if archive || saved.is_empty() || crate::runmeta::read_optional(run)?.is_none()
        {
            None
        } else {
            Some(crate::budget::summary_proposed_locked(run, &saved)?)
        };
        Ok(Self {
            saved,
            budget,
            accounting,
            findings,
            meta,
            state,
            reasons,
            progress,
            attempts,
            confirmed,
            needs_validation,
            rejected,
            strict_errors,
            proof_errors,
            attempt_gaps,
            adjudication_gaps,
            decision_errors,
        })
    }

    /// Strict finding validation reuses the evidence checks in this view.
    pub fn validation_errors(&self) -> Vec<String> {
        let mut errors = self.strict_errors.clone();
        errors.extend(self.attempt_gaps.clone());
        errors.extend(self.decision_errors.values().flatten().cloned());
        let mut seen = std::collections::BTreeSet::new();
        errors.retain(|error| seen.insert(error.clone()));
        errors
    }

    pub fn complete(&self) -> bool {
        self.state.is_none()
    }

    /// Carry the canonical completion inputs into a format renderer.
    pub fn apply(&self, meta: &mut ReportMeta) {
        meta.review_limits.clone_from(&self.meta.review_limits);
        meta.timeline = self.meta.timeline.clone();
        meta.coverage.clone_from(&self.meta.coverage);
        meta.critic.clone_from(&self.meta.critic);
    }
}

pub(crate) fn completion_state(file: &FindingsFile, meta: &ReportMeta) -> Option<String> {
    let blocked = meta
        .review_limits
        .iter()
        .any(|s| s.contains("stopped") || s.starts_with("blocker "))
        || meta.coverage.iter().any(|s| s.starts_with("blocked:"));
    let unfinished = meta.critic.as_ref().is_none_or(|c| !c.passed())
        || !meta.review_limits.is_empty()
        || meta.coverage.iter().any(|s| {
            ["blocked:", "deferred:", "planned:", "candidate:"]
                .iter()
                .any(|prefix| s.starts_with(prefix))
        })
        || !crate::model::validate(file).is_empty()
        || file
            .findings
            .iter()
            .any(|f| f.verdict == Verdict::NeedsValidation)
        || meta
            .timeline
            .iter()
            .any(|r| !r.historical && r.state != "done");
    let blocked_units = meta
        .coverage
        .iter()
        .filter(|s| s.starts_with("blocked:"))
        .count();
    let deferred_units = meta
        .coverage
        .iter()
        .filter(|s| s.starts_with("deferred:"))
        .count();
    if blocked_units > 0 || deferred_units > 0 {
        return Some(format!("Incomplete coverage: {blocked_units} blocked unit(s), {deferred_units} deferred unit(s). Verification and pending work still require review."));
    }
    if unfinished {
        Some(format!("{} review: verification, coverage or pending work remains. {} confirmed finding(s) recorded.{}", if blocked { "Blocked" } else { "Incomplete" }, file.findings.iter().filter(|f| f.verdict == Verdict::Confirmed).count(), if meta.review_limits.is_empty() { String::new() } else { format!(" {}", meta.review_limits.join("; ")) }))
    } else {
        None
    }
}
