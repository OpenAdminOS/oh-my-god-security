//! The sole publication projection of a run. All inputs are read under its lock.
use crate::model::{FindingsFile, Verdict};
use crate::report::ReportMeta;
use serde_json::{json, Value};
use std::path::Path;

pub struct View {
    pub findings: FindingsFile,
    pub meta: ReportMeta,
    pub state: Option<String>,
    pub reasons: Vec<String>,
    pub progress: Value,
    pub attempts: std::collections::BTreeMap<String, crate::attempts::Attempt>,
    pub confirmed: usize,
    pub needs_validation: usize,
    pub rejected: usize,
    pub strict_errors: Vec<String>,
    pub decision_errors: std::collections::BTreeMap<String, Vec<String>>,
}

impl View {
    pub fn load(run: &Path) -> Result<Self, String> {
        crate::runmeta::with_lock(run, || Self::load_locked(run))
    }

    pub fn with_findings(run: &Path, findings: &FindingsFile) -> Result<Self, String> {
        crate::runmeta::with_lock(run, || Self::build_locked(run, Some(findings)))
    }

    /// Caller holds the metadata lock, including through publication.
    pub(crate) fn load_locked(run: &Path) -> Result<Self, String> {
        Self::build_locked(run, None)
    }

    fn build_locked(run: &Path, supplied: Option<&FindingsFile>) -> Result<Self, String> {
        let saved = crate::runmeta::read_optional(run)?.unwrap_or_default();
        let stored = crate::run_artifact::optional_text(
            run,
            Path::new("findings.json"),
            crate::run_artifact::FINDINGS_BYTES,
        )?;
        let raw = match supplied {
            Some(file) => file.clone(),
            None => stored
                .as_deref()
                .map(crate::shape::findings)
                .transpose()?
                .unwrap_or_default(),
        };
        let strict_errors = crate::model::validate(&raw);
        let mut decision_errors = std::collections::BTreeMap::new();
        for finding in &raw.findings {
            let one = FindingsFile {
                findings: vec![finding.clone()],
            };
            let mut errors = crate::attempts::finding_gaps(run, &one)?;
            errors.extend(crate::proof::validate_proofs(&one, run));
            decision_errors.insert(finding.fingerprint.clone(), errors);
        }
        let findings = crate::attempts::project(&saved, &raw);
        let attempts = crate::attempts::states(&crate::attempts::history(&saved)?)?;
        let mut coverage_reasons = Vec::new();
        let mut meta = ReportMeta {
            review_limits: crate::attempts::gaps(&saved)?,
            timeline: crate::report::timeline(run)?,
            ..Default::default()
        };
        meta.review_limits
            .extend(crate::model::validate_drafts(&raw));
        meta.review_limits
            .extend(decision_errors.values().flatten().cloned());
        if stored.is_none() && supplied.is_none() {
            meta.review_limits.push("findings.json missing".into());
        }
        if let Some(text) = crate::run_artifact::optional_text(
            run,
            Path::new("coverage-ledger.json"),
            crate::run_artifact::LEDGER_BYTES,
        )? {
            let ledger = crate::shape::ledger(&text)?;
            coverage_reasons.extend(
                ledger
                    .units
                    .iter()
                    .filter(|u| u.status == "blocked")
                    .map(|u| format!("blocked unit {}", u.id)),
            );
            meta.coverage = crate::ledger::coverage_lines(&ledger);
            meta.critic = Some(crate::critic::critique_dir_raw(run, &findings)?);
        }
        meta.review_limits.extend(
            crate::adjudication::check(run, &findings)?
                .into_iter()
                .map(|gap| format!("Adjudication gap: {gap}")),
        );
        if let Some(text) = crate::run_artifact::optional_text(
            run,
            Path::new("architecture.json"),
            crate::run_artifact::ARCHITECTURE_BYTES,
        )? {
            let architecture: crate::architecture::ArchitectureFile =
                serde_json::from_value(crate::shape::strict_json(&text)?)
                    .map_err(|e| e.to_string())?;
            meta.review_limits.extend(
                architecture
                    .unexamined
                    .into_iter()
                    .map(|gap| format!("Unexamined: {gap}")),
            );
        }
        if let Some(critic) = &meta.critic {
            meta.review_limits.extend(critic.gaps.clone());
        }
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
        let mut progress = crate::run_artifact::optional_text(
            run,
            Path::new(crate::status::FILE),
            crate::run_artifact::STATUS_BYTES,
        )?
        .map(|s| crate::shape::strict_json(&s))
        .transpose()?
        .unwrap_or_else(|| json!({"stages":[],"updated_ms":0}));
        progress["counters"]["confirmed"] = json!(confirmed);
        progress["counters"]["needs_validation"] = json!(needs_validation);
        progress["counters"]["rejected"] = json!(rejected);
        progress["review_state"] = json!(state.as_deref().unwrap_or("complete"));
        progress["review_complete"] = json!(state.is_none());
        Ok(Self {
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
            decision_errors,
        })
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
