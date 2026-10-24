use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Confirmed,
    NeedsValidation,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofTier {
    Traced,
    TestProven,
    SandboxExploited,
    /// A real exploit run on a dedicated disposable host, for targets whose
    /// decisive proof cannot execute inside the OS sandbox (privileged
    /// installers, root helpers). Lower portability than `sandbox_exploited`;
    /// requires a disposable-host attestation in `prerequisites`.
    DedicatedHost,
}

impl ProofTier {
    pub fn label(self) -> &'static str {
        match self {
            ProofTier::Traced => "traced",
            ProofTier::TestProven => "test proven",
            ProofTier::SandboxExploited => "sandbox exploited",
            ProofTier::DedicatedHost => "dedicated host",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Informational => "informational",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub path: String,
    #[serde(default)]
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    #[serde(default)]
    pub fingerprint: String,
    pub title: String,
    pub verdict: Verdict,
    #[serde(default)]
    pub severity: Option<Severity>,
    pub proof_tier: ProofTier,
    pub attack_class: String,
    pub entry_point: String,
    pub sink: String,
    pub boundary: String,
    pub location: Location,
    #[serde(default)]
    pub evidence: String,
    #[serde(default)]
    pub fix_brief: Option<String>,
    #[serde(default)]
    pub intent_question: Option<String>,
    /// Root cause family shared across copied locations, for honest counts.
    #[serde(default)]
    pub family: Option<String>,
    /// Attacker prerequisites, kept separate from evidence prose.
    #[serde(default)]
    pub prerequisites: Option<String>,
    /// Identity of the independent verifier, when one reviewed this record.
    #[serde(default)]
    pub verified_by: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindingsFile {
    #[serde(default)]
    pub findings: Vec<Finding>,
}

/// Enforce the locked evidence rules. Returns every violation found.
pub fn validate(file: &FindingsFile) -> Vec<String> {
    let mut errors = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (i, f) in file.findings.iter().enumerate() {
        let at = format!("findings[{i}] '{}'", f.title);
        let expected = crate::fingerprint(&f.attack_class, &f.entry_point, &f.sink, &f.boundary);
        if f.fingerprint.is_empty() {
            errors.push(format!("{at}: fingerprint is empty, expected {expected}"));
        } else if f.fingerprint != expected {
            errors.push(format!(
                "{at}: fingerprint {} does not match computed identity {expected}",
                f.fingerprint
            ));
        }
        if !seen.insert(expected.clone()) {
            errors.push(format!("{at}: duplicate finding identity {expected}"));
        }
        match f.verdict {
            Verdict::Confirmed => {
                if f.severity.is_none() {
                    errors.push(format!("{at}: confirmed findings require severity"));
                }
                if f.proof_tier == ProofTier::Traced {
                    errors.push(format!(
                        "{at}: traced evidence alone can never be confirmed, reach test_proven or sandbox_exploited"
                    ));
                }
                if f.evidence.trim().is_empty() {
                    errors.push(format!("{at}: confirmed findings require evidence"));
                }
            }
            Verdict::NeedsValidation => {
                if f.severity.is_some() {
                    errors.push(format!("{at}: needs_validation must not carry severity"));
                }
                let has_question = f
                    .intent_question
                    .as_deref()
                    .map(|q| !q.trim().is_empty())
                    .unwrap_or(false);
                if !has_question && f.evidence.trim().is_empty() {
                    errors.push(format!(
                        "{at}: needs_validation requires an intent_question or the exact missing fact in evidence"
                    ));
                }
            }
            Verdict::Rejected => {
                if f.severity.is_some() {
                    errors.push(format!("{at}: rejected findings must not carry severity"));
                }
            }
        }
        // A dedicated-host proof asserts a real run on a disposable machine. It
        // must record that attestation so a productive host is never implied.
        if f.proof_tier == ProofTier::DedicatedHost {
            let has_attestation = f
                .prerequisites
                .as_deref()
                .map(|p| !p.trim().is_empty())
                .unwrap_or(false);
            if !has_attestation {
                errors.push(format!(
                    "{at}: dedicated_host proof must record a disposable-host attestation in prerequisites"
                ));
            }
        }
    }
    errors
}
