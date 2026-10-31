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
}

impl ProofTier {
    pub fn label(self) -> &'static str {
        match self {
            ProofTier::Traced => "traced",
            ProofTier::TestProven => "test proven",
            ProofTier::SandboxExploited => "sandbox exploited",
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Location {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    /// Further locations of the same root cause, so one defect copied into
    /// several places stays one record and counts once.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<Location>,
    #[serde(default)]
    pub evidence: String,
    #[serde(default)]
    pub fix_brief: Option<String>,
    #[serde(default)]
    pub intent_question: Option<String>,
    /// Library question this record asks (see `omgs intent list`), so one
    /// recorded answer resolves every record that shares it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_id: Option<String>,
    /// Root cause family shared across copied locations, for honest counts.
    #[serde(default)]
    pub family: Option<String>,
    /// Attacker prerequisites, kept separate from evidence prose.
    #[serde(default)]
    pub prerequisites: Option<String>,
    /// Identity of the hunter whose candidate produced this record.
    #[serde(default)]
    pub hunted_by: Option<String>,
    /// Identity of the independent verifier who decided this record. Must
    /// differ from `hunted_by`: the author never certifies its own candidate.
    #[serde(default)]
    pub verified_by: Option<String>,
    /// Fingerprints of further candidates the verifier merged into this
    /// record. The record's own fingerprint is implicit.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<String>,
    /// The runner-written proof record behind `proof_tier`, `proofs/<n>.json`
    /// beside the findings file. Required for any tier above traced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_ref: Option<String>,
    /// Source to sink steps, in order, for readers and fixing agents.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trace: Vec<TraceStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceStep {
    pub location: Location,
    pub note: String,
}

/// `findings` is required, so a misspelled key fails to parse instead of
/// reading as an empty, trivially valid findings file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindingsFile {
    pub findings: Vec<Finding>,
}

/// Normalized agent identity for separation checks: trimmed, lowercase.
pub fn identity(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty())
}

/// True for the `omgs fingerprint` output shape `omgs-` plus 16 hex digits.
pub fn is_fingerprint(value: &str) -> bool {
    value.len() == 21
        && value.starts_with("omgs-")
        && value[5..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Enforce the locked evidence rules. Returns every violation found.
pub fn validate(file: &FindingsFile) -> Vec<String> {
    let mut errors = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let own: std::collections::HashSet<String> = file
        .findings
        .iter()
        .map(|f| crate::fingerprint(&f.attack_class, &f.entry_point, &f.sink, &f.boundary))
        .collect();
    let mut absorbed: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (i, f) in file.findings.iter().enumerate() {
        let at = format!("findings[{i}] '{}'", f.title);
        if let Err(error) = crate::classes::validate(&f.attack_class) {
            errors.push(format!("{at}: {error}"));
        }
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
        let mut places = std::collections::HashSet::new();
        for loc in std::iter::once(&f.location).chain(&f.locations) {
            if loc.line == Some(0) {
                errors.push(format!("{at}: location line must be one-based"));
            }
            if loc.path.trim().is_empty() {
                errors.push(format!("{at}: location path is empty"));
            } else if !places.insert(loc) {
                errors.push(format!(
                    "{at}: location {}{} is listed more than once",
                    loc.path,
                    loc.line.map(|l| format!(":{l}")).unwrap_or_default()
                ));
            }
        }
        for (j, step) in f.trace.iter().enumerate() {
            if step.location.path.trim().is_empty() || step.location.line == Some(0) {
                errors.push(format!(
                    "{at}: trace[{j}] needs a path and a one-based line"
                ));
            }
            if step.note.trim().is_empty() {
                errors.push(format!("{at}: trace[{j}] note is empty"));
            }
        }
        if let Some(id) = &f.intent_id {
            if crate::intent::find(id).is_none() {
                errors.push(format!(
                    "{at}: intent_id '{id}' is not in the intent library, see omgs intent list"
                ));
            }
        }
        match (identity(&f.hunted_by), identity(&f.verified_by)) {
            (None, _) => errors.push(format!(
                "{at}: hunted_by is required, record which hunter produced the candidate"
            )),
            (_, None) => errors.push(format!(
                "{at}: verified_by is required, every record needs an independent verifier pass"
            )),
            (Some(h), Some(v)) if h == v => errors.push(format!(
                "{at}: verified_by must differ from hunted_by, a hunter never verifies its own candidate"
            )),
            _ => {}
        }
        for c in &f.candidates {
            if !is_fingerprint(c) {
                errors.push(format!(
                    "{at}: candidates entry '{c}' is not an omgs fingerprint"
                ));
            } else if *c == expected {
                errors.push(format!(
                    "{at}: candidates must not repeat the record's own fingerprint"
                ));
            } else if own.contains(c) {
                errors.push(format!(
                    "{at}: candidate {c} is another record's identity and cannot also be merged here"
                ));
            } else if let Some(prev) = absorbed.insert(c.clone(), i) {
                if prev != i {
                    errors.push(format!(
                        "{at}: candidate {c} is already merged into findings[{prev}]"
                    ));
                } else {
                    errors.push(format!("{at}: candidate {c} is listed more than once"));
                }
            }
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
                    .unwrap_or(false)
                    || f.intent_id.is_some();
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
    }
    errors
}
