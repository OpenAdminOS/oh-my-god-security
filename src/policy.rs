//! Committed base policy and deterministic proof gate. No worktree policy reads.
use crate::model::{FindingsFile, Severity, Verdict};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const PATH: &str = ".omgs/policy.json";
pub const MAX_BYTES: u64 = 1 << 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema: String,
    pub mode: Mode,
    /// Explicit null retains the unselected persona and unbounded legacy budget.
    pub persona: Option<String>,
    pub budget: Option<u64>,
    pub severity_threshold: Severity,
    /// Literal repository-relative file or directory prefixes, not globs.
    pub excluded_paths: Vec<String>,
    pub accepted_intent: Vec<AcceptedIntent>,
    pub suppressions: Vec<Suppression>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Gate,
    Advisory,
}
impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Gate => "gate",
            Self::Advisory => "advisory",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedIntent {
    pub id: String,
    pub answer: String,
    pub scope: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suppression {
    pub fingerprint: String,
    pub reason: String,
    /// UTC Unix seconds. At this instant the suppression stops applying.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_unix: Option<u64>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            schema: "omgs-policy/1".into(),
            mode: Mode::Advisory,
            persona: None,
            budget: None,
            severity_threshold: Severity::High,
            excluded_paths: vec![],
            accepted_intent: vec![],
            suppressions: vec![],
        }
    }
}

fn nonempty(s: &str) -> bool {
    !s.trim().is_empty() && !s.chars().any(char::is_control)
}
fn relative(s: &str) -> bool {
    nonempty(s)
        && !s.contains(['\\', ':'])
        && !s.starts_with('/')
        && s.split('/').all(|p| !["", ".", ".."].contains(&p))
}

pub fn parse(text: &str) -> Result<Policy, String> {
    if text.len() as u64 > MAX_BYTES {
        return Err("policy exceeds 1 MiB".into());
    }
    let value = crate::shape::strict_json(text)?;
    let object = value.as_object().ok_or("policy must be an object")?;
    // Option fields are nullable but still required. Serde alone treats missing
    // Option values as None. Enforce object form at every nested level as well.
    for key in [
        "schema",
        "mode",
        "persona",
        "budget",
        "severity_threshold",
        "excluded_paths",
        "accepted_intent",
        "suppressions",
    ] {
        if !object.contains_key(key) {
            return Err(format!("policy requires {key}"));
        }
    }
    for key in ["mode", "severity_threshold"] {
        if !object[key].is_string() {
            return Err(format!("{key} must be a string"));
        }
    }
    for key in ["accepted_intent", "suppressions"] {
        if !object[key]
            .as_array()
            .is_some_and(|a| a.iter().all(|v| v.is_object()))
        {
            return Err(format!("{key} must contain objects"));
        }
    }
    for suppression in object["suppressions"].as_array().unwrap() {
        if suppression
            .get("expires_unix")
            .is_some_and(|v| v.as_u64().is_none())
        {
            return Err("expires_unix must be an unsigned integer when present".into());
        }
    }
    let p: Policy = serde_json::from_value(value).map_err(|e| e.to_string())?;
    if p.schema != "omgs-policy/1" {
        return Err("unsupported policy schema".into());
    }
    if let Some(name) = &p.persona {
        crate::persona::defaults(name)?;
    }
    let mut paths = std::collections::BTreeSet::new();
    for path in &p.excluded_paths {
        if !relative(path) || !paths.insert(path) {
            return Err("excluded_paths requires unique literal relative paths".into());
        }
    }
    let mut ids = std::collections::BTreeSet::new();
    for a in &p.accepted_intent {
        if crate::intent::find(&a.id).is_none()
            || !nonempty(&a.answer)
            || !nonempty(&a.source)
            || !(a.scope == "repo" || relative(&a.scope))
            || !ids.insert((&a.id, &a.scope))
        {
            return Err("invalid or duplicate accepted intent answer".into());
        }
    }
    let mut ids = std::collections::BTreeSet::new();
    for s in &p.suppressions {
        if !crate::model::is_fingerprint(&s.fingerprint)
            || !nonempty(&s.reason)
            || !ids.insert(&s.fingerprint)
        {
            return Err("invalid or duplicate suppression; a reason is required".into());
        }
    }
    Ok(p)
}

pub fn text(p: &Policy) -> Result<String, String> {
    let text = format!(
        "{}\n",
        serde_json::to_string_pretty(p).map_err(|e| e.to_string())?
    );
    if text.len() as u64 > MAX_BYTES {
        return Err("policy exceeds 1 MiB".into());
    }
    parse(&text)?;
    Ok(text)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub source: String,
    pub base_commit: Option<String>,
    /// Digest of the exact committed blob, or canonical documented defaults.
    pub sha256: String,
    pub policy: Policy,
    pub original: Option<String>,
}

// These built-ins read objects only. No checkout, attributes, filters, diff,
// hooks, fsmonitor, pager, replace refs or lazy object fetching are involved.
// Clear inherited Git redirections/config overrides and ignore global config.
fn git(target: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    let exe = crate::platform::which("git").ok_or("git is required for --base")?;
    let mut c = Command::new(exe);
    c.env_clear();
    for key in ["PATH", "SystemRoot", "WINDIR", "SYSTEMDRIVE", "TEMP", "TMP"] {
        if let Some(v) = std::env::var_os(key) {
            c.env(key, v);
        }
    }
    c.env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            "--no-pager",
            "--no-replace-objects",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "diff.external=",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "protocol.allow=never",
        ])
        .current_dir(target)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = c.spawn().map_err(|e| format!("git object read: {e}"))?;
    let mut bytes = Vec::new();
    let read = child
        .stdout
        .take()
        .unwrap()
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes);
    if read.is_err() || bytes.len() as u64 > MAX_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Err("git object read failed or exceeds 1 MiB".into());
    }
    if !child.wait().map_err(|e| e.to_string())?.success() {
        return Err(format!(
            "git {} failed; base must be a locally available commit",
            args[0]
        ));
    }
    Ok(bytes)
}

pub fn load_base(target: &Path, base: Option<&str>) -> Result<Snapshot, String> {
    let commit = if let Some(base) = base {
        if base.trim().is_empty() {
            return Err("--base must name a commit".into());
        }
        let bytes = git(
            target,
            &[
                "rev-parse",
                "--verify",
                "--end-of-options",
                &format!("{base}^{{commit}}"),
            ],
        )?;
        let oid = String::from_utf8(bytes)
            .map_err(|e| e.to_string())?
            .trim()
            .to_string();
        if ![40, 64].contains(&oid.len()) || !oid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("base did not resolve to a commit object id".into());
        }
        Some(oid)
    } else {
        None
    };
    if let Some(commit) = &commit {
        let entry = git(target, &["ls-tree", "-z", commit, "--", PATH])?;
        if !entry.is_empty() {
            let entry = std::str::from_utf8(&entry).map_err(|e| e.to_string())?;
            let (header, path) = entry.split_once('\t').ok_or("invalid policy tree entry")?;
            let fields: Vec<_> = header.split_whitespace().collect();
            if fields.len() != 3
                || !["100644", "100755"].contains(&fields[0])
                || fields[1] != "blob"
                || path != format!("{PATH}\0")
            {
                return Err("base policy must be a regular committed blob".into());
            }
            let bytes = git(target, &["cat-file", "blob", fields[2]])?;
            let original = String::from_utf8(bytes).map_err(|e| e.to_string())?;
            let policy = parse(&original)?;
            return Ok(Snapshot {
                source: format!("{commit}:{PATH}"),
                base_commit: Some(commit.clone()),
                sha256: crate::sha256::digest(original.as_bytes()),
                policy,
                original: Some(original),
            });
        }
    }
    let policy = Policy::default();
    Ok(Snapshot {
        source: "defaults:no-base-policy".into(),
        base_commit: commit,
        sha256: crate::sha256::digest(text(&policy)?.as_bytes()),
        policy,
        original: None,
    })
}

/// Run storage is reviewer-owned, outside the target. A head policy never
/// participates, even when it is present on disk or committed at HEAD.
pub fn snapshot(run: &Path) -> Result<Snapshot, String> {
    let m = crate::runmeta::read(run)?;
    let value = m
        .get("policy")
        .ok_or("run has no base-policy snapshot; initialize a new run")?;
    parse(
        &serde_json::to_string(value.get("policy").ok_or("snapshot requires policy")?)
            .map_err(|e| e.to_string())?,
    )?;
    for key in ["source", "base_commit", "sha256", "original"] {
        if value.get(key).is_none() {
            return Err(format!("policy snapshot requires {key}"));
        }
    }
    let s: Snapshot = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    parse(&serde_json::to_string(&s.policy).map_err(|e| e.to_string())?)?;
    let original = s.original.clone().unwrap_or(text(&s.policy)?);
    if crate::sha256::digest(original.as_bytes()) != s.sha256 {
        return Err("policy digest mismatch".into());
    }
    if let Some(raw) = &s.original {
        if serde_json::to_value(parse(raw)?).map_err(|e| e.to_string())?
            != serde_json::to_value(&s.policy).map_err(|e| e.to_string())?
        {
            return Err("policy snapshot differs from committed blob".into());
        }
        let base = s.base_commit.as_deref().ok_or("policy needs base_commit")?;
        if s.source != format!("{base}:{PATH}") {
            return Err("policy source mismatch".into());
        }
    } else if s.source != "defaults:no-base-policy" {
        return Err("invalid default policy source".into());
    }
    let target = m
        .get("target")
        .and_then(|v| v.as_str())
        .ok_or("run needs target")?;
    let run = std::fs::canonicalize(run).map_err(|e| e.to_string())?;
    let target = std::fs::canonicalize(target).map_err(|e| e.to_string())?;
    if run.starts_with(target) {
        return Err("run must live outside target".into());
    }
    Ok(s)
}

pub fn excludes(p: &Policy, path: &str) -> bool {
    p.excluded_paths
        .iter()
        .any(|prefix| path == prefix || path.starts_with(&format!("{prefix}/")))
}
fn rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Informational => 0,
    }
}

pub fn gate(run: &Path) -> Result<u8, String> {
    let s = snapshot(run)?;
    let bytes = crate::platform::read_bounded(&run.join("findings.json"), 16 << 20)
        .map_err(|e| e.to_string())?;
    let file = crate::shape::findings(std::str::from_utf8(&bytes).map_err(|e| e.to_string())?)?;
    let errors = crate::model::validate(&file);
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    let mut blocking = 0;
    for finding in file
        .findings
        .iter()
        .filter(|f| f.verdict == Verdict::Confirmed)
    {
        let proofs = crate::proof::validate_proofs(
            &FindingsFile {
                findings: vec![finding.clone()],
            },
            run,
        );
        if !proofs.is_empty() {
            println!("ineligible {}: {}", finding.fingerprint, proofs.join("; "));
            continue;
        }
        if rank(finding.severity.unwrap()) < rank(s.policy.severity_threshold) {
            continue;
        }
        if let Some(suppression) = s.policy.suppressions.iter().find(|s| {
            s.fingerprint == finding.fingerprint
                && s.expires_unix
                    .is_none_or(|expiry| crate::runmeta::now_unix() < expiry)
        }) {
            println!("suppressed {}: {}", finding.fingerprint, suppression.reason);
            continue;
        }
        blocking += 1;
        println!(
            "{} {} ({})",
            if s.policy.mode == Mode::Advisory {
                "would block"
            } else {
                "blocks"
            },
            finding.fingerprint,
            finding.severity.unwrap().label()
        );
    }
    println!(
        "{}: {blocking} eligible finding(s); policy {} sha256 {}",
        s.policy.mode.label(),
        s.source,
        s.sha256
    );
    Ok(u8::from(blocking > 0 && s.policy.mode == Mode::Gate))
}

/// Whole-file unified diff so no untrusted diff driver is ever invoked.
pub fn propose(run: &Path, answers: &crate::intent::Answers) -> Result<std::path::PathBuf, String> {
    let s = snapshot(run)?;
    let mut p = s.policy;
    for a in &answers.answers {
        p.accepted_intent
            .retain(|old| old.id != a.id || old.scope != a.scope);
        p.accepted_intent.push(AcceptedIntent {
            id: a.id.clone(),
            answer: a.answer.clone(),
            scope: a.scope.clone(),
            source: a.source.clone(),
        });
    }
    p.accepted_intent
        .sort_by(|a, b| (&a.id, &a.scope).cmp(&(&b.id, &b.scope)));
    let new = text(&p)?;
    let old = s.original.unwrap_or_default();
    let mut diff = String::new();
    if old != new {
        diff.push_str(&format!("diff --git a/{PATH} b/{PATH}\n"));
        if old.is_empty() {
            diff.push_str("new file mode 100644\n");
        }
        diff.push_str(&format!(
            "--- {}\n+++ b/{PATH}\n@@ -{},{} +1,{} @@\n",
            if old.is_empty() {
                "/dev/null".into()
            } else {
                format!("a/{PATH}")
            },
            usize::from(!old.is_empty()),
            old.lines().count(),
            new.lines().count()
        ));
        for line in old.lines() {
            diff.push_str(&format!("-{line}\n"));
        }
        if !old.is_empty() && !old.ends_with('\n') {
            diff.push_str("\\ No newline at end of file\n");
        }
        for line in new.lines() {
            diff.push_str(&format!("+{line}\n"));
        }
    }
    let path = run.join("policy.patch");
    crate::runmeta::write_atomic(&path, &diff)?;
    Ok(path)
}
