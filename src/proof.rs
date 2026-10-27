//! Proof records: what `omgs prove` ran, under which enforced controls, and
//! what happened, written by the runner beside the findings as
//! `proofs/<n>.json`. A finding that claims a proof tier must point at one.

use crate::model::{FindingsFile, ProofTier};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const SCHEMA: &str = "omgs-proof/1";
pub const DIR: &str = "proofs";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Survivor {
    pub pid: i32,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofRecord {
    pub schema: String,
    pub n: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding: Option<String>,
    /// Proof test path relative to the target, when the run executes one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test: Option<String>,
    /// SHA-256 of the proof test as it existed in the target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_sha256: Option<String>,
    /// Draft the test was staged from, when it was not already in the target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_from: Option<String>,
    /// The record this run replayed, when it was `omgs prove --replay`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replays: Option<u32>,
    /// `test` (tier 1) or `local_app` (tier 2).
    pub tier: String,
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Commit the target's checkout pointed at, read from `.git` as text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_head: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_sha256: Option<String>,
    pub marker_nonce: String,
    pub command_started: bool,
    pub command_finished: bool,
    pub started_at_ms: u64,
    pub duration_ms: u64,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub capture_complete: bool,
    /// Every signal, reap and survivor scan succeeded.
    #[serde(default)]
    pub cleanup_complete: bool,
    /// The executor itself reported an error (bad policy, backend failure),
    /// so the command may never have started.
    #[serde(default)]
    pub executor_error: bool,
    pub survivors: Vec<Survivor>,
    pub mxc_version: String,
    pub containment: String,
    pub executor: String,
    pub executor_sha256: String,
    pub config_sha256: String,
    pub enforced: Vec<String>,
    pub gaps: Vec<String>,
    pub output_sha256: String,
    pub output_bytes_total: u64,
    /// Capped and redacted; the digest covers exactly this saved text.
    pub output: String,
    pub omgs_version: String,
}

impl ProofRecord {
    /// A run whose result can be trusted at all: it finished on its own, the
    /// output was fully captured and nothing escaped.
    pub fn clean(&self) -> bool {
        self.command_started
            && self.command_finished
            && self.exit_code.is_some()
            && self.marker_nonce.len() == 64
            && self.marker_nonce.bytes().all(|b| b.is_ascii_hexdigit())
            && !self.timed_out
            && self.capture_complete
            && self.cleanup_complete
            && !self.executor_error
            && self.survivors.is_empty()
    }

    /// A nonzero exit that a failing assertion can produce, as opposed to a
    /// shell that could not find or execute the command (126, 127) or a
    /// process killed by a signal (above 128, or no code at all).
    pub fn assertion_failure(&self) -> bool {
        matches!(self.exit_code, Some(c) if (1..=125).contains(&c))
    }
}

/// Reserve the next proof number under `<run>/proofs/` by creating its
/// directory, which fails if another prove took the number first.
pub fn reserve(run: &Path) -> Result<(u32, PathBuf), String> {
    let dir = run.join(DIR);
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let mut n = std::fs::read_dir(&dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.strip_suffix(".json")
                .unwrap_or(&name)
                .parse::<u32>()
                .ok()
        })
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or("proof numbers exhausted")?;
    loop {
        let d = dir.join(n.to_string());
        match std::fs::create_dir(&d) {
            Ok(()) => return Ok((n, d)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && n < u32::MAX => n += 1,
            Err(e) => return Err(format!("create {}: {e}", d.display())),
        }
    }
}

pub fn record_path(run: &Path, n: u32) -> PathBuf {
    run.join(DIR).join(format!("{n}.json"))
}

/// The value a finding puts in `proof_ref` for record `n`.
pub fn reference(n: u32) -> String {
    format!("{DIR}/{n}.json")
}

pub fn write(run: &Path, record: &ProofRecord) -> Result<PathBuf, String> {
    let path = record_path(run, record.n);
    let text = serde_json::to_string_pretty(record).map_err(|e| e.to_string())?;
    crate::runmeta::write_atomic(&path, &format!("{text}\n"))?;
    Ok(path)
}

/// Load the record a `proof_ref` names, accepting only `proofs/<n>.json`
/// so a reference cannot point outside the run directory.
pub fn load(run: &Path, proof_ref: &str) -> Result<ProofRecord, String> {
    let n: u32 = proof_ref
        .strip_prefix("proofs/")
        .and_then(|r| r.strip_suffix(".json"))
        .and_then(|r| r.parse().ok())
        .ok_or_else(|| format!("proof_ref '{proof_ref}' must look like proofs/<n>.json"))?;
    let path = record_path(run, n);
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    // Strict like every other run input: duplicate keys and unknown fields
    // are errors.
    let record: ProofRecord =
        crate::shape::proof(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
    if record.schema != SCHEMA || record.n != n || n == 0 {
        return Err(format!("{} is not proof record {n}", path.display()));
    }
    Ok(record)
}

/// Every record that claims a proof tier must reference a clean proof record
/// for its own fingerprint and tier. `run` is the directory that holds the
/// findings file.
pub fn validate_proofs(file: &FindingsFile, run: &Path) -> Vec<String> {
    let mut errors = Vec::new();
    for (i, f) in file.findings.iter().enumerate() {
        let at = format!("findings[{i}] '{}'", f.title);
        let want = match f.proof_tier {
            ProofTier::Traced => continue,
            ProofTier::TestProven => "test",
            ProofTier::SandboxExploited => "local_app",
        };
        let Some(r) = f.proof_ref.as_deref().filter(|r| !r.trim().is_empty()) else {
            errors.push(format!(
                "{at}: proof_tier {} requires proof_ref to a record written by omgs prove --run --finding",
                f.proof_tier.label()
            ));
            continue;
        };
        let record = match load(run, r) {
            Ok(rec) => rec,
            Err(e) => {
                errors.push(format!("{at}: {e}"));
                continue;
            }
        };
        if record.finding.as_deref() != Some(f.fingerprint.as_str()) {
            errors.push(format!(
                "{at}: {r} was recorded for finding {}, not {}",
                record.finding.as_deref().unwrap_or("none"),
                f.fingerprint
            ));
        }
        if record.tier != want {
            errors.push(format!(
                "{at}: {r} ran at tier {}, which cannot support {}",
                record.tier,
                f.proof_tier.label()
            ));
        }
        if !record.clean() {
            errors.push(format!(
                "{at}: {r} did not finish cleanly (timeout, executor error, incomplete capture or cleanup, or surviving processes)"
            ));
        }
        errors.extend(
            runner_evidence(run, &record)
                .into_iter()
                .map(|e| format!("{at}: {r} {e}")),
        );
        // Both tiers use one convention: the proof test or harness exits with a
        // failing assertion when the target permits the unauthorized effect.
        {
            match (&record.test, &record.test_sha256) {
                (Some(t), Some(_)) => {
                    if !command_names(&record.command, t) {
                        errors.push(format!(
                            "{at}: {r} ran a command that does not name its proof test {t}"
                        ));
                    }
                }
                _ => errors.push(format!(
                    "{at}: {r} names no proof test; run omgs prove with --test <path in the target>"
                )),
            }
            // Every non-rejected record needs the test failing on the target; a
            // rejected one may rest on a control test that passes.
            if (f.verdict != crate::model::Verdict::Rejected && !record.assertion_failure())
                || !matches!(record.exit_code, Some(0..=125))
            {
                errors.push(format!(
                    "{at}: {r} exited {}, a proven record needs the proof test failing on the target (126, 127 and signals mean the test never ran)",
                    record
                        .exit_code
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "without a code".into())
                ));
            }
        }
    }
    errors
}

/// Whether one quote-aware whitespace token of `command` is the
/// full test path or its file name. A sanity check that the
/// recorded command is the proof test, not evidence that it executed it:
/// replay and the independent evaluator must check that separately.
pub fn command_names(command: &str, test: &str) -> bool {
    let norm = |s: &str| s.replace('\\', "/");
    let test = norm(test);
    let name = test.rsplit('/').next().unwrap_or(&test).to_string();
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quote = None;
    for c in command.chars() {
        if quote == Some(c) {
            quote = None;
        } else if quote.is_none() && (c == '\'' || c == '"') {
            quote = Some(c);
        } else if quote.is_none() && c.is_whitespace() {
            tokens.push(std::mem::take(&mut token));
        } else {
            token.push(c);
        }
    }
    tokens.push(token);
    tokens.iter().map(|t| norm(t)).any(|tok| {
        let tok = tok.strip_prefix("./").unwrap_or(&tok);
        !tok.is_empty() && !name.is_empty() && (tok == test || tok == name)
    })
}

/// Cross-checks against what the runner wrote beside the record: the
/// executor digest is one OMGS pins, the containment matches it, the MXC
/// config saved for this run hashes to the recorded digest, and controls
/// were recorded. This catches hand-written or edited records; it is not a
/// defence against a process that runs as the user and forges every file.
pub fn runner_evidence(run: &Path, record: &ProofRecord) -> Vec<String> {
    let mut errors = Vec::new();
    match crate::sandbox::pinned_executors()
        .into_iter()
        .find(|e| e.sha256 == record.executor_sha256)
    {
        None => errors.push(format!(
            "names executor digest {}, which is not a pinned MXC {} executor",
            record.executor_sha256,
            crate::sandbox::MXC_VERSION
        )),
        Some(e) if e.containment != record.containment => errors.push(format!(
            "claims containment {} for an executor that provides {}",
            record.containment, e.containment
        )),
        Some(e) => {
            if !record.executor.ends_with(e.file) {
                errors.push(format!(
                    "names executor {} for the {} digest",
                    record.executor, e.file
                ));
            }
            let os = match e.containment {
                "seatbelt" => "macos",
                "bubblewrap" => "linux",
                _ => "windows",
            };
            let tier = if record.tier == "local_app" {
                crate::sandbox::Tier::LocalApp
            } else {
                crate::sandbox::Tier::Test
            };
            let (declared, _) = crate::sandbox::declared_controls(os, tier);
            if let Some(missing) = declared.iter().find(|c| !record.enforced.contains(c)) {
                errors.push(format!("does not list the required control '{missing}'"));
            }
        }
    }
    if record.mxc_version != crate::sandbox::MXC_VERSION {
        errors.push(format!(
            "ran MXC {}, not the pinned {}",
            record.mxc_version,
            crate::sandbox::MXC_VERSION
        ));
    }
    let run_target = crate::runmeta::read(run)
        .ok()
        .and_then(|m| m.get("target").and_then(|v| v.as_str()).map(String::from));
    if let Some(rt) = run_target {
        let canon = |p: &str| std::fs::canonicalize(p).unwrap_or_else(|_| PathBuf::from(p));
        match &record.target {
            Some(t) if canon(t) == canon(&rt) => {}
            _ => errors.push(format!(
                "target must be present and match this run's target {rt}"
            )),
        }
    }
    if record.target.is_some() && record.target_sha256.as_ref().is_none_or(|d| !is_digest(d)) {
        errors.push("has no valid target snapshot digest".into());
    }
    if record.test_from.is_some() {
        let draft = run.join(DIR).join(record.n.to_string()).join("test-draft");
        if crate::sha256::digest_file(&draft).ok().as_ref() != record.test_sha256.as_ref()
            || record.test_sha256.is_none()
        {
            errors.push("test-draft does not match test_sha256".into());
        }
    }
    if crate::sha256::digest(record.output.as_bytes()) != record.output_sha256 {
        errors.push("redacted output does not match output_sha256".into());
    }
    let config = run
        .join(DIR)
        .join(record.n.to_string())
        .join("mxc-config.json");
    match std::fs::read(&config) {
        Ok(bytes) if crate::sha256::digest(&bytes) == record.config_sha256 => {
            match std::str::from_utf8(&bytes)
                .map_err(|e| e.to_string())
                .and_then(crate::shape::strict_json)
            {
                Ok(config) => errors.extend(config_evidence(run, record, &config)),
                Err(e) => errors.push(format!("invalid MXC config: {e}")),
            }
        }
        Ok(_) => errors.push(format!(
            "does not match the MXC config the runner saved at {}",
            config.display()
        )),
        Err(e) => errors.push(format!("has no runner config at {}: {e}", config.display())),
    }
    if record.enforced.is_empty() {
        errors.push("lists no enforced controls".into());
    }
    errors
}

fn is_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn config_evidence(run: &Path, record: &ProofRecord, config: &serde_json::Value) -> Vec<String> {
    let mut errors = Vec::new();
    let os = match record.containment.as_str() {
        "seatbelt" => "macos",
        "bubblewrap" => "linux",
        _ => "windows",
    };
    for (pointer, expected) in [
        ("/version", "1.0.0"),
        ("/containment", record.containment.as_str()),
        ("/network/egress/default", "deny"),
        ("/network/ingress/default", "deny"),
        ("/network/ingress/hostLoopback", "deny"),
    ] {
        if config.pointer(pointer).and_then(|v| v.as_str()) != Some(expected) {
            errors.push(format!("MXC config {pointer} must be {expected}"));
        }
    }
    let wrapped = crate::sandbox::wrapped_command(os, &record.command, &record.marker_nonce);
    if config
        .pointer("/process/commandLine")
        .and_then(|v| v.as_str())
        != Some(&wrapped)
    {
        errors.push("MXC config commandLine is not the wrapped record.command".into());
    }
    if config
        .pointer("/process/timeout")
        .and_then(|v| v.as_u64())
        .is_none_or(|t| !(1..=u64::from(u32::MAX)).contains(&t))
    {
        errors.push("MXC config timeout must be a finite MXC millisecond count".into());
    }
    let dir = run.join(DIR).join(record.n.to_string());
    let dir = std::fs::canonicalize(&dir).unwrap_or(dir);
    let norm = |p: &str| {
        let p = p.replace('\\', "/");
        let p = p.strip_prefix("//?/").unwrap_or(&p);
        if os == "windows" {
            p.to_ascii_lowercase()
        } else {
            p.to_string()
        }
    };
    let workspace = norm(&dir.join("workspace").to_string_lossy());
    let scratch = norm(&dir.join("scratch").to_string_lossy());
    if config
        .pointer("/process/cwd")
        .and_then(|v| v.as_str())
        .map(&norm)
        != Some(workspace.clone())
    {
        errors.push("MXC config cwd must be this proof's proofs/<n>/workspace".into());
    }
    let rw = config
        .pointer("/filesystem/readwritePaths")
        .and_then(|v| v.as_array());
    if rw.is_none_or(|paths| {
        paths.len() != 2
            || !paths.iter().all(|p| {
                p.as_str().is_some_and(|p| {
                    let p = norm(p);
                    p == workspace || p == scratch
                })
            })
            || ![&workspace, &scratch].iter().all(|want| {
                paths
                    .iter()
                    .any(|p| p.as_str().map(&norm).as_ref() == Some(*want))
            })
    }) {
        errors.push(
            "MXC config readwritePaths must be limited to this proof's workspace and scratch"
                .into(),
        );
    }
    errors
}

/// Content identity of the copied target before staging the proof test.
/// Links are hashed as links, never followed into outside content.
pub fn tree_digest(root: &Path) -> std::io::Result<String> {
    fn field(h: &mut crate::sha256::Sha256, bytes: &[u8]) {
        h.update(&(bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    fn walk(root: &Path, dir: &Path, h: &mut crate::sha256::Sha256) -> std::io::Result<()> {
        let mut entries = std::fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            if entry.file_name() == ".git" {
                continue;
            }
            let path = entry.path();
            let rel = path.strip_prefix(root).map_err(std::io::Error::other)?;
            field(h, rel.as_os_str().as_encoded_bytes());
            let meta = std::fs::symlink_metadata(&path)?;
            if crate::platform::is_link(&meta) {
                field(h, b"link");
                let link = std::fs::canonicalize(&path)
                    .ok()
                    .and_then(|p| p.strip_prefix(root).ok().map(PathBuf::from))
                    .map(|p| PathBuf::from("@workspace").join(p))
                    .unwrap_or(std::fs::read_link(&path)?);
                field(h, link.as_os_str().as_encoded_bytes());
            } else {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    field(h, &(meta.permissions().mode() & 0o777).to_le_bytes());
                }
                if meta.is_dir() {
                    field(h, b"dir");
                    walk(root, &path, h)?;
                } else if meta.is_file() {
                    field(h, b"file");
                    field(h, crate::sha256::digest_file(&path)?.as_bytes());
                } else {
                    return Err(std::io::Error::other("unsupported target file type"));
                }
            }
        }
        Ok(())
    }
    let root = std::fs::canonicalize(root)?;
    let mut h = crate::sha256::Sha256::new();
    walk(&root, &root, &mut h)?;
    Ok(crate::sha256::hex(&h.finish()))
}

/// The checkout's commit, read from `.git` as data. Git itself is never run
/// against the target, since repository config can execute programs.
pub fn git_head(target: &Path) -> Option<String> {
    let mut git = target.join(".git");
    if git.is_file() {
        let text = std::fs::read_to_string(&git).ok()?;
        let p = PathBuf::from(text.trim().strip_prefix("gitdir:")?.trim());
        git = if p.is_absolute() { p } else { target.join(p) };
    }
    let head = std::fs::read_to_string(git.join("HEAD")).ok()?;
    let head = head.trim();
    let Some(reference) = head.strip_prefix("ref:").map(str::trim) else {
        return is_hex40(head).then(|| head.to_string());
    };
    if reference.contains("..") {
        return None;
    }
    // Linked worktrees keep branch refs in the common dir.
    let common = std::fs::read_to_string(git.join("commondir"))
        .ok()
        .map(|c| git.join(c.trim()))
        .unwrap_or_else(|| git.clone());
    for dir in [&git, &common] {
        if let Ok(v) = std::fs::read_to_string(dir.join(reference)) {
            let v = v.trim();
            if is_hex40(v) {
                return Some(v.to_string());
            }
        }
        if let Ok(packed) = std::fs::read_to_string(dir.join("packed-refs")) {
            for line in packed.lines() {
                if let Some((sha, name)) = line.split_once(' ') {
                    if name == reference && is_hex40(sha) {
                        return Some(sha.to_string());
                    }
                }
            }
        }
    }
    None
}

fn is_hex40(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Mask values that look like credentials before output lands in a record:
/// the rest of a line after a credential keyword and its separator, and PEM
/// private key bodies. Proof runs use dummy secrets, so this is a backstop.
pub fn redact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_pem = false;
    for line in text.split_inclusive('\n') {
        let lower = line.to_ascii_lowercase();
        if lower.contains("-----begin") && lower.contains("private key") {
            in_pem = true;
            out.push_str("[omgs redacted private key]\n");
            continue;
        }
        if in_pem {
            if lower.contains("-----end") {
                in_pem = false;
            }
            continue;
        }
        out.push_str(&redact_line(line, &lower));
    }
    out
}

/// One line: credential URLs lose their user info, bearer tokens and the
/// value after a credential keyword (quoted or bare, `:` or `=`) are masked.
fn redact_line(line: &str, lower: &str) -> String {
    const KEYS: [&str; 13] = [
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "api-key",
        "authorization",
        "private_key",
        "cookie",
        "passphrase",
        "access_key",
        "session",
    ];
    let mut line = line.to_string();
    let mut lower = lower.to_string();
    // scheme://user:pass@host
    let mut from = 0;
    while let Some(i) = lower[from..].find("://").map(|i| i + from + 3) {
        let end = lower[i..]
            .find(|c: char| c == '/' || c.is_whitespace() || c == '"' || c == '\'')
            .map(|e| e + i)
            .unwrap_or(lower.len());
        if let Some(at) = lower[i..end].rfind('@').map(|a| a + i) {
            if lower[i..at].contains(':') {
                line.replace_range(i..at, "[omgs redacted]");
                lower = line.to_ascii_lowercase();
            }
        }
        from = i.min(lower.len());
    }
    let cut = KEYS
        .iter()
        .flat_map(|k| lower.match_indices(k).map(|(i, _)| i + k.len()))
        .filter_map(|after| {
            lower[after..]
                .find([':', '='])
                .filter(|j| {
                    lower[after..after + j].chars().all(|c| {
                        c.is_whitespace()
                            || c == '"'
                            || c == '\''
                            || c.is_alphanumeric()
                            || c == '_'
                    })
                })
                .map(|j| after + j + 1)
        })
        .chain(lower.find("bearer ").map(|i| i + "bearer ".len()))
        .min();
    match cut {
        Some(c) if line.is_char_boundary(c) => {
            let newline = line.ends_with('\n');
            line.truncate(c);
            line.push_str(" [omgs redacted]");
            if newline {
                line.push('\n');
            }
            line
        }
        _ => line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_covers_cookie_sessions_and_credential_suffixes() {
        for line in [
            "aws_secret_access_key = very-secret",
            "Cookie: sessionid=private",
            "passphrase: private",
            "access_key=private",
            "session_id: private",
            "TOKEN_VALUE=private",
        ] {
            let masked = redact(line);
            assert!(masked.contains("[omgs redacted]"), "{masked}");
            assert!(
                !masked.contains("private") && !masked.contains("very-secret"),
                "{masked}"
            );
        }
    }

    #[test]
    fn tree_digest_includes_dirty_changes_but_excludes_git() {
        let d = std::env::temp_dir().join(format!("omgs-digest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(".git")).unwrap();
        std::fs::write(d.join("a"), b"one").unwrap();
        let first = tree_digest(&d).unwrap();
        std::fs::write(d.join(".git/HEAD"), b"changed").unwrap();
        assert_eq!(tree_digest(&d).unwrap(), first);
        std::fs::write(d.join("a"), b"two").unwrap();
        assert_ne!(tree_digest(&d).unwrap(), first);
        std::fs::write(d.join("a"), b"one").unwrap();
        std::fs::create_dir(d.join("empty")).unwrap();
        assert_ne!(tree_digest(&d).unwrap(), first);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn redaction_masks_credentials_and_keeps_the_rest() {
        let text = "ok line\nAPI_KEY=abc123\nToken: xyz\nauthorization required\n-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\ndone\n";
        let r = redact(text);
        assert!(r.contains("ok line\n"));
        assert!(r.contains("API_KEY= [omgs redacted]\n"));
        assert!(r.contains("Token: [omgs redacted]\n"));
        assert!(r.contains("authorization required\n"));
        assert!(!r.contains("abc123") && !r.contains("xyz") && !r.contains("MIIB"));
        assert!(r.ends_with("done\n"));
        let json = redact("{\"api_key\": \"k-123\", \"x\": 1}\n");
        assert!(!json.contains("k-123"), "{json}");
        let bearer = redact("Authorization header: Bearer eyJabc.def\ncurl -H x\n");
        assert!(!bearer.contains("eyJabc"), "{bearer}");
        let twice = redact("token x then token=abc\n");
        assert!(!twice.contains("abc"), "{twice}");
        assert!(command_names(
            "sh tests/security/x.test.sh",
            "tests/security/x.test.sh"
        ));
        assert!(command_names(
            "cmd.exe /d /c tests\\security\\x.cmd",
            "tests/security/x.cmd"
        ));
        assert!(command_names(
            "swiftc main.swift v/Verifier.swift",
            "main.swift"
        ));
        assert!(!command_names("exit 1 # x.test.shy", "tests/x.test.sh"));
        assert!(command_names(
            "sh 'tests/proof with spaces.sh'",
            "tests/proof with spaces.sh"
        ));
        assert!(!command_names("sh 'exit 1 # tests/x.sh'", "tests/x.sh"));
        assert!(!command_names("echo prefix/tests/x.sh", "tests/x.sh"));
        let url = redact("fetch https://bob:hunter2@example.test/x ok\n");
        assert!(
            !url.contains("hunter2") && url.contains("example.test/x ok"),
            "{url}"
        );
    }

    #[test]
    fn reserve_numbers_are_unique_and_refs_stay_inside_the_run() {
        let run = std::env::temp_dir().join(format!("omgs-proof-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&run);
        let (a, _) = reserve(&run).unwrap();
        let (b, _) = reserve(&run).unwrap();
        assert_eq!((a, b), (1, 2));
        assert!(load(&run, "../x.json").is_err());
        assert!(load(&run, "proofs/../../etc.json").is_err());
        let _ = std::fs::remove_dir_all(&run);
    }
}
