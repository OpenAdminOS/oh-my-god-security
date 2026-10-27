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
    /// Capped and redacted; the digest covers the capped text before redaction.
    pub output: String,
    pub omgs_version: String,
}

impl ProofRecord {
    /// A run whose result can be trusted at all: it finished on its own, the
    /// output was fully captured and nothing escaped.
    pub fn clean(&self) -> bool {
        !self.timed_out
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
    let mut n = 1 + std::fs::read_dir(&dir)
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
        .unwrap_or(0);
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
    let record: ProofRecord = crate::shape::strict_json(&text)
        .and_then(|v| serde_json::from_value(v).map_err(|e| e.to_string()))
        .map_err(|e| format!("parse {}: {e}", path.display()))?;
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
                    let name = t.rsplit(['/', '\\']).next().unwrap_or(t);
                    if !record.command.contains(name) {
                        errors.push(format!(
                            "{at}: {r} ran a command that does not name its proof test {t}"
                        ));
                    }
                }
                _ => errors.push(format!(
                    "{at}: {r} names no proof test; run omgs prove with --test <path in the target>"
                )),
            }
            if !record.assertion_failure() {
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

/// Cross-checks against what the runner wrote beside the record: the
/// executor digest is one OMGS pins, the containment matches it, the MXC
/// config saved for this run hashes to the recorded digest, and controls
/// were recorded. This catches hand-written or edited records; it is not a
/// defence against a process that runs as the user and forges every file.
fn runner_evidence(run: &Path, record: &ProofRecord) -> Vec<String> {
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
    if let Some(t) = &record.target {
        let run_target = crate::runmeta::read(run)
            .ok()
            .and_then(|m| m.get("target").and_then(|v| v.as_str()).map(String::from));
        if let Some(rt) = run_target {
            let canon = |p: &str| std::fs::canonicalize(p).unwrap_or_else(|_| PathBuf::from(p));
            if canon(t) != canon(&rt) {
                errors.push(format!("ran against {t}, not this run's target {rt}"));
            }
        }
    }
    let config = run
        .join(DIR)
        .join(record.n.to_string())
        .join("mxc-config.json");
    match std::fs::read(&config) {
        Ok(bytes) if crate::sha256::digest(&bytes) == record.config_sha256 => {}
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
    const KEYS: [&str; 9] = [
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "api-key",
        "authorization",
        "private_key",
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
        .filter_map(|k| lower.find(k).map(|i| i + k.len()))
        .filter_map(|after| {
            lower[after..]
                .find([':', '='])
                .filter(|j| {
                    lower[after..after + j]
                        .chars()
                        .all(|c| c.is_whitespace() || c == '"' || c == '\'')
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
