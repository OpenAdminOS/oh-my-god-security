//! Proof records: what `omgs prove` ran, under which enforced controls, and
//! what happened, written by the runner beside the findings as
//! `proofs/<n>.json`. A finding that claims a proof tier must point at one.

use crate::model::{FindingsFile, ProofTier};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const SCHEMA: &str = "omgs-proof/1";
pub const DIR: &str = "proofs";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Survivor {
    pub pid: i32,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRecord {
    pub schema: String,
    pub n: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding: Option<String>,
    /// Proof test path relative to the target, when the run executes one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test: Option<String>,
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
        !self.timed_out && self.capture_complete && self.survivors.is_empty()
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
    let record: ProofRecord =
        serde_json::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
    if record.schema != SCHEMA || record.n != n {
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
                "{at}: {r} did not finish cleanly (timed out, incomplete capture or surviving processes)"
            ));
        }
        // A tier 1 proof is a security test that fails on the vulnerable code.
        if want == "test" && !matches!(record.exit_code, Some(c) if c != 0) {
            errors.push(format!(
                "{at}: {r} exited {}, a test_proven record needs the proof test failing on the target",
                record
                    .exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "without a code".into())
            ));
        }
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
    const KEYS: [&str; 8] = [
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "private_key",
    ];
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
        let cut = KEYS
            .iter()
            .filter_map(|k| lower.find(k).map(|i| i + k.len()))
            .filter_map(|after| {
                lower[after..]
                    .find([':', '='])
                    .filter(|j| lower[after..after + j].trim().is_empty())
                    .map(|j| after + j + 1)
            })
            .min();
        match cut {
            Some(c) if line.is_char_boundary(c) => {
                out.push_str(&line[..c]);
                out.push_str(" [omgs redacted]");
                if line.ends_with('\n') {
                    out.push('\n');
                }
            }
            _ => out.push_str(line),
        }
    }
    out
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
