//! Proof records: what `omgs prove` ran, under which enforced controls, and
//! what happened, written by the runner beside the findings as
//! `proofs/<n>.json`. A finding that claims a proof tier must point at one.

use crate::model::{FindingsFile, ProofTier};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const SCHEMA: &str = "omgs-proof/2";
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
    pub command_sha256: String,
    pub wrapped_command_sha256: String,
    /// Toolchain grants at proof time, independent of the validating host.
    pub readable_roots: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Commit the target's checkout pointed at, read from `.git` as text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_head: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_sha256: Option<String>,
    /// Original canonical proof directory, retained when a run is archived.
    pub proof_dir: String,
    pub marker_nonce: String,
    pub command_started: bool,
    pub command_finished: bool,
    /// The wrapper opened the named test inside the sandbox before execution.
    #[serde(default)]
    pub test_reachable: Option<bool>,
    pub timeout_ms: u64,
    pub started_at_ms: u64,
    pub duration_ms: u64,
    pub exit_code: Option<i32>,
    /// Required even when no recipe contract was declared.
    pub contract: Contract,
    pub timed_out: bool,
    pub capture_complete: bool,
    /// Every signal, reap and survivor scan succeeded.
    #[serde(default)]
    pub cleanup_complete: bool,
    /// The executor itself reported an error (bad policy, backend failure),
    /// so the command may never have started.
    #[serde(default)]
    pub executor_error: bool,
    #[serde(default)]
    pub killed: bool,
    #[serde(default)]
    pub interrupted: bool,
    pub survivors: Vec<Survivor>,
    pub mxc_version: String,
    pub containment: String,
    pub executor: String,
    pub executor_sha256: String,
    pub config_sha256: String,
    pub enforced: Vec<String>,
    pub gaps: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
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
            && (self.test_reachable == Some(true)
                || (self.test.is_none() && self.test_reachable.is_none()))
            && self.exit_code.is_some()
            && self.marker_nonce.len() == 64
            && self.marker_nonce.bytes().all(|b| b.is_ascii_hexdigit())
            && !self.timed_out
            && self.capture_complete
            && self.cleanup_complete
            && !self.executor_error
            && !self.killed
            && !self.interrupted
            && self.survivors.is_empty()
    }

    /// Exit 2 is a usage or harness error, never assertion evidence.
    /// A declared recipe contract additionally requires both full-stream markers.
    pub fn assertion_failure(&self) -> bool {
        match &self.contract {
            Contract::Recipe {
                expect_marker,
                boundary_marker_seen,
                authorized_control_seen,
            } => {
                valid_expect_marker(expect_marker)
                    && self.exit_code == Some(1)
                    && *boundary_marker_seen
                    && *authorized_control_seen
            }
            Contract::None => matches!(self.exit_code, Some(1 | 3..=125)),
        }
    }

    pub fn supports_verdict(&self, rejected: bool) -> bool {
        self.assertion_failure()
            || (self.contract.expect_marker().is_none() && rejected && self.exit_code == Some(0))
    }
}

/// Required discriminator and evidence. Missing and null fields are errors.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Contract {
    None,
    Recipe {
        expect_marker: String,
        boundary_marker_seen: bool,
        authorized_control_seen: bool,
    },
}

impl Contract {
    pub fn expect_marker(&self) -> Option<&str> {
        match self {
            Self::None => None,
            Self::Recipe { expect_marker, .. } => Some(expect_marker),
        }
    }

    pub fn evidence(&self) -> (bool, bool) {
        match self {
            Self::None => (false, false),
            Self::Recipe {
                boundary_marker_seen,
                authorized_control_seen,
                ..
            } => (*boundary_marker_seen, *authorized_control_seen),
        }
    }
}

/// Exact full-stream lines, scoped to this run and declared boundary label.
pub fn boundary_marker(marker: &str, nonce: &str) -> String {
    format!("OMGS_BOUNDARY_{nonce}_{marker}")
}

pub fn control_marker(nonce: &str) -> String {
    format!("OMGS_CONTROL_{nonce}")
}

/// Contracts use one short ASCII line, distinct from runner and control markers.
pub fn valid_expect_marker(marker: &str) -> bool {
    !marker.is_empty()
        && marker.len() <= 128
        && marker
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && marker != "AUTHORIZED_CONTROL_OK"
        && !marker.starts_with("OMGS_")
}

/// Reserve the next proof number under `<run>/proofs/` by creating its
/// directory, which fails if another prove took the number first.
pub fn reserve(run: &Path) -> Result<(u32, PathBuf), String> {
    let dir = run.join(DIR);
    crate::platform::create_private_tree(&dir)
        .map_err(|e| format!("create {}: {e}", dir.display()))?;
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
        match crate::platform::create_private_dir_new(&d) {
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
    let mut record = record.clone();
    record.command = redact(&record.command);
    for survivor in &mut record.survivors {
        survivor.command = redact(&survivor.command);
    }
    let text = serde_json::to_string_pretty(&record).map_err(|e| e.to_string())?;
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
    if proof_ref != reference(n) || n == 0 {
        return Err(format!(
            "proof_ref '{proof_ref}' must use canonical proofs/<n>.json form"
        ));
    }
    let path = record_path(run, n);
    let text = read_text(&path, 2 << 20)?;
    // Strict like every other run input: duplicate keys and unknown fields
    // are errors.
    let record: ProofRecord =
        crate::shape::proof(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
    if record.schema != SCHEMA || record.n != n || n == 0 {
        return Err(format!("{} is not proof record {n}", path.display()));
    }
    Ok(record)
}

fn read_text(path: &Path, limit: u64) -> Result<String, String> {
    crate::platform::read_bounded(path, limit)
        .map_err(|e| format!("read {}: {e}", path.display()))
        .and_then(|bytes| String::from_utf8(bytes).map_err(|e| e.to_string()))
}

/// Exact replay input stays beside the config; the record carries a redacted
/// display and digests. Config and command artifacts may contain credentials.
pub fn recorded_command(run: &Path, record: &ProofRecord) -> Result<String, String> {
    let path = run.join(DIR).join(record.n.to_string()).join("command.txt");
    let command = read_text(&path, 1 << 20)?;
    if crate::sha256::digest(command.as_bytes()) != record.command_sha256
        || redact(&command) != record.command
    {
        return Err("saved command does not match record.command or command_sha256".into());
    }
    Ok(command)
}

/// Every record that claims a proof tier must reference a clean proof record
/// for its own fingerprint and tier. `run` is the directory that holds the
/// findings file.
pub fn validate_proofs(file: &FindingsFile, run: &Path) -> Vec<String> {
    let mut errors = Vec::new();
    for (i, f) in file.findings.iter().enumerate() {
        let at = format!("findings[{i}] '{}'", f.title);
        let want = match f.proof_tier {
            ProofTier::Traced => {
                if f.proof_ref.is_some() {
                    errors.push(format!("{at}: traced findings must not carry proof_ref; retain the source trace in evidence"));
                }
                continue;
            }
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
        if record.replays.is_some() {
            errors.push(format!(
                "{at}: proof_ref must name the original proof, not a replay"
            ));
        }
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
        if record.test.is_some() && record.test_reachable != Some(true) {
            errors.push(format!(
                "{at}: {r} proof test was not reachable inside the sandbox"
            ));
        }
        errors.extend(
            runner_evidence(run, &record)
                .into_iter()
                .map(|e| format!("{at}: {r} {e}")),
        );
        // Both tiers use one convention: the proof test or harness exits with a
        // failing assertion when the target permits the unauthorized effect.
        match (&record.test, &record.test_sha256) {
            (Some(t), Some(_)) => {
                if recorded_command(run, &record).is_ok_and(|command| !command_names(&command, t)) {
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
        if !record.supports_verdict(f.verdict == crate::model::Verdict::Rejected) {
            errors.push(format!(
                "{at}: {r} exited {:?}; proof support requires assertion exit 1 or 3..=125 (exit 2 is a harness or usage error); a declared contract requires exit 1, its nonce-qualified boundary and control markers from full-stream capture",
                record.exit_code
            ));
        }
    }
    errors
}

/// Whether one quote-aware shell token of `command` is the
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
        } else if quote.is_none()
            && (matches!(c, ' ' | '\t' | '\r' | '\n') || ";&|()<>".contains(c))
        {
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
    if record
        .contract
        .expect_marker()
        .is_some_and(|m| !valid_expect_marker(m))
    {
        errors.push("invalid boundary marker contract".into());
    }
    if record.tier == "local_app" && record.containment != "bubblewrap" {
        errors.push("local_app records require bubblewrap containment on Linux".into());
    }
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
            let (declared, gaps) = crate::sandbox::declared_controls(os, tier);
            for gap in gaps {
                let present = if gap.starts_with("readable toolchain roots and caches") {
                    record.gaps.iter().any(|g| {
                        g.starts_with(
                            "readable toolchain roots and caches (may contain private content): ",
                        )
                    })
                } else {
                    record.gaps.contains(&gap)
                };
                if !present {
                    errors.push(format!("does not list the required gap '{gap}'"));
                }
            }
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
    if run.join(crate::runmeta::FILE).exists() {
        if let Err(error) = crate::runmeta::read(run) {
            errors.push(format!("invalid run metadata: {error}"));
        }
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
    if record.test_from.is_none() {
        if let (Some(target), Some(test)) = (&record.target, &record.test) {
            let rel = test.replace('\\', "/");
            if Path::new(&rel).is_absolute()
                || rel.contains(':')
                || rel.split('/').any(|p| p == "..")
            {
                errors.push("test must be relative to the recorded target".into());
            } else if Path::new(target).exists() {
                let digest = crate::sha256::digest_file(&Path::new(target).join(rel));
                if digest.ok().as_ref() != record.test_sha256.as_ref()
                    || record.test_sha256.is_none()
                {
                    errors.push(
                        "target test changed or is unreadable; does not match test_sha256".into(),
                    );
                }
            }
        }
    }
    if crate::sha256::digest(record.output.as_bytes()) != record.output_sha256 {
        errors.push("redacted output does not match output_sha256".into());
    }
    let config = run
        .join(DIR)
        .join(record.n.to_string())
        .join("mxc-config.json");
    match crate::platform::read_bounded(&config, 2 << 20) {
        Ok(bytes) if crate::sha256::digest(&bytes) == record.config_sha256 => {
            match std::str::from_utf8(&bytes)
                .map_err(|e| e.to_string())
                .and_then(crate::shape::strict_json)
            {
                Ok(config) => match recorded_command(run, record) {
                    Ok(command) => errors.extend(config_evidence(record, &config, &command)),
                    Err(e) => errors.push(e),
                },
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

fn config_evidence(record: &ProofRecord, config: &serde_json::Value, command: &str) -> Vec<String> {
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
    let wrapped = crate::sandbox::wrapped_command_at(
        os,
        command,
        &record.marker_nonce,
        record.test.as_deref(),
        record.system_root.as_deref().unwrap_or(r"C:\Windows"),
    );
    if config
        .pointer("/process/commandLine")
        .and_then(|v| v.as_str())
        != Some(&wrapped)
        || crate::sha256::digest(wrapped.as_bytes()) != record.wrapped_command_sha256
    {
        errors.push("MXC config commandLine is not the wrapped record.command".into());
    }
    if !(1..=u64::from(u32::MAX)).contains(&record.timeout_ms)
        || config.pointer("/process/timeout").and_then(|v| v.as_u64())
            != Some(crate::sandbox::executor_timeout_ms(os, record.timeout_ms))
    {
        errors.push(
            "MXC config timeout must match the platform timeout policy for finite record.timeout_ms"
                .into(),
        );
    }
    if os == "windows"
        && !record
            .enforced
            .contains(&format!("wall_clock={}ms", record.timeout_ms))
    {
        errors.push("Windows proof requires the recorded finite supervisor wall clock".into());
    }
    let norm = |p: &str| {
        let p = if os == "windows" {
            crate::platform::mxc_path(Path::new(p))
        } else {
            p.to_string()
        };
        let p = p.replace('\\', "/");
        if os == "windows" {
            p.to_ascii_lowercase()
        } else {
            p
        }
    };
    // Keep the original config intact when a run is moved. Every grant must
    // still be relative to the same canonical proofs/<n> anchor in its cwd.
    let cwd = config
        .pointer("/process/cwd")
        .and_then(|v| v.as_str())
        .map(norm)
        .unwrap_or_default();
    let recorded_dir = norm(&record.proof_dir);
    let suffix = format!("/proofs/{}/workspace", record.n);
    let absolute = if os == "windows" {
        cwd.starts_with("//")
            || (cwd.as_bytes().get(1) == Some(&b':') && cwd.as_bytes().get(2) == Some(&b'/'))
    } else {
        cwd.starts_with('/')
    };
    if !absolute
        || cwd != format!("{recorded_dir}/workspace")
        || !cwd.ends_with(&suffix)
        || cwd.split('/').any(|p| p == "." || p == "..")
    {
        errors.push("MXC config cwd must be this proof's proofs/<n>/workspace".into());
    }
    let dir = recorded_dir;
    let workspace = format!("{dir}/workspace");
    let scratch = format!("{dir}/scratch");
    let allowed = format!("{dir}/markers/allowed");
    let denied = format!("{dir}/markers/denied");
    let roots: Vec<String> = record.readable_roots.iter().map(|p| norm(p)).collect();
    let static_roots: Vec<String> = crate::sandbox::toolchain_roots(os, None)
        .iter()
        .map(|p| norm(&p.to_string_lossy()))
        .collect();
    let absolute = |p: &str| {
        if os == "windows" {
            p.starts_with("//")
                || (p.as_bytes().get(1) == Some(&b':') && p.as_bytes().get(2) == Some(&b'/'))
        } else {
            p.starts_with('/')
        }
    };
    if roots.iter().any(|p| {
        !absolute(p)
            || p.split('/').any(|c| c == "." || c == "..")
            || !(static_roots.contains(p)
                || ["/.cargo/bin", "/.cargo/registry", "/.cargo/git", "/.rustup"]
                    .iter()
                    .any(|suffix| p.strip_suffix(suffix).is_some_and(|base| !base.is_empty())))
    }) || roots.iter().collect::<std::collections::HashSet<_>>().len() != roots.len()
    {
        errors.push(
            "recorded readable_roots must be static toolchains or absolute Rust cache roots".into(),
        );
    }
    let readonly = config
        .pointer("/filesystem/readonlyPaths")
        .and_then(|v| v.as_array());
    if readonly.is_none_or(|paths| {
        paths.iter().any(|p| {
            p.as_str().is_none_or(|p| {
                let p = norm(p);
                !(roots.contains(&p) || os == "macos" && p == allowed)
            })
        })
    }) {
        errors.push("MXC config readonlyPaths must be limited to toolchain roots and this proof's allowed marker".into());
    }
    if os == "macos"
        && readonly.is_none_or(|paths| {
            !paths
                .iter()
                .any(|p| p.as_str().map(norm).as_ref() == Some(&allowed))
        })
    {
        errors.push("MXC config readonlyPaths must include this proof's allowed marker".into());
    }
    let denied_paths = config
        .pointer("/filesystem/deniedPaths")
        .and_then(|v| v.as_array());
    let expected_denied = if os == "macos" { vec![denied] } else { vec![] };
    if denied_paths.is_none_or(|paths| {
        paths
            .iter()
            .map(|p| p.as_str().map(norm))
            .collect::<Option<Vec<_>>>()
            .as_ref()
            != Some(&expected_denied)
    }) {
        errors.push("MXC config deniedPaths must match this proof's denied marker policy".into());
    }
    let path_at = |suffix: &str| {
        let separator = if os == "windows" { "\\" } else { "/" };
        PathBuf::from(format!(
            "{}{separator}{}",
            record.proof_dir,
            suffix.replace('/', separator)
        ))
    };
    let cargo_bin = record
        .readable_roots
        .iter()
        .find(|p| norm(p).ends_with("/.cargo/bin"));
    let rust = cargo_bin.map(|bin| crate::sandbox::RustHomes {
        bin: PathBuf::from(bin),
        cargo_home: path_at("scratch/cargo-home"),
        rustup_home: record
            .readable_roots
            .iter()
            .find(|p| norm(p).ends_with("/.rustup"))
            .map(PathBuf::from),
    });
    let allowed_path = path_at("markers/allowed");
    let expected = crate::sandbox::mxc_config_at(
        &crate::sandbox::ConfigInput {
            os,
            contract: record
                .contract
                .expect_marker()
                .map(|m| (m, record.marker_nonce.as_str())),
            containment: &record.containment,
            command: &wrapped,
            timeout_ms: record.timeout_ms,
            workspace: &path_at("workspace"),
            scratch: &path_at("scratch"),
            allowed_marker: (os == "macos").then_some(allowed_path.as_path()),
            readonly: record.readable_roots.iter().map(PathBuf::from).collect(),
            denied: if os == "macos" {
                vec![path_at("markers/denied")]
            } else {
                vec![]
            },
            rust,
            list_parents: config.pointer("/processContainer/filesystem").is_some(),
        },
        record.system_root.as_deref().unwrap_or(r"C:\Windows"),
    );
    if config.pointer("/process/env") != expected.pointer("/process/env") {
        errors.push("MXC config process.env must match full allowlisted KEY=value entries reconstructed from the record".into());
    }
    if config != &expected {
        errors
            .push("MXC config has unknown keys or values outside the closed runner schema".into());
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
                    .any(|p| p.as_str().map(norm).as_ref() == Some(*want))
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
/// Links are hashed as links, never followed into outside content. All .git
/// content is included because config and hooks can change execution.
pub fn tree_digest(root: &Path) -> std::io::Result<String> {
    fn field(h: &mut crate::sha256::Sha256, bytes: &[u8]) {
        h.update(&(bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    fn walk(root: &Path, dir: &Path, h: &mut crate::sha256::Sha256) -> std::io::Result<()> {
        let mut entries = std::fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            crate::supervise::check_interrupted()?;
            let path = entry.path();
            let rel = path.strip_prefix(root).map_err(std::io::Error::other)?;
            let meta = std::fs::symlink_metadata(&path)?;
            if crate::platform::contentless(&meta) {
                continue;
            }
            field(h, rel.as_os_str().as_encoded_bytes());
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
                    return Err(std::io::Error::other(format!("unsupported target file type at {}; only regular files, directories and symlinks are supported", path.display())));
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
    // Repository metadata is source input, not private proof evidence. Git can
    // create normally shared read ACLs on Windows. Keep bounded no-follow reads
    // without requiring those source files to have the run store's private ACL.
    let source_text = |dir: &Path, relative: &Path, limit| {
        crate::platform::read_bounded_in(dir, relative, limit)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
    };
    let mut git = target.join(".git");
    if git.is_file() {
        let text = source_text(target, Path::new(".git"), 1 << 20)?;
        let p = PathBuf::from(text.trim().strip_prefix("gitdir:")?.trim());
        git = if p.is_absolute() { p } else { target.join(p) };
    }
    let head = source_text(&git, Path::new("HEAD"), 1 << 20)?;
    let head = head.trim();
    let Some(reference) = head.strip_prefix("ref:").map(str::trim) else {
        return is_hex40(head).then(|| head.to_string());
    };
    if reference.contains("..") {
        return None;
    }
    // Linked worktrees keep branch refs in the common dir.
    let common = source_text(&git, Path::new("commondir"), 1 << 20)
        .map(|c| git.join(c.trim()))
        .unwrap_or_else(|| git.clone());
    for dir in [&git, &common] {
        if let Some(v) = source_text(dir, Path::new(reference), 1 << 20) {
            let v = v.trim();
            if is_hex40(v) {
                return Some(v.to_string());
            }
        }
        if let Some(packed) = source_text(dir, Path::new("packed-refs"), 16 << 20) {
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
/// credential flag values, assignments and PEM private key bodies.
/// Proof runs use dummy secrets, so this is a backstop.
pub fn redact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_pem = false;
    for line in text.split_inclusive('\n') {
        let mut lower = line.to_owned();
        lower.make_ascii_lowercase();
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
    let line = redact_url_userinfo(line, lower);
    let mut lower = line.to_owned();
    lower.make_ascii_lowercase();
    let line_end = line.trim_end_matches(['\r', '\n']).len();
    // Split each name once, without allocating per keyword or component.
    let sensitive = |name: &str| {
        let mut previous: &[u8] = b"";
        for component in name.as_bytes().split(|b| matches!(b, b'-' | b'_')) {
            if matches!(
                component,
                b"pass"
                    | b"pwd"
                    | b"passcode"
                    | b"auth"
                    | b"credentials"
                    | b"credential"
                    | b"password"
                    | b"passwd"
                    | b"secret"
                    | b"token"
                    | b"apikey"
                    | b"authorization"
                    | b"cookie"
                    | b"passphrase"
                    | b"session"
            ) || component == b"key" && matches!(previous, b"api" | b"private" | b"access")
            {
                return true;
            }
            previous = component;
        }
        false
    };
    let mut masks = Vec::new();
    let mut quotes = QuoteCursor::default();
    let mut i = 0;
    while i < lower.len() {
        let name_byte = |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'_';
        if !name_byte(lower.as_bytes()[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < lower.len() && name_byte(lower.as_bytes()[i]) {
            i += 1;
        }
        let name = &lower[start..i];
        if !sensitive(name) {
            continue;
        }
        let flag = name.starts_with('-');
        let mut separator = i;
        if matches!(lower.as_bytes().get(separator), Some(b'\'' | b'"')) {
            separator += 1;
        }
        let spaced = lower
            .as_bytes()
            .get(separator)
            .is_some_and(|b| b.is_ascii_whitespace() || *b == 0x0b);
        while lower
            .as_bytes()
            .get(separator)
            .is_some_and(|b| b.is_ascii_whitespace() || *b == 0x0b)
        {
            separator += 1;
        }
        let assigned = lower.as_bytes().get(separator) == Some(&b'=')
            || lower.as_bytes().get(separator) == Some(&b':')
                && lower.as_bytes().get(separator + 1) != Some(&b':')
                && (flag || name != "pass");
        if !(assigned || flag && spaced && !name.starts_with("--no-")) {
            continue;
        }
        let value = separator + usize::from(assigned);
        if flag {
            let mut value = value;
            while !assigned
                && lower
                    .as_bytes()
                    .get(value)
                    .is_some_and(|b| b.is_ascii_whitespace() || *b == 0x0b)
            {
                value += 1;
            }
            if lower[value..].starts_with("[omgs redacted]") {
                i = value + "[omgs redacted]".len();
                continue;
            }
            if !assigned && lower[value..].starts_with("--") {
                continue;
            }
            let (end, replacement) = value_mask(&line, value, line_end, quotes.at(&line, value));
            if end > value {
                masks.push((value, end, replacement));
                i = end;
            }
        } else {
            // Headers and assignments may contain whitespace within the secret.
            masks.push((value, line_end, " [omgs redacted]"));
            break;
        }
    }
    let keyword_masks = masks;
    let mut masks = Vec::new();
    let mut quotes = QuoteCursor::default();
    let mut masked_until = 0;
    for (at, _) in lower.match_indices("bearer") {
        let mut start = at + "bearer".len();
        if !line
            .as_bytes()
            .get(start)
            .is_some_and(|b| b.is_ascii_whitespace() || *b == 0x0b)
        {
            continue;
        }
        while line
            .as_bytes()
            .get(start)
            .is_some_and(|b| b.is_ascii_whitespace() || *b == 0x0b)
        {
            start += 1;
        }
        if start < masked_until {
            continue;
        }
        if !lower[start..].starts_with("[omgs redacted]") {
            let (end, replacement) = value_mask(&line, start, line_end, quotes.at(&line, start));
            masked_until = end;
            masks.push((start, end, replacement));
        }
    }
    // Both scans produce ordered, nonoverlapping masks. Merge in linear time.
    let mut keywords = keyword_masks.into_iter().peekable();
    let mut bearers = masks.into_iter().peekable();
    let masks = std::iter::from_fn(|| {
        if bearers.peek().is_none()
            || keywords
                .peek()
                .is_some_and(|k| k.0 <= bearers.peek().unwrap().0)
        {
            keywords.next()
        } else {
            bearers.next()
        }
    });
    let mut out = String::with_capacity(line.len());
    let mut from = 0;
    for (start, end, replacement) in masks {
        if start < from || end <= start {
            continue;
        }
        out.push_str(&line[from..start]);
        out.push_str(replacement);
        from = end;
    }
    out.push_str(&line[from..]);
    out
}

/// Copy URL spans forward instead of shifting and lowercasing the entire line
/// for every credential URL. Authority scans stop at the next slash, so nested
/// scheme markers also consume only a bounded number of passes over each byte.
fn redact_url_userinfo(line: &str, lower: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut from = 0;
    let mut copied = 0;
    while let Some(i) = lower[from..].find("://").map(|i| i + from + 3) {
        let end = lower[i..]
            .find(|c: char| c == '/' || c.is_whitespace() || c == '"' || c == '\'')
            .map(|e| e + i)
            .unwrap_or(lower.len());
        if let Some(at) = lower[i..end].rfind('@').map(|a| a + i) {
            if lower[i..at].contains(':') {
                out.push_str(&line[copied..i]);
                out.push_str("[omgs redacted]");
                copied = at;
            }
        }
        from = i;
    }
    out.push_str(&line[copied..]);
    out
}

/// One shell token, preserving a quote opened before the value.
fn value_mask(
    line: &str,
    start: usize,
    line_end: usize,
    mut quote: Option<char>,
) -> (usize, &'static str) {
    let replacement = match quote {
        Some('\'') => "[omgs redacted]'",
        Some('"') => "[omgs redacted]\"",
        _ => "[omgs redacted]",
    };
    // The line ending is a hard limit even inside an unclosed quote, so a
    // masked value never swallows the next line.
    let end = line_end.max(start);
    let mut escaped = false;
    for (offset, c) in line[start..end].char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' && quote != Some('\'') {
            escaped = true;
        } else if quote == Some(c) {
            quote = None;
        } else if quote.is_none() {
            if c == '\'' || c == '"' {
                quote = Some(c);
            } else if c == ' ' || c == '\t' || ";&|()<>".contains(c) {
                // Only shell delimiters end an argument; other Unicode
                // whitespace stays inside it and inside the mask.
                return (start + offset, replacement);
            }
        }
    }
    (end, replacement)
}

/// Carry shell quote state forward; each prefix is consumed only once.
#[derive(Default)]
struct QuoteCursor {
    pos: usize,
    quote: Option<char>,
    escaped: bool,
}

impl QuoteCursor {
    fn at(&mut self, line: &str, at: usize) -> Option<char> {
        for c in line[self.pos..at].chars() {
            if self.escaped {
                self.escaped = false;
            } else if c == '\\' && self.quote != Some('\'') {
                self.escaped = true;
            } else if self.quote == Some(c) {
                self.quote = None;
            } else if self.quote.is_none() && matches!(c, '\'' | '"') {
                self.quote = Some(c);
            }
        }
        self.pos = at;
        self.quote
    }
}

/// Stable CLI contract: success 0, supported assertion 1, harness/execution error 2.
pub fn outer_exit(record: &ProofRecord) -> u8 {
    if !record.clean() {
        2
    } else if record.assertion_failure() {
        1
    } else if record.exit_code == Some(0) {
        0
    } else {
        2
    }
}
/// Replays cannot replace originals or cross finding, command, snapshot or tier.
pub fn reproduces(original: &ProofRecord, replay: &ProofRecord) -> bool {
    original.replays.is_none()
        && replay.replays == Some(original.n)
        && original.finding == replay.finding
        && original.finding.is_some()
        && original.command_sha256 == replay.command_sha256
        && original.command == replay.command
        && original.target == replay.target
        && original.test == replay.test
        && original.timeout_ms == replay.timeout_ms
        && original.target_head == replay.target_head
        && original.target_sha256 == replay.target_sha256
        && original.test_sha256 == replay.test_sha256
        && original.tier == replay.tier
        && original.exit_code == replay.exit_code
        && original.contract == replay.contract
        && original.clean()
        && replay.clean()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adjacent_bearer_values_are_redacted_idempotently() {
        for line in [
            "Bearer bearer TOP_SECRET",
            "Bearer bearer bearer TOP_SECRET",
        ] {
            let masked = redact(line);
            assert!(!masked.contains("TOP_SECRET"), "{masked}");
            assert_eq!(redact(&masked), masked);
        }
    }

    #[test]
    fn multiline_commands_name_their_tests() {
        for sep in ["\n", "\r", "\r\n"] {
            assert!(command_names(
                &format!("sh tests/check.sh{sep}exit 1"),
                "tests/check.sh"
            ));
            assert!(!command_names(
                &format!(r#"sh "tests/check.sh{sep}suffix""#),
                "tests/check.sh"
            ));
        }
    }

    #[test]
    fn long_credential_lines_have_bounded_redaction_time() {
        let line = "tool \"--password=hidden value\" Bearer secret ".repeat(30_000);
        let started = std::time::Instant::now();
        let masked = redact(&line);
        let elapsed = started.elapsed();
        eprintln!("redact {} bytes: {elapsed:?}", line.len());
        assert!(elapsed < std::time::Duration::from_secs(2), "{elapsed:?}");
        assert!(!masked.contains("hidden") && !masked.contains("secret"));
        assert_eq!(redact(&masked), masked);
        // Exact output, so over-redaction cannot make this pass quickly.
        let unit = redact("tool \"--password=hidden value\" Bearer secret ");
        assert!(
            unit.starts_with("tool \"--password=") && unit.contains("Bearer"),
            "{unit}"
        );
        assert_eq!(masked, unit.repeat(30_000));
    }

    #[test]
    fn generated_credentials_are_masked_idempotently() {
        for name in [
            "password",
            "api_key",
            "access-key",
            "client_secret",
            "token",
        ] {
            for separator in ["=", " ", "\t"] {
                for value in [
                    "SENSITIVE_VALUE",
                    "'SENSITIVE_VALUE more'",
                    "\"SENSITIVE_VALUE é\"",
                ] {
                    for prefix in ["", "é ", "visible; "] {
                        let input = format!("{prefix}--{name}{separator}{value} --verbose");
                        let masked = redact(&input);
                        assert!(!masked.contains("SENSITIVE_VALUE"), "{input}: {masked}");
                        assert!(masked.ends_with(" --verbose"), "{input}: {masked}");
                        assert_eq!(redact(&masked), masked, "{input}");
                    }
                }
            }
        }
        for count in 1..32 {
            for unit in [
                "https://user:SENSITIVE_VALUE@host/path ",
                "scheme://user:SENSITIVE_VALUE@host://next/path ",
                "Bearer\x0bSENSITIVE_VALUE ",
                "\"--token=SENSITIVE_VALUE more\" ",
            ] {
                let input = unit.repeat(count);
                let masked = redact(&input);
                assert!(!masked.contains("SENSITIVE_VALUE"), "{input}: {masked}");
                assert_eq!(redact(&masked), masked, "{input}");
            }
        }
    }

    #[test]
    fn long_url_and_line_ending_runs_have_bounded_redaction_time() {
        let started = std::time::Instant::now();
        for line in [
            "https://user:URL_VALUE@host/path ".repeat(10_000),
            format!(
                "{}{}",
                "Bearer BEARER_VALUE ".repeat(10_000),
                "\r".repeat(100_000)
            ),
            format!(
                "{}{}",
                "--token=FLAG_VALUE ".repeat(10_000),
                "\r".repeat(100_000)
            ),
        ] {
            let masked = redact(&line);
            assert!(!masked.contains("_VALUE"));
            assert_eq!(redact(&masked), masked);
        }
        let elapsed = started.elapsed();
        // Exact outputs, so over-redaction cannot make the timing pass.
        let url = redact("https://user:URL_VALUE@host/path ");
        assert!(url.contains("@host/path "), "{url}");
        assert_eq!(
            redact(&"https://user:URL_VALUE@host/path ".repeat(10_000)),
            url.repeat(10_000)
        );
        for unit in ["Bearer BEARER_VALUE ", "--token=FLAG_VALUE "] {
            let one = redact(unit);
            assert!(one.starts_with(&unit[..6]), "{one}");
            let line = format!("{}{}", unit.repeat(10_000), "\r".repeat(100_000));
            assert_eq!(
                redact(&line),
                format!("{}{}", one.repeat(10_000), "\r".repeat(100_000))
            );
        }
        eprintln!("redact hostile URLs and trailing CR runs: {elapsed:?}");
        assert!(elapsed < std::time::Duration::from_secs(2), "{elapsed:?}");
    }

    #[test]
    fn unicode_whitespace_stays_in_unquoted_test_arguments() {
        for sep in ['\u{a0}', '\u{2003}'] {
            let test = format!("tests/a{sep}b.sh");
            assert!(command_names(&format!("sh {test}"), &test));
            assert!(!command_names(
                &format!("sh prefix{sep}tests/check.sh"),
                "tests/check.sh"
            ));
            assert!(!command_names(
                &format!("sh tests/check.sh{sep}suffix"),
                "tests/check.sh"
            ));
        }
    }

    #[test]
    fn credential_values_end_only_at_shell_delimiters_or_the_line_end() {
        for sep in ['\u{a0}', '\u{2003}', '\r'] {
            let line = format!("--password=public{sep}SECRET_SUFFIX --verbose\n");
            let r = redact(&line);
            assert!(!r.contains("SECRET_SUFFIX"), "{sep:?}: {r}");
            assert!(r.contains("--verbose"), "{sep:?}: {r}");
            assert_eq!(redact(&r), r);
        }
        let r = redact("it's --token abc\nnext line\n");
        assert!(!r.contains("abc"), "{r}");
        assert!(r.contains("\nnext line\n"), "{r}");
        let r = redact("--token \"abc def\nnext\n");
        assert!(!r.contains("abc"), "{r}");
        assert!(r.ends_with("\nnext\n"), "{r}");
    }

    #[test]
    fn quoted_credential_tokens_mask_the_entire_value() {
        for value in [
            "\"--password=public SECRET_SUFFIX\"",
            "'--password=public SECRET_SUFFIX'",
            "\"--password\" \"public SECRET_SUFFIX\"",
            "'--password' 'public SECRET_SUFFIX'",
            "\"--password public SECRET_SUFFIX\"",
            "'--password public SECRET_SUFFIX'",
            "\"--password=public SECRET_SUFFIX\"tail",
            "--password='public SECRET_SUFFIX'",
            "--password=\"public SECRET_SUFFIX\"",
        ] {
            let command = format!("sh proof.sh {value} --verbose following");
            let masked = redact(&command);
            assert!(
                !masked.contains("public") && !masked.contains("SECRET_SUFFIX"),
                "{masked}"
            );
            assert!(masked.ends_with(" --verbose following"), "{masked}");
            assert_eq!(redact(&masked), masked, "{command}");
        }
    }

    #[test]
    fn namespaces_and_go_pass_output_are_not_credentials() {
        for line in [
            "auth::tests token::x session::y",
            "--- PASS: TestX (0.00s)",
            "pass: TestX passed",
            "bypass: fine",
        ] {
            assert_eq!(redact(line), line);
        }
        for line in [
            "pass=hidden",
            "--pass hidden",
            "--pass:hidden",
            "token: hidden",
        ] {
            assert!(!redact(line).contains("hidden"), "{line}");
        }
    }

    #[test]
    fn quoted_bearer_values_keep_following_arguments_and_idempotence() {
        for line in [
            "tool \"Bearer hidden secret\" following",
            "tool 'Bearer hidden secret' following",
        ] {
            let masked = redact(line);
            assert!(
                !masked.contains("hidden") && !masked.contains("secret"),
                "{masked}"
            );
            assert!(masked.ends_with(" following"), "{masked}");
            assert_eq!(redact(&masked), masked);
        }
    }

    #[test]
    fn bearer_accepts_ascii_whitespace_and_skips_it_before_masking() {
        for separator in ["  ", "\t", " \t ", "\x0b", "\x0c"] {
            for line in [
                format!("curl Bearer{separator}secret following"),
                format!("tool 'bEaReR{separator}secret hidden' following"),
            ] {
                let masked = redact(&line);
                assert!(
                    !masked.contains("secret") && !masked.contains("hidden"),
                    "{masked}"
                );
                assert!(masked.ends_with(" following"), "{masked}");
                assert_eq!(redact(&masked), masked);
            }
        }
        assert_eq!(redact("Bearerish visible"), "Bearerish visible");
    }

    #[test]
    fn redaction_covers_cookie_sessions_and_credential_suffixes() {
        for line in [
            "aws_secret_access_key = very-secret",
            "Cookie: sessionid=private",
            "passphrase: private",
            "access_key=private",
            "session_id: private",
            "TOKEN_VALUE=private",
            "credentials: private",
            "tool --token private",
            "tool --password private",
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
    fn credential_flag_components_are_redacted() {
        for flag in [
            "-access-token",
            "-client_secret",
            "\"--access-token\"",
            "'--client_secret'",
            "--access-token",
            "--secret-key",
            "--client_secret",
            "--my-password-value",
            "--api-key",
            "--api_key",
            "--service-api-key",
        ] {
            for separator in [" ", "="] {
                let text = format!("tool {flag}{separator}hidden-credential");
                let masked = redact(&text);
                assert!(!masked.contains("hidden-credential"), "{text}: {masked}");
                assert!(masked.contains("[omgs redacted]"), "{masked}");
            }
        }
        assert_eq!(
            redact("tool --tokenizer value -p visible"),
            "tool --tokenizer value -p visible"
        );
    }

    #[test]
    fn redaction_preserves_flag_suffixes_and_is_idempotent() {
        for line in [
            "--pass=v",
            "--pwd=v",
            "PASS=v",
            "MY_PWD=v",
            "passcode: v",
            "--auth=v",
        ] {
            let masked = redact(line);
            assert!(!masked.contains('v'), "{line}: {masked}");
            assert!(masked.contains("[omgs redacted]"), "{masked}");
            assert_eq!(redact(&masked), masked);
        }
        for line in [
            "jest --no-session tests/x.test.ts",
            "tool --passage value --author writer --passwordless yes -pVALUE tests/x.ts",
            "PASSAGE=v AUTHOR=v PASSWORDLESS=v",
            "jest --auth= tests/x.ts",
        ] {
            assert_eq!(redact(line), line);
        }
        for line in [
            "jest --session-timeout 30 tests/x.ts",
            "jest --token hidden tests/x.ts",
            "jest --auth=hidden tests/x.ts",
            "jest --auth=--hidden tests/x.ts",
            "jest --no-session=hidden tests/x.ts",
            "jest --pass 'hidden credential' tests/x.ts",
            "jest \"--pwd\"=\"hidden credential\" tests/x.ts",
            "jest --token hidden --pwd hidden tests/x.ts\n",
            "jest --auth hidden; echo tests/x.ts",
        ] {
            let masked = redact(line);
            assert!(masked.contains("tests/x.ts"), "{line}: {masked}");
            assert!(!masked.contains("hidden"), "{line}: {masked}");
            assert_eq!(redact(&masked), masked, "{line}");
        }
    }

    #[test]
    fn shell_operators_bound_test_tokens_unless_quoted() {
        for command in [
            "sh tests/check.sh; exit 1",
            "sh tests/check.sh&&exit 1",
            "sh tests/check.sh||exit 1",
            "sh tests/check.sh|cat",
            "sh tests/check.sh&wait",
            "(tests/check.sh)",
            "cat<tests/check.sh",
            "cat>tests/check.sh",
        ] {
            assert!(command_names(command, "tests/check.sh"), "{command}");
        }
        assert!(command_names(
            "sh 'tests/a;b&c(d)<e>.sh'",
            "tests/a;b&c(d)<e>.sh"
        ));
        assert!(!command_names(
            "echo 'tests/check.sh; exit 1'",
            "tests/check.sh"
        ));
    }

    #[test]
    fn tree_digest_includes_dirty_changes_and_git_behavior() {
        let d = crate::platform::temp_root()
            .unwrap()
            .join(format!("omgs-digest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("nested/.git/hooks")).unwrap();
        for name in ["a", "nested/.git/config", "nested/.git/hooks/pre-commit"] {
            std::fs::write(d.join(name), b"one").unwrap();
        }
        let first = tree_digest(&d).unwrap();
        for name in ["a", "nested/.git/config", "nested/.git/hooks/pre-commit"] {
            std::fs::write(d.join(name), b"two").unwrap();
            assert_ne!(tree_digest(&d).unwrap(), first, "{name}");
            std::fs::write(d.join(name), b"one").unwrap();
            assert_eq!(tree_digest(&d).unwrap(), first, "{name}");
        }
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
        let run = crate::platform::temp_root()
            .unwrap()
            .join(format!("omgs-proof-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&run);
        let (a, _) = reserve(&run).unwrap();
        let (b, _) = reserve(&run).unwrap();
        assert_eq!((a, b), (1, 2));
        assert!(load(&run, "../x.json").is_err());
        assert!(load(&run, "proofs/../../etc.json").is_err());
        let _ = std::fs::remove_dir_all(&run);
    }
}
