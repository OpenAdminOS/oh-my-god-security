//! Committed base policy and deterministic proof gate. No worktree policy reads.
use crate::model::{Severity, Verdict};
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
    pub gate_tests: Vec<GateTest>,
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
    pub expires_unix: u64,
}

/// Owner-reviewed executable contract. Commands execute only inside MXC.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateTest {
    pub id: String,
    pub test: String,
    pub command: String,
    pub expect_marker: String,
    pub severity: Severity,
    pub timeout_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}
pub const MAX_EXPIRY: u64 = 253_402_300_799; // Last second of year 9999.
pub const MAX_SUPPRESSION_SECONDS: u64 = 365 * 24 * 60 * 60;

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
            gate_tests: vec![],
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
        "gate_tests",
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
    for key in ["accepted_intent", "suppressions", "gate_tests"] {
        if !object[key]
            .as_array()
            .is_some_and(|a| a.iter().all(|v| v.is_object()))
        {
            return Err(format!("{key} must contain objects"));
        }
    }
    for suppression in object["suppressions"].as_array().unwrap() {
        if !suppression
            .get("expires_unix")
            .and_then(|v| v.as_u64())
            .is_some_and(|expiry| expiry <= MAX_EXPIRY)
        {
            return Err(
                "expires_unix is required and must be UTC Unix seconds through year 9999".into(),
            );
        }
    }
    for test in object["gate_tests"].as_array().unwrap() {
        if !test.get("severity").is_some_and(|v| v.is_string())
            || test.get("fingerprint").is_some_and(|v| !v.is_string())
        {
            return Err("gate test severity and optional fingerprint must be strings".into());
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
    let mut ids = std::collections::BTreeSet::new();
    let mut tests = std::collections::BTreeSet::new();
    for t in &p.gate_tests {
        if !nonempty(&t.id)
            || !relative(&t.test)
            || t.test.contains(['\'', '"'])
            || !crate::proof::valid_expect_marker(&t.expect_marker)
            || !crate::proof::command_names(&t.command, &t.test)
            || t.fingerprint
                .as_ref()
                .is_some_and(|f| !crate::model::is_fingerprint(f))
            || !ids.insert(&t.id)
            || !tests.insert(&t.test)
        {
            return Err("invalid or duplicate gate test contract".into());
        }
        crate::sandbox::validate_input(&t.command, t.timeout_ms)?;
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
    use std::process::Command;
    let target = std::fs::canonicalize(target).map_err(|e| e.to_string())?;
    let git_dir = target.join(".git");
    let meta = std::fs::symlink_metadata(&git_dir).map_err(|e| e.to_string())?;
    if !meta.is_dir()
        || crate::platform::is_link(&meta)
        || std::fs::symlink_metadata(git_dir.join("commondir")).is_ok()
    {
        return Err("redirected git directories are blocked; use a standalone checkout".into());
    }
    // Read without following links or opening special files. Reject every include
    // section before Git can open an included FIFO, device or external config.
    for name in ["config", "config.worktree"] {
        let config_path = std::path::PathBuf::from(".git").join(name);
        if name == "config.worktree"
            && std::fs::symlink_metadata(target.join(&config_path)).is_err()
        {
            continue;
        }
        let config = crate::platform::read_bounded_in(&target, &config_path, MAX_BYTES)
            .map_err(|e| format!("git config: {e}"))?;
        let config = std::str::from_utf8(&config).map_err(|e| e.to_string())?;
        for line in config.lines() {
            let compact: String = line
                .chars()
                .filter(|c| !c.is_whitespace())
                .flat_map(char::to_lowercase)
                .collect();
            if compact
                .trim_start_matches('\u{feff}')
                .starts_with("[include")
            {
                return Err("git config includes are blocked".into());
            }
        }
    }
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
        .arg(format!("--git-dir={}", crate::platform::mxc_path(&git_dir)))
        .arg(format!(
            "--work-tree={}",
            crate::platform::mxc_path(&target)
        ))
        .current_dir(&target)
        .args(args);
    let result = crate::supervise::run(
        c,
        &crate::supervise::Limits {
            wall_ms: 3_000,
            cpu_secs: None,
            file_size_bytes: None,
            open_files: None,
            memory_bytes: None,
            tasks: None,
            output_cap_bytes: 64 << 20,
        },
        None,
    );
    if result.timed_out || !result.cleanup_complete || !result.capture_complete {
        return Err("git object read deadline, output limit or child cleanup failure".into());
    }
    if !result.success {
        return Err(format!(
            "git {} failed; objects must be locally available",
            args[0]
        ));
    }
    Ok(result.stdout_bytes)
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
            // Anchor expiry to the commit that last changed policy, not the base
            // commit, so unrelated later commits cannot extend a suppression.
            let stamp = git(
                target,
                &[
                    "log",
                    "--no-show-signature",
                    "--no-use-mailmap",
                    "-1",
                    "--format=%ct",
                    commit,
                    "--",
                    PATH,
                ],
            )?;
            let stamp: u64 = std::str::from_utf8(&stamp)
                .map_err(|e| e.to_string())?
                .trim()
                .parse()
                .map_err(|_| "invalid policy commit timestamp")?;
            if stamp > MAX_EXPIRY
                || policy
                    .suppressions
                    .iter()
                    .any(|s| s.expires_unix > stamp.saturating_add(MAX_SUPPRESSION_SECONDS))
            {
                return Err("suppression expiry exceeds 365 days from the policy commit".into());
            }
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

/// CLI-owned provenance, stored beside the reviewer's answers, outside the run.
/// The canonical run path selects the record, never an editable metadata id.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedPolicy {
    pub target: String,
    pub run: String,
    pub generation: String,
    pub directory_identity: (u64, u64),
    pub base_commit: Option<String>,
    pub sha256: String,
    /// CLI settings are retained only when the base has no policy blob.
    pub no_base_policy: Option<Policy>,
}

impl TrustedPolicy {
    pub fn new(
        target: &Path,
        run: &Path,
        generation: &str,
        snapshot: &Snapshot,
    ) -> Result<Self, String> {
        let base = load_base(target, snapshot.base_commit.as_deref())?;
        Ok(Self {
            target: target.to_string_lossy().into(),
            run: run.to_string_lossy().into(),
            generation: generation.into(),
            directory_identity: crate::platform::directory_identity(run)
                .map_err(|e| e.to_string())?,
            base_commit: base.base_commit,
            sha256: base.sha256,
            no_base_policy: base.original.is_none().then(|| snapshot.policy.clone()),
        })
    }
}

/// Policy authenticated by a reviewer-owned record and re-read from Git.
/// Construction is private so patch generators cannot receive a raw snapshot.
pub struct AuthenticatedPolicy(Snapshot);
impl AuthenticatedPolicy {
    pub fn snapshot(&self) -> &Snapshot {
        &self.0
    }
    pub fn into_snapshot(self) -> Snapshot {
        self.0
    }
}

/// Metadata is compared for diagnostics only. Neither its commit, digest nor
/// embedded policy is used to select or reconstruct the baseline.
pub fn committed_snapshot(
    run: &Path,
    target: &Path,
    trusted: &TrustedPolicy,
) -> Result<AuthenticatedPolicy, String> {
    let run = std::fs::canonicalize(run).map_err(|e| e.to_string())?;
    let target = std::fs::canonicalize(target).map_err(|e| e.to_string())?;
    if run.starts_with(&target) {
        return Err("run must live outside target".into());
    }
    if Path::new(&trusted.target) != target || Path::new(&trusted.run) != run {
        return Err("trusted policy record belongs to another target or run".into());
    }
    let generation = crate::run_artifact::read(
        &run,
        Path::new(".omgs-claim"),
        crate::run_artifact::CLAIM_BYTES,
    )
    .map_err(|e| {
        format!("run generation unavailable: {e}; re-initialize into a new output path")
    })?;
    if trusted.generation.len() != 64
        || !trusted.generation.bytes().all(|b| b.is_ascii_hexdigit())
        || generation != trusted.generation.as_bytes()
        || crate::platform::directory_identity(&run).map_err(|e| e.to_string())?
            != trusted.directory_identity
    {
        return Err("trusted policy run generation or directory identity mismatch; re-initialize into a new output path".into());
    }
    if trusted.base_commit.as_deref().is_some_and(|b| !oid(b)) {
        return Err("trusted base must be a full immutable commit SHA".into());
    }
    let mut base = load_base(&target, trusted.base_commit.as_deref())
        .map_err(|e| format!("cannot read committed base policy: {e}"))?;
    if base.base_commit != trusted.base_commit || base.sha256 != trusted.sha256 {
        return Err("committed base policy differs from trusted record".into());
    }
    match (&base.original, &trusted.no_base_policy) {
        (None, Some(settings)) => {
            // Validate settings using the same strict policy parser as init.
            base.policy = parse(&text(settings)?)?;
            base.sha256 = crate::sha256::digest(text(&base.policy)?.as_bytes());
        }
        (Some(_), None) => {}
        _ => return Err("trusted policy settings do not match base policy presence".into()),
    }
    let meta = crate::runmeta::read(&run)?;
    if meta.get("policy") != Some(&serde_json::to_value(&base).map_err(|e| e.to_string())?) {
        eprintln!("warning: run policy snapshot differs from trusted record; ignoring snapshot");
    }
    Ok(AuthenticatedPolicy(base))
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

/// Temporary gate data is independent of advisory run storage and always removed.
struct GateDir(std::path::PathBuf);
impl Drop for GateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn oid(s: &str) -> bool {
    [40, 64].contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Export only immutable committed regular files. No checkout hooks, filters,
/// local modifications, untracked files or run artifacts participate.
fn export_head(
    target: &Path,
    head: &str,
    out: &Path,
) -> Result<std::collections::BTreeSet<String>, String> {
    let mut paths = std::collections::BTreeSet::new();
    let mut folded = std::collections::BTreeSet::new();
    let tree = git(target, &["ls-tree", "-rz", head])?;
    for entry in tree.split(|b| *b == 0).filter(|e| !e.is_empty()) {
        let tab = entry
            .iter()
            .position(|b| *b == b'\t')
            .ok_or("invalid tree entry")?;
        let header = std::str::from_utf8(&entry[..tab]).map_err(|e| e.to_string())?;
        let fields: Vec<_> = header.split_whitespace().collect();
        let path = std::str::from_utf8(&entry[tab + 1..]).map_err(|e| e.to_string())?;
        if fields.len() != 3
            || !["100644", "100755"].contains(&fields[0])
            || fields[1] != "blob"
            || !oid(fields[2])
            || !relative(path)
            || path.split('/').any(|p| {
                let stem = p.split('.').next().unwrap_or("").to_ascii_uppercase();
                p.eq_ignore_ascii_case(".git")
                    || p.ends_with(['.', ' '])
                    || (cfg!(windows)
                        && (p.contains(['<', '>', '"', '|', '?', '*'])
                            || [
                                "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5",
                                "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4",
                                "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
                            ]
                            .contains(&stem.as_str())))
            })
        {
            return Err(format!(
                "blocked head tree entry: {path}; gate requires regular files"
            ));
        }
        if !folded.insert(path.to_lowercase()) {
            return Err("case-colliding head paths are blocked".into());
        }
        paths.insert(path.to_string());
        let bytes = git(target, &["cat-file", "blob", fields[2]])?;
        let file = out.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).map_err(|e| e.to_string())?;
        std::fs::write(&file, bytes).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &file,
                std::fs::Permissions::from_mode(if fields[0] == "100755" { 0o755 } else { 0o644 }),
            )
            .map_err(|e| e.to_string())?;
        }
    }
    Ok(paths)
}

pub fn gate(target: &Path, base: &str, head: &str, run: Option<&Path>) -> Result<u8, String> {
    if !oid(base) || !oid(head) {
        return Err("gate requires full immutable --base and --head SHAs".into());
    }
    let s = load_base(target, Some(base))?;
    // Once advisory is established by valid base policy, even infrastructure
    // errors are display-only. Invalid policy cannot establish advisory mode.
    let outcome = gate_tests(target, base, head, &s.policy);
    if let Some(run) = run {
        advisory_findings(run, &s.policy);
    }
    match outcome {
        Ok(blocked) => Ok(u8::from(blocked && s.policy.mode == Mode::Gate)),
        Err(e) if s.policy.mode == Mode::Advisory => {
            println!("advisory: would block (infrastructure): {e}");
            Ok(0)
        }
        Err(e) => Err(e),
    }
}
fn gate_tests(target: &Path, base: &str, head: &str, p: &Policy) -> Result<bool, String> {
    let actual = git(target, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    if std::str::from_utf8(&actual)
        .map_err(|e| e.to_string())?
        .trim()
        != head
    {
        return Err("checkout does not match --head".into());
    }
    let tests: Vec<_> = p
        .gate_tests
        .iter()
        .filter(|t| rank(t.severity) >= rank(p.severity_threshold))
        .filter(|t| {
            !p.suppressions.iter().any(|s| {
                (t.fingerprint.as_deref() == Some(&s.fingerprint) || t.id == s.fingerprint)
                    && crate::runmeta::now_unix() < s.expires_unix
            })
        })
        .collect();
    if tests.is_empty() {
        println!("{}: no active registered gate tests", p.mode.label());
        return Ok(false);
    }
    // Inspect all active registrations before export or sandbox setup can fail.
    let blobs = |commit: &str| -> Result<std::collections::BTreeMap<Vec<u8>, Vec<u8>>, String> {
        let tree = git(target, &["ls-tree", "-rz", commit])?;
        tree.split(|b| *b == 0)
            .filter(|e| !e.is_empty())
            .map(|entry| {
                let tab = entry
                    .iter()
                    .position(|b| *b == b'\t')
                    .ok_or("invalid tree entry")?;
                let blob = entry[..tab]
                    .split(|b| *b == b' ')
                    .nth(2)
                    .ok_or("invalid tree entry")?;
                Ok((entry[tab + 1..].to_vec(), blob.to_vec()))
            })
            .collect()
    };
    let before = blobs(base)?;
    let after = blobs(head)?;
    for t in &tests {
        if before.get(t.test.as_bytes()) != after.get(t.test.as_bytes()) {
            println!(
                "WARNING: registered gate test modified in head: {} {}",
                t.id, t.test
            );
        }
    }
    let path = crate::platform::scratch_root()
        .map_err(|e| e.to_string())?
        .join(format!(
            "omgs-gate-{}",
            crate::platform::random_nonce().map_err(|e| e.to_string())?
        ));
    crate::platform::create_private_dir_new(&path).map_err(|e| e.to_string())?;
    let dir = GateDir(path);
    let checkout = dir.0.join("head");
    std::fs::create_dir(&checkout).map_err(|e| e.to_string())?;
    let paths = export_head(target, head, &checkout)?;
    let mut blocked = false;
    for (n, t) in tests.iter().enumerate() {
        if !paths.contains(&t.test) {
            return Err(format!("registered test missing from head: {}", t.test));
        }
        let result = crate::sandbox::prove(&crate::sandbox::ProveRequest {
            expect_marker: Some(t.expect_marker.clone()),
            command: t.command.clone(),
            test: Some(t.test.clone()),
            timeout_ms: t.timeout_ms,
            target: Some(checkout.clone()),
            run_dir: dir.0.join(format!("proof-{n}")),
            tier: crate::sandbox::Tier::Test,
            stage: None,
            expected_tree_sha256: None,
        });
        let r = match result {
            crate::sandbox::ProveOutcome::Blocked { reason } => {
                return Err(format!("{}: {reason}", t.id))
            }
            crate::sandbox::ProveOutcome::Ran(r) => r,
        };
        let r = &r.run;
        if !r.command_started
            || !r.command_finished
            || r.test_reachable != Some(true)
            || r.timed_out
            || r.killed
            || r.interrupted
            || r.executor_error
            || !r.capture_complete
            || !r.cleanup_complete
            || !r.survivors.is_empty()
        {
            return Err(format!("{}: blocked or unclean gate execution", t.id));
        }
        match r.exit_code {
            Some(0) => println!("passes {}", t.id),
            Some(1) if r.boundary_marker_seen && r.authorized_control_seen => {
                blocked = true;
                println!(
                    "{} {}",
                    if p.mode == Mode::Advisory {
                        "would block"
                    } else {
                        "blocks"
                    },
                    t.id
                );
            }
            _ => return Err(format!("{}: test failed outside its recipe contract", t.id)),
        }
    }
    std::fs::remove_dir_all(&dir.0).map_err(|e| format!("gate scratch cleanup failed: {e}"))?;
    Ok(blocked)
}
fn advisory_findings(run: &Path, p: &Policy) {
    let display = || -> Result<(), String> {
        let bytes = crate::run_artifact::read(
            run,
            Path::new("findings.json"),
            crate::run_artifact::FINDINGS_BYTES,
        )
        .map_err(|e| e.to_string())?;
        let f = crate::shape::findings(std::str::from_utf8(&bytes).map_err(|e| e.to_string())?)?;
        for f in f
            .findings
            .iter()
            .filter(|f| f.verdict == Verdict::Confirmed)
        {
            if !p
                .gate_tests
                .iter()
                .any(|t| t.fingerprint.as_deref() == Some(&f.fingerprint))
            {
                println!(
                    "advisory: confirmed finding {} is not yet a registered gate test",
                    f.fingerprint
                );
            }
        }
        Ok(())
    };
    if let Err(e) = display() {
        println!(
            "advisory run unavailable: {}",
            crate::platform::escape_controls(&e)
        );
    }
}

/// Whole-file unified diff so no untrusted diff driver is ever invoked.
pub fn propose(
    run: &Path,
    answers: &crate::intent::Answers,
    policy: &AuthenticatedPolicy,
) -> Result<std::path::PathBuf, String> {
    let file = match crate::run_artifact::optional_text(
        run,
        Path::new("findings.json"),
        crate::run_artifact::FINDINGS_BYTES,
    )? {
        Some(text) => crate::shape::findings(&text)?,
        None => crate::model::FindingsFile::default(),
    };
    let staged = crate::handoff::stage_validated(run, &file)?;
    for reason in &staged.excluded {
        eprintln!("{reason}");
    }
    propose_staged(run, answers, &staged, policy)
}

/// Use the same admitted records and exact test patch as the staging export.
pub fn propose_staged(
    run: &Path,
    answers: &crate::intent::Answers,
    staged: &crate::handoff::StagedTests,
    policy: &AuthenticatedPolicy,
) -> Result<std::path::PathBuf, String> {
    let s = policy.snapshot();
    let mut p = s.policy.clone();
    propose_tests(run, &mut p, &staged.admitted)?;
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
    let old = s.original.as_deref().unwrap_or_default();
    let mut diff = file_patch(PATH, old, &new);
    diff.push_str(&staged.patch);
    let path = run.join("policy.patch");
    crate::runmeta::write_atomic(&path, &diff)?;
    Ok(path)
}

fn propose_tests(
    run: &Path,
    p: &mut Policy,
    file: &crate::model::FindingsFile,
) -> Result<(), String> {
    for f in file
        .findings
        .iter()
        .filter(|f| f.verdict == Verdict::Confirmed)
    {
        let record = crate::proof::load(
            run,
            f.proof_ref
                .as_deref()
                .ok_or("confirmed finding requires proof")?,
        )?;
        if record.tier != "test" {
            continue;
        }
        let Some(marker) = record.contract.expect_marker() else {
            continue;
        };
        let test = record
            .test
            .as_deref()
            .ok_or("gate proposal requires test path")?;
        let command = crate::proof::recorded_command(run, &record)?;
        if let Some(old) = p
            .gate_tests
            .iter()
            .find(|t| t.test == test || t.id == f.fingerprint)
        {
            println!("already registered: {}", old.id);
            continue;
        }
        p.gate_tests.push(GateTest {
            id: f.fingerprint.clone(),
            test: test.into(),
            command,
            expect_marker: marker.into(),
            severity: f.severity.ok_or("confirmed finding requires severity")?,
            timeout_ms: record.timeout_ms,
            fingerprint: Some(f.fingerprint.clone()),
        });
    }
    p.gate_tests.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(())
}
fn file_patch(path: &str, old: &str, new: &str) -> String {
    if old == new {
        return String::new();
    }
    let mut diff = format!("diff --git a/{path} b/{path}\n");
    if old.is_empty() {
        diff.push_str("new file mode 100644\n");
    }
    diff.push_str(&format!(
        "--- {}\n+++ b/{path}\n@@ -{},{} +1,{} @@\n",
        if old.is_empty() {
            "/dev/null".into()
        } else {
            format!("a/{path}")
        },
        usize::from(!old.is_empty()),
        old.split_inclusive('\n').count(),
        new.split_inclusive('\n').count()
    ));
    for (prefix, text) in [("-", old), ("+", new)] {
        for line in text.split_inclusive('\n') {
            diff.push_str(prefix);
            diff.push_str(line);
            if !line.ends_with('\n') {
                diff.push_str("\n\\ No newline at end of file\n");
            }
        }
    }
    diff
}
