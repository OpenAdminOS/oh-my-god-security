//! Proof execution under Microsoft MXC, the only sandbox backend. OMGS writes
//! a deny-by-default MXC 1.0.0 config, runs the SHA-256 pinned executor for
//! this OS under `supervise::run`, and reports exactly what was enforced.
//! Target code never runs anywhere else: without a verified executor OMGS
//! refuses and the finding stays at the tier it already earned.

use crate::{platform, sha256, supervise};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The MXC release the executors below are pinned to.
pub const MXC_VERSION: &str = "1.0.1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Executor {
    pub file: &'static str,
    pub sha256: &'static str,
    /// MXC `containment` value for this executor.
    pub containment: &'static str,
}

/// The pinned executor for an OS and architecture, or why there is none.
pub fn executor_for(os: &str, arch: &str) -> Result<Executor, String> {
    let e = |file, sha256, containment| {
        Ok(Executor {
            file,
            sha256,
            containment,
        })
    };
    match (os, arch) {
        ("macos", "aarch64") => e(
            "mxc-exec-mac",
            "c54390e48a25187fdae10758c6a286bede49416cb610c88c6705fd8445e97f60",
            "seatbelt",
        ),
        ("macos", _) => Err("MXC ships its macOS executor for Apple Silicon only, so omgs prove cannot run target code on this Intel Mac. Findings stay at the traced tier; run proofs on an Apple Silicon Mac, Linux or Windows 11.".into()),
        ("linux", "aarch64") => e(
            "lxc-exec",
            "e8391d55c566ce95c6c838d349941fa0797f037fa617aa0fa4ec39443c6ccddf",
            "bubblewrap",
        ),
        ("linux", "x86_64") => e(
            "lxc-exec",
            "5bd6bdf45bc6c0ecc9bccf372762b571de1f468142c4b2ff80fdb4c540922f26",
            "bubblewrap",
        ),
        ("windows", "aarch64") => e(
            "wxc-exec.exe",
            "91aa4171e8809f33f19622c381116188eab7d8c8cffad231230a31b58146ee77",
            "process",
        ),
        ("windows", "x86_64") => e(
            "wxc-exec.exe",
            "090f5d1f7bb93104ab08dcd4e8034ef954aeefcdaf6658dde5f7dff4cfc12f3a",
            "process",
        ),
        _ => Err(format!(
            "MXC has no executor for {os} {arch}, so omgs prove cannot run target code here."
        )),
    }
}

/// Every executor OMGS pins, across platforms.
pub fn pinned_executors() -> Vec<Executor> {
    [
        ("macos", "aarch64"),
        ("linux", "aarch64"),
        ("linux", "x86_64"),
        ("windows", "aarch64"),
        ("windows", "x86_64"),
    ]
    .into_iter()
    .filter_map(|(os, arch)| executor_for(os, arch).ok())
    .collect()
}

pub fn this_executor() -> Result<Executor, String> {
    executor_for(std::env::consts::OS, std::env::consts::ARCH)
}

/// Where OMGS installs the executor: `<data dir>/mxc/<version>/<file>`.
pub fn install_path(exec: &Executor) -> Option<PathBuf> {
    platform::data_dir().map(|d| d.join("mxc").join(MXC_VERSION).join(exec.file))
}

#[derive(Debug, Clone)]
pub struct Located {
    pub path: PathBuf,
    pub executor: Executor,
}

/// Find the executor (`OMGS_MXC_EXEC`, then the OMGS install path, then PATH)
/// and accept it only when its SHA-256 matches the pin. A mismatch is never
/// skipped over silently: it is named in the error.
pub fn locate_executor() -> Result<Located, String> {
    let executor = this_executor()?;
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = std::env::var_os("OMGS_MXC_EXEC").filter(|v| !v.is_empty()) {
        candidates.push(PathBuf::from(p));
    }
    candidates.extend(install_path(&executor));
    candidates.extend(platform::which(executor.file));
    let mut problems = Vec::new();
    for path in candidates {
        if !path.is_file() {
            continue;
        }
        match sha256::digest_file(&path) {
            Ok(d) if d == executor.sha256 => return Ok(Located { path, executor }),
            Ok(d) => problems.push(format!(
                "{} has SHA-256 {d}, expected {} for MXC {MXC_VERSION}",
                path.display(),
                executor.sha256
            )),
            Err(e) => problems.push(format!("{} unreadable: {e}", path.display())),
        }
    }
    let wanted = install_path(&executor)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| executor.file.to_string());
    if problems.is_empty() {
        Err(format!(
            "MXC {MXC_VERSION} executor {} not found. Install it with the OMGS installer (it places the pinned, Microsoft-signed executor at {wanted}) or set OMGS_MXC_EXEC. Run omgs doctor for details.",
            executor.file
        ))
    } else {
        Err(format!(
            "no MXC executor matched the pinned digest, refusing to run: {}",
            problems.join("; ")
        ))
    }
}

/// Tier 1 runs a test; tier 2 runs a locally built app and its client
/// together. Both use the same network policy: external network and host
/// loopback denied. Tier 2 needs a loopback private to the sandbox, which
/// only Linux provides (its own network namespace), so it runs only there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Test,
    LocalApp,
}

pub struct ProveRequest {
    pub command: String,
    pub timeout_ms: u64,
    /// Copied into the per-run workspace, which becomes the cwd. The original
    /// is not mounted into the sandbox at all.
    pub target: Option<PathBuf>,
    /// Per-proof directory: holds workspace, scratch, markers and the config.
    pub run_dir: PathBuf,
    pub tier: Tier,
    /// A draft test kept outside the target, copied into the workspace at
    /// the given target-relative path before the command runs.
    pub stage: Option<(PathBuf, String)>,
}

pub struct ProveResult {
    pub executor: PathBuf,
    pub executor_sha256: String,
    pub containment: String,
    pub config_sha256: String,
    pub enforced: Vec<String>,
    pub gaps: Vec<String>,
    pub run: supervise::Supervised,
}

pub enum ProveOutcome {
    Blocked { reason: String },
    Ran(Box<ProveResult>),
}

fn mxc_path(p: &Path) -> String {
    let s = p.to_string_lossy().to_string();
    // Windows canonicalize yields extended-length paths that cmd.exe rejects
    // as a working directory. Strip the prefix for config consumption.
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        s
    }
}

/// Every parent directory of a Windows or Unix path string, outermost first,
/// with a bare drive written as its root (`C:` becomes `C:\`).
fn parent_dirs(p: &str) -> Vec<String> {
    p.char_indices()
        .filter(|(_, c)| *c == '\\' || *c == '/')
        .map(|(i, _)| &p[..i])
        .filter(|a| !a.is_empty())
        .map(|a| {
            if a.ends_with(':') {
                format!("{a}\\")
            } else {
                a.to_string()
            }
        })
        .collect()
}

/// Toolchain roots made readable inside the sandbox when they exist. System
/// directories are already readable under every MXC backend.
fn toolchain_roots(os: &str, home: Option<&Path>) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = match os {
        "macos" => vec![
            "/Applications/Xcode.app".into(),
            "/Library/Developer/CommandLineTools".into(),
            "/opt/homebrew".into(),
            "/usr/local/bin".into(),
            "/usr/local/lib".into(),
            "/usr/local/microsoft".into(),
        ],
        "linux" => vec!["/opt".into(), "/usr/local".into()],
        "windows" => vec![
            r"C:\Program Files\PowerShell\7".into(),
            r"C:\Program Files\nodejs".into(),
            r"C:\Program Files\Git".into(),
        ],
        _ => vec![],
    };
    // Only the parts of ~/.cargo a build needs: tools and the crate caches.
    // ~/.cargo itself holds config.toml and credentials, which stay unreadable;
    // cargo gets a fresh CARGO_HOME in scratch that links to the caches.
    if let Some(h) = home {
        for sub in RUST_CACHES.iter().chain(["bin"].iter()) {
            roots.push(h.join(".cargo").join(sub));
        }
        roots.push(h.join(".rustup"));
    }
    roots
}

const RUST_CACHES: [&str; 2] = ["registry", "git"];

/// Rust locations for the sandboxed environment.
pub struct RustHomes {
    /// The real `~/.cargo/bin`, put first on PATH.
    pub bin: PathBuf,
    /// A per-run CARGO_HOME in scratch, linking to the readable caches.
    pub cargo_home: PathBuf,
    pub rustup_home: Option<PathBuf>,
}

/// Link `link` to the directory `to`: a symlink on Unix, a junction on
/// Windows (which needs no privilege).
fn link_dir(to: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(to, link)
    }
    #[cfg(windows)]
    {
        let ok = Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(link)
            .arg(to)
            .stdout(std::process::Stdio::null())
            .status()?
            .success();
        if ok {
            Ok(())
        } else {
            Err(std::io::Error::other("mklink /J failed"))
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (to, link);
        Err(std::io::Error::other("directory links unsupported"))
    }
}

/// Everything that varies per run, kept separate from probing the host so
/// the config is testable.
pub struct ConfigInput<'a> {
    pub os: &'a str,
    pub containment: &'a str,
    pub command: &'a str,
    pub timeout_ms: u64,
    pub workspace: &'a Path,
    pub scratch: &'a Path,
    pub allowed_marker: Option<&'a Path>,
    pub readonly: Vec<PathBuf>,
    pub denied: Vec<PathBuf>,
    pub rust: Option<RustHomes>,
}

pub fn mxc_config(input: &ConfigInput) -> serde_json::Value {
    let scratch = mxc_path(input.scratch);
    let mut env: Vec<String> = if input.os == "windows" {
        vec![
            format!(
                "SYSTEMROOT={}",
                std::env::var("SYSTEMROOT").unwrap_or_else(|_| "C:\\Windows".into())
            ),
            format!("USERPROFILE={scratch}"),
            format!("LOCALAPPDATA={scratch}"),
            format!("TEMP={scratch}"),
            format!("TMP={scratch}"),
            "PATH=C:\\Windows\\System32;C:\\Windows;C:\\Program Files\\PowerShell\\7;C:\\Program Files\\nodejs;C:\\Program Files\\Git\\cmd".into(),
        ]
    } else {
        let mut path = if input.os == "macos" {
            "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".to_string()
        } else {
            "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".to_string()
        };
        if let Some(r) = &input.rust {
            path = format!("{}:{path}", r.bin.display());
        }
        vec![
            format!("HOME={scratch}"),
            format!("TMPDIR={scratch}/"),
            format!("XDG_CACHE_HOME={scratch}/cache"),
            format!("CLANG_MODULE_CACHE_PATH={scratch}/clang-cache"),
            format!("PATH={path}"),
            "LANG=C.UTF-8".into(),
        ]
    };
    if let Some(r) = &input.rust {
        if input.os == "windows" {
            if let Some(p) = env.iter_mut().find(|e| e.starts_with("PATH=")) {
                *p = format!("PATH={};{}", mxc_path(&r.bin), &p[5..]);
            }
        }
        env.push(format!("CARGO_HOME={}", mxc_path(&r.cargo_home)));
        env.push("CARGO_NET_OFFLINE=true".into());
        if let Some(rh) = &r.rustup_home {
            env.push(format!("RUSTUP_HOME={}", mxc_path(rh)));
        }
    }
    let mut readonly: Vec<String> = input.readonly.iter().map(|p| mxc_path(p)).collect();
    if let Some(m) = input.allowed_marker {
        readonly.push(mxc_path(m));
    }
    let mut config = serde_json::json!({
        "version": "1.0.0",
        "containment": input.containment,
        "process": {
            "commandLine": input.command,
            "cwd": mxc_path(input.workspace),
            "timeout": input.timeout_ms,
            "env": env
        },
        "network": {
            "egress": { "default": "deny" },
            "ingress": { "default": "deny", "hostLoopback": "deny" }
        },
        "filesystem": {
            "readwritePaths": [mxc_path(input.workspace), scratch],
            "readonlyPaths": readonly,
            "deniedPaths": input.denied.iter().map(|p| mxc_path(p)).collect::<Vec<_>>()
        }
    });
    match input.os {
        "windows" => {
            // Windows console hosts such as pwsh fail DLL init when Win32k is
            // fully blocked. Allow the UI subsystem, never input or clipboard.
            config["ui"] =
                serde_json::json!({ "disable": false, "injection": false, "clipboard": "none" });
            // Runtimes such as Node resolve real paths by listing every parent
            // directory from the drive root, which the container denies.
            // Grant listing (not reading) of exactly those parents.
            let mut enumerate: Vec<String> = Vec::new();
            let granted = [mxc_path(input.workspace), scratch.clone()];
            for p in granted.iter().chain(readonly.iter()) {
                for a in parent_dirs(p) {
                    if !enumerate.contains(&a) {
                        enumerate.push(a);
                    }
                }
            }
            config["processContainer"] = serde_json::json!({
                "ui": { "isolation": "desktop" },
                "filesystem": { "enumeratePaths": enumerate }
            });
        }
        "macos" => {
            // User and group lookups (getpwuid) go through opendirectoryd;
            // pwsh and several toolchains fail without it.
            config["seatbelt"] = serde_json::json!({
                "extraMachLookups": ["com.apple.system.opendirectoryd.libinfo"]
            });
        }
        _ => {}
    }
    config
}

/// Controls this config enforces, and what it leaves open, in report wording.
pub fn declared_controls(os: &str, tier: Tier) -> (Vec<String>, Vec<String>) {
    let mut enforced = vec![
        format!("mxc {MXC_VERSION} deny-by-default filesystem"),
        "target copied to a per-run workspace; the original is not mounted".to_string(),
        "external network egress denied".to_string(),
        "environment cleared to an allowlist with scratch home, temp and cache".to_string(),
    ];
    let mut gaps = Vec::new();
    enforced.push("inbound network and host loopback denied".into());
    if tier == Tier::LocalApp {
        enforced.push(
            "loopback private to the sandbox network namespace; host services unreachable".into(),
        );
    }
    if os == "windows" {
        gaps.push("process tree owned by the MXC ProcessContainer; no per-process CPU, file size or open file limits on Windows".into());
    }
    (enforced, gaps)
}

/// What the supervisor adds around MXC on this OS, for `omgs doctor`. Each
/// proof record lists what was actually applied on that run.
pub fn declared_limits(os: &str) -> Vec<String> {
    let mut v = vec!["wall clock limit; the whole process tree is killed on expiry".to_string()];
    if os != "windows" {
        v.push("CPU time, file size and open file limits".into());
        v.push("process group signalled before the leader is reaped".into());
    }
    match os {
        "macos" => v.push("survivor sweep: sandboxed processes that left the group are found and killed, and the run fails".into()),
        "linux" => v.push("memory and task limits through a systemd user scope when one is available".into()),
        _ => {}
    }
    v
}

/// Copy `src` into the empty directory `dst`: an APFS clone on macOS, a
/// reflink where the filesystem supports it on Linux, a plain copy otherwise.
pub fn copy_tree(src: &Path, dst: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dst).map_err(|e| format!("create {}: {e}", dst.display()))?;
    let from = format!("{}/.", src.display());
    let attempts: Vec<Vec<&str>> = if cfg!(target_os = "macos") {
        vec![vec!["-c", "-R", "-p"], vec!["-R", "-p"]]
    } else if cfg!(target_os = "linux") {
        vec![vec!["-a", "--reflink=auto"]]
    } else {
        vec![]
    };
    for flags in attempts {
        let ok = Command::new(if cfg!(target_os = "macos") {
            "/bin/cp"
        } else {
            "cp"
        })
        .args(&flags)
        .arg(&from)
        .arg(dst)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
        if ok {
            return Ok(());
        }
        // A partial clone must not be mixed with the next attempt.
        let _ = std::fs::remove_dir_all(dst);
        std::fs::create_dir_all(dst).map_err(|e| e.to_string())?;
    }
    copy_recursive(src, dst)
}

fn copy_recursive(src: &Path, dst: &Path) -> Result<(), String> {
    for entry in std::fs::read_dir(src).map_err(|e| format!("read {}: {e}", src.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let ty = entry.file_type().map_err(|e| e.to_string())?;
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            std::fs::create_dir_all(&to).map_err(|e| e.to_string())?;
            copy_recursive(&entry.path(), &to)?;
        } else if ty.is_file() {
            std::fs::copy(entry.path(), &to)
                .map_err(|e| format!("copy {}: {e}", entry.path().display()))?;
        }
        // Symlinks are skipped on the fallback path rather than followed out
        // of the target tree.
    }
    Ok(())
}

/// Why tier 2 cannot run on this OS, if it cannot.
pub fn tier2_unavailable(os: &str) -> Option<String> {
    (os != "linux").then(|| {
        format!(
            "tier 2 runs only on Linux: on {os} the sandbox shares the host loopback, so a local app under test could reach or be reached by services on this machine. Run tier 2 on Linux or in a Linux VM; tier 1 proofs work here."
        )
    })
}

/// A readable root that contains, or is contained in, the run directory.
fn overlapping_root<'a>(run_dir: &Path, readonly: &'a [PathBuf]) -> Option<&'a PathBuf> {
    readonly
        .iter()
        .find(|r| run_dir.starts_with(r) || r.starts_with(run_dir))
}

pub fn prove(req: &ProveRequest) -> ProveOutcome {
    if req.tier == Tier::LocalApp {
        if let Some(reason) = tier2_unavailable(std::env::consts::OS) {
            return ProveOutcome::Blocked { reason };
        }
    }
    let located = match locate_executor() {
        Ok(l) => l,
        Err(reason) => return ProveOutcome::Blocked { reason },
    };
    let os = std::env::consts::OS;
    let blocked = |reason: String| ProveOutcome::Blocked { reason };
    if let Err(e) = std::fs::create_dir_all(&req.run_dir) {
        return blocked(format!("cannot create {}: {e}", req.run_dir.display()));
    }
    // MXC and Seatbelt match canonical paths, so resolve symlinks like /tmp.
    let run_dir = std::fs::canonicalize(&req.run_dir).unwrap_or_else(|_| req.run_dir.clone());
    let workspace = run_dir.join("workspace");
    let scratch = run_dir.join("scratch");
    if workspace.exists() || scratch.exists() {
        return blocked(format!(
            "{} already holds a proof run; use a fresh directory",
            run_dir.display()
        ));
    }
    if let Some(target) = &req.target {
        let target = std::fs::canonicalize(target).unwrap_or_else(|_| target.clone());
        if !target.is_dir() {
            return blocked(format!("target {} is not a directory", target.display()));
        }
        if run_dir.starts_with(&target) {
            return blocked("the proof directory must be outside the target tree".into());
        }
        if let Err(e) = copy_tree(&target, &workspace) {
            return blocked(format!("could not copy the target into the workspace: {e}"));
        }
    } else if let Err(e) = std::fs::create_dir_all(&workspace) {
        return blocked(e.to_string());
    }
    if let Some((draft, rel)) = &req.stage {
        let dest = workspace.join(rel);
        let staged = dest
            .parent()
            .map(std::fs::create_dir_all)
            .unwrap_or(Ok(()))
            .and_then(|_| std::fs::copy(draft, &dest).map(|_| ()));
        if let Err(e) = staged {
            return blocked(format!("cannot stage the draft test at {rel}: {e}"));
        }
    }
    for d in [
        scratch.clone(),
        scratch.join("cache"),
        scratch.join("clang-cache"),
    ] {
        if let Err(e) = std::fs::create_dir_all(&d) {
            return blocked(format!("cannot create {}: {e}", d.display()));
        }
    }

    let home = platform::home();
    let readonly: Vec<PathBuf> = toolchain_roots(os, home.as_deref())
        .into_iter()
        .filter(|p| p.exists())
        .collect();
    // A run directory under a readable root would make the workspace, the
    // config and both sweep markers readable to every sandbox.
    if let Some(root) = overlapping_root(&run_dir, &readonly) {
        return blocked(format!(
            "the proof directory {} overlaps the readable toolchain root {}; put OMGS_HOME or --run elsewhere",
            run_dir.display(),
            root.display()
        ));
    }

    // Run a private copy verified after copying, so the file that executes is
    // the file that was hashed, not whatever later sits at the shared path.
    let exec_dir = run_dir.join("executor");
    let executor = exec_dir.join(located.executor.file);
    let copied = std::fs::create_dir_all(&exec_dir)
        .and_then(|_| std::fs::copy(&located.path, &executor).map(|_| ()));
    if let Err(e) = copied {
        return blocked(format!("cannot stage the MXC executor: {e}"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&exec_dir, std::fs::Permissions::from_mode(0o700));
        if let Err(e) = std::fs::set_permissions(&executor, std::fs::Permissions::from_mode(0o700))
        {
            return blocked(format!("cannot stage the MXC executor: {e}"));
        }
    }
    match sha256::digest_file(&executor) {
        Ok(d) if d == located.executor.sha256 => {}
        Ok(d) => {
            return blocked(format!(
                "the staged MXC executor hashed to {d}, not the pin {}; refusing to run",
                located.executor.sha256
            ))
        }
        Err(e) => return blocked(format!("cannot hash the staged MXC executor: {e}")),
    }

    let markers = if os == "macos" {
        let dir = run_dir.join("markers");
        let m = supervise::SweepMarkers {
            allowed: dir.join("allowed"),
            denied: dir.join("denied"),
        };
        let made = std::fs::create_dir_all(&dir)
            .and_then(|_| std::fs::write(&m.allowed, b"omgs"))
            .and_then(|_| std::fs::write(&m.denied, b"omgs"));
        if let Err(e) = made {
            return blocked(format!("cannot create survivor markers: {e}"));
        }
        Some(m)
    } else {
        None
    };

    // The sweep tells this run's processes apart by a read the policy allows
    // (allowed marker) next to one it denies; deny it explicitly so no
    // readable root can ever grant it.
    let denied: Vec<PathBuf> = markers.iter().map(|m| m.denied.clone()).collect();
    let rust = match home.as_ref().map(|h| h.join(".cargo")) {
        Some(cargo) if readonly.contains(&cargo.join("bin")) => {
            let cargo_home = scratch.join("cargo-home");
            if let Err(e) = std::fs::create_dir_all(&cargo_home) {
                return blocked(format!("cannot create {}: {e}", cargo_home.display()));
            }
            for sub in RUST_CACHES {
                let real = cargo.join(sub);
                if readonly.contains(&real) {
                    if let Err(e) = link_dir(&real, &cargo_home.join(sub)) {
                        return blocked(format!("cannot link the cargo {sub} cache: {e}"));
                    }
                }
            }
            let rustup = home.as_ref().map(|h| h.join(".rustup"));
            Some(RustHomes {
                bin: cargo.join("bin"),
                cargo_home,
                rustup_home: rustup.filter(|r| readonly.contains(r)),
            })
        }
        _ => None,
    };
    let config = mxc_config(&ConfigInput {
        os,
        containment: located.executor.containment,
        command: &req.command,
        timeout_ms: req.timeout_ms,
        workspace: &workspace,
        scratch: &scratch,
        allowed_marker: markers.as_ref().map(|m| m.allowed.as_path()),
        readonly,
        denied,
        rust,
    });
    let config_text = serde_json::to_string_pretty(&config).unwrap_or_default();
    let config_path = run_dir.join("mxc-config.json");
    if let Err(e) = crate::runmeta::write_atomic_bytes(&config_path, config_text.as_bytes()) {
        return blocked(format!("failed to write MXC config: {e}"));
    }

    let mut cmd = Command::new(&executor);
    cmd.arg("--config").arg(&config_path);
    cmd.env_clear();
    if os == "windows" {
        for k in ["SYSTEMROOT", "WINDIR", "TEMP", "TMP"] {
            if let Some(v) = std::env::var_os(k) {
                cmd.env(k, v);
            }
        }
    }
    cmd.current_dir(&run_dir);
    let limits = supervise::Limits {
        // The executor enforces the config timeout itself; the supervisor
        // allows a short margin for teardown before killing it.
        wall_ms: req.timeout_ms.saturating_add(15_000),
        cpu_secs: Some(req.timeout_ms.div_ceil(1000).saturating_mul(2).max(10)),
        file_size_bytes: Some(1 << 30),
        open_files: Some(1024),
        memory_bytes: Some(4 << 30),
        tasks: Some(512),
        output_cap_bytes: 256 * 1024,
    };
    let run = supervise::run(cmd, &limits, markers.as_ref());
    let (mut enforced, mut gaps) = declared_controls(os, req.tier);
    enforced.extend(run.enforced.iter().cloned());
    gaps.extend(run.notes.iter().cloned());
    // The workspace and scratch can be large and hold build output; the
    // config stays as part of the proof evidence.
    let _ = std::fs::remove_dir_all(&workspace);
    let _ = std::fs::remove_dir_all(&scratch);
    let _ = std::fs::remove_dir_all(&exec_dir);
    if let Some(m) = &markers {
        if let Some(dir) = m.allowed.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
    ProveOutcome::Ran(Box::new(ProveResult {
        executor: located.path,
        executor_sha256: located.executor.sha256.to_string(),
        containment: located.executor.containment.to_string(),
        config_sha256: sha256::digest(config_text.as_bytes()),
        enforced,
        gaps,
        run,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_directories_inside_readable_roots_are_refused() {
        let roots = vec![PathBuf::from("/home/u/.cargo/bin"), PathBuf::from("/opt")];
        assert!(overlapping_root(Path::new("/home/u/.cargo/bin/omgs/run"), &roots).is_some());
        assert!(overlapping_root(Path::new("/opt/x"), &roots).is_some());
        assert!(overlapping_root(Path::new("/home/u"), &roots).is_some());
        assert!(overlapping_root(Path::new("/home/u/.local/share/omgs/run"), &roots).is_none());
    }

    #[test]
    fn parent_dirs_cover_windows_and_unix_paths() {
        assert_eq!(
            parent_dirs(r"C:\Users\u\run\workspace"),
            vec![r"C:\", r"C:\Users", r"C:\Users\u", r"C:\Users\u\run"]
        );
        assert_eq!(parent_dirs("/a/b/c"), vec!["/a", "/a/b"]);
    }

    #[test]
    fn every_supported_platform_has_a_pin_and_intel_mac_refuses() {
        for (os, arch, file) in [
            ("macos", "aarch64", "mxc-exec-mac"),
            ("linux", "aarch64", "lxc-exec"),
            ("linux", "x86_64", "lxc-exec"),
            ("windows", "aarch64", "wxc-exec.exe"),
            ("windows", "x86_64", "wxc-exec.exe"),
        ] {
            let e = executor_for(os, arch).expect("pinned");
            assert_eq!(e.file, file);
            assert_eq!(e.sha256.len(), 64);
        }
        let intel = executor_for("macos", "x86_64").unwrap_err();
        assert!(intel.contains("Apple Silicon"));
        assert!(executor_for("freebsd", "x86_64").is_err());
    }
}
