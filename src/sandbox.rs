//! Proof execution under Microsoft MXC, the only sandbox backend. OMGS writes
//! a deny-by-default config in MXC's 1.0.0 schema, runs the SHA-256 pinned executor for
//! this OS under `supervise::run`, and reports exactly what was enforced.
//! Target code never runs anywhere else: without a verified executor OMGS
//! refuses and the finding stays at the tier it already earned.

mod preflight;
mod sensors;
pub use preflight::{windows_build_report, windows_policy, windows_probe};
pub use sensors::{run_sensor, SensorRequest};

use crate::platform::mxc_path;
use crate::{platform, sha256, supervise};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The MXC release the executors below are pinned to.
pub const MXC_VERSION: &str = "1.0.1";
/// Run metadata sandbox text written at init, before any proof runs.
pub const REQUIRED_TEXT: &str =
    "MXC required for proofs; each proof record names the executor that ran it";

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
    if cfg!(all(target_os = "macos", target_arch = "x86_64")) && rosetta_translated() {
        return Err("this x86_64 omgs binary is running under Rosetta on Apple Silicon; install omgs-aarch64-apple-darwin to run proofs with the arm64 MXC executor".into());
    }
    executor_for(std::env::consts::OS, std::env::consts::ARCH)
}

// Host discovery must share doctor's overall deadline, including commands
// that run before the first proof is prepared.
fn host_query(program: &str, args: &[&str]) -> Option<String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_clear()
        .stdin(std::process::Stdio::null());
    let run = supervise::run(
        cmd,
        &supervise::Limits {
            wall_ms: 3000,
            cpu_secs: None,
            file_size_bytes: None,
            open_files: None,
            memory_bytes: None,
            tasks: None,
            output_cap_bytes: 4096,
        },
        None,
    );
    run.success.then_some(run.stdout)
}

fn rosetta_translated() -> bool {
    host_query("/usr/sbin/sysctl", &["-in", "sysctl.proc_translated"])
        .is_some_and(|out| out.trim() == "1")
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
    if cfg!(target_os = "macos") {
        require_macos_version(macos_major())?;
    }
    let check = |path: &Path| match sha256::digest_file(path) {
        Ok(d) if d == executor.sha256 => Ok(()),
        Ok(d) => Err(format!(
            "{} has SHA-256 {d}, expected {} for MXC {MXC_VERSION}",
            platform::describe_path(path),
            executor.sha256
        )),
        Err(e) => Err(format!("{} unreadable: {e}", platform::describe_path(path))),
    };
    // An explicit OMGS_MXC_EXEC is authoritative: if it is wrong, say so
    // rather than quietly using some other executor. It is made absolute so
    // the file that runs is the one hashed here, not a PATH search result.
    if let Some(p) = std::env::var_os("OMGS_MXC_EXEC").filter(|v| !v.is_empty()) {
        let path = std::path::absolute(PathBuf::from(p))
            .map_err(|e| format!("OMGS_MXC_EXEC is set but unusable, refusing to run: {e}"))?;
        return check(&path)
            .map(|_| Located {
                path,
                executor: executor.clone(),
            })
            .map_err(|e| format!("OMGS_MXC_EXEC is set but unusable, refusing to run: {e}"));
    }
    let mut problems = Vec::new();
    for path in install_path(&executor)
        .into_iter()
        .chain(platform::which(executor.file))
    {
        if !path.is_file() {
            continue;
        }
        match check(&path) {
            Ok(()) => return Ok(Located { path, executor }),
            Err(e) => problems.push(e),
        }
    }
    if problems.is_empty() {
        Err(format!(
            "MXC {MXC_VERSION} executor {} not found. {}",
            executor.file,
            install_hint(&executor)
        ))
    } else {
        Err(format!(
            "no MXC executor matched the pinned digest, refusing to run: {}",
            problems.join("; ")
        ))
    }
}

/// The running macOS major version, read from `sw_vers`.
fn macos_major() -> Option<u32> {
    host_query("/usr/bin/sw_vers", &["-productVersion"])?
        .trim()
        .split('.')
        .next()?
        .parse()
        .ok()
}

fn require_macos_version(major: Option<u32>) -> Result<(), String> {
    match major {
        Some(15..) => Ok(()),
        Some(major) => Err(format!("MXC needs macOS 15 or later; this Mac runs macOS {major}, so omgs prove cannot run target code here.")),
        None => Err("cannot determine the macOS version from sw_vers; refusing to run target code because MXC needs macOS 15 or later".into()),
    }
}

/// Manual install steps for the pinned executor, shown when it is missing.
pub fn install_hint(executor: &Executor) -> String {
    let member = format!(
        "{}/{}",
        if std::env::consts::ARCH == "aarch64" {
            "arm64"
        } else {
            "x64"
        },
        executor.file
    );
    let dest = install_path(executor)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| executor.file.to_string());
    format!(
        "Install it once: download mxc-release-binaries.zip from https://github.com/microsoft/mxc/releases/tag/v{MXC_VERSION} (SHA-256 {MXC_ZIP_SHA256}), extract only {member}, and place it at {dest} (its own SHA-256 must be {}). Or point OMGS_MXC_EXEC at an existing copy. Run omgs doctor to check.",
        executor.sha256
    )
}

/// SHA-256 of Microsoft's MXC release archive the executors are taken from.
pub const MXC_ZIP_SHA256: &str = "0e832239454ba7fcd338ff56218a287eef4c0a01c1484084b869f55feff8abe9";

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
    pub expect_marker: Option<String>,
    pub command: String,
    pub test: Option<String>,
    pub timeout_ms: u64,
    /// Copied into the per-run workspace, which becomes the cwd. The original
    /// is not mounted into the sandbox at all.
    pub target: Option<PathBuf>,
    /// Per-proof directory: holds workspace, scratch and the config.
    pub run_dir: PathBuf,
    pub tier: Tier,
    /// A draft test kept outside the target, copied into the workspace at
    /// the given target-relative path before the command runs.
    pub stage: Option<(PathBuf, String)>,
    pub expected_tree_sha256: Option<String>,
    pub inputs: Option<crate::proof_inputs::Selection>,
    pub expected_inputs: Option<crate::proof_inputs::Manifest>,
    pub harness: Vec<crate::proof::HarnessFile>,
    /// Offer the screenshot helper to the command and keep its PNG files.
    pub screenshots: bool,
}

pub struct ProveResult {
    pub executor: PathBuf,
    pub executor_sha256: String,
    pub containment: String,
    pub config_sha256: String,
    pub wrapped_command_sha256: String,
    pub readable_roots: Vec<String>,
    pub system_root: Option<String>,
    pub marker_nonce: String,
    pub target_sha256: Option<String>,
    pub input_manifest: Option<crate::proof_inputs::Manifest>,
    pub enforced: Vec<String>,
    pub gaps: Vec<String>,
    pub notes: Vec<String>,
    pub screenshots: Option<crate::screenshot::Screenshots>,
    pub run: supervise::Supervised,
}

pub enum ProveOutcome {
    Blocked { reason: String },
    Ran(Box<ProveResult>),
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
pub fn toolchain_roots(os: &str, home: Option<&Path>) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = match os {
        "macos" => vec![
            "/Applications/Xcode.app".into(),
            "/Library/Developer/CommandLineTools".into(),
            "/opt/homebrew/bin".into(),
            "/opt/homebrew/lib".into(),
            "/opt/homebrew/opt".into(),
            HOMEBREW_RUSTUP_BIN.into(),
            "/opt/homebrew/Cellar".into(),
            "/opt/homebrew/share".into(),
            "/opt/homebrew/include".into(),
            "/opt/homebrew/Frameworks".into(),
            "/usr/local/bin".into(),
            "/usr/local/lib".into(),
            "/usr/local/microsoft".into(),
        ],
        // MXC mounts system binaries/libraries, but not compiler headers.
        "linux" => vec!["/opt".into(), "/usr/local".into(), "/usr/include".into()],
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
pub(crate) const HOMEBREW_RUSTUP_BIN: &str = "/opt/homebrew/opt/rustup/bin";

/// Rust locations for the sandboxed environment.
pub struct RustHomes {
    /// The admitted Rust proxy directory, put first on PATH.
    pub bin: PathBuf,
    /// A per-run CARGO_HOME in scratch, linking to the readable caches.
    pub cargo_home: PathBuf,
    pub rustup_home: Option<PathBuf>,
}

/// Select only explicitly admitted Rust roots, without probing the host or
/// consulting HOME. Proof validation uses the same selection as staging.
pub(crate) fn select_rust_homes(
    os: &str,
    readonly: &[PathBuf],
    cargo_home: &Path,
) -> Option<RustHomes> {
    let bin = rust_root(os, readonly, "/.cargo/bin").or_else(|| {
        readonly
            .iter()
            .find(|p| os == "macos" && p.as_path() == Path::new(HOMEBREW_RUSTUP_BIN))
    })?;
    Some(RustHomes {
        bin: bin.clone(),
        cargo_home: cargo_home.to_path_buf(),
        rustup_home: rust_root(os, readonly, "/.rustup").cloned(),
    })
}

fn rust_root<'a>(os: &str, readonly: &'a [PathBuf], suffix: &str) -> Option<&'a PathBuf> {
    readonly.iter().find(|p| {
        let path = mxc_path(p).replace('\\', "/");
        if os == "windows" {
            path.to_ascii_lowercase().ends_with(suffix)
        } else {
            path.ends_with(suffix)
        }
    })
}

/// Link `link` to the directory `to`: a symlink on Unix, a junction on
/// Windows (which needs no privilege).
fn link_dir(to: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        create_staging_link(to, link)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
        extern "system" {
            fn DeviceIoControl(
                handle: *mut core::ffi::c_void,
                code: u32,
                input: *const u8,
                input_len: u32,
                output: *mut u8,
                output_len: u32,
                returned: *mut u32,
                overlapped: *mut core::ffi::c_void,
            ) -> i32;
        }
        let target = std::fs::canonicalize(to)?;
        let print = mxc_path(&target);
        let substitute = if let Some(unc) = print.strip_prefix(r"\\") {
            format!(r"\??\UNC\{unc}")
        } else {
            format!(r"\??\{print}")
        };
        let wide = |s: &str| std::ffi::OsStr::new(s).encode_wide().collect::<Vec<_>>();
        let (sub, print) = (wide(&substitute), wide(&print));
        let data_len = 8 + (sub.len() + print.len() + 2) * 2;
        if data_len + 8 > 16 * 1024 || sub.contains(&0) || print.contains(&0) {
            return Err(std::io::Error::other(
                "junction target is too long or contains NUL",
            ));
        }
        let mut data = Vec::with_capacity(data_len + 8);
        data.extend_from_slice(&0xa000_0003u32.to_le_bytes());
        for n in [
            data_len,
            0,
            0,
            sub.len() * 2,
            (sub.len() + 1) * 2,
            print.len() * 2,
        ] {
            data.extend_from_slice(&(n as u16).to_le_bytes());
        }
        for c in sub.into_iter().chain([0]).chain(print).chain([0]) {
            data.extend_from_slice(&c.to_le_bytes());
        }
        create_staging_dir(link)?;
        let result = (|| {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(0x0020_0000 | 0x0200_0000)
                .open(link)?;
            let mut returned = 0;
            // SAFETY: the directory handle and reparse buffer live through the call.
            let ok = unsafe {
                DeviceIoControl(
                    file.as_raw_handle(),
                    0x0009_00a4,
                    data.as_ptr(),
                    data.len() as u32,
                    std::ptr::null_mut(),
                    0,
                    &mut returned,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        })();
        if result.is_err() {
            let _ = std::fs::remove_dir(link);
        }
        result
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
    /// Declaration and nonce bound to the saved config and command.
    pub contract: Option<(&'a str, &'a str)>,
    pub os: &'a str,
    pub containment: &'a str,
    pub command: &'a str,
    pub timeout_ms: u64,
    pub workspace: &'a Path,
    pub scratch: &'a Path,
    pub readonly: Vec<PathBuf>,
    pub denied: Vec<PathBuf>,
    pub rust: Option<RustHomes>,
    /// Windows only: let the container list the parent directories of the
    /// granted paths when the MXC probe reports support for it.
    pub list_parents: bool,
    /// Screenshot helper inside scratch, exported as `OMGS_SCREENSHOT`.
    pub screenshot: Option<PathBuf>,
}

pub fn environment_keys(os: &str) -> Vec<&'static str> {
    let mut keys = if os == "windows" {
        vec![
            "SYSTEMROOT",
            "USERPROFILE",
            "LOCALAPPDATA",
            "TEMP",
            "TMP",
            "PATH",
            "PATHEXT",
        ]
    } else {
        vec![
            "HOME",
            "TMPDIR",
            "XDG_CACHE_HOME",
            "CLANG_MODULE_CACHE_PATH",
            "PATH",
            "LANG",
        ]
    };
    if os == "macos" {
        keys.push("OPENSSL_CONF");
    }
    keys.extend([
        "CARGO_HOME",
        "CARGO_NET_OFFLINE",
        "RUSTUP_HOME",
        "RUSTUP_AUTO_INSTALL",
        "OMGS_PROOF_CONTRACT",
    ]);
    keys
}

pub fn environment(
    os: &str,
    scratch: &str,
    rust: Option<&RustHomes>,
    system_root: &str,
) -> Vec<String> {
    let mut env: Vec<String> = if os == "windows" {
        vec![
            format!("SYSTEMROOT={system_root}"),
            format!("USERPROFILE={scratch}"),
            format!("LOCALAPPDATA={scratch}"),
            format!("TEMP={scratch}"),
            format!("TMP={scratch}"),
            format!("PATH={system_root}\\System32;{system_root};C:\\Program Files\\PowerShell\\7;C:\\Program Files\\nodejs;C:\\Program Files\\Git\\cmd"),
            "PATHEXT=.COM;.EXE;.BAT;.CMD".into(),
        ]
    } else {
        let mut path = if os == "macos" {
            "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".to_string()
        } else {
            "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".to_string()
        };
        if let Some(r) = rust {
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
    if os == "macos" {
        env.push(format!("OPENSSL_CONF={scratch}/openssl.cnf"));
    }
    if let Some(r) = rust {
        if os == "windows" {
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
    env.push("RUSTUP_AUTO_INSTALL=0".into());
    env
}

pub fn mxc_config(input: &ConfigInput) -> serde_json::Value {
    let system_root = std::env::var("SYSTEMROOT").unwrap_or_else(|_| r"C:\Windows".into());
    mxc_config_at(input, &system_root)
}

// Windows timeout cleanup must pass through the supervisor's Ctrl+Break path.
// MXC 1.0.1 treats zero as infinite; the finite budget is enforced by OMGS.
pub fn executor_timeout_ms(os: &str, timeout_ms: u64) -> u64 {
    if os == "windows" {
        0
    } else {
        timeout_ms
    }
}

pub fn supervisor_timeout_ms(os: &str, timeout_ms: u64) -> u64 {
    if os == "windows" {
        timeout_ms
    } else {
        timeout_ms.saturating_add(15_000)
    }
}

pub fn mxc_config_at(input: &ConfigInput, system_root: &str) -> serde_json::Value {
    let scratch = mxc_path(input.scratch);
    let mut env = environment(input.os, &scratch, input.rust.as_ref(), system_root);
    env.push(format!(
        "OMGS_PROOF_CONTRACT={}",
        input.contract.map(|(m, _)| m).unwrap_or("none")
    ));
    if let Some((_, nonce)) = input.contract {
        env.push(format!("OMGS_PROOF_NONCE={nonce}"));
    }
    if let Some(helper) = &input.screenshot {
        env.push(format!("{}={}", crate::screenshot::ENV, mxc_path(helper)));
    }
    let readonly: Vec<String> = input.readonly.iter().map(|p| mxc_path(p)).collect();
    let mut config = serde_json::json!({
        "version": "1.0.0",
        "containment": input.containment,
        "process": {
            "commandLine": input.command,
            "cwd": mxc_path(input.workspace),
            "timeout": executor_timeout_ms(input.os, input.timeout_ms),
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
            config["processContainer"] = if input.list_parents {
                serde_json::json!({
                    "ui": { "isolation": "desktop" },
                    "filesystem": { "enumeratePaths": enumerate }
                })
            } else {
                serde_json::json!({ "ui": { "isolation": "desktop" } })
            };
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
        "MXC configuration accepted by executor --dry-run before workload execution".into(),
        "environment cleared to an allowlist with scratch home, temp and cache".to_string(),
    ];
    let mut gaps = vec![
        "no total disk quota; only a 1 GiB per-file size limit on Unix, no file size limit on Windows".into(),
        "a target file hardlinked to outside content is copied as readable workspace content; git checkouts cannot create such a hardlink".into(),
    ];
    let readable: Vec<_> = toolchain_roots(os, platform::home().as_deref())
        .into_iter()
        .filter(|p| p.exists())
        .map(|p| p.display().to_string())
        .collect();
    gaps.push(format!(
        "readable toolchain roots and caches (may contain private content): {}",
        readable.join(", ")
    ));
    gaps.extend(conditional_gaps(os));
    enforced.push("inbound network and host loopback denied".into());
    if tier == Tier::LocalApp {
        enforced.push(
            "loopback private to the sandbox network namespace; host services unreachable".into(),
        );
    }
    if os == "macos" {
        enforced.extend([
            "launchd_resource_coalition".into(),
            "launchd_tcc_path_admission".into(),
        ]);
    }
    if os == "linux" {
        enforced
            .push("MXC PID namespace teardown kills descendants, including new sessions".into());
    }
    if os == "windows" {
        gaps.push("Windows expiry or interruption requests executor Ctrl+Break, waits up to 5000ms for MXC cleanup, then forces termination if needed; an owned kill-on-close job terminates descendants if OMGS dies; forced death can skip MXC ACL restoration".into());
        gaps.push("process tree owned by the MXC ProcessContainer; no per-process CPU, file size or open file limits on Windows".into());
    }
    (enforced, gaps)
}

/// The folders a Windows config lets sandboxed code list, named so the
/// proof record states exactly which directory names it could see.
pub fn listing_gap(config: &serde_json::Value) -> Option<String> {
    let paths = config
        .pointer("/processContainer/filesystem/enumeratePaths")?
        .as_array()?
        .iter()
        .filter_map(|p| p.as_str())
        .collect::<Vec<_>>();
    (!paths.is_empty()).then(|| {
        format!(
            "sandboxed code can list the names of entries directly inside these parent folders: {}",
            paths.join(", ")
        )
    })
}

pub fn conditional_gaps(os: &str) -> Vec<String> {
    let mut gaps = Vec::new();
    if os != "linux" {
        gaps.push("memory and task limits not applied: Linux cgroups required".into());
    } else {
        gaps.push("memory and task limits conditional on an available systemd user scope".into());
    }
    if os == "windows" {
        gaps.push("parent directory enumeration conditional on Windows support; directory listing and absolute path resolution may fail without it".into());
    }
    gaps
}

/// MXC's timeout is an unsigned 32-bit millisecond count; zero is unbounded.
pub fn validate_input(command: &str, timeout_ms: u64) -> Result<(), String> {
    if command.trim().is_empty() || command.contains('\0') {
        return Err("--cmd must be nonempty and contain no NUL".into());
    }
    if !(1..=u64::from(u32::MAX)).contains(&timeout_ms) {
        return Err(format!("--timeout-ms must be in 1..={}", u32::MAX));
    }
    Ok(())
}

fn wrapper_name(command: &str, nonce: &str, test: Option<&str>) -> String {
    format!(
        ".omgs-{}",
        sha256::digest(format!("{nonce}\0{command}\0{}", test.unwrap_or("")).as_bytes())
    )
}

pub fn wrapped_command(os: &str, command: &str, nonce: &str, test: Option<&str>) -> String {
    let root = std::env::var("SYSTEMROOT").unwrap_or_else(|_| r"C:\Windows".into());
    wrapped_command_at(os, command, nonce, test, &root)
}

pub fn wrapped_command_at(
    os: &str,
    command: &str,
    nonce: &str,
    test: Option<&str>,
    root: &str,
) -> String {
    if os == "windows" {
        format!(
            r#""{root}\System32\cmd.exe" /d /v:off /c {}.cmd"#,
            wrapper_name(command, nonce, test)
        )
    } else {
        let quoted = command.replace('\'', "'\"'\"'");
        let check = test.map(|t| {
            let t = t.replace('\'', "'\"'\"'");
            format!("if [ -f './{t}' ] && /bin/cat './{t}' >/dev/null 2>&1; then printf 'OMGS_TEST_{nonce}:1\\n'; else printf 'OMGS_TEST_{nonce}:0\\nOMGS_END_{nonce}:126\\n'; exit 126; fi; ")
        }).unwrap_or_default();
        format!("printf '\\nOMGS_START_{nonce}\\n'; {check}/bin/sh -c '{quoted}'; omgs_exit=$?; printf '\\nOMGS_END_{nonce}:%s\\n' \"$omgs_exit\"; exit \"$omgs_exit\"")
    }
}

fn write_wrapper(
    os: &str,
    workspace: &Path,
    command: &str,
    nonce: &str,
    test: Option<&str>,
) -> std::io::Result<()> {
    if os == "windows" {
        let name = wrapper_name(command, nonce, test);
        let root = std::env::var("SYSTEMROOT").unwrap_or_else(|_| r"C:\Windows".into());
        // Explicit exit preserves cmd's 9009 for a missing command.
        let command = format!("({}) & exit /b", command.replace('%', "%%"));
        // Denied redirection can retain exit 0; gate on the built-in running.
        let check = test.map(|t| {
            let t = t.replace('/', "\\").replace('%', "%%");
            format!("if not exist \"{t}\" goto omgs_unreachable\r\nif exist \"{t}\\\" goto omgs_unreachable\r\nset \"omgs_readable=\"\r\n(set \"omgs_readable=1\") <\"{t}\"\r\nif not defined omgs_readable goto omgs_unreachable\r\necho OMGS_TEST_{nonce}:1\r\n")
        }).unwrap_or_default();
        let wrapper = format!("@echo off\r\necho OMGS_START_{nonce}\r\n{check}\"{root}\\System32\\cmd.exe\" /d /v:off /s /c \"{command}\"\r\nset \"omgs_exit=%errorlevel%\"\r\necho(\r\necho OMGS_END_{nonce}:%omgs_exit%\r\nexit /b %omgs_exit%\r\n:omgs_unreachable\r\necho OMGS_TEST_{nonce}:0\r\necho OMGS_END_{nonce}:126\r\nexit /b 126\r\n");
        let permissions = std::fs::metadata(workspace)?.permissions();
        stage_content(
            workspace,
            &format!("{name}.cmd"),
            std::io::Cursor::new(wrapper),
            crate::proof_inputs::permissions(fixed_file_mode(), permissions),
        )?;
    }
    Ok(())
}

fn retry_without_enumeration(os: &str, run: &supervise::Supervised) -> bool {
    os == "windows"
        && !run.command_started
        && run.enumerate_rejected
        && !run.timed_out
        && !run.interrupted
        && !run.killed
        && run.capture_complete
        && run.cleanup_complete
        && run.survivors.is_empty()
}

/// What the supervisor adds around MXC on this OS, for `omgs doctor`. Each
/// proof record lists what was actually applied on that run.
pub fn declared_limits(os: &str) -> Vec<String> {
    let mut v = if os == "windows" {
        vec!["Windows expiry or interruption requests executor Ctrl+Break, waits up to 5000ms for MXC cleanup, then forces termination if needed; an owned kill-on-close job terminates descendants if OMGS dies; forced death can skip MXC ACL restoration".to_string()]
    } else {
        vec!["wall clock limit; the process group is killed on expiry".to_string()]
    };
    if os != "windows" {
        v.push("CPU time, file size and open file limits".into());
        v.push("process group signalled before the leader is reaped".into());
    }
    if os == "macos" {
        v.push("launchd resource coalition: sealed anchor task count certifies cleanup; survivors are killed and fail the run".into());
    }
    v
}

/// Materialize fresh entries in sorted order, preserving only admitted bytes,
/// link text and allow-listed permissions, never source filesystem metadata.
pub fn copy_tree(src: &Path, dst: &Path) -> Result<(), String> {
    copy_tree_with_gaps(src, dst).map(|_| ())
}

const MAX_SPECIAL_PATHS: usize = 20;

#[derive(Default)]
struct PathSummary {
    count: usize,
    paths: Vec<PathBuf>,
}

impl PathSummary {
    fn push(&mut self, path: PathBuf) {
        self.count += 1;
        self.paths.push(path);
        self.paths.sort();
        self.paths.truncate(MAX_SPECIAL_PATHS);
    }
}

fn copy_tree_with_gaps(src: &Path, dst: &Path) -> Result<Vec<String>, String> {
    let mut gaps = Vec::new();
    let mut special_paths = PathSummary::default();
    let mut links = 0;
    let mut outside_links = 0;
    let root = std::fs::canonicalize(src).map_err(|e| e.to_string())?;
    inspect_target(
        &root,
        &root,
        &mut special_paths,
        &mut links,
        &mut outside_links,
        &mut 0,
    )?;
    let specials = special_paths.count;
    gaps.extend(
        special_paths
            .paths
            .iter()
            .take(MAX_SPECIAL_PATHS)
            .map(|path| format!("skipped target socket or FIFO: {}", path.display())),
    );
    if specials > MAX_SPECIAL_PATHS {
        gaps.push(format!(
            "skipped {} additional target sockets or FIFOs",
            specials - MAX_SPECIAL_PATHS
        ));
    }
    if outside_links > 0 {
        let action = "copied as links, sandbox access rules apply";
        gaps.push(format!(
            "{outside_links} target link(s) resolve outside the target or do not resolve: {action}"
        ));
    }
    crate::proof_inputs::check_staging()?;
    std::fs::create_dir_all(dst).map_err(|e| format!("create {}: {e}", dst.display()))?;
    set_input_permissions(dst, root_mode())?;
    let roots = (root, dst.to_path_buf());
    copy_recursive(&roots.0, dst, &roots, None, &mut 0)?;
    set_input_permissions(dst, root_mode())?;
    record_live_links(&roots.0, dst, dst, &mut PathSummary::default(), &mut gaps)?;
    Ok(gaps)
}

// Explicit selections omit everything else from the sandbox. Always include root
// Git metadata. Refuse links in scoped inputs, including ancestor components.
pub(crate) fn copy_selected(
    root: &Path,
    dst: &Path,
    selection: &crate::proof_inputs::Selection,
) -> Result<Vec<String>, String> {
    selection.validate()?;
    crate::proof_inputs::verify_selection(root, selection)?;
    std::fs::create_dir_all(dst).map_err(|e| e.to_string())?;
    set_input_permissions(dst, root_mode())?;
    let mut paths = selection.paths.clone();
    if root.join(".git").try_exists().map_err(|e| e.to_string())?
        && !paths.iter().any(|p| p == ".git")
    {
        paths.retain(|p| !p.starts_with(".git/"));
        paths.push(".git".into());
    }
    paths.sort();
    let mut specials = PathSummary::default();
    let mut inspected = 0;
    for rel in &paths {
        let mut from = root.to_path_buf();
        for part in Path::new(rel) {
            from.push(part);
            let meta = std::fs::symlink_metadata(&from).map_err(|e| e.to_string())?;
            if platform::is_link(&meta) {
                return Err("scoped inputs cannot contain links".into());
            }
        }
        let meta = std::fs::symlink_metadata(&from).map_err(|e| e.to_string())?;
        if !meta.is_dir() && !meta.is_file() {
            return Err("selected input must be a file or directory".into());
        }
        if meta.is_dir() {
            let mut links = 0;
            let mut outside = 0;
            inspect_target(
                root,
                &from,
                &mut specials,
                &mut links,
                &mut outside,
                &mut inspected,
            )?;
            if links != 0 {
                return Err("scoped inputs cannot contain links".into());
            }
        }
        if rel == ".git" && meta.is_file() {
            return Err(
                "external Git directories are not execution inputs; use a standalone checkout"
                    .into(),
            );
        }
    }
    // One sorted traversal also creates shared ancestors in a fixed order.
    let selection = crate::proof_inputs::Selection { version: 1, paths };
    copy_recursive(
        root,
        dst,
        &(root.to_path_buf(), dst.to_path_buf()),
        Some(&selection),
        &mut 0,
    )?;
    crate::proof_inputs::verify_selection(dst, &selection)?;
    set_input_permissions(dst, root_mode())?;
    let mut gaps: Vec<_> = specials
        .paths
        .iter()
        .take(MAX_SPECIAL_PATHS)
        .map(|p| format!("skipped target socket or FIFO: {}", p.display()))
        .collect();
    if specials.count > MAX_SPECIAL_PATHS {
        gaps.push(format!(
            "skipped {} additional target sockets or FIFOs",
            specials.count - MAX_SPECIAL_PATHS
        ));
    }
    Ok(gaps)
}

fn root_mode() -> u32 {
    if cfg!(unix) {
        0o755
    } else {
        0
    }
}

// Runner-created directories and single-file harnesses are always searchable
// and executable on Unix, writable on Windows. Never inherit the host umask.
fn create_staging_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir(path)?;
    let current = std::fs::symlink_metadata(path)?.permissions();
    std::fs::set_permissions(path, crate::proof_inputs::permissions(root_mode(), current))
}

fn fixed_file_mode() -> u32 {
    if cfg!(unix) {
        0o644
    } else {
        0
    }
}

fn set_input_permissions(path: &Path, mode: u32) -> Result<(), String> {
    let current = std::fs::symlink_metadata(path)
        .map_err(|e| e.to_string())?
        .permissions();
    std::fs::set_permissions(path, crate::proof_inputs::permissions(mode, current))
        .map_err(|e| e.to_string())
}

fn inspect_target(
    root: &Path,
    dir: &Path,
    specials: &mut PathSummary,
    links: &mut usize,
    outside_links: &mut usize,
    count: &mut usize,
) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
        crate::proof_inputs::check_staging()?;
        let entry = entry.map_err(|e| e.to_string())?;
        crate::proof_inputs::admit_entry(count)?;
        let path = entry.path();
        let relative = path.strip_prefix(root).map_err(|e| e.to_string())?;
        let name = relative
            .to_str()
            .ok_or("execution input paths must be UTF-8")?
            .replace(std::path::MAIN_SEPARATOR, "/");
        crate::proof_inputs::safe_path(&name)?;
        let meta = std::fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
        if platform::is_link(&meta) {
            crate::proof_inputs::admit_link(&entry.path())?;
            *links += 1;
            if !std::fs::canonicalize(entry.path()).is_ok_and(|p| p.starts_with(root)) {
                *outside_links += 1;
            }
            continue;
        }
        if meta.is_dir() {
            inspect_target(root, &entry.path(), specials, links, outside_links, count)?;
        } else if platform::contentless(&meta) {
            specials.push(
                entry
                    .path()
                    .strip_prefix(root)
                    .map_err(|e| e.to_string())?
                    .to_path_buf(),
            );
        } else if !meta.is_file() {
            return Err(format!(
                "unsupported target file type at {}; devices are refused",
                entry.path().display()
            ));
        }
    }
    Ok(())
}

fn record_live_links(
    root: &Path,
    dst: &Path,
    dir: &Path,
    live: &mut PathSummary,
    gaps: &mut Vec<String>,
) -> Result<(), String> {
    if cfg!(unix) {
        crate::proof_inputs::children(dir, |entry| {
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            if platform::is_link(&meta) {
                if std::fs::canonicalize(&path).is_ok_and(|p| p.starts_with(root)) {
                    live.push(path.strip_prefix(dst).map_err(|e| e.to_string())?.into());
                }
            } else if meta.is_dir() {
                record_live_links(root, dst, &path, live, gaps)?;
            }
            Ok(())
        })?;
        if dir == dst {
            for rel in &live.paths {
                gaps.push(format!(
                    "target link reaches live target from workspace: {}",
                    rel.display()
                ));
            }
            if live.count > MAX_SPECIAL_PATHS {
                gaps.push(format!(
                    "{} additional target links reach live target from workspace",
                    live.count - MAX_SPECIAL_PATHS
                ));
            }
        }
    }
    Ok(())
}

/// `roots` is (canonical source root, destination root) of the whole copy.
fn copy_recursive(
    src: &Path,
    dst: &Path,
    roots: &(PathBuf, PathBuf),
    selection: Option<&crate::proof_inputs::Selection>,
    count: &mut usize,
) -> Result<(), String> {
    crate::proof_inputs::children_selected(&roots.0, src, selection, count, |entry, count| {
        crate::proof_inputs::check_staging()?;
        let path = entry.path();
        let rel = path.strip_prefix(&roots.0).map_err(|e| e.to_string())?;
        let name = rel
            .to_str()
            .ok_or("execution input paths must be UTF-8")?
            .replace(std::path::MAIN_SEPARATOR, "/");
        crate::proof_inputs::safe_path(&name)?;
        let meta = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        let to = dst.join(entry.file_name());
        if platform::is_link(&meta) {
            if selection.is_some() {
                return Err("scoped inputs cannot contain links".into());
            }
            crate::proof_inputs::admit_link(&path)?;
            copy_link(&path, &to)?;
        } else if meta.is_dir() {
            create_staging_dir(&to).map_err(|e| e.to_string())?;
            copy_recursive(&path, &to, roots, selection, count)?;
            set_input_permissions(&to, crate::proof_inputs::mode(&meta))?;
        } else if meta.is_file() {
            // stage_file uses create_new and dense writes, with no clone/copy
            // operation that could retain xattrs, ACLs, flags or sparse holes.
            if crate::proof_inputs::canonical_git_index(rel) {
                let bytes = crate::proof_inputs::read_index(&path)?;
                let bytes = crate::proof_inputs::normalize_index(&bytes)?;
                stage_content(
                    dst,
                    entry
                        .file_name()
                        .to_str()
                        .ok_or("execution input paths must be UTF-8")?,
                    std::io::Cursor::new(bytes),
                    meta.permissions(),
                )
                .map_err(|e| e.to_string())?;
            } else {
                stage_file(
                    dst,
                    entry
                        .file_name()
                        .to_str()
                        .ok_or("execution input paths must be UTF-8")?,
                    &path,
                )
                .map_err(|e| e.to_string())?;
            }
        } else if !platform::contentless(&meta) {
            return Err(format!(
                "unsupported target file type at {}; devices are refused",
                path.display()
            ));
        }
        Ok(())
    })
}

// Linux creates symlinks as 0777 regardless of umask. macOS filters their
// initial permissions through umask, so reset the link itself without following it.
#[cfg(unix)]
fn create_staging_link(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)?;
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(link.as_os_str().as_bytes())?;
        // SAFETY: path is NUL terminated. lchmod changes only the new link,
        // including dangling and outside links, never its referent.
        if unsafe { libc::lchmod(path.as_ptr(), 0o777) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Preserve exact link text, including dangling and outside links.
#[cfg(unix)]
fn copy_link(link: &Path, to: &Path) -> Result<(), String> {
    let target = std::fs::read_link(link).map_err(|e| e.to_string())?;
    create_staging_link(&target, to).map_err(|e| format!("link {}: {e}", to.display()))
}

#[cfg(windows)]
fn copy_link(link: &Path, _to: &Path) -> Result<(), String> {
    crate::proof_inputs::admit_link(link)
}

/// Why tier 2 cannot run on this OS, if it cannot.
pub fn tier2_unavailable(os: &str) -> Option<String> {
    (os != "linux").then(|| {
        format!(
            "tier 2 runs only on Linux: a local app and its client need a loopback of their own, which the {os} sandbox can only get by opening this machine's loopback to the app. OMGS keeps it closed, so run tier 2 on Linux or in a Linux VM; tier 1 proofs work here."
        )
    })
}

/// Copy `draft` to `workspace/rel` without following any link. The workspace
/// is a copy of the target, which controls its layout: a symlinked directory
/// on the way would otherwise make this unsandboxed write land on the host.
pub fn stage_file(workspace: &Path, rel: &str, draft: &Path) -> std::io::Result<()> {
    // Caller-supplied source drafts follow the checkout content policy.
    let source = crate::proof_inputs::admitted_file(draft).map_err(std::io::Error::other)?;
    let meta = source.metadata()?;
    let permissions =
        crate::proof_inputs::permissions(crate::proof_inputs::mode(&meta), meta.permissions());
    stage_content(workspace, rel, source, permissions)
}

fn stage_content(
    workspace: &Path,
    rel: &str,
    mut source: impl std::io::Read,
    permissions: std::fs::Permissions,
) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind, Write};
    let parts: Vec<&str> = rel
        .split(['/', '\\'])
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    let Some((file, dirs)) = parts.split_last() else {
        return Err(Error::new(ErrorKind::InvalidInput, "empty test path"));
    };
    if parts.iter().any(|p| *p == ".." || p.contains(':')) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "test path leaves the workspace",
        ));
    }
    let mut dir = workspace.to_path_buf();
    for part in dirs {
        dir.push(part);
        match std::fs::symlink_metadata(&dir) {
            Ok(m) if m.file_type().is_dir() && !platform::is_link(&m) => {}
            Ok(_) => {
                return Err(Error::other(format!(
                    "{} is a link or file in the target, not a directory",
                    dir.display()
                )))
            }
            Err(e) if e.kind() == ErrorKind::NotFound => create_staging_dir(&dir)?,
            Err(e) => return Err(e),
        }
    }
    let dest = dir.join(file);
    match std::fs::symlink_metadata(&dest) {
        Ok(_) => {
            return Err(Error::other(format!(
                "{} already exists in the target",
                dest.display()
            )))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    // create_new refuses an entry that appeared since, link or not.
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&dest)?;
    let mut bytes = vec![0u8; 1 << 16];
    loop {
        crate::proof_inputs::check_staging().map_err(Error::other)?;
        let n = source.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        out.write_all(&bytes[..n])?;
    }
    let mode = crate::proof_inputs::permission_mode(&permissions);
    // Windows Permissions also carries file attributes. Never transfer directory
    // attributes from a harness root onto a newly created regular file.
    out.set_permissions(crate::proof_inputs::permissions(
        mode,
        out.metadata()?.permissions(),
    ))
}

/// Admit the entire harness before writing any file. A harness owns fresh
/// file names only, never an existing target entry or metadata tree.
/// Restrict names to unambiguous portable ASCII rather than trying to emulate
/// every filesystem's Unicode folding and generated DOS short-name rules.
pub(crate) fn preflight_harness(workspace: &Path, paths: &[&str]) -> Result<(), String> {
    if paths.is_empty() {
        return Ok(());
    }
    let mut nodes = std::collections::BTreeMap::new();
    for path in paths {
        crate::proof_inputs::safe_path(path)?;
        let parts: Vec<_> = path.split('/').collect();
        let mut prefix = String::new();
        for (i, part) in parts.iter().enumerate() {
            let upper = part.to_ascii_uppercase();
            let stem = upper.split('.').next().unwrap_or("");
            if !part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                || part.starts_with('.')
                || part.ends_with('.')
                || matches!(stem, "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
                || ["COM", "LPT"].iter().any(|p| {
                    stem.strip_prefix(p)
                        .is_some_and(|n| n.len() == 1 && n.as_bytes()[0].is_ascii_digit())
                })
            {
                return Err(format!(
                    "harness path has a reserved or ambiguous component: {path}"
                ));
            }
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            let leaf = i + 1 == parts.len();
            let key = prefix.to_ascii_lowercase();
            if let Some((previous, was_leaf)) = nodes.get(&key) {
                if previous != &prefix || *was_leaf || leaf {
                    return Err(format!("harness paths alias or overlap: {path}"));
                }
            } else {
                nodes.insert(key, (prefix.clone(), leaf));
            }
        }
    }
    crate::proof_inputs::check_paths(workspace, paths, true)
}

/// A readable root that contains, or is contained in, the run directory.
fn overlapping_root<'a>(run_dir: &Path, readonly: &'a [PathBuf]) -> Option<&'a PathBuf> {
    let normalize = |p: &Path| {
        let p = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        if cfg!(windows) {
            PathBuf::from(mxc_path(&p).to_lowercase())
        } else {
            p
        }
    };
    let run_dir = normalize(run_dir);
    readonly.iter().find(|r| {
        let root = normalize(r);
        #[cfg(target_os = "macos")]
        {
            crate::tcc::overlaps(&run_dir, &root)
        }
        #[cfg(not(target_os = "macos"))]
        {
            run_dir.starts_with(&root) || root.starts_with(&run_dir)
        }
    })
}

struct BlockedCleanup {
    path: PathBuf,
    armed: bool,
}

impl Drop for BlockedCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

struct StagedWorkspace {
    digest: Option<String>,
    manifest: Option<crate::proof_inputs::Manifest>,
    rust: Option<RustHomes>,
    gaps: Vec<String>,
}

#[cfg(test)]
thread_local! {
    // One-shot deterministic mutation between the pre-copy and post-copy reads.
    static STAGING_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

fn stage_workspace(
    req: &ProveRequest,
    workspace: &Path,
    scratch: &Path,
    readonly: &[PathBuf],
    nonce: &str,
) -> Result<StagedWorkspace, String> {
    let _staging = crate::proof_inputs::StagingGuard::begin();
    let mut gaps = Vec::new();
    let mut source_before = None;
    let mut stamps_before = None;
    if let Some(target) = &req.target {
        let target = std::fs::canonicalize(target).map_err(|e| format!("target: {e}"))?;
        if !target.is_dir() {
            return Err(format!("target {} is not a directory", target.display()));
        }
        if workspace.starts_with(&target) {
            return Err("the proof directory must be outside the target tree".into());
        }
        if target.join(".git").is_file()
            || std::fs::symlink_metadata(target.join(".git")).is_ok_and(|m| platform::is_link(&m))
        {
            return Err(
                "external Git directories are not execution inputs; use a standalone checkout"
                    .into(),
            );
        }
        stamps_before = Some(crate::proof_inputs::source_stamps(
            &target,
            req.inputs.as_ref(),
        )?);
        source_before = Some(crate::proof_inputs::manifest(&target, req.inputs.clone())?);
        crate::out::err(&format!(
            "proof inputs: copy started ({})",
            if req.inputs.is_some() {
                "selected paths"
            } else {
                "full target"
            }
        ));
        let started = std::time::Instant::now();
        gaps = match &req.inputs {
            Some(selection) => copy_selected(&target, workspace, selection)?,
            None => copy_tree_with_gaps(&target, workspace)?,
        };
        #[cfg(test)]
        STAGING_HOOK.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook();
            }
        });
        crate::out::err(&format!(
            "proof inputs: copy complete ({} ms)",
            started.elapsed().as_millis()
        ));
    } else {
        create_staging_dir(workspace).map_err(|e| e.to_string())?;
    }
    let mut harness_paths: Vec<_> = req.harness.iter().map(|f| f.path.as_str()).collect();
    if let Some((_, path)) = &req.stage {
        harness_paths.push(path);
    }
    preflight_harness(workspace, &harness_paths)?;
    if let Some(target) = &req.target {
        // Selections must not let a harness impersonate omitted target files.
        preflight_harness(target, &harness_paths)?;
    }
    crate::out::err("proof inputs: hash started");
    let started = std::time::Instant::now();
    let manifest = req
        .target
        .as_ref()
        .map(|_| {
            crate::proof_inputs::manifest_to(
                workspace,
                req.inputs.clone(),
                &req.run_dir.join("input-manifest.json"),
            )
        })
        .transpose()?;
    let digest = manifest
        .as_ref()
        .map(crate::proof_inputs::Manifest::digest)
        .transpose()?;
    crate::out::err(&format!(
        "proof inputs: hash complete ({} entries, {} ms)",
        manifest.as_ref().map(|m| m.count).unwrap_or(0),
        started.elapsed().as_millis()
    ));
    if let Some(target) = &req.target {
        let source_after = crate::proof_inputs::manifest(target, req.inputs.clone())
            .map_err(|e| format!("target changed during staging: {e}"))?;
        let stamps_after = crate::proof_inputs::source_stamps(target, req.inputs.as_ref())
            .map_err(|e| format!("target changed during staging: {e}"))?;
        if stamps_before != Some(stamps_after)
            || source_before.as_ref() != Some(&source_after)
            || manifest.as_ref() != Some(&source_after)
        {
            return Err(
                "target changed during staging; refusing to execute inconsistent inputs".into(),
            );
        }
    }
    if req
        .expected_tree_sha256
        .as_ref()
        .is_some_and(|want| Some(want) != digest.as_ref())
    {
        let details = match (&req.expected_inputs, &manifest) {
            (Some(old), Some(new)) => old.differences(new),
            _ => "input identity mismatch".into(),
        };
        return Err(format!(
            "target snapshot differs from the recorded tree; refusing to replay; {details}"
        ));
    }
    for file in &req.harness {
        let rel = Path::new("harness").join(&file.path);
        let (bytes, permissions) = crate::run_artifact::read_with_permissions(
            &req.run_dir,
            &rel,
            crate::run_artifact::DRAFT_BYTES,
        )
        .map_err(|e| e.to_string())?;
        if sha256::digest(&bytes) != file.sha256 {
            return Err("retained harness digest mismatch".into());
        }
        stage_content(
            workspace,
            &file.path,
            std::io::Cursor::new(bytes),
            crate::proof_inputs::permissions(file.mode, permissions),
        )
        .map_err(|e| e.to_string())?;
    }
    if let Some((draft, rel)) = &req.stage {
        // CLI drafts were retained beneath run_dir. Pin the original run
        // boundary, including proofs/N, rather than treating N as trusted.
        let boundary = req
            .run_dir
            .parent()
            .and_then(Path::parent)
            .ok_or("proof directory needs a run boundary")?;
        let relative = draft
            .strip_prefix(boundary)
            .map_err(|_| "retained draft is outside its run boundary")?;
        let (bytes, permissions) = crate::run_artifact::read_with_permissions(
            boundary,
            relative,
            crate::run_artifact::DRAFT_BYTES,
        )
        .map_err(|e| e.to_string())?;
        // Single-file drafts bind bytes only. Their staged mode is a fixed
        // policy constant, never retained evidence or source permissions.
        stage_content(
            workspace,
            rel,
            std::io::Cursor::new(bytes),
            crate::proof_inputs::permissions(root_mode(), permissions),
        )
        .map_err(|e| format!("cannot stage the draft test at {rel}: {e}"))?;
    }
    for dir in [
        scratch.to_path_buf(),
        scratch.join("cache"),
        scratch.join("clang-cache"),
    ] {
        create_staging_dir(&dir).map_err(|e| e.to_string())?;
    }
    if cfg!(target_os = "macos") {
        stage_content(
            scratch,
            "openssl.cnf",
            std::io::empty(),
            crate::proof_inputs::permissions(
                fixed_file_mode(),
                std::fs::metadata(scratch)
                    .map_err(|e| e.to_string())?
                    .permissions(),
            ),
        )
        .map_err(|e| e.to_string())?;
    }
    let os = std::env::consts::OS;
    let rust = select_rust_homes(os, readonly, &scratch.join("cargo-home"));
    if let Some(rust) = &rust {
        create_staging_dir(&rust.cargo_home).map_err(|e| e.to_string())?;
        for sub in RUST_CACHES {
            if let Some(real) = rust_root(os, readonly, &format!("/.cargo/{sub}")) {
                link_dir(real, &rust.cargo_home.join(sub))
                    .map_err(|e| format!("cannot link the cargo {sub} cache: {e}"))?;
            }
        }
    }
    write_wrapper(
        std::env::consts::OS,
        workspace,
        &req.command,
        nonce,
        req.test.as_deref(),
    )
    .map_err(|e| format!("cannot write command wrapper: {e}"))?;
    crate::proof_inputs::normalize_timestamps(workspace)?;
    crate::proof_inputs::check_staging()?;
    Ok(StagedWorkspace {
        digest,
        manifest,
        rust,
        gaps,
    })
}

pub fn prove(req: &ProveRequest) -> ProveOutcome {
    #[cfg(any(unix, windows))]
    let _signals = match supervise::interruption::Guard::install() {
        Ok(guard) => guard,
        Err(e) => {
            return ProveOutcome::Blocked {
                reason: format!("cannot install proof signal guard: {e}"),
            }
        }
    };
    if req.run_dir.join("workspace").exists() || req.run_dir.join("scratch").exists() {
        return ProveOutcome::Blocked {
            reason: format!(
                "{} already holds a proof run; use a fresh directory",
                req.run_dir.display()
            ),
        };
    }
    let mut cleanup = BlockedCleanup {
        path: req.run_dir.clone(),
        armed: true,
    };
    if req
        .expect_marker
        .as_ref()
        .is_some_and(|m| !crate::proof::valid_expect_marker(m))
    {
        return ProveOutcome::Blocked {
            reason: "invalid boundary marker contract".into(),
        };
    }
    if let Err(reason) = validate_input(&req.command, req.timeout_ms) {
        return ProveOutcome::Blocked { reason };
    }
    #[cfg(target_os = "macos")]
    if let Err(e) = crate::tcc::admit_path(&req.run_dir) {
        return ProveOutcome::Blocked {
            reason: e.to_string(),
        };
    }
    let nonce = match platform::random_nonce() {
        Ok(n) => n,
        Err(e) => {
            return ProveOutcome::Blocked {
                reason: format!("cannot create command nonce: {e}"),
            }
        }
    };
    if let Some(test) = &req.test {
        if test.is_empty()
            || test.starts_with(['/', '\\'])
            || Path::new(test).is_absolute()
            || test.contains(['\0', '\r', '\n', ':'])
            || test.split(['/', '\\']).any(|p| p == "..")
            || (cfg!(windows) && test.contains('"'))
        {
            return ProveOutcome::Blocked {
                reason: "proof test must be a safe workspace-relative file path".into(),
            };
        }
    }
    let wrapped = wrapped_command(
        std::env::consts::OS,
        &req.command,
        &nonce,
        req.test.as_deref(),
    );
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
    let (list_parents, probe_fallback, mut notes, windows_gaps) = if os == "windows" {
        match preflight::windows_policy(windows_probe(&located.path)) {
            Ok(policy) => policy,
            Err(reason) => return blocked(reason),
        }
    } else {
        (false, false, Vec::new(), Vec::new())
    };
    if os == "windows" {
        notes.push(windows_build_report());
    }
    if let Err(e) = platform::private_dir(&req.run_dir) {
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
    let home = platform::home();
    let mut readonly: Vec<PathBuf> = toolchain_roots(os, home.as_deref())
        .into_iter()
        .filter(|p| p.exists())
        .collect();
    // A missing or unusable browser never blocks the proof; the record names why.
    let mut screenshots = req
        .screenshots
        .then(crate::screenshot::Screenshots::default);
    // Everything that can fail for screenshot reasons is settled here, before
    // any grant, so a failure becomes the record's blocker instead.
    let mut helper = None;
    let mut browser_grant = None;
    if let Some(shots) = screenshots.as_mut() {
        let helper_scratch = PathBuf::from(mxc_path(&scratch));
        match crate::screenshot::browser(os, std::env::var_os(crate::screenshot::BROWSER_ENV))
            .and_then(|b| {
                let text =
                    crate::screenshot::helper(os, &PathBuf::from(mxc_path(&b)), &helper_scratch)
                        .map_err(|e| format!("cannot prepare the screenshot helper: {e}"))?;
                admit_browser(os, &b, &run_dir, &readonly).map(|root| (b, text, root))
            }) {
            Ok((b, text, root)) => {
                shots.browser = Some(mxc_path(&b));
                readonly.extend(root.clone());
                browser_grant = root;
                helper = Some(text);
            }
            Err(reason) => shots.blocker = Some(reason),
        }
    }
    // A run directory under a readable root would make the workspace, the
    // config readable to every sandbox.
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

    #[cfg(target_os = "macos")]
    for path in [&run_dir].into_iter().chain(readonly.iter()) {
        if let Err(e) = crate::tcc::admit_path(path) {
            return blocked(e.to_string());
        }
    }
    let ownership = (os == "macos").then(|| supervise::MacOwnership {
        grants: readonly
            .iter()
            .cloned()
            .chain([workspace.clone(), scratch.clone()])
            .collect(),
    });
    let denied = Vec::new();
    let StagedWorkspace {
        digest: target_sha256,
        manifest: input_manifest,
        rust,
        gaps: mut extra_gaps,
    } = match stage_workspace(req, &workspace, &scratch, &readonly, &nonce) {
        Ok(staged) => staged,
        Err(reason) => return blocked(reason),
    };
    let screenshot = match helper
        .as_ref()
        .map(|h| write_screenshot_helper(h, &scratch))
    {
        Some(Ok(path)) => Some(path),
        Some(Err(reason)) => {
            screenshots_unavailable(&mut screenshots, &mut helper, &scratch, os, reason);
            readonly.retain(|r| Some(r) != browser_grant.as_ref());
            None
        }
        None => None,
    };
    #[cfg(target_os = "macos")]
    {
        let safe = supervise::capture_root().and_then(|root| {
            let grants: Vec<_> = [&workspace, &scratch]
                .into_iter()
                .chain(readonly.iter())
                .cloned()
                .collect();
            supervise::validate_capture_grants(&root, &grants)
        });
        if let Err(e) = safe {
            return blocked(format!("unsafe capture location: {e}"));
        }
    }
    extra_gaps.extend(windows_gaps);
    let mut input = ConfigInput {
        contract: req.expect_marker.as_deref().map(|m| (m, nonce.as_str())),
        os,
        containment: located.executor.containment,
        command: &wrapped,
        timeout_ms: req.timeout_ms,
        workspace: &workspace,
        scratch: &scratch,
        readonly,
        denied,
        rust,
        list_parents,
        screenshot,
    };
    if let Err(e) = supervise::check_interrupted() {
        return blocked(e.to_string());
    }
    let limits = supervise::Limits {
        // Windows uses only our timer so MXC's internal timeout cannot race
        // its console-control cleanup. Unix allows MXC a teardown margin.
        wall_ms: supervisor_timeout_ms(os, req.timeout_ms),
        cpu_secs: Some(req.timeout_ms.div_ceil(1000).saturating_mul(2).max(10)),
        file_size_bytes: Some(1 << 30),
        open_files: Some(1024),
        memory_bytes: Some(4 << 30),
        tasks: Some(512),
        output_cap_bytes: 256 * 1024,
    };
    for path in std::iter::once(located.path.clone()).chain(
        req.test
            .as_ref()
            .and_then(|test| req.target.as_ref().map(|target| target.join(test))),
    ) {
        if std::fs::symlink_metadata(&path).is_ok_and(|m| platform::is_link(&m)) {
            extra_gaps.push(platform::describe_path(&path));
        }
    }
    let (config_text, mut run) = loop {
        let config = mxc_config(&input);
        #[cfg(target_os = "macos")]
        if let Err(error) = crate::tcc::admit_config(&config) {
            return blocked(error.to_string());
        }
        let config_text = serde_json::to_string_pretty(&config).unwrap_or_default();
        let config_path = run_dir.join("mxc-config.json");
        if let Err(e) = crate::runmeta::write_atomic_bytes(&config_path, config_text.as_bytes()) {
            return blocked(format!("failed to write MXC config: {e}"));
        }
        #[cfg(windows)]
        let acl = match preflight::WindowsAclSnapshot::capture(
            [&workspace, &scratch]
                .into_iter()
                .chain(input.readonly.iter()),
        ) {
            Ok(acl) => acl,
            Err(reason) => return blocked(reason),
        };
        let validation = preflight::dry_run(&executor, &config_path, &run_dir);
        #[cfg(windows)]
        let validation = {
            let mut validation = validation;
            acl.verify(&mut validation);
            validation
        };
        if probe_fallback
            && !validation.success
            && input.list_parents
            && retry_without_enumeration(os, &validation)
        {
            input.list_parents = false;
            notes.push(
                "Windows enumeration fallback: dry-run refusal; retry without enumeratePaths"
                    .into(),
            );
            extra_gaps.push(preflight::enumeration_gap());
            continue;
        }
        if let Err(reason) = preflight::dry_run_result(&validation) {
            return blocked(reason);
        }
        let cmd = preflight::workload_command(&executor, &config_path, &run_dir);
        let run = supervise::run_contracted(
            cmd,
            &limits,
            ownership.as_ref(),
            &nonce,
            req.expect_marker.as_deref(),
        );
        #[cfg(windows)]
        let run = {
            let mut run = run;
            acl.verify(&mut run);
            run
        };
        // MXC rejects the policy before starting anything, so nothing ran and
        // retrying without the setting is safe.
        if probe_fallback && input.list_parents && retry_without_enumeration(os, &run) {
            for dir in [&workspace, &scratch] {
                if let Err(e) = std::fs::remove_dir_all(dir) {
                    return blocked(format!("cannot reset retry workspace: {e}"));
                }
            }
            let StagedWorkspace {
                digest,
                manifest: _,
                rust,
                gaps: retry_gaps,
            } = match stage_workspace(req, &workspace, &scratch, &input.readonly, &nonce) {
                Ok(staged) => staged,
                Err(reason) => return blocked(reason),
            };
            if digest != target_sha256 {
                return blocked("target changed before MXC retry".into());
            }
            if let Some(Err(reason)) = helper
                .as_ref()
                .map(|h| write_screenshot_helper(h, &scratch))
            {
                screenshots_unavailable(&mut screenshots, &mut helper, &scratch, os, reason);
                input.readonly.retain(|r| Some(r) != browser_grant.as_ref());
                input.screenshot = None;
            }
            for gap in retry_gaps {
                if !extra_gaps.contains(&gap) {
                    extra_gaps.push(gap);
                }
            }
            input.rust = rust;
            input.list_parents = false;
            notes.push(
                "Windows enumeration fallback: executor refusal; retry without enumeratePaths"
                    .into(),
            );
            extra_gaps.push(preflight::enumeration_gap());
            continue;
        }
        break (config_text, run);
    };
    if run.command_started && !run.command_finished && !run.interrupted && !run.killed {
        if run.duration_ms >= req.timeout_ms {
            run.timed_out = true;
        } else {
            run.killed = true;
        }
    }
    if os != "windows" && matches!(run.exit_code, Some(129..=255)) {
        run.killed = true;
    }
    run.success &= run.command_started
        && run.command_finished
        && !run.timed_out
        && !run.killed
        && (req.test.is_none() || run.test_reachable == Some(true));
    if req.test.is_some() && run.test_reachable != Some(true) {
        run.notes
            .push("named proof test readability was not established inside the sandbox".into());
    }
    let (mut enforced, mut gaps) = declared_controls(os, req.tier);
    if let Some(gap) = serde_json::from_str(&config_text)
        .ok()
        .as_ref()
        .and_then(listing_gap)
    {
        gaps.push(gap);
    }
    enforced.retain(|control| {
        !matches!(
            control.as_str(),
            "launchd_resource_coalition" | "launchd_tcc_path_admission"
        ) || run.enforced.contains(control)
    });
    enforced.extend(
        run.enforced
            .iter()
            .filter(|c| !enforced.contains(c))
            .cloned()
            .collect::<Vec<_>>(),
    );
    gaps.extend(extra_gaps);
    for note in &run.notes {
        if note.starts_with("Windows executor shutdown:") {
            notes.push(note.clone());
        } else if !gaps.contains(note) {
            gaps.push(note.clone());
        }
    }
    if let (Some(shots), Some(_)) = (screenshots.as_mut(), &helper) {
        let (files, mut skipped) =
            crate::screenshot::collect(&scratch, &run_dir.join(crate::screenshot::DIR));
        let helper_kept =
            std::fs::symlink_metadata(scratch.join(crate::screenshot::helper_name(os)))
                .is_ok_and(|m| m.is_file());
        if !helper_kept {
            skipped.push("the screenshot helper was missing after the run".into());
        }
        if files.is_empty() && skipped.is_empty() {
            skipped.push("no screenshot was produced: the command did not run the helper or the browser wrote nothing".into());
        }
        shots.files = files;
        shots.skipped = skipped;
    }
    // The workspace and scratch can be large and hold build output; the
    // config stays as part of the proof evidence.
    let _ = std::fs::remove_dir_all(&workspace);
    let _ = std::fs::remove_dir_all(&scratch);
    let _ = std::fs::remove_dir_all(&exec_dir);
    cleanup.armed = false;
    ProveOutcome::Ran(Box::new(ProveResult {
        executor: located.path,
        executor_sha256: located.executor.sha256.to_string(),
        containment: located.executor.containment.to_string(),
        config_sha256: sha256::digest(config_text.as_bytes()),
        wrapped_command_sha256: sha256::digest(wrapped.as_bytes()),
        readable_roots: input.readonly.iter().map(|p| mxc_path(p)).collect(),
        system_root: (os == "windows")
            .then(|| std::env::var("SYSTEMROOT").unwrap_or_else(|_| r"C:\Windows".into())),
        marker_nonce: nonce,
        target_sha256,
        input_manifest,
        enforced,
        gaps,
        notes,
        screenshots,
        run,
    }))
}

/// The browser directory to add as a read-only grant, if no existing grant
/// already covers it, or the reason the browser cannot be granted.
fn admit_browser(
    os: &str,
    browser: &Path,
    run_dir: &Path,
    readonly: &[PathBuf],
) -> Result<Option<PathBuf>, String> {
    let root = PathBuf::from(crate::screenshot::browser_root(os, &mxc_path(browser)));
    if run_dir.starts_with(&root) || root.starts_with(run_dir) {
        return Err(format!(
            "the browser directory {} overlaps the proof directory",
            root.display()
        ));
    }
    #[cfg(target_os = "macos")]
    crate::tcc::admit_path(&root).map_err(|e| format!("browser directory refused: {e}"))?;
    Ok((!readonly.iter().any(|r| root.starts_with(r))).then_some(root))
}

/// A helper that cannot be written leaves the proof running without
/// screenshots; the record names why and grants nothing for the browser.
fn screenshots_unavailable(
    screenshots: &mut Option<crate::screenshot::Screenshots>,
    helper: &mut Option<(String, String)>,
    scratch: &Path,
    os: &str,
    reason: String,
) {
    let _ = std::fs::remove_file(scratch.join(crate::screenshot::helper_name(os)));
    let _ = std::fs::remove_dir_all(scratch.join(crate::screenshot::DIR));
    *helper = None;
    if let Some(shots) = screenshots.as_mut() {
        shots.browser = None;
        shots.blocker = Some(reason);
    }
}

/// Writes the prepared capture helper and its output directory into the
/// freshly staged scratch, refusing anything already present there.
fn write_screenshot_helper(helper: &(String, String), scratch: &Path) -> Result<PathBuf, String> {
    use std::io::Write;
    let (name, text) = helper;
    let path = scratch.join(name);
    std::fs::create_dir(scratch.join(crate::screenshot::DIR))
        .and_then(|_| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
        })
        .and_then(|mut file| file.write_all(text.as_bytes()))
        .map_err(|e| format!("cannot write the screenshot helper: {e}"))?;
    Ok(PathBuf::from(mxc_path(&path)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_refuses_oversized_sparse_source_before_copy_and_expired_postwalk() {
        let base = crate::platform::scratch_root().unwrap().join(format!(
            "staging-limits-{}",
            crate::platform::random_nonce().unwrap()
        ));
        crate::platform::create_private_dir_new(&base).unwrap();
        let target = base.join("target");
        std::fs::create_dir(&target).unwrap();
        let input = target.join("input");
        let run_dir = base.join("proof");
        crate::platform::create_private_dir_new(&run_dir).unwrap();
        let request = ProveRequest {
            screenshots: false,
            command: "never executed".into(),
            expect_marker: None,
            test: None,
            timeout_ms: 1000,
            target: Some(target.clone()),
            run_dir: run_dir.clone(),
            tier: Tier::Test,
            stage: None,
            expected_tree_sha256: None,
            inputs: None,
            expected_inputs: None,
            harness: vec![],
        };
        let sparse = std::fs::File::create(&input).unwrap();
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            extern "system" {
                fn DeviceIoControl(
                    handle: *mut core::ffi::c_void,
                    code: u32,
                    input: *const u8,
                    input_len: u32,
                    output: *mut u8,
                    output_len: u32,
                    returned: *mut u32,
                    overlapped: *mut core::ffi::c_void,
                ) -> i32;
            }
            let mut returned = 0;
            // SAFETY: the owned file handle is live, no buffers are passed,
            // and returned points to writable storage. FSCTL_SET_SPARSE makes
            // the oversized fixture cheap on Windows as well as Unix.
            let ok = unsafe {
                DeviceIoControl(
                    sparse.as_raw_handle(),
                    0x0009_00c4,
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                    0,
                    &mut returned,
                    std::ptr::null_mut(),
                )
            };
            assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
        }
        sparse
            .set_len(crate::proof_inputs::MAX_SOURCE_BYTES + 1)
            .unwrap();
        drop(sparse);
        let workspace = run_dir.join("workspace");
        let result = stage_workspace(&request, &workspace, &run_dir.join("scratch"), &[], "nonce");
        assert!(matches!(result, Err(ref e) if e.contains("aggregate source byte budget")));
        assert!(!workspace.exists());
        std::fs::write(&input, b"ab").unwrap();
        STAGING_HOOK
            .with(|hook| *hook.borrow_mut() = Some(Box::new(crate::proof_inputs::expire_staging)));
        let result = stage_workspace(&request, &workspace, &run_dir.join("scratch"), &[], "nonce");
        assert!(matches!(result, Err(ref e) if e.contains("staging deadline exceeded")));
        assert!(!run_dir.join("config.json").exists());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn restored_source_writes_and_membership_changes_refuse_staging() {
        for membership in [false, true] {
            let base = crate::platform::scratch_root().unwrap().join(format!(
                "staging-restored-{}-{}",
                std::process::id(),
                crate::platform::random_nonce().unwrap()
            ));
            crate::platform::create_private_dir_new(&base).unwrap();
            let target = base.join("target");
            std::fs::create_dir(&target).unwrap();
            std::fs::write(target.join("input"), b"0").unwrap();
            let identity = crate::proof_inputs::manifest(&target, None).unwrap();
            let modified = std::fs::metadata(target.join("input"))
                .unwrap()
                .modified()
                .unwrap();
            let source = target.clone();
            STAGING_HOOK.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    for _ in 0..8 {
                        if membership {
                            std::fs::write(source.join("transient"), b"synthetic").unwrap();
                            std::fs::remove_file(source.join("transient")).unwrap();
                        } else {
                            std::fs::write(source.join("input"), b"1").unwrap();
                            std::fs::write(source.join("input"), b"0").unwrap();
                        }
                    }
                    // Restoring mtime must not hide the OS change time.
                    if !membership {
                        std::fs::File::options()
                            .write(true)
                            .open(source.join("input"))
                            .unwrap()
                            .set_times(std::fs::FileTimes::new().set_modified(modified))
                            .unwrap();
                    }
                }))
            });
            let run_dir = base.join("proof");
            crate::platform::create_private_dir_new(&run_dir).unwrap();
            let request = ProveRequest {
                screenshots: false,
                command: "never executed".into(),
                expect_marker: None,
                test: None,
                timeout_ms: 1000,
                target: Some(target.clone()),
                run_dir: run_dir.clone(),
                tier: Tier::Test,
                stage: None,
                expected_tree_sha256: None,
                inputs: None,
                expected_inputs: None,
                harness: vec![],
            };
            let workspace = run_dir.join("workspace");
            let result =
                stage_workspace(&request, &workspace, &run_dir.join("scratch"), &[], "nonce");
            assert!(matches!(result, Err(ref e) if e.contains("target changed during staging")));
            assert_eq!(
                identity,
                crate::proof_inputs::manifest(&target, None).unwrap(),
                "all content identities agree after restoring the source"
            );
            assert_eq!(
                identity,
                crate::proof_inputs::manifest(&workspace, None).unwrap()
            );
            assert!(
                !run_dir.join("config.json").exists(),
                "refuse before execution setup"
            );
            std::fs::remove_dir_all(base).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn host_discovery_respects_overall_deadline() {
        assert_eq!(
            host_query("/bin/sh", &["-c", "printf ready"]),
            Some("ready".into())
        );
        let _deadline = supervise::Deadline::after(std::time::Duration::from_millis(100));
        let start = std::time::Instant::now();
        assert!(host_query("/bin/sh", &["-c", "while :; do :; done"]).is_none());
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn macos_version_check_refuses_old_or_unknown_versions() {
        assert!(require_macos_version(Some(14))
            .unwrap_err()
            .contains("macOS 15"));
        assert!(require_macos_version(None)
            .unwrap_err()
            .contains("cannot determine"));
        assert!(require_macos_version(Some(15)).is_ok());
        assert!(require_macos_version(Some(26)).is_ok());
    }

    #[test]
    fn homebrew_grants_exclude_configuration_and_state() {
        let roots = toolchain_roots("macos", None);
        for denied in ["/opt/homebrew/etc", "/opt/homebrew/var"] {
            assert!(!roots.iter().any(|r| Path::new(denied).starts_with(r)));
        }
        assert!(roots.contains(&PathBuf::from("/opt/homebrew/Cellar")));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn rust_layouts_round_trip_staging_and_proof_validation_without_host_discovery() {
        const CHILD: &str = "OMGS_TEST_RUST_LAYOUT_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let absolute = platform::temp_root()
                .unwrap()
                .join(format!("omgs-rust-layouts-home-{}", std::process::id()));
            let absolute_home = absolute.join("host-home");
            for (home, discovered) in [
                (None, "0"),
                (Some(""), "0"),
                (Some("relative-home"), "0"),
                (absolute_home.to_str(), "1"),
            ] {
                let mut child = std::process::Command::new(std::env::current_exe().unwrap());
                child.args([
                    "--exact",
                    "sandbox::tests::rust_layouts_round_trip_staging_and_proof_validation_without_host_discovery",
                    "--nocapture",
                ]).env(CHILD, discovered).env_remove("HOME");
                if let Some(home) = home {
                    child.env("HOME", home);
                }
                let output = child.output().unwrap();
                assert!(
                    output.status.success(),
                    "HOME={home:?}: {}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            let _ = std::fs::remove_dir_all(absolute);
            return;
        }
        // Discovery decides whether HOME contributes roots: missing, empty and
        // relative values must yield none, an absolute one its Rust roots.
        let discovered = platform::home();
        assert_eq!(
            discovered.is_some(),
            std::env::var(CHILD).unwrap() == "1",
            "{discovered:?}"
        );
        let dir = platform::temp_root()
            .unwrap()
            .join(format!("omgs-rust-layouts-{}", std::process::id()));
        platform::create_private_tree(&dir).unwrap();
        let home = discovered.clone().unwrap_or_else(|| dir.join("host-home"));
        for sub in ["bin", "registry", "git"] {
            std::fs::create_dir_all(home.join(".cargo").join(sub)).unwrap();
        }
        std::fs::create_dir_all(home.join(".rustup")).unwrap();
        for name in ["config.toml", "credentials", "credentials.toml"] {
            std::fs::write(home.join(".cargo").join(name), b"host secret").unwrap();
        }
        let brew_bin = PathBuf::from(HOMEBREW_RUSTUP_BIN);
        // Subprocesses isolate HOME changes; no installed Rust tools are needed.
        for has_home in [discovered.is_some()] {
            for layout in ["cargo", "homebrew", "both"] {
                let run = dir.join(format!("{layout}-{has_home}"));
                let proof_dir = run.join("proofs/1");
                platform::create_private_tree(&proof_dir).unwrap();
                let req = ProveRequest {
                    screenshots: false,
                    expect_marker: None,
                    command: "cargo run --offline".into(),
                    test: None,
                    timeout_ms: 1000,
                    target: None,
                    run_dir: proof_dir.clone(),
                    tier: Tier::Test,
                    stage: None,
                    expected_tree_sha256: None,
                    inputs: None,
                    expected_inputs: None,
                    harness: vec![],
                };
                let readonly: Vec<_> = toolchain_roots("macos", discovered.as_deref())
                    .into_iter()
                    .filter(|p| {
                        if p == &brew_bin {
                            layout != "cargo"
                        } else if p == &home.join(".cargo/bin") {
                            layout != "homebrew"
                        } else {
                            p.starts_with(&home)
                        }
                    })
                    .collect();
                for name in ["config.toml", "credentials", "credentials.toml"] {
                    let secret = home.join(".cargo").join(name);
                    assert!(!readonly.iter().any(|root| secret.starts_with(root)));
                }
                let workspace = proof_dir.join("workspace");
                let scratch = proof_dir.join("scratch");
                let nonce = "a".repeat(64);
                let staged =
                    stage_workspace(&req, &workspace, &scratch, &readonly, &nonce).unwrap();
                let expected_bin = if has_home && layout != "homebrew" {
                    Some(home.join(".cargo/bin"))
                } else if layout != "cargo" {
                    Some(brew_bin.clone())
                } else {
                    None
                };
                assert_eq!(staged.rust.as_ref().map(|r| &r.bin), expected_bin.as_ref());
                if let Some(rust) = &staged.rust {
                    assert_eq!(rust.cargo_home, scratch.join("cargo-home"));
                    assert_eq!(rust.rustup_home, has_home.then(|| home.join(".rustup")));
                    for sub in RUST_CACHES {
                        let link = rust.cargo_home.join(sub);
                        if has_home {
                            assert_eq!(
                                std::fs::read_link(link).unwrap(),
                                home.join(".cargo").join(sub)
                            );
                        } else {
                            assert!(!link.exists());
                        }
                    }
                    for name in ["config.toml", "credentials", "credentials.toml"] {
                        assert!(!rust.cargo_home.join(name).exists());
                    }
                } else {
                    assert!(!scratch.join("cargo-home").exists());
                }
                let wrapped = wrapped_command("macos", &req.command, &nonce, None);
                let config = mxc_config_at(
                    &ConfigInput {
                        os: "macos",
                        contract: None,
                        containment: "seatbelt",
                        command: &wrapped,
                        timeout_ms: req.timeout_ms,
                        workspace: &workspace,
                        scratch: &scratch,
                        readonly: readonly.clone(),
                        denied: vec![],
                        rust: staged.rust,
                        list_parents: false,
                        screenshot: None,
                    },
                    "",
                );
                let env = config["process"]["env"].as_array().unwrap();
                assert!(env.contains(&serde_json::json!("RUSTUP_AUTO_INSTALL=0")));
                assert_eq!(
                    env.contains(&serde_json::json!("CARGO_NET_OFFLINE=true")),
                    expected_bin.is_some()
                );
                assert_eq!(
                    env.iter()
                        .any(|v| v.as_str().unwrap().starts_with("CARGO_HOME=")),
                    expected_bin.is_some()
                );
                if let Some(bin) = expected_bin {
                    assert!(env.iter().any(|v| v
                        .as_str()
                        .unwrap()
                        .starts_with(&format!("PATH={}:", bin.display()))));
                }
                let config_text = serde_json::to_string_pretty(&config).unwrap();
                crate::runmeta::write_atomic(&proof_dir.join("mxc-config.json"), &config_text)
                    .unwrap();
                crate::runmeta::write_atomic(&proof_dir.join("command.txt"), &req.command).unwrap();
                let (enforced, gaps) = declared_controls("macos", Tier::Test);
                let executor = pinned_executors()
                    .into_iter()
                    .find(|e| e.containment == "seatbelt")
                    .unwrap();
                let record: crate::proof::ProofRecord = serde_json::from_value(serde_json::json!({
                    "schema": crate::proof::SCHEMA, "n": 1, "tier": "test",
                    "command": req.command, "command_sha256": sha256::digest(req.command.as_bytes()),
                    "wrapped_command_sha256": sha256::digest(wrapped.as_bytes()),
                    "readable_roots": readonly.iter().map(|p| mxc_path(p)).collect::<Vec<_>>(),
                    "proof_dir": mxc_path(&proof_dir), "marker_nonce": nonce,
                    "command_started": true, "command_finished": true, "timeout_ms": req.timeout_ms,
                    "started_at_ms": 0, "duration_ms": 0, "exit_code": 0, "contract": {"kind": "none"},
                    "timed_out": false, "capture_complete": true, "cleanup_complete": true,
                    "survivors": [], "mxc_version": MXC_VERSION, "containment": "seatbelt",
                    "executor": executor.file, "executor_sha256": executor.sha256,
                    "config_sha256": sha256::digest(config_text.as_bytes()),
                    "enforced": enforced, "gaps": gaps, "output_sha256": sha256::digest(b""),
                    "output_bytes_total": 0, "output": "", "omgs_version": env!("CARGO_PKG_VERSION"),
                    "output_audit": {"version":1,"marker_observations":[],"stream_bytes":[0,0],"retained_stream_bytes":[0,0],"redactions":[],"captured_text_bytes":0,"decoded_capture_bytes":0}
                })).unwrap();
                crate::proof::write(&run, &record).unwrap();
                let saved = crate::proof::load(&run, "proofs/1.json").unwrap();
                let errors = crate::proof::runner_evidence(&run, &saved);
                assert!(
                    errors.is_empty(),
                    "layout={layout}, has_home={has_home}: {errors:?}"
                );
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rust_selection_prefers_cargo_and_limits_homebrew_fallback_to_macos() {
        let cargo_home = Path::new("/run/scratch/cargo-home");
        let brew_bin = PathBuf::from(HOMEBREW_RUSTUP_BIN);
        let cargo_bin = PathBuf::from("/home/u/.cargo/bin");
        for os in ["macos", "linux", "windows"] {
            let roots = vec![brew_bin.clone()];
            assert_eq!(
                select_rust_homes(os, &roots, cargo_home).is_some(),
                os == "macos"
            );
            let roots = vec![brew_bin.clone(), cargo_bin.clone()];
            let rust = select_rust_homes(os, &roots, cargo_home).unwrap();
            assert_eq!(rust.bin, cargo_bin);
            assert_eq!(rust.cargo_home, cargo_home);
            assert!(rust.rustup_home.is_none());
            assert!(select_rust_homes(os, &[], cargo_home).is_none());
        }
        let roots = vec![
            PathBuf::from(r"C:\Users\U\.CARGO\BIN"),
            PathBuf::from(r"C:\Users\U\.RUSTUP"),
        ];
        let rust = select_rust_homes("windows", &roots, cargo_home).unwrap();
        assert_eq!(rust.bin, roots[0]);
        assert_eq!(rust.rustup_home.as_ref(), Some(&roots[1]));
    }

    #[test]
    fn linux_system_headers_are_an_explicit_readonly_grant() {
        assert!(toolchain_roots("linux", None).contains(&PathBuf::from("/usr/include")));
        let input = ConfigInput {
            contract: None,
            os: "linux",
            containment: "bubblewrap",
            command: "exit 0",
            timeout_ms: 1000,
            workspace: Path::new("/tmp/workspace"),
            scratch: Path::new("/tmp/scratch"),
            readonly: vec![PathBuf::from("/usr/include")],
            denied: vec![],
            rust: None,
            list_parents: false,
            screenshot: None,
        };
        let config = mxc_config(&input);
        let text = serde_json::to_string(&config).unwrap();
        assert!(text.contains("/usr/include"));
        assert!(config["filesystem"]["readwritePaths"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p != "/usr/include"));
        assert!(config["filesystem"]["readonlyPaths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p == "/usr/include"));
    }

    #[test]
    fn harness_modes_are_fixed_or_identity_bound_on_every_platform() {
        let base = crate::platform::temp_root()
            .unwrap()
            .join(format!("omgs-harness-modes-{}", std::process::id()));
        platform::create_private_tree(&base).unwrap();
        for directory in [false, true] {
            let run = base.join(if directory { "directory" } else { "single" });
            let proof_dir = run.join("proofs/1");
            platform::create_private_tree(&proof_dir).unwrap();
            let retained = if directory {
                proof_dir.join("harness/checks/deep/test")
            } else {
                proof_dir.join("test-draft")
            };
            platform::create_private_tree(retained.parent().unwrap()).unwrap();
            crate::runmeta::write_atomic_bytes(&retained, b"harness bytes").unwrap();
            let bound_mode = if cfg!(unix) { 0o640 } else { 1 };
            let req = ProveRequest {
                screenshots: false,
                expect_marker: None,
                command: "echo fixture".into(),
                test: Some("checks/deep/test".into()),
                timeout_ms: 1000,
                target: None,
                run_dir: proof_dir.clone(),
                tier: Tier::Test,
                stage: (!directory).then(|| (retained.clone(), "checks/deep/test".into())),
                expected_tree_sha256: None,
                inputs: None,
                expected_inputs: None,
                harness: if directory {
                    vec![crate::proof::HarnessFile {
                        path: "checks/deep/test".into(),
                        sha256: sha256::digest(b"harness bytes"),
                        mode: bound_mode,
                    }]
                } else {
                    vec![]
                },
            };
            for (i, retained_mode) in [
                if cfg!(unix) { 0o600 } else { 0 },
                if cfg!(unix) { 0o700 } else { 1 },
            ]
            .into_iter()
            .enumerate()
            {
                set_input_permissions(&retained, retained_mode).unwrap();
                let workspace = proof_dir.join(format!("workspace{i}"));
                let scratch = proof_dir.join(format!("scratch{i}"));
                stage_workspace(&req, &workspace, &scratch, &[], "fixture-nonce").unwrap();
                for path in [
                    workspace.clone(),
                    workspace.join("checks"),
                    workspace.join("checks/deep"),
                    scratch.clone(),
                    scratch.join("cache"),
                    scratch.join("clang-cache"),
                ] {
                    assert_eq!(
                        crate::proof_inputs::mode(&std::fs::metadata(path).unwrap()),
                        root_mode()
                    );
                }
                let file = workspace.join("checks/deep/test");
                assert_eq!(std::fs::read(&file).unwrap(), b"harness bytes");
                assert_eq!(
                    crate::proof_inputs::mode(&std::fs::metadata(&file).unwrap()),
                    if directory { bound_mode } else { root_mode() }
                );
                // Exercise the Windows wrapper materialization even on Unix.
                write_wrapper(
                    "windows",
                    &workspace,
                    "echo fixture",
                    "wrapper-fixture-nonce",
                    req.test.as_deref(),
                )
                .unwrap();
                let wrapper = workspace.join(format!(
                    "{}.cmd",
                    wrapper_name("echo fixture", "wrapper-fixture-nonce", req.test.as_deref())
                ));
                assert_eq!(
                    crate::proof_inputs::mode(&std::fs::metadata(&wrapper).unwrap()),
                    fixed_file_mode()
                );
                assert!(std::fs::read_to_string(wrapper)
                    .unwrap()
                    .contains("OMGS_START_wrapper-fixture-nonce"));
                // Read-only Windows fixtures must be restored before cleanup.
                set_input_permissions(&file, fixed_file_mode()).unwrap();
            }
            set_input_permissions(&retained, fixed_file_mode()).unwrap();
        }
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn blocked_proofs_remove_their_staging_directory() {
        let d = crate::platform::temp_root()
            .unwrap()
            .join(format!("omgs-blocked-{}", std::process::id()));
        let req = |command: &str| ProveRequest {
            screenshots: false,
            expect_marker: None,
            command: command.into(),
            test: None,
            timeout_ms: 1000,
            target: None,
            run_dir: d.clone(),
            tier: Tier::Test,
            stage: None,
            expected_tree_sha256: None,
            inputs: None,
            expected_inputs: None,
            harness: vec![],
        };
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("test-draft"), b"draft").unwrap();
        assert!(matches!(prove(&req("")), ProveOutcome::Blocked { .. }));
        assert!(!d.exists());
        if locate_executor().is_ok() {
            let mut request = req("echo ok");
            request.stage = Some((d.join("missing"), "test".into()));
            assert!(matches!(prove(&request), ProveOutcome::Blocked { .. }));
            assert!(!d.exists());
            request.stage = None;
            request.expected_tree_sha256 = Some("a".repeat(64));
            assert!(matches!(prove(&request), ProveOutcome::Blocked { .. }));
            assert!(!d.exists());
        }
    }

    #[test]
    fn windows_timeout_is_owned_by_supervisor_without_an_internal_timer() {
        for timeout in [1, 2000, u64::from(u32::MAX)] {
            assert_eq!(executor_timeout_ms("windows", timeout), 0);
            assert_eq!(supervisor_timeout_ms("windows", timeout), timeout);
            for os in ["linux", "macos"] {
                assert_eq!(executor_timeout_ms(os, timeout), timeout);
                assert_eq!(supervisor_timeout_ms(os, timeout), timeout + 15_000);
            }
        }
    }

    #[test]
    fn environment_allowlist_matches_every_emitted_key() {
        for os in ["macos", "linux", "windows"] {
            for contract in [None, Some(("BOUNDARY", "nonce"))] {
                let config = mxc_config(&ConfigInput {
                    contract,
                    os,
                    containment: "test",
                    command: "echo test",
                    timeout_ms: 1000,
                    workspace: Path::new("/run/workspace"),
                    scratch: Path::new("/run/scratch"),
                    readonly: vec![],
                    denied: vec![],
                    rust: Some(RustHomes {
                        bin: "/tools/bin".into(),
                        cargo_home: "/run/scratch/cargo-home".into(),
                        rustup_home: Some("/tools/rustup".into()),
                    }),
                    list_parents: false,
                    screenshot: None,
                });
                let mut keys: Vec<_> = config["process"]["env"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap().split_once('=').unwrap().0)
                    .collect();
                let mut expected = environment_keys(os);
                if contract.is_some() {
                    expected.push("OMGS_PROOF_NONCE");
                }
                keys.sort_unstable();
                expected.sort_unstable();
                assert_eq!(keys, expected, "{os}");
            }
        }
    }

    #[test]
    fn selected_copy_is_batched_exact_and_charges_omitted_siblings_before_copying() {
        let d = crate::platform::temp_root().unwrap().join(format!(
            "omgs-selected-width-{}",
            crate::platform::random_nonce().unwrap()
        ));
        let src = d.join("source");
        std::fs::create_dir_all(src.join("selected/nested")).unwrap();
        for n in (0..300).rev() {
            std::fs::write(src.join(format!("selected/nested/p{n:04}")), b"synthetic").unwrap();
            std::fs::write(src.join(format!("omitted{n:04}")), b"omitted").unwrap();
        }
        let selection = crate::proof_inputs::Selection {
            version: 1,
            paths: vec!["selected".into()],
        };
        let dst = d.join("copy");
        copy_selected(&src, &dst, &selection).unwrap();
        assert_eq!(
            crate::proof_inputs::manifest(&src, Some(selection.clone())).unwrap(),
            crate::proof_inputs::manifest(&dst, Some(selection.clone())).unwrap()
        );
        assert_eq!(std::fs::read_dir(&dst).unwrap().count(), 1);
        assert_eq!(
            std::fs::read_dir(dst.join("selected/nested"))
                .unwrap()
                .count(),
            300
        );
        let capped = d.join("capped");
        std::fs::create_dir(&capped).unwrap();
        let mut count = crate::proof_inputs::MAX_ENTRIES - 1;
        let error = copy_recursive(
            &src,
            &capped,
            &(src.clone(), capped.clone()),
            Some(&selection),
            &mut count,
        )
        .unwrap_err();
        assert!(error.contains("exceeds"));
        assert_eq!(count, crate::proof_inputs::MAX_ENTRIES);
        assert_eq!(std::fs::read_dir(&capped).unwrap().count(), 0);
        std::fs::remove_dir_all(d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn fresh_staging_normalizes_hardlinks_sparse_files_and_special_modes() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = crate::platform::temp_root().unwrap().join(format!(
            "omgs-fresh-{}",
            crate::platform::random_nonce().unwrap()
        ));
        let src = d.join("source");
        std::fs::create_dir_all(src.join("dir")).unwrap();
        std::fs::write(src.join("a"), b"same").unwrap();
        std::fs::hard_link(src.join("a"), src.join("b")).unwrap();
        let sparse = std::fs::File::create(src.join("zeros")).unwrap();
        sparse.set_len(2 << 20).unwrap();
        drop(sparse);
        std::fs::set_permissions(src.join("a"), std::fs::Permissions::from_mode(0o6755)).unwrap();
        std::fs::set_permissions(src.join("dir"), std::fs::Permissions::from_mode(0o3775)).unwrap();
        let before = crate::proof_inputs::manifest(&src, None).unwrap();
        let first = d.join("first");
        copy_tree(&src, &first).unwrap();
        assert_eq!(crate::proof_inputs::manifest(&first, None).unwrap(), before);
        for name in ["a", "b"] {
            let meta = std::fs::metadata(first.join(name)).unwrap();
            assert_eq!(meta.nlink(), 1);
            assert_eq!(meta.mode() & 0o7777, 0o755);
        }
        assert_ne!(
            std::fs::metadata(first.join("a")).unwrap().ino(),
            std::fs::metadata(first.join("b")).unwrap().ino()
        );
        assert_eq!(
            std::fs::metadata(first.join("dir")).unwrap().mode() & 0o7777,
            0o775
        );
        assert_eq!(std::fs::metadata(&first).unwrap().mode() & 0o7777, 0o755);
        assert!(std::fs::metadata(first.join("zeros")).unwrap().blocks() >= (2 << 20) / 512);
        // Independent files, dense bytes and no special bits admit identically.
        std::fs::remove_file(src.join("b")).unwrap();
        std::fs::write(src.join("b"), b"same").unwrap();
        std::fs::set_permissions(src.join("a"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(src.join("b"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(src.join("dir"), std::fs::Permissions::from_mode(0o775)).unwrap();
        std::fs::write(src.join("zeros"), vec![0; 2 << 20]).unwrap();
        assert_eq!(crate::proof_inputs::manifest(&src, None).unwrap(), before);
        let second = d.join("second");
        copy_tree(&src, &second).unwrap();
        assert_eq!(
            crate::proof_inputs::manifest(&second, None).unwrap(),
            before
        );
        assert_eq!(
            std::fs::metadata(first.join("zeros")).unwrap().blocks(),
            std::fs::metadata(second.join("zeros")).unwrap().blocks()
        );
        std::fs::remove_dir_all(d).unwrap();
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn fresh_staging_never_transfers_source_extended_attributes() {
        use std::os::unix::ffi::OsStrExt;
        let d = crate::platform::temp_root().unwrap().join(format!(
            "omgs-xattr-{}",
            crate::platform::random_nonce().unwrap()
        ));
        let src = d.join("source");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("file"), b"bytes").unwrap();
        for path in [&src, &src.join("file")] {
            let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            let name = c"user.omgs_fixture";
            #[cfg(target_os = "macos")]
            let result = unsafe {
                libc::setxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    b"BEFORE".as_ptr().cast(),
                    6,
                    0,
                    0,
                )
            };
            #[cfg(target_os = "linux")]
            let result = unsafe {
                libc::setxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    b"BEFORE".as_ptr().cast(),
                    6,
                    0,
                )
            };
            assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
        }
        let before = crate::proof_inputs::manifest(&src, None).unwrap();
        for (n, value) in [b"BEFORE".as_slice(), b"AFTER".as_slice()]
            .iter()
            .enumerate()
        {
            let path = std::ffi::CString::new(src.join("file").as_os_str().as_bytes()).unwrap();
            #[cfg(target_os = "macos")]
            let result = unsafe {
                libc::setxattr(
                    path.as_ptr(),
                    c"user.omgs_fixture".as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                    0,
                )
            };
            #[cfg(target_os = "linux")]
            let result = unsafe {
                libc::setxattr(
                    path.as_ptr(),
                    c"user.omgs_fixture".as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            };
            assert_eq!(result, 0);
            assert_eq!(crate::proof_inputs::manifest(&src, None).unwrap(), before);
            let dst = d.join(format!("copy-{n}"));
            copy_tree(&src, &dst).unwrap();
            for path in [&dst, &dst.join("file")] {
                let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                #[cfg(target_os = "macos")]
                let result = unsafe {
                    libc::getxattr(
                        path.as_ptr(),
                        c"user.omgs_fixture".as_ptr(),
                        std::ptr::null_mut(),
                        0,
                        0,
                        0,
                    )
                };
                #[cfg(target_os = "linux")]
                let result = unsafe {
                    libc::getxattr(
                        path.as_ptr(),
                        c"user.omgs_fixture".as_ptr(),
                        std::ptr::null_mut(),
                        0,
                    )
                };
                assert_eq!(result, -1, "source xattr must be absent");
            }
            assert_eq!(crate::proof_inputs::manifest(&dst, None).unwrap(), before);
        }
        std::fs::remove_dir_all(d).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn fresh_staging_never_transfers_source_acls_or_flags() {
        use std::os::macos::fs::MetadataExt;
        use std::os::unix::ffi::OsStrExt;
        let d = crate::platform::temp_root().unwrap().join(format!(
            "omgs-acl-{}",
            crate::platform::random_nonce().unwrap()
        ));
        let src = d.join("source");
        std::fs::create_dir_all(src.join("dir")).unwrap();
        std::fs::write(src.join("file"), b"bytes").unwrap();
        let before = crate::proof_inputs::manifest(&src, None).unwrap();
        let acl_listing = |path: &Path| {
            let out = Command::new("/bin/ls")
                .arg("-lde")
                .arg(path)
                .output()
                .unwrap();
            assert!(out.status.success());
            String::from_utf8(out.stdout)
                .unwrap()
                .lines()
                .skip(1)
                .any(|line| line.trim_start().starts_with("0:"))
        };
        for path in [&src, &src.join("dir"), &src.join("file")] {
            let status = Command::new("/bin/chmod")
                .args(["+a", "everyone allow read"])
                .arg(path)
                .status()
                .unwrap();
            assert!(status.success());
            assert!(acl_listing(path));
            let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::chflags(cpath.as_ptr(), libc::UF_HIDDEN) }, 0);
        }
        assert_eq!(crate::proof_inputs::manifest(&src, None).unwrap(), before);
        let dst = d.join("copy");
        copy_tree(&src, &dst).unwrap();
        for path in [&dst, &dst.join("dir"), &dst.join("file")] {
            assert!(!acl_listing(path));
            assert_eq!(std::fs::metadata(path).unwrap().st_flags(), 0);
        }
        assert_eq!(crate::proof_inputs::manifest(&dst, None).unwrap(), before);
        std::fs::remove_dir_all(d).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_file_directory_and_dangling_links_have_one_admission_policy() {
        let d = crate::platform::temp_root().unwrap().join(format!(
            "omgs-link-admission-{}",
            crate::platform::random_nonce().unwrap()
        ));
        let src = d.join("source");
        std::fs::create_dir_all(src.join("dir")).unwrap();
        std::fs::write(src.join("file"), b"bytes").unwrap();
        let src = std::fs::canonicalize(src).unwrap();
        for kind in ["file", "directory", "dangling", "junction"] {
            let link = src.join("link");
            let result = match kind {
                "junction" => link_dir(&src.join("dir"), &link),
                "directory" => std::os::windows::fs::symlink_dir("dir", &link),
                "file" => std::os::windows::fs::symlink_file("file", &link),
                _ => std::os::windows::fs::symlink_file("missing", &link),
            };
            if let Err(e) = result {
                // Windows symlinks need Developer Mode or SeCreateSymbolicLinkPrivilege.
                // Junctions always exercise directory reparse admission.
                if kind != "junction" && e.raw_os_error() == Some(1314) {
                    crate::out::err(&format!("{kind} symlink fixture unavailable: {e}"));
                    continue;
                }
                panic!("{kind}: {e}");
            }
            let validation = crate::proof_inputs::manifest(&src, None).unwrap_err();
            let staging = copy_tree(&src, &d.join(format!("copy-{kind}"))).unwrap_err();
            assert_eq!(staging, validation);
            assert!(staging.contains("unsupported execution input link on Windows"));
            if matches!(kind, "directory" | "junction") {
                std::fs::remove_dir(link).unwrap();
            } else {
                std::fs::remove_file(link).unwrap();
            }
        }
        std::fs::remove_dir_all(d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn noncanonical_target_names_are_refused_before_copying() {
        let base = crate::platform::temp_root().unwrap().join(format!(
            "omgs-names-{}",
            crate::platform::random_nonce().unwrap()
        ));
        let src = base.join("target");
        std::fs::create_dir_all(&src).unwrap();
        for name in [r"a\b", "a:b"] {
            let path = src.join(name);
            std::fs::write(&path, b"fixture").unwrap();
            let expected = crate::proof_inputs::manifest(&src, None).unwrap_err();
            assert!(expected.contains("canonical relative paths"));
            let dst = base.join("copy");
            assert_eq!(copy_tree(&src, &dst).unwrap_err(), expected);
            assert!(!dst.exists());
            std::fs::remove_file(path).unwrap();
        }
        std::fs::remove_dir_all(base).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn copies_content_and_skips_sockets_and_fifos() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        let d = PathBuf::from("/tmp").join(format!("omgs-c-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let src = d.join("target");
        let dst = d.join("copy");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("a"), b"hardlinked content").unwrap();
        std::fs::hard_link(src.join("a"), src.join("b")).unwrap();
        let data = vec![37u8; 8 << 20];
        std::fs::write(src.join("large"), &data).unwrap();
        std::fs::create_dir(src.join("dir")).unwrap();
        for (name, target) in [
            ("file-link", PathBuf::from("a")),
            ("directory-link", PathBuf::from("dir")),
            (
                "absolute-link",
                std::fs::canonicalize(src.join("a")).unwrap(),
            ),
            ("outside-link", d.join("outside")),
            ("dangling-link", PathBuf::from("missing")),
        ] {
            std::os::unix::fs::symlink(target, src.join(name)).unwrap();
        }
        std::fs::write(d.join("outside"), "outside").unwrap();
        let digest = crate::proof_inputs::manifest(&src, None).unwrap();
        copy_tree(&src, &dst).unwrap();
        let copied_digest = crate::proof_inputs::manifest(&dst, None).unwrap();
        assert_eq!(std::fs::read(dst.join("large")).unwrap(), data);
        assert_ne!(
            std::fs::metadata(dst.join("a")).unwrap().ino(),
            std::fs::metadata(dst.join("b")).unwrap().ino()
        );
        let fifo = src.join("pipe");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let start = std::time::Instant::now();
        let socket = std::os::unix::net::UnixListener::bind(src.join("socket")).unwrap();
        let special_copy = d.join("special-copy");
        let gaps = copy_tree_with_gaps(&src, &special_copy).unwrap();
        assert_eq!(gaps.len(), 4);
        assert!(
            gaps.iter().any(|g| g.starts_with("2 target link(s)")),
            "{gaps:?}"
        );
        for name in [
            "file-link",
            "directory-link",
            "absolute-link",
            "outside-link",
            "dangling-link",
        ] {
            assert_eq!(
                std::fs::read_link(dst.join(name)).unwrap(),
                std::fs::read_link(special_copy.join(name)).unwrap()
            );
        }
        for name in ["pipe", "socket"] {
            assert!(gaps.iter().any(|gap| gap.ends_with(name)), "{gaps:?}");
            assert!(!special_copy.join(name).exists());
        }
        assert_eq!(crate::proof_inputs::manifest(&src, None).unwrap(), digest);
        assert_eq!(
            crate::proof_inputs::manifest(&special_copy, None).unwrap(),
            copied_digest
        );
        assert!(crate::sha256::digest_file(&fifo).is_err());
        assert!(crate::sha256::digest_file(Path::new("/dev/zero")).is_err());
        std::os::unix::fs::symlink(&fifo, d.join("fifo-link")).unwrap();
        assert!(crate::sha256::digest_file(&d.join("fifo-link")).is_err());
        std::os::unix::fs::symlink(&src, d.join("dir-link")).unwrap();
        assert!(crate::sha256::digest_file(&d.join("dir-link")).is_err());
        assert!(start.elapsed().as_secs() < 10);
        drop(socket);
        std::fs::remove_dir_all(d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn copied_absolute_reentering_and_chained_links_disclose_live_target_access() {
        use std::os::unix::fs::symlink;
        let d = crate::platform::temp_root()
            .unwrap()
            .join(format!("omgs-live-links-{}", std::process::id()));
        let src = d.join("target");
        std::fs::create_dir_all(&src).unwrap();
        let src = std::fs::canonicalize(src).unwrap();
        std::fs::write(src.join("file"), "original").unwrap();
        symlink(src.join("file"), src.join("absolute")).unwrap();
        symlink("../target/file", src.join("reenter")).unwrap();
        symlink("absolute", src.join("chain")).unwrap();
        symlink("file", src.join("internal")).unwrap();
        for fallback in [false, true] {
            if fallback {
                use std::os::unix::ffi::OsStrExt;
                let name = std::ffi::CString::new(src.join("pipe").as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
            let dst = d.join(format!("copy-{fallback}"));
            let gaps = copy_tree_with_gaps(&src, &dst).unwrap();
            for link in ["absolute", "reenter", "chain"] {
                assert!(
                    gaps.contains(&format!(
                        "target link reaches live target from workspace: {link}"
                    )),
                    "{gaps:?}"
                );
                assert_eq!(
                    std::fs::canonicalize(dst.join(link)).unwrap(),
                    src.join("file")
                );
            }
            assert!(!gaps.iter().any(|g| g.ends_with(": internal")));
        }
        std::fs::remove_dir_all(d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn special_file_gaps_list_twenty_paths_then_the_remaining_count() {
        use std::os::unix::ffi::OsStrExt;
        let d = crate::platform::temp_root()
            .unwrap()
            .join(format!("omgs-gap-cap-{}", std::process::id()));
        let src = d.join("target");
        std::fs::create_dir_all(&src).unwrap();
        for n in (0..27).rev() {
            let path = src.join(format!("pipe-{n}"));
            let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        }
        let gaps = copy_tree_with_gaps(&src, &d.join("copy")).unwrap();
        assert_eq!(gaps.len(), 21);
        assert!(gaps[..20]
            .iter()
            .all(|g| g.starts_with("skipped target socket or FIFO: pipe-")));
        let mut expected: Vec<_> = (0..27)
            .map(|n| format!("skipped target socket or FIFO: pipe-{n}"))
            .collect();
        expected.sort();
        assert_eq!(gaps[..20], expected[..20]);
        assert_eq!(gaps[20], "skipped 7 additional target sockets or FIFOs");
        assert_eq!(std::fs::read_dir(d.join("copy")).unwrap().count(), 0);
        std::fs::remove_dir_all(d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn live_target_link_gaps_are_sorted_and_capped() {
        let d = crate::platform::temp_root()
            .unwrap()
            .join(format!("omgs-live-link-cap-{}", std::process::id()));
        let root = d.join("target");
        let copy = d.join("copy");
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        std::fs::create_dir_all(&copy).unwrap();
        std::fs::write(root.join("file"), "data").unwrap();
        let links: Vec<_> = (0..27)
            .rev()
            .map(|i| PathBuf::from(format!("link-{i:02}")))
            .collect();
        for link in &links {
            std::os::unix::fs::symlink(root.join("file"), copy.join(link)).unwrap();
        }
        let mut gaps = Vec::new();
        record_live_links(&root, &copy, &copy, &mut PathSummary::default(), &mut gaps).unwrap();
        assert_eq!(gaps.len(), 21);
        assert!(gaps[0].ends_with("link-00"));
        assert!(gaps[19].ends_with("link-19"));
        assert_eq!(
            gaps[20],
            "7 additional target links reach live target from workspace"
        );
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn invalid_commands_and_mxc_timeouts_are_refused() {
        for (command, timeout) in [
            ("", 100),
            ("  ", 100),
            ("echo ok", 0),
            ("echo ok", u64::from(u32::MAX) + 1),
        ] {
            assert!(validate_input(command, timeout).is_err());
        }
        assert!(validate_input("echo ok", u64::from(u32::MAX)).is_ok());
    }

    #[test]
    fn enumeration_retry_requires_a_clean_windows_executor_refusal() {
        let mut run = supervise::Supervised {
            exit_code: None,
            executor_exit_code: None,
            command_started: false,
            command_finished: false,
            test_reachable: None,
            boundary_marker_seen: false,
            authorized_control_seen: false,
            marker_observations: vec![],
            stream_bytes: [0; 2],
            retained_stream_bytes: [0; 2],
            decoded_capture_bytes: 0,
            enumerate_rejected: true,
            executor_error: true,
            killed: false,
            interrupted: false,
            success: false,
            timed_out: false,
            duration_ms: 1,
            output: String::new(),
            stdout: String::new(),
            stdout_bytes: Vec::new(),
            output_bytes_total: 0,
            capture_complete: true,
            cleanup_complete: true,
            survivors: vec![],
            enforced: vec![],
            notes: vec![],
        };
        assert!(retry_without_enumeration("windows", &run));
        assert!(!retry_without_enumeration("linux", &run));
        run.command_started = true;
        assert!(!retry_without_enumeration("windows", &run));
        run.command_started = false;
        run.cleanup_complete = false;
        assert!(!retry_without_enumeration("windows", &run));
        run.cleanup_complete = true;
        run.capture_complete = false;
        assert!(!retry_without_enumeration("windows", &run));
        run.capture_complete = true;
        run.timed_out = true;
        assert!(!retry_without_enumeration("windows", &run));
    }

    #[cfg(windows)]
    #[test]
    fn augmentation_refusal_never_constructs_a_config_invocation() {
        let Ok(located) = locate_executor() else {
            return;
        };
        let probe = windows_probe(&located.path).unwrap();
        if probe.needs_dacl_augmentation != Some(true) {
            return;
        }
        let d = crate::platform::temp_root()
            .unwrap()
            .join(format!("omgs-refusal-no-config-{}", std::process::id()));
        let before = preflight::config_invocations();
        let request = ProveRequest {
            screenshots: false,
            expect_marker: None,
            command: "echo must-not-run".into(),
            test: None,
            timeout_ms: 1000,
            target: None,
            run_dir: d.clone(),
            tier: Tier::Test,
            stage: None,
            expected_tree_sha256: None,
            inputs: None,
            expected_inputs: None,
            harness: vec![],
        };
        let ProveOutcome::Blocked { reason } = prove(&request) else {
            panic!("augmented tier ran");
        };
        assert!(reason.contains("MXC 1.0.1 leaves changed ACEs"));
        assert!(!d.exists());
        assert_eq!(preflight::config_invocations(), before);
    }

    #[cfg(windows)]
    #[test]
    fn readable_root_overlap_uses_canonical_case_insensitive_paths() {
        let d = crate::platform::temp_root()
            .unwrap()
            .join(format!("OmGs-Overlap-{}", std::process::id()));
        let root = d.join("Toolchain");
        let run = root.join("proofs/1");
        std::fs::create_dir_all(&run).unwrap();
        let canonical = std::fs::canonicalize(&run).unwrap();
        let readable = vec![PathBuf::from(root.to_string_lossy().to_lowercase())];
        assert!(overlapping_root(&canonical, &readable).is_some());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn junctions_accept_metacharacters_without_a_shell_and_staging_refuses_them() {
        let d = crate::platform::temp_root()
            .unwrap()
            .join(format!("omgs-junction-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let to = d.join("cache & echo injected ^ % ! (x)");
        let link = d.join("link & echo injected ^ % ! (x)");
        std::fs::create_dir_all(&to).unwrap();
        std::fs::write(to.join("file"), b"content").unwrap();
        link_dir(&to, &link).unwrap();
        assert_eq!(std::fs::read(link.join("file")).unwrap(), b"content");
        assert!(platform::is_link(
            &std::fs::symlink_metadata(&link).unwrap()
        ));
        assert!(stage_file(
            &d,
            &format!("{}/new", link.file_name().unwrap().to_string_lossy()),
            &to.join("file")
        )
        .is_err());
        assert!(!to.join("new").exists());
        let _ = std::fs::remove_dir_all(d);
    }

    #[cfg(unix)]
    #[test]
    fn staging_never_writes_through_a_link_in_the_target() {
        let d = crate::platform::temp_root()
            .unwrap()
            .join(format!("omgs-stage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let (ws, outside) = (d.join("ws"), d.join("outside"));
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let draft = d.join("draft");
        std::fs::write(&draft, b"test").unwrap();
        std::os::unix::fs::symlink(&outside, ws.join("tests")).unwrap();
        assert!(stage_file(&ws, "tests/x.sh", &draft).is_err());
        std::os::unix::fs::symlink(outside.join("f"), ws.join("f.sh")).unwrap();
        assert!(stage_file(&ws, "f.sh", &draft).is_err());
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none());
        assert!(stage_file(&ws, "a/b/c.sh", &draft).is_ok());
        std::fs::write(ws.join("existing.sh"), b"old").unwrap();
        assert!(stage_file(&ws, "existing.sh", &draft).is_err());
        assert_eq!(std::fs::read(ws.join("existing.sh")).unwrap(), b"old");
        assert!(stage_file(&ws, "../x", &draft).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn harness_preflight_rejects_all_collisions_and_portable_aliases_before_writes() {
        let base = crate::platform::temp_root().unwrap().join(format!(
            "omgs-harness-preflight-{}",
            crate::platform::random_nonce().unwrap()
        ));
        crate::platform::create_private_tree(&base).unwrap();
        let ws = base.join("workspace");
        crate::platform::private_dir(&ws).unwrap();
        std::fs::write(ws.join("security.sh"), "ORIGINAL").unwrap();
        std::fs::create_dir(ws.join("checks")).unwrap();
        for path in [
            "security.sh",
            "SECURITY.SH",
            "security.sh/child",
            "checks",
            ".git/config",
            ".omgs-wrapper",
            "securi~1.sh",
            "x\\security.sh",
            "x:stream",
            "security.sh.",
            "security.sh ",
            "CON",
            "NUL.txt",
            "COM1.sh",
            "caf\u{e9}/entry.sh",
            "cafe\u{301}/entry.sh",
        ] {
            assert!(
                preflight_harness(&ws, &["entry.sh", path]).is_err(),
                "{path}"
            );
            assert!(!ws.join("entry.sh").exists());
            assert_eq!(std::fs::read(ws.join("security.sh")).unwrap(), b"ORIGINAL");
        }
        for paths in [
            vec!["new/a.sh", "NEW/b.sh"],
            vec!["new/a.sh", "new/A.sh"],
            vec!["new", "new/a.sh"],
            vec!["new/a.sh", "new"],
        ] {
            assert!(preflight_harness(&ws, &paths).is_err(), "{paths:?}");
        }
        assert!(preflight_harness(
            &ws,
            &["new/entry.sh", "new/nested/helper.sh", "checks/new.sh"]
        )
        .is_ok());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("missing", ws.join("dangling")).unwrap();
            assert!(preflight_harness(&ws, &["dangling/entry.sh"]).is_err());
        }
        let request = ProveRequest {
            screenshots: false,
            command: "never executed".into(),
            expect_marker: None,
            test: Some("entry.sh".into()),
            timeout_ms: 1000,
            target: Some(ws.clone()),
            run_dir: base.join("proof"),
            tier: Tier::Test,
            stage: None,
            expected_tree_sha256: None,
            inputs: None,
            expected_inputs: None,
            harness: ["entry.sh", "security.sh"]
                .into_iter()
                .map(|path| crate::proof::HarnessFile {
                    path: path.into(),
                    sha256: crate::sha256::digest(b"replacement"),
                    mode: 0,
                })
                .collect(),
        };
        let copied = base.join("copy");
        let result = stage_workspace(&request, &copied, &base.join("scratch"), &[], "nonce");
        assert!(matches!(result, Err(e) if e.contains("harness destination collides")));
        assert!(!copied.join("entry.sh").exists());
        assert_eq!(
            std::fs::read(copied.join("security.sh")).unwrap(),
            b"ORIGINAL"
        );
        std::fs::write(ws.join("caf\u{e9}"), "unicode").unwrap();
        assert!(preflight_harness(&ws, &["fresh/entry.sh"]).is_err());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn run_directories_inside_readable_roots_are_refused() {
        let roots = vec![PathBuf::from("/home/u/.cargo/bin"), PathBuf::from("/opt")];
        assert!(overlapping_root(Path::new("/home/u/.cargo/bin/omgs/run"), &roots).is_some());
        assert!(overlapping_root(Path::new("/opt/x"), &roots).is_some());
        assert!(overlapping_root(Path::new("/home/u"), &roots).is_some());
        assert!(overlapping_root(Path::new("/home/u/.local/share/omgs/run"), &roots).is_none());
        #[cfg(target_os = "macos")]
        assert!(overlapping_root(Path::new("/system/volumes/data/OPT/x"), &roots).is_some());
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
