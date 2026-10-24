use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Sandbox backends in priority order: an explicitly configured MXC
/// executor, then OS native sandboxing (Seatbelt on macOS, bubblewrap on
/// Linux). OMGS fails closed when no backend is available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    Mxc(PathBuf),
    Seatbelt,
    Bubblewrap(PathBuf),
}

impl Backend {
    pub fn label(&self) -> String {
        match self {
            Backend::Mxc(p) => format!("MXC executor {}", p.display()),
            Backend::Seatbelt => "Seatbelt (sandbox-exec), network denied".into(),
            Backend::Bubblewrap(p) => {
                format!("bubblewrap {}, network namespace denied", p.display())
            }
        }
    }
}

fn which(name: &str) -> Option<PathBuf> {
    let out = Command::new("which").arg(name).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(PathBuf::from(text))
    }
}

pub fn find_backend() -> Option<Backend> {
    if let Ok(path) = std::env::var("OMGS_MXC_EXEC") {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(Backend::Mxc(p));
        }
    }
    for name in ["wxc-exec", "wxc-exec.exe", "mxc-exec"] {
        if let Some(p) = which(name) {
            return Some(Backend::Mxc(p));
        }
    }
    if cfg!(target_os = "macos") && Path::new("/usr/bin/sandbox-exec").exists() {
        return Some(Backend::Seatbelt);
    }
    if cfg!(target_os = "linux") {
        if let Some(p) = which("bwrap") {
            return Some(Backend::Bubblewrap(p));
        }
    }
    None
}

pub struct ProveRequest {
    pub command: String,
    pub timeout_ms: u64,
    pub cwd: Option<PathBuf>,
    pub scratch: PathBuf,
}

pub enum ProveOutcome {
    BlockedNoSandbox {
        request_json: String,
    },
    Ran {
        backend: String,
        success: bool,
        timed_out: bool,
        output: String,
    },
}

fn request_json(req: &ProveRequest) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "command": req.command,
        "network": { "egress": { "default": "deny" } },
        "timeoutMs": req.timeout_ms,
        "omgs_policy": {
            "target_access": "read_only",
            "writes": "scratch_only",
            "environment": "empty_allowlist",
            "network": "denied"
        }
    }))
    .unwrap_or_default()
}

/// Terminate the sandboxed command and any descendants. The command is its own
/// process-group leader (see base_env), so signalling the negative pid reaches
/// grandchildren a bare child.kill() would leave running and holding the pipes.
#[cfg(unix)]
fn kill_group(child: &mut Child) {
    let group = format!("-{}", child.id());
    let _ = Command::new("/bin/kill").arg("-TERM").arg(&group).status();
    std::thread::sleep(Duration::from_millis(200));
    let _ = Command::new("/bin/kill").arg("-KILL").arg(&group).status();
    let _ = child.kill();
}

#[cfg(not(unix))]
fn kill_group(child: &mut Child) {
    let _ = child.kill();
}

fn run_with_timeout(mut child: Child, timeout_ms: u64) -> (bool, bool, String) {
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let out_thread = std::thread::spawn(move || {
        let mut s = String::new();
        if let Some(mut r) = stdout.take() {
            let _ = r.read_to_string(&mut s);
        }
        s
    });
    let err_thread = std::thread::spawn(move || {
        let mut s = String::new();
        if let Some(mut r) = stderr.take() {
            let _ = r.read_to_string(&mut s);
        }
        s
    });
    let start = Instant::now();
    let mut timed_out = false;
    let success = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) => {
                if start.elapsed() > Duration::from_millis(timeout_ms) {
                    timed_out = true;
                    kill_group(&mut child);
                    let _ = child.wait();
                    break false;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break false,
        }
    };
    let mut output = out_thread.join().unwrap_or_default();
    output.push_str(&err_thread.join().unwrap_or_default());
    (success, timed_out, output)
}

fn base_env(cmd: &mut Command, scratch: &Path) {
    cmd.env_clear()
        .env("HOME", scratch)
        .env("TMPDIR", scratch)
        .env(
            "PATH",
            "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        )
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Run the sandboxed command as its own process-group leader so a timeout
    // can signal the whole group, not just the immediate child.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
}

/// MXC 1.0.0 one-shot config for wxc-exec style executors. Verified live
/// against MXC SDK v1.0.0 release binaries on Windows: an empty env array is
/// rejected there, so the required presence-only variables point at scratch.
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

pub fn mxc_config_json(req: &ProveRequest, scratch: &Path, cwd: &Path) -> String {
    let scratch_s = mxc_path(scratch);
    let env: Vec<String> = if cfg!(windows) {
        vec![
            format!(
                "SYSTEMROOT={}",
                std::env::var("SYSTEMROOT").unwrap_or_else(|_| "C:\\Windows".into())
            ),
            format!("LOCALAPPDATA={scratch_s}"),
            format!("TEMP={scratch_s}"),
            format!("TMP={scratch_s}"),
            "PATH=C:\\Windows\\System32;C:\\Windows;C:\\Program Files\\PowerShell\\7".into(),
        ]
    } else {
        vec![
            format!("HOME={scratch_s}"),
            format!("TMPDIR={scratch_s}"),
            "PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".into(),
            "LANG=C.UTF-8".into(),
        ]
    };
    let mut readonly = Vec::new();
    if cwd != scratch {
        readonly.push(mxc_path(cwd));
    }
    let mut config = serde_json::json!({
        "version": "1.0.0",
        "containment": "process",
        "process": {
            "commandLine": req.command,
            "cwd": mxc_path(cwd),
            "timeout": req.timeout_ms,
            "env": env
        },
        "network": {
            "egress": { "default": "deny" },
            "ingress": { "default": "deny", "hostLoopback": "deny" }
        },
        "filesystem": {
            "readwritePaths": [scratch_s],
            "readonlyPaths": readonly
        },
        // Windows console hosts such as pwsh fail DLL init when Win32k is
        // fully blocked. Allow the UI subsystem, never input or clipboard.
        "ui": { "disable": false, "injection": false, "clipboard": "none" }
    });
    if cfg!(windows) {
        config["processContainer"] = serde_json::json!({ "ui": { "isolation": "desktop" } });
    }
    serde_json::to_string_pretty(&config).unwrap_or_default()
}

pub fn prove(req: &ProveRequest) -> ProveOutcome {
    let Some(backend) = find_backend() else {
        return ProveOutcome::BlockedNoSandbox {
            request_json: request_json(req),
        };
    };
    let label = backend.label();
    let _ = std::fs::create_dir_all(&req.scratch);
    // Seatbelt matches canonical paths, so resolve symlinks like /tmp first.
    let scratch = std::fs::canonicalize(&req.scratch).unwrap_or_else(|_| req.scratch.clone());
    let cwd = req
        .cwd
        .clone()
        .map(|p| std::fs::canonicalize(&p).unwrap_or(p))
        .unwrap_or_else(|| scratch.clone());
    let mut cmd = match &backend {
        Backend::Mxc(executor) => {
            let config_path = scratch.join("omgs-mxc-config.json");
            if let Err(e) = std::fs::write(&config_path, mxc_config_json(req, &scratch, &cwd)) {
                return ProveOutcome::Ran {
                    backend: label,
                    success: false,
                    timed_out: false,
                    output: format!("failed to write MXC config: {e}"),
                };
            }
            let mut c = Command::new(executor);
            c.args(["--config", &config_path.to_string_lossy()]);
            c.stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            c
        }
        Backend::Seatbelt => {
            let scratch_str = scratch.to_string_lossy().replace('"', "");
            // Seatbelt is last-match-wins. Target build and test tooling needs
            // broad file-read and process-exec, so those stay open, but network
            // is denied, writes are confined to scratch, and the daemons that
            // let sandboxed code mutate the host out of band are denied by name:
            // cfprefsd (preferences), LaunchServices/coreservicesd, distributed
            // and local notifications, mDNSResponder, and AppleEvents. This
            // closes the observed cfprefsd write escape without breaking builds.
            let profile = format!(
                "(version 1)(allow default)(deny network*)(deny mach-register)(deny mach-lookup (global-name \"com.apple.cfprefsd.daemon\") (global-name \"com.apple.cfprefsd.agent\") (global-name \"com.apple.launchservicesd\") (global-name \"com.apple.coreservices.launchservicesd\") (global-name \"com.apple.CoreServices.coreservicesd\") (global-name \"com.apple.distributed_notifications@1v3\") (global-name \"com.apple.system.notification_center\") (global-name \"com.apple.mDNSResponder\") (global-name \"com.apple.coreservices.appleevents\"))(deny file-write*)(allow file-write* (subpath \"{scratch_str}\") (literal \"/dev/null\") (literal \"/dev/tty\"))"
            );
            let mut c = Command::new("/usr/bin/sandbox-exec");
            c.args(["-p", &profile, "/bin/sh", "-c", &req.command]);
            base_env(&mut c, &scratch);
            c.current_dir(&cwd);
            c
        }
        Backend::Bubblewrap(bwrap) => {
            // Isolate namespaces and mask the writable host dirs. The root bind
            // stays read-only and broad so arbitrary toolchains still resolve;
            // narrowing it to an explicit path set needs validation on a real
            // Linux host and is deferred. Network is off via --unshare-all.
            let mut c = Command::new(bwrap);
            c.args([
                "--unshare-all",
                "--new-session",
                "--die-with-parent",
                "--ro-bind",
                "/",
                "/",
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "--tmpfs",
                "/tmp",
                "--tmpfs",
                "/run",
                "--tmpfs",
                "/var/run",
                "--bind",
                &scratch.to_string_lossy(),
                &scratch.to_string_lossy(),
                "--chdir",
                &cwd.to_string_lossy(),
                "/bin/sh",
                "-c",
                &req.command,
            ]);
            base_env(&mut c, &scratch);
            c
        }
    };
    match cmd.spawn() {
        Ok(child) => {
            let (success, timed_out, output) = run_with_timeout(child, req.timeout_ms);
            ProveOutcome::Ran {
                backend: label,
                success,
                timed_out,
                output,
            }
        }
        Err(e) => ProveOutcome::Ran {
            backend: label,
            success: false,
            timed_out: false,
            output: format!("failed to start sandbox backend: {e}"),
        },
    }
}
