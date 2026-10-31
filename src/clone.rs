//! Review clones: Git runs with no inherited configuration except the
//! credential and generic proxy or CA settings a private repository needs,
//! so the user's URL rewrites, URL-specific HTTP settings, attribute files,
//! templates and auxiliary download mechanisms cannot move or extend the
//! clone. Every step shares one deadline.
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// Git's well-known empty tree, the attribute source for review clones.
pub const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
/// Review clones rely on `--attr-source`, added in Git 2.42.
pub const MIN_GIT: (u32, u32) = (2, 42);
const STEP_MS: u64 = 5_000;
const RESOLVE_MS: u64 = 30_000;

/// Host environment a clone keeps: process basics, home directories that
/// credential helpers read, proxies and CA bundles. Everything else,
/// including GIT_CONFIG_* injection, is dropped.
const ENV_KEEP: [&str; 29] = [
    "PATH",
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "XDG_CONFIG_HOME",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
    "SystemRoot",
    "WINDIR",
    "SYSTEMDRIVE",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "GIT_SSL_CAINFO",
    "GIT_SSL_CAPATH",
    "GIT_ASKPASS",
];

/// One shared deadline for a whole clone transaction.
#[derive(Clone, Copy)]
pub struct Deadline(Instant);

impl Deadline {
    pub fn after(ms: u64) -> Self {
        Self(Instant::now() + Duration::from_millis(ms))
    }
    /// Milliseconds left, capped at `cap`; an error once the deadline passed.
    pub fn left(&self, cap: u64) -> Result<u64, String> {
        let left = self
            .0
            .checked_duration_since(Instant::now())
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if left == 0 {
            return Err("clone deadline exceeded".into());
        }
        Ok(left.min(cap))
    }
}

fn null_device() -> &'static str {
    if cfg!(windows) {
        "NUL"
    } else {
        "/dev/null"
    }
}

/// Parse `git config --null --get-regexp` output: records end with NUL and
/// hold `key` or `key\nvalue`.
pub fn parse_config_null(bytes: &[u8]) -> Vec<(String, Option<String>)> {
    bytes
        .split(|b| *b == 0)
        .filter(|r| !r.is_empty())
        .filter_map(|record| {
            let text = std::str::from_utf8(record).ok()?;
            Some(match text.split_once('\n') {
                Some((k, v)) => (k.to_string(), Some(v.to_string())),
                None => (text.to_string(), None),
            })
        })
        .collect()
}

/// Settings carried into the isolated clone: every credential setting and
/// only the generic (never URL-specific) proxy and CA settings.
pub fn carried(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.starts_with("credential.")
        || [
            "http.proxy",
            "http.sslcainfo",
            "http.sslcapath",
            "http.sslbackend",
            "http.schannelcheckrevoke",
            "http.schannelusesslcainfo",
        ]
        .contains(&key.as_str())
}

fn bounded(mut cmd: Command, deadline: &Deadline, cap: u64) -> Result<Vec<u8>, String> {
    let wall_ms = deadline.left(cap)?;
    let result = crate::supervise::run(
        {
            cmd.stdin(std::process::Stdio::null());
            cmd
        },
        &crate::supervise::Limits {
            wall_ms,
            cpu_secs: None,
            file_size_bytes: None,
            open_files: None,
            memory_bytes: None,
            tasks: None,
            output_cap_bytes: 1 << 20,
        },
        None,
    );
    if result.interrupted {
        return Err("clone interrupted".into());
    }
    if result.timed_out {
        return Err("clone deadline exceeded".into());
    }
    // A drained stream can still have been cut at the cap; parsing a
    // truncated configuration could drop a later reset of a setting.
    if !result.capture_complete || result.stdout_bytes.len() as u64 != result.stream_bytes[0] {
        return Err("git output exceeded its limit".into());
    }
    match result.exit_code {
        Some(0) | Some(1) => Ok(result.stdout_bytes),
        _ => Err("git configuration read failed".into()),
    }
}

/// The user's system and global credential, proxy and CA settings, read in
/// Git's own order. Repository-local configuration is never consulted.
pub fn carried_config(
    git: &Path,
    deadline: &Deadline,
) -> Result<Vec<(String, Option<String>)>, String> {
    let mut out = Vec::new();
    for scope in ["--system", "--global"] {
        // Git finds the normal system and global files from HOME and
        // XDG_CONFIG_HOME; caller overrides of either source are dropped.
        let mut cmd = host_git(git);
        cmd.args([
            "config",
            scope,
            "--includes",
            "--null",
            "--get-regexp",
            r"^(credential\..*|http\.[a-z]+)$",
        ]);
        let bytes = bounded(cmd, deadline, STEP_MS)?;
        if bytes.last().is_some_and(|b| *b != 0) {
            return Err("git configuration output ended inside a record".into());
        }
        out.extend(
            parse_config_null(&bytes)
                .into_iter()
                .filter(|(k, _)| carried(k)),
        );
    }
    Ok(out)
}

/// `git version 2.47.1` (with vendor suffixes) meets the minimum.
pub fn version_ok(text: &str) -> bool {
    let version = text.split_whitespace().nth(2).unwrap_or_default();
    let mut parts = version.split('.').map(|p| {
        p.chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse::<u32>()
            .unwrap_or(0)
    });
    (parts.next().unwrap_or(0), parts.next().unwrap_or(0)) >= MIN_GIT
}

pub fn require_git(git: &Path, deadline: &Deadline) -> Result<(), String> {
    let mut cmd = host_git(git);
    cmd.arg("--version");
    let out = bounded(cmd, deadline, STEP_MS)?;
    let text = String::from_utf8_lossy(&out);
    if !version_ok(&text) {
        return Err(format!(
            "review clones need Git {}.{} or later to keep repository attributes from selecting filters; found {}",
            MIN_GIT.0,
            MIN_GIT.1,
            crate::platform::escape_controls(text.trim())
        ));
    }
    Ok(())
}

/// Resolve on a helper thread so a stalled resolver cannot outlive the
/// deadline or keep the clone lock held.
pub fn resolve(host: &str, deadline: &Deadline) -> Result<Vec<IpAddr>, String> {
    let wait = Duration::from_millis(deadline.left(RESOLVE_MS)?);
    let (tx, rx) = std::sync::mpsc::channel();
    let name = host.to_string();
    std::thread::spawn(move || {
        let _ = tx.send(crate::batch::public_addresses(&name));
    });
    rx.recv_timeout(wait)
        .map_err(|_| format!("resolving {host} exceeded the clone deadline"))?
}

/// The resolve pin for `http.curloptResolve`.
pub fn pin(host: &str, addrs: &[IpAddr]) -> String {
    let list = addrs
        .iter()
        .map(|ip| match ip {
            IpAddr::V6(v6) => format!("[{v6}]"),
            IpAddr::V4(v4) => v4.to_string(),
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{host}:443:{list}")
}

/// A Git command with only the kept host environment, so GIT_CONFIG_*,
/// GIT_TRACE* and every other Git variable from the caller are dropped.
fn host_git(git: &Path) -> Command {
    let mut c = Command::new(git);
    c.env_clear();
    for (key, value) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if ENV_KEEP.contains(&name.as_ref()) || name.starts_with("GCM_") {
            c.env(&key, value);
        }
    }
    c
}

/// An isolated Git command for a review clone.
pub fn git(git: &Path, carried: &[(String, Option<String>)], pin: Option<&str>) -> Command {
    let mut c = host_git(git);
    c.env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", null_device())
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .arg(format!("--attr-source={EMPTY_TREE}"));
    for (key, value) in carried {
        c.arg("-c").arg(match value {
            Some(v) => format!("{key}={v}"),
            None => key.clone(),
        });
    }
    for setting in [
        format!("core.attributesFile={}", null_device()),
        format!("core.hooksPath={}", null_device()),
        "core.fsmonitor=false".into(),
        "protocol.allow=never".into(),
        "protocol.https.allow=always".into(),
        "http.followRedirects=false".into(),
        "fetch.uriProtocols=".into(),
        "transfer.bundleURI=false".into(),
    ] {
        c.arg("-c").arg(setting);
    }
    if let Some(pin) = pin {
        c.arg("-c").arg(format!("http.curloptResolve={pin}"));
    }
    c
}

/// An empty template directory, so no user or system template can add
/// attributes, hooks or configuration to the new repository.
pub fn empty_template(targets: &Path) -> Result<PathBuf, String> {
    let dir = targets.join(".omgs-empty-git-template");
    crate::platform::private_dir(&dir).map_err(|e| e.to_string())?;
    let meta = std::fs::symlink_metadata(&dir).map_err(|e| e.to_string())?;
    if crate::platform::is_link(&meta) || !meta.is_dir() {
        return Err("clone template directory is not a plain directory".into());
    }
    if std::fs::read_dir(&dir)
        .map_err(|e| e.to_string())?
        .next()
        .is_some()
    {
        return Err(format!(
            "clone template directory {} must stay empty",
            dir.display()
        ));
    }
    Ok(dir)
}

/// Read `origin` of an existing clone under the same isolation and deadline.
pub fn origin(git_path: &Path, dest: &Path, deadline: &Deadline) -> Option<String> {
    let mut cmd = git(git_path, &[], None);
    cmd.arg("-C")
        .arg(dest)
        .args(["remote", "get-url", "origin"]);
    bounded(cmd, deadline, STEP_MS)
        .ok()
        .map(|o| String::from_utf8_lossy(&o).trim().to_string())
        .filter(|o| !o.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_records_parse_and_only_safe_keys_are_carried() {
        let parsed = parse_config_null(
            b"credential.helper\nosxkeychain\0credential.https://example.com.username\nalice\0http.proxy\nhttp://proxy.example:3128\0credential.usehttppath\0",
        );
        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed[3], ("credential.usehttppath".into(), None));
        for key in [
            "credential.helper",
            "credential.https://example.com.helper",
            "http.proxy",
            "http.sslCAInfo",
        ] {
            assert!(carried(key), "{key}");
        }
        for key in [
            "http.followredirects",
            "http.https://example.com.followredirects",
            "http.curloptresolve",
            "url.https://internal.example/.insteadof",
            "core.attributesfile",
            "fetch.uriprotocols",
            "filter.lfs.smudge",
            "init.templatedir",
            "protocol.file.allow",
        ] {
            assert!(!carried(key), "{key}");
        }
    }

    #[test]
    fn git_versions_are_compared_numerically() {
        assert!(version_ok("git version 2.42.0"));
        assert!(version_ok("git version 2.54.0 (Apple Git-157)"));
        assert!(version_ok("git version 2.47.1.windows.2"));
        assert!(version_ok("git version 3.0.0"));
        assert!(!version_ok("git version 2.41.9"));
        assert!(!version_ok("git version 2.9.5"));
        assert!(!version_ok("not git"));
    }

    #[test]
    fn pins_bracket_ipv6_and_list_every_address() {
        let addrs: Vec<IpAddr> = vec![
            "140.82.112.3".parse().unwrap(),
            "2606:50c0::153".parse().unwrap(),
        ];
        assert_eq!(
            pin("github.com", &addrs),
            "github.com:443:140.82.112.3,[2606:50c0::153]"
        );
    }

    #[test]
    fn isolated_git_drops_config_injection_and_sets_every_safeguard() {
        let carried = vec![("credential.helper".to_string(), Some("store".to_string()))];
        let cmd = git(Path::new("git"), &carried, Some("example.com:443:1.1.1.1"));
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args[0], format!("--attr-source={EMPTY_TREE}"));
        for want in [
            "credential.helper=store",
            "protocol.allow=never",
            "protocol.https.allow=always",
            "http.followRedirects=false",
            "fetch.uriProtocols=",
            "transfer.bundleURI=false",
            "core.fsmonitor=false",
            "http.curloptResolve=example.com:443:1.1.1.1",
        ] {
            assert!(args.iter().any(|a| a == want), "{want}: {args:?}");
        }
        // Safeguards follow carried settings, so a carried value cannot override them.
        let carried_at = args
            .iter()
            .position(|a| a == "credential.helper=store")
            .unwrap();
        let redirect_at = args
            .iter()
            .position(|a| a == "http.followRedirects=false")
            .unwrap();
        assert!(carried_at < redirect_at);
        let envs: Vec<(String, Option<String>)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        let env = |k: &str| {
            envs.iter()
                .find(|(name, _)| name == k)
                .and_then(|(_, v)| v.clone())
        };
        assert_eq!(env("GIT_CONFIG_NOSYSTEM").as_deref(), Some("1"));
        assert_eq!(env("GIT_CONFIG_GLOBAL").as_deref(), Some(null_device()));
        assert_eq!(env("GIT_ATTR_NOSYSTEM").as_deref(), Some("1"));
        assert!(env("GIT_CONFIG_PARAMETERS").is_none());
        assert!(env("GIT_CONFIG_COUNT").is_none());
    }

    // Real Git: a hostile global configuration reaches none of the
    // transport, attribute or filter settings of an isolated command.
    #[test]
    fn isolated_git_ignores_the_users_global_configuration() {
        let Some(git_path) = crate::platform::which("git") else {
            eprintln!("skipping: git not found");
            return;
        };
        let home = crate::platform::temp_root().unwrap().join(format!(
            "omgs-clone-iso-{}",
            crate::platform::random_nonce().unwrap()
        ));
        crate::platform::create_private_dir_new(&home).unwrap();
        std::fs::write(
            home.join(".gitconfig"),
            "[url \"https://internal.example/\"]\n\tinsteadOf = https://github.com/\n[http \"https://github.com/\"]\n\tfollowRedirects = true\n[core]\n\tattributesFile = /tmp/attrs\n[filter \"lfs\"]\n\tsmudge = git-lfs smudge %f\n[fetch]\n\turiProtocols = https\n[credential]\n\thelper = store\n",
        )
        .unwrap();
        let mut cmd = git(&git_path, &[], None);
        cmd.env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join("xdg"))
            .current_dir(&home)
            .args(["config", "--list"]);
        let out = cmd.output().unwrap();
        let listed = String::from_utf8_lossy(&out.stdout).to_lowercase();
        for absent in [
            "insteadof",
            "followredirects=true",
            "attributesfile=/tmp/attrs",
            "filter.lfs",
            "uriprotocols=https",
            "credential.helper=store",
        ] {
            assert!(!listed.contains(absent), "{absent}: {listed}");
        }
        for present in [
            "http.followredirects=false",
            "protocol.allow=never",
            "fetch.uriprotocols=",
        ] {
            assert!(listed.contains(present), "{present}: {listed}");
        }
        std::fs::remove_dir_all(home).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn configuration_output_cut_at_the_cap_is_refused() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "head -c 1100000 /dev/zero"]);
        let err = bounded(cmd, &Deadline::after(10_000), STEP_MS).unwrap_err();
        assert!(err.contains("exceeded its limit"), "{err}");
    }

    #[test]
    fn a_passed_deadline_stops_every_step() {
        let deadline = Deadline::after(0);
        std::thread::sleep(Duration::from_millis(2));
        assert!(deadline.left(1000).is_err());
        assert!(resolve("example.com", &deadline).is_err());
    }
}
