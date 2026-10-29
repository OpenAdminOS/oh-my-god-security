//! Best-effort release notification. Never downloads assets or changes files.
use crate::supervise::{self, Limits};
use std::ffi::{OsStr, OsString};
use std::process::Command;

const REMOTE: &str = "https://github.com/OpenAdminOS/oh-my-god-security.git";
const OUTPUT_CAP: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Version([u64; 3]);

impl Version {
    fn parse(raw: &str) -> Option<Self> {
        let parts: Vec<_> = raw.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        let mut numbers = [0; 3];
        for (number, part) in numbers.iter_mut().zip(parts) {
            if part.is_empty()
                || !part.bytes().all(|b| b.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
            {
                return None;
            }
            *number = part.parse().ok()?;
        }
        Some(Self(numbers))
    }
}

fn latest_tag(output: &str) -> Option<Version> {
    let mut latest = None;
    for line in output.lines() {
        let (oid, reference) = line.split_once('\t')?;
        if ![40, 64].contains(&oid.len()) || !oid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        if reference.ends_with("^{}") {
            continue;
        }
        if let Some(version) = reference
            .strip_prefix("refs/tags/v")
            .and_then(Version::parse)
        {
            latest = Some(latest.map_or(version, |previous: Version| previous.max(version)));
        }
    }
    latest
}

fn lookup_command(remote: &OsStr) -> Option<Command> {
    if remote.is_empty() {
        return None;
    }
    let git = crate::platform::which("git")?;
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let mut command = Command::new(git);
    command.env_clear();
    for key in ["PATH", "SystemRoot", "WINDIR", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    // Ignore repository, system, global and environment-injected configuration.
    // A null home also prevents libcurl from finding stored .netrc credentials.
    // ls-remote with an explicit URL works without a valid local Git directory.
    command
        .env("HOME", null)
        .env("USERPROFILE", null)
        .env("XDG_CONFIG_HOME", null)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", null)
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            &format!("--git-dir={null}"),
            "-c",
            "credential.helper=",
            "-c",
            "core.askPass=",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
            "-c",
            "protocol.file.allow=always",
            "ls-remote",
            "--tags",
            "--",
        ])
        .arg(remote)
        .arg("refs/tags/v*");
    Some(command)
}

/// One bounded Git lookup, with no output on any failure. The caller decides
/// whether to print the informational line; this never authorizes an install.
pub fn check() -> Option<String> {
    let current = Version::parse(env!("CARGO_PKG_VERSION"))?;
    let remote = std::env::var_os("OMGS_UPDATE_REMOTE").unwrap_or_else(|| OsString::from(REMOTE));
    let command = lookup_command(&remote)?;
    let result = supervise::run(
        command,
        &Limits {
            wall_ms: 3_000,
            cpu_secs: None,
            file_size_bytes: None,
            open_files: None,
            memory_bytes: None,
            tasks: None,
            output_cap_bytes: OUTPUT_CAP,
        },
        None,
    );
    if !result.success
        || !result.capture_complete
        || !result.cleanup_complete
        || result.output_bytes_total > OUTPUT_CAP as u64
    {
        return None;
    }
    let latest = latest_tag(std::str::from_utf8(&result.stdout_bytes).ok()?)?;
    let message = if latest > current {
        let [major, minor, patch] = latest.0;
        format!("update available {major}.{minor}.{patch}")
    } else {
        "up to date".to_string()
    };
    Some(format!("omgs {}: {message}", env!("CARGO_PKG_VERSION")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(names: &[&str]) -> String {
        names
            .iter()
            .map(|name| format!("{}\trefs/tags/{name}\n", "a".repeat(40)))
            .collect()
    }

    #[test]
    fn update_tags_use_numeric_order_and_ignore_dereferences() {
        assert_eq!(
            latest_tag(&tags(&["v0.9.9", "v99.0.0^{}", "v0.10.0", "v0.1.0"])),
            Some(Version([0, 10, 0]))
        );
        assert_eq!(latest_tag(&tags(&["v99.0.0^{}"])), None);
        assert!(Version([2, 0, 0]) > Version([1, 99, 99]));
        assert!(Version([1, 0, 10]) > Version([1, 0, 9]));
    }

    #[test]
    fn update_tags_require_strict_release_versions() {
        for tag in [
            "0.1.0",
            "v1.0.0-rc.1",
            "v1.0.0+build",
            "junk",
            "v1.2",
            "v1.2.3.4",
            "v01.2.3",
            "v1.02.3",
            "v1.2.03",
            "v+1.2.3",
            "v1.2.-3",
            "v1.2.3 ",
            "v1.2.３",
            "v18446744073709551616.0.0",
        ] {
            assert_eq!(latest_tag(&tags(&[tag])), None, "{tag}");
        }
        assert_eq!(latest_tag(&tags(&["v0.0.0"])), Some(Version([0, 0, 0])));
    }

    #[test]
    fn update_tags_reject_unparseable_output() {
        for output in ["", "not git output", "bad\trefs/tags/v1.0.0\n"] {
            assert_eq!(latest_tag(output), None);
        }
        let valid = tags(&["v1.0.0"]);
        assert_eq!(latest_tag(&format!("{valid}garbage\n")), None);
        let sha256 = format!("{}\trefs/tags/v1.2.3\n", "b".repeat(64));
        assert_eq!(latest_tag(&sha256), Some(Version([1, 2, 3])));
    }
}
