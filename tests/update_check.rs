use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = omgs::platform::temp_root().unwrap().join(format!(
            "omgs-update-check-{}",
            omgs::platform::random_nonce().unwrap()
        ));
        omgs::platform::private_dir(&path).unwrap();
        Self(path)
    }

    fn bare(&self, name: &str, tags: &[&str]) -> PathBuf {
        let repo = self.0.join(name);
        git(&self.0, &["init", "--bare", repo.to_str().unwrap()]);
        let tree = git(&repo, &["mktree"]);
        let tree = std::str::from_utf8(&tree.stdout).unwrap().trim();
        for tag in tags {
            git(&repo, &["update-ref", &format!("refs/tags/{tag}"), tree]);
        }
        git(
            &repo,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "tag",
                "-a",
                "v0.0.1",
                tree,
                "-m",
                "annotated tag with a dereference line",
            ],
        );
        repo
    }

    fn check(&self, remote: &Path) -> Output {
        Command::new(env!("CARGO_BIN_EXE_omgs"))
            .arg("update-check")
            .env("OMGS_UPDATE_REMOTE", remote)
            .current_dir(&self.0)
            .output()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn git(cwd: &Path, args: &[&str]) -> Output {
    let output = Command::new(omgs::platform::which("git").expect("git required for tests"))
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success(), "{args:?}: {output:?}");
    output
}

fn assert_line(output: Output, expected: &str) {
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(output.stdout, expected.as_bytes(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn update_check_selects_highest_release_from_local_bare_remote() {
    let fixture = Fixture::new();
    let remote = fixture.bare(
        "mirror with spaces.git",
        &["v0.9.9", "v0.10.0", "v99.0.0-rc.1", "v98.0.0+build", "junk"],
    );
    assert_line(
        fixture.check(&remote),
        &format!(
            "omgs {}: update available 0.10.0\n",
            env!("CARGO_PKG_VERSION")
        ),
    );
}

#[test]
fn update_check_is_up_to_date_when_equal_or_ahead() {
    let fixture = Fixture::new();
    for tags in [
        vec!["v0.0.9"],
        vec![concat!("v", env!("CARGO_PKG_VERSION"))],
    ] {
        let remote = fixture.bare(tags[0], &tags);
        assert_line(
            fixture.check(&remote),
            &format!("omgs {}: up to date\n", env!("CARGO_PKG_VERSION")),
        );
    }
}

#[test]
fn update_check_is_silent_and_bounded_when_offline() {
    let fixture = Fixture::new();
    let start = Instant::now();
    assert_line(fixture.check(&fixture.0.join("unreachable.git")), "");
    assert!(start.elapsed() < Duration::from_secs(8));
}

#[test]
fn update_check_is_silent_without_release_tags() {
    let fixture = Fixture::new();
    let remote = fixture.bare("no-releases.git", &["v99.0.0-rc.1", "junk"]);
    git(&remote, &["update-ref", "-d", "refs/tags/v0.0.1"]);
    assert_line(fixture.check(&remote), "");
}

#[test]
fn update_check_ignores_local_and_injected_git_configuration() {
    let fixture = Fixture::new();
    let remote = fixture.bare("mirror.git", &["v0.10.0"]);
    git(&fixture.0, &["init"]);
    let rewrite = format!("url.{}.insteadOf", fixture.0.join("missing.git").display());
    git(&fixture.0, &["config", &rewrite, remote.to_str().unwrap()]);
    let output = Command::new(env!("CARGO_BIN_EXE_omgs"))
        .arg("update-check")
        .current_dir(&fixture.0)
        .env("OMGS_UPDATE_REMOTE", &remote)
        .env("GIT_CONFIG_GLOBAL", fixture.0.join(".git/config"))
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", &rewrite)
        .env("GIT_CONFIG_VALUE_0", &remote)
        .output()
        .unwrap();
    assert_line(
        output,
        &format!(
            "omgs {}: update available 0.10.0\n",
            env!("CARGO_PKG_VERSION")
        ),
    );
}

#[test]
fn update_check_is_silent_when_git_is_missing_or_remote_is_empty() {
    let fixture = Fixture::new();
    for (key, value) in [("PATH", ""), ("OMGS_UPDATE_REMOTE", "")] {
        let output = Command::new(env!("CARGO_BIN_EXE_omgs"))
            .arg("update-check")
            .current_dir(&fixture.0)
            .env("OMGS_UPDATE_REMOTE", fixture.0.join("missing.git"))
            .env(key, value)
            .output()
            .unwrap();
        assert_line(output, "");
    }
}

#[cfg(unix)]
#[test]
fn update_check_discards_failed_invalid_excessive_or_timed_out_output() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let git = fixture.0.join("git");
    let valid = format!("printf '{}\\trefs/tags/v9.0.0\\n'\n", "a".repeat(40));
    for script in [
        "printf 'not git output\\n'".to_string(),
        "printf '\\377\\n'".to_string(),
        format!("{valid}exit 1"),
        format!("{valid}printf '%070000d' 0 >&2"),
        format!("{valid}/bin/sleep 30"),
    ] {
        std::fs::write(&git, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o700)).unwrap();
        let start = Instant::now();
        let output = Command::new(env!("CARGO_BIN_EXE_omgs"))
            .arg("update-check")
            .current_dir(&fixture.0)
            .env("OMGS_UPDATE_REMOTE", fixture.0.join("unused.git"))
            .env("PATH", &fixture.0)
            .output()
            .unwrap();
        assert_line(output, "");
        assert!(start.elapsed() < Duration::from_secs(8), "{script}");
    }
}

#[test]
fn update_check_help_and_usage_follow_cli_conventions() {
    for flag in ["--help", "-h"] {
        let output = Command::new(env!("CARGO_BIN_EXE_omgs"))
            .args(["update-check", flag])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("omgs update-check"));
    }
    let output = Command::new(env!("CARGO_BIN_EXE_omgs"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&output.stderr).contains("omgs update-check"));
    for extra in ["--unknown", "positional"] {
        let output = Command::new(env!("CARGO_BIN_EXE_omgs"))
            .args(["update-check", extra])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}
