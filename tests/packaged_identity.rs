//! Offline packaging and CLI ergonomics regressions.
use std::path::{Path, PathBuf};
use std::process::Command;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = omgs::platform::temp_root().unwrap().join(format!(
            "omgs-packaged-{}",
            omgs::platform::random_nonce().unwrap()
        ));
        omgs::platform::create_private_tree(&root).unwrap();
        Self(root)
    }
    fn skill(&self) -> PathBuf {
        let root = self.0.join("skill");
        for (name, bytes) in omgs::setup::BUNDLED {
            let path = root.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        root
    }
    /// An owner-private run directory below the fixture root. The OS temp
    /// root itself is shared (root-owned /tmp on Linux), so runs never sit there.
    fn run(&self) -> PathBuf {
        let run = self.0.join("run");
        omgs::platform::create_private_dir(&run).unwrap();
        run
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn cli() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_omgs"));
    command.env_remove("OMGS_SKILL_DIR");
    command
}

#[test]
fn same_version_skill_skew_fails_before_review_side_effects() {
    let fixture = Fixture::new();
    let skill = fixture.skill();
    assert_eq!(
        omgs::setup::check_identity(&skill).unwrap(),
        omgs::setup::bundled_digest()
    );
    let identity = cli()
        .args(["identity", "--skill-dir"])
        .arg(&skill)
        .output()
        .unwrap();
    assert!(identity.status.success(), "{identity:?}");
    let identity: serde_json::Value = serde_json::from_slice(&identity.stdout).unwrap();
    assert_eq!(
        identity["bundled_skill_sha256"],
        omgs::setup::bundled_digest()
    );
    let revision = identity["build_revision"].as_str().unwrap();
    assert!(revision.trim_end_matches("+dirty").len() == 40);
    for mutation in ["changed", "missing", "extra"] {
        let path = skill.join("agents/red-hunter.md");
        match mutation {
            "changed" => std::fs::write(&path, "different brief").unwrap(),
            "missing" => std::fs::remove_file(&path).unwrap(),
            _ => {
                std::fs::write(
                    &path,
                    omgs::setup::BUNDLED
                        .iter()
                        .find(|(p, _)| *p == "agents/red-hunter.md")
                        .unwrap()
                        .1,
                )
                .unwrap();
                std::fs::write(skill.join("extra.txt"), "extra").unwrap();
            }
        }
        assert!(omgs::setup::check_identity(&skill)
            .unwrap_err()
            .contains("skill identity mismatch"));
        for args in [
            vec!["review", "--repo-url", "https://example.invalid/owner/repo"],
            vec!["audit", "init", "--target", "missing"],
            vec!["batch", "init", "--list", "missing", "--out", "missing"],
        ] {
            let home = fixture.0.join("unused-home");
            let out = cli()
                .args(args)
                .arg("--skill-dir")
                .arg(&skill)
                .env("OMGS_HOME", &home)
                .output()
                .unwrap();
            assert_eq!(out.status.code(), Some(2), "{out:?}");
            assert!(String::from_utf8_lossy(&out.stderr).contains("skill identity mismatch"));
            assert!(!home.exists());
        }
    }
    let out = cli()
        .args(["identity"])
        .env("OMGS_SKILL_DIR", &skill)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("selected sha256"));
}

#[test]
fn identity_digest_binds_paths_and_content_not_modes() {
    let fixture = Fixture::new();
    let skill = fixture.skill();
    let original = omgs::setup::check_identity(&skill).unwrap();
    std::fs::rename(skill.join("VERSION"), skill.join("VERSION-renamed")).unwrap();
    assert!(omgs::setup::check_identity(&skill).is_err());
    std::fs::rename(skill.join("VERSION-renamed"), skill.join("VERSION")).unwrap();
    assert_eq!(omgs::setup::check_identity(&skill).unwrap(), original);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        std::fs::set_permissions(
            skill.join("VERSION"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert_eq!(omgs::setup::check_identity(&skill).unwrap(), original);
        symlink(skill.join("VERSION"), skill.join("linked")).unwrap();
        assert!(omgs::setup::check_identity(&skill).is_err());
    }
}

#[test]
fn counter_help_lists_every_accepted_name_and_invalid_updates_are_atomic() {
    let output = cli().args(["status", "--help"]).output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stderr).unwrap();
    for counter in omgs::status::COUNTERS {
        assert!(text.contains(counter));
    }
    let fixture = Fixture::new();
    let run = fixture.run();
    omgs::runmeta::write_atomic(&run.join(omgs::runmeta::FILE), "{}").unwrap();
    let output = cli()
        .arg("status")
        .arg("--run")
        .arg(&run)
        .args([
            "--stage",
            "hunt",
            "--state",
            "active",
            "--counter",
            "candidates=2",
            "--counter",
            "unsupported=1",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unsupported"),
        "{output:?}"
    );
    assert!(!run.join(omgs::status::FILE).exists());
    assert_eq!(
        std::fs::read_to_string(run.join(omgs::runmeta::FILE)).unwrap(),
        "{}"
    );
}

#[cfg(unix)]
#[test]
fn status_closed_stdout_succeeds_after_saving_mutation() {
    use std::os::fd::FromRawFd;
    let fixture = Fixture::new();
    let run = fixture.run();
    omgs::runmeta::write_atomic(&run.join(omgs::runmeta::FILE), "{}").unwrap();
    let mut fds = [0; 2];
    // SAFETY: writable descriptor array; this test owns both returned descriptors.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // SAFETY: descriptors were returned by pipe and are each consumed once.
    let reader = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    let writer = unsafe { std::fs::File::from_raw_fd(fds[1]) };
    drop(reader);
    let output = cli()
        .arg("status")
        .arg("--run")
        .arg(&run)
        .args([
            "--stage",
            "hunt",
            "--state",
            "active",
            "--counter",
            "candidates=2",
        ])
        .stdout(writer)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let status: serde_json::Value =
        serde_json::from_slice(&std::fs::read(run.join(omgs::status::FILE)).unwrap()).unwrap();
    assert_eq!(status["counters"]["candidates"], 2);
    assert_eq!(status["stages"][0]["status"], "active");
}

#[test]
fn packaging_verifier_accepts_final_binary_and_rejects_wrong_revision_and_bundle() {
    let fixture = Fixture::new();
    let skill = fixture.skill();
    let revision = omgs::setup::identity()["build_revision"]
        .as_str()
        .unwrap()
        .to_string();
    for (rev, valid) in [
        (&revision[..], true),
        ("0000000000000000000000000000000000000000", false),
    ] {
        let out = Command::new(if cfg!(windows) { "python" } else { "python3" })
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/verify_identity.py"))
            .arg(rev)
            .arg(&skill)
            .arg(env!("CARGO_BIN_EXE_omgs"))
            .output()
            .unwrap();
        assert_eq!(out.status.success(), valid, "{out:?}");
    }
    std::fs::write(skill.join("VERSION"), "0.1.0-skew").unwrap();
    let out = Command::new(if cfg!(windows) { "python" } else { "python3" })
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/verify_identity.py"))
        .arg(&revision)
        .arg(&skill)
        .arg(env!("CARGO_BIN_EXE_omgs"))
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[cfg(unix)]
#[test]
fn clone_progress_has_bounded_start_completion_reuse_and_failure_phases() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let bin = fixture.0.join("bin");
    std::fs::create_dir(&bin).unwrap();
    let stub = bin.join("git");
    std::fs::write(&stub, "#!/bin/sh\nfor arg in \"$@\"; do last=\"$arg\"; done\ncase \" $* \" in\n*' clone '*) case \" $* \" in *' --quiet --depth 1 --no-recurse-submodules -- '*) ;; *) exit 9 ;; esac; if [ \"$FAIL_CLONE\" = yes ]; then exit 1; fi; mkdir -p \"$last\" ;;\n*' get-url '*) echo https://example.invalid/owner/repo ;;\n*) exit 1 ;;\nesac\n").unwrap();
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    let skill = fixture.skill();
    let invoke = |home: &Path, fail: bool| {
        cli()
            .env("OMGS_SKILL_DIR", fixture.0.join("missing-skill"))
            .env("OMGS_HOME", home)
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("FAIL_CLONE", if fail { "yes" } else { "no" })
            .args([
                "review",
                "--repo-url",
                "https://example.invalid/owner/repo",
                "--no-sensors",
                "--skill-dir",
            ])
            .arg(&skill)
            .output()
            .unwrap()
    };
    let home = fixture.0.join("home");
    let first = invoke(&home, false);
    assert!(first.status.success(), "{first:?}");
    let text = String::from_utf8(first.stderr).unwrap();
    let phases: Vec<_> = text
        .lines()
        .filter(|l| l.starts_with("clone phase="))
        .collect();
    assert_eq!(phases.len(), 2, "{text}");
    assert!(phases[0].contains("phase=start depth=1 destination="));
    assert!(phases[1].contains("phase=complete destination="));
    assert!(!text.contains('\r'));
    let reused = invoke(&home, false);
    assert!(reused.status.success(), "{reused:?}");
    assert!(String::from_utf8_lossy(&reused.stderr).contains("clone phase=reused destination="));
    let failed = invoke(&fixture.0.join("failed"), true);
    assert!(!failed.status.success());
    let text = String::from_utf8(failed.stderr).unwrap();
    assert!(text.contains("clone phase=failed destination="));
    assert!(!text.contains("clone phase=complete"));
    assert!(!fixture
        .0
        .join("failed/targets/example.invalid/owner/repo")
        .exists());
}

#[test]
fn artifact_privacy_preflight_is_content_silent_and_refuses_aliases() {
    let fixture = Fixture::new();
    let path = fixture.0.join("record.json");
    omgs::platform::write_private_new(&path, b"private synthetic evidence").unwrap();
    let out = cli()
        .args(["artifact-check", "--run"])
        .arg(&fixture.0)
        .args(["--path", "record.json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("synthetic evidence"));
    std::fs::hard_link(&path, fixture.0.join("alias")).unwrap();
    let out = cli()
        .args(["artifact-check", "--run"])
        .arg(&fixture.0)
        .args(["--path", "record.json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}
