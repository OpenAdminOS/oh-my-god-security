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
    assert!(revision == "unknown revision" || revision.trim_end_matches("+dirty").len() == 40);
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
        (&revision[..], revision != "unknown revision"),
        ("unknown revision", false),
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
    let brief = String::from_utf8_lossy(&first.stdout);
    let private_bundle = home
        .join("skill-bundles")
        .join(omgs::setup::bundled_digest());
    assert!(brief.contains(&private_bundle.display().to_string()));
    assert!(!brief.contains(&skill.display().to_string()));
    assert!(brief.contains(&omgs::setup::bundled_digest()));
    let text = String::from_utf8(first.stderr).unwrap();
    let phases: Vec<_> = text
        .lines()
        .filter(|l| l.starts_with("clone phase="))
        .collect();
    assert_eq!(phases.len(), 2, "{text}");
    assert!(phases[0].contains("phase=start depth=1 destination="));
    assert!(phases[1].contains("phase=complete destination="));
    assert!(!text.contains('\r'));
    // A same-version installation must not choose the default review bundle.
    let stale = fixture.0.join(".agents/skills/omgs-security-review");
    std::fs::create_dir_all(&stale).unwrap();
    std::fs::write(stale.join("SKILL.md"), "stale installed brief").unwrap();
    std::fs::write(stale.join("VERSION"), "0.1.0").unwrap();
    let default_review = cli()
        .env("HOME", &fixture.0)
        .env("OMGS_HOME", &home)
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .args([
            "review",
            "--repo-url",
            "https://example.invalid/owner/repo",
            "--no-sensors",
        ])
        .output()
        .unwrap();
    assert!(default_review.status.success(), "{default_review:?}");
    let default_brief = String::from_utf8(default_review.stdout).unwrap();
    let bundle = std::fs::canonicalize(
        home.join("skill-bundles")
            .join(omgs::setup::bundled_digest()),
    )
    .unwrap();
    assert!(default_brief.contains(&bundle.display().to_string()));
    assert!(default_brief.contains(&omgs::setup::bundled_digest()));
    assert!(!default_brief.contains(&stale.display().to_string()));
    assert_eq!(
        omgs::setup::check_identity(&bundle).unwrap(),
        omgs::setup::bundled_digest()
    );
    let list = fixture.0.join("repos.txt");
    std::fs::write(&list, "https://example.invalid/owner/repo\n").unwrap();
    let batch = cli()
        .env("HOME", &fixture.0)
        .env("OMGS_HOME", &home)
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .args(["batch", "init", "--no-sensors", "--list"])
        .arg(&list)
        .arg("--out")
        .arg(fixture.0.join("batch"))
        .output()
        .unwrap();
    assert!(batch.status.success(), "{batch:?}");
    let batch_brief = String::from_utf8(batch.stdout).unwrap();
    assert!(batch_brief.contains(&bundle.display().to_string()));
    assert!(batch_brief.contains(&omgs::setup::bundled_digest()));
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

#[path = "../build_revision.rs"]
mod build_revision;

#[test]
fn source_archive_revision_supports_metadata_and_unknown_without_git() {
    let fixture = Fixture::new();
    assert!(!fixture.0.join(".git").exists());
    assert_eq!(
        build_revision::resolve(&fixture.0, None).unwrap(),
        "unknown revision"
    );
    let revision = "1234567890abcdef1234567890abcdef12345678";
    std::fs::write(fixture.0.join("BUILD-REVISION"), format!("{revision}\n")).unwrap();
    assert_eq!(build_revision::resolve(&fixture.0, None).unwrap(), revision);
    let supplied = "abcdef1234567890abcdef1234567890abcdef12";
    assert_eq!(
        build_revision::resolve(&fixture.0, Some(supplied.into())).unwrap(),
        supplied
    );
    assert!(build_revision::resolve(&fixture.0, Some("unknown revision".into())).is_err());
    std::fs::write(fixture.0.join("BUILD-REVISION"), "bad metadata").unwrap();
    assert!(build_revision::resolve(&fixture.0, None).is_err());
}

#[test]
fn default_review_binds_embedded_bundle_despite_stale_installed_skill() {
    let fixture = Fixture::new();
    let stale = fixture.0.join(".agents/skills/omgs-security-review");
    std::fs::create_dir_all(&stale).unwrap();
    std::fs::write(stale.join("SKILL.md"), "stale brief").unwrap();
    std::fs::write(stale.join("VERSION"), "0.1.0").unwrap();
    let target = fixture.0.join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("sample.rs"), "fn example() {}\n").unwrap();
    let run = fixture.0.join("runs/review");
    let out = cli()
        .env("HOME", &fixture.0)
        .env("OMGS_HOME", fixture.0.join("data"))
        .args(["audit", "init", "--no-sensors", "--target"])
        .arg(&target)
        .arg("--out")
        .arg(&run)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let meta = omgs::runmeta::read(&run).unwrap();
    let selected = Path::new(meta["skill_dir"].as_str().unwrap());
    assert!(selected.is_absolute());
    assert_ne!(selected, stale);
    assert_eq!(
        omgs::setup::check_identity(selected).unwrap(),
        omgs::setup::bundled_digest()
    );
    assert_eq!(meta["skill_identity"], omgs::setup::identity());
    let brief = String::from_utf8(out.stderr).unwrap();
    assert!(brief.contains(&selected.display().to_string()));
    assert!(brief.contains(&omgs::setup::bundled_digest()));
    assert!(brief.contains("ignoring other installed skills"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(selected).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(selected.join("SKILL.md"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    assert_eq!(
        std::fs::read_to_string(stale.join("SKILL.md")).unwrap(),
        "stale brief"
    );
    std::fs::write(selected.join("SKILL.md"), "changed cache").unwrap();
    assert!(omgs::setup::materialize(selected)
        .unwrap_err()
        .contains("skill identity mismatch"));
}

#[test]
fn default_bundle_materialization_waits_for_storage_boundary_admission() {
    let fixture = Fixture::new();
    let target = fixture.0.join("target");
    std::fs::create_dir(&target).unwrap();
    for home in [target.clone(), fixture.0.join("run")] {
        let run = fixture.0.join("run");
        let out = cli()
            .env("OMGS_HOME", &home)
            .args(["audit", "init", "--no-sensors", "--target"])
            .arg(&target)
            .arg("--out")
            .arg(&run)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{out:?}");
        assert!(!home.join("skill-bundles").exists());
        assert!(!run.exists());
        if home == run {
            assert!(String::from_utf8_lossy(&out.stderr)
                .contains("trusted policy store must live outside the run directory"));
        }
    }
}

#[cfg(unix)]
#[test]
fn external_writable_bundles_are_copied_before_briefing() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let source = fixture.skill();
    // Both a replaceable guide directory and its files are writable by others.
    for path in [&source, &source.join("agents")] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777)).unwrap();
    }
    let guide = source.join("agents/red-hunter.md");
    std::fs::set_permissions(&guide, std::fs::Permissions::from_mode(0o666)).unwrap();
    let original = std::fs::read(&guide).unwrap();
    let target = fixture.0.join("target");
    std::fs::create_dir(&target).unwrap();
    let home = fixture.0.join("data");
    for explicit in [true, false] {
        let run = fixture
            .0
            .join(if explicit { "runs/flag" } else { "runs/env" });
        let mut command = cli();
        command
            .env("OMGS_HOME", &home)
            .args(["audit", "init", "--no-sensors", "--target"])
            .arg(&target)
            .arg("--out")
            .arg(&run);
        if explicit {
            command.arg("--skill-dir").arg(&source);
        } else {
            command.env("OMGS_SKILL_DIR", &source);
        }
        let out = command.output().unwrap();
        assert!(out.status.success(), "{out:?}");
        let meta = omgs::runmeta::read(&run).unwrap();
        let selected = Path::new(meta["skill_dir"].as_str().unwrap());
        assert_eq!(
            selected,
            home.join("skill-bundles")
                .join(omgs::setup::bundled_digest())
        );
        let brief = String::from_utf8(out.stderr).unwrap();
        assert!(brief.contains(&selected.display().to_string()));
        assert!(!brief.contains(&source.display().to_string()));
        assert_eq!(meta["skill_identity"], omgs::setup::identity());
        assert_eq!(
            std::fs::metadata(selected).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let private_guide = selected.join("agents/red-hunter.md");
        assert_eq!(
            std::fs::metadata(&private_guide)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        std::fs::write(&guide, "replacement after identity validation").unwrap();
        assert_eq!(std::fs::read(&private_guide).unwrap(), original);
        assert_eq!(
            omgs::setup::check_identity(selected).unwrap(),
            omgs::setup::bundled_digest()
        );
        std::fs::write(&guide, &original).unwrap();
    }
    let bundle = home
        .join("skill-bundles")
        .join(omgs::setup::bundled_digest());
    std::fs::write(bundle.join("SKILL.md"), "changed cache").unwrap();
    assert!(omgs::setup::materialize_selected(&bundle, Some(&source))
        .unwrap_err()
        .contains("skill identity mismatch"));
    std::fs::write(
        bundle.join("SKILL.md"),
        std::fs::read(source.join("SKILL.md")).unwrap(),
    )
    .unwrap();
    omgs::setup::check_identity(&bundle).unwrap();
    // Revalidate the snapshot even when a matching private cache already exists.
    std::fs::write(&guide, "changed external selection").unwrap();
    assert!(omgs::setup::materialize_selected(&bundle, Some(&source))
        .unwrap_err()
        .contains("skill identity mismatch"));
}

#[test]
fn review_and_batch_admit_storage_before_materializing_bundles() {
    for batch in [false, true] {
        for location in ["target", "target/cache", "output", "output/cache"] {
            let fixture = Fixture::new();
            let clones = fixture.0.join("clones");
            let target = clones.join("example.invalid/owner/repo");
            std::fs::create_dir_all(&target).unwrap();
            for args in [
                vec!["init", "--quiet"],
                vec![
                    "remote",
                    "add",
                    "origin",
                    "https://example.invalid/owner/repo",
                ],
            ] {
                let result = Command::new("git")
                    .arg("-C")
                    .arg(&target)
                    .args(args)
                    .output()
                    .unwrap();
                assert!(result.status.success(), "{result:?}");
            }
            let output = fixture.0.join("output");
            let home = match location {
                "target" => target.clone(),
                "target/cache" => target.join("cache"),
                "output" => output.clone(),
                _ => output.join("cache"),
            };
            let mut command = cli();
            command.env("OMGS_HOME", &home);
            if batch {
                let list = fixture.0.join("repos.txt");
                std::fs::write(&list, "https://example.invalid/owner/repo\n").unwrap();
                command.args(["batch", "init", "--list"]).arg(&list);
            } else {
                command.args(["review", "--repo-url", "https://example.invalid/owner/repo"]);
            }
            let out = command
                .args(["--no-sensors", "--clone-root"])
                .arg(&clones)
                .arg("--out")
                .arg(&output)
                .output()
                .unwrap();
            assert_eq!(out.status.code(), Some(2), "{batch} {location}: {out:?}");
            assert!(!home.join("skill-bundles").exists(), "{batch} {location}");
            assert!(!output.exists(), "{batch} {location}");
            let error = String::from_utf8_lossy(&out.stderr);
            assert!(
                error.contains("resolves inside the target")
                    || error.contains("trusted policy store must live outside the run directory"),
                "{error}"
            );
        }
    }
}
