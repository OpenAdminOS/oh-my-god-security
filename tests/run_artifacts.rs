//! The same admission matrix applies to every kind of retained run evidence.
use omgs::run_artifact::*;
use std::path::{Path, PathBuf};

const KINDS: &[(&str, u64)] = &[
    ("pipeline-status.json", STATUS_BYTES),
    ("findings.json", FINDINGS_BYTES),
    ("coverage-ledger.json", LEDGER_BYTES),
    ("candidates.json", CANDIDATES_BYTES),
    ("candidates-hunter.json", CANDIDATES_BYTES),
    ("sensors.json", SENSORS_BYTES),
    ("sensor-hits.json", SENSOR_HITS_BYTES),
    ("architecture.json", ARCHITECTURE_BYTES),
    ("proofs/1.json", PROOF_BYTES),
    ("proofs/1/command.txt", COMMAND_BYTES),
    ("proofs/1/mxc-config.json", CONFIG_BYTES),
    ("proofs/1/test-draft", DRAFT_BYTES),
    ("run-metadata.json", METADATA_BYTES),
    ("evaluation.json", EVALUATION_BYTES),
    ("dispositions.json", DISPOSITIONS_BYTES),
    ("intent-answers.json", ANSWERS_BYTES),
    (".omgs-claim", CLAIM_BYTES),
    ("benchmark-run.json", BENCHMARK_BYTES),
];

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = omgs::platform::temp_root().unwrap().join(format!(
            "omgs-artifact-matrix-{}",
            omgs::platform::random_nonce().unwrap()
        ));
        omgs::platform::create_private_tree(&root).unwrap();
        Self(root)
    }
    fn leaf(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        omgs::platform::create_private_tree(path.parent().unwrap()).unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn symlink_file(source: &Path, dest: &Path) {
    std::os::unix::fs::symlink(source, dest).unwrap();
}
#[cfg(windows)]
fn symlink_file(source: &Path, dest: &Path) {
    std::os::windows::fs::symlink_file(source, dest).unwrap();
}
#[cfg(unix)]
fn symlink_dir(source: &Path, dest: &Path) {
    std::os::unix::fs::symlink(source, dest).unwrap();
}
#[cfg(windows)]
fn symlink_dir(source: &Path, dest: &Path) {
    std::os::windows::fs::symlink_dir(source, dest).unwrap();
}

#[test]
fn every_artifact_kind_enforces_admission_and_bounds() {
    for &(name, limit) in KINDS {
        let f = Fixture::new();
        let path = f.leaf(name);
        assert!(
            optional_text(&f.0, Path::new(name), limit)
                .unwrap()
                .is_none(),
            "{name}"
        );
        omgs::runmeta::write_atomic(&path, "ok").unwrap();
        assert_eq!(read(&f.0, Path::new(name), limit).unwrap(), b"ok", "{name}");
        let outside = f.0.join("outside");
        omgs::runmeta::write_atomic(&outside, "outside").unwrap();
        std::fs::remove_file(&path).unwrap();
        symlink_file(&outside, &path);
        assert_rejected(&f.0, name, limit, "symlink");
        std::fs::remove_file(&outside).unwrap();
        assert_rejected(&f.0, name, limit, "dangling symlink");
        std::fs::remove_file(&path).unwrap();
        omgs::runmeta::write_atomic(&outside, "outside").unwrap();
        std::fs::hard_link(&outside, &path).unwrap();
        assert_rejected(&f.0, name, limit, "hardlink");
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_rejected(&f.0, name, limit, "directory");
        std::fs::remove_dir(&path).unwrap();
        omgs::platform::write_private_new(&path, b"").unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(limit).unwrap();
        assert_eq!(
            read(&f.0, Path::new(name), limit).unwrap().len() as u64,
            limit,
            "{name}"
        );
        file.set_len(limit + 1).unwrap();
        let error = read(&f.0, Path::new(name), limit).unwrap_err().to_string();
        assert!(error.contains("byte limit"), "{name}: {error}");
        assert_rejected(&f.0, name, limit, "oversized");
    }
}

fn assert_rejected(run: &Path, name: &str, limit: u64, attack: &str) {
    let error = optional_text(run, Path::new(name), limit).unwrap_err();
    assert!(
        error.contains(name) || error.contains(&Path::new(name).display().to_string()),
        "{attack}: {error}"
    );
    assert!(error.contains("run artifact"), "{name} {attack}: {error}");
    if let Some(error) = consumer_error(run, name) {
        assert!(
            error.contains("run artifact"),
            "consumer {name} {attack}: {error}"
        );
    }
}

// Exercise the owning consumers too, so moving a call back to an unbounded
// path reader cannot leave this matrix green merely because the helper is safe.
fn consumer_error(run: &Path, name: &str) -> Option<String> {
    let empty = omgs::model::FindingsFile::default();
    let error = match name {
        "pipeline-status.json" => {
            let timeline = omgs::report::timeline(run)
                .err()
                .expect("timeline must refuse");
            let update = omgs::status::Update {
                stage: "report",
                label: None,
                parent: None,
                state: "done",
                detail: None,
                counters: &[],
                log: None,
            };
            assert!(omgs::status::apply(run, &update).is_err());
            timeline
        }
        "findings.json" => omgs::critic::critique_run(run).unwrap_err(),
        "coverage-ledger.json" => omgs::critic::critique_dir(run, &empty).unwrap_err(),
        "candidates.json" | "candidates-hunter.json" => {
            omgs::runmeta::write_atomic(&run.join("coverage-ledger.json"), r#"{"units":[]}"#)
                .unwrap();
            omgs::critic::critique_dir(run, &empty).unwrap_err()
        }
        "sensors.json" | "sensor-hits.json" => omgs::sensors::read_report(run).unwrap_err(),
        "architecture.json" => omgs::adjudication::report_lines(run, &empty).unwrap_err(),
        "run-metadata.json" => omgs::runmeta::read(run).unwrap_err(),
        "evaluation.json" => omgs::adjudication::load(run).unwrap_err(),
        "proofs/1.json" => omgs::proof::load(run, name).unwrap_err(),
        "proofs/1/command.txt" => omgs::proof::recorded_command(run, &proof_record()).unwrap_err(),
        "proofs/1/mxc-config.json" | "proofs/1/test-draft" => {
            omgs::proof::runner_evidence(run, &proof_record())
                .into_iter()
                .find(|e| {
                    e.contains("run artifact")
                        && e.contains(Path::new(name).file_name().unwrap().to_str().unwrap())
                })
                .expect("proof evidence must refuse")
        }
        _ => return None,
    };
    Some(error)
}

fn proof_record() -> omgs::proof::ProofRecord {
    serde_json::from_value(serde_json::json!({
        "schema":omgs::proof::SCHEMA,"n":1,"tier":"test","test_from":"draft",
        "command":"test","command_sha256":"","wrapped_command_sha256":"",
        "readable_roots":[],"proof_dir":"","marker_nonce":"",
        "command_started":true,"command_finished":true,"timeout_ms":1000,
        "started_at_ms":0,"duration_ms":0,"exit_code":1,"contract":{"kind":"none"},
        "timed_out":false,"capture_complete":true,"survivors":[],"mxc_version":"",
        "containment":"","executor":"","executor_sha256":"","config_sha256":"",
        "enforced":[],"gaps":[],"output_sha256":"","output_bytes_total":0,"output":"","omgs_version":"test"
    })).unwrap()
}

#[test]
fn linked_proof_ancestors_are_refused_for_every_proof_artifact() {
    for &(name, limit) in KINDS.iter().filter(|(name, _)| name.starts_with("proofs/")) {
        for ancestor in ["proofs", "proofs/1"] {
            if ancestor == "proofs/1" && name == "proofs/1.json" {
                continue;
            }
            let f = Fixture::new();
            let path = f.leaf(name);
            omgs::runmeta::write_atomic(&path, "ok").unwrap();
            let original = f.0.join(ancestor);
            let moved = f.0.join("moved");
            std::fs::rename(&original, &moved).unwrap();
            symlink_dir(&moved, &original);
            assert_rejected(&f.0, name, limit, ancestor);
            // Linked ancestors are errors even when their child is missing.
            std::fs::remove_file(moved.join(path.strip_prefix(&original).unwrap())).unwrap();
            assert_rejected(&f.0, name, limit, "linked ancestor with absent child");
        }
    }
}

#[cfg(unix)]
#[test]
fn fifo_reader_child() {
    let Some(run) = std::env::var_os("OMGS_TEST_ARTIFACT_FIFO_RUN") else {
        return;
    };
    for (i, &(name, limit)) in KINDS.iter().enumerate() {
        assert_rejected(&Path::new(&run).join(i.to_string()), name, limit, "FIFO");
    }
}

#[cfg(unix)]
#[test]
fn fifo_matrix_finishes_under_short_timeout() {
    let f = Fixture::new();
    for (i, &(name, _)) in KINDS.iter().enumerate() {
        let path = f.leaf(&format!("{i}/{name}"));
        let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: valid NUL-terminated path, private fixture, no writer needed.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    }
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "fifo_reader_child", "--nocapture"])
        .env("OMGS_TEST_ARTIFACT_FIFO_RUN", &f.0)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let started = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let output = child.wait_with_output().unwrap();
            assert!(
                status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            break;
        }
        if started.elapsed() > std::time::Duration::from_secs(3) {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("FIFO admission exceeded 3 seconds");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn run_relative_paths_cannot_escape() {
    let f = Fixture::new();
    for name in ["../outside", "/outside", "proofs/../../outside", ""] {
        assert!(read(&f.0, Path::new(name), 64).is_err(), "{name}");
    }
}
