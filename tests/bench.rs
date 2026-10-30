use serde_json::{json, Value};
use std::path::PathBuf;

fn copy_private(from: &std::path::Path, to: &std::path::Path) {
    omgs::platform::create_private_tree(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_private(&entry.path(), &dest);
        } else {
            omgs::runmeta::write_atomic_bytes(&dest, &std::fs::read(entry.path()).unwrap())
                .unwrap();
        }
    }
}

fn root() -> PathBuf {
    static ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        // Checked-out files can be owned by Administrators on Windows. Build
        // valid archived run fixtures using the same private writer as the CLI.
        let dir = omgs::platform::temp_root()
            .unwrap()
            .join(format!("omgs-score-source-{}", std::process::id()));
        copy_private(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("benchmark/fixtures/score"),
            &dir,
        );
        dir
    })
    .clone()
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("../benchmark/fixtures/score/cases.json")).unwrap()
}
fn score() -> Value {
    omgs::bench::score(
        &root().join("cases.json"),
        &[root().join("run-1"), root().join("run-2")],
    )
    .unwrap()
}

// Decimal variance samples can round differently across supported platforms.
fn assert_metrics_close(actual: &Value, expected: &Value) {
    match (actual, expected) {
        (Value::Object(a), Value::Object(e)) => {
            assert_eq!(a.keys().collect::<Vec<_>>(), e.keys().collect::<Vec<_>>());
            for (key, expected) in e {
                assert_metrics_close(&a[key], expected);
            }
        }
        (Value::Array(a), Value::Array(e)) => {
            assert_eq!(a.len(), e.len());
            for (actual, expected) in a.iter().zip(e) {
                assert_metrics_close(actual, expected);
            }
        }
        (Value::Number(a), Value::Number(e)) if a.is_f64() && e.is_f64() => {
            let (a, e) = (a.as_f64().unwrap(), e.as_f64().unwrap());
            assert!((a - e).abs() <= 1e-12 + 1e-12 * e.abs(), "{a} != {e}");
        }
        _ => assert_eq!(actual, expected),
    }
}

#[test]
fn golden_hand_computed_metrics() {
    let s = score();
    let c = &s["cohorts"][0];
    let actual = json!({
        "recalls":c["runs"].as_array().unwrap().iter().map(|r|r["recall"].clone()).collect::<Vec<_>>(),
        "union":c["union_recall"],"mean_recall":c["mean_recall"],"recall_variance":c["recall_variance"],
        "false_positives":c["runs"].as_array().unwrap().iter().map(|r|r["false_positives"].clone()).collect::<Vec<_>>(),
        "fdr":c["runs"].as_array().unwrap().iter().map(|r|r["false_discovery_fraction"].clone()).collect::<Vec<_>>(),
        "negative_unit_rate":c["runs"].as_array().unwrap().iter().map(|r|r["negative_unit_rate"].clone()).collect::<Vec<_>>(),
        "rejection":c["runs"].as_array().unwrap().iter().map(|r|r["verifier_false_rejection_rate"].clone()).collect::<Vec<_>>(),
        "pending":c["runs"].as_array().unwrap().iter().map(|r|r["true_candidates_pending"].clone()).collect::<Vec<_>>(),
        "fp_variance":c["false_positive_variance"],"frequency":c["detection_frequency"],
        "cost_variance":s["cost_variance"],"time_variance":s["time_variance"],
        "costs":s["cost_per_run"].as_array().unwrap().iter().map(|r|r["numerator"]["cost_usd"].clone()).collect::<Vec<_>>(),
        "total_cost":s["total_k_run_cost_usd"],"cli_calls":s["cli_model_calls"]
    });
    let expected: Value =
        serde_json::from_str(include_str!("../benchmark/fixtures/score/expected.json")).unwrap();
    assert_metrics_close(&actual, &expected);
    assert_eq!(c["mean_recall"]["value"], c["recall_variance"]["mean"]);
    assert_eq!(
        c["runs"][0]["unexpected_confirmations"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        c["runs"][0]["needs_validation"],
        json!({"numerator":1,"denominator":1,"value":1.0})
    );
    for r in c["runs"].as_array().unwrap() {
        assert_eq!(r["blocked_or_exhausted"].as_array().unwrap().len(), 1);
        assert_eq!(r["paired_outcomes"].as_array().unwrap().len(), 8);
    }
}

// Sweep every required field at every depth, including nullable fields.
fn omissions(v: &Value, path: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
    match v {
        Value::Object(o) => {
            for (k, v) in o {
                path.push(k.clone());
                if k != "aliases" {
                    out.push(path.clone());
                }
                omissions(v, path, out);
                path.pop();
            }
        }
        Value::Array(a) => {
            for (i, v) in a.iter().enumerate() {
                path.push(i.to_string());
                omissions(v, path, out);
                path.pop();
            }
        }
        _ => {}
    }
}
fn at_mut<'a>(v: &'a mut Value, path: &[String]) -> &'a mut Value {
    let mut node = v;
    for key in path {
        node = if node.is_array() {
            &mut node[key.parse::<usize>().unwrap()]
        } else {
            &mut node[key]
        };
    }
    node
}
#[test]
fn required_fields_are_never_defaulted() {
    let v = fixture();
    let mut paths = Vec::new();
    omissions(&v, &mut Vec::new(), &mut paths);
    for path in paths {
        let mut broken = v.clone();
        at_mut(&mut broken, &path[..path.len() - 1])
            .as_object_mut()
            .unwrap()
            .remove(path.last().unwrap());
        assert!(
            omgs::bench::manifest(&broken).is_err(),
            "accepted missing {path:?}"
        );
    }
}
#[test]
fn examples_aliases_and_manifest_semantics_fail_closed() {
    let mut v = fixture();
    v["examples_only"] = json!(true);
    assert!(omgs::bench::manifest(&v).is_err());
    v = fixture();
    v["cases"][0]["example_only"] = json!(true);
    assert!(omgs::bench::manifest(&v).is_err());
    for (pointer, bad) in [
        ("/cases/0/budget/max_wall_seconds", json!(-1)),
        (
            "/cases/0/provenance/human_confirmation/reviewed_at",
            json!("2026-02-30T00:00:00Z"),
        ),
        (
            "/cases/0/expected_findings/0/positive_snapshot_ids",
            json!(["missing"]),
        ),
        ("/cases/0/fixtures/network", json!("allowed")),
        ("/cases/0/fixtures", json!([])),
        ("/cases/0/snapshots/0/source_ref", json!("main")),
    ] {
        let mut v = fixture();
        *v.pointer_mut(pointer).unwrap() = bad;
        assert!(omgs::bench::manifest(&v).is_err(), "{pointer}");
    }
    v = fixture();
    v["cases"][0]["expected_findings"][0]["aliases"] =
        v["cases"][0]["expected_findings"][1]["aliases"].clone();
    assert!(omgs::bench::manifest(&v).is_err());
    assert!(omgs::bench::score(
        &root().join("cases.json"),
        &[root().join("run-1"), root().join("run-1")]
    )
    .is_err());
    assert!(omgs::bench::score(&root().join("cases.json"), &[root().join("run-1")]).is_err());
}
#[test]
fn cli_emits_json_and_markdown_offline() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args(["bench", "score", "--cases"])
        .arg(root().join("cases.json"))
        .arg("--runs")
        .arg(root().join("run-1"))
        .arg("--runs")
        .arg(root().join("run-2"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&out.stdout).unwrap(),
        score()
    );
    assert!(String::from_utf8_lossy(&out.stderr)
        .contains("| not_applicable:development:1 | r1 | 1/4 (0.25) |"));
}

struct SavedRuns(PathBuf);
impl SavedRuns {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = omgs::platform::temp_root().unwrap().join(format!(
            "omgs-score-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        copy_private(&root(), &dir);
        Self(dir)
    }
    fn edit(&self, path: &str, mutate: impl FnOnce(&mut Value)) {
        let path = self.0.join(path);
        let mut v = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        mutate(&mut v);
        std::fs::write(path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    }
    fn score(&self) -> Value {
        self.try_score().unwrap()
    }
    fn try_score(&self) -> Result<Value, String> {
        omgs::bench::score(
            &self.0.join("cases.json"),
            &[self.0.join("run-1"), self.0.join("run-2")],
        )
    }
}
impl Drop for SavedRuns {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn assert_invalid_positive(saved: &SavedRuns, message: &str) {
    let s = saved.score();
    let c = &s["cohorts"][0];
    let r = &c["runs"][0];
    assert_eq!(
        r["recall"],
        json!({"numerator":0,"denominator":4,"value":0.0})
    );
    assert_eq!(r["true_positive_detections"]["numerator"], 0);
    assert_eq!(c["union_recall"]["numerator"], 2);
    assert_eq!(c["detection_frequency"][0]["frequency"]["numerator"], 0);
    assert_eq!(r["paired_outcomes"][0]["recovered"], false);
    let report = r["invalid_evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["snapshot_id"] == "positive" && e["fingerprint"] == "omgs-d7c7756a1f68ec92")
        .unwrap();
    assert!(report["errors"].to_string().contains(message), "{report}");
    assert!(omgs::bench::markdown(&s).contains("Invalid evidence"));
}

#[test]
fn proofless_exports_are_reported_and_not_recovered() {
    let saved = SavedRuns::new();
    saved.edit("run-1/benchmark-run.json", |r| {
        r["observations"][0]["source_run"] = Value::Null
    });
    assert_invalid_positive(&saved, "missing source_run");
    let saved = SavedRuns::new();
    saved.edit("run-1/benchmark-run.json", |r| {
        r["observations"][0]["findings"][0]["proof_ref"] = Value::Null
    });
    saved.edit("run-1/positive/findings.json", |r| {
        r["findings"][0]["proof_ref"] = Value::Null
    });
    assert_invalid_positive(&saved, "requires proof_ref");
    let saved = SavedRuns::new();
    std::fs::remove_file(saved.0.join("run-1/positive/proofs/1.json")).unwrap();
    assert_invalid_positive(&saved, "read");
}

#[test]
fn mismatched_proof_references_are_reported_and_not_recovered() {
    let saved = SavedRuns::new();
    saved.edit("run-1/benchmark-run.json", |r| {
        r["observations"][0]["findings"][0]["proof_ref"] = json!("proofs/2.json")
    });
    assert_invalid_positive(&saved, "does not match source");
    saved.edit("run-1/positive/findings.json", |r| {
        r["findings"][0]["proof_ref"] = json!("proofs/2.json")
    });
    assert_invalid_positive(&saved, "was recorded for finding");
}

#[test]
fn wrong_proof_revisions_cannot_count_as_tp_recovery_or_fp() {
    let saved = SavedRuns::new();
    saved.edit("run-1/positive/proofs/1.json", |r| {
        r["target_head"] = json!("2".repeat(40))
    });
    assert_invalid_positive(&saved, "target_head 2222222222222222222222222222222222222222 does not match frozen snapshot source_ref 1111111111111111111111111111111111111111");
    saved.edit("run-1/fixed/proofs/1.json", |r| {
        r["target_head"] = json!("1".repeat(40))
    });
    assert_invalid_fixed(&saved, "target_head 1111111111111111111111111111111111111111 does not match frozen snapshot source_ref 2222222222222222222222222222222222222222");
}

#[test]
fn missing_proof_revisions_cannot_count_as_tp_recovery_or_fp() {
    // Both absent and explicit null revisions must fail closed.
    for absent in [true, false] {
        let saved = SavedRuns::new();
        for snapshot in ["positive", "fixed"] {
            saved.edit(&format!("run-1/{snapshot}/proofs/1.json"), |r| {
                if absent {
                    r.as_object_mut().unwrap().remove("target_head");
                } else {
                    r["target_head"] = Value::Null;
                }
            });
        }
        assert_invalid_positive(&saved, "target_head <missing>");
        assert_invalid_fixed(&saved, "target_head <missing>");
    }
}

fn assert_invalid_fixed(saved: &SavedRuns, message: &str) {
    let s = saved.score();
    let r = &s["cohorts"][0]["runs"][0];
    assert_eq!(r["false_positives"]["numerator"], 0);
    assert_eq!(r["false_discovery_fraction"]["numerator"], 0);
    assert_eq!(r["negative_unit_rate"]["numerator"], 0);
    let report = r["invalid_evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["snapshot_id"] == "fixed" && e["fingerprint"] == "omgs-d7c7756a1f68ec92")
        .unwrap();
    assert!(report["errors"].to_string().contains(message), "{report}");
}

#[test]
fn source_archive_assigned_to_another_snapshot_cannot_count_as_tp_recovery_or_fp() {
    let saved = SavedRuns::new();
    saved.edit("run-1/benchmark-run.json", |r| {
        // Export the entire archive to isolate snapshot binding from omissions.
        r["observations"][1]["source_run"] = json!("positive");
        r["observations"][1]["findings"] = r["observations"][0]["findings"].clone();
    });
    assert_invalid_fixed(&saved, "does not match frozen snapshot source_ref");
    let s = saved.score();
    assert_eq!(s["cohorts"][0]["runs"][0]["recall"]["numerator"], 1);
    assert_eq!(
        s["cohorts"][0]["runs"][0]["true_positive_detections"]["numerator"],
        1
    );
    let saved = SavedRuns::new();
    saved.edit("run-1/benchmark-run.json", |r| {
        r["observations"][0]["source_run"] = json!("fixed");
        r["observations"][0]["findings"] = r["observations"][1]["findings"].clone();
    });
    assert_invalid_positive(&saved, "does not match frozen snapshot source_ref");
}

#[test]
fn clearing_fixed_findings_and_adjudications_rejects_export_without_metrics() {
    let saved = SavedRuns::new();
    saved.edit("run-1/benchmark-run.json", |r| {
        r["observations"][1]["findings"] = json!([]);
        r["observations"][1]["adjudications"] = json!([]);
    });
    let error = saved.try_score().unwrap_err();
    assert!(
        error.contains("run \"r1\" case \"fixture\" snapshot \"fixed\""),
        "{error}"
    );
    assert!(error.contains("incomplete observation"), "{error}");
    assert!(error.contains("omgs-d7c7756a1f68ec92"), "{error}");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args(["bench", "score", "--cases"])
        .arg(saved.0.join("cases.json"))
        .arg("--runs")
        .arg(saved.0.join("run-1"))
        .arg("--runs")
        .arg(saved.0.join("run-2"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty(), "partial metrics were emitted");
    assert!(String::from_utf8_lossy(&out.stderr).contains("incomplete observation"));
}

#[test]
fn partial_exports_cannot_omit_confirmed_or_needs_validation_findings() {
    for index in [0, 2, 3] {
        for status in ["complete", "blocked", "budget_exhausted"] {
            let saved = SavedRuns::new();
            let mut omitted = Value::Null;
            saved.edit("run-1/benchmark-run.json", |r| {
                let o = &mut r["observations"][0];
                omitted =
                    o["findings"].as_array_mut().unwrap().remove(index)["fingerprint"].clone();
                o["status"] = json!(status);
                if status != "complete" {
                    o["blockers"] = json!(["fixture incomplete"]);
                }
            });
            let error = saved.try_score().unwrap_err();
            assert!(error.contains("incomplete observation"), "{error}");
            assert!(error.contains(omitted.as_str().unwrap()), "{error}");
        }
    }
}

#[test]
fn empty_exports_still_validate_supplied_source_archives() {
    for invalid in [false, true] {
        let saved = SavedRuns::new();
        saved.edit("run-1/benchmark-run.json", |r| {
            r["observations"][1]["findings"] = json!([]);
            r["observations"][1]["adjudications"] = json!([]);
        });
        if invalid {
            saved.edit("run-1/fixed/findings.json", |r| {
                r["findings"][0]["evidence"] = json!("");
            });
        } else {
            std::fs::remove_file(saved.0.join("run-1/fixed/findings.json")).unwrap();
        }
        let error = saved.try_score().unwrap_err();
        assert!(error.contains("source_run \"fixed\""), "{error}");
        assert!(
            error.contains(if invalid {
                "confirmed findings require evidence"
            } else {
                "findings.json"
            }),
            "{error}"
        );
    }
}

#[test]
fn invalid_proofs_and_recipe_contracts_are_reported_and_not_recovered() {
    for (pointer, value, message) in [
        ("/cleanup_complete", json!(false), "did not finish cleanly"),
        (
            "/contract/authorized_control_seen",
            json!(false),
            "declared contract requires",
        ),
        (
            "/contract/boundary_marker_seen",
            json!(false),
            "declared contract requires",
        ),
        ("/exit_code", json!(2), "harness or usage error"),
        ("/schema", json!("omgs-proof/1"), "unsupported schema"),
        ("/output_sha256", json!("0".repeat(64)), "output_sha256"),
    ] {
        let saved = SavedRuns::new();
        saved.edit("run-1/positive/proofs/1.json", |r| {
            *r.pointer_mut(pointer).unwrap() = value
        });
        assert_invalid_positive(&saved, message);
    }
}

#[test]
fn pending_and_disputed_adjudications_remain_visible_without_recovery() {
    for outcome in ["pending", "disputed"] {
        let saved = SavedRuns::new();
        saved.edit("run-1/benchmark-run.json", |r| {
            r["observations"][0]["adjudications"] = json!([{
                "fingerprint":r["observations"][0]["findings"][0]["fingerprint"],
                "outcome":outcome,"negative_unit":null,
                "review":{"reviewer":"fixture-review","reviewed_at":"2026-10-28T00:00:00Z","evidence_path":"review.txt"}
            }]);
        });
        let s = saved.score();
        let c = &s["cohorts"][0];
        let r = &c["runs"][0];
        assert_eq!(
            r["recall"],
            json!({"numerator":0,"denominator":4,"value":0.0})
        );
        assert_eq!(r["true_positive_detections"]["numerator"], 0);
        assert_eq!(r["false_discovery_fraction"]["denominator"], 1);
        assert_eq!(c["union_recall"]["numerator"], 2);
        assert_eq!(c["detection_frequency"][0]["frequency"]["numerator"], 0);
        assert_eq!(r["paired_outcomes"][0]["recovered"], false);
        assert_eq!(r["pending_adjudications"].as_array().unwrap().len(), 1);
        assert_eq!(r["pending_adjudications"][0]["outcome"], outcome);
        assert_eq!(r["true_candidates_pending"]["numerator"], 1);
        assert!(r["invalid_evidence"].as_array().unwrap().is_empty());
        saved.edit("run-1/benchmark-run.json", |r| {
            r["observations"][0]["adjudications"] = json!([])
        });
        let resolved = saved.score();
        assert_eq!(resolved["cohorts"][0]["runs"][0]["recall"]["numerator"], 1);
    }
}

#[test]
fn repository_url_variants_cannot_leak_across_splits() {
    for url in [
        "https://github.com/Owner/Repo/",
        "https://github.com/owner/repo.git/",
        "https://GitHub.com/OWNER/REPO.git",
        "https://github.com/owner/repo.GIT/",
    ] {
        let mut m = fixture();
        m["cases"][0]["source"]["repository_url"] = json!("https://github.com/Owner/Repo.git");
        let mut other = m["cases"][0].clone();
        other["id"] = json!("other");
        other["source"]["repository_url"] = json!(url);
        m["cases"].as_array_mut().unwrap().push(other);
        assert!(omgs::bench::manifest(&m).is_ok());
        m["cases"][1]["split"]["cohort_id"] = json!("other-family");
        m["cases"][1]["split"]["partition"] = json!("held_out");
        assert!(
            omgs::bench::manifest(&m)
                .unwrap_err()
                .contains("repository family"),
            "{url}"
        );
    }
}

#[test]
fn archived_golden_sources_pass_validate_offline() {
    for relative in ["run-1/positive", "run-1/fixed", "run-2/positive"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
            .args(["validate", "--findings"])
            .arg(root().join(relative).join("findings.json"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    for r in score()["cohorts"][0]["runs"].as_array().unwrap() {
        assert!(r["invalid_evidence"].as_array().unwrap().is_empty());
    }
}

#[test]
fn missing_or_invalid_source_findings_are_reported() {
    let saved = SavedRuns::new();
    std::fs::remove_file(saved.0.join("run-1/positive/findings.json")).unwrap();
    assert!(saved.try_score().unwrap_err().contains("findings.json"));
    let saved = SavedRuns::new();
    saved.edit("run-1/positive/findings.json", |r| {
        r["findings"].as_array_mut().unwrap().remove(0);
    });
    assert_invalid_positive(&saved, "missing from source");
    let saved = SavedRuns::new();
    saved.edit("run-1/positive/findings.json", |r| {
        r["findings"][0]["evidence"] = json!("")
    });
    assert!(saved
        .try_score()
        .unwrap_err()
        .contains("confirmed findings require evidence"));
    let saved = SavedRuns::new();
    saved.edit("run-1/benchmark-run.json", |r| {
        r["observations"][0]["findings"][0]["verdict"] = json!("needs_validation")
    });
    assert_invalid_positive(&saved, "does not match source");
    let saved = SavedRuns::new();
    saved.edit("run-1/benchmark-run.json", |r| {
        r["observations"][0]["findings"][0]["proof_tier"] = json!("sandbox_exploited")
    });
    assert_invalid_positive(&saved, "does not match source");
}

#[test]
fn archived_verifier_lifecycle_controls_scoring() {
    for state in ["active", "stopped", "missing"] {
        let saved = SavedRuns::new();
        for snapshot in ["positive", "fixed"] {
            saved.edit(&format!("run-1/{snapshot}/run-metadata.json"), |meta| {
                let records = meta["attempts"].as_array_mut().unwrap();
                match state {
                    "active" => { records.pop(); }
                    "stopped" => records.push(json!({"at":"2026-01-01T00:00:02Z","record":{
                        "event":"stop","id":"fixture-verifier","actor":"host","kind":"policy",
                        "reason":"Stop archived output","artifacts":["findings.json"],"disposition":"quarantined"
                    }})),
                    _ => records.clear(),
                }
            });
        }
        assert_invalid_positive(
            &saved,
            if state == "missing" {
                "no recorded attempt"
            } else {
                "completed attempt"
            },
        );
        assert_invalid_fixed(
            &saved,
            if state == "missing" {
                "no recorded attempt"
            } else {
                "completed attempt"
            },
        );
    }
    // The unchanged completed archive remains eligible.
    assert_eq!(score()["cohorts"][0]["runs"][0]["recall"]["numerator"], 1);
}

#[test]
fn benchmark_accounting_uses_host_attempt_subtotals_and_cumulative_turns() {
    let saved = SavedRuns::new();
    saved.edit("run-1/run-metadata.json", |meta| {
        meta["accounting"]["host"] = json!({"tokens":50,"cost_usd":0.25,"duration_ms":500});
        meta["accounting"]["blue-verifier@blue"] = json!({"tokens":150,"cost_usd":0.75,"duration_ms":1500,"covered_turn":"one","unreported":false});
        meta["attempts"] = json!([
            {"at":"first","record":{"event":"start","id":"blue","role":"verifier","identity":"blue","context":"synthetic","inputs":["in"],"outputs":["out"],"isolation":"procedural"}},
            {"at":"first","record":{"event":"dispatch","id":"blue","turn":"one","actor":"host","reason":"Authorized turn"}}
        ]);
    });
    let usage = |score: Value| score["cost_per_run"][0]["numerator"].clone();
    let first = usage(saved.score());
    assert_eq!(first["tokens"], 500);
    assert_eq!(first["cost_usd"], 2.5);
    assert_eq!(first["duration_ms"], 5000);
    saved.edit("run-1/run-metadata.json", |meta| {
        meta["attempts"].as_array_mut().unwrap().push(json!({"at":"later","record":{"event":"dispatch","id":"blue","turn":"two","actor":"host","reason":"Authorized continuation"}}));
    });
    let later = usage(saved.score());
    assert!(later["tokens"].is_null());
    assert!(later["cost_usd"].is_null());
    assert_eq!(later["known_subtotals"]["tokens"], 500);
    assert_eq!(later["unknown_usage"]["tokens"], 1);
    assert_eq!(later["roles"]["blue-verifier@blue"]["unreported"], true);
    saved.edit("run-1/run-metadata.json", |meta| {
        meta["accounting"]["blue-verifier@blue"] =
            json!({"tokens":200,"cost_usd":1.0,"duration_ms":2000,"covered_turn":"two"});
    });
    let refreshed = usage(saved.score());
    assert_eq!(refreshed["tokens"], 550);
    assert_eq!(refreshed["cost_usd"], 2.75);
    saved.edit("run-1/run-metadata.json", |meta| {
        meta["accounting"]["blue-verifier@unknown"] =
            json!({"tokens":null,"cost_usd":null,"duration_ms":null});
        meta["attempts"].as_array_mut().unwrap().push(json!({"at":"later","record":{"event":"start","id":"unknown","role":"verifier","identity":"unknown","context":"synthetic","inputs":["in"],"outputs":["out"],"isolation":"procedural"}}));
    });
    let unknown = usage(saved.score());
    assert!(unknown["cost_usd"].is_null());
    assert_eq!(unknown["known_subtotals"]["cost_usd"], 2.75);
    assert_eq!(unknown["unknown_usage"]["cost_usd"], 1);
    saved.edit("run-1/run-metadata.json", |meta| {
        meta["accounting"]["host"] = json!({"tokens":null,"cost_usd":null,"duration_ms":null});
    });
    assert_eq!(usage(saved.score())["unknown_usage"]["cost_usd"], 2);
}
