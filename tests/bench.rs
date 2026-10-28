use serde_json::{json, Value};
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("benchmark/fixtures/score")
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
        let dir = std::env::temp_dir().join(format!(
            "omgs-score-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fn copy(from: &std::path::Path, to: &std::path::Path) {
            std::fs::create_dir_all(to).unwrap();
            for entry in std::fs::read_dir(from).unwrap() {
                let entry = entry.unwrap();
                let dest = to.join(entry.file_name());
                if entry.file_type().unwrap().is_dir() {
                    copy(&entry.path(), &dest);
                } else {
                    std::fs::copy(entry.path(), dest).unwrap();
                }
            }
        }
        copy(&root(), &dir);
        Self(dir)
    }
    fn edit(&self, path: &str, mutate: impl FnOnce(&mut Value)) {
        let path = self.0.join(path);
        let mut v = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        mutate(&mut v);
        std::fs::write(path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    }
    fn score(&self) -> Value {
        omgs::bench::score(
            &self.0.join("cases.json"),
            &[self.0.join("run-1"), self.0.join("run-2")],
        )
        .unwrap()
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
    assert_invalid_positive(&saved, "findings.json");
    let saved = SavedRuns::new();
    saved.edit("run-1/positive/findings.json", |r| {
        r["findings"].as_array_mut().unwrap().remove(0);
    });
    assert_invalid_positive(&saved, "missing from source");
    let saved = SavedRuns::new();
    saved.edit("run-1/positive/findings.json", |r| {
        r["findings"][0]["evidence"] = json!("")
    });
    assert_invalid_positive(&saved, "confirmed findings require evidence");
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
