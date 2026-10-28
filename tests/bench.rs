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

#[test]
fn golden_hand_computed_metrics() {
    let s = score();
    let c = &s["cohorts"][0];
    let actual = json!({
        "recalls":c["runs"].as_array().unwrap().iter().map(|r|r["recall"].clone()).collect::<Vec<_>>(),
        "union":c["union_recall"],"recall_variance":c["recall_variance"],
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
    assert_eq!(actual, expected);
    assert_eq!(c["mean_recall"], c["recall_variance"]);
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
