use omgs::critic::{critique, Candidate, SourcedCandidate};
use omgs::ledger::{add_unit, set_status, validate_ledger, Ledger, Unit};
use omgs::model::{validate, Finding, FindingsFile, Location, ProofTier, Severity, Verdict};
use omgs::report::{render_html, render_markdown, render_sarif, ReportMeta};

/// A valid confirmed record for `key`, hunted by red-1 and verified by blue-1.
fn record(key: &str) -> Finding {
    let attack_class = format!("class_{key}");
    Finding {
        fingerprint: omgs::fingerprint(&attack_class, "GET /api/x", "db.x", "tenant"),
        title: format!("Title {key}"),
        verdict: Verdict::Confirmed,
        severity: Some(Severity::High),
        proof_tier: ProofTier::TestProven,
        attack_class,
        entry_point: "GET /api/x".into(),
        sink: "db.x".into(),
        boundary: "tenant".into(),
        location: Location {
            path: "app/api/x/route.ts".into(),
            line: Some(3),
        },
        locations: vec![],
        evidence: "Trace: x. Sandbox evidence: failed invariant.".into(),
        fix_brief: None,
        intent_question: None,
        family: None,
        prerequisites: None,
        hunted_by: Some("red-1".into()),
        verified_by: Some("blue-1".into()),
        candidates: vec![],
    }
}

fn file(findings: Vec<Finding>) -> FindingsFile {
    FindingsFile { findings }
}

fn has(errors: &[String], needle: &str) -> bool {
    errors.iter().any(|e| e.contains(needle))
}

fn copy_at(path: &str, line: u32) -> Location {
    Location {
        path: path.into(),
        line: Some(line),
    }
}

#[test]
fn grouped_locations_validate_render_and_count_once() {
    let mut f = record("a");
    f.locations = vec![
        copy_at("runbooks/two.ps1", 40),
        copy_at("runbooks/three.ps1", 41),
    ];
    let ff = file(vec![f]);
    assert!(validate(&ff).is_empty(), "{:?}", validate(&ff));
    let meta = ReportMeta::default();
    let md = render_markdown(&ff, &meta);
    assert!(
        md.contains("Locations: app/api/x/route.ts:3, runbooks/two.ps1:40, runbooks/three.ps1:41")
    );
    assert!(md.contains("Confirmed findings: 1\n"));
    let html = render_html(&ff, &meta);
    assert!(html.contains("<dt>Also at</dt><dd><code>runbooks/two.ps1:40</code> <code>runbooks/three.ps1:41</code></dd>"));
    assert!(html.contains("and 2 more locations"));
    let sarif: serde_json::Value = serde_json::from_str(&render_sarif(&ff, &meta)).unwrap();
    let locs = &sarif["runs"][0]["results"][0]["locations"];
    assert_eq!(locs.as_array().unwrap().len(), 3);
    assert_eq!(
        locs[2]["physicalLocation"]["artifactLocation"]["uri"],
        "runbooks/three.ps1"
    );
}

#[test]
fn repeated_or_empty_location_is_rejected() {
    let mut f = record("a");
    f.locations = vec![copy_at("app/api/x/route.ts", 3)];
    assert!(has(
        &validate(&file(vec![f.clone()])),
        "listed more than once"
    ));
    f.locations = vec![copy_at("b.ts", 1), copy_at("b.ts", 1)];
    assert!(has(
        &validate(&file(vec![f.clone()])),
        "listed more than once"
    ));
    f.locations = vec![copy_at(" ", 1)];
    assert!(has(&validate(&file(vec![f])), "location path is empty"));
}

#[test]
fn hunter_and_verifier_are_required_and_distinct() {
    let mut f = record("a");
    f.hunted_by = None;
    assert!(has(
        &validate(&file(vec![f.clone()])),
        "hunted_by is required"
    ));
    f.hunted_by = Some("red-1".into());
    f.verified_by = Some("  ".into());
    assert!(has(
        &validate(&file(vec![f.clone()])),
        "verified_by is required"
    ));
    f.verified_by = Some(" RED-1 ".into());
    assert!(has(
        &validate(&file(vec![f])),
        "verified_by must differ from hunted_by"
    ));
}

#[test]
fn merged_candidates_are_checked_across_records() {
    let a = record("a");
    let b = record("b");
    let stray = omgs::fingerprint("class_c", "GET /api/x", "db.x", "tenant");

    let mut bad = a.clone();
    bad.candidates = vec!["nope".into()];
    assert!(has(
        &validate(&file(vec![bad])),
        "is not an omgs fingerprint"
    ));

    let mut own = a.clone();
    own.candidates = vec![a.fingerprint.clone()];
    assert!(has(&validate(&file(vec![own])), "own fingerprint"));

    let mut other = a.clone();
    other.candidates = vec![b.fingerprint.clone()];
    assert!(has(
        &validate(&file(vec![other, b.clone()])),
        "another record's identity"
    ));

    let mut first = a.clone();
    first.candidates = vec![stray.clone()];
    let mut second = b.clone();
    second.candidates = vec![stray.clone()];
    assert!(has(
        &validate(&file(vec![first.clone(), second])),
        "already merged into findings[0]"
    ));

    first.candidates = vec![stray.clone(), stray];
    assert!(has(&validate(&file(vec![first])), "listed more than once"));
}

#[test]
fn ledger_transition_rules() {
    let mut ledger = Ledger::default();
    add_unit(
        &mut ledger,
        Unit::new("route:a", "app/a/route.ts", &["missing_authz"], "planned"),
    )
    .unwrap();
    assert!(
        add_unit(&mut ledger, Unit::new("route:a", "x", &[], "planned"))
            .unwrap_err()
            .contains("already exists")
    );
    assert!(add_unit(&mut ledger, Unit::new("x", "x", &[], "bogus")).is_err());
    assert!(add_unit(&mut ledger, Unit::new("y", "y", &[], "blocked"))
        .unwrap_err()
        .contains("requires a note"));

    let err = set_status(&mut ledger, "route:a", "covered", &[], None).unwrap_err();
    assert!(err.contains("requires at least one evidence"));
    assert_eq!(
        ledger.units[0].status, "planned",
        "a rejected change is not applied"
    );

    set_status(
        &mut ledger,
        "route:a",
        "covered",
        &["omgs-0123456789abcdef".into()],
        None,
    )
    .unwrap();
    set_status(
        &mut ledger,
        "route:a",
        "covered",
        &["omgs-0123456789abcdef".into()],
        None,
    )
    .unwrap();
    assert_eq!(
        ledger.units[0].evidence.len(),
        1,
        "evidence is not duplicated"
    );

    assert!(set_status(&mut ledger, "route:a", "deferred", &[], Some(" ")).is_err());
    set_status(
        &mut ledger,
        "route:a",
        "deferred",
        &[],
        Some("needs a running DB"),
    )
    .unwrap();
    assert!(validate_ledger(&ledger).is_empty());
    assert!(set_status(&mut ledger, "missing", "covered", &[], None)
        .unwrap_err()
        .contains("not found"));
}

#[test]
fn ledger_round_trip_keeps_unknown_fields() {
    let text = r#"{"units":[{"id":"u","surface":".","attack_classes":[],"status":"planned","owner":"red-2"}],"version":3}"#;
    let ledger: Ledger = serde_json::from_str(text).unwrap();
    let back = serde_json::to_value(&ledger).unwrap();
    assert_eq!(back["version"], 3);
    assert_eq!(back["units"][0]["owner"], "red-2");
    assert!(back["units"][0].get("evidence").is_none());
}

#[test]
fn ledger_rejects_duplicate_ids_and_bad_status() {
    let ledger: Ledger = serde_json::from_str(
        r#"{"units":[{"id":"u","surface":".","attack_classes":[],"status":"planned"},{"id":"u","surface":".","attack_classes":[],"status":"examined"}]}"#,
    )
    .unwrap();
    let errors = validate_ledger(&ledger);
    assert!(has(&errors, "duplicate unit id"));
    assert!(has(&errors, "status 'examined' is not one of"));
}

/// The prose fields every candidate must carry, filled with placeholders.
fn filled() -> Candidate {
    Candidate {
        source_ref: "abc123".into(),
        location: omgs::critic::CandidateLocation {
            path: "app/api/x/route.ts".into(),
            line: Some(3),
        },
        attacker_capability: "signed-in member of tenant A".into(),
        trace: "route reads id, no tenant check, returns row".into(),
        concrete_result: "tenant B row returned".into(),
        counterevidence: "no middleware or RLS applies".into(),
        proof_plan: "two tenants, assert 404 for the foreign row".into(),
        ..Candidate::default()
    }
}

/// A candidate as a hunter writes it to a candidates file.
fn candidate_json(c: &Candidate) -> serde_json::Value {
    serde_json::json!({
        "hunter": c.hunter, "unit_ids": c.unit_ids, "source_ref": c.source_ref,
        "title": c.title, "attack_class": c.attack_class, "entry_point": c.entry_point,
        "sink": c.sink, "boundary": c.boundary,
        "location": { "path": c.location.path, "line": c.location.line },
        "attacker_capability": c.attacker_capability, "trace": c.trace,
        "concrete_result": c.concrete_result, "counterevidence": c.counterevidence,
        "missing_fact": null, "intent_question": null, "proof_plan": c.proof_plan,
        "fingerprint": c.fingerprint
    })
}

/// A complete run: one unit covered by one verified finding from one candidate.
fn complete_run() -> (Ledger, Vec<SourcedCandidate>, FindingsFile) {
    let f = record("a");
    let mut ledger = Ledger::default();
    let mut unit = Unit::new("route:x", "app/api/x/route.ts", &["class_a"], "covered");
    unit.evidence = vec![f.fingerprint.clone()];
    ledger.units.push(unit);
    let c = Candidate {
        fingerprint: f.fingerprint.clone(),
        hunter: "red-1".into(),
        unit_ids: vec!["route:x".into()],
        title: f.title.clone(),
        attack_class: f.attack_class.clone(),
        entry_point: f.entry_point.clone(),
        sink: f.sink.clone(),
        boundary: f.boundary.clone(),
        ..filled()
    };
    let sc = SourcedCandidate {
        file: "candidates-red-1.json".into(),
        candidate: c,
    };
    (ledger, vec![sc], file(vec![f]))
}

#[test]
fn critic_passes_a_complete_run() {
    let (ledger, cands, findings) = complete_run();
    let report = critique(&ledger, 1, &cands, &findings);
    assert!(report.passed(), "{:?}", report.gaps);
    assert_eq!(report.summary(), "pass (1 units, 1 candidates, 1 findings)");
}

#[test]
fn critic_reports_each_gap_class() {
    let gaps =
        |l: &Ledger, n: usize, c: &[SourcedCandidate], f: &FindingsFile| critique(l, n, c, f).gaps;

    let (mut ledger, cands, findings) = complete_run();
    ledger
        .units
        .push(Unit::new("stack:node", ".", &[], "planned"));
    assert!(has(
        &gaps(&ledger, 1, &cands, &findings),
        "unit 'stack:node' is still planned"
    ));

    let (mut ledger, cands, findings) = complete_run();
    ledger.units[0].evidence.clear();
    let g = gaps(&ledger, 1, &cands, &findings);
    assert!(has(&g, "covered requires at least one evidence"));
    assert!(has(&g, "no ledger unit cites"));

    let (ledger, _cands, findings) = complete_run();
    assert!(has(
        &gaps(&ledger, 0, &[], &findings),
        "no candidates*.json file"
    ));
    assert!(has(
        &gaps(&ledger, 1, &[], &findings),
        "traces to no hunter candidate"
    ));

    let (ledger, mut cands, findings) = complete_run();
    cands[0].candidate.unit_ids = vec!["route:ghost".into()];
    assert!(has(
        &gaps(&ledger, 1, &cands, &findings),
        "unit 'route:ghost' is not in the ledger"
    ));

    let (ledger, mut cands, findings) = complete_run();
    cands[0].candidate.hunter = " ".into();
    assert!(has(
        &gaps(&ledger, 1, &cands, &findings),
        "hunter is not recorded"
    ));

    let (ledger, mut cands, findings) = complete_run();
    cands[0].candidate.sink = "db.other".into();
    assert!(has(
        &gaps(&ledger, 1, &cands, &findings),
        "does not match computed identity"
    ));

    let (ledger, mut cands, findings) = complete_run();
    let orphan = record("z");
    cands.push(SourcedCandidate {
        file: "candidates-red-2.json".into(),
        candidate: Candidate {
            fingerprint: orphan.fingerprint.clone(),
            hunter: "red-2".into(),
            unit_ids: vec!["route:x".into()],
            title: "Orphan".into(),
            attack_class: orphan.attack_class,
            entry_point: orphan.entry_point,
            sink: orphan.sink,
            boundary: orphan.boundary,
            ..filled()
        },
    });
    assert!(has(
        &gaps(&ledger, 2, &cands, &findings),
        "'Orphan' was never verified"
    ));

    let (ledger, cands, mut findings) = complete_run();
    findings.findings[0].verified_by = Some("blue-1".into());
    findings.findings[0].hunted_by = Some("red-9".into());
    assert!(has(
        &gaps(&ledger, 1, &cands, &findings),
        "hunted_by 'red-9' is not the hunter"
    ));

    // A verifier that also hunted a merged candidate is not independent.
    let (ledger, mut cands, mut findings) = complete_run();
    let merged = record("m");
    cands.push(SourcedCandidate {
        file: "candidates-blue.json".into(),
        candidate: Candidate {
            fingerprint: merged.fingerprint.clone(),
            hunter: "Blue-1".into(),
            unit_ids: vec!["route:x".into()],
            title: "Copy".into(),
            attack_class: merged.attack_class,
            entry_point: merged.entry_point,
            sink: merged.sink,
            boundary: merged.boundary,
            ..filled()
        },
    });
    findings.findings[0].candidates = vec![merged.fingerprint];
    assert!(has(
        &gaps(&ledger, 2, &cands, &findings),
        "verified_by 'blue-1' hunted a candidate"
    ));

    let (ledger, cands, mut findings) = complete_run();
    findings.findings[0].candidates = vec![record("q").fingerprint];
    assert!(has(
        &gaps(&ledger, 1, &cands, &findings),
        "is not in any candidates file"
    ));
}

#[test]
fn report_renders_critic_result() {
    let (ledger, cands, findings) = complete_run();
    let mut meta = ReportMeta {
        critic: Some(critique(&ledger, 1, &cands, &findings)),
        ..ReportMeta::default()
    };
    let html = render_html(&findings, &meta);
    assert!(html.contains("Coverage critic: pass (1 units, 1 candidates, 1 findings)"));
    assert!(render_markdown(&findings, &meta).contains("Coverage critic: pass"));

    meta.critic = Some(critique(&ledger, 0, &[], &findings));
    let html = render_html(&findings, &meta);
    assert!(html.contains("<ul class=\"gaps\"><li>no candidates*.json file"));
    let md = render_markdown(&findings, &meta);
    assert!(md.contains("## Coverage critic gaps\n\n- no candidates*.json file"));

    meta.critic = None;
    assert!(render_html(&findings, &meta).contains("Coverage critic: not run"));
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("omgs-wf-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn omgs(args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn cli_ledger_and_critic_end_to_end() {
    let dir = scratch("cli");
    let (ledger, cands, findings) = complete_run();
    let mut ledger = ledger;
    ledger.units[0].status = "planned".into();
    ledger.units[0].evidence.clear();
    let w = |name: &str, v: String| std::fs::write(dir.join(name), v).unwrap();
    w(
        "coverage-ledger.json",
        serde_json::to_string(&ledger).unwrap(),
    );
    w("findings.json", serde_json::to_string(&findings).unwrap());
    let c = &cands[0].candidate;
    w(
        "candidates-red-1.json",
        serde_json::json!({"candidates": [candidate_json(c)]}).to_string(),
    );
    let run = dir.to_str().unwrap();
    let ledger_path = dir.join("coverage-ledger.json");
    let lp = ledger_path.to_str().unwrap();

    let out = omgs(&["critic", "--run", run]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("still planned"));

    let out = omgs(&[
        "ledger", "set", "--ledger", lp, "--unit", "route:x", "--status", "covered",
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "covered without evidence is refused"
    );

    let fp = c.fingerprint.as_str();
    let out = omgs(&[
        "ledger",
        "set",
        "--ledger",
        lp,
        "--unit",
        "route:x",
        "--status",
        "covered",
        "--evidence",
        fp,
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = omgs(&["critic", "--run", run]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("critic: pass"));

    let out = omgs(&["ledger", "list", "--ledger", lp]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("covered: route:x (1 evidence)"));

    let report_dir = dir.join("out");
    let out = omgs(&[
        "report",
        "--findings",
        dir.join("findings.json").to_str().unwrap(),
        "--out",
        report_dir.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let md = std::fs::read_to_string(report_dir.join("REPORT.md")).unwrap();
    assert!(md.contains("Coverage critic: pass"));
    assert!(
        md.contains("verifier blue-1"),
        "verifier comes from the records"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn critic_includes_findings_validation() {
    let (ledger, cands, mut findings) = complete_run();
    findings.findings[0].verified_by = None;
    let gaps = critique(&ledger, 1, &cands, &findings).gaps;
    assert!(has(&gaps, "findings findings[0]"));
    assert!(has(&gaps, "verified_by is required"));
}

#[test]
fn critic_rejects_a_misspelled_candidates_file() {
    let dir = scratch("misspelled");
    let (ledger, _cands, _findings) = complete_run();
    std::fs::write(
        dir.join("coverage-ledger.json"),
        serde_json::to_string(&ledger).unwrap(),
    )
    .unwrap();
    std::fs::write(dir.join("findings.json"), r#"{"findings": []}"#).unwrap();
    std::fs::write(dir.join("candidates-red-1.json"), r#"{"candidate": []}"#).unwrap();
    let err = omgs::critic::critique_run(&dir).unwrap_err();
    assert!(err.contains("candidates-red-1.json"), "{err}");
    std::fs::write(dir.join("candidates-red-1.json"), r#"{"candidates": []}"#).unwrap();
    assert!(omgs::critic::critique_run(&dir).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn report_critic_describes_the_rendered_findings() {
    let dir = scratch("selected");
    let (ledger, cands, findings) = complete_run();
    std::fs::write(
        dir.join("coverage-ledger.json"),
        serde_json::to_string(&ledger).unwrap(),
    )
    .unwrap();
    let c = &cands[0].candidate;
    std::fs::write(
        dir.join("candidates-red-1.json"),
        serde_json::json!({"candidates": [candidate_json(c)]}).to_string(),
    )
    .unwrap();
    // A stale sibling findings.json must not be what the critic checks.
    std::fs::write(dir.join("findings.json"), r#"{"findings": []}"#).unwrap();
    std::fs::write(
        dir.join("selected.json"),
        serde_json::to_string(&findings).unwrap(),
    )
    .unwrap();
    let out_dir = dir.join("out");
    let out = omgs(&[
        "report",
        "--findings",
        dir.join("selected.json").to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let md = std::fs::read_to_string(out_dir.join("REPORT.md")).unwrap();
    assert!(md.contains("Coverage critic: pass (1 units, 1 candidates, 1 findings)"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn critic_gaps_are_escaped_in_html() {
    let (mut ledger, cands, findings) = complete_run();
    ledger.units.push(Unit::new(
        "<img src=x onerror=alert(1)>",
        ".",
        &[],
        "planned",
    ));
    let meta = ReportMeta {
        critic: Some(critique(&ledger, 1, &cands, &findings)),
        ..ReportMeta::default()
    };
    let html = render_html(&findings, &meta);
    assert!(!html.contains("<img src=x"));
    assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
}

#[test]
fn ledger_requires_the_units_key() {
    assert!(
        serde_json::from_str::<Ledger>(r#"{"unit": [{"id": "u", "status": "planned"}]}"#).is_err()
    );
    let empty: Ledger = serde_json::from_str(r#"{"units": []}"#).unwrap();
    assert!(empty.units.is_empty());
    let dir = scratch("units-key");
    std::fs::write(
        dir.join("coverage-ledger.json"),
        r#"{"unit": [{"id": "sensitive-route", "status": "planned"}]}"#,
    )
    .unwrap();
    std::fs::write(dir.join("findings.json"), r#"{"findings": []}"#).unwrap();
    std::fs::write(dir.join("candidates-red-1.json"), r#"{"candidates": []}"#).unwrap();
    let out = omgs(&["critic", "--run", dir.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a malformed ledger is an error, never a pass"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn findings_file_requires_the_findings_key() {
    assert!(serde_json::from_str::<FindingsFile>(r#"{"finding": [{"title": "x"}]}"#).is_err());
    assert!(serde_json::from_str::<FindingsFile>(r#"{"findings": []}"#).is_ok());
    let dir = scratch("findings-key");
    let mut ledger = Ledger::default();
    let mut unit = Unit::new("u", ".", &[], "covered");
    unit.evidence = vec!["path/a.ts".into()];
    ledger.units.push(unit);
    std::fs::write(
        dir.join("coverage-ledger.json"),
        serde_json::to_string(&ledger).unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.join("findings.json"),
        r#"{"finding": [{"title": "dropped"}]}"#,
    )
    .unwrap();
    std::fs::write(dir.join("candidates-red-1.json"), r#"{"candidates": []}"#).unwrap();
    assert_eq!(
        omgs(&["critic", "--run", dir.to_str().unwrap()])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        omgs(&[
            "validate",
            "--findings",
            dir.join("findings.json").to_str().unwrap()
        ])
        .status
        .code(),
        Some(2)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ledger_units_require_every_schema_field() {
    let full = r#"{"id":"u","surface":".","attack_classes":[],"status":"planned"}"#;
    assert!(serde_json::from_str::<Unit>(full).is_ok());
    for drop in [
        "\"surface\":\".\",",
        "\"attack_classes\":[],",
        ",\"status\":\"planned\"",
    ] {
        let text = full.replace(drop, "");
        assert!(
            serde_json::from_str::<Unit>(&text).is_err(),
            "accepted {text}"
        );
    }
    let mut ledger = Ledger::default();
    ledger.units.push(Unit::new("u", " ", &[], "planned"));
    assert!(validate_ledger(&ledger)
        .iter()
        .any(|e| e.contains("surface is empty")));
}

#[test]
fn candidates_require_every_schema_field() {
    let (_, cands, _) = complete_run();
    let full = candidate_json(&cands[0].candidate);
    assert!(serde_json::from_value::<Candidate>(full.clone()).is_ok());
    for key in [
        "hunter",
        "unit_ids",
        "source_ref",
        "title",
        "attack_class",
        "entry_point",
        "sink",
        "boundary",
        "location",
        "attacker_capability",
        "trace",
        "concrete_result",
        "counterevidence",
        "proof_plan",
        "fingerprint",
    ] {
        let mut v = full.clone();
        v.as_object_mut().unwrap().remove(key);
        assert!(
            serde_json::from_value::<Candidate>(v).is_err(),
            "accepted a candidate without {key}"
        );
    }
    for (key, wrong) in [
        ("trace", serde_json::json!(7)),
        ("location", serde_json::json!("app/x.ts")),
        ("unit_ids", serde_json::json!("route:x")),
    ] {
        let mut v = full.clone();
        v[key] = wrong;
        assert!(
            serde_json::from_value::<Candidate>(v).is_err(),
            "accepted a wrong type for {key}"
        );
    }
    let mut v = full.clone();
    v["severity"] = serde_json::json!("high");
    assert!(
        serde_json::from_value::<Candidate>(v).is_err(),
        "candidates never carry severity"
    );
    let mut v = full;
    v["trace"] = serde_json::json!(" ");
    let blank: Candidate = serde_json::from_value(v).unwrap();
    let (ledger, _, findings) = complete_run();
    let sc = SourcedCandidate {
        file: "c.json".into(),
        candidate: blank,
    };
    assert!(has(
        &critique(&ledger, 1, &[sc], &findings).gaps,
        "trace is empty"
    ));
}

#[test]
fn critic_flags_blank_identity_inputs_on_merged_candidates() {
    let (ledger, mut cands, mut findings) = complete_run();
    let blank = Candidate {
        fingerprint: omgs::fingerprint("class_m", "GET /api/x", "", "tenant"),
        hunter: "red-1".into(),
        unit_ids: vec!["route:x".into()],
        title: "Copy".into(),
        attack_class: "class_m".into(),
        entry_point: "GET /api/x".into(),
        sink: "".into(),
        boundary: "tenant".into(),
        ..filled()
    };
    findings.findings[0].candidates = vec![blank.fingerprint.clone()];
    cands.push(SourcedCandidate {
        file: "candidates-red-1.json".into(),
        candidate: blank,
    });
    let gaps = critique(&ledger, 1, &cands, &findings).gaps;
    assert!(has(&gaps, "'Copy': sink is empty"), "{gaps:?}");
}

#[cfg(unix)]
#[test]
fn critic_refuses_symlinked_candidate_files() {
    let dir = scratch("symlinked-candidates");
    let (ledger, cands, findings) = complete_run();
    std::fs::write(
        dir.join("coverage-ledger.json"),
        serde_json::to_string(&ledger).unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.join("findings.json"),
        serde_json::to_string(&findings).unwrap(),
    )
    .unwrap();
    let real = dir.join("elsewhere.json");
    std::fs::write(
        &real,
        serde_json::json!({"candidates": [candidate_json(&cands[0].candidate)]}).to_string(),
    )
    .unwrap();
    std::os::unix::fs::symlink(&real, dir.join("candidates-other.json")).unwrap();
    let err = omgs::critic::critique_run(&dir).unwrap_err();
    assert!(
        err.contains("candidates-other.json is not a regular file"),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
