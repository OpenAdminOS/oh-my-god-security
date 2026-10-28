use omgs::critic::{critique, Candidate, SourcedCandidate};
use omgs::ledger::{add_unit, set_status, validate_ledger, Ledger, Unit};
use omgs::model::{validate, Finding, FindingsFile, Location, ProofTier, Severity, Verdict};
use omgs::report::{render_html, render_markdown, render_sarif, ReportMeta};

// Valid storage fixtures must have the same owner and ACL as runtime files,
// including when the Windows test process has an elevated token.
fn write_private_fixture(
    path: impl AsRef<std::path::Path>,
    bytes: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    omgs::runmeta::write_atomic_bytes(path.as_ref(), bytes.as_ref())
}

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
        intent_id: None,
        family: None,
        prerequisites: None,
        hunted_by: Some("red-1".into()),
        verified_by: Some("blue-1".into()),
        candidates: vec![],
        proof_ref: None,
        trace: vec![],
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
/// Write a clean failing-test proof record for every record above traced and
/// point it there, as `omgs prove --run --finding` would.
fn attest(dir: &std::path::Path, mut findings: FindingsFile) -> FindingsFile {
    for f in findings.findings.iter_mut() {
        if f.proof_tier == ProofTier::Traced {
            continue;
        }
        let (n, proof_dir) = omgs::proof::reserve(dir).unwrap();
        let proof_dir = proof_dir.canonicalize().unwrap();
        let os = std::env::consts::OS;
        let executor = omgs::sandbox::this_executor().unwrap();
        let tier = if f.proof_tier == ProofTier::TestProven {
            omgs::sandbox::Tier::Test
        } else {
            omgs::sandbox::Tier::LocalApp
        };
        let nonce = "a".repeat(64);
        let command = "npm test -- tests/security/x.test.ts";
        let wrapped =
            omgs::sandbox::wrapped_command(os, command, &nonce, Some("tests/security/x.test.ts"));
        let allowed_marker = proof_dir.join("markers/allowed");
        let config = omgs::sandbox::mxc_config(&omgs::sandbox::ConfigInput {
            contract: None,
            os,
            containment: executor.containment,
            command: &wrapped,
            timeout_ms: 1000,
            workspace: &proof_dir.join("workspace"),
            scratch: &proof_dir.join("scratch"),
            allowed_marker: if os == "macos" {
                Some(allowed_marker.as_path())
            } else {
                None
            },
            readonly: vec![],
            denied: if os == "macos" {
                vec![proof_dir.join("markers/denied")]
            } else {
                vec![]
            },
            rust: None,
            list_parents: false,
        })
        .to_string();
        std::fs::write(proof_dir.join("mxc-config.json"), &config).unwrap();
        std::fs::write(proof_dir.join("command.txt"), command).unwrap();
        let record = omgs::proof::ProofRecord {
            schema: omgs::proof::SCHEMA.into(),
            n,
            finding: Some(f.fingerprint.clone()),
            test: Some("tests/security/x.test.ts".into()),
            test_sha256: Some("0".repeat(64)),
            test_from: None,
            replays: None,
            tier: if f.proof_tier == ProofTier::TestProven {
                "test"
            } else {
                "local_app"
            }
            .into(),
            command: omgs::proof::redact(command),
            command_sha256: omgs::sha256::digest(command.as_bytes()),
            wrapped_command_sha256: omgs::sha256::digest(wrapped.as_bytes()),
            readable_roots: vec![],
            system_root: (os == "windows")
                .then(|| std::env::var("SYSTEMROOT").unwrap_or_else(|_| r"C:\Windows".into())),
            target: None,
            target_head: None,
            target_sha256: None,
            proof_dir: proof_dir.to_string_lossy().into(),
            marker_nonce: nonce,
            command_started: true,
            command_finished: true,
            test_reachable: Some(true),
            timeout_ms: 1000,
            started_at_ms: 0,
            duration_ms: 1,
            exit_code: Some(1),
            contract: omgs::proof::Contract::None,
            timed_out: false,
            capture_complete: true,
            cleanup_complete: true,
            executor_error: false,
            killed: false,
            interrupted: false,
            survivors: vec![],
            mxc_version: omgs::sandbox::MXC_VERSION.into(),
            containment: executor.containment.into(),
            executor: executor.file.into(),
            executor_sha256: executor.sha256.into(),
            config_sha256: omgs::sha256::digest(config.as_bytes()),
            enforced: {
                let mut controls = omgs::sandbox::declared_controls(os, tier).0;
                controls.push("wall_clock=1000ms".into());
                controls
            },
            gaps: omgs::sandbox::declared_controls(os, tier).1,
            notes: vec![],
            output_sha256: omgs::sha256::digest(b""),
            output_bytes_total: 0,
            output: String::new(),
            omgs_version: "test".into(),
        };
        omgs::proof::write(dir, &record).unwrap();
        f.proof_ref = Some(omgs::proof::reference(n));
    }
    findings
}

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
    static BASE: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    let base = BASE.get_or_init(|| {
        let base =
            std::env::temp_dir().join(format!("omgs-private-fixtures-{}", std::process::id()));
        omgs::platform::create_private_tree(&base).unwrap();
        base
    });
    let dir = base.join(format!("omgs-wf-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    omgs::platform::private_dir(&dir).unwrap();
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
    let findings = attest(&dir, findings);
    let mut ledger = ledger;
    ledger.units[0].status = "planned".into();
    ledger.units[0].evidence.clear();
    let w = |name: &str, v: String| write_private_fixture(dir.join(name), v).unwrap();
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
    write_private_fixture(
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
    let findings = attest(&dir, findings);
    write_private_fixture(
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
    write_private_fixture(
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
    write_private_fixture(
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
    write_private_fixture(
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

#[test]
fn array_shaped_and_null_inputs_are_errors() {
    use omgs::shape;
    assert!(shape::candidates("[[]]").is_err());
    assert!(shape::candidates(r#"{"candidates": [[]]}"#).is_err());
    assert!(shape::findings("[[]]").is_err());
    assert!(shape::ledger("[[]]").is_err());
    assert!(shape::ledger(r#"{"units": [["u", ".", [], "planned"]]}"#).is_err());
    let (_, cands, findings) = complete_run();
    let mut c = candidate_json(&cands[0].candidate);
    c["location"] = serde_json::json!(["app/x.ts", 3]);
    assert!(
        shape::candidates(&serde_json::json!({"candidates": [c.clone()]}).to_string()).is_err()
    );
    c["location"] = serde_json::json!({"path": "app/x.ts", "line": null});
    assert!(
        shape::candidates(&serde_json::json!({"candidates": [c.clone()]}).to_string()).is_err()
    );
    c["location"] = serde_json::json!({"path": "app/x.ts"});
    assert!(shape::candidates(&serde_json::json!({"candidates": [c]}).to_string()).is_ok());
    let mut f = serde_json::to_value(&findings).unwrap();
    f["findings"][0]["location"]["line"] = serde_json::json!(null);
    assert!(shape::findings(&f.to_string()).is_err());

    // End to end: an otherwise complete run with a positional candidates file fails.
    let dir = scratch("array-shapes");
    let (ledger, _, findings) = complete_run();
    write_private_fixture(
        dir.join("coverage-ledger.json"),
        serde_json::to_string(&ledger).unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.join("findings.json"),
        serde_json::to_string(&findings).unwrap(),
    )
    .unwrap();
    std::fs::write(dir.join("candidates-red-1.json"), "[[]]").unwrap();
    assert_eq!(
        omgs(&["critic", "--run", dir.to_str().unwrap()])
            .status
            .code(),
        Some(2)
    );
    std::fs::write(dir.join("findings.json"), "[[]]").unwrap();
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
fn duplicate_keys_and_enum_objects_are_errors() {
    use omgs::shape;
    assert!(shape::findings(r#"{"findings":[{}],"findings":[]}"#).is_err());
    assert!(shape::ledger(r#"{"units":[],"units":[]}"#).is_err());
    assert!(shape::candidates(r#"{"candidates":[],"candidates":[]}"#).is_err());
    let (_, cands, findings) = complete_run();
    let mut c = candidate_json(&cands[0].candidate).to_string();
    c = c.replacen(
        "\"hunter\":\"red-1\"",
        "\"hunter\":\"red-1\",\"hunter\":\"blue-1\"",
        1,
    );
    assert!(c.contains("\"hunter\":\"blue-1\""), "test setup");
    assert!(shape::candidates(&format!("{{\"candidates\":[{c}]}}")).is_err());
    for (key, form) in [
        ("verdict", serde_json::json!({"confirmed": null})),
        ("proof_tier", serde_json::json!({"test_proven": null})),
        ("severity", serde_json::json!({"high": null})),
    ] {
        let mut f = serde_json::to_value(&findings).unwrap();
        f["findings"][0][key] = form;
        assert!(
            shape::findings(&f.to_string()).is_err(),
            "{key} object form accepted"
        );
    }
    assert!(shape::ledger(
        r#"{"units":[{"id":"u","surface":".","attack_classes":[],"status":{"covered":null}}]}"#
    )
    .is_err());
    assert!(shape::findings(&serde_json::to_string(&findings).unwrap()).is_ok());
}

#[test]
fn report_fails_on_malformed_companion_files() {
    let dir = scratch("report-malformed");
    let (ledger, _, findings) = complete_run();
    let findings = attest(&dir, findings);
    std::fs::write(
        dir.join("findings.json"),
        serde_json::to_string(&findings).unwrap(),
    )
    .unwrap();
    let report = |dir: &std::path::Path| {
        omgs(&[
            "report",
            "--findings",
            dir.join("findings.json").to_str().unwrap(),
            "--out",
            dir.join("out").to_str().unwrap(),
        ])
    };
    write_private_fixture(dir.join("coverage-ledger.json"), "{").unwrap();
    assert_eq!(report(&dir).status.code(), Some(2), "malformed ledger");
    write_private_fixture(
        dir.join("coverage-ledger.json"),
        serde_json::to_string(&ledger).unwrap(),
    )
    .unwrap();
    std::fs::write(dir.join("candidates-red-1.json"), "[[]]").unwrap();
    assert_eq!(report(&dir).status.code(), Some(2), "malformed candidates");
    assert!(!dir.join("out/REPORT.html").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn zero_lines_and_dangling_ledgers_are_errors() {
    let mut f = record("a");
    f.locations = vec![copy_at("copied.swift", 0)];
    assert!(has(
        &validate(&file(vec![f.clone()])),
        "line must be one-based"
    ));
    let mut v = serde_json::to_value(file(vec![f])).unwrap();
    assert!(omgs::shape::findings(&v.to_string()).is_err());
    v["findings"][0]["locations"] = serde_json::json!([]);
    v["findings"][0]["severity"] = serde_json::json!("high");
    assert!(omgs::shape::findings(&v.to_string()).is_ok());
    let mut open = record("b");
    open.verdict = Verdict::NeedsValidation;
    open.severity = None;
    open.proof_tier = ProofTier::Traced;
    assert!(
        omgs::shape::findings(&serde_json::to_string(&file(vec![open])).unwrap()).is_ok(),
        "a serialized absent severity (null) parses"
    );
    #[cfg(unix)]
    {
        let dir = scratch("dangling-ledger");
        let (_, _, findings) = complete_run();
        let findings = attest(&dir, findings);
        std::fs::write(
            dir.join("findings.json"),
            serde_json::to_string(&findings).unwrap(),
        )
        .unwrap();
        std::os::unix::fs::symlink(dir.join("nowhere.json"), dir.join("coverage-ledger.json"))
            .unwrap();
        let out = omgs(&[
            "report",
            "--findings",
            dir.join("findings.json").to_str().unwrap(),
            "--out",
            dir.join("out").to_str().unwrap(),
        ]);
        assert_eq!(out.status.code(), Some(2));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn round_trips_flag_values_and_ledgerless_candidates() {
    // A location without a line survives serialization and strict parsing.
    let mut f = record("a");
    f.location.line = None;
    f.locations = vec![Location {
        path: "b.ts".into(),
        line: None,
    }];
    let text = serde_json::to_string(&file(vec![f])).unwrap();
    assert!(!text.contains("\"line\":null"));
    assert!(omgs::shape::findings(&text).is_ok());

    let dir = scratch("flags-and-candidates");
    let (ledger, _, _) = complete_run();
    let lp = dir.join("coverage-ledger.json");
    std::fs::write(&lp, serde_json::to_string(&ledger).unwrap()).unwrap();
    let before = std::fs::read(&lp).unwrap();
    for args in [
        vec![
            "--status",
            "blocked",
            "--evidence",
            "--note",
            "needs a database",
        ],
        vec!["--status", "blocked", "--note"],
    ] {
        let mut full = vec![
            "ledger",
            "set",
            "--ledger",
            lp.to_str().unwrap(),
            "--unit",
            "route:x",
        ];
        full.extend(args);
        let out = omgs(&full);
        assert_eq!(out.status.code(), Some(2), "{full:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("requires a value"));
        assert_eq!(std::fs::read(&lp).unwrap(), before, "nothing written");
    }

    std::fs::remove_file(&lp).unwrap();
    std::fs::write(dir.join("findings.json"), r#"{"findings": []}"#).unwrap();
    std::fs::write(dir.join("candidates-red.json"), "[[]]").unwrap();
    let out = omgs(&[
        "report",
        "--findings",
        dir.join("findings.json").to_str().unwrap(),
        "--out",
        dir.join("out").to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(!dir.join("out/REPORT.html").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ledger_notes_must_be_strings() {
    let unit = |note: &str| {
        format!(
            r#"{{"units":[{{"id":"u","surface":".","attack_classes":[],"status":"planned","note":{note}}}]}}"#
        )
    };
    assert!(omgs::shape::ledger(&unit("null")).is_err());
    assert!(omgs::shape::ledger(&unit("7")).is_err());
    assert!(omgs::shape::ledger(&unit(r#""why""#)).is_ok());
}

#[test]
fn report_fails_on_malformed_sensors_and_ignores_unrelated_candidate_names() {
    let dir = scratch("sensors-bad");
    std::fs::write(dir.join("findings.json"), r#"{"findings": []}"#).unwrap();
    std::fs::write(dir.join("candidates-notes.md"), "notes").unwrap();
    let report = || {
        omgs(&[
            "report",
            "--findings",
            dir.join("findings.json").to_str().unwrap(),
            "--out",
            dir.join("out").to_str().unwrap(),
        ])
    };
    assert!(
        report().status.success(),
        "a stray candidates-notes.md is not a candidates file"
    );
    std::fs::write(dir.join("sensors.json"), "{\"tools_run\": [").unwrap();
    assert_eq!(report().status.code(), Some(2), "truncated sensors.json");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sensors_documents_must_be_objects() {
    assert!(omgs::shape::sensors("[[],[],[]]").is_err());
    assert!(omgs::shape::sensors(
        r#"{"tools_run":[],"tools_unavailable":[],"hits":[["gitleaks","r","f",1,false]]}"#
    )
    .is_err());
    assert!(
        omgs::shape::sensors(r#"{"tools_run":[],"tools_unavailable":[],"hits":[],"hits":[]}"#)
            .is_err()
    );
    assert!(omgs::shape::sensors(r#"{"tools_run":["gitleaks"],"tools_unavailable":[],"hits":[{"tool":"gitleaks","rule":"r","file":"f","line":1,"vendored":false}]}"#).is_ok());
    let dir = scratch("sensors-array");
    std::fs::write(dir.join("findings.json"), r#"{"findings": []}"#).unwrap();
    std::fs::write(dir.join("sensors.json"), "[[],[],[]]").unwrap();
    let out = omgs(&[
        "report",
        "--findings",
        dir.join("findings.json").to_str().unwrap(),
        "--out",
        dir.join("out").to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn forged_or_broken_proof_records_are_rejected() {
    let dir = scratch("forged");
    let (_, _, findings) = complete_run();
    let findings = attest(&dir, findings);
    let check = |dir: &std::path::Path| omgs::proof::validate_proofs(&findings, dir);
    assert!(check(&dir).is_empty(), "{:?}", check(&dir));
    let record_path = dir.join("proofs/1.json");
    let original = std::fs::read_to_string(&record_path).unwrap();
    let edit = |f: &dyn Fn(&mut serde_json::Value)| {
        let mut v: serde_json::Value = serde_json::from_str(&original).unwrap();
        f(&mut v);
        std::fs::write(&record_path, v.to_string()).unwrap();
    };
    type Change = dyn Fn(&mut serde_json::Value);
    let cases: [(&str, &Change); 10] = [
        ("was recorded for finding", &|v| {
            v["finding"] = "omgs-0000000000000000".into()
        }),
        ("cannot support", &|v| v["tier"] = "local_app".into()),
        ("saved command does not match", &|v| {
            v["command"] = "exit 1".into()
        }),
        ("not a pinned MXC", &|v| {
            v["executor_sha256"] = "1".repeat(64).into()
        }),
        ("claims containment", &|v| v["containment"] = "none".into()),
        ("does not match the MXC config", &|v| {
            v["config_sha256"] = "2".repeat(64).into()
        }),
        ("no enforced controls", &|v| {
            v["enforced"] = serde_json::json!([])
        }),
        ("proof support requires assertion exit", &|v| {
            v["exit_code"] = 127.into()
        }),
        ("did not finish cleanly", &|v| {
            v["cleanup_complete"] = false.into()
        }),
        ("names no proof test", &|v| {
            v["test_sha256"] = serde_json::Value::Null
        }),
    ];
    for (needle, change) in cases {
        edit(change);
        let errors = check(&dir);
        assert!(has(&errors, needle), "{needle}: {errors:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn report_and_critic_refuse_a_confirmed_record_without_a_proof() {
    let dir = scratch("unproven");
    let (ledger, cands, findings) = complete_run();
    let w = |name: &str, v: String| std::fs::write(dir.join(name), v).unwrap();
    w(
        "coverage-ledger.json",
        serde_json::to_string(&ledger).unwrap(),
    );
    w(
        "candidates-red-1.json",
        serde_json::json!({"candidates": [candidate_json(&cands[0].candidate)]}).to_string(),
    );
    // Confirmed and test_proven, but no proof record was ever written.
    w("findings.json", serde_json::to_string(&findings).unwrap());
    let report = omgs(&[
        "report",
        "--findings",
        dir.join("findings.json").to_str().unwrap(),
        "--out",
        dir.join("out").to_str().unwrap(),
    ]);
    assert_eq!(report.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&report.stderr).contains("requires proof_ref"));
    let critic = omgs(&["critic", "--run", dir.to_str().unwrap()]);
    assert!(!critic.status.success());
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&critic.stdout),
        String::from_utf8_lossy(&critic.stderr)
    );
    assert!(said.contains("requires proof_ref"), "{said}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn saved_configs_are_checked_even_when_their_digest_matches() {
    let dir = scratch("config-policy");
    let (_, _, findings) = complete_run();
    let findings = attest(&dir, findings);
    let config_path = dir.join("proofs/1/mxc-config.json");
    let original: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    let mut record = omgs::proof::load(&dir, "proofs/1.json").unwrap();
    for (pointer, value, needle) in [
        ("/containment", serde_json::json!("none"), "containment"),
        (
            "/process/commandLine",
            serde_json::json!("exit 1"),
            "wrapped record.command",
        ),
        (
            "/process/cwd",
            serde_json::json!("/elsewhere/workspace"),
            "cwd",
        ),
        (
            "/network/egress/default",
            serde_json::json!("allow"),
            "egress",
        ),
        (
            "/network/ingress/default",
            serde_json::json!("allow"),
            "ingress",
        ),
        (
            "/network/ingress/hostLoopback",
            serde_json::json!("allow"),
            "hostLoopback",
        ),
        (
            "/filesystem/readwritePaths",
            serde_json::json!(["/"]),
            "readwritePaths",
        ),
        // The other platform's timeout policy: Windows saves 0, Unix the budget.
        (
            "/process/timeout",
            serde_json::json!(if cfg!(windows) { 1000 } else { 0 }),
            "timeout",
        ),
        ("/process/timeout", serde_json::json!(2000), "timeout"),
        (
            "/filesystem/readonlyPaths",
            serde_json::json!(["/"]),
            "readonlyPaths",
        ),
        (
            "/filesystem/readonlyPaths",
            serde_json::json!(["/opt/homebrew"]),
            "readonlyPaths",
        ),
        (
            "/filesystem/deniedPaths",
            serde_json::json!(null),
            "deniedPaths",
        ),
        (
            "/filesystem/deniedPaths",
            serde_json::json!(["/elsewhere/denied"]),
            "deniedPaths",
        ),
        (
            "/process/env",
            serde_json::json!(["AWS_SECRET_ACCESS_KEY=secret"]),
            "allowlisted",
        ),
        (
            "/process/env",
            serde_json::json!(["PATH=/bin", "PATH=/elsewhere"]),
            "allowlisted",
        ),
    ] {
        let mut config = original.clone();
        *config.pointer_mut(pointer).unwrap() = value;
        let text = config.to_string();
        record.config_sha256 = omgs::sha256::digest(text.as_bytes());
        std::fs::write(&config_path, text).unwrap();
        omgs::proof::write(&dir, &record).unwrap();
        let errors = omgs::proof::validate_proofs(&findings, &dir);
        assert!(has(&errors, needle), "{pointer}: {errors:?}");
    }
    let text = original.to_string();
    record.config_sha256 = omgs::sha256::digest(text.as_bytes());
    std::fs::write(&config_path, &text).unwrap();
    record.test_from = Some("outside-draft".into());
    record.test_sha256 = Some(omgs::sha256::digest(b"draft"));
    std::fs::write(dir.join("proofs/1/test-draft"), b"draft").unwrap();
    omgs::proof::write(&dir, &record).unwrap();
    assert!(omgs::proof::validate_proofs(&findings, &dir).is_empty());
    std::fs::write(dir.join("proofs/1/test-draft"), b"changed").unwrap();
    assert!(has(
        &omgs::proof::validate_proofs(&findings, &dir),
        "test-draft"
    ));
    record.test_from = None;
    record.output = "changed".into();
    omgs::proof::write(&dir, &record).unwrap();
    assert!(has(
        &omgs::proof::validate_proofs(&findings, &dir),
        "output_sha256"
    ));
    record.output.clear();
    write_private_fixture(
        dir.join("run-metadata.json"),
        serde_json::json!({"target": dir.join("target")} ).to_string(),
    )
    .unwrap();
    omgs::proof::write(&dir, &record).unwrap();
    assert!(has(
        &omgs::proof::validate_proofs(&findings, &dir),
        "target must be present"
    ));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn every_proven_verdict_requires_a_valid_inner_exit_and_clean_markers() {
    let dir = scratch("verdict-exits");
    let (_, _, findings) = complete_run();
    let findings = attest(&dir, findings);
    let original = omgs::proof::load(&dir, "proofs/1.json").unwrap();
    for verdict in [
        Verdict::Confirmed,
        Verdict::NeedsValidation,
        Verdict::Rejected,
    ] {
        for reachable in [None, Some(false)] {
            for exit in [0, 1] {
                let mut findings = findings.clone();
                findings.findings[0].verdict = verdict;
                let mut record = original.clone();
                record.test_reachable = reachable;
                record.exit_code = Some(exit);
                omgs::proof::write(&dir, &record).unwrap();
                let errors = omgs::proof::validate_proofs(&findings, &dir);
                assert!(has(&errors, "did not finish cleanly"), "{errors:?}");
                assert!(
                    has(&errors, "not reachable inside the sandbox"),
                    "{errors:?}"
                );
            }
        }
        for code in [
            None,
            Some(-1),
            Some(0),
            Some(1),
            Some(2),
            Some(3),
            Some(125),
            Some(126),
            Some(127),
            Some(137),
        ] {
            let mut findings = findings.clone();
            findings.findings[0].verdict = verdict;
            let mut record = original.clone();
            record.exit_code = code;
            omgs::proof::write(&dir, &record).unwrap();
            let errors = omgs::proof::validate_proofs(&findings, &dir);
            let allowed = matches!(code, Some(1 | 3..=125))
                || (verdict == Verdict::Rejected && code == Some(0));
            assert_eq!(
                errors.is_empty(),
                allowed,
                "{verdict:?} {code:?}: {errors:?}"
            );
        }
    }
    for field in ["command_started", "command_finished"] {
        let mut record = serde_json::to_value(&original).unwrap();
        record[field] = false.into();
        std::fs::write(dir.join("proofs/1.json"), record.to_string()).unwrap();
        assert!(has(
            &omgs::proof::validate_proofs(&findings, &dir),
            "did not finish cleanly"
        ));
    }
    let _ = std::fs::remove_dir_all(dir);
}

// Update a synthetic runner config when constructing a contracted fixture.
fn bind_contract(dir: &std::path::Path, record: &mut omgs::proof::ProofRecord) {
    let path = dir.join(format!("proofs/{}/mxc-config.json", record.n));
    let mut config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let env = config["process"]["env"].as_array_mut().unwrap();
    env.retain(|v| !v.as_str().unwrap().starts_with("OMGS_PROOF_"));
    env.push(
        format!(
            "OMGS_PROOF_CONTRACT={}",
            record.contract.expect_marker().unwrap_or("none")
        )
        .into(),
    );
    if record.contract.expect_marker().is_some() {
        env.push(format!("OMGS_PROOF_NONCE={}", record.marker_nonce).into());
    }
    let text = config.to_string();
    std::fs::write(path, &text).unwrap();
    record.config_sha256 = omgs::sha256::digest(text.as_bytes());
}

#[test]
fn linked_proof_contract_requires_boundary_control_and_assertion_exit() {
    let dir = scratch("proof-contract");
    let (_, _, findings) = complete_run();
    let findings = attest(&dir, findings);
    let original = omgs::proof::load(&dir, "proofs/1.json").unwrap();
    for (label, exit, boundary, control, allowed) in [
        ("import failure", 2, false, false, false),
        ("control failure", 2, false, false, false),
        ("missing boundary", 1, false, true, false),
        ("missing control", 1, true, false, false),
        ("dependency failure", 2, false, true, false),
        ("harness error with markers", 2, true, true, false),
        ("other assertion exit", 3, true, true, false),
        ("fixed", 0, false, true, false),
        ("boundary beyond saved cap", 1, true, true, true),
    ] {
        let mut record = original.clone();
        record.contract = omgs::proof::Contract::Recipe {
            expect_marker: "BOUNDARY_ASSERTION_FAILED".into(),
            boundary_marker_seen: boundary,
            authorized_control_seen: control,
        };
        bind_contract(&dir, &mut record);
        record.exit_code = Some(exit);
        // Saved output contains neither marker. The runner's full-stream
        // evidence must be used rather than re-scanning this capped prefix.
        assert!(record.output.is_empty());
        omgs::proof::write(&dir, &record).unwrap();
        let errors = omgs::proof::validate_proofs(&findings, &dir);
        assert_eq!(errors.is_empty(), allowed, "{label}: {errors:?}");
    }
    for marker in [
        "",
        "AUTHORIZED_CONTROL_OK",
        "OMGS_START_fake",
        "has space",
        "has\nnewline",
    ] {
        let mut record = original.clone();
        record.contract = omgs::proof::Contract::Recipe {
            expect_marker: marker.into(),
            boundary_marker_seen: true,
            authorized_control_seen: true,
        };
        omgs::proof::write(&dir, &record).unwrap();
        assert!(!omgs::proof::validate_proofs(&findings, &dir).is_empty());
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn contract_deletions_nulls_and_downgrades_fail_validation_and_replay() {
    let dir = scratch("contract-tampering");
    write_private_fixture(dir.join(omgs::runmeta::FILE), "{}").unwrap();
    let (_, _, findings) = complete_run();
    let findings = attest(&dir, findings);
    let findings_path = dir.join("findings.json");
    std::fs::write(&findings_path, serde_json::to_vec(&findings).unwrap()).unwrap();
    let mut record = omgs::proof::load(&dir, "proofs/1.json").unwrap();
    record.contract = omgs::proof::Contract::Recipe {
        expect_marker: "BOUNDARY_ASSERTION_FAILED".into(),
        boundary_marker_seen: true,
        authorized_control_seen: true,
    };
    bind_contract(&dir, &mut record);
    omgs::proof::write(&dir, &record).unwrap();
    assert!(omgs::proof::validate_proofs(&findings, &dir).is_empty());
    let original = serde_json::to_value(&record).unwrap();
    let path = dir.join("proofs/1.json");
    for field in [
        "contract",
        "kind",
        "expect_marker",
        "boundary_marker_seen",
        "authorized_control_seen",
    ] {
        for null in [false, true] {
            let mut value = original.clone();
            let parent = if field == "contract" {
                &mut value
            } else {
                &mut value["contract"]
            };
            if null {
                parent[field] = serde_json::Value::Null;
            } else {
                parent.as_object_mut().unwrap().remove(field);
            }
            std::fs::write(&path, value.to_string()).unwrap();
            assert!(
                !omgs::proof::validate_proofs(&findings, &dir).is_empty(),
                "{field} null={null}"
            );
            for args in [
                vec!["validate", "--findings", findings_path.to_str().unwrap()],
                vec!["prove", "--run", dir.to_str().unwrap(), "--replay", "1"],
            ] {
                let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
                    .args(args)
                    .output()
                    .unwrap();
                assert!(!out.status.success(), "{field} null={null}");
                assert!(
                    String::from_utf8_lossy(&out.stderr).contains("proof:"),
                    "{}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
    }
    // A valid explicit none declaration cannot replace a contracted record.
    // The saved config digest and reconstruction bind the contract to command.txt.
    for mutation in ["none", "label", "nonce", "command", "legacy"] {
        let mut value = original.clone();
        match mutation {
            "none" => value["contract"] = serde_json::json!({"kind":"none"}),
            "label" => value["contract"]["expect_marker"] = "OTHER_BOUNDARY".into(),
            "nonce" => value["marker_nonce"] = "b".repeat(64).into(),
            "command" => value["command_sha256"] = "0".repeat(64).into(),
            "legacy" => {
                value["schema"] = "omgs-proof/1".into();
                value.as_object_mut().unwrap().remove("contract");
                value["expect_marker"] = "BOUNDARY_ASSERTION_FAILED".into();
            }
            _ => unreachable!(),
        }
        std::fs::write(&path, value.to_string()).unwrap();
        assert!(
            !omgs::proof::validate_proofs(&findings, &dir).is_empty(),
            "{mutation}"
        );
        for args in [
            vec!["validate", "--findings", findings_path.to_str().unwrap()],
            vec!["prove", "--run", dir.to_str().unwrap(), "--replay", "1"],
        ] {
            let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
                .args(args)
                .output()
                .unwrap();
            assert!(!out.status.success(), "{mutation}");
            if mutation != "legacy" && mutation != "command" {
                let error = String::from_utf8_lossy(&out.stderr);
                assert!(error.contains("invalid"), "{mutation}: {error}");
            }
            if mutation == "legacy" {
                let error = String::from_utf8_lossy(&out.stderr);
                assert!(
                    error.contains("predates the current policy")
                        && error.contains("rerun omgs prove"),
                    "{error}"
                );
            }
        }
    }
    assert!(!dir.join("proofs/3").exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn proof_and_trace_objects_reject_positional_shapes_and_bad_locations() {
    let dir = scratch("proof-shapes");
    let (_, _, findings) = complete_run();
    let findings = attest(&dir, findings);
    let path = dir.join("proofs/1.json");
    let original = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, "[]").unwrap();
    assert!(omgs::proof::load(&dir, "proofs/1.json")
        .unwrap_err()
        .contains("JSON object"));
    let mut record: serde_json::Value = serde_json::from_str(&original).unwrap();
    record["survivors"] = serde_json::json!([[1, "x"]]);
    std::fs::write(&path, record.to_string()).unwrap();
    assert!(omgs::proof::load(&dir, "proofs/1.json")
        .unwrap_err()
        .contains("JSON object"));
    let value = serde_json::to_value(findings).unwrap();
    for trace in [
        serde_json::json!([[{"path":"x","line":1}, "note"]]),
        serde_json::json!([{"location":["x",1], "note":"n"}]),
        serde_json::json!([{"location":{"path":"x","line":null}, "note":"n"}]),
        serde_json::json!([{"location":{"path":"x","line":0}, "note":"n"}]),
        serde_json::json!([{"location":{"path":"x","line":1.5}, "note":"n"}]),
    ] {
        let mut f = value.clone();
        f["findings"][0]["trace"] = trace;
        assert!(omgs::shape::findings(&f.to_string()).is_err());
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn archived_proofs_validate_with_the_original_config_paths() {
    let dir = scratch("archive-proof");
    let (_, _, findings) = complete_run();
    let findings = attest(&dir, findings);
    let archived = scratch("archived-proof");
    std::fs::remove_dir_all(&archived).unwrap();
    std::fs::rename(&dir, &archived).unwrap();
    let errors = omgs::proof::validate_proofs(&findings, &archived);
    assert!(errors.is_empty(), "{errors:?}");
    for reference in [
        "proofs/+1.json",
        "proofs/01.json",
        "proofs/0.json",
        "proofs/1/../1.json",
    ] {
        assert!(
            omgs::proof::load(&archived, reference).is_err(),
            "{reference}"
        );
    }
    assert!(omgs::proof::load(&archived, "proofs/1.json").is_ok());
    std::fs::remove_dir_all(archived).unwrap();
}

#[test]
fn proof_validation_checks_target_test_and_declared_gaps() {
    let dir = scratch("target-test-digest");
    let (_, _, findings) = complete_run();
    let findings = attest(&dir, findings);
    let mut record = omgs::proof::load(&dir, "proofs/1.json").unwrap();
    let target = dir.join("target");
    std::fs::create_dir_all(target.join("tests/security")).unwrap();
    let test = target.join(record.test.as_ref().unwrap());
    std::fs::write(&test, b"original test").unwrap();
    record.target = Some(target.to_string_lossy().into());
    record.target_sha256 = Some(omgs::proof::tree_digest(&target).unwrap());
    record.test_sha256 = Some(omgs::sha256::digest(b"original test"));
    omgs::proof::write(&dir, &record).unwrap();
    assert!(omgs::proof::validate_proofs(&findings, &dir).is_empty());
    std::fs::write(&test, b"changed test").unwrap();
    assert!(has(
        &omgs::proof::validate_proofs(&findings, &dir),
        "target test changed"
    ));
    std::fs::remove_file(&test).unwrap();
    assert!(has(
        &omgs::proof::validate_proofs(&findings, &dir),
        "target test changed"
    ));
    std::fs::write(test, b"original test").unwrap();
    let gaps = record.gaps.clone();
    for index in 0..gaps.len() {
        record.gaps = gaps.clone();
        record.gaps.remove(index);
        omgs::proof::write(&dir, &record).unwrap();
        assert!(has(
            &omgs::proof::validate_proofs(&findings, &dir),
            "required gap"
        ));
    }
    record.gaps = gaps;
    let readable = record
        .gaps
        .iter_mut()
        .find(|g| g.starts_with("readable toolchain"))
        .unwrap();
    *readable =
        "readable toolchain roots and caches (may contain private content): /old-host/cache".into();
    omgs::proof::write(&dir, &record).unwrap();
    assert!(omgs::proof::validate_proofs(&findings, &dir).is_empty());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn multiline_records_validate_and_dry_run_evidence_is_required() {
    for sep in ["\n", "\r\n"] {
        let dir = scratch(if sep == "\n" {
            "multiline-proof"
        } else {
            "crlf-proof"
        });
        let (_, _, findings) = complete_run();
        let findings = attest(&dir, findings);
        let mut record = omgs::proof::load(&dir, "proofs/1.json").unwrap();
        let command = format!("npm test -- tests/security/x.test.ts{sep}exit 1");
        record.command = command.clone();
        record.command_sha256 = omgs::sha256::digest(command.as_bytes());
        let wrapped = omgs::sandbox::wrapped_command(
            std::env::consts::OS,
            &command,
            &record.marker_nonce,
            record.test.as_deref(),
        );
        record.wrapped_command_sha256 = omgs::sha256::digest(wrapped.as_bytes());
        let config_path = dir.join("proofs/1/mxc-config.json");
        let mut config: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
        config["process"]["commandLine"] = wrapped.into();
        let text = config.to_string();
        record.config_sha256 = omgs::sha256::digest(text.as_bytes());
        std::fs::write(config_path, text).unwrap();
        std::fs::write(dir.join("proofs/1/command.txt"), command).unwrap();
        omgs::proof::write(&dir, &record).unwrap();
        assert!(omgs::proof::validate_proofs(&findings, &dir).is_empty());
        let mut old = serde_json::to_value(&record).unwrap();
        old.as_object_mut().unwrap().remove("notes");
        assert!(omgs::shape::proof(&old.to_string())
            .unwrap()
            .notes
            .is_empty());
        record.enforced.retain(|c| !c.contains("--dry-run"));
        omgs::proof::write(&dir, &record).unwrap();
        assert!(has(
            &omgs::proof::validate_proofs(&findings, &dir),
            "required control"
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn config_paths_cannot_move_independently_of_the_recorded_directory() {
    let dir = scratch("config-anchor");
    let (_, _, findings) = complete_run();
    let findings = attest(&dir, findings);
    let mut record = omgs::proof::load(&dir, "proofs/1.json").unwrap();
    let path = dir.join("proofs/1/mxc-config.json");
    let config = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&config).unwrap();
    let cwd = parsed["process"]["cwd"].as_str().unwrap();
    let original = cwd
        .strip_suffix("workspace")
        .unwrap()
        .trim_end_matches(['/', '\\']);
    let replacement = dir.join("unrelated/proofs/1").to_string_lossy().to_string();
    let original = serde_json::to_string(original).unwrap();
    let replacement = serde_json::to_string(&replacement).unwrap();
    let config = config.replace(
        &original[1..original.len() - 1],
        &replacement[1..replacement.len() - 1],
    );
    record.config_sha256 = omgs::sha256::digest(config.as_bytes());
    std::fs::write(path, config).unwrap();
    omgs::proof::write(&dir, &record).unwrap();
    let errors = omgs::proof::validate_proofs(&findings, &dir);
    assert!(has(&errors, "cwd"), "{errors:?}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn traced_findings_forbid_proof_references() {
    let dir = scratch("traced-proof-ref");
    let (_, _, findings) = complete_run();
    let mut findings = attest(&dir, findings);
    findings.findings[0].proof_tier = ProofTier::Traced;
    for reference in ["proofs/1.json", "proofs/01.json", "", "missing"] {
        findings.findings[0].proof_ref = Some(reference.into());
        assert!(has(
            &omgs::proof::validate_proofs(&findings, &dir),
            "traced findings must not carry proof_ref"
        ));
    }
    findings.findings[0].proof_ref = None;
    assert!(omgs::proof::validate_proofs(&findings, &dir).is_empty());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn saved_configs_use_recorded_roots_full_env_and_a_closed_schema() {
    let dir = scratch("recorded-home");
    let (_, _, findings) = complete_run();
    let findings = attest(&dir, findings);
    let mut record = omgs::proof::load(&dir, "proofs/1.json").unwrap();
    // Executor names are informational; its verified digest identifies it.
    record.executor = "renamed-executor".into();
    let os = std::env::consts::OS;
    let source_home = if cfg!(windows) {
        r"C:\Users\source-home"
    } else {
        "/source-home"
    };
    let cargo = std::path::Path::new(source_home).join(".cargo").join("bin");
    let rustup = std::path::Path::new(source_home).join(".rustup");
    record.readable_roots = vec![
        cargo.to_string_lossy().into(),
        rustup.to_string_lossy().into(),
    ];
    let proof_dir = std::path::PathBuf::from(&record.proof_dir);
    let command = omgs::proof::recorded_command(&dir, &record).unwrap();
    let wrapped =
        omgs::sandbox::wrapped_command(os, &command, &record.marker_nonce, record.test.as_deref());
    let allowed = proof_dir.join("markers/allowed");
    let config = omgs::sandbox::mxc_config(&omgs::sandbox::ConfigInput {
        contract: None,
        os,
        containment: &record.containment,
        command: &wrapped,
        timeout_ms: record.timeout_ms,
        workspace: &proof_dir.join("workspace"),
        scratch: &proof_dir.join("scratch"),
        allowed_marker: (os == "macos").then_some(allowed.as_path()),
        readonly: record
            .readable_roots
            .iter()
            .map(std::path::PathBuf::from)
            .collect(),
        denied: if os == "macos" {
            vec![proof_dir.join("markers/denied")]
        } else {
            vec![]
        },
        rust: Some(omgs::sandbox::RustHomes {
            bin: cargo,
            cargo_home: proof_dir.join("scratch").join("cargo-home"),
            rustup_home: Some(rustup),
        }),
        list_parents: false,
    });
    let config_path = proof_dir.join("mxc-config.json");
    let findings_path = dir.join("findings.json");
    std::fs::write(&findings_path, serde_json::to_vec(&findings).unwrap()).unwrap();
    let save = |config: &serde_json::Value, record: &mut omgs::proof::ProofRecord| {
        let bytes = serde_json::to_vec(config).unwrap();
        record.config_sha256 = omgs::sha256::digest(&bytes);
        std::fs::write(&config_path, bytes).unwrap();
        omgs::proof::write(&dir, record).unwrap();
    };
    save(&config, &mut record);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args(["validate", "--findings", findings_path.to_str().unwrap()])
        .env("HOME", dir.join("different-home"))
        .env("USERPROFILE", dir.join("different-home"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for key in [if cfg!(windows) { "USERPROFILE" } else { "HOME" }, "PATH"] {
        let mut forged = config.clone();
        let env = forged["process"]["env"].as_array_mut().unwrap();
        let entry = env
            .iter_mut()
            .find(|v| v.as_str().unwrap().starts_with(&format!("{key}=")))
            .unwrap();
        *entry = format!("{key}=/forged").into();
        save(&forged, &mut record);
        assert!(has(
            &omgs::proof::validate_proofs(&findings, &dir),
            "KEY=value"
        ));
    }
    for pointer in [
        "",
        "/process",
        "/filesystem",
        "/network",
        "/network/egress",
        "/network/ingress",
    ] {
        let mut forged = config.clone();
        forged
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), true.into());
        save(&forged, &mut record);
        assert!(
            has(
                &omgs::proof::validate_proofs(&findings, &dir),
                "closed runner schema"
            ),
            "{pointer}"
        );
    }
    save(&config, &mut record);
    record.survivors.push(omgs::proof::Survivor {
        pid: 123,
        command: "tool --client_secret private-value".into(),
    });
    omgs::proof::write(&dir, &record).unwrap();
    assert!(!std::fs::read_to_string(dir.join("proofs/1.json"))
        .unwrap()
        .contains("private-value"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn validation_and_replay_reject_special_tests_within_a_second() {
    let dir = scratch("special-proof-test");
    let (ledger, cands, findings) = complete_run();
    let findings = attest(&dir, findings);
    write_private_fixture(
        dir.join("coverage-ledger.json"),
        serde_json::to_vec(&ledger).unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.join("candidates-red-1.json"),
        serde_json::json!({"candidates": [candidate_json(&cands[0].candidate)]}).to_string(),
    )
    .unwrap();
    std::fs::write(
        dir.join("findings.json"),
        serde_json::to_vec(&findings).unwrap(),
    )
    .unwrap();
    let target = dir.join("target");
    std::fs::create_dir_all(target.join("tests/security")).unwrap();
    let test = target.join("tests/security/x.test.ts");
    let mut record = omgs::proof::load(&dir, "proofs/1.json").unwrap();
    record.target = Some(target.to_string_lossy().into());
    record.target_sha256 = Some("0".repeat(64));
    write_private_fixture(
        dir.join(omgs::runmeta::FILE),
        serde_json::json!({"target": target}).to_string(),
    )
    .unwrap();
    let draft = dir.join("proofs/1/test-draft");
    for path in [&test, &draft] {
        record.test_from = (path == &draft).then(|| "original-draft".into());
        omgs::proof::write(&dir, &record).unwrap();
        for special in ["fifo", "zero-link", "directory"] {
            match special {
                "fifo" => {
                    use std::os::unix::ffi::OsStrExt;
                    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                }
                "zero-link" => std::os::unix::fs::symlink("/dev/zero", path).unwrap(),
                "directory" => std::fs::create_dir(path).unwrap(),
                _ => unreachable!(),
            }
            let start = std::time::Instant::now();
            assert!(!omgs::proof::runner_evidence(&dir, &record).is_empty());
            assert!(
                start.elapsed() < std::time::Duration::from_secs(1),
                "{special}"
            );
            for args in [
                vec!["validate", "--findings", "findings.json"],
                vec!["report", "--findings", "findings.json", "--out", "out"],
                vec!["critic", "--run", "."],
                vec!["prove", "--run", ".", "--replay", "1"],
            ] {
                let start = std::time::Instant::now();
                let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
                    .args(&args)
                    .current_dir(&dir)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap();
                let status = loop {
                    if let Some(status) = child.try_wait().unwrap() {
                        break status;
                    }
                    if start.elapsed() >= std::time::Duration::from_secs(1) {
                        child.kill().unwrap();
                        child.wait().unwrap();
                        panic!("{special} blocked {args:?}");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                };
                assert!(!status.success(), "{special}: {args:?}");
            }
            if special == "directory" {
                std::fs::remove_dir(path).unwrap();
            } else {
                std::fs::remove_file(path).unwrap();
            }
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn missing_or_altered_commands_do_not_report_a_test_name_cascade() {
    let dir = scratch("command-error");
    let (_, _, findings) = complete_run();
    let findings = attest(&dir, findings);
    assert!(omgs::proof::validate_proofs(&findings, &dir).is_empty());
    let path = dir.join("proofs/1/command.txt");
    std::fs::remove_file(&path).unwrap();
    for replacement in [None, Some("altered command")] {
        if let Some(text) = replacement {
            std::fs::write(&path, text).unwrap();
        }
        let errors = omgs::proof::validate_proofs(&findings, &dir);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(!has(&errors, "does not name"), "{errors:?}");
        assert!(has(&errors, "command"), "{errors:?}");
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn local_app_records_require_linux_bubblewrap_containment() {
    let dir = scratch("local-app-containment");
    let (_, _, findings) = complete_run();
    let mut findings = attest(&dir, findings);
    findings.findings[0].proof_tier = ProofTier::SandboxExploited;
    let mut record = omgs::proof::load(&dir, "proofs/1.json").unwrap();
    record.tier = "local_app".into();
    for containment in ["seatbelt", "processcontainer"] {
        record.containment = containment.into();
        omgs::proof::write(&dir, &record).unwrap();
        assert!(has(
            &omgs::proof::validate_proofs(&findings, &dir),
            "local_app records require bubblewrap"
        ));
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn forged_readable_roots_are_rejected_even_with_matching_config_digests() {
    let dir = scratch("forged-roots");
    let (_, _, findings) = complete_run();
    let findings = attest(&dir, findings);
    let mut record = omgs::proof::load(&dir, "proofs/1.json").unwrap();
    let path = dir.join("proofs/1/mxc-config.json");
    let config: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let root = omgs::sandbox::toolchain_roots(std::env::consts::OS, None)[0]
        .to_string_lossy()
        .to_string();
    let absolute = if cfg!(windows) {
        r"C:\arbitrary"
    } else {
        "/arbitrary"
    };
    let traversal = if cfg!(windows) {
        r"C:\fake\..\.cargo\bin"
    } else {
        "/fake/../.cargo/bin"
    };
    for roots in [
        vec![absolute.to_string()],
        vec![traversal.to_string()],
        vec![root.clone(), root],
    ] {
        record.readable_roots = roots.clone();
        let mut forged = config.clone();
        let mut readonly = roots;
        if cfg!(target_os = "macos") {
            readonly.push(format!("{}/markers/allowed", record.proof_dir));
        }
        forged["filesystem"]["readonlyPaths"] = serde_json::json!(readonly);
        let bytes = serde_json::to_vec(&forged).unwrap();
        record.config_sha256 = omgs::sha256::digest(&bytes);
        std::fs::write(&path, bytes).unwrap();
        omgs::proof::write(&dir, &record).unwrap();
        assert!(has(
            &omgs::proof::validate_proofs(&findings, &dir),
            "recorded readable_roots"
        ));
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn windows_unc_proof_directories_match_writer_and_validator() {
    let dir = scratch("unc-proof-dir");
    let (_, _, findings) = complete_run();
    let findings = attest(&dir, findings);
    let mut record = omgs::proof::load(&dir, "proofs/1.json").unwrap();
    let executor = omgs::sandbox::executor_for("windows", "x86_64").unwrap();
    record.containment = executor.containment.into();
    record.executor_sha256 = executor.sha256.into();
    record.enforced = omgs::sandbox::declared_controls("windows", omgs::sandbox::Tier::Test).0;
    record
        .enforced
        .push(format!("wall_clock={}ms", record.timeout_ms));
    record.gaps = omgs::sandbox::declared_controls("windows", omgs::sandbox::Tier::Test).1;
    record.system_root = Some(r"C:\Windows".into());
    let command = omgs::proof::recorded_command(&dir, &record).unwrap();
    let wrapped = omgs::sandbox::wrapped_command_at(
        "windows",
        &command,
        &record.marker_nonce,
        record.test.as_deref(),
        r"C:\Windows",
    );
    record.wrapped_command_sha256 = omgs::sha256::digest(wrapped.as_bytes());
    for prefix in [
        r"\\server\share\run\proofs\1",
        r"\\?\UNC\server\share\run\proofs\1",
        r"\\?\unc\server\share\run\proofs\1",
    ] {
        record.proof_dir = prefix.into();
        let workspace = std::path::PathBuf::from(format!("{prefix}\\workspace"));
        let scratch = std::path::PathBuf::from(format!("{prefix}\\scratch"));
        let config = omgs::sandbox::mxc_config_at(
            &omgs::sandbox::ConfigInput {
                contract: None,
                os: "windows",
                containment: &record.containment,
                command: &wrapped,
                timeout_ms: record.timeout_ms,
                workspace: &workspace,
                scratch: &scratch,
                allowed_marker: None,
                readonly: vec![],
                denied: vec![],
                rust: None,
                list_parents: true,
            },
            r"C:\Windows",
        );
        assert_eq!(
            config["process"]["cwd"],
            r"\\server\share\run\proofs\1\workspace"
        );
        let bytes = serde_json::to_vec(&config).unwrap();
        record.config_sha256 = omgs::sha256::digest(&bytes);
        std::fs::write(dir.join("proofs/1/mxc-config.json"), bytes).unwrap();
        omgs::proof::write(&dir, &record).unwrap();
        let errors = omgs::proof::validate_proofs(&findings, &dir);
        assert!(errors.is_empty(), "{prefix}: {errors:?}");

        let mut internal_timer = config.clone();
        internal_timer["process"]["timeout"] = record.timeout_ms.into();
        let bytes = serde_json::to_vec(&internal_timer).unwrap();
        record.config_sha256 = omgs::sha256::digest(&bytes);
        std::fs::write(dir.join("proofs/1/mxc-config.json"), bytes).unwrap();
        omgs::proof::write(&dir, &record).unwrap();
        assert!(has(
            &omgs::proof::validate_proofs(&findings, &dir),
            "platform timeout policy"
        ));

        let bytes = serde_json::to_vec(&config).unwrap();
        record.config_sha256 = omgs::sha256::digest(&bytes);
        std::fs::write(dir.join("proofs/1/mxc-config.json"), bytes).unwrap();
        record.enforced.retain(|c| !c.starts_with("wall_clock="));
        omgs::proof::write(&dir, &record).unwrap();
        assert!(has(
            &omgs::proof::validate_proofs(&findings, &dir),
            "finite supervisor wall clock"
        ));
        record
            .enforced
            .push(format!("wall_clock={}ms", record.timeout_ms));
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn persona_never_changes_validation_critic_or_verdicts() {
    let dir = scratch("persona-evidence");
    let target = dir.join("repo");
    std::fs::create_dir_all(target.join("tests/security")).unwrap();
    std::fs::write(target.join("tests/security/x.test.ts"), "fixture").unwrap();
    let mut outcomes = Vec::new();
    for persona in ["builder", "inheritor", "team"] {
        let run = dir.join(persona);
        let out = omgs(&[
            "audit",
            "init",
            "--target",
            target.to_str().unwrap(),
            "--out",
            run.to_str().unwrap(),
            "--persona",
            persona,
            "--no-sensors",
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let (ledger, candidates, mut findings) = complete_run();
        // Repeat identical accepted and broken proof inputs for all verdicts.
        let mut results = Vec::new();
        for verdict in [
            Verdict::Confirmed,
            Verdict::NeedsValidation,
            Verdict::Rejected,
        ] {
            findings.findings[0].verdict = verdict;
            findings.findings[0].severity = if verdict == Verdict::Confirmed {
                Some(omgs::model::Severity::High)
            } else {
                None
            };
            let proven = attest(&run, findings.clone());
            let saved_proof = run.join(proven.findings[0].proof_ref.as_ref().unwrap());
            let mut record: omgs::proof::ProofRecord =
                serde_json::from_str(&std::fs::read_to_string(&saved_proof).unwrap()).unwrap();
            record.target = Some(target.canonicalize().unwrap().to_string_lossy().into());
            record.target_sha256 = Some(omgs::proof::tree_digest(&target).unwrap());
            record.test_sha256 = Some(omgs::sha256::digest(b"fixture"));
            omgs::proof::write(&run, &record).unwrap();
            std::fs::write(
                run.join("findings.json"),
                serde_json::to_string(&proven).unwrap(),
            )
            .unwrap();
            write_private_fixture(
                run.join("coverage-ledger.json"),
                serde_json::to_string(&ledger).unwrap(),
            )
            .unwrap();
            std::fs::write(
                run.join("candidates-red-1.json"),
                serde_json::json!({"candidates":[candidate_json(&candidates[0].candidate)]})
                    .to_string(),
            )
            .unwrap();
            let validate = || {
                omgs(&[
                    "validate",
                    "--findings",
                    run.join("findings.json").to_str().unwrap(),
                ])
                .status
                .code()
            };
            let critic = || {
                omgs(&["critic", "--run", run.to_str().unwrap()])
                    .status
                    .code()
            };
            let check = omgs(&[
                "validate",
                "--findings",
                run.join("findings.json").to_str().unwrap(),
            ]);
            assert_eq!(
                check.status.code(),
                Some(0),
                "{}",
                String::from_utf8_lossy(&check.stderr)
            );
            assert_eq!(critic(), Some(0));
            let proof_path = run.join(proven.findings[0].proof_ref.as_ref().unwrap());
            let mut proof: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&proof_path).unwrap()).unwrap();
            proof["command_finished"] = false.into();
            std::fs::write(&proof_path, proof.to_string()).unwrap();
            results.push((validate(), critic(), proven.findings[0].verdict));
            assert_eq!(results.last().unwrap().0, Some(1));
            assert_eq!(results.last().unwrap().1, Some(1));
            // Traced evidence cannot confirm, for any persona.
            let mut traced = proven.clone();
            traced.findings[0].proof_tier = ProofTier::Traced;
            traced.findings[0].proof_ref = None;
            std::fs::write(
                run.join("findings.json"),
                serde_json::to_string(&traced).unwrap(),
            )
            .unwrap();
            assert_eq!(
                validate(),
                Some(if verdict == Verdict::Confirmed { 1 } else { 0 })
            );
        }
        outcomes.push(results);
    }
    assert_eq!(outcomes[0], outcomes[1]);
    assert_eq!(outcomes[1], outcomes[2]);
    std::fs::remove_dir_all(dir).unwrap();
}
