//! Synthetic mapping/accountability regressions. Source inspection never runs target code.
use omgs::ledger::{validate_ledger, Ledger, Unit};
use serde_json::json;
use std::path::PathBuf;

fn unit(id: &str, status: &str) -> Unit {
    let mut u = Unit::new(id, "src/decision.ts", &["missing_authz"], status);
    u.evidence = vec!["src/decision.ts".into()];
    u.extra.insert(
        "scope_paths".into(),
        json!([{"path":"src/decision.ts","operation":"GET"}]),
    );
    u
}
fn ledger(units: Vec<Unit>) -> Ledger {
    thread_local! {
        static TARGET: Temp = {
            let t = Temp::new();
            omgs::platform::private_dir(&t.0.join("src")).unwrap();
            std::fs::write(t.0.join("src/decision.ts"), "source").unwrap();
            t
        };
    }
    let mut ledger = Ledger {
        units,
        ..Default::default()
    };
    TARGET.with(|t| ledger.extra.insert("scope_root".into(), json!(t.0)));
    ledger
}
fn has(errors: &[String], text: &str) -> bool {
    errors.iter().any(|e| e.contains(text))
}

#[test]
fn t10_broad_seeds_require_reconciled_bounded_nonoverlapping_children() {
    let mut parent = unit("stack:node", "covered");
    assert!(has(
        &validate_ledger(&ledger(vec![parent.clone()])),
        "child_units"
    ));
    parent.extra.insert("child_units".into(), json!(["get"]));
    assert!(has(
        &validate_ledger(&ledger(vec![parent.clone()])),
        "missing"
    ));
    let mut child = unit("get", "planned");
    assert!(has(
        &validate_ledger(&ledger(vec![parent.clone(), child.clone()])),
        "remains planned"
    ));
    child.status = "covered".into();
    assert!(validate_ledger(&ledger(vec![parent.clone(), child.clone()])).is_empty());
    let other = unit("duplicate", "covered");
    parent
        .extra
        .insert("child_units".into(), json!(["get", "duplicate"]));
    assert!(has(
        &validate_ledger(&ledger(vec![parent.clone(), child.clone(), other.clone()])),
        "overlapping ownership"
    ));
    let mut other = other;
    other.extra.insert(
        "scope_paths".into(),
        json!([{"path":"src/decision.ts","operation":"POST"}]),
    );
    assert!(validate_ledger(&ledger(vec![parent, child, other])).is_empty());
}

#[test]
fn t48_operations_require_complete_source_review_and_method_links() {
    let mut parent = unit("route:src/route.ts", "covered");
    parent.extra.insert("checklist".into(), json!("operations"));
    parent.extra.insert("child_units".into(), json!(["get"]));
    let child = unit("get", "covered");
    for syntax in [json!(null), json!("uncertain"), json!(true)] {
        parent.extra.insert("syntax_review".into(), syntax);
        assert!(has(
            &validate_ledger(&ledger(vec![parent.clone(), child.clone()])),
            "source-only syntax_review"
        ));
    }
    parent
        .extra
        .insert("syntax_review".into(), json!("complete"));
    parent
        .extra
        .insert("operations".into(), json!({"GET":"missing"}));
    assert!(has(
        &validate_ledger(&ledger(vec![parent.clone(), child.clone()])),
        "operations must map"
    ));
    parent
        .extra
        .insert("operations".into(), json!({"GET":"get"}));
    assert!(validate_ledger(&ledger(vec![parent, child])).is_empty());
}

#[test]
fn t53_partial_coverage_retains_residuals_and_rejects_invalid_graphs() {
    let mut examined = unit("examined", "covered");
    examined.extra.insert("partial".into(), json!(true));
    assert!(has(
        &validate_ledger(&ledger(vec![examined.clone()])),
        "residual_units"
    ));
    for ids in [
        json!(["absent"]),
        json!(["examined"]),
        json!(["rest", "rest"]),
        json!("rest"),
    ] {
        examined.extra.insert("residual_units".into(), ids);
        assert!(
            !validate_ledger(&ledger(vec![examined.clone(), unit("rest", "planned")])).is_empty()
        );
    }
    examined
        .extra
        .insert("residual_units".into(), json!(["rest"]));
    let mut rest = unit("rest", "planned");
    let l = ledger(vec![examined.clone(), rest.clone()]);
    assert!(validate_ledger(&l).is_empty());
    let report = omgs::critic::critique(&l, 1, &[], &omgs::model::FindingsFile::default());
    assert!(has(&report.gaps, "rest"));
    rest.extra
        .insert("residual_units".into(), json!(["examined"]));
    assert!(has(
        &validate_ledger(&ledger(vec![examined, rest])),
        "cycle"
    ));
}

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let root = omgs::platform::temp_root().unwrap().join(format!(
            "omgs-mapping-{}",
            omgs::platform::random_nonce().unwrap()
        ));
        omgs::platform::create_private_tree(&root).unwrap();
        Self(std::fs::canonicalize(root).unwrap())
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn t46_assets_remain_accountable_and_public_scripts_remain_code() {
    use omgs::paths::{classify, Class};
    assert_eq!(classify("public/icon.png"), Class::Asset);
    assert_eq!(classify("public/start.js"), Class::Code);
    assert_eq!(classify("public/run.ps1"), Class::Code);
    assert_eq!(classify("public/unknown.bin"), Class::Code);
    let t = Temp::new();
    std::fs::create_dir(t.0.join("public")).unwrap();
    std::fs::write(t.0.join("public/icon.png"), b"\x89PNG\r\n\x1a\n").unwrap();
    std::fs::write(t.0.join("public/start.js"), "export const start = 1;").unwrap();
    let run = t.0.join("run");
    // Output must be outside the target, so use a separate target subdirectory.
    let target = t.0.join("public");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .env("RUSTUP_AUTO_INSTALL", "0")
        .env("OMGS_HOME", t.0.join("home"))
        .args([
            "audit",
            "init",
            "--target",
            target.to_str().unwrap(),
            "--out",
            run.to_str().unwrap(),
            "--no-sensors",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let l: Ledger =
        serde_json::from_slice(&std::fs::read(run.join("coverage-ledger.json")).unwrap()).unwrap();
    let asset = l.units.iter().find(|u| u.id == "assets:excluded").unwrap();
    assert_eq!(asset.extra["excluded_count"], 1);
    assert_eq!(asset.extra["excluded_paths"], json!(["icon.png"]));
    let report = omgs::critic::critique(&l, 1, &[], &omgs::model::FindingsFile::default());
    assert!(has(&report.gaps, "assets:excluded"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            target.join("icon.png"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert_eq!(
            omgs::paths::classify_file(&target, std::path::Path::new("icon.png")),
            Class::Code
        );
    }
}

#[test]
fn t67_native_hints_seed_caller_and_credential_operation_checklists() {
    let t = Temp::new();
    std::fs::write(
        t.0.join("Listener.swift"),
        "func listener() { /* NSXPCListener; SecItemCopyMatching */ }",
    )
    .unwrap();
    let units = omgs::mapping::native_units(&t.0, &[PathBuf::from("Listener.swift")]);
    assert_eq!(units.len(), 2);
    assert!(units
        .iter()
        .any(|u| u.attack_classes == ["ipc_authorization"]));
    assert!(units
        .iter()
        .any(|u| u.attack_classes == ["secret_disclosure"]));
    assert!(units
        .iter()
        .all(|u| u.status == "planned" && u.extra["checklist"] == "operations"));
    for class in ["ipc_authorization", "secret_disclosure"] {
        assert!(omgs::stack_attack_classes("swift").contains(&class));
    }
}

#[test]
fn t52_t68_registry_covers_seeds_packs_and_native_intent() {
    let all = omgs::classes::all();
    let unique: std::collections::BTreeSet<_> = all.iter().collect();
    assert_eq!(all.len(), unique.len());
    assert!(all.iter().all(|c| omgs::classes::valid_identifier(c)));
    for stack in [
        "nextjs-app-router",
        "aspnet",
        "powershell",
        "swift",
        "static-web",
        "shell",
        "browser-extension",
        "python",
        "rust",
        "node",
    ] {
        for class in omgs::stack_attack_classes(stack) {
            assert!(omgs::classes::known(class), "{class}");
        }
    }
    for q in &omgs::intent::library().questions {
        for class in &q.attack_classes {
            assert!(omgs::classes::known(class), "{class}");
        }
    }
    for id in [
        "native.accepted-callers",
        "native.secret-disclosure",
        "native.privileged-operations",
    ] {
        assert!(omgs::intent::find(id)
            .unwrap()
            .stacks
            .contains(&"swift".to_string()));
    }
    assert!(!omgs::intent::list(Some("swift"), Some("ipc_authorization")).is_empty());
    assert!(!omgs::intent::list(Some("swift"), Some("secret_disclosure")).is_empty());
    assert!(omgs::classes::known("artifact_poisoning"));
    assert!(omgs::classes::known("ssrf"));
    let t = Temp::new();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .env("OMGS_HOME", &t.0)
        .args(["intent", "list", "--attack-class", "artifact_poisoning"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("no intent questions"));
}

#[test]
fn t09_t49_native_map_and_architecture_array_contracts_are_explicit() {
    let recon = include_str!("../skill/RECONNAISSANCE.md");
    for text in [
        "enforcement` as an array of strings",
        "MachServices",
        "shouldAcceptNewConnection",
        "NSXPCInterface",
        "setClasses",
        "audit-token",
        "native.accepted-callers",
    ] {
        assert!(recon.contains(text), "{text}");
    }
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../skill/schemas/architecture.schema.json")).unwrap();
    assert!(schema.is_object());
    assert!(omgs::architecture::from_json(r#"{"boundaries":[{"enforcement":"guard"}]}"#).is_err());
    assert!(omgs::architecture::from_json(r#"{"boundaries":[{"enforcement":["guard"]}]}"#).is_ok());
}

#[test]
fn t47_sensor_skip_summary_seeds_an_unresolved_inventory_unit() {
    let report = omgs::sensors::SensorsReport {
        tools_run: vec!["synthetic".into()],
        tools_unavailable: vec![],
        hits: vec![],
        gaps: vec![
            "synthetic: 12 input entries/subtrees skipped; 2 manifest records omitted".into(),
        ],
    };
    let mut l = Ledger::default();
    omgs::sensors::seed_units(&report, &mut l);
    assert_eq!(l.units.len(), 1);
    assert!(omgs::ledger::is_inventory_gap(&l.units[0]));
    assert_eq!(l.units[0].status, "blocked");
    let critic = omgs::critic::critique(&l, 1, &[], &omgs::model::FindingsFile::default());
    assert!(has(&critic.gaps, "inventory:sensor-input"));
    assert!(!omgs::sensors::reconcile(&report, &Ledger::default()).is_empty());
}

#[test]
fn t10_t48_cli_mapping_updates_are_atomic_and_route_seeds_need_methods() {
    let t = Temp::new();
    let target = t.0.join("target");
    let run = t.0.join("run");
    std::fs::create_dir_all(target.join("app/api/items")).unwrap();
    // Reexport and alias syntax deliberately receives no inferred method list.
    std::fs::write(
        target.join("app/api/items/route.ts"),
        "export { handler as GET } from './shared';\n",
    )
    .unwrap();
    let cli = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
            .env("OMGS_HOME", t.0.join("state"))
            .env("RUSTUP_AUTO_INSTALL", "0")
            .args(args)
            .output()
            .unwrap()
    };
    assert!(cli(&[
        "audit",
        "init",
        "--target",
        target.to_str().unwrap(),
        "--out",
        run.to_str().unwrap(),
        "--no-sensors"
    ])
    .status
    .success());
    let path = run.join("coverage-ledger.json");
    let path = path.to_str().unwrap();
    let before = std::fs::read(path).unwrap();
    let l: Ledger = serde_json::from_slice(&before).unwrap();
    let route = l
        .units
        .iter()
        .find(|u| u.id == "route:app/api/items/route.ts")
        .unwrap();
    assert_eq!(route.extra["checklist"], "operations");
    assert!(!route.extra.contains_key("operations"));
    let close = [
        "ledger",
        "set",
        "--ledger",
        path,
        "--unit",
        route.id.as_str(),
        "--status",
        "covered",
        "--evidence",
        "app/api/items/route.ts",
    ];
    assert!(!cli(&close).status.success());
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert!(cli(&[
        "ledger",
        "add",
        "--ledger",
        path,
        "--unit",
        "route-get",
        "--surface",
        "GET items",
        "--classes",
        "missing_authz,idor_tenant_isolation,client_only_auth",
        "--mapping",
        r#"{"scope_paths":[{"path":"app/api/items/route.ts","operation":"GET"}]}"#
    ])
    .status
    .success());
    assert!(cli(&[
        "ledger",
        "set",
        "--ledger",
        path,
        "--unit",
        "route-get",
        "--status",
        "covered",
        "--evidence",
        "app/api/items/route.ts"
    ])
    .status
    .success());
    let mut close = close.to_vec();
    close.extend(["--mapping", r#"{"child_units":["route-get"],"operations":{"GET":"route-get"},"syntax_review":"complete"}"#]);
    let out = cli(&close);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        include_str!("../schemas/coverage-ledger.schema.json"),
        include_str!("../skill/schemas/coverage-ledger.schema.json")
    );
}

#[test]
fn t52_pack_class_names_and_bundled_registry_stay_aligned() {
    for (name, bytes) in omgs::setup::BUNDLED
        .iter()
        .filter(|(name, _)| name.starts_with("packs/"))
    {
        let text = std::str::from_utf8(bytes).unwrap();
        for token in text
            .split('`')
            .skip(1)
            .step_by(2)
            .filter(|t| omgs::classes::valid_identifier(t))
        {
            if [
                "intent_id",
                "needs_validation",
                "catch",
                "delete",
                "eval",
                "fetch",
                "iex",
                "params",
                "relforcerowsecurity",
                "relrowsecurity",
                "replace",
                "rolbypassrls",
                "rolsuper",
                "update",
            ]
            .contains(&token)
            {
                continue;
            }
            assert!(omgs::classes::known(token), "{name}: {token}");
        }
    }
    for file in ["intent/classes.json", "schemas/coverage-ledger.schema.json"] {
        assert!(omgs::setup::BUNDLED.iter().any(|(name, _)| *name == file));
    }
}

#[test]
fn t10_closed_and_deferred_stack_checklists_cannot_hide_missing_partitions() {
    let mut parent = unit("stack:node", "out_of_scope");
    parent.note = Some("Not reviewed yet".into());
    assert!(has(
        &validate_ledger(&ledger(vec![parent.clone()])),
        "child_units"
    ));
    parent.status = "deferred".into();
    let critic = omgs::critic::critique(
        &ledger(vec![parent.clone()]),
        1,
        &[],
        &omgs::model::FindingsFile::default(),
    );
    assert!(has(&critic.gaps, "stack:node"));
    parent.extra.insert(
        "child_units".into(),
        json!((0..257).map(|n| format!("child{n}")).collect::<Vec<_>>()),
    );
    assert!(has(&validate_ledger(&ledger(vec![parent])), "1 to 256"));
}

#[test]
fn t10_t53_metadata_and_graph_failures_leave_additions_unchanged() {
    let mut l = ledger(vec![unit("existing", "planned")]);
    let before = serde_json::to_value(&l).unwrap();
    let mut dangling = unit("partial", "out_of_scope");
    dangling.note = Some("Explicitly excluded remainder".into());
    dangling.extra.insert("partial".into(), json!(true));
    dangling
        .extra
        .insert("residual_units".into(), json!(["missing"]));
    assert!(omgs::ledger::add_unit(&mut l, dangling).is_err());
    assert_eq!(serde_json::to_value(&l).unwrap(), before);
    for scope in [
        json!(["../outside"]),
        json!(["/absolute"]),
        json!(["src/x", "src/x"]),
        json!("src/x"),
    ] {
        let mut u = unit("bad-scope", "planned");
        u.extra.insert("scope_paths".into(), scope);
        assert!(omgs::ledger::add_unit(&mut l, u).is_err());
        assert_eq!(serde_json::to_value(&l).unwrap(), before);
    }
    let mut u = unit("metadata", "planned");
    assert!(omgs::mapping::apply_metadata(&mut u, r#"{"child_units":[],"unknown":1}"#).is_err());
    assert!(!u.extra.contains_key("child_units"));
}

#[test]
fn additional_a_unknown_classes_fail_validation_and_fingerprint_creation() {
    let candidates: serde_json::Value =
        serde_json::from_str(include_str!("../skill/schemas/candidates.schema.json")).unwrap();
    let findings: serde_json::Value =
        serde_json::from_str(include_str!("../skill/schemas/findings.schema.json")).unwrap();
    for schema in [candidates, findings] {
        let key = if schema["properties"].get("candidates").is_some() {
            "candidates"
        } else {
            "findings"
        };
        assert_eq!(
            schema["properties"][key]["items"]["properties"]["attack_class"]["enum"],
            json!(omgs::classes::all())
        );
    }
    let t = Temp::new();
    let unknown = "unregistered_boundary_typo";
    let fp = omgs::fingerprint(unknown, "GET /x", "db.x", "owner");
    let candidate = json!({"candidates":[{
        "hunter":"red", "unit_ids":["u"], "source_ref":"synthetic", "title":"Synthetic boundary",
        "attack_class":unknown, "entry_point":"GET /x", "sink":"db.x", "boundary":"owner",
        "location":{"path":"src/x.ts","line":1}, "attacker_capability":"caller",
        "trace":"source trace", "concrete_result":"predicted read", "counterevidence":"guard inspected",
        "proof_plan":"synthetic decision only", "fingerprint":fp
    }]});
    let path = t.0.join("candidates.json");
    omgs::runmeta::write_atomic(&path, &candidate.to_string()).unwrap();
    let cli = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
            .env("OMGS_HOME", &t.0)
            .env("RUSTUP_AUTO_INSTALL", "0")
            .args(args)
            .output()
            .unwrap()
    };
    let out = cli(&["validate", "--candidates", path.to_str().unwrap()]);
    assert!(!out.status.success());
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("unknown attack class"), "{text}");
    for class in omgs::classes::all() {
        assert!(text.contains(class), "{class}");
    }
    let out = cli(&[
        "fingerprint",
        "--attack-class",
        unknown,
        "--entry-point",
        "GET /x",
        "--sink",
        "db.x",
        "--boundary",
        "owner",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let mut finding = omgs::shape::findings(include_str!("fixtures/report-run/findings.json"))
        .unwrap()
        .findings
        .into_iter()
        .next()
        .unwrap();
    finding.attack_class = unknown.into();
    let errors = omgs::model::validate(&omgs::model::FindingsFile {
        findings: vec![finding],
    });
    assert!(has(&errors, "unknown attack class"));
    for class in [
        "download_integrity",
        "deletion_path_safety",
        "download_and_execute",
    ] {
        let out = cli(&[
            "fingerprint",
            "--attack-class",
            class,
            "--entry-point",
            "GET /x",
            "--sink",
            "db.x",
            "--boundary",
            "owner",
        ]);
        assert!(out.status.success());
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            omgs::fingerprint(class, "GET /x", "db.x", "owner")
        );
    }
}

#[test]
fn parent_classes_survive_nested_partitions_and_reasoned_exclusions() {
    let mut parent = unit("stack:node", "covered");
    parent.attack_classes.push("input_validation".into());
    parent.extra.insert("child_units".into(), json!(["middle"]));
    let mut middle = unit("middle", "covered");
    let child = unit("leaf", "covered");
    let mut l = ledger(vec![parent, middle.clone(), child]);
    assert!(has(
        &validate_ledger(&l),
        "input_validation' is unaccounted"
    ));
    assert!(!omgs::critic::critique(&l, 1, &[], &Default::default()).passed());
    middle.attack_classes.push("input_validation".into());
    middle.extra.insert("child_units".into(), json!(["leaf"]));
    l.units[1] = middle;
    assert!(has(
        &validate_ledger(&l),
        "middle: parent class 'input_validation'"
    ));
    let mut excluded = unit("validation-excluded", "out_of_scope");
    excluded.attack_classes = vec!["input_validation".into()];
    excluded.note = Some("Reviewed source accepts no external input".into());
    l.units[1]
        .extra
        .insert("child_units".into(), json!(["leaf", "validation-excluded"]));
    l.units.push(excluded);
    assert!(validate_ledger(&l).is_empty(), "{:?}", validate_ledger(&l));
    l.units[3].note = None;
    assert!(has(
        &validate_ledger(&l),
        "input_validation' is unaccounted"
    ));
}

#[test]
fn equivalent_scope_spellings_cannot_duplicate_ownership() {
    let mut spellings = vec!["src/./decision.ts", "src//decision.ts"];
    if cfg!(windows) {
        spellings.push(r"src\decision.ts");
    }
    for spelling in spellings {
        let mut parent = unit("stack:node", "covered");
        parent.extra.insert("child_units".into(), json!(["a", "b"]));
        let a = unit("a", "covered");
        let mut b = unit("b", "covered");
        b.extra.insert(
            "scope_paths".into(),
            json!([{"path":spelling,"operation":"GET"}]),
        );
        assert!(
            has(
                &validate_ledger(&ledger(vec![parent, a, b])),
                "overlapping ownership"
            ),
            "{spelling}"
        );
    }
}

#[test]
fn documented_legacy_classes_keep_their_identity() {
    for (old, new) in [
        ("idor", "idor_tenant_isolation"),
        ("missing_authorization", "missing_authz"),
        ("client_only_authorization", "client_only_auth"),
        ("webhook_verification", "webhook_signature"),
    ] {
        assert!(omgs::classes::validate(old).is_ok());
        assert_eq!(omgs::classes::replacement(old).as_deref(), Some(new));
        assert_ne!(
            omgs::fingerprint(old, "entry", "sink", "boundary"),
            omgs::fingerprint(new, "entry", "sink", "boundary")
        );
    }
}

#[test]
fn filesystem_case_aliases_cannot_duplicate_ownership() {
    let t = Temp::new();
    let target = t.0.join("target");
    std::fs::create_dir_all(target.join("src")).unwrap();
    std::fs::write(target.join("src/decision.ts"), "source").unwrap();
    let mut parent = unit("stack:node", "covered");
    parent.extra.insert("child_units".into(), json!(["a", "b"]));
    let a = unit("a", "covered");
    let mut b = unit("b", "covered");
    b.extra.insert(
        "scope_paths".into(),
        json!([{"path":"src/DECISION.ts","operation":"GET"}]),
    );
    let mut l = ledger(vec![parent, a, b]);
    l.extra.insert("scope_root".into(), json!(target));
    if target.join("src/DECISION.ts").exists() {
        assert!(has(&validate_ledger(&l), "overlapping ownership"));
        assert!(!omgs::critic::critique(&l, 1, &[], &Default::default()).passed());
    } else {
        // Both names really exist on this case-sensitive comparison path.
        std::fs::write(target.join("src/DECISION.ts"), "other source").unwrap();
        assert!(validate_ledger(&l).is_empty(), "{:?}", validate_ledger(&l));
    }
    // Operation names are not filesystem names, so their case stays intact.
    l.units[2].extra.insert(
        "scope_paths".into(),
        json!([{"path":"src/decision.ts","operation":"get"}]),
    );
    assert!(validate_ledger(&l).is_empty());
}

#[test]
fn legacy_partitions_require_target_context_before_closure() {
    for scope in ["src/café.ts", "src/cafe\u{301}.ts", "src/nonexistent.ts"] {
        let mut parent = unit("stack:node", "covered");
        parent.extra.insert("child_units".into(), json!(["a", "b"]));
        let mut a = unit("a", "covered");
        a.extra.insert(
            "scope_paths".into(),
            json!([{"path":"src/café.ts","operation":"GET"}]),
        );
        let mut b = unit("b", "covered");
        b.extra.insert(
            "scope_paths".into(),
            json!([{"path":scope,"operation":"GET"}]),
        );
        let mut l = ledger(vec![parent, a, b]);
        l.extra.remove("scope_root");
        assert!(has(
            &validate_ledger(&l),
            "omgs ledger migrate --run <dir> before closure"
        ));
        assert!(!omgs::critic::critique(&l, 1, &[], &Default::default()).passed());
        l.extra.insert("scope_root".into(), json!("relative"));
        assert!(has(
            &validate_ledger(&l),
            "scope target and relative path are invalid"
        ));
    }
}

#[test]
fn target_context_rejects_absent_scopes_and_resolves_unicode_aliases() {
    let t = Temp::new();
    omgs::platform::private_dir(&t.0.join("src")).unwrap();
    std::fs::write(t.0.join("src/café.ts"), "source").unwrap();
    let mut parent = unit("stack:node", "covered");
    parent.extra.insert("child_units".into(), json!(["a", "b"]));
    let mut a = unit("a", "covered");
    a.extra.insert(
        "scope_paths".into(),
        json!([{"path":"src/café.ts","operation":"GET"}]),
    );
    let mut b = unit("b", "covered");
    b.extra.insert(
        "scope_paths".into(),
        json!([{"path":"src/cafe\u{301}.ts","operation":"GET"}]),
    );
    let mut l = ledger(vec![parent, a, b]);
    l.extra.insert("scope_root".into(), json!(t.0));
    if t.0.join("src/cafe\u{301}.ts").exists() {
        assert!(has(&validate_ledger(&l), "overlapping ownership"));
    } else {
        assert!(has(&validate_ledger(&l), "absent from target"));
    }
    l.units[2].extra.insert(
        "scope_paths".into(),
        json!([{"path":"src/nonexistent.ts","operation":"GET"}]),
    );
    assert!(has(&validate_ledger(&l), "absent from target"));
}

#[cfg(any(unix, windows))]
#[test]
fn scope_directory_aliases_never_escape_or_duplicate_target_ownership() {
    let t = Temp::new();
    let target = t.0.join("target");
    // Build each directory separately so Windows inheritance stays private.
    for dir in [&target, &target.join("src"), &t.0.join("outside")] {
        omgs::platform::private_dir(dir).unwrap();
    }
    std::fs::write(target.join("src/decision.ts"), "internal").unwrap();
    std::fs::write(t.0.join("outside/decision.ts"), "external").unwrap();
    for (alias, destination) in [
        ("internal", target.join("src")),
        ("external", t.0.join("outside")),
    ] {
        let link = target.join(alias);
        #[cfg(unix)]
        std::os::unix::fs::symlink(&destination, &link).unwrap();
        #[cfg(windows)]
        assert!(std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&destination)
            .status()
            .unwrap()
            .success());
        let mut parent = unit("stack:node", "covered");
        parent.extra.insert("child_units".into(), json!(["a", "b"]));
        let a = unit("a", "covered");
        let mut b = unit("b", "covered");
        b.extra.insert(
            "scope_paths".into(),
            json!([{"path":format!("{alias}/decision.ts"),"operation":"GET"}]),
        );
        let mut l = ledger(vec![parent, a, b]);
        l.extra.insert("scope_root".into(), json!(target));
        assert!(has(&validate_ledger(&l), "symlinks or reparse points"));
        assert!(!omgs::critic::critique(&l, 1, &[], &Default::default()).passed());
        #[cfg(unix)]
        std::fs::remove_file(link).unwrap();
        #[cfg(windows)]
        std::fs::remove_dir(link).unwrap();
    }
}

fn scope_partition(target: &std::path::Path, scopes: &[serde_json::Value]) -> Ledger {
    let mut parent = unit("stack:node", "covered");
    let ids: Vec<_> = (0..scopes.len()).map(|i| format!("child:{i}")).collect();
    parent.extra.insert("child_units".into(), json!(ids));
    let mut units = vec![parent];
    for (id, scope) in ids.iter().zip(scopes) {
        let mut child = unit(id, "covered");
        child.extra.insert("scope_paths".into(), json!([scope]));
        units.push(child);
    }
    let mut l = ledger(units);
    l.extra.insert("scope_root".into(), json!(target));
    l
}

#[test]
fn literal_hash_paths_validate_the_entire_directory_and_filename() {
    let t = Temp::new();
    for directory in ["src", "src#ipc"] {
        omgs::platform::private_dir(&t.0.join(directory)).unwrap();
    }
    for path in ["src#ipc/Decision.swift", "src/Decision#read.swift"] {
        std::fs::write(t.0.join(path), "source").unwrap();
        for operation in [None, Some("read")] {
            let mut scope = json!({"path":path});
            if let Some(operation) = operation {
                scope["operation"] = json!(operation);
            }
            let l = scope_partition(&t.0, &[scope.clone()]);
            assert!(validate_ledger(&l).is_empty(), "{:?}", validate_ledger(&l));
            let duplicate = scope_partition(&t.0, &[scope.clone(), scope.clone()]);
            assert!(has(&validate_ledger(&duplicate), "overlapping ownership"));
            let mut missing = scope.clone();
            missing["path"] = json!(format!("{path}.absent"));
            assert!(has(
                &validate_ledger(&scope_partition(&t.0, &[missing])),
                "absent from target"
            ));
            std::fs::remove_file(t.0.join(path)).unwrap();
            assert!(has(&validate_ledger(&l), "absent from target"));
            std::fs::write(t.0.join(path), "source").unwrap();
        }
    }
}

#[test]
fn hash_scope_paths_and_operations_have_separate_ownership_identity() {
    let t = Temp::new();
    omgs::platform::private_dir(&t.0.join("src")).unwrap();
    std::fs::write(t.0.join("src/Decision"), "source").unwrap();
    std::fs::write(t.0.join("src/Decision#read"), "other source").unwrap();
    let whole = json!({"path":"src/Decision#read"});
    let op = json!({"path":"src/Decision","operation":"read"});
    let l = scope_partition(&t.0, &[whole.clone(), op.clone()]);
    assert!(validate_ledger(&l).is_empty(), "{:?}", validate_ledger(&l));
    let l = scope_partition(&t.0, &[op, json!("src/Decision#read")]);
    assert!(has(&validate_ledger(&l), "migrate to objects"));
    let l = scope_partition(
        &t.0,
        &[
            whole,
            json!({"path":"src/Decision#read","operation":"read"}),
        ],
    );
    assert!(has(&validate_ledger(&l), "overlapping ownership"));
    let l = scope_partition(
        &t.0,
        &[
            json!({"path":"src"}),
            json!({"path":"src/Decision#read","operation":"read"}),
        ],
    );
    assert!(has(&validate_ledger(&l), "overlapping ownership"));
}

#[test]
fn hash_path_case_aliases_follow_the_target_filesystem() {
    let t = Temp::new();
    for directory in ["src", "src#ipc"] {
        omgs::platform::private_dir(&t.0.join(directory)).unwrap();
    }
    for (path, alias) in [
        ("src#ipc/Decision.swift", "SRC#IPC/DECISION.swift"),
        ("src/Decision#read.swift", "src/DECISION#READ.swift"),
    ] {
        std::fs::write(t.0.join(path), "source").unwrap();
        for operation in [None, Some("read")] {
            let mut a = json!({"path":path});
            let mut b = json!({"path":alias});
            if let Some(operation) = operation {
                a["operation"] = json!(operation);
                b["operation"] = json!(operation);
            }
            let l = scope_partition(&t.0, &[a, b]);
            if t.0.join(alias).exists() {
                assert!(has(&validate_ledger(&l), "overlapping ownership"));
            } else {
                assert!(has(&validate_ledger(&l), "absent from target"));
            }
        }
    }
}

#[test]
fn legacy_hash_strings_are_refused_regardless_of_target_contents() {
    for (plain_exists, hash_exists) in [(true, false), (false, true), (true, true), (false, false)]
    {
        let t = Temp::new();
        omgs::platform::private_dir(&t.0.join("dir")).unwrap();
        if plain_exists {
            std::fs::write(t.0.join("dir/a"), "plain source").unwrap();
        }
        if hash_exists {
            std::fs::write(t.0.join("dir/a#b"), "literal source").unwrap();
        }
        let errors = validate_ledger(&scope_partition(&t.0, &[json!("dir/a#b")]));
        for expected in [
            "ambiguous",
            "migrate to objects",
            r#"{"path":"dir/a#b"}"#,
            r#"{"path":"dir/a","operation":"b"}"#,
        ] {
            assert!(has(&errors, expected), "{errors:?}");
        }
        if plain_exists && hash_exists {
            let explicit = scope_partition(
                &t.0,
                &[
                    json!({"path":"dir/a#b"}),
                    json!({"path":"dir/a","operation":"b"}),
                ],
            );
            assert!(
                validate_ledger(&explicit).is_empty(),
                "{:?}",
                validate_ledger(&explicit)
            );
        }
    }
}

#[cfg(any(unix, windows))]
#[test]
fn legacy_hash_strings_are_refused_even_when_the_literal_path_is_a_link() {
    let t = Temp::new();
    omgs::platform::private_dir(&t.0.join("dir")).unwrap();
    // A directory link also exercises Windows junctions without symlink privileges.
    let destination = t.0.join("dir").join("a");
    omgs::platform::private_dir(&destination).unwrap();
    let link = t.0.join("dir").join("a#b");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&destination, &link).unwrap();
    #[cfg(windows)]
    assert!(std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&link)
        .arg(&destination)
        .status()
        .unwrap()
        .success());
    let errors = validate_ledger(&scope_partition(&t.0, &[json!("dir/a#b")]));
    assert!(has(&errors, "migrate to objects"), "{errors:?}");
    let errors = validate_ledger(&scope_partition(&t.0, &[json!({"path":"dir/a#b"})]));
    assert!(has(&errors, "symlinks or reparse points"), "{errors:?}");
    #[cfg(unix)]
    std::fs::remove_file(link).unwrap();
    #[cfg(windows)]
    std::fs::remove_dir(link).unwrap();
}

#[test]
fn legacy_plain_paths_have_whole_path_ownership() {
    let t = Temp::new();
    omgs::platform::private_dir(&t.0.join("dir")).unwrap();
    std::fs::write(t.0.join("dir/a"), "source").unwrap();
    let l = scope_partition(&t.0, &[json!("dir/a")]);
    assert!(validate_ledger(&l).is_empty(), "{:?}", validate_ledger(&l));
    for other in [
        json!({"path":"dir/a"}),
        json!({"path":"dir/a","operation":"b"}),
    ] {
        let errors = validate_ledger(&scope_partition(&t.0, &[json!("dir/a"), other]));
        assert!(has(&errors, "overlapping ownership"), "{errors:?}");
    }
}

#[test]
fn legacy_hash_strings_require_migration_and_object_operations_are_validated() {
    for legacy in [
        "dir/a#b",
        "src#ipc/Decision.swift",
        "src#ipc/Decision.swift#read",
        "src/Decision#read.swift#read",
        "src/Decision.swift#",
        "src/Decision.swift#read/write",
        "src/Decision.swift#read#write",
        "src/Decision.swift#read\n",
    ] {
        let mut child = unit("legacy", "planned");
        child.extra.insert("scope_paths".into(), json!([legacy]));
        assert!(
            has(&validate_ledger(&ledger(vec![child])), "migrate to objects"),
            "{legacy}"
        );
    }
    let mut child = unit("valid", "planned");
    for operation in ["GET", "read", "_", "Service.read:arg-1", &"a".repeat(128)] {
        child.extra.insert(
            "scope_paths".into(),
            json!([{"path":"src#ipc/Decision#read.swift","operation":operation}]),
        );
        assert!(validate_ledger(&ledger(vec![child.clone()])).is_empty());
    }
    for scope in [
        json!({"path":"src/file","operation":""}),
        json!({"path":"src/file","operation":"1read"}),
        json!({"path":"src/file","operation":"read#write"}),
        json!({"path":"src/file","operation":"réad"}),
        json!({"path":"src/file","operation":"a".repeat(129)}),
        json!({"path":"src/file","operation":null}),
        json!({"path":"src/file","extra":true}),
        json!({"path":"../outside"}),
        json!({"path":"/absolute"}),
        json!({"path":""}),
        json!({"operation":"read"}),
    ] {
        child
            .extra
            .insert("scope_paths".into(), json!([scope.clone()]));
        assert!(
            !validate_ledger(&ledger(vec![child.clone()])).is_empty(),
            "{scope}"
        );
    }
    child.extra.insert(
        "scope_paths".into(),
        json!(["src/decision.ts", {"path":"src/decision.ts"}]),
    );
    assert!(has(&validate_ledger(&ledger(vec![child])), "unique"));
}

#[cfg(any(unix, windows))]
#[test]
fn links_beneath_hash_directories_cannot_bypass_scope_validation() {
    let t = Temp::new();
    for directory in ["src", "src#ipc", "outside"] {
        omgs::platform::private_dir(&t.0.join(directory)).unwrap();
    }
    std::fs::write(t.0.join("outside").join("Decision#read.swift"), "source").unwrap();
    let link = t.0.join("src#ipc").join("linked");
    #[cfg(unix)]
    std::os::unix::fs::symlink(t.0.join("outside"), &link).unwrap();
    #[cfg(windows)]
    assert!(std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&link)
        .arg(t.0.join("outside"))
        .status()
        .unwrap()
        .success());
    for operation in [None, Some("read")] {
        let mut scope = json!({"path":"src#ipc/linked/Decision#read.swift"});
        if let Some(operation) = operation {
            scope["operation"] = json!(operation);
        }
        let l = scope_partition(&t.0, &[scope]);
        assert!(has(&validate_ledger(&l), "symlinks or reparse points"));
    }
    #[cfg(unix)]
    std::fs::remove_file(link).unwrap();
    #[cfg(windows)]
    std::fs::remove_dir(link).unwrap();
}

fn command(t: &Temp) -> std::process::Command {
    let home = t.0.join("home");
    omgs::platform::private_dir(&home).unwrap();
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"));
    cmd.env("OMGS_HOME", home).env("RUSTUP_AUTO_INSTALL", "0");
    cmd
}
fn write_json(path: &std::path::Path, value: &impl serde::Serialize) {
    omgs::runmeta::write_atomic(path, &serde_json::to_string(value).unwrap()).unwrap();
}

#[test]
fn legacy_cli_migration_binds_metadata_and_allows_partition_closure() {
    let t = Temp::new();
    let run = t.0.join("run");
    let target = t.0.join("target");
    omgs::platform::private_dir(&run).unwrap();
    omgs::platform::private_dir(&target).unwrap();
    omgs::platform::private_dir(&target.join("src")).unwrap();
    std::fs::write(target.join("src/decision.ts"), "source").unwrap();
    let mut parent = unit("stack:node", "planned");
    parent.extra.insert("child_units".into(), json!(["child"]));
    let mut l = ledger(vec![parent, unit("child", "covered")]);
    l.extra.remove("scope_root");
    l.extra.insert("custom".into(), json!("preserved"));
    let path = run.join("coverage-ledger.json");
    write_json(&path, &l);
    let close = || {
        command(&t)
            .args(["ledger", "set", "--ledger"])
            .arg(&path)
            .args([
                "--unit",
                "stack:node",
                "--status",
                "covered",
                "--evidence",
                "src/decision.ts",
            ])
            .output()
            .unwrap()
    };
    assert!(!close().status.success());
    let original = std::fs::read(&path).unwrap();
    let migrate = || {
        command(&t)
            .args(["ledger", "migrate", "--run"])
            .arg(&run)
            .output()
            .unwrap()
    };
    assert!(!migrate().status.success());
    assert_eq!(std::fs::read(&path).unwrap(), original);
    write_json(&run.join("run-metadata.json"), &json!({"target": target}));
    // A malformed existing partition cannot be published by migration.
    let mut invalid = l.clone();
    invalid.units[0]
        .extra
        .insert("child_units".into(), json!(["missing"]));
    write_json(&path, &invalid);
    let invalid_bytes = std::fs::read(&path).unwrap();
    assert!(!migrate().status.success());
    assert_eq!(std::fs::read(&path).unwrap(), invalid_bytes);
    write_json(&path, &l);
    let out = migrate();
    assert!(out.status.success(), "{out:?}");
    assert!(close().status.success());
    let migrated: Ledger = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(migrated.extra["custom"], "preserved");
    assert_eq!(migrated.extra["scope_root"], json!(target));
    assert!(validate_ledger(&migrated).is_empty());
    let out = command(&t)
        .args(["ledger", "migrate", "--run"])
        .arg(&run)
        .arg("--ledger")
        .arg(&path)
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn edited_scope_root_cannot_redirect_cli_or_critic_resolution() {
    let t = Temp::new();
    let run = t.0.join("run");
    let target = t.0.join("target");
    let other = t.0.join("other");
    for dir in [&run, &target, &other] {
        omgs::platform::private_dir(dir).unwrap();
    }
    write_json(&run.join("run-metadata.json"), &json!({"target": target}));
    let mut l = Ledger::default();
    l.extra.insert("scope_root".into(), json!(target.join(".")));
    assert!(omgs::mapping::validate_run_root(&l, &run).is_ok());
    l.extra.insert("scope_root".into(), json!(other));
    write_json(&run.join("coverage-ledger.json"), &l);
    let before = std::fs::read(run.join("coverage-ledger.json")).unwrap();
    for args in [
        vec!["ledger", "list", "--ledger"],
        vec!["ledger", "migrate", "--run"],
    ] {
        let path = if args[1] == "list" {
            run.join("coverage-ledger.json")
        } else {
            run.clone()
        };
        let out = command(&t).args(args).arg(path).output().unwrap();
        assert!(!out.status.success(), "{out:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("this run's target"),
            "{out:?}"
        );
    }
    assert!(omgs::critic::critique_dir(&run, &Default::default())
        .unwrap_err()
        .contains("this run's target"));
    assert_eq!(
        std::fs::read(run.join("coverage-ledger.json")).unwrap(),
        before
    );
}

#[test]
fn ledger_add_rejects_unregistered_classes_and_intent_resolves_aliases() {
    let t = Temp::new();
    let path = t.0.join("coverage-ledger.json");
    write_json(&path, &Ledger::default());
    let before = std::fs::read(&path).unwrap();
    let out = command(&t)
        .args(["ledger", "add", "--ledger"])
        .arg(&path)
        .args([
            "--unit",
            "test",
            "--surface",
            "src/a.ts",
            "--classes",
            "missing_authz,typo_class",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("unknown attack class typo_class; expected")
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    for (alias, replacement) in [
        ("idor", "idor_tenant_isolation"),
        ("fail-closed", "fail_closed_semantics"),
    ] {
        let list = |class| {
            command(&t)
                .args(["intent", "list", "--attack-class", class])
                .output()
                .unwrap()
        };
        let aliased = list(alias);
        let registered = list(replacement);
        assert!(aliased.status.success());
        assert_eq!(aliased.stdout, registered.stdout);
        assert!(!String::from_utf8_lossy(&aliased.stdout).contains("no intent questions"));
    }
}

#[cfg(unix)]
#[test]
fn audit_init_rejects_non_utf8_canonical_target_without_panicking() {
    use std::os::unix::ffi::OsStringExt;
    let t = Temp::new();
    let target =
        t.0.join(std::ffi::OsString::from_vec(b"target-\xff".to_vec()));
    use std::os::unix::fs::DirBuilderExt;
    if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(&target) {
        #[cfg(target_os = "macos")]
        if e.raw_os_error() == Some(92) {
            eprintln!("non UTF-8 fixture unavailable on this filesystem: {e}");
            return;
        }
        panic!("non UTF-8 fixture creation failed: {e}");
    }
    let direct = command(&t)
        .args(["audit", "init", "--target"])
        .arg(&target)
        .output()
        .unwrap();
    assert_eq!(direct.status.code(), Some(2), "{direct:?}");
    assert!(String::from_utf8_lossy(&direct.stderr).contains("arguments must be UTF-8"));
    let alias = t.0.join("alias");
    std::os::unix::fs::symlink(&target, &alias).unwrap();
    let run = t.0.join("run");
    let out = command(&t)
        .args(["audit", "init", "--target"])
        .arg(alias)
        .arg("--out")
        .arg(&run)
        .arg("--no-sensors")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("UTF-8 target path"));
    assert!(!run.exists());
}
