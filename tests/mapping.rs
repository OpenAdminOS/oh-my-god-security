//! Synthetic mapping/accountability regressions. Source inspection never runs target code.
use omgs::ledger::{validate_ledger, Ledger, Unit};
use serde_json::json;
use std::path::PathBuf;

fn unit(id: &str, status: &str) -> Unit {
    let mut u = Unit::new(id, "src/decision.ts", &["missing_authz"], status);
    u.evidence = vec!["src/decision.ts".into()];
    u.extra
        .insert("scope_paths".into(), json!(["src/decision.ts#GET"]));
    u
}
fn ledger(units: Vec<Unit>) -> Ledger {
    Ledger {
        units,
        ..Default::default()
    }
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
    other
        .extra
        .insert("scope_paths".into(), json!(["src/decision.ts#POST"]));
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
        Self(root)
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
        "missing_authz",
        "--mapping",
        r##"{"scope_paths":["app/api/items/route.ts#GET"]}"##
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
            .filter(|t| t.contains('_') && omgs::classes::valid_identifier(t))
        {
            if ["intent_id", "needs_validation"].contains(&token) {
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
