use omgs::paths::{classify, Class};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("omgs-roles-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}
fn cli(args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args(args)
        .output()
        .unwrap()
}
fn read(path: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn init(target: &Path, run: &Path, extra: &[&str]) -> Value {
    let mut args = vec![
        "audit",
        "init",
        "--target",
        target.to_str().unwrap(),
        "--out",
        run.to_str().unwrap(),
        "--no-sensors",
    ];
    args.extend_from_slice(extra);
    let out = cli(&args);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    read(&run.join("run-metadata.json"))
}

#[test]
fn classifier_table_covers_every_class_and_stack_conventions() {
    for (path, class) in [
        ("src/main.rs", Class::Code),
        ("src/service.ts", Class::Code),
        ("scripts/apply.ps1", Class::Code),
        ("scripts/run.sh", Class::Code),
        ("vendor/tests/x.py", Class::Vendored),
        ("node_modules/package/main.js", Class::Vendored),
        ("lib/third_party/x.c", Class::Vendored),
        (r"APP\NODE_MODULES\x.js", Class::Vendored),
        ("build/output.swift", Class::Vendored),
        ("lib/foo.min.js", Class::Vendored),
        ("tests/security.rs", Class::Test),
        ("src/__tests__/auth.ts", Class::Test),
        ("src/auth.spec.tsx", Class::Test),
        ("src/auth.test.js", Class::Test),
        ("test_auth.py", Class::Test),
        ("auth_test.py", Class::Test),
        ("AuthTests.cs", Class::Test),
        ("AuthTests.swift", Class::Test),
        ("Auth.Tests.ps1", Class::Test),
        ("auth_test.go", Class::Test),
        ("auth.bats", Class::Test),
        ("tests/check.sh", Class::Test),
        ("fixtures/handler.js", Class::Test),
        ("docs/example.py", Class::Docs),
        ("README.md", Class::Docs),
        ("docs/guide.mdx", Class::Docs),
        ("LICENSE", Class::Docs),
        ("data/export.json", Class::Data),
        ("export.csv", Class::Data),
        ("package.json", Class::Data),
        ("assets/icon.png", Class::Data),
        ("contest/main.rs", Class::Code),
    ] {
        assert_eq!(classify(path), class, "{path}");
    }
    let root = scratch("large-data");
    let file = std::fs::File::create(root.join("dump.json")).unwrap();
    file.set_len(20 << 20).unwrap();
    assert_eq!(classify("dump.json"), Class::Data);
    let meta = init(&root, &root.with_extension("run"), &[]);
    assert_eq!(meta["files_first_party"], 0);
    assert_eq!(meta["path_classes"]["data"], 1);
    std::fs::remove_dir_all(root.with_extension("run")).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn monorepo_stacks_are_scoped_and_exclude_docs_tests_and_vendor() {
    let dir = scratch("monorepo");
    let target = dir.join("repo");
    let files = [
        ("apps/web/package.json", "{}"),
        ("apps/web/app/api/x/route.ts", ""),
        (
            "apps/addon/manifest.json",
            r#"{"manifest_version":3,"name":"fixture"}"#,
        ),
        ("apps/addon/main.js", ""),
        ("scripts/package.json", "{}"),
        ("scripts/deploy.sh", ""),
        ("docs/sample.py", ""),
        ("tests/example.swift", ""),
        ("vendor/hidden/manifest.json", r#"{"manifest_version":3}"#),
        ("vendor/hidden/tool.ps1", ""),
        ("dump.json", "{}"),
        ("ordinary/manifest.json", r#"{"name":"ordinary"}"#),
    ];
    for (path, text) in files {
        let path = target.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    let meta = init(&target, &dir.join("run"), &[]);
    let projects = meta["subprojects"].as_array().unwrap();
    assert_eq!(projects.len(), 3, "{projects:?}");
    for (root, stack) in [
        ("apps/web", "nextjs-app-router"),
        ("apps/addon", "browser-extension"),
        ("scripts", "shell"),
    ] {
        let p = projects.iter().find(|p| p["root"] == root).unwrap();
        assert!(p["stacks"].as_array().unwrap().contains(&json!(stack)));
    }
    assert!(!meta["detected_stacks"]
        .as_array()
        .unwrap()
        .contains(&json!("python")));
    let arch = read(&dir.join("run/architecture.json"));
    assert!(arch["stack"]["notes"]
        .as_str()
        .unwrap()
        .contains("apps/addon: "));
    let ledger = read(&dir.join("run/coverage-ledger.json"));
    assert!(ledger["units"]
        .as_array()
        .unwrap()
        .iter()
        .any(|u| u["surface"] == "apps/addon"));
    for version in [json!(2), json!(3), json!("3"), json!(4), Value::Null] {
        std::fs::write(
            target.join("apps/addon/manifest.json"),
            json!({"manifest_version":version}).to_string(),
        )
        .unwrap();
        let projects = omgs::stacks::detect(
            &target,
            &[
                "apps/addon/manifest.json".into(),
                "apps/addon/main.js".into(),
            ],
        );
        let detected = projects
            .iter()
            .any(|p| p.stacks.contains(&"browser-extension"));
        assert_eq!(detected, version == 2 || version == 3);
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn persona_defaults_and_explicit_overrides_are_recorded() {
    let dir = scratch("personas");
    let target = dir.join("repo");
    std::fs::create_dir(&target).unwrap();
    for (name, budget, depth) in [
        ("builder", 24, "concise"),
        ("inheritor", 64, "full"),
        ("team", 96, "full"),
    ] {
        let meta = init(&target, &dir.join(name), &["--persona", name]);
        assert_eq!(meta["persona"], name);
        assert_eq!(meta["budget_agent_calls"], budget);
        assert_eq!(meta["report_depth"], depth);
        assert_eq!(meta["mode"], "advisory");
        assert_eq!(meta["execution_policy"], "sandboxed-source-and-local-only");
        let overridden = init(
            &target,
            &dir.join(format!("{name}-override")),
            &["--persona", name, "--budget", "7", "--mode", "gate"],
        );
        assert_eq!(overridden["budget_agent_calls"], 7);
        assert_eq!(overridden["mode"], "gate");
    }
    let bad = cli(&[
        "audit",
        "init",
        "--target",
        target.to_str().unwrap(),
        "--out",
        dir.join("bad").to_str().unwrap(),
        "--persona",
        "other",
    ]);
    assert_eq!(bad.status.code(), Some(2));
    assert!(!dir.join("bad").exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn accounting_unknown_round_trips_through_status_and_report() {
    let dir = scratch("accounting");
    let target = dir.join("repo");
    std::fs::create_dir(&target).unwrap();
    let run = dir.join("run");
    init(&target, &run, &["--persona", "builder"]);
    let out = cli(&[
        "status",
        "--run",
        run.to_str().unwrap(),
        "--stage",
        "hunt",
        "--state",
        "done",
        "--accounting",
        "red-hunter=100,unknown,",
        "--accounting",
        "blue-verifier=0,0,0",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("red-hunter: tokens 100, cost USD unknown, duration ms unknown"));
    let meta = read(&run.join("run-metadata.json"));
    assert!(meta["accounting"]["red-hunter"]["duration_ms"].is_null());
    assert_eq!(meta["accounting"]["blue-verifier"]["tokens"], 0);
    let out = cli(&[
        "report",
        "--findings",
        run.join("findings.json").to_str().unwrap(),
        "--out",
        run.to_str().unwrap(),
        "--accounting",
        "evaluator=unknown,0.12,50",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for path in ["REPORT.md", "REPORT.html"] {
        let text = std::fs::read_to_string(run.join(path)).unwrap();
        assert!(text.contains("red-hunter: tokens 100, cost USD unknown, duration ms unknown"));
        assert!(text.contains("evaluator: tokens unknown, cost USD 0.12, duration ms 50"));
        assert!(text.contains("green-fixer: tokens unknown, cost USD unknown, duration ms unknown"));
    }
    let meta = omgs::runmeta::read(&run).unwrap();
    assert_eq!(
        omgs::accounting::read(&meta).unwrap()["red-hunter"].duration_ms,
        None
    );
    for bad in [
        "red-hunter=-1,0,0",
        "red-hunter=0,NaN,0",
        "red-hunter=0,-1,0",
        "red-hunter=0,inf,0",
        "unknown=0,0,0",
        "red-hunter=1,2",
    ] {
        assert!(omgs::accounting::parse(&[bad.into()]).is_err(), "{bad}");
    }
    // Invalid input must not rewrite progress or accounting.
    let before = std::fs::read(run.join("pipeline-status.json")).unwrap();
    let out = cli(&[
        "status",
        "--run",
        run.to_str().unwrap(),
        "--stage",
        "hunt",
        "--state",
        "active",
        "--accounting",
        "red-hunter=-1,0,0",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        std::fs::read(run.join("pipeline-status.json")).unwrap(),
        before
    );
    for bad in [
        json!({"accounting":[]}),
        json!({"accounting":{"red-hunter":[null,null,null]}}),
        json!({"accounting":{"red-hunter":{"tokens":-1}}}),
    ] {
        assert!(omgs::accounting::read(bad.as_object().unwrap()).is_err());
    }
    std::fs::remove_dir_all(dir).unwrap();
}
