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
