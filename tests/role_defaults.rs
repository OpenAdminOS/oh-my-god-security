use omgs::paths::{classify, classify_with_size, Class};
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
        ("lib/third_party/x.c", Class::Code),
        (r"APP\NODE_MODULES\x.js", Class::Code),
        ("build/output.swift", Class::Code),
        ("lib/foo.min.js", Class::Code),
        ("tests/security.rs", Class::Test),
        ("src/__tests__/auth.ts", Class::Code),
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
        ("fixtures/handler.js", Class::Code),
        ("docs/example.py", Class::Code),
        ("README.md", Class::Docs),
        ("docs/guide.mdx", Class::Code),
        ("LICENSE", Class::Docs),
        ("data/export.json", Class::Code),
        ("export.csv", Class::Code),
        ("package.json", Class::Code),
        ("assets/icon.png", Class::Code),
        ("contest/main.rs", Class::Code),
    ] {
        assert_eq!(classify(path), class, "{path}");
    }
    let root = scratch("large-data");
    let file = std::fs::File::create(root.join("dump.json")).unwrap();
    file.set_len(20 << 20).unwrap();
    assert_eq!(classify("dump.json"), Class::Code);
    assert_eq!(classify_with_size("dump.json", 20 << 20), Class::Data);
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
    assert_eq!(projects.len(), 4, "{projects:?}");
    for (root, stack) in [
        ("apps/web", "nextjs-app-router"),
        ("apps/addon", "browser-extension"),
        ("scripts", "shell"),
    ] {
        let p = projects.iter().find(|p| p["root"] == root).unwrap();
        assert!(p["stacks"].as_array().unwrap().contains(&json!(stack)));
    }
    assert!(meta["detected_stacks"]
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
fn briefs_and_pack_intents_are_complete() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("skill");
    let skill = std::fs::read_to_string(root.join("SKILL.md")).unwrap();
    assert!(skill.contains("verbatim"));
    assert!(skill.contains("Do not paraphrase"));
    for role in ["red-hunter", "blue-verifier", "evaluator", "green-fixer"] {
        let path = format!("agents/{role}.md");
        assert!(skill.contains(&path));
        let brief = std::fs::read_to_string(root.join(path)).unwrap();
        for section in [
            "## Inputs",
            "## Allowed reads",
            "## Output and schema",
            "## Exact commands",
            "## Never do",
        ] {
            assert!(brief.contains(section), "{role}: {section}");
        }
        assert!(brief.contains("outside omgs prove"));
    }
    for name in ["identity-binding", "fail-closed-semantics"] {
        let pack = std::fs::read_to_string(root.join(format!("packs/{name}.md"))).unwrap();
        for section in [
            "## What to hunt",
            "## Source patterns that matter",
            "## Proof shape",
            "## False leads a verifier should kill",
            "## Intent questions",
        ] {
            assert!(pack.contains(section));
        }
    }
    for entry in std::fs::read_dir(root.join("packs")).unwrap() {
        let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
        let intents = text.split("## Intent questions").nth(1).unwrap();
        for line in intents.lines().filter(|l| l.starts_with("- `")) {
            let id = line.split('`').nth(1).unwrap();
            assert!(omgs::intent::find(id).is_some(), "unknown intent {id}");
        }
    }
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

#[cfg(unix)]
#[test]
fn native_manifest_paths_do_not_reinterpret_literal_backslashes() {
    let dir = scratch("native-manifest");
    let target = dir.join("repo");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::create_dir_all(dir.join("outside")).unwrap();
    std::fs::write(
        dir.join("outside/manifest.json"),
        r#"{"manifest_version":3}"#,
    )
    .unwrap();
    let literal = PathBuf::from(r"..\outside\manifest.json");
    std::fs::write(target.join(&literal), "{}").unwrap();
    std::fs::create_dir_all(target.join(r"apps\addon")).unwrap();
    std::fs::write(
        target.join(r"apps\addon/manifest.json"),
        r#"{"manifest_version":3}"#,
    )
    .unwrap();
    assert_eq!(
        omgs::platform::read_bounded_in(&target, &literal, 1024).unwrap(),
        b"{}"
    );
    let projects = omgs::stacks::detect(&target, std::slice::from_ref(&literal));
    assert!(!projects
        .iter()
        .any(|p| p.stacks.contains(&"browser-extension")));
    let meta = init(&target, &dir.join("run"), &[]);
    let projects = meta["subprojects"].as_array().unwrap();
    assert_eq!(projects.len(), 2);
    let addon = projects
        .iter()
        .find(|p| p["root"] == "apps%5Caddon")
        .unwrap();
    assert_eq!(addon["stacks"], json!(["browser-extension"]));
    for path in [
        PathBuf::from("../outside/manifest.json"),
        dir.join("outside/manifest.json"),
    ] {
        assert!(omgs::platform::read_bounded_in(&target, &path, 1024).is_err());
        assert!(omgs::stacks::detect(&target, &[path]).is_empty());
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn manifest_reads_reject_symlinked_ancestors() {
    let dir = scratch("manifest-ancestor");
    let target = dir.join("repo");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::create_dir_all(dir.join("outside/nested")).unwrap();
    std::fs::write(
        dir.join("outside/nested/manifest.json"),
        r#"{"manifest_version":3}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink(dir.join("outside"), target.join("linked")).unwrap();
    let path = PathBuf::from("linked/nested/manifest.json");
    assert!(omgs::platform::read_bounded_in(&target, &path, 1024).is_err());
    assert!(!omgs::stacks::detect(&target, &[path])
        .iter()
        .any(|p| p.stacks.contains(&"browser-extension")));
    let meta = init(&target, &dir.join("run"), &[]);
    assert_eq!(meta["detected_stacks"], json!([]));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn runtime_routes_and_docs_application_keep_coverage() {
    let dir = scratch("runtime-names");
    let target = dir.join("repo");
    for file in [
        "apps/docs/package.json",
        "apps/docs/src/index.ts",
        "app/api/docs/route.ts",
        "app/api/spec/route.ts",
        "docs/guide.md",
        "tests/fixture.ts",
    ] {
        let path = target.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "").unwrap();
    }
    let meta = init(&target, &dir.join("run"), &[]);
    let projects = meta["subprojects"].as_array().unwrap();
    assert!(projects
        .iter()
        .any(|p| p["root"] == "apps/docs" && p["stacks"] == json!(["node"])));
    let ledger = read(&dir.join("run/coverage-ledger.json"));
    let units = ledger["units"].as_array().unwrap();
    for route in ["app/api/docs/route.ts", "app/api/spec/route.ts"] {
        assert!(units
            .iter()
            .any(|u| u["id"] == format!("route:{route}") && u["status"] == "planned"));
    }
    for (id, label) in [
        ("docs:excluded", "documentation"),
        ("tests:excluded", "test or fixture"),
    ] {
        let unit = units.iter().find(|u| u["id"] == id).unwrap();
        assert_eq!(unit["status"], "out_of_scope");
        assert_eq!(unit["surface"], format!("1 {label} file(s)"));
        assert!(unit["note"].as_str().unwrap().contains("1 "));
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn fixture_manifests_cannot_create_projects_or_leak_stacks() {
    let dir = scratch("fixture-roots");
    let paths = [
        "package.json",
        "src/main.js",
        "tests/fixtures/x/package.json",
        "tests/fixtures/x/main.py",
        "tests/fixtures/y/Cargo.toml",
        "tests/fixtures/y/src/main.rs",
        "spec/fixtures/addon/manifest.json",
    ];
    let projects = omgs::stacks::detect(&dir, &paths.map(PathBuf::from));
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].root, ".");
    assert_eq!(projects[0].stacks, vec!["node"]);
    for path in &paths[2..] {
        assert_eq!(classify(path), Class::Test);
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn many_project_markers_use_nearest_ancestor_and_inventory_is_bounded() {
    let dir = scratch("many-roots");
    let mut paths = Vec::new();
    for i in 0..2000 {
        paths.push(PathBuf::from(format!("packages/p{i}/package.json")));
        paths.push(PathBuf::from(format!("packages/p{i}/src/main.py")));
        paths.push(PathBuf::from(format!("packages/p{i}/nested/Cargo.toml")));
    }
    let projects = omgs::stacks::detect(&dir, &paths);
    assert_eq!(projects.len(), 4000);
    assert_eq!(
        projects
            .iter()
            .filter(|p| p.root.ends_with("/nested") && p.stacks == ["rust"])
            .count(),
        2000
    );
    assert_eq!(
        projects
            .iter()
            .filter(|p| !p.root.ends_with("/nested") && p.stacks == ["python"])
            .count(),
        2000
    );
    let mut oversized = vec![PathBuf::from("README.md"); omgs::stacks::INVENTORY_LIMIT];
    oversized.push(PathBuf::from("outside-cap/package.json"));
    assert!(omgs::stacks::detect(&dir, &oversized).is_empty());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn mixed_monorepo_keeps_unknown_stacks_and_generic_coverage() {
    let dir = scratch("unknown-stack");
    let target = dir.join("repo");
    for file in [
        "apps/web/package.json",
        "services/worker/go.mod",
        "services/worker/main.go",
    ] {
        let path = target.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "").unwrap();
    }
    let meta = init(&target, &dir.join("run"), &[]);
    let projects = meta["subprojects"].as_array().unwrap();
    assert_eq!(projects.len(), 2);
    assert!(projects
        .iter()
        .any(|p| p["root"] == "services/worker" && p["stacks"] == json!([])));
    let ledger = read(&dir.join("run/coverage-ledger.json"));
    assert!(ledger["units"]
        .as_array()
        .unwrap()
        .iter()
        .any(|u| u["surface"] == "services/worker"
            && u["status"] == "planned"
            && !u["attack_classes"].as_array().unwrap().is_empty()));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn sql_and_html_always_stay_code_and_test_suffixes_need_boundaries() {
    for file in [
        "dump.sql",
        "dump.html",
        "backup.dump.sql",
        "dumps/site.html",
        "exports/database.sql",
    ] {
        assert_eq!(classify(file), Class::Code, "{file}");
    }
    for file in [
        "templates/index.html",
        "migrations/001_create.sql",
        "Latest.cs",
        "Contest.cs",
        "Latest.java",
        "src/Latest.kt",
    ] {
        assert_eq!(classify(file), Class::Code, "{file}");
    }
    for file in [
        "AuthTest.cs",
        "AuthTests.cs",
        "auth_test.cs",
        "AuthTest.java",
        "AuthTest.kt",
        "AuthTests.swift",
    ] {
        assert_eq!(classify(file), Class::Test, "{file}");
    }
    let dir = scratch("large-dumps");
    for file in ["dump.sql", "dump.html", "template.html"] {
        std::fs::File::create(dir.join(file))
            .unwrap()
            .set_len(20 << 20)
            .unwrap();
    }
    let run = dir.with_extension("run");
    let meta = init(&dir, &run, &[]);
    assert!(meta["path_classes"].get("data").is_none());
    assert_eq!(meta["files_first_party"], 3);
    std::fs::remove_dir_all(run).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

fn assert_no_persona(meta: &Value, budget: Option<u64>) {
    assert!(meta["persona"].is_null());
    assert_eq!(meta["report_depth"], "full");
    assert_eq!(meta["budget_profile"], "standard");
    assert_eq!(meta["budget_agent_calls"].as_u64(), budget);
    if budget.is_none() {
        assert!(meta.get("budget_agent_calls").is_none());
    }
}

#[test]
fn no_persona_audit_review_and_batch_preserve_full_defaults() {
    let dir = scratch("no-persona-entrypoints");
    let target = dir.join("data/targets/github.com/acme/shop");
    std::fs::create_dir_all(&target).unwrap();
    for args in [
        vec!["init"],
        vec!["remote", "add", "origin", "https://github.com/acme/shop"],
    ] {
        let out = std::process::Command::new(omgs::platform::which("git").unwrap())
            .arg("-C")
            .arg(&target)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    for budget in [None, Some(7)] {
        let extra = if budget.is_some() {
            vec!["--budget", "7"]
        } else {
            vec![]
        };
        let audit_run = dir.join(format!("audit-{budget:?}"));
        assert_no_persona(&init(&target, &audit_run, &extra), budget);
        let out = cli(&[
            "report",
            "--findings",
            audit_run.join("findings.json").to_str().unwrap(),
            "--out",
            audit_run.to_str().unwrap(),
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_no_persona(&read(&audit_run.join("run-metadata.json")), budget);
        let html = std::fs::read_to_string(audit_run.join("REPORT.html")).unwrap();
        assert!(!html.contains("<details><summary>Coverage details</summary>"));
        let mut args = vec![
            "review",
            "--repo-url",
            "https://github.com/acme/shop",
            "--no-sensors",
        ];
        args.extend_from_slice(&extra);
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
            .env("OMGS_HOME", dir.join("data"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let run = PathBuf::from(String::from_utf8_lossy(&out.stdout).lines().next().unwrap());
        assert_no_persona(&read(&run.join("run-metadata.json")), budget);
        let list = dir.join("list.txt");
        std::fs::write(&list, "https://github.com/acme/shop\n").unwrap();
        let batch = dir.join(format!("batch-{budget:?}"));
        let mut args = vec![
            "batch",
            "init",
            "--list",
            list.to_str().unwrap(),
            "--out",
            batch.to_str().unwrap(),
            "--no-sensors",
        ];
        args.extend_from_slice(&extra);
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
            .env("OMGS_HOME", dir.join("data"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let batch_meta = read(&batch.join("batch.json"));
        let run = PathBuf::from(batch_meta["runs"][0]["run_dir"].as_str().unwrap());
        assert_no_persona(&read(&run.join("run-metadata.json")), budget);
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn installed_brief_references_resolve_to_packaged_schemas() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let skill = root.join("skill");
    // setup copies this tree verbatim. Every SKILL_DIR reference must exist
    // without a repository checkout or a second findings schema copy.
    assert!(!root.join("schemas/findings.schema.json").exists());
    let schema = read(&skill.join("schemas/findings.schema.json"));
    assert_eq!(schema["title"], "OMGS findings");
    assert!(schema["required"]
        .as_array()
        .unwrap()
        .contains(&json!("findings")));
    for role in ["red-hunter", "blue-verifier", "evaluator", "green-fixer"] {
        let brief = std::fs::read_to_string(skill.join(format!("agents/{role}.md"))).unwrap();
        assert!(!brief.contains("skill/schemas/"));
        for reference in brief.split("SKILL_DIR/").skip(1) {
            let path = reference
                .split(|c: char| c.is_whitespace() || [',', ';', ')', '`'].contains(&c))
                .next()
                .unwrap();
            assert!(
                skill.join(path.trim_end_matches('.')).is_file(),
                "{role}: {path}"
            );
        }
    }
}

#[test]
fn initial_proof_belongs_to_verifier_and_replay_to_evaluator() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let hunter = std::fs::read_to_string(root.join("skill/agents/red-hunter.md")).unwrap();
    assert!(!hunter.lines().any(|l| l.starts_with("omgs prove")));
    assert!(hunter.contains("Only the verifier runs the initial proof"));
    for (path, command) in [
        (
            "skill/agents/blue-verifier.md",
            "omgs prove --run OUTPUT_DIR --finding",
        ),
        (
            "skill/agents/evaluator.md",
            "omgs prove --run OUTPUT_DIR --replay",
        ),
    ] {
        assert!(std::fs::read_to_string(root.join(path))
            .unwrap()
            .contains(command));
    }
    let skill = std::fs::read_to_string(root.join("skill/SKILL.md")).unwrap();
    assert!(skill
        .contains("Hunters hand proof plans and drafts to the verifier and never execute proofs"));
    assert!(skill.contains("The independent verifier submits"));
    let decisions = std::fs::read_to_string(root.join("DECISIONS.md")).unwrap();
    assert!(!decisions.contains("red agents hunt and prove"));
}

#[test]
fn adversarial_classifier_requires_exclusion_evidence() {
    for (path, size, expected) in [
        ("app/api/tests/route.ts", 0, Class::Code),
        ("app/api/fixtures/route.ts", 0, Class::Code),
        ("pages/api/test.ts", 0, Class::Code),
        ("src/views/export.html", 0, Class::Code),
        ("migrations/exports/001.sql", 0, Class::Code),
        ("src/test_utils.py", 0, Class::Code),
        ("tests/fixtures/app/route.ts", 0, Class::Test),
        ("data/dump.ndjson", 20 << 20, Class::Data),
        ("docs/guide.md", 0, Class::Docs),
        ("data/dump.json", (1 << 20) - 1, Class::Code),
        ("data/dump.json", 1 << 20, Class::Data),
        ("templates/exports/dump.html", 20 << 20, Class::Code),
        ("migrations/dump.sql", 20 << 20, Class::Code),
        ("src/server/tests/tool.ps1", 0, Class::Code),
        ("server/fixtures/run.sh", 0, Class::Code),
        ("src/vendor/handler.ts", 0, Class::Code),
        ("backend/tests/route.ts", 0, Class::Code),
        ("templates/__tests__/export.html", 0, Class::Code),
        ("app/api/node_modules/route.ts", 0, Class::Code),
        ("src/auth.test.helper.ts", 0, Class::Code),
        ("docs/guide.py", 0, Class::Code),
        ("dist/server.js", 0, Class::Code),
        ("production/unknown.format", 0, Class::Code),
        ("tests_auth.py", 0, Class::Code),
        ("tests/auth.py", 0, Class::Test),
        ("checks/__tests__/auth.ts", 0, Class::Code),
        ("src/auth.test.ts", 0, Class::Test),
        ("auth_test.go", 0, Class::Test),
        ("test_auth.py", 0, Class::Test),
        ("AuthTests.cs", 0, Class::Test),
    ] {
        assert_eq!(classify_with_size(path, size), expected, "{path}");
    }
}

#[test]
fn adversarial_routes_seed_hunting_and_disclose_sorted_exclusions() {
    let dir = scratch("adversarial-coverage");
    let target = dir.join("repo");
    let run = dir.join("run");
    let runtime = [
        "app/api/tests/route.ts",
        "app/api/fixtures/route.ts",
        "pages/api/test.ts",
        "src/views/export.html",
        "migrations/exports/001.sql",
        "src/test_utils.py",
    ];
    for path in runtime.into_iter().chain([
        "tests/fixtures/app/route.ts",
        "vendor/package/tool.sh",
        "node_modules/pkg/index.js",
        "docs/guide.md",
        "data/dump.ndjson",
    ]) {
        let path = target.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "").unwrap();
        if path.extension().unwrap() == "ndjson" {
            // A real 20 MiB NDJSON dump, rather than a sparse placeholder.
            let rows = b"{\"row\":0}\n".repeat((20 << 20) / 10);
            assert_eq!(rows.len(), 20 << 20);
            std::fs::write(&path, rows).unwrap();
        }
    }
    for i in (0..25).rev() {
        std::fs::write(target.join(format!("tests/test_{i:02}.py")), "").unwrap();
    }
    let meta = init(&target, &run, &[]);
    assert_eq!(meta["files_first_party"], runtime.len());
    let ledger = read(&run.join("coverage-ledger.json"));
    let units = ledger["units"].as_array().unwrap();
    for route in &runtime[..3] {
        assert!(
            units
                .iter()
                .any(|u| u["id"] == format!("route:{route}") && u["status"] == "planned"),
            "{route}"
        );
    }
    let tests = units.iter().find(|u| u["id"] == "tests:excluded").unwrap();
    assert_eq!(tests["excluded_count"], 26);
    assert_eq!(tests["excluded_source_count"], 26);
    let sample = tests["excluded_source_paths"].as_array().unwrap();
    assert_eq!(sample.len(), 20);
    assert_eq!(sample[0], "tests/fixtures/app/route.ts");
    assert_eq!(sample[19], "tests/test_18.py");
    assert!(sample.windows(2).all(|w| w[0].as_str() < w[1].as_str()));
    let vendor = units
        .iter()
        .find(|u| u["id"] == "vendored:excluded")
        .unwrap();
    assert_eq!(vendor["excluded_source_count"], 2);
    assert_eq!(
        vendor["excluded_source_paths"],
        json!(["node_modules/pkg/index.js", "vendor/package/tool.sh"])
    );
    let data = units.iter().find(|u| u["id"] == "data:excluded").unwrap();
    assert_eq!(data["excluded_paths"], json!(["data/dump.ndjson"]));
    let listed = cli(&[
        "ledger",
        "list",
        "--ledger",
        run.join("coverage-ledger.json").to_str().unwrap(),
    ]);
    assert!(listed.status.success());
    assert!(String::from_utf8_lossy(&listed.stdout).contains("tests/fixtures/app/route.ts"));
    let out = cli(&["critic", "--run", run.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "unhunted production routes must not pass"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("app/api/tests/route.ts"));
    std::fs::remove_dir_all(dir).unwrap();
}

fn set_spending(run: &Path, calls: u64, proofs: u64) {
    omgs::runmeta::update(run, |m| {
        m.insert("agent_calls_used".into(), json!(calls));
        m.insert("proof_runs_used".into(), json!(proofs));
        Ok(())
    })
    .unwrap();
}
fn allowance(run: &Path) -> Value {
    let out = cli(&["budget", "--run", run.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn fixer_allowance_counts_multiple_rounds_once_and_never_goes_negative() {
    let dir = scratch("cumulative-fix-budget");
    let target = dir.join("repo");
    std::fs::create_dir_all(&target).unwrap();
    let root = dir.join("original");
    init(&target, &root, &["--persona", "builder"]);
    set_spending(&root, 10, 4);
    let fix1 = dir.join("fix1");
    let meta = init(
        &target,
        &fix1,
        &["--fix-of", root.to_str().unwrap(), "--persona", "builder"],
    );
    assert_eq!(meta["budget_agent_calls"], 10);
    set_spending(&fix1, 4, 2);
    assert_eq!(allowance(&root)["remaining"], 4);
    assert_eq!(allowance(&fix1)["calls_and_proofs_used"], 20);
    assert_eq!(
        read(&root.join("run-metadata.json"))["agent_calls_used"],
        10
    );
    let fix2 = dir.join("fix2");
    let meta = init(
        &target,
        &fix2,
        &["--fix-of", root.to_str().unwrap(), "--persona", "builder"],
    );
    assert_eq!(meta["budget_agent_calls"], 4);
    set_spending(&fix2, 1, 1);
    assert_eq!(allowance(&root)["remaining"], 2);
    omgs::budget::charge_proof(&root).unwrap();
    omgs::budget::charge_proof(&fix2).unwrap();
    assert_eq!(allowance(&root)["remaining"], 0);
    assert!(omgs::budget::charge_proof(&root)
        .unwrap_err()
        .starts_with("run budget exhausted"));
    assert!(omgs::budget::charge_proof(&fix1)
        .unwrap_err()
        .starts_with("run budget exhausted"));
    let fix3 = dir.join("fix3");
    assert_eq!(
        init(&target, &fix3, &["--fix-of", root.to_str().unwrap()])["budget_agent_calls"],
        0
    );
    set_spending(&fix2, 9, 9);
    assert_eq!(allowance(&root)["remaining"], 0);
    set_spending(&root, u64::MAX, 1);
    let out = cli(&["budget", "--run", root.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("overflow"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn uncapped_fix_runs_stay_uncapped_and_broken_links_fail_closed() {
    let dir = scratch("uncapped-fix-budget");
    let target = dir.join("repo");
    std::fs::create_dir_all(&target).unwrap();
    let root = dir.join("original");
    init(&target, &root, &[]);
    let fix = dir.join("fix");
    let meta = init(
        &target,
        &fix,
        &["--fix-of", root.to_str().unwrap(), "--persona", "builder"],
    );
    assert!(meta.get("budget_agent_calls").is_none());
    set_spending(&fix, 30, 40);
    assert!(allowance(&fix)["remaining"].is_null());
    omgs::runmeta::update(&root, |m| {
        let duplicate = m["fix_runs"][0].clone();
        m["fix_runs"].as_array_mut().unwrap().push(duplicate);
        Ok(())
    })
    .unwrap();
    assert!(!cli(&["budget", "--run", root.to_str().unwrap()])
        .status
        .success());
    std::fs::remove_dir_all(&fix).unwrap();
    assert!(!cli(&["budget", "--run", root.to_str().unwrap()])
        .status
        .success());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn concurrent_fix_proofs_cannot_exceed_the_original_cap() {
    let dir = scratch("concurrent-fix-budget");
    let target = dir.join("repo");
    std::fs::create_dir_all(&target).unwrap();
    let root = dir.join("original");
    init(&target, &root, &["--budget", "1"]);
    let fix1 = dir.join("fix1");
    let fix2 = dir.join("fix2");
    for fix in [&fix1, &fix2] {
        init(&target, fix, &["--fix-of", root.to_str().unwrap()]);
    }
    let threads: Vec<_> = [root.clone(), fix1, fix2]
        .into_iter()
        .map(|run| std::thread::spawn(move || omgs::budget::charge_proof(&run)))
        .collect();
    let successes = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .filter(Result::is_ok)
        .count();
    assert_eq!(successes, 1);
    assert_eq!(allowance(&root)["calls_and_proofs_used"], 1);
    assert_eq!(allowance(&root)["remaining"], 0);
    std::fs::remove_dir_all(dir).unwrap();
}
