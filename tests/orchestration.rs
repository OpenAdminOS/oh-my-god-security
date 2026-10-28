use omgs::batch::{
    parse_repo_url, read_list, render_index_html, render_index_markdown, summarize, BatchRun,
    RunSummary,
};
use omgs::model::{validate, Finding, FindingsFile, Location, ProofTier, Verdict};
use omgs::report::{render_html, render_markdown, ReportMeta};
use std::path::Path;

// Valid storage fixtures must have the same owner and ACL as runtime files,
// including when the Windows test process has an elevated token.
fn write_private_fixture(
    path: impl AsRef<std::path::Path>,
    bytes: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    omgs::runmeta::write_atomic_bytes(path.as_ref(), bytes.as_ref())
}

fn scratch(name: &str) -> std::path::PathBuf {
    static BASE: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    let base = BASE.get_or_init(|| {
        let base = omgs::platform::temp_root()
            .unwrap()
            .join(format!("omgs-private-fixtures-{}", std::process::id()));
        omgs::platform::create_private_tree(&base).unwrap();
        base
    });
    let dir = base.join(format!("omgs-orch-{}-{name}", std::process::id()));
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
fn repo_urls_are_strictly_validated() {
    let ok = parse_repo_url("https://github.com/Acme/shop.git/").unwrap();
    assert_eq!(
        (ok.host.as_str(), ok.owner.as_str(), ok.name.as_str()),
        ("github.com", "Acme", "shop")
    );
    for bad in [
        "file:///etc",
        "ext::sh -c id",
        "-uhttps://github.com/a/b",
        "http://github.com/a/b",
        "git@github.com:a/b.git",
        "https://github.com/a/..",
        "https://github.com/../b",
        "https://github.com/a/.git",
        "https://github.com/a",
        "https://github.com/a/b/c",
        "https://user:pw@github.com/a/b",
        "https://github.com/a/b?x=1",
        "https://github.com/a/-b",
        "https://github.com/a/b%2F..",
        "https://localhost/a/b",
        "https://github.com/a/b c",
        "https://10.0.0.5/a/b",
        "https://169.254.169.254/a/b",
        "https://github.com:22/a/b",
        "https://intranet/a/b",
    ] {
        assert!(parse_repo_url(bad).is_err(), "accepted {bad}");
    }
}

#[test]
fn list_files_skip_comments_and_blanks() {
    let urls = read_list("# repos\nhttps://github.com/a/b\n\n  https://github.com/c/d  # note\n");
    assert_eq!(
        urls,
        vec!["https://github.com/a/b", "https://github.com/c/d"]
    );
}

#[test]
fn review_refuses_bad_urls_before_cloning() {
    let out = omgs(&["review", "--repo-url", "file:///etc"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("only https:// URLs"));
}

fn summary(url: &str, blockers: Vec<String>) -> RunSummary {
    RunSummary {
        url: url.into(),
        report_href: Some("github.com__a__b/REPORT.html".into()),
        state: "complete".into(),
        confirmed: 1,
        needs_validation: 2,
        rejected: 3,
        blockers,
        agent_calls: Some(40),
        budget: None,
        reroutes: 1,
        refusal_events: Vec::new(),
    }
}

#[test]
fn batch_index_is_deterministic_offline_and_escaped() {
    let runs = vec![
        summary("https://github.com/a/b", vec![]),
        RunSummary {
            agent_calls: None,
            report_href: None,
            ..summary(
                "https://github.com/c/d",
                vec![
                    "critic: unit '<img src=x onerror=alert(1)>' | [x](javascript:alert(1))".into(),
                ],
            )
        },
    ];
    let html = render_index_html(&runs);
    assert_eq!(html, render_index_html(&runs));
    // Offline: no tags that load anything, and the only links are relative.
    for banned in ["<img", "<script", "<link", "<iframe", "url(", "http://"] {
        assert!(!html.contains(banned), "found {banned}");
    }
    assert_eq!(html.matches("<a href=").count(), 1);
    assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
    assert!(html.contains("<a href=\"github.com__a__b/REPORT.html\">"));
    assert!(html.contains("2 repositories: 2 confirmed, 4 needs validation, 6 rejected"));
    assert!(html.contains("40 recorded, some runs not recorded"));
    let md = render_index_markdown(&runs);
    assert_eq!(md, render_index_markdown(&runs));
    assert!(!md.contains("[x](javascript"), "markdown link injection");
    assert!(md.contains("Agent calls: 40 recorded, some runs not recorded"));
}

#[test]
fn batch_summary_reads_a_run_directory() {
    let index = scratch("batch");
    let run = index.join("github.com__a__b");
    omgs::platform::create_private_dir(&run).unwrap();
    std::fs::write(run.join("findings.json"), r#"{"findings": []}"#).unwrap();
    write_private_fixture(
        run.join("run-metadata.json"),
        r#"{"run_status":"complete","agent_calls_used":12,"reroutes":[{"role":"hunter","from":"m1","to":"m2","reason":"declined"}],"blockers":["route exhausted"]}"#,
    )
    .unwrap();
    write_private_fixture(
        run.join("coverage-ledger.json"),
        r#"{"units":[{"id":"u1","surface":".","attack_classes":[],"status":"blocked","note":"no db"}]}"#,
    )
    .unwrap();
    std::fs::write(run.join("REPORT.html"), "x").unwrap();
    let s = summarize(
        &BatchRun {
            url: "https://github.com/a/b".into(),
            run_dir: Some(run.to_string_lossy().to_string()),
            status: "initialized".into(),
            ..Default::default()
        },
        &index,
    )
    .unwrap();
    assert_eq!(s.state, "complete");
    assert_eq!(s.agent_calls, Some(12));
    assert_eq!(s.reroutes, 1);
    assert!(s.blockers.iter().any(|b| b == "route exhausted"));
    assert!(s.blockers.iter().any(|b| b == "blocked unit u1"));
    assert!(s.blockers.iter().any(|b| b.starts_with("critic")));
    assert_eq!(
        s.report_href.as_deref(),
        Some("github.com__a__b/REPORT.html")
    );
    let _ = std::fs::remove_dir_all(&index);
}

#[test]
fn status_updates_stages_children_counters_and_log() {
    use omgs::status::{apply, Update};
    let dir = scratch("status");
    let u = |stage, parent, state, log| Update {
        stage,
        label: None,
        parent,
        state,
        detail: Some("d"),
        counters: &[],
        log,
    };
    apply(&dir, &u("hunt", None, "active", Some("hunt started"))).unwrap();
    apply(&dir, &u("red-1", Some("hunt"), "done", None)).unwrap();
    apply(
        &dir,
        &Update {
            counters: &[("candidates".to_string(), 4)],
            ..u("hunt", None, "done", None)
        },
    )
    .unwrap();
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("pipeline-status.json")).unwrap())
            .unwrap();
    assert_eq!(v["stages"].as_array().unwrap().len(), 1);
    assert_eq!(v["stages"][0]["status"], "done");
    assert!(
        v["stages"][0]["ended_ms"].as_u64().unwrap()
            >= v["stages"][0]["started_ms"].as_u64().unwrap()
    );
    assert_eq!(v["stages"][0]["children"][0]["id"], "red-1");
    assert_eq!(v["counters"]["candidates"], 4);
    assert_eq!(v["log"][0]["m"], "hunt started");
    assert!(v["updated_ms"].as_u64().unwrap() > 0);
    assert!(apply(&dir, &u("hunt", None, "running", None)).is_err());
    assert!(apply(
        &dir,
        &Update {
            counters: &[("bogus".to_string(), 1)],
            ..u("hunt", None, "done", None)
        }
    )
    .is_err());
    for i in 0..250 {
        let m = format!("m{i}");
        apply(
            &dir,
            &Update {
                stage: "hunt",
                label: None,
                parent: None,
                state: "active",
                detail: None,
                counters: &[],
                log: Some(&m),
            },
        )
        .unwrap();
    }
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("pipeline-status.json")).unwrap())
            .unwrap();
    assert_eq!(v["log"].as_array().unwrap().len(), 200);
    assert_eq!(v["log"][199]["m"], "m249");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn watch_routes_and_host_rules() {
    use omgs::watch::respond;
    let dir = scratch("watch");
    write_private_fixture(
        dir.join("pipeline-status.json"),
        r#"{"stages":[],"updated_ms":5}"#,
    )
    .unwrap();
    std::fs::write(dir.join("findings.json"), "secret").unwrap();
    let req = |line: &str, host: &str| format!("{line}\r\nHost: {host}\r\n\r\n");
    let r = respond(&req("GET / HTTP/1.1", "127.0.0.1:4000"), 4000, &dir);
    assert_eq!(r.status, 200);
    assert!(String::from_utf8_lossy(&r.body).contains("pipeline-status.json"));
    let r = respond(
        &req("GET /pipeline-status.json?_=1 HTTP/1.1", "localhost:4000"),
        4000,
        &dir,
    );
    assert_eq!(
        (r.status, r.body.as_slice()),
        (200, br#"{"stages":[],"updated_ms":5}"#.as_slice())
    );
    for path in [
        "/findings.json",
        "/../findings.json",
        "/REPORT.html",
        "/run-metadata.json",
    ] {
        let r = respond(
            &req(&format!("GET {path} HTTP/1.1"), "127.0.0.1:4000"),
            4000,
            &dir,
        );
        assert_eq!(r.status, 404, "{path}");
    }
    assert_eq!(
        respond(&req("POST / HTTP/1.1", "127.0.0.1:4000"), 4000, &dir).status,
        405
    );
    for host in ["evil.example:4000", "127.0.0.1:4001", "127.0.0.1"] {
        assert_eq!(
            respond(&req("GET / HTTP/1.1", host), 4000, &dir).status,
            403,
            "{host}"
        );
    }
    assert_eq!(
        respond("GET / HTTP/1.1\r\n\r\n", 4000, &dir).status,
        403,
        "no Host"
    );
    let two = "GET / HTTP/1.1\r\nHost: 127.0.0.1:4000\r\nHost: evil.example\r\n\r\n";
    assert_eq!(respond(two, 4000, &dir).status, 403, "duplicate Host");
    assert_eq!(respond("garbage\r\n\r\n", 4000, &dir).status, 400);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn watch_serves_loopback_and_stops_when_the_run_completes() {
    use std::io::{Read, Write};
    let dir = scratch("watch-live");
    write_private_fixture(
        dir.join("run-metadata.json"),
        r#"{"run_status":"in_progress"}"#,
    )
    .unwrap();
    let (listener, port) = omgs::watch::bind().unwrap();
    assert!(listener.local_addr().unwrap().ip().is_loopback());
    let d = dir.clone();
    let server = std::thread::spawn(move || {
        omgs::watch::serve(listener, port, &d, std::time::Duration::from_secs(60))
    });
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        s,
        "GET /pipeline-status.json HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
    )
    .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    assert!(resp.contains("Cache-Control: no-store"));
    assert!(resp.contains("X-Content-Type-Options: nosniff"));
    assert!(resp.ends_with(r#"{"stages":[],"updated_ms":0}"#));
    write_private_fixture(
        dir.join("run-metadata.json"),
        r#"{"run_status":"complete"}"#,
    )
    .unwrap();
    let start = std::time::Instant::now();
    server.join().unwrap();
    assert!(
        start.elapsed() < std::time::Duration::from_secs(20),
        "stops after the grace period"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn route_follows_fallbacks_and_records_reroutes() {
    let dir = scratch("route");
    write_private_fixture(
        dir.join("run-metadata.json"),
        r#"{"run_status":"in_progress"}"#,
    )
    .unwrap();
    let models = dir.join("models.json");
    std::fs::write(&models, r#"{"roles":{"hunter":["model-a","model-b"]}}"#).unwrap();
    let run = dir.to_str().unwrap();
    let m = models.to_str().unwrap();
    let out = omgs(&["route", "--run", run, "--role", "hunter", "--models", m]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "model-a");
    let out = omgs(&[
        "route",
        "--run",
        run,
        "--role",
        "hunter",
        "--models",
        m,
        "--refused",
        "model-a",
    ]);
    assert_eq!(out.status.code(), Some(2), "--refused needs --reason");
    let out = omgs(&[
        "route",
        "--run",
        run,
        "--role",
        "hunter",
        "--models",
        m,
        "--refused",
        "model-a",
        "--reason",
        "declined security review",
    ]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "model-b");
    let out = omgs(&["route", "--run", run, "--role", "hunter", "--models", m]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "model-b",
        "refusals persist"
    );
    let out = omgs(&[
        "route",
        "--run",
        run,
        "--role",
        "hunter",
        "--models",
        m,
        "--refused",
        "model-b",
        "--reason",
        "declined",
    ]);
    assert_eq!(out.status.code(), Some(1), "exhausted fallbacks");
    let meta: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("run-metadata.json")).unwrap())
            .unwrap();
    assert_eq!(meta["reroutes"].as_array().unwrap().len(), 2);
    assert_eq!(meta["reroutes"][0]["to"], "model-b");
    assert!(meta["reroutes"][1]["to"].is_null());
    assert!(meta["blockers"][0]
        .as_str()
        .unwrap()
        .contains("every model"));
    let out = omgs(&["route", "--run", run, "--role", "verifier", "--models", m]);
    assert_eq!(out.status.code(), Some(1), "unconfigured role is a blocker");
    std::fs::write(&models, r#"{"roles":{"wizard":["x"]}}"#).unwrap();
    assert_eq!(
        omgs(&["route", "--run", run, "--role", "hunter", "--models", m])
            .status
            .code(),
        Some(2)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn intent_library_is_well_formed() {
    let lib = omgs::intent::library();
    assert!(lib.questions.len() >= 10);
    let mut ids = std::collections::HashSet::new();
    for q in &lib.questions {
        assert!(ids.insert(q.id.as_str()), "duplicate id {}", q.id);
        assert!(
            !q.question.trim().is_empty() && !q.stacks.is_empty() && !q.attack_classes.is_empty()
        );
    }
    assert!(!omgs::intent::list(Some("powershell"), None).is_empty());
    assert!(
        omgs::intent::list(Some("powershell"), Some("feed_to_policy_write"))
            .iter()
            .any(|q| q.id == "feed.lower-security-minimum")
    );
}

fn open_record(key: &str, intent_id: Option<&str>, path: &str) -> Finding {
    let attack_class = format!("class_{key}");
    Finding {
        fingerprint: omgs::fingerprint(&attack_class, "GET /x", "db.x", "tenant"),
        title: format!("Title {key}"),
        verdict: Verdict::NeedsValidation,
        severity: None,
        proof_tier: ProofTier::Traced,
        attack_class,
        entry_point: "GET /x".into(),
        sink: "db.x".into(),
        boundary: "tenant".into(),
        location: Location {
            path: path.into(),
            line: Some(1),
        },
        locations: vec![],
        evidence: String::new(),
        fix_brief: None,
        intent_question: None,
        intent_id: intent_id.map(String::from),
        family: None,
        prerequisites: None,
        hunted_by: Some("red-1".into()),
        verified_by: Some("blue-1".into()),
        candidates: vec![],
        proof_ref: None,
        trace: vec![],
    }
}

#[test]
fn intent_ids_validate_group_and_show_answers() {
    let mut bad = open_record("z", Some("no.such-id"), "a.ts");
    assert!(validate(&FindingsFile {
        findings: vec![bad.clone()]
    })
    .iter()
    .any(|e| e.contains("not in the intent library")));
    bad.intent_id = Some("web.public-resource".into());
    assert!(
        validate(&FindingsFile {
            findings: vec![bad]
        })
        .is_empty(),
        "an id counts as the question"
    );

    let file = FindingsFile {
        findings: vec![
            open_record("a", Some("web.public-resource"), "app/api/a/route.ts"),
            open_record("b", Some("web.public-resource"), "app/api/b/route.ts"),
            open_record("c", Some("web.cross-tenant-read"), "lib/c.ts"),
        ],
    };
    let mut answers = omgs::intent::Answers::default();
    omgs::intent::record(
        &mut answers,
        omgs::intent::Answer {
            id: "web.public-resource".into(),
            answer: "signed-in users only".into(),
            scope: "app/api".into(),
            source: "owner".into(),
            recorded_unix: 1,
        },
    )
    .unwrap();
    assert!(omgs::intent::record(
        &mut answers,
        omgs::intent::Answer {
            id: "nope".into(),
            answer: "x".into(),
            scope: "repo".into(),
            source: "o".into(),
            recorded_unix: 1,
        }
    )
    .is_err());
    let meta = ReportMeta {
        accounting: Default::default(),
        persona: String::new(),
        report_depth: String::new(),
        intent_answers: answers,
        ..ReportMeta::default()
    };
    let html = render_html(&file, &meta);
    assert_eq!(
        html.matches("class=\"intent-item\"").count(),
        2,
        "two groups for three records"
    );
    assert!(html.contains("Q1, about <a href="));
    assert!(html.contains("Recorded answer: signed-in users only (scope app/api, from owner)"));
    assert!(html.contains("2 questions about intended behavior"));
    let md = render_markdown(&file, &meta);
    assert!(
        md.contains("Intent question data (untrusted):\n\n```text\nIs this resource meant to be readable without signing in?\n```")
    );
    assert_eq!(
        md.matches("Recorded answer data (untrusted):").count(),
        2,
        "scope app/api covers a and b only"
    );
}

#[test]
fn answer_scopes_match_path_prefixes_only_at_boundaries() {
    let answers = omgs::intent::Answers {
        target: "/x".into(),
        answers: vec![omgs::intent::Answer {
            id: "web.public-resource".into(),
            answer: "public".into(),
            scope: "src".into(),
            source: "o".into(),
            recorded_unix: 1,
        }],
    };
    assert_eq!(
        omgs::intent::applicable(&answers, "web.public-resource", "src/a.ts").len(),
        1
    );
    assert!(omgs::intent::applicable(&answers, "web.public-resource", "srcx/a.ts").is_empty());
    assert!(omgs::intent::applicable(&answers, "web.cross-tenant-read", "src/a.ts").is_empty());
}

#[test]
fn report_marks_the_run_complete_and_records_metadata() {
    let dir = scratch("complete");
    std::fs::write(dir.join("findings.json"), r#"{"findings": []}"#).unwrap();
    write_private_fixture(
        dir.join("run-metadata.json"),
        r#"{"run_status":"in_progress","models":{"hunter":"model-a"},"reroutes":[{"role":"hunter","from":"model-z","to":"model-a","reason":"declined"}]}"#,
    )
    .unwrap();
    let out = omgs(&[
        "report",
        "--findings",
        dir.join("findings.json").to_str().unwrap(),
        "--out",
        dir.to_str().unwrap(),
        "--hunters",
        "3",
        "--agent-calls",
        "41",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(omgs::runmeta::is_complete(Path::new(&dir)));
    let meta = omgs::runmeta::read(&dir).unwrap();
    assert_eq!(meta["hunters"], 3);
    assert_eq!(meta["agent_calls_used"], 41);
    let md = std::fs::read_to_string(dir.join("REPORT.md")).unwrap();
    assert!(md.contains("Models: hunter: model-a. reroutes: hunter model-z to model-a (declined)"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn audit_refuses_output_reached_through_a_symlink_into_the_target() {
    let dir = scratch("symlink");
    let target = dir.join("target");
    std::fs::create_dir_all(&target).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&target, dir.join("link")).unwrap();
        let out = omgs(&[
            "audit",
            "init",
            "--target",
            target.to_str().unwrap(),
            "--out",
            dir.join("link/run").to_str().unwrap(),
            "--no-sensors",
        ]);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("outside the target tree"));
        assert!(!target.join("run").exists());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn intent_answers_are_keyed_by_the_full_target_path() {
    let home = std::path::Path::new("/h");
    let a = omgs::intent::answers_file(home, std::path::Path::new("/x/acme/shop"));
    let b = omgs::intent::answers_file(home, std::path::Path::new("/y/other/shop"));
    assert_ne!(a, b, "same directory name, different repositories");
    assert_eq!(
        a,
        omgs::intent::answers_file(home, std::path::Path::new("/x/acme/shop"))
    );
}

#[test]
fn batch_file_requires_runs() {
    assert!(omgs::batch::parse_batch(r#"{"run": []}"#).is_err());
    assert!(omgs::batch::parse_batch(r#"[0, []]"#).is_err());
    assert!(omgs::batch::parse_batch(r#"{"runs": [["u", null, null, "failed"]]}"#).is_err());
    assert!(omgs::batch::parse_batch(r#"{"runs": []}"#).is_ok());
}

#[test]
fn concurrent_route_and_status_updates_are_not_lost() {
    let dir = scratch("concurrent");
    write_private_fixture(
        dir.join("run-metadata.json"),
        r#"{"run_status":"in_progress"}"#,
    )
    .unwrap();
    let models = dir.join("models.json");
    std::fs::write(
        &models,
        r#"{"roles":{"hunter":["m1","m2","m3","m4","m5","m6"]}}"#,
    )
    .unwrap();
    let run = dir.to_str().unwrap().to_string();
    let m = models.to_str().unwrap().to_string();
    let mut kids = Vec::new();
    for i in 1..=4 {
        kids.push(
            std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
                .args(["route", "--run", &run, "--role", "hunter", "--models", &m])
                .args(["--refused", &format!("m{i}"), "--reason", "declined"])
                .spawn()
                .unwrap(),
        );
        kids.push(
            std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
                .args(["status", "--run", &run, "--parent", "hunt", "--stage"])
                .args([&format!("red-{i}"), "--state", "active"])
                .spawn()
                .unwrap(),
        );
    }
    for mut k in kids {
        assert!(k.wait().unwrap().success());
    }
    let meta = omgs::runmeta::read(&dir).unwrap();
    assert_eq!(meta["reroutes"].as_array().unwrap().len(), 4);
    let status: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("pipeline-status.json")).unwrap())
            .unwrap();
    assert_eq!(status["stages"][0]["children"].as_array().unwrap().len(), 4);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn status_log_timestamps_are_strings_per_schema() {
    let dir = scratch("ts");
    omgs::status::apply(
        &dir,
        &omgs::status::Update {
            stage: "map",
            label: None,
            parent: None,
            state: "active",
            detail: None,
            counters: &[],
            log: Some("mapping"),
        },
    )
    .unwrap();
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("pipeline-status.json")).unwrap())
            .unwrap();
    let ts = v["log"][0]["ts"].as_str().expect("ts is a string");
    assert_eq!(ts.len(), 8);
    assert_eq!(omgs::runmeta::clock(3_723_000), "01:02:03");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_trickling_client_cannot_hold_the_watch_server() {
    use std::io::Write;
    let dir = scratch("slow");
    write_private_fixture(
        dir.join("run-metadata.json"),
        r#"{"run_status":"in_progress"}"#,
    )
    .unwrap();
    let (listener, port) = omgs::watch::bind().unwrap();
    let d = dir.clone();
    let start = std::time::Instant::now();
    let server = std::thread::spawn(move || {
        omgs::watch::serve(listener, port, &d, std::time::Duration::from_millis(300))
    });
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    let writer = std::thread::spawn(move || {
        for _ in 0..20 {
            if s.write_all(b"G").is_err() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(400));
        }
    });
    server.join().unwrap();
    assert!(
        start.elapsed() < std::time::Duration::from_secs(4),
        "max deadline held despite a slow client: {:?}",
        start.elapsed()
    );
    let _ = writer.join();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn run_directories_are_always_fresh() {
    let dir = scratch("fresh");
    let target = dir.join("target");
    std::fs::create_dir_all(&target).unwrap();
    let out = dir.join("run");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("findings.json"), "keep me").unwrap();
    let res = omgs(&[
        "audit",
        "init",
        "--target",
        target.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--no-sensors",
    ]);
    assert_eq!(res.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&res.stderr).contains("not empty"));
    assert_eq!(
        std::fs::read_to_string(out.join("findings.json")).unwrap(),
        "keep me"
    );
    // A `..` after a missing component cannot smuggle the output into the target.
    let sneaky = dir.join("missing/../target/runs");
    let res = omgs(&[
        "audit",
        "init",
        "--target",
        target.to_str().unwrap(),
        "--out",
        sneaky.to_str().unwrap(),
        "--no-sensors",
    ]);
    assert_eq!(res.status.code(), Some(2));
    assert!(!target.join("runs").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn batch_index_refuses_output_inside_a_target() {
    let dir = scratch("index-target");
    let target = dir.join("target");
    std::fs::create_dir_all(&target).unwrap();
    let batch = serde_json::json!({"runs": [{"url": "https://github.com/a/b",
        "target": target.to_string_lossy(), "run_dir": null, "status": "failed", "error": "x"}]});
    std::fs::write(dir.join("batch.json"), batch.to_string()).unwrap();
    let res = omgs(&[
        "batch",
        "index",
        "--batch",
        dir.join("batch.json").to_str().unwrap(),
        "--out",
        target.join("idx").to_str().unwrap(),
    ]);
    assert_eq!(res.status.code(), Some(2));
    assert!(!target.join("idx").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn answers_files_are_strict_and_bound_to_the_run_target() {
    let dir = scratch("answers");
    write_private_fixture(
        dir.join("intent-answers.json"),
        r#"{"target":"/x","answer":[]}"#,
    )
    .unwrap();
    assert!(omgs::intent::load_answers(&dir.join("intent-answers.json")).is_err());
    assert!(omgs::intent::load_answers(&dir.join("absent.json"))
        .unwrap()
        .answers
        .is_empty());
    write_private_fixture(
        dir.join("intent-answers.json"),
        r#"{"target":"/somewhere/else","answers":[{"id":"web.public-resource","answer":"public","scope":"repo","source":"o","recorded_unix":1}]}"#,
    )
    .unwrap();
    write_private_fixture(
        dir.join("run-metadata.json"),
        r#"{"target":"/this/target"}"#,
    )
    .unwrap();
    let mut f = open_record("a", Some("web.public-resource"), "a.ts");
    f.title = "Shared question".into();
    std::fs::write(
        dir.join("findings.json"),
        serde_json::to_string(&FindingsFile { findings: vec![f] }).unwrap(),
    )
    .unwrap();
    let res = omgs(&[
        "report",
        "--findings",
        dir.join("findings.json").to_str().unwrap(),
        "--out",
        dir.to_str().unwrap(),
    ]);
    assert!(
        res.status.success(),
        "{}",
        String::from_utf8_lossy(&res.stderr)
    );
    assert!(String::from_utf8_lossy(&res.stderr).contains("answers not shown"));
    let md = std::fs::read_to_string(dir.join("REPORT.md")).unwrap();
    assert!(!md.contains("Recorded answer"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn answer_store_writes_enforce_the_limit_without_replacing_valid_answers() {
    let dir = scratch("answer-write-limit");
    let target = dir.join("target");
    let home = dir.join("home");
    std::fs::create_dir_all(&target).unwrap();
    let canonical = std::fs::canonicalize(&target).unwrap();
    let path = omgs::intent::answers_file(&home, &canonical);
    omgs::platform::create_private_tree(path.parent().unwrap()).unwrap();
    let mut answers = omgs::intent::Answers {
        target: canonical.to_string_lossy().to_string(),
        answers: vec![omgs::intent::Answer {
            id: "web.public-resource".into(),
            answer: "public".into(),
            scope: "repo".into(),
            source: "owner".into(),
            recorded_unix: 1,
        }],
    };
    let overhead = serde_json::to_string_pretty(&answers).unwrap().len() + 1;
    answers.answers[0]
        .answer
        .push_str(&"x".repeat((1 << 20) - overhead));
    omgs::intent::save_answers(&path, &answers).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert_eq!(before.len(), 1 << 20);
    let loaded = omgs::intent::load_answers(&path).unwrap();
    assert_eq!(loaded.target, answers.target);
    assert_eq!(loaded.answers, answers.answers);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .args([
            "intent",
            "answer",
            "--target",
            target.to_str().unwrap(),
            "--id",
            "web.public-resource",
            "--answer",
            "private",
            "--source",
            "owner",
            "--scope",
            "src",
        ])
        .env("OMGS_HOME", &home)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("1 MiB byte limit"));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    answers.answers[0].answer.push('x');
    assert!(omgs::intent::save_answers(&path, &answers)
        .unwrap_err()
        .contains("1 MiB byte limit"));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn run_local_answer_snapshots_require_bounded_single_link_files() {
    let dir = scratch("run-answer-reader");
    let path = dir.join("intent-answers.json");
    omgs::platform::write_private_new(&path, b"").unwrap();
    let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.set_len((1 << 20) + 1).unwrap();
    assert!(omgs::intent::load_answers(&path)
        .unwrap_err()
        .contains("byte limit"));
    drop(file);
    std::fs::write(&path, r#"{"target":"/x","answers":[]}"#).unwrap();
    std::fs::hard_link(&path, dir.join("hardlink")).unwrap();
    assert!(omgs::intent::load_answers(&path).is_err());
    std::fs::remove_file(dir.join("hardlink")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        std::fs::rename(&path, dir.join("original")).unwrap();
        std::os::unix::fs::symlink(dir.join("original"), &path).unwrap();
        assert!(omgs::intent::load_answers(&path).is_err());
        std::fs::remove_file(&path).unwrap();
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let start = std::time::Instant::now();
        assert!(omgs::intent::load_answers(&path).is_err());
        assert!(start.elapsed().as_secs() < 1);
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn batch_index_follows_symlinks_before_dotdot() {
    let dir = scratch("alias-dotdot");
    let target = dir.join("target");
    std::fs::create_dir_all(target.join("child")).unwrap();
    std::os::unix::fs::symlink(target.join("child"), dir.join("alias")).unwrap();
    let batch = serde_json::json!({"runs": [{"url": "https://github.com/a/b",
        "target": target.to_string_lossy(), "status": "failed", "error": "x"}]});
    std::fs::write(dir.join("batch.json"), batch.to_string()).unwrap();
    let res = omgs(&[
        "batch",
        "index",
        "--batch",
        dir.join("batch.json").to_str().unwrap(),
        "--out",
        dir.join("alias/../idx").to_str().unwrap(),
    ]);
    assert_eq!(
        res.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&res.stderr)
    );
    assert!(!target.join("idx").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_slow_response_reader_cannot_hold_the_watch_server() {
    let dir = scratch("slow-reader");
    write_private_fixture(
        dir.join("run-metadata.json"),
        r#"{"run_status":"in_progress"}"#,
    )
    .unwrap();
    let big = format!(
        r#"{{"stages":[],"updated_ms":1,"pad":"{}"}}"#,
        "x".repeat(900_000)
    );
    write_private_fixture(dir.join("pipeline-status.json"), big).unwrap();
    let (listener, port) = omgs::watch::bind().unwrap();
    let d = dir.clone();
    let start = std::time::Instant::now();
    let server = std::thread::spawn(move || {
        omgs::watch::serve(listener, port, &d, std::time::Duration::from_millis(300))
    });
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    use std::io::Write;
    write!(
        s,
        "GET /pipeline-status.json HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
    )
    .unwrap();
    // Never read the response.
    server.join().unwrap();
    assert!(
        start.elapsed() < std::time::Duration::from_secs(4),
        "{:?}",
        start.elapsed()
    );
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn concurrent_intent_answers_and_ledger_updates_are_not_lost() {
    let dir = scratch("answers-race");
    let home = dir.join("home");
    let target = dir.join("app");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let mut kids = Vec::new();
    for i in 0..20 {
        kids.push(
            std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
                .env("HOME", &home)
                .env_remove("OMGS_HOME")
                .args(["intent", "answer", "--target", target.to_str().unwrap()])
                .args([
                    "--id",
                    "web.public-resource",
                    "--answer",
                    "public",
                    "--source",
                    "o",
                ])
                .args(["--scope", &format!("src/m{i}")])
                .spawn()
                .unwrap(),
        );
    }
    let ledger = dir.join("coverage-ledger.json");
    write_private_fixture(&ledger, r#"{"units": []}"#).unwrap();
    for i in 0..20 {
        kids.push(
            std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
                .args(["ledger", "add", "--ledger", ledger.to_str().unwrap()])
                .args(["--unit", &format!("u{i}"), "--surface", "."])
                .spawn()
                .unwrap(),
        );
    }
    for mut k in kids {
        assert!(k.wait().unwrap().success());
    }
    let canonical = std::fs::canonicalize(&target).unwrap();
    let path = omgs::intent::answers_file(&home.join(".local/share/omgs"), &canonical);
    let answers = omgs::intent::load_answers(&path).unwrap();
    assert_eq!(answers.answers.len(), 20);
    let l = omgs::shape::ledger(&std::fs::read_to_string(&ledger).unwrap()).unwrap();
    assert_eq!(l.units.len(), 20);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn malformed_routing_history_stops_route() {
    let dir = scratch("route-malformed");
    let models = dir.join("models.json");
    std::fs::write(&models, r#"{"roles":{"hunter":["m1","m2"]}}"#).unwrap();
    for bad in [
        r#"{"reroutes":{}}"#,
        r#"{"reroutes":[{"role":"hunter"}]}"#,
        r#"{"models":[]}"#,
    ] {
        write_private_fixture(dir.join("run-metadata.json"), bad).unwrap();
        let out = omgs(&[
            "route",
            "--run",
            dir.to_str().unwrap(),
            "--role",
            "hunter",
            "--models",
            models.to_str().unwrap(),
            "--refused",
            "m1",
            "--reason",
            "declined",
        ]);
        assert_eq!(out.status.code(), Some(2), "{bad}");
        assert_eq!(
            std::fs::read_to_string(dir.join("run-metadata.json")).unwrap(),
            bad
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn configs_reject_positional_and_duplicate_forms() {
    assert!(omgs::intent::parse_answers(
        r#"["/t",[["web.public-resource","public","repo","owner",1]]]"#
    )
    .is_err());
    assert!(omgs::intent::parse_answers(r#"{"target":"/t","answers":[["a"]]}"#).is_err());
    assert!(omgs::intent::parse_answers(r#"{"target":"/t","target":"/u","answers":[]}"#).is_err());
    assert!(omgs::intent::parse_answers(r#"{"target":"/t","answers":[]}"#).is_ok());
    let dir = scratch("models-shape");
    for bad in [
        r#"[{"hunter":["m1"]}]"#,
        r#"{"roles":{"hunter":[["m1"]]}}"#,
        r#"{"roles":[]}"#,
    ] {
        std::fs::write(dir.join("models.json"), bad).unwrap();
        assert!(
            omgs::route::load_models(&dir.join("models.json")).is_err(),
            "{bad}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn status_keeps_an_unreadable_file() {
    let dir = scratch("status-unreadable");
    write_private_fixture(dir.join("pipeline-status.json"), [0xff, 0xfe, 0x00]).unwrap();
    let r = omgs::status::apply(
        &dir,
        &omgs::status::Update {
            stage: "map",
            label: None,
            parent: None,
            state: "active",
            detail: None,
            counters: &[],
            log: None,
        },
    );
    assert!(r.is_err());
    assert_eq!(
        std::fs::read(dir.join("pipeline-status.json")).unwrap(),
        vec![0xff, 0xfe, 0x00]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn concurrent_inits_cannot_share_one_run_directory() {
    let dir = scratch("claim");
    let out = dir.join("run");
    let mut kids = Vec::new();
    for i in 0..6 {
        let t = dir.join(format!("t{i}"));
        std::fs::create_dir_all(&t).unwrap();
        kids.push(
            std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
                .args(["audit", "init", "--target", t.to_str().unwrap()])
                .args(["--out", out.to_str().unwrap(), "--no-sensors"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
    }
    let ok = kids
        .into_iter()
        .filter(|_| true)
        .map(|mut k| k.wait().unwrap().success())
        .filter(|s| *s)
        .count();
    assert_eq!(ok, 1, "exactly one init claims the directory");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn batch_output_inside_the_targets_area_is_refused_before_cloning() {
    let dir = scratch("batch-inside");
    let home = dir.join("home");
    let targets = home.join(".local/share/omgs/targets/github.com/a/b");
    std::fs::create_dir_all(&targets).unwrap();
    std::fs::write(dir.join("list.txt"), "https://github.com/a/b\n").unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .env("HOME", &home)
        .env_remove("OMGS_HOME")
        .args([
            "batch",
            "init",
            "--list",
            dir.join("list.txt").to_str().unwrap(),
        ])
        .args(["--out", targets.join("idx").to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("outside the reviewed targets"));
    assert!(!targets.join("idx").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn report_shows_only_reviewer_recorded_answers() {
    let dir = scratch("provenance");
    let home = dir.join("home");
    let target = dir.join("app");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let run_cmd = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
            .env("HOME", &home)
            .env_remove("OMGS_HOME")
            .args(args)
            .output()
            .unwrap()
    };
    let t = target.to_str().unwrap();
    assert!(run_cmd(&[
        "intent",
        "answer",
        "--target",
        t,
        "--id",
        "web.public-resource",
        "--answer",
        "signed-in users only",
        "--source",
        "owner",
    ])
    .status
    .success());
    let run = dir.join("run");
    assert!(run_cmd(&[
        "audit",
        "init",
        "--target",
        t,
        "--out",
        run.to_str().unwrap(),
        "--no-sensors"
    ])
    .status
    .success());
    let f = open_record("a", Some("web.public-resource"), "app/x.ts");
    std::fs::write(
        run.join("findings.json"),
        serde_json::to_string(&FindingsFile { findings: vec![f] }).unwrap(),
    )
    .unwrap();
    // A forged extra answer in the run snapshot is not in the reviewer store.
    let mut snap: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(run.join("intent-answers.json")).unwrap())
            .unwrap();
    snap["answers"].as_array_mut().unwrap().push(serde_json::json!({
        "id": "web.public-resource", "answer": "FORGED", "scope": "app", "source": "x", "recorded_unix": 1
    }));
    write_private_fixture(run.join("intent-answers.json"), snap.to_string()).unwrap();
    let out = run_cmd(&[
        "report",
        "--findings",
        run.join("findings.json").to_str().unwrap(),
        "--out",
        run.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let md = std::fs::read_to_string(run.join("REPORT.md")).unwrap();
    assert!(md.contains("Recorded answer data (untrusted):\n\n```text\nsigned-in users only"));
    assert!(!md.contains("FORGED"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn index_writes_replace_links_instead_of_following_them() {
    let dir = scratch("index-links");
    let target = dir.join("target");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("sentinel.html"), "original").unwrap();
    std::fs::write(target.join("hard.md"), "original").unwrap();
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    std::os::unix::fs::symlink(target.join("sentinel.html"), out.join("INDEX.html")).unwrap();
    std::fs::hard_link(target.join("hard.md"), out.join("INDEX.md")).unwrap();
    std::fs::write(out.join("batch.json"), r#"{"runs": []}"#).unwrap();
    let res = omgs(&[
        "batch",
        "index",
        "--batch",
        out.join("batch.json").to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(
        res.status.success(),
        "{}",
        String::from_utf8_lossy(&res.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(target.join("sentinel.html")).unwrap(),
        "original"
    );
    assert_eq!(
        std::fs::read_to_string(target.join("hard.md")).unwrap(),
        "original"
    );
    assert!(!std::fs::symlink_metadata(out.join("INDEX.html"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(std::fs::read_to_string(out.join("INDEX.md"))
        .unwrap()
        .contains("OMGS batch index"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn duplicate_keys_in_run_metadata_and_batch_files_are_errors() {
    let dir = scratch("dup-meta");
    let models = dir.join("models.json");
    std::fs::write(&models, r#"{"roles":{"hunter":["m1","m2"]}}"#).unwrap();
    let bad = r#"{"reroutes":[{"role":"hunter","from":"m1"}],"reroutes":[]}"#;
    write_private_fixture(dir.join("run-metadata.json"), bad).unwrap();
    let out = omgs(&[
        "route",
        "--run",
        dir.to_str().unwrap(),
        "--role",
        "hunter",
        "--models",
        models.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        std::fs::read_to_string(dir.join("run-metadata.json")).unwrap(),
        bad
    );
    assert!(
        omgs::batch::parse_batch(r#"{"runs":[{"url":"u","status":"failed"}],"runs":[]}"#).is_err()
    );
    write_private_fixture(
        dir.join("pipeline-status.json"),
        r#"{"stages":[],"stages":[]}"#,
    )
    .unwrap();
    assert!(omgs::status::apply(
        &dir,
        &omgs::status::Update {
            stage: "map",
            label: None,
            parent: None,
            state: "active",
            detail: None,
            counters: &[],
            log: None,
        }
    )
    .is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn watch_never_serves_a_linked_or_special_status_file() {
    let dir = scratch("watch-links");
    std::fs::write(dir.join("findings.json"), "SECRET FINDING").unwrap();
    std::os::unix::fs::symlink(dir.join("findings.json"), dir.join("pipeline-status.json"))
        .unwrap();
    let req = "GET /pipeline-status.json HTTP/1.1\r\nHost: 127.0.0.1:4000\r\n\r\n";
    let r = omgs::watch::respond(req, 4000, &dir);
    assert!(!String::from_utf8_lossy(&r.body).contains("SECRET"));
    std::fs::remove_file(dir.join("pipeline-status.json")).unwrap();
    std::fs::hard_link(dir.join("findings.json"), dir.join("pipeline-status.json")).unwrap();
    let r = omgs::watch::respond(req, 4000, &dir);
    assert!(
        !String::from_utf8_lossy(&r.body).contains("SECRET"),
        "hardlink"
    );
    std::fs::remove_file(dir.join("pipeline-status.json")).unwrap();
    let fifo = std::ffi::CString::new(dir.join("pipeline-status.json").to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let start = std::time::Instant::now();
    let r = omgs::watch::respond(req, 4000, &dir);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(1),
        "FIFO must not block"
    );
    assert_eq!(r.status, 200);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn batch_index_fails_on_malformed_run_metadata() {
    let index = scratch("index-malformed");
    let run = index.join("r");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::write(run.join("findings.json"), r#"{"findings": []}"#).unwrap();
    write_private_fixture(
        run.join("run-metadata.json"),
        r#"{"blockers":["x"],"blockers":[]}"#,
    )
    .unwrap();
    let r = BatchRun {
        url: "https://github.com/a/b".into(),
        run_dir: Some(run.to_string_lossy().to_string()),
        status: "initialized".into(),
        ..Default::default()
    };
    assert!(summarize(&r, &index).is_err());
    let _ = std::fs::remove_dir_all(&index);
}

#[test]
fn batch_index_rejects_wrong_metadata_types() {
    let index = scratch("index-types");
    let run = index.join("r");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::write(run.join("findings.json"), r#"{"findings": []}"#).unwrap();
    let r = BatchRun {
        url: "https://github.com/a/b".into(),
        run_dir: Some(run.to_string_lossy().to_string()),
        status: "initialized".into(),
        ..Default::default()
    };
    for bad in [
        r#"{"blockers":"route exhausted"}"#,
        r#"{"reroutes":{}}"#,
        r#"{"blockers":[7]}"#,
        r#"{"agent_calls_used":"12"}"#,
        r#"{"run_status":1}"#,
    ] {
        write_private_fixture(run.join("run-metadata.json"), bad).unwrap();
        assert!(summarize(&r, &index).is_err(), "{bad}");
    }
    let _ = std::fs::remove_dir_all(&index);
}

#[test]
fn batch_init_needs_an_empty_output_directory() {
    let dir = scratch("batch-nonempty");
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let out = dir.join("out");
    std::fs::create_dir_all(out.join("github.com")).unwrap();
    std::fs::write(dir.join("list.txt"), "https://github.com/a/b\n").unwrap();
    let res = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .env("HOME", &home)
        .env_remove("OMGS_HOME")
        .args([
            "batch",
            "init",
            "--list",
            dir.join("list.txt").to_str().unwrap(),
        ])
        .args(["--out", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(res.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&res.stderr).contains("not empty"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn similar_paths_never_share_an_answer_store() {
    let home = std::path::Path::new("/h");
    let a = omgs::intent::answers_file(home, std::path::Path::new("/x/shop"));
    let b = omgs::intent::answers_file(home, std::path::Path::new("/x/shop "));
    let c = omgs::intent::answers_file(home, std::path::Path::new("/x/Shop"));
    assert_ne!(a, b);
    assert_ne!(a, c);
}

#[test]
fn report_rejects_malformed_routing_metadata() {
    let dir = scratch("report-routing");
    std::fs::write(dir.join("findings.json"), r#"{"findings": []}"#).unwrap();
    for bad in [
        r#"{"reroutes": false}"#,
        r#"{"models": {"hunter": 42}}"#,
        r#"{"reroutes": [{"role": "hunter", "from": 3}]}"#,
    ] {
        write_private_fixture(dir.join("run-metadata.json"), bad).unwrap();
        let out = omgs(&[
            "report",
            "--findings",
            dir.join("findings.json").to_str().unwrap(),
            "--out",
            dir.join("out").to_str().unwrap(),
        ]);
        assert_eq!(out.status.code(), Some(2), "{bad}");
        assert_eq!(
            std::fs::read_to_string(dir.join("run-metadata.json")).unwrap(),
            bad
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn status_refuses_a_malformed_document_without_rewriting_it() {
    let dir = scratch("status-malformed");
    for bad in [
        r#"{"stages":[17]}"#,
        r#"{"stages":[{"id":"a","label":"A","status":"weird"}]}"#,
        r#"{"counters":{"confirmed":"oops"}}"#,
        r#"{"log":[false]}"#,
        r#"{"updated_ms":"now"}"#,
    ] {
        write_private_fixture(dir.join("pipeline-status.json"), bad).unwrap();
        let r = omgs::status::apply(
            &dir,
            &omgs::status::Update {
                stage: "map",
                label: None,
                parent: None,
                state: "active",
                detail: None,
                counters: &[],
                log: None,
            },
        );
        assert!(r.is_err(), "{bad}");
        assert_eq!(
            std::fs::read_to_string(dir.join("pipeline-status.json")).unwrap(),
            bad
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn concurrent_reviews_of_one_url_never_delete_each_others_clone() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("clone-race");
    let home = dir.join("home");
    let bin = dir.join("bin");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    // A stub git: clone sleeps, then succeeds for the first caller and fails
    // for any later one, as a real clone into an existing path would.
    let stub = format!(
        "#!/bin/sh\nfor a in \"$@\"; do last=\"$a\"; done\ncase \" $* \" in\n  *' clone '*) sleep 1; if mkdir \"{m}\" 2>/dev/null; then mkdir -p \"$last\"; exit 0; else exit 1; fi ;;\n  *' get-url '*) echo https://github.com/a/b ;;\n  *) exit 1 ;;\nesac\n",
        m = dir.join("cloned-once").display()
    );
    std::fs::write(bin.join("git"), stub).unwrap();
    std::fs::set_permissions(bin.join("git"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let spawn = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
            .env("HOME", &home)
            .env_remove("OMGS_HOME")
            .env("PATH", &path)
            .args([
                "review",
                "--repo-url",
                "https://github.com/a/b",
                "--no-sensors",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap()
    };
    let (mut a, mut b) = (spawn(), spawn());
    let (ra, rb) = (a.wait().unwrap(), b.wait().unwrap());
    let dest = home.join(".local/share/omgs/targets/github.com/a/b");
    assert!(dest.is_dir(), "the clone survives");
    assert!(
        ra.success() && rb.success(),
        "the second review reuses the first clone"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn route_rejects_wrong_value_types_without_writing() {
    let dir = scratch("route-values");
    let models = dir.join("models.json");
    std::fs::write(&models, r#"{"roles":{"hunter":["m1","m2"]}}"#).unwrap();
    for bad in [
        r#"{"models":{"verifier":42}}"#,
        r#"{"blockers":[7]}"#,
        r#"{"reroutes":[{"role":"hunter","from":"m0","to":5}]}"#,
        r#"{"reroutes":[{"role":"hunter","from":"m0","reason":false}]}"#,
    ] {
        write_private_fixture(dir.join("run-metadata.json"), bad).unwrap();
        let out = omgs(&[
            "route",
            "--run",
            dir.to_str().unwrap(),
            "--role",
            "hunter",
            "--models",
            models.to_str().unwrap(),
        ]);
        assert_eq!(out.status.code(), Some(2), "{bad}");
        assert_eq!(
            std::fs::read_to_string(dir.join("run-metadata.json")).unwrap(),
            bad
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn status_accepts_schema_minimal_log_entries() {
    let dir = scratch("status-minimal-log");
    write_private_fixture(
        dir.join("pipeline-status.json"),
        r#"{"stages":[],"updated_ms":1,"log":[{"m":"mapping started"}]}"#,
    )
    .unwrap();
    omgs::status::apply(
        &dir,
        &omgs::status::Update {
            stage: "map",
            label: None,
            parent: None,
            state: "active",
            detail: None,
            counters: &[],
            log: None,
        },
    )
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn answer_stores_inside_the_target_are_never_trusted() {
    let forge = |store_dir: &std::path::Path, target: &std::path::Path| {
        std::fs::create_dir_all(target).unwrap();
        let canonical = std::fs::canonicalize(target).unwrap();
        let answers = serde_json::json!({
            "target": canonical.to_string_lossy(),
            "answers": [{"id": "web.public-resource", "answer": "FORGED_BY_TARGET",
                         "scope": "repo", "source": "target", "recorded_unix": 1}]
        });
        std::fs::create_dir_all(store_dir).unwrap();
        let name = omgs::intent::answers_file(std::path::Path::new("/h"), &canonical)
            .file_name()
            .unwrap()
            .to_owned();
        std::fs::write(store_dir.join(name), answers.to_string()).unwrap();
    };
    // Case 1: HOME inside the target.
    let dir = scratch("store-in-target");
    let target = dir.join("app");
    let home = target.join("home");
    forge(&home.join(".local/share/omgs/intent"), &target);
    let run = dir.join("run");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .env("HOME", &home)
        .env_remove("OMGS_HOME")
        .args(["audit", "init", "--target", target.to_str().unwrap()])
        .args(["--out", run.to_str().unwrap(), "--no-sensors"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!run.join("intent-answers.json").exists());

    // Case 2: the store directory links into the target.
    let dir2 = scratch("store-linked");
    let target2 = dir2.join("app");
    let home2 = dir2.join("home");
    forge(&target2.join("planted"), &target2);
    std::fs::create_dir_all(home2.join(".local/share/omgs")).unwrap();
    std::os::unix::fs::symlink(
        target2.join("planted"),
        home2.join(".local/share/omgs/intent"),
    )
    .unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .env("HOME", &home2)
        .env_remove("OMGS_HOME")
        .args(["intent", "answer", "--target", target2.to_str().unwrap()])
        .args([
            "--id",
            "web.public-resource",
            "--answer",
            "public",
            "--source",
            "o",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "writing through the link is refused"
    );
    let run2 = dir2.join("run");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .env("HOME", &home2)
        .env_remove("OMGS_HOME")
        .args(["audit", "init", "--target", target2.to_str().unwrap()])
        .args(["--out", run2.to_str().unwrap(), "--no-sensors"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(!run2.join("intent-answers.json").exists());
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

#[cfg(unix)]
#[test]
fn a_hardlinked_answer_store_is_never_trusted() {
    let dir = scratch("store-hardlink");
    let home = dir.join("home");
    let target = dir.join("app");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&target).unwrap();
    let run_omgs = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
            .env("HOME", &home)
            .env_remove("OMGS_HOME")
            .args(args)
            .output()
            .unwrap()
    };
    let t = target.to_str().unwrap();
    assert!(run_omgs(&[
        "intent",
        "answer",
        "--target",
        t,
        "--id",
        "web.public-resource",
        "--answer",
        "public",
        "--source",
        "owner",
    ])
    .status
    .success());
    let canonical = std::fs::canonicalize(&target).unwrap();
    let store = omgs::intent::answers_file(&home.join(".local/share/omgs"), &canonical);
    std::fs::hard_link(&store, target.join("alias.json")).unwrap();
    let forged = std::fs::read_to_string(&store)
        .unwrap()
        .replace("\"public\"", "\"FORGED_BY_TARGET\"");
    std::fs::write(target.join("alias.json"), forged).unwrap();
    let run = dir.join("run");
    let out = run_omgs(&[
        "audit",
        "init",
        "--target",
        t,
        "--out",
        run.to_str().unwrap(),
        "--no-sensors",
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!run.join("intent-answers.json").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_rejected_option_leaves_no_claimed_run_directory() {
    let dir = scratch("no-claim-on-error");
    let target = dir.join("app");
    std::fs::create_dir_all(&target).unwrap();
    let out = dir.join("run");
    for bad in [["--mode", "Gate"], ["--budget", "many"]] {
        let res = omgs(&[
            "audit",
            "init",
            "--target",
            target.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--no-sensors",
            bad[0],
            bad[1],
        ]);
        assert_eq!(res.status.code(), Some(2), "{bad:?}");
        assert!(!out.exists(), "nothing claimed for {bad:?}");
    }
    let ok = omgs(&[
        "audit",
        "init",
        "--target",
        target.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--no-sensors",
        "--mode",
        "gate",
    ]);
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn a_reused_clone_matches_by_repository_identity_not_spelling() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("origin-spelling");
    let home = dir.join("home");
    let bin = dir.join("bin");
    std::fs::create_dir_all(home.join(".local/share/omgs/targets/github.com/acme/shop")).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(
        bin.join("git"),
        "#!/bin/sh\ncase \" $* \" in\n  *' get-url '*) echo https://GitHub.com/acme/shop.git ;;\n  *) exit 1 ;;\nesac\n",
    )
    .unwrap();
    std::fs::set_permissions(bin.join("git"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let res = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .env("HOME", &home)
        .env_remove("OMGS_HOME")
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .args([
            "review",
            "--repo-url",
            "https://github.com/acme/shop/",
            "--no-sensors",
        ])
        .output()
        .unwrap();
    assert!(
        res.status.success(),
        "{}",
        String::from_utf8_lossy(&res.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn markdown_shows_intent_answers_for_every_verdict() {
    let mut confirmed = open_record("c", Some("web.public-resource"), "app/c.ts");
    confirmed.verdict = Verdict::Confirmed;
    confirmed.severity = Some(omgs::model::Severity::High);
    confirmed.proof_tier = ProofTier::TestProven;
    confirmed.evidence = "Trace: x. Sandbox evidence: y.".into();
    let mut rejected = open_record("r", Some("web.public-resource"), "app/r.ts");
    rejected.verdict = Verdict::Rejected;
    rejected.evidence = "Counterevidence: guarded.".into();
    let file = FindingsFile {
        findings: vec![confirmed, rejected],
    };
    let meta = ReportMeta {
        accounting: Default::default(),
        persona: String::new(),
        report_depth: String::new(),
        intent_answers: omgs::intent::Answers {
            target: "/x".into(),
            answers: vec![omgs::intent::Answer {
                id: "web.public-resource".into(),
                answer: "signed-in users only".into(),
                scope: "repo".into(),
                source: "owner".into(),
                recorded_unix: 1,
            }],
        },
        ..ReportMeta::default()
    };
    let md = render_markdown(&file, &meta);
    assert_eq!(
        md.matches("Recorded answer data (untrusted):\n\n```text\nsigned-in users only")
            .count(),
        2,
        "{md}"
    );
    assert_eq!(md.matches("Intent question data (untrusted):").count(), 2);
}

#[test]
fn cli_errors_put_the_error_before_a_short_usage_hint() {
    for args in [vec![], vec!["prove", "--unknown"], vec!["prove"]] {
        let out = omgs(&args);
        assert_eq!(out.status.code(), Some(2));
        let error = String::from_utf8_lossy(&out.stderr);
        let lines: Vec<_> = error.lines().collect();
        assert_eq!(lines.len(), 2, "{error}");
        assert!(lines[0].starts_with("error: "), "{error}");
        assert_eq!(lines[1], "run omgs --help for usage");
    }
}

#[test]
fn audit_init_accepts_hunter_and_verifier_metadata() {
    let d = scratch("audit-identities");
    let target = d.join("target");
    std::fs::create_dir_all(&target).unwrap();
    let run = d.join("run");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .env("OMGS_HOME", d.join("home"))
        .args([
            "audit",
            "init",
            "--target",
            target.to_str().unwrap(),
            "--out",
            run.to_str().unwrap(),
            "--hunter",
            "hunter-1",
            "--verifier",
            "verifier-1",
            "--no-sensors",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta = omgs::runmeta::read(&run).unwrap();
    assert_eq!(meta["hunter"], "hunter-1");
    assert_eq!(meta["verifier"], "verifier-1");
    std::fs::remove_dir_all(d).unwrap();
}

#[cfg(any(unix, windows))]
#[test]
fn default_storage_refusal_names_path_permissions_and_migration() {
    let dir = scratch("default-storage-refusal");
    let target = dir.join("app");
    std::fs::create_dir(&target).unwrap();
    let store = dir.join("store");
    omgs::platform::create_private_dir(&store).unwrap();
    let base = store.join("app");
    omgs::platform::create_private_dir(&base).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    #[cfg(windows)]
    {
        let result = std::process::Command::new("icacls")
            .arg(&base)
            .args(["/grant", "*S-1-5-32-545:(OI)(CI)(W)"])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_omgs"))
        .env("OMGS_HOME", &store)
        .args([
            "audit",
            "init",
            "--target",
            target.to_str().unwrap(),
            "--no-sensors",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains(base.to_str().unwrap()), "{error}");
    assert!(error.contains("README.md#storage-migration"), "{error}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        assert!(
            error.contains(&format!(
                "owner uid {}",
                std::fs::metadata(&base).unwrap().uid()
            )),
            "{error}"
        );
        assert!(error.contains("mode 0755"), "{error}");
        assert_eq!(
            std::fs::metadata(&base).unwrap().permissions().mode() & 0o7777,
            0o755
        );
    }
    #[cfg(windows)]
    {
        assert!(error.contains("owner and DACL:"), "{error}");
        assert!(omgs::platform::check_private_dir(&base).is_err());
    }
    std::fs::remove_dir_all(dir).unwrap();
}
