use omgs::batch::{
    parse_repo_url, read_list, render_index_html, render_index_markdown, summarize, BatchRun,
    RunSummary,
};
use omgs::model::{validate, Finding, FindingsFile, Location, ProofTier, Verdict};
use omgs::report::{render_html, render_markdown, ReportMeta};
use std::path::Path;

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("omgs-orch-{}-{name}", std::process::id()));
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
        reroutes: 1,
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
    std::fs::create_dir_all(&run).unwrap();
    std::fs::write(run.join("findings.json"), r#"{"findings": []}"#).unwrap();
    std::fs::write(
        run.join("run-metadata.json"),
        r#"{"run_status":"complete","agent_calls_used":12,"reroutes":[{"role":"hunter"}],"blockers":["route exhausted"]}"#,
    )
    .unwrap();
    std::fs::write(
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
    );
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
    std::fs::write(
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
    std::fs::write(
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
    std::fs::write(
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
    std::fs::write(
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
        md.contains("Intent question: Is this resource meant to be readable without signing in?")
    );
    assert_eq!(
        md.matches("Recorded answer:").count(),
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
    std::fs::write(
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
    assert!(serde_json::from_str::<omgs::batch::BatchFile>(r#"{"run": []}"#).is_err());
    assert!(serde_json::from_str::<omgs::batch::BatchFile>(r#"{"runs": []}"#).is_ok());
}
