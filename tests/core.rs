use omgs::model::{validate, Finding, FindingsFile, Location, ProofTier, Severity, Verdict};
use omgs::report::{render_html, ReportMeta};

fn finding(verdict: Verdict, tier: ProofTier, severity: Option<Severity>) -> Finding {
    Finding {
        fingerprint: omgs::fingerprint(
            "idor_tenant_isolation",
            "GET /api/orders/:id",
            "db.orders.find",
            "customer",
        ),
        title: "Order readable across accounts".into(),
        verdict,
        severity,
        proof_tier: tier,
        attack_class: "idor_tenant_isolation".into(),
        entry_point: "GET /api/orders/:id".into(),
        sink: "db.orders.find".into(),
        boundary: "customer".into(),
        location: Location {
            path: "app/api/orders/[id]/route.ts".into(),
            line: Some(12),
        },
        locations: vec![],
        evidence: "dummy tenant B order returned to tenant A".into(),
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

#[test]
fn fingerprint_is_stable_and_semantic() {
    let a = omgs::fingerprint("IDOR_Tenant_Isolation", "GET /x", "db.find", "Customer");
    let b = omgs::fingerprint("idor_tenant_isolation", "GET /x", "db.find", "customer");
    assert_eq!(a, b);
    assert!(a.starts_with("omgs-"));
}

#[test]
fn traced_cannot_be_confirmed() {
    let file = FindingsFile {
        findings: vec![finding(
            Verdict::Confirmed,
            ProofTier::Traced,
            Some(Severity::High),
        )],
    };
    assert!(validate(&file)
        .iter()
        .any(|e| e.contains("traced evidence alone")));
}

#[test]
fn test_proven_confirmed_is_valid() {
    let file = FindingsFile {
        findings: vec![finding(
            Verdict::Confirmed,
            ProofTier::TestProven,
            Some(Severity::High),
        )],
    };
    assert!(validate(&file).is_empty(), "{:?}", validate(&file));
}

#[test]
fn needs_validation_rejects_severity() {
    let file = FindingsFile {
        findings: vec![finding(
            Verdict::NeedsValidation,
            ProofTier::Traced,
            Some(Severity::Low),
        )],
    };
    assert!(validate(&file)
        .iter()
        .any(|e| e.contains("must not carry severity")));
}

#[test]
fn html_report_escapes_target_content() {
    let mut f = finding(
        Verdict::Confirmed,
        ProofTier::TestProven,
        Some(Severity::High),
    );
    f.title = "<script>alert(1)</script>".into();
    f.fingerprint = omgs::fingerprint(&f.attack_class, &f.entry_point, &f.sink, &f.boundary);
    let file = FindingsFile { findings: vec![f] };
    let html = render_html(
        &file,
        &ReportMeta {
            repo: "x".into(),
            source_ref: "abc".into(),
            mode: "gate".into(),
            sandbox: "MXC".into(),
            coverage: vec!["covered: stack:powershell".into()],
            sensors: Some("gitleaks run, 0 hit(s), 0 vendored".into()),
            hunters: None,
            verifier: None,
            agent_calls: None,
            critic: None,
            models: vec![],
            reroutes: vec![],
            artifact_base: String::new(),
            timeline: Vec::new(),
            accounting: Default::default(),
            persona: String::new(),
            report_depth: String::new(),
            intent_answers: Default::default(),
        },
    );
    assert!(!html.contains("<script>alert"));
    assert!(html.contains("&lt;script&gt;"));
    assert!(
        !html.contains("http://") && !html.contains("https://"),
        "one pager must make no external requests"
    );
    assert!(html.contains("covered: stack:powershell"));
}

#[test]
fn mxc_config_matches_verified_contract() {
    use omgs::sandbox::{declared_controls, mxc_config, tier2_unavailable, ConfigInput, Tier};
    use std::path::{Path, PathBuf};
    let input = |os: &'static str| ConfigInput {
        contract: None,
        os,
        containment: "process",
        command: "cmd.exe /d /s /c echo hi",
        timeout_ms: 30000,
        workspace: Path::new("/work/run/workspace"),
        scratch: Path::new("/work/run/scratch"),
        allowed_marker: Some(Path::new("/work/run/markers/allowed")),
        readonly: vec![PathBuf::from("/opt/homebrew")],
        denied: vec![PathBuf::from("/home/u/.cargo/credentials.toml")],
        rust: None,
        list_parents: true,
    };
    let v = mxc_config(&input("windows"));
    assert_eq!(v["version"], "1.0.0");
    assert_eq!(v["containment"], "process");
    assert_eq!(v["process"]["cwd"], "/work/run/workspace");
    assert_eq!(v["network"]["egress"]["default"], "deny");
    assert_eq!(v["network"]["ingress"]["default"], "deny");
    assert_eq!(v["network"]["ingress"]["hostLoopback"], "deny");
    assert_eq!(
        v["filesystem"]["readwritePaths"],
        serde_json::json!(["/work/run/workspace", "/work/run/scratch"])
    );
    assert_eq!(
        v["filesystem"]["readonlyPaths"],
        serde_json::json!(["/opt/homebrew", "/work/run/markers/allowed"])
    );
    assert_eq!(
        v["filesystem"]["deniedPaths"][0],
        "/home/u/.cargo/credentials.toml"
    );
    assert_eq!(v["processContainer"]["ui"]["isolation"], "desktop");
    let env = v["process"]["env"].as_array().expect("env");
    assert!(env.iter().any(|e| e == "USERPROFILE=/work/run/scratch"));
    assert!(env.iter().any(|e| e == "LOCALAPPDATA=/work/run/scratch"));

    let mac = mxc_config(&input("macos"));
    assert_eq!(
        mac["seatbelt"]["extraMachLookups"][0],
        "com.apple.system.opendirectoryd.libinfo"
    );
    assert!(mac["process"]["env"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e == "HOME=/work/run/scratch"));

    // Tier 2 needs a loopback private to the sandbox, which only Linux has.
    assert!(tier2_unavailable("linux").is_none());
    for os in ["macos", "windows"] {
        assert!(tier2_unavailable(os).unwrap().contains("only on Linux"));
    }
    let linux = mxc_config(&input("linux"));
    assert_eq!(linux["network"]["ingress"]["hostLoopback"], "deny");
    let (enforced, _) = declared_controls("linux", Tier::LocalApp);
    assert!(enforced.iter().any(|e| e.contains("loopback private")));
    let (enforced, gaps) = declared_controls("linux", Tier::Test);
    assert!(gaps.iter().any(|g| g.contains("no total disk quota")));
    assert!(gaps.iter().any(|g| g.contains("readable toolchain roots")));
    assert!(enforced.iter().any(|e| e.contains("egress denied")));
}

#[test]
fn stack_detection_matches_field_ecosystems() {
    let ps = omgs::detect_stacks(&["Scripts/Update-Thing.ps1".into(), "README.md".into()]);
    assert!(ps.contains(&"powershell"));
    let swift = omgs::detect_stacks(&["Package.swift".into(), "Sources/main.swift".into()]);
    assert!(swift.contains(&"swift"));
    let aspnet = omgs::detect_stacks(&["App.csproj".into(), "Views/Home/Index.cshtml".into()]);
    assert!(aspnet.contains(&"aspnet"));
    let statik = omgs::detect_stacks(&["index.html".into(), "script.js".into()]);
    assert!(statik.contains(&"static-web"));
    let next = omgs::detect_stacks(&["app/api/x/route.ts".into(), "package.json".into()]);
    assert!(next.contains(&"nextjs-app-router"));
}

#[test]
fn vendored_roots_require_specific_evidence() {
    assert!(omgs::is_vendored_path("vendor/package/main.js"));
    assert!(omgs::is_vendored_path("node_modules/package/main.js"));
    assert!(!omgs::is_vendored_path(
        "Web/MonacoEditor/min/vs/editor/editor.main.js"
    ));
    assert!(!omgs::is_vendored_path("lib/foo.min.js"));
    assert!(!omgs::is_vendored_path("bin/tool.dll"));
    assert!(!omgs::is_vendored_path("Scripts/Update-Thing.ps1"));
    assert!(!omgs::is_vendored_path("app/api/orders/route.ts"));
}

#[test]
fn markdown_report_shows_rejected_and_pending_evidence() {
    use omgs::report::render_markdown;
    let mut rejected = finding(Verdict::Rejected, ProofTier::Traced, None);
    rejected.title = "Rejected lead".into();
    rejected.evidence = "counterevidence: values are escaped".into();
    let mut pending = finding(Verdict::NeedsValidation, ProofTier::Traced, None);
    pending.title = "Pending lead".into();
    pending.attack_class = "other_class".into();
    pending.fingerprint = omgs::fingerprint(
        &pending.attack_class,
        &pending.entry_point,
        &pending.sink,
        &pending.boundary,
    );
    let file = FindingsFile {
        findings: vec![rejected, pending],
    };
    let md = render_markdown(
        &file,
        &ReportMeta {
            repo: "x".into(),
            source_ref: "abc".into(),
            mode: "advisory".into(),
            sandbox: "none".into(),
            coverage: vec!["planned: stack:swift".into()],
            sensors: None,
            hunters: None,
            verifier: None,
            agent_calls: None,
            critic: None,
            models: vec![],
            reroutes: vec![],
            artifact_base: String::new(),
            timeline: Vec::new(),
            accounting: Default::default(),
            persona: String::new(),
            report_depth: String::new(),
            intent_answers: Default::default(),
        },
    );
    assert!(md.contains("Rejected after verification"));
    assert!(md.contains("counterevidence: values are escaped"));
    assert!(md.contains("planned: stack:swift"));
}

fn meta() -> ReportMeta {
    ReportMeta {
        repo: "acme/shop".into(),
        source_ref: "abc123".into(),
        mode: "advisory".into(),
        sandbox: "Seatbelt".into(),
        coverage: vec!["covered: stack:nextjs-app-router".into()],
        sensors: Some("gitleaks run, 0 hit(s), 0 vendored".into()),
        hunters: Some(2),
        verifier: Some("blue-1".into()),
        agent_calls: Some(37),
        critic: None,
        models: vec![],
        reroutes: vec![],
        artifact_base: String::new(),
        timeline: Vec::new(),
        accounting: Default::default(),
        persona: String::new(),
        report_depth: String::new(),
        intent_answers: Default::default(),
    }
}

/// A distinct, valid record of the given verdict, keyed by `key`.
fn keyed(key: &str, verdict: Verdict) -> Finding {
    let tier = if verdict == Verdict::Confirmed {
        ProofTier::TestProven
    } else {
        ProofTier::Traced
    };
    let severity = (verdict == Verdict::Confirmed).then_some(Severity::High);
    let mut f = finding(verdict, tier, severity);
    f.attack_class = format!("class_{key}");
    f.title = format!("Title {key}");
    f.evidence = format!("Trace: evidence body {key}. Missing fact: missing {key}.");
    f.fingerprint = omgs::fingerprint(&f.attack_class, &f.entry_point, &f.sink, &f.boundary);
    f
}

fn section<'a>(html: &'a str, id: &str, next: &str) -> &'a str {
    let start = html.find(&format!("id=\"{id}\"")).expect("section start");
    let end = html[start..]
        .find(&format!("id=\"{next}\""))
        .map_or(html.len(), |e| start + e);
    &html[start..end]
}

#[test]
fn html_intent_section_lists_only_records_with_intent_question() {
    let mut asked = keyed("asked", Verdict::NeedsValidation);
    asked.intent_question = Some("Is export meant for every member?".into());
    let quiet = keyed("quiet", Verdict::NeedsValidation);
    let mut blank = keyed("blank", Verdict::NeedsValidation);
    blank.intent_question = Some("   ".into());
    let file = FindingsFile {
        findings: vec![quiet, asked, blank, keyed("ruled", Verdict::Rejected)],
    };
    assert!(validate(&file).is_empty(), "{:?}", validate(&file));
    let html = render_html(&file, &meta());
    let intent = section(&html, "intent", "pending");
    assert_eq!(intent.matches("class=\"intent-item\"").count(), 1);
    assert!(intent.contains("Is export meant for every member?"));
    assert!(intent.contains("Title asked"));
    assert!(!intent.contains("Title quiet") && !intent.contains("Title blank"));
    // The intent section asks the question; it never repeats evidence.
    assert!(!intent.contains("evidence body"));
    assert!(!intent.contains("missing asked"));
    // The full record, with its missing fact, still lives under Needs validation.
    let pending = section(&html, "pending", "rejected");
    assert!(pending.contains("evidence body asked"));
    assert!(pending.contains("class=\"callout c-missing\""));
}

#[test]
fn evidence_splits_on_known_lead_ins() {
    use omgs::report::split_evidence;
    let text = "Opening context. Trace: a calls b (x.swift:1-2). Then c. Sandbox evidence (omgs prove, Seatbelt): ran it. Observed output: ok=false. Missing fact: root behavior. Manual plan: use a spare Mac. Proposed fix: Invariant: stay inside. Acceptance check: test passes. Evaluator adjudication (independent pass): upheld. Scope note from evaluation: narrow.";
    let parts = split_evidence(text);
    let labels: Vec<Option<&str>> = parts.iter().map(|p| p.label.as_deref()).collect();
    assert_eq!(
        labels,
        vec![
            None,
            Some("Trace"),
            Some("Sandbox evidence (omgs prove, Seatbelt)"),
            Some("Missing fact"),
            Some("Manual plan"),
            Some("Proposed fix"),
            Some("Evaluator adjudication (independent pass)"),
            Some("Scope note from evaluation"),
        ]
    );
    assert_eq!(parts[1].body, "a calls b (x.swift:1-2). Then c.");
    // Nothing is dropped: rejoining the parts rebuilds the original text.
    let rebuilt: Vec<String> = parts
        .iter()
        .map(|p| match &p.label {
            Some(l) => format!("{l}: {}", p.body),
            None => p.body.clone(),
        })
        .collect();
    assert_eq!(rebuilt.join(" "), text);

    // Without lead-ins the evidence stays one unlabelled block.
    let plain = split_evidence("Values are escaped before rendering, so the claim fails.");
    assert_eq!(plain.len(), 1);
    assert!(plain[0].label.is_none());
    // A marker word that does not open a lead-in is ordinary prose.
    let prose = split_evidence("Trace: x. Missing fact is product intent, recorded as a question.");
    assert_eq!(prose.len(), 1);
    assert!(prose[0].body.ends_with("recorded as a question."));
    assert!(split_evidence("").is_empty());
}

#[test]
fn html_escapes_hostile_strings_end_to_end() {
    let mut f = keyed("x", Verdict::Confirmed);
    f.title = "<script>alert(1)</script>\" onmouseover=\"alert(2)".into();
    f.evidence = "Trace: <img src=x onerror=alert(3)>. Sandbox evidence (<b>x</b>): </p><script>alert(4)</script>. Proposed fix: Invariant: <iframe src=//evil>.".into();
    f.fix_brief = Some("<a href=\"javascript:alert(5)\">fix</a>".into());
    f.prerequisites = Some("<style>body{display:none}</style>".into());
    f.verified_by = Some("<svg onload=alert(6)>".into());
    f.location.path = "app/<script>/route.ts".into();
    f.fingerprint = "\"><script>alert(7)</script>".into();
    let mut q = keyed("q", Verdict::NeedsValidation);
    q.intent_question = Some("<script>alert(8)</script>?".into());
    let file = FindingsFile {
        findings: vec![f, q],
    };
    let hostile_meta = ReportMeta {
        repo: "<script>alert(9)</script>".into(),
        source_ref: "\"><img src=x>".into(),
        mode: "<b>gate</b>".into(),
        sandbox: "<script>".into(),
        coverage: vec!["covered: <script>alert(10)</script>".into()],
        sensors: Some("<img src=y>".into()),
        hunters: None,
        verifier: Some("<script>alert(11)</script>".into()),
        agent_calls: None,
        critic: None,
        models: vec![],
        reroutes: vec![],
        artifact_base: String::new(),
        timeline: Vec::new(),
        accounting: Default::default(),
        persona: String::new(),
        report_depth: String::new(),
        intent_answers: Default::default(),
    };
    let html = render_html(&file, &hostile_meta);
    let lower = html.to_lowercase();
    for tag in [
        "<script",
        "<img",
        "<iframe",
        "<svg",
        "<b>",
        "<a href=\"javascript",
    ] {
        assert!(!lower.contains(tag), "unescaped {tag} in output");
    }
    assert_eq!(
        lower.matches("<style").count(),
        1,
        "only the report stylesheet"
    );
    assert!(!html.contains("\" onmouseover="));
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;&quot; onmouseover=&quot;alert(2)"));
    assert!(html.contains("&lt;img src=x onerror=alert(3)&gt;"));
    assert!(html.contains("&lt;script&gt;alert(8)&lt;/script&gt;?"));
    assert!(html.contains("&lt;script&gt;alert(11)&lt;/script&gt;"));
    assert!(html.contains("covered: &lt;script&gt;alert(10)&lt;/script&gt;"));
    // Anchors derived from a hostile fingerprint keep only safe characters.
    assert!(html.contains("id=\"f-scriptalert7script\""));
}

#[test]
fn html_report_makes_no_external_requests() {
    let mut asked = keyed("asked", Verdict::NeedsValidation);
    asked.intent_question = Some("Intended?".into());
    let file = FindingsFile {
        findings: vec![
            keyed("c", Verdict::Confirmed),
            asked,
            keyed("r", Verdict::Rejected),
        ],
    };
    let html = render_html(&file, &meta());
    assert!(!html.contains("http://") && !html.contains("https://"));
    assert!(!html.contains("src=") && !html.contains("url("));
    assert!(!html.to_lowercase().contains("<script"));
    for (i, _) in html.match_indices("href=\"") {
        assert!(
            html[i + 6..].starts_with('#'),
            "non anchor link at {}",
            &html[i..(i + 40).min(html.len())]
        );
    }
    assert!(html.contains("http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'"));
}

#[test]
fn html_report_is_deterministic_and_counts_every_bucket() {
    let mut asked = keyed("asked", Verdict::NeedsValidation);
    asked.intent_question = Some("Intended?".into());
    let file = FindingsFile {
        findings: vec![
            keyed("c", Verdict::Confirmed),
            asked,
            keyed("v", Verdict::NeedsValidation),
            keyed("r", Verdict::Rejected),
        ],
    };
    let first = render_html(&file, &meta());
    assert_eq!(first, render_html(&file, &meta()));
    assert!(first.contains(
        "Outcome of 4 records: 1 confirmed, 2 needs validation, 1 rejected after verification."
    ));
    assert!(first.contains("Severity: high"));
    assert!(first.contains("id=\"f-omgs-"));
}

#[test]
fn evidence_and_anchors_survive_awkward_input() {
    use omgs::report::split_evidence;
    for text in [
        "",
        "Trace:",
        "Missing fact:",
        "Trace",
        "Caf\u{e9}. Trace: \u{fc}n\u{ef}. Missing fact: \u{2713}",
        "\u{fc}. Trace: x.\u{e9} Missing fact: y",
        "Sandbox evidence ((a) (b)): x. Trace (open: y",
        "Trace (see a. Missing fact: b): c",
    ] {
        let rebuilt: Vec<String> = split_evidence(text)
            .iter()
            .map(|p| match &p.label {
                Some(l) if p.body.is_empty() => format!("{l}:"),
                Some(l) => format!("{l}: {}", p.body),
                None => p.body.clone(),
            })
            .collect();
        assert_eq!(rebuilt.join(" "), text.trim(), "lossless split of {text:?}");
    }
    // Lead-ins after leading whitespace, questions, and closing brackets.
    let labels = |t: &str| -> Vec<Option<String>> {
        split_evidence(t).into_iter().map(|p| p.label).collect()
    };
    assert_eq!(labels(" Trace: x"), vec![Some("Trace".to_string())]);
    assert_eq!(
        labels("Is it intended? Missing fact: x"),
        vec![None, Some("Missing fact".to_string())]
    );
    assert_eq!(
        labels("See line 3 (x.) Missing fact: y"),
        vec![None, Some("Missing fact".to_string())]
    );

    // Empty, duplicate, and suffix-colliding fingerprints still get unique ids.
    let mut a = keyed("a", Verdict::Confirmed);
    a.fingerprint = String::new();
    a.evidence = "Trace: t. Missing fact: stays in place for confirmed.".into();
    let mut b = keyed("b", Verdict::NeedsValidation);
    b.fingerprint = "dup".into();
    let mut c = keyed("c", Verdict::Rejected);
    c.fingerprint = "dup".into();
    c.evidence = "Missing fact: stays in place for rejected.".into();
    let mut d = keyed("d", Verdict::NeedsValidation);
    d.fingerprint = "dup-t".into();
    let html = render_html(
        &FindingsFile {
            findings: vec![a, b, c, d],
        },
        &meta(),
    );
    let ids: Vec<&str> = html
        .match_indices(" id=\"")
        .map(|(i, _)| {
            let rest = &html[i + 5..];
            &rest[..rest.find('"').unwrap()]
        })
        .collect();
    let unique: std::collections::BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(ids.len(), unique.len(), "duplicate ids in {ids:?}");
    // Only needs_validation hoists its missing fact into a callout.
    assert_eq!(html.matches("class=\"callout c-missing\"").count(), 2);
    assert!(html.contains("<h5>Missing fact</h5><p>stays in place for confirmed.</p>"));
    assert!(html.contains("<h5>Missing fact</h5><p>stays in place for rejected.</p>"));
}

#[test]
fn report_shows_run_metadata_or_not_recorded() {
    use omgs::report::render_markdown;
    let file = FindingsFile {
        findings: vec![keyed("c", Verdict::Confirmed)],
    };
    // meta() records all three run-metadata values.
    let md = render_markdown(&file, &meta());
    assert!(md.contains("Run: hunters 2, verifier blue-1, agent calls 37"));
    let html = render_html(&file, &meta());
    assert!(html.contains("hunters 2, verifier blue-1, agent calls 37"));

    // Nothing recorded renders each value as "not recorded".
    let bare = ReportMeta {
        repo: "x".into(),
        source_ref: "abc".into(),
        mode: "advisory".into(),
        sandbox: "none".into(),
        coverage: vec![],
        sensors: None,
        hunters: None,
        verifier: None,
        agent_calls: None,
        critic: None,
        models: vec![],
        reroutes: vec![],
        artifact_base: String::new(),
        timeline: Vec::new(),
        accounting: Default::default(),
        persona: String::new(),
        report_depth: String::new(),
        intent_answers: Default::default(),
    };
    let md2 = render_markdown(&file, &bare);
    assert!(
        md2.contains("Run: hunters not recorded, verifier not recorded, agent calls not recorded")
    );
}

#[test]
fn semgrep_parser_keeps_only_metadata() {
    use omgs::sensors::{parse_semgrep, SensorsReport};
    use std::path::Path;
    let mut report = SensorsReport {
        tools_run: vec![],
        tools_unavailable: vec![],
        hits: vec![],
    };
    // A semgrep "extra.lines" field can echo matched source; it must not survive.
    let json = r#"{"results":[
      {"check_id":"rules.nil-team","path":"/t/src/Helper.swift","start":{"line":42},"extra":{"lines":"let token = \"supersecret\""}},
      {"check_id":"rules.vendored","path":"/t/lib/foo.min.js","start":{"line":1}}
    ],"errors":[]}"#;
    parse_semgrep(json, Path::new("/t"), &mut report);
    assert_eq!(report.hits.len(), 2);
    let h = &report.hits[0];
    assert_eq!(h.tool, "semgrep");
    assert_eq!(h.rule, "rules.nil-team");
    assert_eq!(h.file, "src/Helper.swift");
    assert_eq!(h.line, Some(42));
    assert!(!h.vendored);
    assert!(
        !report.hits[1].vendored,
        "minification alone is not vendor evidence"
    );
    let dump = format!("{report:?}");
    assert!(!dump.contains("supersecret"), "matched source text leaked");
}

// --- architecture map ---------------------------------------------------------

use omgs::architecture::{
    from_json, render_architecture_html, render_architecture_markdown, validate_architecture,
    ArchitectureFile, Boundary, Component, Flow, InputSurface, Principal, Zone,
};

fn arch() -> ArchitectureFile {
    ArchitectureFile {
        target: "demo-app".into(),
        zones: vec![
            Zone {
                id: "z1".into(),
                name: "Internet".into(),
                trust: Some("untrusted".into()),
                ..Default::default()
            },
            Zone {
                id: "z2".into(),
                name: "Application".into(),
                trust: Some("application".into()),
                ..Default::default()
            },
            Zone {
                id: "z3".into(),
                name: "Data".into(),
                trust: Some("data".into()),
                ..Default::default()
            },
        ],
        components: vec![
            Component {
                id: "c".into(),
                name: "Browser".into(),
                zone: "z1".into(),
                kind: Some("client".into()),
                ..Default::default()
            },
            Component {
                id: "r".into(),
                name: "GET /x".into(),
                zone: "z2".into(),
                kind: Some("route".into()),
                entry_point: true,
                path: "app/x/route.ts".into(),
                ..Default::default()
            },
            Component {
                id: "d".into(),
                name: "Postgres".into(),
                zone: "z3".into(),
                kind: Some("datastore".into()),
                ..Default::default()
            },
        ],
        boundaries: vec![Boundary {
            id: "bd".into(),
            name: "edge".into(),
            between: Some(vec!["z1".into(), "z2".into()]),
            ..Default::default()
        }],
        flows: vec![
            Flow {
                from: "c".into(),
                to: "r".into(),
                crosses: "bd".into(),
                ..Default::default()
            },
            Flow {
                from: "r".into(),
                to: "d".into(),
                ..Default::default()
            },
        ],
        input_surfaces: vec![InputSurface {
            id: "s".into(),
            component: "r".into(),
            attacker: "anon".into(),
            ..Default::default()
        }],
        unexamined: vec!["admin console not mapped".into()],
        ..Default::default()
    }
}

#[test]
fn architecture_validate_accepts_and_rejects() {
    assert!(validate_architecture(&arch()).is_empty());

    let mut empty = ArchitectureFile {
        target: "t".into(),
        ..Default::default()
    };
    let errs = validate_architecture(&empty);
    assert!(errs.iter().any(|e| e.contains("zones is empty")));
    assert!(errs.iter().any(|e| e.contains("components is empty")));

    // dangling flow and unknown zone
    empty = arch();
    empty.flows.push(Flow {
        from: "nope".into(),
        to: "r".into(),
        ..Default::default()
    });
    empty.components.push(Component {
        id: "x".into(),
        name: "X".into(),
        zone: "ghost".into(),
        ..Default::default()
    });
    let errs = validate_architecture(&empty);
    assert!(errs
        .iter()
        .any(|e| e.contains("from 'nope' is not a component")));
    assert!(errs
        .iter()
        .any(|e| e.contains("zone 'ghost' is not defined")));
}

#[test]
fn architecture_render_is_deterministic() {
    let a = arch();
    assert_eq!(render_architecture_html(&a), render_architecture_html(&a));
    assert_eq!(
        render_architecture_markdown(&a),
        render_architecture_markdown(&a)
    );
    let html = render_architecture_html(&a);
    assert!(html.contains("Architecture"));
    assert!(html.contains("<svg"));
    assert!(html.contains("Postgres"));
}

#[test]
fn architecture_html_loads_nothing_external() {
    let html = render_architecture_html(&arch());
    assert!(!html.contains("http://") && !html.contains("https://"));
    assert!(!html.contains("src=") && !html.contains("url("));
    assert!(!html.to_lowercase().contains("<script"));
    assert_eq!(
        html.matches("<svg").count(),
        1,
        "exactly one trusted diagram"
    );
    for (i, _) in html.match_indices("href=\"") {
        assert!(html[i + 6..].starts_with('#'), "non-anchor link at {i}");
    }
    assert!(html.contains("http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'"));
}

#[test]
fn architecture_escapes_hostile_fields() {
    let payload = "<script>alert(1)</script>\" onmouseover=\"alert(2)";
    let mut a = arch();
    a.target = payload.into();
    a.components[1].name = payload.into();
    a.components[1].tech = payload.into();
    a.zones[1].name = payload.into();
    let html = render_architecture_html(&a).to_lowercase();
    assert!(!html.contains("<script"));
    assert!(!html.contains("onmouseover=\""));
    assert!(!html.contains("<img"));
    assert!(render_architecture_html(&a).contains("&lt;script&gt;alert(1)&lt;/script&gt;"));

    let md = render_architecture_markdown(&a);
    assert!(!md.contains("<script>"));
    assert!(md.contains("&lt;script&gt;"));
}

#[test]
fn architecture_renders_minimal_and_skips_empty_sections() {
    let a = ArchitectureFile {
        target: "tiny".into(),
        zones: vec![Zone {
            id: "z".into(),
            name: "App".into(),
            ..Default::default()
        }],
        components: vec![Component {
            id: "only".into(),
            name: "App".into(),
            zone: "z".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    assert!(validate_architecture(&a).is_empty());
    let html = render_architecture_html(&a);
    assert!(!html.contains("id=\"flows\""));
    assert!(!html.contains("id=\"boundaries\""));
    assert!(!html.contains("id=\"surface\""));
    assert!(html.contains("Nothing recorded as unexamined"));
}

#[test]
fn architecture_from_json_is_lenient() {
    // unknown kind value and an unknown top-level field must not fail parsing
    let a = from_json(
        r#"{ "target":"j", "surprise": true,
             "zones":[{"id":"z","name":"App"}],
             "components":[{"id":"c","name":"C","zone":"z","kind":"frobnicator"}] }"#,
    )
    .expect("lenient parse");
    assert_eq!(a.components[0].kind.as_deref(), Some("frobnicator"));
    assert!(validate_architecture(&a).is_empty());
    let _ = render_architecture_html(&a);
}

#[test]
fn architecture_markdown_neutralizes_link_injection() {
    let mut a = arch();
    a.components[1].name = "![x](http://evil)".into();
    a.components[1].tech = "[click](javascript:alert(1))".into();
    let md = render_architecture_markdown(&a);
    assert!(
        !md.contains("]("),
        "link/image target syntax must be escaped"
    );
    assert!(!md.contains("!["), "image syntax must be escaped");
    assert!(
        md.contains("\\!\\[x\\]"),
        "payload should appear backslash-escaped"
    );
}

#[test]
fn architecture_validate_catches_structural_gaps() {
    // empty/missing component zone must fail, not hide the component
    let mut a = arch();
    a.components[0].zone = String::new();
    assert!(validate_architecture(&a)
        .iter()
        .any(|e| e.contains("zone is empty")));

    // explicit empty boundary.between is invalid (schema needs exactly two)
    a = arch();
    a.boundaries[0].between = Some(vec![]);
    assert!(validate_architecture(&a)
        .iter()
        .any(|e| e.contains("must name exactly two zones")));

    // absent between (None) is allowed
    a = arch();
    a.boundaries[0].between = None;
    assert!(validate_architecture(&a).is_empty());

    // duplicate flow ids are rejected
    a = arch();
    a.flows[0].id = "dup".into();
    a.flows[1].id = "dup".into();
    assert!(validate_architecture(&a)
        .iter()
        .any(|e| e.contains("duplicate flow id 'dup'")));
}

#[test]
fn architecture_html_includes_notes_and_principals() {
    let mut a = arch();
    a.notes = "Mapped the web app only".into();
    a.principals = vec![Principal {
        id: "p".into(),
        name: "Admin".into(),
        kind: Some("admin".into()),
        ..Default::default()
    }];
    let html = render_architecture_html(&a);
    assert!(html.contains("id=\"notes\""));
    assert!(html.contains("Mapped the web app only"));
    assert!(html.contains("id=\"principals\""));
    assert!(html.contains("Admin"));
}

#[test]
fn architecture_html_neutralizes_banned_byte_sequences() {
    let mut a = arch();
    a.stack.notes = "see https://service.example/api with src= and url( here".into();
    let html = render_architecture_html(&a);
    // the invariant bans survive as inert entities, not literal bytes
    assert!(!html.contains("https://"));
    assert!(!html.contains("src="));
    assert!(!html.contains("url("));
    // but the text is still readable
    assert!(html.contains("service.example"));
}

#[test]
fn architecture_clamps_wide_labels_only_when_needed() {
    // normal labels must not be width-clamped (clamping would stretch them)
    assert!(!render_architecture_html(&arch()).contains("textLength"));

    // pathological wide labels get a width clamp so they stay inside their box
    let mut a = arch();
    a.zones[0].name = "W".repeat(300);
    a.components[0].name = "W".repeat(20);
    let html = render_architecture_html(&a);
    assert!(html.contains("class=\"arch-zone\" text-anchor=\"middle\" textLength=\"290\""));
    assert!(html.contains("class=\"arch-name\" textLength=\"180\""));
}

#[test]
fn architecture_clamps_css_uppercased_labels() {
    // ß uppercases to "SS" in CSS; the width estimate must account for it
    let mut a = arch();
    a.zones[0].name = "\u{00df}".repeat(24);
    let html = render_architecture_html(&a);
    assert!(html.contains("class=\"arch-zone\" text-anchor=\"middle\" textLength=\"290\""));

    // kind is uppercased by CSS, so a long lowercase kind must still clamp
    let mut b = arch();
    b.components[0].kind = Some("a".repeat(26));
    assert!(render_architecture_html(&b).contains("class=\"arch-kind\" textLength=\"180\""));
}

#[test]
fn architecture_single_column_reserves_a_gutter() {
    // one zone, three components, a -> c skipping b: a same-column flow needs a
    // reserved right gutter so it does not cross node b.
    let a = ArchitectureFile {
        target: "one".into(),
        zones: vec![Zone {
            id: "z".into(),
            name: "App".into(),
            ..Default::default()
        }],
        components: vec![
            Component {
                id: "a".into(),
                name: "A".into(),
                zone: "z".into(),
                ..Default::default()
            },
            Component {
                id: "b".into(),
                name: "B".into(),
                zone: "z".into(),
                ..Default::default()
            },
            Component {
                id: "c".into(),
                name: "C".into(),
                zone: "z".into(),
                ..Default::default()
            },
        ],
        flows: vec![Flow {
            from: "a".into(),
            to: "c".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    assert!(validate_architecture(&a).is_empty());
    let html = render_architecture_html(&a);
    // base single-column width is 292; the reserved gutter widens it to 396
    assert!(html.contains("viewBox=\"0 0 396"));
    assert_eq!(html.matches("<svg").count(), 1);
}

#[test]
fn architecture_sample_fixture_is_valid() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/architecture.sample.json"
    );
    let txt = std::fs::read_to_string(path).expect("read sample");
    let a = from_json(&txt).expect("parse sample");
    assert!(
        validate_architecture(&a).is_empty(),
        "sample must validate: {:?}",
        validate_architecture(&a)
    );
    assert_eq!(render_architecture_html(&a).matches("<svg").count(), 1);
    let _ = render_architecture_markdown(&a);
}

#[test]
fn architecture_renders_cyclic_flows_without_panic() {
    let mut a = arch();
    a.flows.push(Flow {
        from: "r".into(),
        to: "c".into(),
        ..Default::default()
    });
    a.flows.push(Flow {
        from: "c".into(),
        to: "r".into(),
        ..Default::default()
    });
    assert!(validate_architecture(&a).is_empty());
    let first = render_architecture_html(&a);
    assert_eq!(first, render_architecture_html(&a));
    assert!(first.contains("<svg"));
}
