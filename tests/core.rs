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
        evidence: "dummy tenant B order returned to tenant A".into(),
        fix_brief: None,
        intent_question: None,
        family: None,
        prerequisites: None,
        verified_by: None,
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
    use omgs::sandbox::{mxc_config_json, ProveRequest};
    use std::path::PathBuf;
    let req = ProveRequest {
        command: "cmd.exe /d /s /c echo hi".into(),
        timeout_ms: 30000,
        cwd: Some(PathBuf::from("/work/target")),
        scratch: PathBuf::from("/work/scratch"),
    };
    let text = mxc_config_json(
        &req,
        &PathBuf::from("/work/scratch"),
        &PathBuf::from("/work/target"),
    );
    let v: serde_json::Value = serde_json::from_str(&text).expect("config must parse");
    assert_eq!(v["version"], "1.0.0");
    assert_eq!(v["containment"], "process");
    assert_eq!(v["network"]["egress"]["default"], "deny");
    assert_eq!(v["network"]["ingress"]["hostLoopback"], "deny");
    assert_eq!(v["filesystem"]["readwritePaths"][0], "/work/scratch");
    assert_eq!(v["filesystem"]["readonlyPaths"][0], "/work/target");
    assert!(v["process"]["env"]
        .as_array()
        .map(|a| !a.is_empty())
        .unwrap_or(false));
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
fn vendored_paths_are_excluded() {
    assert!(omgs::is_vendored_path(
        "Web/MonacoEditor/min/vs/editor/editor.main.js"
    ));
    assert!(omgs::is_vendored_path("lib/foo.min.js"));
    assert!(omgs::is_vendored_path("bin/tool.dll"));
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
fn dedicated_host_confirmed_requires_attestation() {
    // Confirmed at the dedicated_host tier with no attestation is rejected:
    // the tier asserts a real run and must never imply a productive host.
    let mut without = finding(
        Verdict::Confirmed,
        ProofTier::DedicatedHost,
        Some(Severity::High),
    );
    without.prerequisites = None;
    let file = FindingsFile {
        findings: vec![without],
    };
    assert!(validate(&file)
        .iter()
        .any(|e| e.contains("disposable-host attestation")));

    // With the disposable-host attestation recorded it is valid.
    let mut with = finding(
        Verdict::Confirmed,
        ProofTier::DedicatedHost,
        Some(Severity::High),
    );
    with.prerequisites =
        Some("Throwaway macOS VM, no real data or credentials; snapshot discarded after.".into());
    let ok = FindingsFile {
        findings: vec![with],
    };
    assert!(validate(&ok).is_empty(), "{:?}", validate(&ok));
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
    assert!(report.hits[1].vendored, "a .min.js path is vendored");
    let dump = format!("{report:?}");
    assert!(!dump.contains("supersecret"), "matched source text leaked");
}
