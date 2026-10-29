//! Readability and policy regression checks for the installed skill bundle.
use std::path::Path;

fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn setup_requires_one_informational_update_check_after_version_match() {
    let setup = normalized(include_str!("../skill/SETUP.md"));
    for requirement in [
        "After the exact version match passes (including after a consented first installation)",
        "`\"<OMGS_BIN>\" update-check` once per run at setup, before the review starts",
        "it downloads no executable and updates no files",
        "Never fetch release information in the agent",
        "tell the user a newer OMGS skill exists",
        "with continue as the default",
        "npx skills add https://github.com/OpenAdminOS/oh-my-god-security --skill omgs-security-review",
        "Reload the refreshed skill and its `VERSION`",
        "existing typed-yes consent flow",
        "install the matching pinned binary before the review starts",
        "Do not rerun update-check during this run",
        "No answer means continue",
        "No output or failure means proceed silently",
        "Never block a review on this check or auto-download anything on the strength of the check alone",
        "Explicit consent is still required before any download",
    ] {
        assert!(setup.contains(requirement), "missing setup rule: {requirement}");
    }
    assert!(setup.find("require the exact string").unwrap() < setup.find("update-check").unwrap());
}

// Inspect the entry's phase routing, not the concatenated bundle or detail index.
fn phase_routes(entry: &str) -> Vec<String> {
    let phases = entry
        .split_once("## Seven phases\n")
        .expect("phase list")
        .1
        .split_once("## Non-negotiable rules")
        .expect("end of phase list")
        .0;
    let mut routes = Vec::new();
    for line in phases.lines() {
        if line.as_bytes().first().is_some_and(u8::is_ascii_digit) {
            routes.push(String::new());
        }
        if let Some(route) = routes.last_mut() {
            route.push_str(line);
            route.push(' ');
        }
    }
    routes.into_iter().map(|route| normalized(&route)).collect()
}

#[test]
fn entry_routes_mandatory_reading_at_phase_boundaries() {
    let entry = include_str!("../skill/SKILL.md");
    let routes = phase_routes(entry);
    assert_eq!(routes.len(), 7);
    let preamble = "(PIPELINE.md#the-pipeline-multi-agent-by-default)";
    for (index, phase) in [(0, "Initialize"), (1, "Map")] {
        let route = &routes[index];
        assert!(route.contains(&format!("[{phase}]{preamble}")));
        for requirement in ["pipeline preamble", "`sensor-hits.json`", "`sensors.json`"] {
            assert!(
                route.contains(requirement),
                "{phase}: missing {requirement}"
            );
        }
    }
    assert!(routes[0].contains("before initialization"));
    assert!(routes[0].contains("sensor restrictions"));
    assert!(routes[2].contains("before hunting, read [DECISION-RULES.md](DECISION-RULES.md)"));
    assert!(routes[6]
        .contains("before reporting, read [HANDOFF-AND-PROGRESS.md](HANDOFF-AND-PROGRESS.md)"));

    // These prerequisites apply to every dispatch and every artifact consumer,
    // so they must precede all phases rather than appear only in the file index.
    let phase_intro = entry
        .split_once("## Seven phases\n")
        .unwrap()
        .1
        .split_once("1. [Initialize]")
        .unwrap()
        .0;
    let phase_intro = normalized(phase_intro);
    assert!(phase_intro.contains(
        "Before dispatching any agent, read [BUDGETS-AND-ROUTING.md](BUDGETS-AND-ROUTING.md)"
    ));
    assert!(phase_intro.contains(
        "Before consuming any handoff artifacts, read [HANDOFF-AND-PROGRESS.md](HANDOFF-AND-PROGRESS.md)"
    ));

    let pipeline = include_str!("../skill/PIPELINE.md");
    let preamble = pipeline.split_once("### Initialize").unwrap().0;
    assert!(preamble.contains("## The pipeline (multi-agent by default)"));
    for rule in [
        "never fall back\nto host execution",
        "Read `sensor-hits.json` and `sensors.json` during mapping.",
    ] {
        assert!(preamble.contains(rule), "missing preamble rule: {rule}");
    }
}

#[test]
fn entry_is_short_and_guides_are_wrapped() {
    let entry = include_bytes!("../skill/SKILL.md");
    assert!(entry.len() < 9_000, "entry is {} bytes", entry.len());
    for (name, bytes) in omgs::setup::BUNDLED {
        let path = Path::new(name);
        if path.extension().and_then(|v| v.to_str()) != Some("md")
            || !(path.parent() == Some(Path::new("")) || path.parent() == Some(Path::new("agents")))
        {
            continue;
        }
        assert!(bytes.len() < 20_000, "{name} is {} bytes", bytes.len());
        let text = std::str::from_utf8(bytes).unwrap();
        let mut fenced = false;
        for (index, line) in text.lines().enumerate() {
            if line.starts_with("```") {
                fenced = !fenced;
            }
            // Keep executable syntax and Markdown pipe-table rows intact. URLs are
            // exempt only when the indivisible URL token itself exceeds the limit.
            let long_url = line.split_whitespace().any(|token| {
                token.chars().count() > 100
                    && (token.contains("https://") || token.contains("http://"))
            });
            assert!(
                line.chars().count() <= 100 || fenced || line.starts_with('|') || long_url,
                "{name}:{} exceeds 100 characters: {line}",
                index + 1
            );
        }
    }
}

#[test]
fn load_bearing_rules_survive_moves() {
    let all = omgs::setup::BUNDLED
        .iter()
        .filter(|(name, _)| name.ends_with(".md"))
        .map(|(_, bytes)| normalized(std::str::from_utf8(bytes).unwrap()))
        .collect::<Vec<_>>()
        .join("\n");
    for rule in [
        "Resolve `OMGS_BIN` in this order: `omgs` on PATH, then `${OMGS_HOME}/bin/omgs` when `OMGS_HOME` is set",
        "Read `VERSION` beside this file.",
        "Provenance failure alone is labelled unverified and does not assert tampering.",
        "require the exact string `omgs <VERSION>`.",
        "On mismatch, stop and report both versions clearly.",
        "Before the first binary or executor download, show this exact consent text,",
        "Wait for the user's explicit consent.",
        "Never auto-consent from a general review request.",
        "Use that exact path for subsequent commands.",
        "A checksum, signature or executor-pin failure stops installation.",
        "Publication is atomic per file, not a transaction across the entire installation.",
        "The installer never uses a test override.",
        "never fetch the full MXC archive or substitute direct execution.",
        "Never install target dependencies or a toolchain to make a proof work.",
        "Hand each role brief over **verbatim**, plus its explicit scope and resolved inputs.",
        "Do not paraphrase or summarize a brief.",
        "Tier 2 approval is given only by a person at a terminal with `omgs approve --target <repo>`; never run that command yourself.",
        "tier 2 runs only on Linux, elsewhere it exits 3 with the reason",
        "Exit 2 is a harness or usage error and never supports a proof.",
        "Fixed or wrong-nonce markers earn no support.",
        "missing or null contract fields are invalid.",
        "A recipe contract requires exit 1 and both nonce-qualified marker flags",
        "No approval is implied by a general audit request.",
        "Hunters hand proof plans and drafts to the verifier and never execute proofs.",
        "Never write step-by-step operational instructions, weaponized commands, credential harvesting",
        "Do include the minimal synthetic input and the external test draft the verifier needs,",
        "It is never the author of a record it judges.",
        "the evaluator is independent of both hunt and verify.",
        "The evaluator in step 6 replays every proof it upholds with `omgs prove --run OUTPUT_DIR --replay <n>` instead of trusting the record file",
        "Never silently reset or expand a budget, or claim an unreviewed area is clean.",
        "An untrusted PR head cannot change its own gate.",
        "No dependency installation, package fetching, real credentials, or inherited host environment is permitted during proofs.",
        "Never run an unsandboxed fallback.",
        "Stop immediately on an unexpected external destination, real secret, or effect outside the synthetic fixture.",
        "Never turn a blocked proof into a rejection or a confirmation.",
        "Do not publish a score or coverage percentage.",
        "Scanner matches are leads, not confirmations.",
        "OMGS never runs it automatically.",
        "Gate installs no dependencies.",
        "Never treat patch creation as authorization to fix, weaken the proof, or bypass the shared budget.",
    ] {
        assert!(all.contains(rule), "missing preserved rule: {rule}");
    }
}

#[test]
fn bundled_markdown_links_resolve_after_moves() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut documents = omgs::setup::BUNDLED
        .iter()
        .filter(|(name, _)| name.ends_with(".md"))
        .map(|(name, bytes)| (root.join("skill").join(name), bytes.to_vec()))
        .collect::<Vec<_>>();
    documents.push((
        root.join("README.md"),
        std::fs::read(root.join("README.md")).unwrap(),
    ));
    for entry in std::fs::read_dir(root.join("docs")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|v| v.to_str()) == Some("md") {
            documents.push((path.clone(), std::fs::read(path).unwrap()));
        }
    }
    for (path, bytes) in documents {
        let text = String::from_utf8(bytes).unwrap();
        for tail in text.split("](").skip(1) {
            let Some((target, _)) = tail.split_once(')') else {
                continue;
            };
            if target.contains("://") || target.starts_with('#') {
                continue;
            }
            let (file, anchor) = target.split_once('#').unwrap_or((target, ""));
            let destination = path.parent().unwrap().join(file);
            assert!(destination.exists(), "{}: missing {target}", path.display());
            // Check anchors for the relocated guides, including phase links.
            if !anchor.is_empty() && destination.extension().and_then(|v| v.to_str()) == Some("md")
            {
                let guide = std::fs::read_to_string(&destination).unwrap();
                let headings = guide
                    .lines()
                    .filter(|line| line.starts_with('#'))
                    .map(|line| {
                        line.trim_start_matches('#')
                            .trim()
                            .to_lowercase()
                            .chars()
                            .filter_map(|c| {
                                if c.is_alphanumeric() || c == '-' {
                                    Some(c)
                                } else if c == ' ' {
                                    Some('-')
                                } else {
                                    None
                                }
                            })
                            .collect::<String>()
                    })
                    .collect::<Vec<_>>();
                assert!(
                    headings.iter().any(|h| h == anchor),
                    "{}: missing anchor {target}",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn progress_is_required_without_browser_consent() {
    let entry = normalized(include_str!("../skill/SKILL.md"));
    let pipeline = normalized(include_str!("../skill/PIPELINE.md"));
    let handoff = normalized(include_str!("../skill/HANDOFF-AND-PROGRESS.md"));
    assert!(entry.contains("At run start, read [HANDOFF-AND-PROGRESS.md]"));
    assert!(entry.contains("mandatory `omgs status`"));
    assert!(entry.contains("immediately after initialization, even without the live view"));
    for rule in [
        "verify that `OUTPUT_DIR/pipeline-status.json` exists",
        "If status fails, report and resolve the error",
        "mark the outgoing stage `done`",
        "mark the incoming stage `active`",
        "Before **every** sandbox proof or replay, including evaluator replays",
    ] {
        assert!(pipeline.contains(rule), "missing progress rule: {rule}");
    }
    for stage in [
        "initialize",
        "map",
        "hunt",
        "verify",
        "prove",
        "adjudicate",
        "report",
    ] {
        assert!(
            pipeline.contains(&format!(
                "omgs status --run OUTPUT_DIR --stage {stage} --state active --detail \""
            )),
            "missing entry update for {stage}"
        );
    }
    assert!(pipeline.contains("--stage report --state done --detail"));
    for rule in [
        "Only an explicit yes authorizes opening it",
        "Continue the review without a browser if the user says no or does not answer",
        "In a headless or non-interactive session, do not open a browser",
        "open \"$URL\"",
        "xdg-open \"$URL\"",
        "start \"\" \"%URL%\"",
        "never open a browser without that explicit yes",
    ] {
        assert!(
            handoff.contains(rule),
            "missing browser consent rule: {rule}"
        );
    }
}

#[test]
fn dashboard_explains_counters_and_sandbox_limits() {
    let dashboard = include_str!("../skill/progress/dashboard.html");
    for text in [
        ">Leads found</div>",
        ">Proven problems</div>",
        ">Still checking</div>",
        ">Ruled out</div>",
        "Leads are possibilities, not findings. Only proven problems count as confirmed.",
        "Proofs run on a copy and cannot modify the original.",
        "Writes stay within the copy and scratch folders.",
        "Granted toolchain folders and caches remain readable.",
        "No network in or out, and no access to this computer's local services (host loopback).",
    ] {
        assert!(
            dashboard.contains(text),
            "missing dashboard explanation: {text}"
        );
    }
    assert!(!dashboard.contains("the original is never touched"));
}

#[test]
fn dashboard_maps_stages_to_plain_language_and_architecture_areas() {
    let dashboard = include_str!("../skill/progress/dashboard.html");
    assert!(dashboard.contains("<h2 id=\"now-heading\">Happening now</h2>"));
    for (area, heading) in [
        ("agent", "Your agent reads the code"),
        ("omgs", "OMGS checks and records"),
        ("sandbox", "Sandbox runs the proofs"),
    ] {
        assert!(dashboard.contains(&format!("id=\"area-{area}\"")));
        assert!(dashboard.contains(&format!("<h3>{heading}</h3>")));
    }
    let stages = dashboard
        .split_once("const STAGES={")
        .expect("dashboard stage descriptions")
        .1
        .split_once("};")
        .unwrap()
        .0;
    for (id, area, label, detail) in [
        (
            "initialize",
            "omgs",
            "Prepare the review",
            "OMGS is recording the project and review settings.",
        ),
        (
            "map",
            "omgs",
            "Understand the project",
            "OMGS is mapping how the project fits together.",
        ),
        (
            "hunt",
            "agent",
            "Look for possible problems",
            "Your agent is reading the code for possible security problems.",
        ),
        (
            "verify",
            "agent",
            "Check each lead",
            "An independent agent is checking whether each lead holds up.",
        ),
        (
            "challenge",
            "agent",
            "Check each lead",
            "An independent agent is checking whether each lead holds up.",
        ),
        (
            "prove",
            "sandbox",
            "Test leads safely",
            "The sandbox is testing whether a lead breaks a security rule.",
        ),
        (
            "adjudicate",
            "omgs",
            "Review the evidence",
            "The evidence is being reviewed before any decision is final.",
        ),
        (
            "evaluate",
            "omgs",
            "Review the evidence",
            "The evidence is being reviewed before any decision is final.",
        ),
        (
            "report",
            "omgs",
            "Prepare your report",
            "OMGS is preparing the results and remaining questions.",
        ),
    ] {
        let entry = stages
            .lines()
            .find(|line| line.trim_start().starts_with(&format!("{id}:")))
            .unwrap_or_else(|| panic!("missing dashboard stage: {id}"));
        for property in [
            format!("area:\"{area}\""),
            format!("label:\"{label}\""),
            format!("detail:\"{detail}\""),
        ] {
            assert!(entry.contains(&property), "{id}: missing {property}");
        }
    }
    // Pin both the lookup fallback and the code that consumes the mapping.
    for code in [
        "Object.prototype.hasOwnProperty.call(STAGES,st.id)?STAGES[st.id]:null",
        "return info?info.label:st.label;",
        "return info?info.detail:stageLabel(st)+\" is in progress.\";",
        "const info=active&&stageInfo(active.owner);",
        "for(const area of [\"agent\",\"omgs\",\"sandbox\"])",
        "document.getElementById(\"area-\"+area),current=!!info&&info.area===area;",
        "el.classList.toggle(\"active\",current);",
    ] {
        assert!(
            dashboard.contains(code),
            "missing dashboard stage routing: {code}"
        );
    }
}

#[test]
fn dashboard_escapes_stage_and_log_values_before_html_rendering() {
    let dashboard = include_str!("../skill/progress/dashboard.html");
    let escape = dashboard
        .split_once("function esc(s){")
        .expect("dashboard escape function")
        .1
        .split_once("const STATES=")
        .unwrap()
        .0;
    for code in [
        "String(s==null?\"\":s).replace(/[&<>\"']/g",
        "\"&\":\"&amp;\"",
        "\"<\":\"&lt;\"",
        "\">\":\"&gt;\"",
        "\"\\\"\":\"&quot;\"",
        "\"'\":\"&#39;\"",
    ] {
        assert!(escape.contains(code), "missing dashboard escaping: {code}");
    }
    let nodes = dashboard
        .split_once("function renderNode(st){")
        .unwrap()
        .1
        .split_once("function render(d){")
        .unwrap()
        .0;
    for code in [
        "esc(stageLabel(st))",
        "esc(st.detail||\"\")",
        "esc(stageLabel(c))",
        "esc(c.detail||\"\")",
    ] {
        assert!(
            nodes.contains(code),
            "unescaped dashboard stage field: {code}"
        );
    }
    let log = dashboard
        .split_once("document.getElementById(\"log\").innerHTML=")
        .unwrap()
        .1
        .split_once("const upd=")
        .unwrap()
        .0;
    for code in ["esc(e.ts||\"\")", "esc(e.m||\"\")", "kindClass(e.kind)"] {
        assert!(log.contains(code), "unescaped dashboard log field: {code}");
    }
}

#[test]
fn dashboard_announces_summary_only_when_it_changes() {
    let dashboard = include_str!("../skill/progress/dashboard.html");
    assert!(dashboard.contains("<p id=\"happening\" role=\"status\">"));
    let render = dashboard
        .split_once("function render(d){")
        .unwrap()
        .1
        .split_once("async function tick(){")
        .unwrap()
        .0;
    assert!(render.contains(
        "const summary=document.getElementById(\"happening\"),sentence=happening(stages,active);"
    ));
    assert!(render.contains("if(summary.textContent!==sentence)summary.textContent=sentence;"));
    // No other assignment may bypass the change guard on each two-second poll.
    assert_eq!(render.matches("summary.textContent=").count(), 1);
}
