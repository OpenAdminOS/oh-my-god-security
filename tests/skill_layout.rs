//! Readability and policy regression checks for the installed skill bundle.
use std::path::Path;

fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
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
