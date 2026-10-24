use omgs::architecture::{
    render_architecture_html, render_architecture_markdown, validate_architecture, ArchitectureFile,
};
use omgs::critic::critique_run;
use omgs::ledger::{add_unit, coverage_lines, set_status, validate_ledger, Ledger, Unit, STATUSES};
use omgs::model::{identity, validate, FindingsFile};
use omgs::report::{render_html, render_markdown, render_sarif, ReportMeta};
use omgs::sandbox::{prove, ProveOutcome, ProveRequest};
use omgs::sensors::run_sensors;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}
fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn usage() {
    eprintln!(
        "omgs {}\n\nUsage:\n  omgs setup [--yes] [--from <skill-dir>]\n  omgs review --repo-url <url> [--mode gate|advisory] [--budget <n>]\n  omgs audit init --target <repo> [--out <run-dir>] [--mode gate|advisory] [--budget <n>] [--no-sensors]\n  omgs validate --findings <findings.json>\n  omgs fingerprint --attack-class <c> --entry-point <e> --sink <s> --boundary <b>\n  omgs prove --cmd <command> [--cwd <dir>] [--scratch <dir>] [--timeout-ms <n>]\n  omgs report --findings <findings.json> --out <dir> [--repo <name>] [--ref <ref>] [--mode gate|advisory] [--sandbox <label>] [--hunters <n>] [--verifier <id>] [--agent-calls <n>]\n  omgs architecture --in <architecture.json> --out <dir>\n  omgs ledger list --ledger <coverage-ledger.json>\n  omgs ledger add --ledger <coverage-ledger.json> --unit <id> --surface <s> [--classes a,b] [--status <status>] [--note <text>]\n  omgs ledger set --ledger <coverage-ledger.json> --unit <id> --status <status> [--evidence <ref>]... [--note <text>]\n  omgs critic --run <run-dir>\n  omgs check --target <repo> [--out <run-dir>]\n",
        env!("CARGO_PKG_VERSION")
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first().map(|s| s.as_str()) else {
        usage();
        return ExitCode::from(2);
    };
    let rest = &args[1..];
    if rest.iter().any(|a| a == "--help" || a == "-h") {
        usage();
        return ExitCode::SUCCESS;
    }
    let result: Result<(), String> = match cmd {
        "--help" | "-h" | "help" => {
            usage();
            Ok(())
        }
        "--version" | "-V" => {
            println!("omgs {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "setup" => cmd_setup(rest),
        "review" => cmd_review(rest),
        "audit" => cmd_audit(rest),
        "validate" => cmd_validate(rest),
        "fingerprint" => cmd_fingerprint(rest),
        "prove" => cmd_prove(rest),
        "report" => cmd_report(rest),
        "architecture" => cmd_architecture(rest),
        "ledger" => cmd_ledger(rest),
        "critic" => cmd_critic(rest),
        "check" => cmd_check(rest),
        other => Err(format!("unknown command '{other}'")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if e == "__EXIT3__" {
                ExitCode::from(3)
            } else if e == "__EXIT1__" {
                ExitCode::from(1)
            } else {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        }
    }
}

fn read_findings(path: &str) -> Result<FindingsFile, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("parse {path}: {e}"))
}

fn cmd_validate(args: &[String]) -> Result<(), String> {
    let path = flag(args, "--findings").ok_or("validate requires --findings <path>")?;
    let file = read_findings(&path)?;
    let errors = validate(&file);
    if errors.is_empty() {
        println!("valid: {} finding(s)", file.findings.len());
        Ok(())
    } else {
        for e in &errors {
            eprintln!("invalid: {e}");
        }
        Err("__EXIT1__".into())
    }
}

fn read_architecture(path: &str) -> Result<ArchitectureFile, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("parse {path}: {e}"))
}

fn cmd_architecture(args: &[String]) -> Result<(), String> {
    let inp = flag(args, "--in").ok_or("architecture requires --in <architecture.json>")?;
    let out = flag(args, "--out").ok_or("architecture requires --out <dir>")?;
    let file = read_architecture(&inp)?;
    let errors = validate_architecture(&file);
    if !errors.is_empty() {
        for e in &errors {
            eprintln!("invalid: {e}");
        }
        return Err("__EXIT1__".into());
    }
    let dir = Path::new(&out);
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join("ARCHITECTURE.md"),
        render_architecture_markdown(&file),
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join("ARCHITECTURE.html"),
        render_architecture_html(&file),
    )
    .map_err(|e| e.to_string())?;
    println!(
        "wrote {}, {}",
        dir.join("ARCHITECTURE.md").display(),
        dir.join("ARCHITECTURE.html").display()
    );
    Ok(())
}

fn cmd_fingerprint(args: &[String]) -> Result<(), String> {
    let get = |n: &str| flag(args, n).ok_or_else(|| format!("fingerprint requires {n}"));
    println!(
        "{}",
        omgs::fingerprint(
            &get("--attack-class")?,
            &get("--entry-point")?,
            &get("--sink")?,
            &get("--boundary")?
        )
    );
    Ok(())
}

fn cmd_prove(args: &[String]) -> Result<(), String> {
    let command = flag(args, "--cmd").ok_or("prove requires --cmd <command>")?;
    let timeout: u64 = flag(args, "--timeout-ms")
        .and_then(|v| v.parse().ok())
        .unwrap_or(120_000);
    let scratch = flag(args, "--scratch")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".local/share/omgs/prove-scratch"));
    let request = ProveRequest {
        command,
        timeout_ms: timeout,
        cwd: flag(args, "--cwd").map(PathBuf::from),
        scratch,
    };
    match prove(&request) {
        ProveOutcome::BlockedNoSandbox { request_json } => {
            eprintln!("needs_validation: no sandbox backend found, target code was not executed.");
            eprintln!("Install an MXC executor (OMGS_MXC_EXEC), Seatbelt (macOS) or bubblewrap (Linux), then rerun. Planned containment request:");
            eprintln!("{request_json}");
            Err("__EXIT3__".into())
        }
        ProveOutcome::Ran {
            backend,
            success,
            timed_out,
            output,
        } => {
            eprintln!(
                "sandbox backend: {backend}{}",
                if timed_out { " (timed out)" } else { "" }
            );
            print!("{output}");
            if success && !timed_out {
                Ok(())
            } else {
                Err("__EXIT1__".into())
            }
        }
    }
}

fn cmd_report(args: &[String]) -> Result<(), String> {
    let path = flag(args, "--findings").ok_or("report requires --findings <path>")?;
    let out = flag(args, "--out").ok_or("report requires --out <dir>")?;
    let file = read_findings(&path)?;
    let errors = validate(&file);
    if !errors.is_empty() {
        for e in &errors {
            eprintln!("invalid: {e}");
        }
        return Err("__EXIT1__".into());
    }
    let findings_dir = Path::new(&path)
        .parent()
        .map(|p| {
            if p.as_os_str().is_empty() {
                Path::new(".")
            } else {
                p
            }
        })
        .map(|p| p.to_path_buf());
    let mut coverage: Vec<String> = Vec::new();
    let mut critic = None;
    if let Some(dir) = &findings_dir {
        if let Ok(text) = std::fs::read_to_string(dir.join("coverage-ledger.json")) {
            if let Ok(ledger) = serde_json::from_str::<Ledger>(&text) {
                coverage = coverage_lines(&ledger);
            }
            match critique_run(dir) {
                Ok(c) => {
                    if !c.passed() {
                        eprintln!(
                            "warning: coverage critic found {} gap(s); they are listed in the report. Run omgs critic --run {} for detail.",
                            c.gaps.len(),
                            dir.display()
                        );
                    }
                    critic = Some(c);
                }
                Err(e) => eprintln!("warning: coverage critic not run: {e}"),
            }
        }
    }
    let mut sensors_summary: Option<String> = None;
    if let Some(dir) = &findings_dir {
        if let Ok(text) = std::fs::read_to_string(dir.join("sensors.json")) {
            if let Ok(rep) = serde_json::from_str::<omgs::sensors::SensorsReport>(&text) {
                let vendored = rep.hits.iter().filter(|h| h.vendored).count();
                sensors_summary = Some(format!(
                    "{} run, {} hit(s), {} vendored",
                    if rep.tools_run.is_empty() {
                        "no tools".into()
                    } else {
                        rep.tools_run.join(", ")
                    },
                    rep.hits.len(),
                    vendored
                ));
            }
        }
    }
    // Identities recorded on the findings stand in for unpassed flags.
    let recorded = |pick: fn(&omgs::model::Finding) -> &Option<String>| {
        file.findings
            .iter()
            .filter_map(|f| identity(pick(f)))
            .collect::<std::collections::BTreeSet<_>>()
    };
    let hunter_ids = recorded(|f| &f.hunted_by);
    let verifier_ids = recorded(|f| &f.verified_by);
    let hunters = flag(args, "--hunters")
        .and_then(|s| s.parse::<u32>().ok())
        .or_else(|| (!hunter_ids.is_empty()).then_some(hunter_ids.len() as u32));
    let verifier = flag(args, "--verifier")
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            (!verifier_ids.is_empty())
                .then(|| verifier_ids.into_iter().collect::<Vec<_>>().join(", "))
        });
    let agent_calls = flag(args, "--agent-calls").and_then(|s| s.parse::<u32>().ok());
    if hunters.is_none() || verifier.is_none() || agent_calls.is_none() {
        eprintln!(
            "warning: run metadata incomplete; pass --hunters <n>, --verifier <id>, and --agent-calls <n>. Unrecorded values render as \"not recorded\"."
        );
    }
    let meta = ReportMeta {
        repo: flag(args, "--repo").unwrap_or_else(|| "target".into()),
        source_ref: flag(args, "--ref").unwrap_or_else(|| "working tree".into()),
        mode: flag(args, "--mode").unwrap_or_else(|| "advisory".into()),
        sandbox: flag(args, "--sandbox").unwrap_or_else(|| "not recorded".into()),
        coverage,
        sensors: sensors_summary,
        hunters,
        verifier,
        agent_calls,
        critic,
    };
    let dir = Path::new(&out);
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("REPORT.md"), render_markdown(&file, &meta))
        .map_err(|e| e.to_string())?;
    std::fs::write(dir.join("REPORT.html"), render_html(&file, &meta))
        .map_err(|e| e.to_string())?;
    std::fs::write(dir.join("findings.sarif.json"), render_sarif(&file, &meta))
        .map_err(|e| e.to_string())?;
    println!(
        "wrote {}, {}, {}",
        dir.join("REPORT.md").display(),
        dir.join("REPORT.html").display(),
        dir.join("findings.sarif.json").display()
    );
    Ok(())
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
}

fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > 12 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        // Use the directory entry's own type so a symlink is never followed out
        // of the target tree (is_dir() would resolve the link target).
        let Ok(ftype) = entry.file_type() else {
            continue;
        };
        if ftype.is_symlink() {
            continue;
        }
        let path = entry.path();
        if ftype.is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            if ["node_modules", ".git", ".next", "target", "dist"].contains(&name.as_str()) {
                continue;
            }
            walk(&path, depth + 1, out);
        } else if ftype.is_file() {
            out.push(path);
        }
    }
}

fn cmd_audit(args: &[String]) -> Result<(), String> {
    if args.first().map(|s| s.as_str()) != Some("init") {
        return Err("usage: omgs audit init --target <repo>".into());
    }
    let rest = &args[1..];
    let target_raw = flag(rest, "--target").ok_or("audit init requires --target <repo>")?;
    let target =
        std::fs::canonicalize(&target_raw).map_err(|e| format!("target {target_raw}: {e}"))?;
    let repo = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "target".into());
    let out = match flag(rest, "--out") {
        Some(o) => PathBuf::from(o),
        None => {
            let base = home().join(".local/share/omgs").join(&repo);
            let mut n = 1;
            loop {
                let candidate = base.join(format!("run-{n}"));
                if !candidate.exists() {
                    break candidate;
                }
                n += 1;
            }
        }
    };
    let out_abs = if out.is_absolute() {
        out.clone()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(&out)
    };
    if out_abs.starts_with(&target) {
        return Err(
            "run output must live outside the target tree, so findings never enter git history"
                .into(),
        );
    }
    std::fs::create_dir_all(&out_abs).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&out_abs, std::fs::Permissions::from_mode(0o700));
    }
    if out_abs.starts_with("/tmp") || out_abs.starts_with("/private/tmp") {
        eprintln!("warning: run output is under a shared temp directory and describes vulnerabilities. Prefer the default runs directory under your home.");
    }
    let mode = flag(rest, "--mode").unwrap_or_else(|| "advisory".into());
    if mode != "gate" && mode != "advisory" {
        return Err("--mode must be gate or advisory".into());
    }
    let budget: Option<u64> = flag(rest, "--budget").and_then(|v| v.parse().ok());
    let source_ref = std::process::Command::new("git")
        .args([
            "-C",
            &target.to_string_lossy(),
            "rev-parse",
            "--short",
            "HEAD",
        ])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "working tree".into());
    let mut files = Vec::new();
    walk(&target, 0, &mut files);
    let rel_paths: Vec<String> = files
        .iter()
        .map(|f| {
            f.strip_prefix(&target)
                .unwrap_or(f)
                .to_string_lossy()
                .to_string()
        })
        .collect();
    let vendored_count = rel_paths
        .iter()
        .filter(|p| omgs::is_vendored_path(p))
        .count();
    let first_party: Vec<String> = rel_paths
        .iter()
        .filter(|p| !omgs::is_vendored_path(p))
        .cloned()
        .collect();
    let stacks = omgs::detect_stacks(&first_party);
    let mut units = Vec::new();
    for rel in &first_party {
        let is_route = rel.ends_with("/route.ts")
            || rel.ends_with("/route.tsx")
            || rel.contains("/pages/api/");
        if is_route {
            units.push(Unit::new(
                &format!("route:{rel}"),
                rel,
                &["missing_authz", "idor_tenant_isolation", "client_only_auth"],
                "planned",
            ));
        }
    }
    for stack in &stacks {
        units.push(Unit::new(
            &format!("stack:{stack}"),
            ".",
            &omgs::stack_attack_classes(stack),
            "planned",
        ));
    }
    if vendored_count > 0 {
        let mut unit = Unit::new(
            "vendored:excluded",
            &format!("{vendored_count} vendored or generated file(s)"),
            &[],
            "out_of_scope",
        );
        unit.note = Some("vendored or generated code is excluded from hunting by default".into());
        units.push(unit);
    }
    if units.is_empty() {
        units.push(Unit::new(
            "surface:whole-repo",
            ".",
            &["missing_authz", "input_validation"],
            "planned",
        ));
    }
    let ledger = Ledger {
        units,
        ..Ledger::default()
    };
    let started_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let meta = serde_json::json!({
        "repo": repo, "target": target.to_string_lossy(), "source_ref": source_ref,
        "mode": mode, "budget_agent_calls": budget, "profile": "standard",
        "execution_policy": "sandboxed-source-and-local-only", "run_status": "in_progress",
        "detected_stacks": stacks.clone(),
        "files_total": rel_paths.len(),
        "files_first_party": first_party.len(),
        "files_vendored_excluded": vendored_count,
        "started_unix": started_unix,
        "agent_calls_used": null,
        "hunter": flag(rest, "--hunter"),
        "verifier": flag(rest, "--verifier")
    });
    std::fs::write(
        out_abs.join("run-metadata.json"),
        serde_json::to_string_pretty(&meta).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(
        out_abs.join("coverage-ledger.json"),
        serde_json::to_string_pretty(&ledger).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(out_abs.join("findings.json"), "{\n  \"findings\": []\n}\n")
        .map_err(|e| e.to_string())?;
    let arch_seed = serde_json::json!({
        "target": target.to_string_lossy(),
        "source_ref": source_ref,
        "stack": {
            "notes": format!(
                "Detected stacks: {}. Files: {} total, {} first party, {} vendored excluded.",
                if stacks.is_empty() { "none recognized".to_string() } else { stacks.join(", ") },
                rel_paths.len(),
                first_party.len(),
                vendored_count
            )
        },
        "zones": [],
        "components": [],
        "notes": "Seeded by omgs audit. The reconnaissance agent fills zones, components, principals, boundaries, flows, and input_surfaces, records what was not examined in 'unexamined', then renders the map with: omgs architecture --in architecture.json --out <run-dir>."
    });
    std::fs::write(
        out_abs.join("architecture.json"),
        format!("{}\n", serde_json::to_string_pretty(&arch_seed).unwrap()),
    )
    .map_err(|e| e.to_string())?;
    if !has(rest, "--no-sensors") {
        let sensors = run_sensors(&target, &out_abs);
        std::fs::write(
            out_abs.join("sensors.json"),
            serde_json::to_string_pretty(&sensors).unwrap_or_default(),
        )
        .map_err(|e| e.to_string())?;
    }
    println!("{}", out_abs.display());
    Ok(())
}

fn copy_dir(src: &Path, dst: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dst).map_err(|e| e.to_string())?;
    for entry in std::fs::read_dir(src).map_err(|e| e.to_string())?.flatten() {
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_dir(&from, &to)?;
        } else {
            std::fs::copy(&from, &to).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn cmd_setup(args: &[String]) -> Result<(), String> {
    let from = flag(args, "--from")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("skill"));
    let candidates = [
        home().join(".claude/skills/omgs"),
        home().join(".codex/skills/omgs"),
        home().join(".agents/skills/omgs"),
    ];
    let detected: Vec<&PathBuf> = candidates
        .iter()
        .filter(|p| {
            p.parent()
                .and_then(|s| s.parent())
                .map(|h| h.exists())
                .unwrap_or(false)
        })
        .collect();
    println!("skill source: {}", from.display());
    if detected.is_empty() {
        println!(
            "no known agent home detected, default target: {}",
            candidates[2].display()
        );
    }
    for target in &candidates {
        println!("skill target: {}", target.display());
    }
    if !has(args, "--yes") {
        println!("dry run. Rerun with --yes to install the skill pack into the targets above.");
        return Ok(());
    }
    if !from.exists() {
        return Err(format!(
            "skill source {} not found, run setup from the OMGS repository or pass --from",
            from.display()
        ));
    }
    let targets: Vec<&PathBuf> = if detected.is_empty() {
        vec![&candidates[2]]
    } else {
        detected
    };
    for target in targets {
        copy_dir(&from, target)?;
        println!("installed: {}", target.display());
    }
    Ok(())
}

fn cmd_check(args: &[String]) -> Result<(), String> {
    let target_raw = flag(args, "--target").ok_or("check requires --target <repo>")?;
    let target = std::fs::canonicalize(&target_raw).map_err(|e| e.to_string())?;
    for tool in ["gitleaks", "trufflehog", "osv-scanner", "semgrep"] {
        let present = std::process::Command::new("which")
            .arg(tool)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        println!(
            "sensor {tool}: {}",
            if present {
                "available"
            } else {
                "not installed"
            }
        );
    }
    let mut files = Vec::new();
    walk(&target, 0, &mut files);
    let proofs = files
        .iter()
        .filter(|f| {
            let s = f.to_string_lossy();
            s.contains("/tests/security/")
                || s.contains(".security.test.")
                || s.contains(".security.spec.")
        })
        .count();
    println!("committed proof tests found: {proofs}");
    let scratch = flag(args, "--out")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".local/share/omgs/prove-scratch"));
    std::fs::create_dir_all(&scratch).map_err(|e| e.to_string())?;
    let sensors = run_sensors(&target, &scratch);
    for tool in &sensors.tools_run {
        let hits: Vec<_> = sensors.hits.iter().filter(|h| &h.tool == tool).collect();
        let vendored = hits.iter().filter(|h| h.vendored).count();
        println!(
            "sensor {tool} ran: {} hit(s), {} vendored",
            hits.len(),
            vendored
        );
        for h in hits.iter().take(10) {
            println!(
                "  {} {}:{} vendored={}",
                h.rule,
                h.file,
                h.line.unwrap_or(0),
                h.vendored
            );
        }
    }
    if let Some(out) = flag(args, "--out") {
        let dir = PathBuf::from(out);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        std::fs::write(
            dir.join("sensors.json"),
            serde_json::to_string_pretty(&sensors).unwrap_or_default(),
        )
        .map_err(|e| e.to_string())?;
    }
    println!("check is deterministic and executes no target code. Run proof tests through: omgs prove --cmd <test command>");
    Ok(())
}

fn read_ledger(path: &str) -> Result<Ledger, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("parse {path}: {e}"))
}

fn write_ledger(path: &str, ledger: &Ledger) -> Result<(), String> {
    let text = serde_json::to_string_pretty(ledger).map_err(|e| e.to_string())?;
    std::fs::write(path, format!("{text}\n")).map_err(|e| format!("write {path}: {e}"))
}

/// Every value given for a repeatable flag, in order.
fn flags(args: &[String], name: &str) -> Vec<String> {
    args.windows(2)
        .filter(|w| w[0] == name)
        .map(|w| w[1].clone())
        .collect()
}

fn cmd_ledger(args: &[String]) -> Result<(), String> {
    let usage = "usage: omgs ledger list|add|set --ledger <file> ...";
    let sub = args.first().map(|s| s.as_str()).ok_or(usage)?;
    let rest = &args[1..];
    let path = flag(rest, "--ledger").ok_or("ledger requires --ledger <file>")?;
    let mut ledger = read_ledger(&path)?;
    match sub {
        "list" => {
            for line in coverage_lines(&ledger) {
                println!("{line}");
            }
            let errors = validate_ledger(&ledger);
            for e in &errors {
                eprintln!("invalid: {e}");
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err("__EXIT1__".into())
            }
        }
        "add" => {
            let unit = flag(rest, "--unit").ok_or("ledger add requires --unit <id>")?;
            let surface = flag(rest, "--surface").ok_or("ledger add requires --surface <s>")?;
            let classes = flag(rest, "--classes").unwrap_or_default();
            let classes: Vec<&str> = classes
                .split(',')
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .collect();
            let status = flag(rest, "--status").unwrap_or_else(|| "planned".into());
            let mut new = Unit::new(&unit, &surface, &classes, &status);
            new.note = flag(rest, "--note").filter(|n| !n.trim().is_empty());
            add_unit(&mut ledger, new)?;
            write_ledger(&path, &ledger)?;
            println!("{unit}: {status}");
            Ok(())
        }
        "set" => {
            let unit = flag(rest, "--unit").ok_or("ledger set requires --unit <id>")?;
            let status = flag(rest, "--status").ok_or("ledger set requires --status <status>")?;
            if !STATUSES.contains(&status.as_str()) {
                return Err(format!("--status must be one of {}", STATUSES.join(", ")));
            }
            let evidence = flags(rest, "--evidence");
            let note = flag(rest, "--note");
            set_status(&mut ledger, &unit, &status, &evidence, note.as_deref())?;
            write_ledger(&path, &ledger)?;
            println!("{unit}: {status}");
            Ok(())
        }
        _ => Err(usage.into()),
    }
}

fn cmd_critic(args: &[String]) -> Result<(), String> {
    let run = flag(args, "--run").ok_or("critic requires --run <run-dir>")?;
    let report = critique_run(Path::new(&run))?;
    for gap in &report.gaps {
        eprintln!("gap: {gap}");
    }
    println!("critic: {}", report.summary());
    if report.passed() {
        Ok(())
    } else {
        Err("__EXIT1__".into())
    }
}

fn cmd_review(args: &[String]) -> Result<(), String> {
    let url = flag(args, "--repo-url").ok_or("review requires --repo-url <url>")?;
    let name = url
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("target")
        .trim_end_matches(".git")
        .to_string();
    let dest = home().join(".local/share/omgs/targets").join(&name);
    if !dest.exists() {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let status = std::process::Command::new("git")
            .args(["clone", "--depth", "1", &url, &dest.to_string_lossy()])
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("git clone failed for {url}"));
        }
    }
    let mut init_args = vec![
        "init".to_string(),
        "--target".to_string(),
        dest.to_string_lossy().to_string(),
    ];
    if let Some(mode) = flag(args, "--mode") {
        init_args.push("--mode".into());
        init_args.push(mode);
    }
    if let Some(budget) = flag(args, "--budget") {
        init_args.push("--budget".into());
        init_args.push(budget);
    }
    cmd_audit(&init_args)?;
    println!("agent brief: load the omgs skill, follow its pipeline against {}, validate findings with omgs validate, prove only through omgs prove, and render with omgs report.", dest.display());
    Ok(())
}
