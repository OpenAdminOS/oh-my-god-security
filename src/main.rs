use omgs::model::{validate, FindingsFile};
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
        "omgs {}\n\nUsage:\n  omgs setup [--yes] [--from <skill-dir>]\n  omgs review --repo-url <url> [--mode gate|advisory] [--budget <n>]\n  omgs audit init --target <repo> [--out <run-dir>] [--mode gate|advisory] [--budget <n>] [--no-sensors]\n  omgs validate --findings <findings.json>\n  omgs fingerprint --attack-class <c> --entry-point <e> --sink <s> --boundary <b>\n  omgs prove --cmd <command> [--cwd <dir>] [--scratch <dir>] [--timeout-ms <n>]\n  omgs report --findings <findings.json> --out <dir> [--repo <name>] [--ref <ref>] [--mode gate|advisory] [--sandbox <label>] [--hunters <n>] [--verifier <id>] [--agent-calls <n>]\n  omgs ledger set --ledger <coverage-ledger.json> --unit <id> --status <status>\n  omgs check --target <repo> [--out <run-dir>]\n",
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
        "ledger" => cmd_ledger(rest),
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
    let findings_dir = Path::new(&path).parent().map(|p| p.to_path_buf());
    let mut coverage: Vec<String> = Vec::new();
    if let Some(dir) = &findings_dir {
        if let Ok(text) = std::fs::read_to_string(dir.join("coverage-ledger.json")) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(units) = v.get("units").and_then(|u| u.as_array()) {
                    for u in units {
                        coverage.push(format!(
                            "{}: {}",
                            u.get("status")
                                .and_then(|s| s.as_str())
                                .unwrap_or("planned"),
                            u.get("id").and_then(|s| s.as_str()).unwrap_or("unit")
                        ));
                    }
                }
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
    let hunters = flag(args, "--hunters").and_then(|s| s.parse::<u32>().ok());
    let verifier = flag(args, "--verifier");
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
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if ["node_modules", ".git", ".next", "target", "dist"].contains(&name.as_str()) {
                continue;
            }
            walk(&path, depth + 1, out);
        } else {
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
            units.push(serde_json::json!({
                "id": format!("route:{}", rel),
                "surface": rel,
                "attack_classes": ["missing_authz", "idor_tenant_isolation", "client_only_auth"],
                "status": "planned"
            }));
        }
    }
    for stack in &stacks {
        units.push(serde_json::json!({
            "id": format!("stack:{}", stack),
            "surface": ".",
            "attack_classes": omgs::stack_attack_classes(stack),
            "status": "planned"
        }));
    }
    if vendored_count > 0 {
        units.push(serde_json::json!({
            "id": "vendored:excluded",
            "surface": format!("{} vendored or generated file(s)", vendored_count),
            "attack_classes": [],
            "status": "out_of_scope"
        }));
    }
    if units.is_empty() {
        units.push(serde_json::json!({
            "id": "surface:whole-repo",
            "surface": ".",
            "attack_classes": ["missing_authz", "input_validation"],
            "status": "planned"
        }));
    }
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
        serde_json::to_string_pretty(&serde_json::json!({ "units": units })).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(out_abs.join("findings.json"), "{\n  \"findings\": []\n}\n")
        .map_err(|e| e.to_string())?;
    std::fs::write(
        out_abs.join("architecture.md"),
        format!(
            "# Architecture\n\nSeeded deterministically by omgs. Detected stacks: {}. Files: {} total, {} first party, {} vendored excluded. The auditing agent completes trust boundaries, input surfaces and data flows here during reconnaissance, and states what was not examined.\n",
            if stacks.is_empty() { "none recognized".to_string() } else { stacks.join(", ") },
            rel_paths.len(),
            first_party.len(),
            vendored_count
        ),
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

fn cmd_ledger(args: &[String]) -> Result<(), String> {
    if args.first().map(|s| s.as_str()) != Some("set") {
        return Err("usage: omgs ledger set --ledger <file> --unit <id> --status <status>".into());
    }
    let rest = &args[1..];
    let path = flag(rest, "--ledger").ok_or("ledger set requires --ledger <file>")?;
    let unit = flag(rest, "--unit").ok_or("ledger set requires --unit <id>")?;
    let status = flag(rest, "--status").ok_or("ledger set requires --status <status>")?;
    let valid = [
        "planned",
        "candidate",
        "covered",
        "deferred",
        "blocked",
        "out_of_scope",
    ];
    if !valid.contains(&status.as_str()) {
        return Err(format!("--status must be one of {}", valid.join(", ")));
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("read {path}: {e}"))?;
    let mut value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("parse {path}: {e}"))?;
    let units = value
        .get_mut("units")
        .and_then(|u| u.as_array_mut())
        .ok_or("ledger has no units array")?;
    let mut found = false;
    for u in units.iter_mut() {
        if u.get("id").and_then(|v| v.as_str()) == Some(unit.as_str()) {
            u["status"] = serde_json::json!(status);
            found = true;
        }
    }
    if !found {
        return Err(format!("ledger unit not found: {unit}"));
    }
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&value).unwrap_or_default(),
    )
    .map_err(|e| e.to_string())?;
    println!("{unit}: {status}");
    Ok(())
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
    println!("agent brief: load the omgs skill, follow its six phases against {}, validate findings with omgs validate, prove only through omgs prove, and render with omgs report.", dest.display());
    Ok(())
}
