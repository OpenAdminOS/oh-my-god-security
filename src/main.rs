use omgs::architecture::{
    render_architecture_html, render_architecture_markdown, validate_architecture, ArchitectureFile,
};
use omgs::critic::{critique_dir, critique_run};
use omgs::ledger::{add_unit, coverage_lines, set_status, validate_ledger, Ledger, Unit, STATUSES};
use omgs::model::{identity, validate, FindingsFile};
use omgs::report::{render_html, render_markdown, render_sarif, ReportMeta};
use omgs::sandbox::{prove, ProveOutcome, ProveRequest};
use omgs::sensors::run_sensors;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The value after `name`. A following token that is itself an option means
/// the value is missing, never that the option name is the value.
fn flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].clone())
        .filter(|v| !v.starts_with("--"))
}
fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn usage() {
    eprintln!(
        "omgs {}\n\nUsage:\n  omgs setup [--yes] [--from <skill-dir>]\n  omgs review --repo-url <https-url> [--mode gate|advisory] [--budget <n>] [--no-sensors]\n  omgs batch init --list <file> --out <dir> [--mode gate|advisory] [--budget <n>] [--no-sensors]\n  omgs batch index --batch <batch.json> --out <dir>\n  omgs audit init --target <repo> [--out <run-dir>] [--mode gate|advisory] [--budget <n>] [--no-sensors]\n  omgs validate --findings <findings.json>\n  omgs fingerprint --attack-class <c> --entry-point <e> --sink <s> --boundary <b>\n  omgs prove --cmd <command> [--cwd <dir>] [--scratch <dir>] [--timeout-ms <n>]\n  omgs report --findings <findings.json> --out <dir> [--repo <name>] [--ref <ref>] [--mode gate|advisory] [--sandbox <label>] [--hunters <n>] [--verifier <id>] [--agent-calls <n>]\n  omgs architecture --in <architecture.json> --out <dir>\n  omgs ledger list --ledger <coverage-ledger.json>\n  omgs ledger add --ledger <coverage-ledger.json> --unit <id> --surface <s> [--classes a,b] [--status <status>] [--note <text>]\n  omgs ledger set --ledger <coverage-ledger.json> --unit <id> --status <status> [--evidence <ref>]... [--note <text>]\n  omgs critic --run <run-dir>\n  omgs status --run <run-dir> --stage <id> --state pending|active|done|failed [--label <l>] [--parent <id>] [--detail <d>] [--counter name=n]... [--log <m>]\n  omgs watch --run <run-dir> [--max-ms <n>]\n  omgs route --run <run-dir> --role hunter|verifier|evaluator|guard [--refused <model> --reason <text>] [--models <models.json>]\n  omgs intent list [--stack <s>] [--attack-class <c>]\n  omgs intent answer --target <repo> --id <id> --answer <text> --source <who> [--scope repo|<path>]\n  omgs check --target <repo> [--out <run-dir>]\n\nEvery option except --yes and --no-sensors takes a value, and a value may not begin with --.\n",
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
    // Every option except the switches takes a value; a missing one is an
    // error rather than being skipped or taking the next option's name.
    const SWITCHES: [&str; 2] = ["--yes", "--no-sensors"];
    for (i, a) in rest.iter().enumerate() {
        if a.starts_with("--") && !SWITCHES.contains(&a.as_str()) {
            match rest.get(i + 1) {
                Some(v) if !v.starts_with("--") => {}
                _ => {
                    eprintln!("error: {a} requires a value");
                    return ExitCode::from(2);
                }
            }
        }
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
        "batch" => cmd_batch(rest),
        "status" => cmd_status(rest),
        "watch" => cmd_watch(rest),
        "route" => cmd_route(rest),
        "intent" => cmd_intent(rest),
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
    omgs::shape::findings(&text).map_err(|e| format!("parse {path}: {e}"))
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
        // An absent ledger means the critic does not apply; a ledger or
        // candidates file that exists but does not parse is an error, so a
        // malformed run can never render as a clean report.
        let ledger_path = dir.join("coverage-ledger.json");
        // symlink_metadata sees a dangling link that exists() reports as
        // absent; only a genuinely missing entry skips the critic.
        let present = match std::fs::symlink_metadata(&ledger_path) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(format!("inspect {}: {e}", ledger_path.display())),
        };
        if !present {
            // Without a ledger the critic does not apply, but candidate files
            // mean a pipeline ran: refuse rather than report over them.
            let has_candidates = std::fs::read_dir(dir)
                .map_err(|e| format!("read {}: {e}", dir.display()))?
                .flatten()
                .any(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    name.starts_with("candidates") && name.ends_with(".json")
                });
            if has_candidates {
                return Err(format!(
                    "{} has candidates files but no coverage-ledger.json; restore the ledger so the critic can run",
                    dir.display()
                ));
            }
        }
        if present {
            let text = std::fs::read_to_string(&ledger_path)
                .map_err(|e| format!("read {}: {e}", ledger_path.display()))?;
            let ledger = omgs::shape::ledger(&text)
                .map_err(|e| format!("parse {}: {e}", ledger_path.display()))?;
            coverage = coverage_lines(&ledger);
            let c = critique_dir(dir, &file)?;
            if !c.passed() {
                eprintln!(
                    "warning: coverage critic found {} gap(s); they are listed in the report. Run omgs critic --run {} for detail.",
                    c.gaps.len(),
                    dir.display()
                );
            }
            critic = Some(c);
        }
    }
    let mut sensors_summary: Option<String> = None;
    if let Some(dir) = &findings_dir {
        let path = dir.join("sensors.json");
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => Some(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("read {}: {e}", path.display())),
        };
        if let Some(text) = text {
            {
                let rep = omgs::shape::sensors(&text)
                    .map_err(|e| format!("parse {}: {e}", path.display()))?;
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
    // Verifier identities recorded on the findings stand in for an unpassed
    // --verifier. The hunter count is not inferred: hunters that found nothing
    // or were merged into another record would be missed.
    let verifier_ids: std::collections::BTreeSet<String> = file
        .findings
        .iter()
        .filter_map(|f| identity(&f.verified_by))
        .collect();
    let hunters = flag(args, "--hunters").and_then(|s| s.parse::<u32>().ok());
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
        models: run_models(findings_dir.as_deref()),
        reroutes: run_reroutes(findings_dir.as_deref()),
        intent_answers: run_answers(findings_dir.as_deref())?,
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
    // Record what this report rendered in the run metadata and mark the run
    // complete, which also lets a running omgs watch shut itself down.
    if let Some(run) = findings_dir
        .as_deref()
        .filter(|d| d.join(omgs::runmeta::FILE).is_file())
    {
        omgs::runmeta::update(run, |m| {
            if let Some(n) = meta.hunters {
                m.insert("hunters".into(), serde_json::json!(n));
            }
            if let Some(v) = &meta.verifier {
                m.insert("verifier".into(), serde_json::json!(v));
            }
            if let Some(n) = meta.agent_calls {
                m.insert("agent_calls_used".into(), serde_json::json!(n));
            }
            m.insert("run_status".into(), serde_json::json!("complete"));
            m.insert(
                "completed_unix".into(),
                serde_json::json!(omgs::runmeta::now_unix()),
            );
            Ok(())
        })?;
    }
    Ok(())
}

/// The run's intent answers, only when they belong to the run's target as
/// recorded in run metadata; anything else is ignored with a warning.
fn run_answers(dir: Option<&Path>) -> Result<omgs::intent::Answers, String> {
    let Some(dir) = dir else {
        return Ok(Default::default());
    };
    let answers = omgs::intent::load_answers(&dir.join("intent-answers.json"))?;
    if answers.answers.is_empty() {
        return Ok(answers);
    }
    // Provenance: answers render only when the run directory sits outside the
    // target it names, and each answer also exists in the reviewer's own
    // store for that target. Files next to the findings could have been
    // written by the target itself, so matching them to each other proves
    // nothing.
    let refuse = |why: &str| {
        eprintln!("warning: intent answers not shown: {why}");
        Ok(Default::default())
    };
    let target = omgs::runmeta::read(dir)
        .ok()
        .and_then(|m| m.get("target").and_then(|t| t.as_str()).map(PathBuf::from))
        .and_then(|t| std::fs::canonicalize(t).ok());
    let Some(target) = target else {
        return refuse("run metadata names no existing target");
    };
    let run = std::fs::canonicalize(dir).map_err(|e| e.to_string())?;
    if run.starts_with(&target) {
        return refuse("the run directory is inside the target");
    }
    if Path::new(&answers.target) != target {
        return refuse("they belong to a different target");
    }
    let store = omgs::intent::load_answers(&omgs::intent::answers_file(
        &home().join(".local/share/omgs"),
        &target,
    ))?;
    let total = answers.answers.len();
    let kept: Vec<_> = answers
        .answers
        .into_iter()
        .filter(|a| store.answers.contains(a))
        .collect();
    if kept.len() < total {
        eprintln!(
            "warning: {} intent answer(s) not in the reviewer's store were not shown",
            total - kept.len()
        );
    }
    Ok(omgs::intent::Answers {
        target: answers.target,
        answers: kept,
    })
}

/// "role: model" lines from run metadata `models`, sorted by role.
fn run_models(dir: Option<&Path>) -> Vec<String> {
    let Some(meta) = dir.and_then(|d| omgs::runmeta::read(d).ok()) else {
        return Vec::new();
    };
    meta.get("models")
        .and_then(|m| m.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(role, model)| model.as_str().map(|v| format!("{role}: {v}")))
                .collect()
        })
        .unwrap_or_default()
}

/// One line per recorded reroute, in the order they happened.
fn run_reroutes(dir: Option<&Path>) -> Vec<String> {
    let Some(meta) = dir.and_then(|d| omgs::runmeta::read(d).ok()) else {
        return Vec::new();
    };
    meta.get("reroutes")
        .and_then(|r| r.as_array())
        .map(|list| {
            list.iter()
                .map(|r| {
                    let get = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("none");
                    format!(
                        "{} {} to {} ({})",
                        get("role"),
                        get("from"),
                        get("to"),
                        get("reason")
                    )
                })
                .collect()
        })
        .unwrap_or_default()
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
    let run = audit_init(&args[1..])?;
    println!("{}", run.display());
    Ok(())
}

/// Resolve `p` physically through its nearest existing ancestor, so every
/// symlink (and any `..` after one) is followed by the OS before the
/// outside-the-target check. A `..` that follows a missing directory cannot be
/// resolved, so it fails closed rather than being guessed lexically.
fn resolve_existing_prefix(p: &Path) -> Result<PathBuf, String> {
    let mut existing = p.to_path_buf();
    let mut rest = Vec::new();
    while !existing.exists() {
        match (existing.file_name(), existing.parent()) {
            (Some(name), Some(parent)) => {
                rest.push(name.to_os_string());
                existing = parent.to_path_buf();
            }
            _ => {
                return Err(format!(
                    "cannot resolve {} ('..' after a missing directory); use a path without it",
                    p.display()
                ))
            }
        }
    }
    let mut resolved = std::fs::canonicalize(&existing)
        .map_err(|e| format!("resolve {}: {e}", existing.display()))?;
    for name in rest.iter().rev() {
        resolved.push(name);
    }
    Ok(resolved)
}

/// Initialize a run and return its directory.
fn audit_init(rest: &[String]) -> Result<PathBuf, String> {
    let target_raw = flag(rest, "--target").ok_or("audit init requires --target <repo>")?;
    let target =
        std::fs::canonicalize(&target_raw).map_err(|e| format!("target {target_raw}: {e}"))?;
    let repo = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "target".into());
    let outside = |p: &Path| -> Result<(), String> {
        if resolve_existing_prefix(p)?.starts_with(&target) {
            Err(
                "run output must live outside the target tree, so findings never enter git history"
                    .into(),
            )
        } else {
            Ok(())
        }
    };
    let out_abs = match flag(rest, "--out") {
        Some(o) => {
            let out = PathBuf::from(o);
            let out_abs = if out.is_absolute() {
                out
            } else {
                std::env::current_dir()
                    .map_err(|e| e.to_string())?
                    .join(&out)
            };
            outside(&out_abs)?;
            // A run directory is always fresh: reusing one would overwrite a
            // finished run or mix two targets' evidence and answers.
            if std::fs::read_dir(&out_abs).is_ok_and(|mut d| d.next().is_some()) {
                return Err(format!(
                    "{} already exists and is not empty; choose a new run directory",
                    out_abs.display()
                ));
            }
            std::fs::create_dir_all(&out_abs).map_err(|e| e.to_string())?;
            out_abs
        }
        None => {
            // Claim run-N with an exclusive create, so parallel inits (batch
            // mode) never share a run directory.
            let base = home().join(".local/share/omgs").join(&repo);
            std::fs::create_dir_all(&base).map_err(|e| e.to_string())?;
            let mut n = 1;
            loop {
                let candidate = base.join(format!("run-{n}"));
                outside(&candidate)?;
                match std::fs::create_dir(&candidate) {
                    Ok(()) => break candidate,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => n += 1,
                    Err(e) => return Err(format!("create {}: {e}", candidate.display())),
                }
            }
        }
    };
    // The check above ran before creation; recheck the created directory in
    // case a link was swapped in between.
    outside(&std::fs::canonicalize(&out_abs).map_err(|e| e.to_string())?)?;
    // Claim the directory exclusively, so two concurrent inits given the same
    // --out cannot both pass the emptiness check and overwrite each other.
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out_abs.join(".omgs-claim"))
        .map_err(|e| {
            format!(
                "{} is already claimed by another run ({e}); choose a new run directory",
                out_abs.display()
            )
        })?;
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
    // Bring the reviewer's recorded intent answers for this exact target into
    // the run, so earlier answers resolve matching questions in the report.
    let answers_src = omgs::intent::answers_file(&home().join(".local/share/omgs"), &target);
    if answers_src.is_file() {
        let answers = omgs::intent::load_answers(&answers_src)?;
        if Path::new(&answers.target) == target {
            let text = serde_json::to_string_pretty(&answers).map_err(|e| e.to_string())?;
            std::fs::write(out_abs.join("intent-answers.json"), format!("{text}\n"))
                .map_err(|e| format!("copy intent answers: {e}"))?;
        } else {
            eprintln!(
                "warning: {} belongs to {}, not {}; intent answers not copied",
                answers_src.display(),
                answers.target,
                target.display()
            );
        }
    }
    Ok(out_abs)
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
    omgs::shape::ledger(&text).map_err(|e| format!("parse {path}: {e}"))
}

fn write_ledger(path: &str, ledger: &Ledger) -> Result<(), String> {
    let text = serde_json::to_string_pretty(ledger).map_err(|e| e.to_string())?;
    omgs::runmeta::write_atomic(Path::new(path), &format!("{text}\n"))
}

/// Every value given for a repeatable flag, in order.
fn flags(args: &[String], name: &str) -> Vec<String> {
    args.windows(2)
        .filter(|w| w[0] == name && !w[1].starts_with("--"))
        .map(|w| w[1].clone())
        .collect()
}

fn cmd_ledger(args: &[String]) -> Result<(), String> {
    let usage = "usage: omgs ledger list|add|set --ledger <file> ...";
    let sub = args.first().map(|s| s.as_str()).ok_or(usage)?;
    let rest = &args[1..];
    let path = flag(rest, "--ledger").ok_or("ledger requires --ledger <file>")?;
    let lock = Path::new(&path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .join(".omgs-run.lock");
    omgs::runmeta::with_lock_file(&lock, || ledger_locked(sub, rest, &path))
}

fn ledger_locked(sub: &str, rest: &[String], path: &str) -> Result<(), String> {
    let usage = "usage: omgs ledger list|add|set --ledger <file> ...";
    let path = path.to_string();
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

/// Clone (or reuse) a repository for review. Only validated https URLs reach
/// git, as a positional argument after `--`, with every other transport
/// disabled and no prompts; a reused clone must have the same origin.
fn clone_target(raw_url: &str) -> Result<PathBuf, String> {
    let repo = omgs::batch::parse_repo_url(raw_url)?;
    let targets = home().join(".local/share/omgs/targets");
    let dest = targets.join(&repo.host).join(&repo.owner).join(&repo.name);
    let git = || {
        let mut c = std::process::Command::new("git");
        c.env("GIT_TERMINAL_PROMPT", "0").args([
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
        ]);
        c
    };
    if dest.exists() {
        let origin = git()
            .args(["-C", &dest.to_string_lossy(), "remote", "get-url", "origin"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
        if origin.as_deref() != Some(repo.url.as_str()) {
            return Err(format!(
                "{} exists but its origin is {}, not {}; remove it or review that URL",
                dest.display(),
                origin.as_deref().unwrap_or("unknown"),
                repo.url
            ));
        }
        return Ok(dest);
    }
    let parent = dest.parent().ok_or("invalid clone destination")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&targets, std::fs::Permissions::from_mode(0o700));
    }
    let status = git()
        .args(["clone", "--depth", "1", "--no-recurse-submodules", "--"])
        .arg(&repo.url)
        .arg(&dest)
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        let _ = std::fs::remove_dir_all(&dest);
        return Err(format!("git clone failed for {}", repo.url));
    }
    Ok(dest)
}

fn init_args(dest: &Path, args: &[String], out: Option<&Path>) -> Vec<String> {
    let mut v = vec!["--target".to_string(), dest.to_string_lossy().to_string()];
    for name in ["--mode", "--budget"] {
        if let Some(value) = flag(args, name) {
            v.push(name.into());
            v.push(value);
        }
    }
    if let Some(o) = out {
        v.push("--out".into());
        v.push(o.to_string_lossy().to_string());
    }
    if has(args, "--no-sensors") {
        v.push("--no-sensors".into());
    }
    v
}

fn brief(dest: &Path, run: &Path) -> String {
    format!("agent brief: load the omgs skill, follow its pipeline against {} with run directory {}, validate findings with omgs validate, prove only through omgs prove, reconcile with omgs critic, and render with omgs report.", dest.display(), run.display())
}

fn cmd_review(args: &[String]) -> Result<(), String> {
    let url = flag(args, "--repo-url").ok_or("review requires --repo-url <url>")?;
    let dest = clone_target(&url)?;
    let run = audit_init(&init_args(&dest, args, None))?;
    println!("{}", run.display());
    println!("{}", brief(&dest, &run));
    Ok(())
}

fn cmd_batch(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(|s| s.as_str());
    let rest = args.get(1..).unwrap_or_default();
    match sub {
        Some("init") => {
            let list = flag(rest, "--list").ok_or("batch init requires --list <file>")?;
            let out = PathBuf::from(flag(rest, "--out").ok_or("batch init requires --out <dir>")?);
            let text = std::fs::read_to_string(&list).map_err(|e| format!("read {list}: {e}"))?;
            let urls = omgs::batch::read_list(&text);
            if urls.is_empty() {
                return Err(format!("{list} lists no repository URLs"));
            }
            // The batch output must sit outside the targets area and every
            // target in the list, including ones that later fail to clone.
            let targets_root = home().join(".local/share/omgs/targets");
            let dests: Vec<PathBuf> = urls
                .iter()
                .filter_map(|u| omgs::batch::parse_repo_url(u).ok())
                .map(|r| targets_root.join(&r.host).join(&r.owner).join(&r.name))
                .collect();
            let out_abs = if out.is_absolute() {
                out.clone()
            } else {
                std::env::current_dir().map_err(|e| e.to_string())?.join(&out)
            };
            let resolved = resolve_existing_prefix(&out_abs)?;
            for t in std::iter::once(&targets_root).chain(&dests) {
                if resolved.starts_with(resolve_existing_prefix(t)?) {
                    return Err(format!(
                        "batch output must live outside the reviewed targets, and {} is inside {}",
                        out_abs.display(),
                        t.display()
                    ));
                }
            }
            std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o700));
            }
            let out = std::fs::canonicalize(&out).map_err(|e| e.to_string())?;
            if out.join("batch.json").exists() {
                return Err(format!(
                    "{} already holds a batch; choose a new --out",
                    out.display()
                ));
            }
            let mut batch = omgs::batch::BatchFile {
                created_unix: omgs::runmeta::now_unix(),
                runs: Vec::new(),
            };
            for url in urls {
                let attempt = omgs::batch::parse_repo_url(&url).and_then(|r| {
                    // One path component per part keeps runs distinct: no
                    // separator inside a part can make two URLs collide.
                    let run_dir = out.join(&r.host).join(&r.owner).join(&r.name);
                    let dest = clone_target(&url)?;
                    let run = audit_init(&init_args(&dest, rest, Some(&run_dir)))?;
                    Ok((dest, run))
                });
                match attempt {
                    Ok((dest, run)) => {
                        println!("{}", brief(&dest, &run));
                        batch.runs.push(omgs::batch::BatchRun {
                            url,
                            target: Some(dest.to_string_lossy().to_string()),
                            run_dir: Some(run.to_string_lossy().to_string()),
                            status: "initialized".into(),
                            error: None,
                        });
                    }
                    Err(e) => {
                        eprintln!("failed: {url}: {e}");
                        // Keep the target path a valid URL maps to, so later
                        // containment checks still know it.
                        let target = omgs::batch::parse_repo_url(&url).ok().map(|r| {
                            targets_root
                                .join(&r.host)
                                .join(&r.owner)
                                .join(&r.name)
                                .to_string_lossy()
                                .to_string()
                        });
                        batch.runs.push(omgs::batch::BatchRun {
                            url,
                            target,
                            status: "failed".into(),
                            error: Some(e),
                            ..Default::default()
                        });
                    }
                }
            }
            let path = out.join("batch.json");
            let text = serde_json::to_string_pretty(&batch).map_err(|e| e.to_string())?;
            omgs::runmeta::write_atomic(&path, &format!("{text}\n"))?;
            let failed = batch.runs.iter().filter(|r| r.status == "failed").count();
            println!(
                "{}: {} initialized, {failed} failed",
                path.display(),
                batch.runs.len() - failed
            );
            if failed > 0 {
                Err("__EXIT1__".into())
            } else {
                Ok(())
            }
        }
        Some("index") => {
            let path = flag(rest, "--batch").ok_or("batch index requires --batch <batch.json>")?;
            let text = std::fs::read_to_string(&path).map_err(|e| format!("read {path}: {e}"))?;
            let batch =
                omgs::batch::parse_batch(&text).map_err(|e| format!("parse {path}: {e}"))?;
            let out = PathBuf::from(flag(rest, "--out").ok_or("batch index requires --out <dir>")?);
            let out_abs = if out.is_absolute() {
                out.clone()
            } else {
                std::env::current_dir().map_err(|e| e.to_string())?.join(&out)
            };
            let mut targets: Vec<PathBuf> = vec![resolve_existing_prefix(
                &home().join(".local/share/omgs/targets"),
            )?];
            for r in &batch.runs {
                if let Some(t) = r.target.as_deref() {
                    targets.push(resolve_existing_prefix(Path::new(t))?);
                }
            }
            let inside = |p: &Path| -> Result<(), String> {
                match targets.iter().find(|t| p.starts_with(t)) {
                    Some(t) => Err(format!(
                        "index output must live outside every reviewed target, and {} is inside {}",
                        out_abs.display(),
                        t.display()
                    )),
                    None => Ok(()),
                }
            };
            inside(&resolve_existing_prefix(&out_abs)?)?;
            std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
            // Recheck the directory as it now exists, before writing anything.
            let out = std::fs::canonicalize(&out).map_err(|e| e.to_string())?;
            inside(&out)?;
            let runs: Vec<_> = batch
                .runs
                .iter()
                .map(|r| omgs::batch::summarize(r, &out))
                .collect();
            std::fs::write(out.join("INDEX.md"), omgs::batch::render_index_markdown(&runs))
                .map_err(|e| e.to_string())?;
            std::fs::write(out.join("INDEX.html"), omgs::batch::render_index_html(&runs))
                .map_err(|e| e.to_string())?;
            println!(
                "wrote {}, {}",
                out.join("INDEX.md").display(),
                out.join("INDEX.html").display()
            );
            Ok(())
        }
        _ => Err("usage: omgs batch init --list <file> --out <dir> | omgs batch index --batch <batch.json> --out <dir>".into()),
    }
}

fn cmd_status(args: &[String]) -> Result<(), String> {
    let run = flag(args, "--run").ok_or("status requires --run <run-dir>")?;
    let stage = flag(args, "--stage").ok_or("status requires --stage <id>")?;
    let state = flag(args, "--state").ok_or("status requires --state <state>")?;
    let mut counters = Vec::new();
    for c in flags(args, "--counter") {
        let (k, v) = c
            .split_once('=')
            .ok_or_else(|| format!("--counter expects name=number, got '{c}'"))?;
        let n: u64 = v
            .parse()
            .map_err(|_| format!("--counter {k} needs a whole number"))?;
        counters.push((k.to_string(), n));
    }
    let label = flag(args, "--label");
    let parent = flag(args, "--parent");
    let detail = flag(args, "--detail");
    let log = flag(args, "--log");
    omgs::status::apply(
        Path::new(&run),
        &omgs::status::Update {
            stage: &stage,
            label: label.as_deref(),
            parent: parent.as_deref(),
            state: &state,
            detail: detail.as_deref(),
            counters: &counters,
            log: log.as_deref(),
        },
    )?;
    println!("{stage}: {state}");
    Ok(())
}

fn cmd_watch(args: &[String]) -> Result<(), String> {
    let run = PathBuf::from(flag(args, "--run").ok_or("watch requires --run <run-dir>")?);
    if !run.join(omgs::runmeta::FILE).is_file() {
        return Err(format!(
            "{} is not a run directory (no {})",
            run.display(),
            omgs::runmeta::FILE
        ));
    }
    let max_ms: u64 = match flag(args, "--max-ms") {
        Some(v) => v.parse().map_err(|_| "--max-ms needs a whole number")?,
        None => 4 * 60 * 60 * 1000,
    };
    let (listener, port) = omgs::watch::bind()?;
    println!("progress: http://127.0.0.1:{port}/ (loopback only; stops when the run completes)");
    omgs::watch::serve(
        listener,
        port,
        &run,
        std::time::Duration::from_millis(max_ms),
    );
    Ok(())
}

fn models_path(args: &[String]) -> PathBuf {
    flag(args, "--models")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".local/share/omgs/models.json"))
}

fn cmd_route(args: &[String]) -> Result<(), String> {
    let run = PathBuf::from(flag(args, "--run").ok_or("route requires --run <run-dir>")?);
    let role = flag(args, "--role").ok_or("route requires --role <role>")?;
    if !omgs::route::ROLES.contains(&role.as_str()) {
        return Err(format!(
            "--role must be one of {}",
            omgs::route::ROLES.join(", ")
        ));
    }
    let models = omgs::route::load_models(&models_path(args))?;
    let newly = flag(args, "--refused");
    let reason = flag(args, "--reason").unwrap_or_default();
    if newly.is_some() && reason.trim().is_empty() {
        return Err("--refused requires --reason <text>".into());
    }
    // Read the refusal history, pick the next model, and record the result in
    // one locked transaction, so concurrent reroutes never lose an entry.
    let next = omgs::runmeta::update(&run, |m| {
        // Malformed history must stop the command: silently ignoring it would
        // forget earlier refusals and send work back to a refusing model.
        for (key, ok) in [
            ("reroutes", m.get("reroutes").is_none_or(|v| v.is_array())),
            ("models", m.get("models").is_none_or(|v| v.is_object())),
            ("blockers", m.get("blockers").is_none_or(|v| v.is_array())),
        ] {
            if !ok {
                return Err(format!("run metadata field '{key}' is malformed"));
            }
        }
        let mut refused: Vec<String> = Vec::new();
        for (i, r) in m
            .get("reroutes")
            .and_then(|r| r.as_array())
            .into_iter()
            .flatten()
            .enumerate()
        {
            let (Some(r_role), Some(from)) = (
                r.get("role").and_then(|v| v.as_str()),
                r.get("from").and_then(|v| v.as_str()),
            ) else {
                return Err(format!(
                    "run metadata reroutes[{i}] needs string role and from"
                ));
            };
            if r_role == role {
                refused.push(from.to_string());
            }
        }
        if let Some(model) = &newly {
            if !refused.contains(model) {
                refused.push(model.clone());
            }
        }
        let next = omgs::route::next_model(&models, &role, &refused);
        if let Some(from) = &newly {
            let entry = serde_json::json!({
                "role": role,
                "from": from,
                "to": next.as_ref().ok(),
                "reason": reason,
                "at_unix": omgs::runmeta::now_unix(),
            });
            if let Some(list) = m
                .entry("reroutes")
                .or_insert_with(|| serde_json::json!([]))
                .as_array_mut()
            {
                list.push(entry);
            }
        }
        match &next {
            Ok(model) => {
                if let Some(obj) = m
                    .entry("models")
                    .or_insert_with(|| serde_json::json!({}))
                    .as_object_mut()
                {
                    obj.insert(role.clone(), serde_json::json!(model));
                }
            }
            Err(e) => {
                if let Some(list) = m
                    .entry("blockers")
                    .or_insert_with(|| serde_json::json!([]))
                    .as_array_mut()
                {
                    let e = serde_json::json!(e);
                    if !list.contains(&e) {
                        list.push(e);
                    }
                }
            }
        }
        Ok(next)
    })?;
    match next {
        Ok(model) => {
            println!("{model}");
            Ok(())
        }
        Err(e) => {
            eprintln!("blocked: {e}");
            Err("__EXIT1__".into())
        }
    }
}

fn cmd_intent(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(|s| s.as_str());
    let rest = args.get(1..).unwrap_or_default();
    match sub {
        Some("list") => {
            let stack = flag(rest, "--stack");
            let class = flag(rest, "--attack-class");
            for q in omgs::intent::list(stack.as_deref(), class.as_deref()) {
                println!("{}: {}", q.id, q.question);
                if !q.answers.is_empty() {
                    println!("  answers: {}", q.answers.join(" | "));
                }
            }
            Ok(())
        }
        Some("answer") => {
            let target_raw = flag(rest, "--target").ok_or("intent answer requires --target <repo>")?;
            let target = std::fs::canonicalize(&target_raw)
                .map_err(|e| format!("target {target_raw}: {e}"))?;
            let get = |n: &str| flag(rest, n).ok_or_else(|| format!("intent answer requires {n}"));
            let answer = omgs::intent::Answer {
                id: get("--id")?,
                answer: get("--answer")?,
                scope: flag(rest, "--scope").unwrap_or_else(|| "repo".into()),
                source: get("--source")?,
                recorded_unix: omgs::runmeta::now_unix(),
            };
            let path = omgs::intent::answers_file(&home().join(".local/share/omgs"), &target);
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            }
            let id = answer.id.clone();
            // The whole load, merge, and replace runs under a per-target lock
            // so concurrent answers are never lost.
            let lock = path.with_extension("lock");
            omgs::runmeta::with_lock_file(&lock, || {
            let mut answers = omgs::intent::load_answers(&path)?;
            let target_s = target.to_string_lossy().to_string();
            if !answers.target.is_empty() && answers.target != target_s {
                return Err(format!(
                    "{} belongs to {}, refusing to mix answers",
                    path.display(),
                    answers.target
                ));
            }
            answers.target = target_s;
            omgs::intent::record(&mut answers, answer)?;
            let text = serde_json::to_string_pretty(&answers).map_err(|e| e.to_string())?;
            omgs::runmeta::write_atomic(&path, &format!("{text}\n"))?;
            Ok(())
            })?;
            println!("recorded {id} in {}", path.display());
            Ok(())
        }
        _ => Err("usage: omgs intent list [--stack <s>] [--attack-class <c>] | omgs intent answer --target <repo> --id <id> --answer <text> --source <who> [--scope repo|<path>]".into()),
    }
}
