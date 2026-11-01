use omgs::architecture::{
    render_architecture_html, render_architecture_markdown, validate_architecture, ArchitectureFile,
};
use omgs::ledger::{add_unit, coverage_lines, set_status, validate_ledger, Ledger, Unit, STATUSES};
use omgs::model::{identity, FindingsFile};
use omgs::report::{render_html, render_markdown, render_sarif, ReportMeta};
use omgs::sandbox::{prove, ProveOutcome, ProveRequest, Tier};
use omgs::sensors::run_sensors;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn boolean_option(name: &str) -> bool {
    [
        "--yes",
        "--dry-run",
        "--install-skills",
        "--replace",
        "--verify-mxc",
        "--no-sensors",
        "--screenshots",
        "--live",
        "--help",
        "-h",
    ]
    .contains(&name)
}

fn free_text_option(name: &str) -> bool {
    [
        "--cmd", "--note", "--answer", "--detail", "--log", "--reason",
    ]
    .contains(&name)
}

/// Walk option/value pairs so a free-text value cannot become another option.
fn options(args: &[String]) -> impl Iterator<Item = (&str, Option<&str>)> {
    let mut i = 0;
    std::iter::from_fn(move || {
        while let Some(arg) = args.get(i) {
            i += 1;
            if !arg.starts_with('-') {
                continue;
            }
            if let Some((name, value)) = arg.split_once('=') {
                return Some((name, Some(value)));
            }
            let value = if boolean_option(arg) {
                None
            } else {
                let value = args.get(i).map(String::as_str);
                i += usize::from(value.is_some());
                value
            };
            return Some((arg.as_str(), value));
        }
        None
    })
}

fn flag(args: &[String], name: &str) -> Option<String> {
    options(args)
        .find(|(option, _)| *option == name)
        .and_then(|(_, value)| value.map(str::to_string))
}
fn has(args: &[String], name: &str) -> bool {
    options(args).any(|(option, _)| option == name)
}

fn usage() {
    omgs::help::usage();
}

fn validate_output_paths(args: &[String]) -> Result<(), String> {
    for (name, value) in options(args) {
        if matches!(
            name,
            "--out" | "--run" | "--runs" | "--fix-of" | "--clone-root"
        ) {
            if let Some(value) = value {
                let path = Path::new(value);
                omgs::platform::validate_output_path(path)?;
                let absolute = if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    std::env::current_dir()
                        .map_err(|e| e.to_string())?
                        .join(path)
                };
                omgs::platform::validate_output_path(&resolve_existing_prefix(&absolute)?)?;
            }
        }
    }
    omgs::platform::validate_output_path(&data_dir())?;
    omgs::platform::validate_output_path(&std::env::current_dir().map_err(|e| e.to_string())?)
}

fn clone_root(args: &[String]) -> Result<PathBuf, String> {
    let path = flag(args, "--clone-root")
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir().join("targets"));
    omgs::platform::validate_output_path(&path)?;
    if path.is_absolute() {
        Ok(path)
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|e| e.to_string())
    }
}

fn command_help(cmd: &str, args: &[String]) {
    omgs::help::command(cmd, args);
}

fn validate_options(cmd: &str, args: &[String]) -> Result<bool, String> {
    let (allowed, positional): (&str, bool) = match cmd {
        "setup" => ("--yes --from --dry-run --install-skills --replace --verify-mxc --write-policy --mode", false),
        "coalition-anchor" => ("--directory", false),
        "install-self" => ("--to --staging --binary --binary-sha256 --mxc --mxc-sha256 --license --license-sha256", false),
        "identity" => ("--skill-dir", false),
        "artifact-check" => ("--run --path", false),
        "review" => ("--skill-dir --repo-url --mode --budget --no-sensors --persona --out --clone-root", false),
        "audit" if args.first().is_some_and(|a| a == "init") => (
            "--skill-dir --target --base --out --mode --budget --no-sensors --hunter --verifier --persona --fix-of --clone-root",
            true,
        ),
        "batch" if args.first().is_some_and(|a| a == "init") => {
            ("--skill-dir --list --out --mode --budget --no-sensors --persona --clone-root", true)
        }
        "batch" if args.first().is_some_and(|a| a == "index") => ("--batch --out", true),
        "bench" if args.first().is_some_and(|a| a == "score") => ("--cases --runs", true),
        "validate" => ("--findings --candidates --dispositions --evaluation", false),
        "findings" if args.first().is_some_and(|a| a == "merge") => ("--run --from", true),
        "fingerprint" => ("--attack-class --entry-point --sink --boundary", false),
        "prove" => (
            "--cmd --target --run --finding --test --test-from --inputs-from --expect-marker --replay --tier --timeout-ms --screenshots",
            false,
        ),
        "approve" => ("--target", false),
        "report" => (
            "--findings --out --repo --ref --mode --sandbox --persona --hunters --verifier --agent-calls --accounting --model",
            false,
        ),
        "handoff" => ("--run --finding", false),
        "stage" => ("--run", false),
        "architecture" => ("--in --out", false),
        "ledger" if args.first().is_some_and(|a| a == "migrate") => ("--run", true),
        "ledger" if args.first().is_some_and(|a| a == "ingest") => ("--ledger --dispositions", true),
        "ledger" if args.first().is_some_and(|a| a == "list") => ("--ledger", true),
        "ledger" if args.first().is_some_and(|a| a == "add") => {
            ("--ledger --unit --surface --classes --status --note --mapping", true)
        }
        "ledger" if args.first().is_some_and(|a| a == "set") => {
            ("--ledger --unit --status --evidence --note --mapping --attempt-ref --blocker-ref", true)
        }
        "gate" => ("--target --base --head --run", false),
        "critic" => ("--run", false),
        "budget" => ("--run --charge-calls", false),
        "status" => (
            "--run --stage --state --label --parent --detail --counter --log --accounting",
            false,
        ),
        "attempt" => ("--run --event --resolve-blocker --actor --reason --replacement", false),
        "watch" => ("--run --max-ms", false),
        "route" => ("--run --role --refused --reason --models --model", false),
        "intent" if args.first().is_some_and(|a| a == "list") => ("--stack --attack-class", true),
        "intent" if args.first().is_some_and(|a| a == "propose") => ("--run", true),
        "intent" if args.first().is_some_and(|a| a == "answer") => {
            ("--target --id --answer --source --scope", true)
        }
        "check" => ("--target --out", false),
        "doctor" => ("--live", false),
        "update-check" => ("", false),
        "help" | "--help" | "-h" | "--version" | "-V" => ("", false),
        "audit" | "batch" | "ledger" | "intent" | "bench" | "findings"
            if args == ["--help"] || args == ["-h"] =>
        {
            ("", false)
        }
        _ => return Err(format!("unknown command or subcommand '{cmd}'")),
    };
    let mut help_requested = false;
    let mut seen = std::collections::HashSet::new();
    let mut i = usize::from(positional);
    while i < args.len() {
        let (option, inline) = args[i]
            .split_once('=')
            .map_or((args[i].as_str(), None), |(k, v)| (k, Some(v)));
        let help = option == "--help" || option == "-h";
        help_requested |= help;
        if !help && !allowed.split_whitespace().any(|a| a == option) {
            return Err(format!("unknown option '{option}' for {cmd}"));
        }
        let repeatable = (cmd == "ledger" && option == "--evidence")
            || (cmd == "status" && ["--counter", "--log"].contains(&option))
            || (cmd == "bench" && option == "--runs")
            || (["status", "report"].contains(&cmd) && option == "--accounting")
            || (cmd == "report" && option == "--model")
            || (cmd == "findings" && option == "--from");
        if !seen.insert(option) && !repeatable {
            return Err(format!("duplicate option '{option}'"));
        }
        i += 1;
        if boolean_option(option) {
            if inline.is_some() {
                return Err(format!("{option} does not take a value"));
            }
        } else if inline.is_none() {
            match args.get(i) {
                Some(value)
                    if free_text_option(option)
                        && (allowed.split_whitespace().any(|known| {
                            value == known || value.starts_with(&format!("{known}="))
                        }) || matches!(value.as_str(), "--help" | "-h")
                            || value.starts_with("--help=")) =>
                {
                    return Err(format!(
                        "{option} requires an unambiguous value; use {option}=value for free text beginning with a known option"
                    ));
                }
                Some(value) if free_text_option(option) || !value.starts_with("--") => i += 1,
                _ => {
                    return Err(format!(
                        "{option} requires a value; use {option}=value if it begins with --"
                    ))
                }
            }
        }
    }
    Ok(help_requested)
}

fn cli_error(error: &str) {
    omgs::out::err(&format!("error: {}", error.replace(['\r', '\n'], " ")));
    omgs::out::err("run omgs --help for usage");
}

fn main() -> ExitCode {
    let Ok(args) = std::env::args_os()
        .skip(1)
        .map(|a| a.into_string())
        .collect::<Result<Vec<_>, _>>()
    else {
        cli_error("command arguments must be UTF-8");
        return ExitCode::from(2);
    };
    let Some(cmd) = args.first().map(|s| s.as_str()) else {
        cli_error("a command is required");
        return ExitCode::from(2);
    };
    let rest = &args[1..];
    match validate_options(cmd, rest) {
        Err(e) => {
            cli_error(&e);
            return ExitCode::from(2);
        }
        Ok(true) => {
            command_help(cmd, rest);
            return ExitCode::SUCCESS;
        }
        Ok(false) => {}
    }
    if let Err(e) = validate_output_paths(rest) {
        cli_error(&e);
        return ExitCode::from(2);
    }
    let result: Result<(), String> = match cmd {
        "--help" | "-h" | "help" => {
            usage();
            Ok(())
        }
        "--version" | "-V" => {
            omgs::out::line(&format!("omgs {}", env!("CARGO_PKG_VERSION")));
            Ok(())
        }
        "identity" => cmd_identity(rest),
        "artifact-check" => cmd_artifact_check(rest),
        "update-check" => cmd_update_check(),
        "coalition-anchor" => cmd_coalition_anchor(rest),
        "install-self" => cmd_install_self(rest),
        "gate" => cmd_gate(rest),
        "setup" => cmd_setup(rest),
        "stage" => cmd_stage(rest),
        "review" => cmd_review(rest),
        "audit" => cmd_audit(rest),
        "validate" => cmd_validate(rest),
        "findings" => cmd_findings(rest),
        "fingerprint" => cmd_fingerprint(rest),
        "bench" => cmd_bench(rest),
        "prove" => cmd_prove(rest),
        "approve" => cmd_approve(rest),
        "report" => cmd_report(rest),
        "handoff" => cmd_handoff(rest),
        "architecture" => cmd_architecture(rest),
        "ledger" => cmd_ledger(rest),
        "critic" => cmd_critic(rest),
        "budget" => cmd_budget(rest),
        "batch" => cmd_batch(rest),
        "attempt" => cmd_attempt(rest),
        "status" => cmd_status(rest),
        "watch" => cmd_watch(rest),
        "route" => cmd_route(rest),
        "intent" => cmd_intent(rest),
        "check" => cmd_check(rest),
        "doctor" => cmd_doctor(rest),
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
                cli_error(&e);
                ExitCode::from(2)
            }
        }
    }
}

fn cmd_identity(args: &[String]) -> Result<(), String> {
    selected_skill(args)?;
    omgs::out::line(&format!("{}", omgs::setup::identity()));
    Ok(())
}

fn cmd_artifact_check(args: &[String]) -> Result<(), String> {
    let run = flag(args, "--run").ok_or("artifact-check requires --run")?;
    let path = flag(args, "--path").ok_or("artifact-check requires relative --path")?;
    omgs::run_artifact::check_containment(Path::new(&run), Path::new(&path))?;
    omgs::out::line(&format!("artifact containment checked: {path}"));
    Ok(())
}

/// Validate external selection before cloning, scanning or creating a run.
fn selected_skill(args: &[String]) -> Result<(), String> {
    let selected = flag(args, "--skill-dir")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("OMGS_SKILL_DIR").map(PathBuf::from));
    if let Some(path) = selected {
        omgs::setup::check_identity(&path)?;
    }
    Ok(())
}

fn bundle_cache() -> PathBuf {
    data_dir().join("skill-bundles")
}

fn review_skill(args: &[String]) -> Result<PathBuf, String> {
    let selected = flag(args, "--skill-dir")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("OMGS_SKILL_DIR").map(PathBuf::from));
    omgs::setup::materialize_selected(
        &bundle_cache().join(omgs::setup::bundled_digest()),
        selected.as_deref(),
    )
}

fn cmd_update_check() -> Result<(), String> {
    if let Some(line) = omgs::update::check() {
        omgs::out::line(&line);
    }
    Ok(())
}

fn cmd_coalition_anchor(rest: &[String]) -> Result<(), String> {
    let dir = flag(rest, "--directory").ok_or("coalition-anchor requires --directory")?;
    #[cfg(target_os = "macos")]
    {
        omgs::coalition::anchor(&PathBuf::from(dir)).map_err(|e| e.to_string())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = dir;
        Err("launchd coalition anchors require macOS".into())
    }
}

fn cmd_install_self(rest: &[String]) -> Result<(), String> {
    let to = PathBuf::from(flag(rest, "--to").ok_or("install-self requires --to")?);
    let staging = PathBuf::from(flag(rest, "--staging").ok_or("install-self requires --staging")?);
    let source =
        |name: Option<String>, hash: Option<String>| -> Result<(PathBuf, String), String> {
            Ok((
                PathBuf::from(name.ok_or("install-self requires a source name")?),
                hash.ok_or("install-self requires a source SHA-256")?,
            ))
        };
    let binary = source(flag(rest, "--binary"), flag(rest, "--binary-sha256"))?;
    let mxc = flag(rest, "--mxc")
        .map(|n| source(Some(n), flag(rest, "--mxc-sha256")))
        .transpose()?;
    let license = flag(rest, "--license")
        .map(|n| source(Some(n), flag(rest, "--license-sha256")))
        .transpose()?;
    omgs::install::install_self(
        &to,
        &staging,
        (&binary.0, &binary.1),
        mxc.as_ref().map(|s| (s.0.as_path(), s.1.as_str())),
        license.as_ref().map(|s| (s.0.as_path(), s.1.as_str())),
    )
    .map_err(|e| e.to_string())
}

fn cmd_gate(args: &[String]) -> Result<(), String> {
    let outcome = (|| {
        let target = flag(args, "--target").ok_or("gate requires --target")?;
        let base = flag(args, "--base").ok_or("gate requires --base")?;
        let head = flag(args, "--head").ok_or("gate requires --head")?;
        let run = flag(args, "--run").map(PathBuf::from);
        omgs::policy::gate(Path::new(&target), &base, &head, run.as_deref())
    })();
    match outcome {
        Ok(0) => Ok(()),
        Ok(_) => Err("__EXIT1__".into()),
        Err(e) => {
            cli_error(&e);
            Err("__EXIT3__".into())
        }
    }
}

fn cmd_budget(args: &[String]) -> Result<(), String> {
    let run = flag(args, "--run").ok_or("budget requires --run <run-dir>")?;
    if let Some(n) = flag(args, "--charge-calls") {
        let n = n
            .parse::<u64>()
            .map_err(|_| "--charge-calls needs a non-negative integer")?;
        omgs::budget::charge_calls(Path::new(&run), n)?;
    }
    let root = omgs::budget::original(Path::new(&run))?;
    omgs::runmeta::with_lock(&root, || {
        let allowance = omgs::budget::allowance(&root)?;
        omgs::out::json(&allowance)?;
        Ok(())
    })
}

fn read_findings(path: &str) -> Result<FindingsFile, String> {
    let text = omgs::run_artifact::text_path(Path::new(path), omgs::run_artifact::FINDINGS_BYTES)?;
    omgs::shape::findings(&text).map_err(|e| format!("parse {path}: {e}"))
}

/// Merge per-verifier findings files into the run's single findings.json.
/// Parallel verifiers each write their own file; the host merges them under
/// the run lock. A fingerprint present in two inputs with different content
/// is refused, as is a record whose fingerprint is not its computed identity.
/// Drafts merge as drafts; `omgs validate --findings` checks the result.
fn cmd_findings(args: &[String]) -> Result<(), String> {
    let usage = "usage: omgs findings merge --run <run-dir> --from <file> [--from <file>]...";
    let (sub, rest) = args.split_first().ok_or(usage)?;
    if sub != "merge" {
        return Err(usage.into());
    }
    let run = flag(rest, "--run").ok_or("findings merge requires --run <run-dir>")?;
    let sources = flags(rest, "--from");
    if sources.is_empty() {
        return Err("findings merge requires at least one --from <file>".into());
    }
    let run = Path::new(&run);
    omgs::runmeta::with_lock(run, || {
        let target = run.join("findings.json");
        let mut merged = match omgs::run_artifact::optional_text(
            run,
            Path::new("findings.json"),
            omgs::run_artifact::FINDINGS_BYTES,
        )? {
            Some(text) => omgs::shape::findings(&text)
                .map_err(|e| format!("parse {}: {e}", target.display()))?,
            None => omgs::model::FindingsFile::default(),
        };
        let mut origin: std::collections::BTreeMap<String, String> = merged
            .findings
            .iter()
            .map(|f| (f.fingerprint.clone(), "findings.json".to_string()))
            .collect();
        let mut added = 0;
        for source in &sources {
            let text = omgs::run_artifact::text_path(
                Path::new(source),
                omgs::run_artifact::FINDINGS_BYTES,
            )?;
            let file = omgs::shape::findings(&text).map_err(|e| format!("parse {source}: {e}"))?;
            for finding in file.findings {
                let expected = omgs::fingerprint(
                    &finding.attack_class,
                    &finding.entry_point,
                    &finding.sink,
                    &finding.boundary,
                );
                if finding.fingerprint != expected {
                    omgs::out::err(&format!(
                        "invalid: {source}: '{}' has fingerprint '{}', expected {expected}",
                        omgs::platform::escape_controls(&finding.title),
                        omgs::platform::escape_controls(&finding.fingerprint)
                    ));
                    return Err("__EXIT1__".into());
                }
                if let Some(existing) = merged
                    .findings
                    .iter()
                    .find(|m| m.fingerprint == finding.fingerprint)
                {
                    if serde_json::to_value(existing).ok() == serde_json::to_value(&finding).ok() {
                        continue;
                    }
                    return Err(format!(
                        "{} differs between {} and {source}; reconcile the records before merging",
                        finding.fingerprint, origin[&finding.fingerprint]
                    ));
                }
                origin.insert(finding.fingerprint.clone(), source.clone());
                merged.findings.push(finding);
                added += 1;
            }
        }
        let text = format!(
            "{}\n",
            serde_json::to_string_pretty(&merged).map_err(|e| e.to_string())?
        );
        if text.len() as u64 > omgs::run_artifact::FINDINGS_BYTES {
            return Err(format!(
                "merged findings.json would be {} bytes, over the {} byte limit every reader enforces; nothing was written",
                text.len(),
                omgs::run_artifact::FINDINGS_BYTES
            ));
        }
        omgs::runmeta::write_atomic(&target, &text)?;
        omgs::out::line(&format!(
            "merged {added} new finding(s) from {} file(s); findings.json holds {}",
            sources.len(),
            merged.findings.len()
        ));
        Ok(())
    })
}

fn cmd_validate(args: &[String]) -> Result<(), String> {
    let path = [
        "--findings",
        "--candidates",
        "--dispositions",
        "--evaluation",
    ]
    .iter()
    .find_map(|k| flag(args, k));
    if let Some(path) = path {
        let dir = Path::new(&path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        omgs::runmeta::with_archive_lock(dir, || cmd_validate_locked(args))
    } else {
        cmd_validate_locked(args)
    }
}

fn cmd_validate_locked(args: &[String]) -> Result<(), String> {
    let inputs = [
        "--findings",
        "--candidates",
        "--dispositions",
        "--evaluation",
    ];
    if inputs.iter().filter(|k| flag(args, k).is_some()).count() != 1 {
        return Err("validate requires exactly one of --findings, --candidates, --dispositions, --evaluation".into());
    }
    for kind in &inputs[1..] {
        if let Some(path) = flag(args, kind) {
            let limit = match *kind {
                "--candidates" => omgs::run_artifact::CANDIDATES_BYTES,
                "--dispositions" => omgs::run_artifact::DISPOSITIONS_BYTES,
                _ => omgs::run_artifact::EVALUATION_BYTES,
            };
            let text = omgs::run_artifact::text_path(Path::new(&path), limit)?;
            match *kind {
                "--candidates" => {
                    omgs::adjudication::candidates(&text)?;
                }
                "--dispositions" => {
                    omgs::adjudication::dispositions(&text)?;
                }
                _ => {
                    omgs::adjudication::parse(&text)?;
                }
            }
            omgs::out::line(&format!("valid: {kind}"));
            return Ok(());
        }
    }
    let path = flag(args, "--findings").unwrap();
    let file = read_findings(&path)?;
    let dir = Path::new(&path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let view = omgs::review::View::for_publication_locked(
        dir,
        &file,
        &omgs::runmeta::read_optional(dir)?.unwrap_or_default(),
    )?;
    let errors = view.validation_errors();
    if errors.is_empty() {
        omgs::out::line(&format!(
            "valid: {} finding(s); review {}",
            view.findings.findings.len(),
            omgs::platform::escape_controls(view.state.as_deref().unwrap_or("complete"))
        ));
        Ok(())
    } else {
        for e in &errors {
            omgs::out::err(&format!("invalid: {}", omgs::platform::escape_controls(e)));
        }
        Err("__EXIT1__".into())
    }
}

fn read_architecture(path: &str) -> Result<ArchitectureFile, String> {
    let text =
        omgs::run_artifact::text_path(Path::new(path), omgs::run_artifact::ARCHITECTURE_BYTES)?;
    serde_json::from_str(&text).map_err(|e| format!("parse {path}: {e}"))
}

fn cmd_architecture(args: &[String]) -> Result<(), String> {
    let inp = flag(args, "--in").ok_or("architecture requires --in <architecture.json>")?;
    let out = flag(args, "--out").ok_or("architecture requires --out <dir>")?;
    let input_dir = Path::new(&inp)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    omgs::runmeta::with_lock(input_dir, || {
        let file = read_architecture(&inp)?;
        let errors = validate_architecture(&file);
        if !errors.is_empty() {
            for e in &errors {
                omgs::out::err(&format!("invalid: {}", omgs::platform::escape_controls(e)));
            }
            return Err("__EXIT1__".into());
        }
        let dir = Path::new(&out);
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let mut writes = omgs::runmeta::Transaction::default();
        writes.text(
            dir.join("ARCHITECTURE.md"),
            render_architecture_markdown(&file),
        );
        writes.text(
            dir.join("ARCHITECTURE.html"),
            render_architecture_html(&file),
        );
        writes.commit()?;
        omgs::out::line(&format!(
            "wrote {}, {}",
            dir.join("ARCHITECTURE.md").display(),
            dir.join("ARCHITECTURE.html").display()
        ));
        Ok(())
    })
}

fn cmd_bench(args: &[String]) -> Result<(), String> {
    let cases = flag(args, "--cases").ok_or("bench score requires --cases <manifest>")?;
    let dirs: Vec<PathBuf> = flags(args, "--runs")
        .into_iter()
        .map(PathBuf::from)
        .collect();
    omgs::bench::publish_score(Path::new(&cases), &dirs, |result| {
        omgs::out::json(&result)?;
        for line in omgs::bench::markdown(&result).lines() {
            omgs::out::err(line);
        }
        Ok(())
    })
}

fn cmd_fingerprint(args: &[String]) -> Result<(), String> {
    let get = |n: &str| flag(args, n).ok_or_else(|| format!("fingerprint requires {n}"));
    let class = get("--attack-class")?;
    omgs::classes::validate(&class)?;
    omgs::out::line(
        &(omgs::fingerprint(
            &class,
            &get("--entry-point")?,
            &get("--sink")?,
            &get("--boundary")?,
        )),
    );
    Ok(())
}

fn release_proof_charge(run: &Path) -> Result<(), String> {
    omgs::budget::release_proof(run)
}

fn cmd_prove(args: &[String]) -> Result<(), String> {
    let _preparation = omgs::proof_inputs::StagingGuard::begin();
    #[cfg(unix)]
    let _signals = omgs::supervise::interruption::Guard::install().map_err(|e| e.to_string())?;
    let run = flag(args, "--run").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    {
        for path in std::iter::once(data_dir()).chain(run.iter().cloned()) {
            if let Err(error) = omgs::tcc::admit_path(&path) {
                omgs::out::err(&format!(
                    "needs_validation: target code was not executed. {error}"
                ));
                return Err("__EXIT3__".into());
            }
        }
    }

    // A replay reruns a recorded proof exactly, so an independent evaluator
    // can check a result instead of trusting the file that claims it.
    let replay = match flag(args, "--replay") {
        Some(v) => {
            let r = run
                .as_ref()
                .ok_or("--replay needs --run <run-dir>, the run that holds the record")?;
            for conflicting in [
                "--expect-marker",
                "--cmd",
                "--finding",
                "--test",
                "--tier",
                "--target",
                "--timeout-ms",
                "--inputs-from",
                "--screenshots",
            ] {
                if flag(args, conflicting).is_some() || has(args, conflicting) {
                    return Err(format!(
                        "--replay takes everything from the record; drop {conflicting}"
                    ));
                }
            }
            let n: u32 = v
                .parse()
                .map_err(|_| format!("--replay takes a proof number, got '{v}'"))?;
            Some(omgs::proof::load(r, &omgs::proof::reference(n))?)
        }
        None => None,
    };
    let command = match &replay {
        Some(r) => omgs::proof::recorded_command(run.as_ref().unwrap(), r)?,
        None => flag(args, "--cmd").ok_or("prove requires --cmd <command>")?,
    };
    let expect_marker = match &replay {
        Some(r) => r.contract.expect_marker().map(String::from),
        None => flag(args, "--expect-marker"),
    };
    if expect_marker
        .as_ref()
        .is_some_and(|m| !omgs::proof::valid_expect_marker(m))
    {
        return Err("--expect-marker must be 1..=128 ASCII letters, digits or underscores, distinct from AUTHORIZED_CONTROL_OK and OMGS_ markers".into());
    }
    let timeout_ms: u64 = match flag(args, "--timeout-ms") {
        Some(v) => v
            .parse()
            .map_err(|_| format!("--timeout-ms must be a whole number, got '{v}'"))?,
        None => replay.as_ref().map(|r| r.timeout_ms).unwrap_or(120_000),
    };
    omgs::sandbox::validate_input(&command, timeout_ms)?;
    let tier = match (&replay, flag(args, "--tier").as_deref()) {
        (Some(r), _) if r.tier == "local_app" => Tier::LocalApp,
        (Some(_), _) | (None, None | Some("1")) => Tier::Test,
        (None, Some("2")) => Tier::LocalApp,
        (None, Some(other)) => return Err(format!("--tier must be 1 or 2, got '{other}'")),
    };
    let finding = match &replay {
        Some(r) => r.finding.clone(),
        None => flag(args, "--finding"),
    };
    if let Some(fp) = &finding {
        if !omgs::model::is_fingerprint(fp) {
            return Err(format!("--finding '{fp}' is not an omgs fingerprint"));
        }
        if run.is_none() {
            return Err(
                "--finding needs --run <run-dir> so the proof record lands beside the findings"
                    .into(),
            );
        }
    }
    let test = match &replay {
        Some(r) => r.test.clone(),
        None => flag(args, "--test"),
    };
    if finding.is_some() && test.is_none() {
        return Err("--finding requires --test <target-relative path>".into());
    }
    if let Some(t) = &test {
        if t.trim().is_empty() || !omgs::proof::command_names(&command, t) {
            return Err(format!(
                "--cmd must name --test {t} as a full path or file name token"
            ));
        }
        if Path::new(t).is_absolute() || t.contains(':') || t.split(['/', '\\']).any(|s| s == "..")
        {
            return Err(format!(
                "--test '{t}' must be a path relative to the target"
            ));
        }
    }
    let meta = match &run {
        Some(r) => Some(omgs::budget::metadata(r)?),
        None => None,
    };
    let canon = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let target = match &replay {
        // A replay never takes a host path from the record: the target must be
        // this run's own target, so an edited record cannot point it elsewhere.
        Some(r) => match &r.target {
            None => None,
            Some(t) => {
                let run_target = meta
                    .as_ref()
                    .and_then(|m| m.get("target").and_then(|v| v.as_str()))
                    .ok_or(
                        "--replay of a record with a target needs a run initialised against it",
                    )?;
                if canon(Path::new(t)) != canon(Path::new(run_target)) {
                    return Err(format!(
                        "{} names target {t}, not this run's target {run_target}; refusing to replay it",
                        omgs::proof::reference(r.n)
                    ));
                }
                Some(PathBuf::from(run_target))
            }
        },
        None => flag(args, "--target").map(PathBuf::from).or_else(|| {
            meta.as_ref()
                .and_then(|m| m.get("target").and_then(|t| t.as_str()).map(PathBuf::from))
        }),
    };
    let target = match target {
        Some(t) => {
            Some(std::fs::canonicalize(&t).map_err(|e| format!("target {}: {e}", t.display()))?)
        }
        None => None,
    };
    if let Some(run_target) = meta
        .as_ref()
        .and_then(|m| m.get("target"))
        .and_then(|v| v.as_str())
    {
        if target.as_deref().map(canon) != Some(canon(Path::new(run_target))) {
            return Err(format!(
                "--target must match this run's target {run_target}"
            ));
        }
    }
    let target_head = target.as_deref().and_then(omgs::proof::git_head);
    if let Some(r) = &replay {
        if r.target_head != target_head {
            return Err(
                "target commit differs from the recorded target_head; refusing to replay".into(),
            );
        }
        let errors = omgs::proof::runner_evidence(run.as_ref().unwrap(), r);
        if !errors.is_empty() {
            if errors
                .iter()
                .any(|e| e.starts_with("target snapshot differs"))
            {
                omgs::out::err(&format!(
                    "needs_validation: target code was not executed. {}",
                    errors.join("; ")
                ));
                return Err("__EXIT3__".into());
            }
            return Err(format!(
                "cannot replay invalid record: {}",
                errors.join("; ")
            ));
        }
    }
    let expected_inputs = replay
        .as_ref()
        .map(|r| omgs::proof_inputs::retained(run.as_ref().unwrap(), r))
        .transpose()?
        .flatten();
    let inputs = match (&expected_inputs, flag(args, "--inputs-from")) {
        (Some(manifest), _) => manifest.selection.clone(),
        (None, Some(path)) => {
            if target.is_none() {
                return Err("--inputs-from requires a target".into());
            }
            let selection = omgs::proof_inputs::read_selection(Path::new(&path))?;
            Some(selection)
        }
        _ => None,
    };
    let harness = match &replay {
        Some(r) if !r.harness.is_empty() => {
            Some(omgs::proof::retained_harness(run.as_ref().unwrap(), r)?)
        }
        None => match flag(args, "--test-from").map(PathBuf::from) {
            Some(path) if path.is_dir() => {
                if let Some(base) = &target {
                    if omgs::paths::overlaps(&path, base)? {
                        return Err("--test-from must be outside the target".into());
                    }
                }
                let test = test.as_deref().ok_or("--test-from needs --test")?;
                Some(match omgs::proof::harness_artifact(&path, test)? {
                    Some(harness) => harness,
                    None => omgs::proof::prepare_harness(&path, test)?,
                })
            }
            _ => None,
        },
        _ => None,
    };
    // The proof test is either already in the target or a draft kept
    // outside it (`--test-from`) that the runner stages into the workspace
    // copy at the `--test` path. Its digest goes on the record so a reader can
    // tell which test produced the result.
    let draft = match (&replay, flag(args, "--test-from")) {
        (Some(_), Some(_)) => {
            return Err("--replay takes everything from the record; drop --test-from".into())
        }
        // The runner kept its own copy of the draft beside the record; the
        // original path in the record is informational only.
        (Some(r), None) => r.test_from.as_ref().map(|_| {
            run.as_ref()
                .map(|d| d.join("proofs").join(r.n.to_string()).join("test-draft"))
                .unwrap_or_default()
        }),
        (None, d) => {
            if harness.is_some() {
                None
            } else {
                d.map(PathBuf::from)
            }
        }
    };
    if draft.is_some() && test.is_none() {
        return Err("--test-from needs --test <target-relative path> to stage it at".into());
    }
    // Replay evidence is read once through the run boundary and that exact
    // snapshot is staged below, even if the retained pathname is replaced.
    let prepared_draft = match (&replay, &run) {
        (Some(record), Some(run)) if record.test_from.is_some() => Some(
            omgs::run_artifact::read_with_permissions(
                run,
                &Path::new("proofs")
                    .join(record.n.to_string())
                    .join("test-draft"),
                omgs::run_artifact::DRAFT_BYTES,
            )
            .map_err(|e| e.to_string())?,
        ),
        (None, _) => draft
            .as_ref()
            .map(|path| omgs::proof_inputs::read_draft(path))
            .transpose()?,
        _ => None,
    };
    let test_sha256 = if let Some(h) = &harness {
        test.as_ref()
            .and_then(|t| h.files.iter().find(|f| &f.path == t))
            .map(|f| f.sha256.clone())
    } else {
        match (&test, &draft) {
            (Some(_), Some(d)) => {
                let digest = prepared_draft
                    .as_ref()
                    .map(|(bytes, _)| omgs::sha256::digest(bytes))
                    .ok_or("missing prepared proof draft")?;
                let d = std::fs::canonicalize(d)
                    .map_err(|e| format!("--test-from {}: {e}", d.display()))?;
                if let Some(base) = &target {
                    if omgs::paths::overlaps(&d, base)? {
                        return Err("--test-from must be a draft outside the target; drop it to use a test already in the target".into());
                    }
                }
                if !d.is_file() {
                    return Err(format!("--test-from {} is not a file", d.display()));
                }
                Some(digest)
            }
            (Some(t), None) => {
                let base = target
                    .as_ref()
                    .ok_or("--test needs a target to find the test in")?;
                let path = base.join(t);
                if !path.is_file() {
                    return Err(format!(
                    "--test {t} does not resolve to a regular file at {}; stage a draft with --test-from <file>",
                    omgs::platform::describe_path(&path)
                ));
                }
                if std::fs::symlink_metadata(&path).is_ok_and(|m| omgs::platform::is_link(&m)) {
                    omgs::out::err(&format!(
                        "proof test: {}",
                        omgs::platform::describe_path(&path)
                    ));
                }
                Some(
                    omgs::proof_inputs::hash_file(&path).map_err(|e| {
                        format!("read {}: {e}", omgs::platform::describe_path(&path))
                    })?,
                )
            }
            (None, _) => None,
        }
    };
    let draft = match draft {
        Some(d) => Some(
            std::fs::canonicalize(&d).map_err(|e| format!("--test-from {}: {e}", d.display()))?,
        ),
        None => None,
    };
    if let Some(r) = &replay {
        if r.test_sha256 != test_sha256 {
            return Err(format!(
                "the proof test differs from the one {} ran; refusing to replay a different test",
                omgs::proof::reference(r.n)
            ));
        }
    }
    if tier == Tier::LocalApp {
        if let Some(why) = omgs::sandbox::tier2_unavailable(std::env::consts::OS) {
            omgs::out::err(&format!(
                "needs_validation: target code was not executed. {why}"
            ));
            return Err("__EXIT3__".into());
        }
        let t = target
            .as_ref()
            .ok_or("--tier 2 needs a target, since approval is per repository")?;
        if !omgs::approval::is_approved(&data_dir(), t)? {
            omgs::out::err(&format!("needs_validation: tier 2 runs a locally built app and needs a one-time human approval for {}.", t.display()));
            omgs::out::err(&format!(
                "Ask the person you are working for to run, at their own terminal: omgs approve --target {}",
                t.display()
            ));
            return Err("__EXIT3__".into());
        }
    }
    omgs::supervise::check_interrupted().map_err(|e| e.to_string())?;
    let proof_dir = match &run {
        Some(r) => {
            // Check and charge the budget in one locked step, before anything
            // runs, so concurrent proofs cannot overspend it. A run that is
            // interrupted keeps its charge; a blocked one gets it back below.
            let charged = omgs::budget::charge_proof(r);
            if let Err(e) = charged {
                if e.starts_with("run budget exhausted") {
                    omgs::out::err(&format!(
                        "needs_validation: target code was not executed. {e}"
                    ));
                    return Err("__EXIT3__".into());
                }
                return Err(e);
            }
            match omgs::proof::reserve(r) {
                Ok(reserved) => Some(reserved),
                Err(e) => {
                    release_proof_charge(r)?;
                    return Err(e);
                }
            }
        }
        None => None,
    };
    let run_dir = match &proof_dir {
        Some((_, d)) => d.clone(),
        None => data_dir().join("prove").join(format!(
            "{}-{}",
            omgs::runmeta::now_ms(),
            std::process::id()
        )),
    };
    // Nothing ran: give the budget charge and the reserved number back.
    let release = || {
        let _ = std::fs::remove_dir_all(&run_dir);
        if let (Some(r), Some(_)) = (&run, &proof_dir) {
            let _ = release_proof_charge(r);
        }
    };
    // Keep the runner's own copy of the draft beside the record and stage
    // from it, so what ran is what was hashed and a replay never reads a host
    // path out of the record.
    let staged_draft = match &draft {
        Some(d) => {
            let copy = run_dir.join("test-draft");
            let kept = omgs::platform::private_dir(&run_dir)
                .and_then(|_| match &prepared_draft {
                    Some((bytes, permissions)) => {
                        omgs::runmeta::write_atomic_bytes_with_permissions(
                            &copy,
                            bytes,
                            permissions.clone(),
                        )
                    }
                    None => Err(std::io::Error::other("missing prepared proof draft")),
                })
                .map_err(|e| e.to_string())
                .and_then(|_| {
                    let (boundary, relative) = match &run {
                        Some(run) => (
                            run.as_path(),
                            copy.strip_prefix(run).map_err(|e| e.to_string())?,
                        ),
                        None => (run_dir.as_path(), Path::new("test-draft")),
                    };
                    omgs::run_artifact::read(boundary, relative, omgs::run_artifact::DRAFT_BYTES)
                        .map(|bytes| omgs::sha256::digest(&bytes))
                        .map_err(|e| e.to_string())
                });
            if kept.ok() != test_sha256 {
                release();
                return Err(format!("could not keep a verified copy of {}", d.display()));
            }
            Some(copy)
        }
        None => None,
    };
    if let Some(harness) = &harness {
        if let Err(e) = omgs::proof::keep_harness(&run_dir, harness) {
            release();
            return Err(e);
        }
    }
    // Handoff acceptance commands reuse the exact selection through --inputs-from.
    if let (Some(selection), Some(_)) = (&inputs, &proof_dir) {
        let kept = serde_json::to_string(selection)
            .map_err(|e| e.to_string())
            .and_then(|text| {
                omgs::runmeta::write_atomic_bytes(
                    &run_dir.join(omgs::proof_inputs::SELECTION_FILE),
                    text.as_bytes(),
                )
                .map_err(|e| e.to_string())
            });
        if let Err(e) = kept {
            release();
            return Err(e);
        }
    }
    let screenshots = match &replay {
        Some(r) => r.screenshots.is_some(),
        None => has(args, "--screenshots"),
    };
    let request = ProveRequest {
        screenshots,
        expect_marker: expect_marker.clone(),
        command: command.clone(),
        test: test.clone(),
        timeout_ms,
        target: target.clone(),
        run_dir: run_dir.clone(),
        tier,
        stage: staged_draft.zip(test.clone()),
        expected_tree_sha256: replay.as_ref().and_then(|r| r.target_sha256.clone()),
        inputs,
        expected_inputs,
        harness: harness
            .as_ref()
            .map(|h| h.files.clone())
            .unwrap_or_default(),
    };
    if let Some(test) = &request.test {
        omgs::out::err(&format!(
            "proof harness: {} (relative to workspace root {})",
            omgs::platform::escape_controls(test),
            omgs::platform::escape_controls(&run_dir.join("workspace").to_string_lossy())
        ));
    }
    let started_at_ms = omgs::runmeta::now_ms();
    let result = match prove(&request) {
        ProveOutcome::Blocked { reason } => {
            release();
            omgs::out::err(&format!(
                "needs_validation: target code was not executed. {}",
                omgs::platform::escape_controls(&reason)
            ));
            return Err("__EXIT3__".into());
        }
        ProveOutcome::Ran(r) => r,
    };
    let s = &result.run;
    let output = omgs::proof::redact(&s.output);
    omgs::runmeta::write_atomic_bytes(&run_dir.join("command.txt"), command.as_bytes())
        .map_err(|e| e.to_string())?;
    let record = omgs::proof::ProofRecord {
        schema: omgs::proof::SCHEMA.into(),
        n: proof_dir.as_ref().map(|(n, _)| *n).unwrap_or(0),
        finding,
        test,
        test_sha256,
        test_from: draft.as_ref().map(|d| d.to_string_lossy().to_string()),
        replays: replay.as_ref().map(|r| r.n),
        tier: match tier {
            Tier::Test => "test".into(),
            Tier::LocalApp => "local_app".into(),
        },
        command: omgs::proof::redact(&command),
        command_sha256: omgs::sha256::digest(command.as_bytes()),
        wrapped_command_sha256: result.wrapped_command_sha256.clone(),
        readable_roots: result.readable_roots.clone(),
        system_root: result.system_root.clone(),
        target: target.as_ref().map(|t| t.to_string_lossy().to_string()),
        target_head,
        target_sha256: result.target_sha256.clone(),
        execution_inputs: result.input_manifest.as_ref().map(|manifest| {
            omgs::proof::ExecutionInputs {
                selection: manifest.selection.clone(),
                version: omgs::proof_inputs::VERSION,
                sha256: result.target_sha256.clone().unwrap(),
            }
        }),
        harness: harness
            .as_ref()
            .map(|h| h.files.clone())
            .unwrap_or_default(),
        output_audit: Some(omgs::proof::output_audit(s)),
        proof_dir: std::fs::canonicalize(&run_dir)
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .into(),
        marker_nonce: result.marker_nonce.clone(),
        command_started: s.command_started,
        command_finished: s.command_finished,
        test_reachable: s.test_reachable,
        timeout_ms,
        started_at_ms,
        duration_ms: s.duration_ms,
        exit_code: s.exit_code,
        contract: match expect_marker {
            Some(expect_marker) => omgs::proof::Contract::Recipe {
                expect_marker,
                boundary_marker_seen: s.boundary_marker_seen,
                authorized_control_seen: s.authorized_control_seen,
            },
            None => omgs::proof::Contract::None,
        },
        timed_out: s.timed_out,
        capture_complete: s.capture_complete,
        cleanup_complete: s.cleanup_complete,
        executor_error: s.executor_error,
        killed: s.killed,
        interrupted: s.interrupted,
        survivors: s
            .survivors
            .iter()
            .map(|v| omgs::proof::Survivor {
                pid: v.pid,
                command: omgs::proof::redact(&v.command),
            })
            .collect(),
        mxc_version: omgs::sandbox::MXC_VERSION.into(),
        containment: result.containment.clone(),
        executor: result.executor.to_string_lossy().to_string(),
        executor_sha256: result.executor_sha256.clone(),
        config_sha256: result.config_sha256.clone(),
        enforced: result.enforced.clone(),
        gaps: result.gaps.clone(),
        notes: result.notes.clone(),
        screenshots: result.screenshots.clone(),
        output_sha256: omgs::sha256::digest(output.as_bytes()),
        output_bytes_total: s.output_bytes_total,
        output,
        omgs_version: env!("CARGO_PKG_VERSION").into(),
    };
    let record_path = match (&run, &proof_dir) {
        (Some(r), Some(_)) => omgs::proof::write(r, &record)?,
        _ => {
            let p = run_dir.join("record.json");
            let text = serde_json::to_string_pretty(&record).map_err(|e| e.to_string())?;
            omgs::runmeta::write_atomic(&p, &format!("{text}\n"))?;
            p
        }
    };
    omgs::out::text(&record.output);
    omgs::out::err(&format!(
        "sandbox: MXC {} ({}), executor {} sha256 {}",
        omgs::sandbox::MXC_VERSION,
        result.containment,
        result.executor.display(),
        result.executor_sha256
    ));
    for e in &result.enforced {
        omgs::out::err(&format!("  enforced: {e}"));
    }
    for g in &result.gaps {
        omgs::out::err(&format!(
            "  not enforced: {}",
            omgs::platform::escape_controls(g)
        ));
    }
    for v in &s.survivors {
        omgs::out::err(&format!(
            "  survivor killed: pid {} {}",
            v.pid,
            omgs::proof::redact(&v.command)
        ));
    }
    omgs::out::err(&format!(
        "exit {}{}{}, {} ms",
        s.exit_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "none".into()),
        if s.executor_error {
            ", executor error"
        } else if s.killed {
            ", killed"
        } else if s.timed_out {
            ", timed out"
        } else {
            ""
        },
        if s.capture_complete {
            ""
        } else {
            ", output capture incomplete"
        },
        s.duration_ms
    ));
    match (&proof_dir, &replay) {
        (_, Some(original)) => omgs::out::err(&format!(
            "replay record: {} (original {})",
            record_path.display(),
            omgs::proof::record_path(run.as_ref().unwrap(), original.n).display()
        )),
        (Some((n, _)), None) => omgs::out::err(&format!(
            "proof record: {} (proof_ref {})",
            record_path.display(),
            omgs::proof::reference(*n)
        )),
        (None, None) => omgs::out::err(&format!(
            "proof record: {} (not linked to a run)",
            record_path.display()
        )),
    }
    if record.finding.is_some() && replay.is_none() {
        let rejected = match &run {
            Some(d) => omgs::run_artifact::optional_text(
                d,
                Path::new("findings.json"),
                omgs::run_artifact::FINDINGS_BYTES,
            )?
            .map(|t| omgs::shape::findings(&t))
            .transpose()?
            .is_some_and(|fs| {
                fs.findings.iter().any(|f| {
                    Some(&f.fingerprint) == record.finding.as_ref()
                        && f.verdict == omgs::model::Verdict::Rejected
                })
            }),
            None => false,
        };
        let mut reasons = Vec::new();
        if !record.command_started {
            reasons.push("command never started (executor error)");
        }
        if !record.command_finished {
            reasons.push("command did not emit its end marker");
        }
        if record.test.is_some() && record.test_reachable != Some(true) {
            reasons.push("proof test was not reachable inside the sandbox");
        }
        if !record.clean() {
            reasons.push("run did not finish cleanly");
        }
        if !record.supports_verdict(rejected) {
            reasons.push("proof requires assertion exit 1 or 3..=125; exit 2 is a harness or usage error; a declared contract requires exit 1, its nonce-qualified boundary and control markers from full-stream capture");
        }
        let tier_name = if record.tier == "test" {
            "test_proven"
        } else {
            "sandbox_exploited"
        };
        omgs::out::err(&format!(
            "proof support for {tier_name}: {}",
            if reasons.is_empty() {
                "yes".into()
            } else {
                format!("no: {}", reasons.join("; "))
            }
        ));
    }
    if let Some(orig) = &replay {
        let code = |c: Option<i32>| c.map(|c| c.to_string()).unwrap_or_else(|| "none".into());
        let same = record.exit_code == orig.exit_code
            && record.contract == orig.contract
            && record.clean()
            && orig.clean();
        omgs::out::err(&format!(
            "replay of {}: recorded exit {}, replayed exit {}: {}",
            omgs::proof::reference(orig.n),
            code(orig.exit_code),
            code(record.exit_code),
            if same { "reproduced" } else { "NOT reproduced" }
        ));
        return if same {
            Ok(())
        } else {
            Err("__EXIT1__".into())
        };
    }
    match omgs::proof::outer_exit(&record) {
        0 => Ok(()),
        1 => Err("__EXIT1__".into()),
        _ => Err("proof harness or execution error; see retained record".into()),
    }
}

fn doctor_probe_command(_os: &str, name: &str) -> String {
    // Use the same PATH lookup as proof commands, including Apple's compiler
    // shims. A working direct compiler does not establish shim readiness.
    match name {
        "sh" => "sh -c 'exit 0'".into(),
        "java" => "java -version".into(),
        "go" => "go version".into(),
        _ => format!("{name} --version"),
    }
}

fn doctor_probe_timeout_ms(os: &str, name: &str) -> u64 {
    if os == "macos" && matches!(name, "swiftc" | "clang") {
        // xcrun may perform SDK discovery on its first launch. This changes
        // only doctor's fixed probe budget, not proof containment limits.
        30_000
    } else {
        3_000
    }
}

fn doctor_tool_failure(name: &str, reason: &str) -> String {
    format!(
        "{name} on host PATH but failed to launch inside MXC\n  reason: {}",
        omgs::platform::escape_controls(reason)
    )
}

fn doctor_probe_result(run: &omgs::supervise::Supervised) -> Result<(), String> {
    if run.success
        && run.command_started
        && run.command_finished
        && run.capture_complete
        && run.cleanup_complete
        && !run.executor_error
        && !run.timed_out
        && !run.killed
        && !run.interrupted
        && run.survivors.is_empty()
    {
        return Ok(());
    }
    Err(format!(
        "timeout={}, capture_complete={}, cleanup_complete={}, executor_error={}, exit={:?}; {}",
        run.timed_out,
        run.capture_complete,
        run.cleanup_complete,
        run.executor_error,
        run.exit_code,
        run.output
    ))
}

const DOCTOR_TOOLS: &[&str] = &[
    "sh", "swiftc", "cargo", "clang", "python3", "node", "npm", "pwsh", "go", "dotnet", "java",
];
const DOCTOR_LIVE_BUDGET: std::time::Duration = std::time::Duration::from_secs(180);

fn doctor_live_with_budget(
    budget: std::time::Duration,
    check: impl FnOnce(&mut Vec<String>) -> Result<(), String>,
) -> Result<(), String> {
    let _deadline = omgs::supervise::Deadline::after(budget);
    let mut remaining = vec!["outside-file denial".to_string()];
    remaining.extend(DOCTOR_TOOLS.iter().map(|name| name.to_string()));
    let result = check(&mut remaining);
    if omgs::supervise::Deadline::expired() {
        omgs::out::err(&format!(
            "doctor --live overall wall-clock deadline of {}s exceeded; remaining probes were not checked",
            budget.as_secs()
        ));
        for name in remaining {
            omgs::out::line(&format!(
                "{name} not checked: overall doctor deadline exceeded"
            ));
        }
        return Err("__EXIT1__".into());
    }
    result
}

fn cmd_doctor(args: &[String]) -> Result<(), String> {
    if has(args, "--live") {
        doctor_live_with_budget(DOCTOR_LIVE_BUDGET, |remaining| {
            cmd_doctor_inner(args, remaining)
        })
    } else {
        cmd_doctor_inner(args, &mut Vec::new())
    }
}

/// What this machine can and cannot do for OMGS. Executes no target code;
/// `--live` runs one fixed command inside MXC to show a denial is enforced.
fn cmd_doctor_inner(args: &[String], remaining: &mut Vec<String>) -> Result<(), String> {
    omgs::scratch::recover()?;
    use omgs::platform::which;
    let os = std::env::consts::OS;
    omgs::out::line(&format!(
        "omgs {} on {os} {}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH
    ));
    omgs::out::line(&format!("data directory: {}", data_dir().display()));
    if os == "windows" {
        omgs::out::line(&format!("note: {}", omgs::sandbox::windows_build_report()));
    }
    let ready = match omgs::sandbox::locate_executor() {
        Ok(l) => {
            omgs::out::line(&format!(
                "sandbox: MXC {} executor {} ({}), SHA-256 matches the pin",
                omgs::sandbox::MXC_VERSION,
                l.path.display(),
                l.executor.containment
            ));
            if os == "windows" {
                match omgs::sandbox::windows_policy(omgs::sandbox::windows_probe(&l.path)) {
                    Ok((_, _, notes, gaps)) => {
                        for note in notes {
                            omgs::out::line(&format!(
                                "note: {}",
                                omgs::platform::escape_controls(&note)
                            ));
                        }
                        for gap in gaps {
                            omgs::out::line(&format!(
                                "  not enforced: {}",
                                omgs::platform::escape_controls(&gap)
                            ));
                        }
                    }
                    Err(reason) => {
                        omgs::out::line(&format!(
                            "sandbox: not ready. {}",
                            omgs::platform::escape_controls(&reason)
                        ));
                        return Err(if has(args, "--live") {
                            "__EXIT3__"
                        } else {
                            "__EXIT1__"
                        }
                        .into());
                    }
                }
            }
            true
        }
        Err(e) => {
            omgs::out::line(&format!("sandbox: not ready. {e}"));
            false
        }
    };
    let (enforced, gaps) = omgs::sandbox::declared_controls(os, Tier::Test);
    omgs::out::line(if ready {
        "proof controls when MXC starts successfully (conditional limits are reported per run):"
    } else {
        "planned proof controls if a verified MXC executor becomes available:"
    });
    for e in enforced
        .iter()
        .chain(omgs::sandbox::declared_limits(os).iter())
    {
        omgs::out::line(&format!("  {e}"));
    }
    for g in &gaps {
        omgs::out::line(&format!(
            "  not enforced: {}",
            omgs::platform::escape_controls(g)
        ));
    }
    if let Some(why) = omgs::sandbox::tier2_unavailable(os) {
        omgs::out::line(&why);
    }
    let found = |names: &[&str]| -> Vec<String> {
        names
            .iter()
            .filter(|n| which(n).is_some())
            .map(|n| n.to_string())
            .collect()
    };
    let tools = found(DOCTOR_TOOLS);
    for name in DOCTOR_TOOLS {
        if !tools.iter().any(|t| t == name) {
            omgs::out::line(&format!("{name} not on host PATH"));
            remaining.retain(|probe| probe != name);
        }
    }
    omgs::out::line(&format!(
        "toolchains on PATH: {}",
        if tools.is_empty() {
            "none".into()
        } else {
            tools.join(", ")
        }
    ));
    let sensors = found(&["gitleaks", "semgrep", "trufflehog", "osv-scanner"]);
    omgs::out::line(&format!(
        "sensors on PATH: {}",
        if sensors.is_empty() {
            "none".into()
        } else {
            sensors.join(", ")
        }
    ));
    if os == "linux"
        && std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            .map(|v| v.trim() == "1")
            .unwrap_or(false)
    {
        omgs::out::line("hint: this kernel restricts unprivileged user namespaces (Ubuntu 24.04 and later). MXC needs them; see the README section on Linux for the AppArmor profile.");
    }
    if os == "windows" {
        omgs::out::line("note: upstream MXC issue https://github.com/microsoft/mxc/issues/1465 reports STATUS_DLL_INIT_FAILED for toolchains in Windows session 0; use an existing interactive desktop session when affected.");
    }
    if !ready {
        if has(args, "--live") {
            omgs::out::line("live check: not run, no verified executor");
            return Err("__EXIT3__".into());
        }
        return Err("__EXIT1__".into());
    }
    if has(args, "--live") {
        omgs::supervise::check_interrupted().map_err(|e| e.to_string())?;
        let probe = omgs::platform::scratch_root()
            .map_err(|e| e.to_string())?
            .join(format!(
                "doctor-{}",
                omgs::platform::random_nonce().map_err(|e| e.to_string())?
            ));
        omgs::platform::create_private_dir_new(&probe).map_err(|e| e.to_string())?;
        let target = probe.join("target");
        omgs::platform::create_private_tree(&target).map_err(|e| e.to_string())?;
        // Two fresh tokens: one inside the workspace that must be readable
        // (proves the command really ran), one outside that must not be.
        // Neither appears in a denial message, which echoes only the path.
        let token = |tag: &str| {
            omgs::sha256::digest(
                format!("{tag}-{}-{}", omgs::runmeta::now_ms(), std::process::id()).as_bytes(),
            )
        };
        let (inside, outside) = (token("inside"), token("outside"));
        let inside_test = "probe/deep/inside.txt";
        std::fs::create_dir_all(target.join("probe/deep")).map_err(|e| e.to_string())?;
        write_out(target.join(inside_test), inside.as_bytes()).map_err(|e| e.to_string())?;
        let secret = probe.join("outside.txt");
        write_out(&secret, outside.as_bytes()).map_err(|e| e.to_string())?;
        let cmd = if os == "windows" {
            format!(
                "cmd.exe /d /c type probe\\deep\\inside.txt & type \"{}\"",
                secret.display()
            )
        } else {
            format!("cat {inside_test}; cat '{}'", secret.display())
        };
        let request = ProveRequest {
            screenshots: false,
            expect_marker: None,
            command: cmd,
            test: Some(inside_test.into()),
            timeout_ms: 30_000,
            target: Some(target),
            run_dir: probe.join("run"),
            tier: Tier::Test,
            stage: None,
            expected_tree_sha256: None,
            inputs: None,
            expected_inputs: None,
            harness: vec![],
        };
        let outcome = match prove(&request) {
            ProveOutcome::Ran(r) => r,
            ProveOutcome::Blocked { reason } => {
                let _ = std::fs::remove_dir_all(&probe);
                omgs::out::err(&format!(
                    "needs_validation: target code was not executed. {}",
                    omgs::platform::escape_controls(&reason)
                ));
                return Err("__EXIT3__".into());
            }
        };
        let out = outcome.run.output.clone();
        let _ = std::fs::remove_dir_all(&probe);
        omgs::supervise::check_interrupted().map_err(|e| e.to_string())?;
        remaining.retain(|name| name != "outside-file denial");
        if !out.contains(&inside)
            || !outcome.run.command_started
            || !outcome.run.command_finished
            || outcome.run.test_reachable != Some(true)
            || outcome.run.timed_out
            || !outcome.run.capture_complete
            || !outcome.run.cleanup_complete
            || !outcome.run.survivors.is_empty()
        {
            omgs::out::line("live check FAILED: the probe did not run (it could not read its own workspace). Its output:");
            omgs::out::line(&(omgs::proof::redact(&out)));
            for g in &outcome.gaps {
                omgs::out::line(&format!("  note: {}", omgs::platform::escape_controls(g)));
            }
            return Err("__EXIT1__".into());
        }
        if out.contains(&outside) || outcome.run.exit_code == Some(0) {
            omgs::out::line(
                "live check FAILED: the sandboxed command could read a file outside its workspace",
            );
            return Err("__EXIT1__".into());
        }
        if outcome
            .gaps
            .iter()
            .any(|g| g.starts_with("this Windows version refuses parent directory enumeration"))
        {
            omgs::out::line("live check: the probe read a nested workspace file; outside read not proven on this host");
        } else {
            omgs::out::line("live check: the probe ran, read a nested workspace file, and was denied a file outside it");
        }
        for note in &outcome.notes {
            omgs::out::line(&format!("note: {}", omgs::platform::escape_controls(note)));
        }
        omgs::out::line("applied on that run:");
        for e in &outcome.enforced {
            omgs::out::line(&format!("  {e}"));
        }
        for g in &outcome.gaps {
            omgs::out::line(&format!(
                "  not enforced: {}",
                omgs::platform::escape_controls(g)
            ));
        }
        let mut inside = Vec::new();
        for name in &tools {
            // Per-tool limits share the overall preparation and probe budget.
            if let Err(error) = omgs::supervise::check_interrupted() {
                let _ = std::fs::remove_dir_all(&probe);
                return Err(error.to_string());
            }
            let reach = ProveRequest {
                screenshots: false,
                expect_marker: None,
                command: doctor_probe_command(os, name),
                test: None,
                timeout_ms: doctor_probe_timeout_ms(os, name),
                target: None,
                run_dir: probe.join(format!("reach-{name}")),
                tier: Tier::Test,
                stage: None,
                expected_tree_sha256: None,
                inputs: None,
                expected_inputs: None,
                harness: vec![],
            };
            let result = match prove(&reach) {
                ProveOutcome::Ran(r) => doctor_probe_result(&r.run),
                ProveOutcome::Blocked { reason } => Err(reason),
            };
            if omgs::supervise::Deadline::expired() {
                let _ = std::fs::remove_dir_all(&probe);
                return Err("__EXIT1__".into());
            }
            remaining.retain(|probe| probe != name);
            match result {
                Ok(()) => inside.push(name.as_str()),
                Err(reason) => {
                    omgs::out::line(&(doctor_tool_failure(name, &reason)));
                }
            }
        }
        omgs::out::line(&format!(
            "toolchains reachable inside the sandbox: {}",
            if inside.is_empty() {
                "none".into()
            } else {
                inside.join(", ")
            }
        ));
        let _ = std::fs::remove_dir_all(&probe);
    }
    Ok(())
}

fn cmd_approve(args: &[String]) -> Result<(), String> {
    let raw = flag(args, "--target").ok_or("approve requires --target <repo>")?;
    let target = std::fs::canonicalize(&raw).map_err(|e| format!("target {raw}: {e}"))?;
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .filter(|n| !n.is_empty())
        .ok_or(
            "approve requires a target with a folder name; filesystem roots cannot be approved",
        )?;
    if let Some(why) = omgs::sandbox::tier2_unavailable(std::env::consts::OS) {
        omgs::out::err(&format!(
            "needs_validation: target code was not executed. {why}"
        ));
        return Err("__EXIT3__".into());
    }
    omgs::out::line(&format!("Tier 2 builds and runs {} as a local app inside MXC, on dummy data, with external network denied.", target.display()));
    omgs::out::line(&format!(
        "Type the folder name '{name}' to approve tier 2 for this repository:"
    ));
    let typed = omgs::approval::read_from_terminal()?;
    if typed.trim() != name {
        return Err("not approved: the typed name did not match".into());
    }
    omgs::approval::approve(&data_dir(), &target)?;
    omgs::out::line(&format!("approved tier 2 for {}", target.display()));
    Ok(())
}

fn write_handoff(
    dir: &Path,
    handoff: &omgs::handoff::Handoff,
    artifact_base: &str,
) -> Result<(), String> {
    let mut writes = omgs::runmeta::Transaction::default();
    writes.text(
        dir.join("HANDOFF.md"),
        omgs::handoff::markdown_at(handoff, artifact_base),
    );
    writes.text(
        dir.join("handoff.json"),
        serde_json::to_string_pretty(handoff).map_err(|e| e.to_string())?,
    );
    writes.commit()
}

fn cmd_handoff(args: &[String]) -> Result<(), String> {
    let run = PathBuf::from(flag(args, "--run").ok_or("handoff requires --run <dir>")?);
    let only = flag(args, "--finding");
    omgs::handoff::publish(&run, only.as_deref(), |h| write_handoff(&run, h, ""))?;
    omgs::out::line(&format!(
        "wrote HANDOFF.md and handoff.json in {}",
        run.display()
    ));
    Ok(())
}

fn cmd_stage(args: &[String]) -> Result<(), String> {
    let run = PathBuf::from(flag(args, "--run").ok_or("stage requires --run <dir>")?);
    if omgs::runmeta::read_optional(&run)?.is_some() {
        omgs::budget::with_family_lock(&run, || cmd_stage_locked(&run))
    } else {
        omgs::runmeta::with_lock(&run, || {
            if omgs::runmeta::read_optional(&run)?.is_some() {
                return Err("run metadata appeared before test staging; retry".into());
            }
            cmd_stage_locked(&run)
        })
    }
}

fn cmd_stage_locked(run: &Path) -> Result<(), String> {
    let file = read_findings(&run.join("findings.json").to_string_lossy())?;
    let staged = omgs::handoff::stage_validated(run, &file)?;
    for reason in &staged.excluded {
        omgs::out::err(&omgs::platform::escape_controls(reason));
    }
    let mut writes = omgs::runmeta::Transaction::default();
    writes.text(run.join("proposed-tests.patch"), staged.patch.clone());
    // Only finalized findings export retained tests. Policy-aware runs also
    // produce the owner-reviewable registry and intent proposal.
    if omgs::run_artifact::optional_text(
        run,
        Path::new(omgs::runmeta::FILE),
        omgs::run_artifact::METADATA_BYTES,
    )?
    .is_some()
        && omgs::runmeta::read(run)?.contains_key("policy")
    {
        writes.text(
            run.join("policy.patch"),
            prepare_intent_proposal(run, &staged)?,
        );
    }
    writes.commit()?;
    omgs::out::line(&format!(
        "wrote {}",
        run.join("proposed-tests.patch").display()
    ));
    Ok(())
}

fn cmd_report(args: &[String]) -> Result<(), String> {
    let path = flag(args, "--findings").ok_or("report requires --findings <path>")?;
    let out = flag(args, "--out").ok_or("report requires --out <dir>")?;
    let file = read_findings(&path)?;
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
    // Admission refuses candidate artifacts without their coverage record.
    if let Some(dir) = &findings_dir {
        if omgs::run_artifact::optional_text(
            dir,
            Path::new("coverage-ledger.json"),
            omgs::run_artifact::LEDGER_BYTES,
        )?
        .is_none()
            && std::fs::read_dir(dir)
                .map_err(|e| e.to_string())?
                .flatten()
                .any(|e| {
                    let name = e.file_name();
                    let name = name.to_string_lossy();
                    name.starts_with("candidates") && name.ends_with(".json")
                })
        {
            return Err("candidates files but no coverage-ledger.json; restore the ledger so the critic can run".into());
        }
    }
    // Explicit flags override saved metadata. Verifier identities on findings
    // are a last resort. Never infer hunter counts from the surviving records:
    // hunters that found nothing or were merged into another record would be missed.
    let verifier_ids: std::collections::BTreeSet<String> = file
        .findings
        .iter()
        .filter_map(|f| identity(&f.verified_by))
        .collect();
    let supplied_usage = omgs::accounting::parse(&flags(args, "--accounting"))?;
    let saved_text = findings_dir
        .as_deref()
        .map(|d| {
            omgs::run_artifact::optional_text(
                d,
                Path::new(omgs::runmeta::FILE),
                omgs::run_artifact::METADATA_BYTES,
            )
        })
        .transpose()?
        .flatten();
    let publication_run = findings_dir.as_deref().filter(|_| saved_text.is_some());
    let saved = publication_run
        .map(omgs::runmeta::read)
        .transpose()?
        .unwrap_or_default();
    omgs::batch::check_meta_types(&saved)?;
    let submission = omgs::accounting::Submission::observe(&saved, supplied_usage)?;
    let hunters = flag(args, "--hunters")
        .and_then(|s| s.parse::<u32>().ok())
        .or_else(|| {
            saved
                .get("hunters")
                .and_then(|v| v.as_u64())
                .and_then(|n| u32::try_from(n).ok())
        });
    let verifier = flag(args, "--verifier")
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            saved
                .get("verifier")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(str::to_owned)
        })
        .or_else(|| {
            (!verifier_ids.is_empty())
                .then(|| verifier_ids.into_iter().collect::<Vec<_>>().join(", "))
        });
    let explicit_agent_calls = flag(args, "--agent-calls")
        .map(|n| {
            n.parse::<u32>()
                .map_err(|_| "--agent-calls needs a non-negative integer")
        })
        .transpose()?;
    let agent_calls = explicit_agent_calls.or_else(|| {
        saved
            .get("agent_calls_used")
            .and_then(|v| v.as_u64())
            .and_then(|n| u32::try_from(n).ok())
    });
    if hunters.is_none() || verifier.is_none() || agent_calls.is_none() {
        omgs::out::err("warning: run metadata incomplete; pass --hunters <n>, --verifier <id>, and --agent-calls <n>. Unrecorded values render as \"not recorded\".");
    }
    let mut publication = std::collections::BTreeMap::new();
    for (option, key) in [
        ("--repo", "repo"),
        ("--ref", "source_ref"),
        ("--sandbox", "sandbox"),
    ] {
        if let Some(value) = flag(args, option) {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(format!(
                    "{option} needs nonblank publication text without control characters"
                ));
            }
            publication.insert(key, value);
        }
    }
    let supplied_models = omgs::route::parse_identities(&flags(args, "--model"))?;
    omgs::report::publish_prepared(
        findings_dir.as_deref(),
        explicit_agent_calls,
        &supplied_models,
        &publication,
        |saved, writes| {
            submission.apply(saved)?;
            omgs::runmeta::check_numeric_fields(saved)?;
            let saved = saved.clone();
            let run = findings_dir.as_deref().unwrap_or(Path::new("."));
            let proposed_progress = if run.join(omgs::status::FILE).exists() {
                Some(omgs::status::propose_locked(
                    run,
                    &omgs::status::Update {
                        stage: "report",
                        label: None,
                        parent: None,
                        state: "done",
                        detail: None,
                        counters: &[],
                        log: None,
                    },
                    &[],
                )?)
            } else {
                None
            };
            let fresh = read_findings(&path)?;
            let errors = omgs::model::validate_drafts(&fresh);
            if !errors.is_empty() {
                for error in &errors {
                    omgs::out::err(&format!(
                        "invalid: {}",
                        omgs::platform::escape_controls(error)
                    ));
                }
                return Err("__EXIT1__".into());
            }
            let view = omgs::review::View::for_report_locked(
                run,
                &fresh,
                &saved,
                proposed_progress.as_ref(),
            )?;
            if proposed_progress.is_some() {
                writes.text(
                    run.join(omgs::status::FILE),
                    serde_json::to_string_pretty(&view.progress).map_err(|e| e.to_string())?,
                );
            }
            if !view.proof_errors.is_empty() {
                for error in &view.proof_errors {
                    omgs::out::err(&format!(
                        "invalid: {}",
                        omgs::platform::escape_controls(error)
                    ));
                }
                return Err("__EXIT1__".into());
            }
            let accounting = view.accounting.clone();
            let hunters = flag(args, "--hunters")
                .and_then(|s| s.parse::<u32>().ok())
                .or_else(|| {
                    saved
                        .get("hunters")
                        .and_then(|v| v.as_u64())
                        .and_then(|n| u32::try_from(n).ok())
                });
            let verifier = flag(args, "--verifier")
                .or_else(|| {
                    saved
                        .get("verifier")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned)
                })
                .or_else(|| {
                    let ids: std::collections::BTreeSet<_> = view
                        .findings
                        .findings
                        .iter()
                        .filter_map(|f| identity(&f.verified_by))
                        .collect();
                    (!ids.is_empty()).then(|| ids.into_iter().collect::<Vec<_>>().join(", "))
                });
            let agent_calls = saved
                .get("agent_calls_used")
                .and_then(|v| v.as_u64())
                .and_then(|n| u32::try_from(n).ok());
            let persona = flag(args, "--persona")
                .or_else(|| {
                    saved
                        .get("persona")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned)
                })
                .unwrap_or_default();
            if !persona.is_empty() {
                omgs::persona::defaults(&persona)?;
            }
            let report_depth = if persona == "builder" {
                "concise"
            } else {
                "full"
            }
            .to_string();
            let defaulted = |explicit: Option<String>, key: &str, fallback: &str| {
                explicit
                    .or_else(|| {
                        saved
                            .get("publication")
                            .and_then(|p| p.get(key))
                            .or_else(|| saved.get(key))
                            .and_then(|v| v.as_str())
                            .map(str::to_owned)
                    })
                    .unwrap_or_else(|| fallback.into())
            };
            let mut models = run_models(findings_dir.as_deref())?;
            for (role, model) in &supplied_models {
                models.retain(|line| !line.starts_with(&format!("{role}:")));
                models.push(format!("{role}: {model}"));
            }
            models.sort();
            let mut meta = ReportMeta {
                repo: defaulted(None, "repo", "target"),
                source_ref: defaulted(None, "source_ref", "working tree"),
                mode: defaulted(flag(args, "--mode"), "mode", "advisory"),
                sandbox: defaulted(None, "sandbox", "not recorded"),
                artifact_base: String::new(),
                review_limits: Vec::new(),
                timeline: Vec::new(),
                coverage: Vec::new(),
                sensors: None,
                hunters,
                verifier,
                agent_calls,
                critic: None,
                models,
                reroutes: run_reroutes(findings_dir.as_deref())?,
                intent_answers: run_answers(findings_dir.as_deref())?,
                screenshots: Default::default(),
                accounting,
                persona,
                report_depth,
            };
            view.apply(&mut meta);
            let file = view.findings.clone();
            let handoff = omgs::handoff::build_view(
                findings_dir.as_deref().unwrap_or(Path::new(".")),
                &view,
                None,
            )?;
            let dir = Path::new(&out);
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            if let Some(run) = &findings_dir {
                meta.artifact_base = omgs::report::artifact_base(dir, run)?;
                meta.screenshots = omgs::report::screenshots(run, &file);
                meta.sandbox = omgs::report::sandbox_text(run, &meta.sandbox);
            }
            let sensors = findings_dir
                .as_deref()
                .map(omgs::sensors::read_report)
                .transpose()?
                .flatten();
            meta.sensors = sensors.as_ref().map(|rep| format!(
                "{} run, {} hit(s), {} vendored; pattern matches only, never a clean bill of health",
                if rep.tools_run.is_empty() { "no tools".into() } else { rep.tools_run.join(", ") },
                rep.hits.len(), rep.hits.iter().filter(|h| h.vendored).count()
            ));
            let evidence = omgs::adjudication::report_lines_view(run, &view)?;
            let evidence_md = omgs::adjudication::render_lines(&evidence, false);
            let evidence_html = omgs::adjudication::render_lines(&evidence, true);
            let sensor_md = omgs::report::sensor_section(sensors.as_ref(), false);
            let sensor_html = omgs::report::sensor_section(sensors.as_ref(), true);
            writes.text(
                dir.join("REPORT.md"),
                format!("{}{sensor_md}{evidence_md}", render_markdown(&file, &meta)),
            );
            writes.text(
                dir.join("REPORT.html"),
                render_html(&file, &meta)
                    .replace("</body>", &format!("{sensor_html}{evidence_html}</body>")),
            );
            writes.text(dir.join("findings.sarif.json"), render_sarif(&file, &meta));
            writes.text(
                dir.join("HANDOFF.md"),
                omgs::handoff::markdown_at(&handoff, &meta.artifact_base),
            );
            writes.text(
                dir.join("handoff.json"),
                serde_json::to_string_pretty(&handoff).map_err(|e| e.to_string())?,
            );
            let completion = omgs::report::Completion {
                hunters: meta.hunters,
                verifier: meta.verifier.clone(),
                complete: view.complete(),
            };

            Ok(completion)
        },
    )?;
    let dir = Path::new(&out);
    omgs::out::line(&format!(
        "wrote {}, {}, {}, {}, {}",
        dir.join("REPORT.md").display(),
        dir.join("REPORT.html").display(),
        dir.join("findings.sarif.json").display(),
        dir.join("HANDOFF.md").display(),
        dir.join("handoff.json").display()
    ));
    Ok(())
}

/// The reviewer's answer store for `target`, only when it physically lives
/// outside the target: HOME, the store directory, or any parent resolving
/// into the target (or the store file being a link) would let the target
/// author "recorded" answers.
fn trusted_store(target: &Path) -> Result<PathBuf, String> {
    let path = omgs::intent::answers_file(&data_dir(), target);
    // Publishers replace the leaf atomically. Resolve its stable parent so
    // canonicalization cannot race that replacement; the leaf is checked
    // separately here and opened without following links by read_store.
    let parent = path.parent().ok_or("intent answer store needs a parent")?;
    // Compare the parent, never the leaf: the store is a regular file, so it
    // lies inside the target exactly when its directory does. Opening the leaf
    // outside the writer's lock fails on Windows while it is being replaced.
    let resolved = resolve_existing_prefix(parent)?;
    if omgs::paths::overlaps(&resolved, target)? {
        return Err(format!(
            "the intent answer store {} resolves inside the target {}; refusing to use it",
            path.display(),
            target.display()
        ));
    }
    if std::fs::symlink_metadata(&path).is_ok_and(|m| !m.file_type().is_file()) {
        return Err(format!(
            "the intent answer store {} is not a regular file; refusing to use it",
            path.display()
        ));
    }
    if parent.exists() {
        omgs::platform::check_private_dir(parent)
            .map_err(|e| format!("owner-private intent store: {e}"))?;
    }
    Ok(path)
}

/// Read the reviewer's answer store through a descriptor opened without
/// following links, and only when it is a regular file with exactly one link,
/// so neither a symlink nor a hardlink planted in the target can change what
/// the store says. A missing store means no answers yet.
fn read_store(path: &Path) -> Result<omgs::intent::Answers, String> {
    omgs::intent::load_answers(path)
}

/// A missing store is a new store for this exact target. Existing stores must
/// name the target, including when they contain no answers.
fn read_target_store(target: &Path) -> Result<omgs::intent::Answers, String> {
    let path = trusted_store(target)?;
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(omgs::intent::Answers {
                target: target.to_string_lossy().into_owned(),
                answers: Vec::new(),
            });
        }
        Err(e) => return Err(e.to_string()),
        Ok(_) => {}
    }
    let store = read_store(&path)?;
    if Path::new(&store.target) != target {
        return Err("the reviewer's store for this path belongs to another target".into());
    }
    Ok(store)
}

/// Each run has an independent record in the existing reviewer-owned store.
/// Bind to the physical path rather than metadata that an artifact writer edits.
fn trusted_policy_path(target: &Path, run: &Path) -> Result<PathBuf, String> {
    let store = trusted_store(target)?;
    let parent = store.parent().ok_or("trusted store needs a parent")?;
    let resolved = resolve_existing_prefix(parent)?;
    if omgs::paths::overlaps(&resolved, run)? {
        return Err("trusted policy store must live outside the run directory".into());
    }
    let run_hash = omgs::sha256::digest(run.as_os_str().as_encoded_bytes());
    let name = store
        .file_stem()
        .ok_or("trusted store needs a name")?
        .to_string_lossy();
    Ok(parent.join(format!("{name}-policy-{run_hash}.json")))
}

fn authenticated_policy(
    run: &Path,
    target: &Path,
) -> Result<omgs::policy::AuthenticatedPolicy, String> {
    let run = std::fs::canonicalize(run).map_err(|e| e.to_string())?;
    let target = std::fs::canonicalize(target).map_err(|e| e.to_string())?;
    let path = trusted_policy_path(&target, &run)?;
    let bytes = omgs::platform::read_bounded(&path, omgs::policy::MAX_BYTES)
        .map_err(|e| format!("trusted policy record unavailable: {e}; initialize a fresh audit; see docs/policy-workflow.md#pre-policy-runs"))?;
    let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
    let record = serde_json::from_value(omgs::shape::strict_json(text)?).map_err(|e| {
        format!("invalid trusted policy record: {e}; re-initialize into a new output path")
    })?;
    omgs::policy::committed_snapshot(&run, &target, &record)
}

fn save_trusted_policy(
    target: &Path,
    run: &Path,
    generation: &str,
    snapshot: &omgs::policy::Snapshot,
) -> Result<(), String> {
    let run = std::fs::canonicalize(run).map_err(|e| e.to_string())?;
    let path = trusted_policy_path(target, &run)?;
    omgs::platform::create_private_tree(path.parent().ok_or("trusted store needs a parent")?)
        .map_err(|e| e.to_string())?;
    // Re-resolve and admit the store after creating it.
    let path = trusted_policy_path(target, &run)?;
    let record = omgs::policy::TrustedPolicy::new(target, &run, generation, snapshot)?;
    let text = serde_json::to_string_pretty(&record).map_err(|e| e.to_string())?;
    if text.len() as u64 > omgs::policy::MAX_BYTES {
        return Err("trusted policy record exceeds 1 MiB".into());
    }
    omgs::platform::write_private_new(&path, text.as_bytes()).map_err(|e| {
        format!("cannot publish trusted policy record: {e}; re-initialize into a new output path")
    })
}

/// The run's intent answers, only when they belong to the run's target as
/// recorded in run metadata; anything else is ignored with a warning.
fn run_answers(dir: Option<&Path>) -> Result<omgs::intent::Answers, String> {
    let Some(dir) = dir else {
        return Ok(Default::default());
    };
    let answers = match omgs::run_artifact::optional_text(
        dir,
        Path::new("intent-answers.json"),
        omgs::run_artifact::ANSWERS_BYTES,
    )? {
        Some(text) => omgs::intent::parse_answers(&text)?,
        None => Default::default(),
    };
    if answers.answers.is_empty() {
        return Ok(answers);
    }
    // Provenance: answers render only when the run directory sits outside the
    // target it names, and each answer also exists in the reviewer's own
    // store for that target. Files next to the findings could have been
    // written by the target itself, so matching them to each other proves
    // nothing.
    let refuse = |why: &str| {
        omgs::out::err(&format!("warning: intent answers not shown: {why}"));
        Ok(Default::default())
    };
    let target = omgs::runmeta::read_optional(dir)?
        .and_then(|m| m.get("target").and_then(|t| t.as_str()).map(PathBuf::from))
        .and_then(|t| std::fs::canonicalize(t).ok());
    let Some(target) = target else {
        return refuse("run metadata names no existing target");
    };
    let run = std::fs::canonicalize(dir).map_err(|e| e.to_string())?;
    if omgs::paths::overlaps(&run, &target)? {
        return refuse("the run directory is inside the target");
    }
    if Path::new(&answers.target) != target {
        return refuse("they belong to a different target");
    }
    let store = match read_target_store(&target) {
        Ok(s) => s,
        Err(e) => return refuse(&e),
    };
    // Run-local policy contents cannot attest owner acceptance. Read the
    // committed blob again using the same object-only path as init and gate.
    let accepted = match authenticated_policy(dir, &target) {
        Ok(s) => s.into_snapshot().policy.accepted_intent,
        Err(e) => {
            omgs::out::err(&format!(
                "warning: policy-derived intent answers not shown: {e}"
            ));
            Vec::new()
        }
    };
    let total = answers.answers.len();
    let kept: Vec<_> = answers
        .answers
        .into_iter()
        .filter(|a| {
            store.answers.contains(a)
                || accepted.iter().any(|p| {
                    p.id == a.id
                        && p.answer == a.answer
                        && p.scope == a.scope
                        && p.source == a.source
                })
        })
        .collect();
    if kept.len() < total {
        omgs::out::err(&format!(
            "warning: {} intent answer(s) not in the reviewer's store were not shown",
            total - kept.len()
        ));
    }
    Ok(omgs::intent::Answers {
        target: answers.target,
        answers: kept,
    })
}

/// "role: model" lines from run metadata `models`, sorted by role.
fn run_models(dir: Option<&Path>) -> Result<Vec<String>, String> {
    let Some(meta) = dir.map(omgs::runmeta::read_optional).transpose()?.flatten() else {
        return Ok(Vec::new());
    };
    Ok(meta
        .get("models")
        .and_then(|m| m.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(role, model)| model.as_str().map(|v| format!("{role}: {v}")))
                .collect()
        })
        .unwrap_or_default())
}

/// One line per recorded reroute, in the order they happened.
fn run_reroutes(dir: Option<&Path>) -> Result<Vec<String>, String> {
    let Some(meta) = dir.map(omgs::runmeta::read_optional).transpose()?.flatten() else {
        return Ok(Vec::new());
    };
    Ok(meta
        .get("reroutes")
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
        .unwrap_or_default())
}

/// Mutable run output goes through an atomic replace, so a planted symlink
/// or hardlink at the destination is
/// replaced rather than written through into another location.
fn write_out(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    omgs::runmeta::write_atomic_bytes(path.as_ref(), contents.as_ref())
}

/// Never a relative fallback: without a home OMGS would write into the cwd,
/// which may be the target.
fn home() -> PathBuf {
    omgs::platform::home().unwrap_or_else(|| {
        omgs::out::err("error: HOME (USERPROFILE on Windows) must be set to an absolute path");
        std::process::exit(2)
    })
}

fn data_dir() -> PathBuf {
    omgs::platform::data_dir().unwrap_or_else(|| home().join(".local").join("share").join("omgs"))
}

/// Counts describe omitted entries or subtrees, never guessed file totals.
#[derive(Default)]
struct InventoryGap {
    count: usize,
    samples: std::collections::BTreeSet<String>,
}

#[derive(Default)]
struct InventoryGaps(std::collections::BTreeMap<&'static str, InventoryGap>);
impl InventoryGaps {
    fn record(&mut self, reason: &'static str, path: &Path, root: &Path) {
        let gap = self.0.entry(reason).or_default();
        gap.count += 1;
        gap.samples
            .insert(omgs::platform::escape_controls(&omgs::paths::display(
                path.strip_prefix(root).unwrap_or(path),
            )));
        if gap.samples.len() > 20 {
            gap.samples.pop_last();
        }
    }

    fn description(reason: &str, gap: &InventoryGap, limit: usize) -> String {
        let reason = match reason {
            "depth" => "depth limit of 12 exceeded; subtrees not traversed".into(),
            "symlink" => "symlinks or reparse points skipped; targets not traversed".into(),
            "read" => "directory or entry read failed; content not inventoried".into(),
            _ => format!(
                "inventory size limit of {limit} files reached; remaining paths not inventoried"
            ),
        };
        format!(
            "{reason}; {} omitted entry/subtree event(s); first {} sorted samples: {}",
            gap.count,
            gap.samples.len(),
            gap.samples.iter().cloned().collect::<Vec<_>>().join(", ")
        )
    }
}

fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    walk_limited(
        dir,
        dir,
        depth,
        out,
        omgs::stacks::INVENTORY_LIMIT,
        &mut InventoryGaps::default(),
    );
}

fn walk_limited(
    root: &Path,
    dir: &Path,
    depth: usize,
    out: &mut Vec<PathBuf>,
    limit: usize,
    gaps: &mut InventoryGaps,
) -> bool {
    if depth > 12 {
        gaps.record("depth", dir, root);
        return false;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => {
            gaps.record("read", dir, root);
            return false;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                gaps.record("read", dir, root);
                continue;
            }
        };
        let path = entry.path();
        if out.len() >= limit {
            gaps.record("limit", &path, root);
            return true;
        }
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(_) => {
                gaps.record("read", &path, root);
                continue;
            }
        };
        if omgs::platform::is_link(&meta) {
            gaps.record("symlink", &path, root);
            continue;
        }
        if meta.is_dir() {
            if entry.file_name() == ".git" {
                continue;
            }
            if walk_limited(root, &path, depth + 1, out, limit, gaps) {
                return true;
            }
        } else if meta.is_file() {
            out.push(path);
        }
    }
    false
}

fn cmd_audit(args: &[String]) -> Result<(), String> {
    if args.first().map(|s| s.as_str()) != Some("init") {
        return Err("usage: omgs audit init --target <repo>".into());
    }
    let run = audit_init(&args[1..])?;
    let meta = omgs::runmeta::read(&run)?;
    let target = meta
        .get("target")
        .and_then(|v| v.as_str())
        .ok_or("run lacks target")?;
    omgs::out::err(&(brief(Path::new(target), &run)?));
    omgs::out::line(&format!("{}", run.display()));
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

fn admit_bundle_cache(fences: &[PathBuf]) -> Result<(), String> {
    let cache = resolve_existing_prefix(&bundle_cache())?;
    let store_root = data_dir().join("intent");
    for fence in fences.iter().chain(std::iter::once(&store_root)) {
        if !omgs::paths::overlaps(&cache, fence)? {
            continue;
        }
        return Err(format!(
            "the skill bundle cache {} overlaps {}; set OMGS_HOME outside the target and the run output",
            cache.display(),
            fence.display()
        ));
    }
    Ok(())
}

/// Initialize a run and return its directory.
fn audit_init(rest: &[String]) -> Result<PathBuf, String> {
    validate_output_paths(rest)?;
    selected_skill(rest)?;
    let target = flag(rest, "--target").ok_or("audit init requires --target <repo>")?;
    let target = std::fs::canonicalize(&target).map_err(|e| format!("target {target}: {e}"))?;
    // Admit storage boundaries before materializing the default bundle. In
    // particular, a cache must not populate a target or an invalid run output.
    trusted_store(&target)?;
    let mut fences = vec![target.clone()];
    let out = flag(rest, "--out").map(PathBuf::from).unwrap_or_else(|| {
        data_dir().join(
            target
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("target")),
        )
    });
    omgs::platform::validate_output_path(&out)?;
    trusted_policy_path(&target, &out)?;
    if omgs::paths::overlaps(&target, &out)? {
        return Err(
            "run output must live outside the target tree, so findings never enter git history"
                .into(),
        );
    }
    if has(rest, "--clone-root") {
        let root = clone_root(rest)?;
        admit_clone_storage(&root, &target, &out)?;
        fences.push(root);
    }
    fences.push(out);
    admit_bundle_cache(&fences)?;
    let skill = review_skill(rest)?;
    admit_bundle_cache(&fences)?;
    let run = audit_init_selected(rest)?;
    admit_bundle_cache(&fences)?;
    omgs::runmeta::update(&run, |meta| {
        meta.insert("skill_dir".into(), serde_json::json!(skill));
        meta.insert("skill_identity".into(), omgs::setup::identity());
        Ok(())
    })?;
    Ok(run)
}

fn audit_init_selected(rest: &[String]) -> Result<PathBuf, String> {
    let Some(parent) = flag(rest, "--fix-of") else {
        return audit_init_limited(rest, omgs::stacks::INVENTORY_LIMIT);
    };
    if flag(rest, "--budget").is_some() {
        return Err("--fix-of computes the budget; omit --budget".into());
    }
    let target = flag(rest, "--target").ok_or("audit init requires --target <repo>")?;
    authenticated_policy(Path::new(&parent), Path::new(&target))?;
    omgs::budget::init_fix(
        Path::new(&parent),
        |root| {
            Ok(authenticated_policy(root, Path::new(&target))?
                .snapshot()
                .policy
                .budget)
        },
        |root, original, remaining| {
            let target = flag(rest, "--target").ok_or("audit init requires --target <repo>")?;
            let target = std::fs::canonicalize(target).map_err(|e| e.to_string())?;
            if original.get("target").and_then(|v| v.as_str()) != target.to_str() {
                return Err("fix run target must match its original run".into());
            }
            let runs_dir = root.parent().ok_or("original run needs a runs directory")?;
            let output_parent = if let Some(out) = flag(rest, "--out") {
                let out = PathBuf::from(out);
                let absolute = if out.is_absolute() {
                    out
                } else {
                    std::env::current_dir()
                        .map_err(|e| e.to_string())?
                        .join(out)
                };
                resolve_existing_prefix(absolute.parent().ok_or("fix output needs a parent")?)?
            } else {
                data_dir().join(target.file_name().ok_or("target needs a name")?)
            };
            if resolve_existing_prefix(&output_parent)? != runs_dir {
                return Err("fix run must be in the trusted runs directory; supply --out with a sibling of the original run".into());
            }
            let mut args = rest.to_vec();
            if let Some(cap) = remaining {
                args.extend(["--budget".into(), cap.to_string()]);
            }
            let run = audit_init_limited(&args, omgs::stacks::INVENTORY_LIMIT)?;
            if remaining.is_none() {
                // Persona defaults must not invent a cap for an uncapped original.
                omgs::runmeta::update(&run, |m| {
                    m.remove("budget_agent_calls");
                    Ok(())
                })?;
            }
            Ok(run)
        },
    )
}

fn audit_init_limited(rest: &[String], inventory_limit: usize) -> Result<PathBuf, String> {
    let target_raw = flag(rest, "--target").ok_or("audit init requires --target <repo>")?;
    let target =
        std::fs::canonicalize(&target_raw).map_err(|e| format!("target {target_raw}: {e}"))?;
    target
        .to_str()
        .ok_or("audit init requires a UTF-8 target path")?;
    let repo = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "target".into());
    // Validate every input and read the answer store before claiming a run
    // directory, so a mistyped option or an untrusted store never leaves a
    // claimed, half-written run behind.
    let base = flag(rest, "--base");
    let mut policy = if let Some(parent) = flag(rest, "--fix-of") {
        let inherited = authenticated_policy(Path::new(&parent), &target)?.into_snapshot();
        if base.is_some() {
            return Err("fix runs inherit base policy; omit --base".into());
        }
        inherited
    } else {
        omgs::policy::load_base(&target, base.as_deref())?
    };
    let committed = policy.original.is_some();
    let selected_persona = flag(rest, "--persona");
    let selected_mode = flag(rest, "--mode");
    let selected_budget = flag(rest, "--budget")
        .map(|v| {
            v.parse::<u64>()
                .map_err(|_| format!("--budget must be a whole number, got '{v}'"))
        })
        .transpose()?;
    if committed
        && (selected_mode
            .as_ref()
            .is_some_and(|m| m != policy.policy.mode.label())
            || selected_persona
                .as_ref()
                .is_some_and(|p| Some(p) != policy.policy.persona.as_ref())
            || (selected_budget.is_some()
                && selected_budget != policy.policy.budget
                && !has(rest, "--fix-of")))
    {
        return Err("CLI overrides conflict with committed base policy".into());
    }
    let persona = selected_persona
        .or_else(|| policy.policy.persona.clone())
        .map(|p| omgs::persona::defaults(&p))
        .transpose()?;
    let mode = if committed {
        policy.policy.mode.label().to_string()
    } else {
        selected_mode.unwrap_or_else(|| policy.policy.mode.label().into())
    };
    if mode != "gate" && mode != "advisory" {
        return Err("--mode must be gate or advisory".into());
    }
    let budget = if committed {
        if has(rest, "--fix-of") {
            selected_budget.map(|cap| policy.policy.budget.map_or(cap, |p| cap.min(p)))
        } else {
            policy.policy.budget
        }
    } else if has(rest, "--fix-of") {
        selected_budget
    } else {
        selected_budget
            .or(policy.policy.budget)
            .or(persona.map(|p| p.budget))
    };
    if !committed {
        policy.policy.mode = if mode == "gate" {
            omgs::policy::Mode::Gate
        } else {
            omgs::policy::Mode::Advisory
        };
        policy.policy.persona = persona.map(|p| p.name.to_string());
        policy.policy.budget = budget;
        policy.sha256 = omgs::sha256::digest(omgs::policy::text(&policy.policy)?.as_bytes());
    }
    let answers_src = trusted_store(&target)?;
    let answers = if answers_src.is_file() {
        let answers = read_store(&answers_src)?;
        if Path::new(&answers.target) == target {
            Some(answers)
        } else {
            omgs::out::err(&format!(
                "warning: {} belongs to {}, not {}; intent answers not copied",
                answers_src.display(),
                answers.target,
                target.display()
            ));
            None
        }
    } else {
        None
    };
    let outside = |p: &Path| -> Result<(), String> {
        if has(rest, "--clone-root") {
            admit_clone_storage(&clone_root(rest)?, &target, p)?;
        }
        admit_bundle_cache(&[target.clone(), p.to_path_buf()])?;
        trusted_policy_path(&target, p)?;
        if omgs::paths::overlaps(p, &target)? {
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
            let parent = out_abs
                .parent()
                .ok_or("run output needs a runs directory")?;
            omgs::platform::create_private_tree(parent)
                .map_err(|e| format!("owner-private runs directory {}: {e}", parent.display()))?;
            omgs::platform::create_private_dir(&out_abs).map_err(|e| e.to_string())?;
            out_abs
        }
        None => {
            // Claim run-N with an exclusive create, so parallel inits (batch
            // mode) never share a run directory.
            let base = data_dir().join(&repo);
            omgs::platform::validate_output_path(&base)?;
            outside(&base)?;
            omgs::platform::create_private_tree(&base).map_err(|e| {
                format!(
                    "default run storage {}: {e}; see README.md#storage-migration",
                    base.display()
                )
            })?;
            let mut n = 1;
            loop {
                let candidate = base.join(format!("run-{n}"));
                outside(&candidate)?;
                match omgs::platform::create_private_dir_new(&candidate) {
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
    let generation = omgs::platform::random_nonce().map_err(|e| e.to_string())?;
    omgs::platform::write_private_new(&out_abs.join(".omgs-claim"), generation.as_bytes())
        .map_err(|e| format!("run already claimed ({e}); re-initialize into a new output path"))?;
    omgs::platform::check_private_dir(&out_abs).map_err(|e| e.to_string())?;
    if out_abs.starts_with("/tmp") || out_abs.starts_with("/private/tmp") {
        omgs::out::err("warning: run output is under a shared temp directory and describes vulnerabilities. Prefer the default runs directory under your home.");
    }
    save_trusted_policy(&target, &out_abs, &generation, &policy)?;
    let source_ref = omgs::proof::git_head(&target).unwrap_or_else(|| "working tree".into());
    let mut files = Vec::new();
    let mut omissions = InventoryGaps::default();
    walk_limited(
        &target,
        &target,
        0,
        &mut files,
        inventory_limit,
        &mut omissions,
    );
    let native_paths: Vec<PathBuf> = files
        .iter()
        .filter_map(|f| f.strip_prefix(&target).ok().map(Path::to_path_buf))
        .collect();
    let rel_paths: Vec<String> = native_paths
        .iter()
        .map(|p| omgs::paths::display(p))
        .collect();
    let classified: Vec<_> = native_paths
        .iter()
        .zip(&rel_paths)
        .map(|(native, rel)| (rel.clone(), omgs::paths::classify_file(&target, native)))
        .collect();
    let counts = omgs::architecture::path_counts(&classified);
    let vendored_count = counts
        .get(&omgs::paths::Class::Vendored)
        .copied()
        .unwrap_or(0);
    let first_party: Vec<String> = classified
        .iter()
        .filter(|(path, class)| {
            *class == omgs::paths::Class::Code && !omgs::policy::excludes(&policy.policy, path)
        })
        .map(|(path, _)| path.clone())
        .collect();
    let projects = omgs::stacks::detect(&target, &native_paths);
    let stacks: Vec<_> = projects
        .iter()
        .flat_map(|p| p.stacks.iter().copied())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut units = Vec::new();
    for rel in &first_party {
        let is_route = rel.ends_with("/route.ts")
            || rel.ends_with("/route.tsx")
            || rel.starts_with("pages/api/")
            || rel.contains("/pages/api/");
        if is_route {
            let mut unit = Unit::new(
                &format!("route:{rel}"),
                rel,
                &["missing_authz", "idor_tenant_isolation", "client_only_auth"],
                "planned",
            );
            unit.extra
                .insert("checklist".into(), serde_json::json!("operations"));
            units.push(unit);
        }
    }
    units.extend(omgs::mapping::native_units(&target, &native_paths));
    for project in &projects {
        for stack in &project.stacks {
            let id = if project.root == "." {
                format!("stack:{stack}")
            } else {
                format!("stack:{}:{stack}", project.root)
            };
            let mut unit = Unit::new(
                &id,
                &project.root,
                &omgs::stack_attack_classes(stack),
                "planned",
            );
            unit.extra
                .insert("checklist".into(), serde_json::json!("partition"));
            unit.note = Some("Mapping placeholder: split into bounded surface/boundary/class units before hunter dispatch; cite those unit ids when closing this checklist. Never use it to duplicate candidate ownership.".into());
            units.push(unit);
        }
    }
    for project in projects.iter().filter(|p| p.stacks.is_empty()) {
        units.push(Unit::new(
            &format!("project:{}:generic", project.root),
            &project.root,
            &["missing_authz", "input_validation"],
            "planned",
        ));
    }
    for class in counts.keys().copied() {
        let Some((id, label)) = omgs::paths::exclusion_group(class) else {
            continue;
        };
        let count = counts.get(&class).copied().unwrap_or(0);
        if count > 0 {
            let mut unit = Unit::new(id, &format!("{count} {label} file(s)"), &[], "planned");
            unit.note = Some(format!(
                "{count} {label} file(s) require review before exclusion"
            ));
            let mut paths: Vec<_> = classified
                .iter()
                .filter(|(_, c)| *c == class)
                .map(|(p, _)| p.clone())
                .collect();
            paths.sort();
            // Include all exclusions, including unknown executable formats, so
            // extending source recognition cannot conceal a coverage change.
            unit.extra
                .insert("excluded_count".into(), serde_json::json!(paths.len()));
            unit.extra.insert(
                "excluded_paths".into(),
                serde_json::json!(&paths[..paths.len().min(20)]),
            );
            let mut source_paths: Vec<_> = paths
                .into_iter()
                .filter(|p| omgs::paths::is_source(p))
                .collect();
            unit.extra.insert(
                "excluded_source_count".into(),
                serde_json::json!(source_paths.len()),
            );
            source_paths.truncate(20);
            if !source_paths.is_empty() {
                unit.note.as_mut().unwrap().push_str(&format!(
                    "; first {} excluded source path(s), sorted: {}",
                    source_paths.len(),
                    source_paths.join(", ")
                ));
            }
            unit.extra.insert(
                "excluded_source_paths".into(),
                serde_json::json!(source_paths),
            );
            units.push(unit);
        }
    }
    for prefix in &policy.policy.excluded_paths {
        let mut paths: Vec<_> = rel_paths
            .iter()
            .filter(|p| *p == prefix || p.starts_with(&format!("{prefix}/")))
            .cloned()
            .collect();
        paths.sort();
        let mut unit = Unit::new(&format!("policy:excluded:{prefix}"), prefix, &[], "planned");
        unit.note = Some(format!(
            "{} policy-excluded file(s) require review before exclusion",
            paths.len()
        ));
        unit.extra
            .insert("excluded_count".into(), serde_json::json!(paths.len()));
        unit.extra.insert(
            "excluded_paths".into(),
            serde_json::json!(&paths[..paths.len().min(20)]),
        );
        let sources: Vec<_> = paths.iter().filter(|p| omgs::paths::is_source(p)).collect();
        unit.extra.insert(
            "excluded_source_count".into(),
            serde_json::json!(sources.len()),
        );
        unit.extra.insert(
            "excluded_source_paths".into(),
            serde_json::json!(&sources[..sources.len().min(20)]),
        );
        units.push(unit);
    }
    let inventory_gaps: Vec<String> = omissions
        .0
        .iter()
        .map(|(reason, gap)| InventoryGaps::description(reason, gap, inventory_limit))
        .collect();
    for (reason, gap) in &omissions.0 {
        let mut unit = Unit::new(&format!("inventory:{reason}"), ".", &[], "blocked");
        unit.note = Some(InventoryGaps::description(reason, gap, inventory_limit));
        unit.extra
            .insert("inventory_gap_reason".into(), serde_json::json!(reason));
        unit.extra
            .insert("inventory_gap_count".into(), serde_json::json!(gap.count));
        unit.extra.insert(
            "inventory_gap_samples".into(),
            serde_json::json!(gap.samples),
        );
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
    let mut ledger = Ledger {
        units,
        ..Ledger::default()
    };
    ledger
        .extra
        .insert("scope_root".into(), serde_json::json!(target));
    let started_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut meta = serde_json::json!({
        "repo": repo, "target": target.to_string_lossy(), "source_ref": source_ref,
        "run_id": omgs::platform::random_nonce().map_err(|e| e.to_string())?,
        "sandbox": omgs::sandbox::REQUIRED_TEXT,
        "mode": mode, "budget_agent_calls": budget, "execution_profile": "standard",
        "policy": policy,
        "persona": persona.map(|p| p.name), "report_depth": persona.map_or("full", |p| p.report_depth),
        "budget_profile": persona.map_or("standard", |p| if budget == Some(p.budget) { p.budget_profile } else { "custom" }),
        "persona_budget_profile": persona.map(|p| p.budget_profile),
        "persona_budget_default": persona.map(|p| p.budget),
        "budget_semantics": "combined_calls_proofs_replays",
        "inventory_gaps": inventory_gaps,
        "inventory_limit": inventory_limit,
        "accounting": omgs::accounting::read(&serde_json::Map::new())?,
        "execution_policy": "sandboxed-source-and-local-only", "run_status": "in_progress",
        "detected_stacks": stacks.clone(),
        "subprojects": projects,
        "path_classes": counts,
        "files_total": rel_paths.len(),
        "files_first_party": first_party.len(),
        "files_vendored_excluded": vendored_count,
        "started_unix": started_unix,
        "hunter": flag(rest, "--hunter"),
        "verifier": flag(rest, "--verifier")
    });
    if budget.is_none() {
        meta.as_object_mut().unwrap().remove("budget_agent_calls");
    }
    write_out(
        out_abs.join("run-metadata.json"),
        serde_json::to_string_pretty(&meta).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    write_out(
        out_abs.join("coverage-ledger.json"),
        serde_json::to_string_pretty(&ledger).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    write_out(out_abs.join("findings.json"), "{\n  \"findings\": []\n}\n")
        .map_err(|e| e.to_string())?;
    let arch_seed = serde_json::json!({
        "target": target.to_string_lossy(),
        "source_ref": source_ref,
        "stack": {
            "notes": format!(
                "Detected stacks: {}. Files: {} total, {} first party code, {} vendored excluded. Subprojects: {}. Classes: {}.",
                if stacks.is_empty() { "none recognized".to_string() } else { stacks.join(", ") },
                rel_paths.len(),
                first_party.len(),
                vendored_count,
                projects.iter().map(|p| format!("{}: {}", p.root, p.stacks.join(", "))).collect::<Vec<_>>().join("; "),
                serde_json::to_string(&counts).unwrap()
            )
        },
        "zones": [],
        "components": [],
        "unexamined": inventory_gaps,
        "notes": "Seeded by omgs audit. The reconnaissance agent fills zones, components, principals, boundaries, flows, and input_surfaces, records what was not examined in 'unexamined', then renders the map with: omgs architecture --in architecture.json --out <run-dir>."
    });
    write_out(
        out_abs.join("architecture.json"),
        format!("{}\n", serde_json::to_string_pretty(&arch_seed).unwrap()),
    )
    .map_err(|e| e.to_string())?;
    if !has(rest, "--no-sensors") {
        let sensors = run_sensors(&target, &out_abs);
        omgs::sensors::seed_units(&sensors, &mut ledger);
        write_out(
            out_abs.join("coverage-ledger.json"),
            serde_json::to_string_pretty(&ledger).unwrap(),
        )
        .map_err(|e| e.to_string())?;
        write_out(
            out_abs.join("sensor-hits.json"),
            serde_json::to_string_pretty(&sensors.hits).unwrap(),
        )
        .map_err(|e| e.to_string())?;
        write_out(
            out_abs.join("sensors.json"),
            serde_json::to_string_pretty(&sensors).unwrap_or_default(),
        )
        .map_err(|e| e.to_string())?;
    }
    // Bring the reviewer's recorded intent answers for this exact target into
    // the run, so earlier answers resolve matching questions in the report.
    let mut answers = answers.unwrap_or_else(|| omgs::intent::Answers {
        target: target.to_string_lossy().into(),
        answers: vec![],
    });
    for a in &policy.policy.accepted_intent {
        omgs::intent::record(
            &mut answers,
            omgs::intent::Answer {
                id: a.id.clone(),
                answer: a.answer.clone(),
                scope: a.scope.clone(),
                source: a.source.clone(),
                recorded_unix: started_unix,
            },
        )?;
    }
    if !answers.answers.is_empty() {
        omgs::intent::save_answers(&out_abs.join("intent-answers.json"), &answers)
            .map_err(|e| format!("copy intent answers: {e}"))?;
    }
    Ok(out_abs)
}

fn setup_prompt(prompt: &str, default: &str) -> Result<String, String> {
    use std::io::Write;
    omgs::out::text(&format!("{prompt} [{default}]: "));
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|e| e.to_string())?;
    Ok(if answer.trim().is_empty() {
        default.into()
    } else {
        answer.trim().into()
    })
}

fn cmd_setup(args: &[String]) -> Result<(), String> {
    use std::io::IsTerminal;
    if has(args, "--yes") && has(args, "--dry-run") {
        return Err("choose --yes or --dry-run".into());
    }
    let targets = omgs::setup::detected(&home());
    for target in &targets {
        omgs::out::line(&format!("skill target: {}", target.display()));
    }
    if targets.is_empty() {
        omgs::out::line("no installed coding agent directories detected");
    }
    let explicit =
        has(args, "--install-skills") || has(args, "--verify-mxc") || has(args, "--write-policy");
    let wizard = !explicit
        && !has(args, "--yes")
        && !has(args, "--dry-run")
        && std::io::stdin().is_terminal();
    let mut install = has(args, "--yes") || has(args, "--install-skills");
    let mut verify = has(args, "--yes") || has(args, "--verify-mxc");
    let mut repo = flag(args, "--write-policy");
    let mut mode = flag(args, "--mode").unwrap_or_else(|| "advisory".into());
    if !["gate", "advisory"].contains(&mode.as_str()) {
        return Err("--mode must be gate or advisory".into());
    }
    if wizard {
        install = setup_prompt("Install skill into detected agents? yes/no", "yes")? == "yes";
        verify = setup_prompt("Verify MXC with a live deny test? yes/no", "yes")? == "yes";
        let chosen = setup_prompt("Repository for a new default policy (blank skips)", "")?;
        if !chosen.is_empty() {
            repo = Some(chosen);
            mode = setup_prompt("Policy mode: gate/advisory", "advisory")?;
        }
    }
    let policy_mode = match mode.as_str() {
        "gate" => omgs::policy::Mode::Gate,
        "advisory" => omgs::policy::Mode::Advisory,
        _ => return Err("--mode must be gate or advisory".into()),
    };
    if has(args, "--dry-run") || (!wizard && !explicit && !has(args, "--yes")) {
        omgs::out::line("dry run; no files written and no live test run");
        if let Some(repo) = repo {
            omgs::out::line(&format!("would create default {mode} policy in {repo}"));
        }
        return Ok(());
    }
    if install && !targets.is_empty() {
        let from = flag(args, "--from").map(PathBuf::from);
        omgs::setup::install(from.as_deref(), &targets, has(args, "--replace"))?;
    }
    if let Some(repo) = repo {
        let path = omgs::setup::write_policy(Path::new(&repo), policy_mode)?;
        omgs::out::line(&format!(
            "created {}; review and commit it before using it as base policy",
            path.display()
        ));
    }
    if verify {
        cmd_doctor(&["--live".into()])?;
    }
    Ok(())
}

fn cmd_check(args: &[String]) -> Result<(), String> {
    let target_raw = flag(args, "--target").ok_or("check requires --target <repo>")?;
    let target = std::fs::canonicalize(&target_raw).map_err(|e| e.to_string())?;
    for tool in ["gitleaks", "trufflehog", "osv-scanner", "semgrep"] {
        let present = omgs::platform::which(tool).is_some();
        omgs::out::line(&format!(
            "sensor {tool}: {}",
            if present {
                "available"
            } else {
                "not installed"
            }
        ));
    }
    let mut files = Vec::new();
    walk(&target, 0, &mut files);
    let proofs = files
        .iter()
        .filter(|f| {
            let s = f.to_string_lossy().replace('\\', "/");
            s.contains("/tests/security/")
                || s.contains(".security.test.")
                || s.contains(".security.spec.")
        })
        .count();
    omgs::out::line(&format!("committed proof tests found: {proofs}"));
    let artifacts = flag(args, "--out")
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir().join("prove-scratch"));
    let sensors = run_sensors(&target, &artifacts);
    for tool in &sensors.tools_run {
        let hits: Vec<_> = sensors.hits.iter().filter(|h| &h.tool == tool).collect();
        let vendored = hits.iter().filter(|h| h.vendored).count();
        omgs::out::line(&format!(
            "sensor {tool} ran: {} hit(s), {} vendored",
            hits.len(),
            vendored
        ));
        for h in hits.iter().take(10) {
            omgs::out::line(&format!(
                "  {} {}:{} vendored={}",
                h.rule,
                h.file,
                h.line.unwrap_or(0),
                h.vendored
            ));
        }
    }
    for gap in &sensors.gaps {
        omgs::out::line(&format!("sensor gap: {gap}"));
    }
    if let Some(out) = flag(args, "--out") {
        let dir = PathBuf::from(out);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        omgs::sensors::publish_report(&dir, &sensors)?;
    }
    omgs::out::line("check is deterministic and executes no target code. Run proof tests through: omgs prove --cmd <test command>");
    Ok(())
}

fn read_ledger(path: &str) -> Result<Ledger, String> {
    let text = omgs::run_artifact::text_path(Path::new(path), omgs::run_artifact::LEDGER_BYTES)?;
    omgs::shape::ledger(&text).map_err(|e| format!("parse {path}: {e}"))
}

fn write_ledger(path: &str, ledger: &Ledger) -> Result<(), String> {
    let text = serde_json::to_string_pretty(ledger).map_err(|e| e.to_string())?;
    let path = Path::new(path);
    let errors = validate_ledger(ledger);
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut writes = omgs::runmeta::Transaction::default();
    writes.text(path, format!("{text}\n"));
    if let Some(mut saved) = omgs::runmeta::read_optional(dir)? {
        saved.insert("run_status".into(), serde_json::json!("in_progress"));
        writes.metadata(dir, &saved)?;
    }
    writes.commit()
}

/// Every value given for a repeatable flag, in order.
fn flags(args: &[String], name: &str) -> Vec<String> {
    options(args)
        .filter(|(option, _)| *option == name)
        .filter_map(|(_, value)| value.map(str::to_string))
        .collect()
}

fn cmd_ledger(args: &[String]) -> Result<(), String> {
    let usage =
        "usage: omgs ledger list|add|set --ledger <file> ...; omgs ledger migrate --run <dir>";
    let sub = args.first().map(|s| s.as_str()).ok_or(usage)?;
    let rest = &args[1..];
    let path = if sub == "migrate" {
        let run = flag(rest, "--run").ok_or("ledger migrate requires --run <dir>")?;
        Path::new(&run)
            .join("coverage-ledger.json")
            .to_str()
            .ok_or("run path must be UTF-8")?
            .to_string()
    } else {
        flag(rest, "--ledger").ok_or("ledger requires --ledger <file>")?
    };
    let dir = Path::new(&path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if omgs::runmeta::read_optional(dir)?.is_some() {
        omgs::budget::with_family_lock(dir, || ledger_locked(sub, rest, &path))
    } else {
        omgs::runmeta::with_lock(dir, || ledger_locked(sub, rest, &path))
    }
}

fn ledger_locked(sub: &str, rest: &[String], path: &str) -> Result<(), String> {
    let usage =
        "usage: omgs ledger list|add|set --ledger <file> ...; omgs ledger migrate --run <dir>";
    let path = path.to_string();
    let mut ledger = read_ledger(&path)?;
    let run = Path::new(&path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    omgs::mapping::validate_run_root(&ledger, run)?;
    match sub {
        "migrate" => {
            omgs::mapping::migrate(&mut ledger, run)?;
            write_ledger(&path, &ledger)?;
            omgs::out::line("migrated scope_root from run-metadata.json");
            Ok(())
        }
        "ingest" => {
            let input =
                flag(rest, "--dispositions").ok_or("ledger ingest requires --dispositions")?;
            let text = omgs::run_artifact::text_path(
                Path::new(&input),
                omgs::run_artifact::DISPOSITIONS_BYTES,
            )?;
            let dispositions = omgs::adjudication::dispositions(&text)?;
            for d in dispositions.units {
                let status = if d.disposition == "candidate" {
                    "covered"
                } else {
                    &d.disposition
                };
                set_status(&mut ledger, &d.unit_id, status, &d.evidence, Some(&d.note))?;
                let unit = ledger.units.iter_mut().find(|u| u.id == d.unit_id).unwrap();
                unit.extra.remove("attempt_ref");
                unit.extra.remove("blocker_ref");
                if let Some(id) = d.attempt_ref {
                    unit.extra
                        .insert("attempt_ref".into(), serde_json::json!(id));
                }
                if let Some(id) = d.blocker_ref {
                    unit.extra
                        .insert("blocker_ref".into(), serde_json::json!(id));
                }
            }
            write_ledger(&path, &ledger)?;
            omgs::out::line("ingested dispositions");
            Ok(())
        }
        "list" => {
            for line in coverage_lines(&ledger) {
                omgs::out::line(&line);
            }
            let errors = validate_ledger(&ledger);
            for e in &errors {
                omgs::out::err(&format!("invalid: {}", omgs::platform::escape_controls(e)));
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
            for class in &classes {
                omgs::classes::validate(class)?;
            }
            let status = flag(rest, "--status").unwrap_or_else(|| "planned".into());
            let mut new = Unit::new(&unit, &surface, &classes, &status);
            new.note = flag(rest, "--note").filter(|n| !n.trim().is_empty());
            if let Some(mapping) = flag(rest, "--mapping") {
                omgs::mapping::apply_metadata(&mut new, &mapping)?;
            }
            add_unit(&mut ledger, new)?;
            write_ledger(&path, &ledger)?;
            omgs::out::line(&format!("{status}: {unit}"));
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
            if let Some(mapping) = flag(rest, "--mapping") {
                let target = ledger
                    .units
                    .iter_mut()
                    .find(|u| u.id == unit)
                    .ok_or("ledger unit not found")?;
                omgs::mapping::apply_metadata(target, &mapping)?;
            }
            set_status(&mut ledger, &unit, &status, &evidence, note.as_deref())?;
            let unit = ledger.units.iter_mut().find(|u| u.id == unit).unwrap();
            for (flag_name, key) in [
                ("--attempt-ref", "attempt_ref"),
                ("--blocker-ref", "blocker_ref"),
            ] {
                unit.extra.remove(key);
                if let Some(id) = flag(rest, flag_name) {
                    unit.extra.insert(key.into(), serde_json::json!(id));
                }
            }
            let unit = unit.id.clone();
            write_ledger(&path, &ledger)?;
            omgs::out::line(&format!("{status}: {unit}"));
            Ok(())
        }
        _ => Err(usage.into()),
    }
}

fn cmd_critic(args: &[String]) -> Result<(), String> {
    let run = flag(args, "--run").ok_or("critic requires --run <run-dir>")?;
    omgs::runmeta::with_lock(Path::new(&run), || {
        let report = omgs::critic::critique_run_locked(Path::new(&run))?;
        for gap in &report.gaps {
            omgs::out::err(&format!("gap: {}", omgs::platform::escape_controls(gap)));
        }
        omgs::out::line(&format!("critic: {}", report.summary()));
        if report.passed() {
            Ok(())
        } else {
            Err("__EXIT1__".into())
        }
    })
}

/// A review clone is shallow; a stalled or oversized one fails instead of
/// holding the run. One deadline covers version probe, configuration reads,
/// resolution and the clone itself.
const CLONE_DEADLINE_MS: u64 = 600_000;
const CLONE_FILE_BYTES: u64 = 1 << 30;

fn clone_deadline_ms() -> u64 {
    // Debug builds only, so tests need not wait for the real deadline.
    #[cfg(debug_assertions)]
    if let Some(ms) = std::env::var("OMGS_TEST_CLONE_DEADLINE_MS")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return ms;
    }
    CLONE_DEADLINE_MS
}

/// Clone (or reuse) a repository for review. Only validated https URLs reach
/// git, as a positional argument after `--`, under the isolation in
/// `omgs::clone`; a reused clone must have the same origin.
fn clone_target(raw_url: &str, args: &[String]) -> Result<PathBuf, String> {
    let repo = omgs::batch::parse_repo_url(raw_url)?;
    let targets = clone_root(args)?;
    let dest = targets.join(&repo.host).join(&repo.owner).join(&repo.name);
    let out = flag(args, "--out")
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir().join(&repo.name));
    admit_clone_storage(&targets, &dest, &out)?;
    let git_path = omgs::platform::which("git").ok_or("git not found on an absolute PATH entry")?;
    // Interruption stops the supervised Git group and removes the partial
    // checkout before the lock is released.
    #[cfg(any(unix, windows))]
    let _signals = omgs::supervise::interruption::Guard::install()
        .map_err(|e| format!("cannot install clone signal handlers: {e}"))?;
    let deadline = omgs::clone::Deadline::after(clone_deadline_ms());
    let parent = dest.parent().ok_or("invalid clone destination")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    admit_clone_storage(&targets, &dest, &out)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&targets, std::fs::Permissions::from_mode(0o700));
    }
    // One lock per destination covers the existence check, the clone, and
    // any cleanup, so a concurrent review of the same URL can never delete a
    // clone another process just created.
    let lock = parent.join(format!(".{}.lock", repo.name));
    omgs::runmeta::with_lock_file(&lock, || {
        if dest.exists() {
            let origin = omgs::clone::origin(&git_path, &dest, &deadline);
            // Compare the repository identity, not the spelling: a trailing
            // slash, `.git`, or host case must not reject a reused clone.
            let same = origin
                .as_deref()
                .and_then(|o| omgs::batch::parse_repo_url(o).ok())
                .is_some_and(|o| {
                    o.host == repo.host
                        && o.owner.eq_ignore_ascii_case(&repo.owner)
                        && o.name.eq_ignore_ascii_case(&repo.name)
                });
            if !same {
                return Err(format!(
                    "{} exists but its origin is {}, not {}; remove it or review that URL",
                    dest.display(),
                    omgs::platform::escape_controls(origin.as_deref().unwrap_or("unknown")),
                    repo.url
                ));
            }
            omgs::out::err(&format!(
                "clone phase=reused destination={}",
                dest.display()
            ));
            return Ok(dest.clone());
        }
        omgs::out::err(&format!(
            "clone phase=start depth=1 destination={}",
            dest.display()
        ));
        let failed = |why: String| {
            let _ = std::fs::remove_dir_all(&dest);
            omgs::out::err(&format!(
                "clone phase=failed destination={}",
                dest.display()
            ));
            why
        };
        omgs::clone::require_git(&git_path, &deadline).map_err(failed)?;
        let carried = omgs::clone::carried_config(&git_path, &deadline).map_err(failed)?;
        let template = omgs::clone::empty_template(&targets).map_err(failed)?;
        // Resolve once, refuse non-public addresses and pin the clone to them,
        // so neither a second lookup nor a redirect can move it elsewhere.
        let addrs = omgs::clone::resolve(&repo.host, &deadline).map_err(failed)?;
        let pin = omgs::clone::pin(&repo.host, &addrs);
        let mut clone = omgs::clone::git(&git_path, &carried, Some(&pin));
        // Git diagnostics can contain remote-controlled text, so they are
        // captured and discarded; the escaped phase/error messages are the
        // terminal output boundary.
        clone
            .args([
                "clone",
                "--quiet",
                "--depth",
                "1",
                "--no-recurse-submodules",
            ])
            .arg(format!("--template={}", template.display()))
            .arg("--")
            .arg(&repo.url)
            .arg(&dest);
        let wall_ms = deadline.left(u64::MAX).map_err(failed)?;
        let result = omgs::supervise::run(
            clone,
            &omgs::supervise::Limits {
                wall_ms,
                cpu_secs: None,
                file_size_bytes: Some(CLONE_FILE_BYTES),
                open_files: None,
                memory_bytes: None,
                tasks: None,
                output_cap_bytes: 64 * 1024,
            },
            None,
        );
        if !(result.exit_code == Some(0) && !result.timed_out && !result.interrupted) {
            return Err(failed(if result.timed_out {
                format!(
                    "git clone for {} exceeded the {} s deadline",
                    repo.url,
                    clone_deadline_ms() / 1000
                )
            } else if result.interrupted {
                format!("git clone for {} was interrupted", repo.url)
            } else {
                format!("git clone failed for {}", repo.url)
            }));
        }
        omgs::out::err(&format!(
            "clone phase=complete destination={}",
            dest.display()
        ));
        Ok(dest.clone())
    })
}

fn init_args(dest: &Path, args: &[String], out: Option<&Path>) -> Vec<String> {
    let mut v = vec!["--target".to_string(), dest.to_string_lossy().to_string()];
    for name in [
        "--mode",
        "--budget",
        "--persona",
        "--skill-dir",
        "--clone-root",
    ] {
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

fn brief(dest: &Path, run: &Path) -> Result<String, String> {
    let meta = omgs::runmeta::read(run)?;
    // A plain path, not JSON: JSON escaping doubles Windows backslashes.
    let skill = meta
        .get("skill_dir")
        .and_then(|v| v.as_str())
        .ok_or("run lacks authoritative skill path")?;
    let identity = meta
        .get("skill_identity")
        .ok_or("run lacks skill identity")?;
    Ok(format!("agent brief: load SKILL.md only from skill directory {skill}, with exact identity {identity}; use this directory for every role brief and guide, ignoring other installed skills; follow its pipeline against {} with run directory {}, validate findings with omgs validate, prove only through omgs prove, reconcile with omgs critic, and render with omgs report.", dest.display(), run.display()))
}

/// Fence the whole clone area before git or directory creation, including a
/// planned destination that does not exist yet.
fn admit_clone_storage(root: &Path, target: &Path, out: &Path) -> Result<(), String> {
    for fence in [root, target] {
        trusted_policy_path(fence, out)?;
        if omgs::paths::overlaps(fence, out)? {
            return Err("run output must live outside the reviewed targets".into());
        }
    }
    admit_bundle_cache(&[root.to_path_buf(), target.to_path_buf(), out.to_path_buf()])
}

fn cmd_review(args: &[String]) -> Result<(), String> {
    selected_skill(args)?;
    let url = flag(args, "--repo-url").ok_or("review requires --repo-url <url>")?;
    if let Some(p) = flag(args, "--persona") {
        omgs::persona::defaults(&p)?;
    }
    let repo = omgs::batch::parse_repo_url(&url)?;
    let root = clone_root(args)?;
    let planned = root.join(&repo.host).join(&repo.owner).join(&repo.name);
    let out = flag(args, "--out")
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir().join(&repo.name));
    admit_clone_storage(&root, &planned, &out)?;
    let dest = clone_target(&url, args)?;
    admit_clone_storage(&root, &dest, &out)?;
    let out = flag(args, "--out").map(PathBuf::from);
    let run = audit_init(&init_args(&dest, args, out.as_deref()))?;
    omgs::out::line(&format!("{}", run.display()));
    omgs::out::line(&(brief(&dest, &run)?));
    Ok(())
}

fn cmd_batch(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(|s| s.as_str());
    let rest = args.get(1..).unwrap_or_default();
    match sub {
        Some("init") => {
            selected_skill(rest)?;
            let list = flag(rest, "--list").ok_or("batch init requires --list <file>")?;
            let out = PathBuf::from(flag(rest, "--out").ok_or("batch init requires --out <dir>")?);
            let text = std::fs::read_to_string(&list).map_err(|e| format!("read {list}: {e}"))?;
            let urls = omgs::batch::read_list(&text);
            if urls.is_empty() {
                return Err(format!("{list} lists no repository URLs"));
            }
            if let Some(p) = flag(rest, "--persona") { omgs::persona::defaults(&p)?; }
            // Reject bad shared options before cloning or claiming anything.
            if let Some(m) = flag(rest, "--mode") {
                if m != "gate" && m != "advisory" {
                    return Err("--mode must be gate or advisory".into());
                }
            }
            if let Some(b) = flag(rest, "--budget") {
                b.parse::<u64>()
                    .map_err(|_| format!("--budget must be a whole number, got '{b}'"))?;
            }
            // The batch output must sit outside the targets area and every
            // target in the list, including ones that later fail to clone.
            let targets_root = clone_root(rest)?;
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
                if omgs::paths::overlaps(&resolved, t)? {
                    return Err(format!(
                        "batch output must live outside the reviewed targets, and {} is inside {}",
                        out_abs.display(),
                        t.display()
                    ));
                }
            }
            // Admit shared cache and policy storage against every target and
            // the whole batch output before creating either directory.
            let mut fences = vec![resolved.clone()];
            for target in std::iter::once(&targets_root).chain(&dests) {
                fences.push(resolve_existing_prefix(target)?);
            }
            for target in std::iter::once(&targets_root).chain(&dests) {
                trusted_policy_path(&resolve_existing_prefix(target)?, &resolved)?;
            }
            admit_bundle_cache(&fences)?;
            // The batch directory must be new or empty: anything already in it
            // (a planted symlink at <host>/<owner> for example) could redirect
            // a run into a target.
            if std::fs::read_dir(&out).is_ok_and(|mut d| d.next().is_some()) {
                return Err(format!(
                    "{} is not empty; batch init needs a new or empty --out",
                    out.display()
                ));
            }
            std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o700));
            }
            let out = std::fs::canonicalize(&out).map_err(|e| e.to_string())?;
            let resolved_targets = std::iter::once(&targets_root)
                .chain(&dests)
                .map(|t| resolve_existing_prefix(t))
                .collect::<Result<Vec<_>, String>>()?;
            let contained = |p: &Path| -> Result<(), String> {
                let p = resolve_existing_prefix(p)?;
                admit_bundle_cache(std::slice::from_ref(&p))?;
                for t in &resolved_targets {
                    trusted_policy_path(t, &p)?;
                    if omgs::paths::overlaps(&p, t)? {
                        return Err(format!("run directory {} resolves inside {}", p.display(), t.display()));
                    }
                }
                Ok(())
            };
            contained(&out)?;
            admit_bundle_cache(&resolved_targets)?;
            // Claim the batch directory exclusively before any work, so two
            // concurrent batch inits sharing --out cannot both proceed and
            // overwrite each other's batch.json.
            if out.join("batch.json").exists() {
                return Err(format!(
                    "{} already holds a batch; choose a new --out",
                    out.display()
                ));
            }
            omgs::platform::write_private_new(&out.join(".omgs-batch-claim"), b"")
                .map_err(|e| {
                    format!(
                        "{} is already claimed by another batch ({e}); choose a new --out",
                        out.display()
                    )
                })?;
            let mut batch = omgs::batch::BatchFile {
                created_unix: omgs::runmeta::now_unix(),
                runs: Vec::new(),
            };
            for url in urls {
                let attempt = omgs::batch::parse_repo_url(&url).and_then(|r| {
                    // One path component per part keeps runs distinct: no
                    // separator inside a part can make two URLs collide.
                    let run_dir = out.join(&r.host).join(&r.owner).join(&r.name);
                    // Every run path is checked against every listed target,
                    // before the run is created and again after.
                    contained(&run_dir)?;
                    let dest = clone_target(&url, rest)?;
                    contained(&run_dir)?;
                    let run = audit_init(&init_args(&dest, rest, Some(&run_dir)))?;
                    contained(&run)?;
                    Ok((dest, run))
                });
                match attempt {
                    Ok((dest, run)) => {
                        omgs::out::line(&(brief(&dest, &run)?));
                        batch.runs.push(omgs::batch::BatchRun {
                            url,
                            target: Some(dest.to_string_lossy().to_string()),
                            run_dir: Some(run.to_string_lossy().to_string()),
                            status: "initialized".into(),
                            error: None,
                        });
                    }
                    Err(e) => {
                        omgs::out::err(&format!("failed: {url}: {e}"));
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
            omgs::out::line(&format!(
                "{}: {} initialized, {failed} failed",
                path.display(),
                batch.runs.len() - failed
            ));
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
                &data_dir().join("targets"),
            )?];
            for r in &batch.runs {
                if let Some(t) = r.target.as_deref() {
                    targets.push(resolve_existing_prefix(Path::new(t))?);
                }
            }
            let store = resolve_existing_prefix(&data_dir().join("intent"))?;
            let inside = |p: &Path| -> Result<(), String> {
                admit_bundle_cache(&[p.to_path_buf()])?;
                if omgs::paths::overlaps(p, &store)? {
                    return Err(format!("index output must live outside the trusted intent and policy store, and {} overlaps {}", out_abs.display(), store.display()));
                }
                for t in &targets {
                    if omgs::paths::overlaps(p, t)? {
                        return Err(format!("index output must live outside every reviewed target, and {} is inside {}", out_abs.display(), t.display()));
                    }
                }
                Ok(())
            };
            inside(&resolve_existing_prefix(&out_abs)?)?;
            std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
            // Recheck the directory as it now exists, before writing anything.
            let out = std::fs::canonicalize(&out).map_err(|e| e.to_string())?;
            inside(&out)?;
            let paths = batch.runs.iter().filter_map(|r| r.run_dir.as_deref()).map(PathBuf::from).collect::<Vec<_>>();
            omgs::runmeta::with_run_locks(&paths, false, || {
            let runs = batch
                .runs
                .iter()
                .map(|r| omgs::batch::summarize_locked(r, &out))
                .collect::<Result<Vec<_>, String>>()?;
            let mut writes = omgs::runmeta::Transaction::default();
            writes.text(out.join("INDEX.md"), omgs::batch::render_index_markdown(&runs));
            writes.text(out.join("INDEX.html"), omgs::batch::render_index_html(&runs));
            writes.commit()?;
            Ok(())
            })?;
            omgs::out::line(&format!(
                "wrote {}, {}",
                out.join("INDEX.md").display(),
                out.join("INDEX.html").display()
            ));
            Ok(())
        }
        _ => Err("usage: omgs batch init --list <file> --out <dir> | omgs batch index --batch <batch.json> --out <dir>".into()),
    }
}

fn cmd_status(args: &[String]) -> Result<(), String> {
    let run = flag(args, "--run").ok_or("status requires --run <run-dir>")?;
    let stage = flag(args, "--stage").ok_or("status requires --stage <id>")?;
    let state = flag(args, "--state").ok_or("status requires --state <state>")?;
    let supplied_usage = omgs::accounting::parse(&flags(args, "--accounting"))?;
    let observed = omgs::runmeta::read(Path::new(&run))?;
    let submission = omgs::accounting::Submission::observe(&observed, supplied_usage)?;
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
    let logs = flags(args, "--log");
    let (review_state, usage) = omgs::budget::with_family_lock(Path::new(&run), || {
        let mut saved = omgs::runmeta::read(Path::new(&run))?;
        let m = &mut saved;
        submission.apply(m)?;
        omgs::runmeta::check_numeric_fields(m)?;
        let (writes, view) = omgs::status::prepare_locked(
            Path::new(&run),
            m,
            &omgs::status::Update {
                stage: &stage,
                label: label.as_deref(),
                parent: parent.as_deref(),
                state: &state,
                detail: detail.as_deref(),
                counters: &counters,
                log: None,
            },
            &logs,
        )?;
        writes.commit()?;
        Ok((
            view.state.unwrap_or_else(|| "complete".into()),
            view.accounting,
        ))
    })?;
    let mut output = vec![format!(
        "{}: {state}; review {}",
        omgs::platform::escape_controls(&stage),
        omgs::platform::escape_controls(&review_state)
    )];
    if !flags(args, "--accounting").is_empty() {
        for line in omgs::accounting::lines(&usage) {
            output.push(line);
        }
    }
    match omgs::out::lines(&output) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(format!("status saved, but output failed: {e}")),
    }
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
    let (listener, port, token) = omgs::watch::bind()?;
    omgs::out::line(&format!(
        "progress: http://127.0.0.1:{port}/#token={token} (loopback only; the token is for you alone; stops when the run completes)"
    ));
    omgs::watch::serve(
        listener,
        port,
        &token,
        &run,
        std::time::Duration::from_millis(max_ms),
    );
    Ok(())
}

fn models_path(args: &[String]) -> PathBuf {
    flag(args, "--models")
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir().join("models.json"))
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

    if let Some(label) = flag(args, "--model") {
        if flag(args, "--refused").is_some() || flag(args, "--models").is_some() {
            return Err("--model records an identity and cannot combine with refusal or routing configuration".into());
        }
        let labels = omgs::route::parse_identities(&[format!("{role}={label}")])?;
        omgs::runmeta::update(&run, |m| {
            omgs::batch::check_meta_types(m)?;
            let saved = m
                .entry("models")
                .or_insert_with(|| serde_json::json!({}))
                .as_object_mut()
                .ok_or("models must be an object")?;
            for (role, value) in labels {
                saved.insert(role, serde_json::json!(value));
            }
            Ok(())
        })?;
        omgs::out::line(&omgs::platform::escape_controls(&label));
        return Ok(());
    }
    let newly = flag(args, "--refused");
    let reason = flag(args, "--reason").unwrap_or_default();
    if newly.is_some() && reason.trim().is_empty() {
        return Err("--refused requires --reason <text>".into());
    }
    let model_path = models_path(args);
    let missing = !model_path.try_exists().map_err(|e| e.to_string())?;
    let default_route = missing && flag(args, "--models").is_none();
    // Without configuration, retain the host's choice until it is refused.
    // A named refusal never becomes an implicit retry of the same host default.
    let models = if default_route && newly.is_none() {
        omgs::route::Models {
            roles: omgs::route::ROLES
                .into_iter()
                .map(|r| (r.to_string(), vec!["host-default".into()]))
                .collect(),
        }
    } else if missing && newly.is_some() {
        omgs::route::Models::default()
    } else {
        omgs::route::load_models(&model_path)?
    };
    // Read the refusal history, pick the next model, and record the result in
    // one locked transaction, so concurrent reroutes never lose an entry.
    let next = omgs::runmeta::update(&run, |m| {
        // Malformed history must stop the command: silently ignoring it would
        // forget earlier refusals and send work back to a refusing model.
        omgs::batch::check_meta_types(m)?;
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
        let next = if default_route && !refused.is_empty() {
            Err(format!(
                "no configured fallback for role '{role}' after refusal; keep the blocker recorded"
            ))
        } else if default_route {
            Ok(m.get("models")
                .and_then(|v| v.get(&role))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("host-default")
                .to_string())
        } else {
            omgs::route::next_model(&models, &role, &refused)
        };
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
                let count = m
                    .get("blocker_events")
                    .and_then(|v| v.as_array())
                    .map_or(0, Vec::len);
                omgs::attempts::blocker(
                    m,
                    &format!("route-{count}"),
                    "active",
                    "host-route",
                    &format!(
                        "{role}: {}: {reason}: {e}",
                        newly.as_deref().unwrap_or("unconfigured")
                    ),
                    None,
                )?;
            }
        }
        Ok(next)
    })?;
    match next {
        // Saved routes and models.json are editable files: never echo raw controls.
        Ok(model) => {
            omgs::out::line(&omgs::platform::escape_controls(&model));
            Ok(())
        }
        Err(e) => {
            omgs::out::err(&format!("blocked: {}", omgs::platform::escape_controls(&e)));
            Err("__EXIT1__".into())
        }
    }
}

fn intent_propose(run: &Path) -> Result<(), String> {
    omgs::budget::with_family_lock(run, || intent_propose_with_tests(run, None))
}

fn prepare_intent_proposal(
    run: &Path,
    staged: &omgs::handoff::StagedTests,
) -> Result<String, String> {
    let mut answers = run_answers(Some(run))?;
    let meta = omgs::runmeta::read(run)?;
    let target = Path::new(
        meta.get("target")
            .and_then(|v| v.as_str())
            .ok_or("run needs target")?,
    );
    let store = read_target_store(target)?;
    let policy = authenticated_policy(run, target)?;
    for answer in store.answers {
        omgs::intent::record(&mut answers, answer)?;
    }
    omgs::policy::prepare_staged(run, &answers, staged, &policy)
}

fn intent_propose_with_tests(
    run: &Path,
    staged: Option<&omgs::handoff::StagedTests>,
) -> Result<(), String> {
    let answers = run_answers(Some(run))?;
    let meta = omgs::runmeta::read(run)?;
    let target = meta
        .get("target")
        .and_then(|v| v.as_str())
        .ok_or("run needs target")?;
    let store = read_target_store(Path::new(target))?;
    let policy = authenticated_policy(run, Path::new(target))?;
    let mut merged = answers;
    for answer in store.answers {
        omgs::intent::record(&mut merged, answer)?;
    }
    omgs::out::line(&format!(
        "owner review patch: {}",
        match staged {
            Some(tests) => omgs::policy::propose_staged(run, &merged, tests, &policy)?,
            None => omgs::policy::propose(run, &merged, &policy)?,
        }
        .display()
    ));
    Ok(())
}

fn cmd_intent(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(|s| s.as_str());
    let rest = args.get(1..).unwrap_or_default();
    match sub {
        Some("list") => {
            let stack = flag(rest, "--stack");
            let class = flag(rest, "--attack-class").map(|c| c.replace('-', "_"));
            let class = class.map(|c| if c == "fail_closed" { "fail_closed_semantics".into() } else { c });
            if let Some(c) = &class {
                if !omgs::classes::known(c) { return Err(format!("unknown attack class {c}; expected {}", omgs::classes::all().join(", "))); }
            }
            let class = class.map(|c| omgs::classes::replacement(&c).unwrap_or(c));
            let questions = omgs::intent::list(stack.as_deref(), class.as_deref());
            if questions.is_empty() { omgs::out::line("no intent questions for this class/stack; record unresolved owner intent explicitly"); }
            for q in questions {
                omgs::out::line(&format!("{}: {}", q.id, q.question));
                if !q.answers.is_empty() {
                    omgs::out::line(&format!("  answers: {}", q.answers.join(" | ")));
                }
            }
            Ok(())
        }
        Some("propose") => {
            let run = flag(rest, "--run").ok_or("intent propose requires --run <dir>")?;
            let run = Path::new(&run);
            intent_propose(run)?;
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
            let path = trusted_store(&target)?;
            if let Some(dir) = path.parent() {
                omgs::platform::create_private_tree(dir).map_err(|e| e.to_string())?;
            }
            // Recheck after creating the directories, in case a parent link
            // appeared in between.
            let path = trusted_store(&target)?;
            let id = answer.id.clone();
            // The whole load, merge, and replace runs under a per-target lock
            // so concurrent answers are never lost.
            let lock = path.with_extension("lock");
            omgs::runmeta::with_lock_file(&lock, || {
            let mut answers = read_store(&path)?;
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
            omgs::intent::save_answers(&path, &answers)?;
            Ok(())
            })?;
            omgs::out::line(&format!("recorded {id} in {}", path.display()));
            Ok(())
        }
        _ => Err("usage: omgs intent list [--stack <s>] [--attack-class <c>] | omgs intent answer --target <repo> --id <id> --answer <text> --source <who> [--scope repo|<path>]".into()),
    }
}

fn cmd_attempt(args: &[String]) -> Result<(), String> {
    let run = PathBuf::from(flag(args, "--run").ok_or("attempt requires --run")?);
    if flag(args, "--event").is_some() == flag(args, "--resolve-blocker").is_some() {
        return Err("attempt requires exactly one of --event or --resolve-blocker".into());
    }
    if let Some(id) = flag(args, "--resolve-blocker") {
        let actor = flag(args, "--actor").ok_or("resolution requires --actor")?;
        let reason = flag(args, "--reason").ok_or("resolution requires --reason")?;
        let replacement = flag(args, "--replacement").ok_or("resolution requires --replacement")?;
        omgs::runmeta::update(&run, |m| {
            omgs::attempts::blocker(m, &id, "resolved", &actor, &reason, Some(&replacement))
        })
    } else {
        let path = flag(args, "--event").ok_or("attempt requires --event <record.json>")?;
        let text =
            omgs::run_artifact::text_path(Path::new(&path), omgs::run_artifact::METADATA_BYTES)?;
        let event =
            serde_json::from_value(omgs::shape::strict_json(&text)?).map_err(|e| e.to_string())?;
        let outcome = omgs::attempts::append(&run, event)?;
        omgs::out::line(match outcome {
            omgs::attempts::AppendOutcome::Recorded => "recorded",
            omgs::attempts::AppendOutcome::AlreadyRecorded => {
                "already recorded; do not dispatch again"
            }
        });
        Ok(())
    }
}

#[cfg(test)]
mod cli_tests {
    #[test]
    fn doctor_overall_deadline_covers_preparation_and_leaves_unchecked_probes() {
        for preparation in [true, false] {
            let result = super::doctor_live_with_budget(std::time::Duration::ZERO, |remaining| {
                if !preparation {
                    remaining.retain(|name| name != "outside-file denial");
                }
                assert!(omgs::supervise::check_interrupted().is_err());
                assert!(remaining.iter().any(|name| name == "sh"));
                assert!(remaining.iter().any(|name| name == "java"));
                Ok(())
            });
            assert_eq!(result, Err("__EXIT1__".into()));
            assert!(!omgs::supervise::Deadline::expired());
        }
    }

    #[test]
    fn doctor_budget_stops_real_scratch_recovery() {
        const MODE: &str = "OMGS_TEST_DOCTOR_RECOVERY";
        if let Ok(mode) = std::env::var(MODE) {
            if mode == "seed" {
                let scratch = omgs::scratch::Scratch::create("sensor").unwrap();
                std::fs::write(scratch.path().join("raw"), b"discard").unwrap();
                // Process exit releases the lock without running owner cleanup.
                std::mem::forget(scratch);
                return;
            }
            let home = omgs::platform::scratch_root().unwrap();
            let orphan = std::fs::read_dir(&home)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| path.join("payload/raw").is_file())
                .expect("seeded orphan");
            let result = super::doctor_live_with_budget(std::time::Duration::ZERO, |remaining| {
                let recovery = omgs::scratch::recover();
                omgs::out::line(&format!(
                    "recover_result={recovery:?}, orphan_exists={}",
                    orphan.exists()
                ));
                assert!(recovery
                    .as_ref()
                    .is_err_and(|e| e.contains("deadline exceeded")));
                assert!(orphan.join("payload/raw").is_file());
                assert_eq!(remaining.len(), super::DOCTOR_TOOLS.len() + 1);
                recovery
            });
            assert_eq!(result, Err("__EXIT1__".into()));
            // The next run can still validate ownership and finish recovery.
            omgs::scratch::recover().unwrap();
            assert!(!orphan.exists());
            return;
        }
        let home = omgs::platform::temp_root().unwrap().join(format!(
            "omgs-doctor-recovery-{}",
            omgs::platform::random_nonce().unwrap()
        ));
        omgs::platform::create_private_dir_new(&home).unwrap();
        for mode in ["seed", "recover"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "cli_tests::doctor_budget_stops_real_scratch_recovery",
                    "--nocapture",
                ])
                .env("OMGS_HOME", &home)
                .env(MODE, mode)
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !output.status.success() || mode == "recover" {
                std::fs::remove_dir_all(&home).unwrap();
            }
            assert!(output.status.success(), "{mode}: {stdout}\n{stderr}");
            if mode == "recover" {
                omgs::out::line(&format!("{stdout}{stderr}"));
                assert!(stderr.contains("overall wall-clock deadline of 0s exceeded"));
                for name in ["outside-file denial", "sh", "java"] {
                    assert!(stdout.contains(&format!(
                        "{name} not checked: overall doctor deadline exceeded"
                    )));
                }
            }
        }
    }

    #[test]
    fn doctor_shell_probe_and_unreachable_reasons() {
        assert_eq!(super::doctor_probe_command("macos", "sh"), "sh -c 'exit 0'");
        for os in ["macos", "linux", "windows"] {
            for name in ["swiftc", "clang"] {
                let command = super::doctor_probe_command(os, name);
                assert_eq!(command, format!("{name} --version"));
                assert_eq!(
                    super::doctor_probe_timeout_ms(os, name),
                    if os == "macos" { 30_000 } else { 3_000 }
                );
            }
        }
        assert_eq!(
            super::doctor_tool_failure("node", "timeout=true"),
            "node on host PATH but failed to launch inside MXC\n  reason: timeout=true"
        );
        let limits = omgs::supervise::Limits {
            wall_ms: 100,
            cpu_secs: None,
            file_size_bytes: None,
            open_files: None,
            memory_bytes: None,
            tasks: None,
            output_cap_bytes: 1024,
        };
        #[cfg(unix)]
        let mut command = std::process::Command::new("/bin/sh");
        #[cfg(unix)]
        command.args(["-c", "sleep 10"]);
        #[cfg(windows)]
        let mut command = std::process::Command::new("cmd.exe");
        #[cfg(windows)]
        command.args(["/d", "/c", "for /l %i in (1,0,2) do @rem"]);
        let mut run = omgs::supervise::run(command, &limits, None);
        assert!(super::doctor_probe_result(&run)
            .unwrap_err()
            .contains("timeout=true"));
        run.timed_out = false;
        run.success = true;
        run.command_started = true;
        run.command_finished = true;
        run.capture_complete = false;
        assert!(super::doctor_probe_result(&run).is_err());
        run.capture_complete = true;
        run.executor_error = true;
        assert!(super::doctor_probe_result(&run).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn doctor_rejects_failing_compiler_shims_even_when_direct_binaries_work() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "omgs-doctor-shims-{}",
            omgs::platform::random_nonce().unwrap()
        ));
        let shims = dir.join("shims");
        let direct = dir.join("Toolchains/XcodeDefault.xctoolchain/usr/bin");
        std::fs::create_dir_all(&shims).unwrap();
        std::fs::create_dir_all(&direct).unwrap();
        for name in ["swiftc", "clang"] {
            for (path, body) in [
                (
                    shims.join(name),
                    "#!/bin/sh\necho shim-unavailable >&2\nexit 1\n",
                ),
                (direct.join(name), "#!/bin/sh\necho direct-compiler-ready\n"),
            ] {
                std::fs::write(&path, body).unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            // Exercise the same acceptance check used by doctor with runner
            // markers. The direct binary is a positive control only; readiness
            // must be decided by the shim that proof commands resolve.
            let command = super::doctor_probe_command("macos", name);
            assert_eq!(command, format!("{name} --version"));
            for (path, ready) in [(&direct, true), (&shims, false)] {
                let script = format!(
                    "printf 'OMGS_START_doctor\\n'; {command}; status=$?; printf '\\nOMGS_END_doctor:%s\\n' \"$status\"; exit \"$status\""
                );
                let mut probe = std::process::Command::new("/bin/sh");
                probe.args(["-c", &script]).env_clear().env("PATH", path);
                let run = omgs::supervise::run_marked(
                    probe,
                    &omgs::supervise::Limits {
                        wall_ms: super::doctor_probe_timeout_ms("macos", name),
                        cpu_secs: None,
                        file_size_bytes: None,
                        open_files: None,
                        memory_bytes: None,
                        tasks: None,
                        output_cap_bytes: 1024,
                    },
                    None,
                    "doctor",
                );
                assert_eq!(super::doctor_probe_result(&run).is_ok(), ready, "{run:?}");
                assert!(
                    run.output.contains(if ready {
                        "direct-compiler-ready"
                    } else {
                        "shim-unavailable"
                    }),
                    "{run:?}"
                );
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn free_text_and_inline_values_cannot_become_options() {
        for (cmd, sub, name) in [
            ("prove", "", "--cmd"),
            ("ledger", "add", "--note"),
            ("ledger", "set", "--note"),
            ("intent", "answer", "--answer"),
            ("status", "", "--detail"),
            ("status", "", "--log"),
            ("route", "", "--reason"),
        ] {
            for value in ["--version", "--unknown", "--live"] {
                for inline in [false, true] {
                    let mut args = Vec::new();
                    if !sub.is_empty() {
                        args.push(sub.to_string());
                    }
                    if inline {
                        args.push(format!("{name}={value}"));
                    } else {
                        args.extend(strings(&[name, value]));
                    }
                    assert_eq!(validate_options(cmd, &args), Ok(false), "{args:?}");
                    assert_eq!(flag(&args, name).as_deref(), Some(value));
                    assert!(!has(&args, value), "{args:?}");
                }
            }
        }
        let args = strings(&["--target=--folder"]);
        assert_eq!(validate_options("approve", &args), Ok(false));
        assert_eq!(flag(&args, "--target").as_deref(), Some("--folder"));
        let error = validate_options("approve", &strings(&["--target", "--folder"])).unwrap_err();
        assert!(error.contains("use --target=value if it begins with --"));
        assert!(validate_options("doctor", &strings(&["--live=yes"])).is_err());
        let args = strings(&["--counter=a=1", "--counter", "b=2"]);
        assert_eq!(flags(&args, "--counter"), ["a=1", "b=2"]);
    }

    #[test]
    fn free_text_values_cannot_swallow_known_options() {
        for (cmd, sub, name, known) in [
            ("prove", "", "--cmd", "--timeout-ms"),
            ("ledger", "add", "--note", "--unit"),
            ("ledger", "set", "--note", "--evidence"),
            ("intent", "answer", "--answer", "--scope"),
            ("status", "", "--detail", "--state"),
            ("status", "", "--log", "--run"),
            ("route", "", "--reason", "--role"),
        ] {
            for value in [
                known.to_string(),
                format!("{known}=5000"),
                format!("{known}=5000 extra text"),
                "--help".into(),
                "-h".into(),
                "--help=anything".into(),
            ] {
                let mut args = Vec::new();
                if !sub.is_empty() {
                    args.push(sub.to_string());
                }
                args.extend([name.to_string(), value.clone()]);
                let error = validate_options(cmd, &args).unwrap_err();
                assert!(error.contains(&format!("use {name}=value")), "{error}");
                args.pop();
                args.pop();
                args.push(format!("{name}={value}"));
                assert_eq!(validate_options(cmd, &args), Ok(false));
                assert_eq!(flag(&args, name), Some(value));
            }
        }
    }

    #[test]
    fn oversized_answer_store_is_refused() {
        let path = omgs::platform::temp_root()
            .unwrap()
            .join(format!("omgs-answer-large-{}.json", std::process::id()));
        omgs::platform::write_private_new(&path, b"").unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len((1 << 20) + 1).unwrap();
        assert!(read_store(&path).unwrap_err().contains("byte limit"));
        drop(file);
        std::fs::remove_file(path).unwrap();
    }

    fn function<'a>(source: &'a str, name: &str) -> &'a str {
        let body = source.split_once(&format!("\nfn {name}(")).unwrap().1;
        body.split("\nfn ").next().unwrap()
    }

    fn read_options(body: &str) -> BTreeSet<&str> {
        let mut names = BTreeSet::new();
        for helper in ["flag(", "has(", "flags("] {
            for call in body.split(helper).skip(1) {
                let arg = call.split_once(',').unwrap().1.trim_start();
                if let Some(literal) = arg.strip_prefix('"') {
                    names.insert(literal.split('"').next().unwrap());
                } else {
                    let variable = arg.split(')').next().unwrap();
                    let values = match variable {
                        "n" => body
                            .split("get(\"")
                            .skip(1)
                            .map(|s| s.split('"').next().unwrap())
                            .collect::<Vec<_>>(),
                        "option" => vec!["--repo", "--ref", "--sandbox"],
                        "flag_name" => vec!["--attempt-ref", "--blocker-ref"],
                        "k" | "kind" => vec![
                            "--findings",
                            "--candidates",
                            "--dispositions",
                            "--evaluation",
                        ],
                        "name" | "conflicting" => {
                            let array = body
                                .split_once(&format!("for {variable} in ["))
                                .unwrap()
                                .1
                                .split(']')
                                .next()
                                .unwrap();
                            array.split('"').skip(1).step_by(2).collect()
                        }
                        other => panic!("unmapped dynamic option read: {other}"),
                    };
                    assert!(!values.is_empty());
                    names.extend(values);
                }
            }
        }
        names
    }

    fn accepted(cmd: &str, sub: &str, option: &str) {
        let mut args = Vec::new();
        if !sub.is_empty() {
            args.push(sub.to_string());
        }
        args.push(option.to_string());
        if !boolean_option(option) {
            args.push("value".into());
        }
        assert!(validate_options(cmd, &args).is_ok(), "{cmd} {args:?}");
    }

    const COMMANDS: &[(&str, &str)] = &[
        ("identity", ""),
        ("artifact-check", ""),
        ("setup", ""),
        ("install-self", ""),
        ("coalition-anchor", ""),
        ("gate", ""),
        ("stage", ""),
        ("review", ""),
        ("audit", "init"),
        ("batch", "init"),
        ("batch", "index"),
        ("validate", ""),
        ("findings", "merge"),
        ("fingerprint", ""),
        ("bench", "score"),
        ("prove", ""),
        ("approve", ""),
        ("report", ""),
        ("handoff", ""),
        ("stage", ""),
        ("architecture", ""),
        ("ledger", "migrate"),
        ("ledger", "ingest"),
        ("ledger", "list"),
        ("ledger", "add"),
        ("ledger", "set"),
        ("critic", ""),
        ("budget", ""),
        ("attempt", ""),
        ("status", ""),
        ("watch", ""),
        ("route", ""),
        ("intent", "list"),
        ("intent", "propose"),
        ("intent", "answer"),
        ("check", ""),
        ("doctor", ""),
        ("update-check", ""),
    ];

    #[test]
    fn every_option_read_is_in_its_subcommand_allowlist() {
        let source = include_str!("main.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let mut covered = BTreeMap::<String, BTreeSet<&str>>::new();
        for &(cmd, sub) in COMMANDS {
            let name = format!("cmd_{}", cmd.replace('-', "_"));
            let mut sections = vec![(name.as_str(), function(source, &name))];
            match (cmd, sub) {
                ("identity" | "review" | "audit", _) | ("batch", "init") => {
                    sections.push(("selected_skill", function(source, "selected_skill")));
                    sections.push(("review_skill", function(source, "review_skill")));
                    if cmd == "audit" {
                        sections.push(("audit_init", function(source, "audit_init")));
                        sections.push((
                            "audit_init_selected",
                            function(source, "audit_init_selected"),
                        ));
                        sections
                            .push(("audit_init_limited", function(source, "audit_init_limited")));
                    }
                }
                ("doctor", _) => {
                    sections.push(("cmd_doctor_inner", function(source, "cmd_doctor_inner")));
                }
                ("validate", _) => {
                    sections.push((
                        "cmd_validate_locked",
                        function(source, "cmd_validate_locked"),
                    ));
                }
                ("route", _) => sections.push(("models_path", function(source, "models_path"))),
                ("ledger", _) => {
                    // The migration path reads --run; other ledger commands
                    // select an explicit --ledger. Audit each actual branch.
                    let paths = sections[0]
                        .1
                        .split_once("if sub == \"migrate\" {")
                        .unwrap()
                        .1;
                    let (migration, existing) = paths.split_once("} else {").unwrap();
                    sections[0].1 = if sub == "migrate" {
                        migration
                    } else {
                        existing.split("};").next().unwrap()
                    };
                    let body = function(source, "ledger_locked");
                    let branch = body.split_once(&format!("\"{sub}\" => {{")).unwrap().1;
                    sections.push((
                        "ledger_locked",
                        branch.split("\n        \"").next().unwrap(),
                    ));
                }
                _ => {}
            }
            if cmd == "batch" || cmd == "intent" {
                let branch = sections[0]
                    .1
                    .split_once(&format!("Some(\"{sub}\") => {{"))
                    .unwrap()
                    .1;
                sections[0].1 = branch.split("\n        Some(").next().unwrap();
            }
            if cmd == "review" || (cmd == "batch" && sub == "init") {
                sections.push(("init_args", function(source, "init_args")));
                sections.push(("clone_root", function(source, "clone_root")));
                sections.push(("clone_target", function(source, "clone_target")));
            }
            for (name, body) in sections {
                let names = read_options(body);
                for option in &names {
                    accepted(cmd, sub, option);
                }
                covered.entry(name.to_string()).or_default().extend(names);
            }
        }
        for declaration in source.split("\nfn ").skip(1) {
            let name = declaration.split('(').next().unwrap();
            if ["flag", "has", "flags"].contains(&name) {
                continue;
            }
            if ["flag(", "has(", "flags("]
                .iter()
                .any(|call| declaration.contains(call))
            {
                assert!(
                    covered.contains_key(name),
                    "unmapped option-reading function {name}"
                );
                assert!(
                    read_options(declaration).is_subset(&covered[name]),
                    "uncovered option read in {name}"
                );
            }
        }
    }

    #[test]
    fn documented_omgs_options_are_accepted() {
        for text in [
            include_str!("../README.md"),
            include_str!("../docs/internals.md"),
            include_str!("../skill/SKILL.md"),
        ] {
            for part in text.split("--").skip(1) {
                let end = part
                    .find(|c: char| !c.is_ascii_alphanumeric() && c != '-')
                    .unwrap_or(part.len());
                let name = &part[..end];
                // External commands, root version flag and the syntax placeholder.
                if name.is_empty()
                    || name.starts_with('-')
                    || [
                        "global",
                        "skill",
                        "release",
                        "ignore-missing",
                        "dry-run",
                        "config",
                        "probe",
                        "version",
                        "opt",
                        "no-ignore-tag",
                        "no-ignore",
                        "no-git-ignore",
                        "disable-nosem",
                        "max-target-bytes",
                        "max-memory",
                        "jobs",
                        "no-verification",
                        "no-update",
                        "json",
                        "offline-vulnerabilities",
                        "offline",
                        "no-call-analysis",
                        "no-resolve",
                        "download-offline-databases",
                        "no-pager",
                        "no-replace-objects",
                        "tags",
                        "verify",
                        "end-of-options",
                    ]
                    .contains(&name)
                {
                    continue;
                }
                let option = format!("--{name}");
                assert!(
                    COMMANDS.iter().any(|(cmd, sub)| {
                        let mut args = Vec::new();
                        if !sub.is_empty() {
                            args.push(sub.to_string());
                        }
                        args.push(option.clone());
                        if !boolean_option(&option) {
                            args.push("value".into());
                        }
                        validate_options(cmd, &args).is_ok()
                    }),
                    "undocumented CLI option acceptance: {option}"
                );
            }
            let text = text.replace("\\\n", " ");
            for line in text.lines() {
                for mention in line.split("omgs ").skip(1) {
                    let mut words = mention.split_whitespace();
                    let Some(cmd) = words.next() else { continue };
                    let sub = if ["audit", "batch", "ledger", "intent"].contains(&cmd) {
                        words.next().unwrap_or("")
                    } else {
                        ""
                    };
                    if !COMMANDS.contains(&(cmd, sub)) {
                        continue;
                    }
                    let tail = words.collect::<Vec<_>>().join(" ");
                    let command = tail.split('`').next().unwrap();
                    let mut quote = None;
                    let mut visible = String::new();
                    for c in command.chars() {
                        if quote == Some(c) {
                            quote = None;
                        } else if quote.is_none() && ['\'', '"'].contains(&c) {
                            quote = Some(c);
                        } else if quote.is_none() {
                            visible.push(c);
                        }
                    }
                    for part in visible.split("--").skip(1) {
                        let end = part
                            .find(|c: char| !c.is_ascii_alphanumeric() && c != '-')
                            .unwrap_or(part.len());
                        if end > 0 {
                            accepted(cmd, sub, &format!("--{}", &part[..end]));
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod inventory_regressions {
    #[test]
    fn size_limit_is_persisted_as_a_coverage_gap() {
        let dir = omgs::platform::temp_root()
            .unwrap()
            .join(format!("omgs-inventory-limit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let target = dir.join("repo");
        let run = dir.join("run");
        omgs::platform::create_private_dir(&dir).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        for i in 0..4 {
            std::fs::write(target.join(format!("{i}.rs")), "").unwrap();
        }
        let args = vec![
            "--target".into(),
            target.to_string_lossy().into_owned(),
            "--out".into(),
            run.to_string_lossy().into_owned(),
            "--no-sensors".into(),
        ];
        super::audit_init_limited(&args, 3).unwrap();
        let read = |name| {
            serde_json::from_str::<serde_json::Value>(
                &std::fs::read_to_string(run.join(name)).unwrap(),
            )
            .unwrap()
        };
        let meta = read("run-metadata.json");
        assert_eq!(meta["files_total"], 3);
        assert_eq!(meta["inventory_limit"], 3);
        assert!(meta["inventory_gaps"][0]
            .as_str()
            .unwrap()
            .contains("3 files"));
        let ledger = read("coverage-ledger.json");
        assert!(ledger["units"]
            .as_array()
            .unwrap()
            .iter()
            .any(|u| u["id"] == "inventory:limit" && u["status"] == "blocked"));
        assert_eq!(
            read("architecture.json")["unexamined"],
            meta["inventory_gaps"]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn omissions_are_bounded_sorted_and_directory_read_failures_are_recorded() {
        let root = omgs::platform::temp_root()
            .unwrap()
            .join("omgs-nonexistent-inventory-root");
        let mut gaps = super::InventoryGaps::default();
        let mut files = Vec::new();
        super::walk_limited(&root, &root.join("missing"), 0, &mut files, 100, &mut gaps);
        assert_eq!(gaps.0["read"].count, 1);
        for n in (0..30).rev() {
            gaps.record("symlink", &root.join(format!("link{n:02}")), &root);
        }
        assert_eq!(gaps.0["symlink"].count, 30);
        assert_eq!(gaps.0["symlink"].samples.len(), 20);
        assert_eq!(gaps.0["symlink"].samples.first().unwrap(), "link00");
        assert_eq!(gaps.0["symlink"].samples.last().unwrap(), "link19");
    }

    #[test]
    fn linked_javascript_and_deep_python_remain_explicit_report_gaps() {
        let dir = omgs::platform::temp_root()
            .unwrap()
            .join(format!("omgs-inventory-omissions-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        omgs::platform::create_private_dir(&dir).unwrap();
        let target = dir.join("repo");
        let external = dir.join("external");
        std::fs::create_dir(&target).unwrap();
        std::fs::create_dir(&external).unwrap();
        std::fs::write(target.join("visible.rs"), "fn main() {} ").unwrap();
        std::fs::write(external.join("hidden.js"), "eval(input)").unwrap();
        let mut deep = target.clone();
        for _ in 0..13 {
            deep.push("nested");
        }
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("hidden.py"), "eval(input)").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&external, target.join("linked")).unwrap();
        #[cfg(windows)]
        assert!(std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(target.join("linked"))
            .arg(&external)
            .status()
            .unwrap()
            .success());
        let run = dir.join("run");
        let args = vec![
            "--target".into(),
            target.to_str().unwrap().into(),
            "--out".into(),
            run.to_str().unwrap().into(),
            "--no-sensors".into(),
        ];
        super::audit_init_limited(&args, 100).unwrap();
        let read = |name| {
            serde_json::from_str::<serde_json::Value>(
                &std::fs::read_to_string(run.join(name)).unwrap(),
            )
            .unwrap()
        };
        let meta = read("run-metadata.json");
        assert_eq!(meta["files_total"], 1);
        assert_eq!(meta["detected_stacks"], serde_json::json!(["rust"]));
        assert_eq!(meta["inventory_gaps"].as_array().unwrap().len(), 2);
        assert_eq!(
            read("architecture.json")["unexamined"],
            meta["inventory_gaps"]
        );
        let ledger = read("coverage-ledger.json");
        for reason in ["depth", "symlink"] {
            let unit = ledger["units"]
                .as_array()
                .unwrap()
                .iter()
                .find(|u| u["id"] == format!("inventory:{reason}"))
                .unwrap();
            assert_eq!(unit["status"], "blocked");
            assert_eq!(unit["inventory_gap_count"], 1);
            assert_eq!(unit["inventory_gap_samples"].as_array().unwrap().len(), 1);
        }
        omgs::runmeta::write_atomic(&run.join("candidates-red.json"), "{\"candidates\":[]}")
            .unwrap();
        let args = vec![
            "--findings".into(),
            run.join("findings.json").to_str().unwrap().into(),
            "--out".into(),
            run.to_str().unwrap().into(),
        ];
        super::cmd_report(&args).unwrap();
        for name in ["REPORT.md", "REPORT.html"] {
            let report = std::fs::read_to_string(run.join(name)).unwrap();
            assert!(report.contains("inventory:depth"));
            assert!(report.contains("inventory:symlink"));
            assert!(report.contains("linked"));
            assert!(report.contains("nested/nested"));
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
