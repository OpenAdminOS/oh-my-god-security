use omgs::architecture::{
    render_architecture_html, render_architecture_markdown, validate_architecture, ArchitectureFile,
};
use omgs::critic::critique_run;
use omgs::ledger::{add_unit, coverage_lines, set_status, validate_ledger, Ledger, Unit, STATUSES};
use omgs::model::{identity, validate, FindingsFile};
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

fn clone_root(args: &[String]) -> Result<PathBuf, String> {
    let path = flag(args, "--clone-root")
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir().join("targets"));
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
        "review" => ("--repo-url --mode --budget --no-sensors --persona --out --clone-root", false),
        "audit" if args.first().is_some_and(|a| a == "init") => (
            "--target --base --out --mode --budget --no-sensors --hunter --verifier --persona --fix-of",
            true,
        ),
        "batch" if args.first().is_some_and(|a| a == "init") => {
            ("--list --out --mode --budget --no-sensors --persona --clone-root", true)
        }
        "batch" if args.first().is_some_and(|a| a == "index") => ("--batch --out", true),
        "bench" if args.first().is_some_and(|a| a == "score") => ("--cases --runs", true),
        "validate" => ("--findings --candidates --dispositions --evaluation", false),
        "fingerprint" => ("--attack-class --entry-point --sink --boundary", false),
        "prove" => (
            "--cmd --target --run --finding --test --test-from --expect-marker --replay --tier --timeout-ms",
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
        "ledger" if args.first().is_some_and(|a| a == "ingest") => ("--ledger --dispositions", true),
        "ledger" if args.first().is_some_and(|a| a == "list") => ("--ledger", true),
        "ledger" if args.first().is_some_and(|a| a == "add") => {
            ("--ledger --unit --surface --classes --status --note", true)
        }
        "ledger" if args.first().is_some_and(|a| a == "set") => {
            ("--ledger --unit --status --evidence --note --attempt-ref --blocker-ref", true)
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
        "audit" | "batch" | "ledger" | "intent" | "bench" if args == ["--help"] || args == ["-h"] => {
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
            || (cmd == "report" && option == "--model");
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
    eprintln!("error: {}", error.replace(['\r', '\n'], " "));
    eprintln!("run omgs --help for usage");
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
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
    let result: Result<(), String> = match cmd {
        "--help" | "-h" | "help" => {
            usage();
            Ok(())
        }
        "--version" | "-V" => {
            println!("omgs {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "update-check" => cmd_update_check(),
        "coalition-anchor" => cmd_coalition_anchor(rest),
        "install-self" => cmd_install_self(rest),
        "gate" => cmd_gate(rest),
        "setup" => cmd_setup(rest),
        "stage" => cmd_stage(rest),
        "review" => cmd_review(rest),
        "audit" => cmd_audit(rest),
        "validate" => cmd_validate(rest),
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

fn cmd_update_check() -> Result<(), String> {
    if let Some(line) = omgs::update::check() {
        println!("{line}");
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
    let allowance = omgs::runmeta::with_lock(&root, || omgs::budget::allowance(&root))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&allowance).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn read_findings(path: &str) -> Result<FindingsFile, String> {
    let text = omgs::run_artifact::text_path(Path::new(path), omgs::run_artifact::FINDINGS_BYTES)?;
    omgs::shape::findings(&text).map_err(|e| format!("parse {path}: {e}"))
}

/// Evidence rules plus proof records, which live in `proofs/` beside the
/// findings file.
fn validate_at(file: &FindingsFile, path: &str) -> Vec<String> {
    let dir = Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut errors = validate(file);
    errors.extend(omgs::proof::validate_proofs(file, dir));
    match omgs::attempts::finding_gaps(dir, file) {
        Ok(gaps) => errors.extend(gaps),
        Err(e) => errors.push(e),
    }
    errors
}

fn cmd_validate(args: &[String]) -> Result<(), String> {
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
            println!("valid: {kind}");
            return Ok(());
        }
    }
    let path = flag(args, "--findings").unwrap();
    let file = read_findings(&path)?;
    let errors = validate_at(&file, &path);
    if errors.is_empty() {
        let dir = Path::new(&path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let view = omgs::review::View::with_findings(dir, &file)?;
        println!(
            "valid: {} finding(s); review {}",
            view.findings.findings.len(),
            view.state.as_deref().unwrap_or("complete")
        );
        Ok(())
    } else {
        for e in &errors {
            eprintln!("invalid: {e}");
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
    write_out(
        dir.join("ARCHITECTURE.md"),
        render_architecture_markdown(&file),
    )
    .map_err(|e| e.to_string())?;
    write_out(
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

fn cmd_bench(args: &[String]) -> Result<(), String> {
    let cases = flag(args, "--cases").ok_or("bench score requires --cases <manifest>")?;
    let dirs: Vec<PathBuf> = flags(args, "--runs")
        .into_iter()
        .map(PathBuf::from)
        .collect();
    let result = omgs::bench::score(Path::new(&cases), &dirs)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?
    );
    eprint!("{}", omgs::bench::markdown(&result));
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

fn release_proof_charge(run: &Path) -> Result<(), String> {
    omgs::budget::release_proof(run)
}

fn cmd_prove(args: &[String]) -> Result<(), String> {
    #[cfg(unix)]
    let _signals = omgs::supervise::interruption::Guard::install().map_err(|e| e.to_string())?;
    let run = flag(args, "--run").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    {
        for path in std::iter::once(data_dir()).chain(run.iter().cloned()) {
            if let Err(error) = omgs::tcc::admit_path(&path) {
                eprintln!("needs_validation: target code was not executed. {error}");
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
            ] {
                if flag(args, conflicting).is_some() {
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
            return Err(format!(
                "cannot replay invalid record: {}",
                errors.join("; ")
            ));
        }
    }
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
        (None, d) => d.map(PathBuf::from),
    };
    if draft.is_some() && test.is_none() {
        return Err("--test-from needs --test <target-relative path> to stage it at".into());
    }
    // Replay evidence is read once through the run boundary and that exact
    // snapshot is staged below, even if the retained pathname is replaced.
    let replay_draft = match (&replay, &run) {
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
        _ => None,
    };
    let test_sha256 = match (&test, &draft) {
        (Some(_), Some(d)) => {
            let digest = match &replay_draft {
                Some((bytes, _)) => omgs::sha256::digest(bytes),
                // A caller-supplied draft is source input, not retained evidence.
                None => omgs::sha256::digest_file(d)
                    .map_err(|e| format!("--test-from {}: {e}", d.display()))?,
            };
            let d = std::fs::canonicalize(d)
                .map_err(|e| format!("--test-from {}: {e}", d.display()))?;
            if target.as_ref().is_some_and(|base| d.starts_with(base)) {
                return Err("--test-from must be a draft outside the target; drop it to use a test already in the target".into());
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
                eprintln!("proof test: {}", omgs::platform::describe_path(&path));
            }
            Some(
                omgs::sha256::digest_file(&path)
                    .map_err(|e| format!("read {}: {e}", omgs::platform::describe_path(&path)))?,
            )
        }
        (None, _) => None,
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
            eprintln!("needs_validation: target code was not executed. {why}");
            return Err("__EXIT3__".into());
        }
        let t = target
            .as_ref()
            .ok_or("--tier 2 needs a target, since approval is per repository")?;
        if !omgs::approval::is_approved(&data_dir(), t)? {
            eprintln!("needs_validation: tier 2 runs a locally built app and needs a one-time human approval for {}.", t.display());
            eprintln!(
                "Ask the person you are working for to run, at their own terminal: omgs approve --target {}",
                t.display()
            );
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
                    eprintln!("needs_validation: target code was not executed. {e}");
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
                .and_then(|_| match &replay_draft {
                    Some((bytes, permissions)) => {
                        omgs::runmeta::write_atomic_bytes_with_permissions(
                            &copy,
                            bytes,
                            permissions.clone(),
                        )
                    }
                    None => omgs::sandbox::stage_file(&run_dir, "test-draft", d),
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
    let request = ProveRequest {
        expect_marker: expect_marker.clone(),
        command: command.clone(),
        test: test.clone(),
        timeout_ms,
        target: target.clone(),
        run_dir: run_dir.clone(),
        tier,
        stage: staged_draft.zip(test.clone()),
        expected_tree_sha256: replay.as_ref().and_then(|r| r.target_sha256.clone()),
    };
    let started_at_ms = omgs::runmeta::now_ms();
    let result = match prove(&request) {
        ProveOutcome::Blocked { reason } => {
            release();
            eprintln!(
                "needs_validation: target code was not executed. {}",
                omgs::platform::escape_controls(&reason)
            );
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
    {
        use std::io::Write;
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(record.output.as_bytes())
            .map_err(|e| e.to_string())?;
        stdout.flush().map_err(|e| e.to_string())?;
    }
    eprintln!(
        "sandbox: MXC {} ({}), executor {} sha256 {}",
        omgs::sandbox::MXC_VERSION,
        result.containment,
        result.executor.display(),
        result.executor_sha256
    );
    for e in &result.enforced {
        eprintln!("  enforced: {e}");
    }
    for g in &result.gaps {
        eprintln!("  not enforced: {}", omgs::platform::escape_controls(g));
    }
    for v in &s.survivors {
        eprintln!(
            "  survivor killed: pid {} {}",
            v.pid,
            omgs::proof::redact(&v.command)
        );
    }
    eprintln!(
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
    );
    match &proof_dir {
        Some((n, _)) => eprintln!(
            "proof record: {} (proof_ref {})",
            record_path.display(),
            omgs::proof::reference(*n)
        ),
        None => eprintln!(
            "proof record: {} (not linked to a run)",
            record_path.display()
        ),
    }
    if record.finding.is_some() {
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
        eprintln!(
            "proof support for {tier_name}: {}",
            if reasons.is_empty() {
                "yes".into()
            } else {
                format!("no: {}", reasons.join("; "))
            }
        );
    }
    if let Some(orig) = &replay {
        let code = |c: Option<i32>| c.map(|c| c.to_string()).unwrap_or_else(|| "none".into());
        let same = record.exit_code == orig.exit_code
            && record.contract == orig.contract
            && record.clean()
            && orig.clean();
        eprintln!(
            "replay of {}: recorded exit {}, replayed exit {}: {}",
            omgs::proof::reference(orig.n),
            code(orig.exit_code),
            code(record.exit_code),
            if same { "reproduced" } else { "NOT reproduced" }
        );
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
        eprintln!(
            "doctor --live overall wall-clock deadline of {}s exceeded; remaining probes were not checked",
            budget.as_secs()
        );
        for name in remaining {
            println!("{name} not checked: overall doctor deadline exceeded");
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
    println!(
        "omgs {} on {os} {}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH
    );
    println!("data directory: {}", data_dir().display());
    if os == "windows" {
        println!("note: {}", omgs::sandbox::windows_build_report());
    }
    let ready = match omgs::sandbox::locate_executor() {
        Ok(l) => {
            println!(
                "sandbox: MXC {} executor {} ({}), SHA-256 matches the pin",
                omgs::sandbox::MXC_VERSION,
                l.path.display(),
                l.executor.containment
            );
            if os == "windows" {
                match omgs::sandbox::windows_policy(omgs::sandbox::windows_probe(&l.path)) {
                    Ok((_, _, notes, gaps)) => {
                        for note in notes {
                            println!("note: {}", omgs::platform::escape_controls(&note));
                        }
                        for gap in gaps {
                            println!("  not enforced: {}", omgs::platform::escape_controls(&gap));
                        }
                    }
                    Err(reason) => {
                        println!(
                            "sandbox: not ready. {}",
                            omgs::platform::escape_controls(&reason)
                        );
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
            println!("sandbox: not ready. {e}");
            false
        }
    };
    let (enforced, gaps) = omgs::sandbox::declared_controls(os, Tier::Test);
    println!(
        "{}",
        if ready {
            "proof controls when MXC starts successfully (conditional limits are reported per run):"
        } else {
            "planned proof controls if a verified MXC executor becomes available:"
        }
    );
    for e in enforced
        .iter()
        .chain(omgs::sandbox::declared_limits(os).iter())
    {
        println!("  {e}");
    }
    for g in &gaps {
        println!("  not enforced: {}", omgs::platform::escape_controls(g));
    }
    if let Some(why) = omgs::sandbox::tier2_unavailable(os) {
        println!("{why}");
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
            println!("{name} not on host PATH");
            remaining.retain(|probe| probe != name);
        }
    }
    println!(
        "toolchains on PATH: {}",
        if tools.is_empty() {
            "none".into()
        } else {
            tools.join(", ")
        }
    );
    let sensors = found(&["gitleaks", "semgrep", "trufflehog", "osv-scanner"]);
    println!(
        "sensors on PATH: {}",
        if sensors.is_empty() {
            "none".into()
        } else {
            sensors.join(", ")
        }
    );
    if os == "linux"
        && std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            .map(|v| v.trim() == "1")
            .unwrap_or(false)
    {
        println!("hint: this kernel restricts unprivileged user namespaces (Ubuntu 24.04 and later). MXC needs them; see the README section on Linux for the AppArmor profile.");
    }
    if os == "windows" {
        println!("note: upstream MXC issue https://github.com/microsoft/mxc/issues/1465 reports STATUS_DLL_INIT_FAILED for toolchains in Windows session 0; use an existing interactive desktop session when affected.");
    }
    if !ready {
        if has(args, "--live") {
            println!("live check: not run, no verified executor");
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
            expect_marker: None,
            command: cmd,
            test: Some(inside_test.into()),
            timeout_ms: 30_000,
            target: Some(target),
            run_dir: probe.join("run"),
            tier: Tier::Test,
            stage: None,
            expected_tree_sha256: None,
        };
        let outcome = match prove(&request) {
            ProveOutcome::Ran(r) => r,
            ProveOutcome::Blocked { reason } => {
                let _ = std::fs::remove_dir_all(&probe);
                eprintln!(
                    "needs_validation: target code was not executed. {}",
                    omgs::platform::escape_controls(&reason)
                );
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
            println!(
                "live check FAILED: the probe did not run (it could not read its own workspace). Its output:"
            );
            println!("{}", omgs::proof::redact(&out));
            for g in &outcome.gaps {
                println!("  note: {}", omgs::platform::escape_controls(g));
            }
            return Err("__EXIT1__".into());
        }
        if out.contains(&outside) || outcome.run.exit_code == Some(0) {
            println!(
                "live check FAILED: the sandboxed command could read a file outside its workspace"
            );
            return Err("__EXIT1__".into());
        }
        if outcome
            .gaps
            .iter()
            .any(|g| g.starts_with("this Windows version refuses parent directory enumeration"))
        {
            println!("live check: the probe read a nested workspace file; outside read not proven on this host");
        } else {
            println!("live check: the probe ran, read a nested workspace file, and was denied a file outside it");
        }
        for note in &outcome.notes {
            println!("note: {}", omgs::platform::escape_controls(note));
        }
        println!("applied on that run:");
        for e in &outcome.enforced {
            println!("  {e}");
        }
        for g in &outcome.gaps {
            println!("  not enforced: {}", omgs::platform::escape_controls(g));
        }
        let mut inside = Vec::new();
        for name in &tools {
            // Per-tool limits share the overall preparation and probe budget.
            if let Err(error) = omgs::supervise::check_interrupted() {
                let _ = std::fs::remove_dir_all(&probe);
                return Err(error.to_string());
            }
            let reach = ProveRequest {
                expect_marker: None,
                command: doctor_probe_command(os, name),
                test: None,
                timeout_ms: doctor_probe_timeout_ms(os, name),
                target: None,
                run_dir: probe.join(format!("reach-{name}")),
                tier: Tier::Test,
                stage: None,
                expected_tree_sha256: None,
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
                    println!("{}", doctor_tool_failure(name, &reason));
                }
            }
        }
        println!(
            "toolchains reachable inside the sandbox: {}",
            if inside.is_empty() {
                "none".into()
            } else {
                inside.join(", ")
            }
        );
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
        eprintln!("needs_validation: target code was not executed. {why}");
        return Err("__EXIT3__".into());
    }
    println!("Tier 2 builds and runs {} as a local app inside MXC, on dummy data, with external network denied.", target.display());
    println!("Type the folder name '{name}' to approve tier 2 for this repository:");
    let typed = omgs::approval::read_from_terminal()?;
    if typed.trim() != name {
        return Err("not approved: the typed name did not match".into());
    }
    omgs::approval::approve(&data_dir(), &target)?;
    println!("approved tier 2 for {}", target.display());
    Ok(())
}

fn write_handoff(
    dir: &Path,
    handoff: &omgs::handoff::Handoff,
    artifact_base: &str,
) -> Result<(), String> {
    omgs::runmeta::write_atomic(
        &dir.join("HANDOFF.md"),
        &omgs::handoff::markdown_at(handoff, artifact_base),
    )?;
    omgs::runmeta::write_atomic(
        &dir.join("handoff.json"),
        &format!(
            "{}\n",
            serde_json::to_string_pretty(handoff).map_err(|e| e.to_string())?
        ),
    )
}

fn cmd_handoff(args: &[String]) -> Result<(), String> {
    let run = PathBuf::from(flag(args, "--run").ok_or("handoff requires --run <dir>")?);
    let file = read_findings(&run.join("findings.json").to_string_lossy())?;
    let mut errors = omgs::model::validate_drafts(&file);
    errors.extend(omgs::proof::validate_proofs(&file, &run));
    if !errors.is_empty() {
        return Err(errors.join("\n"));
    }
    let only = flag(args, "--finding");
    let h = omgs::handoff::build(&run, &file, only.as_deref())?;
    write_handoff(&run, &h, "")?;
    println!("wrote HANDOFF.md and handoff.json in {}", run.display());
    Ok(())
}

fn cmd_stage(args: &[String]) -> Result<(), String> {
    let run = PathBuf::from(flag(args, "--run").ok_or("stage requires --run <dir>")?);
    let file = read_findings(&run.join("findings.json").to_string_lossy())?;
    let staged = omgs::handoff::stage_validated(&run, &file)?;
    for reason in &staged.excluded {
        eprintln!("{reason}");
    }
    omgs::runmeta::write_atomic(&run.join("proposed-tests.patch"), &staged.patch)?;
    println!("wrote {}", run.join("proposed-tests.patch").display());
    // Legacy runs can still export retained tests. Policy-aware runs also
    // produce the owner-reviewable registry and intent proposal.
    if omgs::run_artifact::optional_text(
        &run,
        Path::new(omgs::runmeta::FILE),
        omgs::run_artifact::METADATA_BYTES,
    )?
    .is_some()
        && omgs::runmeta::read(&run)?.contains_key("policy")
    {
        intent_propose_with_tests(&run, Some(&staged))?;
    }
    Ok(())
}

fn cmd_report(args: &[String]) -> Result<(), String> {
    let path = flag(args, "--findings").ok_or("report requires --findings <path>")?;
    let out = flag(args, "--out").ok_or("report requires --out <dir>")?;
    let file = read_findings(&path)?;
    let mut errors = omgs::model::validate_drafts(&file);
    errors.extend(omgs::proof::validate_proofs(
        &file,
        Path::new(&path).parent().unwrap_or(Path::new(".")),
    ));
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
    let mut sensors_summary: Option<String> = None;
    if let Some(dir) = &findings_dir {
        let path = dir.join("sensors.json");
        let text = omgs::run_artifact::optional_text(
            dir,
            Path::new("sensors.json"),
            omgs::run_artifact::SENSORS_BYTES,
        )?;
        if let Some(text) = text {
            {
                let rep = omgs::shape::sensors(&text)
                    .map_err(|e| format!("parse {}: {e}", path.display()))?;
                let vendored = rep.hits.iter().filter(|h| h.vendored).count();
                sensors_summary = Some(format!(
                    "{} run, {} hit(s), {} vendored; pattern matches only, never a clean bill of health",
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
    let raw_file = file;
    let file = omgs::review::View::with_findings(
        findings_dir.as_deref().unwrap_or(Path::new(".")),
        &raw_file,
    )?
    .findings;
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
    let mut saved = publication_run
        .map(omgs::runmeta::read)
        .transpose()?
        .unwrap_or_default();
    omgs::batch::check_meta_types(&saved)?;
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
        eprintln!(
            "warning: run metadata incomplete; pass --hunters <n>, --verifier <id>, and --agent-calls <n>. Unrecorded values render as \"not recorded\"."
        );
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
    if let Some(run) = publication_run {
        omgs::runmeta::update(run, |m| {
            let p = m
                .entry("publication")
                .or_insert_with(|| serde_json::json!({}))
                .as_object_mut()
                .ok_or("publication must be an object")?;
            for (key, value) in &publication {
                p.insert((*key).into(), serde_json::json!(value));
            }
            Ok(())
        })?;
        saved = omgs::runmeta::read(run)?;
    }
    let supplied_models = omgs::route::parse_identities(&flags(args, "--model"))?;
    omgs::report::publish(
        publication_run,
        explicit_agent_calls,
        &supplied_models,
        || {
            let mut accounting = omgs::accounting::read(&saved)?;
            omgs::accounting::submit(&saved, &mut accounting, supplied_usage.clone())?;
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
                repo: defaulted(flag(args, "--repo"), "repo", "target"),
                source_ref: defaulted(flag(args, "--ref"), "source_ref", "working tree"),
                mode: defaulted(flag(args, "--mode"), "mode", "advisory"),
                sandbox: defaulted(flag(args, "--sandbox"), "sandbox", "not recorded"),
                artifact_base: String::new(),
                review_limits: Vec::new(),
                timeline: Vec::new(),
                coverage: Vec::new(),
                sensors: sensors_summary,
                hunters,
                verifier,
                agent_calls,
                critic: None,
                models,
                reroutes: run_reroutes(findings_dir.as_deref())?,
                intent_answers: run_answers(findings_dir.as_deref())?,
                accounting,
                persona,
                report_depth,
            };
            let view = omgs::review::View::with_findings(
                findings_dir.as_deref().unwrap_or(Path::new(".")),
                &raw_file,
            )?;
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
            }
            let sensors = findings_dir
                .as_deref()
                .map(omgs::sensors::read_report)
                .transpose()?
                .flatten();
            let evidence = omgs::adjudication::report_lines(
                findings_dir.as_deref().unwrap_or(Path::new(".")),
                &file,
            )?;
            let evidence_md = omgs::adjudication::render_lines(&evidence, false);
            let evidence_html = omgs::adjudication::render_lines(&evidence, true);
            let sensor_md = omgs::report::sensor_section(sensors.as_ref(), false);
            let sensor_html = omgs::report::sensor_section(sensors.as_ref(), true);
            write_out(
                dir.join("REPORT.md"),
                format!("{}{sensor_md}{evidence_md}", render_markdown(&file, &meta)),
            )
            .map_err(|e| e.to_string())?;
            write_out(
                dir.join("REPORT.html"),
                render_html(&file, &meta)
                    .replace("</body>", &format!("{sensor_html}{evidence_html}</body>")),
            )
            .map_err(|e| e.to_string())?;
            write_out(dir.join("findings.sarif.json"), render_sarif(&file, &meta))
                .map_err(|e| e.to_string())?;
            write_handoff(dir, &handoff, &meta.artifact_base)?;
            println!(
                "wrote {}, {}, {}, {}, {}",
                dir.join("REPORT.md").display(),
                dir.join("REPORT.html").display(),
                dir.join("findings.sarif.json").display(),
                dir.join("HANDOFF.md").display(),
                dir.join("handoff.json").display()
            );
            let mut completion = omgs::report::Completion {
                hunters: meta.hunters,
                verifier: meta.verifier.clone(),
                accounting: supplied_usage.clone(),
                complete: view.complete(),
            };
            let status_run = findings_dir
                .as_deref()
                .map(|run| {
                    omgs::run_artifact::optional_text(
                        run,
                        Path::new(omgs::status::FILE),
                        omgs::run_artifact::STATUS_BYTES,
                    )
                    .map(|text| text.map(|_| run))
                })
                .transpose()?
                .flatten();
            if let Some(run) = status_run {
                omgs::status::apply(
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
                )?;
            }
            if let Some(run) = status_run {
                let view = omgs::review::View::with_findings(run, &raw_file)?;
                view.apply(&mut meta);
                let file = &view.findings;
                completion.complete = view.complete();
                write_handoff(
                    dir,
                    &omgs::handoff::build_view(run, &view, None)?,
                    &meta.artifact_base,
                )?;
                write_out(dir.join("findings.sarif.json"), render_sarif(file, &meta))
                    .map_err(|e| e.to_string())?;
                write_out(
                    dir.join("REPORT.md"),
                    format!("{}{sensor_md}{evidence_md}", render_markdown(file, &meta)),
                )
                .map_err(|e| e.to_string())?;
                write_out(
                    dir.join("REPORT.html"),
                    render_html(file, &meta)
                        .replace("</body>", &format!("{sensor_html}{evidence_html}</body>")),
                )
                .map_err(|e| e.to_string())?;
            }

            Ok(completion)
        },
    )
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
    let resolved = resolve_existing_prefix(parent)?
        .join(path.file_name().ok_or("intent answer store needs a name")?);
    if resolved.starts_with(target) {
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
    if resolved.starts_with(run) {
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
        eprintln!("warning: intent answers not shown: {why}");
        Ok(Default::default())
    };
    let target = omgs::runmeta::read_optional(dir)?
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
    let store = match read_target_store(&target) {
        Ok(s) => s,
        Err(e) => return refuse(&e),
    };
    // Run-local policy contents cannot attest owner acceptance. Read the
    // committed blob again using the same object-only path as init and gate.
    let accepted = match authenticated_policy(dir, &target) {
        Ok(s) => s.into_snapshot().policy.accepted_intent,
        Err(e) => {
            eprintln!("warning: policy-derived intent answers not shown: {e}");
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
        eprintln!("error: HOME (USERPROFILE on Windows) must be set to an absolute path");
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
            eprintln!(
                "warning: {} belongs to {}, not {}; intent answers not copied",
                answers_src.display(),
                answers.target,
                target.display()
            );
            None
        }
    } else {
        None
    };
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
        eprintln!("warning: run output is under a shared temp directory and describes vulnerabilities. Prefer the default runs directory under your home.");
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
            units.push(Unit::new(
                &format!("route:{rel}"),
                rel,
                &["missing_authz", "idor_tenant_isolation", "client_only_auth"],
                "planned",
            ));
        }
    }
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
    for (class, id, label) in [
        (
            omgs::paths::Class::Vendored,
            "vendored:excluded",
            "vendored or generated",
        ),
        (omgs::paths::Class::Docs, "docs:excluded", "documentation"),
        (
            omgs::paths::Class::Data,
            "data:excluded",
            "large structured data",
        ),
        (
            omgs::paths::Class::Test,
            "tests:excluded",
            "test or fixture",
        ),
    ] {
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
    let started_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut meta = serde_json::json!({
        "repo": repo, "target": target.to_string_lossy(), "source_ref": source_ref,
        "run_id": omgs::platform::random_nonce().map_err(|e| e.to_string())?,
        "sandbox": "MXC required; runtime version not recorded",
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
    print!("{prompt} [{default}]: ");
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
        println!("skill target: {}", target.display());
    }
    if targets.is_empty() {
        println!("no installed coding agent directories detected");
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
        println!("dry run; no files written and no live test run");
        if let Some(repo) = repo {
            println!("would create default {mode} policy in {repo}");
        }
        return Ok(());
    }
    if install && !targets.is_empty() {
        let from = flag(args, "--from").map(PathBuf::from);
        omgs::setup::install(from.as_deref(), &targets, has(args, "--replace"))?;
    }
    if let Some(repo) = repo {
        let path = omgs::setup::write_policy(Path::new(&repo), policy_mode)?;
        println!(
            "created {}; review and commit it before using it as base policy",
            path.display()
        );
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
            let s = f.to_string_lossy().replace('\\', "/");
            s.contains("/tests/security/")
                || s.contains(".security.test.")
                || s.contains(".security.spec.")
        })
        .count();
    println!("committed proof tests found: {proofs}");
    let scratch = flag(args, "--out")
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir().join("prove-scratch"));
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
    for gap in &sensors.gaps {
        println!("sensor gap: {gap}");
    }
    if let Some(out) = flag(args, "--out") {
        let dir = PathBuf::from(out);
        write_out(
            dir.join("sensor-hits.json"),
            serde_json::to_string_pretty(&sensors.hits).unwrap(),
        )
        .map_err(|e| e.to_string())?;
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        write_out(
            dir.join("sensors.json"),
            serde_json::to_string_pretty(&sensors).unwrap_or_default(),
        )
        .map_err(|e| e.to_string())?;
    }
    println!("check is deterministic and executes no target code. Run proof tests through: omgs prove --cmd <test command>");
    Ok(())
}

fn read_ledger(path: &str) -> Result<Ledger, String> {
    let text = omgs::run_artifact::text_path(Path::new(path), omgs::run_artifact::LEDGER_BYTES)?;
    omgs::shape::ledger(&text).map_err(|e| format!("parse {path}: {e}"))
}

fn write_ledger(path: &str, ledger: &Ledger) -> Result<(), String> {
    let text = serde_json::to_string_pretty(ledger).map_err(|e| e.to_string())?;
    let path = Path::new(path);
    omgs::runmeta::invalidate_completion_locked(path.parent().unwrap_or(Path::new(".")))?;
    omgs::runmeta::write_atomic(path, &format!("{text}\n"))
}

/// Every value given for a repeatable flag, in order.
fn flags(args: &[String], name: &str) -> Vec<String> {
    options(args)
        .filter(|(option, _)| *option == name)
        .filter_map(|(_, value)| value.map(str::to_string))
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
            println!("ingested dispositions");
            Ok(())
        }
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
            println!("{status}: {unit}");
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
            println!("{status}: {unit}");
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
fn clone_target(raw_url: &str, args: &[String]) -> Result<PathBuf, String> {
    let repo = omgs::batch::parse_repo_url(raw_url)?;
    let targets = clone_root(args)?;
    let dest = targets.join(&repo.host).join(&repo.owner).join(&repo.name);
    let git_path = omgs::platform::which("git").ok_or("git not found on an absolute PATH entry")?;
    let git = || {
        let mut c = std::process::Command::new(&git_path);
        c.env("GIT_TERMINAL_PROMPT", "0").args([
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
        ]);
        c
    };
    let parent = dest.parent().ok_or("invalid clone destination")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
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
            let origin = git()
                .args(["-C", &dest.to_string_lossy(), "remote", "get-url", "origin"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
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
                    origin.as_deref().unwrap_or("unknown"),
                    repo.url
                ));
            }
            return Ok(dest.clone());
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
        Ok(dest.clone())
    })
}

fn init_args(dest: &Path, args: &[String], out: Option<&Path>) -> Vec<String> {
    let mut v = vec!["--target".to_string(), dest.to_string_lossy().to_string()];
    for name in ["--mode", "--budget", "--persona"] {
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
    if let Some(p) = flag(args, "--persona") {
        omgs::persona::defaults(&p)?;
    }
    let dest = clone_target(&url, args)?;
    let out = flag(args, "--out").map(PathBuf::from);
    let run = audit_init(&init_args(&dest, args, out.as_deref()))?;
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
                if resolved.starts_with(resolve_existing_prefix(t)?) {
                    return Err(format!(
                        "batch output must live outside the reviewed targets, and {} is inside {}",
                        out_abs.display(),
                        t.display()
                    ));
                }
            }
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
                match resolved_targets.iter().find(|t| p.starts_with(t)) {
                    Some(t) => Err(format!(
                        "run directory {} resolves inside {}",
                        p.display(),
                        t.display()
                    )),
                    None => Ok(()),
                }
            };
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
                &data_dir().join("targets"),
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
            let runs = batch
                .runs
                .iter()
                .map(|r| omgs::batch::summarize(r, &out))
                .collect::<Result<Vec<_>, String>>()?;
            write_out(out.join("INDEX.md"), omgs::batch::render_index_markdown(&runs))
                .map_err(|e| e.to_string())?;
            write_out(out.join("INDEX.html"), omgs::batch::render_index_html(&runs))
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
    let supplied_usage = omgs::accounting::parse(&flags(args, "--accounting"))?;
    // Refuse malformed metadata before updating progress.
    omgs::runmeta::read(Path::new(&run))?;
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
    omgs::status::apply_with_logs(
        Path::new(&run),
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
    let usage = omgs::runmeta::update(Path::new(&run), |m| {
        let mut usage = omgs::accounting::read(m)?;
        omgs::accounting::submit(m, &mut usage, supplied_usage)?;
        m.insert(
            "accounting".into(),
            serde_json::to_value(&usage).map_err(|e| e.to_string())?,
        );
        Ok(usage)
    })?;
    let view = omgs::review::View::load(Path::new(&run))?;
    println!(
        "{stage}: {state}; review {}",
        view.state.as_deref().unwrap_or("complete")
    );
    if !flags(args, "--accounting").is_empty() {
        for line in omgs::accounting::lines(&usage) {
            println!("{line}");
        }
    }
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
        println!("{label}");
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

fn intent_propose(run: &Path) -> Result<(), String> {
    intent_propose_with_tests(run, None)
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
    println!(
        "owner review patch: {}",
        match staged {
            Some(tests) => omgs::policy::propose_staged(run, &merged, tests, &policy)?,
            None => omgs::policy::propose(run, &merged, &policy)?,
        }
        .display()
    );
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
                let valid: std::collections::BTreeSet<_> = omgs::intent::list(None, None).iter().flat_map(|q| q.attack_classes.iter().cloned()).collect();
                if !valid.contains(c) { return Err(format!("unknown attack class {c}; expected {}", valid.into_iter().collect::<Vec<_>>().join(", "))); }
            }
            for q in omgs::intent::list(stack.as_deref(), class.as_deref()) {
                println!("{}: {}", q.id, q.question);
                if !q.answers.is_empty() {
                    println!("  answers: {}", q.answers.join(" | "));
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
            println!("recorded {id} in {}", path.display());
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
        println!(
            "{}",
            match outcome {
                omgs::attempts::AppendOutcome::Recorded => "recorded",
                omgs::attempts::AppendOutcome::AlreadyRecorded =>
                    "already recorded; do not dispatch again",
            }
        );
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
                println!(
                    "recover_result={recovery:?}, orphan_exists={}",
                    orphan.exists()
                );
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
                println!("{stdout}{stderr}");
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
        ("fingerprint", ""),
        ("bench", "score"),
        ("prove", ""),
        ("approve", ""),
        ("report", ""),
        ("handoff", ""),
        ("stage", ""),
        ("architecture", ""),
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
                ("audit", _) => {
                    sections.push(("audit_init", function(source, "audit_init")));
                    sections.push(("audit_init_limited", function(source, "audit_init_limited")));
                }
                ("doctor", _) => {
                    sections.push(("cmd_doctor_inner", function(source, "cmd_doctor_inner")));
                }
                ("route", _) => sections.push(("models_path", function(source, "models_path"))),
                ("ledger", _) => {
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
