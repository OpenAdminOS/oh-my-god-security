//! Installed scanners parse hostile source, so they use the proof executor too.
use super::*;

pub struct SensorRequest<'a> {
    pub executable: &'a Path,
    pub args: Vec<String>,
    pub target: &'a Path,
    pub artifacts: &'a Path,
    pub readonly: Vec<PathBuf>,
    pub env: Vec<String>,
    pub limits: supervise::Limits,
    pub semgrep: bool,
    pub config: &'static str,
}

fn quote(arg: &str) -> Result<String, String> {
    if arg.contains(['\0', '\r', '\n']) {
        return Err("sensor argument contains a control character".into());
    }
    if cfg!(windows) {
        // cmd expands percent even inside quotes. Refuse rather than changing
        // a path or allowing a second command through a quoted argument.
        if arg.contains(['"', '%', '!']) {
            return Err("sensor argument cannot be quoted safely on Windows".into());
        }
        Ok(format!("\"{arg}\""))
    } else {
        Ok(format!("'{}'", arg.replace('\'', "'\"'\"'")))
    }
}

pub fn run_sensor(mut req: SensorRequest<'_>) -> Result<(String, i32, Vec<String>), String> {
    crate::scratch::recover()?;
    let located =
        locate_executor().map_err(|_| "pinned MXC unavailable; sensor not run".to_string())?;
    let os = std::env::consts::OS;
    let (list_parents, _, _, mut gaps) = if os == "windows" {
        preflight::windows_policy(windows_probe(&located.path))?
    } else {
        (false, false, Vec::new(), Vec::new())
    };
    let executable = std::fs::canonicalize(req.executable).map_err(|_| "cannot resolve scanner")?;
    let runtime = scanner_runtime_roots(&executable, req.semgrep)?;
    let mut readonly = runtime.roots;
    if let Some(python) = runtime.python {
        let python_grants = python_runtime_grants(&req, &python)?;
        let sites: Vec<_> = python_grants
            .iter()
            .filter(|p| p.file_name().is_some_and(|n| n == "site-packages"))
            .map(|p| mxc_path(p))
            .collect();
        let path = std::env::join_paths(&sites)
            .map_err(|_| "cannot represent Python package search path; sensor not run")?
            .into_string()
            .map_err(|_| "invalid Python package search path; sensor not run")?;
        req.env.push(format!("PYTHONPATH={path}"));
        req.env.push("PYTHONNOUSERSITE=1".into());
        readonly.extend(python_grants);
    }
    readonly.extend(req.readonly.iter().cloned());
    let homes: Vec<_> = ["HOME", "USERPROFILE"]
        .into_iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .collect();
    validate_sensor_grants(&readonly, &homes, req.target, req.artifacts)?;
    let _signals = supervise::interruption::Guard::install()
        .map_err(|_| "cannot install sensor interruption guard".to_string())?;
    let nonce = platform::random_nonce().map_err(|_| "cannot create sensor nonce")?;
    let mut scratch = crate::scratch::Scratch::create_checked("sensor", |root| {
        if overlapping_root(req.target, &[root.to_path_buf()]).is_some() {
            return Err("private sensor scratch overlaps target; sensor not run".into());
        }
        if overlapping_root(req.artifacts, &[root.to_path_buf()]).is_some() {
            return Err("private sensor scratch overlaps artifacts; sensor not run".into());
        }
        if overlapping_root(root, &readonly).is_some() {
            return Err("private sensor scratch overlaps a readable grant; sensor not run".into());
        }
        Ok(())
    })?;
    let root = scratch.path();
    req.readonly = readonly;
    let result = run_in_scratch(req, &located, &root, list_parents, &nonce, &mut gaps);
    if scratch.cleanup().is_err() {
        return Err("private sensor scratch cleanup failed; raw scanner data may remain in the OMGS data directory".into());
    }
    match result {
        Ok((output, code)) => Ok((output, code, gaps)),
        Err(reason) if gaps.is_empty() => Err(reason),
        Err(reason) => Err(format!(
            "{reason}; retained input coverage: {}",
            gaps.join("; ")
        )),
    }
}

fn run_in_scratch(
    req: SensorRequest<'_>,
    located: &Located,
    root: &Path,
    list_parents: bool,
    nonce: &str,
    gaps: &mut Vec<String>,
) -> Result<(String, i32), String> {
    let os = std::env::consts::OS;
    let root = std::fs::canonicalize(root).map_err(|_| "cannot resolve sensor scratch")?;
    let executor = root.join(located.executor.file);
    std::fs::copy(&located.path, &executor).map_err(|_| "cannot stage sensor executor")?;
    if sha256::digest_file(&executor).map_err(|_| "cannot hash staged sensor executor")?
        != located.executor.sha256
    {
        return Err("staged sensor executor does not match pin".into());
    }
    let work = root.join("scratch");
    platform::create_private_dir_new(&work).map_err(|_| "cannot create sensor home")?;
    let executable = std::fs::canonicalize(req.executable).map_err(|_| "cannot resolve scanner")?;
    let mut readonly = req.readonly;
    let target = root.join("target");
    platform::create_private_dir_new(&target).map_err(|_| "cannot create sensor workspace")?;
    let mut budget = InputBudget {
        semgrep: req.semgrep,
        ..Default::default()
    };
    copy_input(req.target, Path::new(""), &target, &mut budget)?;
    if budget.skipped > 0 {
        gaps.push(format!("{} input entries/subtrees skipped; {} manifest records omitted (16 MiB/file, 64 MiB total, 10000 staged files, 100000 enumerated entries, 64 directory levels)", budget.skipped, budget.skipped.saturating_sub(budget.manifest.len())));
        for record in &budget.manifest {
            gaps.push(format!("input skip: {record}"));
        }
    }
    if req.semgrep {
        if budget.semgrep_oversized > 0 {
            gaps.push(format!(
                "{} input files exceed Semgrep's 1000000 byte target limit; not scanned by Semgrep",
                budget.semgrep_oversized
            ));
        }
        remove_semgrep_ignores(&target)?;
    }
    if overlapping_root(&root, &readonly).is_some() {
        // The private workspace is intentionally within root, but no granted
        // runtime/database/target may encompass the whole disposable directory.
        return Err("sensor scratch overlaps a readable runtime, database or target".into());
    }
    readonly.push(target.clone());
    #[cfg(target_os = "macos")]
    {
        let capture = supervise::capture_root().map_err(|_| "capture root unavailable")?;
        let mut grants = readonly.clone();
        grants.push(work.clone());
        supervise::validate_capture_grants(&capture, &grants)
            .map_err(|_| "sensor grants overlap private capture")?;
    }
    let config_file = root.join("empty.toml");
    std::fs::write(&config_file, req.config).map_err(|_| "cannot write empty sensor config")?;
    readonly.push(config_file.clone());
    let mut args = vec![quote(&mxc_path(&executable))?];
    for arg in req.args {
        // These placeholders are owned by OMGS, never target input.
        let arg = match arg.as_str() {
            "{target}" => mxc_path(&target),
            "{config}" => mxc_path(&config_file),
            _ => arg,
        };
        args.push(quote(&arg)?);
    }
    let command = args.join(" ");
    write_wrapper(os, &work, &command, nonce, None).map_err(|_| "cannot write sensor wrapper")?;
    if os == "windows" {
        // MXC redirects TEMP into USERPROFILE/Packages/<container>/AC/Temp,
        // but does not create the directory. Create it inside the container,
        // where MXC restricts writes to our disposable scratch root.
        let path = work.join(format!("{}.cmd", wrapper_name(&command, nonce, None)));
        let script = std::fs::read_to_string(&path).map_err(|_| "cannot read sensor wrapper")?;
        let script = script.replacen(
            "@echo off\r\n",
            "@echo off\r\nif not exist \"%TEMP%\\\" mkdir \"%TEMP%\"\r\n",
            1,
        );
        std::fs::write(path, script).map_err(|_| "cannot prepare redirected sensor temp")?;
    }
    let wrapped = wrapped_command(os, &command, nonce, None);
    let ownership = (os == "macos").then(|| supervise::MacOwnership {
        grants: readonly.iter().cloned().chain([work.clone()]).collect(),
    });
    let input = ConfigInput {
        contract: None,
        os,
        containment: located.executor.containment,
        command: &wrapped,
        timeout_ms: req.limits.wall_ms,
        workspace: &work,
        scratch: &work,
        readonly,
        denied: Vec::new(),
        rust: None,
        list_parents,
    };
    let mut config = mxc_config(&input);
    // Only private scratch is writable. In particular, the target and rules
    // remain read-only even when the scanner tries to create sidecar files.
    config["filesystem"]["readwritePaths"] = serde_json::json!([mxc_path(&work)]);
    let env = config["process"]["env"].as_array_mut().unwrap();
    env.extend(req.env.into_iter().map(serde_json::Value::String));
    #[cfg(target_os = "macos")]
    crate::tcc::admit_config(&config).map_err(|e| e.to_string())?;
    let path = root.join("mxc-config.json");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap())
        .map_err(|_| "cannot write sensor config")?;
    #[cfg(windows)]
    let acl =
        preflight::WindowsAclSnapshot::capture([&work].into_iter().chain(input.readonly.iter()))?;
    let usage = crate::scratch::UsageMonitor::start(work.clone());
    #[allow(unused_mut)]
    let mut validation = preflight::dry_run(&executor, &path, &root);
    #[cfg(windows)]
    acl.verify(&mut validation);
    if !validation.success || !validation.cleanup_complete || !validation.capture_complete {
        return Err(
            "MXC sensor configuration rejected or preflight incomplete; sensor not run".into(),
        );
    }
    let cmd = preflight::workload_command(&executor, &path, &root);
    let mut limits = req.limits;
    limits.wall_ms = supervisor_timeout_ms(os, limits.wall_ms);
    limits.file_size_bytes = Some(
        limits
            .file_size_bytes
            .unwrap_or(crate::scratch::SENSOR_WRITE_BYTES)
            .min(crate::scratch::SENSOR_WRITE_BYTES),
    );
    #[allow(unused_mut)]
    let mut run =
        supervise::run_monitored(cmd, &limits, ownership.as_ref(), nonce, &usage.cancellation);
    #[cfg(windows)]
    acl.verify(&mut run);
    if let Err(reason) = usage.finish() {
        if !run.cleanup_complete || !run.survivors.is_empty() {
            return Err(format!("{reason}; workload cleanup could not be verified"));
        }
        gaps.push(reason);
        return Ok((String::new(), 3));
    }
    // Never retain executor diagnostics, scanner stderr, or survivor commands.
    if run.timed_out
        || run.interrupted
        || run.killed
        || run.executor_error
        || !run.command_started
        || !run.command_finished
        || !run.capture_complete
        || !run.cleanup_complete
        || !run.survivors.is_empty()
        || run.output_bytes_total > limits.output_cap_bytes as u64
    {
        let timed_out = run.timed_out
            || (!run.command_finished
                && run.duration_ms
                    >= limits
                        .wall_ms
                        .saturating_sub(if os == "windows" { 0 } else { 15000 }));
        return Err(format!("scan failed, timed out, or output incomplete (timeout={timed_out}, started={}, finished={}, cleanup={}, capture={})", run.command_started, run.command_finished, run.cleanup_complete, run.capture_complete));
    }
    if os == "linux"
        && !run
            .enforced
            .iter()
            .any(|s| s.starts_with("cgroup_memory_max="))
    {
        gaps.push("memory and task limits not applied: Linux cgroups required".into());
    }
    if run.output.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.contains("\"level\":\"error\"")
            || lower.contains("\"level\":\"warn\"")
            || lower.contains("skipping ")
            || lower.contains("skipped ")
    }) {
        gaps.push(
            "scanner reported diagnostics or skipped input; raw diagnostics discarded".into(),
        );
    }
    let start = format!("OMGS_START_{nonce}\n");
    let end = format!("\nOMGS_END_{nonce}:");
    let normalized = run.stdout.replace("\r\n", "\n");
    let output = normalized
        .split_once(&start)
        .and_then(|(_, s)| s.rsplit_once(&end))
        .map(|(s, _)| s.to_owned())
        .ok_or("missing sensor output boundary")?;
    let output = output
        .lines()
        .map(|line| {
            // OSV and Semgrep produce one JSON document (possibly multiline), so
            // the full-document pass below handles those. TruffleHog is NDJSON.
            translate_paths(line, &target)
        })
        .collect::<Vec<_>>()
        .join("\n");
    let output = translate_paths(&output, &target);
    Ok((output, run.exit_code.ok_or("missing sensor exit status")?))
}

fn remove_semgrep_ignores(dir: &Path) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|_| "cannot inspect copied ignore files")? {
        let entry = entry.map_err(|_| "cannot inspect copied ignore entry")?;
        let meta = std::fs::symlink_metadata(entry.path())
            .map_err(|_| "cannot inspect copied ignore metadata")?;
        if entry.file_name() == ".semgrepignore" {
            if meta.is_dir() && !platform::is_link(&meta) {
                std::fs::remove_dir_all(entry.path())
            } else {
                std::fs::remove_file(entry.path())
            }
            .map_err(|_| "cannot remove copied semgrepignore")?;
        } else if meta.is_dir() && !platform::is_link(&meta) {
            remove_semgrep_ignores(&entry.path())?;
        }
    }
    Ok(())
}

fn translate_paths(output: &str, target: &Path) -> String {
    fn visit(v: &mut serde_json::Value, target: &Path) {
        match v {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    if matches!(key.as_str(), "path" | "file" | "File") {
                        if let Some(file) = value.as_str() {
                            if let Ok(rel) = Path::new(file).strip_prefix(target) {
                                *value = serde_json::json!(platform::mxc_path(rel));
                            }
                        }
                    } else {
                        visit(value, target);
                    }
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    visit(item, target);
                }
            }
            _ => {}
        }
    }
    // Use strict JSON so translation cannot hide duplicate keys from parsers.
    match crate::shape::strict_json(output) {
        Ok(mut v) => {
            visit(&mut v, Path::new(&mxc_path(target)));
            serde_json::to_string(&v).unwrap()
        }
        Err(_) => output.to_string(),
    }
}

#[derive(Default)]
struct InputBudget {
    bytes: u64,
    entries: usize,
    staged: usize,
    skipped: usize,
    semgrep_oversized: usize,
    semgrep: bool,
    manifest: Vec<String>,
}
impl InputBudget {
    fn skip(&mut self, path: &Path, reason: &str) {
        self.skipped += 1;
        if self.manifest.len() < 128 {
            let path = if path.as_os_str().is_empty() {
                ".".into()
            } else {
                crate::paths::display(path)
            };
            let shortened: String = path.chars().take(1024).collect();
            self.manifest.push(
                serde_json::json!({
                    "path": shortened, "path_truncated": path.chars().count() > 1024,
                    "reason": reason,
                })
                .to_string(),
            );
        }
    }
}
fn copy_input(
    root: &Path,
    rel: &Path,
    dest: &Path,
    budget: &mut InputBudget,
) -> Result<(), String> {
    let mut files = Vec::new();
    inventory_input(root, rel, budget, &mut files)?;
    files.sort_by_key(|(path, _)| {
        let class = crate::paths::classify_file(root, path);
        (
            class != crate::paths::Class::Code,
            !crate::paths::is_source(&crate::paths::display(path)),
            path.clone(),
        )
    });
    for (path, size) in files {
        supervise::check_interrupted().map_err(|_| "sensor input copy interrupted")?;
        let reason = if size > 16 << 20 {
            Some("file byte limit")
        } else if budget.staged >= 10000 {
            Some("staged file limit")
        } else if budget.bytes + size > 64 << 20 {
            Some("total byte limit")
        } else {
            None
        };
        if let Some(reason) = reason {
            budget.skip(&path, reason);
            continue;
        }
        match platform::read_bounded_in(root, &path, (16 << 20).min((64 << 20) - budget.bytes)) {
            Ok(bytes) => {
                if bytes.len() > crate::sensors::SEMGREP_MAX_TARGET_BYTES {
                    budget.semgrep_oversized += 1;
                    if budget.semgrep {
                        budget.skip(
                            &path,
                            "Semgrep target byte limit; file staged but not scanned",
                        );
                    }
                }
                budget.bytes += bytes.len() as u64;
                budget.staged += 1;
                if let Some(parent) = dest.join(&path).parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|_| "cannot create sensor input directory")?;
                }
                std::fs::write(dest.join(&path), bytes).map_err(|_| "cannot copy sensor input")?;
            }
            Err(_) => budget.skip(&path, "unreadable, changed or unsafe file"),
        }
    }
    Ok(())
}
fn inventory_input(
    root: &Path,
    rel: &Path,
    budget: &mut InputBudget,
    files: &mut Vec<(PathBuf, u64)>,
) -> Result<(), String> {
    supervise::check_interrupted().map_err(|_| "sensor input inventory interrupted")?;
    if rel.components().count() > 64 {
        budget.skip(rel, "directory depth limit; subtree unenumerated");
        return Ok(());
    }
    if budget.entries >= 100000 {
        budget.skip(rel, "enumeration limit; subtree unenumerated");
        return Ok(());
    }
    let entries = match std::fs::read_dir(root.join(rel)) {
        Ok(entries) => entries,
        Err(_) => {
            budget.skip(rel, "unreadable directory; subtree unenumerated");
            return Ok(());
        }
    };
    let mut dirs = Vec::new();
    for entry in entries {
        if budget.entries >= 100000 {
            budget.skip(
                rel,
                "enumeration limit; remaining directory entries unenumerated",
            );
            break;
        }
        budget.entries += 1;
        let Ok(entry) = entry else {
            budget.skip(rel, "unreadable directory entry; identity unavailable");
            continue;
        };
        let path = rel.join(entry.file_name());
        let meta = match std::fs::symlink_metadata(entry.path()) {
            Ok(meta) => meta,
            Err(_) => {
                budget.skip(&path, "unreadable metadata");
                continue;
            }
        };
        if platform::is_link(&meta) {
            budget.skip(&path, "link; not followed");
        } else if meta.is_dir() {
            dirs.push(path);
        } else if meta.is_file() {
            files.push((path, meta.len()));
        } else {
            budget.skip(&path, "special file");
        }
    }
    // Defer conventional bulk containers during bounded discovery. Staging then
    // sorts all discovered first-party code before assets and exclusions.
    dirs.sort_by_key(|p| {
        let name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_ascii_lowercase();
        (
            [
                "public",
                "assets",
                "images",
                "node_modules",
                "vendor",
                ".git",
            ]
            .contains(&name.as_str()),
            p.clone(),
        )
    });
    for dir in dirs {
        inventory_input(root, &dir, budget, files)?;
    }
    Ok(())
}

// Never derive directory grants from a bin/Scripts name. Even the Python
// discovery process starts with file grants only and runs inside pinned MXC.
struct ScannerRuntime {
    roots: Vec<PathBuf>,
    python: Option<PythonRuntime>,
}
struct PythonRuntime {
    interpreter: PathBuf,
    venv: Option<PathBuf>,
}
fn scanner_runtime_roots(executable: &Path, semgrep: bool) -> Result<ScannerRuntime, String> {
    use std::io::Read;
    let mut roots = vec![executable.to_path_buf()];
    let mut header = Vec::new();
    std::fs::File::open(executable)
        .and_then(|f| f.take(1024).read_to_end(&mut header))
        .map_err(|_| "cannot read installed scanner header")?;
    let mut interpreter = None;
    if header.starts_with(b"#!") {
        let header = String::from_utf8_lossy(&header);
        let name = header[2..]
            .split_whitespace()
            .next()
            .ok_or("missing scanner interpreter")?;
        let path = std::fs::canonicalize(name).map_err(|_| "scanner interpreter unavailable")?;
        roots.push(path);
        if semgrep {
            let name_path = Path::new(name);
            let file = name_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_ascii_lowercase();
            if file.starts_with("python") {
                interpreter = Some(PathBuf::from(name));
            } else if file == "env" {
                return Err(
                    "Python runtime not proven: env interpreter is ambiguous; sensor not run"
                        .into(),
                );
            }
            // Other script runtimes use file-only grants, like native tools.
        }
    }
    let launcher_prefix = executable
        .parent()
        .and_then(Path::parent)
        .filter(|p| p.join("pyvenv.cfg").is_file());
    if cfg!(windows) && semgrep && interpreter.is_none() {
        if let Some(prefix) = launcher_prefix {
            let python = prefix.join("Scripts/python.exe");
            if !python.is_file() {
                return Err(
                    "Python runtime not proven: venv interpreter unavailable; sensor not run"
                        .into(),
                );
            }
            interpreter = Some(python);
        }
    }
    Ok(ScannerRuntime {
        roots,
        python: interpreter.map(|interpreter| {
            // A config beside the entry script can be stale or unrelated.
            // Only the selected interpreter's own configuration proves a venv.
            let venv = interpreter
                .parent()
                .and_then(Path::parent)
                .filter(|p| p.join("pyvenv.cfg").is_file())
                .map(Path::to_path_buf);
            PythonRuntime { interpreter, venv }
        }),
    })
}

// Installation metadata may be world-readable. It is not private run data,
// but links, special files and unbounded reads still cannot establish grants.
fn read_venv_config(prefix: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let file = platform::open_single_link(&prefix.join("pyvenv.cfg"))
        .map_err(|_| "cannot read scanner runtime configuration")?
        .ok_or("cannot read scanner runtime configuration")?;
    let mut config = Vec::new();
    file.take(16385)
        .read_to_end(&mut config)
        .map_err(|_| "cannot read scanner runtime configuration")?;
    if config.len() > 16384 {
        return Err("scanner runtime configuration exceeds byte limit".into());
    }
    Ok(config)
}

fn python_runtime_grants(
    req: &SensorRequest<'_>,
    python: &PythonRuntime,
) -> Result<Vec<PathBuf>, String> {
    // -I excludes inherited Python configuration and -S prevents site/.pth
    // execution during discovery. All reported paths still pass grant policy.
    // Some non-system interpreters cannot bootstrap with file-only grants. They
    // are deliberately refused rather than guessing a wider bootstrap prefix.
    const DISCOVER: &str = "import sys,os; os.environ['HOME']=sys.argv[1]; os.environ['USERPROFILE']=sys.argv[1]; os.environ['APPDATA']=sys.argv[2]; import sysconfig,site,json; print(json.dumps({'base':sys.base_prefix,'prefix':sys.prefix,'sites':[sysconfig.get_path(k) for k in ('purelib','platlib')]+[site.getusersitepackages()]}))";
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .ok_or("Python runtime not proven: user profile unavailable; sensor not run")?;
    let appdata = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join("AppData/Roaming"));
    if let Some(prefix) = &python.venv {
        read_venv_config(prefix)?;
    }
    let readonly = python.venv.iter().map(|p| p.join("pyvenv.cfg")).collect();
    let discovered = run_sensor(SensorRequest {
        executable: &python.interpreter,
        args: vec![
            "-I".into(),
            "-S".into(),
            "-c".into(),
            DISCOVER.into(),
            mxc_path(&home),
            mxc_path(&appdata),
        ],
        target: req.target,
        artifacts: req.artifacts,
        readonly,
        env: Vec::new(),
        limits: req.limits.clone(),
        semgrep: false,
        config: "",
    });
    let (output, code, _) = discovered.map_err(|_| {
        "Python runtime not proven: file-only MXC introspection failed; sensor not run"
    })?;
    if code != 0 {
        return Err(
            "Python runtime not proven: file-only MXC introspection failed; sensor not run".into(),
        );
    }
    let data = crate::shape::strict_json(&output)
        .map_err(|_| "Python runtime not proven: invalid MXC introspection; sensor not run")?;
    python_grants_from_discovery(&data, python.venv.as_deref())
}

fn python_grants_from_discovery(
    data: &serde_json::Value,
    venv: Option<&Path>,
) -> Result<Vec<PathBuf>, String> {
    let mut roots = Vec::new();
    for key in ["base", "prefix"] {
        let path = data[key]
            .as_str()
            .map(Path::new)
            .filter(|p| p.is_absolute() && p.is_dir())
            .ok_or("Python runtime not proven: invalid interpreter prefix; sensor not run")?;
        roots.push(std::fs::canonicalize(path).map_err(|_| "cannot resolve Python prefix")?);
    }
    let sites = data["sites"]
        .as_array()
        .ok_or("Python runtime not proven: missing package paths; sensor not run")?;
    let mut candidates: Vec<PathBuf> = sites
        .iter()
        .filter_map(|p| p.as_str().map(PathBuf::from))
        .collect();
    if let Some(venv) = venv {
        // Resolve the venv's sys.prefix from its configuration, not bin's name.
        // Only the base interpreter runs during discovery, so read the version
        // from pyvenv.cfg to identify the venv's package directory.
        let config = read_venv_config(venv)?;
        let config = String::from_utf8_lossy(&config);
        let version = config
            .lines()
            .find_map(|l| {
                let (key, value) = l.split_once('=')?;
                (key.trim() == "version").then_some(value.trim())
            })
            .ok_or("Python runtime not proven: missing venv version; sensor not run")?;
        let parts: Vec<_> = version.split('.').collect();
        if parts.len() < 2
            || !parts
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err("Python runtime not proven: invalid venv version; sensor not run".into());
        }
        roots.push(std::fs::canonicalize(venv).map_err(|_| "cannot resolve Python venv")?);
        candidates.push(venv.join(format!("lib/python{}.{}/site-packages", parts[0], parts[1])));
        candidates.push(venv.join("Lib/site-packages"));
    }
    // Do not grant a whole user installation or every package search path.
    // Only the specific site-packages containing the tool is needed.
    let mut found = false;
    for site in candidates {
        if site.is_absolute()
            && site.file_name().is_some_and(|n| n == "site-packages")
            && site.join("semgrep").is_dir()
        {
            roots.push(
                std::fs::canonicalize(site)
                    .map_err(|_| "cannot resolve Python package directory")?,
            );
            found = true;
        }
    }
    if !found {
        return Err(
            "Python runtime not proven: Semgrep site-packages unavailable; sensor not run".into(),
        );
    }
    roots.sort();
    roots.dedup();
    Ok(roots)
}

fn validate_sensor_grants(
    grants: &[PathBuf],
    homes: &[PathBuf],
    target: &Path,
    artifacts: &Path,
) -> Result<(), String> {
    let normalize = |p: &Path| {
        let p = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        if cfg!(windows) {
            PathBuf::from(mxc_path(&p).to_lowercase())
        } else {
            p
        }
    };
    let mut shared: Vec<PathBuf> = ["APPDATA", "LOCALAPPDATA", "XDG_DATA_HOME"]
        .into_iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .collect();
    let mut secrets: Vec<PathBuf> = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .into_iter()
        .collect();
    if cfg!(target_os = "macos") {
        secrets.extend([
            PathBuf::from("/Library/Keychains"),
            PathBuf::from("/System/Library/Keychains"),
        ]);
    }
    for home in homes {
        for sub in [
            ".ssh",
            ".aws",
            ".config",
            ".gnupg",
            ".azure",
            ".kube",
            ".docker",
            "Library/Keychains",
            "AppData/Roaming/Microsoft/Credentials",
            "AppData/Roaming/Microsoft/Protect",
            "AppData/Local/Microsoft/Credentials",
            "AppData/Local/Microsoft/Vault",
        ] {
            secrets.push(home.join(sub));
        }
        shared.push(home.join(".local"));
        shared.extend(
            [
                ".local/share",
                ".local/state",
                ".cache",
                "Library",
                "AppData",
                "Application Data",
                "Documents",
                "Desktop",
                "Downloads",
            ]
            .map(|sub| home.join(sub)),
        );
    }
    for grant in grants {
        let normalized = normalize(grant);
        if homes.iter().any(|h| normalize(h).starts_with(&normalized)) {
            return Err("sensor runtime grant exposes HOME or user profile; sensor not run".into());
        }
        if secrets.iter().any(|p| {
            let secret = normalize(p);
            normalized.starts_with(&secret) || secret.starts_with(&normalized)
        }) {
            return Err("sensor runtime grant exposes a secret location; sensor not run".into());
        }
        // Refuse each shared root and its ancestors. Descendants are permitted
        // only when selected explicitly by the caller (rules/database) or
        // established by Python discovery, never inferred from bin/Scripts.
        if shared.iter().any(|p| normalize(p).starts_with(&normalized)) {
            return Err(
                "sensor runtime grant exposes a shared user-data prefix; sensor not run".into(),
            );
        }
        if overlapping_root(target, std::slice::from_ref(grant)).is_some()
            || overlapping_root(artifacts, std::slice::from_ref(grant)).is_some()
        {
            return Err(
                "sensor runtime grant overlaps original target or artifacts; sensor not run".into(),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn runtime_grants_refuse_profiles_targets_artifacts_and_aliases() {
        let root = std::env::temp_dir().join(format!(
            "omgs-runtime-{}",
            &platform::random_nonce().unwrap()[..16]
        ));
        std::fs::create_dir_all(root.join("home/bin")).unwrap();
        std::fs::create_dir_all(root.join("profile")).unwrap();
        std::fs::create_dir_all(root.join("target/src")).unwrap();
        std::fs::create_dir_all(root.join("run")).unwrap();
        let _cleanup = Scratch(root.clone());
        let homes = vec![root.join("home"), root.join("profile")];
        let check = |grant: PathBuf| {
            validate_sensor_grants(&[grant], &homes, &root.join("target"), &root.join("run"))
        };
        for grant in [
            &root,
            &homes[0],
            &homes[1],
            &root.join("target"),
            &root.join("target/src"),
            &root.join("run"),
        ] {
            assert!(check(grant.clone()).is_err(), "{}", grant.display());
        }
        assert!(check(root.join("home/bin")).is_ok());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&homes[0], root.join("alias")).unwrap();
            assert!(check(root.join("alias")).is_err());
        }
    }

    #[test]
    fn python_discovery_grants_only_reported_prefixes_and_tool_site() {
        let root = std::env::temp_dir().join(format!(
            "omgs-python-{}",
            &platform::random_nonce().unwrap()[..16]
        ));
        let _cleanup = Scratch(root.clone());
        let home = root.join("home");
        let base = root.join("python");
        let venv = home.join("venv");
        let site = home.join(".local/lib/python3.13/site-packages");
        let unrelated = home.join("other/site-packages");
        for path in [&base, &venv, &site.join("semgrep"), &unrelated] {
            std::fs::create_dir_all(path).unwrap();
        }
        std::fs::write(venv.join("pyvenv.cfg"), "version = 3.13.2\n").unwrap();
        let discovery = serde_json::json!({
            "base": base, "prefix": base, "sites": [site, unrelated]
        });
        let grants = python_grants_from_discovery(&discovery, Some(&venv)).unwrap();
        assert_eq!(grants.len(), 3);
        for path in [&base, &venv, &site] {
            assert!(grants.contains(&std::fs::canonicalize(path).unwrap()));
        }
        validate_sensor_grants(
            &grants,
            std::slice::from_ref(&home),
            &root.join("target"),
            &root.join("run"),
        )
        .unwrap();
        // Public installation metadata is accepted, but aliases cannot turn
        // a private file into a readable bootstrap grant.
        let config = venv.join("pyvenv.cfg");
        let alias = root.join("config-alias");
        std::fs::rename(&config, &alias).unwrap();
        std::fs::hard_link(&alias, &config).unwrap();
        assert!(python_grants_from_discovery(&discovery, Some(&venv)).is_err());
        for path in [
            home.join(".local"),
            home.join(".local/share"),
            home.join("Library"),
            home.join("AppData"),
        ] {
            std::fs::create_dir_all(&path).unwrap();
            let reason = validate_sensor_grants(
                &[path],
                std::slice::from_ref(&home),
                &root.join("target"),
                &root.join("run"),
            )
            .unwrap_err();
            // Library and AppData also contain denylisted secret locations.
            assert!(
                reason.contains("shared user-data") || reason.contains("secret location"),
                "{reason}"
            );
        }
        for sub in [".ssh", ".aws", ".config", "Library/Keychains"] {
            let secret = home.join(sub);
            std::fs::create_dir_all(secret.join("site-packages/semgrep")).unwrap();
            for path in [&secret, &secret.join("site-packages")] {
                assert!(validate_sensor_grants(
                    std::slice::from_ref(path),
                    std::slice::from_ref(&home),
                    &root.join("target"),
                    &root.join("run")
                )
                .unwrap_err()
                .contains("secret location"));
            }
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(home.join(".ssh"), root.join("alias")).unwrap();
            assert!(validate_sensor_grants(
                &[root.join("alias")],
                &[home],
                &root.join("target"),
                &root.join("run")
            )
            .is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn bin_and_scripts_names_never_prove_a_python_prefix() {
        let root = std::env::temp_dir().join(format!(
            "omgs-python-prefix-{}",
            &platform::random_nonce().unwrap()[..16]
        ));
        let _cleanup = Scratch(root.clone());
        for dir in ["home/.local/bin", "home/Scripts"] {
            let bin = root.join(dir);
            std::fs::create_dir_all(&bin).unwrap();
            let interpreter = bin.join("python3");
            std::fs::write(&interpreter, "native fixture").unwrap();
            let scanner = bin.join("semgrep");
            std::fs::write(&scanner, format!("#!{}\n", interpreter.display())).unwrap();
            let runtime = scanner_runtime_roots(&scanner, true).unwrap();
            assert_eq!(
                runtime.roots,
                vec![scanner, std::fs::canonicalize(interpreter).unwrap()]
            );
            assert!(runtime.python.unwrap().venv.is_none());
            let prefix = bin.parent().unwrap();
            std::fs::write(prefix.join("pyvenv.cfg"), "version = 3.13.2\n").unwrap();
            let proven = scanner_runtime_roots(&bin.join("semgrep"), true).unwrap();
            assert_eq!(proven.python.unwrap().venv.as_deref(), Some(prefix));
            assert!(proven.roots.iter().all(|p| p.is_file()));
        }
        let interpreter = root.join("python3");
        std::fs::write(&interpreter, "native fixture").unwrap();
        let prefix = root.join("home/unrelated");
        std::fs::create_dir_all(prefix.join("bin")).unwrap();
        std::fs::write(prefix.join("pyvenv.cfg"), "version = 3.13.2\n").unwrap();
        let scanner = prefix.join("bin/semgrep");
        std::fs::write(&scanner, format!("#!{}\n", interpreter.display())).unwrap();
        let runtime = scanner_runtime_roots(&scanner, true).unwrap();
        assert!(runtime.python.unwrap().venv.is_none());
        assert!(!runtime.roots.contains(&prefix));
    }
}

#[cfg(test)]
mod bounded_input_tests {
    use super::*;
    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn t47_source_stages_before_assets_and_skips_keep_bounded_reasons() {
        let root = crate::platform::temp_root()
            .unwrap()
            .join(format!("omgs-input-{}", platform::random_nonce().unwrap()));
        let _cleanup = Temp(root.clone());
        let input = root.join("input");
        let dest = root.join("dest");
        std::fs::create_dir_all(input.join("public")).unwrap();
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(input.join("public/a.png"), b"image").unwrap();
        std::fs::write(input.join("public/z.ts"), b"export const decision = true;").unwrap();
        let mut budget = InputBudget {
            staged: 9999,
            ..Default::default()
        };
        copy_input(&input, Path::new(""), &dest, &mut budget).unwrap();
        assert!(dest.join("public/z.ts").is_file());
        assert!(!dest.join("public/a.png").exists());
        let skipped: serde_json::Value = serde_json::from_str(&budget.manifest[0]).unwrap();
        assert_eq!(skipped["path"], "public/a.png");
        assert_eq!(skipped["reason"], "staged file limit");
        for n in 0..200 {
            budget.skip(Path::new(&format!("public/{n}.png")), "file byte limit");
        }
        assert_eq!(budget.skipped, 201);
        assert_eq!(budget.manifest.len(), 128);
        let mut full = InputBudget {
            entries: 100000,
            ..Default::default()
        };
        inventory_input(&input, Path::new("public"), &mut full, &mut Vec::new()).unwrap();
        assert!(full.manifest[0].contains("subtree unenumerated"));
        assert!(full.manifest[0].contains("public"));
    }
    #[cfg(unix)]
    #[test]
    fn t47_links_have_path_reasons_without_following_them() {
        let root = crate::platform::temp_root().unwrap().join(format!(
            "omgs-link-input-{}",
            platform::random_nonce().unwrap()
        ));
        let _cleanup = Temp(root.clone());
        std::fs::create_dir_all(root.join("input")).unwrap();
        std::fs::create_dir_all(root.join("dest")).unwrap();
        std::os::unix::fs::symlink("/never/read", root.join("input/link")).unwrap();
        let mut budget = InputBudget::default();
        copy_input(
            &root.join("input"),
            Path::new(""),
            &root.join("dest"),
            &mut budget,
        )
        .unwrap();
        assert_eq!(budget.skipped, 1);
        assert!(budget.manifest[0].contains("link; not followed"));
        assert_eq!(std::fs::read_dir(root.join("dest")).unwrap().count(), 0);
    }
}

#[cfg(test)]
mod semgrep_input_tests {
    use super::*;
    #[test]
    fn t47_semgrep_size_skips_retain_the_source_identity() {
        let root = crate::platform::temp_root().unwrap().join(format!(
            "omgs-semgrep-bound-{}",
            platform::random_nonce().unwrap()
        ));
        let input = root.join("input");
        let dest = root.join("dest");
        std::fs::create_dir_all(&input).unwrap();
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(
            input.join("large.ts"),
            vec![b' '; crate::sensors::SEMGREP_MAX_TARGET_BYTES + 1],
        )
        .unwrap();
        let mut budget = InputBudget {
            semgrep: true,
            ..Default::default()
        };
        copy_input(&input, Path::new(""), &dest, &mut budget).unwrap();
        assert!(dest.join("large.ts").is_file());
        assert_eq!(budget.skipped, 1);
        assert_eq!(budget.semgrep_oversized, 1);
        assert!(budget.manifest[0].contains("large.ts"));
        assert!(budget.manifest[0].contains("Semgrep target byte limit"));
        std::fs::remove_dir_all(root).unwrap();
    }
}
