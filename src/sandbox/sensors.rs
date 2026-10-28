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

// Drop is a fallback for setup failures and unwinding. Normal exits explicitly
// remove the tree after supervision and report any failure without raw content.
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
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
    let located =
        locate_executor().map_err(|_| "pinned MXC unavailable; sensor not run".to_string())?;
    let os = std::env::consts::OS;
    let (list_parents, _, _, mut gaps) = if os == "windows" {
        preflight::windows_policy(windows_probe(&located.path))?
    } else {
        (false, false, Vec::new(), Vec::new())
    };
    let executable = std::fs::canonicalize(req.executable).map_err(|_| "cannot resolve scanner")?;
    let mut readonly = scanner_runtime_roots(&executable, req.semgrep)?;
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
    let temp = std::fs::canonicalize(std::env::temp_dir())
        .map_err(|_| "cannot resolve private sensor temp parent")?;
    let root = temp.join(format!("omgs-sensor-{}", &nonce[..16]));
    if overlapping_root(req.target, std::slice::from_ref(&root)).is_some() {
        return Err("private sensor scratch overlaps target; sensor not run".into());
    }
    if overlapping_root(req.artifacts, std::slice::from_ref(&root)).is_some() {
        return Err("private sensor scratch overlaps artifacts; sensor not run".into());
    }
    if overlapping_root(&root, &readonly).is_some() {
        return Err("private sensor scratch overlaps a readable grant; sensor not run".into());
    }
    platform::create_private_dir_new(&root).map_err(|_| "cannot create private sensor scratch")?;
    let scratch = Scratch(root);
    req.readonly = readonly;
    let result = run_in_scratch(req, &located, &scratch.0, list_parents, &nonce, &mut gaps);
    let removed = std::fs::remove_dir_all(&scratch.0).is_ok();
    if !removed {
        return Err("private sensor scratch cleanup failed; raw scanner data may remain in the OS temporary directory".into());
    }
    result.map(|(output, code)| (output, code, gaps))
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
    let mut budget = InputBudget::default();
    copy_input(req.target, Path::new(""), &target, &mut budget)?;
    if budget.skipped > 0 {
        gaps.push(format!("{} input entries skipped: links, special files, unreadable files or input bounds (16 MiB/file, 64 MiB total, 10000 entries, 64 directory levels)", budget.skipped));
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
    let markers = if os == "macos" {
        let markers = supervise::SweepMarkers {
            allowed: root.join("allowed"),
            denied: root.join("denied"),
        };
        std::fs::write(&markers.allowed, "omgs")
            .and_then(|_| std::fs::write(&markers.denied, "omgs"))
            .map_err(|_| "cannot create sensor sweep markers")?;
        Some(markers)
    } else {
        None
    };
    let input = ConfigInput {
        contract: None,
        os,
        containment: located.executor.containment,
        command: &wrapped,
        timeout_ms: req.limits.wall_ms,
        workspace: &work,
        scratch: &work,
        allowed_marker: markers.as_ref().map(|m| m.allowed.as_path()),
        readonly,
        denied: markers.iter().map(|m| m.denied.clone()).collect(),
        rust: None,
        list_parents,
    };
    let mut config = mxc_config(&input);
    // Only private scratch is writable. In particular, the target and rules
    // remain read-only even when the scanner tries to create sidecar files.
    config["filesystem"]["readwritePaths"] = serde_json::json!([mxc_path(&work)]);
    let env = config["process"]["env"].as_array_mut().unwrap();
    env.extend(req.env.into_iter().map(serde_json::Value::String));
    let path = root.join("mxc-config.json");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap())
        .map_err(|_| "cannot write sensor config")?;
    #[cfg(windows)]
    let acl =
        preflight::WindowsAclSnapshot::capture([&work].into_iter().chain(input.readonly.iter()))?;
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
    #[allow(unused_mut)]
    let mut run = supervise::run_marked(cmd, &limits, markers.as_ref(), nonce);
    #[cfg(windows)]
    acl.verify(&mut run);
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
    skipped: usize,
    semgrep_oversized: usize,
}
fn copy_input(
    root: &Path,
    rel: &Path,
    dest: &Path,
    budget: &mut InputBudget,
) -> Result<(), String> {
    supervise::check_interrupted().map_err(|_| "sensor input copy interrupted")?;
    if rel.components().count() > 64 {
        budget.skipped += 1;
        return Ok(());
    }
    for entry in std::fs::read_dir(root.join(rel)).map_err(|_| "cannot enumerate sensor input")? {
        budget.entries += 1;
        if budget.entries > 10000 {
            budget.skipped += 1;
            break;
        }
        let Ok(entry) = entry else {
            budget.skipped += 1;
            continue;
        };
        let path = rel.join(entry.file_name());
        let meta = match std::fs::symlink_metadata(entry.path()) {
            Ok(meta) => meta,
            Err(_) => {
                budget.skipped += 1;
                continue;
            }
        };
        if platform::is_link(&meta) {
            budget.skipped += 1;
            continue;
        }
        if meta.is_dir() {
            std::fs::create_dir(dest.join(&path))
                .map_err(|_| "cannot create sensor input directory")?;
            copy_input(root, &path, dest, budget)?;
        } else if meta.is_file() && meta.len() <= 16 << 20 && budget.bytes + meta.len() <= 64 << 20
        {
            // The no-follow bounded read refuses link swaps and growing files.
            match platform::read_bounded_in(root, &path, (16 << 20).min((64 << 20) - budget.bytes))
            {
                Ok(bytes) => {
                    if bytes.len() > crate::sensors::SEMGREP_MAX_TARGET_BYTES {
                        budget.semgrep_oversized += 1;
                    }
                    budget.bytes += bytes.len() as u64;
                    std::fs::write(dest.join(&path), bytes)
                        .map_err(|_| "cannot copy sensor input")?;
                }
                Err(_) => budget.skipped += 1,
            }
        } else {
            budget.skipped += 1;
        }
    }
    Ok(())
}

// Native tools need only their executable, not the directory containing it.
// Python entry points additionally need their package prefix and interpreter.
fn scanner_runtime_roots(executable: &Path, semgrep: bool) -> Result<Vec<PathBuf>, String> {
    use std::io::Read;
    let mut roots = vec![executable.to_path_buf()];
    let mut header = Vec::new();
    std::fs::File::open(executable)
        .and_then(|f| f.take(1024).read_to_end(&mut header))
        .map_err(|_| "cannot read installed scanner header")?;
    if header.starts_with(b"#!") {
        let header = String::from_utf8_lossy(&header);
        let interpreter = header[2..]
            .split_whitespace()
            .next()
            .ok_or("missing scanner interpreter")?;
        let path =
            std::fs::canonicalize(interpreter).map_err(|_| "scanner interpreter unavailable")?;
        roots.push(path.clone());
        if semgrep {
            add_package_prefix(executable, &mut roots);
            add_package_prefix(&path, &mut roots);
        }
    }
    if semgrep {
        // Windows Python console launchers have no shebang. Virtual environment
        // configuration identifies both the package prefix and base runtime.
        if let Some(prefix) = executable.parent().and_then(Path::parent) {
            if prefix.join("pyvenv.cfg").is_file() {
                roots.push(prefix.to_path_buf());
                let config = platform::read_bounded(&prefix.join("pyvenv.cfg"), 16384)
                    .map_err(|_| "cannot read scanner runtime configuration")?;
                for line in String::from_utf8_lossy(&config).lines() {
                    if let Some(("home", home)) =
                        line.split_once('=').map(|(k, v)| (k.trim(), v.trim()))
                    {
                        let home = Path::new(home);
                        if !home.is_absolute() || !home.is_dir() {
                            return Err("scanner base runtime unavailable".into());
                        }
                        if home.file_name().is_some_and(|n| n == "bin") {
                            add_package_prefix(&home.join("python3"), &mut roots);
                        } else {
                            roots.push(home.to_path_buf());
                        }
                    }
                }
            }
        }
    }
    roots.sort();
    roots.dedup();
    roots
        .into_iter()
        .map(|p| {
            std::fs::canonicalize(p).map_err(|_| "cannot resolve scanner runtime grant".into())
        })
        .collect()
}

fn add_package_prefix(executable: &Path, roots: &mut Vec<PathBuf>) {
    let Some(bin) = executable.parent() else {
        return;
    };
    if bin
        .file_name()
        .is_some_and(|n| n == "bin" || n == "Scripts")
    {
        if let Some(prefix) = bin.parent() {
            // MXC already supplies system binaries and libraries. As with
            // prove's toolchain roots, never infer all of /usr or /opt.
            if !["/", "/usr", "/usr/local", "/opt", "/opt/homebrew"]
                .iter()
                .any(|p| prefix == Path::new(p))
            {
                roots.push(prefix.to_path_buf());
            } else {
                for name in ["lib", "lib64"] {
                    let lib = prefix.join(name);
                    if lib.is_dir() {
                        roots.push(lib);
                    }
                }
            }
        }
    }
}

fn validate_sensor_grants(
    grants: &[PathBuf],
    homes: &[PathBuf],
    target: &Path,
    artifacts: &Path,
) -> Result<(), String> {
    for grant in grants {
        // A child of HOME can be a legitimate installation. An ancestor grants
        // the whole profile. Target and artifact overlap is unsafe either way.
        let normalize = |p: &Path| {
            let p = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
            if cfg!(windows) {
                PathBuf::from(mxc_path(&p).to_lowercase())
            } else {
                p
            }
        };
        if homes
            .iter()
            .any(|h| normalize(h).starts_with(normalize(grant)))
        {
            return Err("sensor runtime grant exposes HOME or user profile; sensor not run".into());
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

    #[cfg(unix)]
    #[test]
    fn python_runtime_uses_install_prefix_and_refuses_home_prefix() {
        let root = std::env::temp_dir().join(format!(
            "omgs-python-{}",
            &platform::random_nonce().unwrap()[..16]
        ));
        let _cleanup = Scratch(root.clone());
        let home = root.join("home");
        for prefix in [&home, &home.join("venv")] {
            let bin = prefix.join("bin");
            std::fs::create_dir_all(&bin).unwrap();
            let interpreter = bin.join("python3");
            std::fs::write(&interpreter, "native fixture").unwrap();
            let scanner = bin.join("semgrep");
            std::fs::write(&scanner, format!("#!{}\n", interpreter.display())).unwrap();
            let grants = scanner_runtime_roots(&scanner, true).unwrap();
            assert!(grants.contains(&std::fs::canonicalize(prefix).unwrap()));
            assert!(!grants.contains(&root));
            let result = validate_sensor_grants(
                &grants,
                std::slice::from_ref(&home),
                &root.join("target"),
                &root.join("run"),
            );
            assert_eq!(result.is_err(), prefix == &home);
        }
    }
}
