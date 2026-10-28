use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SensorHit {
    pub tool: String,
    pub rule: String,
    pub file: String,
    pub line: Option<u64>,
    pub vendored: bool,
    pub class: crate::paths::Class,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SensorsReport {
    pub tools_run: Vec<String>,
    pub tools_unavailable: Vec<String>,
    pub hits: Vec<SensorHit>,
    /// Older runs predate explicit failure reasons. New runs always write gaps.
    #[serde(default)]
    pub gaps: Vec<String>,
}

use crate::platform::which;

/// Run deterministic sensor tools against source text. Sensors never execute
/// target code. Raw scanner output can contain matched secret values, so only
/// rule, file and line metadata is retained and the raw report is deleted.
pub fn run_sensors(target: &Path, scratch_dir: &Path) -> SensorsReport {
    let target = std::fs::canonicalize(target).unwrap_or_else(|_| target.to_path_buf());
    let target = target.as_path();
    let scratch = std::fs::canonicalize(scratch_dir).unwrap_or_else(|_| scratch_dir.to_path_buf());
    let scratch_dir = scratch.as_path();
    let mut report = SensorsReport {
        tools_run: Vec::new(),
        tools_unavailable: Vec::new(),
        hits: Vec::new(),
        gaps: Vec::new(),
    };
    match which("gitleaks") {
        Some(executable) => {
            let raw = scratch_dir.join("gitleaks-raw.json");
            let status = Command::new(executable)
                .args([
                    "detect",
                    "--source",
                    &target.to_string_lossy(),
                    "--no-git",
                    "--report-format",
                    "json",
                    "--report-path",
                    &raw.to_string_lossy(),
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            if status.is_ok() {
                report.tools_run.push("gitleaks".into());
                if let Ok(text) = std::fs::read_to_string(&raw) {
                    if let Ok(serde_json::Value::Array(items)) =
                        serde_json::from_str::<serde_json::Value>(&text)
                    {
                        for item in items {
                            let file = item
                                .get("File")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let rel = Path::new(&file)
                                .strip_prefix(target)
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or(file);
                            report.hits.push(SensorHit {
                                tool: "gitleaks".into(),
                                rule: item
                                    .get("RuleID")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown")
                                    .to_string(),
                                class: crate::paths::classify_file(target, Path::new(&rel)),
                                fingerprint: String::new(),
                                vendored: crate::is_vendored_path(&rel),
                                file: rel,
                                line: item.get("StartLine").and_then(|v| v.as_u64()),
                            });
                        }
                    }
                }
            } else {
                report.tools_unavailable.push("gitleaks".into());
            }
            let _ = std::fs::remove_file(&raw);
        }
        None => report.tools_unavailable.push("gitleaks".into()),
    }
    run_semgrep(target, scratch_dir, &mut report);
    run_offline("trufflehog", target, scratch_dir, &mut report);
    run_offline("osv-scanner", target, scratch_dir, &mut report);
    for hit in &mut report.hits {
        hit.fingerprint = hit_fingerprint(hit);
    }
    report
}

/// Run semgrep if present and given an offline ruleset. Stays network-free by
/// default: the config comes from `OMGS_SEMGREP_CONFIG` (a local rules path),
/// or `OMGS_SEMGREP_ALLOW_REGISTRY=1` opts into the `auto` registry explicitly.
/// Only rule, file and line metadata is kept; the raw report is deleted.
fn run_semgrep(target: &Path, scratch_dir: &Path, report: &mut SensorsReport) {
    let Some(executable) = which("semgrep") else {
        report.tools_unavailable.push("semgrep".into());
        return;
    };
    let registry_ok = std::env::var("OMGS_SEMGREP_ALLOW_REGISTRY").is_ok_and(|v| v == "1");
    // A nonempty OMGS_SEMGREP_CONFIG is only trusted when it names an existing
    // local file or directory. A registry shorthand ("auto", "p/default"), a
    // URL, or any nonexistent value would make semgrep fetch rules over the
    // network, so it is allowed only under the explicit registry opt-in.
    let config = match std::env::var("OMGS_SEMGREP_CONFIG") {
        Ok(c) if !c.trim().is_empty() => {
            let raw = c.trim();
            let path = Path::new(raw);
            if path.exists() {
                // Fail closed: if the path cannot be canonicalized (for example it
                // vanished after the exists() check), do not fall back to the raw
                // string, which semgrep could still read as a registry shorthand.
                match std::fs::canonicalize(path) {
                    Ok(p) => p.to_string_lossy().to_string(),
                    Err(_) => {
                        report.tools_unavailable.push("semgrep".into());
                        return;
                    }
                }
            } else if registry_ok {
                raw.to_string()
            } else {
                report.tools_unavailable.push("semgrep".into());
                return;
            }
        }
        _ => {
            if registry_ok {
                "auto".into()
            } else {
                // Present but no offline ruleset: do not fetch rules silently.
                report.tools_unavailable.push("semgrep".into());
                return;
            }
        }
    };
    let raw = scratch_dir.join("semgrep-raw.json");
    let status = Command::new(executable)
        .args([
            "scan",
            "--json",
            "--strict",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            "--config",
            &config,
            "--output",
            &raw.to_string_lossy(),
            &target.to_string_lossy(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    // semgrep exits 0 with no findings and 1 with findings; both are a real
    // scan. Any other code (bad rules, invalid YAML, internal error) or a
    // signal is a failed scan and must not look like a clean, zero-hit run.
    match status.as_ref().map(|s| s.code()) {
        Ok(Some(0)) | Ok(Some(1)) => match std::fs::read_to_string(&raw) {
            Ok(text) => {
                // A nonempty `errors` array means target files or rules failed to
                // parse: the scan is incomplete and must not read as a clean run.
                // Unparseable output is treated the same way.
                let incomplete = serde_json::from_str::<serde_json::Value>(&text)
                    .ok()
                    .and_then(|v| {
                        v.get("errors")
                            .and_then(|e| e.as_array())
                            .map(|a| !a.is_empty())
                    })
                    .unwrap_or(true);
                if incomplete {
                    report.tools_unavailable.push("semgrep".into());
                } else {
                    report.tools_run.push("semgrep".into());
                    parse_semgrep(&text, target, report);
                }
            }
            Err(_) => report.tools_unavailable.push("semgrep".into()),
        },
        _ => report.tools_unavailable.push("semgrep".into()),
    }
    let _ = std::fs::remove_file(&raw);
}

/// Extract rule/file/line metadata from a semgrep JSON report. Split out so the
/// parser is unit-testable without a semgrep install.
pub fn parse_semgrep(text: &str, target: &Path, report: &mut SensorsReport) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    let Some(results) = value.get("results").and_then(|r| r.as_array()) else {
        return;
    };
    for item in results {
        let file = item
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let rel = Path::new(&file)
            .strip_prefix(target)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or(file);
        report.hits.push(SensorHit {
            tool: "semgrep".into(),
            rule: item
                .get("check_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            class: crate::paths::classify_file(target, Path::new(&rel)),
            fingerprint: String::new(),
            vendored: crate::is_vendored_path(&rel),
            file: rel,
            line: item
                .get("start")
                .and_then(|s| s.get("line"))
                .and_then(|v| v.as_u64()),
        });
    }
}

/// Identity is derived from retained metadata, never from a secret value.
pub fn hit_fingerprint(hit: &SensorHit) -> String {
    let identity = serde_json::to_vec(&(&hit.tool, &hit.rule, &hit.file, hit.line)).unwrap();
    crate::sha256::digest(&identity)
}

fn field<'a>(value: &'a serde_json::Value, key: &str) -> Result<&'a serde_json::Value, ()> {
    value.as_object().and_then(|v| v.get(key)).ok_or(())
}

fn text(value: &serde_json::Value) -> Result<&str, ()> {
    value.as_str().filter(|s| !s.trim().is_empty()).ok_or(())
}

fn array(value: &serde_json::Value) -> Result<&Vec<serde_json::Value>, ()> {
    value.as_array().ok_or(())
}

fn metadata_hit(
    tool: &str,
    rule: &str,
    file: &str,
    line: Option<u64>,
    target: &Path,
) -> Result<SensorHit, ()> {
    #[cfg(windows)]
    let target_display = crate::platform::mxc_path(target);
    #[cfg(windows)]
    let target = Path::new(&target_display);
    #[cfg(windows)]
    let file_display = crate::platform::mxc_path(Path::new(file));
    #[cfg(windows)]
    let file = file_display.as_str();
    let path = Path::new(file);
    let relative = if path.is_absolute() {
        path.strip_prefix(target).map_err(|_| ())?
    } else {
        path
    };
    if !crate::paths::safe_relative(relative) || line == Some(0) {
        return Err(());
    }
    let class = crate::paths::classify_file(target, relative);
    let mut hit = SensorHit {
        tool: tool.into(),
        rule: crate::platform::escape_controls(rule),
        file: crate::paths::display(relative),
        line,
        vendored: class == crate::paths::Class::Vendored,
        class,
        fingerprint: String::new(),
    };
    hit.fingerprint = hit_fingerprint(&hit);
    Ok(hit)
}

/// TruffleHog emits JSON objects separated by newlines. An empty stream is a
/// valid zero-hit scan, but any non-JSON line or missing identity aborts it.
fn trufflehog_hits(output: &str, target: &Path) -> Result<Vec<SensorHit>, ()> {
    let mut hits = Vec::new();
    for line in output.lines().filter(|l| !l.trim().is_empty()) {
        let v = crate::shape::strict_json(line).map_err(|_| ())?;
        let rule = text(field(&v, "DetectorName")?)?;
        let raw = field(&v, "Raw")?.as_str().ok_or(())?;
        let fs = field(field(field(&v, "SourceMetadata")?, "Data")?, "Filesystem")?;
        let file = text(field(fs, "file")?)?;
        let line = field(fs, "line")?.as_u64().filter(|n| *n > 0).ok_or(())?;
        // Even a scanner echoing the match in metadata must not persist it.
        if !raw.is_empty() && (rule.contains(raw) || file.contains(raw)) {
            return Err(());
        }
        hits.push(metadata_hit("trufflehog", rule, file, Some(line), target)?);
    }
    Ok(hits)
}

fn osv_hits(output: &str, target: &Path) -> Result<Vec<SensorHit>, ()> {
    let v = crate::shape::strict_json(output).map_err(|_| ())?;
    let mut hits = Vec::new();
    for source in array(field(&v, "results")?)? {
        let file = text(field(field(source, "source")?, "path")?)?;
        for package in array(field(source, "packages")?)? {
            let info = field(package, "package")?;
            // Package identity is required even though it is not persisted.
            text(field(info, "name")?)?;
            text(field(info, "version")?)?;
            text(field(info, "ecosystem")?)?;
            for vulnerability in array(field(package, "vulnerabilities")?)? {
                let rule = text(field(vulnerability, "id")?)?;
                hits.push(metadata_hit("osv-scanner", rule, file, None, target)?);
            }
        }
    }
    Ok(hits)
}

fn osv_database() -> Option<std::path::PathBuf> {
    let root = std::env::var_os("OMGS_OSV_DB")
        .map(std::path::PathBuf::from)
        .or_else(|| crate::platform::data_dir().map(|d| d.join("osv-db")))?;
    let root = std::fs::canonicalize(root).ok()?;
    // Require an existing nonempty ecosystem archive. The scanner validates its
    // contents and fails closed for missing ecosystems or a corrupt archive.
    let present = std::fs::read_dir(root.join("osv-scanner")).ok()?.any(|e| {
        e.ok().is_some_and(|e| {
            e.path()
                .join("all.zip")
                .metadata()
                .is_ok_and(|m| m.is_file() && m.len() > 0)
        })
    });
    present.then_some(root)
}

fn sensor_limits() -> crate::supervise::Limits {
    crate::supervise::Limits {
        wall_ms: 120_000,
        cpu_secs: Some(120),
        file_size_bytes: Some(16 * 1024 * 1024),
        open_files: Some(256),
        memory_bytes: None,
        tasks: None,
        output_cap_bytes: 4 * 1024 * 1024,
    }
}

fn run_offline(tool: &str, target: &Path, scratch: &Path, report: &mut SensorsReport) {
    let Some(executable) = which(tool) else {
        report.tools_unavailable.push(tool.into());
        report.gaps.push(format!("{tool}: not present on PATH"));
        return;
    };
    let database = if tool == "osv-scanner" {
        match osv_database() {
            Some(db) => Some(db),
            None => {
                report
                    .gaps
                    .push("osv-scanner: osv database not present; no download attempted".into());
                return;
            }
        }
    } else {
        None
    };
    let home = scratch.join(format!("{tool}-home"));
    if std::fs::create_dir_all(&home).is_err() {
        report
            .gaps
            .push(format!("{tool}: cannot create isolated sensor home"));
        return;
    }
    let mut cmd = offline_command(&executable);
    cmd.env_clear()
        .current_dir(scratch)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("TMPDIR", &home)
        .env("TMP", &home)
        .env("TEMP", &home)
        .env("XDG_CACHE_HOME", &home)
        .env("LOCALAPPDATA", &home)
        .env("RUSTUP_AUTO_INSTALL", "0");
    #[cfg(windows)]
    for key in ["SystemRoot", "WINDIR"] {
        if let Some(value) = std::env::var_os(key) {
            cmd.env(key, value);
        }
    }
    if let Some(db) = database {
        cmd.env("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", db).args([
            "scan",
            "source",
            "--offline",
            "--offline-vulnerabilities",
            "--format=json",
            "--recursive",
            "--no-call-analysis",
            "--no-resolve",
        ]);
    } else {
        cmd.args(["filesystem", "--no-verification", "--no-update", "--json"]);
    }
    cmd.arg(target);
    #[cfg(windows)]
    report.gaps.push(format!(
        "{tool}: OS network containment unavailable; offline flags only"
    ));
    #[cfg(target_os = "macos")]
    if !Path::new("/usr/bin/sandbox-exec").is_file() {
        report.gaps.push(format!(
            "{tool}: OS network containment unavailable; offline flags only"
        ));
    }
    let result = crate::supervise::run(cmd, &sensor_limits(), None);
    // Never save raw output, stderr, parser diagnostics or survivor commands:
    // each can contain secrets. Capped or unclean capture is never parsed.
    if result.timed_out
        || result.interrupted
        || !result.capture_complete
        || !result.cleanup_complete
        || result.output_bytes_total > sensor_limits().output_cap_bytes as u64
        || !matches!(result.exit_code, Some(0))
            && !(tool == "osv-scanner" && result.exit_code == Some(1))
    {
        report.gaps.push(format!(
            "{tool}: scan failed, timed out, or output incomplete"
        ));
        return;
    }
    let hits = if result.stdout.contains('\u{fffd}') {
        Err(())
    } else if tool == "trufflehog" {
        trufflehog_hits(&result.stdout, target)
    } else {
        osv_hits(&result.stdout, target)
    };
    match hits {
        Ok(hits) => {
            report.tools_run.push(tool.into());
            report.hits.extend(hits);
        }
        Err(()) => report.gaps.push(format!(
            "{tool}: malformed JSON output or missing required metadata"
        )),
    }
}

/// Tools are trusted installations and read source as data. Deny socket
/// creation on Linux and all network operations on macOS as extra containment.
fn offline_command(executable: &Path) -> Command {
    #[cfg(target_os = "macos")]
    if Path::new("/usr/bin/sandbox-exec").is_file() {
        let mut cmd = Command::new("/usr/bin/sandbox-exec");
        cmd.args(["-p", "(version 1)(allow default)(deny network*)"]);
        cmd.arg(executable);
        return cmd;
    }
    #[allow(unused_mut)]
    let mut cmd = Command::new(executable);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: the child only installs a fixed seccomp filter using stack
        // memory and async-signal-safe syscalls before exec. Failure blocks it.
        unsafe {
            cmd.pre_exec(|| {
                let mut filter = [
                    libc::sock_filter {
                        code: 0x20,
                        jt: 0,
                        jf: 0,
                        k: 0,
                    },
                    libc::sock_filter {
                        code: 0x15,
                        jt: 0,
                        jf: 1,
                        k: libc::SYS_socket as u32,
                    },
                    libc::sock_filter {
                        code: 0x06,
                        jt: 0,
                        jf: 0,
                        k: 0x00050000 | libc::EPERM as u32,
                    },
                    libc::sock_filter {
                        code: 0x06,
                        jt: 0,
                        jf: 0,
                        k: 0x7fff0000,
                    },
                ];
                let program = libc::sock_fprog {
                    len: filter.len() as u16,
                    filter: filter.as_mut_ptr(),
                };
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || libc::prctl(libc::PR_SET_SECCOMP, 2, &program) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    cmd
}

/// Every code hit has its own candidate unit so one resolution cannot hide
/// another hit from the same tool. Excluded classes retain their group review.
pub fn seed_units(report: &SensorsReport, ledger: &mut crate::ledger::Ledger) {
    for hit in report
        .hits
        .iter()
        .filter(|h| h.class == crate::paths::Class::Code)
    {
        let id = format!("sensor:{}:{}", hit.tool, hit.fingerprint);
        if !ledger.units.iter().any(|u| u.id == id) {
            ledger.units.push(crate::ledger::Unit::new(
                &id,
                &hit.file,
                &["sensor_hit"],
                "candidate",
            ));
        }
    }
    // A scanner may see a file omitted by inventory limits or link handling.
    // It still needs an exclusion group even when inventory never seeded one.
    for (class, id) in [
        (crate::paths::Class::Test, "tests:excluded"),
        (crate::paths::Class::Docs, "docs:excluded"),
        (crate::paths::Class::Data, "data:excluded"),
        (crate::paths::Class::Vendored, "vendored:excluded"),
    ] {
        let paths: std::collections::BTreeSet<_> = report
            .hits
            .iter()
            .filter(|h| h.class == class)
            .map(|h| h.file.clone())
            .collect();
        if !paths.is_empty() && !ledger.units.iter().any(|u| u.id == id) {
            let mut unit =
                crate::ledger::Unit::new(id, "sensor hit exclusion group", &[], "planned");
            unit.extra
                .insert("excluded_count".into(), serde_json::json!(paths.len()));
            unit.extra.insert(
                "excluded_paths".into(),
                serde_json::json!(paths.into_iter().take(20).collect::<Vec<_>>()),
            );
            ledger.units.push(unit);
        }
    }
}

pub fn reconcile(report: &SensorsReport, ledger: &crate::ledger::Ledger) -> Vec<String> {
    let mut expected = crate::ledger::Ledger::default();
    seed_units(report, &mut expected);
    expected
        .units
        .iter()
        .filter_map(
            |expected| match ledger.units.iter().find(|u| u.id == expected.id) {
                Some(u)
                    if crate::ledger::is_exclusion(expected) || u.surface == expected.surface =>
                {
                    None
                }
                _ => Some(format!(
                    "sensor hit '{}' has no matching ledger unit",
                    expected.id
                )),
            },
        )
        .collect()
}

/// The summary and the standalone hit list must agree. Neither malformed
/// artifact can be silently ignored during reporting or reconciliation.
pub fn read_report(dir: &Path) -> Result<Option<SensorsReport>, String> {
    let report = match std::fs::read_to_string(dir.join("sensors.json")) {
        Ok(text) => Some(crate::shape::sensors(&text)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("read sensors.json: {e}")),
    };
    match std::fs::read_to_string(dir.join("sensor-hits.json")) {
        Ok(text) => {
            let value = crate::shape::strict_json(&text)?;
            if !value
                .as_array()
                .is_some_and(|hits| hits.iter().all(|h| h.is_object()))
            {
                return Err("sensor-hits.json must be an array of hit objects".into());
            }
            let hits: Vec<SensorHit> =
                serde_json::from_value(value).map_err(|_| "invalid sensor-hits.json")?;
            if report.as_ref().map(|r| &r.hits) != Some(&hits) {
                return Err("sensor-hits.json disagrees with sensors.json".into());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("read sensor-hits.json: {e}")),
    }
    Ok(report)
}

#[cfg(test)]
mod offline_tests {
    use super::*;
    use serde_json::json;

    fn truffle() -> serde_json::Value {
        json!({"DetectorName":"fixture","Raw":"secret-value","SourceMetadata":{"Data":{"Filesystem":{"file":"src/app.rs","line":2}}}})
    }
    #[test]
    fn trufflehog_required_fields_and_shapes_fail_closed() {
        let target = Path::new("/target");
        let valid = truffle();
        assert_eq!(
            trufflehog_hits(&valid.to_string(), target).unwrap().len(),
            1
        );
        assert!(trufflehog_hits("", target).unwrap().is_empty());
        for pointer in [
            "/DetectorName",
            "/Raw",
            "/SourceMetadata",
            "/SourceMetadata/Data",
            "/SourceMetadata/Data/Filesystem",
            "/SourceMetadata/Data/Filesystem/file",
            "/SourceMetadata/Data/Filesystem/line",
        ] {
            for replacement in [serde_json::Value::Null, json!([]), json!({})] {
                let mut value = valid.clone();
                *value.pointer_mut(pointer).unwrap() = replacement;
                assert!(
                    trufflehog_hits(&value.to_string(), target).is_err(),
                    "{pointer}"
                );
            }
            let mut value = valid.clone();
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            value
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(
                trufflehog_hits(&value.to_string(), target).is_err(),
                "{pointer}"
            );
        }
        for file in ["../outside.rs", "/outside.rs", "src/secret-value.rs", ""] {
            let mut value = valid.clone();
            value["SourceMetadata"]["Data"]["Filesystem"]["file"] = json!(file);
            assert!(trufflehog_hits(&value.to_string(), target).is_err());
        }
        let mut value = valid.clone();
        value["SourceMetadata"]["Data"]["Filesystem"]["line"] = json!(0);
        assert!(trufflehog_hits(&value.to_string(), target).is_err());
        assert!(trufflehog_hits(&format!("{valid}\n{{broken"), target).is_err());
        assert!(trufflehog_hits(r#"{"DetectorName":"x","DetectorName":"y"}"#, target).is_err());
    }
    #[test]
    fn osv_required_fields_and_shapes_fail_closed() {
        let target = Path::new("/target");
        let valid = json!({"results":[{"source":{"path":"Cargo.lock"},"packages":[{"package":{"name":"a","version":"1","ecosystem":"crates.io"},"vulnerabilities":[{"id":"OSV-1"}]}]}]});
        assert_eq!(osv_hits(&valid.to_string(), target).unwrap().len(), 1);
        assert!(osv_hits(r#"{"results":[]}"#, target).unwrap().is_empty());
        for pointer in [
            "/results",
            "/results/0/source",
            "/results/0/source/path",
            "/results/0/packages",
            "/results/0/packages/0/package",
            "/results/0/packages/0/package/name",
            "/results/0/packages/0/package/version",
            "/results/0/packages/0/package/ecosystem",
            "/results/0/packages/0/vulnerabilities",
            "/results/0/packages/0/vulnerabilities/0/id",
        ] {
            let mut value = valid.clone();
            *value.pointer_mut(pointer).unwrap() = serde_json::Value::Null;
            assert!(osv_hits(&value.to_string(), target).is_err(), "{pointer}");
            let mut value = valid.clone();
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            value
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(osv_hits(&value.to_string(), target).is_err(), "{pointer}");
        }
        assert!(osv_hits(r#"{"results":[],"results":[]}"#, target).is_err());
        assert!(osv_hits("[]", target).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn unix_metadata_preserves_literal_windows_looking_names() {
        let hit = metadata_hit(
            "trufflehog",
            "fixture",
            r"\\?\vendor/lib.rs",
            Some(1),
            Path::new("/target"),
        )
        .unwrap();
        assert_eq!(hit.class, crate::paths::Class::Code);
        assert_eq!(hit.file, "%5C%5C?%5Cvendor/lib.rs");
    }

    #[cfg(unix)]
    #[test]
    fn sensor_supervision_enforces_wall_clock_and_output_cap() {
        let mut limits = sensor_limits();
        limits.wall_ms = 50;
        limits.output_cap_bytes = 64;
        let mut cmd = offline_command(Path::new("/bin/sh"));
        cmd.args(["-c", "exec /bin/sleep 5"]).env_clear();
        let result = crate::supervise::run(cmd, &limits, None);
        assert!(result.timed_out);
        assert!(result.duration_ms < 3000);
        let mut cmd = offline_command(Path::new("/bin/sh"));
        cmd.args(["-c", "printf '%01000d' 0"]).env_clear();
        let result = crate::supervise::run(cmd, &limits, None);
        assert!(result.output_bytes_total > 64);
        assert!(result.stdout.len() <= 64);
    }
}
