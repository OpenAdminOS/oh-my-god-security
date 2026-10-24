use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SensorHit {
    pub tool: String,
    pub rule: String,
    pub file: String,
    pub line: Option<u64>,
    pub vendored: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SensorsReport {
    pub tools_run: Vec<String>,
    pub tools_unavailable: Vec<String>,
    pub hits: Vec<SensorHit>,
}

fn which(name: &str) -> Option<PathBuf> {
    let out = Command::new("which").arg(name).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(PathBuf::from(text))
    }
}

/// Run deterministic sensor tools against source text. Sensors never execute
/// target code. Raw scanner output can contain matched secret values, so only
/// rule, file and line metadata is retained and the raw report is deleted.
pub fn run_sensors(target: &Path, scratch_dir: &Path) -> SensorsReport {
    let mut report = SensorsReport {
        tools_run: Vec::new(),
        tools_unavailable: Vec::new(),
        hits: Vec::new(),
    };
    match which("gitleaks") {
        Some(_) => {
            let raw = scratch_dir.join("gitleaks-raw.json");
            let status = Command::new("gitleaks")
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
    for tool in ["trufflehog", "osv-scanner"] {
        if which(tool).is_none() {
            report.tools_unavailable.push(tool.into());
        }
    }
    report
}

/// Run semgrep if present and given an offline ruleset. Stays network-free by
/// default: the config comes from `OMGS_SEMGREP_CONFIG` (a local rules path),
/// or `OMGS_SEMGREP_ALLOW_REGISTRY=1` opts into the `auto` registry explicitly.
/// Only rule, file and line metadata is kept; the raw report is deleted.
fn run_semgrep(target: &Path, scratch_dir: &Path, report: &mut SensorsReport) {
    if which("semgrep").is_none() {
        report.tools_unavailable.push("semgrep".into());
        return;
    }
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
    let status = Command::new("semgrep")
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
            vendored: crate::is_vendored_path(&rel),
            file: rel,
            line: item
                .get("start")
                .and_then(|s| s.get("line"))
                .and_then(|v| v.as_u64()),
        });
    }
}
