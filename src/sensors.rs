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
    let config = match std::env::var("OMGS_SEMGREP_CONFIG") {
        Ok(c) if !c.trim().is_empty() => c,
        _ => {
            if std::env::var("OMGS_SEMGREP_ALLOW_REGISTRY").is_ok_and(|v| v == "1") {
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
    if status.is_ok() {
        report.tools_run.push("semgrep".into());
        if let Ok(text) = std::fs::read_to_string(&raw) {
            parse_semgrep(&text, target, report);
        }
    } else {
        report.tools_unavailable.push("semgrep".into());
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
