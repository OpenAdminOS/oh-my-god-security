use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SensorHit {
    pub tool: String,
    pub rule: String,
    pub file: String,
    pub line: Option<u64>,
    pub vendored: bool,
    pub class: crate::paths::Class,
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<PackageIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PackageIdentity {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
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
pub fn run_sensors(target: &Path, artifacts: &Path) -> SensorsReport {
    let target = std::fs::canonicalize(target).unwrap_or_else(|_| target.to_path_buf());
    let target = target.as_path();
    let mut report = SensorsReport {
        tools_run: Vec::new(),
        tools_unavailable: Vec::new(),
        hits: Vec::new(),
        gaps: Vec::new(),
    };
    if let Err(e) = crate::scratch::recover() {
        report
            .gaps
            .push(format!("scratch recovery unavailable: {e}"));
        return report;
    }
    for tool in ["gitleaks", "semgrep", "trufflehog", "osv-scanner"] {
        run_offline(tool, target, artifacts, &mut report);
    }
    for hit in &mut report.hits {
        hit.fingerprint = hit_fingerprint(hit);
    }
    report
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
        if let Ok(hit) = metadata_hit(
            "semgrep",
            item.get("check_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown"),
            &file,
            item.get("start")
                .and_then(|s| s.get("line"))
                .and_then(|v| v.as_u64()),
            target,
        ) {
            report.hits.push(hit);
        }
    }
}

/// Identity is derived from retained metadata, never from a secret value.
pub fn hit_fingerprint(hit: &SensorHit) -> String {
    let identity = if let Some(package) = &hit.package {
        serde_json::to_vec(&(&hit.tool, &hit.rule, &hit.file, hit.line, package)).unwrap()
    } else {
        serde_json::to_vec(&(&hit.tool, &hit.rule, &hit.file, hit.line)).unwrap()
    };
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
        file: crate::platform::escape_controls(&crate::paths::display(relative)),
        line,
        vendored: class == crate::paths::Class::Vendored,
        class,
        fingerprint: String::new(),
        package: None,
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
        // Even a scanner echoing any raw representation in metadata must
        // not persist it. ExtraData can contain nested detector secret fields.
        fn echoes(value: &serde_json::Value, rule: &str, file: &str) -> bool {
            match value {
                serde_json::Value::String(s) => {
                    !s.is_empty() && (rule.contains(s) || file.contains(s))
                }
                serde_json::Value::Array(a) => a.iter().any(|v| echoes(v, rule, file)),
                serde_json::Value::Object(o) => o.values().any(|v| echoes(v, rule, file)),
                _ => false,
            }
        }
        if (!raw.is_empty() && (rule.contains(raw) || file.contains(raw)))
            || ["RawV2", "ExtraData"]
                .iter()
                .any(|key| v.get(key).is_some_and(|v| echoes(v, rule, file)))
        {
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
            let identity = PackageIdentity {
                name: crate::platform::escape_controls(text(field(info, "name")?)?),
                version: crate::platform::escape_controls(text(field(info, "version")?)?),
                ecosystem: crate::platform::escape_controls(text(field(info, "ecosystem")?)?),
            };
            for vulnerability in array(field(package, "vulnerabilities")?)? {
                let rule = text(field(vulnerability, "id")?)?;
                let mut hit = metadata_hit("osv-scanner", rule, file, None, target)?;
                hit.package = Some(identity.clone());
                hit.fingerprint = hit_fingerprint(&hit);
                hits.push(hit);
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
        memory_bytes: Some(2 << 30),
        tasks: Some(128),
        output_cap_bytes: 4 * 1024 * 1024,
    }
}

pub(crate) const SEMGREP_MAX_TARGET_BYTES: usize = 1_000_000;

fn run_offline(tool: &str, target: &Path, artifacts: &Path, report: &mut SensorsReport) {
    let Some(executable) = which(tool) else {
        report.tools_unavailable.push(tool.into());
        report.gaps.push(format!("{tool}: not present on PATH"));
        return;
    };
    let mut readonly = Vec::new();
    let mut env = Vec::new();
    let args: Vec<String> = match tool {
        "osv-scanner" => {
            let Some(db) = osv_database() else {
                report
                    .gaps
                    .push("osv-scanner: osv database not present; no download attempted".into());
                return;
            };
            env.push(format!(
                "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY={}",
                crate::platform::mxc_path(&db)
            ));
            readonly.push(db);
            [
                "scan",
                "source",
                "--offline",
                "--offline-vulnerabilities",
                "--format=json",
                "--recursive",
                "--no-call-analysis",
                "--no-resolve",
                "--no-ignore",
                "--config",
                "{config}",
                "{target}",
            ]
            .map(str::to_string)
            .to_vec()
        }
        "semgrep" => {
            let config =
                std::env::var_os("OMGS_SEMGREP_CONFIG").and_then(|p| std::fs::canonicalize(p).ok());
            let Some(config) = config else {
                report.tools_unavailable.push(tool.into());
                report.gaps.push(
                    "semgrep: local rules required; registry fetching is disabled inside MXC"
                        .into(),
                );
                return;
            };
            let mut args = [
                "scan",
                "--json",
                "--strict",
                "--quiet",
                "--metrics=off",
                "--disable-version-check",
                "--disable-nosem",
                "--no-git-ignore",
                "--max-memory=512",
                "--jobs=1",
                "--config",
            ]
            .map(str::to_string)
            .to_vec();
            args.insert(1, format!("--max-target-bytes={SEMGREP_MAX_TARGET_BYTES}"));
            args.push(crate::platform::mxc_path(&config));
            args.push("{target}".into());
            readonly.push(config);
            args
        }
        "gitleaks" => [
            "detect",
            "--source",
            "{target}",
            "--no-git",
            "--ignore-gitleaks-allow",
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--config",
            "{config}",
        ]
        .map(str::to_string)
        .to_vec(),
        _ => [
            "filesystem",
            "--no-verification",
            "--no-update",
            "--json",
            "--no-ignore-tag",
            "{target}",
        ]
        .map(str::to_string)
        .to_vec(),
    };
    let result = crate::sandbox::run_sensor(crate::sandbox::SensorRequest {
        executable: &executable,
        args,
        target,
        artifacts,
        readonly,
        env,
        limits: sensor_limits(),
        semgrep: tool == "semgrep",
        config: if tool == "gitleaks" {
            GITLEAKS_CONFIG
        } else {
            ""
        },
    });
    let (output, code, gaps) = match result {
        Ok(result) => result,
        Err(reason) => {
            report.gaps.push(format!("{tool}: {reason}"));
            return;
        }
    };
    report
        .gaps
        .extend(gaps.into_iter().map(|g| format!("{tool}: {g}")));
    if code != 0 && !(matches!(tool, "osv-scanner" | "semgrep" | "gitleaks") && code == 1) {
        report.gaps.push(format!(
            "{tool}: scan failed, timed out, or output incomplete (exit={code})"
        ));
        return;
    }
    let hits = if output.contains('\u{fffd}') {
        Err(())
    } else {
        match tool {
            "trufflehog" => trufflehog_hits(&output, target),
            "osv-scanner" => osv_hits(&output, target),
            "semgrep" | "gitleaks" => simple_hits(tool, &output, target),
            _ => unreachable!(),
        }
    };
    // Preserve only the existence of diagnostics or skipped inputs, never
    // their raw text or file contents. Tool-reported omissions are accountable.
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&output) {
        for key in [
            "errors",
            "skipped",
            "skipped_files",
            "warnings",
            "paths.skipped",
        ] {
            let value = if key == "paths.skipped" {
                v.pointer("/paths/skipped")
            } else {
                v.get(key)
            };
            if value.is_some_and(|v| !v.is_null() && v.as_array().is_none_or(|a| !a.is_empty())) {
                report.gaps.push(format!(
                    "{tool}: tool reported skipped input or diagnostics ({key})"
                ));
            }
        }
    }
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

fn simple_hits(tool: &str, output: &str, target: &Path) -> Result<Vec<SensorHit>, ()> {
    let v = crate::shape::strict_json(output).map_err(|_| ())?;
    let items = if tool == "semgrep" {
        array(field(&v, "results")?)?
    } else {
        array(&v)?
    };
    let mut hits = Vec::new();
    for item in items {
        let (rule, file, line) = if tool == "semgrep" {
            (
                text(field(item, "check_id")?)?,
                text(field(item, "path")?)?,
                field(field(item, "start")?, "line")?.as_u64().ok_or(())?,
            )
        } else {
            (
                text(field(item, "RuleID")?)?,
                text(field(item, "File")?)?,
                field(item, "StartLine")?.as_u64().ok_or(())?,
            )
        };
        // Semgrep paths in the disposable copy are returned relative to the
        // scan root by requesting a relative target from that copy's parent.
        hits.push(metadata_hit(tool, rule, file, Some(line), target)?);
    }
    Ok(hits)
}

/// Every code hit has its own candidate unit so one resolution cannot hide
/// another hit from the same tool. Excluded classes retain their group review.
pub fn seed_units(report: &SensorsReport, ledger: &mut crate::ledger::Ledger) {
    for (i, gap) in report
        .gaps
        .iter()
        .enumerate()
        .filter(|(_, gap)| gap.contains("input entries/subtrees skipped"))
    {
        let id = format!("inventory:sensor-input:{i}");
        if !ledger.units.iter().any(|u| u.id == id) {
            let mut unit = crate::ledger::Unit::new(&id, "bounded sensor input", &[], "blocked");
            unit.note = Some(gap.clone());
            unit.extra.insert(
                "inventory_gap_reason".into(),
                serde_json::json!(
                    "sensor input skipped; reconcile retained path/reason manifest in sensors.json"
                ),
            );
            ledger.units.push(unit);
        }
    }
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
    let classes: std::collections::BTreeSet<_> = report.hits.iter().map(|h| h.class).collect();
    for class in classes {
        let Some((id, _)) = crate::paths::exclusion_group(class) else {
            continue;
        };
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
    let report = match crate::run_artifact::optional_text(
        dir,
        Path::new("sensors.json"),
        crate::run_artifact::SENSORS_BYTES,
    )? {
        Some(text) => Some(crate::shape::sensors(&text)?),
        None => None,
    };
    if let Some(text) = crate::run_artifact::optional_text(
        dir,
        Path::new("sensor-hits.json"),
        crate::run_artifact::SENSOR_HITS_BYTES,
    )? {
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
    Ok(report)
}

/// Azure Functions keys need not carry the signatures recognized by default rules.
/// Keep this URL-specific to avoid treating arbitrary base64 values as credentials.
pub const GITLEAKS_CONFIG: &str = r#"[extend]
useDefault = true

[[rules]]
id = "omgs-azure-functions-url-key"
description = "Azure Functions URL code parameter"
regex = '''(?i)https://[a-z0-9.-]+\.azurewebsites\.net/[^\s"'<>]*[?&]code=([a-z0-9_+/%=-]{32,})'''
secretGroup = 1
keywords = ["azurewebsites.net"]
"#;

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
    #[test]
    fn alternate_raw_representations_cannot_echo_into_metadata() {
        for key in ["RawV2", "ExtraData"] {
            let mut value = truffle();
            value[key] = json!({"nested": ["alternate-secret"]});
            value["DetectorName"] = json!("rule-alternate-secret");
            assert!(trufflehog_hits(&value.to_string(), Path::new("/target")).is_err());
        }
    }

    #[test]
    fn legacy_osv_artifacts_require_regeneration() {
        let hit = metadata_hit(
            "osv-scanner",
            "OSV-1",
            "Cargo.lock",
            None,
            Path::new("/target"),
        )
        .unwrap();
        let report = SensorsReport {
            tools_run: vec![],
            tools_unavailable: vec![],
            hits: vec![hit],
            gaps: vec![],
        };
        assert!(
            crate::shape::sensors(&serde_json::to_string(&report).unwrap())
                .unwrap_err()
                .contains("regenerate")
        );
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
    #[test]
    fn every_parser_escapes_control_paths_and_markdown_metadata_is_literal() {
        let file = "src/new\nline\r\u{1b}[31m`<img src=x>.rs";
        let target = Path::new("/target");
        let expected = crate::platform::escape_controls(&crate::paths::display(Path::new(file)));
        let mut truffle = truffle();
        truffle["SourceMetadata"]["Data"]["Filesystem"]["file"] = json!(file);
        let osv = json!({"results":[{"source":{"path":file},"packages":[{"package":{"name":"<b>p</b>\nsecond","version":"1`","ecosystem":"test"},"vulnerabilities":[{"id":"OSV-1"}]}]}]});
        let semgrep = json!({"results":[{"check_id":"<script>\r\n# heading","path":file,"start":{"line":1}}]});
        let gitleaks = json!([{"RuleID":"fixture","File":file,"StartLine":1}]);
        let mut report = SensorsReport {
            tools_run: vec![],
            tools_unavailable: vec![],
            hits: vec![],
            gaps: vec![],
        };
        report
            .hits
            .extend(trufflehog_hits(&truffle.to_string(), target).unwrap());
        report
            .hits
            .extend(osv_hits(&osv.to_string(), target).unwrap());
        report
            .hits
            .extend(simple_hits("semgrep", &semgrep.to_string(), target).unwrap());
        report
            .hits
            .extend(simple_hits("gitleaks", &gitleaks.to_string(), target).unwrap());
        parse_semgrep(&semgrep.to_string(), target, &mut report);
        assert!(report.hits.iter().all(|h| h.file == expected));
        let markdown = crate::report::sensor_section(Some(&report), false);
        assert!(!markdown.contains(['\r', '\u{1b}']));
        // Backticks, HTML and Markdown are literal inside the longer span.
        assert!(markdown.contains("<img"));
        assert!(markdown.contains("<script>"));
        assert_eq!(
            markdown
                .lines()
                .filter(|l| l.starts_with("- `` ") && l.ends_with(" ``"))
                .count(),
            5
        );
        assert!(markdown.contains("<b>p</b>\\nsecond"));
        // Also protect report rendering of older, unescaped metadata.
        report.hits[0].file = file.into();
        let markdown = crate::report::sensor_section(Some(&report), false);
        assert!(!markdown.contains(['\r', '\u{1b}']));
        assert!(!markdown.contains("new\nline"));
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_result_transport_preserves_sensor_capture_caps() {
        use crate::supervise::{run, MacOwnership};
        use std::process::Command;
        let dir = crate::platform::temp_root().unwrap().join(format!(
            "omgs-result-output-{}",
            crate::platform::random_nonce().unwrap()
        ));
        crate::platform::create_private_dir_new(&dir).unwrap();
        let payload = dir.join("payload");
        let command = || {
            let mut cmd = Command::new("/bin/cat");
            cmd.arg(&payload).env_clear().current_dir(&dir);
            cmd
        };
        // Use the owning sensor policy, including its unchanged deadline.
        let limits = sensor_limits();
        let cap = limits.output_cap_bytes;
        for count in [1024 * 1024, cap - 1, cap, cap + 1] {
            // ASCII, JSON's worst-case control escaping, and lossy UTF-8.
            for byte in [b'A', 0, 255] {
                std::fs::write(&payload, vec![byte; count]).unwrap();
                let direct = run(command(), &limits, None);
                let owned = run(command(), &limits, Some(&MacOwnership::default()));
                assert!(
                    direct.success && owned.success,
                    "cap={cap}, count={count}, byte={byte}; direct exit={:?}, timeout={}, capture={}, cleanup={}, notes={:?}; launchd exit={:?}, timeout={}, capture={}, cleanup={}, notes={:?}",
                    direct.exit_code, direct.timed_out, direct.capture_complete, direct.cleanup_complete, direct.notes,
                    owned.exit_code, owned.timed_out, owned.capture_complete, owned.cleanup_complete, owned.notes
                );
                if cap == 4 * 1024 * 1024 && count == 1024 * 1024 && byte == b'A' {
                    assert!(serde_json::to_vec(&owned).unwrap().len() > 4 * 1024 * 1024);
                }
                assert_eq!(owned.output_bytes_total, count as u64);
                assert_eq!(owned.stdout_bytes, vec![byte; cap.min(count)]);
                let mut expected = serde_json::to_value(&direct).unwrap();
                let mut actual = serde_json::to_value(&owned).unwrap();
                for value in [&mut expected, &mut actual] {
                    let object = value.as_object_mut().unwrap();
                    object.remove("duration_ms");
                    object.remove("enforced");
                }
                assert!(
                    actual == expected,
                    "output or status changed: cap={cap}, count={count}, byte={byte}"
                );
                assert!(owned.cleanup_complete && owned.capture_complete);
                assert!(direct
                    .enforced
                    .iter()
                    .all(|control| owned.enforced.contains(control)));
                assert!(owned
                    .enforced
                    .contains(&"launchd_resource_coalition".into()));
                assert!(owned
                    .enforced
                    .contains(&"launchd_tcc_path_admission".into()));
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
