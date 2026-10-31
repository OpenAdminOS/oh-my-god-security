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
    /// Position identity, or an opaque identity authenticated with an ephemeral key.
    /// Neither raw match data nor the key is retained. Absent on legacy artifacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurrence: Option<String>,
    /// Safe provenance only. Indices refer to the ordered normalized input
    /// hit stream before deduplication, never to secret-bearing match text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duplicate_sources: Option<DuplicateSources>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DuplicateSources {
    pub first_source_index: usize,
    pub count: u64,
    pub source_indexes: Vec<usize>,
    pub omitted: u64,
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

/// Collapse identity-equal hits across the normalized scanner stream. The
/// global source-index sample is bounded even when many fingerprints repeat.
pub fn deduplicate_hits(hits: &mut Vec<SensorHit>) {
    let mut unique: Vec<SensorHit> = Vec::new();
    let mut seen = std::collections::BTreeMap::new();
    let mut retained = 0usize;
    for (source_index, mut hit) in std::mem::take(hits).into_iter().enumerate() {
        hit.fingerprint = hit_fingerprint(&hit);
        // Legacy line-only identities cannot establish occurrence equality.
        if hit.package.is_none() && hit.occurrence.is_none() {
            unique.push(hit);
            continue;
        }
        if let Some(&(position, first_index)) = seen.get(&hit.fingerprint) {
            let first: &mut SensorHit = &mut unique[position];
            let sources = first
                .duplicate_sources
                .get_or_insert_with(|| DuplicateSources {
                    first_source_index: first_index,
                    count: 0,
                    source_indexes: Vec::new(),
                    omitted: 0,
                });
            sources.count = sources.count.saturating_add(1);
            let mut indices = vec![source_index];
            if let Some(prior) = hit.duplicate_sources {
                sources.count = sources.count.saturating_add(prior.count);
                sources.omitted = sources.omitted.saturating_add(prior.omitted);
                indices.extend(prior.source_indexes);
            }
            for index in indices {
                if retained < 128 {
                    sources.source_indexes.push(index);
                    retained += 1;
                } else {
                    sources.omitted = sources.omitted.saturating_add(1);
                }
            }
        } else {
            if let Some(sources) = &mut hit.duplicate_sources {
                let available = 128usize.saturating_sub(retained);
                sources.omitted = sources
                    .omitted
                    .saturating_add(sources.source_indexes.len().saturating_sub(available) as u64);
                sources.source_indexes.truncate(available);
                retained += sources.source_indexes.len();
            }
            seen.insert(hit.fingerprint.clone(), (unique.len(), source_index));
            unique.push(hit);
        }
    }
    *hits = unique;
}

use crate::platform::which;

/// Run deterministic sensor tools against source text. Sensors never execute
/// target code. Raw scanner output can contain matched secret values, so only
/// rule, file, line and opaque occurrence identities are retained; the raw report is deleted.
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
    let Ok(mut identities) = OccurrenceCoordinator::new() else {
        report
            .gaps
            .push("sensor occurrence randomness unavailable".into());
        return report;
    };
    for tool in ["gitleaks", "semgrep", "trufflehog", "osv-scanner"] {
        run_offline(tool, target, artifacts, &mut report, &mut identities);
    }
    deduplicate_hits(&mut report.hits);
    report
}

/// Publish both sensor projections together and reopen any saved completion.
/// Scanning must finish before this function acquires family/run locks.
pub fn publish_report(dir: &Path, report: &SensorsReport) -> Result<(), String> {
    let publish = || {
        let mut writes = crate::runmeta::Transaction::default();
        writes.text(
            dir.join("sensor-hits.json"),
            serde_json::to_string_pretty(&report.hits).map_err(|e| e.to_string())?,
        );
        writes.text(
            dir.join("sensors.json"),
            serde_json::to_string_pretty(report).map_err(|e| e.to_string())?,
        );
        let mut saved = crate::runmeta::read_optional(dir)?.unwrap_or_default();
        saved.insert("run_status".into(), serde_json::json!("in_progress"));
        if crate::runmeta::read_optional(dir)?.is_some() {
            writes.metadata(dir, &saved)?;
        }
        let progress = crate::status::propose_locked(
            dir,
            &crate::status::Update {
                stage: "sensors",
                label: Some("Reconcile sensor export"),
                parent: None,
                state: "pending",
                detail: Some("New sensor artifacts require coverage reconciliation"),
                counters: &[],
                log: None,
            },
            &[],
        )?;
        let view = crate::review::View::for_sensors_locked(dir, &saved, &progress, report)?;
        writes.text(
            dir.join(crate::status::FILE),
            serde_json::to_string_pretty(&view.progress).map_err(|e| e.to_string())?,
        );
        writes.commit()
    };
    if crate::runmeta::read_optional(dir)?.is_some() {
        crate::budget::with_family_lock(dir, publish)
    } else {
        crate::runmeta::with_lock(dir, publish)
    }
}

/// Extract rule/file/line metadata from a semgrep JSON report. Split out so the
/// parser is unit-testable without a semgrep install.
pub fn parse_semgrep(
    text: &str,
    target: &Path,
    report: &mut SensorsReport,
    identities: &mut OccurrenceCoordinator,
) {
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
        if let Ok(mut hit) = metadata_hit(
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
            identities.identify(&mut hit, item);
            report.hits.push(hit);
        }
    }
}

/// Run-scoped occurrence identities. Keep this coordinator in the parent that
/// parses every scanner process and batch. Its ephemeral key is never serialized.
/// Authenticate every record, including positioned records, so conflicting input
/// order cannot choose which record receives an unkeyed position identity.
pub struct OccurrenceCoordinator {
    key: String,
}

impl OccurrenceCoordinator {
    pub fn new() -> std::io::Result<Self> {
        Ok(Self {
            key: crate::platform::random_nonce()?,
        })
    }

    fn identify(&self, hit: &mut SensorHit, item: &serde_json::Value) {
        let record = serde_json::to_vec(item).unwrap();
        // HMAC-SHA-256, RFC 2104. random_nonce supplies a 64-byte ASCII key.
        let mut inner_pad = [0x36u8; 64];
        let mut outer_pad = [0x5cu8; 64];
        for (i, byte) in self.key.bytes().enumerate() {
            inner_pad[i] ^= byte;
            outer_pad[i] ^= byte;
        }
        let mut inner = crate::sha256::Sha256::new();
        inner.update(&inner_pad);
        inner.update(b"omgs-occurrence-v2\0");
        inner.update(&record);
        let mut outer = crate::sha256::Sha256::new();
        outer.update(&outer_pad);
        outer.update(&inner.finish());
        hit.occurrence = Some(crate::sha256::hex(&outer.finish()));
        hit.fingerprint = hit_fingerprint(hit);
    }
}

/// Identity uses retained metadata and an opaque occurrence, never match text.
pub fn hit_fingerprint(hit: &SensorHit) -> String {
    let identity = if let Some(package) = &hit.package {
        serde_json::to_vec(&(&hit.tool, &hit.rule, &hit.file, hit.line, package)).unwrap()
    } else if let Some(occurrence) = &hit.occurrence {
        serde_json::to_vec(&(
            "occurrence-v1",
            &hit.tool,
            &hit.rule,
            &hit.file,
            hit.line,
            occurrence,
        ))
        .unwrap()
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
        occurrence: None,
        duplicate_sources: None,
    };
    hit.fingerprint = hit_fingerprint(&hit);
    Ok(hit)
}

/// TruffleHog emits JSON objects separated by newlines. An empty stream is a
/// valid zero-hit scan, but any non-JSON line or missing identity aborts it.
fn trufflehog_hits_with_identity(
    output: &str,
    target: &Path,
    identities: &mut OccurrenceCoordinator,
) -> Result<Vec<SensorHit>, ()> {
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
        let mut hit = metadata_hit("trufflehog", rule, file, Some(line), target)?;
        identities.identify(&mut hit, &v);
        hits.push(hit);
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

fn run_offline(
    tool: &str,
    target: &Path,
    artifacts: &Path,
    report: &mut SensorsReport,
    identities: &mut OccurrenceCoordinator,
) {
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
            "trufflehog" => trufflehog_hits_with_identity(&output, target, identities),
            "osv-scanner" => osv_hits(&output, target),
            "semgrep" | "gitleaks" => simple_hits_with_identity(tool, &output, target, identities),
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

fn simple_hits_with_identity(
    tool: &str,
    output: &str,
    target: &Path,
    identities: &mut OccurrenceCoordinator,
) -> Result<Vec<SensorHit>, ()> {
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
        let mut hit = metadata_hit(tool, rule, file, Some(line), target)?;
        identities.identify(&mut hit, item);
        hits.push(hit);
    }
    Ok(hits)
}

#[cfg(test)]
fn simple_hits(tool: &str, output: &str, target: &Path) -> Result<Vec<SensorHit>, ()> {
    simple_hits_with_identity(
        tool,
        output,
        target,
        &mut OccurrenceCoordinator::new().map_err(|_| ())?,
    )
}

#[cfg(test)]
fn trufflehog_hits(output: &str, target: &Path) -> Result<Vec<SensorHit>, ()> {
    trufflehog_hits_with_identity(
        output,
        target,
        &mut OccurrenceCoordinator::new().map_err(|_| ())?,
    )
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
        Some(text) => Some(crate::shape::sensors(&text).map_err(|e| format!("sensors.json: {e}"))?),
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

    const OCCURRENCE_FIXTURE_ENV: &str = "OMGS_TEST_OCCURRENCE_FIXTURE";

    #[test]
    fn same_line_occurrences_remain_distinct_and_exact_repeats_merge() {
        let target = Path::new("/target");
        for tool in ["gitleaks", "semgrep", "trufflehog"] {
            let first = match tool {
                "gitleaks" => json!({"RuleID":"fixture", "File":"src/app.rs", "StartLine":2,
                    "StartColumn":1, "EndColumn":8, "Secret":"first-synthetic-match"}),
                "semgrep" => json!({"check_id":"fixture", "path":"src/app.rs",
                    "start":{"line":2,"col":1}, "end":{"line":2,"col":8},
                    "extra":{"lines":"first-synthetic-match"}}),
                _ => truffle(),
            };
            let mut second = first.clone();
            let mut third = first.clone();
            match tool {
                "gitleaks" => {
                    second["Secret"] = json!("second-synthetic-match");
                    third["StartColumn"] = json!(20);
                }
                "semgrep" => {
                    second["extra"]["lines"] = json!("second-synthetic-match");
                    third["start"]["col"] = json!(20);
                }
                _ => {
                    second["Raw"] = json!("second-synthetic-match");
                    third["SourceMetadata"]["Data"]["Filesystem"]["column"] = json!(20);
                }
            }
            let items = vec![first.clone(), second, third, first];
            let mut hits = if tool == "trufflehog" {
                trufflehog_hits(
                    &items
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("\n"),
                    target,
                )
                .unwrap()
            } else {
                let value = if tool == "semgrep" {
                    json!({"results":items})
                } else {
                    json!(items)
                };
                simple_hits(tool, &value.to_string(), target).unwrap()
            };
            deduplicate_hits(&mut hits);
            assert_eq!(hits.len(), 3, "{tool}");
            assert_eq!(hits[0].duplicate_sources.as_ref().unwrap().count, 1);
            let serialized = serde_json::to_string(&hits).unwrap();
            for secret in [
                "first-synthetic-match",
                "second-synthetic-match",
                "secret-value",
            ] {
                assert!(!serialized.contains(secret));
            }
            let mut ledger = crate::ledger::Ledger::default();
            seed_units(
                &SensorsReport {
                    tools_run: vec![],
                    tools_unavailable: vec![],
                    hits,
                    gaps: vec![],
                },
                &mut ledger,
            );
            assert_eq!(ledger.units.len(), 3);
        }
    }

    #[test]
    fn occurrence_process_fixture() {
        if let Ok(record) = std::env::var(OCCURRENCE_FIXTURE_ENV) {
            // Serial libtest output can leave its test label on the current line.
            crate::out::line("");
            crate::out::line(&format!("OCCURRENCE_RECORD:{record}"));
        }
    }

    #[test]
    fn identities_span_parser_calls_and_processes_without_order_dependence() {
        let dir = crate::platform::temp_root().unwrap().join(format!(
            "omgs-occurrence-{}",
            crate::platform::random_nonce().unwrap()
        ));
        crate::platform::create_private_tree(&dir).unwrap();
        let home = dir.join("home");
        crate::platform::private_dir(&home).unwrap();
        let target = &dir;
        let mut identities = OccurrenceCoordinator::new().unwrap();
        for tool in ["semgrep", "gitleaks", "trufflehog"] {
            for positioned in [true, false] {
                let first = match tool {
                    "semgrep" => {
                        json!({"check_id":"fixture", "path":"src/app.rs", "start":{"line":1}, "extra":{"lines":"first-private-match"}})
                    }
                    "gitleaks" => {
                        json!({"RuleID":"fixture", "File":"src/app.rs", "StartLine":1, "Secret":"first-private-match"})
                    }
                    _ => truffle(),
                };
                let mut first = first;
                if positioned {
                    match tool {
                        "semgrep" => first["start"]["col"] = json!(1),
                        "gitleaks" => first["StartColumn"] = json!(1),
                        _ => first["SourceMetadata"]["Data"]["Filesystem"]["column"] = json!(1),
                    }
                }
                let mut second = first.clone();
                match tool {
                    "semgrep" => second["extra"]["lines"] = json!("second-private-match"),
                    "gitleaks" => second["Secret"] = json!("second-private-match"),
                    _ => second["Raw"] = json!("second-private-match"),
                }
                // A fresh coordinator with the same run key must assign the
                // same identities even when its first conflicting record changes.
                let reverse = OccurrenceCoordinator {
                    key: identities.key.clone(),
                };
                let mut forward_hits = Vec::new();
                let mut reverse_hits = Vec::new();
                for item in [&first, &second] {
                    let mut hit =
                        metadata_hit(tool, "fixture", "src/app.rs", Some(1), target).unwrap();
                    identities.identify(&mut hit, item);
                    forward_hits.push(hit.occurrence);
                }
                for item in [&second, &first] {
                    let mut hit =
                        metadata_hit(tool, "fixture", "src/app.rs", Some(1), target).unwrap();
                    reverse.identify(&mut hit, item);
                    reverse_hits.push(hit.occurrence);
                }
                reverse_hits.reverse();
                assert_eq!(forward_hits, reverse_hits);
                let mut hits = Vec::new();
                for item in [&first, &second, &second, &first] {
                    // Independent scanner processes emit their batches; only the
                    // parent owns the run key and assigns occurrence identities.
                    let output = std::process::Command::new(std::env::current_exe().unwrap())
                        .args([
                            "--exact",
                            "sensors::offline_tests::occurrence_process_fixture",
                            "--nocapture",
                        ])
                        .env("OMGS_HOME", &home)
                        .env("RUSTUP_AUTO_INSTALL", "0")
                        .env("RUST_TEST_THREADS", "1")
                        .env(OCCURRENCE_FIXTURE_ENV, item.to_string())
                        .output()
                        .unwrap();
                    assert!(output.status.success());
                    let stdout = String::from_utf8(output.stdout).unwrap();
                    let record = stdout
                        .lines()
                        .find_map(|line| line.strip_prefix("OCCURRENCE_RECORD:"))
                        .unwrap();
                    if tool == "trufflehog" {
                        hits.extend(
                            trufflehog_hits_with_identity(record, target, &mut identities).unwrap(),
                        );
                    } else {
                        let item: serde_json::Value = serde_json::from_str(record).unwrap();
                        let batch = if tool == "semgrep" {
                            json!({"results":[item]})
                        } else {
                            json!([item])
                        };
                        hits.extend(
                            simple_hits_with_identity(
                                tool,
                                &batch.to_string(),
                                target,
                                &mut identities,
                            )
                            .unwrap(),
                        );
                        if tool == "semgrep" {
                            let mut report = SensorsReport {
                                tools_run: vec![],
                                tools_unavailable: vec![],
                                hits: vec![],
                                gaps: vec![],
                            };
                            parse_semgrep(&batch.to_string(), target, &mut report, &mut identities);
                            assert_eq!(
                                report.hits.last().unwrap().occurrence,
                                hits.last().unwrap().occurrence
                            );
                        }
                    }
                }
                assert_eq!(hits[0].occurrence, hits[3].occurrence);
                assert_eq!(hits[1].occurrence, hits[2].occurrence);
                assert_ne!(hits[0].occurrence, hits[1].occurrence);
                deduplicate_hits(&mut hits);
                assert_eq!(hits.len(), 2);
                assert!(hits
                    .iter()
                    .all(|hit| hit.duplicate_sources.as_ref().unwrap().count == 1));
                let serialized = serde_json::to_string(&hits).unwrap();
                assert!(!serialized.contains("private-match"));
                assert!(!serialized.contains(&identities.key));
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn positioned_identity_is_keyed_even_for_short_secret_guesses() {
        for tool in ["gitleaks", "semgrep", "trufflehog"] {
            let mut expected = None;
            for guess in ["0000", "0427", "9999"] {
                let item = match tool {
                    "gitleaks" => json!({"StartColumn":1,"EndColumn":8,"Secret":guess}),
                    "semgrep" => json!({"start":{"col":1},"end":{"col":8},"extra":{"lines":guess}}),
                    _ => json!({"SourceMetadata":{"Data":{"Filesystem":{"column":1}}},"Raw":guess}),
                };
                let mut hit =
                    metadata_hit(tool, "fixture", "src/app.rs", Some(2), Path::new("/target"))
                        .unwrap();
                OccurrenceCoordinator::new()
                    .unwrap()
                    .identify(&mut hit, &item);
                if let Some(expected) = &expected {
                    assert_ne!(&hit, expected);
                } else {
                    expected = Some(hit);
                }
            }
        }
    }

    #[test]
    fn legacy_line_only_identity_requires_regeneration_without_merging() {
        let hit = metadata_hit(
            "gitleaks",
            "fixture",
            "src/app.rs",
            Some(1),
            Path::new("/target"),
        )
        .unwrap();
        let fingerprint = hit.fingerprint.clone();
        let mut hits = vec![hit.clone(), hit];
        deduplicate_hits(&mut hits);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].fingerprint, fingerprint);
        let report = SensorsReport {
            tools_run: vec![],
            tools_unavailable: vec![],
            hits,
            gaps: vec![],
        };
        assert!(
            crate::shape::sensors(&serde_json::to_string(&report).unwrap())
                .unwrap_err()
                .contains("regenerate")
        );
    }

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
        parse_semgrep(
            &semgrep.to_string(),
            target,
            &mut report,
            &mut OccurrenceCoordinator::new().unwrap(),
        );
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
