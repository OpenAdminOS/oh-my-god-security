//! Offline scoring of frozen, independently adjudicated benchmark artifacts.
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, String>;

fn object<'a>(v: &'a Value, fields: &str) -> Result<&'a serde_json::Map<String, Value>> {
    let o = v.as_object().ok_or("expected JSON object")?;
    for field in fields.split_whitespace() {
        if !o.contains_key(field) {
            return Err(format!("required field {field} is missing"));
        }
    }
    for field in o.keys() {
        if !fields.split_whitespace().any(|f| f == field) {
            return Err(format!("unknown field {field}"));
        }
    }
    Ok(o)
}
fn list(v: &Value) -> Result<&Vec<Value>> {
    v.as_array().ok_or_else(|| "expected JSON array".into())
}
fn text(v: &Value) -> Result<&str> {
    v.as_str()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| "expected nonempty string".into())
}
fn strings(v: &Value) -> Result<()> {
    let mut seen = BTreeSet::new();
    for item in list(v)? {
        if !seen.insert(text(item)?) {
            return Err("duplicate list entry".into());
        }
    }
    Ok(())
}
fn texts(v: &Value, fields: &str) -> Result<()> {
    for f in fields.split_whitespace() {
        text(&v[f]).map_err(|e| format!("{f}: {e}"))?;
    }
    Ok(())
}
fn choice(v: &Value, choices: &str) -> Result<()> {
    let s = text(v)?;
    if choices.split_whitespace().any(|c| s == c) {
        Ok(())
    } else {
        Err(format!("invalid enum {s}"))
    }
}
fn boolean(v: &Value) -> Result<()> {
    v.as_bool()
        .map(|_| ())
        .ok_or_else(|| "expected boolean".into())
}
fn number(v: &Value) -> Result<()> {
    v.as_f64()
        .filter(|n| n.is_finite() && *n >= 0.0)
        .map(|_| ())
        .ok_or_else(|| "expected finite nonnegative number".into())
}
fn integer(v: &Value) -> Result<()> {
    v.as_u64()
        .map(|_| ())
        .ok_or_else(|| "expected unsigned integer".into())
}
fn hex(v: &Value, len: usize) -> Result<()> {
    if text(v)?.len() == len && text(v)?.bytes().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!("expected {len} hex digits"))
    }
}
fn date(v: &Value, timestamp: bool) -> Result<()> {
    let s = text(v)?;
    let b = s.as_bytes();
    if b.len() != if timestamp { 20 } else { 10 } || b[4] != b'-' || b[7] != b'-' {
        return Err("expected ISO UTC date".into());
    }
    if !s.is_ascii() {
        return Err("date must be ASCII".into());
    }
    let n = |a, b| {
        s.get(a..b)
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or("invalid date")
    };
    let (y, m, d) = (n(0, 4)?, n(5, 7)?, n(8, 10)?);
    let days = match m {
        4 | 6 | 9 | 11 => 30,
        2 if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) => 29,
        2 => 28,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => 0,
    };
    if y == 0 || d == 0 || d > days {
        return Err("invalid calendar date".into());
    }
    if timestamp
        && (b[10] != b'T'
            || b[13] != b':'
            || b[16] != b':'
            || b[19] != b'Z'
            || n(11, 13)? > 23
            || n(14, 16)? > 59
            || n(17, 19)? > 59)
    {
        return Err("expected ISO UTC timestamp".into());
    }
    Ok(())
}
fn url(v: &Value) -> Result<()> {
    if text(v)?.starts_with("https://") && !text(v)?.chars().any(char::is_whitespace) {
        Ok(())
    } else {
        Err("expected HTTPS URL".into())
    }
}
fn identity(v: &Value) -> Result<String> {
    texts(v, "attack_class entry_point sink boundary")?;
    Ok(crate::fingerprint(
        text(&v["attack_class"])?,
        text(&v["entry_point"])?,
        text(&v["sink"])?,
        text(&v["boundary"])?,
    ))
}
fn review(v: &Value) -> Result<()> {
    object(v, "reviewer reviewed_at evidence_path")?;
    texts(v, "reviewer evidence_path")?;
    date(&v["reviewed_at"], true)
}
fn refs(v: &Value, snapshots: &BTreeMap<String, String>, roles: &str) -> Result<()> {
    strings(v)?;
    for id in list(v)? {
        let role = snapshots
            .get(text(id)?)
            .ok_or("unknown snapshot reference")?;
        if !roles.split_whitespace().any(|r| r == role) {
            return Err("snapshot role mismatch".into());
        }
    }
    Ok(())
}

fn repository_family(url: &str) -> String {
    let url = url.trim_end_matches('/');
    let url = if url.to_ascii_lowercase().ends_with(".git") {
        &url[..url.len() - 4]
    } else {
        url
    };
    let rest = url.strip_prefix("https://").unwrap_or(url);
    if rest
        .split('/')
        .next()
        .is_some_and(|host| host.eq_ignore_ascii_case("github.com"))
    {
        url.to_ascii_lowercase()
    } else {
        url.to_owned()
    }
}

/// Required fields are checked before any value is used. Null is explicit only.
pub fn manifest(v: &Value) -> Result<()> {
    object(v, "format_version examples_only cases")?;
    if v["format_version"] != 1 {
        return Err("unsupported manifest version".into());
    }
    boolean(&v["examples_only"])?;
    if v["examples_only"] == true {
        return Err("examples_only manifests cannot be scored".into());
    }
    let mut ids = BTreeSet::new();
    let mut splits = BTreeMap::new();
    let mut repositories = BTreeMap::new();
    for c in list(&v["cases"])? {
        validate_case(c).map_err(|e| format!("case {}: {e}", c["id"]))?;
        if !ids.insert(text(&c["id"])?) {
            return Err("duplicate case id".into());
        }
        let split = (&c["split"]["partition"], &c["split"]["rotation_id"]);
        if let Some(url) = c["source"]["repository_url"].as_str() {
            if let Some(previous) = repositories.insert(repository_family(url), &c["split"]) {
                if previous != &c["split"] {
                    return Err("repository family has inconsistent cohort/split".into());
                }
            }
        }

        if let Some(previous) = splits.insert(text(&c["split"]["cohort_id"])?, split) {
            if previous != split {
                return Err("family has inconsistent split".into());
            }
        }
    }
    if ids.is_empty() {
        return Err("manifest has no cases".into());
    }
    Ok(())
}
fn validate_case(c: &Value) -> Result<()> {
    object(c, "id example_only kind description source stack provenance cutoff split snapshots fixtures expected_findings known_clean_units budget")?;
    texts(c, "id description")?;
    boolean(&c["example_only"])?;
    if c["example_only"] == true {
        return Err("example_only cases cannot be scored".into());
    }
    choice(&c["kind"], "real_fix_pair generated_app clean_negative")?;
    let source = &c["source"];
    object(source, "repository_url authorization_basis license")?;
    if !source["repository_url"].is_null() {
        url(&source["repository_url"])?;
    }
    texts(source, "authorization_basis")?;
    object(&source["license"], "spdx_id redistribution_status note")?;
    texts(&source["license"], "spdx_id redistribution_status note")?;
    object(&c["stack"], "language nextjs_version database")?;
    texts(&c["stack"], "language nextjs_version database")?;
    let p = &c["provenance"];
    object(p, "advisory_id advisory_url first_public_disclosure_at first_public_fix_at timeline_evidence_urls generator human_confirmation")?;
    review(&p["human_confirmation"])?;
    if c["kind"] == "real_fix_pair" {
        text(&p["advisory_id"])?;
        url(&p["advisory_url"])?;
        date(&p["first_public_disclosure_at"], true)?;
        date(&p["first_public_fix_at"], true)?;
        strings(&p["timeline_evidence_urls"])?;
        if list(&p["timeline_evidence_urls"])?.is_empty() {
            return Err("timeline evidence is empty".into());
        }
        for u in list(&p["timeline_evidence_urls"])? {
            url(u)?;
        }
    } else {
        for f in [
            "advisory_id",
            "advisory_url",
            "first_public_disclosure_at",
            "first_public_fix_at",
            "timeline_evidence_urls",
        ] {
            if !p[f].is_null() {
                return Err(format!("{f} must be null for non-real cases"));
            }
        }
    }
    if c["kind"] == "generated_app" {
        object(&p["generator"], "agent model prompt_sha256 seed")?;
        texts(&p["generator"], "agent model")?;
        hex(&p["generator"]["prompt_sha256"], 64)?;
        if !p["generator"]["seed"].is_null() {
            integer(&p["generator"]["seed"])?;
        }
    } else if !p["generator"].is_null() {
        return Err("generator must be null".into());
    }
    let cut = &c["cutoff"];
    object(cut, "latest_model_knowledge_cutoff eligibility reason")?;
    text(&cut["reason"])?;
    choice(
        &cut["eligibility"],
        "eligible ineligible unknown not_applicable",
    )?;
    if !cut["latest_model_knowledge_cutoff"].is_null() {
        date(&cut["latest_model_knowledge_cutoff"], false)?;
    }
    if c["kind"] == "real_fix_pair" {
        if cut["eligibility"] == "not_applicable" {
            return Err("real pairs need a cutoff cohort".into());
        }
        if cut["eligibility"] == "eligible" {
            date(&cut["latest_model_knowledge_cutoff"], false)?;
            for f in ["first_public_disclosure_at", "first_public_fix_at"] {
                if text(&p[f])?[..10] <= *text(&cut["latest_model_knowledge_cutoff"])? {
                    return Err("eligible timeline must be after cutoff".into());
                }
            }
        }
    } else if cut["eligibility"] != "not_applicable"
        || !cut["latest_model_knowledge_cutoff"].is_null()
    {
        return Err("non-real cases require not_applicable cutoff".into());
    }
    object(&c["split"], "cohort_id partition rotation_id")?;
    texts(&c["split"], "cohort_id rotation_id")?;
    choice(&c["split"]["partition"], "development held_out")?;
    let mut snapshots = BTreeMap::new();
    for s in list(&c["snapshots"])? {
        object(s, "id role source_ref fixture_path toolchain_manifest_path")?;
        texts(s, "id fixture_path toolchain_manifest_path")?;
        hex(&s["source_ref"], 40)?;
        choice(&s["role"], "vulnerable fixed clean")?;
        if snapshots
            .insert(text(&s["id"])?.to_owned(), text(&s["role"])?.to_owned())
            .is_some()
        {
            return Err("duplicate snapshot".into());
        }
    }
    if snapshots.is_empty() {
        return Err("no snapshots".into());
    }
    if c["kind"] == "real_fix_pair"
        && !(snapshots.values().any(|r| r == "fixed")
            && snapshots.values().any(|r| r == "vulnerable"))
    {
        return Err("real pair needs vulnerable and fixed snapshots".into());
    }
    let f = &c["fixtures"];
    object(f,"policy_path setup_manifest_path dependency_snapshot_sha256 network data tier2_first_run_approval_required")?;
    texts(f, "policy_path setup_manifest_path")?;
    hex(&f["dependency_snapshot_sha256"], 64)?;
    choice(&f["network"], "denied")?;
    choice(&f["data"], "synthetic_only")?;
    if f["tier2_first_run_approval_required"] != true {
        return Err("tier 2 approval must be required".into());
    }
    let mut defects = BTreeSet::new();
    let mut fingerprints = BTreeSet::new();
    for e in list(&c["expected_findings"])? {
        // Aliases are optional, but every supplied alias needs independent review.
        let mut base = e.clone();
        let aliases = base
            .as_object_mut()
            .ok_or("expected finding object")?
            .remove("aliases");
        object(&base,"id attack_class entry_point sink boundary location invariant positive_snapshot_ids negative_snapshot_ids minimum_proof_tier proof_test_path")?;
        texts(e, "id invariant proof_test_path")?;
        if !defects.insert(text(&e["id"])?) || !fingerprints.insert(identity(e)?) {
            return Err("duplicate expected defect identity".into());
        }
        object(&e["location"], "path line")?;
        text(&e["location"]["path"])?;
        if !e["location"]["line"].is_null() {
            integer(&e["location"]["line"])?;
            if e["location"]["line"] == 0 {
                return Err("line is one-based".into());
            }
        }
        refs(&e["positive_snapshot_ids"], &snapshots, "vulnerable")?;
        refs(&e["negative_snapshot_ids"], &snapshots, "fixed clean")?;
        if list(&e["positive_snapshot_ids"])?.is_empty() {
            return Err("defect needs positive snapshot".into());
        }
        choice(&e["minimum_proof_tier"], "test_proven sandbox_exploited")?;
        if let Some(aliases) = aliases {
            for a in list(&aliases)? {
                object(a, "attack_class entry_point sink boundary review")?;
                review(&a["review"])?;
                if !fingerprints.insert(identity(a)?) {
                    return Err("ambiguous alias identity".into());
                }
            }
        }
    }
    if c["kind"] == "clean_negative" && !defects.is_empty() {
        return Err("clean case has defects".into());
    }
    if c["kind"] != "clean_negative" && defects.is_empty() {
        return Err("positive case needs confirmed defects".into());
    }
    let mut clean = BTreeSet::new();
    for u in list(&c["known_clean_units"])? {
        object(u, "snapshot_ids surface boundary attack_class invariant")?;
        texts(u, "surface boundary attack_class invariant")?;
        refs(&u["snapshot_ids"], &snapshots, "vulnerable fixed clean")?;
        for snapshot in list(&u["snapshot_ids"])? {
            if !clean.insert((
                text(snapshot)?,
                text(&u["surface"])?,
                text(&u["boundary"])?,
                text(&u["attack_class"])?,
            )) {
                return Err("duplicate negative unit/snapshot".into());
            }
        }

        if list(&u["snapshot_ids"])?.is_empty() {
            return Err("negative unit needs snapshot".into());
        }
    }
    let b = &c["budget"];
    object(
        b,
        "max_agent_calls max_model_tokens max_cost_usd max_wall_seconds max_proof_runs",
    )?;
    for f in [
        "max_agent_calls",
        "max_model_tokens",
        "max_wall_seconds",
        "max_proof_runs",
    ] {
        integer(&b[f])?;
    }
    number(&b["max_cost_usd"])?;
    Ok(())
}

fn read(path: &Path) -> Result<Value> {
    let s = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    crate::shape::strict_json(&s).map_err(|e| format!("{}: {e}", path.display()))
}
fn ratio(n: usize, d: usize) -> Value {
    json!({"numerator":n,"denominator":d,"value":if d==0 {None} else {Some(n as f64/d as f64)}})
}
fn stats(values: Vec<Option<f64>>) -> Value {
    let known: Vec<f64> = values.iter().flatten().copied().collect();
    let n = known.len();
    let all = n == values.len() && n > 0;
    let mean = all.then(|| known.iter().sum::<f64>() / n as f64);
    let min = all.then(|| known.iter().copied().fold(f64::INFINITY, f64::min));
    let max = all.then(|| known.iter().copied().fold(f64::NEG_INFINITY, f64::max));
    let sd = mean.map(|m| {
        (known
            .iter()
            .map(|v| {
                let delta = v - m;
                delta * delta
            })
            .sum::<f64>()
            / n as f64)
            .sqrt()
    });
    json!({"distribution":values,"numerator":n,"denominator":values.len(),"mean":mean,"min":min,"max":max,"range":min.zip(max).map(|(a,b)|b-a),"standard_deviation":sd})
}
fn tier(v: &Value) -> Result<u8> {
    match text(v)? {
        "traced" => Ok(0),
        "test_proven" => Ok(1),
        "sandbox_exploited" => Ok(2),
        _ => Err("unknown proof tier".into()),
    }
}
fn ids(e: &Value) -> Result<BTreeSet<String>> {
    let mut set = BTreeSet::from([identity(e)?]);
    if let Some(aliases) = e.get("aliases") {
        for a in list(aliases)? {
            set.insert(identity(a)?);
        }
    }
    Ok(set)
}
fn contains(v: &Value, s: &str) -> bool {
    v.as_array().is_some_and(|a| a.iter().any(|v| v == s))
}

fn validate_run(r: &Value, m: &Value) -> Result<()> {
    object(
        r,
        "format_version run_id campaign_id repetitions configuration manifest_sha256 observations resource_usage",
    )?;
    if r["format_version"] != 1 {
        return Err("unsupported run version".into());
    }
    texts(r, "run_id campaign_id configuration")?;
    hex(&r["manifest_sha256"], 64)?;
    integer(&r["repetitions"])?;
    let resource = &r["resource_usage"];
    object(resource, "proof_tool_cost_usd wall_seconds")?;
    for f in ["proof_tool_cost_usd", "wall_seconds"] {
        if !resource[f].is_null() {
            number(&resource[f])?;
        }
    }
    let mut seen = BTreeSet::new();
    for o in list(&r["observations"])? {
        object(o,"case_id snapshot_id status blockers examined_units unexamined_units candidates findings adjudications source_run")?;
        texts(o, "case_id snapshot_id")?;
        choice(&o["status"], "complete blocked budget_exhausted")?;
        for f in ["blockers", "examined_units", "unexamined_units"] {
            strings(&o[f])?;
        }
        if o["status"] != "complete" && list(&o["blockers"])?.is_empty() {
            return Err("incomplete observation needs blocker".into());
        }
        let case = list(&m["cases"])?
            .iter()
            .find(|c| c["id"] == o["case_id"])
            .ok_or("unknown run case")?;
        if !list(&case["snapshots"])?
            .iter()
            .any(|s| s["id"] == o["snapshot_id"])
        {
            return Err("unknown run snapshot".into());
        }
        if !seen.insert((text(&o["case_id"])?, text(&o["snapshot_id"])?)) {
            return Err("duplicate snapshot observation".into());
        }
        if !o["source_run"].is_null() {
            text(&o["source_run"])?;
        }
        let mut candidates = BTreeSet::new();
        for c in list(&o["candidates"])? {
            object(c, "attack_class entry_point sink boundary verifier")?;
            choice(&c["verifier"], "accepted rejected pending")?;
            if !candidates.insert(identity(c)?) {
                return Err("duplicate candidate identity".into());
            }
        }
        let mut findings = BTreeSet::new();
        for f in list(&o["findings"])? {
            object(
                f,
                "fingerprint attack_class entry_point sink boundary verdict proof_tier proof_ref",
            )?;
            choice(&f["verdict"], "confirmed rejected needs_validation")?;
            tier(&f["proof_tier"])?;
            if !f["proof_ref"].is_null() {
                text(&f["proof_ref"])?;
            }
            let fp = identity(f)?;
            if f["fingerprint"] != fp || !findings.insert(fp) {
                return Err("incorrect or duplicate finding fingerprint".into());
            }
        }
        let mut adjudications = BTreeSet::new();
        for a in list(&o["adjudications"])? {
            object(a, "fingerprint outcome negative_unit review")?;
            if !crate::model::is_fingerprint(text(&a["fingerprint"])?)
                || !findings.contains(text(&a["fingerprint"])?)
            {
                return Err("adjudication has no finding".into());
            }
            if !adjudications.insert(text(&a["fingerprint"])?) {
                return Err("duplicate adjudication".into());
            }
            choice(&a["outcome"], "false_positive pending disputed")?;
            review(&a["review"])?;
            if a["outcome"] == "false_positive" {
                let i = a["negative_unit"]
                    .as_u64()
                    .ok_or("FP needs negative_unit index")? as usize;
                let unit = list(&case["known_clean_units"])?
                    .get(i)
                    .ok_or("unknown negative unit")?;
                if !contains(&unit["snapshot_ids"], text(&o["snapshot_id"])?) {
                    return Err("negative unit snapshot mismatch".into());
                }
            } else if !a["negative_unit"].is_null() {
                return Err("unresolved negative_unit must be null".into());
            }
        }
    }
    let required: usize = list(&m["cases"])?
        .iter()
        .map(|c| c["snapshots"].as_array().unwrap().len())
        .sum();
    if seen.len() != required {
        return Err("every snapshot needs an observation, including blocked snapshots".into());
    }
    Ok(())
}

// Keep proof validation results separate from the evaluator's exported claims.
struct ScoringRun {
    export: Value,
    accounting: Value,
    evidence_errors: Evidence,
}

struct Evidence {
    findings: BTreeMap<(String, String, String), Vec<String>>,
    observations: BTreeMap<(String, String), ObservationReview>,
}

struct ObservationReview {
    state: Option<String>,
    needs_validation: usize,
    decisions: BTreeMap<String, crate::model::Verdict>,
}

fn source_findings(dir: &Path, observation: &Value) -> Result<(crate::review::View, PathBuf)> {
    let source = text(&observation["source_run"]).map_err(|_| "missing source_run".to_owned())?;
    // Archived source runs must stay within the supplied repetition, including symlinks.
    if source.contains('\\')
        || source.contains(':')
        || source.starts_with('/')
        || source
            .split('/')
            .any(|part| part == ".." || part.is_empty())
    {
        return Err("source_run must be a relative directory within the repetition".into());
    }
    let root = std::fs::canonicalize(dir).map_err(|e| e.to_string())?;
    let relative = Path::new(source).join("findings.json");
    // Admit the archive boundary, then read publication inputs under its lock.
    crate::run_artifact::text(&root, &relative, crate::run_artifact::FINDINGS_BYTES)?;
    let source = root.join(source);
    let view = crate::review::View::load_archive_locked(&source)?;
    if !view.strict_errors.is_empty() {
        return Err(view.strict_errors.join("; "));
    }
    Ok((view, source))
}

fn evidence_errors(dir: &Path, r: &Value, manifest: &Value) -> Result<Evidence> {
    let mut errors = BTreeMap::new();
    let mut observations = BTreeMap::new();
    for o in list(&r["observations"])? {
        let case = list(&manifest["cases"])?
            .iter()
            .find(|c| c["id"] == o["case_id"])
            .ok_or("unknown run case")?;
        let snapshot = list(&case["snapshots"])?
            .iter()
            .find(|s| s["id"] == o["snapshot_id"])
            .ok_or("unknown run snapshot")?;
        let context = || {
            format!(
                "run {} case {} snapshot {} source_run {}",
                r["run_id"], o["case_id"], o["snapshot_id"], o["source_run"]
            )
        };
        let source = if o["source_run"].is_null() {
            Err("missing source_run".to_owned())
        } else {
            // Reject incomplete exports before producing any metrics, even if
            // the observation is blocked or exports no findings at all.
            let source = source_findings(dir, o).map_err(|e| format!("{}: {e}", context()))?;
            let exported: BTreeSet<_> = list(&o["findings"])?
                .iter()
                .map(|f| text(&f["fingerprint"]))
                .collect::<Result<_>>()?;
            let omitted: Vec<_> = source
                .0
                .findings
                .findings
                .iter()
                .filter(|f| {
                    matches!(
                        f.verdict,
                        crate::model::Verdict::Confirmed | crate::model::Verdict::NeedsValidation
                    ) && !exported.contains(f.fingerprint.as_str())
                })
                .map(|f| f.fingerprint.as_str())
                .collect();
            if !omitted.is_empty() {
                return Err(format!(
                    "{}: incomplete observation: export omits confirmed or needs_validation source findings: {}",
                    context(), omitted.join(", ")
                ));
            }
            Ok(source)
        };
        // Validate every observation before inspecting exports, including empty ones.
        let review = match &source {
            Ok((view, _)) => ObservationReview {
                state: view.state.clone(),
                needs_validation: view.needs_validation,
                decisions: view
                    .findings
                    .findings
                    .iter()
                    .flat_map(|f| {
                        std::iter::once(&f.fingerprint)
                            .chain(f.candidates.iter())
                            .map(move |fp| (fp.clone(), f.verdict))
                    })
                    .collect(),
            },
            Err(e) => ObservationReview {
                state: Some(e.clone()),
                needs_validation: 0,
                decisions: BTreeMap::new(),
            },
        };
        observations.insert(
            (text(&o["case_id"])?.into(), text(&o["snapshot_id"])?.into()),
            review,
        );
        for f in list(&o["findings"])? {
            let result = match &source {
                Err(e) => vec![e.clone()],
                Ok((view, source)) => match view
                    .findings
                    .findings
                    .iter()
                    .find(|s| s.fingerprint == f["fingerprint"])
                {
                    None => vec!["exported finding is missing from source findings.json".into()],
                    Some(finding) => {
                        let original = serde_json::to_value(finding).map_err(|e| e.to_string())?;
                        if [
                            "fingerprint",
                            "attack_class",
                            "entry_point",
                            "sink",
                            "boundary",
                            "verdict",
                            "proof_tier",
                            "proof_ref",
                        ]
                        .iter()
                        .any(|key| original[*key] != f[*key])
                        {
                            {
                                let mut errors = view.decision_errors[&finding.fingerprint].clone();
                                errors.push("exported finding does not match source findings.json (identity, verdict, tier or proof_ref)".into());
                                errors
                            }
                        } else {
                            // The same offline proof validator used by `omgs validate`, including
                            // runner artifacts and omgs-proof/2 contract rules. No replay.
                            let mut proof_errors =
                                view.decision_errors[&finding.fingerprint].clone();
                            if let Some(proof_ref) = finding.proof_ref.as_deref() {
                                // Load errors are already reported by validate_proofs.
                                if let Ok(record) = crate::proof::load(source, proof_ref) {
                                    let expected = text(&snapshot["source_ref"])?;
                                    if record.target_head.as_deref() != Some(expected) {
                                        proof_errors.push(format!(
                                            "{proof_ref}: target_head {} does not match frozen snapshot source_ref {expected}",
                                            record.target_head.as_deref().unwrap_or("<missing>")
                                        ));
                                    }
                                }
                            }
                            proof_errors
                        }
                    }
                },
            };
            errors.insert(
                (
                    text(&o["case_id"])?.to_owned(),
                    text(&o["snapshot_id"])?.to_owned(),
                    text(&f["fingerprint"])?.to_owned(),
                ),
                result,
            );
        }
    }
    Ok(Evidence {
        findings: errors,
        observations,
    })
}

// Use the same cumulative usage model as report and status.
fn accounting(dir: &Path) -> Result<Value> {
    let view = crate::review::View::load_archive_locked(dir)?;
    let mut usage = crate::accounting::aggregate(&view.saved)?;
    if let Some(calls) = view.saved.get("agent_calls_used") {
        integer(calls)?;
        usage["calls"] = calls.clone();
    }
    Ok(usage)
}

/// Each directory is one complete repetition over all frozen snapshots.
pub fn score(cases: &Path, dirs: &[PathBuf]) -> Result<Value> {
    publish_score(cases, dirs, Ok)
}

/// Keep every repetition and source-run snapshot locked through output.
pub fn publish_score<T>(
    cases: &Path,
    dirs: &[PathBuf],
    publish: impl FnOnce(Value) -> Result<T>,
) -> Result<T> {
    let inputs = score_inputs(dirs)?;
    crate::runmeta::with_run_locks(&inputs, true, || {
        if score_inputs(dirs)? != inputs {
            return Err("benchmark inputs changed before publication; retry".into());
        }
        publish(score_locked(cases, dirs)?)
    })
}

fn score_inputs(dirs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut inputs = BTreeSet::new();
    for dir in dirs {
        let root = std::fs::canonicalize(dir).map_err(|e| e.to_string())?;
        inputs.insert(root.clone());
        let r = crate::shape::strict_json(&crate::run_artifact::text(
            &root,
            Path::new("benchmark-run.json"),
            crate::run_artifact::BENCHMARK_BYTES,
        )?)?;
        for o in list(&r["observations"])? {
            if let Some(source) = o["source_run"].as_str() {
                if source.contains(['\\', ':'])
                    || source.starts_with('/')
                    || source.split('/').any(|p| p == ".." || p.is_empty())
                {
                    return Err(
                        "source_run must be a relative directory within the repetition".into(),
                    );
                }
                let source = std::fs::canonicalize(root.join(source)).map_err(|e| e.to_string())?;
                if !source.starts_with(&root) {
                    return Err("source_run escapes repetition".into());
                }
                inputs.insert(source);
            }
        }
    }
    Ok(inputs.into_iter().collect())
}

fn score_locked(cases: &Path, dirs: &[PathBuf]) -> Result<Value> {
    let m = read(cases)?;
    manifest(&m)?;
    if dirs.is_empty() {
        return Err("at least one --runs directory is required".into());
    }
    let mut runs = Vec::new();
    let mut names = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for dir in dirs {
        if !paths.insert(std::fs::canonicalize(dir).map_err(|e| e.to_string())?) {
            return Err("duplicate run directory".into());
        }
        let r = crate::shape::strict_json(&crate::run_artifact::text(
            dir,
            Path::new("benchmark-run.json"),
            crate::run_artifact::BENCHMARK_BYTES,
        )?)?;
        validate_run(&r, &m)?;
        let bytes = serde_json::to_vec(&m).map_err(|e| e.to_string())?;
        if r["manifest_sha256"] != crate::sha256::digest(&bytes) {
            return Err("run manifest_sha256 does not match frozen cases".into());
        }

        if !names.insert(text(&r["run_id"])?.to_owned()) {
            return Err("duplicate run id".into());
        }
        if r["repetitions"].as_u64() != Some(dirs.len() as u64) {
            return Err("run count differs from predeclared repetitions".into());
        }
        if let Some(first) = runs.first() {
            let first: &ScoringRun = first;
            let first = &first.export;
            for field in ["campaign_id", "configuration", "repetitions"] {
                if r[field] != first[field] {
                    return Err("inconsistent campaign configuration".into());
                }
            }
        }
        runs.push(ScoringRun {
            evidence_errors: evidence_errors(dir, &r, &m)?,
            export: r,
            accounting: accounting(dir)?,
        });
    }
    let mut cohorts = BTreeMap::<String, Vec<&Value>>::new();
    for c in list(&m["cases"])? {
        let key = format!(
            "{}:{}:{}",
            text(&c["cutoff"]["eligibility"])?,
            text(&c["split"]["partition"])?,
            text(&c["split"]["rotation_id"])?
        );
        cohorts.entry(key).or_default().push(c);
    }
    let mut output = Vec::new();
    for (cohort, cases) in cohorts {
        output.push(score_cohort(&cohort, &cases, &runs)?);
    }
    let costs: Vec<Option<f64>> = runs
        .iter()
        .map(|r| r.accounting["cost_usd"].as_f64())
        .collect();
    let total = costs.iter().try_fold(0.0, |s, c| c.map(|v| s + v));
    Ok(
        json!({"format_version":1,"cohort":"entire_campaign","campaign_id":runs[0].export["campaign_id"],"configuration":runs[0].export["configuration"],"k":runs.len(),"cli_model_calls":0,"cohorts":output,"cost_per_run":runs.iter().map(|r|json!({"run_id":r.export["run_id"],"numerator":r.accounting,"denominator":1,"cohort":"entire_campaign","resource_usage":r.export["resource_usage"]})).collect::<Vec<_>>(),"total_k_run_cost_usd":{"numerator":total,"denominator":runs.len(),"cohort":"entire_campaign"},"cost_variance":stats(costs),"time_variance":stats(runs.iter().map(|r|r.export["resource_usage"]["wall_seconds"].as_f64()).collect())}),
    )
}
// Escape the separator and escape character so case/defect pairs cannot alias.
fn defect_key(case_id: &str, defect_id: &str) -> String {
    let component = |s: &str| s.replace('%', "%25").replace(':', "%3A");
    format!("{}:{}", component(case_id), component(defect_id))
}

fn score_cohort(cohort: &str, cases: &[&Value], runs: &[ScoringRun]) -> Result<Value> {
    let denominator: usize = cases
        .iter()
        .map(|c| c["expected_findings"].as_array().unwrap().len())
        .sum();
    let negative_units: usize = cases
        .iter()
        .map(|c| {
            c["known_clean_units"]
                .as_array()
                .unwrap()
                .iter()
                .map(|u| u["snapshot_ids"].as_array().unwrap().len())
                .sum::<usize>()
        })
        .sum();
    let mut union = BTreeSet::new();
    let mut frequency = BTreeMap::<String, usize>::new();
    for c in cases {
        for e in list(&c["expected_findings"])? {
            frequency.insert(defect_key(text(&c["id"])?, text(&e["id"])?), 0);
        }
    }
    let mut per_run = Vec::new();
    let mut recalls = Vec::new();
    let mut fps = Vec::new();
    for run in runs {
        let r = &run.export;
        let mut recovered = BTreeSet::new();
        let mut tp = BTreeSet::new();
        let mut fp = 0;
        let mut fp_units = BTreeSet::new();
        let mut submitted = BTreeSet::new();
        let mut rejected = BTreeSet::new();
        let mut pending = BTreeSet::new();
        let mut unexpected = Vec::new();
        let mut invalid_evidence = Vec::new();
        let mut pending_adjudications = Vec::new();
        let mut needs_validation = 0;
        let mut blocked = Vec::new();
        let mut paired = Vec::new();
        for c in cases {
            let cid = text(&c["id"])?;
            for o in list(&r["observations"])?
                .iter()
                .filter(|o| o["case_id"] == cid)
            {
                let sid = text(&o["snapshot_id"])?;
                let review = &run.evidence_errors.observations[&(cid.into(), sid.into())];
                let review_gaps: Vec<_> = review.state.iter().cloned().collect();
                needs_validation += review.needs_validation;
                if o["status"] != "complete" || !review_gaps.is_empty() {
                    let mut reasons = list(&o["blockers"])?.clone();
                    reasons.extend(review_gaps.iter().map(|s| json!(s)));
                    blocked.push(json!({"case_id":cid,"snapshot_id":sid,"status":if o["status"] == "complete" { json!("incomplete") } else { o["status"].clone() },"blockers":reasons}));
                }
                let status = if o["status"] == "complete" && !review_gaps.is_empty() {
                    json!("incomplete")
                } else {
                    o["status"].clone()
                };
                let mut invalid = BTreeSet::new();
                let mut unresolved = BTreeSet::new();
                for f in list(&o["findings"])? {
                    let fingerprint = text(&f["fingerprint"])?;
                    let errors = &run.evidence_errors.findings
                        [&(cid.to_owned(), sid.to_owned(), fingerprint.to_owned())];
                    if !errors.is_empty() {
                        invalid.insert(fingerprint);
                        invalid_evidence.push(json!({"case_id":cid,"snapshot_id":sid,"fingerprint":fingerprint,"source_run":o["source_run"],"errors":errors}));
                    }
                    if let Some(adj) = list(&o["adjudications"])?.iter().find(|a| {
                        a["fingerprint"] == fingerprint
                            && (a["outcome"] == "pending" || a["outcome"] == "disputed")
                    }) {
                        unresolved.insert(fingerprint);
                        pending_adjudications.push(json!({"case_id":cid,"snapshot_id":sid,"fingerprint":fingerprint,"outcome":adj["outcome"],"review":adj["review"]}));
                    }
                }
                let mut matched = BTreeSet::new();
                for e in list(&c["expected_findings"])? {
                    let key = defect_key(cid, text(&e["id"])?);
                    let aliases = ids(e)?;
                    let positive = contains(&e["positive_snapshot_ids"], sid);
                    let cs: Vec<&Value> = list(&o["candidates"])?
                        .iter()
                        .filter(|c| identity(c).is_ok_and(|fp| aliases.contains(&fp)))
                        .collect();
                    if positive && !cs.is_empty() {
                        submitted.insert(key.clone());
                        if cs.iter().any(|c| {
                            identity(c).is_ok_and(|fp| {
                                review.decisions.get(&fp) == Some(&crate::model::Verdict::Rejected)
                            })
                        }) {
                            rejected.insert(key.clone());
                        }
                        if cs.iter().any(|c| {
                            identity(c).is_ok_and(|fp| {
                                !matches!(
                                    review.decisions.get(&fp),
                                    Some(
                                        crate::model::Verdict::Confirmed
                                            | crate::model::Verdict::Rejected
                                    )
                                )
                            })
                        }) {
                            pending.insert(key.clone());
                        }
                    }
                    let mut found = false;
                    for f in list(&o["findings"])? {
                        if positive
                            && !invalid.contains(text(&f["fingerprint"])?)
                            && !unresolved.contains(text(&f["fingerprint"])?)
                            && f["verdict"] == "confirmed"
                            && tier(&f["proof_tier"])? >= tier(&e["minimum_proof_tier"])?
                            && aliases.contains(text(&f["fingerprint"])?)
                        {
                            if list(&o["adjudications"])?.iter().any(|a| {
                                a["fingerprint"] == f["fingerprint"]
                                    && a["outcome"] == "false_positive"
                            }) {
                                return Err(
                                    "positive match conflicts with false-positive adjudication"
                                        .into(),
                                );
                            }
                            recovered.insert(key.clone());
                            tp.insert((key.clone(), sid.to_owned()));
                            matched.insert(text(&f["fingerprint"])?.to_owned());
                            found = true;
                        }
                    }
                    if positive || contains(&e["negative_snapshot_ids"], sid) {
                        paired.push(json!({"case_id":cid,"defect_id":e["id"],"snapshot_id":sid,"positive":positive,"recovered":found,"status":status}));
                    }
                }
                for f in list(&o["findings"])? {
                    if f["verdict"] != "confirmed" {
                        continue;
                    }
                    let fingerprint = text(&f["fingerprint"])?;
                    if matched.contains(fingerprint)
                        || invalid.contains(fingerprint)
                        || unresolved.contains(fingerprint)
                    {
                        continue;
                    }
                    let adj = list(&o["adjudications"])?
                        .iter()
                        .find(|a| a["fingerprint"] == fingerprint);
                    if tier(&f["proof_tier"])? > 0
                        && adj.is_some_and(|a| a["outcome"] == "false_positive")
                    {
                        fp += 1;
                        fp_units.insert((
                            cid.to_owned(),
                            sid.to_owned(),
                            adj.unwrap()["negative_unit"].as_u64().unwrap(),
                        ));
                    } else {
                        unexpected.push(json!({"case_id":cid,"snapshot_id":sid,"fingerprint":fingerprint,"proof_tier":f["proof_tier"],"adjudication":adj.map(|a|a["outcome"].clone()).unwrap_or(json!("unreviewed"))}));
                    }
                }
            }
        }
        for key in &recovered {
            *frequency.get_mut(key).unwrap() += 1;
        }
        union.extend(recovered.iter().cloned());
        recalls.push(if denominator == 0 {
            None
        } else {
            Some(recovered.len() as f64 / denominator as f64)
        });
        fps.push(Some(fp as f64));
        let snapshot_context: Vec<Value> = list(&r["observations"])?.iter()
            .filter(|o| cases.iter().any(|c| c["id"] == o["case_id"]))
            .map(|o| {
                let review = &run.evidence_errors.observations[&(o["case_id"].as_str().unwrap().into(), o["snapshot_id"].as_str().unwrap().into())];
                let gaps: Vec<_> = review.state.iter().cloned().collect();
                let mut blockers = o["blockers"].as_array().unwrap().clone();
                blockers.extend(gaps.iter().map(|s| json!(s)));
                json!({"case_id":o["case_id"],"snapshot_id":o["snapshot_id"],"status":if o["status"] == "complete" && !gaps.is_empty() { json!("incomplete") } else { o["status"].clone() },"blockers":blockers,"examined_units":o["examined_units"],"unexamined_units":o["unexamined_units"]})
            })
            .collect();
        per_run.push(json!({"run_id":r["run_id"],"recall":ratio(recovered.len(),denominator),"false_positives":ratio(fp,1),"true_positive_detections":ratio(tp.len(),1),"false_discovery_fraction":ratio(fp,tp.len()+fp),"negative_unit_rate":ratio(fp_units.len(),negative_units),"verifier_false_rejection_rate":ratio(rejected.len(),submitted.len()),"true_candidates_pending":ratio(pending.len(),submitted.len()),"needs_validation":ratio(needs_validation,1),"unexpected_confirmations":unexpected,"invalid_evidence":invalid_evidence,"pending_adjudications":pending_adjudications,"blocked_or_exhausted":blocked,"paired_outcomes":paired,"snapshot_context":snapshot_context}));
    }
    Ok(
        json!({"cohort":cohort,"context":cases,"runs":per_run,"mean_recall":ratio(frequency.values().sum(),denominator * runs.len()),"union_recall":ratio(union.len(),denominator),"recall_variance":stats(recalls),"false_positive_variance":stats(fps),"detection_frequency":frequency.into_iter().map(|(id,n)|json!({"defect":id,"frequency":ratio(n,runs.len())})).collect::<Vec<_>>()}),
    )
}

pub fn markdown(result: &Value) -> String {
    let mut s=String::from("| Cohort | Run | Recall | FP | FDR | Negative-unit rate | Verifier rejection | Verifier pending | Pending adjudications | Invalid evidence |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
    let display = |v: &Value| format!("{}/{} ({})", v["numerator"], v["denominator"], v["value"]);
    for c in result["cohorts"].as_array().unwrap() {
        let name = crate::handoff::markdown_inline(c["cohort"].as_str().unwrap());
        for r in c["runs"].as_array().unwrap() {
            s.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                name,
                crate::handoff::markdown_inline(r["run_id"].as_str().unwrap()),
                display(&r["recall"]),
                r["false_positives"]["numerator"],
                display(&r["false_discovery_fraction"]),
                display(&r["negative_unit_rate"]),
                display(&r["verifier_false_rejection_rate"]),
                display(&r["true_candidates_pending"]),
                r["pending_adjudications"].as_array().unwrap().len(),
                r["invalid_evidence"].as_array().unwrap().len()
            ));
        }
        s.push_str(&format!(
            "| {name} | union of {} | {} | | | | | | | |\n",
            result["k"],
            display(&c["union_recall"])
        ));
    }
    s.push_str("\n| Cohort | Mean recall | Detections / opportunities |\n| --- | --- | --- |\n");
    for c in result["cohorts"].as_array().unwrap() {
        s.push_str(&format!(
            "| {} | {} | {}/{} |\n",
            crate::handoff::markdown_inline(c["cohort"].as_str().unwrap()),
            c["mean_recall"]["value"],
            c["mean_recall"]["numerator"],
            c["mean_recall"]["denominator"]
        ));
    }
    s.push_str("\nPopulation standard deviations and full context are in JSON. Unknown billing stays null. Cost covers the entire campaign, not an allocated cohort estimate.\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn copy_private(from: &Path, to: &Path) {
        crate::platform::create_private_tree(to).unwrap();
        for entry in std::fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name() == ".omgs-run.lock" {
                continue;
            }
            let dest = to.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_private(&entry.path(), &dest);
            } else {
                crate::runmeta::write_atomic_bytes(&dest, &std::fs::read(entry.path()).unwrap())
                    .unwrap();
            }
        }
    }

    #[test]
    fn colon_ids_do_not_merge_distinct_defects() {
        let m: Value =
            serde_json::from_str(include_str!("../benchmark/fixtures/score/cases.json")).unwrap();
        let original: Value = serde_json::from_str(include_str!(
            "../benchmark/fixtures/score/run-1/benchmark-run.json"
        ))
        .unwrap();
        let mut first = m["cases"][0].clone();
        first["id"] = json!("fixture:a");
        first["expected_findings"] = json!([first["expected_findings"][0]]);
        first["expected_findings"][0]["id"] = json!("b");
        let mut second = first.clone();
        second["id"] = json!("fixture");
        second["expected_findings"][0]["id"] = json!("a:b");
        let mut observations = Vec::new();
        for c in [&first, &second] {
            for o in original["observations"].as_array().unwrap() {
                let mut o = o.clone();
                o["case_id"] = c["id"].clone();
                observations.push(o);
            }
        }
        let mut run = original.clone();
        run["observations"] = json!(observations);
        let source = crate::platform::temp_root()
            .unwrap()
            .join(format!("omgs-colon-score-{}", std::process::id()));
        copy_private(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("benchmark/fixtures/score/run-1"),
            &source,
        );
        let result = score_cohort(
            "separate_ids",
            &[&first, &second],
            &[ScoringRun {
                evidence_errors: evidence_errors(
                    &source,
                    &run,
                    &json!({"cases": [&first, &second]}),
                )
                .unwrap(),
                export: run,
                accounting: json!({}),
            }],
        )
        .unwrap();
        std::fs::remove_dir_all(source).unwrap();
        assert_eq!(result["union_recall"], ratio(2, 2));
        assert_eq!(result["runs"][0]["recall"], ratio(2, 2));
        assert_eq!(result["detection_frequency"].as_array().unwrap().len(), 2);
        assert_ne!(defect_key("x%3A", "y"), defect_key("x:", "y"));
    }
    #[test]
    fn run_shapes_and_zero_denominators() {
        let m: Value =
            serde_json::from_str(include_str!("../benchmark/fixtures/score/cases.json")).unwrap();
        let r: Value = serde_json::from_str(include_str!(
            "../benchmark/fixtures/score/run-1/benchmark-run.json"
        ))
        .unwrap();
        for (pointer, bad) in [
            (
                "/observations/0/findings/0/fingerprint",
                json!("omgs-0000000000000000"),
            ),
            ("/observations/2/blockers", json!([])),
            ("/observations/0/case_id", json!("unknown")),
            ("/observations/1/adjudications/0/negative_unit", json!(1)),
            ("/resource_usage/wall_seconds", json!(-1)),
            ("/observations/0/candidates/0/verifier", json!("deferred")),
        ] {
            let mut broken = r.clone();
            *broken.pointer_mut(pointer).unwrap() = bad;
            assert!(validate_run(&broken, &m).is_err(), "{pointer}");
        }
        let mut broken = r.clone();
        broken["observations"].as_array_mut().unwrap().pop();
        assert!(validate_run(&broken, &m).is_err());
        assert_eq!(
            ratio(0, 0),
            json!({"numerator":0,"denominator":0,"value":null})
        );
        assert_eq!(stats(vec![None, None])["standard_deviation"], Value::Null);
        assert!(date(&json!("2026-01-0é"), false).is_err());
    }
}
