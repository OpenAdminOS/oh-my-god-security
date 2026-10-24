//! Batch reviews of many repositories: strict repository URL parsing for the
//! clone step, and a deterministic offline index across the runs.

use crate::html_escape;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A repository URL that passed validation, split into its safe parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoUrl {
    pub url: String,
    pub host: String,
    pub owner: String,
    pub name: String,
}

fn safe_segment(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && !s.starts_with('-')
        && !s.starts_with('.')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// Accept only `https://<host>/<owner>/<name>[.git][/]`. Everything that
/// could reach git as an option, a local path, another transport, embedded
/// credentials, or a path traversal is refused.
pub fn parse_repo_url(raw: &str) -> Result<RepoUrl, String> {
    let url = raw.trim();
    let bad = |why: &str| Err(format!("refusing repository URL '{url}': {why}"));
    let Some(rest) = url.strip_prefix("https://") else {
        return bad("only https:// URLs are accepted");
    };
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return bad("whitespace or control characters");
    }
    if rest.contains(['?', '#', '@', '%', '\\']) {
        return bad("credentials, queries, fragments, and escapes are not accepted");
    }
    let mut parts = rest.trim_end_matches('/').split('/');
    let host = parts.next().unwrap_or_default().to_ascii_lowercase();
    let owner = parts.next().unwrap_or_default().to_string();
    let name = parts.next().unwrap_or_default();
    if parts.next().is_some() {
        return bad("expected https://<host>/<owner>/<name>");
    }
    // A domain name with an alphabetic top-level label: this rejects IP
    // literals (no reaching an internal address by number), bare hostnames
    // such as localhost, and ports.
    let labels: Vec<&str> = host.split('.').collect();
    let host_ok = labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        && labels
            .last()
            .is_some_and(|tld| tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic()));
    if !host_ok {
        return bad("host must be a domain name, not an IP address or bare hostname");
    }
    let name = name.strip_suffix(".git").unwrap_or(name).to_string();
    if !safe_segment(&owner) || !safe_segment(&name) {
        return bad("owner and name may use letters, digits, '.', '_', '-' only");
    }
    Ok(RepoUrl {
        url: url.to_string(),
        host,
        owner,
        name,
    })
}

/// Repository URLs from a list file: one per line, `#` starts a comment.
pub fn read_list(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or_default().trim())
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BatchFile {
    #[serde(default)]
    pub created_unix: u64,
    /// Required, so a misspelled key fails instead of indexing nothing.
    pub runs: Vec<BatchRun>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BatchRun {
    pub url: String,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub run_dir: Option<String>,
    /// `initialized` or `failed`.
    pub status: String,
    #[serde(default)]
    pub error: Option<String>,
}

/// Parse `batch.json`, requiring a JSON object with a `runs` array of
/// objects, so a positional or misshapen file is an error.
pub fn parse_batch(text: &str) -> Result<BatchFile, String> {
    let v = crate::shape::strict_json(text)?;
    let runs = v
        .as_object()
        .and_then(|o| o.get("runs"))
        .and_then(|r| r.as_array())
        .ok_or("batch.json must be an object with a runs array")?;
    if runs.iter().any(|r| !r.is_object()) {
        return Err("every batch.json run must be a JSON object".into());
    }
    serde_json::from_value(v).map_err(|e| e.to_string())
}

/// What the index shows for one run, gathered from its run directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunSummary {
    pub url: String,
    /// Link to the run's REPORT.html relative to the index, when it exists.
    pub report_href: Option<String>,
    pub state: String,
    pub confirmed: usize,
    pub needs_validation: usize,
    pub rejected: usize,
    /// Critic gaps, blocked units, init errors, and exhausted model routes.
    pub blockers: Vec<String>,
    pub agent_calls: Option<u64>,
    pub reroutes: usize,
}

/// Contents of `path`, `None` only when no entry exists. Anything present
/// but unreadable (a dangling link, a directory, bad permissions) is an error.
fn read_present(path: &Path) -> Result<Option<String>, String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("inspect {}: {e}", path.display())),
        Ok(_) => std::fs::read_to_string(path)
            .map(Some)
            .map_err(|e| format!("read {}: {e}", path.display())),
    }
}

/// The run metadata fields the index reads must have their documented
/// types; a wrong type is an error, never a silently empty value.
pub fn check_meta_types(meta: &serde_json::Map<String, serde_json::Value>) -> Result<(), String> {
    use serde_json::Value;
    let wrong = |k: &str| Err(format!("{k} has the wrong type"));
    match meta.get("run_status") {
        None | Some(Value::String(_)) => {}
        _ => return wrong("run_status"),
    }
    match meta.get("agent_calls_used") {
        None | Some(Value::Null) => {}
        Some(v) if v.is_u64() => {}
        _ => return wrong("agent_calls_used"),
    }
    match meta.get("reroutes") {
        None => {}
        Some(Value::Array(a)) if a.iter().all(|r| r.is_object()) => {}
        _ => return wrong("reroutes"),
    }
    match meta.get("blockers") {
        None => {}
        Some(Value::Array(a)) if a.iter().all(|b| b.is_string()) => {}
        _ => return wrong("blockers"),
    }
    match meta.get("models") {
        None => {}
        Some(Value::Object(m)) if m.values().all(|v| v.is_string()) => {}
        _ => return wrong("models"),
    }
    if let Some(Value::Array(list)) = meta.get("reroutes") {
        for r in list {
            let field_ok = |k: &str, null_ok: bool| match r.get(k) {
                Some(Value::String(_)) => true,
                Some(Value::Null) | None => null_ok,
                _ => false,
            };
            if !(field_ok("role", false)
                && field_ok("from", false)
                && field_ok("to", true)
                && field_ok("reason", true))
            {
                return wrong("reroutes entry");
            }
        }
    }
    Ok(())
}

/// Summarize one run directory. A file that is absent leaves its fields
/// empty and says so in `blockers`, so a half-finished run is visible; a file
/// that exists but is malformed is an error, so the index never shows a
/// clean row for a run whose evidence could not be read.
pub fn summarize(run: &BatchRun, index_dir: &Path) -> Result<RunSummary, String> {
    let mut s = RunSummary {
        url: run.url.clone(),
        state: run.status.clone(),
        ..RunSummary::default()
    };
    if let Some(e) = &run.error {
        s.blockers.push(format!("init failed: {e}"));
    }
    let Some(dir) = run.run_dir.as_deref().map(Path::new) else {
        return Ok(s);
    };
    let at = |name: &str, e: String| format!("{}: {name}: {e}", dir.display());
    match read_present(&dir.join("findings.json"))? {
        Some(text) => {
            use crate::model::Verdict;
            let f = crate::shape::findings(&text).map_err(|e| at("findings.json", e))?;
            for x in &f.findings {
                match x.verdict {
                    Verdict::Confirmed => s.confirmed += 1,
                    Verdict::NeedsValidation => s.needs_validation += 1,
                    Verdict::Rejected => s.rejected += 1,
                }
            }
        }
        None => s.blockers.push("findings.json missing".into()),
    }
    if read_present(&dir.join(crate::runmeta::FILE))?.is_some() {
        let meta = crate::runmeta::read(dir)?;
        check_meta_types(&meta).map_err(|e| at(crate::runmeta::FILE, e))?;
        if let Some(st) = meta.get("run_status").and_then(|v| v.as_str()) {
            s.state = st.to_string();
        }
        s.agent_calls = meta.get("agent_calls_used").and_then(|v| v.as_u64());
        s.reroutes = meta
            .get("reroutes")
            .and_then(|v| v.as_array())
            .map_or(0, |a| a.len());
        if let Some(blocked) = meta.get("blockers").and_then(|v| v.as_array()) {
            s.blockers
                .extend(blocked.iter().filter_map(|b| b.as_str()).map(String::from));
        }
    }
    if let Some(text) = read_present(&dir.join("coverage-ledger.json"))? {
        let ledger = crate::shape::ledger(&text).map_err(|e| at("coverage-ledger.json", e))?;
        for u in ledger.units.iter().filter(|u| u.status == "blocked") {
            s.blockers.push(format!("blocked unit {}", u.id));
        }
        let c = crate::critic::critique_run(dir)?;
        if !c.passed() {
            s.blockers.push(format!("critic: {}", c.summary()));
        }
    } else {
        s.blockers.push("coverage-ledger.json missing".into());
    }
    if dir.join("REPORT.html").is_file() {
        s.report_href = dir
            .strip_prefix(index_dir)
            .ok()
            .map(|rel| format!("{}/REPORT.html", rel.to_string_lossy()));
    }
    Ok(s)
}

pub fn render_index_markdown(runs: &[RunSummary]) -> String {
    let mut out = String::from("# OMGS batch index\n\n");
    let total = |f: fn(&RunSummary) -> usize| runs.iter().map(f).sum::<usize>();
    out.push_str(&format!(
        "Repositories: {}\nConfirmed: {}\nNeeds validation: {}\nRejected: {}\nAgent calls: {}\n\n",
        runs.len(),
        total(|r| r.confirmed),
        total(|r| r.needs_validation),
        total(|r| r.rejected),
        agent_total(runs)
    ));
    out.push_str("| Repository | State | Confirmed | Needs validation | Rejected | Agent calls | Reroutes | Blockers |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for r in runs {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            md_cell(&r.url),
            md_cell(&r.state),
            r.confirmed,
            r.needs_validation,
            r.rejected,
            r.agent_calls
                .map_or("not recorded".into(), |n| n.to_string()),
            r.reroutes,
            if r.blockers.is_empty() {
                "none".to_string()
            } else {
                md_cell(&r.blockers.join("; "))
            }
        ));
    }
    out
}

fn agent_total(runs: &[RunSummary]) -> String {
    if runs.iter().any(|r| r.agent_calls.is_none()) {
        let known: u64 = runs.iter().filter_map(|r| r.agent_calls).sum();
        format!("{known} recorded, some runs not recorded")
    } else {
        runs.iter()
            .filter_map(|r| r.agent_calls)
            .sum::<u64>()
            .to_string()
    }
}

/// A Markdown table cell: escaped so target-derived text cannot break the
/// row or inject a link.
fn md_cell(s: &str) -> String {
    crate::architecture::md_inline(s)
}

pub fn render_index_html(runs: &[RunSummary]) -> String {
    let mut rows = String::new();
    for r in runs {
        let repo = match &r.report_href {
            Some(href) => format!(
                "<a href=\"{}\">{}</a>",
                html_escape(href),
                html_escape(&r.url)
            ),
            None => html_escape(&r.url),
        };
        let blockers = if r.blockers.is_empty() {
            "none".to_string()
        } else {
            let items: String = r
                .blockers
                .iter()
                .map(|b| format!("<li>{}</li>", html_escape(b)))
                .collect();
            format!("<ul>{items}</ul>")
        };
        rows.push_str(&format!(
            "<tr><td>{repo}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{blockers}</td></tr>",
            html_escape(&r.state),
            r.confirmed,
            r.needs_validation,
            r.rejected,
            r.agent_calls
                .map_or("not recorded".into(), |n| n.to_string()),
            r.reroutes,
        ));
    }
    let total = |f: fn(&RunSummary) -> usize| runs.iter().map(f).sum::<usize>();
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta name=\"color-scheme\" content=\"light dark\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\"><title>OMGS batch index</title><style>{CSS}</style></head><body><main><h1>OMGS batch index</h1><p class=\"lede\">{} repositories: {} confirmed, {} needs validation, {} rejected. Agent calls: {}.</p><table><thead><tr><th scope=\"col\">Repository</th><th scope=\"col\">State</th><th scope=\"col\">Confirmed</th><th scope=\"col\">Needs validation</th><th scope=\"col\">Rejected</th><th scope=\"col\">Agent calls</th><th scope=\"col\">Reroutes</th><th scope=\"col\">Blockers</th></tr></thead><tbody>{rows}</tbody></table><p class=\"note\">Generated by omgs {} from each run directory. This page loads no external resources and runs no scripts.</p></main></body></html>\n",
        runs.len(),
        total(|r| r.confirmed),
        total(|r| r.needs_validation),
        total(|r| r.rejected),
        html_escape(&agent_total(runs)),
        html_escape(env!("CARGO_PKG_VERSION")),
    )
}

const CSS: &str = ":root{color-scheme:light dark;--bg:#f6f6f4;--surface:#fff;--text:#18181b;--muted:#4f4f57;--line:#deded9;--link:#1d4ed8}@media (prefers-color-scheme:dark){:root{--bg:#111113;--surface:#18181b;--text:#ececef;--muted:#b4b4bc;--line:#2e2e34;--link:#9ab8ff}}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 system-ui,-apple-system,\"Segoe UI\",Roboto,sans-serif}main{max-width:1100px;margin:0 auto;padding:32px 24px}h1{margin:0 0 8px;font-size:24px}a{color:var(--link)}.lede{color:var(--muted)}table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--line);font-size:14px}th,td{text-align:left;vertical-align:top;padding:8px 10px;border-top:1px solid var(--line);overflow-wrap:anywhere}th{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}td ul{margin:0;padding-left:18px}.note{margin-top:16px;font-size:13px;color:var(--muted)}";
