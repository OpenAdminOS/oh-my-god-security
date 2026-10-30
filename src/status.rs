//! `pipeline-status.json`, the optional live progress file the dashboard polls.
//! `omgs status` updates it so orchestrators never hand-write the JSON.

use crate::runmeta::{now_ms, timestamp, with_lock, write_atomic};
use serde_json::{json, Map, Value};
use std::path::Path;

pub const FILE: &str = "pipeline-status.json";
pub const STATES: [&str; 4] = ["pending", "active", "done", "failed"];
pub const COUNTERS: [&str; 4] = ["candidates", "confirmed", "needs_validation", "rejected"];
/// Log lines kept, newest last, so the file stays small on long runs.
const LOG_LIMIT: usize = 200;

pub struct Update<'a> {
    pub stage: &'a str,
    pub label: Option<&'a str>,
    /// Parent stage id when `stage` is a sub-agent, such as one hunter.
    pub parent: Option<&'a str>,
    pub state: &'a str,
    pub detail: Option<&'a str>,
    pub counters: &'a [(String, u64)],
    pub log: Option<&'a str>,
}

fn upsert<'v>(
    list: &'v mut Vec<Value>,
    id: &str,
    label: Option<&str>,
    restart: bool,
) -> &'v mut Map<String, Value> {
    let pos = match list
        .iter()
        .position(|s| s.get("id").and_then(|v| v.as_str()) == Some(id))
    {
        Some(p) => p,
        None => {
            list.push(json!({ "id": id, "attempt_id": format!("{id}:1"), "label": label.unwrap_or(id), "status": "pending" }));
            list.len() - 1
        }
    };
    let entry = list[pos]
        .as_object_mut()
        .expect("stage entries are objects");
    let restarting = entry
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|s| s == "done" || s == "failed");
    if restarting && restart {
        let mut previous = entry.clone();
        previous.remove("history");
        entry
            .entry("history")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .expect("validated history")
            .push(Value::Object(previous));
        let round = entry["history"].as_array().unwrap().len() + 1;
        entry.insert("attempt_id".into(), json!(format!("{id}:{round}")));
        entry.insert("label".into(), json!(label.unwrap_or(id)));
        entry.remove("children");
        entry.remove("detail");
        entry.remove("started_ms");
        entry.remove("ended_ms");
        entry.insert("status".into(), json!("pending"));
    }
    if let Some(l) = label {
        entry.insert("label".into(), json!(l));
    }
    entry
}

fn set_state(entry: &mut Map<String, Value>, state: &str, detail: Option<&str>, now: u64) {
    let was = entry
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("pending")
        .to_string();
    entry.insert("status".into(), json!(state));
    if state == "active" && was != "active" {
        entry.insert("started_ms".into(), json!(now));
        entry.remove("ended_ms");
    }
    if (state == "done" || state == "failed") && !entry.contains_key("ended_ms") {
        entry.insert("ended_ms".into(), json!(now));
    }
    if let Some(d) = detail {
        entry.insert("detail".into(), json!(d));
    }
}

/// Apply one update to the status file in `dir`, creating it when absent,
/// under the run lock so parallel hunters never drop each other's updates.
pub fn apply(dir: &Path, u: &Update) -> Result<(), String> {
    apply_with_logs(dir, u, &[])
}

/// Append all supplied log messages in the same status transaction.
pub fn apply_with_logs(dir: &Path, u: &Update, logs: &[String]) -> Result<(), String> {
    with_lock(dir, || apply_with_logs_locked(dir, u, logs))
}

/// Caller holds the run lock through the enclosing publication.
pub fn apply_with_logs_locked(dir: &Path, u: &Update, logs: &[String]) -> Result<(), String> {
    apply_locked(dir, u, logs)?;
    if u.state != "done" {
        crate::runmeta::invalidate_completion_locked(dir)?;
    }
    let view = crate::review::View::load_locked(dir)?;
    write_atomic(
        &dir.join(FILE),
        &serde_json::to_string_pretty(&view.progress).map_err(|e| e.to_string())?,
    )
}

/// Check an existing status document against the status schema before it is
/// updated, so a malformed file is refused rather than carried forward.
pub fn check_document(doc: &Map<String, Value>) -> Result<(), String> {
    fn stage(v: &Value, at: &str, nested: bool) -> Result<(), String> {
        let o = v.as_object().ok_or(format!("{at} must be an object"))?;
        for key in ["id", "label"] {
            if !o.get(key).is_some_and(|x| x.is_string()) {
                return Err(format!("{at}.{key} must be a string"));
            }
        }
        if !o
            .get("status")
            .and_then(|s| s.as_str())
            .is_some_and(|s| STATES.contains(&s))
        {
            return Err(format!("{at}.status must be one of {}", STATES.join(", ")));
        }
        if o.get("attempt_id").is_some_and(|d| !d.is_string()) {
            return Err(format!("{at}.attempt_id must be a string"));
        }
        if o.get("detail").is_some_and(|d| !d.is_string()) {
            return Err(format!("{at}.detail must be a string"));
        }
        for key in ["started_ms", "ended_ms"] {
            if o.get(key).is_some_and(|t| !t.is_u64()) {
                return Err(format!("{at}.{key} must be an integer"));
            }
        }
        if let Some(history) = o.get("history") {
            for old in history.as_array().ok_or("history must be an array")? {
                if old.get("history").is_some() {
                    return Err("history cannot nest".into());
                }
                stage(old, at, nested)?;
            }
        }
        match (o.get("children"), nested) {
            (None, _) => Ok(()),
            (Some(_), true) => Err(format!("{at} cannot have children")),
            (Some(Value::Array(list)), false) => {
                for (i, c) in list.iter().enumerate() {
                    stage(c, &format!("{at}.children[{i}]"), true)?;
                }
                Ok(())
            }
            (Some(_), false) => Err(format!("{at}.children must be an array")),
        }
    }
    if let Some(stages) = doc.get("stages") {
        let list = stages.as_array().ok_or("stages must be an array")?;
        for (i, s) in list.iter().enumerate() {
            stage(s, &format!("stages[{i}]"), false)?;
        }
    }
    if let Some(c) = doc.get("counters") {
        let c = c.as_object().ok_or("counters must be an object")?;
        for (k, v) in c {
            if !COUNTERS.contains(&k.as_str()) || !v.is_u64() {
                return Err(format!(
                    "counters.{k} must be a known counter with an integer"
                ));
            }
        }
    }
    if let Some(log) = doc.get("log") {
        let log = log.as_array().ok_or("log must be an array")?;
        for (i, e) in log.iter().enumerate() {
            // Per the status schema: m is required; ts and kind are optional
            // strings.
            let ok = e.as_object().is_some_and(|o| {
                o.get("m").is_some_and(|x| x.is_string())
                    && ["ts", "kind"]
                        .iter()
                        .all(|k| o.get(*k).is_none_or(|x| x.is_string()))
            });
            if !ok {
                return Err(format!(
                    "log[{i}] needs a string m (ts and kind are optional strings)"
                ));
            }
        }
    }
    for (key, ok) in [
        (
            "updated_ms",
            doc.get("updated_ms").is_none_or(|v| v.is_u64()),
        ),
        ("run", doc.get("run").is_none_or(|v| v.is_string())),
        ("target", doc.get("target").is_none_or(|v| v.is_string())),
    ] {
        if !ok {
            return Err(format!("{key} has the wrong type"));
        }
    }
    Ok(())
}

fn apply_locked(dir: &Path, u: &Update, logs: &[String]) -> Result<(), String> {
    if !STATES.contains(&u.state) {
        return Err(format!("--state must be one of {}", STATES.join(", ")));
    }
    for (k, _) in u.counters {
        if !COUNTERS.contains(&k.as_str()) {
            return Err(format!(
                "unknown counter '{k}', expected one of {}",
                COUNTERS.join(", ")
            ));
        }
    }
    let path = dir.join(FILE);
    let mut doc: Map<String, Value> = match crate::run_artifact::optional_text(
        dir,
        Path::new(FILE),
        crate::run_artifact::STATUS_BYTES,
    )? {
        Some(text) => match crate::shape::strict_json(&text) {
            Ok(Value::Object(m)) => m,
            _ => return Err(format!("{} is not a status object", path.display())),
        },
        None => Map::new(),
    };
    check_document(&doc).map_err(|e| format!("{}: {e}", path.display()))?;
    let now = now_ms();
    if !doc.contains_key("run") {
        if let Some(name) = dir.file_name() {
            doc.insert("run".into(), json!(name.to_string_lossy()));
        }
    }
    let stages = doc
        .entry("stages")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or("stages is not an array")?;
    match u.parent {
        Some(parent) => {
            let p = upsert(stages, parent, None, false);
            let children = p
                .entry("children")
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .ok_or("children is not an array")?;
            set_state(
                upsert(
                    children,
                    u.stage,
                    u.label,
                    ["pending", "active"].contains(&u.state),
                ),
                u.state,
                u.detail,
                now,
            );
        }
        None => {
            let mut matches = Vec::new();
            for (i, s) in stages.iter().enumerate() {
                if s["id"].as_str() == Some(u.stage) {
                    matches.push((i, None));
                }
                if let Some(children) = s["children"].as_array() {
                    for (j, child) in children.iter().enumerate() {
                        if child["id"].as_str() == Some(u.stage) {
                            matches.push((i, Some(j)));
                        }
                    }
                }
            }
            if matches.len() > 1 {
                return Err("ambiguous stage id; specify --parent".into());
            }
            if let Some((i, Some(_))) = matches.first().copied() {
                let children = stages[i]["children"].as_array_mut().unwrap();
                set_state(
                    upsert(
                        children,
                        u.stage,
                        u.label,
                        ["pending", "active"].contains(&u.state),
                    ),
                    u.state,
                    u.detail,
                    now,
                );
            } else {
                set_state(
                    upsert(
                        stages,
                        u.stage,
                        u.label,
                        ["pending", "active"].contains(&u.state),
                    ),
                    u.state,
                    u.detail,
                    now,
                );
            }
        }
    }
    if !u.counters.is_empty() {
        let counters = doc
            .entry("counters")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or("counters is not an object")?;
        for (k, n) in u.counters {
            counters.insert(k.clone(), json!(n));
        }
    }
    for m in u
        .log
        .into_iter()
        .chain(logs.iter().map(String::as_str))
        .filter(|m| !m.trim().is_empty())
    {
        let log = doc
            .entry("log")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or("log is not an array")?;
        log.push(json!({ "ts": timestamp(now), "kind": u.state, "m": m }));
        let excess = log.len().saturating_sub(LOG_LIMIT);
        log.drain(..excess);
    }
    doc.insert("updated_ms".into(), json!(now));
    let text = serde_json::to_string_pretty(&Value::Object(doc)).map_err(|e| e.to_string())?;
    write_atomic(&path, &format!("{text}\n"))
}
