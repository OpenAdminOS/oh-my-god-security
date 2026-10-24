//! `pipeline-status.json`, the optional live progress file the dashboard polls.
//! `omgs status` updates it so orchestrators never hand-write the JSON.

use crate::runmeta::{clock, now_ms, with_lock, write_atomic};
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
) -> &'v mut Map<String, Value> {
    let pos = match list
        .iter()
        .position(|s| s.get("id").and_then(|v| v.as_str()) == Some(id))
    {
        Some(p) => p,
        None => {
            list.push(json!({ "id": id, "label": label.unwrap_or(id), "status": "pending" }));
            list.len() - 1
        }
    };
    let entry = list[pos]
        .as_object_mut()
        .expect("stage entries are objects");
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
        entry.entry("started_ms").or_insert(json!(now));
        entry.insert("ended_ms".into(), json!(now));
    }
    if let Some(d) = detail {
        entry.insert("detail".into(), json!(d));
    }
}

/// Apply one update to the status file in `dir`, creating it when absent,
/// under the run lock so parallel hunters never drop each other's updates.
pub fn apply(dir: &Path, u: &Update) -> Result<(), String> {
    with_lock(dir, || apply_locked(dir, u))
}

fn apply_locked(dir: &Path, u: &Update) -> Result<(), String> {
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
    let mut doc: Map<String, Value> = match std::fs::read_to_string(&path) {
        Ok(text) => match serde_json::from_str(&text) {
            Ok(Value::Object(m)) => m,
            _ => return Err(format!("{} is not a status object", path.display())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Map::new(),
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
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
            let p = upsert(stages, parent, None);
            let children = p
                .entry("children")
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .ok_or("children is not an array")?;
            set_state(upsert(children, u.stage, u.label), u.state, u.detail, now);
        }
        None => set_state(upsert(stages, u.stage, u.label), u.state, u.detail, now),
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
    if let Some(m) = u.log.filter(|m| !m.trim().is_empty()) {
        let log = doc
            .entry("log")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or("log is not an array")?;
        log.push(json!({ "ts": clock(now), "kind": u.state, "m": m }));
        let excess = log.len().saturating_sub(LOG_LIMIT);
        log.drain(..excess);
    }
    doc.insert("updated_ms".into(), json!(now));
    let text = serde_json::to_string_pretty(&Value::Object(doc)).map_err(|e| e.to_string())?;
    write_atomic(&path, &format!("{text}\n"))
}
