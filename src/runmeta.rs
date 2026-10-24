//! Run metadata (`run-metadata.json`) and small helpers for rewriting run
//! files atomically, so a reader such as `omgs watch` never sees a torn write.

use serde_json::{Map, Value};
use std::path::Path;

pub const FILE: &str = "run-metadata.json";

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Write `text` to `path` through a sibling temporary file and a rename.
pub fn write_atomic(path: &Path, text: &str) -> Result<(), String> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    std::fs::write(&tmp, text).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("rename {}: {e}", path.display())
    })
}

pub fn read(dir: &Path) -> Result<Map<String, Value>, String> {
    let path = dir.join(FILE);
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    match serde_json::from_str(&text) {
        Ok(Value::Object(m)) => Ok(m),
        Ok(_) => Err(format!("{} is not a JSON object", path.display())),
        Err(e) => Err(format!("parse {}: {e}", path.display())),
    }
}

/// Apply `change` to the run metadata in `dir` and write it back atomically.
pub fn update(dir: &Path, change: impl FnOnce(&mut Map<String, Value>)) -> Result<(), String> {
    let mut meta = read(dir)?;
    change(&mut meta);
    let text = serde_json::to_string_pretty(&Value::Object(meta)).map_err(|e| e.to_string())?;
    write_atomic(&dir.join(FILE), &format!("{text}\n"))
}

pub fn is_complete(dir: &Path) -> bool {
    read(dir)
        .ok()
        .and_then(|m| {
            m.get("run_status")
                .and_then(|s| s.as_str())
                .map(|s| s == "complete")
        })
        .unwrap_or(false)
}
