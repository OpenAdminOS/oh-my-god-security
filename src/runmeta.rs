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

const LOCK: &str = ".omgs-run.lock";

/// Run `f` while holding an exclusive OS file lock on `lock_path`. The OS
/// releases the lock when the file is closed, including when the process
/// crashes, so there is no stale-lock breaking that could let two holders in.
pub fn with_lock_file<T>(
    lock_path: &Path,
    f: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock_path)
        .map_err(|e| format!("open lock {}: {e}", lock_path.display()))?;
    let start = std::time::Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) => {
                if start.elapsed() > std::time::Duration::from_secs(30) {
                    return Err(format!("timed out waiting for {}", lock_path.display()));
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(format!("lock {}: {e}", lock_path.display()))
            }
        }
    }
    let result = f();
    let _ = file.unlock();
    result
}

/// Run `f` under the run directory's lock, so concurrent omgs processes
/// (parallel hunters updating status, route, ledger, report) serialize their
/// read-modify-write cycles instead of losing each other's changes.
pub fn with_lock<T>(dir: &Path, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    with_lock_file(&dir.join(LOCK), f)
}

/// Apply `change` to the run metadata in `dir` under the run lock and write
/// it back atomically. `change` may fail, in which case nothing is written.
pub fn update<T>(
    dir: &Path,
    change: impl FnOnce(&mut Map<String, Value>) -> Result<T, String>,
) -> Result<T, String> {
    with_lock(dir, || {
        let mut meta = read(dir)?;
        let out = change(&mut meta)?;
        let text = serde_json::to_string_pretty(&Value::Object(meta)).map_err(|e| e.to_string())?;
        write_atomic(&dir.join(FILE), &format!("{text}\n"))?;
        Ok(out)
    })
}

/// Clock time of day in UTC for log lines, for example "14:03:09".
pub fn clock(ms: u64) -> String {
    let secs = ms / 1000;
    format!(
        "{:02}:{:02}:{:02}",
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60
    )
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
