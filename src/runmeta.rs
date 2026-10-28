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

/// Write `bytes` to `path` through an exclusively created sibling temporary
/// file and a rename. The rename replaces the directory entry itself, so an
/// existing symlink or hardlink at `path` is replaced, never written through,
/// and a pre-planted temporary name is never followed either. Windows also
/// refuses existing destinations that fail private, single-link admission.
pub fn write_atomic_bytes(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    #[cfg(windows)]
    if let Some(file) = crate::platform::open_single_link(path)? {
        crate::platform::check_private_file(&file)
            .map_err(|e| std::io::Error::other(format!("storage {}: {e}", path.display())))?;
    }
    #[cfg(unix)]
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file()) {
        use std::os::unix::fs::OpenOptionsExt;
        // Regular destinations are admitted before replacement. Links remain
        // safe to replace as directory entries, without following their target.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        crate::platform::check_private_file(&file)
            .map_err(|e| std::io::Error::other(format!("storage {}: {e}", path.display())))?;
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    let mut n = 0u32;
    let (tmp, mut file) = loop {
        let tmp = path.with_file_name(format!(".{name}.{}.{n}.tmp", std::process::id()));
        #[cfg(windows)]
        let opened = crate::platform::open_private_write(&tmp, true);
        #[cfg(not(windows))]
        let opened = {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(&tmp)
        };
        match opened {
            Ok(f) => break (tmp, f),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && n < 1000 => n += 1,
            Err(e) => return Err(e),
        }
    };
    if let Err(e) = crate::platform::check_private_file(&file)
        .and_then(|_| file.write_all(bytes))
        .and_then(|_| file.sync_all())
    {
        let _ = std::fs::remove_file(&tmp);
        return Err(std::io::Error::other(format!(
            "storage {}: {e}",
            tmp.display()
        )));
    }
    drop(file);
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// `write_atomic_bytes` for text, with the error as a message.
pub fn write_atomic(path: &Path, text: &str) -> Result<(), String> {
    write_atomic_bytes(path, text.as_bytes()).map_err(|e| format!("write {}: {e}", path.display()))
}

pub fn read(dir: &Path) -> Result<Map<String, Value>, String> {
    let path = dir.join(FILE);
    let text = {
        let file = crate::platform::open_single_link(&path)
            .map_err(|e| format!("read {}: {e}", path.display()))?
            .ok_or_else(|| format!("read {}: file missing", path.display()))?;
        crate::platform::check_private_file(&file)
            .map_err(|e| format!("storage {}: {e}", path.display()))?;
        std::io::read_to_string(file).map_err(|e| format!("read {}: {e}", path.display()))?
    };
    match crate::shape::strict_json(&text) {
        Ok(Value::Object(m)) => {
            check_numeric_fields(&m)?;
            Ok(m)
        }
        Ok(_) => Err(format!("{} is not a JSON object", path.display())),
        Err(e) => Err(format!("parse {}: {e}", path.display())),
    }
}

/// Counters and budgets are unsigned integers when present, never null.
pub fn check_numeric_fields(meta: &Map<String, Value>) -> Result<(), String> {
    for key in ["budget_agent_calls", "agent_calls_used", "proof_runs_used"] {
        if meta.get(key).is_some_and(|v| v.as_u64().is_none()) {
            return Err(format!("{key} must be a non-negative integer or absent"));
        }
    }
    crate::accounting::read(meta)?;
    Ok(())
}

const LOCK: &str = ".omgs-run.lock";

/// Run `f` while holding an exclusive OS file lock on `lock_path`. The OS
/// releases the lock when the file is closed, including when the process
/// crashes, so there is no stale-lock breaking that could let two holders in.
pub fn with_lock_file<T>(
    lock_path: &Path,
    f: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    #[cfg(windows)]
    let opened = crate::platform::open_private_write(lock_path, false);
    #[cfg(not(windows))]
    let opened = {
        let mut options = std::fs::OpenOptions::new();
        options.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        options.open(lock_path)
    };
    let file = opened.map_err(|e| format!("open lock {}: {e}", lock_path.display()))?;
    crate::platform::check_private_file(&file)
        .map_err(|e| format!("storage {}: {e}", lock_path.display()))?;
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
    crate::budget::with_family_lock(dir, || {
        let mut meta = read(dir)?;
        let out = change(&mut meta)?;
        check_numeric_fields(&meta)?;
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
