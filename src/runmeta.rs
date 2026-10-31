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
    write_atomic_content(path, bytes, None)
}

/// Retain a safely read draft's executable mode on the temporary descriptor,
/// before publishing it. Never chmod a destination path that can be swapped.
pub fn write_atomic_bytes_with_permissions(
    path: &Path,
    bytes: &[u8],
    permissions: std::fs::Permissions,
) -> std::io::Result<()> {
    write_atomic_content(path, bytes, Some(permissions))
}

fn write_atomic_content(
    path: &Path,
    bytes: &[u8],
    permissions: Option<std::fs::Permissions>,
) -> std::io::Result<()> {
    let temporary = prepare_atomic_content(path, bytes, permissions)?;
    std::fs::rename(&temporary, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&temporary);
    })
}

fn prepare_atomic_content(
    path: &Path,
    bytes: &[u8],
    permissions: Option<std::fs::Permissions>,
) -> std::io::Result<std::path::PathBuf> {
    use std::io::Write;
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
        return Err(std::io::Error::other("destination is a directory"));
    }
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
        .and_then(|_| match permissions {
            Some(p) => file.set_permissions(p),
            None => Ok(()),
        })
        .and_then(|_| file.sync_all())
    {
        let _ = std::fs::remove_file(&tmp);
        return Err(std::io::Error::other(format!(
            "storage {}: {e}",
            tmp.display()
        )));
    }
    drop(file);
    Ok(tmp)
}

/// `write_atomic_bytes` for text, with the error as a message.
pub fn write_atomic(path: &Path, text: &str) -> Result<(), String> {
    write_atomic_bytes(path, text.as_bytes()).map_err(|e| format!("write {}: {e}", path.display()))
}

/// A locked publication: construct every byte first, admit and stage every
/// destination, then replace artifacts followed by metadata and status.
/// Backup directory entries permit rollback if a rename fails during commit.
#[derive(Default)]
pub struct Transaction {
    files: Vec<(std::path::PathBuf, Vec<u8>)>,
}

impl Transaction {
    pub fn text(&mut self, path: impl Into<std::path::PathBuf>, text: impl Into<String>) {
        self.files.push((path.into(), text.into().into_bytes()));
    }

    pub fn metadata(&mut self, dir: &Path, meta: &Map<String, Value>) -> Result<(), String> {
        check_numeric_fields(meta)?;
        self.text(
            dir.join(FILE),
            serde_json::to_string_pretty(meta).map_err(|e| e.to_string())?,
        );
        Ok(())
    }

    pub fn commit(self) -> Result<(), String> {
        self.commit_prepared(
            #[cfg(test)]
            || {},
        )
    }

    fn commit_prepared(mut self, #[cfg(test)] before_commit: impl FnOnce()) -> Result<(), String> {
        self.files
            .sort_by_key(|(p, _)| match p.file_name().and_then(|s| s.to_str()) {
                Some(FILE) => 1,
                Some(crate::status::FILE) => 2,
                _ => 0,
            });
        let mut unique = std::collections::BTreeSet::new();
        let mut staged = Vec::new();
        for (path, bytes) in &self.files {
            if !unique.insert(path.clone()) {
                return Err(format!(
                    "duplicate transaction destination: {}",
                    path.display()
                ));
            }
            if path.file_name().and_then(|s| s.to_str()) == Some(FILE) {
                parse(path, std::str::from_utf8(bytes).map_err(|e| e.to_string())?)?;
            }
            if path.file_name().and_then(|s| s.to_str()) == Some(crate::status::FILE) {
                let value = crate::shape::strict_json(
                    std::str::from_utf8(bytes).map_err(|e| e.to_string())?,
                )?;
                crate::status::check_document(
                    value.as_object().ok_or("status must be an object")?,
                )?;
            }
        }
        // All temporary and backup entries live in a private sibling directory.
        // No existing entry is changed until all staging succeeds. A regular
        // destination is only ever replaced by one atomic rename, so readers
        // never find it missing; rollback restores a private byte copy. Any
        // other entry, such as a link that must be replaced and not followed,
        // is moved aside first; no-follow readers refuse it anyway.
        #[derive(Clone, Copy)]
        enum Previous {
            Absent,
            Copied,
            Moved,
        }
        let mut backups = Vec::new();
        let mut previous = Vec::new();
        let mut keep = vec![false; self.files.len()];
        let result = (|| {
            for (path, bytes) in &self.files {
                let tmp = prepare_atomic_content(path, bytes, None)
                    .map_err(|e| format!("prepare {}: {e}", path.display()))?;
                staged.push(tmp);
                let backup = path.with_file_name(format!(
                    ".omgs-transaction-{}",
                    crate::platform::random_nonce().map_err(|e| e.to_string())?
                ));
                crate::platform::create_private_dir_new(&backup).map_err(|e| e.to_string())?;
                backups.push(backup.clone());
                previous.push(match std::fs::symlink_metadata(path) {
                    Ok(m) if m.file_type().is_file() => {
                        std::fs::copy(path, backup.join("previous"))
                            .map_err(|e| format!("back up {}: {e}", path.display()))?;
                        Previous::Copied
                    }
                    Ok(_) => Previous::Moved,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Previous::Absent,
                    Err(e) => return Err(format!("inspect {}: {e}", path.display())),
                });
            }
            #[cfg(test)]
            before_commit();
            for (i, (path, _)) in self.files.iter().enumerate() {
                let replaced = (|| {
                    if let Previous::Moved = previous[i] {
                        std::fs::rename(path, backups[i].join("previous"))?;
                    }
                    std::fs::rename(&staged[i], path)
                })();
                if let Err(error) = replaced {
                    let mut recovery = Vec::new();
                    for j in (0..=i).rev() {
                        let dest = &self.files[j].0;
                        let old = backups[j].join("previous");
                        let restored = match previous[j] {
                            Previous::Absent if j < i => std::fs::remove_file(dest),
                            Previous::Copied if j < i => std::fs::rename(&old, dest),
                            Previous::Moved if std::fs::symlink_metadata(&old).is_ok() => {
                                if j < i {
                                    std::fs::remove_file(dest)
                                } else {
                                    Ok(())
                                }
                                .and_then(|()| std::fs::rename(&old, dest))
                            }
                            _ => Ok(()),
                        };
                        if let Err(e) = restored {
                            keep[j] = true;
                            recovery.push(format!(
                                "restore {} from {}: {e}",
                                dest.display(),
                                backups[j].display()
                            ));
                        }
                    }
                    return Err(format!(
                        "commit {}: {error}{}",
                        path.display(),
                        if recovery.is_empty() {
                            String::new()
                        } else {
                            format!("; recovery required: {}", recovery.join("; "))
                        }
                    ));
                }
            }
            Ok(())
        })();
        for path in staged {
            let _ = std::fs::remove_file(path);
        }
        // Retain only an original that an OS error prevented restoring.
        for (path, keep) in backups.into_iter().zip(keep) {
            if !keep {
                let _ = std::fs::remove_dir_all(path);
            }
        }
        result
    }
}

pub fn read(dir: &Path) -> Result<Map<String, Value>, String> {
    let text =
        crate::run_artifact::text(dir, Path::new(FILE), crate::run_artifact::METADATA_BYTES)?;
    parse(&dir.join(FILE), &text)
}

pub fn read_optional(dir: &Path) -> Result<Option<Map<String, Value>>, String> {
    crate::run_artifact::optional_text(dir, Path::new(FILE), crate::run_artifact::METADATA_BYTES)?
        .map(|text| parse(&dir.join(FILE), &text))
        .transpose()
}

fn parse(path: &Path, text: &str) -> Result<Map<String, Value>, String> {
    match crate::shape::strict_json(text) {
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
    let accounting = crate::accounting::read(meta)?;
    let attempts = crate::attempts::states(&crate::attempts::history(meta)?)?;
    for key in accounting.keys() {
        if let Some((role, id)) = key.split_once('@') {
            let expected = match role {
                "red-hunter" => "hunter",
                "blue-verifier" => "verifier",
                "green-fixer" => "guard",
                other => other,
            };
            if !attempts.get(id).is_some_and(|a| a.role == expected) {
                return Err("accounting key must match a recorded attempt and role".into());
            }
        }
    }
    if let Some(p) = meta.get("publication") {
        let p = p.as_object().ok_or("publication must be an object")?;
        for (k, v) in p {
            if !["repo", "source_ref", "sandbox"].contains(&k.as_str())
                || !v
                    .as_str()
                    .is_some_and(|s| !s.trim().is_empty() && !s.chars().any(char::is_control))
            {
                return Err("invalid publication label".into());
            }
        }
    }
    crate::attempts::active_blockers(meta)?;
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
    with_lock_file_checked(lock_path, || Ok(()), f)
}

pub(crate) fn with_lock_file_checked<T>(
    lock_path: &Path,
    check: impl Fn() -> std::io::Result<()>,
    f: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    check().map_err(|e| e.to_string())?;
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
        check().map_err(|e| e.to_string())?;
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
    let result = check().map_err(|e| e.to_string()).and_then(|()| f());
    let _ = file.unlock();
    result
}

/// Run `f` under the run directory's lock, so concurrent omgs processes
/// (parallel hunters updating status, route, ledger, report) serialize their
/// read-modify-write cycles instead of losing each other's changes.
pub fn with_lock<T>(dir: &Path, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    with_lock_file(&dir.join(LOCK), f)
}

/// Hold all input locks through a multi-run publication. Never wait for one
/// lock while holding another: family writers acquire parent before child.
/// Establish absent locks before reading; read-only archives must already have locks.
pub fn with_run_locks<T>(
    dirs: &[std::path::PathBuf],
    archive: bool,
    publish: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let input_paths = || -> Result<std::collections::BTreeSet<std::path::PathBuf>, String> {
        let mut paths = std::collections::BTreeSet::new();
        for dir in dirs {
            let dir = std::fs::canonicalize(dir).map_err(|e| e.to_string())?;
            if !archive && read_optional(&dir)?.is_some() {
                paths.insert(crate::budget::original(&dir)?.join(LOCK));
            }
            paths.insert(dir.join(LOCK));
        }
        Ok(paths)
    };
    let paths = input_paths()?;
    let start = std::time::Instant::now();
    loop {
        let mut held = Vec::new();
        let mut blocked = false;
        for path in &paths {
            let file = {
                // Create and admit the lock without retaining any other lock.
                if !path.try_exists().map_err(|e| e.to_string())? {
                    blocked = true;
                    break;
                }
                crate::platform::open_single_link(path).map_err(|e| e.to_string())?
            };
            let Some(file) = file else {
                blocked = true;
                break;
            };
            crate::platform::check_private_file(&file).map_err(|e| e.to_string())?;
            match file.try_lock_shared() {
                Ok(()) => held.push(file),
                Err(std::fs::TryLockError::WouldBlock) => {
                    blocked = true;
                    break;
                }
                Err(e) => return Err(format!("publication input lock: {e}")),
            }
        }
        if !blocked {
            if input_paths()? != paths {
                return Err("publication input family changed; retry".into());
            }
            return publish();
        }
        drop(held);
        // No lock remains held during creation or waiting.
        {
            for path in &paths {
                if !path.try_exists().map_err(|e| e.to_string())? {
                    with_lock_file(path, || Ok(()))?;
                }
            }
        }
        if start.elapsed().as_secs() >= 30 {
            return Err("timed out waiting for publication inputs".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Read archived data under an enforceable shared lock. Establish an absent
/// lock while no other lock is held, or refuse an archive that cannot be locked.
pub fn with_archive_lock<T>(dir: &Path, read: impl Fn() -> Result<T, String>) -> Result<T, String> {
    with_run_locks(&[dir.to_path_buf()], true, read)
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
        let mut transaction = Transaction::default();
        transaction.text(dir.join(FILE), format!("{text}\n"));
        transaction.commit()?;
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
    crate::review::View::load(dir).is_ok_and(|view| view.complete())
}

/// ISO 8601 UTC, including the date across long-running rounds.
pub fn timestamp(ms: u64) -> String {
    let days = (ms / 86_400_000) as i64;
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{}Z", clock(ms))
}

#[cfg(test)]
mod transaction_tests {
    #[test]
    fn rename_failure_restores_all_previously_committed_destinations() {
        let dir = crate::platform::temp_root().unwrap().join(format!(
            "omgs-transaction-test-{}",
            crate::platform::random_nonce().unwrap()
        ));
        crate::platform::create_private_dir_new(&dir).unwrap();
        for name in ["first", "second", super::FILE] {
            super::write_atomic(
                &dir.join(name),
                if name == super::FILE {
                    "{}"
                } else {
                    "previous"
                },
            )
            .unwrap();
        }
        let mut transaction = super::Transaction::default();
        transaction.text(dir.join("first"), "replacement");
        transaction.text(dir.join("second"), "replacement");
        transaction.metadata(&dir, &serde_json::Map::new()).unwrap();
        let result = transaction.commit_prepared(|| {
            let staged = std::fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".second.")
                })
                .unwrap();
            std::fs::remove_file(staged).unwrap();
        });
        assert!(result.unwrap_err().contains("commit"));
        assert_eq!(
            std::fs::read_to_string(dir.join("first")).unwrap(),
            "previous"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("second")).unwrap(),
            "previous"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join(super::FILE)).unwrap(),
            "{}"
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 3);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn concurrent_readers_never_see_a_destination_missing_during_commit() {
        let dir = crate::platform::temp_root().unwrap().join(format!(
            "omgs-transaction-test-{}",
            crate::platform::random_nonce().unwrap()
        ));
        crate::platform::create_private_dir_new(&dir).unwrap();
        let path = dir.join(super::FILE);
        super::write_atomic(&path, "{}").unwrap();
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watcher = {
            let (path, done) = (path.clone(), done.clone());
            std::thread::spawn(move || {
                let mut missing = 0;
                while !done.load(std::sync::atomic::Ordering::Relaxed) {
                    if std::fs::symlink_metadata(&path).is_err() {
                        missing += 1;
                    }
                }
                missing
            })
        };
        for _ in 0..300 {
            let mut transaction = super::Transaction::default();
            transaction.metadata(&dir, &serde_json::Map::new()).unwrap();
            transaction.commit().unwrap();
        }
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(watcher.join().unwrap(), 0);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
