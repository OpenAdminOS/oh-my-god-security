//! Disposable, admitted storage with live-owner locks and conservative recovery.
use crate::platform;
#[path = "scratch_fs.rs"]
mod fs;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::{Path, PathBuf};

pub const GATE_EXPORT_BYTES: u64 = 4 << 30;
pub const GATE_EXPORT_ENTRIES: usize = 200_000;
// Bound gate materialization and downstream path consumers. Cleanup itself has
// no depth cap, including for trees written by an untrusted scanner.
pub const GATE_EXPORT_DEPTH: usize = 256;
pub const SENSOR_WRITE_BYTES: u64 = 1 << 30;
pub const SENSOR_WRITE_ENTRIES: usize = 100_000;
const LOCK: &str = ".omgs-scratch.lock";
const OWNER: &str = ".omgs-scratch.json";
const PAYLOAD: &str = "payload";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    version: u8,
    name: String,
    identity: (u64, u64),
}

pub struct Scratch {
    root: PathBuf,
    lock: Option<File>,
    removed: bool,
    parent_handle: File,
    root_handle: File,
}
impl Scratch {
    pub fn create(kind: &str) -> Result<Self, String> {
        Self::create_checked(kind, |_| Ok(()))
    }

    pub fn create_checked(
        kind: &str,
        check: impl FnOnce(&Path) -> Result<(), String>,
    ) -> Result<Self, String> {
        let parent = platform::scratch_root().map_err(|e| e.to_string())?;
        Self::create_in(&parent, kind, check)
    }

    fn create_in(
        parent: &Path,
        kind: &str,
        check: impl FnOnce(&Path) -> Result<(), String>,
    ) -> Result<Self, String> {
        if !["gate", "sensor"].contains(&kind) {
            return Err("invalid scratch kind".into());
        }
        platform::check_private_dir(parent).map_err(|e| e.to_string())?;
        crate::runmeta::with_lock_file(&parent.join(LOCK), || {
            report(recover_in(parent)?)?;
            crate::supervise::check_interrupted().map_err(|e| e.to_string())?;
            let name = format!(
                "omgs-{kind}-{}",
                platform::random_nonce().map_err(|e| e.to_string())?
            );
            let root = parent.join(&name);
            check(&root)?;
            platform::create_private_dir_new(&root).map_err(|e| e.to_string())?;
            // The parent lock excludes recovery until the owner record and run
            // lock are published. A crash before publication remains invalid.
            let initialized = || -> Result<(File, File, File), String> {
                platform::write_private_new(&root.join(LOCK), b"").map_err(|e| e.to_string())?;
                let parent_handle = fs::open_parent(parent).map_err(|e| e.to_string())?;
                let root_handle = fs::open_root(&parent_handle, root.file_name().unwrap())
                    .map_err(|e| e.to_string())?;
                let lock = open_lock(&root_handle)?;
                lock.try_lock().map_err(|e| e.to_string())?;
                let owner = Owner {
                    version: 1,
                    name,
                    identity: platform::held_directory_identity(&root_handle)
                        .map_err(|e| e.to_string())?,
                };
                platform::write_private_new(
                    &root.join(OWNER),
                    &serde_json::to_vec(&owner).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
                platform::create_private_dir_new(&root.join(PAYLOAD)).map_err(|e| e.to_string())?;
                Ok((lock, parent_handle, root_handle))
            };
            match initialized() {
                Ok((lock, parent_handle, root_handle)) => {
                    validate_held(&root_handle, &name_for(&root)?)?;
                    Ok(Self {
                        root,
                        lock: Some(lock),
                        removed: false,
                        parent_handle,
                        root_handle,
                    })
                }
                Err(e) => {
                    // An incompletely published layout is intentionally left
                    // for inspection. Never resolve a potentially replaced root.
                    Err(e)
                }
            }
        })
    }

    pub fn path(&self) -> PathBuf {
        self.root.join(PAYLOAD)
    }

    pub fn cleanup(&mut self) -> Result<(), String> {
        self.cleanup_with(|root| fs::remove(root, std::ffi::OsStr::new(PAYLOAD)))
    }

    fn cleanup_with(
        &mut self,
        remove_payload: impl FnOnce(&File) -> std::io::Result<()>,
    ) -> Result<(), String> {
        if self.removed {
            return Ok(());
        }
        // Losing the lock is not evidence of removal. Fail closed after a
        // partial metadata teardown, including when Drop retries cleanup.
        if self.lock.is_none() {
            return Err("scratch cleanup incomplete; removal was not verified".into());
        }
        with_parent_lock(&self.parent_handle, || {
            let root = fs::pin_removal(&self.root_handle).map_err(|e| e.to_string())?;
            validate_held(&root, &name_for(&self.root)?)?;
            remove_layout(
                &self.parent_handle,
                &root,
                &self.root,
                &mut self.lock,
                &|| Ok(()),
                remove_payload,
            )
            .map_err(|e| format!("scratch cleanup failed: {e}"))?;
            self.removed = true;
            Ok(())
        })
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        if let Err(e) = self.cleanup() {
            eprintln!("{}", platform::escape_controls(&e));
        }
    }
}

fn open_lock(root: &File) -> Result<File, String> {
    #[cfg(unix)]
    let file = fs::open(root, std::ffi::OsStr::new(LOCK), false).map_err(|e| e.to_string())?;
    #[cfg(windows)]
    let file = platform::open_scratch_lock(root, Path::new(LOCK)).map_err(|e| e.to_string())?;
    if !platform::is_single_link_file(&file).map_err(|e| e.to_string())? {
        return Err("scratch lock must be a single-link regular file".into());
    }
    platform::check_private_file(&file).map_err(|e| e.to_string())?;
    Ok(file)
}
fn with_parent_lock<T>(
    parent: &File,
    body: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let lock = open_lock(parent)?;
    let start = std::time::Instant::now();
    loop {
        match lock.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock)
                if start.elapsed() < std::time::Duration::from_secs(30) =>
            {
                std::thread::sleep(std::time::Duration::from_millis(5))
            }
            Err(e) => return Err(format!("scratch parent lock unavailable: {e}")),
        }
    }
    body()
}
fn name_for(root: &Path) -> Result<String, String> {
    root.file_name()
        .and_then(|n| n.to_str())
        .map(str::to_owned)
        .ok_or_else(|| "invalid scratch name".into())
}
fn valid_name(name: &str) -> bool {
    ["omgs-gate-", "omgs-sensor-"].iter().any(|prefix| {
        name.strip_prefix(prefix)
            .is_some_and(|nonce| nonce.len() == 64 && nonce.bytes().all(|b| b.is_ascii_hexdigit()))
    })
}
fn validate_held(root: &File, name: &str) -> Result<(), String> {
    validate_held_checked(root, name, &|| Ok(()))
}
fn validate_held_checked(
    root: &File,
    name: &str,
    check: &impl Fn() -> std::io::Result<()>,
) -> Result<(), String> {
    check().map_err(|e| e.to_string())?;
    platform::check_private_dir_handle(root).map_err(|e| e.to_string())?;
    let owner_file =
        fs::open(root, std::ffi::OsStr::new(OWNER), false).map_err(|e| e.to_string())?;
    platform::check_private_file(&owner_file).map_err(|e| e.to_string())?;
    if !platform::is_single_link_file(&owner_file).map_err(|e| e.to_string())? {
        return Err("invalid owner file".into());
    }
    let bytes = platform::read_bounded_file(owner_file, 4096).map_err(|e| e.to_string())?;
    let owner: Owner = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if !valid_name(name)
        || owner.version != 1
        || owner.name != name
        || owner.identity != platform::held_directory_identity(root).map_err(|e| e.to_string())?
    {
        return Err("scratch ownership record mismatch".into());
    }
    for name in fs::names_checked(root, check).map_err(|e| e.to_string())? {
        check().map_err(|e| e.to_string())?;
        if ![LOCK, OWNER, PAYLOAD].iter().any(|n| name == *n) {
            return Err("unexpected scratch layout".into());
        }
        if name == PAYLOAD {
            let payload = fs::open(root, &name, true).map_err(|e| e.to_string())?;
            platform::check_private_dir_handle(&payload).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Report invalid/foreign entries without deleting them. Active locks are skipped.
pub fn recover() -> Result<(), String> {
    crate::supervise::check_interrupted().map_err(|e| e.to_string())?;
    let parent = platform::scratch_root().map_err(|e| e.to_string())?;
    crate::runmeta::with_lock_file_checked(
        &parent.join(LOCK),
        crate::supervise::check_interrupted,
        || {
            report(recover_in(&parent)?)?;
            Ok(())
        },
    )
}
fn report(warnings: Vec<String>) -> Result<(), String> {
    for warning in warnings {
        crate::supervise::check_interrupted().map_err(|e| e.to_string())?;
        eprintln!("{}", platform::escape_controls(&warning));
    }
    crate::supervise::check_interrupted().map_err(|e| e.to_string())
}
fn remove_layout(
    parent: &File,
    root: &File,
    path: &Path,
    lock: &mut Option<File>,
    check: &impl Fn() -> std::io::Result<()>,
    remove_payload: impl FnOnce(&File) -> std::io::Result<()>,
) -> std::io::Result<()> {
    match remove_payload(root) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    // Payload removal is resumable while both ownership files remain. Once
    // it finishes, commit the fixed-size metadata teardown without another
    // cancellation point that could strand an ownerless layout.
    check()?;
    fs::remove_file(root, std::ffi::OsStr::new(OWNER))?;
    // Retain the run lock on payload/owner failure so cleanup can safely retry.
    // A failure after taking it stays failed rather than claiming success.
    drop(lock.take());
    fs::remove_file(root, std::ffi::OsStr::new(LOCK))?;
    fs::remove_root(parent, path.file_name().unwrap(), root)
}
fn recover_in(parent: &Path) -> Result<Vec<String>, String> {
    let held = fs::open_parent(parent).map_err(|e| e.to_string())?;
    recover_held(parent, &held, &crate::supervise::check_interrupted, || {})
}
fn recover_held(
    parent: &Path,
    held: &File,
    check: &impl Fn() -> std::io::Result<()>,
    mut after_validate: impl FnMut(),
) -> Result<Vec<String>, String> {
    let mut warnings = Vec::new();
    for name in fs::names_checked(held, check).map_err(|e| e.to_string())? {
        check().map_err(|e| e.to_string())?;
        let name_text = name.to_string_lossy();
        if !name_text.starts_with("omgs-gate-") && !name_text.starts_with("omgs-sensor-") {
            continue;
        }
        let path = parent.join(&name);
        let reap = || -> Result<(), String> {
            let root = match fs::open_root(held, &name) {
                Ok(root) => root,
                // Another Windows owner pins the name without delete sharing.
                #[cfg(windows)]
                Err(e) if e.raw_os_error() == Some(32) => return Ok(()),
                Err(e) => return Err(e.to_string()),
            };
            validate_held_checked(&root, &name_text, check)?;
            let lock = open_lock(&root)?;
            match lock.try_lock() {
                Ok(()) => {}
                Err(std::fs::TryLockError::WouldBlock) => return Ok(()),
                Err(e) => return Err(e.to_string()),
            }
            let root = fs::pin_removal(&root).map_err(|e| e.to_string())?;
            validate_held_checked(&root, &name_text, check)?;
            after_validate();
            remove_layout(held, &root, &path, &mut Some(lock), check, |root| {
                fs::remove_checked(root, std::ffi::OsStr::new(PAYLOAD), check)
            })
            .map_err(|e| e.to_string())
        };
        if let Err(e) = {
            let mut reap = reap;
            reap()
        } {
            // Cancellation is incomplete recovery, never an ignorable warning.
            check().map_err(|e| e.to_string())?;
            warnings.push(format!(
                "scratch recovery left {} alone: {e}",
                path.display()
            ));
        }
    }
    check().map_err(|e| e.to_string())?;
    Ok(warnings)
}

/// Polling is a fallback, not a filesystem quota. Latch any inspection failure
/// or overrun, including transient overruns observed before final teardown.
pub struct UsageMonitor {
    pub cancellation: std::sync::Arc<std::sync::atomic::AtomicBool>,
    stop: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<Result<(), String>>>,
}
impl UsageMonitor {
    pub fn start(path: PathBuf) -> Self {
        let (stop, rx) = std::sync::mpsc::channel();
        let initial_failure = check_usage(&path, SENSOR_WRITE_BYTES, SENSOR_WRITE_ENTRIES).err();
        let cancellation = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
            initial_failure.is_some(),
        ));
        let notify = cancellation.clone();
        let thread = std::thread::spawn(move || {
            let mut failure = initial_failure;
            loop {
                if let Err(e) = check_usage(&path, SENSOR_WRITE_BYTES, SENSOR_WRITE_ENTRIES) {
                    failure.get_or_insert(e);
                    notify.store(true, std::sync::atomic::Ordering::Release);
                }
                if rx.recv_timeout(std::time::Duration::from_millis(100))
                    != Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                {
                    // Always inspect after the supervised process has stopped.
                    check_usage(&path, SENSOR_WRITE_BYTES, SENSOR_WRITE_ENTRIES)?;
                    return failure.map_or(Ok(()), Err);
                }
            }
        });
        Self {
            cancellation,
            stop: Some(stop),
            thread: Some(thread),
        }
    }
    pub fn finish(mut self) -> Result<(), String> {
        self.join()
    }
    fn join(&mut self) -> Result<(), String> {
        self.stop.take();
        self.thread.take().map_or(Ok(()), |t| {
            t.join()
                .unwrap_or_else(|_| Err("sensor scratch usage monitor failed".into()))
        })
    }
}
impl Drop for UsageMonitor {
    fn drop(&mut self) {
        let _ = self.join();
    }
}

fn check_usage(path: &Path, bytes: u64, entries: usize) -> Result<(), String> {
    usage::check(path, bytes, entries).map_err(|e| {
        let reason = match e.to_string().as_str() {
            "scratch bytes exceeded" => format!("byte limit exceeded (limit {bytes} bytes)"),
            "scratch entries exceeded" => format!("entry limit exceeded (limit {entries} entries)"),
            _ => format!("inspection unavailable (limits {bytes} bytes, {entries} entries): {e}"),
        };
        format!("writable sensor scratch {reason}; scan discarded; reduce scanner writes or repair scratch storage and retry")
    })
}

#[cfg(unix)]
mod usage {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;
    pub fn check(path: &Path, bytes: u64, entries: usize) -> io::Result<()> {
        let dir = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        walk(&dir, &mut (0, 0), (bytes, entries), 0)
    }
    fn walk(
        dir: &std::fs::File,
        used: &mut (u64, usize),
        cap: (u64, usize),
        depth: usize,
    ) -> io::Result<()> {
        if depth > 64 {
            return Err(io::Error::other("scratch depth exceeded"));
        }
        // SAFETY: duplicate a live descriptor with close-on-exec. The monitor
        // runs while MXC is spawned, so no scratch handle may leak to it.
        let fd = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is an owned directory descriptor.
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            // SAFETY: fdopendir failed without taking ownership.
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }
        struct Stream(*mut libc::DIR);
        impl Drop for Stream {
            fn drop(&mut self) {
                unsafe {
                    libc::closedir(self.0);
                }
            }
        }
        let stream = Stream(stream);
        loop {
            // SAFETY: stream remains live, and the entry is used before readdir.
            // SAFETY: errno is thread-local. Clear it to distinguish EOF from
            // a failed readdir, which must make usage inspection fail closed.
            #[cfg(target_os = "macos")]
            unsafe {
                *libc::__error() = 0;
            }
            #[cfg(target_os = "linux")]
            unsafe {
                *libc::__errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                if io::Error::last_os_error()
                    .raw_os_error()
                    .is_some_and(|e| e != 0)
                {
                    return Err(io::Error::last_os_error());
                }
                break;
            }
            // SAFETY: readdir returns a NUL-terminated name.
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
            if [b".".as_slice(), b"..".as_slice()].contains(&name.to_bytes()) {
                continue;
            }
            used.1 += 1;
            if used.1 > cap.1 {
                return Err(io::Error::other("scratch entries exceeded"));
            }
            let mut meta = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: name, dir and writable stat storage are live. Never follow links.
            if unsafe {
                libc::fstatat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    meta.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful fstatat initialized meta.
            let meta = unsafe { meta.assume_init() };
            used.0 = used.0.saturating_add(
                (meta.st_size.max(0) as u64)
                    .max((meta.st_blocks.max(0) as u64).saturating_mul(512)),
            );
            if used.0 > cap.0 {
                return Err(io::Error::other("scratch bytes exceeded"));
            }
            if meta.st_mode & libc::S_IFMT == libc::S_IFDIR {
                // SAFETY: open a child relative to the retained parent, no link traversal.
                let child = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if child < 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: child is a new owned descriptor.
                let child = unsafe { std::fs::File::from_raw_fd(child) };
                walk(&child, used, cap, depth + 1)?;
            }
        }
        Ok(())
    }
}
#[cfg(windows)]
mod usage {
    use crate::platform;

    use std::os::windows::fs::OpenOptionsExt;
    use std::{io, path::Path};
    pub fn check(path: &Path, bytes: u64, entries: usize) -> io::Result<()> {
        walk(path, &mut (0, 0), (bytes, entries), 0)
    }
    fn walk(
        path: &Path,
        used: &mut (u64, usize),
        cap: (u64, usize),
        depth: usize,
    ) -> io::Result<()> {
        if depth > 64 {
            return Err(io::Error::other("scratch depth exceeded"));
        }
        // No delete sharing: retain every ancestor until its traversal ends.
        let dir = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(3)
            .custom_flags(0x0200_0000 | 0x0020_0000)
            .open(path)?;
        if !dir.metadata()?.is_dir() || platform::is_link(&dir.metadata()?) {
            return Err(io::Error::other("scratch directory replaced"));
        }
        named_streams(path, used, cap)?;
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let meta = std::fs::symlink_metadata(entry.path())?;
            used.1 += 1;
            used.0 = used.0.saturating_add(meta.len());
            if meta.is_file() && !platform::is_link(&meta) {
                named_streams(&entry.path(), used, cap)?;
            }
            enforce(*used, cap)?;
            if meta.is_dir() && !platform::is_link(&meta) {
                walk(&entry.path(), used, cap, depth + 1)?;
            }
        }
        Ok(())
    }

    fn enforce(used: (u64, usize), cap: (u64, usize)) -> io::Result<()> {
        if used.0 > cap.0 {
            return Err(io::Error::other("scratch bytes exceeded"));
        }
        if used.1 > cap.1 {
            return Err(io::Error::other("scratch entries exceeded"));
        }
        Ok(())
    }

    // NTFS alternate streams consume scratch too. Pin the non-reparse file
    // without delete sharing before enumerating streams by its stable path.
    fn named_streams(path: &Path, used: &mut (u64, usize), cap: (u64, usize)) -> io::Result<()> {
        use std::os::windows::ffi::OsStrExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(3)
            .custom_flags(0x0220_0000)
            .open(path)?;
        if platform::is_link(&file.metadata()?) {
            return Err(io::Error::other("scratch file replaced"));
        }
        #[repr(C)]
        struct StreamData {
            size: i64,
            name: [u16; 296],
        }
        extern "system" {
            fn FindFirstStreamW(
                path: *const u16,
                level: u32,
                data: *mut StreamData,
                flags: u32,
            ) -> *mut core::ffi::c_void;
            fn FindNextStreamW(handle: *mut core::ffi::c_void, data: *mut StreamData) -> i32;
            fn FindClose(handle: *mut core::ffi::c_void) -> i32;
        }
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut data = std::mem::MaybeUninit::<StreamData>::zeroed();
        // SAFETY: path and correctly sized stream storage remain live.
        let handle = unsafe { FindFirstStreamW(wide.as_ptr(), 0, data.as_mut_ptr(), 0) };
        if handle as isize == -1 {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(38) {
                Ok(())
            } else {
                Err(error)
            };
        }
        struct Streams(*mut core::ffi::c_void);
        impl Drop for Streams {
            fn drop(&mut self) {
                unsafe {
                    FindClose(self.0);
                }
            }
        }
        let _streams = Streams(handle);
        loop {
            // SAFETY: successful FindFirstStreamW/FindNextStreamW initialized data.
            let stream = unsafe { &*data.as_ptr() };
            let end = stream
                .name
                .iter()
                .position(|c| *c == 0)
                .ok_or_else(|| io::Error::other("invalid stream name"))?;
            let name = String::from_utf16_lossy(&stream.name[..end]);
            if name != "::$DATA" {
                used.1 += 1;
                used.0 = used.0.saturating_add(stream.size.max(0) as u64);
                enforce(*used, cap)?;
            }
            // SAFETY: handle and writable data remain live throughout enumeration.
            if unsafe { FindNextStreamW(handle, data.as_mut_ptr()) } == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(38) {
                    break;
                } // ERROR_HANDLE_EOF
                return Err(error);
            }
        }
        Ok(())
    }
}
#[cfg(not(any(unix, windows)))]
mod usage {
    pub fn check(_: &std::path::Path, _: u64, _: usize) -> std::io::Result<()> {
        Err(std::io::Error::other("scratch usage unavailable"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parent() -> PathBuf {
        let parent = if cfg!(windows) {
            platform::home().unwrap()
        } else {
            platform::temp_root().unwrap()
        };
        let root = parent.join(format!(
            "omgs-scratch-test-{}",
            platform::random_nonce().unwrap()
        ));
        platform::create_private_dir_new(&root).unwrap();
        root
    }
    fn abandon(mut scratch: Scratch) -> PathBuf {
        scratch.lock.take().unwrap().unlock().unwrap();
        // Simulate termination without running the owner's Drop cleanup.
        scratch.removed = true;
        scratch.root.clone()
    }
    fn deep_payload(scratch: &Scratch) {
        let mut path = scratch.path();
        for _ in 0..160 {
            path.push("d");
            std::fs::create_dir(&path).unwrap();
        }
        std::fs::write(path.join("raw"), b"discard").unwrap();
    }
    #[test]
    fn cleanup_retries_failed_payload_removal_and_drop_retries_too() {
        let parent = parent();
        let mut scratch = Scratch::create_in(&parent, "sensor", |_| Ok(())).unwrap();
        std::fs::write(scratch.path().join("raw"), b"discard").unwrap();
        for _ in 0..2 {
            let error = scratch
                .cleanup_with(|_| Err(std::io::Error::other("injected removal failure")))
                .unwrap_err();
            assert!(error.contains("injected removal failure"), "{error}");
            assert!(scratch.path().join("raw").exists());
            assert!(scratch.lock.is_some());
            assert!(!scratch.removed);
        }
        scratch.cleanup().unwrap();
        assert!(!scratch.path().exists());
        assert!(scratch.removed);
        scratch.cleanup().unwrap();
        drop(scratch);

        let mut scratch = Scratch::create_in(&parent, "gate", |_| Ok(())).unwrap();
        let root = scratch.root.clone();
        std::fs::write(scratch.path().join("raw"), b"discard").unwrap();
        assert!(scratch
            .cleanup_with(|_| Err(std::io::Error::other("injected removal failure")))
            .is_err());
        drop(scratch);
        assert!(!root.exists());
        std::fs::remove_dir_all(parent).unwrap();
    }
    #[test]
    fn cleanup_without_lock_never_claims_verified_removal() {
        let parent = parent();
        let mut scratch = Scratch::create_in(&parent, "sensor", |_| Ok(())).unwrap();
        let lock = scratch.lock.take();
        assert!(scratch.cleanup().unwrap_err().contains("not verified"));
        assert!(scratch.path().exists());
        scratch.lock = lock;
        scratch.cleanup().unwrap();
        drop(scratch);
        std::fs::remove_dir_all(parent).unwrap();
    }
    #[test]
    fn deep_gate_and_sensor_payloads_are_removed_and_recovered() {
        let parent = parent();
        for kind in ["gate", "sensor"] {
            let mut scratch = Scratch::create_in(&parent, kind, |_| Ok(())).unwrap();
            deep_payload(&scratch);
            scratch.cleanup().unwrap();
            assert!(!scratch.path().exists());
            drop(scratch);
            let scratch = Scratch::create_in(&parent, kind, |_| Ok(())).unwrap();
            deep_payload(&scratch);
            let root = abandon(scratch);
            assert!(recover_in(&parent).unwrap().is_empty());
            assert!(!root.exists());
        }
        std::fs::remove_dir_all(parent).unwrap();
    }
    #[test]
    fn interrupted_recovery_preserves_ownership_until_payload_removal_finishes() {
        let parent = parent();
        let scratch = Scratch::create_in(&parent, "gate", |_| Ok(())).unwrap();
        let first = scratch.path().join("nested/first");
        let second = scratch.path().join("nested/second");
        std::fs::create_dir(first.parent().unwrap()).unwrap();
        std::fs::write(&first, b"discard").unwrap();
        std::fs::write(&second, b"discard").unwrap();
        let root = abandon(scratch);
        let held = fs::open_parent(&parent).unwrap();
        let owner = std::fs::read(root.join(OWNER)).unwrap();
        let timeout = || std::io::Error::new(std::io::ErrorKind::TimedOut, "deadline exceeded");
        let calls = std::cell::Cell::new(0);
        for stage in ["enumeration", "recursive removal", "metadata teardown"] {
            let error = recover_held(
                &parent,
                &held,
                &|| {
                    calls.set(calls.get() + 1);
                    let stop = match stage {
                        "enumeration" => calls.get() >= 3,
                        "recursive removal" => !first.exists() || !second.exists(),
                        _ => !root.join(PAYLOAD).exists(),
                    };
                    if stop {
                        Err(timeout())
                    } else {
                        Ok(())
                    }
                },
                || {},
            )
            .unwrap_err();
            assert!(error.contains("deadline exceeded"), "{stage}: {error}");
            assert_eq!(std::fs::read(root.join(OWNER)).unwrap(), owner);
            assert!(root.join(LOCK).is_file());
            validate_held(
                &fs::open_root(&held, root.file_name().unwrap()).unwrap(),
                &name_for(&root).unwrap(),
            )
            .unwrap();
            if stage == "enumeration" {
                assert!(first.exists() && second.exists());
            } else if stage == "recursive removal" {
                assert_ne!(first.exists(), second.exists());
            }
        }
        assert!(recover_in(&parent).unwrap().is_empty());
        assert!(!root.exists());
        drop(held);
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn recovery_reaps_abandoned_but_preserves_active_and_invalid() {
        let parent = parent();
        let abandoned = Scratch::create_in(&parent, "gate", |_| Ok(())).unwrap();
        std::fs::write(abandoned.path().join("raw"), "discard me").unwrap();
        let abandoned_path = abandoned.root.clone();
        // Explicitly free the simulated owner's lock. Concurrent process-spawn
        // tests can briefly inherit a forked descriptor before close-on-exec.
        abandon(abandoned);
        let active = Scratch::create_in(&parent, "sensor", |_| Ok(())).unwrap();
        assert!(!abandoned_path.exists());
        let invalid = parent.join(format!("omgs-gate-{}", platform::random_nonce().unwrap()));
        platform::create_private_dir_new(&invalid).unwrap();
        std::fs::write(invalid.join("foreign"), "preserve me").unwrap();
        let warnings =
            crate::runmeta::with_lock_file(&parent.join(LOCK), || recover_in(&parent)).unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("scratch recovery left"));
        assert!(active.path().is_dir());
        assert!(invalid.join("foreign").is_file());
        drop(active);
        std::fs::remove_dir_all(parent).unwrap();
    }
    #[test]
    fn recovery_refuses_unexpected_layout_and_copied_owner_record() {
        let parent = parent();
        let unexpected = Scratch::create_in(&parent, "gate", |_| Ok(())).unwrap();
        std::fs::write(unexpected.root.join("foreign"), "preserve").unwrap();

        let copied = Scratch::create_in(&parent, "sensor", |_| Ok(())).unwrap();
        let bytes = std::fs::read(unexpected.root.join(OWNER)).unwrap();
        crate::runmeta::write_atomic_bytes(&copied.root.join(OWNER), &bytes).unwrap();
        let unexpected = abandon(unexpected);
        let copied = abandon(copied);
        crate::runmeta::with_lock_file(&parent.join(LOCK), || recover_in(&parent)).unwrap();
        assert!(unexpected.join("foreign").is_file());
        assert!(copied.is_dir());
        std::fs::remove_dir_all(parent).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn recovery_does_not_follow_root_or_payload_links() {
        use std::os::unix::fs::symlink;
        let parent = parent();
        let outside = parent.join("outside");
        platform::create_private_dir_new(&outside).unwrap();
        std::fs::write(outside.join("keep"), "keep").unwrap();
        let link = parent.join(format!("omgs-gate-{}", platform::random_nonce().unwrap()));
        symlink(&outside, &link).unwrap();
        let scratch = Scratch::create_in(&parent, "sensor", |_| Ok(())).unwrap();
        std::fs::remove_dir(scratch.path()).unwrap();
        symlink(&outside, scratch.path()).unwrap();
        let scratch = abandon(scratch);
        recover_in(&parent).unwrap();
        assert!(std::fs::symlink_metadata(link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(scratch.exists());
        assert_eq!(std::fs::read(outside.join("keep")).unwrap(), b"keep");
        std::fs::remove_dir_all(parent).unwrap();
    }
    fn swap_after_final_validation(active_swap: bool) {
        let parent = parent();
        let outside = parent.join("outside");
        platform::create_private_dir_new(&outside).unwrap();
        platform::create_private_dir_new(&outside.join(PAYLOAD)).unwrap();
        std::fs::write(outside.join("payload/keep"), b"outside").unwrap();
        let abandoned = abandon(Scratch::create_in(&parent, "gate", |_| Ok(())).unwrap());
        let active = Scratch::create_in(&outside, "sensor", |_| Ok(())).unwrap();
        std::fs::write(active.path().join("keep"), b"active").unwrap();
        let held = fs::open_parent(&parent).unwrap();
        let moved = parent.join("admitted-moved");
        let mut attempted = false;
        let mut swapped = false;
        let warnings = recover_held(&parent, &held, &|| Ok(()), || {
            attempted = true;
            match std::fs::rename(&abandoned, &moved) {
                Ok(()) => {}
                // Windows pins the directory name until handle-based deletion.
                #[cfg(windows)]
                Err(e) if [Some(5), Some(32)].contains(&e.raw_os_error()) => return,
                Err(e) => panic!("rename: {e}"),
            }
            if active_swap {
                std::fs::rename(&active.root, &abandoned).unwrap();
            } else {
                #[cfg(unix)]
                std::os::unix::fs::symlink(&outside, &abandoned).unwrap();
                #[cfg(windows)]
                assert!(std::process::Command::new("cmd")
                    .args(["/c", "mklink", "/J"])
                    .arg(&abandoned)
                    .arg(&outside)
                    .status()
                    .unwrap()
                    .success());
            }
            swapped = true;
        })
        .unwrap();
        assert!(attempted);
        #[cfg(unix)]
        assert!(swapped && !warnings.is_empty());
        #[cfg(windows)]
        assert!(!swapped && warnings.is_empty());
        assert_eq!(
            std::fs::read(outside.join("payload/keep")).unwrap(),
            b"outside"
        );
        if active_swap && swapped {
            assert_eq!(
                std::fs::read(abandoned.join("payload/keep")).unwrap(),
                b"active"
            );
            std::fs::rename(&abandoned, &active.root).unwrap();
        } else {
            assert_eq!(
                std::fs::read(active.path().join("keep")).unwrap(),
                b"active"
            );
        }
        drop(held);
        drop(active);
        std::fs::remove_dir_all(parent).unwrap();
    }
    #[test]
    fn final_validation_swap_to_outside_link_preserves_payload() {
        swap_after_final_validation(false);
    }
    #[test]
    fn final_validation_swap_to_active_scratch_preserves_payload() {
        swap_after_final_validation(true);
    }

    #[test]
    fn writable_usage_enforces_bytes_entries_and_monitor_latches_overruns() {
        let parent = parent();
        let path = parent.join("work");
        platform::create_private_dir_new(&path).unwrap();
        assert!(check_usage(&path, 1 << 20, 10).is_ok());
        std::fs::write(path.join("one"), vec![0; 8192]).unwrap();
        assert!(check_usage(&path, 4096, 10)
            .unwrap_err()
            .contains("byte limit exceeded (limit 4096 bytes)"));
        assert!(check_usage(&path, 1 << 20, 0)
            .unwrap_err()
            .contains("entry limit exceeded (limit 0 entries)"));
        assert!(check_usage(&path.join("missing"), 4096, 10)
            .unwrap_err()
            .contains("inspection unavailable (limits 4096 bytes, 10 entries)"));
        let file = File::create(path.join("large")).unwrap();
        file.set_len(SENSOR_WRITE_BYTES + 1).unwrap();
        let monitor = UsageMonitor::start(path.clone());
        // The initial sample observes the overrun, even though the final one
        // will see a clean tree.
        std::fs::remove_file(path.join("large")).unwrap();
        assert!(monitor.finish().is_err());
        std::fs::remove_dir_all(parent).unwrap();
    }
}

#[cfg(test)]
mod process_tests {
    use super::*;
    #[test]
    #[ignore = "subprocess helper invoked by crash_recovery_after_owner_kill"]
    fn scratch_owner_process() {
        let parent = PathBuf::from(std::env::var_os("OMGS_TEST_SCRATCH_PARENT").unwrap());
        let scratch = Scratch::create_in(&parent, "sensor", |_| Ok(())).unwrap();
        let mut path = scratch.path();
        for _ in 0..160 {
            path.push("d");
            std::fs::create_dir(&path).unwrap();
        }
        std::fs::write(path.join("raw"), "discard").unwrap();
        std::fs::write(parent.join("ready"), b"ready").unwrap();
        loop {
            std::thread::park();
        }
    }
    #[cfg(unix)]
    #[test]
    fn deep_cleanup_with_low_descriptor_limit() {
        const CHILD: &str = "OMGS_TEST_LOW_FD_CLEANUP";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "scratch::process_tests::deep_cleanup_with_low_descriptor_limit",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) },
            0
        );
        let mut limit = unsafe { limit.assume_init() };
        limit.rlim_cur = limit.rlim_cur.min(64);
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        let parent = platform::temp_root()
            .unwrap()
            .join(format!("omgs-low-fd-{}", platform::random_nonce().unwrap()));
        platform::create_private_dir_new(&parent).unwrap();
        let mut scratch = Scratch::create_in(&parent, "sensor", |_| Ok(())).unwrap();
        let mut path = scratch.path();
        for _ in 0..300 {
            path.push("d");
            std::fs::create_dir(&path).unwrap();
        }
        std::fs::write(path.join("raw"), b"discard").unwrap();
        scratch.cleanup().unwrap();
        assert!(!scratch.path().exists());
        drop(scratch);
        std::fs::remove_dir_all(parent).unwrap();
    }
    #[test]
    fn crash_recovery_after_owner_kill() {
        use std::process::Command;
        use std::time::{Duration, Instant};
        let parent = if cfg!(windows) {
            platform::home().unwrap()
        } else {
            platform::temp_root().unwrap()
        };
        let parent = parent.join(format!(
            "omgs-crash-test-{}",
            platform::random_nonce().unwrap()
        ));
        platform::create_private_dir_new(&parent).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "scratch::process_tests::scratch_owner_process",
                "--ignored",
            ])
            .env("OMGS_TEST_SCRATCH_PARENT", &parent)
            .spawn()
            .unwrap();
        let start = Instant::now();
        while !parent.join("ready").exists() {
            assert!(start.elapsed() < Duration::from_secs(15));
            assert!(child.try_wait().unwrap().is_none());
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            crate::runmeta::with_lock_file(&parent.join(LOCK), || recover_in(&parent))
                .unwrap()
                .is_empty()
        );
        assert!(std::fs::read_dir(&parent).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("omgs-sensor-")));
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(
            crate::runmeta::with_lock_file(&parent.join(LOCK), || recover_in(&parent))
                .unwrap()
                .is_empty()
        );
        assert!(!std::fs::read_dir(&parent).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("omgs-sensor-")));
        std::fs::remove_dir_all(parent).unwrap();
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    #[test]
    fn writable_usage_counts_directory_streams_including_root() {
        let parent = crate::platform::home().unwrap().join(format!(
            "omgs-dir-stream-test-{}",
            crate::platform::random_nonce().unwrap()
        ));
        crate::platform::create_private_dir_new(&parent).unwrap();
        let nested = parent.join("nested");
        crate::platform::create_private_dir_new(&nested).unwrap();
        assert!(super::check_usage(&parent, 32768, 10).is_ok());
        for dir in [&parent, &nested] {
            let stream = std::path::PathBuf::from(format!("{}:extra", dir.display()));
            std::fs::write(&stream, vec![0; 8192]).unwrap();
            assert!(super::check_usage(&parent, 4096, 10)
                .unwrap_err()
                .contains("byte limit exceeded (limit 4096 bytes)"));
            assert!(super::check_usage(&parent, 32768, 1)
                .unwrap_err()
                .contains("entry limit exceeded (limit 1 entries)"));
            std::fs::remove_file(stream).unwrap();
        }
        std::fs::remove_dir_all(parent).unwrap();
    }
    #[test]
    fn writable_usage_counts_alternate_streams() {
        let parent = crate::platform::home().unwrap().join(format!(
            "omgs-stream-test-{}",
            crate::platform::random_nonce().unwrap()
        ));
        crate::platform::create_private_dir_new(&parent).unwrap();
        std::fs::write(parent.join("file"), b"x").unwrap();
        std::fs::write(parent.join("file:extra"), vec![0; 8192]).unwrap();
        assert!(super::check_usage(&parent, 4096, 10).is_err());
        assert!(super::check_usage(&parent, 16384, 10).is_ok());
        std::fs::remove_dir_all(parent).unwrap();
    }
}
