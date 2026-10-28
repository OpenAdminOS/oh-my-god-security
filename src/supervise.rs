use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Limits {
    pub wall_ms: u64,
    pub cpu_secs: Option<u64>,
    pub file_size_bytes: Option<u64>,
    pub open_files: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub tasks: Option<u64>,
    pub output_cap_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct SweepMarkers {
    pub allowed: PathBuf,
    pub denied: PathBuf,
}

#[derive(Debug, Clone)]
pub struct Survivor {
    pub pid: i32,
    pub command: String,
}

#[derive(Debug, Clone)]
pub struct Supervised {
    pub exit_code: Option<i32>,
    /// Executor status is independent of the wrapper-reported workload status.
    pub executor_exit_code: Option<i32>,
    pub command_started: bool,
    pub command_finished: bool,
    pub test_reachable: Option<bool>,
    pub boundary_marker_seen: bool,
    pub authorized_control_seen: bool,
    pub enumerate_rejected: bool,
    pub success: bool,
    pub timed_out: bool,
    pub executor_error: bool,
    pub killed: bool,
    pub interrupted: bool,
    pub duration_ms: u64,
    pub output: String,
    pub stdout: String,
    pub output_bytes_total: u64,
    pub capture_complete: bool,
    /// Every group signal, reap and survivor scan succeeded. False means the
    /// run cannot vouch that nothing it started is still running.
    pub cleanup_complete: bool,
    pub survivors: Vec<Survivor>,
    pub enforced: Vec<String>,
    pub notes: Vec<String>,
}

const POLL: Duration = Duration::from_millis(10);
#[cfg(unix)]
const TERM_GRACE: Duration = Duration::from_millis(150);
const DRAIN: Duration = Duration::from_secs(2);

#[cfg(unix)]
pub mod interruption {
    use super::*;
    use std::sync::atomic::AtomicI32;
    use std::sync::{Mutex, MutexGuard};

    static SIGNAL: AtomicI32 = AtomicI32::new(0);
    static LOCK: Mutex<()> = Mutex::new(());
    thread_local! { static DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

    extern "C" fn handler(number: libc::c_int) {
        SIGNAL.store(number, Ordering::Relaxed);
    }

    pub fn pending() -> bool {
        DEPTH.with(|d| d.get() != 0) && SIGNAL.load(Ordering::Relaxed) != 0
    }

    pub struct Guard {
        previous: Vec<(libc::c_int, libc::sigaction)>,
        _lock: Option<MutexGuard<'static, ()>>,
    }

    impl Guard {
        pub fn install() -> io::Result<Self> {
            if DEPTH.with(|d| d.get() != 0) {
                DEPTH.with(|d| d.set(d.get() + 1));
                return Ok(Self {
                    previous: Vec::new(),
                    _lock: None,
                });
            }
            let lock = LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
            let mut guard = Self {
                previous: Vec::new(),
                _lock: Some(lock),
            };
            DEPTH.with(|d| d.set(1));
            SIGNAL.store(0, Ordering::Relaxed);
            for number in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
                // SAFETY: zero is a valid initial sigaction before its fields are set.
                let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
                // SAFETY: sigaction fills this initialized writable structure.
                let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
                action.sa_sigaction = handler as *const () as usize;
                // SAFETY: sa_mask is a valid writable signal set.
                unsafe { libc::sigemptyset(&mut action.sa_mask) };
                // SAFETY: both structures live through the call; handler only stores an atomic.
                if unsafe { libc::sigaction(number, &action, &mut old) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                guard.previous.push((number, old));
            }
            Ok(guard)
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            DEPTH.with(|d| d.set(d.get() - 1));
            for (number, old) in &self.previous {
                // SAFETY: old is the saved action for this signal, protected by LOCK.
                unsafe { libc::sigaction(*number, old, std::ptr::null_mut()) };
            }
        }
    }
}

#[cfg(windows)]
pub mod interruption {
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    static SIGNAL: AtomicBool = AtomicBool::new(false);
    static LOCK: Mutex<()> = Mutex::new(());
    thread_local! { static DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
        fn GetConsoleCP() -> u32;
        fn AllocConsole() -> i32;
        fn FreeConsole() -> i32;
        fn GenerateConsoleCtrlEvent(event: u32, group: u32) -> i32;
    }
    unsafe extern "system" fn handler(event: u32) -> i32 {
        if matches!(event, 0 | 1 | 2 | 5 | 6) {
            SIGNAL.store(true, Ordering::Relaxed);
            1
        } else {
            0
        }
    }
    pub fn pending() -> bool {
        DEPTH.with(|d| d.get() != 0) && SIGNAL.load(Ordering::Relaxed)
    }
    pub struct Guard {
        _lock: Option<MutexGuard<'static, ()>>,
        allocated: bool,
    }
    impl Guard {
        pub fn install() -> io::Result<Self> {
            if DEPTH.with(|d| d.get() != 0) {
                DEPTH.with(|d| d.set(d.get() + 1));
                return Ok(Self {
                    _lock: None,
                    allocated: false,
                });
            }
            let lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
            // SSH and CI can lack a console; the executor must share one for Ctrl+Break.
            let allocated = unsafe { GetConsoleCP() == 0 };
            if allocated && unsafe { AllocConsole() } == 0 {
                return Err(io::Error::last_os_error());
            }
            if unsafe { SetConsoleCtrlHandler(Some(handler), 1) } == 0 {
                let error = io::Error::last_os_error();
                if allocated {
                    unsafe { FreeConsole() };
                }
                return Err(error);
            }
            SIGNAL.store(false, Ordering::Relaxed);
            DEPTH.with(|d| d.set(1));
            Ok(Self {
                _lock: Some(lock),
                allocated,
            })
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            DEPTH.with(|d| d.set(d.get() - 1));
            if self._lock.is_some() {
                unsafe { SetConsoleCtrlHandler(Some(handler), 0) };
                if self.allocated {
                    unsafe { FreeConsole() };
                }
            }
        }
    }
    #[cfg(test)]
    pub(crate) fn request_for_test() {
        SIGNAL.store(true, Ordering::Relaxed);
    }

    pub fn stop(group: u32) -> io::Result<()> {
        if unsafe { GenerateConsoleCtrlEvent(1, group) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

// Assign the owner itself before spawning, so children inherit lifetime ownership
// from creation, including descendants in MXC's nested job. The unnamed handle is
// non-inheritable and retained until process teardown, never closed during a run.
#[cfg(windows)]
mod owner_job {
    use std::ffi::c_void;
    use std::sync::OnceLock;

    #[repr(C)]
    #[derive(Default)]
    struct BasicLimits {
        process_time: i64,
        job_time: i64,
        flags: u32,
        minimum_working_set: usize,
        maximum_working_set: usize,
        active_processes: u32,
        affinity: usize,
        priority: u32,
        scheduling: u32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct ExtendedLimits {
        basic: BasicLimits,
        io_counters: [u64; 6],
        process_memory: usize,
        job_memory: usize,
        peak_process_memory: usize,
        peak_job_memory: usize,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateJobObjectW(attributes: *const c_void, name: *const u16) -> *mut c_void;
        fn SetInformationJobObject(
            job: *mut c_void,
            class: i32,
            info: *const c_void,
            size: u32,
        ) -> i32;
        fn AssignProcessToJobObject(job: *mut c_void, process: *mut c_void) -> i32;
        fn GetCurrentProcess() -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    pub fn ensure() -> Result<(), String> {
        static OWNER: OnceLock<Result<(), String>> = OnceLock::new();
        OWNER
            .get_or_init(|| {
                // Null security attributes make the sole job handle non-inheritable.
                let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
                if job.is_null() {
                    return Err(std::io::Error::last_os_error().to_string());
                }
                let mut limits = ExtendedLimits::default();
                limits.basic.flags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                let configured = unsafe {
                    SetInformationJobObject(
                        job,
                        9,
                        (&limits as *const ExtendedLimits).cast(),
                        std::mem::size_of::<ExtendedLimits>() as u32,
                    )
                };
                if configured == 0
                    || unsafe { AssignProcessToJobObject(job, GetCurrentProcess()) } == 0
                {
                    let error = std::io::Error::last_os_error().to_string();
                    unsafe { CloseHandle(job) };
                    return Err(error);
                }
                // Closing this handle would also kill OMGS. Process teardown closes
                // it even after TerminateProcess, killing all remaining descendants.
                Ok(())
            })
            .clone()
    }
}

/// Preparation loops cooperate with the same guard as executor supervision.
pub fn check_interrupted() -> io::Result<()> {
    #[cfg(any(unix, windows))]
    if interruption::pending() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "proof interrupted before execution",
        ));
    }
    Ok(())
}

enum Message {
    Data(usize, Vec<u8>),
    Done(usize, Option<String>),
}

struct Capture {
    streams: [Vec<u8>; 2],
    done: [bool; 2],
    healthy: bool,
    total: u64,
    cap: usize,
    evidence: MarkerScan,
}

#[derive(Default)]
struct MarkerScan {
    nonce: Option<String>,
    expect_marker: Option<String>,
    boundary_marker_seen: bool,
    authorized_control_seen: bool,
    lines: [Vec<u8>; 2],
    overflow: [bool; 2],
    started: bool,
    finished: bool,
    exit_code: Option<i32>,
    test_reachable: Option<bool>,
    invalid: bool,
    enumerate_rejected: bool,
}

impl MarkerScan {
    fn receive(&mut self, stream: usize, bytes: &[u8]) {
        for &byte in bytes {
            if byte == b'\n' {
                self.line(stream);
            } else if self.lines[stream].len() < 4096 {
                self.lines[stream].push(byte);
            } else {
                self.overflow[stream] = true;
            }
        }
    }

    fn line(&mut self, stream: usize) {
        let bytes = std::mem::take(&mut self.lines[stream]);
        let overflow = std::mem::replace(&mut self.overflow[stream], false);
        if overflow {
            return;
        }
        let line = String::from_utf8_lossy(&bytes);
        let line = line.trim_end_matches('\r');
        if let (Some(marker), Some(nonce)) = (&self.expect_marker, &self.nonce) {
            self.boundary_marker_seen |= line == crate::proof::boundary_marker(marker, nonce);
            self.authorized_control_seen |= line == crate::proof::control_marker(nonce);
        }
        let lower = line.to_ascii_lowercase();
        if stream == 1
            && lower.contains("enumeratepaths")
            && (lower.starts_with("request error")
                || lower.starts_with("error:")
                || lower.starts_with("{\"error\":"))
        {
            self.enumerate_rejected = true;
        }
        let Some(nonce) = &self.nonce else { return };
        if line == format!("OMGS_START_{nonce}") {
            self.invalid |= self.started || self.finished;
            self.started = true;
        }
        if let Some(value) = line.strip_prefix(&format!("OMGS_TEST_{nonce}:")) {
            self.invalid |= !self.started || self.finished || self.test_reachable.is_some();
            self.test_reachable = match value {
                "1" => Some(true),
                "0" => Some(false),
                _ => {
                    self.invalid = true;
                    None
                }
            };
        }
        if let Some(code) = line.strip_prefix(&format!("OMGS_END_{nonce}:")) {
            self.invalid |= !self.started || self.finished;
            self.finished = true;
            self.exit_code = code.parse::<i32>().ok();
            self.invalid |= self.exit_code.is_none();
        }
    }
}

impl Capture {
    fn receive(&mut self, message: Message, notes: &mut Vec<String>) {
        match message {
            Message::Data(stream, bytes) => {
                self.evidence.receive(stream, &bytes);
                self.total = self.total.saturating_add(bytes.len() as u64);
                // Retain the stdout prefix first, irrespective of reader scheduling.
                let available = if stream == 0 {
                    self.cap.saturating_sub(self.streams[0].len())
                } else {
                    self.cap
                        .saturating_sub(self.streams[0].len())
                        .saturating_sub(self.streams[1].len())
                };
                let keep = available.min(bytes.len());
                if self.streams[stream].try_reserve(keep).is_ok() {
                    self.streams[stream].extend_from_slice(&bytes[..keep]);
                } else {
                    if self.healthy {
                        notes.push("output capture allocation failed".into());
                    }
                    self.healthy = false;
                }
                if stream == 0 {
                    let remaining = self.cap.saturating_sub(self.streams[0].len());
                    self.streams[1].truncate(remaining);
                }
            }
            Message::Done(stream, error) => {
                self.done[stream] = true;
                if let Some(error) = error {
                    self.healthy = false;
                    notes.push(format!("output stream {stream}: {error}"));
                }
            }
        }
    }

    fn drain(&mut self, rx: &mpsc::Receiver<Message>, notes: &mut Vec<String>) {
        // A busy writer must not starve the wall clock check.
        for _ in 0..64 {
            match rx.try_recv() {
                Ok(message) => self.receive(message, notes),
                Err(_) => break,
            }
        }
    }

    fn text(mut self) -> String {
        let mut bytes = std::mem::take(&mut self.streams[0]);
        bytes.extend_from_slice(&self.streams[1]);
        let mut text = String::from_utf8_lossy(&bytes).into_owned();
        let mut end = self.cap.min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text
    }
}

fn reader<R: Read + Send + 'static>(
    mut pipe: R,
    stream: usize,
    tx: mpsc::SyncSender<Message>,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    std::thread::Builder::new()
        .name(format!("omgs-capture-{stream}"))
        .spawn(move || {
            let mut buffer = [0u8; 8192];
            let error = loop {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                match pipe.read(&mut buffer) {
                    Ok(0) => break None,
                    Ok(n) => {
                        if tx
                            .send(Message::Data(stream, buffer[..n].to_vec()))
                            .is_err()
                        {
                            return;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(POLL);
                    }
                    Err(error) => break Some(error.to_string()),
                }
            };
            let _ = tx.send(Message::Done(stream, error));
        })
        .map(|_| ())
}

// Ignore HOME, TMPDIR and OMGS_HOME: each may point into a readable grant.
// Darwin supplies a per-user directory that the pinned Seatbelt baseline denies.
#[cfg(target_os = "macos")]
pub(crate) fn capture_root() -> io::Result<PathBuf> {
    use std::os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, MetadataExt},
    };
    let mut bytes = vec![0u8; 4096];
    // SAFETY: confstr writes at most the supplied buffer length.
    let size = unsafe {
        libc::confstr(
            libc::_CS_DARWIN_USER_TEMP_DIR,
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if size == 0 || size > bytes.len() {
        return Err(io::Error::other(
            "Darwin private temp directory unavailable",
        ));
    }
    let base = std::fs::canonicalize(std::path::Path::new(std::ffi::OsStr::from_bytes(
        &bytes[..size - 1],
    )))?;
    // This allowlist excludes every baseline-readable root, including /opt and
    // /usr/local, and fails closed if Darwin changes its directory layout.
    if !base.starts_with("/private/var/folders") {
        return Err(io::Error::other(
            "Darwin private temp directory is outside /private/var/folders",
        ));
    }
    let dir = base.join("omgs-capture");
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let meta = std::fs::symlink_metadata(&dir)?;
    // SAFETY: geteuid has no preconditions.
    if !meta.is_dir()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o777 != 0o700
        || std::fs::canonicalize(&dir)? != dir
    {
        return Err(io::Error::other(
            "unsafe capture directory ownership, mode or canonical location",
        ));
    }
    let roots = crate::sandbox::toolchain_roots("macos", crate::platform::home().as_deref());
    validate_capture_grants(
        &dir,
        &roots.into_iter().filter(|p| p.exists()).collect::<Vec<_>>(),
    )?;
    Ok(dir)
}

#[cfg(target_os = "macos")]
pub(crate) fn validate_capture_grants(
    root: &std::path::Path,
    grants: &[PathBuf],
) -> io::Result<()> {
    for grant in grants {
        let grant = std::fs::canonicalize(grant)?;
        if root.starts_with(&grant) || grant.starts_with(root) {
            return Err(io::Error::other(format!(
                "capture directory overlaps sandbox grant {}",
                grant.display()
            )));
        }
    }
    Ok(())
}

// Darwin's pipe()+fcntl() is not atomic against unrelated concurrent spawns.
// Open anonymous FIFOs with O_CLOEXEC atomically instead, then unlink them.
#[cfg(target_os = "macos")]
fn capture_pipe() -> io::Result<(std::fs::File, std::fs::File)> {
    use std::ffi::CString;
    use std::os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, OpenOptionsExt},
    };
    let dir = capture_root()?.join(format!("pipe-{}", crate::platform::random_nonce()?));
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    let path = dir.join("pipe");
    let result = (|| {
        let name = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in temp path"))?;
        // SAFETY: name is NUL terminated; the parent is private to this run.
        if unsafe { libc::mkfifo(name.as_ptr(), 0o600) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // std's Unix File opens set O_CLOEXEC in open(), without a race.
        let read = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(&path)?;
        let write = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        Ok((read, write))
    })();
    let unlink = std::fs::remove_file(&path);
    let remove = std::fs::remove_dir(&dir);
    let pair = result?;
    unlink?;
    remove?;
    Ok(pair)
}

#[cfg(unix)]
fn nonblocking(pipe: &impl std::os::fd::AsRawFd) -> io::Result<()> {
    let fd = pipe.as_raw_fd();
    // SAFETY: pipe owns fd throughout both fcntl calls.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    // SAFETY: F_SETFL takes integer flags for this live descriptor.
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn pause(
    rx: &mpsc::Receiver<Message>,
    capture: &mut Capture,
    notes: &mut Vec<String>,
    duration: Duration,
) {
    let start = Instant::now();
    while start.elapsed() < duration {
        let remaining = duration.saturating_sub(start.elapsed());
        match rx.recv_timeout(remaining.min(POLL)) {
            Ok(message) => capture.receive(message, notes),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                std::thread::sleep(remaining);
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

#[cfg(unix)]
fn prepare_unix(cmd: &mut Command, limits: &Limits) -> io::Result<Vec<String>> {
    use std::os::unix::process::CommandExt;

    let settings = [
        (libc::RLIMIT_CPU, limits.cpu_secs, "rlimit_cpu", "s"),
        (
            libc::RLIMIT_FSIZE,
            limits.file_size_bytes,
            "rlimit_fsize",
            "B",
        ),
        (libc::RLIMIT_NOFILE, limits.open_files, "rlimit_nofile", ""),
    ];
    let mut enforced = vec!["process_group".into()];
    for (_, value, name, suffix) in settings {
        if let Some(value) = value {
            if u128::from(value) >= libc::RLIM_INFINITY as u128 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{name}={value} is not a finite rlimit"),
                ));
            }
            enforced.push(format!("{name}={value}{suffix}"));
        }
    }
    #[cfg(target_os = "macos")]
    let descriptor_bound = unsafe { libc::getdtablesize() };
    cmd.process_group(0);
    // SAFETY: all data is prepared before fork; the callback uses only fcntl, setrlimit
    // and errno access, which do not acquire Rust locks or allocate on success.
    unsafe {
        cmd.pre_exec(move || {
            // Darwin has no pipe2(O_CLOEXEC). A concurrent spawn can fork
            // between pipe() and fcntl(FD_CLOEXEC), inheriting another run's
            // write end. Seal all non-stdio descriptors in the child before
            // exec, including Rust's exec-error pipe (already CLOEXEC).
            // Do this before lowering RLIMIT_NOFILE, which could hide fds.
            #[cfg(target_os = "macos")]
            for fd in 3..descriptor_bound {
                if libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0
                    && io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
                {
                    return Err(io::Error::last_os_error());
                }
            }
            for (resource, value, _, _) in settings {
                if let Some(value) = value {
                    let limit = libc::rlimit {
                        rlim_cur: value as libc::rlim_t,
                        rlim_max: value as libc::rlim_t,
                    };
                    if libc::setrlimit(resource, &limit) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
            }
            Ok(())
        });
    }
    Ok(enforced)
}

#[cfg(unix)]
fn exited_without_reaping(pid: u32) -> io::Result<bool> {
    // SAFETY: zero initializes the output storage required by waitid.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: info is writable and pid names our child; WNOWAIT retains it.
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: waitid succeeded and initialized the siginfo pid field.
    Ok(unsafe { info.si_pid() } != 0)
}

#[cfg(unix)]
fn signal(pid: i32, number: i32, notes: &mut Vec<String>) -> bool {
    // SAFETY: kill accepts a numeric pid or negative process group id.
    if unsafe { libc::kill(pid, number) } == 0 {
        return true;
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return true;
    }
    #[cfg(target_os = "macos")]
    if pid < 0 && error.raw_os_error() == Some(libc::EPERM) {
        // Darwin returns EPERM when a group contains only its retained zombie.
        match sweep::group_has_live_processes(-pid) {
            Ok(false) => return true,
            Ok(true) => {}
            Err(error) => notes.push(format!("checking process group {} failed: {error}", -pid)),
        }
    }
    notes.push(format!("signal {number} to {pid} failed: {error}"));
    false
}

struct Waited {
    status: Option<ExitStatus>,
    timed_out: bool,
    interrupted: bool,
    healthy: bool,
}

fn wait(
    child: &mut Child,
    wall_ms: u64,
    check_signals: bool,
    rx: &mpsc::Receiver<Message>,
    capture: &mut Capture,
    notes: &mut Vec<String>,
) -> Waited {
    #[cfg(not(any(unix, windows)))]
    let _ = check_signals;
    let start = Instant::now();
    let mut waited = Waited {
        status: None,
        timed_out: false,
        interrupted: false,
        healthy: true,
    };
    #[cfg(unix)]
    let mut owns_leader = true;
    loop {
        capture.drain(rx, notes);
        #[cfg(any(unix, windows))]
        if check_signals && interruption::pending() {
            waited.interrupted = true;
            notes.push("proof interrupted; executor cleanup required".into());
            break;
        }
        #[cfg(unix)]
        let status = exited_without_reaping(child.id());
        #[cfg(not(unix))]
        let status = child.try_wait().map(|status| {
            waited.status = status;
            waited.status.is_some()
        });
        match status {
            Ok(true) => break,
            Ok(false) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                #[cfg(unix)]
                {
                    owns_leader = error.raw_os_error() != Some(libc::ECHILD);
                }
                notes.push(format!("waiting for executor failed: {error}"));
                waited.healthy = false;
                break;
            }
        }
        if start.elapsed() >= Duration::from_millis(wall_ms) {
            waited.timed_out = true;
            break;
        }
        pause(rx, capture, notes, POLL);
    }

    #[cfg(unix)]
    if owns_leader {
        if let Ok(pid) = i32::try_from(child.id()) {
            waited.healthy &= signal(-pid, libc::SIGTERM, notes);
            pause(rx, capture, notes, TERM_GRACE);
            waited.healthy &= signal(-pid, libc::SIGKILL, notes);
            // Also reach an executor that changed its own process group.
            waited.healthy &= signal(pid, libc::SIGKILL, notes);
        } else {
            notes.push("executor pid does not fit a process group id".into());
            waited.healthy = false;
        }
    }
    #[cfg(windows)]
    if waited.status.is_none() {
        match interruption::stop(child.id()) {
            Ok(()) => notes.push("Windows executor shutdown: Ctrl+Break requested; allowing 5000ms for MXC cleanup".into()),
            Err(e) => notes.push(format!("Windows executor shutdown: Ctrl+Break request failed: {e}; allowing 5000ms before forced termination")),
        }
        let grace = Instant::now();
        while grace.elapsed() < Duration::from_secs(5) {
            match child.try_wait() {
                Ok(Some(status)) => {
                    waited.status = Some(status);
                    break;
                }
                Ok(None) => pause(rx, capture, notes, POLL),
                Err(e) => {
                    notes.push(format!("Windows executor shutdown: grace wait failed: {e}"));
                    break;
                }
            }
        }
        if waited.status.is_some() {
            notes.push(
                "Windows executor shutdown: exited during cleanup grace; no forced termination"
                    .into(),
            );
        } else {
            waited.healthy = false;
            notes.push("Windows executor shutdown: forced termination after cleanup grace; MXC DACL restoration not assured until next startup".into());
        }
    }
    #[cfg(not(unix))]
    if waited.status.is_none() {
        if let Err(error) = child.kill() {
            notes.push(format!("killing executor failed: {error}"));
            waited.healthy = false;
        }
    }

    let reap = Instant::now();
    while waited.status.is_none() {
        match child.try_wait() {
            Ok(Some(status)) => waited.status = Some(status),
            Ok(None) if reap.elapsed() < Duration::from_secs(1) => {
                pause(rx, capture, notes, POLL);
            }
            Ok(None) => {
                notes.push("executor was not reaped within 1000ms after cleanup".into());
                waited.healthy = false;
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                notes.push(format!("reaping executor failed: {error}"));
                waited.healthy = false;
                break;
            }
        }
    }
    waited
}

#[cfg(target_os = "linux")]
mod cgroup {
    use super::*;
    use std::ffi::{OsStr, OsString};
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn executable(path: &Path) -> bool {
        path.metadata()
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }

    fn find(name: &str) -> Option<PathBuf> {
        std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .filter(|p| p.is_absolute())
                .map(|p| p.join(name))
                .find(|p| executable(p))
        })
    }

    pub(super) fn wrap(
        cmd: Command,
        limits: &Limits,
        notes: &mut Vec<String>,
    ) -> (Command, Vec<String>) {
        if limits.memory_bytes.is_none() && limits.tasks.is_none() {
            return (cmd, Vec::new());
        }
        let unavailable = |cmd, notes: &mut Vec<String>, reason| {
            if let Some(bytes) = limits.memory_bytes {
                notes.push(format!("memory_bytes={bytes} not applied: {reason}"));
            }
            if let Some(tasks) = limits.tasks {
                notes.push(format!("tasks={tasks} not applied: {reason}"));
            }
            (cmd, Vec::new())
        };
        let Some(systemd) = find("systemd-run") else {
            return unavailable(
                cmd,
                notes,
                "systemd-run not found on an absolute PATH entry",
            );
        };
        let Some(env) = ["/usr/bin/env", "/bin/env"]
            .into_iter()
            .map(PathBuf::from)
            .find(|p| executable(p))
        else {
            return unavailable(
                cmd,
                notes,
                "env executable unavailable for environment isolation",
            );
        };
        if cmd.get_program().as_encoded_bytes().contains(&b'=') {
            return unavailable(
                cmd,
                notes,
                "executor path contains an env assignment separator",
            );
        }
        // systemd 254 and later expand `$VAR` in the command line, which
        // would rewrite the wrapped arguments; older versions never expand.
        let version = Command::new(&systemd)
            .arg("--version")
            .env_clear()
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<u32>().ok())
            });
        let Some(version) = version else {
            return unavailable(cmd, notes, "systemd-run version unreadable");
        };
        let mut probe = Command::new(&systemd);
        probe.args(["--user", "--scope", "--quiet", "/bin/true"]);
        let result = run(
            probe,
            &Limits {
                wall_ms: 1000,
                cpu_secs: None,
                file_size_bytes: None,
                open_files: None,
                memory_bytes: None,
                tasks: None,
                output_cap_bytes: 512,
            },
            None,
        );
        if !result.success {
            return unavailable(cmd, notes, "systemd-run user scope probe failed");
        }
        let mut wrapper = Command::new(systemd);
        wrapper.env_clear();
        for (key, value) in cmd.get_envs() {
            if let Some(value) = value {
                wrapper.env(key, value);
            }
        }
        // Bus credentials belong to systemd-run. env -i removes them before exec.
        for key in ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "HOME"] {
            if let Some(value) = std::env::var_os(key) {
                wrapper.env(key, value);
            }
        }
        if let Some(cwd) = cmd.get_current_dir() {
            wrapper.current_dir(cwd);
        }
        wrapper.args(["--user", "--scope", "--quiet"]);
        if version >= 254 {
            wrapper.arg("--expand-environment=no");
        }
        let mut enforced = Vec::new();
        if let Some(bytes) = limits.memory_bytes {
            wrapper.args([
                OsStr::new("-p"),
                &OsString::from(format!("MemoryMax={bytes}")),
            ]);
            enforced.push(format!("cgroup_memory_max={bytes}"));
        }
        if let Some(tasks) = limits.tasks {
            wrapper.args([
                OsStr::new("-p"),
                &OsString::from(format!("TasksMax={tasks}")),
            ]);
            enforced.push(format!("cgroup_tasks_max={tasks}"));
        }
        wrapper.arg("--").arg(env).args(["-i", "--"]);
        for (key, value) in cmd.get_envs() {
            if let Some(value) = value {
                let mut assignment = key.to_os_string();
                assignment.push("=");
                assignment.push(value);
                wrapper.arg(assignment);
            }
        }
        wrapper.arg(cmd.get_program()).args(cmd.get_args());
        (wrapper, enforced)
    }
}

#[cfg(target_os = "macos")]
mod sweep {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    extern "C" {
        fn sandbox_check(
            pid: libc::pid_t,
            operation: *const libc::c_char,
            type_: libc::c_int,
            ...
        ) -> libc::c_int;
    }

    fn info(pid: i32) -> io::Result<libc::proc_bsdinfo> {
        // SAFETY: proc_bsdinfo is a plain C output structure.
        let mut info = unsafe { std::mem::zeroed::<libc::proc_bsdinfo>() };
        let size = std::mem::size_of_val(&info) as i32;
        // SAFETY: the buffer has the exact size passed to proc_pidinfo.
        let result = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        if result != size {
            return Err(io::Error::last_os_error());
        }
        Ok(info)
    }

    fn pids() -> io::Result<Vec<i32>> {
        // SAFETY: a null buffer asks libproc for the process count.
        let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
        if count <= 0 {
            return Err(io::Error::last_os_error());
        }
        let mut pids = vec![0i32; (count as usize).saturating_add(1024)];
        let bytes = i32::try_from(pids.len().saturating_mul(std::mem::size_of::<i32>()))
            .map_err(|_| io::Error::other("pid list is too large"))?;
        // SAFETY: pids has bytes writable bytes and remains live through the call.
        let count = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        if count <= 0 {
            return Err(io::Error::last_os_error());
        }
        if count as usize >= pids.len() {
            return Err(io::Error::other("pid list changed beyond its buffer"));
        }
        pids.truncate(count as usize);
        Ok(pids)
    }

    fn owned_pids(uid: libc::uid_t, capacity: usize) -> io::Result<Vec<i32>> {
        let mut pids = vec![0i32; capacity.saturating_add(1024)];
        let size = std::mem::size_of::<i32>();
        let bytes = i32::try_from(pids.len().saturating_mul(size))
            .map_err(|_| io::Error::other("uid pid list is too large"))?;
        // SAFETY: pids has bytes writable bytes; PROC_UID_ONLY filters by uid.
        let count = unsafe { libc::proc_listpids(4, uid, pids.as_mut_ptr().cast(), bytes) };
        if count <= 0 {
            return Err(io::Error::last_os_error());
        }
        if count >= bytes || !(count as usize).is_multiple_of(size) {
            return Err(io::Error::other("uid pid list exceeded its buffer"));
        }
        pids.truncate(count as usize / size);
        pids.sort_unstable();
        Ok(pids)
    }

    pub(super) fn group_has_live_processes(group: i32) -> io::Result<bool> {
        for pid in pids()? {
            if pid <= 0 {
                continue;
            }
            // SAFETY: getpgid accepts a numeric pid without a pointer.
            let pgid = unsafe { libc::getpgid(pid) };
            if pgid < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error);
                }
                continue;
            }
            if pgid == group {
                match info(pid) {
                    Ok(info) if info.pbi_status != 5 => return Ok(true),
                    Ok(_) => {}
                    Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(false)
    }

    fn matches(pid: i32, allowed: &CString, denied: &CString) -> io::Result<bool> {
        let operation = b"file-read-data\0";
        // SAFETY: operation and path are NUL terminated and live through the call.
        let check = |path: &CString| unsafe {
            sandbox_check(pid, operation.as_ptr().cast(), 1, path.as_ptr())
        };
        let allow = check(allowed);
        if allow < 0 {
            return Err(io::Error::last_os_error());
        }
        if allow != 0 {
            return Ok(false);
        }
        let deny = check(denied);
        if deny < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(deny != 0)
    }

    fn command(pid: i32, notes: &mut Vec<String>) -> String {
        let mut buffer = [0u8; 4096];
        // SAFETY: buffer is writable for the specified byte count.
        let mut count =
            unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
        if count <= 0 {
            // SAFETY: the same live buffer is passed with its full byte count.
            count =
                unsafe { libc::proc_name(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
        }
        if count <= 0 {
            notes.push(format!("could not read command for survivor {pid}"));
            return "unknown".into();
        }
        let length = (count as usize).min(buffer.len());
        let end = buffer[..length]
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(length);
        String::from_utf8_lossy(&buffer[..end]).into_owned()
    }

    pub(super) fn run(markers: &SweepMarkers, result: &mut Supervised) -> bool {
        let (Ok(allowed), Ok(denied)) = (
            CString::new(markers.allowed.as_os_str().as_bytes()),
            CString::new(markers.denied.as_os_str().as_bytes()),
        ) else {
            result
                .notes
                .push("survivor sweep markers contain NUL".into());
            return false;
        };
        if !markers.allowed.is_absolute()
            || !markers.denied.is_absolute()
            || markers.allowed == markers.denied
        {
            result
                .notes
                .push("survivor sweep requires distinct absolute marker paths".into());
            return false;
        }
        result.enforced.push("survivor_sweep".into());
        // SAFETY: getpid has no pointer arguments or preconditions.
        let own = unsafe { libc::getpid() };
        // SAFETY: geteuid has no pointer arguments or preconditions.
        let uid = unsafe { libc::geteuid() };
        let start = Instant::now();
        let mut healthy = true;
        let mut seen = Vec::new();
        for _ in 0..20 {
            let pids = match pids() {
                Ok(pids) => pids,
                Err(error) => {
                    result
                        .notes
                        .push(format!("survivor pid enumeration failed: {error}"));
                    return false;
                }
            };
            let owned = match owned_pids(uid, pids.len()) {
                Ok(owned) => owned,
                Err(error) => {
                    result
                        .notes
                        .push(format!("survivor uid enumeration failed: {error}"));
                    return false;
                }
            };
            let mut found = false;
            for pid in pids {
                if start.elapsed() >= DRAIN {
                    result
                        .notes
                        .push("survivor sweep time bound reached before a scan completed".into());
                    return false;
                }
                if pid <= 0 || pid == own || owned.binary_search(&pid).is_err() {
                    continue;
                }
                let before = match info(pid) {
                    Ok(info) if info.pbi_uid == uid && info.pbi_status != 5 => info,
                    Ok(_) => continue,
                    Err(error) => {
                        if !matches!(error.raw_os_error(), Some(libc::ESRCH | libc::ENOENT)) {
                            result
                                .notes
                                .push(format!("survivor uid lookup for {pid} failed: {error}"));
                            healthy = false;
                        }
                        continue;
                    }
                };
                let matched = match matches(pid, &allowed, &denied) {
                    Ok(matched) => matched,
                    Err(error) => {
                        if error.raw_os_error() != Some(libc::ESRCH) {
                            result
                                .notes
                                .push(format!("sandbox check for {pid} failed: {error}"));
                            healthy = false;
                        }
                        continue;
                    }
                };
                if !matched {
                    continue;
                }
                let identity = (pid, before.pbi_start_tvsec, before.pbi_start_tvusec);
                if !seen.contains(&identity) {
                    result.survivors.push(Survivor {
                        pid,
                        command: command(pid, &mut result.notes),
                    });
                    seen.push(identity);
                }
                // Recheck identity after the policy calls, before signalling a pid.
                let after = match info(pid) {
                    Ok(info) => info,
                    Err(error) => {
                        if error.raw_os_error() != Some(libc::ESRCH) {
                            result.notes.push(format!(
                                "survivor identity recheck for {pid} failed: {error}"
                            ));
                            healthy = false;
                        }
                        continue;
                    }
                };
                if after.pbi_uid != uid
                    || after.pbi_start_tvsec != before.pbi_start_tvsec
                    || after.pbi_start_tvusec != before.pbi_start_tvusec
                {
                    continue;
                }
                // A killed zombie cannot execute or fork, and awaits its own parent.
                if after.pbi_status == 5 {
                    continue;
                }
                found = true;
                healthy &= signal(pid, libc::SIGKILL, &mut result.notes);
            }
            if !found {
                return healthy;
            }
            if start.elapsed() >= DRAIN {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        result
            .notes
            .push("survivor sweep reached its scan or time bound with matches present".into());
        false
    }
}

/// Callers must use env_clear before supplying an explicit environment. Command
/// does not expose whether it inherits the host environment; Linux scope wrapping
/// reconstructs only get_envs and clears bus credentials before the executor.
pub fn run(cmd: Command, limits: &Limits, markers: Option<&SweepMarkers>) -> Supervised {
    run_inner(cmd, limits, markers, None, None, true)
}

pub fn run_marked(
    cmd: Command,
    limits: &Limits,
    markers: Option<&SweepMarkers>,
    nonce: &str,
) -> Supervised {
    run_contracted(cmd, limits, markers, nonce, None)
}

pub fn run_contracted(
    cmd: Command,
    limits: &Limits,
    markers: Option<&SweepMarkers>,
    nonce: &str,
    expect_marker: Option<&str>,
) -> Supervised {
    run_inner(cmd, limits, markers, Some(nonce), expect_marker, true)
}

/// Bounded cleanup inspection must still work after the user requested a stop.
#[cfg(windows)]
pub(crate) fn run_cleanup(cmd: Command, limits: &Limits) -> Supervised {
    run_inner(cmd, limits, None, None, None, false)
}

fn run_inner(
    mut cmd: Command,
    limits: &Limits,
    markers: Option<&SweepMarkers>,
    nonce: Option<&str>,
    expect_marker: Option<&str>,
    check_signals: bool,
) -> Supervised {
    let start = Instant::now();
    let mut result = Supervised {
        exit_code: None,
        executor_exit_code: None,
        command_started: false,
        command_finished: false,
        test_reachable: None,
        boundary_marker_seen: false,
        authorized_control_seen: false,
        enumerate_rejected: false,
        success: false,
        timed_out: false,
        executor_error: false,
        killed: false,
        interrupted: false,
        duration_ms: 0,
        output: String::new(),
        stdout: String::new(),
        output_bytes_total: 0,
        capture_complete: false,
        cleanup_complete: false,
        survivors: Vec::new(),
        enforced: Vec::new(),
        notes: Vec::new(),
    };
    #[cfg(target_os = "linux")]
    let cgroups;
    #[cfg(target_os = "linux")]
    {
        (cmd, cgroups) = cgroup::wrap(cmd, limits, &mut result.notes);
    }
    #[cfg(not(target_os = "linux"))]
    if limits.memory_bytes.is_some() || limits.tasks.is_some() {
        result
            .notes
            .push("memory and task limits not applied: Linux cgroups required".into());
    }
    #[cfg(not(unix))]
    for (name, value) in [
        ("cpu_secs", limits.cpu_secs),
        ("file_size_bytes", limits.file_size_bytes),
        ("open_files", limits.open_files),
    ] {
        if let Some(value) = value {
            result
                .notes
                .push(format!("{name}={value} not applied: Unix rlimits required"));
        }
    }
    #[cfg(not(target_os = "macos"))]
    if markers.is_some() {
        result
            .notes
            .push("survivor sweep not applied: only available on macOS".into());
    }
    #[cfg(any(unix, windows))]
    let _signals = if cfg!(windows) || nonce.is_some() {
        match interruption::Guard::install() {
            Ok(guard) => Some(guard),
            Err(error) => {
                result.executor_error = true;
                result.output = format!("failed to install proof signal handlers: {error}");
                result.notes.push(result.output.clone());
                return result;
            }
        }
    } else {
        None
    };
    #[cfg(unix)]
    let unix_controls = match prepare_unix(&mut cmd, limits) {
        Ok(controls) => controls,
        Err(error) => {
            result.executor_error = true;
            result.output = format!("failed to prepare executor: {error}");
            result.notes.push(result.output.clone());
            result.duration_ms = elapsed_ms(start);
            return result;
        }
    };
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        if let Err(error) = owner_job::ensure() {
            result.executor_error = true;
            result.output = format!("failed to establish Windows lifetime job: {error}");
            result.notes.push(result.output.clone());
            return result;
        }
        cmd.creation_flags(0x0000_0200); // CREATE_NEW_PROCESS_GROUP
    }
    cmd.stdin(Stdio::null());
    #[cfg(target_os = "macos")]
    let (stdout, stderr) = match capture_pipe().and_then(|out| capture_pipe().map(|err| (out, err)))
    {
        Ok(((stdout, out), (stderr, err))) => {
            cmd.stdout(Stdio::from(out)).stderr(Stdio::from(err));
            (stdout, stderr)
        }
        Err(error) => {
            result.executor_error = true;
            result.output = format!("failed to prepare output pipes: {error}");
            result.notes.push(result.output.clone());
            return result;
        }
    };
    #[cfg(not(target_os = "macos"))]
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(error) => {
            result.executor_error = true;
            result.output = format!("failed to start executor: {error}");
            result.notes.push(result.output.clone());
            result.duration_ms = elapsed_ms(start);
            return result;
        }
    };
    // File-backed Stdio remains owned by Command after spawn. Close the
    // parent's writers before reading, otherwise EOF could never arrive.
    drop(cmd);
    #[cfg(windows)]
    result
        .enforced
        .push("Windows owner kill-on-close job".into());
    result.enforced.extend([
        format!("wall_clock={}ms", limits.wall_ms),
        format!("output_cap={}B", limits.output_cap_bytes),
    ]);
    #[cfg(unix)]
    result.enforced.extend(unix_controls);
    let mut capture = Capture {
        streams: [Vec::new(), Vec::new()],
        done: [false; 2],
        healthy: true,
        total: 0,
        cap: limits.output_cap_bytes,
        evidence: MarkerScan {
            nonce: nonce.map(String::from),
            expect_marker: expect_marker.map(String::from),
            ..MarkerScan::default()
        },
    };
    let (tx, rx) = mpsc::sync_channel(16);
    let stop = Arc::new(AtomicBool::new(false));
    macro_rules! start_reader {
        ($pipe:expr, $stream:expr) => {
            if let Some(pipe) = $pipe {
                #[cfg(unix)]
                if let Err(error) = nonblocking(&pipe) {
                    result
                        .notes
                        .push(format!("nonblocking capture failed: {error}"));
                    capture.healthy = false;
                }
                if let Err(error) = reader(pipe, $stream, tx.clone(), Arc::clone(&stop)) {
                    result
                        .notes
                        .push(format!("starting output reader failed: {error}"));
                    capture.healthy = false;
                }
            } else {
                result.notes.push("executor output pipe missing".into());
                capture.healthy = false;
            }
        };
    }
    #[cfg(target_os = "macos")]
    {
        start_reader!(Some(stdout), 0);
        start_reader!(Some(stderr), 1);
    }
    #[cfg(not(target_os = "macos"))]
    {
        start_reader!(child.stdout.take(), 0);
        start_reader!(child.stderr.take(), 1);
    }
    drop(tx);
    let waited = wait(
        &mut child,
        limits.wall_ms,
        check_signals,
        &rx,
        &mut capture,
        &mut result.notes,
    );
    result.interrupted = waited.interrupted;
    result.killed = waited.interrupted
        || (!waited.timed_out && waited.status.is_some_and(|s| s.code().is_none()));
    result.timed_out = waited.timed_out;
    if !result.timed_out {
        result.exit_code = waited.status.and_then(|status| status.code());
    }
    result.executor_exit_code = waited.status.and_then(|status| status.code());
    let cleanup_complete = waited.healthy;
    #[cfg(target_os = "macos")]
    let cleanup_complete = match markers {
        Some(markers) => sweep::run(markers, &mut result) && cleanup_complete,
        None => cleanup_complete,
    };
    // The scope's exit status is the command's, so a failing proof test exits
    // nonzero with the limits fully applied. Only systemd-run's own refusal
    // to create the scope means they were not; it is checked once capture ends.
    #[cfg(target_os = "linux")]
    let pending_cgroups = cgroups;
    let drain = Instant::now();
    while capture.done != [true; 2] && drain.elapsed() < DRAIN {
        match rx.recv_timeout(DRAIN.saturating_sub(drain.elapsed()).min(POLL)) {
            Ok(message) => capture.receive(message, &mut result.notes),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
    stop.store(true, Ordering::Relaxed);
    result.capture_complete = capture.done == [true; 2] && capture.healthy;
    if !result.capture_complete {
        result.notes.push(
            "output capture incomplete after bounded drain; a descendant may hold the pipes".into(),
        );
    }
    for stream in 0..2 {
        capture.evidence.line(stream);
    }
    result.boundary_marker_seen = capture.evidence.boundary_marker_seen;
    result.authorized_control_seen = capture.evidence.authorized_control_seen;
    result.enumerate_rejected = capture.evidence.enumerate_rejected;
    if nonce.is_some() {
        result.command_started = capture.evidence.started;
        result.command_finished = capture.evidence.finished && !capture.evidence.invalid;
        result.test_reachable = capture.evidence.test_reachable;
        result.exit_code = capture.evidence.exit_code;
        result.executor_error = !result.command_started && !result.interrupted && !result.killed;
    }
    #[cfg(any(unix, windows))]
    if check_signals && interruption::pending() {
        result.interrupted = true;
        result.killed = true;
        result.executor_error = false;
        result.timed_out = false;
    }
    result.output_bytes_total = capture.total;
    result.stdout = String::from_utf8_lossy(&capture.streams[0]).into_owned();
    result.output = capture.text();
    #[cfg(target_os = "linux")]
    if !pending_cgroups.is_empty() {
        if result.output.contains("Failed to start transient scope") {
            for control in pending_cgroups {
                result.notes.push(format!(
                    "{control} not applied: systemd-run could not start the scope"
                ));
            }
        } else {
            result.enforced.extend(pending_cgroups);
        }
    }
    let executor_failed =
        nonce.is_some() && result.command_finished && result.executor_exit_code != result.exit_code;
    if executor_failed {
        result.notes.push(format!(
            "executor termination disagrees with completed workload: executor={:?}, workload={:?}",
            result.executor_exit_code, result.exit_code
        ));
    }
    result.cleanup_complete = cleanup_complete && !executor_failed;
    result.success = result.exit_code == Some(0)
        && !result.timed_out
        && !result.interrupted
        && !result.killed
        && !result.executor_error
        && result.capture_complete
        && result.survivors.is_empty()
        && result.cleanup_complete;
    result.duration_ms = elapsed_ms(start);
    result
}

fn elapsed_ms(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    #[test]
    fn capture_ignores_unsafe_tmpdir_and_rejects_overlapping_grants() {
        if std::env::var_os("OMGS_CAPTURE_CHILD").is_none() {
            let out = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "supervise::tests::capture_ignores_unsafe_tmpdir_and_rejects_overlapping_grants"])
                .env("OMGS_CAPTURE_CHILD", "1")
                .env("TMPDIR", "/usr/local/omgs-unsafe-temp/nonexistent")
                .output().unwrap();
            assert!(out.status.success(), "{out:?}");
            return;
        }
        let root = capture_root().unwrap();
        assert!(root.starts_with("/private/var/folders"));
        assert!(!root.starts_with(std::env::temp_dir()));
        let pair = capture_pipe().unwrap();
        drop(pair);
        assert!(validate_capture_grants(&root, std::slice::from_ref(&root)).is_err());
        assert!(validate_capture_grants(&root, &[root.parent().unwrap().to_path_buf()]).is_err());
        let alias = root.join("alias");
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        assert!(validate_capture_grants(&root, std::slice::from_ref(&alias)).is_err());
        std::fs::remove_file(alias).unwrap();
    }

    use super::*;

    #[cfg(unix)]
    #[test]
    fn executor_failure_after_end_marker_keeps_workload_status_but_fails_cleanup() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args([
            "-c",
            "printf 'OMGS_START_test\\nOMGS_END_test:0\\n'; exit 99",
        ]);
        let limits = Limits {
            wall_ms: 5000,
            cpu_secs: None,
            file_size_bytes: None,
            open_files: None,
            memory_bytes: None,
            tasks: None,
            output_cap_bytes: 65536,
        };
        let run = run_marked(cmd, &limits, None, "test");
        assert!(run.command_finished, "{run:?}");
        assert_eq!(run.exit_code, Some(0));
        assert_eq!(run.executor_exit_code, Some(99));
        assert!(!run.cleanup_complete && !run.success, "{run:?}");
    }

    #[test]
    fn markers_survive_output_flood_and_chunk_boundaries() {
        let nonce = "a".repeat(64);
        let mut capture = Capture {
            streams: [Vec::new(), Vec::new()],
            done: [false; 2],
            healthy: true,
            total: 0,
            cap: 10,
            evidence: MarkerScan {
                nonce: Some(nonce.clone()),
                expect_marker: Some("BOUNDARY_ASSERTION_FAILED".into()),
                ..MarkerScan::default()
            },
        };
        let mut bytes = format!("OMGS_START_{nonce}\r\nOMGS_TEST_{nonce}:1\r\n").into_bytes();
        bytes.extend(vec![b'x'; 300_000]);
        bytes.extend(
            format!(
                "\nOMGS_CONTROL_{nonce}\r\nOMGS_BOUNDARY_{nonce}_BOUNDARY_ASSERTION_FAILED\r\nOMGS_END_{nonce}:17\r\n"
            )
            .as_bytes(),
        );
        for chunk in bytes.chunks(7) {
            capture.receive(Message::Data(0, chunk.to_vec()), &mut Vec::new());
        }
        assert!(capture.evidence.started && capture.evidence.finished);
        assert!(!capture.evidence.invalid);
        assert_eq!(capture.evidence.exit_code, Some(17));
        assert_eq!(capture.evidence.test_reachable, Some(true));
        assert!(capture.evidence.boundary_marker_seen && capture.evidence.authorized_control_seen);
        assert_eq!(capture.text().len(), 10);
    }

    #[test]
    fn contract_markers_require_exact_complete_lines_on_either_stream() {
        let mut scan = MarkerScan {
            nonce: Some("nonce".into()),
            expect_marker: Some("BOUNDARY".into()),
            ..MarkerScan::default()
        };
        scan.receive(
            0,
            b"prefix BOUNDARY\nBOUNDARY suffix\nAUTHORIZED_CONTROL_OK suffix\n",
        );
        assert!(!scan.boundary_marker_seen && !scan.authorized_control_seen);
        scan.receive(
            0,
            b"BOUNDARY\nAUTHORIZED_CONTROL_OK\nOMGS_BOUNDARY_wrong_BOUNDARY\nOMGS_CONTROL_wrong\n",
        );
        assert!(!scan.boundary_marker_seen && !scan.authorized_control_seen);
        scan.receive(1, b"OMGS_BOUNDARY_nonce_BOU");
        scan.receive(1, b"NDARY\r\n");
        scan.receive(0, b"OMGS_CONTROL_nonce\n");
        assert!(scan.boundary_marker_seen && scan.authorized_control_seen);
    }

    #[test]
    fn errors_wrong_nonce_and_missing_or_duplicate_markers_never_finish_cleanly() {
        let mut scan = MarkerScan {
            nonce: Some("nonce".into()),
            ..MarkerScan::default()
        };
        scan.receive(1, b"Request error: configuration parse error\n");
        scan.receive(0, b"OMGS_START_wrong\nOMGS_END_wrong:1\n");
        assert!(!scan.started && !scan.finished);
        scan.receive(0, b"OMGS_START_nonce\n");
        assert!(scan.started && !scan.finished);
        scan.receive(0, b"OMGS_END_nonce:127\n");
        assert_eq!(scan.exit_code, Some(127));
        scan.receive(0, b"OMGS_END_nonce:0\n");
        assert!(scan.invalid);
        let mut reversed = MarkerScan {
            nonce: Some("n".into()),
            ..MarkerScan::default()
        };
        reversed.receive(0, b"OMGS_END_n:1\nOMGS_START_n\n");
        assert!(reversed.invalid);
    }

    #[test]
    fn test_reachability_markers_require_order_valid_values_and_uniqueness() {
        for bytes in [
            "OMGS_TEST_n:1\nOMGS_START_n\nOMGS_END_n:0\n",
            "OMGS_START_n\nOMGS_END_n:0\nOMGS_TEST_n:1\n",
            "OMGS_START_n\nOMGS_TEST_n:0\nOMGS_TEST_n:1\nOMGS_END_n:0\n",
            "OMGS_START_n\nOMGS_TEST_n:yes\nOMGS_END_n:0\n",
        ] {
            let mut scan = MarkerScan {
                nonce: Some("n".into()),
                ..MarkerScan::default()
            };
            scan.receive(0, bytes.as_bytes());
            assert!(scan.invalid, "{bytes}");
        }
    }

    #[test]
    fn enumeration_rejection_must_be_an_executor_error_line_on_stderr() {
        let mut scan = MarkerScan::default();
        scan.receive(
            0,
            b"Request error: enumeratePaths is not supported by this version of Windows\n",
        );
        scan.receive(
            1,
            b"target says enumeratePaths is not supported by this version of Windows\n",
        );
        assert!(!scan.enumerate_rejected);
        scan.receive(
            1,
            b"Request error: enumeratePaths is not supported by this version of Windows\n",
        );
        assert!(scan.enumerate_rejected);
    }

    #[test]
    fn output_prefix_is_stdout_then_stderr() {
        let mut capture = Capture {
            streams: [Vec::new(), Vec::new()],
            done: [false; 2],
            healthy: true,
            total: 0,
            cap: 6,
            evidence: MarkerScan::default(),
        };
        let mut notes = Vec::new();
        capture.receive(Message::Data(1, b"error".to_vec()), &mut notes);
        capture.receive(Message::Data(0, b"out".to_vec()), &mut notes);
        assert_eq!(capture.total, 8);
        assert_eq!(capture.text(), "outerr");
    }

    #[test]
    fn lossy_output_stays_within_byte_cap() {
        let mut capture = Capture {
            streams: [Vec::new(), Vec::new()],
            done: [false; 2],
            healthy: true,
            total: 0,
            cap: 2,
            evidence: MarkerScan::default(),
        };
        capture.receive(Message::Data(0, vec![255, 255, 255]), &mut Vec::new());
        assert_eq!(capture.total, 3);
        assert!(capture.text().len() <= 2);
    }
}
