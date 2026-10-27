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
    pub success: bool,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub output: String,
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
}

impl Capture {
    fn receive(&mut self, message: Message, notes: &mut Vec<String>) {
        match message {
            Message::Data(stream, bytes) => {
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

#[cfg(unix)]
fn nonblocking(pipe: &impl std::os::fd::AsRawFd) -> io::Result<()> {
    let fd = pipe.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
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
    cmd.process_group(0);
    // Build everything before fork. Only setrlimit and errno access run here.
    unsafe {
        cmd.pre_exec(move || {
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
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
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
    // libc exposes the Darwin field and Linux union through the same accessor.
    Ok(unsafe { info.si_pid() } != 0)
}

#[cfg(unix)]
fn signal(pid: i32, number: i32, notes: &mut Vec<String>) -> bool {
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
    healthy: bool,
}

fn wait(
    child: &mut Child,
    wall_ms: u64,
    rx: &mpsc::Receiver<Message>,
    capture: &mut Capture,
    notes: &mut Vec<String>,
) -> Waited {
    let start = Instant::now();
    let mut waited = Waited {
        status: None,
        timed_out: false,
        healthy: true,
    };
    #[cfg(unix)]
    let mut owns_leader = true;
    loop {
        capture.drain(rx, notes);
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
        probe.args(["--user", "--scope", "--quiet", "true"]);
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
        let mut info = unsafe { std::mem::zeroed::<libc::proc_bsdinfo>() };
        let size = std::mem::size_of_val(&info) as i32;
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
        let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
        if count <= 0 {
            return Err(io::Error::last_os_error());
        }
        let mut pids = vec![0i32; (count as usize).saturating_add(1024)];
        let bytes = i32::try_from(pids.len().saturating_mul(std::mem::size_of::<i32>()))
            .map_err(|_| io::Error::other("pid list is too large"))?;
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
        // PROC_UID_ONLY filters in the kernel, including protected other users.
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
        let mut count =
            unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
        if count <= 0 {
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
        let own = unsafe { libc::getpid() };
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
pub fn run(mut cmd: Command, limits: &Limits, markers: Option<&SweepMarkers>) -> Supervised {
    let start = Instant::now();
    let mut result = Supervised {
        exit_code: None,
        success: false,
        timed_out: false,
        duration_ms: 0,
        output: String::new(),
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
    for (name, value) in [
        ("memory_bytes", limits.memory_bytes),
        ("tasks", limits.tasks),
    ] {
        if let Some(value) = value {
            result.notes.push(format!(
                "{name}={value} not applied: Linux cgroups required"
            ));
        }
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
    #[cfg(unix)]
    let unix_controls = match prepare_unix(&mut cmd, limits) {
        Ok(controls) => controls,
        Err(error) => {
            result.output = format!("failed to prepare executor: {error}");
            result.notes.push(result.output.clone());
            result.duration_ms = elapsed_ms(start);
            return result;
        }
    };
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(error) => {
            result.output = format!("failed to start executor: {error}");
            result.notes.push(result.output.clone());
            result.duration_ms = elapsed_ms(start);
            return result;
        }
    };
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
    start_reader!(child.stdout.take(), 0);
    start_reader!(child.stderr.take(), 1);
    drop(tx);
    let waited = wait(
        &mut child,
        limits.wall_ms,
        &rx,
        &mut capture,
        &mut result.notes,
    );
    result.timed_out = waited.timed_out;
    if !result.timed_out {
        result.exit_code = waited.status.and_then(|status| status.code());
    }
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
    result.output_bytes_total = capture.total;
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
    result.cleanup_complete = cleanup_complete;
    result.success = result.exit_code == Some(0)
        && !result.timed_out
        && result.capture_complete
        && result.survivors.is_empty()
        && cleanup_complete;
    result.duration_ms = elapsed_ms(start);
    result
}

fn elapsed_ms(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_prefix_is_stdout_then_stderr() {
        let mut capture = Capture {
            streams: [Vec::new(), Vec::new()],
            done: [false; 2],
            healthy: true,
            total: 0,
            cap: 6,
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
        };
        capture.receive(Message::Data(0, vec![255, 255, 255]), &mut Vec::new());
        assert_eq!(capture.total, 3);
        assert!(capture.text().len() <= 2);
    }
}
