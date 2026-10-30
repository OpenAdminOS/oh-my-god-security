//! Per-invocation launchd ownership on Darwin. Enumeration locates tasks to
//! signal; only resource accounting certifies that no executable task remains.
use crate::platform;
use crate::supervise::{self, Limits, Supervised, Survivor};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::ffi::{CStr, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const CONTROL: &str = "launchd_resource_coalition";
const POLL: Duration = Duration::from_millis(10);
const CLEANUP: Duration = Duration::from_secs(2);
const STARTUP: Duration = Duration::from_secs(5);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    program: Vec<u8>,
    args: Vec<Vec<u8>>,
    env: Vec<(Vec<u8>, Vec<u8>)>,
    cwd: Vec<u8>,
    limits: Limits,
    nonce: Option<String>,
    marker: Option<String>,
    parent_coalition: u64,
    grants: Vec<PathBuf>,
    capture: supervise::CapturePlan,
}

/// Only this admitted form can publish a request and submit its launchd job.
/// Keep filesystem discovery here, including inputs nested inside MXC config,
/// rather than relying on each caller to remember an independent checklist.
struct AdmittedRequest<'a> {
    request: &'a Request,
    dir: &'a Path,
}
impl Request {
    fn admit<'a>(&'a self, dir: &'a Path) -> io::Result<AdmittedRequest<'a>> {
        self.admit_with(dir, &mut crate::tcc::admit_executor_path)
    }
    fn admit_with<'a>(
        &'a self,
        dir: &'a Path,
        visit: &mut impl FnMut(&Path, bool) -> io::Result<()>,
    ) -> io::Result<AdmittedRequest<'a>> {
        self.admit_with_mxc(dir, &mut crate::tcc::HostMxcFilesystem, visit)
    }
    fn admit_with_mxc<'a>(
        &'a self,
        dir: &'a Path,
        fs: &mut impl crate::tcc::MxcFilesystem,
        visit: &mut impl FnMut(&Path, bool) -> io::Result<()>,
    ) -> io::Result<AdmittedRequest<'a>> {
        // Exhaustive destructuring makes a new handoff field a compile error
        // until its admission semantics are explicitly assigned here.
        let Self {
            program,
            args,
            env,
            cwd,
            limits: _,
            nonce: _,
            marker: _,
            parent_coalition: _,
            grants,
            capture,
        } = self;
        let root = dir
            .parent()
            .ok_or_else(|| io::Error::other("missing job registry"))?;
        visit(root, false)?;
        visit(&root.join("registry"), false)?;
        admit_job_storage_with(dir, &mut |path| visit(path, false))?;
        for (key, value) in anchor_environment(dir)? {
            crate::tcc::visit_environment(OsStr::new(key), &value, &mut |path| visit(path, false))?;
        }
        for (_, path) in executor_environment(dir) {
            visit(&path, false)?;
        }
        // Trusted probe, null stdio and the loader's fixed system locations.
        for path in [
            "/bin/sleep",
            "/dev/null",
            "/usr/lib",
            "/System/Library/Frameworks",
        ] {
            visit(Path::new(path), false)?;
        }
        let cwd = Path::new(OsStr::from_bytes(cwd));
        visit(cwd, false)?;
        let resolve = |bytes: &[u8]| {
            let path = Path::new(OsStr::from_bytes(bytes));
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                cwd.join(path)
            }
        };
        // Launchd must not resolve an executable against an implicit PATH.
        let program = Path::new(OsStr::from_bytes(program));
        if !program.is_absolute() {
            return Err(io::Error::other(
                "launchd executor requires an absolute path",
            ));
        }
        visit(program, false)?;
        for arg in args {
            let path = Path::new(OsStr::from_bytes(arg));
            if path.is_absolute() {
                visit(path, false)?;
            }
        }
        for (key, value) in env {
            crate::tcc::visit_environment(
                OsStr::from_bytes(key),
                OsStr::from_bytes(value),
                &mut |path| visit(path, false),
            )?;
        }
        for grant in grants {
            visit(grant, true)?;
        }
        capture.visit(&mut |path| visit(path, false))?;
        for root in [
            dir.parent()
                .ok_or_else(|| io::Error::other("missing job registry"))?,
            capture.root(),
        ] {
            supervise::validate_capture_grants(root, grants)?;
        }
        for pair in args.windows(2).filter(|pair| pair[0] == b"--config") {
            let path = resolve(&pair[1]);
            visit(&path, false)?; // Before reading even a child-mounted config.
            let config: serde_json::Value =
                serde_json::from_slice(&platform::read_private_bounded_in(
                    path.parent()
                        .ok_or_else(|| io::Error::other("missing config parent"))?,
                    Path::new(
                        path.file_name()
                            .ok_or_else(|| io::Error::other("missing config name"))?,
                    ),
                    CONTROL_BYTES,
                )?)
                .map_err(io::Error::other)?;
            let mut implicit_grants = Vec::new();
            let executor_home = env
                .iter()
                .rev()
                .find(|(key, _)| key == b"HOME")
                .map(|(_, value)| PathBuf::from(OsStr::from_bytes(value)))
                .unwrap_or_else(|| dir.join("executor-home"));
            crate::tcc::visit_mxc_implicit(&config, &executor_home, fs, &mut |path, grant| {
                visit(path, grant)?;
                if grant {
                    implicit_grants.push(path.to_path_buf());
                }
                Ok(())
            })?;
            // Include config grants too: the serialized handoff's separate
            // grant list must never hide a wider effective MXC grant.
            crate::tcc::visit_config_at(&config, &executor_home, &mut |path, grant| {
                visit(path, grant)?;
                if grant {
                    implicit_grants.push(path.to_path_buf());
                }
                Ok(())
            })?;
            for storage in [
                root.to_path_buf(),
                dir.to_path_buf(),
                capture.root().to_path_buf(),
            ] {
                validate_mxc_grants(&storage, &implicit_grants)?;
            }
        }
        Ok(AdmittedRequest { request: self, dir })
    }
}
// Resolve existing ancestors too, since optional MXC grants can name paths
// which have not been created yet (for example executor HOME/Library/Keychains).
fn validate_mxc_grants(root: &Path, grants: &[PathBuf]) -> io::Result<()> {
    for grant in grants {
        let mut ancestor = grant.as_path();
        let mut suffix = Vec::new();
        let mut resolved = loop {
            match std::fs::canonicalize(ancestor) {
                Ok(path) => break path,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    suffix.push(
                        ancestor
                            .file_name()
                            .ok_or_else(|| io::Error::other("invalid MXC grant"))?,
                    );
                    ancestor = ancestor
                        .parent()
                        .ok_or_else(|| io::Error::other("missing MXC grant ancestor"))?;
                }
                Err(e) => return Err(e),
            }
        };
        for part in suffix.into_iter().rev() {
            resolved.push(part);
        }
        if crate::tcc::overlaps(root, grant) || crate::tcc::overlaps(root, &resolved) {
            return Err(io::Error::other(format!(
                "private storage overlaps MXC grant {}",
                grant.display()
            )));
        }
    }
    Ok(())
}

impl AdmittedRequest<'_> {
    fn command(&self) -> Command {
        let req = self.request;
        let mut cmd = Command::new(OsStr::from_bytes(&req.program));
        cmd.args(req.args.iter().map(|s| OsStr::from_bytes(s)))
            .env_clear()
            // Bound executor setup before MXC installs the workload environment.
            // Missing HOME/TMPDIR must not fall back to implicit host storage.
            .envs(executor_environment(self.dir))
            .envs(
                req.env
                    .iter()
                    .map(|(k, v)| (OsStr::from_bytes(k), OsStr::from_bytes(v))),
            )
            .current_dir(OsStr::from_bytes(&req.cwd));
        cmd
    }
    fn plist(&self) -> io::Result<String> {
        let directory = self.dir.to_string_lossy();
        let binary = self.dir.join("omgs");
        let environment = anchor_environment(self.dir)?
            .iter()
            .map(|(key, value)| {
                format!(
                    "<key>{}</key><string>{}</string>",
                    xml(key),
                    xml(&value.to_string_lossy())
                )
            })
            .collect::<String>();
        Ok(format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{}</string>
<key>ProgramArguments</key><array><string>{}</string><string>coalition-anchor</string><string>--directory</string><string>{}</string></array>
<key>WorkingDirectory</key><string>{}</string>
<key>EnvironmentVariables</key><dict>{}</dict>
<key>KeepAlive</key><false/>
<key>RunAtLoad</key><false/>
<key>SessionCreate</key><true/>
<key>ExitTimeOut</key><integer>3</integer>
</dict></plist>"#,
            label(self.dir)?,
            xml(&binary.to_string_lossy()),
            xml(&directory),
            xml(&directory),
            environment
        ))
    }
    fn submit(&self, job: &mut Job, domain: &str) -> io::Result<()> {
        if self.dir != job.dir {
            return Err(io::Error::other("admitted job directory mismatch"));
        }
        self.request.admit(self.dir)?;
        for (_, path) in executor_environment(self.dir) {
            platform::create_private_dir_new(&path)?;
        }
        // Repeat admission after staging and immediately before bootstrap.
        self.request.admit(self.dir)?;
        write(self.dir, "request", self.request)?;
        job.submitted = true;
        launchctl(&[
            OsStr::new("bootstrap"),
            OsStr::new(domain),
            self.dir.join("job.plist").as_os_str(),
        ])?;
        let service = format!("{}/{}", domain, label(self.dir)?);
        launchctl(&[OsStr::new("kickstart"), OsStr::new(&service)])
    }
}

fn executor_environment(dir: &Path) -> [(&'static str, PathBuf); 2] {
    [
        ("HOME", dir.join("executor-home")),
        ("TMPDIR", dir.join("executor-temp")),
    ]
}

fn anchor_environment(dir: &Path) -> io::Result<Vec<(&'static str, OsString)>> {
    let data = dir
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| io::Error::other("missing job data directory"))?;
    Ok(vec![
        ("OMGS_HOME", data.as_os_str().to_owned()),
        ("HOME", dir.as_os_str().to_owned()),
        ("TMPDIR", dir.as_os_str().to_owned()),
        ("PATH", "/usr/bin:/bin:/usr/sbin:/sbin".into()),
        ("RUST_BACKTRACE", "0".into()),
        ("DYLD_INSERT_LIBRARIES", "".into()),
        ("DYLD_LIBRARY_PATH", "".into()),
        ("DYLD_FRAMEWORK_PATH", "".into()),
        ("DYLD_FALLBACK_LIBRARY_PATH", "/usr/lib".into()),
        (
            "DYLD_FALLBACK_FRAMEWORK_PATH",
            "/System/Library/Frameworks".into(),
        ),
    ])
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    boot: String,
    pid: i32,
    generation: u64,
    coalition: u64,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    uuid: [u8; 16],
    generation: u64,
    parent: u64,
    version: u32,
    exec_version: u32,
    reserved: [u64; 2],
}

type Usage = unsafe extern "C" fn(u64, *mut libc::c_void, usize) -> i32;
type Members = unsafe extern "C" fn(u64, *mut i32, *mut usize) -> i32;
type Signal = unsafe extern "C" fn(*const [u32; 8], i32) -> i32;
struct Api {
    usage: Usage,
    members: Option<Members>,
    signal: Signal,
}

fn symbol(name: &CStr) -> io::Result<*mut libc::c_void> {
    // SAFETY: RTLD_DEFAULT searches loaded system libraries, name is terminated.
    let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    if ptr.is_null() {
        Err(io::Error::other(format!(
            "required Darwin interface unavailable: {}",
            name.to_string_lossy()
        )))
    } else {
        Ok(ptr)
    }
}
impl Api {
    fn load() -> io::Result<Self> {
        // SAFETY: these names have the declared Darwin libSystem SPI signatures.
        unsafe {
            Ok(Self {
                usage: std::mem::transmute::<*mut libc::c_void, Usage>(symbol(
                    c"coalition_info_resource_usage",
                )?),
                members: symbol(c"coalition_info_pid_list")
                    .ok()
                    .map(|ptr| std::mem::transmute::<*mut libc::c_void, Members>(ptr)),
                signal: std::mem::transmute::<*mut libc::c_void, Signal>(symbol(
                    c"proc_signal_with_audittoken",
                )?),
            })
        }
    }
    fn active(&self, id: u64) -> io::Result<u64> {
        // The stable resource-usage prefix is tasks_started, tasks_exited.
        // Reserve ample space for the evolving tail; no tail field is consumed.
        let mut usage = [0u64; 256];
        // SAFETY: the aligned buffer is writable for its full supplied length.
        if unsafe { (self.usage)(id, usage.as_mut_ptr().cast(), std::mem::size_of_val(&usage)) }
            != 0
        {
            return Err(io::Error::last_os_error());
        }
        usage[0]
            .checked_sub(usage[1])
            .ok_or_else(|| io::Error::other("invalid coalition task counters"))
    }
    fn members(&self, id: u64) -> io::Result<Vec<i32>> {
        let mut pids = vec![0i32; 65536];
        let mut bytes = pids.len() * 4;
        if let Some(members) = self.members {
            // SAFETY: buffer and size pointer are valid for this call.
            if unsafe { members(id, pids.as_mut_ptr(), &mut bytes) } != 0 {
                return Err(io::Error::last_os_error());
            }
            if bytes >= pids.len() * 4 || !bytes.is_multiple_of(4) {
                return Err(io::Error::other(
                    "coalition member buffer exhausted or invalid",
                ));
            }
            pids.truncate(bytes / 4);
        } else {
            // Some Darwin versions expose membership but no list SPI. Global
            // enumeration supplies candidates only. Vanished or foreign tasks
            // cannot influence the coalition count that certifies completion.
            let capacity = i32::try_from(bytes).map_err(io::Error::other)?;
            // SAFETY: pids owns capacity writable bytes throughout the call.
            let count = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), capacity) };
            if count <= 0 || count as usize >= pids.len() {
                return Err(io::Error::other(
                    "process candidate enumeration failed or exhausted",
                ));
            }
            pids.truncate(count as usize);
            pids.retain(|pid| *pid > 0 && coalition(*pid).is_ok_and(|c| c == id));
        }
        Ok(pids)
    }
    fn signal(&self, pid: i32, identity: Identity) -> io::Result<()> {
        let mut token = [0u32; 8];
        token[5] = pid as u32;
        token[7] = identity.version;
        // SAFETY: Darwin binds the signal to both pid and pidversion, atomically.
        let code = unsafe { (self.signal)(&token, libc::SIGKILL) };
        if code == 0 {
            Ok(())
        } else {
            let error = io::Error::from_raw_os_error(code);
            if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}
fn identity(pid: i32) -> io::Result<Identity> {
    // SAFETY: this is PROC_PIDUNIQIDENTIFIERINFO's plain C output layout.
    let mut value: Identity = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of_val(&value) as i32;
    // SAFETY: arg=1 includes retained zombies. Buffer has exactly size bytes.
    if unsafe { libc::proc_pidinfo(pid, 17, 1, (&mut value as *mut Identity).cast(), size) } != size
    {
        return Err(io::Error::last_os_error());
    }
    if value.generation == 0 {
        return Err(io::Error::other("missing process generation"));
    }
    Ok(value)
}
fn boot_id() -> io::Result<String> {
    let mut buffer = [0u8; 128];
    let mut size = buffer.len();
    // SAFETY: the system boot UUID is read into a bounded writable buffer.
    if unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if size == 0 || size > buffer.len() {
        return Err(io::Error::other("invalid boot identity"));
    }
    let value = CStr::from_bytes_until_nul(&buffer[..size])
        .map_err(io::Error::other)?
        .to_str()
        .map_err(io::Error::other)?;
    if value.len() != 36 || !value.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return Err(io::Error::other("invalid boot UUID"));
    }
    Ok(value.to_owned())
}
fn coalition(pid: i32) -> io::Result<u64> {
    let mut ids = [0u64; 5];
    let size = std::mem::size_of_val(&ids) as i32;
    // SAFETY: PROC_PIDCOALITIONINFO writes the five-u64 C structure.
    if unsafe { libc::proc_pidinfo(pid, 20, 0, ids.as_mut_ptr().cast(), size) } != size
        || ids[0] == 0
    {
        return Err(io::Error::other(
            "PROC_PIDCOALITIONINFO unavailable or invalid",
        ));
    }
    Ok(ids[0])
}
fn command(pid: i32) -> String {
    let mut buffer = [0u8; 4096];
    // SAFETY: buffer is writable for the supplied length.
    let count = unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if count <= 0 {
        return "unknown".into();
    }
    let end = buffer.iter().position(|b| *b == 0).unwrap_or(buffer.len());
    String::from_utf8_lossy(&buffer[..end]).into_owned()
}

fn empty(api: &Api, id: u64) -> io::Result<bool> {
    match api.active(id) {
        Ok(n) => Ok(n == 0),
        // Resource coalitions cannot be reaped while they still contain tasks.
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(true),
        Err(e) => Err(e),
    }
}

trait SweepQueries {
    fn active(&mut self, id: u64) -> io::Result<u64>;
    fn members(&mut self, id: u64) -> io::Result<Vec<i32>>;
    fn inspect(&mut self, pid: i32, id: u64) -> Option<(Identity, String)>;
    fn signal(&mut self, pid: i32, identity: Identity) -> io::Result<()>;
    fn elapsed(&self) -> Duration;
    fn pause(&mut self);
}
struct LiveSweep<'a> {
    api: &'a Api,
    start: Instant,
}
impl SweepQueries for LiveSweep<'_> {
    fn active(&mut self, id: u64) -> io::Result<u64> {
        self.api.active(id)
    }
    fn members(&mut self, id: u64) -> io::Result<Vec<i32>> {
        self.api.members(id)
    }
    fn inspect(&mut self, pid: i32, id: u64) -> Option<(Identity, String)> {
        // A list entry may exit and its PID may be reused at any point.
        // Bracket membership with identity and bind the signal to pidversion.
        let before = identity(pid).ok()?;
        let owned = coalition(pid).is_ok_and(|c| c == id);
        let name = command(pid);
        if !owned || !identity(pid).is_ok_and(|after| after == before) {
            return None;
        }
        Some((before, name))
    }
    fn signal(&mut self, pid: i32, identity: Identity) -> io::Result<()> {
        self.api.signal(pid, identity)
    }
    fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
    fn pause(&mut self) {
        std::thread::sleep(POLL);
    }
}
fn sweep(api: &Api, id: u64, anchor: Option<i32>, survivors: &mut Vec<Survivor>) -> io::Result<()> {
    sweep_with(
        &mut LiveSweep {
            api,
            start: Instant::now(),
        },
        id,
        anchor,
        survivors,
    )
}

fn sweep_with(
    queries: &mut impl SweepQueries,
    id: u64,
    anchor: Option<i32>,
    survivors: &mut Vec<Survivor>,
) -> io::Result<()> {
    let expected = u64::from(anchor.is_some());
    let mut seen = Vec::new();
    let mut observed = false;
    loop {
        let active = match queries.active(id) {
            Ok(n) => n,
            Err(e) if expected == 0 && e.raw_os_error() == Some(libc::ESRCH) => return Ok(()),
            Err(e) => return Err(e),
        };
        if active == expected {
            if observed && seen.is_empty() && anchor.is_some() {
                return Err(io::Error::other("owned activity outlived the executor but disappeared before identification; cleanup certificate obtained, proof remains unclean"));
            }
            return Ok(());
        }
        observed = true;
        if active < expected {
            return Err(io::Error::other("sealed anchor disappeared"));
        }
        if queries.elapsed() >= CLEANUP {
            return Err(io::Error::other(format!(
                "coalition cleanup bound reached with {} unresolved owned tasks",
                active - expected
            )));
        }
        for pid in queries.members(id)? {
            if pid <= 0 || Some(pid) == anchor {
                continue;
            }
            if queries.elapsed() >= CLEANUP {
                break;
            }
            let Some((before, name)) = queries.inspect(pid, id) else {
                continue;
            };
            if !seen.contains(&(pid, before.generation)) {
                survivors.push(Survivor { pid, command: name });
                seen.push((pid, before.generation));
            }
            queries.signal(pid, before)?;
        }
        queries.pause();
    }
}

thread_local! {
    static OWNED: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

pub(crate) fn cleanup(result: &mut Supervised) -> bool {
    let Some(id) = OWNED.with(|id| id.get()) else {
        return true;
    };
    result.enforced.push(CONTROL.into());
    let outcome = Api::load().and_then(|api| {
        sweep(
            &api,
            id,
            Some(std::process::id() as i32),
            &mut result.survivors,
        )
    });
    if let Err(error) = outcome {
        result.notes.push(error.to_string());
        false
    } else {
        true
    }
}

const CONTROL_BYTES: u64 = 4 * 1024 * 1024;

fn result_bytes(limits: &Limits) -> io::Result<u64> {
    // For each captured byte, JSON needs at most six bytes in each of output
    // and stdout (escaping controls also bounds lossy UTF-8), and four in the
    // stdout_bytes array (three decimal digits plus a comma). Keep the existing
    // control budget for status, notes, survivor commands and field names.
    u64::try_from(limits.output_cap_bytes)
        .ok()
        .and_then(|cap| cap.checked_mul(16))
        .and_then(|bytes| bytes.checked_add(CONTROL_BYTES))
        .ok_or_else(|| io::Error::other("result IPC bound overflow"))
}
fn read<T: DeserializeOwned>(dir: &Path, name: &str) -> io::Result<T> {
    read_bounded(dir, name, CONTROL_BYTES)
}
const JOB_LEAVES: &[&str] = &[
    "owner",
    "omgs",
    "job.plist",
    "request",
    "domain",
    "ready",
    "compatible",
    "start",
    "result",
    "error",
    "cancel",
    "orphan",
    "release",
];

/// Leaf admission is lexical. Only the stable directory reaches TCC inspection;
/// leaf opens and cleanup use retained descriptors without following links.
struct JobDirectory {
    file: File,
    parent: File,
    name: std::ffi::CString,
}
impl JobDirectory {
    fn open(dir: &Path) -> io::Result<Self> {
        // Refuse protected locations before opening even the directory. Repeat
        // the check with a pinned handle to detect a replacement during admission.
        admit_job_storage(dir)?;
        Self::open_with(dir, &mut admit_job_storage)
    }
    fn open_with(dir: &Path, admit: &mut impl FnMut(&Path) -> io::Result<()>) -> io::Result<Self> {
        use std::os::fd::FromRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let parent = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(
                dir.parent()
                    .ok_or_else(|| io::Error::other("missing job parent"))?,
            )?;
        let name = Self::name(
            dir.file_name()
                .and_then(OsStr::to_str)
                .ok_or_else(|| io::Error::other("invalid job directory name"))?,
        )?;
        // SAFETY: the parent descriptor and single-entry name remain live.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a newly owned directory descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        platform::check_private_dir_handle(&file)?;
        admit(dir)?;
        // Fail closed if the admitted pathname no longer names our directory.
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata()?;
        if platform::directory_identity(dir)? != (opened.dev(), opened.ino()) {
            return Err(io::Error::other("job directory changed during admission"));
        }
        Ok(Self { file, parent, name })
    }
    fn remove_empty(&self) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let mut entry = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: entry is writable and the parent and entry name remain live.
        // A replacement symlink is inspected itself, never followed.
        if unsafe {
            libc::fstatat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                entry.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fstatat succeeded and initialized entry.
        let entry = unsafe { entry.assume_init() };
        let opened = self.file.metadata()?;
        if entry.st_dev as u64 != opened.dev() || entry.st_ino != opened.ino() {
            return Err(io::Error::other("job directory changed before removal"));
        }
        // SAFETY: unlinkat addresses one entry in the retained parent. Even a
        // swap after the identity check cannot follow a link or recurse into it.
        if unsafe {
            libc::unlinkat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    fn remove(&self) -> io::Result<()> {
        for base in JOB_LEAVES {
            for suffix in ["", ".tmp"] {
                let name = Self::name(&format!("{base}{suffix}"))?;
                // SAFETY: unlinkat removes only this known entry relative to
                // the pinned directory. Links are unlinked, never followed.
                if unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::NotFound {
                        return Err(error);
                    }
                }
            }
        }
        for name in ["executor-home", "executor-temp"] {
            let name = Self::name(name)?;
            // SAFETY: only empty, known executor directories may be removed.
            // Unexpected contents remain available for recovery inspection.
            if unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
                != 0
            {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::NotFound {
                    return Err(error);
                }
            }
        }
        self.remove_empty()
    }
    fn name(name: &str) -> io::Result<std::ffi::CString> {
        // Check raw spelling, since Path components normalize trailing slashes
        // and dot components. A leaf must never choose another directory.
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(io::Error::other("job leaf must be a plain file name"));
        }
        std::ffi::CString::new(name).map_err(io::Error::other)
    }
    fn open_leaf(&self, name: &str, flags: i32, mode: libc::mode_t) -> io::Result<File> {
        use std::os::fd::FromRawFd;
        use std::os::unix::fs::MetadataExt;
        let name = Self::name(name)?;
        // SAFETY: the pinned directory and NUL-terminated leaf remain live.
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                u32::from(mode),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a newly owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        platform::check_private_file(&file)?;
        if !platform::is_single_link_file(&file)?
            || file.metadata()?.dev() != self.file.metadata()?.dev()
        {
            return Err(io::Error::other(
                "job leaf must be a regular file on its directory volume",
            ));
        }
        Ok(file)
    }
    fn create(&self, name: &str, bytes: &[u8], mode: libc::mode_t) -> io::Result<()> {
        use std::io::Write;
        let mut file = self.open_leaf(name, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, mode)?;
        file.write_all(bytes)?;
        file.sync_all()
    }
    fn rename(&self, source: &str, target: &str) -> io::Result<()> {
        let source = Self::name(source)?;
        let target = Self::name(target)?;
        // SAFETY: both names are single entries in the retained directory.
        // renameat replaces a destination link itself, never follows it.
        if unsafe {
            libc::renameat(
                self.file.as_raw_fd(),
                source.as_ptr(),
                self.file.as_raw_fd(),
                target.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
fn read_bounded<T: DeserializeOwned>(dir: &Path, name: &str, limit: u64) -> io::Result<T> {
    use std::io::Read;
    let file = JobDirectory::open(dir)?.open_leaf(name, libc::O_RDONLY, 0)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::other("file exceeds byte limit"));
    }
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}
fn leaf_exists(dir: &Path, name: &str) -> io::Result<bool> {
    match JobDirectory::open(dir)?.open_leaf(name, libc::O_RDONLY, 0) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}
fn write<T: Serialize>(dir: &Path, name: &str, value: &T) -> io::Result<()> {
    JobDirectory::name(name)?;
    let directory = JobDirectory::open(dir)?;
    let tmp = format!("{name}.tmp");
    directory.create(&tmp, &serde_json::to_vec(value)?, 0o600)?;
    directory.rename(&tmp, name)
}
fn write_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("missing job directory"))?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| io::Error::other("invalid job leaf"))?;
    JobDirectory::open(dir)?.create(name, bytes, 0o600)
}
fn lock(dir: &Path, create: bool) -> io::Result<File> {
    let file = JobDirectory::open(dir)?.open_leaf(
        "owner",
        libc::O_RDWR
            | if create {
                libc::O_CREAT | libc::O_EXCL
            } else {
                0
            },
        0o600,
    )?;
    // SAFETY: file owns this descriptor. LOCK_NB never waits on another proof.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}
fn owner_gone(dir: &Path) -> bool {
    lock(dir, false).is_ok()
}
fn admit_private_data_location(data: &Path) -> io::Result<()> {
    // Owner-private mode alone cannot hide files from a sandbox running as the
    // same user. Keep IPC outside the pinned executor's baseline system reads.
    if [
        "/Applications",
        "/Library",
        "/System",
        "/bin",
        "/sbin",
        "/usr",
        "/opt",
        "/etc",
        "/dev",
        "/private/etc",
        "/private/var/db",
        "/private/var/select",
    ]
    .iter()
    .any(|root| crate::tcc::starts_with(data, Path::new(root)))
    {
        return Err(io::Error::other(format!("OMGS_HOME {} is inside a baseline-readable system tree; use owner-private storage such as ~/.local/share/omgs outside sandbox grants", platform::escape_controls(&data.display().to_string()))));
    }
    Ok(())
}
fn root() -> io::Result<PathBuf> {
    let data =
        platform::data_dir().ok_or_else(|| io::Error::other("OMGS data directory unavailable"))?;
    root_with(&data, &mut crate::tcc::admit_path)
}
fn root_with(data: &Path, admit: &mut impl FnMut(&Path) -> io::Result<()>) -> io::Result<PathBuf> {
    admit_private_data_location(data)?;
    admit(data)?;
    platform::create_private_tree(data)?;
    let root = data.join("launchd");
    // A child can be a mount point even when its parent volume was admitted.
    admit(&root)?;
    platform::create_private_tree(&root)?;
    admit(&root)?;
    Ok(root)
}

fn admit_job_storage(dir: &Path) -> io::Result<()> {
    admit_job_storage_with(dir, &mut crate::tcc::admit_path)
}
fn admit_job_storage_with(
    dir: &Path,
    admit: &mut impl FnMut(&Path) -> io::Result<()>,
) -> io::Result<()> {
    // Also the anchor's working directory, HOME and TMPDIR. Leaves cannot
    // select storage: names are lexical and opens are no-follow beneath this
    // directory. Never inspect a transient leaf during admission or recheck.
    admit(dir)
}

fn domain() -> String {
    // The user domain exists for graphical and SSH sessions alike, when enabled.
    let uid = unsafe { libc::geteuid() };
    let gui = format!("gui/{uid}");
    if launchctl(&[OsStr::new("print"), OsStr::new(&gui)]).is_ok() {
        gui
    } else {
        format!("user/{uid}")
    }
}
fn label(dir: &Path) -> io::Result<String> {
    let name = dir
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| io::Error::other("invalid job directory"))?;
    if name.len() != 64 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(io::Error::other("invalid job nonce"));
    }
    Ok(format!("org.openadminos.omgs.proof.{name}"))
}
fn launchctl_output(args: &[&OsStr]) -> Supervised {
    let mut cmd = Command::new("/bin/launchctl");
    cmd.args(args).env_clear();
    let limits = Limits {
        wall_ms: 3000,
        cpu_secs: None,
        file_size_bytes: None,
        open_files: None,
        memory_bytes: None,
        tasks: None,
        output_cap_bytes: 8192,
    };
    supervise::run_inner(cmd, &limits, None, None, None, false, None)
}
fn launchctl(args: &[&OsStr]) -> io::Result<()> {
    let out = launchctl_output(args);
    if out.success {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "launchctl failed ({:?}): {}",
            out.exit_code,
            out.output.trim()
        )))
    }
}
fn job_domain(dir: &Path) -> io::Result<String> {
    let saved: String = read(dir, "domain")?;
    let uid = unsafe { libc::geteuid() };
    if saved != format!("gui/{uid}") && saved != format!("user/{uid}") {
        return Err(io::Error::other("invalid saved launchd domain"));
    }
    Ok(saved)
}
fn remove_job(dir: &Path) -> io::Result<()> {
    let service = format!("{}/{}", job_domain(dir)?, label(dir)?);
    let args = [OsStr::new("print"), OsStr::new(&service)];
    let out = launchctl_output(&args);
    if out.exit_code == Some(113) && out.cleanup_complete && out.capture_complete {
        return Ok(());
    }
    if !out.success {
        return Err(io::Error::other(
            "cannot inspect launchd job before removal",
        ));
    }
    launchctl(&[OsStr::new("bootout"), OsStr::new(&service)])?;
    let out = launchctl_output(&args);
    if out.exit_code != Some(113) || !out.cleanup_complete || !out.capture_complete {
        return Err(io::Error::other(
            "launchd job removal could not be verified",
        ));
    }
    Ok(())
}

/// Recover only nonce directories admitted under the owner-private data root.
/// A held owner lock excludes every active independent invocation.
fn registry(root: &Path) -> io::Result<File> {
    crate::tcc::admit_path(&root.join("registry"))?;
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join("registry"))?;
    let start = Instant::now();
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(file);
        }
        if start.elapsed() >= STARTUP {
            return Err(io::Error::other("job registry recovery busy"));
        }
        std::thread::sleep(POLL);
    }
}
fn reclaim_unpublished(dir: &Path) -> io::Result<()> {
    match JobDirectory::open(dir).and_then(|directory| directory.remove_empty()) {
        Ok(()) => Ok(()),
        // A published job can retire outside the registry lock. Preserve its
        // remaining state, or accept that it already removed the directory.
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Ok(())
        }
        Err(e) => Err(e),
    }
}
// The registry lock must span recovery and directory/owner publication.
fn recover(root: &Path, api: &Api) -> io::Result<()> {
    let boot = boot_id()?;
    for entry in std::fs::read_dir(root)? {
        let dir = entry?.path();
        if dir.file_name() == Some(OsStr::new("registry")) {
            continue;
        }
        crate::tcc::admit_path(&dir)?;
        match platform::check_private_dir(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        }
        label(&dir)?;
        admit_job_storage(&dir)?;
        let directory = match JobDirectory::open(&dir) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let _lock = match lock(&dir, false) {
            Ok(lock) => lock,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            // Publication holds the registry lock across mkdir and owner
            // creation. With that lock held, an empty ownerless directory can
            // only be abandoned. Nonempty state may belong to a concurrently
            // retiring job and must remain intact.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                reclaim_unpublished(&dir)?;
                continue;
            }
            Err(e) => return Err(e),
        };
        if let Ok(ready) = read::<Ready>(&dir, "ready") {
            // Launchd bootstrap state is not persistent. Neither coalition IDs
            // nor process generations may identify ownership across a reboot.
            if ready.boot != boot {
                directory.remove()?;
                continue;
            }
        }
        // Taking the abandoned lock also tells its anchor that the owner is gone
        // through the explicit cancellation file, even while recovery owns it.
        if !leaf_exists(&dir, "orphan")? {
            write_file(&dir.join("orphan"), b"")?;
        }
        if !leaf_exists(&dir, "cancel")? {
            write_file(&dir.join("cancel"), b"")?;
        }
        let start = Instant::now();
        while start.elapsed() < STARTUP {
            if let Ok(ready) = read::<Ready>(&dir, "ready") {
                if empty(api, ready.coalition)? {
                    break;
                }
            } else if leaf_exists(&dir, "error")? {
                break;
            }
            std::thread::sleep(POLL);
        }
        if leaf_exists(&dir, "start")? {
            let _: Ready = read(&dir, "ready")?;
        }
        if let Ok(ready) = read::<Ready>(&dir, "ready") {
            if ready.coalition == coalition(std::process::id() as i32)? {
                return Err(io::Error::other(
                    "orphan coalition overlaps this invocation",
                ));
            }
            // No certificate is produced for an abandoned proof. Terminate the
            // anchor as well if it could not finish its own bounded cleanup.
            sweep(api, ready.coalition, None, &mut Vec::new())?;
        }
        if leaf_exists(&dir, "domain")? {
            remove_job(&dir)?;
        }
        directory.remove()?;
    }
    Ok(())
}

fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn executable() -> io::Result<PathBuf> {
    let current = std::env::current_exe()?;
    // Cargo integration tests call the library from a harness in deps. The
    // sibling binary is the package executable built by Cargo, never PATH.
    if current.parent().is_some_and(|p| p.ends_with("deps")) {
        Ok(current.parent().unwrap().parent().unwrap().join("omgs"))
    } else {
        Ok(current)
    }
}

fn file_version(meta: &std::fs::Metadata) -> (u64, u64, u64, u64, i64, i64, i64, i64) {
    use std::os::unix::fs::MetadataExt;
    (
        meta.dev(),
        meta.ino(),
        meta.len(),
        meta.nlink(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec(),
    )
}
fn verify_copy(source: &mut File, staged: &mut File, before: &std::fs::Metadata) -> io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    source.seek(SeekFrom::Start(0))?;
    staged.seek(SeekFrom::Start(0))?;
    let mut left = [0u8; 65536];
    let mut right = [0u8; 65536];
    let mut expected_hash = crate::sha256::Sha256::new();
    let mut staged_hash = crate::sha256::Sha256::new();
    let mut remaining = before.len();
    while remaining != 0 {
        supervise::check_interrupted()?;
        let size = remaining.min(left.len() as u64) as usize;
        source.read_exact(&mut left[..size])?;
        staged.read_exact(&mut right[..size])?;
        expected_hash.update(&left[..size]);
        staged_hash.update(&right[..size]);
        if left[..size] != right[..size] {
            return Err(io::Error::other("anchor copy bytes differ"));
        }
        remaining -= size as u64;
    }
    if expected_hash.finish() != staged_hash.finish() {
        return Err(io::Error::other("anchor SHA-256 mismatch"));
    }
    if staged.metadata()?.len() != before.len()
        || file_version(&source.metadata()?) != file_version(before)
    {
        return Err(io::Error::other(
            "anchor source or copy changed during verification",
        ));
    }
    Ok(())
}
fn stage_binary(source: &Path, target: &Path) -> io::Result<()> {
    use std::io::{Read, Write};
    let directory = JobDirectory::open(
        target
            .parent()
            .ok_or_else(|| io::Error::other("missing job directory"))?,
    )?;
    let name = target
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| io::Error::other("invalid job leaf"))?;
    let mut source = File::open(source)?;
    let before = source.metadata()?;
    if !before.is_file() {
        return Err(io::Error::other("anchor source is not a regular file"));
    }
    let mut staged =
        directory.open_leaf(name, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, 0o700)?;
    // The trusted source is opened once. Bound copying even if it changes, then
    // compare exact bytes and the source file's identity and modification times.
    let copied = std::io::copy(
        &mut (&mut source).take(before.len().saturating_add(1)),
        &mut staged,
    )?;
    staged.flush()?;
    if copied != before.len() {
        return Err(io::Error::other(
            "anchor source length changed during copying",
        ));
    }
    verify_copy(&mut source, &mut staged, &before)
}

pub(crate) fn run(
    cmd: Command,
    limits: &Limits,
    nonce: Option<&str>,
    marker: Option<&str>,
    cancellation: Option<&AtomicBool>,
    grants: &[PathBuf],
    mut failure: Supervised,
) -> Supervised {
    let started = Instant::now();
    let mut workload_started: Option<Instant> = None;
    let result = (|| -> io::Result<Supervised> {
        let result_limit = result_bytes(limits)?;
        let api = Api::load()?;
        let cwd = cmd
            .get_current_dir()
            .map(Path::to_path_buf)
            .unwrap_or(std::env::current_dir()?);
        let capture = supervise::CapturePlan::new()?;
        let root = root()?;
        supervise::validate_capture_grants(&root, grants)?;
        supervise::validate_capture_grants(capture.root(), grants)?;
        let registry_guard = registry(&root)?;
        recover(&root, &api)?;
        let dir = root.join(platform::random_nonce()?);
        admit_job_storage(&dir)?;
        platform::create_private_dir_new(&dir)?;
        admit_job_storage(&dir)?;
        let owner = lock(&dir, true)?;
        drop(registry_guard);
        let mut job = Job {
            directory: JobDirectory::open(&dir)?,
            dir,
            _owner: owner,
            submitted: false,
        };
        let source = executable()?;
        let binary = job.dir.join("omgs");
        stage_binary(&source, &binary)?;
        let request = Request {
            program: cmd.get_program().as_bytes().to_vec(),
            args: cmd.get_args().map(|s| s.as_bytes().to_vec()).collect(),
            env: cmd
                .get_envs()
                .filter_map(|(k, v)| v.map(|v| (k.as_bytes().to_vec(), v.as_bytes().to_vec())))
                .collect(),
            cwd: cwd.as_os_str().as_bytes().to_vec(),
            limits: limits.clone(),
            nonce: nonce.map(str::to_owned),
            marker: marker.map(str::to_owned),
            parent_coalition: coalition(std::process::id() as i32)?,
            grants: grants.to_vec(),
            capture,
        };
        let request_dir = job.dir.clone();
        let admitted = request.admit(&request_dir)?;
        let plist = admitted.plist()?;
        write_file(&job.dir.join("job.plist"), plist.as_bytes())?;
        let domain = domain();
        write(&job.dir, "domain", &domain)?;
        admitted.submit(&mut job, &domain)?;
        let admission_started = Instant::now();
        let mut ready = None;
        let mut interrupted = false;
        let mut timed_out = false;
        let mut cancel_sent = false;
        loop {
            if supervise::interruption::pending()
                || cancellation.is_some_and(|c| c.load(Ordering::Acquire))
            {
                interrupted = true;
            }
            if supervise::Deadline::expired() {
                timed_out = true;
            }
            if (interrupted || timed_out) && !cancel_sent {
                write_file(&job.dir.join("cancel"), b"")?;
                cancel_sent = true;
            }
            if let Ok(error) = read::<String>(&job.dir, "error") {
                return Err(io::Error::other(error));
            }
            if ready.is_none() && leaf_exists(&job.dir, "compatible")? {
                if let Ok(r) = read::<Ready>(&job.dir, "ready") {
                    if r.boot != boot_id()?
                        || r.coalition == request.parent_coalition
                        || coalition(r.pid)? != r.coalition
                        || identity(r.pid)?.generation != r.generation
                        || api.active(r.coalition)? != 1
                        || api.members(r.coalition)? != [r.pid]
                    {
                        return Err(io::Error::other(
                            "launchd did not establish an exclusive anchor coalition",
                        ));
                    }
                    if cancel_sent {
                        return Err(io::Error::other("proof stopped before launchd admission"));
                    }
                    // wait() inside the anchor owns the executor wall clock.
                    // This timestamp only bounds a lost anchor response; cleanup
                    // keeps its independent grace. Deadline covers preparation.
                    workload_started = Some(Instant::now());
                    write_file(&job.dir.join("start"), b"")?;
                    ready = Some(r);
                }
            }
            if leaf_exists(&job.dir, "result")? {
                let mut result: Supervised = read_bounded(&job.dir, "result", result_limit)?;
                let r = ready
                    .as_ref()
                    .ok_or_else(|| io::Error::other("anchor result without admission"))?;
                if identity(r.pid)?.generation != r.generation
                    || coalition(r.pid)? != r.coalition
                    || api.active(r.coalition)? != 1
                {
                    result.cleanup_complete = false;
                    result
                        .notes
                        .push("sealed anchor certificate unavailable".into());
                }
                result.enforced.push("launchd_tcc_path_admission".into());
                result.interrupted |= interrupted;
                if timed_out && !interrupted {
                    result.timed_out = true;
                    result.interrupted = false;
                    result.killed = false;
                }
                result.killed |= interrupted;
                result.success &= !interrupted && !timed_out && result.cleanup_complete;
                if let Err(error) = job.finish(&api, r) {
                    result.cleanup_complete = false;
                    result.success = false;
                    result
                        .notes
                        .push(format!("launchd lifecycle cleanup failed: {error}"));
                }
                result.duration_ms =
                    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                return Ok(result);
            }
            if ready.is_none() && admission_started.elapsed() >= STARTUP {
                return Err(io::Error::other("launchd anchor startup bound reached"));
            }
            if let Some(r) = &ready {
                if !identity(r.pid).is_ok_and(|i| i.generation == r.generation) {
                    return Err(io::Error::other("launchd anchor died before certification"));
                }
            }
            if workload_started.unwrap_or(admission_started).elapsed()
                >= Duration::from_millis(limits.wall_ms)
                    + STARTUP
                    + CLEANUP
                    + Duration::from_secs(2)
            {
                return Err(io::Error::other("launchd anchor completion bound reached"));
            }
            std::thread::sleep(POLL);
        }
    })();
    match result {
        Ok(result) => result,
        Err(error) => {
            failure.interrupted = supervise::interruption::pending()
                || cancellation.is_some_and(|c| c.load(Ordering::Acquire));
            failure.killed = failure.interrupted;
            failure.timed_out = !failure.interrupted && supervise::Deadline::expired();
            failure.executor_error = !failure.interrupted && !failure.timed_out;
            failure.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            failure.notes.push(format!(
                "macOS launchd coalition required; refusing uncertified execution: {error}"
            ));
            failure.output = failure.notes.last().unwrap().clone();
            failure
        }
    }
}
struct Job {
    dir: PathBuf,
    directory: JobDirectory,
    _owner: File,
    submitted: bool,
}
impl Job {
    fn finish(&mut self, api: &Api, ready: &Ready) -> io::Result<()> {
        write_file(&self.dir.join("release"), b"")?;
        let start = Instant::now();
        while !empty(api, ready.coalition)? {
            if start.elapsed() >= STARTUP {
                return Err(io::Error::other("anchor exit bound reached"));
            }
            std::thread::sleep(POLL);
        }
        remove_job(&self.dir)?;
        self.submitted = false;
        self.directory.remove()
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        if self.submitted {
            let _ = write_file(&self.dir.join("cancel"), b"");
            // Bootout can kill the anchor. Recover by the already published ID,
            // never by a label-derived PID or a same-user process scan.
            if let (Ok(api), Ok(ready)) = (Api::load(), read::<Ready>(&self.dir, "ready")) {
                if ready.coalition
                    != coalition(std::process::id() as i32).unwrap_or(ready.coalition)
                {
                    let _ = sweep(&api, ready.coalition, None, &mut Vec::new());
                }
            }
            if remove_job(&self.dir).is_err() {
                return;
            }
        }
        // Retain recovery state if an error path could leave live members.
        if leaf_exists(&self.dir, "start").unwrap_or(true)
            && read::<Ready>(&self.dir, "ready").is_err()
        {
            return;
        }
        if let (Ok(api), Ok(r)) = (Api::load(), read::<Ready>(&self.dir, "ready")) {
            if !empty(&api, r.coalition).unwrap_or(false) {
                return;
            }
        }
        let _ = self.directory.remove();
    }
}

/// Hidden trusted entry point. No target is started until the parent admits the
/// fresh coalition. After run_inner returns, no path here spawns another process.
pub fn anchor(dir: &Path) -> io::Result<()> {
    admit_job_storage(dir)?;
    platform::check_private_dir(dir)?;
    if dir.parent() != Some(root()?.as_path()) {
        return Err(io::Error::other(
            "anchor directory outside private registry",
        ));
    }
    label(dir)?;
    let outcome = (|| -> io::Result<()> {
        let api = Api::load()?;
        let req: Request = read(dir, "request")?;
        req.admit(dir)?;
        let pid = std::process::id() as i32;
        let id = coalition(pid)?;
        if id == req.parent_coalition || api.active(id)? != 1 || api.members(id)? != [pid] {
            return Err(io::Error::other("anchor coalition is not exclusive"));
        }
        write(
            dir,
            "ready",
            &Ready {
                boot: boot_id()?,
                pid,
                coalition: id,
                generation: identity(pid)?.generation,
            },
        )?;
        // Exercise inheritance, task accounting, enumeration and version-bound
        // signalling on a trusted child before granting permission to execute.
        let mut probe = Command::new("/bin/sleep").arg("30").env_clear().spawn()?;
        let probe_pid = probe.id() as i32;
        let check = (|| -> io::Result<()> {
            if coalition(probe_pid)? != id
                || api.active(id)? != 2
                || !api.members(id)?.contains(&probe_pid)
            {
                return Err(io::Error::other(
                    "coalition inheritance or accounting check failed",
                ));
            }
            let identity = identity(probe_pid)?;
            let mut token = [0u32; 8];
            token[5] = probe_pid as u32;
            token[7] = identity.version.wrapping_add(1).max(1);
            // Exercise rejection as well as success. A changed SPI must never
            // silently degrade to an unversioned PID signal.
            if unsafe { (api.signal)(&token, libc::SIGKILL) } == 0 || api.active(id)? != 2 {
                return Err(io::Error::other(
                    "audit-token signal did not reject a mismatched PID version",
                ));
            }
            api.signal(probe_pid, identity)
        })();
        // This is our unreaped child, so this fallback cannot signal a reused PID.
        if check.is_err() {
            let _ = probe.kill();
        }
        probe.wait()?;
        check?;
        if api.active(id)? != 1 {
            return Err(io::Error::other("coalition exit accounting check failed"));
        }
        write_file(&dir.join("compatible"), b"")?;
        let start = Instant::now();
        while !leaf_exists(dir, "start")? {
            if owner_gone(dir) || leaf_exists(dir, "cancel")? || start.elapsed() >= STARTUP {
                return Ok(());
            }
            std::thread::sleep(POLL);
        }
        if owner_gone(dir) || leaf_exists(dir, "cancel")? {
            return Ok(());
        }
        let admitted = req.admit(dir)?;
        let stop = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        let monitor = {
            let (stop, done, dir) = (stop.clone(), done.clone(), dir.to_path_buf());
            std::thread::spawn(move || {
                while !done.load(Ordering::Acquire) {
                    if leaf_exists(&dir, "cancel").unwrap_or(true) || owner_gone(&dir) {
                        stop.store(true, Ordering::Release);
                        return;
                    }
                    std::thread::sleep(POLL);
                }
            })
        };
        let cmd = admitted.command();
        OWNED.with(|owned| owned.set(Some(id)));
        let result = supervise::run_controlled(
            cmd,
            &req.limits,
            None,
            req.nonce.as_deref(),
            req.marker.as_deref(),
            true,
            supervise::RunControl {
                cancellation: Some(&stop),
                capture: Some(&req.capture),
            },
        );
        done.store(true, Ordering::Release);
        monitor
            .join()
            .map_err(|_| io::Error::other("owner monitor failed"))?;
        OWNED.with(|owned| owned.set(None));
        // SEALED: cleanup ran before capture drain. No process is spawned here.
        write(dir, "result", &result)?;
        let start = Instant::now();
        while !leaf_exists(dir, "release")?
            && !owner_gone(dir)
            && !leaf_exists(dir, "orphan")?
            && start.elapsed() < STARTUP
        {
            std::thread::sleep(POLL);
        }
        Ok(())
    })();
    if let Err(error) = &outcome {
        let _ = write(dir, "error", &error.to_string());
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    struct Chain {
        counts: VecDeque<u64>,
        elapsed: Duration,
        listed: bool,
    }
    impl SweepQueries for Chain {
        fn active(&mut self, _: u64) -> io::Result<u64> {
            Ok(self.counts.pop_front().unwrap_or(2))
        }
        fn members(&mut self, _: u64) -> io::Result<Vec<i32>> {
            // Every rolling parent has vanished before its first identity query.
            Ok(if self.listed {
                vec![100 + self.elapsed.as_millis() as i32]
            } else {
                vec![]
            })
        }
        fn inspect(&mut self, _: i32, _: u64) -> Option<(Identity, String)> {
            None
        }
        fn signal(&mut self, _: i32, _: Identity) -> io::Result<()> {
            panic!("unidentified task must never be signalled")
        }
        fn elapsed(&self) -> Duration {
            self.elapsed
        }
        fn pause(&mut self) {
            self.elapsed += Duration::from_millis(50);
        }
    }
    struct SelectedDeveloper {
        targets: [Option<PathBuf>; 2],
        trusted: [bool; 2],
        inspected: Vec<PathBuf>,
    }
    impl SelectedDeveloper {
        fn new(target: PathBuf) -> Self {
            Self {
                targets: [Some(target), None],
                trusted: [true, true],
                inspected: Vec::new(),
            }
        }
    }
    impl crate::tcc::MxcFilesystem for SelectedDeveloper {
        fn root_controlled_link(&mut self, path: &Path) -> bool {
            self.trusted[usize::from(path.ends_with("developer_dir"))]
        }
        fn read_link(&mut self, path: &Path) -> io::Result<PathBuf> {
            let index = usize::from(path.ends_with("developer_dir"));
            self.targets[index]
                .clone()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }
        fn is_dir(&mut self, path: &Path) -> bool {
            self.inspected.push(path.to_path_buf());
            path.is_dir()
        }
    }
    #[test]
    fn every_handoff_path_must_pass_admission() {
        use std::collections::BTreeSet;
        let data = supervise::capture_root()
            .unwrap()
            .parent()
            .unwrap()
            .join(format!(
                "handoff-test-{}",
                platform::random_nonce().unwrap()
            ));
        platform::create_private_dir_new(&data).unwrap();
        let dir = data.join("launchd").join(platform::random_nonce().unwrap());
        platform::create_private_tree(&dir).unwrap();
        let run = data.join("run").join("proof");
        platform::create_private_tree(&run).unwrap();
        let workspace = run.join("workspace");
        let scratch = run.join("scratch");
        for path in [&workspace, &scratch] {
            platform::create_private_dir_new(path).unwrap();
        }
        let config_path = run.join("mxc-config.json");
        let config = serde_json::json!({
            "filesystem": {"readonlyPaths": ["/usr/bin"], "readwritePaths": [workspace, scratch], "deniedPaths": [run.join("denied")]},
            "process": {"cwd": workspace, "env": [
                format!("HOME={}", scratch.display()), format!("TMPDIR={}/", scratch.display()),
                format!("XDG_CACHE_HOME={}/cache", scratch.display()),
                format!("CLANG_MODULE_CACHE_PATH={}/clang-cache", scratch.display()),
                format!("OPENSSL_CONF={}/openssl.cnf", scratch.display()),
                format!("CARGO_HOME={}/cargo-home", scratch.display()),
                format!("CUSTOM_HOME={}/literal:home", scratch.display()),
                "PATH=/usr/bin:/bin".to_string(), "RUSTUP_HOME=/usr/local/rust".to_string()
            ]}
        });
        platform::write_private_new(&config_path, &serde_json::to_vec(&config).unwrap()).unwrap();
        let request = Request {
            program: run.join("executor/mxc").as_os_str().as_bytes().to_vec(),
            args: vec![
                b"--config".to_vec(),
                config_path.as_os_str().as_bytes().to_vec(),
            ],
            env: vec![(
                b"TMPDIR".to_vec(),
                run.join("executor-temp").as_os_str().as_bytes().to_vec(),
            )],
            cwd: run.as_os_str().as_bytes().to_vec(),
            limits: Limits {
                wall_ms: 5000,
                cpu_secs: None,
                file_size_bytes: None,
                open_files: None,
                memory_bytes: None,
                tasks: None,
                output_cap_bytes: 4096,
            },
            nonce: Some("nonce".into()),
            marker: Some("marker".into()),
            parent_coalition: 1,
            grants: vec![workspace.clone(), scratch.clone()],
            capture: supervise::CapturePlan::new().unwrap(),
        };
        // Exercise the real wire round trip, not a separate test-only builder.
        let request: Request =
            serde_json::from_slice(&serde_json::to_vec(&request).unwrap()).unwrap();
        let developer = data.join("Xcode.APP/Contents/Developer");
        platform::create_private_tree(&developer).unwrap();
        let mut selection = SelectedDeveloper::new(developer.clone());
        let mut checked = BTreeSet::new();
        let admitted = request
            .admit_with_mxc(&dir, &mut selection, &mut |path, _| {
                checked.insert(path.to_path_buf());
                Ok(())
            })
            .unwrap();
        let staged_leaf_admitted = |path: &Path| {
            path.parent() == Some(dir.as_path())
                && checked.contains(&dir)
                && path.file_name() == Some(OsStr::new("omgs"))
        };
        assert!(!staged_leaf_admitted(&dir.join("unadmitted")));
        let plist = admitted.plist().unwrap();
        let command = admitted.command();
        for path in [
            Path::new(command.get_program()),
            command.get_current_dir().unwrap(),
        ]
        .into_iter()
        .chain(
            command
                .get_args()
                .map(Path::new)
                .filter(|path| path.is_absolute()),
        ) {
            assert!(
                checked.contains(path),
                "unadmitted command path: {}",
                path.display()
            );
        }
        for (key, value) in command
            .get_envs()
            .filter_map(|(key, value)| value.map(|value| (key, value)))
        {
            crate::tcc::visit_environment(key, value, &mut |path| {
                assert!(
                    checked.contains(path),
                    "unadmitted command environment: {}",
                    path.display()
                );
                Ok(())
            })
            .unwrap();
        }
        // Inspect the actual launchd wire document too. Any new absolute
        // plist path or environment path must have gone through the gate.
        for value in plist
            .split("<string>")
            .skip(1)
            .map(|part| part.split("</string>").next().unwrap())
        {
            for path in std::env::split_paths(OsStr::new(value)).filter(|path| path.is_absolute()) {
                assert!(
                    (checked.contains(&path) || staged_leaf_admitted(&path)),
                    "unadmitted plist path: {}",
                    path.display()
                );
            }
        }
        let mut expected: BTreeSet<PathBuf> = [
            data.clone(),
            data.join("launchd"),
            data.join("launchd/registry"),
            dir.clone(),
            dir.join("executor-home"),
            dir.join("executor-temp"),
            run.clone(),
            run.join("executor/mxc"),
            run.join("executor-temp"),
            config_path,
            workspace,
            scratch.clone(),
            scratch.join("cache"),
            scratch.join("clang-cache"),
            scratch.join("openssl.cnf"),
            scratch.join("cargo-home"),
            scratch.join("literal:home"),
            scratch.join("literal"),
            run.join("denied"),
        ]
        .into_iter()
        .collect();
        for path in [
            "/usr/bin",
            "/bin",
            "/usr/sbin",
            "/sbin",
            "/bin/sleep",
            "/dev/null",
            "/usr/lib",
            "/System/Library/Frameworks",
            "/usr/local/rust",
            "/",
            "/bin/sh",
            "/usr/libexec",
            "/usr/share",
            "/System",
            "/Library",
            "/private/var/db/timezone",
            "/private/var/db/dyld",
            "/private/var/select",
            "/private/etc",
            "/dev",
            "/dev/zero",
            "/dev/random",
            "/dev/urandom",
            "/dev/tty",
            "/dev/fd",
            "/dev/ptmx",
            "/private/var/db/xcode_select_link",
        ] {
            expected.insert(path.into());
        }
        let capture_json = serde_json::to_value(&request.capture).unwrap();
        let capture_root = PathBuf::from(capture_json["root"].as_str().unwrap());
        expected.insert(capture_root.parent().unwrap().to_path_buf());
        expected.insert(capture_root);
        for dir in capture_json["directories"].as_array().unwrap() {
            let dir = PathBuf::from(dir.as_str().unwrap());
            expected.insert(dir.join("pipe"));
            expected.insert(dir);
        }
        expected.insert(developer.clone());
        expected.insert(data.join("Xcode.APP"));
        assert_eq!(
            selection.inspected.as_slice(),
            std::slice::from_ref(&developer)
        );
        assert_eq!(checked, expected);
        // Refusing any one path must prevent obtaining the submission token.
        for rejected in expected {
            let error = request
                .admit_with_mxc(
                    &dir,
                    &mut SelectedDeveloper::new(developer.clone()),
                    &mut |path, _| {
                        if path == rejected {
                            Err(io::Error::other("injected handoff refusal"))
                        } else {
                            Ok(())
                        }
                    },
                )
                .err()
                .unwrap();
            assert!(
                error.to_string().contains("injected handoff refusal"),
                "{}: {error}",
                rejected.display()
            );
        }
        // Candidate metadata must never touch protected or external storage,
        // including the legacy selection when the first link is absent.
        for target in [
            "/Volumes/Build/Xcode.app/Contents/Developer",
            "/Users/example/Documents/Xcode.app/Contents/Developer",
        ] {
            for legacy in [false, true] {
                let mut selection = SelectedDeveloper::new(target.into());
                if legacy {
                    selection.targets.swap(0, 1);
                }
                let error = request
                    .admit_with_mxc(&dir, &mut selection, &mut crate::tcc::admit_executor_path)
                    .err()
                    .unwrap();
                assert!(error.to_string().contains("TCC consent"), "{error}");
                assert!(
                    selection.inspected.is_empty(),
                    "candidate stat preceded admission"
                );
            }
        }
        // Widened bundles may not overlap registry, job or capture storage.
        for storage in [dir.parent().unwrap(), dir.as_path(), request.capture.root()] {
            let developer = storage.join("Xcode.app/Contents/Developer");
            platform::create_private_tree(&developer).unwrap();
            let error = request
                .admit_with_mxc(
                    &dir,
                    &mut SelectedDeveloper::new(developer.clone()),
                    &mut crate::tcc::admit_executor_path,
                )
                .err()
                .unwrap();
            assert!(
                error
                    .to_string()
                    .contains("private storage overlaps MXC grant"),
                "{error}"
            );
            std::fs::remove_dir_all(developer.parent().unwrap().parent().unwrap()).unwrap();
        }
        // The developer subtree is disjoint from this job, but MXC's widened
        // bundle includes SharedFrameworks and therefore includes the registry.
        let sibling_job = data.join("Xcode.APP/Contents/SharedFrameworks/launchd/job");
        let error = request
            .admit_with_mxc(
                &sibling_job,
                &mut SelectedDeveloper::new(developer.clone()),
                &mut crate::tcc::admit_executor_path,
            )
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains("private storage overlaps MXC grant"),
            "{error}"
        );
        // Canonical selection aliases must also participate in overlap checks.
        let alias = data.join("developer-alias");
        std::os::unix::fs::symlink(request.capture.root(), &alias).unwrap();
        assert!(request
            .admit_with_mxc(
                &dir,
                &mut SelectedDeveloper::new(alias.clone()),
                &mut crate::tcc::admit_executor_path
            )
            .err()
            .unwrap()
            .to_string()
            .contains("private storage overlaps MXC grant"));
        std::fs::remove_file(alias).unwrap();
        // Root ownership checks, first-valid selection and legacy fallback use
        // the same order as MXC, without touching a real selection or volume.
        let mut selection =
            SelectedDeveloper::new("/Volumes/Untrusted/Xcode.app/Contents/Developer".into());
        selection.trusted[0] = false;
        selection.targets[1] = Some(developer.clone());
        request
            .admit_with_mxc(&dir, &mut selection, &mut crate::tcc::admit_executor_path)
            .unwrap();
        assert_eq!(
            selection.inspected.as_slice(),
            std::slice::from_ref(&developer)
        );
        let mut selection = SelectedDeveloper::new(data.join("missing-developer"));
        selection.targets[1] = Some(developer.clone());
        request
            .admit_with_mxc(&dir, &mut selection, &mut crate::tcc::admit_executor_path)
            .unwrap();
        assert_eq!(
            selection.inspected,
            [data.join("missing-developer"), developer.clone()]
        );
        // HOME-expanded config grants must not escape the private-storage
        // overlap check, even though the serialized spelling is only `~`.
        let mut home_config = config.clone();
        home_config["filesystem"]["readonlyPaths"] = serde_json::json!(["~"]);
        std::fs::write(
            run.join("mxc-config.json"),
            serde_json::to_vec(&home_config).unwrap(),
        )
        .unwrap();
        let error = request
            .admit_with_mxc(
                &dir,
                &mut SelectedDeveloper::new(developer.clone()),
                &mut crate::tcc::admit_executor_path,
            )
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains("private storage overlaps MXC grant"),
            "{error}"
        );
        std::fs::write(
            run.join("mxc-config.json"),
            serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
        // The same gate is repeated by the anchor. A changed selection after a
        // successful admission must not reuse an earlier submission token.
        request
            .admit_with_mxc(
                &dir,
                &mut SelectedDeveloper::new(developer.clone()),
                &mut crate::tcc::admit_executor_path,
            )
            .unwrap();
        assert!(request
            .admit_with_mxc(
                &dir,
                &mut SelectedDeveloper::new("/Volumes/Changed/Xcode.app/Contents/Developer".into()),
                &mut crate::tcc::admit_executor_path
            )
            .is_err());
        // The production gate must also inspect config contents, not just its filename.
        let mut protected = config;
        protected["process"]["env"][0] = "HOME=/Users/omgs-tcc-refusal/Documents".into();
        std::fs::write(
            run.join("mxc-config.json"),
            serde_json::to_vec(&protected).unwrap(),
        )
        .unwrap();
        assert!(request
            .admit(&dir)
            .err()
            .unwrap()
            .to_string()
            .contains("TCC consent"));
        assert!(!dir.join("request").exists());
        assert!(!dir.join("job.plist").exists());
        std::fs::remove_dir_all(data).unwrap();
    }
    #[test]
    fn actual_registry_and_job_volumes_are_admitted() {
        let data = supervise::capture_root()
            .unwrap()
            .join(format!("mount-test-{}", platform::random_nonce().unwrap()));
        platform::create_private_dir_new(&data).unwrap();
        let root = data.join("launchd");
        platform::create_private_dir_new(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let data = data.canonicalize().unwrap();
        let mut checked = Vec::new();
        let mut reject_mount = |mount: &Path| {
            checked.push(mount.to_path_buf());
            if mount == root {
                Err(io::Error::other("injected external child volume"))
            } else {
                Ok(())
            }
        };
        let error = root_with(&data, &mut |path| {
            crate::tcc::admit_path_with_volume(path, &mut reject_mount)
        })
        .unwrap_err();
        assert!(error.to_string().contains("external child volume"));
        assert_eq!(checked, [data.clone(), root.clone()]);
        assert!(std::fs::read_dir(&root).unwrap().next().is_none());

        let dir = root.join(platform::random_nonce().unwrap());
        platform::create_private_dir_new(&dir).unwrap();
        // The directory is the storage boundary. Leaf opens separately require
        // same-device regular files and never follow links.
        let error = admit_job_storage_with(&dir, &mut |path| {
            assert_eq!(path, dir);
            crate::tcc::admit_path_with_volume(path, &mut |_| {
                Err(io::Error::other("injected external job volume"))
            })
        })
        .unwrap_err();
        assert!(error.to_string().contains("external job volume"));
        std::fs::remove_dir_all(data).unwrap();
    }
    #[test]
    fn job_leaf_admission_survives_every_publication_transition() {
        let dir = supervise::capture_root()
            .unwrap()
            .join(format!("leaf-race-{}", platform::random_nonce().unwrap()));
        platform::create_private_dir_new(&dir).unwrap();
        let names = [
            "owner",
            "omgs",
            "job.plist",
            "request",
            "domain",
            "ready",
            "compatible",
            "start",
            "result",
            "error",
            "cancel",
            "orphan",
            "release",
        ];
        for base in names {
            for suffix in ["", ".tmp"] {
                let name = format!("{base}{suffix}");
                let leaf = dir.join(&name);
                let moved = dir.join("moved");
                // Inject each transition before canonicalization, at the volume
                // inspection (after canonicalization), and after inspection.
                // No scheduler timing or concurrent test process is involved.
                for step in 0..3 {
                    for transition in 0..3 {
                        if transition != 0 {
                            platform::write_private_new(&leaf, b"1").unwrap();
                        }
                        let inject = || match transition {
                            0 => platform::write_private_new(&leaf, b"1").unwrap(),
                            1 => std::fs::rename(&leaf, &moved).unwrap(),
                            _ => std::fs::remove_file(&leaf).unwrap(),
                        };
                        let directory = JobDirectory::open_with(&dir, &mut |path| {
                            assert_eq!(path, dir);
                            if step == 0 {
                                inject();
                            }
                            let mut inspected = 0;
                            admit_job_storage_with(path, &mut |storage| {
                                assert_eq!(storage, dir, "transient leaf reached path inspection");
                                inspected += 1;
                                crate::tcc::admit_path_with_volume(storage, &mut |_| {
                                    if step == 1 {
                                        inject();
                                    }
                                    Ok(())
                                })
                            })?;
                            assert_eq!(inspected, 1);
                            if step == 2 {
                                inject();
                            }
                            Ok(())
                        })
                        .unwrap();
                        // Recheck the same directory while the leaf is absent
                        // or newly published, then admit its name without I/O.
                        admit_job_storage(&dir).unwrap();
                        JobDirectory::name(&name).unwrap();
                        if transition == 0 {
                            let value = directory.open_leaf(&name, libc::O_RDONLY, 0).unwrap();
                            assert_eq!(value.metadata().unwrap().len(), 1);
                            std::fs::remove_file(&leaf).unwrap();
                        } else {
                            assert_eq!(
                                directory
                                    .open_leaf(&name, libc::O_RDONLY, 0)
                                    .unwrap_err()
                                    .kind(),
                                io::ErrorKind::NotFound
                            );
                            if transition == 1 {
                                std::fs::rename(&moved, &leaf).unwrap();
                                directory.open_leaf(&name, libc::O_RDONLY, 0).unwrap();
                                std::fs::remove_file(&leaf).unwrap();
                            }
                        }
                        directory.create(&name, b"1", 0o600).unwrap();
                        std::fs::remove_file(&leaf).unwrap();
                    }
                }
                // A symlink is never opened, even when planted after admission.
                let directory = JobDirectory::open(&dir).unwrap();
                std::os::unix::fs::symlink("/Users/omgs/Documents/secret", &leaf).unwrap();
                assert!(directory.open_leaf(&name, libc::O_RDONLY, 0).is_err());
                assert!(leaf_exists(&dir, &name).is_err());
                assert!(directory.create(&name, b"changed", 0o600).is_err());
                std::fs::remove_file(&leaf).unwrap();
            }
        }
        for name in [
            "",
            ".",
            "..",
            "../request",
            "a/b",
            "/request",
            "request/",
            "a/./b",
            "a\0b",
        ] {
            assert!(JobDirectory::name(name).is_err(), "{name:?}");
        }
        let alias = dir.with_extension("alias");
        std::os::unix::fs::symlink(&dir, &alias).unwrap();
        assert!(JobDirectory::open(&alias).is_err());
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn job_cleanup_unlinks_only_known_leaves_without_following_links() {
        let root = supervise::capture_root()
            .unwrap()
            .join(format!("cleanup-{}", platform::random_nonce().unwrap()));
        platform::create_private_dir_new(&root).unwrap();
        let dir = root.join(platform::random_nonce().unwrap());
        platform::create_private_dir_new(&dir).unwrap();
        let directory = JobDirectory::open(&dir).unwrap();
        let sentinel = root.join("sentinel");
        platform::write_private_new(&sentinel, b"preserved").unwrap();
        for base in JOB_LEAVES {
            for suffix in ["", ".tmp"] {
                // Every known leaf, including a temporary sibling, can be
                // replaced by a link without redirecting cleanup to its target.
                std::os::unix::fs::symlink(&sentinel, dir.join(format!("{base}{suffix}"))).unwrap();
            }
        }
        for name in ["executor-home", "executor-temp", "unknown"] {
            platform::create_private_dir_new(&dir.join(name)).unwrap();
        }
        platform::write_private_new(&dir.join("unknown/evidence"), b"retained").unwrap();
        assert_eq!(
            directory.remove().unwrap_err().kind(),
            io::ErrorKind::DirectoryNotEmpty
        );
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"preserved");
        assert_eq!(
            std::fs::read(dir.join("unknown/evidence")).unwrap(),
            b"retained"
        );
        for base in JOB_LEAVES {
            for suffix in ["", ".tmp"] {
                assert!(std::fs::symlink_metadata(dir.join(format!("{base}{suffix}"))).is_err());
            }
        }
        std::fs::remove_file(dir.join("unknown/evidence")).unwrap();
        std::fs::remove_dir(dir.join("unknown")).unwrap();
        directory.remove().unwrap();
        assert!(!dir.exists());
        std::fs::remove_file(sentinel).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
    #[test]
    fn job_cleanup_stays_pinned_across_job_and_parent_path_replacement() {
        let root = supervise::capture_root().unwrap().join(format!(
            "cleanup-swap-{}",
            platform::random_nonce().unwrap()
        ));
        platform::create_private_dir_new(&root).unwrap();
        let parent = root.join("parent");
        platform::create_private_dir_new(&parent).unwrap();
        let dir = parent.join(platform::random_nonce().unwrap());
        platform::create_private_dir_new(&dir).unwrap();
        let directory = JobDirectory::open(&dir).unwrap();
        directory.create("request", b"original", 0o600).unwrap();
        let moved = parent.join("moved");
        std::fs::rename(&dir, &moved).unwrap();
        platform::create_private_dir_new(&dir).unwrap();
        platform::write_private_new(&dir.join("request"), b"replacement").unwrap();
        assert!(directory
            .remove()
            .unwrap_err()
            .to_string()
            .contains("changed"));
        assert!(!moved.join("request").exists());
        assert_eq!(std::fs::read(dir.join("request")).unwrap(), b"replacement");
        std::fs::remove_file(dir.join("request")).unwrap();
        std::fs::remove_dir(&dir).unwrap();
        std::os::unix::fs::symlink(&moved, &dir).unwrap();
        assert!(directory
            .remove()
            .unwrap_err()
            .to_string()
            .contains("changed"));
        assert!(std::fs::symlink_metadata(&dir)
            .unwrap()
            .file_type()
            .is_symlink());
        std::fs::remove_file(&dir).unwrap();
        std::fs::rename(&moved, &dir).unwrap();
        let moved_parent = root.join("moved-parent");
        std::fs::rename(&parent, &moved_parent).unwrap();
        platform::create_private_dir_new(&parent).unwrap();
        let replacement = parent.join(dir.file_name().unwrap());
        platform::create_private_dir_new(&replacement).unwrap();
        platform::write_private_new(&replacement.join("request"), b"other parent").unwrap();
        directory.remove().unwrap();
        assert!(!moved_parent.join(dir.file_name().unwrap()).exists());
        assert_eq!(
            std::fs::read(replacement.join("request")).unwrap(),
            b"other parent"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn recovery_removes_previous_boot_job_leaves_and_temporary_siblings() {
        let root = supervise::capture_root().unwrap().join(format!(
            "cleanup-recover-{}",
            platform::random_nonce().unwrap()
        ));
        platform::create_private_dir_new(&root).unwrap();
        let dir = root.join(platform::random_nonce().unwrap());
        platform::create_private_dir_new(&dir).unwrap();
        drop(lock(&dir, true).unwrap());
        write(
            &dir,
            "ready",
            &Ready {
                boot: format!("{}-previous", boot_id().unwrap()),
                coalition: 0,
                pid: 0,
                generation: 0,
            },
        )
        .unwrap();
        let directory = JobDirectory::open(&dir).unwrap();
        for base in JOB_LEAVES {
            directory
                .create(&format!("{base}.tmp"), b"partial", 0o600)
                .unwrap();
        }
        for name in ["executor-home", "executor-temp"] {
            platform::create_private_dir_new(&dir.join(name)).unwrap();
        }
        let guard = registry(&root).unwrap();
        recover(&root, &Api::load().unwrap()).unwrap();
        assert!(!dir.exists());
        drop(guard);
        std::fs::remove_file(root.join("registry")).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
    #[test]
    fn recovery_reclaims_unpublished_ownerless_directories_and_spares_live_jobs() {
        let root = supervise::capture_root()
            .unwrap()
            .join(format!("owner-test-{}", platform::random_nonce().unwrap()));
        platform::create_private_dir_new(&root).unwrap();
        let guard = registry(&root).unwrap();
        let abandoned = root.join(platform::random_nonce().unwrap());
        let live = root.join(platform::random_nonce().unwrap());
        platform::create_private_dir_new(&abandoned).unwrap();
        platform::create_private_dir_new(&live).unwrap();
        let owner = lock(&live, true).unwrap();
        let api = Api::load().unwrap();
        recover(&root, &api).unwrap();
        assert!(!abandoned.exists());
        assert!(live.join("owner").exists());
        assert!(!live.join("cancel").exists());
        assert!(!live.join("orphan").exists());
        // Cleanup can unlink a live job's owner before its other files or
        // directory. That state must not block a concurrent invocation.
        platform::create_private_dir_new(&abandoned).unwrap();
        platform::write_private_new(&abandoned.join("request"), b"evidence").unwrap();
        recover(&root, &api).unwrap();
        assert_eq!(
            std::fs::read(abandoned.join("request")).unwrap(),
            b"evidence"
        );
        // Also cover disappearance after enumeration but before reclamation.
        reclaim_unpublished(&root.join(platform::random_nonce().unwrap())).unwrap();
        assert!(live.join("owner").exists());
        assert!(!live.join("cancel").exists());
        drop(owner);
        drop(guard);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn rolling_chain_and_empty_enumeration_cannot_substitute_for_the_count() {
        for listed in [false, true] {
            let mut chain = Chain {
                counts: VecDeque::new(),
                elapsed: Duration::ZERO,
                listed,
            };
            let mut survivors = Vec::new();
            let error = sweep_with(&mut chain, 7, Some(1), &mut survivors).unwrap_err();
            assert!(error.to_string().contains("unresolved owned tasks"));
            assert!(survivors.is_empty());
            assert_eq!(chain.elapsed, CLEANUP);
        }
    }
    #[test]
    fn unidentified_owned_activity_remains_unclean_after_count_reaches_one() {
        let mut chain = Chain {
            counts: [2, 2, 1].into(),
            elapsed: Duration::ZERO,
            listed: true,
        };
        let error = sweep_with(&mut chain, 7, Some(1), &mut Vec::new()).unwrap_err();
        assert!(error.to_string().contains("proof remains unclean"));
    }
    #[test]
    fn membership_queries_work_without_the_optional_list_interface() {
        let mut api = Api::load().unwrap();
        api.members = None;
        let pid = std::process::id() as i32;
        assert!(api.members(coalition(pid).unwrap()).unwrap().contains(&pid));
    }
    #[test]
    fn previous_boot_state_never_inspects_or_signals_a_reused_coalition() {
        let root = supervise::capture_root()
            .unwrap()
            .join(format!("boot-test-{}", platform::random_nonce().unwrap()));
        platform::create_private_dir_new(&root).unwrap();
        let dir = root.join(platform::random_nonce().unwrap());
        platform::create_private_dir_new(&dir).unwrap();
        drop(lock(&dir, true).unwrap());
        // Deliberately name this live process's coalition. Recovery must discard
        // the stale boot epoch before even reaching the overlap safety check.
        write(
            &dir,
            "ready",
            &Ready {
                boot: "previous-boot".into(),
                pid: std::process::id() as i32,
                generation: 1,
                coalition: coalition(std::process::id() as i32).unwrap(),
            },
        )
        .unwrap();
        let guard = registry(&root).unwrap();
        recover(&root, &Api::load().unwrap()).unwrap();
        drop(guard);
        std::fs::remove_file(root.join("registry")).unwrap();
        assert!(!dir.exists());
        std::fs::remove_dir(root).unwrap();
    }
    #[test]
    fn staged_anchor_requires_exact_bytes_and_a_stable_source() {
        use std::io::{Seek, SeekFrom, Write};
        let dir = supervise::capture_root()
            .unwrap()
            .join(format!("copy-test-{}", platform::random_nonce().unwrap()));
        platform::create_private_dir_new(&dir).unwrap();
        let source = dir.join("source");
        let copy = dir.join("copy");
        platform::write_private_new(&source, b"trusted executable bytes").unwrap();
        stage_binary(&source, &copy).unwrap();
        let mut original = File::open(&source).unwrap();
        let before = original.metadata().unwrap();
        let mut staged = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&copy)
            .unwrap();
        staged.write_all(b"changed").unwrap();
        assert!(verify_copy(&mut original, &mut staged, &before).is_err());
        staged.seek(SeekFrom::Start(0)).unwrap();
        staged.write_all(b"trusted executable bytes").unwrap();
        verify_copy(&mut original, &mut staged, &before).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&source)
            .unwrap()
            .write_all(b"changed")
            .unwrap();
        assert!(verify_copy(&mut original, &mut staged, &before).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn private_ipc_cannot_live_in_baseline_readable_system_trees() {
        for path in [
            "/Library/omgs",
            "/library/omgs",
            "/OPT/omgs",
            "/System/Volumes/Data/omgs",
            "/usr/local/omgs",
            "/opt/omgs",
        ] {
            assert!(admit_private_data_location(Path::new(path))
                .unwrap_err()
                .to_string()
                .contains("baseline-readable"));
        }
        admit_private_data_location(Path::new("/Users/example/.local/share/omgs")).unwrap();
        admit_private_data_location(Path::new("/private/tmp/omgs-private-data")).unwrap();
    }
    #[test]
    fn anchor_loss_is_not_a_clean_certificate() {
        let mut chain = Chain {
            counts: [0].into(),
            elapsed: Duration::ZERO,
            listed: false,
        };
        assert!(sweep_with(&mut chain, 7, Some(1), &mut Vec::new())
            .unwrap_err()
            .to_string()
            .contains("anchor disappeared"));
    }
}
