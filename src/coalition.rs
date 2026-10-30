//! Per-invocation launchd ownership on Darwin. Enumeration locates tasks to
//! signal; only resource accounting certifies that no executable task remains.
use crate::platform;
use crate::supervise::{self, Limits, Supervised, Survivor};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::ffi::{CStr, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::{ffi::OsStrExt, ffi::OsStringExt};
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

fn read<T: DeserializeOwned>(dir: &Path, name: &str) -> io::Result<T> {
    let bytes = platform::read_private_bounded_in(dir, Path::new(name), 4 * 1024 * 1024)?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}
fn write<T: Serialize>(dir: &Path, name: &str, value: &T) -> io::Result<()> {
    platform::write_private_new(
        &dir.join(format!("{name}.tmp")),
        &serde_json::to_vec(value)?,
    )?;
    std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(name))
}
fn lock(dir: &Path, create: bool) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join("owner"))?;
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
    admit_private_data_location(&data)?;
    crate::tcc::admit_path(&data)?;
    platform::create_private_tree(&data)?;
    let root = data.join("launchd");
    platform::create_private_tree(&root)?;
    Ok(root)
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
fn recover(root: &Path, api: &Api) -> io::Result<()> {
    let boot = boot_id()?;
    for entry in std::fs::read_dir(root)? {
        let dir = entry?.path();
        if dir.file_name() == Some(OsStr::new("registry")) {
            continue;
        }
        match platform::check_private_dir(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        }
        label(&dir)?;
        let _lock = match lock(&dir, false) {
            Ok(lock) => lock,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            // Creation has not yet published the owner file.
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if let Ok(ready) = read::<Ready>(&dir, "ready") {
            // Launchd bootstrap state is not persistent. Neither coalition IDs
            // nor process generations may identify ownership across a reboot.
            if ready.boot != boot {
                std::fs::remove_dir_all(&dir)?;
                continue;
            }
        }
        // Taking the abandoned lock also tells its anchor that the owner is gone
        // through the explicit cancellation file, even while recovery owns it.
        if !dir.join("orphan").exists() {
            platform::write_private_new(&dir.join("orphan"), b"")?;
        }
        if !dir.join("cancel").exists() {
            platform::write_private_new(&dir.join("cancel"), b"")?;
        }
        let start = Instant::now();
        while start.elapsed() < STARTUP {
            if let Ok(ready) = read::<Ready>(&dir, "ready") {
                if empty(api, ready.coalition)? {
                    break;
                }
            } else if dir.join("error").exists() {
                break;
            }
            std::thread::sleep(POLL);
        }
        if dir.join("start").exists() {
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
        if dir.join("domain").exists() {
            remove_job(&dir)?;
        }
        std::fs::remove_dir_all(dir)?;
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
    use std::os::unix::fs::OpenOptionsExt;
    let mut source = File::open(source)?;
    let before = source.metadata()?;
    if !before.is_file() {
        return Err(io::Error::other("anchor source is not a regular file"));
    }
    let mut staged = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(target)?;
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
        let api = Api::load()?;
        let cwd = cmd
            .get_current_dir()
            .map(Path::to_path_buf)
            .unwrap_or(std::env::current_dir()?);
        crate::tcc::admit_path(&cwd)?;
        crate::tcc::admit_path(Path::new(cmd.get_program()))?;
        for arg in cmd.get_args().filter(|a| Path::new(a).is_absolute()) {
            crate::tcc::admit_path(Path::new(arg))?;
        }
        crate::tcc::admit_environment(cmd.get_envs().filter_map(|(_, value)| value))?;
        for grant in grants {
            crate::tcc::admit_grant(grant)?;
        }
        let root = root()?;
        supervise::validate_capture_grants(&root, grants)?;
        supervise::validate_capture_grants(&supervise::capture_root()?, grants)?;
        let registry_guard = registry(&root)?;
        recover(&root, &api)?;
        let dir = root.join(platform::random_nonce()?);
        platform::create_private_dir_new(&dir)?;
        let owner = lock(&dir, true)?;
        drop(registry_guard);
        let mut job = Job {
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
            cwd: cmd
                .get_current_dir()
                .map(Path::to_path_buf)
                .unwrap_or(std::env::current_dir()?)
                .as_os_str()
                .as_bytes()
                .to_vec(),
            limits: limits.clone(),
            nonce: nonce.map(str::to_owned),
            marker: marker.map(str::to_owned),
            parent_coalition: coalition(std::process::id() as i32)?,
        };
        write(&job.dir, "request", &request)?;
        let data = job
            .dir
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_string_lossy();
        let directory = job.dir.to_string_lossy();
        let environment = [
            ("OMGS_HOME", data.as_ref()),
            ("HOME", directory.as_ref()),
            ("TMPDIR", directory.as_ref()),
            ("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
            ("RUST_BACKTRACE", "0"),
            ("DYLD_INSERT_LIBRARIES", ""),
            ("DYLD_LIBRARY_PATH", ""),
            ("DYLD_FRAMEWORK_PATH", ""),
            ("DYLD_FALLBACK_LIBRARY_PATH", "/usr/lib"),
            ("DYLD_FALLBACK_FRAMEWORK_PATH", "/System/Library/Frameworks"),
        ]
        .iter()
        .map(|(key, value)| format!("<key>{}</key><string>{}</string>", xml(key), xml(value)))
        .collect::<String>();
        let plist = format!(
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
            label(&job.dir)?,
            xml(&binary.to_string_lossy()),
            xml(&directory),
            xml(&directory),
            environment
        );
        platform::write_private_new(&job.dir.join("job.plist"), plist.as_bytes())?;
        let domain = domain();
        write(&job.dir, "domain", &domain)?;
        job.submitted = true;
        launchctl(&[
            OsStr::new("bootstrap"),
            OsStr::new(&domain),
            job.dir.join("job.plist").as_os_str(),
        ])?;
        let service = format!("{}/{}", domain, label(&job.dir)?);
        launchctl(&[OsStr::new("kickstart"), OsStr::new(&service)])?;
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
                platform::write_private_new(&job.dir.join("cancel"), b"")?;
                cancel_sent = true;
            }
            if let Ok(error) = read::<String>(&job.dir, "error") {
                return Err(io::Error::other(error));
            }
            if ready.is_none() && job.dir.join("compatible").exists() {
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
                    platform::write_private_new(&job.dir.join("start"), b"")?;
                    ready = Some(r);
                }
            }
            if job.dir.join("result").exists() {
                let mut result: Supervised = read(&job.dir, "result")?;
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
    _owner: File,
    submitted: bool,
}
impl Job {
    fn finish(&mut self, api: &Api, ready: &Ready) -> io::Result<()> {
        platform::write_private_new(&self.dir.join("release"), b"")?;
        let start = Instant::now();
        while !empty(api, ready.coalition)? {
            if start.elapsed() >= STARTUP {
                return Err(io::Error::other("anchor exit bound reached"));
            }
            std::thread::sleep(POLL);
        }
        remove_job(&self.dir)?;
        self.submitted = false;
        std::fs::remove_dir_all(&self.dir)
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        if self.submitted {
            let _ = platform::write_private_new(&self.dir.join("cancel"), b"");
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
        if self.dir.join("start").exists() && read::<Ready>(&self.dir, "ready").is_err() {
            return;
        }
        if let (Ok(api), Ok(r)) = (Api::load(), read::<Ready>(&self.dir, "ready")) {
            if !empty(&api, r.coalition).unwrap_or(false) {
                return;
            }
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Hidden trusted entry point. No target is started until the parent admits the
/// fresh coalition. After run_inner returns, no path here spawns another process.
pub fn anchor(dir: &Path) -> io::Result<()> {
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
        platform::write_private_new(&dir.join("compatible"), b"")?;
        let start = Instant::now();
        while !dir.join("start").exists() {
            if owner_gone(dir) || dir.join("cancel").exists() || start.elapsed() >= STARTUP {
                return Ok(());
            }
            std::thread::sleep(POLL);
        }
        if owner_gone(dir) || dir.join("cancel").exists() {
            return Ok(());
        }
        let stop = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        let monitor = {
            let (stop, done, dir) = (stop.clone(), done.clone(), dir.to_path_buf());
            std::thread::spawn(move || {
                while !done.load(Ordering::Acquire) {
                    if dir.join("cancel").exists() || owner_gone(&dir) {
                        stop.store(true, Ordering::Release);
                        return;
                    }
                    std::thread::sleep(POLL);
                }
            })
        };
        let mut cmd = Command::new(OsString::from_vec(req.program));
        cmd.args(req.args.into_iter().map(OsString::from_vec))
            .env_clear()
            .envs(
                req.env
                    .into_iter()
                    .map(|(k, v)| (OsString::from_vec(k), OsString::from_vec(v))),
            )
            .current_dir(OsString::from_vec(req.cwd));
        OWNED.with(|owned| owned.set(Some(id)));
        let result = supervise::run_inner(
            cmd,
            &req.limits,
            None,
            req.nonce.as_deref(),
            req.marker.as_deref(),
            true,
            Some(&stop),
        );
        done.store(true, Ordering::Release);
        monitor
            .join()
            .map_err(|_| io::Error::other("owner monitor failed"))?;
        OWNED.with(|owned| owned.set(None));
        // SEALED: cleanup ran before capture drain. No process is spawned here.
        write(dir, "result", &result)?;
        let start = Instant::now();
        while !dir.join("release").exists()
            && !owner_gone(dir)
            && !dir.join("orphan").exists()
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
        recover(&root, &Api::load().unwrap()).unwrap();
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
