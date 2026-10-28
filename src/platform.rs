//! Small cross-platform helpers: the user's home directory and a PATH search
//! that works on Windows (PATHEXT) without shelling out to `which`.

use std::path::{Path, PathBuf};

/// The user's home directory: `HOME`, then `USERPROFILE` on Windows. Never a
/// relative fallback, so a missing variable cannot point OMGS at the cwd.
pub fn home() -> Option<PathBuf> {
    let from = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    from("HOME").or_else(|| {
        if cfg!(windows) {
            from("USERPROFILE")
        } else {
            None
        }
    })
}

/// The OMGS per-user data directory: `OMGS_HOME`, else `<home>/.local/share/omgs`.
pub fn data_dir() -> Option<PathBuf> {
    if let Some(v) = std::env::var_os("OMGS_HOME").filter(|v| !v.is_empty()) {
        let p = PathBuf::from(v);
        if p.is_absolute() {
            return Some(p);
        }
    }
    home().map(|h| h.join(".local").join("share").join("omgs"))
}

fn is_executable(p: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(p) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Find `name` on PATH. On Windows each PATHEXT extension is tried when the
/// name has none. Relative PATH entries are ignored so the current directory
/// can never supply a tool. Windows batch scripts are excluded to avoid
/// implicit cmd.exe execution with target-controlled arguments.
pub fn which(name: &str) -> Option<PathBuf> {
    #[cfg(windows)]
    if Path::new(name)
        .extension()
        .is_some_and(|e| !["exe", "com"].iter().any(|x| e.eq_ignore_ascii_case(x)))
    {
        return None;
    }
    let path = std::env::var_os("PATH")?;
    let exts: Vec<String> = if cfg!(windows) && Path::new(name).extension().is_none() {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
            .split(';')
            .filter(|e| [".exe", ".com"].iter().any(|x| e.eq_ignore_ascii_case(x)))
            .map(|e| e.to_ascii_lowercase())
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in std::env::split_paths(&path) {
        if !dir.is_absolute() {
            continue;
        }
        for ext in &exts {
            let candidate = dir.join(format!("{name}{ext}"));
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

/// Resolve only OS-selected internal temporary roots. User-supplied storage
/// and installation paths must still pass strict, non-resolving admission.
pub fn temp_root() -> std::io::Result<PathBuf> {
    let root = std::fs::canonicalize(std::env::temp_dir())?;
    // Git for Windows cannot consume extended canonical path prefixes. Keep
    // the physically resolved location, using the ordinary DOS/UNC spelling.
    #[cfg(windows)]
    let root = PathBuf::from(mxc_path(&root));
    Ok(root)
}

/// Admit the internal scratch parent without consulting OS temporary storage.
/// Callers must reserve each child exclusively with create_private_dir_new.
pub fn scratch_root() -> std::io::Result<PathBuf> {
    let root =
        data_dir().ok_or_else(|| std::io::Error::other("OMGS data directory unavailable"))?;
    create_private_tree(&root)?;
    // Git for Windows cannot consume extended canonical path prefixes.
    Ok(PathBuf::from(mxc_path(&std::fs::canonicalize(root)?)))
}

/// One retained staging directory. Sources are leaf names, never caller paths.
pub struct StagingDir(std::fs::File);
impl StagingDir {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        check_private_dir(path)?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options
                .share_mode(0x1 | 0x2)
                .custom_flags(0x0200_0000 | 0x0020_0000);
        }
        let file = options.open(path)?;
        if !file.metadata()?.is_dir() || is_link(&file.metadata()?) {
            return Err(std::io::Error::other("staging must be a real directory"));
        }
        Ok(Self(file))
    }

    pub fn read_verified(&self, name: &Path, expected: &str) -> std::io::Result<Vec<u8>> {
        use std::io::Error;
        if name.components().count() != 1
            || !matches!(
                name.components().next(),
                Some(std::path::Component::Normal(_))
            )
            || expected.len() != 64
            || !expected
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::other(
                "source must be a leaf name with a lowercase SHA-256",
            ));
        }
        #[cfg(unix)]
        let file = {
            use std::os::fd::{AsRawFd, FromRawFd};
            use std::os::unix::ffi::OsStrExt;
            let name = std::ffi::CString::new(name.as_os_str().as_bytes())?;
            // SAFETY: the retained directory and NUL-terminated leaf stay live.
            let fd = unsafe {
                libc::openat(
                    self.0.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(Error::last_os_error());
            }
            // SAFETY: openat returned a new descriptor owned by this File.
            unsafe { std::fs::File::from_raw_fd(fd) }
        };
        #[cfg(windows)]
        let file = windows_private::open_relative(&self.0, name)?;
        #[cfg(not(any(unix, windows)))]
        return Err(Error::other("staging handles unavailable"));
        if !is_single_link_file(&file)? {
            return Err(Error::other(
                "staging source must be a single-link regular file",
            ));
        }
        let bytes = read_bounded_file(file, 104857600)?;
        if crate::sha256::digest(&bytes) != expected {
            return Err(Error::other(format!(
                "verified source checksum mismatch: {}",
                name.display()
            )));
        }
        Ok(bytes)
    }
}

/// Open `path` for reading without following a final symlink (or reparse
/// point on Windows) and without blocking on a FIFO, and accept it only when
/// it is a regular file without hardlink aliases. An opened file may have
/// zero links after a concurrent atomic replacement. `Ok(None)` when missing.
/// Used for files whose content decides trust, so a planted symlink or
/// hardlink cannot substitute another file.
pub fn open_single_link(path: &Path) -> std::io::Result<Option<std::fs::File>> {
    use std::io::{Error, ErrorKind};
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if !is_single_link_file(&file)? {
        return Err(Error::other(format!(
            "{} must be a regular file with a single link",
            path.display()
        )));
    }
    Ok(Some(file))
}

/// Physical directory identity, independent of editable run identifiers.
pub fn directory_identity(path: &Path) -> std::io::Result<(u64, u64)> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0200_0000 | 0x0020_0000);
    }
    let file = options.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_dir() || is_link(&meta) {
        return Err(std::io::Error::other(
            "run must be a directory without links",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok((meta.dev(), meta.ino()))
    }
    #[cfg(windows)]
    {
        windows_file_identity(&file).map(|(volume, index)| (u64::from(volume), index))
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(std::io::Error::other("directory identity unavailable"))
    }
}

/// Admit the object actually held open, without resolving its old pathname.
pub(crate) fn check_private_dir_handle(file: &std::fs::File) -> std::io::Result<()> {
    let meta = file.metadata()?;
    if !meta.is_dir() || is_link(&meta) {
        return Err(std::io::Error::other(
            "scratch must be a non-reparse directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o7777 != 0o700 {
            return Err(std::io::Error::other(
                "scratch requires current owner and mode 0700",
            ));
        }
        #[cfg(target_os = "macos")]
        macos_private::check_file(file, meta.uid())?;
        Ok(())
    }
    #[cfg(windows)]
    {
        windows_private::check_file(file)
    }
}

pub(crate) fn held_directory_identity(file: &std::fs::File) -> std::io::Result<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file.metadata()?;
        Ok((meta.dev(), meta.ino()))
    }
    #[cfg(windows)]
    {
        windows_file_identity(file).map(|(v, i)| (u64::from(v), i))
    }
}

#[cfg(windows)]
pub(crate) use windows_private::{open_scratch_lock, open_scratch_relative, open_scratch_view};

/// Publish a private trust record exclusively. Existing entries are never replaced.
pub fn write_private_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    #[cfg(windows)]
    let mut file = open_private_write(path, true)?;
    #[cfg(not(windows))]
    let mut file = {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path)?
    };
    // Leave failed publications reserved. Partial records must fail closed.
    check_private_file(&file)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Sockets and FIFOs have no snapshot content; devices remain unsupported.
pub fn contentless(meta: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        meta.file_type().is_socket() || meta.file_type().is_fifo()
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        false
    }
}

/// Open content through links, rejecting special files before reading them.
pub fn open_regular(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK);
    }
    if !std::fs::metadata(path)?.is_file() {
        return Err(std::io::Error::other(format!(
            "{} must resolve to a regular file",
            describe_path(path)
        )));
    }
    let file = opts.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other(
            "opened content is not a regular file",
        ));
    }
    Ok(file)
}

pub fn describe_path(path: &Path) -> String {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if is_link(&meta) => format!(
            "{} (symlink to {})",
            path.display(),
            std::fs::canonicalize(path)
                .or_else(|_| std::fs::read_link(path))
                .unwrap_or_default()
                .display()
        ),
        _ => path.display().to_string(),
    }
}

/// Create private storage or validate a directory reserved earlier.
#[cfg(unix)]
pub fn private_dir(path: &Path) -> std::io::Result<()> {
    create_private_tree(path)
}

#[cfg(not(unix))]
pub fn private_dir(path: &Path) -> std::io::Result<()> {
    create_private_tree(path)
}

/// Remove Windows extended path prefixes for both writer and validator.
pub fn mxc_path(path: &Path) -> String {
    let s = path.to_string_lossy();
    if s.get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\UNC\"))
    {
        format!(r"\\{}", &s[8..])
    } else {
        s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
    }
}

/// Read a bounded regular file from the descriptor checked above.
pub fn read_bounded(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    use std::io::{Error, ErrorKind};
    let file =
        open_single_link(path)?.ok_or_else(|| Error::new(ErrorKind::NotFound, "file missing"))?;
    check_private_file(&file)
        .map_err(|e| Error::other(format!("storage {}: {e}", path.display())))?;
    read_bounded_file(file, limit)
}

pub(crate) fn read_bounded_file(file: std::fs::File, limit: u64) -> std::io::Result<Vec<u8>> {
    use std::io::{Error, Read};
    if file.metadata()?.len() > limit {
        return Err(Error::other("file exceeds byte limit"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(Error::other("file exceeds byte limit"));
    }
    Ok(bytes)
}

/// Read an inventory file beneath a trusted target without traversing links.
/// On Unix each component is opened relative to its pinned parent descriptor.
pub fn read_bounded_in(target: &Path, relative: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    with_file_in(target, relative, |file| read_bounded_file(file, limit))
}

/// Read private metadata, checking the opened leaf's owner, mode and ACL.
pub fn read_private_bounded_in(
    target: &Path,
    relative: &Path,
    limit: u64,
) -> std::io::Result<Vec<u8>> {
    with_file_in(target, relative, |file| {
        check_private_file(&file).map_err(|e| {
            std::io::Error::other(format!("storage {}: {e}", target.join(relative).display()))
        })?;
        read_bounded_file(file, limit)
    })
}

fn with_file_in<T>(
    target: &Path,
    relative: &Path,
    read: impl FnOnce(std::fs::File) -> std::io::Result<T>,
) -> std::io::Result<T> {
    if !crate::paths::safe_relative(relative) {
        return Err(std::io::Error::other(
            "inventory path must be relative without parent traversal",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        let mut dir = std::fs::File::open(target)?;
        let mut components = relative.components().peekable();
        while let Some(component) = components.next() {
            let name = std::ffi::CString::new(component.as_os_str().as_bytes())
                .map_err(|_| std::io::Error::other("NUL in inventory path"))?;
            let last = components.peek().is_none();
            let flags = libc::O_RDONLY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | if last {
                    libc::O_NONBLOCK
                } else {
                    libc::O_DIRECTORY
                };
            // SAFETY: dir owns a live directory descriptor and name is NUL-terminated.
            let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: successful openat returns a new descriptor owned here.
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            if last {
                if !is_single_link_file(&file)? {
                    return Err(std::io::Error::other(
                        "inventory content must be a single-link regular file",
                    ));
                }
                return read(file);
            }
            dir = file;
        }
        Err(std::io::Error::other("empty inventory path"))
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Keep every ancestor open without delete sharing, preventing rename
        // or replacement between checking an ancestor and opening its child.
        // The leaf permits FILE_SHARE_DELETE so a lock holder can publish a
        // replacement while this reader finishes reading its original handle.
        let open = |path: &Path, leaf: bool| {
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(0x1 | 0x2 | if leaf { 0x4 } else { 0 })
                .custom_flags(0x0200_0000 | 0x0020_0000)
                .open(path)
        };
        let mut path = std::fs::canonicalize(target)?;
        let root = open(&path, false)?;
        if is_link(&root.metadata()?) || !root.metadata()?.is_dir() {
            return Err(std::io::Error::other(
                "inventory target must be a directory without links",
            ));
        }
        let mut pinned = vec![root];
        let mut components = relative.components().peekable();
        while let Some(component) = components.next() {
            path.push(component);
            let file = open(&path, components.peek().is_none())?;
            let meta = file.metadata()?;
            if is_link(&meta) {
                return Err(std::io::Error::other("inventory links are excluded"));
            }
            if components.peek().is_none() {
                if !is_single_link_file(&file)? {
                    return Err(std::io::Error::other(
                        "inventory content must be a single-link regular file",
                    ));
                }
                return read(file);
            }
            if !meta.is_dir() {
                return Err(std::io::Error::other(
                    "inventory ancestor must be a directory",
                ));
            }
            pinned.push(file);
        }
        Err(std::io::Error::other("empty inventory path"))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, read);
        Err(std::io::Error::other(
            "contained inventory reads unavailable on this platform",
        ))
    }
}

// A retired snapshot with zero directory links is safe to read through its
// already-open handle. Two or more links can alias attacker-controlled storage.
pub(crate) fn is_single_link_file(file: &std::fs::File) -> std::io::Result<bool> {
    let meta = file.metadata()?;
    Ok(meta.is_file() && !is_link(&meta) && link_count(file)? <= 1)
}

#[cfg(unix)]
fn link_count(file: &std::fs::File) -> std::io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(file.metadata()?.nlink())
}

#[cfg(windows)]
fn windows_file_information(file: &std::fs::File) -> std::io::Result<(u64, u32, u64)> {
    use std::os::windows::io::AsRawHandle;
    #[repr(C)]
    #[allow(non_snake_case)]
    struct ByHandleFileInformation {
        dwFileAttributes: u32,
        ftCreationTime: [u32; 2],
        ftLastAccessTime: [u32; 2],
        ftLastWriteTime: [u32; 2],
        dwVolumeSerialNumber: u32,
        nFileSizeHigh: u32,
        nFileSizeLow: u32,
        nNumberOfLinks: u32,
        nFileIndexHigh: u32,
        nFileIndexLow: u32,
    }
    extern "system" {
        fn GetFileInformationByHandle(
            file: *mut core::ffi::c_void,
            info: *mut ByHandleFileInformation,
        ) -> i32;
    }
    let mut info = std::mem::MaybeUninit::<ByHandleFileInformation>::zeroed();
    // SAFETY: the handle is owned by `file` for the duration of the call and
    // `info` is a correctly sized, writable BY_HANDLE_FILE_INFORMATION.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a successful call filled the whole structure.
    let info = unsafe { info.assume_init() };
    Ok((
        u64::from(info.nNumberOfLinks),
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

#[cfg(windows)]
fn link_count(file: &std::fs::File) -> std::io::Result<u64> {
    windows_file_information(file).map(|info| info.0)
}

#[cfg(windows)]
pub(crate) fn windows_file_identity(file: &std::fs::File) -> std::io::Result<(u32, u64)> {
    windows_file_information(file).map(|(_, volume, index)| (volume, index))
}

#[cfg(not(any(unix, windows)))]
fn link_count(_file: &std::fs::File) -> std::io::Result<u64> {
    Err(std::io::Error::other(
        "link count unavailable on this platform",
    ))
}

/// A fresh nonce from the OS CSPRNG, never the clock or process id.
pub fn random_nonce() -> std::io::Result<String> {
    let mut bytes = [0u8; 32];
    #[cfg(unix)]
    {
        use std::io::Read;
        std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    }
    #[cfg(windows)]
    {
        #[link(name = "bcrypt")]
        extern "system" {
            fn BCryptGenRandom(
                algorithm: *mut core::ffi::c_void,
                buffer: *mut u8,
                length: u32,
                flags: u32,
            ) -> i32;
        }
        // SAFETY: the system RNG writes exactly the supplied buffer length.
        if unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                2,
            )
        } < 0
        {
            return Err(std::io::Error::other("system RNG failed"));
        }
    }
    #[cfg(not(any(unix, windows)))]
    return Err(std::io::Error::other("system RNG unavailable"));
    Ok(crate::sha256::hex(&bytes))
}

pub fn is_link(meta: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn which_finds_a_system_tool_and_rejects_nonsense() {
        let tool = if cfg!(windows) { "cmd" } else { "sh" };
        assert!(which(tool).is_some());
        assert!(which("omgs-definitely-not-a-tool-xyz").is_none());
    }

    #[cfg(windows)]
    #[test]
    fn metadata_publication_child() {
        let Some(dir) = std::env::var_os("OMGS_TEST_PUBLICATION_DIR") else {
            return;
        };
        let dir = PathBuf::from(dir);
        crate::runmeta::with_lock(&dir, || {
            crate::runmeta::write_atomic(&dir.join(crate::runmeta::FILE), "new")
        })
        .unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn pinned_metadata_reader_allows_concurrent_atomic_publication() {
        let dir = crate::platform::temp_root()
            .unwrap()
            .join(format!("omgs-share-delete-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        create_private_dir(&dir).unwrap();
        let run = dir.join("run");
        create_private_dir(&run).unwrap();
        crate::runmeta::write_atomic(&run.join(crate::runmeta::FILE), "old").unwrap();
        with_file_in(&dir, &Path::new("run").join(crate::runmeta::FILE), |file| {
            check_private_file(&file)?;
            // Ancestors remain pinned while the validated metadata leaf is open.
            assert!(std::fs::rename(&run, dir.join("moved")).is_err());
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "platform::tests::metadata_publication_child",
                    "--nocapture",
                ])
                .env("OMGS_TEST_PUBLICATION_DIR", &run)
                .output()
                .unwrap();
            assert!(
                child.status.success(),
                "{}{}",
                String::from_utf8_lossy(&child.stdout),
                String::from_utf8_lossy(&child.stderr)
            );
            // Revalidate after publication too: replacement may have reduced
            // the old handle's link count to zero, but it has no aliases.
            assert!(is_single_link_file(&file)?);
            check_private_file(&file)?;
            assert_eq!(read_bounded_file(file, 100)?, b"old");
            assert_eq!(std::fs::read(run.join(crate::runmeta::FILE))?, b"new");
            Ok(())
        })
        .unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn writable_metadata_and_lock_modes_are_refused_without_repair() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = crate::platform::temp_root()
            .unwrap()
            .join(format!("omgs-leaf-mode-{}", random_nonce().unwrap()));
        create_private_dir_new(&dir).unwrap();
        let run = dir.join("run");
        create_private_dir_new(&run).unwrap();
        let metadata = run.join(crate::runmeta::FILE);
        let lock = run.join(".omgs-run.lock");
        for mode in [0o620, 0o602] {
            std::fs::write(&metadata, "{}").unwrap();
            std::fs::set_permissions(&metadata, std::fs::Permissions::from_mode(mode)).unwrap();
            for error in [
                crate::budget::metadata(&run).unwrap_err(),
                crate::runmeta::read(&run).unwrap_err(),
                crate::runmeta::write_atomic(&metadata, "changed").unwrap_err(),
            ] {
                assert!(error.contains(&metadata.display().to_string()), "{error}");
                assert!(error.contains("not group- or world-writable"), "{error}");
                assert!(error.contains("README.md#storage-migration"), "{error}");
            }
            assert_eq!(std::fs::read_to_string(&metadata).unwrap(), "{}");
            assert_eq!(std::fs::metadata(&metadata).unwrap().mode() & 0o777, mode);
            std::fs::write(&lock, "").unwrap();
            std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(crate::runmeta::with_lock(&run, || -> Result<(), String> {
                panic!("unsafe lock admitted")
            })
            .is_err());
        }
        for leaf in [&metadata, &lock] {
            std::fs::set_permissions(leaf, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        crate::runmeta::with_lock(&run, || crate::runmeta::write_atomic(&metadata, "{}")).unwrap();
        assert!(crate::budget::metadata(&run).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn single_link_open_refuses_hardlinks_and_accepts_plain_files() {
        let d = crate::platform::temp_root()
            .unwrap()
            .join(format!("omgs-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let a = d.join("a");
        std::fs::write(&a, b"x").unwrap();
        let held = open_single_link(&a).unwrap().unwrap();
        assert!(open_single_link(&d.join("missing")).unwrap().is_none());
        std::fs::hard_link(&a, d.join("b")).unwrap();
        assert!(open_single_link(&a).is_err());
        assert!(!is_single_link_file(&held).unwrap());
        std::fs::remove_file(d.join("b")).unwrap();
        std::fs::remove_file(&a).unwrap();
        assert!(is_single_link_file(&held).unwrap());
        assert_eq!(read_bounded_file(held, 100).unwrap(), b"x");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(d.join("c-target"), d.join("c")).unwrap();
            std::fs::write(d.join("c-target"), b"y").unwrap();
            assert!(open_single_link(&d.join("c")).is_err());
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// Keep gap diagnostics on one line without terminal control sequences.
pub fn escape_controls(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

#[cfg(test)]
mod diagnostic_tests {
    #[test]
    fn gap_controls_are_escaped_without_changing_printable_paths() {
        assert_eq!(
            super::escape_controls("a\nb\r\t\u{1b}[31m café"),
            "a\\nb\\r\\t\\u{1b}[31m café"
        );
    }
}

#[cfg(target_os = "macos")]
#[path = "macos_private.rs"]
mod macos_private;

#[cfg(windows)]
#[path = "windows_private.rs"]
mod windows_private;

/// Admit every existing directory from the filesystem root to `path`.
/// Missing suffixes are allowed for creation, but parent traversal and links
/// are not. The leaf is a publication/storage directory, never a sticky anchor.
/// No HOME, profile, or root-owned intermediate directory ends the walk.
pub fn safe_path(path: &Path) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    if absolute
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(Error::other(format!(
            "storage {}: parent traversal is forbidden",
            path.display()
        )));
    }
    let mut chain: Vec<_> = absolute.ancestors().collect();
    chain.reverse();
    for entry in chain {
        let meta = match std::fs::symlink_metadata(entry) {
            Ok(meta) => meta,
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(e) => return Err(Error::other(format!("storage {}: {e}", entry.display()))),
        };
        let check = || -> std::io::Result<()> {
            if is_link(&meta) || !meta.is_dir() {
                return Err(Error::other(
                    "storage must be a directory without symlinks or reparse points",
                ));
            }
            let ancestor = entry != absolute;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                // SAFETY: geteuid has no preconditions.
                let user = unsafe { libc::geteuid() };
                if meta.uid() != user && !(ancestor && meta.uid() == 0) {
                    return Err(Error::other(
                        "storage must be owned by the current user (or root for ancestors)",
                    ));
                }
                if meta.mode() & 0o022 != 0 && !(ancestor && meta.mode() & 0o1000 != 0) {
                    return Err(Error::other("storage must not be group- or world-writable (sticky is allowed only on ancestors)"));
                }
                // The next entry is checked independently for trusted ownership.
                // Thus a sticky directory cannot protect an attacker-owned child.
                #[cfg(target_os = "macos")]
                macos_private::check_dir(entry, meta.uid())?;
            }
            #[cfg(windows)]
            windows_private::check_path(entry, ancestor)?;
            Ok(())
        };
        check().map_err(|e| {
            Error::other(format!(
                "storage {}: {e}; see README.md#storage-migration",
                entry.display()
            ))
        })?;
    }
    Ok(())
}

/// Run storage is trusted only while the owner prevents concurrent replacement.
pub fn check_private_dir(path: &Path) -> std::io::Result<()> {
    safe_path(path)?;
    #[cfg(unix)]
    let meta = std::fs::symlink_metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no arguments or memory preconditions.
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o7777 != 0o700 {
            return Err(std::io::Error::other(format!(
                "storage {} must be owned by the current user with mode 0700; observed owner uid {}, mode {:04o}; see README.md#storage-migration",
                path.display(), meta.uid(), meta.mode() & 0o7777,
            )));
        }
        // Linux POSIX access ACLs expose ACL_MASK in the group mode bits.
        // Mode 0700 therefore masks all named-user and group entries to ---;
        // the mask cannot be wider than these bits. Creation with 0700/0600
        // also constrains inherited default ACLs to the requested mode.
        #[cfg(target_os = "macos")]
        macos_private::check_dir(path, meta.uid())?;
        Ok(())
    }
    #[cfg(windows)]
    {
        windows_private::check(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(std::io::Error::other("private storage checks unavailable"))
    }
}

/// Open a new private file or an existing lock without changing its ACL.
#[cfg(windows)]
pub fn open_private_write(path: &Path, create_new: bool) -> std::io::Result<std::fs::File> {
    windows_private::open_write(path, create_new)
}

/// Validate an opened metadata or lock file before using its contents or lock.
pub fn check_private_file(file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        windows_private::check_file(file)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file.metadata()?;
        // Linux's ACL mask is the group mode bits, so this also excludes
        // effective POSIX ACL write grants to named users and groups.
        // SAFETY: geteuid has no arguments or memory preconditions.
        if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
            return Err(std::io::Error::other(format!(
                "storage file must be regular, owned by the current user and not group- or world-writable; observed owner uid {}, mode {:04o}; see README.md#storage-migration",
                meta.uid(), meta.mode() & 0o7777,
            )));
        }
        #[cfg(target_os = "macos")]
        macos_private::check_file(file, meta.uid())?;
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Err(std::io::Error::other("private storage checks unavailable"))
    }
}

/// Create owner-private storage or fail closed on an existing unsafe directory.
/// The complete existing ancestor chain is admitted before creation.
pub fn create_private_dir(path: &Path) -> std::io::Result<()> {
    match create_private_dir_new(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => check_private_dir(path),
        Err(e) => Err(std::io::Error::new(
            e.kind(),
            format!(
                "create storage {}: {e}; see README.md#storage-migration",
                path.display()
            ),
        )),
    }
}

/// Reserve a new directory exclusively with owner-private permissions.
pub fn create_private_dir_new(path: &Path) -> std::io::Result<()> {
    safe_path(path)?;
    #[cfg(not(windows))]
    let builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    #[cfg(not(windows))]
    builder.create(path)?;
    #[cfg(windows)]
    windows_private::create_dir(path)?;
    // Only an exclusive successful create authorizes changing this ACL.
    #[cfg(target_os = "macos")]
    macos_private::restrict_created_dir(path)?;
    check_private_dir(path)
}

/// Create missing storage ancestors privately, checking the requested directory.
pub fn create_private_tree(path: &Path) -> std::io::Result<()> {
    if !path.exists() {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            if !parent.exists() {
                create_private_tree(parent)?;
            }
        }
    }
    create_private_dir(path)
}
