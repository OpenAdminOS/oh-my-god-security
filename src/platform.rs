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

/// Open `path` for reading without following a final symlink (or reparse
/// point on Windows) and without blocking on a FIFO, and accept it only when
/// it is a regular file with exactly one link. `Ok(None)` when it is missing.
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
    let meta = file.metadata()?;
    if !meta.is_file() || is_link(&meta) || link_count(&file)? != 1 {
        return Err(Error::other(format!(
            "{} must be a regular file with a single link",
            path.display()
        )));
    }
    Ok(Some(file))
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

/// Create a private directory, including when the caller reserved it earlier.
pub fn private_dir(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
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
    use std::io::{Error, ErrorKind, Read};
    let file =
        open_single_link(path)?.ok_or_else(|| Error::new(ErrorKind::NotFound, "file missing"))?;
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

#[cfg(unix)]
fn link_count(file: &std::fs::File) -> std::io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(file.metadata()?.nlink())
}

#[cfg(windows)]
fn link_count(file: &std::fs::File) -> std::io::Result<u64> {
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
    Ok(u64::from(unsafe { info.assume_init() }.nNumberOfLinks))
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

    #[test]
    fn single_link_open_refuses_hardlinks_and_accepts_plain_files() {
        let d = std::env::temp_dir().join(format!("omgs-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let a = d.join("a");
        std::fs::write(&a, b"x").unwrap();
        assert!(open_single_link(&a).unwrap().is_some());
        assert!(open_single_link(&d.join("missing")).unwrap().is_none());
        std::fs::hard_link(&a, d.join("b")).unwrap();
        assert!(open_single_link(&a).is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(d.join("c-target"), d.join("c")).unwrap();
            std::fs::write(d.join("c-target"), b"y").unwrap();
            assert!(open_single_link(&d.join("c")).is_err());
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}
