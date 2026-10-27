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
/// can never supply a tool.
pub fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let exts: Vec<String> = if cfg!(windows) && Path::new(name).extension().is_none() {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
            .split(';')
            .filter(|e| !e.is_empty())
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
    if !meta.is_file() || link_count(&file)? != 1 {
        return Err(Error::other(format!(
            "{} must be a regular file with a single link",
            path.display()
        )));
    }
    Ok(Some(file))
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
