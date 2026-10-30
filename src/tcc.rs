//! Refuse launchd inputs that can request macOS Files and Folders consent.
//! The terminal may stage source from protected locations; the independent
//! launchd responsible process must only receive unprotected local paths.
use std::ffi::{c_void, CStr};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFURLCreateFromFileSystemRepresentation(
        allocator: *const c_void,
        bytes: *const u8,
        length: isize,
        directory: u8,
    ) -> *const c_void;
    fn CFURLCopyResourcePropertyForKey(
        url: *const c_void,
        key: *const c_void,
        value: *mut *const c_void,
        error: *mut *const c_void,
    ) -> u8;
    fn CFBooleanGetValue(value: *const c_void) -> u8;
    fn CFBooleanGetTypeID() -> usize;
    fn CFGetTypeID(value: *const c_void) -> usize;
    fn CFRelease(value: *const c_void);
    static kCFURLVolumeIsLocalKey: *const c_void;
    static kCFURLVolumeIsInternalKey: *const c_void;
    static kCFURLVolumeIsRemovableKey: *const c_void;
}
struct Cf(*const c_void);
impl Drop for Cf {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Cf owns a retained Core Foundation object.
            unsafe { CFRelease(self.0) };
        }
    }
}
fn local_internal_volume(path: &Path) -> io::Result<()> {
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: bytes are valid throughout construction; the URL retains them.
    let url = Cf(unsafe {
        CFURLCreateFromFileSystemRepresentation(
            std::ptr::null(),
            bytes.as_ptr(),
            bytes.len() as isize,
            u8::from(path.is_dir()),
        )
    });
    if url.0.is_null() {
        return Err(io::Error::other("cannot identify storage volume"));
    }
    // SAFETY: these immutable exported keys identify Boolean volume properties.
    let keys = unsafe {
        [
            (kCFURLVolumeIsLocalKey, true),
            (kCFURLVolumeIsInternalKey, true),
            (kCFURLVolumeIsRemovableKey, false),
        ]
    };
    for (key, expected) in keys {
        let mut value = std::ptr::null();
        let mut error = std::ptr::null();
        // SAFETY: all output pointers are writable, and the URL and key are live.
        let ok = unsafe { CFURLCopyResourcePropertyForKey(url.0, key, &mut value, &mut error) };
        let (value, _error) = (Cf(value), Cf(error));
        // SAFETY: only a non-null, correctly typed CFBoolean is read.
        if ok == 0
            || value.0.is_null()
            || unsafe {
                CFGetTypeID(value.0) != CFBooleanGetTypeID()
                    || (CFBooleanGetValue(value.0) != 0) != expected
            }
        {
            return Err(io::Error::other(
                "storage must be on a verified local internal, non-removable volume",
            ));
        }
    }
    Ok(())
}
fn system_home() -> io::Result<PathBuf> {
    // HOME is caller controlled. Use the operating system's account directory.
    let mut data = [0u8; 16384];
    // SAFETY: passwd is an output structure initialized by getpwuid_r.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    // SAFETY: buffers and output pointers have their specified writable lengths.
    let status = unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
            &mut entry,
            data.as_mut_ptr().cast(),
            data.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() || entry.pw_dir.is_null() {
        return Err(io::Error::other("cannot determine the OS home directory"));
    }
    // SAFETY: getpwuid_r succeeded and its string lives in data through this copy.
    let home = unsafe { CStr::from_ptr(entry.pw_dir) }.to_bytes();
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(home)))
}
fn prefix_remainder(path: &Path, root: &Path) -> Option<PathBuf> {
    let mut parts = path.components();
    for expected in root.components() {
        if !parts
            .next()?
            .as_os_str()
            .as_bytes()
            .eq_ignore_ascii_case(expected.as_os_str().as_bytes())
        {
            return None;
        }
    }
    Some(parts.collect())
}
pub(crate) fn starts_with(path: &Path, root: &Path) -> bool {
    // Default APFS is case insensitive, but realpath preserves caller casing.
    // Refusing these aliases is also safe on a case sensitive volume.
    prefix_remainder(path, root).is_some()
}
fn data_alias(path: &Path) -> PathBuf {
    prefix_remainder(path, Path::new("/System/Volumes/Data"))
        .map(|p| Path::new("/").join(p))
        .unwrap_or_else(|| path.to_path_buf())
}
pub(crate) fn overlaps(left: &Path, right: &Path) -> bool {
    let (left, right) = (data_alias(left), data_alias(right));
    starts_with(&left, &right) || starts_with(&right, &left)
}
const FOLDERS: &[&str] = &[
    "Desktop",
    "Documents",
    "Downloads",
    "Library",
    "Pictures",
    "Movies",
    "Music",
    ".Trash",
    "iCloud Drive",
    "iCloudDrive",
];
fn protected(path: &Path, home: &Path, grant: bool) -> bool {
    let path = data_alias(path);
    let home = data_alias(home);
    if ["/Volumes", "/Network", "/net", "/automount"]
        .iter()
        .any(|root| starts_with(&path, Path::new(root)))
    {
        return true;
    }
    if FOLDERS.iter().any(|folder| {
        let root = home.join(folder);
        starts_with(&path, &root) || grant && starts_with(&root, &path)
    }) {
        return true;
    }
    // Also catch another user's protected folders and Data-volume aliases.
    let parts: Vec<_> = path.components().map(|p| p.as_os_str()).collect();
    if parts
        .get(1)
        .is_some_and(|p| p.as_bytes().eq_ignore_ascii_case(b"Users"))
    {
        if grant && parts.len() <= 3 {
            return true;
        }
        if parts.get(3).is_some_and(|p| {
            FOLDERS
                .iter()
                .any(|folder| p.as_bytes().eq_ignore_ascii_case(folder.as_bytes()))
        }) {
            return true;
        }
    }
    false
}
fn inspect_with_home(
    path: &Path,
    grant: bool,
    home: &Path,
    volume: &mut impl FnMut(&Path) -> io::Result<()>,
) -> io::Result<()> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let refuse = |reason: &str| {
        io::Error::other(format!("macOS launchd cannot access {} without possible TCC consent: {reason}; use an owner-private local directory outside Desktop, Documents, Downloads, Library, cloud storage and external volumes; set OMGS_HOME to an unprotected location or move the run/tool path", crate::platform::escape_controls(&path.display().to_string())))
    };
    if path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(refuse(
            "parent traversal is not admitted; use the physical path",
        ));
    }
    if protected(&path, home, grant) {
        return Err(refuse("protected location"));
    }
    let mut ancestor = path.as_path();
    let mut suffix = Vec::new();
    let canonical = loop {
        match std::fs::canonicalize(ancestor) {
            Ok(path) => break path,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if let Some(name) = ancestor.file_name() {
                    suffix.push(name.to_os_string());
                }
                ancestor = ancestor
                    .parent()
                    .ok_or_else(|| refuse("no existing ancestor"))?;
            }
            Err(_) => return Err(refuse("cannot inspect the path")),
        }
    };
    let mut resolved = canonical.clone();
    for part in suffix.iter().rev() {
        resolved.push(part);
    }
    if protected(&resolved, home, grant) {
        return Err(refuse("resolved path is protected"));
    }
    volume(&canonical).map_err(|e| refuse(&e.to_string()))
}
fn inspect(path: &Path, grant: bool) -> io::Result<()> {
    inspect_with_home(path, grant, &system_home()?, &mut local_internal_volume)
}
/// Call before creating proof storage or submitting any launchd job.
pub fn admit_path(path: &Path) -> io::Result<()> {
    admit_path_with_volume(path, &mut local_internal_volume)
}
pub(crate) fn admit_path_with_volume(
    path: &Path,
    volume: &mut impl FnMut(&Path) -> io::Result<()>,
) -> io::Result<()> {
    inspect_with_home(path, false, &system_home()?, volume)
}
/// A grant must not include a protected directory either directly or as a child.
pub(crate) fn admit_grant(path: &Path) -> io::Result<()> {
    inspect(path, true)
}

pub(crate) fn admit_environment<'a>(
    values: impl IntoIterator<Item = &'a std::ffi::OsStr>,
) -> io::Result<()> {
    for value in values {
        for path in std::env::split_paths(value).filter(|p| p.is_absolute()) {
            admit_path(&path)?;
        }
    }
    Ok(())
}
pub(crate) fn admit_config(config: &serde_json::Value) -> io::Result<()> {
    for key in ["readonlyPaths", "readwritePaths"] {
        let paths = config
            .pointer(&format!("/filesystem/{key}"))
            .and_then(|p| p.as_array())
            .ok_or_else(|| io::Error::other("missing launchd filesystem paths"))?;
        for path in paths {
            admit_grant(Path::new(path.as_str().ok_or_else(|| {
                io::Error::other("invalid launchd filesystem path")
            })?))?;
        }
    }
    admit_path(Path::new(
        config
            .pointer("/process/cwd")
            .and_then(|p| p.as_str())
            .ok_or_else(|| io::Error::other("missing launchd workload directory"))?,
    ))?;
    let values = config
        .pointer("/process/env")
        .and_then(|p| p.as_array())
        .ok_or_else(|| io::Error::other("missing launchd workload environment"))?;
    for entry in values {
        let (_, value) = entry
            .as_str()
            .and_then(|s| s.split_once('='))
            .ok_or_else(|| io::Error::other("invalid launchd environment entry"))?;
        admit_environment([std::ffi::OsStr::new(value)])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protected_folders_aliases_and_broad_grants_are_rejected_lexically() {
        let home = Path::new("/Users/example");
        for path in [
            "/Users/example/Desktop/x",
            "/users/EXAMPLE/desktop/x",
            "/system/volumes/data/USERS/other/DOCUMENTS/x",
            "/volumes/external/x",
            "/Users/example/Documents/x",
            "/Users/example/Downloads/x",
            "/Users/example/Library/CloudStorage/x",
            "/Users/other/Desktop/x",
            "/System/Volumes/Data/Users/example/Desktop/x",
            "/Volumes/disk/x",
            "/Network/server/x",
        ] {
            assert!(protected(Path::new(path), home, false), "{path}");
        }
        assert!(overlaps(
            Path::new("/Users/example/private/jobs"),
            Path::new("/system/volumes/data/users/EXAMPLE/PRIVATE")
        ));
        assert!(protected(home, home, true));
        assert!(protected(Path::new("/System/Volumes/Data"), home, true));
        assert!(!protected(&home.join(".local/share/omgs"), home, true));
        assert!(!protected(
            Path::new("/private/var/folders/private/T/x"),
            home,
            false
        ));
    }
    #[test]
    fn symlink_aliases_cannot_bypass_protected_folder_admission() {
        let root = crate::supervise::capture_root().unwrap().join(format!(
            "tcc-alias-{}",
            crate::platform::random_nonce().unwrap()
        ));
        crate::platform::create_private_dir_new(&root).unwrap();
        let home = root.join("home");
        crate::platform::create_private_tree(&home.join("Desktop")).unwrap();
        let alias = root.join("alias");
        std::os::unix::fs::symlink(home.join("Desktop"), &alias).unwrap();
        // The synthetic home is entirely in local temp storage. No real
        // protected folder is read, even to test refusal of an alias.
        assert!(inspect_with_home(
            &alias.join("new-run"),
            false,
            &home,
            &mut local_internal_volume
        )
        .unwrap_err()
        .to_string()
        .contains("resolved path is protected"));
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn internal_temp_is_admitted_and_protected_paths_name_the_fix() {
        admit_path(&crate::platform::temp_root().unwrap()).unwrap();
        admit_path(Path::new("/bin/sh")).unwrap();
        assert!(admit_path(Path::new("/private/tmp/../tmp/test"))
            .unwrap_err()
            .to_string()
            .contains("parent traversal"));
        let path = system_home().unwrap().join("Desktop/omgs-tcc-refusal");
        let error = admit_path(&path).unwrap_err().to_string();
        assert!(error.contains(&path.display().to_string()) && error.contains("OMGS_HOME"));
        assert!(protected(&path, &system_home().unwrap(), false));
    }
}
