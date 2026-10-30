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
    // Null stdio is an OS device on devfs, not file storage. Admit only the
    // exact root-owned Darwin null character device, never an arbitrary devfs
    // path, replacement regular file or a device on an external volume.
    if path == Path::new("/dev/null") {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let meta = std::fs::symlink_metadata(path)?;
        if meta.file_type().is_char_device()
            && meta.uid() == 0
            && libc::major(meta.rdev() as libc::dev_t) == 3
            && libc::minor(meta.rdev() as libc::dev_t) == 2
        {
            return Ok(());
        }
        return Err(io::Error::other("invalid system null device"));
    }
    // A job leaf can be created or atomically renamed while another admission
    // resolves it. Querying CFURL volume properties on that ephemeral pathname
    // can fail even though its directory is on healthy internal storage. Use
    // the directory for same-device regular files and ENOENT only. Keep actual
    // directory mount points and cross-device leaves subject to their own check.
    // The requested name may not exist at all (for example job.plist.tmp).
    // In that case admission already selected an existing ancestor, which can
    // itself be a freshly created job directory. CFURL resource availability
    // for that directory is not evidence about the volume. Resolve the actual
    // mount with statfs and query its stable root instead.
    let volume_path = mounted_volume_path(&regular_leaf_volume_path(path)?)?;
    let path = volume_path.as_path();
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
fn mounted_volume_path(path: &Path) -> io::Result<PathBuf> {
    let name = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: statfs initializes this output structure on success.
    let mut volume: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: name is NUL-terminated and volume is writable.
    if unsafe { libc::statfs(name.as_ptr(), &mut volume) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful statfs supplies a NUL-terminated mount point name.
    let mount = unsafe { CStr::from_ptr(volume.f_mntonname.as_ptr()) }.to_bytes();
    let mount = PathBuf::from(std::ffi::OsStr::from_bytes(mount));
    if !mount.is_absolute() {
        return Err(io::Error::other("cannot identify the storage mount point"));
    }
    Ok(mount)
}
fn regular_leaf_volume_path(path: &Path) -> io::Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let leaf = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(io::Error::other("storage path changed to a symbolic link"));
        }
        Ok(meta) if meta.is_file() => Some(meta),
        Ok(_) => return Ok(path.to_path_buf()),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => None,
        Err(error) => return Err(error),
    };
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("storage path has no parent"))?;
    let directory = std::fs::symlink_metadata(parent)?;
    if !directory.is_dir() {
        return Err(io::Error::other("storage parent is not a directory"));
    }
    if leaf.is_some_and(|meta| meta.dev() != directory.dev()) {
        return Ok(path.to_path_buf());
    }
    Ok(parent.to_path_buf())
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

/// MXC 1.0.1 profile_builder.rs:148-208. Keep discovery injectable without
/// changing the machine's root-owned developer selection in tests.
pub(crate) trait MxcFilesystem {
    fn root_controlled_link(&mut self, path: &Path) -> bool;
    fn read_link(&mut self, path: &Path) -> io::Result<PathBuf>;
    fn is_dir(&mut self, path: &Path) -> bool;
}
pub(crate) struct HostMxcFilesystem;
impl MxcFilesystem for HostMxcFilesystem {
    fn root_controlled_link(&mut self, path: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(path).is_ok_and(|meta| {
            meta.file_type().is_symlink()
                && meta.uid() == 0
                && path.ancestors().skip(1).all(|dir| {
                    std::fs::metadata(dir)
                        .is_ok_and(|meta| meta.uid() == 0 && meta.mode() & 0o022 == 0)
                })
        })
    }
    fn read_link(&mut self, path: &Path) -> io::Result<PathBuf> {
        std::fs::read_link(path)
    }
    fn is_dir(&mut self, path: &Path) -> bool {
        path.is_dir()
    }
}

/// Exact lexical bundle widening from MXC profile_builder.rs:223-240.
fn developer_grant(dir: &Path) -> &Path {
    if dir.file_name().is_some_and(|name| name == "Developer") {
        if let Some(contents) = dir
            .parent()
            .filter(|p| p.file_name().is_some_and(|n| n == "Contents"))
        {
            if let Some(bundle) = contents.parent().filter(|p| {
                p.extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("app"))
            }) {
                return bundle;
            }
        }
    }
    dir
}

/// All implicit storage and device paths in MXC 1.0.1's Seatbelt backend.
/// The caller validates grants against private storage as well as TCC.
pub(crate) fn visit_mxc_implicit(
    config: &serde_json::Value,
    executor_home: &Path,
    fs: &mut impl MxcFilesystem,
    visit: &mut impl FnMut(&Path, bool) -> io::Result<()>,
) -> io::Result<()> {
    // A custom profile would replace this inventory with arbitrary grants.
    if config
        .pointer("/seatbelt/profileOverride")
        .is_some_and(|p| !p.is_null())
    {
        return Err(io::Error::other(
            "launchd does not admit MXC profile overrides",
        ));
    }
    // SYSTEM_READ_ALLOW, profile_builder.rs:116-144. `/` is literal only.
    visit(Path::new("/"), false)?;
    for path in [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/lib",
        "/usr/libexec",
        "/usr/share",
        "/System",
        "/Library",
        "/private/var/db/timezone",
        "/private/var/db/dyld",
        "/private/var/select",
        "/private/etc",
    ] {
        visit(Path::new(path), true)?;
    }
    // Literal devices and the TTY regex namespace, lines 139-143, 258-263,
    // 561-564, 612-613. These are verified devfs nodes, never storage grants.
    for path in [
        "/dev",
        "/dev/null",
        "/dev/zero",
        "/dev/random",
        "/dev/urandom",
        "/dev/tty",
        "/dev/fd",
        "/dev/ptmx",
        "/bin/sh",
    ] {
        visit(Path::new(path), false)?;
    }
    for link in [
        "/private/var/db/xcode_select_link",
        "/private/var/select/developer_dir",
    ] {
        let link = Path::new(link);
        // Check the location before MXC's metadata/readlink operations. Admission
        // also follows aliases; MXC itself retains the readlink spelling.
        visit(link, false)?;
        if !fs.root_controlled_link(link) {
            continue;
        }
        if let Ok(target) = fs.read_link(link) {
            if target.is_absolute() {
                // Must precede is_dir: even a rejected candidate can request TCC.
                visit(&target, true)?;
                if fs.is_dir(&target) {
                    visit(developer_grant(&target), true)?;
                    break;
                }
            }
        }
    }
    // Optional GUI and keychain grants, lines 554-556 and 669-683.
    if config.pointer("/ui/disable").and_then(|v| v.as_bool()) == Some(false)
        && config
            .pointer("/seatbelt/guiAccess")
            .and_then(|v| v.as_bool())
            == Some(true)
    {
        visit(Path::new("/private/tmp"), true)?;
        visit(Path::new("/private/var/folders"), true)?;
    }
    if config
        .pointer("/seatbelt/keychainAccess")
        .and_then(|v| v.as_bool())
        == Some(true)
    {
        for path in [
            "/private/var/protected/trustd",
            "/private/var/db/mds",
            "/private/var/folders",
        ] {
            visit(Path::new(path), true)?;
        }
        visit(&executor_home.join("Library/Keychains"), true)?;
    }
    Ok(())
}

/// Only the fixed MXC device namespace is exempt from storage volume checks.
/// General admit_path intentionally continues to reject arbitrary devfs paths.
pub(crate) fn admit_executor_path(path: &Path, grant: bool) -> io::Result<()> {
    if !grant && path == Path::new("/dev/null") {
        // Preserve the existing exact Darwin null-device identity check.
        return admit_path(path);
    }
    if !grant
        && [
            "/private/var/db/xcode_select_link",
            "/private/var/select/developer_dir",
        ]
        .iter()
        .any(|link| path == Path::new(link))
    {
        // MXC lstat/readlink the leaf, not its target. Do not realpath the
        // selection link here: a newly changed target must first pass the
        // lexical TCC check in visit_mxc_implicit, before any target metadata.
        return admit_path(
            path.parent()
                .ok_or_else(|| io::Error::other("missing selection parent"))?,
        );
    }
    if !grant
        && [
            "/dev",
            "/dev/null",
            "/dev/zero",
            "/dev/random",
            "/dev/urandom",
            "/dev/tty",
            "/dev/fd",
            "/dev/ptmx",
        ]
        .iter()
        .any(|p| path == Path::new(p))
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let meta = std::fs::symlink_metadata(path)?;
        let dev = std::fs::symlink_metadata("/dev")?;
        let name = std::ffi::CString::new(path.as_os_str().as_bytes())?;
        // SAFETY: statfs writes one valid output object, with a live C path.
        let mut volume: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statfs(name.as_ptr(), &mut volume) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: Darwin statfs returns a NUL-terminated filesystem name.
        let devfs = unsafe { CStr::from_ptr(volume.f_fstypename.as_ptr()) } == c"devfs";
        if devfs
            && meta.uid() == 0
            && meta.dev() == dev.dev()
            && (meta.file_type().is_char_device()
                || (path == Path::new("/dev") || path == Path::new("/dev/fd")) && meta.is_dir())
        {
            return Ok(());
        }
        return Err(io::Error::other("invalid MXC system device"));
    }
    if grant {
        admit_grant(path)
    } else {
        admit_path(path)
    }
}

/// Inspect path lists and single path values without losing a colon in a
/// literal HOME, TMPDIR or other single-path environment value.
pub(crate) fn visit_environment(
    key: &std::ffi::OsStr,
    value: &std::ffi::OsStr,
    visit: &mut impl FnMut(&Path) -> io::Result<()>,
) -> io::Result<()> {
    if key != "PATH" && !key.as_bytes().starts_with(b"DYLD_") && Path::new(value).is_absolute() {
        visit(Path::new(value))?;
    }
    for path in std::env::split_paths(value).filter(|p| p.is_absolute()) {
        visit(&path)?;
    }
    Ok(())
}

pub(crate) fn admit_config(config: &serde_json::Value) -> io::Result<()> {
    visit_config(config, &mut |path, grant| {
        if grant {
            admit_grant(path)
        } else {
            admit_path(path)
        }
    })
}

/// MXC profile_builder.rs:711-713, 758-803 and seatbelt_runner.rs:932-960
/// expand config paths using the executor's HOME, not the workload's HOME.
/// OMGS emits absolute paths; refuse other relative paths rather than checking
/// them against a different launching directory in the parent and anchor.
pub(crate) fn visit_config_at(
    config: &serde_json::Value,
    executor_home: &Path,
    visit: &mut impl FnMut(&Path, bool) -> io::Result<()>,
) -> io::Result<()> {
    visit_config(config, &mut |path, grant| {
        let expanded = if let Ok(suffix) = path.strip_prefix("~") {
            executor_home.join(suffix)
        } else {
            path.to_path_buf()
        };
        if !expanded.is_absolute() {
            return Err(io::Error::other(
                "launchd MXC paths must be absolute after HOME expansion",
            ));
        }
        visit(&expanded, grant)
    })
}

/// One visitor for every path MXC receives, shared by submission and the anchor.
pub(crate) fn visit_config(
    config: &serde_json::Value,
    visit: &mut impl FnMut(&Path, bool) -> io::Result<()>,
) -> io::Result<()> {
    for key in ["readonlyPaths", "readwritePaths"] {
        let paths = config
            .pointer(&format!("/filesystem/{key}"))
            .and_then(|p| p.as_array())
            .ok_or_else(|| io::Error::other("missing launchd filesystem paths"))?;
        for path in paths {
            visit(
                Path::new(
                    path.as_str()
                        .ok_or_else(|| io::Error::other("invalid launchd filesystem path"))?,
                ),
                true,
            )?;
        }
    }
    if let Some(paths) = config.pointer("/filesystem/deniedPaths") {
        for path in paths
            .as_array()
            .ok_or_else(|| io::Error::other("invalid launchd denied paths"))?
        {
            visit(
                Path::new(
                    path.as_str()
                        .ok_or_else(|| io::Error::other("invalid launchd denied path"))?,
                ),
                false,
            )?;
        }
    }
    visit(
        Path::new(
            config
                .pointer("/process/cwd")
                .and_then(|p| p.as_str())
                .ok_or_else(|| io::Error::other("missing launchd workload directory"))?,
        ),
        false,
    )?;
    let values = config
        .pointer("/process/env")
        .and_then(|p| p.as_array())
        .ok_or_else(|| io::Error::other("missing launchd workload environment"))?;
    for entry in values {
        let (key, value) = entry
            .as_str()
            .and_then(|s| s.split_once('='))
            .ok_or_else(|| io::Error::other("invalid launchd environment entry"))?;
        visit_environment(
            std::ffi::OsStr::new(key),
            std::ffi::OsStr::new(value),
            &mut |path| visit(path, false),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mxc_home_expansion_is_admitted_with_the_effective_executor_home() {
        let config = serde_json::json!({
            "filesystem": {"readonlyPaths": ["~/sdk"], "readwritePaths": ["/workspace"], "deniedPaths": ["~/denied"]},
            "process": {"cwd": "~/work", "env": ["HOME=/workload-home", "TMPDIR=/workload-temp"]}
        });
        let mut paths = Vec::new();
        visit_config_at(&config, Path::new("/executor-home"), &mut |path, grant| {
            paths.push((path.to_path_buf(), grant));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            paths,
            vec![
                (PathBuf::from("/executor-home/sdk"), true),
                (PathBuf::from("/workspace"), true),
                (PathBuf::from("/executor-home/denied"), false),
                (PathBuf::from("/executor-home/work"), false),
                (PathBuf::from("/workload-home"), false),
                (PathBuf::from("/workload-home"), false),
                (PathBuf::from("/workload-temp"), false),
                (PathBuf::from("/workload-temp"), false),
            ]
        );
        let mut relative = config;
        relative["process"]["cwd"] = "relative".into();
        assert!(
            visit_config_at(&relative, Path::new("/executor-home"), &mut |_, _| Ok(())).is_err()
        );
    }
    #[test]
    fn mxc_bundle_widening_matches_exact_suffix_only() {
        for (selected, granted) in [
            (
                "/Applications/Xcode.app/Contents/Developer",
                "/Applications/Xcode.app",
            ),
            (
                "/Applications/Xcode.APP/Contents/Developer",
                "/Applications/Xcode.APP",
            ),
            (
                "/Library/Developer/CommandLineTools",
                "/Library/Developer/CommandLineTools",
            ),
            ("/a.app/contents/Developer", "/a.app/contents/Developer"),
            ("/a.app/Contents/developer", "/a.app/Contents/developer"),
            (
                "/a.app/Contents/Developer/SDKs",
                "/a.app/Contents/Developer/SDKs",
            ),
        ] {
            assert_eq!(developer_grant(Path::new(selected)), Path::new(granted));
        }
    }
    #[test]
    fn mxc_optional_paths_are_inventoried_and_overrides_refused() {
        struct NoSelection;
        impl MxcFilesystem for NoSelection {
            fn root_controlled_link(&mut self, _: &Path) -> bool {
                false
            }
            fn read_link(&mut self, _: &Path) -> io::Result<PathBuf> {
                panic!("untrusted link read")
            }
            fn is_dir(&mut self, _: &Path) -> bool {
                panic!("unselected directory inspected")
            }
        }
        let config = serde_json::json!({"ui": {"disable": false}, "seatbelt": {"guiAccess": true, "keychainAccess": true}});
        let mut paths = Vec::new();
        visit_mxc_implicit(
            &config,
            Path::new("/executor-home"),
            &mut NoSelection,
            &mut |path, grant| {
                paths.push((path.to_path_buf(), grant));
                Ok(())
            },
        )
        .unwrap();
        for link in [
            "/private/var/db/xcode_select_link",
            "/private/var/select/developer_dir",
        ] {
            assert!(paths.contains(&(link.into(), false)), "{link}");
        }
        for path in [
            "/private/tmp",
            "/private/var/folders",
            "/private/var/protected/trustd",
            "/private/var/db/mds",
            "/executor-home/Library/Keychains",
        ] {
            assert!(paths.contains(&(path.into(), true)), "{path}");
        }
        assert!(visit_mxc_implicit(
            &serde_json::json!({"seatbelt": {"profileOverride": "(allow default)"}}),
            Path::new("/executor-home"),
            &mut NoSelection,
            &mut |_, _| Ok(())
        )
        .is_err());
        for device in [
            "/dev",
            "/dev/null",
            "/dev/zero",
            "/dev/random",
            "/dev/urandom",
            "/dev/tty",
            "/dev/fd",
            "/dev/ptmx",
        ] {
            admit_executor_path(Path::new(device), false).unwrap();
        }
        assert!(admit_executor_path(Path::new("/dev/disk0"), false).is_err());
    }
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
    fn leaf_volume_selection_preserves_directory_and_error_checks() {
        let root = crate::supervise::capture_root().unwrap().join(format!(
            "tcc-volume-{}",
            crate::platform::random_nonce().unwrap()
        ));
        crate::platform::create_private_dir_new(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let mount = mounted_volume_path(&root).unwrap();
        assert!(mount.is_dir());
        assert!(!mount.starts_with(&root));
        // This inventoried sibling is never created in production. Its error
        // label names the leaf even though admission checks the job directory.
        inspect_with_home(
            &root.join("job.plist.tmp"),
            false,
            &system_home().unwrap(),
            &mut |existing| {
                assert_eq!(existing, root);
                assert_eq!(mounted_volume_path(existing).unwrap(), mount);
                local_internal_volume(existing)
            },
        )
        .unwrap();
        let leaf = root.join("compatible");
        assert_eq!(regular_leaf_volume_path(&leaf).unwrap(), root);
        crate::platform::write_private_new(&leaf, b"").unwrap();
        assert_eq!(regular_leaf_volume_path(&leaf).unwrap(), root);
        assert_eq!(mounted_volume_path(&leaf).unwrap(), mount);
        assert_eq!(regular_leaf_volume_path(&root).unwrap(), root);
        let alias = root.join("alias");
        std::os::unix::fs::symlink(&leaf, &alias).unwrap();
        assert!(regular_leaf_volume_path(&alias).is_err());
        // ENOTDIR and missing parents are not the admitted leaf ENOENT case.
        assert!(regular_leaf_volume_path(&leaf.join("child")).is_err());
        assert!(regular_leaf_volume_path(&root.join("missing/child")).is_err());
        let error = inspect_with_home(&leaf, false, &system_home().unwrap(), &mut |_| {
            Err(io::Error::other("unverifiable volume"))
        })
        .unwrap_err();
        assert!(error.to_string().contains("unverifiable volume"));
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn disappearing_leaf_uses_its_stable_internal_parent() {
        let root = crate::supervise::capture_root().unwrap().join(format!(
            "tcc-leaf-{}",
            crate::platform::random_nonce().unwrap()
        ));
        crate::platform::create_private_dir_new(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let leaf = root.join("ready.tmp");
        crate::platform::write_private_new(&leaf, b"{}").unwrap();
        // Deterministically publish after realpath but before the volume query.
        let result = inspect_with_home(&leaf, false, &system_home().unwrap(), &mut |path| {
            assert_eq!(path, leaf);
            std::fs::rename(&leaf, root.join("ready")).unwrap();
            local_internal_volume(path)
        });
        std::fs::remove_dir_all(root).unwrap();
        result.unwrap();
    }
    #[test]
    fn internal_temp_is_admitted_and_protected_paths_name_the_fix() {
        admit_path(&crate::platform::temp_root().unwrap()).unwrap();
        admit_path(Path::new("/bin/sh")).unwrap();
        admit_path(Path::new("/dev/null")).unwrap();
        assert!(admit_path(Path::new("/dev/zero")).is_err());
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
