//! macOS extended ACL admission for owner-private storage.
use std::ffi::{c_int, c_void};
use std::io::{Error, Result};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::ptr::{null_mut, NonNull};

type Ptr = *mut c_void;
const ACL_TYPE_EXTENDED: c_int = 0x100;
const ACL_EXTENDED_ALLOW: c_int = 1;
const ACL_EXTENDED_DENY: c_int = 2;
// sys/acl.h: WRITE_DATA/ADD_FILE, APPEND_DATA/ADD_SUBDIRECTORY,
// DELETE, DELETE_CHILD, WRITE_ATTRIBUTES, WRITE_EXTATTRIBUTES,
// WRITE_SECURITY, CHANGE_OWNER. Inheritance flags never exempt a grant.
const MUTATION_RIGHTS: u64 =
    (1 << 2) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 8) | (1 << 10) | (1 << 12) | (1 << 13);

// Darwin's opaque ACL types and enum arguments from sys/acl.h. These APIs
// are in the system C library, requiring no external library or subprocess.
extern "C" {
    fn acl_get_fd_np(fd: c_int, kind: c_int) -> Ptr;
    fn acl_get_entry(acl: Ptr, index: c_int, entry: *mut Ptr) -> c_int;
    fn acl_get_tag_type(entry: Ptr, tag: *mut c_int) -> c_int;
    fn acl_get_qualifier(entry: Ptr) -> Ptr;
    fn acl_get_permset_mask_np(entry: Ptr, mask: *mut u64) -> c_int;
    fn acl_valid(acl: Ptr) -> c_int;
    fn acl_init(count: c_int) -> Ptr;
    fn acl_set_fd_np(fd: c_int, acl: Ptr, kind: c_int) -> c_int;
    fn acl_free(object: Ptr) -> c_int;
    fn mbr_uuid_to_id(uuid: *const u8, id: *mut libc::id_t, kind: *mut c_int) -> c_int;
}

struct Allocation(NonNull<c_void>);
impl Allocation {
    fn new(ptr: Ptr) -> Result<Self> {
        NonNull::new(ptr).map(Self).ok_or_else(Error::last_os_error)
    }
    fn ptr(&self) -> Ptr {
        self.0.as_ptr()
    }
}
impl Drop for Allocation {
    fn drop(&mut self) {
        // SAFETY: only allocations returned by the ACL APIs are wrapped here.
        unsafe { acl_free(self.ptr()) };
    }
}

pub(super) fn check_dir(path: &Path, owner: libc::uid_t) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let result = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .and_then(|file| check_file(&file, owner));
    result.map_err(|e| {
        Error::other(format!(
            "storage {}: {e}; see README.md#storage-migration",
            path.display()
        ))
    })
}

pub(super) fn check_file(file: &std::fs::File, owner: libc::uid_t) -> Result<()> {
    // SAFETY: file owns a live descriptor. Inspect the opened object, even
    // if a concurrent atomic publication has replaced its pathname.
    let result = unsafe {
        let ptr = acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED);
        if ptr.is_null() && Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            // Darwin's filesec_get_property reports ENOENT when a live object
            // has no extended ACL. A pinned descriptor rules out a missing
            // pathname; all other inspection failures remain errors.
            Ok(())
        } else {
            Allocation::new(ptr).and_then(|acl| check(&acl, owner))
        }
    };
    result.map_err(|e| Error::other(format!("{e}; see README.md#storage-migration")))
}

fn check(acl: &Allocation, owner: libc::uid_t) -> Result<()> {
    // SAFETY: the ACL allocation lives throughout iteration. Entry pointers
    // are borrowed from it; each qualifier allocation holds a 16-byte UUID
    // and is freed independently. Every output points to initialized storage.
    unsafe {
        if acl_valid(acl.ptr()) != 0 {
            return Err(Error::last_os_error());
        }
        for index in 0.. {
            let mut entry = null_mut();
            if acl_get_entry(acl.ptr(), index, &mut entry) != 0 {
                let error = Error::last_os_error();
                // Darwin returns -1/EINVAL at the end, including an empty
                // ACL. acl_valid above excludes an invalid ACL handle.
                return if error.raw_os_error() == Some(libc::EINVAL) {
                    Ok(())
                } else {
                    Err(error)
                };
            }
            let mut tag = 0;
            if acl_get_tag_type(entry, &mut tag) != 0 {
                return Err(Error::last_os_error());
            }
            if tag == ACL_EXTENDED_DENY {
                continue;
            }
            if tag != ACL_EXTENDED_ALLOW {
                return Err(Error::other(format!(
                    "unrecognized ACL entry {index} tag {tag}"
                )));
            }
            let mut mask = 0u64;
            if acl_get_permset_mask_np(entry, &mut mask) != 0 {
                return Err(Error::last_os_error());
            }
            if mask & MUTATION_RIGHTS == 0 {
                continue;
            }
            let qualifier = Allocation::new(acl_get_qualifier(entry))?;
            let principal = std::slice::from_raw_parts(qualifier.ptr().cast::<u8>(), 16);
            // Resolve both directory-service and synthesized UUIDs. Only a
            // user ID matching the owner is trusted, never a same-numbered
            // group ID. Unresolvable principals fail this owner exception.
            let mut id = 0;
            let mut kind = -1;
            let code = mbr_uuid_to_id(principal.as_ptr(), &mut id, &mut kind);
            if code != 0 || kind != 0 || id != owner {
                return Err(Error::other(format!(
                    "ACL entry {index} allows mutation by another principal (UUID {}, rights 0x{:x}, effective or inheritable)",
                    crate::sha256::hex(principal), mask & MUTATION_RIGHTS,
                )));
            }
        }
    }
    unreachable!()
}

/// Only called immediately after an exclusive directory create succeeds.
pub(super) fn restrict_created_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    // SAFETY: the new directory's descriptor remains live and acl_init
    // returns an owned empty ACL, freed after acl_set_fd_np copies it.
    unsafe {
        let empty = Allocation::new(acl_init(0))?;
        if acl_set_fd_np(file.as_raw_fd(), empty.ptr(), ACL_TYPE_EXTENDED) != 0 {
            return Err(Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{budget, platform, runmeta};
    use std::path::PathBuf;
    use std::process::Command;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let dir = crate::platform::temp_root().unwrap().join(format!(
                "omgs-macos-acl-{}",
                platform::random_nonce().unwrap()
            ));
            platform::create_private_dir_new(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            // All ACL mutations, including cleanup of deny-delete fixtures,
            // are confined to this exclusively created disposable tree.
            let status = Command::new("/bin/chmod")
                .arg("-RN")
                .arg(&self.0)
                .status()
                .unwrap();
            assert!(status.success());
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn add_acl(path: &Path, entry: &str) {
        let result = Command::new("/bin/chmod")
            .arg("+a")
            .arg(entry)
            .arg(path)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    fn acl_text(path: &Path) -> Vec<u8> {
        let result = Command::new("/bin/ls")
            .arg("-lde")
            .arg(path)
            .output()
            .unwrap();
        assert!(result.status.success());
        // Compare ACL entries only: creating children changes directory
        // link counts, size and timestamps in ls's first line.
        String::from_utf8(result.stdout)
            .unwrap()
            .lines()
            .skip(1)
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes()
    }

    #[test]
    fn explicit_and_inherit_only_mutation_acls_are_refused_without_repair() {
        let fixture = Fixture::new();
        for flags in ["", ",file_inherit,directory_inherit,only_inherit"] {
            for right in [
                "add_file",
                "add_subdirectory",
                "delete_child",
                "delete",
                "write",
                "append",
                "writeattr",
                "writeextattr",
                "writesecurity",
                "chown",
            ] {
                let dir = fixture.0.join("storage");
                platform::create_private_dir_new(&dir).unwrap();
                add_acl(&dir, &format!("everyone allow {right}{flags}"));
                let before = acl_text(&dir);
                let error = platform::create_private_dir(&dir).unwrap_err().to_string();
                assert!(error.contains(&dir.display().to_string()), "{error}");
                assert!(
                    error.contains("ACL entry 0 allows mutation by another principal"),
                    "{error}"
                );
                assert!(error.contains("README.md#storage-migration"), "{error}");
                assert_eq!(acl_text(&dir), before);
                std::fs::remove_dir_all(&dir).unwrap();
            }
        }
    }

    #[test]
    fn inherited_metadata_and_lock_allow_acls_are_refused() {
        let fixture = Fixture::new();
        let run = fixture.0.join("run");
        platform::create_private_dir_new(&run).unwrap();
        add_acl(
            &run,
            "everyone allow write,append,delete,file_inherit,only_inherit",
        );
        let metadata = run.join(runmeta::FILE);
        let lock = run.join(".omgs-run.lock");
        std::fs::write(&metadata, "{}").unwrap();
        std::fs::write(&lock, "").unwrap();
        assert!(String::from_utf8_lossy(&acl_text(&metadata)).contains("inherited"));
        // Leave the inherited child entries intact under an admitted parent.
        assert!(Command::new("/bin/chmod")
            .arg("-N")
            .arg(&run)
            .status()
            .unwrap()
            .success());
        platform::check_private_dir(&run).unwrap();
        let before = acl_text(&metadata);
        for error in [
            budget::metadata(&run).unwrap_err(),
            runmeta::read(&run).unwrap_err(),
            runmeta::write_atomic(&metadata, "changed").unwrap_err(),
        ] {
            assert!(error.contains(&metadata.display().to_string()), "{error}");
            assert!(error.contains("ACL entry 0"), "{error}");
            assert!(error.contains("README.md#storage-migration"), "{error}");
        }
        assert_eq!(acl_text(&metadata), before);
        assert_eq!(std::fs::read_to_string(&metadata).unwrap(), "{}");
        let error = runmeta::with_lock(&run, || -> std::result::Result<(), String> {
            panic!("unsafe lock admitted")
        })
        .unwrap_err();
        assert!(error.contains(&lock.display().to_string()), "{error}");
        assert!(error.contains("ACL entry 0"), "{error}");
    }

    #[test]
    fn deny_only_and_owner_allow_acls_are_admitted() {
        let fixture = Fixture::new();
        add_acl(&fixture.0, "everyone deny delete");
        let before = acl_text(&fixture.0);
        platform::private_dir(&fixture.0).unwrap();
        assert_eq!(acl_text(&fixture.0), before);
        let metadata = fixture.0.join(runmeta::FILE);
        runmeta::write_atomic(&metadata, "{}").unwrap();
        add_acl(&metadata, "everyone deny delete");
        assert!(runmeta::read(&fixture.0).is_ok());
        let owner = Command::new("/usr/bin/id").arg("-un").output().unwrap();
        assert!(owner.status.success());
        add_acl(
            &metadata,
            &format!(
                "user:{} allow write,append,writesecurity,chown",
                String::from_utf8(owner.stdout).unwrap().trim()
            ),
        );
        assert!(runmeta::read(&fixture.0).is_ok());
        // Darwin also accepts synthesized owner UUIDs, including after a
        // directory-service UUID has been assigned to the same account.
        // SAFETY: geteuid has no arguments or memory preconditions.
        let uid = unsafe { libc::geteuid() };
        unsafe {
            extern "C" {
                fn acl_create_entry(acl: *mut Ptr, entry: *mut Ptr) -> c_int;
                fn acl_set_tag_type(entry: Ptr, tag: c_int) -> c_int;
                fn acl_set_qualifier(entry: Ptr, qualifier: *const c_void) -> c_int;
                fn acl_set_permset_mask_np(entry: Ptr, mask: u64) -> c_int;
            }
            // SAFETY: all ACL objects are owned by this fixture and every
            // pointer outlives its API call. Only this temporary file changes.
            let mut acl = Allocation::new(acl_init(1)).unwrap();
            let mut ptr = acl.ptr();
            let mut entry = null_mut();
            let code = acl_create_entry(&mut ptr, &mut entry);
            acl.0 = NonNull::new(ptr).unwrap();
            assert_eq!(code, 0);
            let mut principal = [
                0xff, 0xff, 0xee, 0xee, 0xdd, 0xdd, 0xcc, 0xcc, 0xbb, 0xbb, 0xaa, 0xaa, 0, 0, 0, 0,
            ];
            principal[12..].copy_from_slice(&uid.to_be_bytes());
            assert_eq!(acl_set_tag_type(entry, ACL_EXTENDED_ALLOW), 0);
            assert_eq!(acl_set_qualifier(entry, principal.as_ptr().cast()), 0);
            assert_eq!(acl_set_permset_mask_np(entry, 1 << 2), 0);
            let file = std::fs::File::open(&metadata).unwrap();
            assert_eq!(
                acl_set_fd_np(file.as_raw_fd(), acl.ptr(), ACL_TYPE_EXTENDED),
                0
            );
        }
        assert!(runmeta::read(&fixture.0).is_ok());
        add_acl(
            &fixture.0,
            "everyone allow list,search,readattr,readextattr,readsecurity",
        );
        platform::check_private_dir(&fixture.0).unwrap();
        runmeta::with_lock(&fixture.0, || {
            runmeta::write_atomic(&fixture.0.join("control.json"), "{}")
        })
        .unwrap();
    }

    #[test]
    fn freshly_created_tree_strips_inherited_allow_acls_only_on_new_directories() {
        let fixture = Fixture::new();
        add_acl(
            &fixture.0,
            "everyone allow list,add_file,search,delete_child,file_inherit,directory_inherit",
        );
        let before = acl_text(&fixture.0);
        let run = fixture.0.join("store/repo/run");
        assert!(platform::create_private_tree(&run).is_err());
        assert_eq!(acl_text(&fixture.0), before);
        assert!(!fixture.0.join("store").exists());
        // Non-mutating inherited ACLs remain safe and are stripped only on
        // newly created directories, never on the existing parent.
        restrict_created_dir(&fixture.0).unwrap();
        add_acl(
            &fixture.0,
            "everyone allow list,search,file_inherit,directory_inherit",
        );
        let before = acl_text(&fixture.0);
        platform::create_private_tree(&run).unwrap();
        for dir in [
            fixture.0.join("store"),
            fixture.0.join("store/repo"),
            run.clone(),
        ] {
            platform::check_private_dir(&dir).unwrap();
            assert!(!String::from_utf8_lossy(&acl_text(&dir)).contains("allow"));
        }
        runmeta::with_lock(&run, || {
            runmeta::write_atomic(&run.join(runmeta::FILE), "{}")
        })
        .unwrap();
        assert!(budget::metadata(&run).is_ok());
        assert!(!String::from_utf8_lossy(&acl_text(&run.join(runmeta::FILE))).contains("allow"));
        assert!(!String::from_utf8_lossy(&acl_text(&run.join(".omgs-run.lock"))).contains("allow"));
        assert_eq!(acl_text(&fixture.0), before);
        platform::create_private_tree(&fixture.0).unwrap();
    }
}
