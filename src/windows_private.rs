//! Owner-only Windows run storage. Unknown ACE types fail closed.
use std::ffi::c_void;
use std::io::{Error, Result};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr::{null_mut, NonNull};

type Ptr = *mut c_void;
#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: Ptr, access: u32, token: *mut Ptr) -> i32;
    fn GetTokenInformation(token: Ptr, class: u32, data: Ptr, size: u32, needed: *mut u32) -> i32;
    fn EqualSid(a: Ptr, b: Ptr) -> i32;
    fn GetSecurityInfo(
        handle: Ptr,
        kind: u32,
        info: u32,
        owner: *mut Ptr,
        group: *mut Ptr,
        dacl: *mut Ptr,
        sacl: *mut Ptr,
        descriptor: *mut Ptr,
    ) -> u32;
    fn IsWellKnownSid(sid: Ptr, kind: u32) -> i32;
    fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
        descriptor: Ptr,
        revision: u32,
        info: u32,
        text: *mut *mut u16,
        len: *mut u32,
    ) -> i32;
    fn GetAce(acl: Ptr, index: u32, ace: *mut Ptr) -> i32;
    fn ConvertSidToStringSidW(sid: Ptr, text: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        version: u32,
        descriptor: *mut Ptr,
        size: *mut u32,
    ) -> i32;
    fn GetSecurityDescriptorDacl(
        descriptor: Ptr,
        present: *mut i32,
        acl: *mut Ptr,
        defaulted: *mut i32,
    ) -> i32;
    fn SetNamedSecurityInfoW(
        path: *mut u16,
        kind: u32,
        info: u32,
        owner: Ptr,
        group: Ptr,
        dacl: Ptr,
        sacl: Ptr,
    ) -> u32;
}
#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> Ptr;
    fn CloseHandle(handle: Ptr) -> i32;
    fn LocalFree(mem: Ptr) -> Ptr;
}
struct Local(NonNull<c_void>);
impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: this allocation came from a Windows LocalAlloc API.
        unsafe {
            LocalFree(self.0.as_ptr());
        }
    }
}
fn local(p: Ptr) -> Result<Local> {
    NonNull::new(p).map(Local).ok_or_else(Error::last_os_error)
}
fn user() -> Result<Vec<usize>> {
    // SAFETY: all output buffers are sized by GetTokenInformation. TokenUser
    // starts with a SID pointer whose allocation remains in the returned buffer.
    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(GetCurrentProcess(), 8, &mut token) == 0 {
            return Err(Error::last_os_error());
        }
        let mut needed = 0;
        GetTokenInformation(token, 1, null_mut(), 0, &mut needed);
        let mut data = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
        let ok = GetTokenInformation(token, 1, data.as_mut_ptr().cast(), needed, &mut needed);
        CloseHandle(token);
        if ok == 0 {
            return Err(Error::last_os_error());
        }
        Ok(data)
    }
}
fn wide(path: &Path) -> Result<Vec<u16>> {
    let mut text: Vec<u16> = path.as_os_str().encode_wide().collect();
    if text.contains(&0) {
        return Err(Error::other("NUL in storage path"));
    }
    text.push(0);
    Ok(text)
}

pub fn check(path: &Path) -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    let result = std::fs::OpenOptions::new()
        .access_mode(0x0002_0000) // READ_CONTROL
        .share_mode(0x1 | 0x2 | 0x4)
        .custom_flags(0x0200_0000 | 0x0020_0000) // backup semantics, no reparse traversal
        .open(path)
        .and_then(|file| check_file(&file));
    result.map_err(|e| Error::other(format!("storage {}: {e}", path.display())))
}

pub(super) fn check_file(file: &std::fs::File) -> Result<()> {
    let token = user()?;
    // SAFETY: the descriptor owns all returned SID/ACL pointers until Local
    // drops. GetAce supplies validated ACE pointers within that descriptor.
    unsafe {
        let (mut owner, mut acl, mut sd) = (null_mut(), null_mut(), null_mut());
        let code = GetSecurityInfo(
            file.as_raw_handle(),
            1,
            5,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut sd,
        );
        if code != 0 {
            return Err(Error::from_raw_os_error(code as i32));
        }
        let _sd = local(sd)?;
        let mut summary = null_mut();
        if ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, 5, &mut summary, null_mut())
            == 0
        {
            return Err(Error::last_os_error());
        }
        let _summary = local(summary.cast())?;
        let mut len = 0;
        while *summary.add(len) != 0 {
            len += 1;
        }
        let summary = String::from_utf16_lossy(std::slice::from_raw_parts(summary, len));
        let refuse = |reason| {
            Error::other(format!(
                "{reason}; owner and DACL: {summary}; see README.md#storage-migration"
            ))
        };
        if owner.is_null() || EqualSid(owner, token[0] as Ptr) == 0 || acl.is_null() {
            return Err(refuse(
                "storage must be owned by the current user with a restrictive DACL",
            ));
        }
        // ACL header: revision, reserved, size (u16), AceCount (u16), reserved.
        let count = *acl.cast::<u16>().add(2);
        for i in 0..u32::from(count) {
            let mut ace = null_mut();
            if GetAce(acl, i, &mut ace) == 0 {
                return Err(Error::last_os_error());
            }
            let header = ace.cast::<u8>();
            match *header {
                0 => {
                    let mask = *header.add(4).cast::<u32>();
                    let sid = header.add(8) as Ptr;
                    // Apply the same allowlist to effective and inheritable ACEs,
                    // including files-only and inherit-only grants. CREATOR OWNER
                    // is safe only because the owner above is this token's user.
                    // Well-known SID kinds: SYSTEM 22, Administrators 26,
                    // CREATOR OWNER 3.
                    let trusted = EqualSid(sid, token[0] as Ptr) != 0
                        || IsWellKnownSid(sid, 22) != 0
                        || IsWellKnownSid(sid, 26) != 0
                        || IsWellKnownSid(sid, 3) != 0;
                    // Data, append, EA, delete-child, attributes, delete,
                    // WRITE_DAC, WRITE_OWNER and generic write/all rights.
                    if mask & 0x500d_0156 != 0 && !trusted {
                        return Err(refuse("storage is writable by another principal"));
                    }
                }
                1 => {} // A deny ACE grants no access.
                _ => return Err(refuse("unsupported storage DACL ACE")),
            }
        }
    }
    Ok(())
}

/// Set owner-only access on caller-owned scratch or newly created storage.
/// Admission of existing run storage uses check, without rewriting its DACL.
pub fn restrict(path: &Path) -> Result<()> {
    let original = path;
    let mut path = wide(path)?;
    let token = user()?;
    // SAFETY: each Windows allocation is retained through its last use. The
    // protected DACL grants inheritable full access to this token's user only.
    unsafe {
        let mut sid = null_mut();
        if ConvertSidToStringSidW(token[0] as Ptr, &mut sid) == 0 {
            return Err(Error::last_os_error());
        }
        let _sid = local(sid.cast())?;
        let mut len = 0;
        while *sid.add(len) != 0 {
            len += 1;
        }
        let sid = String::from_utf16(std::slice::from_raw_parts(sid, len))
            .map_err(|e| Error::other(e.to_string()))?;
        let sddl: Vec<u16> = format!("D:P(A;OICI;FA;;;{sid})")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut sd = null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut sd,
            null_mut(),
        ) == 0
        {
            return Err(Error::last_os_error());
        }
        let _sd = local(sd)?;
        let (mut present, mut acl, mut defaulted) = (0, null_mut(), 0);
        if GetSecurityDescriptorDacl(sd, &mut present, &mut acl, &mut defaulted) == 0
            || present == 0
        {
            return Err(Error::last_os_error());
        }
        let code = SetNamedSecurityInfoW(
            path.as_mut_ptr(),
            1,
            0x8000_0005,
            token[0] as Ptr,
            null_mut(),
            acl,
            null_mut(),
        );
        if code != 0 {
            return Err(Error::from_raw_os_error(code as i32));
        }
    }
    check(original)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("omgs-acl-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        crate::platform::create_private_dir(&path).unwrap();
        path
    }

    fn set_acl(path: &Path, extra: &str) {
        let token = user().unwrap();
        let mut path = wide(path).unwrap();
        // SAFETY: all descriptor and SID allocations outlive their uses and
        // path and SDDL are NUL-terminated. Only this test's fixtures change.
        unsafe {
            let mut sid = null_mut();
            assert_ne!(ConvertSidToStringSidW(token[0] as Ptr, &mut sid), 0);
            let _sid = local(sid.cast()).unwrap();
            let mut len = 0;
            while *sid.add(len) != 0 {
                len += 1;
            }
            let sid = String::from_utf16_lossy(std::slice::from_raw_parts(sid, len));
            let sddl: Vec<u16> = format!("D:P(A;OICI;FA;;;{sid}){extra}")
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let mut sd = null_mut();
            assert_ne!(
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    1,
                    &mut sd,
                    null_mut()
                ),
                0
            );
            let _sd = local(sd).unwrap();
            let (mut present, mut acl, mut defaulted) = (0, null_mut(), 0);
            assert_ne!(
                GetSecurityDescriptorDacl(sd, &mut present, &mut acl, &mut defaulted),
                0
            );
            assert_ne!(present, 0);
            assert_eq!(
                SetNamedSecurityInfoW(
                    path.as_mut_ptr(),
                    1,
                    0x8000_0004,
                    null_mut(),
                    null_mut(),
                    acl,
                    null_mut()
                ),
                0
            );
        }
    }

    #[test]
    fn files_only_inherit_write_grants_are_refused() {
        let dir = scratch("inherit");
        // Check every write-capable right, independent of whether it applies
        // to the directory, files, subdirectories, or inheritance only.
        for flags in ["", "OI", "CI", "OIIO", "CIIO", "OICIIO"] {
            for mask in [
                2, 4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000, 0x40000000, 0x10000000,
            ] {
                set_acl(&dir, &format!("(A;{flags};0x{mask:x};;;BU)"));
                let error = crate::platform::check_private_dir(&dir)
                    .unwrap_err()
                    .to_string();
                assert!(
                    error.contains("writable by another principal"),
                    "{flags} {mask:x}: {error}"
                );
            }
        }
        for principal in ["WD", "AU"] {
            set_acl(&dir, &format!("(A;OIIO;FW;;;{principal})"));
            assert!(check(&dir).is_err(), "admitted {principal}");
        }
        set_acl(&dir, "(A;OIIO;FW;;;BU)");
        assert!(crate::platform::create_private_dir(&dir).is_err());
        // Admission must not silently repair an existing ACL.
        assert!(check(&dir).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn explicitly_writable_metadata_and_lock_files_are_refused() {
        let dir = scratch("existing-files");
        let run = dir.join("run");
        crate::platform::create_private_dir(&run).unwrap();
        let metadata = run.join(crate::runmeta::FILE);
        std::fs::write(&metadata, "{}").unwrap();
        set_acl(&metadata, "(A;;FW;;;BU)");
        assert!(crate::platform::check_private_dir(&run).is_ok());
        assert!(crate::budget::metadata(&run).is_err());
        assert!(crate::runmeta::read(&run).is_err());
        assert!(crate::runmeta::write_atomic(&metadata, "{\"changed\":true}").is_err());
        assert_eq!(std::fs::read_to_string(&metadata).unwrap(), "{}");
        let lock = run.join(".omgs-run.lock");
        std::fs::write(&lock, "").unwrap();
        set_acl(&lock, "(A;;FW;;;BU)");
        assert!(
            crate::runmeta::with_lock(&run, || -> std::result::Result<(), String> {
                panic!("unsafe lock admitted")
            })
            .is_err()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn created_tree_and_trusted_system_principals_are_admitted() {
        let dir = scratch("trusted");
        let run = dir.join("run");
        crate::platform::create_private_dir(&run).unwrap();
        crate::runmeta::with_lock(&run, || {
            crate::runmeta::write_atomic(&run.join(crate::runmeta::FILE), "{}")
        })
        .unwrap();
        crate::budget::metadata(&run).unwrap();
        crate::runmeta::read(&run).unwrap();
        for extra in ["(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", "(A;OICIIO;FA;;;CO)"] {
            set_acl(&run, extra);
            crate::platform::check_private_dir(&run).unwrap();
            crate::runmeta::with_lock(&run, || {
                crate::runmeta::write_atomic(&run.join(crate::runmeta::FILE), "{}")
            })
            .unwrap();
            crate::budget::metadata(&run).unwrap();
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
