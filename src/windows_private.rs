//! Owner-only Windows run storage. Unknown ACE types fail closed.
use std::ffi::c_void;
use std::io::{Error, Result};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null_mut, NonNull};

type Ptr = *mut c_void;
#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: Ptr, access: u32, token: *mut Ptr) -> i32;
    fn GetTokenInformation(token: Ptr, class: u32, data: Ptr, size: u32, needed: *mut u32) -> i32;
    fn EqualSid(a: Ptr, b: Ptr) -> i32;
    fn GetNamedSecurityInfoW(
        path: *const u16,
        kind: u32,
        info: u32,
        owner: *mut Ptr,
        group: *mut Ptr,
        dacl: *mut Ptr,
        sacl: *mut Ptr,
        descriptor: *mut Ptr,
    ) -> u32;
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
    let path = wide(path)?;
    let token = user()?;
    // SAFETY: the descriptor owns all returned SID/ACL pointers until Local
    // drops. GetAce supplies validated ACE pointers within that descriptor.
    unsafe {
        let (mut owner, mut acl, mut sd) = (null_mut(), null_mut(), null_mut());
        let code = GetNamedSecurityInfoW(
            path.as_ptr(),
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
        if owner.is_null() || EqualSid(owner, token[0] as Ptr) == 0 || acl.is_null() {
            return Err(Error::other(
                "directory must be owned by the current user with a restrictive DACL",
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
            if *header.add(1) & 8 != 0 {
                continue;
            } // INHERIT_ONLY_ACE
            match *header {
                0 => {
                    let mask = *header.add(4).cast::<u32>();
                    // Data, append, EA, delete-child, attributes, delete,
                    // WRITE_DAC, WRITE_OWNER and generic write/all rights.
                    if mask & 0x500d_0156 != 0
                        && EqualSid(header.add(8) as Ptr, token[0] as Ptr) == 0
                    {
                        return Err(Error::other("directory is writable by another principal"));
                    }
                }
                1 => {} // A deny ACE grants no access.
                _ => return Err(Error::other("unsupported storage DACL ACE")),
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
