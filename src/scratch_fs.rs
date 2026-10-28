//! Handle-relative scratch admission and removal. Never follow ancestor pathnames.
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::path::Path;

pub fn open_parent(path: &Path) -> io::Result<File> {
    crate::platform::check_private_dir(path)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.share_mode(3).custom_flags(0x0220_0000);
    }
    let file = opts.open(path)?;
    crate::platform::check_private_dir_handle(&file)?;
    Ok(file)
}

pub fn open_root(dir: &File, name: &OsStr) -> io::Result<File> {
    #[cfg(unix)]
    {
        open(dir, name, true)
    }
    #[cfg(windows)]
    {
        crate::platform::open_scratch_view(dir, Path::new(name))
    }
}

pub fn pin_removal(root: &File) -> io::Result<File> {
    #[cfg(unix)]
    {
        root.try_clone()
    }
    #[cfg(windows)]
    {
        // An empty NT relative name reopens the object itself, even if its
        // original name was replaced. DELETE access and no delete sharing are
        // needed only during removal, not while MXC brokers workload paths.
        crate::platform::open_scratch_relative(root, Path::new(""), true)
    }
}

pub fn open(dir: &File, name: &OsStr, directory: bool) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(name.as_bytes())?;
        // SAFETY: single leaf and retained parent, never follow a symlink.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC
                    | if directory { libc::O_DIRECTORY } else { 0 },
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    #[cfg(windows)]
    {
        crate::platform::open_scratch_relative(dir, Path::new(name), directory)
    }
}

#[cfg(unix)]
pub fn names(dir: &File) -> io::Result<Vec<OsString>> {
    use std::os::fd::IntoRawFd;
    use std::os::unix::ffi::OsStrExt;
    // Open '.', rather than dup: each enumeration needs an independent offset.
    let fd = open(dir, OsStr::new("."), true)?.into_raw_fd();
    let ptr = unsafe { libc::fdopendir(fd) };
    if ptr.is_null() {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }
    struct Stream(*mut libc::DIR);
    impl Drop for Stream {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    let stream = Stream(ptr);
    let mut names = Vec::new();
    loop {
        #[cfg(target_os = "macos")]
        unsafe {
            *libc::__error() = 0;
        }
        #[cfg(target_os = "linux")]
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error().is_some_and(|e| e != 0) {
                return Err(error);
            }
            return Ok(names);
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        if ![b".".as_slice(), b"..".as_slice()].contains(&name.to_bytes()) {
            names.push(OsStr::from_bytes(name.to_bytes()).to_owned());
        }
    }
}

#[cfg(windows)]
pub fn names(dir: &File) -> io::Result<Vec<OsString>> {
    use std::os::windows::{ffi::OsStringExt, io::AsRawHandle};
    extern "system" {
        fn GetFileInformationByHandleEx(
            h: *mut core::ffi::c_void,
            class: i32,
            data: *mut core::ffi::c_void,
            size: u32,
        ) -> i32;
    }
    // FILE_ID_BOTH_DIR_INFO has FileName at byte 104. u64 storage aligns all fields.
    let mut data = vec![0u64; 8192];
    let mut class = 11; // FileIdBothDirectoryRestartInfo
    let mut names = Vec::new();
    loop {
        if unsafe {
            GetFileInformationByHandleEx(
                dir.as_raw_handle(),
                class,
                data.as_mut_ptr().cast(),
                (data.len() * 8) as u32,
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(18) {
                Ok(names)
            } else {
                Err(error)
            };
        }
        class = 10; // FileIdBothDirectoryInfo
        let bytes =
            unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), data.len() * 8) };
        let mut offset = 0;
        loop {
            let field = |at: usize| -> io::Result<usize> {
                Ok(u32::from_ne_bytes(
                    bytes
                        .get(offset + at..offset + at + 4)
                        .ok_or_else(|| io::Error::other("invalid directory record"))?
                        .try_into()
                        .unwrap(),
                ) as usize)
            };
            let next = field(0)?;
            let len = field(60)?;
            let name = bytes
                .get(offset + 104..offset + 104 + len)
                .filter(|_| len % 2 == 0)
                .ok_or_else(|| io::Error::other("invalid directory name"))?;
            let wide: Vec<u16> = name
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u16::from_ne_bytes(*b))
                .collect();
            let name = OsString::from_wide(&wide);
            if name != "." && name != ".." {
                names.push(name);
            }
            if next == 0 {
                break;
            }
            if next < 104 {
                return Err(io::Error::other("invalid directory offset"));
            }
            offset += next;
        }
    }
}

#[cfg(unix)]
fn unlink(dir: &File, name: &OsStr, directory: bool) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(name.as_bytes())?;
    if unsafe {
        libc::unlinkat(
            dir.as_raw_fd(),
            name.as_ptr(),
            if directory { libc::AT_REMOVEDIR } else { 0 },
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
#[cfg(windows)]
fn delete_handle(file: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    extern "system" {
        fn SetFileInformationByHandle(
            h: *mut core::ffi::c_void,
            class: i32,
            data: *const core::ffi::c_void,
            size: u32,
        ) -> i32;
    }
    let delete: u8 = 1; // FILE_DISPOSITION_INFO.DeleteFile
    if unsafe {
        SetFileInformationByHandle(file.as_raw_handle(), 4, (&delete as *const u8).cast(), 1)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// Each frame owns a directory while it is inspected. Windows keeps all handles
// to pin ancestor names against replacement. Unix keeps a bounded window and
// reopens an evicted parent only through its held child's "..", checking the
// saved identity before using it. A moved child fails closed, never redirecting
// deletion through a substituted ancestor pathname.
struct RemovalFrame {
    dir: Option<File>,
    #[cfg(unix)]
    name: OsString,
    entries: std::vec::IntoIter<OsString>,
    #[cfg(unix)]
    identity: (u64, u64),
}
impl RemovalFrame {
    fn new(dir: File, _name: &OsStr) -> io::Result<Self> {
        Ok(Self {
            entries: names(&dir)?.into_iter(),
            #[cfg(unix)]
            identity: crate::platform::held_directory_identity(&dir)?,
            dir: Some(dir),
            #[cfg(unix)]
            name: _name.to_owned(),
        })
    }
}

// Return None after deleting a non-directory leaf without following it.
fn removal_directory(dir: &File, name: &OsStr) -> io::Result<Option<File>> {
    #[cfg(unix)]
    {
        match open(dir, name, true) {
            Ok(child) => Ok(Some(child)),
            Err(e) if [Some(libc::ENOTDIR), Some(libc::ELOOP)].contains(&e.raw_os_error()) => {
                unlink(dir, name, false)?;
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
    #[cfg(windows)]
    {
        let child = open(dir, name, false)?;
        let meta = child.metadata()?;
        if meta.is_dir() && !crate::platform::is_link(&meta) {
            Ok(Some(child))
        } else {
            delete_handle(&child)?;
            Ok(None)
        }
    }
}

pub fn remove(dir: &File, name: &OsStr) -> io::Result<()> {
    let Some(child) = removal_directory(dir, name)? else {
        return Ok(());
    };
    let mut stack = vec![RemovalFrame::new(child, name)?];
    while let Some(frame) = stack.last_mut() {
        if let Some(entry) = frame.entries.next() {
            if let Some(child) = removal_directory(frame.dir.as_ref().unwrap(), &entry)? {
                let next = RemovalFrame::new(child, &entry)?;
                #[cfg(unix)]
                if stack.len() >= 16 {
                    // Leave room for enumeration, locks and unrelated runtime
                    // descriptors even under a low process descriptor limit.
                    let evicted = stack.len() - 16;
                    stack[evicted].dir.take();
                }
                stack.push(next);
            }
            continue;
        }
        let child = stack.pop().unwrap();
        let child_dir = child.dir.unwrap();
        #[cfg(unix)]
        {
            let parent = if let Some(frame) = stack.last_mut() {
                if frame.dir.is_none() {
                    let reopened = open(&child_dir, OsStr::new(".."), true)?;
                    if crate::platform::held_directory_identity(&reopened)? != frame.identity {
                        return Err(io::Error::other("scratch parent moved during cleanup"));
                    }
                    frame.dir = Some(reopened);
                }
                frame.dir.as_ref().unwrap()
            } else {
                dir
            };
            // Only unlink an empty replacement if the entry was renamed.
            // Descendant deletion always used the admitted directory handle.
            unlink(parent, &child.name, true)?;
        }
        #[cfg(windows)]
        delete_handle(&child_dir)?;
    }
    Ok(())
}

pub fn remove_root(parent: &File, name: &OsStr, root: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        // A concurrent rename may leave the admitted directory for recovery.
        // Never unlink a substituted live scratch directory.
        if crate::platform::held_directory_identity(&open(parent, name, true)?)?
            != crate::platform::held_directory_identity(root)?
        {
            return Err(io::Error::other("scratch root replaced during cleanup"));
        }
        unlink(parent, name, true)
    }
    #[cfg(windows)]
    {
        let _ = (parent, name);
        delete_handle(root)
    }
}
