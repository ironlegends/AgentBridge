//! Private operator journal HANDLE checks and crash-released OS file locks.
//! The lifecycle registry read additionally qualifies the entire settings root.
use std::fs::{File, OpenOptions};
use std::io;

fn reject() -> io::Error { io::Error::other("Private operator journal handle rejected") }

pub(super) fn options(options: &mut OpenOptions) {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        #[cfg(target_os = "linux")]
        options.custom_flags(0x20000); // O_NOFOLLOW
        #[cfg(target_os = "macos")]
        options.custom_flags(0x100); // O_NOFOLLOW
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
        fn getuid() -> u32;
        fn geteuid() -> u32;
    }
    pub(super) fn check(file: &File) -> io::Result<()> {
        let md = file.metadata()?;
        let uid = unsafe { getuid() };
        if uid == 0 || uid != unsafe { geteuid() }
            || !md.is_file() || md.uid() != uid || md.nlink() != 1
            || md.mode() & 0o7777 != 0o600
        { return Err(reject()); }
        Ok(())
    }
    pub(super) fn lock(file: &File) -> io::Result<()> {
        if unsafe { flock(file.as_raw_fd(), 2 | 4) } != 0 { return Err(reject()); }
        Ok(())
    }
    pub(super) fn unlock(file: &File) {
        unsafe { flock(file.as_raw_fd(), 8); }
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::null_mut;

    type Handle = *mut c_void;
    const REPARSE_POINT: u32 = 0x400;
    const DIRECTORY: u32 = 0x10;
    const OWNER_DACL: u32 = 0x1 | 0x4;
    const TOKEN_QUERY: u32 = 0x8;

    #[repr(C)]
    #[derive(Default)]
    struct FileTime { low: u32, high: u32 }
    #[repr(C)]
    #[derive(Default)]
    struct FileInfo {
        attributes: u32,
        created: FileTime,
        accessed: FileTime,
        written: FileTime,
        volume: u32,
        size_hi: u32,
        size_lo: u32,
        links: u32,
        index_hi: u32,
        index_lo: u32,
    }
    #[repr(C)]
    struct SidAndAttributes { sid: Handle, attributes: u32 }

    #[link(name = "Kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn CloseHandle(handle: Handle) -> i32;
        fn LocalFree(pointer: Handle) -> Handle;
        fn GetFileInformationByHandle(handle: Handle, info: *mut FileInfo) -> i32;
        fn LockFile(handle: Handle, offset_lo: u32, offset_hi: u32, size_lo: u32, size_hi: u32) -> i32;
        fn UnlockFile(handle: Handle, offset_lo: u32, offset_hi: u32, size_lo: u32, size_hi: u32) -> i32;
    }
    #[link(name = "Advapi32")]
    extern "system" {
        fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
        fn GetTokenInformation(token: Handle, class: i32, buffer: Handle, len: u32, required: *mut u32) -> i32;
        fn ConvertSidToStringSidW(sid: Handle, output: *mut *mut u16) -> i32;
        fn GetSecurityInfo(handle: Handle, object_type: u32, info: u32,
            owner: *mut Handle, group: *mut Handle, dacl: *mut Handle,
            sacl: *mut Handle, sd: *mut Handle) -> u32;
        fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd: Handle, revision: u32, info: u32, result: *mut *mut u16, size: *mut u32) -> i32;
    }

    fn wide(pointer: *const u16) -> io::Result<String> {
        if pointer.is_null() { return Err(reject()); }
        let mut len = 0;
        unsafe {
            while len < 65536 && *pointer.add(len) != 0 { len += 1; }
            if len == 65536 { return Err(reject()); }
            String::from_utf16(std::slice::from_raw_parts(pointer, len)).map_err(|_| reject())
        }
    }

    fn current_sid() -> io::Result<String> {
        let mut token: Handle = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0
            || token.is_null()
        { return Err(reject()); }
        let result = (|| {
            let mut required = 0u32;
            // TokenUser == 1. First query measures the required aligned buffer.
            unsafe { GetTokenInformation(token, 1, null_mut(), 0, &mut required); }
            if required < size_of::<SidAndAttributes>() as u32 || required > 65536 {
                return Err(reject());
            }
            let mut data = vec![0usize; (required as usize + size_of::<usize>() - 1) / size_of::<usize>()];
            if unsafe { GetTokenInformation(token, 1, data.as_mut_ptr().cast(),
                required, &mut required) } == 0 { return Err(reject()); }
            let sid = unsafe { (*(data.as_ptr() as *const SidAndAttributes)).sid };
            if sid.is_null() { return Err(reject()); }
            let mut text: *mut u16 = null_mut();
            if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 { return Err(reject()); }
            let value = wide(text);
            unsafe { LocalFree(text.cast()); }
            value
        })();
        unsafe { CloseHandle(token); }
        let sid = result?;
        if !sid.starts_with("S-1-")
            || matches!(sid.as_str(), "S-1-5-18" | "S-1-5-19" | "S-1-5-20")
        { return Err(reject()); }
        Ok(sid)
    }

    fn check_acl(text: &str, sid: &str) -> io::Result<()> {
        let after = text.strip_prefix("O:").ok_or_else(reject)?;
        let end = ["G:", "D:", "S:"].iter().filter_map(|part| after.find(part))
            .min().unwrap_or(after.len());
        if &after[..end] != sid { return Err(reject()); }
        let acl = text.split_once("D:").ok_or_else(reject)?.1;
        let acl = acl.split("S:").next().unwrap_or(acl);
        let start = acl.find('(').ok_or_else(reject)?;
        let flags = &acl[..start];
        if !flags.bytes().all(|b| matches!(b, b'P' | b'A' | b'I' | b'R')) {
            return Err(reject());
        }
        let mut rest = &acl[start..];
        let mut owner_present = false;
        while !rest.is_empty() {
            if !rest.starts_with('(') { return Err(reject()); }
            let end = rest.find(')').ok_or_else(reject)?;
            let fields: Vec<_> = rest[1..end].split(';').collect();
            if fields.len() != 6 || fields[0] != "A"
                || !matches!(fields[2], "FA" | "0x1f01ff")
                || !fields[3].is_empty() || !fields[4].is_empty()
                || (fields[5] != sid && fields[5] != "SY")
            { return Err(reject()); }
            if fields[5] == sid { owner_present = true; }
            rest = &rest[end + 1..];
        }
        if !owner_present { return Err(reject()); }
        Ok(())
    }

    pub(super) fn check(file: &File) -> io::Result<()> {
        let handle = file.as_raw_handle().cast();
        let mut info = FileInfo::default();
        if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0
            || info.attributes & (REPARSE_POINT | DIRECTORY) != 0
            || info.links != 1
        { return Err(reject()); }

        let mut sd: Handle = null_mut();
        if unsafe { GetSecurityInfo(handle, 1, OWNER_DACL, null_mut(),
            null_mut(), null_mut(), null_mut(), &mut sd) } != 0
            || sd.is_null() { return Err(reject()); }
        let mut string: *mut u16 = null_mut();
        let success = unsafe { ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd, 1, OWNER_DACL, &mut string, null_mut()) };
        unsafe { LocalFree(sd); }
        if success == 0 || string.is_null() { return Err(reject()); }
        let sddl = wide(string);
        unsafe { LocalFree(string.cast()); }
        check_acl(&sddl?, &current_sid()?)
    }
    pub(super) fn lock(file: &File) -> io::Result<()> {
        if unsafe { LockFile(file.as_raw_handle().cast(), 0, 0, 1, 0) } == 0 {
            return Err(reject());
        }
        Ok(())
    }
    pub(super) fn unlock(file: &File) {
        unsafe { UnlockFile(file.as_raw_handle().cast(), 0, 0, 1, 0); }
    }
}

pub(super) fn check(file: &File) -> io::Result<()> {
    #[cfg(windows)]
    { windows::check(file) }
    #[cfg(unix)]
    { unix::check(file) }
}

pub(super) struct OsLock(File);
impl OsLock {
    pub(super) fn acquire(file: File) -> io::Result<Self> {
        check(&file)?;
        #[cfg(windows)]
        windows::lock(&file)?;
        #[cfg(unix)]
        unix::lock(&file)?;
        Ok(Self(file))
    }
}
impl Drop for OsLock {
    fn drop(&mut self) {
        #[cfg(windows)]
        windows::unlock(&self.0);
        #[cfg(unix)]
        unix::unlock(&self.0);
    }
}
