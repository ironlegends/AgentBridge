//! Verify the owner and DACL of the exact open transfer object. No ACL repair
//! or path-based permission change is performed by this provider.
use super::{private_permissions, Result};
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::null_mut;

type Handle = *mut c_void;
const OWNER_DACL: u32 = 1 | 4;

#[repr(C)]
struct SidAndAttributes { sid: Handle, attributes: u32 }

#[link(name = "Kernel32")]
extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn LocalFree(pointer: Handle) -> Handle;
}
#[link(name = "Advapi32")]
extern "system" {
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn GetTokenInformation(token: Handle, class: i32, buffer: Handle, len: u32, required: *mut u32) -> i32;
    fn ConvertSidToStringSidW(sid: Handle, output: *mut *mut u16) -> i32;
    fn GetSecurityInfo(handle: Handle, kind: u32, info: u32,
        owner: *mut Handle, group: *mut Handle, dacl: *mut Handle, sacl: *mut Handle, sd: *mut Handle) -> u32;
    fn ConvertSecurityDescriptorToStringSecurityDescriptorW(sd: Handle, revision: u32,
        info: u32, result: *mut *mut u16, size: *mut u32) -> i32;
}

fn wide(pointer: *const u16) -> Result<String> {
    if pointer.is_null() { return Err(private_permissions()); }
    let mut len = 0;
    // Only called on NUL-terminated allocations returned by the Win32 security
    // APIs. The bound refuses an unexpectedly large descriptor.
    unsafe {
        while len < 65536 && *pointer.add(len) != 0 { len += 1; }
        if len == 65536 { return Err(private_permissions()); }
        String::from_utf16(std::slice::from_raw_parts(pointer, len)).map_err(|_| private_permissions())
    }
}

fn current_sid() -> Result<String> {
    let mut token = null_mut();
    // SAFETY: initialized output handle and current live process pseudo-handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut token) } == 0 || token.is_null() {
        return Err(private_permissions());
    }
    let result = (|| {
        let mut required = 0u32;
        unsafe { GetTokenInformation(token, 1, null_mut(), 0, &mut required); }
        if required < size_of::<SidAndAttributes>() as u32 || required > 65536 {
            return Err(private_permissions());
        }
        let mut data = vec![0usize; (required as usize).div_ceil(size_of::<usize>())];
        // SAFETY: word-aligned TokenUser buffer with the API-provided size.
        if unsafe { GetTokenInformation(token, 1, data.as_mut_ptr().cast(), required, &mut required) } == 0 {
            return Err(private_permissions());
        }
        let sid = unsafe { (*(data.as_ptr() as *const SidAndAttributes)).sid };
        if sid.is_null() { return Err(private_permissions()); }
        let mut output = null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut output) } == 0 { return Err(private_permissions()); }
        let text = wide(output);
        unsafe { LocalFree(output.cast()); }
        text
    })();
    unsafe { CloseHandle(token); }
    result
}

fn check_acl(text: &str, sid: &str) -> Result<()> {
    let owner = text.strip_prefix("O:").ok_or_else(private_permissions)?;
    let end = ["G:", "D:", "S:"].iter().filter_map(|part| owner.find(part)).min().unwrap_or(owner.len());
    if &owner[..end] != sid { return Err(private_permissions()); }
    let acl = text.split_once("D:").ok_or_else(private_permissions)?.1;
    let acl = acl.split("S:").next().unwrap_or(acl);
    let first = acl.find('(').ok_or_else(private_permissions)?;
    if !acl[..first].bytes().all(|byte| matches!(byte, b'P' | b'A' | b'I' | b'R')) {
        return Err(private_permissions());
    }
    let mut rest = &acl[first..];
    let mut owner_access = false;
    while !rest.is_empty() {
        if !rest.starts_with('(') { return Err(private_permissions()); }
        let end = rest.find(')').ok_or_else(private_permissions)?;
        let fields = rest[1..end].split(';').collect::<Vec<_>>();
        if fields.len() != 6 || fields[0] != "A" || !matches!(fields[2], "FA" | "0x1f01ff")
            || !fields[3].is_empty() || !fields[4].is_empty()
            || (fields[5] != sid && fields[5] != "SY") {
            return Err(private_permissions());
        }
        if fields[5] == sid && !fields[1].contains("IO") { owner_access = true; }
        rest = &rest[end + 1..];
    }
    if !owner_access { return Err(private_permissions()); }
    Ok(())
}

pub(super) fn verify(handle: Handle) -> Result<()> {
    let mut descriptor = null_mut();
    // SAFETY: caller retains the exact open file/directory handle throughout
    // this query; GetSecurityInfo owns the returned descriptor allocation.
    if unsafe { GetSecurityInfo(handle, 1, OWNER_DACL, null_mut(), null_mut(),
        null_mut(), null_mut(), &mut descriptor) } != 0 || descriptor.is_null() {
        return Err(private_permissions());
    }
    let mut output = null_mut();
    let success = unsafe { ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor,
        1, OWNER_DACL, &mut output, null_mut()) };
    unsafe { LocalFree(descriptor); }
    if success == 0 || output.is_null() { return Err(private_permissions()); }
    let text = wide(output);
    unsafe { LocalFree(output.cast()); }
    check_acl(&text?, &current_sid()?)
}
