//! Windows-only private lifecycle state and original process incarnation check.
//! Every OS call here is non-privileged. There is no shell, service, task,
//! elevated token request, TerminateProcess, or JobObject kill-on-close.

use std::{
    ffi::{OsStr, OsString},
    fs::{self, Metadata, OpenOptions},
    mem::{size_of, zeroed},
    os::windows::{ffi::{OsStrExt, OsStringExt}, fs::{MetadataExt, OpenOptionsExt}},
    path::Path,
    ptr,
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, LocalFree, FILETIME},
    Security::{
        GetFileSecurityW, GetTokenInformation, TokenUser, TokenElevation,
        TOKEN_USER, TOKEN_ELEVATION, TOKEN_QUERY, SECURITY_ATTRIBUTES,
        OWNER_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION,
    },
    Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        ConvertSecurityDescriptorToStringSecurityDescriptorW,
    },
    Storage::FileSystem::CreateDirectoryW,
    System::Threading::{
        GetCurrentProcess, OpenProcessToken, OpenProcess, GetProcessTimes,
        QueryFullProcessImageNameW, WaitForSingleObject,
        PROCESS_QUERY_LIMITED_INFORMATION,
    },
};
use crate::{LifecycleError, Ready, Result};

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const SDDL_REVISION: u32 = 1;

fn wide(path: &OsStr) -> Vec<u16> {
    path.encode_wide().chain(std::iter::once(0)).collect()
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0); }
        }
    }
}

/// Extract the real current account SID, not a user-supplied account name.
/// Refuse elevated, SYSTEM or unevaluable tokens for this portable launcher.
fn current_sid() -> Result<String> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(LifecycleError::Uncertain("Windows account token unavailable"));
    }
    let token = Handle(token);
    let mut count = 0u32;
    let mut elevated: TOKEN_ELEVATION = unsafe { zeroed() };
    if unsafe {
        GetTokenInformation(
            token.0, TokenElevation, (&mut elevated as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32, &mut count,
        )
    } == 0 || elevated.TokenIsElevated != 0 {
        return Err(LifecycleError::Uncertain("elevated or unqualified Windows token"));
    }
    let mut needed = 0u32;
    unsafe {
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 || needed > 65536 {
        return Err(LifecycleError::Uncertain("unavailable Windows user SID"));
    }
    let mut storage = vec![0usize; (needed as usize + size_of::<usize>() - 1) / size_of::<usize>()];
    if unsafe {
        GetTokenInformation(
            token.0, TokenUser, storage.as_mut_ptr().cast(),
            needed, &mut needed,
        )
    } == 0 {
        return Err(LifecycleError::Uncertain("Windows user SID could not be read"));
    }
    let raw = unsafe { &*(storage.as_ptr().cast::<TOKEN_USER>()) };
    let mut sid_ptr = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(raw.User.Sid, &mut sid_ptr) } == 0 {
        return Err(LifecycleError::Uncertain("Windows SID serialization failed"));
    }
    let sid = unsafe { from_wide_ptr(sid_ptr) };
    unsafe { LocalFree(sid_ptr.cast()); }
    // Local/domain and Entra/AAD user SIDs are accepted. Known service
    // identities are not portable interactive owners.
    if !sid.starts_with("S-1-") || matches!(
        sid.as_str(), "S-1-5-18" | "S-1-5-19" | "S-1-5-20"
    ) {
        return Err(LifecycleError::Uncertain("non-interactive Windows account"));
    }
    Ok(sid)
}

unsafe fn from_wide_ptr(value: *const u16) -> String {
    let mut len = 0usize;
    while len < 65536 && *value.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(value, len))
}

pub(crate) fn is_reparse(md: &Metadata) -> bool {
    md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

pub(crate) fn private_directory_sddl() -> Result<String> {
    let sid = current_sid()?;
    Ok(format!("O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)"))
}

pub(crate) fn create_private_directory(path: &Path) -> Result<()> {
    // Protected DACL at creation time prevents a permissive parent ACL from
    // ever exposing session secrets. Only the account and SYSTEM are allowed.
    let sddl = private_directory_sddl()?;
    let sddl = wide(OsStr::new(&sddl));
    let mut descriptor = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(), SDDL_REVISION, &mut descriptor, ptr::null_mut(),
        )
    } == 0 {
        return Err(LifecycleError::Uncertain("Windows security descriptor unavailable"));
    }
    let attrs = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let name = wide(path.as_os_str());
    let failure = (unsafe { CreateDirectoryW(name.as_ptr(), &attrs) } == 0)
        .then(std::io::Error::last_os_error);
    unsafe { LocalFree(descriptor.cast()); }
    if let Some(error) = failure {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            return Err(error.into());
        }
        return Err(LifecycleError::Uncertain("private Windows directory creation refused"));
    }
    verify_private_directory(path)
}

fn security_sddl(path: &Path) -> Result<String> {
    let name = wide(path.as_os_str());
    let requested = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut size = 0u32;
    unsafe { GetFileSecurityW(name.as_ptr(), requested, ptr::null_mut(), 0, &mut size); }
    if size == 0 || size > 65536 {
        return Err(LifecycleError::Uncertain("Windows file security descriptor unavailable"));
    }
    let mut bytes = vec![0usize; (size as usize + size_of::<usize>() - 1) / size_of::<usize>()];
    if unsafe {
        GetFileSecurityW(name.as_ptr(), requested, bytes.as_mut_ptr().cast(), size, &mut size)
    } == 0 {
        return Err(LifecycleError::Uncertain("Windows ACL could not be inspected"));
    }
    let mut out = ptr::null_mut();
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            bytes.as_mut_ptr().cast(), SDDL_REVISION, requested,
            &mut out, ptr::null_mut(),
        )
    } == 0 {
        return Err(LifecycleError::Uncertain("Windows ACL serialization failed"));
    }
    let serialized = unsafe { from_wide_ptr(out) };
    unsafe { LocalFree(out.cast()); }
    Ok(serialized)
}

/// A closed, explicit allowlist: owner SID or SYSTEM with full access. No
/// Everyone, Users, Administrators, inherited broad access or unknown ACEs.
fn verify_acl(path: &Path, directory: bool) -> Result<()> {
    check_sddl(&security_sddl(path)?, directory)
}

fn check_sddl(text: &str, directory: bool) -> Result<()> {
    let sid = current_sid()?;
    let after_owner = text.strip_prefix("O:")
        .ok_or(LifecycleError::Uncertain("missing Windows owner SID"))?;
    let owner_end = ["G:", "D:", "S:"].iter()
        .filter_map(|marker| after_owner.find(marker)).min()
        .unwrap_or(after_owner.len());
    if &after_owner[..owner_end] != sid {
        return Err(LifecycleError::Uncertain("Windows owner SID mismatch"));
    }
    let mut acl = text.split("D:").nth(1)
        .ok_or(LifecycleError::Uncertain("missing Windows DACL"))?;
    acl = acl.split("S:").next().unwrap_or(acl);
    if directory && !acl.starts_with('P') {
        return Err(LifecycleError::Uncertain("directory DACL is not protected"));
    }
    let start = acl.find('(')
        .ok_or(LifecycleError::Uncertain("empty Windows DACL"))?;
    // No unsupported control flags. D:P for owner directories, D:AI / D:PAI
    // for inherited owner-only file ACLs.
    let flags = &acl[..start];
    if !flags.bytes().all(|b| matches!(b, b'P' | b'A' | b'I' | b'R')) {
        return Err(LifecycleError::Uncertain("unknown Windows DACL control"));
    }
    let mut remaining = &acl[start..];
    let mut account = false;
    while !remaining.is_empty() {
        if !remaining.starts_with('(') {
            return Err(LifecycleError::Uncertain("malformed Windows ACL entry"));
        }
        let end = remaining.find(')')
            .ok_or(LifecycleError::Uncertain("malformed Windows ACL terminator"))?;
        let ace = &remaining[1..end];
        let parts: Vec<&str> = ace.split(';').collect();
        if parts.len() != 6 || parts[0] != "A"
            || !matches!(parts[2], "FA" | "0x1f01ff")
            || !parts[3].is_empty() || !parts[4].is_empty()
            || (parts[5] != sid && parts[5] != "SY")
        {
            return Err(LifecycleError::Uncertain("unauthorized Windows ACL grant"));
        }
        if parts[5] == sid { account = true; }
        if directory && parts[1] != "OICI" {
            return Err(LifecycleError::Uncertain("directory ACL is not inheritable-owner-only"));
        }
        remaining = &remaining[end+1..];
    }
    if !account {
        return Err(LifecycleError::Uncertain("Windows owner has no explicit grant"));
    }
    Ok(())
}

pub(crate) fn verify_private_directory(path: &Path) -> Result<()> {
    let md = fs::symlink_metadata(path)?;
    if !md.is_dir() || is_reparse(&md) {
        return Err(LifecycleError::Uncertain("unsafe Windows state directory"));
    }
    verify_acl(path, true)
}
pub(crate) fn verify_private_file(path: &Path, md: &Metadata) -> Result<()> {
    if !md.is_file() || is_reparse(md) {
        return Err(LifecycleError::Uncertain("unsafe Windows state file"));
    }
    verify_acl(path, false)
}
pub(crate) fn verify_private_handle(file: &std::fs::File, directory: bool) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};
    let h = file.as_raw_handle().cast();
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(h, &mut info) } == 0 ||
        info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
        (info.dwFileAttributes & 0x10 != 0) != directory || (!directory && info.nNumberOfLinks != 1) {
        return Err(LifecycleError::Uncertain("invalid private object type or link count"));
    }
    let requested = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut sd = ptr::null_mut();
    let result = unsafe { GetSecurityInfo(h, SE_FILE_OBJECT, requested, ptr::null_mut(), ptr::null_mut(),
        ptr::null_mut(), ptr::null_mut(), &mut sd) };
    if result != 0 || sd.is_null() { return Err(LifecycleError::Uncertain("private object ACL unavailable")); }
    let mut out = ptr::null_mut();
    let ok = unsafe { ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION, requested,
        &mut out, ptr::null_mut()) };
    unsafe { LocalFree(sd.cast()); }
    if ok == 0 || out.is_null() { return Err(LifecycleError::Uncertain("private object ACL unreadable")); }
    let text = unsafe { from_wide_ptr(out) };
    unsafe { LocalFree(out.cast()); }
    check_sddl(&text, directory)
}
pub(crate) fn private_open_options(options: &mut OpenOptions) {
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

fn process_creation(handle: HANDLE) -> Result<u64> {
    let mut created: FILETIME = unsafe { zeroed() };
    let mut exited: FILETIME = unsafe { zeroed() };
    let mut kernel: FILETIME = unsafe { zeroed() };
    let mut user: FILETIME = unsafe { zeroed() };
    if unsafe {
        GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user)
    } == 0 {
        return Err(LifecycleError::Uncertain("Windows process times unavailable"));
    }
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

pub(crate) fn self_birth() -> Result<u64> {
    process_creation(unsafe { GetCurrentProcess() })
}

pub(crate) struct ProcessWitness(Handle);

pub(crate) fn observe_process(ready: &Ready, expected: &Path) -> Result<ProcessWitness> {
    let raw = unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | 0x0010_0000, 0, ready.pid)
    };
    if raw.is_null() {
        return Err(LifecycleError::Uncertain("original Windows process unavailable"));
    }
    let witness = ProcessWitness(Handle(raw));
    if process_creation(raw)? != ready.birth {
        return Err(LifecycleError::Uncertain("Windows process incarnation changed"));
    }
    let mut buffer = vec![0u16; 32768];
    let mut n = buffer.len() as u32;
    if unsafe {
        QueryFullProcessImageNameW(raw, 0, buffer.as_mut_ptr(), &mut n)
    } == 0 || n == 0 || n as usize > buffer.len() {
        return Err(LifecycleError::Uncertain("Windows process image unavailable"));
    }
    let actual = fs::canonicalize(std::path::PathBuf::from(OsString::from_wide(&buffer[..n as usize])))?;
    let expected = fs::canonicalize(expected)?;
    if !actual.to_string_lossy().eq_ignore_ascii_case(&expected.to_string_lossy()) {
        return Err(LifecycleError::Uncertain("Windows executable image mismatch"));
    }
    if wait_process_exit(&witness, Duration::ZERO)? {
        return Err(LifecycleError::Uncertain("Windows process already exited"));
    }
    Ok(witness)
}

pub(crate) fn wait_process_exit(witness: &ProcessWitness, remaining: Duration) -> Result<bool> {
    let ms = remaining.as_millis().min((u32::MAX - 1) as u128) as u32;
    // The opened HANDLE names the original incarnation even after PID reuse.
    match unsafe { WaitForSingleObject(witness.0.0, ms) } {
        0 => Ok(true),       // WAIT_OBJECT_0
        258 => Ok(false),    // WAIT_TIMEOUT
        _ => Err(LifecycleError::Uncertain("Windows process wait unavailable")),
    }
}
