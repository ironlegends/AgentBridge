#![cfg(windows)]
#![allow(dead_code)]
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::os::windows::ffi::OsStrExt;

#[link(name = "Advapi32")]
extern "system" {
    fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
    fn GetTokenInformation(token: *mut c_void, class: i32, buffer: *mut c_void, len: u32, needed: *mut u32) -> i32;
    fn ConvertSidToStringSidW(sid: *mut c_void, out: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(text: *const u16, revision: u32, out: *mut *mut c_void, len: *mut u32) -> i32;
    fn SetFileSecurityW(path: *const u16, info: u32, descriptor: *mut c_void) -> i32;
}
#[link(name = "Kernel32")]
extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn LocalFree(pointer: *mut c_void) -> *mut c_void;
    fn CreateMutexW(attributes: *mut c_void, initial_owner: i32, name: *const u16) -> *mut c_void;
    fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
    fn ReleaseMutex(handle: *mut c_void) -> i32;
}

fn wide(value: &std::ffi::OsStr) -> Vec<u16> { value.encode_wide().chain(Some(0)).collect() }

pub fn current_sid() -> String {
    unsafe {
        let mut token = null_mut();
        assert_ne!(OpenProcessToken(GetCurrentProcess(), 8, &mut token), 0);
        let mut size = 0;
        GetTokenInformation(token, 1, null_mut(), 0, &mut size);
        assert!(size >= std::mem::size_of::<usize>() as u32 && size <= 65536);
        let mut data = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
        assert_ne!(GetTokenInformation(token, 1, data.as_mut_ptr().cast(), size, &mut size), 0);
        CloseHandle(token);
        let mut text = null_mut();
        assert_ne!(ConvertSidToStringSidW(*(data.as_ptr() as *const *mut c_void), &mut text), 0);
        let mut length = 0;
        while *text.add(length) != 0 { length += 1; assert!(length < 65536); }
        let result = String::from_utf16(std::slice::from_raw_parts(text, length)).unwrap();
        LocalFree(text.cast());
        result
    }
}

pub fn set_acl(path: &Path, extra: &str) {
    let sid = current_sid();
    let sddl = wide(std::ffi::OsStr::new(&format!("O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY){extra}")));
    let path = wide(path.as_os_str());
    unsafe {
        let mut descriptor = null_mut();
        assert_ne!(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut descriptor, null_mut()), 0);
        let result = SetFileSecurityW(path.as_ptr(), 1 | 4 | 0x8000_0000, descriptor);
        let error = std::io::Error::last_os_error();
        LocalFree(descriptor);
        assert_ne!(result, 0, "synthetic directory ACL setup failed: {error}");
    }
}

pub fn make_private(path: &Path) { set_acl(path, ""); }

// DOS drive mappings are shared across test binaries in this Windows session.
// Serialize the complete synthetic alias lifetime, including replace and Drop.
// This is test-only and does not change any product path authority.
struct DosAliasReservation { handle: *mut c_void }
impl DosAliasReservation {
    fn acquire() -> Self {
        let name = wide(std::ffi::OsStr::new(&format!("Local\\AgentBridge.Test.DosAlias.{}", current_sid())));
        let handle = unsafe { CreateMutexW(null_mut(), 0, name.as_ptr()) };
        assert!(!handle.is_null(), "synthetic DOS alias mutex creation failed: {}", std::io::Error::last_os_error());
        let outcome = unsafe { WaitForSingleObject(handle, 30_000) };
        if outcome == 0 { return Self { handle }; }
        let error = std::io::Error::last_os_error();
        // WAIT_ABANDONED grants ownership but the previous fixture may have
        // left a mapping behind. Fail closed rather than treating it as clean.
        if outcome == 0x80 { unsafe { ReleaseMutex(handle); } }
        unsafe { CloseHandle(handle); }
        panic!("synthetic DOS alias reservation failed (wait {outcome:#x}): {error}");
    }
}
impl Drop for DosAliasReservation {
    fn drop(&mut self) {
        if unsafe { ReleaseMutex(self.handle) } == 0 {
            eprintln!("Synthetic DOS alias mutex release failed: {}", std::io::Error::last_os_error());
        }
        if unsafe { CloseHandle(self.handle) } == 0 {
            eprintln!("Synthetic DOS alias mutex close failed: {}", std::io::Error::last_os_error());
        }
    }
}

pub struct DosAlias { device: Vec<u16>, target: Vec<u16>, root: PathBuf, _reservation: DosAliasReservation }
impl DosAlias {
    pub fn new(target: &Path) -> Self {
        use windows_sys::Win32::Storage::FileSystem::{DefineDosDeviceW, QueryDosDeviceW};
        let reservation = DosAliasReservation::acquire();
        for letter in (b'D'..=b'Z').rev() {
            let device = wide(std::ffi::OsStr::new(&format!("{}:", letter as char)));
            let mut probe = [0u16; 512];
            if unsafe { QueryDosDeviceW(device.as_ptr(), probe.as_mut_ptr(), probe.len() as u32) } != 0 { continue; }
            if std::io::Error::last_os_error().raw_os_error() != Some(2) { continue; }
            let target = wide(std::ffi::OsStr::new(&format!("\\??\\{}", target.display())));
            assert_ne!(unsafe { DefineDosDeviceW(1 | 8, device.as_ptr(), target.as_ptr()) }, 0,
                "synthetic DOS alias creation failed: {}", std::io::Error::last_os_error());
            return Self { device, target, root:PathBuf::from(format!("{}:\\", letter as char)), _reservation: reservation };
        }
        panic!("No unused synthetic drive letter available");
    }
    pub fn root(&self) -> &Path { &self.root }
    pub fn replace(&mut self, target: &Path) {
        use windows_sys::Win32::Storage::FileSystem::DefineDosDeviceW;
        assert_ne!(unsafe { DefineDosDeviceW(1 | 2 | 4 | 8, self.device.as_ptr(), self.target.as_ptr()) }, 0);
        self.target = wide(std::ffi::OsStr::new(&format!("\\??\\{}", target.display())));
        assert_ne!(unsafe { DefineDosDeviceW(1 | 8, self.device.as_ptr(), self.target.as_ptr()) }, 0);
    }
}
impl Drop for DosAlias {
    fn drop(&mut self) {
        use windows_sys::Win32::Storage::FileSystem::DefineDosDeviceW;
        let result = unsafe { DefineDosDeviceW(1 | 2 | 4 | 8, self.device.as_ptr(), self.target.as_ptr()) };
        if result == 0 { eprintln!("Synthetic DOS alias cleanup failed: {}", std::io::Error::last_os_error()); }
    }
}

pub fn enable_case_sensitive(path: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::SetFileInformationByHandle;
    let directory = std::fs::OpenOptions::new().access_mode(0x0100)
        .custom_flags(0x0200_0000).open(path)?;
    let flags = 1u32;
    if unsafe { SetFileInformationByHandle(directory.as_raw_handle(), 23,
        (&flags as *const u32).cast(), std::mem::size_of::<u32>() as u32) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
