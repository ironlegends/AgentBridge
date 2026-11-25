//! Exact inherited Windows CDP pipe handles, without a TCP debugger endpoint.
//! Chrome's --remote-debugging-pipe uses the two handles enumerated by the
//! --remote-debugging-io-pipes Windows switch; stdin/stdout are NOT CDP.
//! The Windows STARTUPINFOEX handle list inherits only those two handles.
//! No shell, process discovery, browser profile import or service required.
#![cfg(windows)]
use super::fail;
use std::ffi::{c_void, OsStr};
use std::fs::File;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;

type Handle = *mut c_void;
const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const CREATE_SUSPENDED: u32 = 0x0000_0004;
const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
const HANDLE_FLAG_INHERIT: u32 = 1;
const WAIT_OBJECT_0: u32 = 0;
const STARTF_USESTDHANDLES: u32 = 0x0000_0100;

#[repr(C)]
struct SecurityAttributes {
    length: u32,
    descriptor: Handle,
    inherit: i32,
}
#[repr(C)]
struct StartupInfo {
    cb: u32,
    reserved: *mut u16,
    desktop: *mut u16,
    title: *mut u16,
    x: u32, y: u32, x_size: u32, y_size: u32,
    x_chars: u32, y_chars: u32, fill_attribute: u32,
    flags: u32,
    show_window: u16,
    reserved2_len: u16,
    reserved2: *mut u8,
    std_in: Handle,
    std_out: Handle,
    std_err: Handle,
}
#[repr(C)]
struct StartupInfoEx {
    startup: StartupInfo,
    attributes: *mut c_void,
}
#[repr(C)]
struct ProcessInformation {
    process: Handle,
    thread: Handle,
    process_id: u32,
    thread_id: u32,
}

#[link(name="kernel32")]
extern "system" {
    fn CreatePipe(
        read: *mut Handle, write: *mut Handle,
        security: *mut SecurityAttributes, size: u32,
    ) -> i32;
    fn SetHandleInformation(handle: Handle, mask: u32, flags: u32) -> i32;
    fn InitializeProcThreadAttributeList(
        list: *mut c_void, count: u32, flags: u32, bytes: *mut usize,
    ) -> i32;
    fn UpdateProcThreadAttribute(
        list: *mut c_void, flags: u32, attribute: usize,
        value: *mut c_void, size: usize, previous: *mut c_void,
        returned: *mut usize,
    ) -> i32;
    fn DeleteProcThreadAttributeList(list: *mut c_void);
    fn CreateProcessW(
        application: *const u16,
        command: *mut u16,
        process_security: *mut SecurityAttributes,
        thread_security: *mut SecurityAttributes,
        inherit_handles: i32,
        flags: u32,
        environment: *mut c_void,
        current_directory: *const u16,
        startup: *mut StartupInfo,
        process: *mut ProcessInformation,
    ) -> i32;
    fn ResumeThread(handle: Handle) -> u32;
    fn WaitForSingleObject(handle: isize, milliseconds: u32) -> u32;
    fn TerminateProcess(handle: Handle, exit_code: u32) -> i32;
}
fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(std::iter::once(0)).collect()
}
fn quote_arg(s: &str) -> io::Result<String> {
    // Our own executable, private data directory and fixed ASCII switches.
    // Refuse quotes and newlines instead of implementing commandline escape
    // ambiguities or using any shell.
    if s.is_empty() || s.contains('"') || s.contains('\r') || s.contains('\n') {
        return Err(fail());
    }
    Ok(format!("\"{s}\""))
}

fn create_pipe() -> io::Result<(OwnedHandle,OwnedHandle)> {
    let mut read = ptr::null_mut();
    let mut write = ptr::null_mut();
    let mut attr = SecurityAttributes {
        length:size_of::<SecurityAttributes>() as u32,
        descriptor:ptr::null_mut(), inherit:1,
    };
    if unsafe { CreatePipe(&mut read,&mut write,&mut attr,0) }==0 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        unsafe {OwnedHandle::from_raw_handle(read)},
        unsafe {OwnedHandle::from_raw_handle(write)}
    ))
}

pub(super) struct ChildProcess {
    process: OwnedHandle,
    thread: OwnedHandle,
}
impl ChildProcess {
    pub(super) fn process_handle(&self) -> Handle {
        self.process.as_raw_handle()
    }
    pub(super) fn resume(&self) -> io::Result<()> {
        if unsafe { ResumeThread(self.thread.as_raw_handle()) }!=1 {
            return Err(fail());
        }
        Ok(())
    }
    pub(super) fn wait(&self) -> io::Result<()> {
        match unsafe { WaitForSingleObject(self.process.as_raw_handle() as isize,3000) } {
            WAIT_OBJECT_0=>Ok(()),
            _=>Err(fail())
        }
    }
    pub(super) fn kill_root(&self) {
        unsafe { TerminateProcess(self.process.as_raw_handle(),1); }
        let _=self.wait();
    }
}

/// Two independent, anonymous CDP pipes with a restricted inheritance list.
/// Child has read-of-commands and write-of-events only. Parent owns the other
/// ends as std File, reusable by the existing bounded JSON CDP codec.
pub(super) fn launch(
    executable:&Path, cwd:&Path, profile:&Path,
) -> io::Result<(ChildProcess,File,File)> {
    let (child_read,parent_write)=create_pipe()?;
    let (parent_read,child_write)=create_pipe()?;
    for handle in [&parent_write,&parent_read] {
        if unsafe { SetHandleInformation(handle.as_raw_handle(),HANDLE_FLAG_INHERIT,0) }==0 {
            return Err(fail());
        }
    }
    let inherited=[child_read.as_raw_handle(),child_write.as_raw_handle()];
    let mut bytes=0usize;
    unsafe { InitializeProcThreadAttributeList(ptr::null_mut(),1,0,&mut bytes); }
    if bytes==0 || bytes>65536 {return Err(fail());}
    // A word-aligned allocation for PROC_THREAD_ATTRIBUTE_LIST.
    let mut buffer=vec![0usize;bytes.div_ceil(size_of::<usize>())];
    let attributes=buffer.as_mut_ptr().cast::<c_void>();
    if unsafe { InitializeProcThreadAttributeList(attributes,1,0,&mut bytes) }==0 {
        return Err(fail());
    }
    let updated=unsafe {
        UpdateProcThreadAttribute(attributes,0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherited.as_ptr() as *mut c_void,
            size_of::<Handle>()*inherited.len(),
            ptr::null_mut(),ptr::null_mut())
    };
    if updated==0 {
        unsafe { DeleteProcThreadAttributeList(attributes); }
        return Err(fail());
    }
    let exe=executable.to_str().ok_or_else(fail)?;
    let data=profile.to_str().ok_or_else(fail)?;
    let args=[
        quote_arg(exe)?,
        "--headless=new".to_owned(),
        "--remote-debugging-pipe".to_owned(),
        format!("--remote-debugging-io-pipes={},{}",inherited[0] as usize,inherited[1] as usize),
        "--no-first-run".to_owned(),
        "--no-default-browser-check".to_owned(),
        quote_arg(&format!("--user-data-dir={data}"))?,
        "--disable-background-networking".to_owned(),
        "--disable-extensions".to_owned(),
        "--disable-default-apps".to_owned(),
        "--disable-component-update".to_owned(),
        "--disable-sync".to_owned(),
        "--disable-crash-reporter".to_owned(),
        "--disable-breakpad".to_owned(),
        "--no-proxy-server".to_owned(),
        "--disable-features=MediaRouter,OptimizationHints".to_owned(),
        "about:blank".to_owned(),
    ];
    let mut command=wide(OsStr::new(&args.join(" ")));
    let app=wide(executable.as_os_str());
    let directory=wide(cwd.as_os_str());
    let mut startup: StartupInfoEx=unsafe {zeroed()};
    startup.startup.cb=size_of::<StartupInfoEx>() as u32;
    // No personal stdin/stdout/stderr. CDP uses only inherited pipe handles.
    startup.startup.flags=STARTF_USESTDHANDLES;
    startup.attributes=attributes;
    let mut result:ProcessInformation=unsafe {zeroed()};
    let created=unsafe {
        CreateProcessW(
            app.as_ptr(),command.as_mut_ptr(),ptr::null_mut(),ptr::null_mut(),
            1,EXTENDED_STARTUPINFO_PRESENT|CREATE_NO_WINDOW|CREATE_SUSPENDED,
            ptr::null_mut(),directory.as_ptr(),&mut startup.startup,&mut result
        )
    };
    unsafe { DeleteProcThreadAttributeList(attributes); }
    if created==0 {return Err(io::Error::last_os_error());}
    // Close the child ends locally; only Chrome owns its copies.
    drop(child_read);
    drop(child_write);
    let owned=ChildProcess {
        process:unsafe {OwnedHandle::from_raw_handle(result.process)},
        thread:unsafe {OwnedHandle::from_raw_handle(result.thread)}
    };
    let stdin=File::from(parent_write);
    let stdout=File::from(parent_read);
    Ok((owned,stdin,stdout))
}
