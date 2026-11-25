//! Win32-native physical pins for the documentary Chrome scratch tree.
//! No shell, token, profile import, or arbitrary-process operation.
#![cfg(windows)]

use super::{refused, random_id};
use std::ffi::{c_void, OsStr};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{FromRawHandle, RawHandle, AsRawHandle};
use std::path::{Component, Path, PathBuf};
use std::ptr::null_mut;
use std::time::{Duration, Instant};

type Handle = *mut c_void;
const INVALID_HANDLE: Handle = -1isize as Handle;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const FILE_LIST_DIRECTORY: u32 = 0x1;
const DELETE: u32 = 0x10000;
const SYNCHRONIZE: u32 = 0x100000;
const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_WRITE: u32 = 2;
const FILE_SHARE_DELETE: u32 = 4;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_DIRECTORY_FILE: u32 = 0x1;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_CREATE: u32 = 2;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const FILE_CREATED: usize = 2;
const MAX_DEPTH: usize = 16;
const MAX_ENTRIES: usize = 4096;
const MAX_BYTES: u64 = 256 * 1024 * 1024;
const CLEANUP_DEADLINE: Duration = Duration::from_secs(5);

fn wide(path: &OsStr) -> Vec<u16> {
    path.encode_wide().chain(std::iter::once(0)).collect()
}

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
    size_high: u32,
    size_low: u32,
    links: u32,
    index_high: u32,
    index_low: u32,
}
#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: Handle,
    object_name: *mut UnicodeString,
    attributes: u32,
    security_descriptor: Handle,
    security_quality_of_service: Handle,
}
#[repr(C)]
struct IoStatusBlock { status: isize, information: usize }

#[link(name="kernel32")]
extern "system" {
    fn CreateFileW(
        name: *const u16, access: u32, share: u32, security: Handle,
        disposition: u32, flags: u32, template: Handle,
    ) -> Handle;
    fn GetFileInformationByHandle(handle: Handle, info: *mut FileInfo) -> i32;
    fn GetFinalPathNameByHandleW(handle: Handle, buffer: *mut u16, length: u32, flags: u32) -> u32;
    fn SetFileInformationByHandle(handle: Handle, class: u32, info: *const c_void, length: u32) -> i32;
}
#[link(name="ntdll")]
extern "system" {
    fn NtCreateFile(
        file_handle: *mut Handle, access: u32, attrs: *mut ObjectAttributes,
        io_status: *mut IoStatusBlock, allocation_size: *mut i64,
        attributes: u32, share: u32, disposition: u32, options: u32,
        ea_buffer: Handle, ea_length: u32,
    ) -> i32;
}

fn canonical_display(path: &Path) -> io::Result<String> {
    let text = path.to_str().ok_or_else(refused)?;
    if text.len() < 3 || !text.as_bytes()[0].is_ascii_alphabetic()
        || text.as_bytes()[1] != b':' || text.as_bytes()[2] != b'\\'
        || text.contains('~')
    { return Err(refused()); }
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Prefix(_)))
        || !matches!(components.next(), Some(Component::RootDir)) {
        return Err(refused());
    }
    if components.any(|c| !matches!(c, Component::Normal(_))) {
        return Err(refused());
    }
    Ok(format!(r"\\?\{text}"))
}

fn final_path(handle: Handle) -> io::Result<String> {
    let mut buffer = vec![0u16; 32768];
    let count = unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0) };
    if count == 0 || count as usize >= buffer.len() { return Err(refused()); }
    String::from_utf16(&buffer[..count as usize]).map_err(|_| refused())
}

fn file_info(handle: Handle) -> io::Result<FileInfo> {
    let mut info = FileInfo::default();
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0
        || info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    { return Err(refused()); }
    Ok(info)
}

fn id(info: &FileInfo) -> (u32, u64) {
    (info.volume, ((info.index_high as u64) << 32) | info.index_low as u64)
}

struct Pin {
    file: File,
    path: PathBuf,
    final_path: String,
    identity: (u32, u64),
    directory: bool,
}
impl Pin {
    fn verified(file: File, path: PathBuf, expected: &str) -> io::Result<Self> {
        let info = file_info(file.as_raw_handle().cast())?;
        let actual = final_path(file.as_raw_handle().cast())?;
        if !actual.eq_ignore_ascii_case(expected)
            || !actual.starts_with(r"\\?\")
            || (info.attributes & FILE_ATTRIBUTE_DIRECTORY == 0 && info.links != 1)
        { return Err(refused()); }
        Ok(Self {
            file, path, final_path: actual, identity: id(&info),
            directory: info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0,
        })
    }
    fn verify(&self) -> io::Result<()> {
        let info = file_info(self.file.as_raw_handle().cast())?;
        let physical = final_path(self.file.as_raw_handle().cast())?;
        if self.identity != id(&info)
            || self.directory != (info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0)
            || !self.final_path.eq_ignore_ascii_case(&physical)
            || (!self.directory && info.links != 1)
        { return Err(refused()); }
        Ok(())
    }
    fn verify_named(&self) -> io::Result<()> {
        self.verify()?;
        // A second inspection HANDLE must share our own DELETE access, while
        // the original pin continues to exclude name replacement.
        let node = open_pin_mode(&self.path, false, true)?;
        if node.identity != self.identity || node.directory != self.directory
            || !node.final_path.eq_ignore_ascii_case(&self.final_path)
        { return Err(refused()); }
        Ok(())
    }
}

fn open_pin(path: &Path, delete: bool) -> io::Result<Pin> {
    open_pin_mode(path, delete, false)
}
fn open_pin_mode(path: &Path, delete: bool, inspection: bool) -> io::Result<Pin> {
    let expected = canonical_display(path)?;
    let name = wide(path.as_os_str());
    let access = FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY
        | if delete { DELETE } else { 0 };
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE
        | if inspection { FILE_SHARE_DELETE } else { 0 };
    let handle = unsafe { CreateFileW(name.as_ptr(), access,
        share, null_mut(), OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, null_mut()) };
    if handle.is_null() || handle == INVALID_HANDLE {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_handle(handle as RawHandle) };
    Pin::verified(file, path.to_owned(), &expected)
}

fn valid_child(name: &OsStr) -> bool {
    let text = name.to_string_lossy();
    !text.is_empty() && text != "." && text != ".." && !text.contains(':')
        && !text.contains('/') && !text.contains('\\')
        && !text.ends_with('.') && !text.ends_with(' ')
        && !text.contains('~')
}

fn pin_ancestors(base: &Path) -> io::Result<Vec<Pin>> {
    let _ = canonical_display(base)?;
    let mut parts = base.components();
    let mut candidate = PathBuf::new();
    candidate.push(parts.next().ok_or_else(refused)?.as_os_str());
    candidate.push(parts.next().ok_or_else(refused)?.as_os_str());
    let mut pins = Vec::new();
    let root = super::at_stage("pin.volume_root", open_pin(&candidate, false))?;
    if !root.directory { return Err(refused()); }
    pins.push(root);
    for part in parts {
        if !matches!(part, Component::Normal(_)) || !valid_child(part.as_os_str()) {
            return Err(refused());
        }
        candidate.push(part);
        let pin = super::at_stage("pin.ancestor", open_pin(&candidate, false))?;
        if !pin.directory { return Err(refused()); }
        pins.push(pin);
    }
    Ok(pins)
}

fn create_directory(parent: &Pin, name: &str) -> io::Result<Pin> {
    if !parent.directory || !valid_child(OsStr::new(name)) || name.len() > 120 {
        return Err(refused());
    }
    parent.verify_named()?;
    let mut chars: Vec<u16> = OsStr::new(name).encode_wide().collect();
    if chars.len() > 240 { return Err(refused()); }
    let mut unicode = UnicodeString {
        length: (chars.len() * 2) as u16,
        maximum_length: (chars.len() * 2) as u16,
        buffer: chars.as_mut_ptr(),
    };
    // Set the DACL in the creation operation, including under a shared TEMP.
    let sddl = agent_bridge_lifecycle::private_directory_sddl().map_err(|_| refused())?;
    let wide_sddl = wide(OsStr::new(&sddl));
    let mut descriptor = null_mut();
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(
        wide_sddl.as_ptr(), 1, &mut descriptor, null_mut()
    ) } == 0 { return Err(refused()); }
    let mut attrs = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: parent.file.as_raw_handle().cast(),
        object_name: &mut unicode,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: descriptor,
        security_quality_of_service: null_mut(),
    };
    let mut status = IoStatusBlock { status: 0, information: 0 };
    let mut handle: Handle = null_mut();
    let result = unsafe {
        NtCreateFile(&mut handle,
            FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | DELETE | SYNCHRONIZE,
            &mut attrs, &mut status, null_mut(), FILE_ATTRIBUTE_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            null_mut(), 0)
    };
    unsafe { LocalFree(descriptor); }
    if result < 0 || handle.is_null() || handle == INVALID_HANDLE
        || status.information != FILE_CREATED
    {
        if !handle.is_null() && handle != INVALID_HANDLE {
            unsafe { drop(File::from_raw_handle(handle as RawHandle)); }
        }
        // NTSTATUS is an OS numeric status, not a file path or user string.
        if result < 0 {
            eprintln!("agent-bridge: doc-stage=profile.directory_create category=NtStatus os_code={result}");
        } else {
            let _ = super::operator_error("profile.directory_create_identity", refused());
        }
        return Err(refused());
    }
    let path = parent.path.join(name);
    let expected = canonical_display(&path)?;
    let file = unsafe { File::from_raw_handle(handle as RawHandle) };
    let pin = Pin::verified(file, path, &expected)?;
    if !pin.directory { return Err(refused()); }
    Ok(pin)
}

struct Budget {
    entries: usize,
    bytes: u64,
    started: Instant,
}
impl Budget {
    fn new() -> Self { Self { entries: 0, bytes: 0, started: Instant::now() } }
    fn consume(&mut self, size: u64, depth: usize) -> io::Result<()> {
        self.entries = self.entries.checked_add(1).ok_or_else(refused)?;
        self.bytes = self.bytes.checked_add(size).ok_or_else(refused)?;
        if self.entries > MAX_ENTRIES || self.bytes > MAX_BYTES
            || depth > MAX_DEPTH || self.started.elapsed() > CLEANUP_DEADLINE
        { return Err(refused()); }
        Ok(())
    }
}

fn mark_delete(pin: &Pin) -> io::Result<()> {
    pin.verify()?;
    // Delete *the opened object*, never a path which may be swapped. Using
    // POSIX semantics avoids a reopen-by-name race and cannot cross reparse.
    const FILE_DISPOSITION_INFO_EX: u32 = 21;
    const DELETE_POSIX: u32 = 0x1 | 0x2;
    let flags = DELETE_POSIX;
    if unsafe { SetFileInformationByHandle(pin.file.as_raw_handle().cast(),
        FILE_DISPOSITION_INFO_EX, (&flags as *const u32).cast(), size_of::<u32>() as u32) } == 0
    { return Err(refused()); }
    Ok(())
}

fn retry_sharing<T>(budget: &Budget, mut action: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let mut sharing_error = None;
    loop {
        if budget.started.elapsed() >= CLEANUP_DEADLINE {
            return Err(sharing_error.unwrap_or_else(refused));
        }
        match action() {
            Ok(value) => return Ok(value),
            Err(error) => {
                // A reader can briefly retain a profile file after our Job is
                // empty. Keep all pin/share checks and retry only this native
                // conflict, never an identity/reparse refusal or another error.
                if error.raw_os_error() != Some(32) { return Err(error); }
                sharing_error = Some(error);
            }
        }
        let remaining = CLEANUP_DEADLINE.saturating_sub(budget.started.elapsed());
        if !remaining.is_zero() {
            std::thread::sleep(remaining.min(Duration::from_millis(20)));
        }
    }
}

fn erase_children(parent: &Pin, depth: usize, budget: &mut Budget) -> io::Result<()> {
    parent.verify_named()?;
    if depth > MAX_DEPTH { return Err(refused()); }
    // The parent HANDLE refuses FILE_SHARE_DELETE, so it cannot be renamed or
    // replaced while this directory is enumerated. Each child is reopened
    // NOFOLLOW and pinned before any recursive access or deletion.
    for entry in fs::read_dir(&parent.path).map_err(|_| refused())? {
        if budget.started.elapsed() > CLEANUP_DEADLINE { return Err(refused()); }
        let entry = entry.map_err(|_| refused())?;
        let name = entry.file_name();
        if !valid_child(&name) { return Err(refused()); }
        let path = parent.path.join(&name);
        let child = retry_sharing(budget, || {
            parent.verify_named()?;
            open_pin(&path, true)
        })?;
        child.verify_named()?;
        let info = file_info(child.file.as_raw_handle().cast())?;
        let size = (u64::from(info.size_high) << 32) | u64::from(info.size_low);
        budget.consume(size, depth)?;
        if child.directory { erase_children(&child, depth + 1, budget)?; }
        mark_delete(&child)?;
        drop(child);
    }
    if fs::read_dir(&parent.path).map_err(|_| refused())?.next().is_some() {
        return Err(refused());
    }
    Ok(())
}

pub(super) struct PrivateTree {
    ancestors: Vec<Pin>,
    root: Option<Pin>,
    profile: Option<Pin>,
    root_path: PathBuf,
    cleaned: bool,
    cleanup_budget: Option<Budget>,
    cleanup_abandoned: bool,
}
impl PrivateTree {
    pub(super) fn create(base: &Path) -> io::Result<Self> {
        let ancestors = super::at_stage("profile.ancestors", pin_ancestors(base))?;
        let temp = ancestors.last().ok_or_else(refused)?;
        let root = super::at_stage("profile.root_create",
            create_directory(temp, &format!("agent-bridge-docview-{}", random_id()?)))?;
        let root_path = root.path.clone();
        let mut tree = Self {
            ancestors, root: Some(root), profile: None,
            root_path, cleaned: false, cleanup_budget: None, cleanup_abandoned: false,
        };
        // If this fails, the Drop guard still removes only the newly created,
        // handle-pinned root directory.
        tree.profile = Some(super::at_stage("profile.data_create",
            create_directory(tree.root.as_ref().ok_or_else(refused)?, "profile"))?);
        Ok(tree)
    }
    pub(super) fn download_root(&self) -> io::Result<PathBuf> {
        self.verify()?;
        Ok(self.root.as_ref().ok_or_else(refused)?.path.clone())
    }
    pub(super) fn data_dir(&self) -> io::Result<PathBuf> {
        self.verify()?;
        Ok(self.profile.as_ref().ok_or_else(refused)?.path.clone())
    }
    pub(super) fn verify(&self) -> io::Result<()> {
        if self.cleaned { return Err(refused()); }
        for pin in &self.ancestors { pin.verify_named()?; }
        self.root.as_ref().ok_or_else(refused)?.verify_named()?;
        if let Some(profile) = &self.profile { profile.verify_named()?; }
        Ok(())
    }
    pub(super) fn html(&self, text: &str) -> io::Result<(PathBuf, File)> {
        self.verify()?;
        let root = self.root.as_ref().ok_or_else(refused)?;
        let path = root.path.join(format!("render-{}.html", random_id()?));
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create_new(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let mut file = opts.open(&path).map_err(|_| refused())?;
        let info = file_info(file.as_raw_handle().cast())?;
        let final_name = final_path(file.as_raw_handle().cast())?;
        if info.links != 1 || info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
            || !final_name.eq_ignore_ascii_case(&canonical_display(&path)?)
        { return Err(refused()); }
        file.write_all(text.as_bytes()).map_err(|_| refused())?;
        file.sync_all().map_err(|_| refused())?;
        Ok((path, file)) // kept open across Chrome rendering: cannot be replaced
    }
    pub(super) fn abandon_cleanup(&mut self) {
        self.cleanup_abandoned = true;
    }

    pub(super) fn cleanup(&mut self) -> io::Result<()> {
        if self.cleanup_abandoned { return Err(refused()); }
        if self.cleaned { return Ok(()); }
        // close(), NativeChrome::drop, PrivateProfile::drop and this guard's
        // Drop all share one deadline and the same entry/byte budget.
        if self.cleanup_budget.get_or_insert_with(Budget::new).started.elapsed()
            >= CLEANUP_DEADLINE
        { return Err(refused()); }
        super::at_stage("cleanup.pin", self.verify())?;
        let budget = self.cleanup_budget.as_mut().ok_or_else(refused)?;
        if let Some(profile) = self.profile.as_ref() {
            super::at_stage("cleanup.profile_children", erase_children(profile, 1, budget))?;
            super::at_stage("cleanup.profile_delete", mark_delete(profile))?;
            self.profile.take(); // closes original handle after POSIX deletion
        }
        let root = self.root.as_ref().ok_or_else(refused)?;
        super::at_stage("cleanup.root_children", erase_children(root, 0, budget))?;
        super::at_stage("cleanup.root_delete", mark_delete(root))?;
        self.root.take();
        // Once the original HANDLE is closed, don't claim a successful cleanup
        // if the namespace still exposes this entry.
        match fs::symlink_metadata(&self.root_path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.cleaned = true;
                Ok(())
            }
            _ => Err(refused()),
        }
    }
}
impl Drop for PrivateTree {
    fn drop(&mut self) {
        if !self.cleaned && !self.cleanup_abandoned { let _ = self.cleanup(); }
    }
}

#[link(name="advapi32")]
extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl: *const u16, revision: u32, descriptor: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
}
#[link(name="kernel32")]
extern "system" {
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}

pub(super) struct BrowserPins { _pins: Vec<Pin> }
pub(super) fn pin_browser(executable: &Path) -> io::Result<BrowserPins> {
    let parent = executable.parent().ok_or_else(refused)?;
    let mut pins = pin_ancestors(parent)?;
    let file = open_pin(executable, false)?;
    if file.directory { return Err(refused()); }
    pins.push(file);
    Ok(BrowserPins { _pins: pins })
}

#[cfg(test)]
#[path = "chrome_native_tests.rs"]
mod tests;
