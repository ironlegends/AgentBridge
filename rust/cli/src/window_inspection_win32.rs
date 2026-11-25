//! Minimal native Windows read-only backend for window_inspection.rs.
//! Raw FFI keeps this isolated module independent of Cargo/feature changes.
//! Never use a caller-supplied HWND or enumerate windows/child elements.

use super::{denied, DedicatedWindow, DesktopAvailability, Identity, WindowObservation};
#[path = "window_inspection_controls_win32.rs"]
mod work_controls;
#[path = "window_inspection_hud_win32.rs"]
mod hud;
use hud::SafetyHud;
pub(super) use work_controls::{ControlRef, controls, act, scroll, send_keys, screenshot};
use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::ptr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

type Handle = isize;
type Hwnd = isize;

const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;
const SYNCHRONIZE: u32 = 0x0010_0000;
const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_USER: u32 = 1;
const TOKEN_ELEVATION: u32 = 20;
const UOI_NAME: i32 = 2;
const GA_ROOT: u32 = 2;
const GW_OWNER: u32 = 4;
const WAIT_TIMEOUT: u32 = 0x102;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_ABANDONED: u32 = 0x80;
const DESKTOP_READOBJECTS: u32 = 0x0001;
const DESKTOP_CREATEWINDOW: u32 = 0x0002;
const DESKTOP_ENUMERATE: u32 = 0x0040;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct FileTime {
    low: u32,
    high: u32,
}
impl FileTime {
    fn as_u64(self) -> u64 {
        ((self.high as u64) << 32) | self.low as u64
    }
}

#[repr(C)]
#[derive(Default)]
struct Rect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

#[repr(C)]
#[derive(Default)]
struct Guid {
    a: u32,
    b: u16,
    c: u16,
    d: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SidAndAttributes {
    sid: *mut c_void,
    attributes: u32,
}

struct OwnedHandle(Handle);

// Keep the process handle open through the final window identity check. A
// PID cannot be recycled while its process object remains referenced.
struct ProcessPin {
    handle: OwnedHandle,
    created: u64,
    image: String,
}

struct ThreadPin {
    handle: OwnedHandle,
    created: u64,
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: OpenProcess/OpenProcessToken/CreateMutexW owned this handle.
            unsafe { CloseHandle(self.0 as *mut c_void); }
        }
    }
}

/// Owns a REAL handle to exactly the preselected, preexisting Win32 desktop.
/// Never uses CreateDesktop, SetThreadDesktop or SwitchDesktop.
struct OwnedDesktop(Handle);

impl Drop for OwnedDesktop {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: only OpenDesktopW results are wrapped here.
            unsafe { CloseDesktop(self.0); }
        }
    }
}

/// Windows mutex ownership is thread-affine. The stdio dispatcher keeps
/// requests on one thread; wrong-thread calls fail instead of unlocking.
struct OwnedDesktopMutex {
    handle: OwnedHandle,
    owner_thread: u32,
    held: bool,
}

impl Drop for OwnedDesktopMutex {
    fn drop(&mut self) {
        if self.held && unsafe { GetCurrentThreadId() } == self.owner_thread {
            // SAFETY: the current thread is the owner, and owns one wait.
            unsafe { ReleaseMutex(self.handle.0); }
        }
    }
}

// A lease cannot depend on further MCP traffic for cleanup. The sole
// Windows mutex owner is a short-lived, dedicated thread that owns both OS
// handles and releases them on expiry, stop, or channel disconnection.
const LEASE_LIFETIME: Duration = Duration::from_secs(120);
const OWNER_READY_TIMEOUT: Duration = Duration::from_secs(3);
const OWNER_VERIFY_TIMEOUT: Duration = Duration::from_secs(1);

enum LeaseCommand {
    Verify(mpsc::SyncSender<bool>),
    Stop,
}

pub(super) struct DesktopLease {
    commands: mpsc::Sender<LeaseCommand>,
    worker: Option<thread::JoinHandle<()>>,
    expires: Instant,
}

struct HeldDesktopLease {
    // Rust drops fields in declaration order: destroy the HUD on its owner
    // thread, release the mutex, then close the selected desktop handle.
    hud: SafetyHud,
    lock: OwnedDesktopMutex,
    desktop: OwnedDesktop,
}

impl HeldDesktopLease {
    fn acquire(spec: &DedicatedWindow) -> io::Result<Self> {
        let desktop = open_selected_desktop(spec)?;
        let handle = named_desktop_mutex(spec)?;
        let outcome = unsafe { WaitForSingleObject(handle.0, 0) };
        if outcome != WAIT_OBJECT_0 {
            if outcome == WAIT_ABANDONED {
                // An abandoned mutex grants ownership. Release it on this
                // thread, then reject rather than inherit an unknown lease.
                unsafe { ReleaseMutex(handle.0); }
            }
            return Err(denied());
        }
        // SetThreadDesktop and the native HUD run ONLY on this newly spawned,
        // windowless lease-owner thread. Never switch the local user desktop.
        let hud = SafetyHud::create(desktop.0, spec)?;
        let guard = Self {
            hud,
            lock: OwnedDesktopMutex {
                handle,
                owner_thread: unsafe { GetCurrentThreadId() },
                held: true,
            },
            desktop,
        };
        guard.verify(spec)?;
        Ok(guard)
    }

    fn verify(&self, spec: &DedicatedWindow) -> io::Result<()> {
        if !self.lock.held
            || unsafe { GetCurrentThreadId() } != self.lock.owner_thread
        {
            return Err(denied());
        }
        require_desktop_name(self.desktop.0, &spec.desktop_name)?;
        self.hud.verify()
    }
}

impl DesktopLease {
    pub(super) fn acquire(spec: &DedicatedWindow) -> io::Result<Self> {
        let (commands, requests) = mpsc::channel();
        let (ready, result) = mpsc::sync_channel(1);
        let selected = spec.clone();
        // Monotonic deadline starts before spawn; no command can extend it.
        let expires = Instant::now() + LEASE_LIFETIME;
        let worker = thread::Builder::new()
            .name("agent-bridge-window-lease".to_owned())
            .spawn(move || {
                let acquired = HeldDesktopLease::acquire(&selected);
                let success = acquired.is_ok();
                if ready.send(success).is_err() {
                    return; // guard (if any) drops on its owning thread
                }
                let Ok(mut guard) = acquired else { return };
                loop {
                    let remaining = expires.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    match requests.recv_timeout(remaining.min(Duration::from_millis(250))) {
                        Ok(LeaseCommand::Verify(response)) => {
                            let valid = Instant::now() < expires
                                && guard.hud.pulse().is_ok()
                                && guard.verify(&selected).is_ok();
                            let _ = response.send(valid);
                            if !valid { break; }
                        }
                        Ok(LeaseCommand::Stop)
                        | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            if guard.hud.pulse().is_err() { break; }
                        }
                    }
                }
                // Explicit release on the owner thread, even without further
                // calls from the MCP client. Then CloseDesktop/CloseHandle.
                drop(guard);
            })?;
        if !matches!(result.recv_timeout(OWNER_READY_TIMEOUT), Ok(true))
            || Instant::now() >= expires
        {
            // The channel disconnects the worker. In case a Win32 call is
            // slow, never transfer ownership or wait forever for startup.
            drop(commands);
            drop(worker);
            return Err(denied());
        }
        Ok(Self { commands, worker: Some(worker), expires })
    }

    pub(super) fn is_expired(&self) -> bool {
        Instant::now() >= self.expires
            || self.worker.as_ref().is_none_or(thread::JoinHandle::is_finished)
    }

    pub(super) fn verify(&self, _: &DedicatedWindow) -> io::Result<()> {
        if self.is_expired() {
            return Err(denied());
        }
        let (response, result) = mpsc::sync_channel(1);
        self.commands.send(LeaseCommand::Verify(response)).map_err(|_| denied())?;
        if !matches!(result.recv_timeout(OWNER_VERIFY_TIMEOUT), Ok(true))
            || self.is_expired()
        {
            return Err(denied());
        }
        Ok(())
    }

    fn close(&mut self) -> io::Result<()> {
        let Some(worker) = self.worker.take() else { return Ok(()) };
        let _ = self.commands.send(LeaseCommand::Stop);
        // The worker only performs bounded Win32 checks and wait-for-command;
        // join confirms the mutex was released on its actual owner thread.
        worker.join().map_err(|_| denied())
    }

    pub(super) fn release(mut self) -> io::Result<()> {
        self.close()
    }
}

impl Drop for DesktopLease {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub(super) fn desktop_availability(spec: &DedicatedWindow) -> DesktopAvailability {
    let _desktop = match open_selected_desktop(spec) {
        Ok(desktop) => desktop,
        Err(_) => return DesktopAvailability::Unavailable,
    };
    let mutex = match named_desktop_mutex(spec) {
        Ok(mutex) => mutex,
        Err(_) => return DesktopAvailability::Unavailable,
    };
    match unsafe { WaitForSingleObject(mutex.0, 0) } {
        WAIT_OBJECT_0 => {
            if unsafe { ReleaseMutex(mutex.0) } != 0 {
                DesktopAvailability::Free
            } else {
                DesktopAvailability::Unavailable
            }
        }
        WAIT_TIMEOUT => DesktopAvailability::Occupied,
        WAIT_ABANDONED => {
            // Ownership was granted, but the previous owner died.
            unsafe { ReleaseMutex(mutex.0); }
            DesktopAvailability::Unavailable
        }
        _ => DesktopAvailability::Unavailable,
    }
}

/// The name is a single safe ASCII segment from the LOCAL CLI, in the
/// caller's own Windows session namespace. It is not controlled by MCP.
fn named_desktop_mutex(spec: &DedicatedWindow) -> io::Result<OwnedHandle> {
    let name = format!(
        "Local\\agent-bridge-window-read-v1-{}",
        spec.desktop_name.to_ascii_lowercase()
    );
    let wide: Vec<u16> = name.encode_utf16()
        .chain(std::iter::once(0)).collect();
    // SAFETY: a NUL-terminated local named mutex, without initial ownership.
    let handle = unsafe { CreateMutexW(ptr::null(), 0, wide.as_ptr()) };
    if handle == 0 { Err(denied()) } else { Ok(OwnedHandle(handle)) }
}

fn open_selected_desktop(spec: &DedicatedWindow) -> io::Result<OwnedDesktop> {
    let wide: Vec<u16> = spec.desktop_name.encode_utf16()
        .chain(std::iter::once(0)).collect();
    // SAFETY: no desktop creation/switching or handle inheritance, only
    // DESKTOP_READOBJECTS. This opens the EXACT desktop in our window station.
    let handle = unsafe { OpenDesktopW(wide.as_ptr(), 0, 0,
        DESKTOP_READOBJECTS | DESKTOP_ENUMERATE | DESKTOP_CREATEWINDOW) };
    if handle == 0 { return Err(denied()); }
    let desktop = OwnedDesktop(handle);
    require_desktop_name(desktop.0, &spec.desktop_name)?;
    Ok(desktop)
}

fn require_desktop_name(desktop: Handle, expected: &str) -> io::Result<()> {
    let actual = user_object_name(desktop)?;
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(denied());
    }
    Ok(())
}

#[link(name = "user32")]
extern "system" {
    fn MessageBoxW(owner: Hwnd, text: *const u16, caption: *const u16, flags: u32) -> i32;
    fn OpenDesktopW(name: *const u16, flags: u32, inherit: i32, access: u32) -> Handle;
    fn CloseDesktop(desktop: Handle) -> i32;
    fn GetForegroundWindow() -> Hwnd;
    fn IsWindow(hwnd: Hwnd) -> i32;
    fn IsWindowVisible(hwnd: Hwnd) -> i32;
    fn IsWindowEnabled(hwnd: Hwnd) -> i32;
    fn IsIconic(hwnd: Hwnd) -> i32;
    fn GetAncestor(hwnd: Hwnd, flags: u32) -> Hwnd;
    fn GetWindow(hwnd: Hwnd, command: u32) -> Hwnd;
    fn GetWindowThreadProcessId(hwnd: Hwnd, process_id: *mut u32) -> u32;
    fn EnumDesktopWindows(desktop: Handle,
        callback: Option<unsafe extern "system" fn(Hwnd, isize) -> i32>,
        state: isize) -> i32;
    fn GetUserObjectInformationW(
        handle: Handle, index: i32, information: *mut c_void, size: u32, needed: *mut u32,
    ) -> i32;
    fn GetWindowTextLengthW(hwnd: Hwnd) -> i32;
    fn GetWindowTextW(hwnd: Hwnd, title: *mut u16, maximum: i32) -> i32;
    fn GetClassNameW(hwnd: Hwnd, class_name: *mut u16, maximum: i32) -> i32;
    fn GetWindowRect(hwnd: Hwnd, rect: *mut Rect) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
    fn OpenThread(access: u32, inherit: i32, thread_id: u32) -> Handle;
    fn GetThreadTimes(
        thread: Handle, created: *mut FileTime, exited: *mut FileTime,
        kernel: *mut FileTime, user: *mut FileTime,
    ) -> i32;
    fn GetCurrentThreadId() -> u32;
    fn CreateMutexW(attributes: *const c_void, initial_owner: i32, name: *const u16) -> Handle;
    fn ReleaseMutex(mutex: Handle) -> i32;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn WaitForSingleObject(handle: Handle, timeout_ms: u32) -> u32;
    fn QueryFullProcessImageNameW(
        process: Handle, flags: u32, name: *mut u16, size: *mut u32,
    ) -> i32;
    fn GetProcessTimes(
        process: Handle, created: *mut FileTime, exited: *mut FileTime,
        kernel: *mut FileTime, user: *mut FileTime,
    ) -> i32;
    fn GetCurrentProcess() -> *mut c_void;
    fn ProcessIdToSessionId(process: u32, session: *mut u32) -> i32;
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
    fn GetTokenInformation(
        token: *mut c_void, information_class: i32, information: *mut c_void,
        length: u32, returned: *mut u32,
    ) -> i32;
    fn EqualSid(left: *mut c_void, right: *mut c_void) -> i32;
}

#[link(name = "ole32")]
extern "system" {
    fn CoCreateGuid(guid: *mut Guid) -> i32;
}

/// The displayed identity is the one observed locally immediately BEFORE
/// the dialogue; the exact HWND, process and thread incarnations are shown.
/// Nothing in the MCP request may set, choose or confirm these values.
pub(super) fn confirm_local_dialog(
    spec: &DedicatedWindow,
    identity: &Identity,
) -> io::Result<()> {
    const MB_YESNO: u32 = 0x0000_0004;
    const MB_ICONWARNING: u32 = 0x0000_0030;
    const MB_DEFBUTTON2: u32 = 0x0000_0100;
    const MB_TASKMODAL: u32 = 0x0000_2000;
    const IDYES: i32 = 6;
    let prompt = format!(
        "Allow MCP inspection and targeted actions on THIS work window?\n\n\
         Desktop: {}\nExecutable: {}\nClass: {}\nTitle: {}\n\n\
         HWND: {:#x}\nPID: {}\nTID: {}\n\
         Process incarnation (FILETIME): {}\n\
         Thread incarnation (FILETIME): {}\n\n\
         No other HWND, even with the same title, will be accepted.\n\
         After approval: control tree and PNG capture of this window only.\n\
         Buttons, scroll, and non-password Edit controls only; no global mouse or keyboard input.\n\n\
         No is selected by default.",
        identity.desktop, identity.image, identity.class_name, identity.title,
        identity.hwnd, identity.process_id, identity.thread_id,
        identity.process_created, identity.thread_created
    );
    // The exact approved app path is already verified by foreground(); keep
    // spec in the signature so the confirmation cannot lose its local scope.
    if !identity.desktop.eq_ignore_ascii_case(&spec.desktop_name) {
        return Err(denied());
    }
    let title: Vec<u16> = "Agent Bridge - Approve Specific Work Window".encode_utf16()
        .chain(std::iter::once(0)).collect();
    let message: Vec<u16> = prompt.encode_utf16()
        .chain(std::iter::once(0)).collect();
    // SAFETY: Both strings are NUL-terminated and live through MessageBoxW.
    // MB_DEFBUTTON2 selects No, and no owner or desktop is switched.
    if unsafe {
        MessageBoxW(0, message.as_ptr(), title.as_ptr(),
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_TASKMODAL)
    } != IDYES {
        return Err(denied());
    }
    Ok(())
}

// GetThreadDesktop can return ACCESS_DENIED for a foreign process. Instead
// prove HWND membership with a scoped native enumeration of the one desktop
// selected by the local operator (never enumerate the Default/user desktop).
fn selected_desktop_contains(spec: &DedicatedWindow, hwnd: Hwnd) -> io::Result<()> {
    struct Target { wanted: Hwnd, found: bool }
    unsafe extern "system" fn compare(candidate: Hwnd, context: isize) -> i32 {
        if context == 0 { return 0; }
        let target = unsafe { &mut *(context as *mut Target) };
        if candidate == target.wanted {
            target.found = true;
            return 0;
        }
        1
    }
    let wide: Vec<u16> = spec.desktop_name.encode_utf16()
        .chain(std::iter::once(0)).collect();
    let handle = unsafe {
        OpenDesktopW(wide.as_ptr(), 0, 0,
            DESKTOP_READOBJECTS | DESKTOP_ENUMERATE)
    };
    if handle == 0 { return Err(denied()); }
    let desktop = OwnedDesktop(handle);
    require_desktop_name(desktop.0, &spec.desktop_name)?;
    let mut target = Target { wanted: hwnd, found: false };
    // Callback stops early only when the exact top-level HWND is encountered.
    unsafe {
        EnumDesktopWindows(desktop.0, Some(compare),
            (&mut target as *mut Target) as isize);
    }
    if !target.found { return Err(denied()); }
    Ok(())
}

fn user_object_name(desktop: Handle) -> io::Result<String> {
    let mut size = 0u32;
    // SAFETY: Null probe obtains the required length. No window data is read.
    unsafe {
        GetUserObjectInformationW(desktop, UOI_NAME, ptr::null_mut(), 0, &mut size);
    }
    if !(4..=512).contains(&size) || size % 2 != 0 {
        return Err(denied());
    }
    let mut data = vec![0u16; size as usize / 2];
    let mut actual = 0u32;
    // SAFETY: buffer is size bytes, an exact UOI_NAME Unicode query.
    if unsafe {
        GetUserObjectInformationW(
            desktop, UOI_NAME, data.as_mut_ptr().cast(), size, &mut actual,
        )
    } == 0 {
        return Err(denied());
    }
    let end = data.iter().position(|unit| *unit == 0).ok_or_else(denied)?;
    String::from_utf16(&data[..end]).map_err(|_| denied())
}

fn token(process: Handle) -> io::Result<OwnedHandle> {
    let mut handle: *mut c_void = ptr::null_mut();
    // Only TOKEN_QUERY is requested; no write or privilege adjustment.
    if unsafe { OpenProcessToken(process as *mut c_void, TOKEN_QUERY, &mut handle) } == 0
        || handle.is_null()
    {
        return Err(denied());
    }
    Ok(OwnedHandle(handle as Handle))
}

fn token_information(token: Handle, kind: u32) -> io::Result<Vec<usize>> {
    let mut size = 0;
    unsafe { GetTokenInformation(token as *mut c_void, kind as i32, ptr::null_mut(), 0, &mut size); }
    if size < 4 || size > 8192 { return Err(denied()); }
    // Use pointer-aligned storage for TOKEN_USER's embedded SID pointer.
    let unit = size_of::<usize>();
    let mut data = vec![0usize; (size as usize + unit - 1) / unit];
    let mut actual = 0;
    if unsafe {
        GetTokenInformation(token as *mut c_void, kind as i32, data.as_mut_ptr().cast(), size, &mut actual)
    } == 0 || actual < 4 || actual > size {
        return Err(denied());
    }
    Ok(data)
}

fn require_same_user_not_elevated(process: Handle) -> io::Result<()> {
    let caller = token(unsafe { GetCurrentProcess() } as Handle)?;
    let target = token(process)?;

    // Refuse elevated targets (including a target owned by another user).
    let elevation = token_information(target.0, TOKEN_ELEVATION)?;
    if elevation.len() * size_of::<usize>() < 4
        || unsafe { ptr::read(elevation.as_ptr().cast::<u32>()) } != 0
    {
        return Err(denied());
    }

    let caller_user = token_information(caller.0, TOKEN_USER)?;
    let target_user = token_information(target.0, TOKEN_USER)?;
    if caller_user.len() * size_of::<usize>() < size_of::<SidAndAttributes>()
        || target_user.len() * size_of::<usize>() < size_of::<SidAndAttributes>()
    {
        return Err(denied());
    }
    // SAFETY: TOKEN_USER begins with SID_AND_ATTRIBUTES; the buffer is
    // pointer-aligned, and read_unaligned is conservative on both targets.
    let local = unsafe {
        ptr::read_unaligned(caller_user.as_ptr().cast::<SidAndAttributes>())
    };
    let remote = unsafe {
        ptr::read_unaligned(target_user.as_ptr().cast::<SidAndAttributes>())
    };
    if local.sid.is_null() || remote.sid.is_null()
        || unsafe { EqualSid(local.sid, remote.sid) } == 0
    {
        return Err(denied());
    }
    Ok(())
}

fn process_identity(pid: u32, spec: &DedicatedWindow) -> io::Result<ProcessPin> {
    if pid == 0 || pid == std::process::id() {
        return Err(denied());
    }
    let mut target_session = 0;
    let mut own_session = 0;
    if unsafe { ProcessIdToSessionId(pid, &mut target_session) } == 0
        || unsafe { ProcessIdToSessionId(std::process::id(), &mut own_session) } == 0
        || target_session != own_session
    {
        return Err(denied());
    }
    let handle = unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid)
    };
    if handle == 0 { return Err(denied()); }
    let handle = OwnedHandle(handle);
    if unsafe { WaitForSingleObject(handle.0, 0) } != WAIT_TIMEOUT {
        return Err(denied());
    }
    require_same_user_not_elevated(handle.0)?;
    let mut image = [0u16; 4096];
    let mut size = image.len() as u32;
    if unsafe {
        QueryFullProcessImageNameW(handle.0, 0, image.as_mut_ptr(), &mut size)
    } == 0 || size == 0 || size as usize >= image.len() {
        return Err(denied());
    }
    let path = String::from_utf16(&image[..size as usize]).map_err(|_| denied())?;
    let expected = spec.executable.to_str().ok_or_else(denied)?;
    if !path.eq_ignore_ascii_case(expected) {
        return Err(denied());
    }

    let (mut created, mut exited, mut kernel, mut user) =
        (FileTime::default(), FileTime::default(), FileTime::default(), FileTime::default());
    if unsafe {
        GetProcessTimes(handle.0, &mut created, &mut exited, &mut kernel, &mut user)
    } == 0 || created.as_u64() == 0 {
        return Err(denied());
    }
    if unsafe { WaitForSingleObject(handle.0, 0) } != WAIT_TIMEOUT {
        return Err(denied());
    }
    Ok(ProcessPin { handle, created: created.as_u64(), image: path })
}

/// A thread ID alone can be recycled. Pin the thread object while
/// observing and include its creation time in the immutable consent identity.
fn thread_identity(tid: u32) -> io::Result<ThreadPin> {
    if tid == 0 { return Err(denied()); }
    let handle = unsafe {
        OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, tid)
    };
    if handle == 0 { return Err(denied()); }
    let handle = OwnedHandle(handle);
    if unsafe { WaitForSingleObject(handle.0, 0) } != WAIT_TIMEOUT {
        return Err(denied());
    }
    let (mut created, mut exited, mut kernel, mut user) =
        (FileTime::default(), FileTime::default(), FileTime::default(), FileTime::default());
    if unsafe {
        GetThreadTimes(handle.0, &mut created, &mut exited, &mut kernel, &mut user)
    } == 0 || created.as_u64() == 0
    {
        return Err(denied());
    }
    if unsafe { WaitForSingleObject(handle.0, 0) } != WAIT_TIMEOUT {
        return Err(denied());
    }
    Ok(ThreadPin { handle, created: created.as_u64() })
}

fn caption(hwnd: Hwnd) -> io::Result<String> {
    let length = unsafe { GetWindowTextLengthW(hwnd) };
    if !(1..=255).contains(&length) { return Err(denied()); }
    let mut chars = [0u16; 256];
    // GetWindowTextW fetches only the TOP-LEVEL caption, not child control text.
    let read = unsafe { GetWindowTextW(hwnd, chars.as_mut_ptr(), chars.len() as i32) };
    if read <= 0 || read > 255 {
        return Err(denied());
    }
    String::from_utf16(&chars[..read as usize]).map_err(|_| denied())
}

fn window_class(hwnd: Hwnd) -> io::Result<String> {
    let mut chars = [0u16; 256];
    let read = unsafe { GetClassNameW(hwnd, chars.as_mut_ptr(), chars.len() as i32) };
    if read <= 0 || read >= 255 {
        return Err(denied());
    }
    String::from_utf16(&chars[..read as usize]).map_err(|_| denied())
}

/// Read ONLY GetForegroundWindow, and recheck the HWND, owner, thread, app,
/// desktop and exact window identity after reading. No EnumWindows and no
/// raw HWND is imported from the client or a previous observation.
pub(super) fn foreground(spec: &DedicatedWindow) -> io::Result<WindowObservation> {
    let hwnd = unsafe { GetForegroundWindow() };
    observe_window(spec, hwnd, true)
}

/// Recheck only the HWND that was physically observed before the local
/// consent dialog. The dialog itself may own the foreground temporarily.
/// This does not enumerate or accept any replacement from MCP.
pub(super) fn verify_selected_identity(spec: &DedicatedWindow, identity: &Identity)
    -> io::Result<()>
{
    let observed = observe_window(spec, identity.hwnd, false)?;
    if observed.identity != *identity { return Err(denied()); }
    Ok(())
}

fn observe_window(spec: &DedicatedWindow, hwnd: Hwnd, foreground_required: bool)
    -> io::Result<WindowObservation>
{
    if hwnd == 0
        || (foreground_required && unsafe { GetForegroundWindow() } != hwnd)
        || unsafe { IsWindow(hwnd) } == 0
        || unsafe { IsWindowVisible(hwnd) } == 0
        || unsafe { IsIconic(hwnd) } != 0
        || unsafe { GetAncestor(hwnd, GA_ROOT) } != hwnd
        || unsafe { GetWindow(hwnd, GW_OWNER) } != 0
    {
        return Err(denied());
    }
    let mut pid = 0;
    let thread = unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
    if thread == 0 || pid == 0 {
        return Err(denied());
    }
    // BEFORE reading any caption, ensure the target is on the exact
    // non-personal desktop chosen locally (not the "Default" desktop).
    selected_desktop_contains(spec, hwnd)?;
    let desktop = spec.desktop_name.clone();
    let process = process_identity(pid, spec)?;
    let thread_pin = thread_identity(thread)?;
    let class_name = window_class(hwnd)?;
    if class_name != spec.class_name {
        return Err(denied());
    }
    let title = caption(hwnd)?;
    if title != spec.title {
        return Err(denied());
    }
    let mut rect = Rect::default();
    if unsafe { GetWindowRect(hwnd, &mut rect) } == 0 {
        return Err(denied());
    }
    let width = i64::from(rect.right) - i64::from(rect.left);
    let height = i64::from(rect.bottom) - i64::from(rect.top);
    if !(32..=16384).contains(&width) || !(24..=16384).contains(&height) {
        return Err(denied());
    }
    let enabled = unsafe { IsWindowEnabled(hwnd) } != 0;

    // The handle is not pinned by Win32; fail closed on all observable
    // replacement/ownership drift, before returning *any* metadata.
    let mut final_pid = 0;
    let final_thread = unsafe { GetWindowThreadProcessId(hwnd, &mut final_pid) };
    if unsafe { IsWindow(hwnd) } == 0
        || (foreground_required && unsafe { GetForegroundWindow() } != hwnd)
        || final_pid != pid || final_thread != thread
        || unsafe { GetAncestor(hwnd, GA_ROOT) } != hwnd
        || unsafe { GetWindow(hwnd, GW_OWNER) } != 0
        || unsafe { IsWindowVisible(hwnd) } == 0
        || unsafe { IsIconic(hwnd) } != 0
        || selected_desktop_contains(spec, hwnd).is_err()
        || window_class(hwnd)? != class_name
        || caption(hwnd)? != title
        || unsafe { WaitForSingleObject(process.handle.0, 0) } != WAIT_TIMEOUT
        || unsafe { WaitForSingleObject(thread_pin.handle.0, 0) } != WAIT_TIMEOUT
    {
        return Err(denied());
    }
    Ok(WindowObservation {
        identity: Identity {
            hwnd, process_id: pid, thread_id: thread, process_created: process.created,
            thread_created: thread_pin.created, desktop, image: process.image, class_name, title,
        },
        x: rect.left,
        y: rect.top,
        width,
        height,
        enabled,
    })
}

pub(super) fn new_id() -> io::Result<String> {
    let mut id = Guid::default();
    if unsafe { CoCreateGuid(&mut id) } < 0 {
        return Err(denied());
    }
    Ok(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        id.a, id.b, id.c, id.d[0], id.d[1], id.d[2], id.d[3],
        id.d[4], id.d[5], id.d[6], id.d[7]
    ))
}