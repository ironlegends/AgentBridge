use std::{
    fs::{self, DirBuilder, Metadata, OpenOptions},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{fs::{DirBuilderExt, MetadataExt, OpenOptionsExt}},
    },
    path::Path,
    time::Duration,
};
use crate::{LifecycleError, Ready, Result};

fn uid() -> Result<u32> {
    let real = unsafe { libc::getuid() };
    let effective = unsafe { libc::geteuid() };
    if real == 0 || real != effective {
        return Err(LifecycleError::Uncertain("lifecycle requires a non-root local user"));
    }
    Ok(real)
}

pub(crate) fn create_private_directory(path: &Path) -> Result<()> {
    uid()?;
    let mut builder = DirBuilder::new();
    builder.mode(0o700).recursive(false);
    builder.create(path)?;
    verify_private_directory(path)
}
pub(crate) fn verify_private_directory(path: &Path) -> Result<()> {
    let owner = uid()?;
    let own = fs::symlink_metadata(path)?;
    if own.file_type().is_symlink() || !own.is_dir()
        || own.uid() != owner || own.mode() & 0o7777 != 0o700
    {
        return Err(LifecycleError::Uncertain("private directory is not mode 0700 / owner-only"));
    }
    for ancestor in path.parent().into_iter().flat_map(Path::ancestors) {
        let md = fs::symlink_metadata(ancestor)?;
        if !md.is_dir() || md.file_type().is_symlink()
            || (md.uid() != 0 && md.uid() != owner) || (md.mode() & 0o022) != 0
        {
            return Err(LifecycleError::Uncertain("unsafe Unix directory ancestor"));
        }
    }
    Ok(())
}
pub(crate) fn verify_private_file(_path: &Path, md: &Metadata) -> Result<()> {
    if md.uid() != uid()? || md.mode() & 0o7777 != 0o600 || md.nlink() != 1 {
        return Err(LifecycleError::Uncertain("private file is not regular 0600 / single-link"));
    }
    Ok(())
}
pub(crate) fn verify_private_handle(file: &std::fs::File, directory: bool) -> Result<()> {
    let m = file.metadata()?;
    let private = if directory { m.is_dir() && m.mode() & 0o7777 == 0o700 }
                  else { m.is_file() && m.nlink() == 1 && m.mode() & 0o7777 == 0o600 };
    if private && m.uid() == uid()? { Ok(()) } else { Err(LifecycleError::Uncertain("private handle permissions failed")) }
}
pub(crate) fn private_open_options(options: &mut OpenOptions) {
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
}
pub(crate) fn is_reparse(_md: &Metadata) -> bool { false }

#[cfg(target_os = "linux")]
fn proc_start(pid: u32) -> Result<u64> {
    let contents = fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| LifecycleError::Uncertain("process start identity unavailable"))?;
    let close = contents.rfind(')')
        .ok_or(LifecycleError::Uncertain("invalid process stat layout"))?;
    // Fields after the comm closing ')' begin with field 3 (state).
    // Field 22 (starttime, kernel clock ticks) is index 19 of that slice.
    contents[close + 1..].split_whitespace().nth(19)
        .ok_or(LifecycleError::Uncertain("missing process start time"))?
        .parse::<u64>()
        .map_err(|_| LifecycleError::Uncertain("invalid process start time"))
}

#[cfg(target_os = "linux")]
pub(crate) fn self_birth() -> Result<u64> {
    proc_start(std::process::id())
}

#[cfg(target_os = "linux")]
pub(crate) struct ProcessWitness(OwnedFd);

#[cfg(target_os = "linux")]
pub(crate) fn observe_process(ready: &Ready, expected: &Path) -> Result<ProcessWitness> {
    // pidfd_open captures an original kernel process incarnation; no kill(2),
    // signal, or procfs PID-only wait is used.
    let raw = unsafe {
        libc::syscall(libc::SYS_pidfd_open, ready.pid as libc::pid_t, 0) as libc::c_int
    };
    if raw < 0 {
        return Err(LifecycleError::Uncertain("Linux pidfd witness unavailable"));
    }
    let witness = ProcessWitness(unsafe { OwnedFd::from_raw_fd(raw) });
    let image = fs::read_link(format!("/proc/{}/exe", ready.pid))
        .map_err(|_| LifecycleError::Uncertain("process image unavailable"))?;
    if fs::canonicalize(&image)? != fs::canonicalize(expected)? ||
       proc_start(ready.pid)? != ready.birth
    {
        return Err(LifecycleError::Uncertain("original Linux incarnation mismatch"));
    }
    // Detect an already exited process before accepting new stop work.
    if wait_process_exit(&witness, Duration::ZERO)? {
        return Err(LifecycleError::Uncertain("original Linux process already exited"));
    }
    Ok(witness)
}

#[cfg(target_os = "linux")]
pub(crate) fn wait_process_exit(witness: &ProcessWitness, remaining: Duration) -> Result<bool> {
    let timeout = remaining.as_millis().min(i32::MAX as u128) as i32;
    let mut fd = libc::pollfd {
        fd: witness.0.as_raw_fd(), events: libc::POLLIN, revents: 0,
    };
    let n = unsafe { libc::poll(&mut fd, 1, timeout) };
    if n < 0 { return Err(LifecycleError::Uncertain("pidfd poll failed")); }
    if n == 0 { return Ok(false); }
    if fd.revents & libc::POLLIN != 0 { return Ok(true); }
    Err(LifecycleError::Uncertain("unexpected pidfd readiness"))
}

// macOS has no Linux pidfd. proc_pidinfo authenticates exact creation time
// and proc_pidpath the image; EVFILT_PROC NOTE_EXIT then watches that process.
// All three checks must succeed before any stop request is written.
#[cfg(target_os = "macos")]
mod mac {
    use super::*;
    use std::mem::{size_of, MaybeUninit};
    use std::path::PathBuf;
    use std::ptr;

    const PROC_PIDTBSDINFO: i32 = 3;
    const MAXCOMLEN: usize = 16;

    #[repr(C)]
    struct BsdInfo {
        pbi_flags: u32,
        pbi_status: u32,
        pbi_xstatus: u32,
        pbi_pid: u32,
        pbi_ppid: u32,
        pbi_uid: u32,
        pbi_gid: u32,
        pbi_ruid: u32,
        pbi_rgid: u32,
        pbi_svuid: u32,
        pbi_svgid: u32,
        rfu_1: u32,
        pbi_comm: [u8; MAXCOMLEN],
        pbi_name: [u8; MAXCOMLEN * 2],
        pbi_nfiles: u32,
        pbi_pgid: u32,
        pbi_pjobc: u32,
        e_tdev: u32,
        e_tpgid: u32,
        pbi_nice: i32,
        pbi_start_tvsec: u64,
        pbi_start_tvusec: u64,
    }

    #[link(name = "proc")]
    extern "C" {
        fn proc_pidinfo(pid: libc::c_int, flavor: libc::c_int, arg: u64,
                        buffer: *mut libc::c_void, buffersize: libc::c_int) -> libc::c_int;
        fn proc_pidpath(pid: libc::c_int, buffer: *mut libc::c_void,
                        buffersize: u32) -> libc::c_int;
    }

    pub(crate) fn birth(pid: u32) -> Result<u64> {
        let mut data = MaybeUninit::<BsdInfo>::zeroed();
        let n = unsafe {
            proc_pidinfo(pid as i32, PROC_PIDTBSDINFO, 0,
                data.as_mut_ptr().cast(), size_of::<BsdInfo>() as i32)
        };
        if n != size_of::<BsdInfo>() as i32 {
            return Err(LifecycleError::Uncertain("macOS process creation record unavailable"));
        }
        let info = unsafe { data.assume_init() };
        if info.pbi_pid != pid || info.pbi_uid != uid()? {
            return Err(LifecycleError::Uncertain("macOS process UID/PID mismatch"));
        }
        info.pbi_start_tvsec.checked_mul(1_000_000)
            .and_then(|n| n.checked_add(info.pbi_start_tvusec))
            .ok_or(LifecycleError::Uncertain("macOS creation timestamp overflow"))
    }

    pub(crate) fn image(pid: u32) -> Result<PathBuf> {
        let mut buffer = [0u8; 4096];
        let n = unsafe {
            proc_pidpath(pid as i32, buffer.as_mut_ptr().cast(), buffer.len() as u32)
        };
        if n <= 0 || n as usize > buffer.len() {
            return Err(LifecycleError::Uncertain("macOS executable path unavailable"));
        }
        let bytes = &buffer[..n as usize];
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Ok(PathBuf::from(std::str::from_utf8(&bytes[..end])
            .map_err(|_| LifecycleError::Uncertain("invalid macOS process image"))?))
    }

    pub(crate) struct ProcessWitness(pub(super) OwnedFd);

    pub(crate) fn observe(ready: &Ready, expected: &Path) -> Result<ProcessWitness> {
        // Register first, then verify birth/image. A pre-existing or reused
        // PID cannot acquire a valid witness without matching the start time.
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return Err(LifecycleError::Uncertain("macOS kqueue unavailable"));
        }
        let witness = ProcessWitness(unsafe { OwnedFd::from_raw_fd(fd) });
        let event = libc::kevent {
            ident: ready.pid as libc::uintptr_t,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: ptr::null_mut(),
        };
        if unsafe { libc::kevent(fd, &event, 1, ptr::null_mut(), 0, ptr::null()) } != 0 {
            return Err(LifecycleError::Uncertain("macOS process exit watch refused"));
        }
        if birth(ready.pid)? != ready.birth
            || fs::canonicalize(image(ready.pid)?)? != fs::canonicalize(expected)?
        {
            return Err(LifecycleError::Uncertain("macOS incarnation mismatch"));
        }
        Ok(witness)
    }

    pub(crate) fn wait_exit(witness: &ProcessWitness, remaining: Duration) -> Result<bool> {
        let limit = libc::timespec {
            tv_sec: remaining.as_secs().min(libc::time_t::MAX as u64) as libc::time_t,
            tv_nsec: remaining.subsec_nanos() as libc::c_long,
        };
        let mut event = MaybeUninit::<libc::kevent>::zeroed();
        let rc = unsafe {
            libc::kevent(witness.0.as_raw_fd(), ptr::null(), 0,
                          event.as_mut_ptr(), 1, &limit)
        };
        if rc == 0 { return Ok(false); }
        if rc != 1 { return Err(LifecycleError::Uncertain("macOS exit witness failed")); }
        let got = unsafe { event.assume_init() };
        if got.filter == libc::EVFILT_PROC && got.fflags & libc::NOTE_EXIT != 0 {
            Ok(true)
        } else {
            Err(LifecycleError::Uncertain("unexpected macOS process event"))
        }
    }
}
#[cfg(target_os = "macos")]
pub(super) use mac::ProcessWitness;
#[cfg(target_os = "macos")]
pub(crate) fn self_birth() -> Result<u64> { mac::birth(std::process::id()) }
#[cfg(target_os = "macos")]
pub(crate) fn observe_process(ready: &Ready, expected: &Path) -> Result<ProcessWitness> {
    mac::observe(ready, expected)
}
#[cfg(target_os = "macos")]
pub(crate) fn wait_process_exit(witness: &ProcessWitness, remaining: Duration) -> Result<bool> {
    mac::wait_exit(witness, remaining)
}

// Other Unix platforms fail closed until a native incarnation witness exists.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) struct ProcessWitness;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn self_birth() -> Result<u64> {
    Err(LifecycleError::Uncertain("unsupported Unix process witness"))
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn observe_process(_ready: &Ready, _expected: &Path) -> Result<ProcessWitness> {
    Err(LifecycleError::Uncertain("unsupported Unix process witness"))
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn wait_process_exit(_witness: &ProcessWitness, _remaining: Duration) -> Result<bool> {
    Err(LifecycleError::Uncertain("unsupported Unix process witness"))
}
