//! Private Chromium pipes on Linux/glibc and macOS. Chrome reads FD 3 and
//! writes FD 4; neither pipe is stdio and no debugger socket is opened.
//! posix_spawn file actions avoid pre_exec allocation and collisions with
//! std::Command's internal exec-error pipe. No executable comes from MCP.
use std::collections::BTreeMap;
use std::ffi::{CStr, CString, OsString};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

fn checked(result: libc::c_int) -> io::Result<()> {
    if result == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(result)) }
}

fn create_pipe() -> io::Result<(File, File)> {
    let mut ends = [-1; 2];
    #[cfg(target_os = "linux")]
    let result = unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) };
    #[cfg(not(target_os = "linux"))]
    let result = unsafe { libc::pipe(ends.as_mut_ptr()) };
    if result != 0 { return Err(io::Error::last_os_error()); }
    // Own both ends before any fallible operation, including Darwin's
    // CLOEXEC setup (Darwin has no pipe2). Child inheritance is separately
    // restricted by POSIX_SPAWN_CLOEXEC_DEFAULT below.
    let input = unsafe { File::from_raw_fd(ends[0]) };
    let output = unsafe { File::from_raw_fd(ends[1]) };
    for file in [&input, &output] {
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok((input, output))
}

fn duplicate_source(source: RawFd) -> io::Result<OwnedFd> {
    // Reserve outside 0..=4 before adding ANY remap. This also handles a
    // source already at its target (dup2(fd,fd) would retain CLOEXEC) and
    // crossed sources, e.g. read=4/write=3. Never modify parent descriptors.
    let fd = unsafe { libc::fcntl(source, libc::F_DUPFD_CLOEXEC, 5) };
    if fd < 0 { return Err(io::Error::last_os_error()); }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

struct Actions(libc::posix_spawn_file_actions_t);
impl Actions {
    fn new() -> io::Result<Self> {
        let mut value = std::mem::MaybeUninit::uninit();
        checked(unsafe { libc::posix_spawn_file_actions_init(value.as_mut_ptr()) })?;
        Ok(Self(unsafe { value.assume_init() }))
    }
}
impl Drop for Actions {
    fn drop(&mut self) { unsafe { libc::posix_spawn_file_actions_destroy(&mut self.0); } }
}
struct Attributes(libc::posix_spawnattr_t);
impl Attributes {
    fn new() -> io::Result<Self> {
        let mut value = std::mem::MaybeUninit::uninit();
        checked(unsafe { libc::posix_spawnattr_init(value.as_mut_ptr()) })?;
        Ok(Self(unsafe { value.assume_init() }))
    }
}
impl Drop for Attributes {
    fn drop(&mut self) { unsafe { libc::posix_spawnattr_destroy(&mut self.0); } }
}

fn fd_action(actions: &mut Actions, symbol: &CStr, descriptor: RawFd) -> io::Result<()> {
    // GLIBC_2.29/2.34 extensions must not raise the minimum libc version of
    // the entire CLI. Resolve in the parent; missing support refuses only
    // this browser operation, with no weaker inheritance fallback.
    let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr()) };
    if address.is_null() { return Err(io::ErrorKind::Unsupported.into()); }
    type Action = unsafe extern "C" fn(*mut libc::posix_spawn_file_actions_t, libc::c_int) -> libc::c_int;
    // Both fixed symbol names below have this exact POSIX extension ABI.
    let action: Action = unsafe { std::mem::transmute(address) };
    checked(unsafe { action(&mut actions.0, descriptor) })
}

fn cstring(value: &std::ffi::OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| io::ErrorKind::InvalidInput.into())
}

/// All sources stay owned until posix_spawn returns. All child remaps are
/// based on private CLOEXEC duplicates above FD 4, then every unrelated FD
/// is closed. The parent's descriptor table and working directory are intact.
fn spawn_process(
    executable: &Path, cwd: &Path, arguments: &[OsString],
    extra_environment: &[(OsString, OsString)], mappings: &[(RawFd, RawFd)],
) -> io::Result<ChildProcess> {
    spawn_process_inner(executable, cwd, arguments, extra_environment, mappings,
        #[cfg(test)] None)
}

fn spawn_process_inner(
    executable: &Path, cwd: &Path, arguments: &[OsString],
    extra_environment: &[(OsString, OsString)], mappings: &[(RawFd, RawFd)],
    #[cfg(test)] diagnostic_stderr: Option<&File>,
) -> io::Result<ChildProcess> {
    if !executable.is_absolute() || !cwd.is_absolute()
        || !(mappings.is_empty()
            || (mappings.len() == 1 && mappings[0].1 == 1)
            || (mappings.len() == 2 && mappings.iter().any(|(_, fd)| *fd == 3)
                && mappings.iter().any(|(_, fd)| *fd == 4)))
        || mappings.iter().any(|(_, target)| !matches!(*target, 1 | 3 | 4))
        || mappings.iter().enumerate().any(|(i, (_, target))|
            mappings[..i].iter().any(|(_, other)| other == target))
    { return Err(io::ErrorKind::InvalidInput.into()); }
    #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
    return Err(io::ErrorKind::Unsupported.into());

    #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
    {
        let sources = mappings.iter().map(|(source, target)|
            duplicate_source(*source).map(|fd| (fd, *target)))
            .collect::<io::Result<Vec<_>>>()?;
        #[cfg(test)]
        let stderr_source = diagnostic_stderr.map(|file| duplicate_source(file.as_raw_fd())).transpose()?;
        let directory = OpenOptions::new().read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(cwd)?;
        let executable = cstring(executable.as_os_str())?;
        let mut args = vec![executable.clone()];
        args.extend(arguments.iter().map(|a| cstring(a)).collect::<io::Result<Vec<_>>>()?);
        let mut argv = args.iter().map(|a| a.as_ptr() as *mut libc::c_char).collect::<Vec<_>>();
        argv.push(std::ptr::null_mut());
        let mut environment = std::env::vars_os().filter(|(key, _)| {
            let key = key.as_bytes();
            !key.starts_with(b"CHROME_") && !key.starts_with(b"DYLD_")
                && key != b"LD_PRELOAD" && key != b"LD_LIBRARY_PATH"
        }).collect::<BTreeMap<_, _>>();
        environment.extend(extra_environment.iter().cloned());
        let environment = environment.into_iter().map(|(mut key, value)| {
            key.push("="); key.push(value); cstring(&key)
        }).collect::<io::Result<Vec<_>>>()?;
        let mut envp = environment.iter().map(|a| a.as_ptr() as *mut libc::c_char).collect::<Vec<_>>();
        envp.push(std::ptr::null_mut());
        let mut actions = Actions::new()?;
        fd_action(&mut actions, c"posix_spawn_file_actions_addfchdir_np", directory.as_raw_fd())?;
        for (fd, flags) in [(0, libc::O_RDONLY), (1, libc::O_WRONLY), (2, libc::O_WRONLY)] {
            checked(unsafe { libc::posix_spawn_file_actions_addopen(
                &mut actions.0, fd, c"/dev/null".as_ptr(), flags, 0) })?;
        }
        #[cfg(test)]
        if let Some(source) = &stderr_source {
            checked(unsafe { libc::posix_spawn_file_actions_adddup2(
                &mut actions.0, source.as_raw_fd(), 2) })?;
        }
        for (source, target) in &sources {
            checked(unsafe { libc::posix_spawn_file_actions_adddup2(
                &mut actions.0, source.as_raw_fd(), *target) })?;
        }
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        fd_action(&mut actions, c"posix_spawn_file_actions_addclosefrom_np",
            if mappings.len() == 2 { 5 } else { 3 })?;
        let mut attributes = Attributes::new()?;
        let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        let mut defaults: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut mask);
            libc::sigemptyset(&mut defaults);
            libc::sigaddset(&mut defaults, libc::SIGPIPE);
        }
        checked(unsafe { libc::posix_spawnattr_setsigmask(&mut attributes.0, &mask) })?;
        checked(unsafe { libc::posix_spawnattr_setsigdefault(&mut attributes.0, &defaults) })?;
        checked(unsafe { libc::posix_spawnattr_setpgroup(&mut attributes.0, 0) })?;
        let flags = libc::POSIX_SPAWN_SETPGROUP | libc::POSIX_SPAWN_SETSIGMASK
            | libc::POSIX_SPAWN_SETSIGDEF;
        #[cfg(target_os = "macos")]
        let flags = flags | libc::POSIX_SPAWN_CLOEXEC_DEFAULT;
        checked(unsafe { libc::posix_spawnattr_setflags(&mut attributes.0, flags as libc::c_short) })?;
        let mut pid = 0;
        checked(unsafe { libc::posix_spawn(&mut pid, executable.as_ptr(),
            &actions.0, &attributes.0, argv.as_ptr(), envp.as_ptr()) })?;
        Ok(ChildProcess { pid, reaped: false, terminated: false, finished: false, exit_code: None,
            #[cfg(test)] diagnostics: None })
    }
}

/// Retain the unreaped leader's identity until the last nonzero group signal.
/// This owns the new process group, not processes that deliberately leave it.
pub(super) struct ChildProcess {
    pid: libc::pid_t,
    reaped: bool,
    terminated: bool,
    finished: bool,
    exit_code: Option<i32>,
    #[cfg(test)]
    diagnostics: Option<test_diagnostics::Capture>,
}

fn signal_group(pid: libc::pid_t, signal: libc::c_int) -> io::Result<()> {
    if unsafe { libc::kill(-pid, signal) } == 0 { Ok(()) }
    else { Err(io::Error::last_os_error()) }
}

impl ChildProcess {
    fn observe_exit(&self) -> io::Result<bool> {
        if self.reaped { return Ok(true); }
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        if unsafe { libc::waitid(libc::P_PID, self.pid as libc::id_t, &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { info.si_pid() } == self.pid)
    }

    fn exited(&self) -> io::Result<bool> {
        match self.observe_exit() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(false),
            result => result,
        }
    }

    pub(super) fn finish(&mut self, timeout: Duration) -> io::Result<()> {
        self.finish_with_signal(timeout, cfg!(target_os = "macos"), signal_group)
    }

    fn finish_with_signal(
        &mut self, timeout: Duration, darwin_exit_transition: bool,
        mut signal: impl FnMut(libc::pid_t, libc::c_int) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.finished { return Ok(()); }
        // One budget covers the signal phase as well as reap/group removal.
        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() >= deadline { return Err(io::ErrorKind::TimedOut.into()); }
            if !self.terminated && !self.reaped {
                // A successful WNOWAIT probe retains our unreaped leader.
                // EINTR is not proof of ownership; ECHILD refuses signaling.
                let owned = match self.observe_exit() {
                    Ok(_) => true,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => false,
                    Err(error) => return Err(error),
                };
                if owned {
                    match signal(self.pid, libc::SIGKILL) {
                        Ok(()) => self.terminated = true,
                        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
                            self.terminated = true;
                        }
                        Err(error) if darwin_exit_transition
                            && error.raw_os_error() == Some(libc::EPERM) => {
                            // XNU removes P_REF_DEAD from proc_find before
                            // setting SZOMB: killpg can return EPERM while
                            // WNOWAIT still reports no exit. Retain the leader
                            // and retry only within this same deadline.
                            // See Apple XNU f6217f8 kern_exit.c:2126/2661 and
                            // kern_sig.c:1702-1718. EPERM alone is no proof.
                            self.terminated = self.exited()?;
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
            if self.terminated && !self.reaped && self.exited()? {
                let mut status = 0;
                let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
                if result == self.pid {
                    self.reaped = true;
                    if libc::WIFEXITED(status) { self.exit_code = Some(libc::WEXITSTATUS(status)); }
                } else if result < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::Interrupted { return Err(error); }
                }
            }
            if self.reaped {
                // No nonzero group signal is allowed after the leader was
                // reaped. Only ESRCH proves cleanup; EPERM never does.
                match signal(self.pid, 0) {
                    Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
                        self.finished = true;
                        return Ok(());
                    }
                    Err(error) if darwin_exit_transition
                        && error.raw_os_error() == Some(libc::EPERM) => {}
                    Err(error) => return Err(error),
                    Ok(()) => {}
                }
            }
            std::thread::sleep(Duration::from_millis(10)
                .min(deadline.saturating_duration_since(Instant::now())));
        }
    }
}
impl Drop for ChildProcess {
    fn drop(&mut self) { let _ = self.finish(Duration::from_millis(500)); }
}

fn chrome_arguments(profile: &Path) -> Vec<OsString> {
    let mut profile_argument = OsString::from("--user-data-dir=");
    profile_argument.push(profile);
    let mut arguments = [
        "--headless=new", "--no-first-run", "--no-default-browser-check",
        "--disable-background-networking", "--disable-extensions",
        "--disable-default-apps", "--disable-component-update", "--disable-sync",
        "--disable-crash-reporter", "--disable-breakpad", "--no-proxy-server",
        "--disable-features=MediaRouter,OptimizationHints",
    ].into_iter().map(OsString::from).collect::<Vec<_>>();
    arguments.push(profile_argument);
    arguments
}

pub(super) fn launch(executable: &Path, cwd: &Path, profile: &Path)
    -> io::Result<(ChildProcess, File, File)>
{
    let (child_read, parent_write) = create_pipe()?;
    let (parent_read, child_write) = create_pipe()?;
    let mut arguments = chrome_arguments(profile);
    arguments.extend(["--remote-debugging-pipe".into(), "about:blank".into()]);
    let mappings = [(child_read.as_raw_fd(), 3), (child_write.as_raw_fd(), 4)];
    #[cfg(test)]
    let child = test_diagnostics::spawn(executable, cwd, &arguments, &[], &mappings)?;
    #[cfg(not(test))]
    let child = spawn_process(executable, cwd, &arguments, &[], &mappings)?;
    Ok((child, parent_write, parent_read))
}

pub(super) fn dump_dom(executable: &Path, profile: &Path, url: &str) -> io::Result<String> {
    let (output, child_output) = create_pipe()?;
    let mut arguments = chrome_arguments(profile);
    arguments.extend(["--dump-dom".into(), "--incognito".into(), "--disable-images".into(), url.into()]);
    let cwd = profile.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let mappings = [(child_output.as_raw_fd(), 1)];
    #[cfg(test)]
    let child = test_diagnostics::spawn(executable, cwd, &arguments, &[], &mappings)?;
    #[cfg(not(test))]
    let child = spawn_process(executable, cwd, &arguments, &[], &mappings)?;
    let mut child = child;
    drop(child_output);
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || { let _ = sender.send(super::super::read_bounded(output)); });
    let deadline = Instant::now() + super::super::CHROME_TIMEOUT;
    while !child.exited()? {
        if Instant::now() >= deadline { return Err(io::ErrorKind::TimedOut.into()); }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    child.finish(super::super::READ_WAIT)?;
    let output = output.map_err(|_| io::ErrorKind::TimedOut)??;
    if child.exit_code != Some(0) || output.is_empty() { return Err(super::fail()); }
    String::from_utf8(output).map_err(|_| io::ErrorKind::InvalidData.into())
}

#[cfg(test)]
#[path = "chrome_cdp_test_diagnostics.rs"]
mod test_diagnostics;

#[cfg(test)]
#[path = "chrome_cdp_unix_tests.rs"]
mod tests;
