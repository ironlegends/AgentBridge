//! Own a process group while retaining the unreaped leader's identity.
use super::LaunchSpec;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

pub(super) struct Process {
    child: Child,
    group: libc::pid_t,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
    stderr: ChildStderr,
    exit: Option<Option<i32>>,
    // A group signal was attempted; finish() must still prove it disappeared.
    terminated: bool,
    reaped: bool,
}

fn nonblocking(pipe: &impl AsRawFd) -> io::Result<()> {
    let descriptor = pipe.as_raw_fd();
    // SAFETY: this live owned pipe descriptor is never closed concurrently.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 { return Err(io::Error::last_os_error()); }
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn reap_fallback(child: &mut Child) {
    // Drop cannot report an OS termination failure. Avoid an unbounded wait
    // in an error path; normal shutdown verifies finish() and reports failure.
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) if Instant::now() >= deadline => return,
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

impl Process {
    pub(super) fn spawn(spec: &LaunchSpec) -> io::Result<Self> {
        let mut command = Command::new(&spec.program);
        command.args(&spec.arguments);
        if let Some(command_line) = &spec.cmd_command {
            command.args(["/D", "/S", "/C", command_line]);
        }
        command.current_dir(&spec.cwd).stdin(Stdio::piped()).stdout(Stdio::piped())
            .stderr(Stdio::piped()).process_group(0);
        let mut child = command.spawn()?;
        let group = child.id() as libc::pid_t;
        let setup = (|| {
            let stdin = child.stdin.take().ok_or_else(|| io::Error::other("Owned stdin missing"))?;
            let stdout = child.stdout.take().ok_or_else(|| io::Error::other("Owned stdout missing"))?;
            let stderr = child.stderr.take().ok_or_else(|| io::Error::other("Owned stderr missing"))?;
            nonblocking(&stdin)?;
            nonblocking(&stdout)?;
            nonblocking(&stderr)?;
            Ok::<_, io::Error>((stdin, stdout, stderr))
        })();
        match setup {
            Ok((stdin, stdout, stderr)) => Ok(Self {
                child, group, stdin: Some(stdin), stdout, stderr,
                exit: None, terminated: false, reaped: false,
            }),
            Err(error) => {
                // The leader has not been reaped, so its group id cannot
                // name an unrelated process group even if it exited early.
                unsafe { libc::kill(-group, libc::SIGKILL); }
                reap_fallback(&mut child);
                Err(error)
            },
        }
    }

    pub(super) fn read_stdout(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stdout.read(bytes)
    }
    pub(super) fn read_stderr(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stderr.read(bytes)
    }
    pub(super) fn write_stdin(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let pipe = self.stdin.as_mut().ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "Owned stdin closed"))?;
        match pipe.write(bytes) {
            Ok(0) if !bytes.is_empty() => Err(io::ErrorKind::WouldBlock.into()),
            result => result,
        }
    }
    pub(super) fn close_stdin(&mut self) { self.stdin.take(); }

    pub(super) fn try_exit(&mut self) -> io::Result<Option<Option<i32>>> {
        if self.exit.is_some() { return Ok(self.exit); }
        // WNOWAIT deliberately retains the leader's identity until group
        // termination is requested. try_wait() here would permit PID/PGID
        // reuse before the signal and could target an unrelated group.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe { libc::waitid(libc::P_PID, self.group as libc::id_t,
            &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted { return Ok(None); }
            return Err(error);
        }
        if unsafe { info.si_pid() } == 0 { return Ok(None); }
        let code = if info.si_code == libc::CLD_EXITED { Some(unsafe { info.si_status() }) } else { None };
        self.exit = Some(code);
        Ok(self.exit)
    }

    pub(super) fn terminate(&mut self) -> io::Result<()> {
        if self.terminated || self.reaped { return Ok(()); }
        self.close_stdin();
        // Only the fresh group created with our still-unreaped child is
        // targeted. No PID or process-group identifier comes from a caller.
        if unsafe { libc::kill(-self.group, libc::SIGKILL) } != 0 {
            let error = io::Error::last_os_error();
            let can_reap = match error.raw_os_error() {
                Some(libc::ESRCH) => true,
                // Darwin excludes zombies from group signals and reports
                // EPERM when no live member was signalled. Reap only after
                // proving our leader exited; finish() must still observe
                // ESRCH, so a live, unsignalable descendant cannot be hidden.
                #[cfg(target_os = "macos")]
                Some(libc::EPERM) => self.try_exit()?.is_some(),
                _ => false,
            };
            if !can_reap { return Err(error); }
        }
        self.terminated = true;
        Ok(())
    }

    pub(super) fn finish(&mut self) -> io::Result<Option<Option<i32>>> {
        if !self.terminated { return Ok(None); }
        if !self.reaped {
            if self.try_exit()?.is_none() { return Ok(None); }
            let Some(status) = self.child.try_wait()? else { return Ok(None); };
            self.reaped = true;
            self.exit.get_or_insert(status.code());
        }
        // Signal 0 only observes the formerly owned group after reaping. A
        // rare PGID reuse can delay/refuse cleanup, but is never signalled.
        // This also waits for descendants that redirected their stdio.
        if unsafe { libc::kill(-self.group, 0) } == 0 { return Ok(None); }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(self.exit),
            // Darwin also reports EPERM for a group containing only zombie
            // descendants. Keep waiting for their reaping, without signalling
            // a group whose leader we reaped. A persistent group times out.
            #[cfg(target_os = "macos")]
            Some(libc::EPERM) => Ok(None),
            _ => Err(error),
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.reaped { return; }
        // Cleanup fallback for thread-creation or pipe-initialization errors.
        // Keep the identity until the group signal, then reap our own child.
        let _ = self.terminate();
        reap_fallback(&mut self.child);
        self.reaped = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exited_group_leader_is_reaped_without_hiding_the_exit_code() {
        let spec = LaunchSpec {
            program: "/bin/sh".into(),
            arguments: vec!["-c".into(), "exit 7".into()],
            cwd: std::env::temp_dir(),
            cmd_command: None,
        };
        let mut process = Process::spawn(&spec).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(code) = process.try_exit().unwrap() {
                assert_eq!(code, Some(7));
                break;
            }
            assert!(Instant::now() < deadline, "group leader did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
        // Force the ordering that exposed Darwin's zombie-only group error:
        // the root is already exited and retained by WNOWAIT before SIGKILL.
        process.terminate().unwrap();
        loop {
            if let Some(code) = process.finish().unwrap() {
                assert_eq!(code, Some(7));
                break;
            }
            assert!(Instant::now() < deadline, "exited group was not reaped");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
