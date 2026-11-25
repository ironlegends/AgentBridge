//! Direct automation children with verified process-tree cleanup.
//!
//! Resource pins and profile admission belong to the provider before spawn.
//! One owner/thread pumps the nonblocking pipes. WouldBlock means retry later;
//! partial stdin writes must not be discarded. A timeout is not cleanup:
//! terminate, drain, poll finish and retain the owner until finish succeeds.
//! Drop enforces kill-on-close as a fallback, not a verified completion receipt.
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
#[cfg(windows)]
use std::path::Path;

#[cfg(windows)]
#[path = "owned_children/windows.rs"]
mod platform;
#[cfg(windows)]
pub(crate) use platform::quote_argument;

pub(crate) struct ChildSpec {
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub cwd: PathBuf,
    /// Case-insensitive Windows names; None removes a variable in this child.
    pub env_overrides: BTreeMap<OsString, Option<OsString>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChildExit { pub code: Option<i32> }

pub(crate) struct OwnedChild { process: platform::Process }

impl OwnedChild {
    pub(crate) fn spawn(spec: &ChildSpec) -> io::Result<Self> {
        Ok(Self { process: platform::Process::spawn(spec)? })
    }

    // The terminal alone resolves PATH/cwd and preserves cmd.exe's raw /C tail.
    // It reaches the same Job/pipe owner; provider ChildSpec never takes a shell.
    #[cfg(windows)]
    pub(crate) fn spawn_terminal(
        executable: &Path, command: &mut [u16], cwd: &Path,
    ) -> io::Result<Self> {
        Ok(Self { process: platform::Process::spawn_prepared(executable, command, cwd, None, false)? })
    }

    #[cfg(windows)]
    pub(crate) fn spawn_terminal_configured(
        executable: &Path, command: &mut [u16], cwd: &Path,
        environment: &BTreeMap<OsString, Option<OsString>>, visible_console: bool,
    ) -> io::Result<Self> {
        let mut block = platform::environment_block(environment)?;
        let process = platform::Process::spawn_prepared(
            executable, command, cwd, block.as_deref_mut(), visible_console,
        )?;
        Ok(Self { process })
    }

    pub(crate) fn root_pid(&self) -> u32 { self.process.root_pid() }
    /// A live membership check, not an enduring capability for a caller PID.
    pub(crate) fn owns_process(&self, pid: u32) -> io::Result<bool> {
        self.process.owns_process(pid)
    }
    pub(crate) fn read_stdout(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.process.read_stdout(buf)
    }
    pub(crate) fn read_stderr(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.process.read_stderr(buf)
    }
    pub(crate) fn write_stdin(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.process.write_stdin(buf)
    }
    pub(crate) fn close_stdin(&mut self) { self.process.close_stdin(); }
    pub(crate) fn try_exit(&mut self) -> io::Result<Option<ChildExit>> {
        self.process.try_exit().map(|exit| exit.map(|code| ChildExit { code }))
    }
    pub(crate) fn terminate(&mut self) -> io::Result<()> { self.process.terminate() }
    pub(crate) fn finish(&mut self) -> io::Result<Option<ChildExit>> {
        self.process.finish().map(|exit| exit.map(|code| ChildExit { code }))
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    pub(super) struct Process;
    fn unsupported<T>() -> io::Result<T> {
        Err(io::Error::new(io::ErrorKind::Unsupported,
            "Owned automation providers require Windows"))
    }
    impl Process {
        pub(super) fn spawn(_: &ChildSpec) -> io::Result<Self> { unsupported() }
        pub(super) fn root_pid(&self) -> u32 { 0 }
        pub(super) fn owns_process(&self, _: u32) -> io::Result<bool> { unsupported() }
        pub(super) fn read_stdout(&mut self, _: &mut [u8]) -> io::Result<usize> { unsupported() }
        pub(super) fn read_stderr(&mut self, _: &mut [u8]) -> io::Result<usize> { unsupported() }
        pub(super) fn write_stdin(&mut self, _: &[u8]) -> io::Result<usize> { unsupported() }
        pub(super) fn close_stdin(&mut self) {}
        pub(super) fn try_exit(&mut self) -> io::Result<Option<Option<i32>>> { unsupported() }
        pub(super) fn terminate(&mut self) -> io::Result<()> { unsupported() }
        pub(super) fn finish(&mut self) -> io::Result<Option<Option<i32>>> { unsupported() }
    }
}

#[cfg(all(test, windows))]
mod tests;