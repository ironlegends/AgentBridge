//! Process containment for operator-approved stdio extension servers.
//!
//! The extensions crate decides policy (executable pin, exact environment,
//! timeouts); this module only starts and owns the child. Windows reuses the
//! owned-children Job owner: Job assignment at creation, kill-on-close, a
//! restricted inherited-handle list, CREATE_NO_WINDOW and the authenticated
//! stdin pipe. Unix owns a fresh process group and signals only that group
//! while its unreaped leader still pins the group identifier. No shell is
//! ever involved and the environment is never inherited.
use agent_bridge_extensions::stdio::{StdioChild, StdioLaunch, StdioLauncher};
use std::io;

/// The production launcher attached to every registry the CLI reads.
pub(crate) struct ContainedLauncher;

impl StdioLauncher for ContainedLauncher {
    fn launch(&self, launch: &StdioLaunch) -> io::Result<Box<dyn StdioChild>> {
        Ok(Box::new(spawn_contained(launch)?))
    }
}

/// Starts one contained child. Each call creates a new owner.
pub(crate) fn spawn_contained(launch: &StdioLaunch) -> io::Result<platform::Contained> {
    platform::spawn(launch)
}

#[cfg(windows)]
mod platform {
    use super::*;
    use crate::owned_children::OwnedChild;
    use std::ffi::OsString;

    pub(crate) type Contained = OwnedChild;

    pub(super) fn spawn(launch: &StdioLaunch) -> io::Result<OwnedChild> {
        let arguments: Vec<OsString> = launch.arguments.iter().map(OsString::from).collect();
        OwnedChild::spawn_with_environment(launch.executable, &arguments, launch.cwd, launch.environment)
    }

    impl StdioChild for OwnedChild {
        fn read_stdout(&mut self, buf: &mut [u8]) -> io::Result<usize> { OwnedChild::read_stdout(self, buf) }
        fn read_stderr(&mut self, buf: &mut [u8]) -> io::Result<usize> { OwnedChild::read_stderr(self, buf) }
        fn write_stdin(&mut self, buf: &[u8]) -> io::Result<usize> { OwnedChild::write_stdin(self, buf) }
        fn close_stdin(&mut self) { OwnedChild::close_stdin(self) }
        /// Terminates the whole Job, root and descendants.
        fn terminate(&mut self) -> io::Result<()> { OwnedChild::terminate(self) }
        /// True only after the root exited and the Job has no live member.
        fn finish(&mut self) -> io::Result<bool> { OwnedChild::finish(self).map(|exit| exit.is_some()) }
    }
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
    use std::time::{Duration, Instant};

    /// Owns a fresh process group while retaining the unreaped leader, so
    /// the group identifier cannot name an unrelated group before SIGKILL.
    pub(crate) struct Contained {
        child: Child,
        group: libc::pid_t,
        stdin: Option<ChildStdin>,
        stdout: ChildStdout,
        stderr: ChildStderr,
        exited: bool,
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
        // Drop cannot report a failure; keep the wait bounded.
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) if Instant::now() >= deadline => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    }

    pub(super) fn spawn(launch: &StdioLaunch) -> io::Result<Contained> {
        if !launch.executable.is_absolute() || !launch.cwd.is_absolute() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                "Stdio executable and working directory must be absolute"));
        }
        let mut command = Command::new(launch.executable);
        command.args(launch.arguments).env_clear().envs(launch.environment)
            .current_dir(launch.cwd).stdin(Stdio::piped()).stdout(Stdio::piped())
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
            Ok((stdin, stdout, stderr)) => Ok(Contained {
                child, group, stdin: Some(stdin), stdout, stderr,
                exited: false, terminated: false, reaped: false,
            }),
            Err(error) => {
                // The leader is unreaped, so the group id is still ours.
                unsafe { libc::kill(-group, libc::SIGKILL); }
                reap_fallback(&mut child);
                Err(error)
            }
        }
    }

    impl Contained {
        fn leader_exited(&mut self) -> io::Result<bool> {
            if self.exited { return Ok(true); }
            // WNOWAIT keeps the leader (and so the group id) until we reap it.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let result = unsafe { libc::waitid(libc::P_PID, self.group as libc::id_t,
                &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT) };
            if result != 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted { return Ok(false); }
                return Err(error);
            }
            self.exited = unsafe { info.si_pid() } != 0;
            Ok(self.exited)
        }
    }

    impl StdioChild for Contained {
        fn read_stdout(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.stdout.read(buf) }
        fn read_stderr(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.stderr.read(buf) }
        fn write_stdin(&mut self, buf: &[u8]) -> io::Result<usize> {
            let pipe = self.stdin.as_mut()
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "Owned stdin closed"))?;
            match pipe.write(buf) {
                Ok(0) if !buf.is_empty() => Err(io::ErrorKind::WouldBlock.into()),
                result => result,
            }
        }
        fn close_stdin(&mut self) { self.stdin.take(); }

        /// SIGKILL to the whole owned group, root and descendants.
        fn terminate(&mut self) -> io::Result<()> {
            if self.terminated || self.reaped { return Ok(()); }
            self.close_stdin();
            if unsafe { libc::kill(-self.group, libc::SIGKILL) } != 0 {
                let error = io::Error::last_os_error();
                let gone = match error.raw_os_error() {
                    Some(libc::ESRCH) => true,
                    // Darwin reports EPERM for a group holding only zombies.
                    #[cfg(target_os = "macos")]
                    Some(libc::EPERM) => self.leader_exited()?,
                    _ => false,
                };
                if !gone { return Err(error); }
            }
            self.terminated = true;
            Ok(())
        }

        /// True once the leader exited, was reaped, and the group is empty.
        fn finish(&mut self) -> io::Result<bool> {
            if !self.reaped {
                if !self.leader_exited()? { return Ok(false); }
                // A server that exited on its own may leave descendants; kill
                // them while the unreaped leader still pins the group id.
                self.terminate()?;
                if self.child.try_wait()?.is_none() { return Ok(false); }
                self.reaped = true;
            }
            // Signal 0 only observes the formerly owned group after reaping.
            if unsafe { libc::kill(-self.group, 0) } == 0 { return Ok(false); }
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::ESRCH) => Ok(true),
                #[cfg(target_os = "macos")]
                Some(libc::EPERM) => Ok(false),
                _ => Err(error),
            }
        }
    }

    impl Drop for Contained {
        fn drop(&mut self) {
            if self.reaped { return; }
            // SIGKILL the group before reaping, then a bounded reap.
            let _ = StdioChild::terminate(self);
            reap_fallback(&mut self.child);
            self.reaped = true;
        }
    }
}

#[cfg(not(any(windows, unix)))]
mod platform {
    use super::*;

    pub(crate) enum Contained {}

    pub(super) fn spawn(_: &StdioLaunch) -> io::Result<Contained> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "Stdio extensions require Windows or Unix"))
    }

    impl StdioChild for Contained {
        fn read_stdout(&mut self, _: &mut [u8]) -> io::Result<usize> { match *self {} }
        fn read_stderr(&mut self, _: &mut [u8]) -> io::Result<usize> { match *self {} }
        fn write_stdin(&mut self, _: &[u8]) -> io::Result<usize> { match *self {} }
        fn close_stdin(&mut self) { match *self {} }
        fn terminate(&mut self) -> io::Result<()> { match *self {} }
        fn finish(&mut self) -> io::Result<bool> { match *self {} }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::path::Path;
    use std::time::{Duration, Instant};

    /// Output read past the returned line stays in `out` for the next call,
    /// so two lines that arrive in one read are both seen.
    fn read_line_with(child: &mut platform::Contained, out: &mut Vec<u8>, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut buf = [0u8; 1024];
        loop {
            match child.read_stdout(&mut buf) {
                Ok(count) => out.extend_from_slice(&buf[..count]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("stdout failed: {error}"),
            }
            let text = String::from_utf8_lossy(out).into_owned();
            let mut start = 0;
            for line in text.split_inclusive('\n').filter(|line| line.ends_with('\n')) {
                start += line.len();
                if let Some(value) = line.trim_end_matches('\n').strip_prefix(needle) {
                    let value = value.to_owned();
                    out.drain(..start);
                    return value;
                }
            }
            assert!(Instant::now() < deadline, "missing {needle:?}: {text}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn unix_stdio_child_group_killed_on_drop() {
        let temp = std::env::temp_dir();
        let heartbeat = temp.join(format!("agent-bridge-stdio-heartbeat-{}", std::process::id()));
        let _ = std::fs::remove_file(&heartbeat);
        let environment = BTreeMap::from([
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
            (OsString::from("AGENT_BRIDGE_STDIO_TEST_HEARTBEAT"), heartbeat.clone().into_os_string()),
        ]);
        // The descendant writes a heartbeat; it is only reachable as a group
        // member, never by PID from this test.
        let arguments = vec!["-c".to_owned(), concat!(
            "echo \"env:${CARGO_MANIFEST_DIR-unset}\"; ",
            "(while :; do printf . >> \"$AGENT_BRIDGE_STDIO_TEST_HEARTBEAT\"; sleep 0.05; done) & ",
            "echo \"descendant:started\"; wait").to_owned()];
        let launch = StdioLaunch {
            executable: Path::new("/bin/sh"), arguments: &arguments, cwd: &temp,
            environment: &environment,
        };
        let mut child = spawn_contained(&launch).unwrap();
        let mut out = Vec::new();
        assert_eq!(read_line_with(&mut child, &mut out, "env:"), "unset", "environment must be exact");
        read_line_with(&mut child, &mut out, "descendant:");
        let deadline = Instant::now() + Duration::from_secs(5);
        while std::fs::metadata(&heartbeat).map(|m| m.len()).unwrap_or(0) < 3 {
            assert!(Instant::now() < deadline, "descendant heartbeat missing");
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(child);
        // Allow one in-flight append, then require the heartbeat to stop.
        std::thread::sleep(Duration::from_millis(200));
        let size = std::fs::metadata(&heartbeat).unwrap().len();
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(std::fs::metadata(&heartbeat).unwrap().len(), size, "group descendant survived drop");
        std::fs::remove_file(heartbeat).unwrap();
    }
}

#[cfg(all(test, windows))]
mod windows_live_tests {
    use super::ContainedLauncher;
    use agent_bridge_extensions::{stdio::observe_executable, Registry, ServerControl};
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    /// The real bridge, served over stdio, is reached through the pinned
    /// executable, the contained launcher and the outbound MCP session.
    /// `cargo test` builds the binary for the integration tests first.
    #[test]
    fn contained_stdio_extension_lists_the_real_bridge_catalog() {
        let test = std::env::current_exe().unwrap();
        let exe = test.parent().unwrap().parent().unwrap().join("agent-bridge.exe");
        assert!(exe.is_file(), "missing {}", exe.display());
        let root = std::env::temp_dir().join(format!("ab-stdio-live-{}", std::process::id()));
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        std::fs::create_dir_all(root.join("db")).unwrap();
        let database = root.join("db").join("bridge.db");
        assert!(std::process::Command::new(&exe).arg("db").arg("init").arg(&database).status().unwrap().success());
        let sha = observe_executable(&exe).unwrap();
        let raw = serde_json::to_vec(&json!({"version":1,"servers":{"bridge":{"stdio":{
            "executable": exe.to_str().unwrap(), "executable_sha256": sha,
            "args": ["stdio", database.to_str().unwrap(),
                "--workspace", root.join("workspace").to_str().unwrap()]},
            "tools":{}}}})).unwrap();
        let registry = Registry::parse(&raw).unwrap();
        let pin = registry.server_sha256("bridge").unwrap().unwrap();
        let controls = BTreeMap::from([("bridge".to_owned(), ServerControl { enabled: true, config_sha256: pin })]);
        let registry = registry.with_controls(&controls).unwrap().with_stdio_launcher(Arc::new(ContainedLauncher));
        let report = registry.refresh_stdio("bridge").unwrap();
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(report["transport"], "stdio", "{report}");
        assert_eq!(report["protocol_version"], "2026-07-28", "{report}");
        assert!(report["live_tool_count"].as_u64().unwrap() > 0, "{report}");
        assert_eq!(report["approved_grants_changed"], false, "{report}");
    }
}
