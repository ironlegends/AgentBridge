//! Bounded stderr for owned test browsers; omitted from production builds.
use super::{create_pipe, ChildProcess};
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread::JoinHandle;

const LIMIT: usize = 32 * 1024;
const FINAL_DRAIN_LIMIT: usize = 256 * 1024;

#[derive(Default)]
struct Output {
    bytes: Vec<u8>,
    truncated: bool,
}

pub(super) struct Capture {
    stop: Arc<AtomicBool>,
    reader: Option<JoinHandle<Output>>,
}

impl Capture {
    fn start() -> io::Result<(Self, File)> {
        let (mut input, output) = create_pipe()?;
        let flags = unsafe { libc::fcntl(input.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(input.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let stop = Arc::new(AtomicBool::new(false));
        let cancel = Arc::clone(&stop);
        let reader = std::thread::Builder::new().name("bridge-test-chrome-stderr".into()).spawn(move || {
            let mut captured = Output::default();
            let mut buffer = [0u8; 8192];
            let mut closing_bytes = 0usize;
            loop {
                let closing = cancel.load(Ordering::Acquire);
                if closing && closing_bytes >= FINAL_DRAIN_LIMIT { break; }
                match input.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        if closing { closing_bytes += count; }
                        let retained = count.min(LIMIT.saturating_sub(captured.bytes.len()));
                        captured.bytes.extend_from_slice(&buffer[..retained]);
                        captured.truncated |= retained < count;
                    }
                    Err(issue) if issue.kind() == io::ErrorKind::WouldBlock => {
                        if closing { break; }
                        let mut descriptor = libc::pollfd {
                            fd: input.as_raw_fd(), events: libc::POLLIN, revents: 0,
                        };
                        if unsafe { libc::poll(&mut descriptor, 1, 25) } < 0
                            && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted { break; }
                    }
                    Err(issue) if issue.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            captured
        })?;
        Ok((Self { stop, reader: Some(reader) }, output))
    }

    fn take(&mut self) -> Output {
        self.stop.store(true, Ordering::Release);
        self.reader.take().and_then(|reader| reader.join().ok()).unwrap_or_default()
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        let captured = self.take();
        if !captured.bytes.is_empty() {
            eprintln!("agent-bridge: native-chrome-test-stderr raw_bytes={} truncated={}\n{}",
                captured.bytes.len(), captured.truncated, String::from_utf8_lossy(&captured.bytes));
        }
    }
}

pub(super) struct Pending {
    // Close the parent writer before stopping its reader on spawn failure.
    writer: File,
    capture: Capture,
}

fn prepare(requested: bool) -> io::Result<Option<Pending>> {
    if !requested { return Ok(None); }
    let (capture, writer) = Capture::start()?;
    Ok(Some(Pending { writer, capture }))
}

fn attach(mut child: ChildProcess, pending: Option<Pending>) -> ChildProcess {
    if let Some(Pending { writer, capture }) = pending {
        drop(writer);
        child.diagnostics = Some(capture);
    }
    child
}

pub(super) fn spawn(
    executable: &Path, cwd: &Path, arguments: &[OsString],
    environment: &[(OsString, OsString)], mappings: &[(RawFd, RawFd)],
) -> io::Result<ChildProcess> {
    let requested = std::env::var_os("AGENT_BRIDGE_TEST_CHROME_DIAGNOSTICS").as_deref()
        == Some(std::ffi::OsStr::new("1"));
    spawn_requested(executable, cwd, arguments, environment, mappings, requested)
}

fn spawn_requested(
    executable: &Path, cwd: &Path, arguments: &[OsString],
    environment: &[(OsString, OsString)], mappings: &[(RawFd, RawFd)], requested: bool,
) -> io::Result<ChildProcess> {
    let pending = prepare(requested)?;
    let stderr = pending.as_ref().map(|pending| &pending.writer);
    let child = super::spawn_process_inner(executable, cwd, arguments, environment, mappings, stderr)?;
    Ok(attach(child, pending))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::Duration;
    const FIXTURE: &str = "browser_docs::chrome::cdp::unixpipe::test_diagnostics::tests::stderr_child_fixture";
    const MARKER: &[u8] = b"owned stderr from exact fixture\n";

    fn fixture(mode: &str, mappings: &[(RawFd, RawFd)]) -> ChildProcess {
        let arguments = ["--exact", FIXTURE, "--ignored", "--nocapture"]
            .into_iter().map(OsString::from).collect::<Vec<_>>();
        spawn_requested(&std::env::current_exe().unwrap(), &std::env::temp_dir(),
            &arguments, &[("AGENT_BRIDGE_STDERR_FIXTURE".into(), mode.into())], mappings, true).unwrap()
    }

    fn read_fixture(input: File) -> Vec<u8> {
        let (sent, received) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = input.take(4096).read_to_end(&mut bytes);
            let _ = sent.send(bytes);
        });
        received.recv_timeout(Duration::from_secs(5)).expect("owned fixture did not close its output")
    }

    fn captured(child: &mut ChildProcess) -> Vec<u8> {
        child.finish(Duration::from_secs(5)).unwrap();
        child.diagnostics.take().expect("requested capture must be attached").take().bytes
    }

    #[test]
    fn diagnostic_spawn_preserves_cdp_fd3_fd4_and_captures_fd2() {
        let (commands, mut input) = create_pipe().unwrap();
        let (events, output) = create_pipe().unwrap();
        let mut child = fixture("cdp", &[(commands.as_raw_fd(), 3), (output.as_raw_fd(), 4)]);
        drop(commands); drop(output);
        input.write_all(b"owned-request\0").unwrap();
        drop(input);
        assert_eq!(read_fixture(events), b"owned-response\0");
        assert_eq!(captured(&mut child), MARKER);
    }

    #[test]
    fn diagnostic_spawn_preserves_stdout_and_captures_fd2_without_cdp_handles() {
        let (input, output) = create_pipe().unwrap();
        let mut child = fixture("stdout", &[(output.as_raw_fd(), 1)]);
        drop(output);
        let bytes = read_fixture(input);
        assert!(bytes.windows(b"owned-stdout".len()).any(|part| part == b"owned-stdout"));
        assert_eq!(captured(&mut child), MARKER);
    }

    #[test]
    #[ignore = "child fixture invoked by the private diagnostic pipe tests"]
    fn stderr_child_fixture() {
        use std::os::fd::FromRawFd;
        std::io::stderr().write_all(MARKER).unwrap();
        match std::env::var("AGENT_BRIDGE_STDERR_FIXTURE").unwrap().as_str() {
            "cdp" => {
                let mut input = unsafe { File::from_raw_fd(3) };
                let mut output = unsafe { File::from_raw_fd(4) };
                let mut request = [0; 14];
                input.read_exact(&mut request).unwrap();
                assert_eq!(&request, b"owned-request\0");
                output.write_all(b"owned-response\0").unwrap();
            }
            "stdout" => {
                assert_eq!(unsafe { libc::fcntl(3, libc::F_GETFD) }, -1);
                assert_eq!(unsafe { libc::fcntl(4, libc::F_GETFD) }, -1);
                std::io::stdout().write_all(b"owned-stdout").unwrap();
            }
            _ => panic!("unknown diagnostic fixture mode"),
        }
    }

    #[test]
    fn stderr_limit_keeps_draining_and_does_not_block_the_writer() {
        let (mut capture, mut writer) = Capture::start().unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            let result = writer.write_all(&vec![b'x'; LIMIT * 4]);
            drop(writer);
            let _ = sent.send(result);
        });
        received.recv_timeout(Duration::from_secs(2)).expect("stderr must drain past its display limit").unwrap();
        writer.join().unwrap();
        let captured = capture.take();
        assert_eq!(captured.bytes, vec![b'x'; LIMIT]);
        assert!(captured.truncated);
    }

    #[test]
    fn stderr_reader_stops_even_when_the_failed_spawn_writer_is_still_open() {
        let (mut capture, writer) = Capture::start().unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        let closer = std::thread::spawn(move || {
            let captured = capture.take();
            let _ = sent.send((captured.bytes, capture.reader.is_none()));
        });
        let (bytes, joined) = received.recv_timeout(Duration::from_secs(5))
            .expect("stderr reader must stop without waiting for writer EOF");
        assert!(bytes.is_empty());
        assert!(joined, "the reader has been joined");
        drop(writer);
        closer.join().unwrap();
    }
}
