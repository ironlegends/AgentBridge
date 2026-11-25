//! Real exec/pipe fixtures: no Chrome installation, display or public socket.
use super::*;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::mpsc;

const FIXTURE: &str = "browser_docs::chrome::cdp::unixpipe::tests::pipe_child_fixture";

fn fixture_args() -> Vec<OsString> {
    ["--exact", FIXTURE, "--ignored", "--nocapture"]
        .into_iter().map(OsString::from).collect()
}

fn fixture_env(mode: &str) -> Vec<(OsString, OsString)> {
    vec![("AGENT_BRIDGE_CDP_PIPE_FIXTURE".into(), mode.into())]
}

fn reply(mut input: File) -> Vec<u8> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut byte = [0];
        while bytes.len() < 4096 {
            if input.read_exact(&mut byte).is_err() { break; }
            bytes.push(byte[0]);
            if byte[0] == 0 { break; }
        }
        let _ = tx.send(bytes);
    });
    rx.recv_timeout(Duration::from_secs(5)).expect("private CDP fixture did not reply")
}

fn assert_protocol(command: &mut File, events: File) {
    command.write_all(b"{\"id\":7,\"method\":\"Browser.getVersion\"}\0").unwrap();
    assert_eq!(reply(events), b"{\"id\":7,\"result\":{\"product\":\"owned-fixture\"}}\0");
}

#[test]
fn private_pipe_transports_nul_frames_and_closes_unselected_descriptors() {
    let (commands, mut input) = create_pipe().unwrap();
    let (events, output) = create_pipe().unwrap();
    // Deliberately non-CLOEXEC: only 0/1/2 and the two selected CDP ends may
    // survive. A launcher that merely trusts its own CLOEXEC flags fails.
    let extra = File::open("/dev/null").unwrap();
    let sentinel = unsafe { libc::fcntl(extra.as_raw_fd(), libc::F_DUPFD, 120) };
    assert!(sentinel >= 120);
    let _sentinel = unsafe { File::from_raw_fd(sentinel) };
    let mut environment = fixture_env("protocol");
    environment.push(("AGENT_BRIDGE_CDP_UNSELECTED_FD".into(), sentinel.to_string().into()));
    let mut child = spawn_process(
        &std::env::current_exe().unwrap(), &std::env::temp_dir(),
        &fixture_args(), &environment,
        &[(commands.as_raw_fd(), 3), (output.as_raw_fd(), 4)],
    ).unwrap();
    drop(commands);
    drop(output);
    assert_protocol(&mut input, events);
    child.finish(Duration::from_secs(5)).unwrap();
}

#[test]
fn swapped_fd3_fd4_sources_are_remapped_without_clobbering_either_pipe() {
    let (commands, mut input) = create_pipe().unwrap();
    let (events, output) = create_pipe().unwrap();
    // All descriptor surgery happens in an isolated fixture subprocess,
    // never in the parallel test runner or an operator's process.
    let mut child = spawn_process(
        &std::env::current_exe().unwrap(), &std::env::temp_dir(),
        &fixture_args(), &fixture_env("collision"),
        &[(commands.as_raw_fd(), 3), (output.as_raw_fd(), 4)],
    ).unwrap();
    drop(commands);
    drop(output);
    assert_protocol(&mut input, events);
    child.finish(Duration::from_secs(5)).unwrap();
}

#[test]
fn spawn_failure_returns_an_error_without_starting_a_child() {
    let missing = std::env::temp_dir().join(format!("missing-chrome-{}", std::process::id()));
    let result = spawn_process(&missing, &std::env::temp_dir(), &[], &[], &[]);
    assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::NotFound));
}

#[test]
fn exited_owned_group_is_reaped_before_cleanup_success() {
    let mut child = spawn_process(
        Path::new("/bin/sh"), &std::env::temp_dir(),
        &["-c".into(), "exit 7".into()], &[], &[],
    ).unwrap();
    let pid = child.pid;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !child.exited().unwrap() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    child.finish(Duration::from_secs(5)).unwrap();
    assert_eq!(child.exit_code, Some(7));
    assert_eq!(unsafe { libc::kill(-pid, 0) }, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    child.finish(Duration::from_millis(1)).unwrap();
}

fn lingering_child() -> (ChildProcess, File) {
    let (commands, mut input) = create_pipe().unwrap();
    let (events, output) = create_pipe().unwrap();
    let child = spawn_process(
        &std::env::current_exe().unwrap(), &std::env::temp_dir(),
        &fixture_args(), &fixture_env("linger"),
        &[(commands.as_raw_fd(), 3), (output.as_raw_fd(), 4)],
    ).unwrap();
    drop(commands);
    drop(output);
    assert_protocol(&mut input, events);
    assert!(!child.exited().unwrap());
    (child, input)
}

#[test]
fn darwin_exit_transition_retries_owned_group_before_reaping() {
    let (mut child, _input) = lingering_child();
    let pid = child.pid;
    let mut attempts = 0;
    let mut queried = false;
    // The child and all wait/reap operations are real. Inject only the
    // Darwin signal error while WNOWAIT still reports a running leader.
    child.finish_with_signal(Duration::from_secs(5), true, |group, signal| {
        assert_eq!(group, pid);
        if signal == libc::SIGKILL {
            assert!(!queried, "no nonzero signal after the group-exit probe");
            attempts += 1;
            if attempts <= 2 { return Err(io::Error::from_raw_os_error(libc::EPERM)); }
        } else {
            assert_eq!(signal, 0);
            queried = true;
        }
        signal_group(group, signal)
    }).unwrap();
    assert_eq!(attempts, 3);
    assert!(queried && child.reaped && child.finished);
    assert_eq!(signal_group(pid, 0).unwrap_err().raw_os_error(), Some(libc::ESRCH));
}

#[test]
fn persistent_group_permission_denial_is_bounded_and_never_cleanup_success() {
    let (mut child, _input) = lingering_child();
    let mut attempts = 0;
    // Other Unix systems retain the immediate permission-denied result.
    let error = child.finish_with_signal(Duration::from_secs(5), false, |_, signal| {
        assert_eq!(signal, libc::SIGKILL);
        attempts += 1;
        Err(io::Error::from_raw_os_error(libc::EPERM))
    }).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EPERM));
    assert_eq!(attempts, 1);
    attempts = 0;
    let start = Instant::now();
    let error = child.finish_with_signal(Duration::from_millis(80), true, |_, signal| {
        assert_eq!(signal, libc::SIGKILL);
        attempts += 1;
        // A descheduled caller may receive its first answer only after the
        // deadline. Reproduce that case without depending on runner load.
        if attempts == 1 { std::thread::sleep(Duration::from_millis(100)); }
        Err(io::Error::from_raw_os_error(libc::EPERM))
    }).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(attempts, 1, "the first pending answer has exhausted the budget");
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(!child.terminated, "EPERM must not mark a live leader as terminated");
    assert!(!child.reaped, "the live leader must retain group ownership");
    assert!(!child.finished, "EPERM must not certify cleanup");
    assert!(!child.exited().unwrap());
    signal_group(child.pid, 0).unwrap();
    child.finish(Duration::from_secs(5)).unwrap();
}

#[test]
fn permission_denied_after_reap_is_not_a_group_exit_certificate() {
    let mut child = spawn_process(
        Path::new("/bin/sh"), &std::env::temp_dir(),
        &["-c".into(), "exit 7".into()], &[], &[],
    ).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !child.exited().unwrap() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut nonzero_signals = 0;
    let mut queries = 0;
    let error = child.finish_with_signal(Duration::from_millis(80), true, |_, signal| {
        if signal == libc::SIGKILL {
            nonzero_signals += 1;
            assert_eq!(queries, 0);
        } else {
            assert_eq!(signal, 0);
            queries += 1;
            // One EPERM answer can exhaust the bound even though the
            // leader has already been reaped. It must never certify exit.
            if queries == 1 { std::thread::sleep(Duration::from_millis(100)); }
        }
        Err(io::Error::from_raw_os_error(libc::EPERM))
    }).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(nonzero_signals, 1);
    assert_eq!(queries, 1, "the first group probe has exhausted the budget");
    assert!(child.reaped, "the group probe must follow actual leader reaping");
    assert!(!child.finished, "EPERM after reap must not certify group exit");
    assert_eq!(child.exit_code, Some(7));
    child.finish(Duration::from_secs(5)).unwrap();
}

#[test]
fn lost_child_ownership_refuses_every_group_signal() {
    let mut child = spawn_process(
        Path::new("/bin/sh"), &std::env::temp_dir(),
        &["-c".into(), "exit 0".into()], &[], &[],
    ).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !child.exited().unwrap() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child.pid, &mut status, libc::WNOHANG) }, child.pid);
    let mut signals = 0;
    let error = child.finish_with_signal(Duration::from_secs(1), true, |_, _| {
        signals += 1;
        Ok(())
    }).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::ECHILD));
    assert_eq!(signals, 0);
    assert!(!child.terminated && !child.finished);
}

#[test]
#[ignore = "subprocess fixture; invoked only by the private pipe tests"]
fn pipe_child_fixture() {
    let mode = std::env::var("AGENT_BRIDGE_CDP_PIPE_FIXTURE").unwrap();
    if mode == "collision" {
        // Preserve the controller's descriptors above the remap targets.
        let controller_in = duplicate_source(3).unwrap();
        let controller_out = duplicate_source(4).unwrap();
        let (commands, input) = create_pipe().unwrap();
        let (events, output) = create_pipe().unwrap();
        let command_source = duplicate_source(commands.as_raw_fd()).unwrap();
        let event_source = duplicate_source(output.as_raw_fd()).unwrap();
        assert_eq!(unsafe { libc::dup2(command_source.as_raw_fd(), 4) }, 4);
        assert_eq!(unsafe { libc::dup2(event_source.as_raw_fd(), 3) }, 3);
        let mut child = spawn_process(
            &std::env::current_exe().unwrap(), &std::env::temp_dir(),
            &fixture_args(), &fixture_env("protocol"), &[(4, 3), (3, 4)],
        ).unwrap();
        drop(commands);
        drop(output);
        let mut control_in = File::from(controller_in);
        let mut control_out = File::from(controller_out);
        let mut input = input;
        let mut request = [0; 4096];
        let count = control_in.read(&mut request).unwrap();
        input.write_all(&request[..count]).unwrap();
        control_out.write_all(&reply(events)).unwrap();
        child.finish(Duration::from_secs(5)).unwrap();
        return;
    }
    assert!(mode == "protocol" || mode == "linger");
    assert_eq!(std::env::current_dir().unwrap(), std::fs::canonicalize(std::env::temp_dir()).unwrap());
    assert_eq!(unsafe { libc::getpid() }, unsafe { libc::getpgrp() });
    for descriptor in [3, 4] {
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        assert!(flags >= 0 && flags & libc::FD_CLOEXEC == 0);
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(descriptor, &mut metadata) }, 0);
        assert_eq!(metadata.st_mode & libc::S_IFMT, libc::S_IFIFO);
    }
    if let Ok(sentinel) = std::env::var("AGENT_BRIDGE_CDP_UNSELECTED_FD") {
        assert_eq!(unsafe { libc::fcntl(sentinel.parse::<i32>().unwrap(), libc::F_GETFD) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    }
    let mut null_byte = [0];
    assert_eq!(unsafe { libc::read(0, null_byte.as_mut_ptr().cast(), 1) }, 0);
    let mut input = unsafe { File::from_raw_fd(3) };
    let mut output = unsafe { File::from_raw_fd(4) };
    let mut request = Vec::new();
    let mut byte = [0];
    loop {
        input.read_exact(&mut byte).unwrap();
        if byte[0] == 0 { break; }
        request.push(byte[0]);
        assert!(request.len() < 4096);
    }
    assert_eq!(request, br#"{"id":7,"method":"Browser.getVersion"}"#);
    output.write_all(b"{\"id\":7,\"result\":{\"product\":\"owned-fixture\"}}\0").unwrap();
    if mode == "linger" {
        // Remain alive until the controller closes its private pipe or
        // cleanup sends SIGKILL; no unrelated process is ever involved.
        let _ = input.read_exact(&mut byte);
    }
}
