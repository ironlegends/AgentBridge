//! Direct processes for a locally selected Fully Unlocked workstation.
//!
//! The startup router alone selects this provider. Every request and every
//! nonblocking stdin write rechecks the shared live profile. A local profile
//! revoker stops and joins all owned sessions without taking that profile
//! lock, so the operator can publish a lower profile only after cleanup.
//! A session ends with its root program: remaining descendants are stopped.

#[cfg(unix)]
#[path = "unrestricted/unix.rs"]
mod platform;
#[cfg(windows)]
#[path = "unrestricted/windows.rs"]
mod platform;
#[cfg(test)]
#[path = "unrestricted/tests.rs"]
mod tests;

mod history;
mod unified;
#[cfg(windows)]
mod diagnostic;
#[cfg(windows)]
pub(super) use diagnostic::run_pinned_git_revision;

use crate::runtime::RuntimeError;
use agent_bridge_desktop::DesktopProfile;
use agent_bridge_gateway::{ToolCallResult, ToolDefinition, ToolMapHandler};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    Arc, Condvar, Mutex, RwLock, RwLockReadGuard, TryLockError,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_SESSIONS: usize = 32;
const MAX_STREAM_BYTES: usize = 256 * 1024;
const MAX_REPLY_BYTES: usize = 64 * 1024;
const MAX_INPUT_BYTES: usize = 64 * 1024;
const INPUT_QUEUE_FRAMES: usize = 4;
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const WORKER_TICK: Duration = Duration::from_millis(10);
type ProcessResult<T> = Result<T, String>;

struct LaunchSpec {
    program: String,
    arguments: Vec<String>,
    cwd: PathBuf,
    // cmd.exe does not use CRT argv parsing for its /C tail.
    cmd_command: Option<String>,
}

fn invalid(message: &str) -> String {
    format!("PROCESS_INVALID_ARGUMENT: {message}")
}

fn fields(args: &Map<String, Value>, allowed: &[&str]) -> ProcessResult<()> {
    if args.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid("unsupported argument"));
    }
    Ok(())
}

fn string<'a>(args: &'a Map<String, Value>, key: &str, limit: usize) -> ProcessResult<&'a str> {
    let text = args.get(key).and_then(Value::as_str)
        .ok_or_else(|| invalid(&format!("{key} must be a string")))?;
    if text.trim().is_empty() || text.len() > limit || text.contains('\0') {
        return Err(invalid(&format!("{key} is empty, too long or contains NUL")));
    }
    Ok(text)
}

fn timeout(args: &Map<String, Value>, default: u64, maximum: u64) -> ProcessResult<Duration> {
    let value = match args.get("timeout_ms") {
        None => default,
        Some(value) => value.as_u64().filter(|value| *value <= maximum)
            .ok_or_else(|| invalid("timeout_ms must be an integer within the advertised range"))?,
    };
    Ok(Duration::from_millis(value))
}

fn parse_start(args: &Map<String, Value>, root: &Path, unified: bool) -> ProcessResult<(LaunchSpec, Duration)> {
    if unified {
        fields(args, &["command", "shell", "program", "args", "cwd", "timeout_ms",
            "window_mode", "temp_mode", "elevation", "agent_desktop_lease_id"])?;
    } else {
        fields(args, &["command", "shell", "program", "args", "cwd", "timeout_ms"])?;
    }
    let has_command = args.contains_key("command");
    let has_program = args.contains_key("program");
    if has_command == has_program {
        return Err(invalid("provide exactly one of command or program"));
    }
    let cwd = if args.contains_key("cwd") {
        let selected = PathBuf::from(string(args, "cwd", 8192)?);
        if selected.is_absolute() { selected } else { root.join(selected) }
    } else { root.to_owned() };
    let wait = timeout(args, if unified { 3000 } else { 1000 }, 30_000)?;
    if unified && wait < Duration::from_millis(250) {
        return Err(invalid("timeout_ms must be an integer from 250 to 30000"));
    }
    let (program, arguments, cmd_command) = if has_program {
        if args.contains_key("shell") { return Err(invalid("shell requires command")); }
        let program = string(args, "program", 8192)?.to_owned();
        let mut arguments = Vec::new();
        if let Some(value) = args.get("args") {
            let array = value.as_array().filter(|array| array.len() <= 128)
                .ok_or_else(|| invalid("args must be an array of at most 128 strings"))?;
            let mut total = 0usize;
            for item in array {
                let argument = item.as_str().filter(|text| text.len() <= 65_536 && !text.contains('\0'))
                    .ok_or_else(|| invalid("each args item must be a string without NUL, at most 65536 bytes"))?;
                total = total.saturating_add(argument.len());
                if total > 256 * 1024 { return Err(invalid("combined args exceed 262144 bytes")); }
                arguments.push(argument.to_owned());
            }
        }
        (program, arguments, None)
    } else {
        if args.contains_key("args") { return Err(invalid("args requires program")); }
        let command = string(args, "command", if unified { 32_768 * 3 } else { 65_536 })?;
        if unified && command.encode_utf16().count() > 32_768 {
            return Err(invalid("command exceeds 32768 UTF-16 units"));
        }
        let shell = if args.contains_key("shell") { string(args, "shell", 32)? }
            else if cfg!(windows) { "powershell" } else { "sh" };
        let shell = match (unified, shell) {
            (true, "powershell.exe") => "powershell",
            (true, "cmd.exe") => "cmd",
            _ => shell,
        };
        match shell {
            "pwsh" | "powershell" => {
                let mut arguments = vec!["-NoLogo", "-NoProfile"];
                if !unified || !unified::visible_requested(args) {
                    arguments.push("-NonInteractive");
                }
                arguments.extend(["-Command", command]);
                (shell.to_owned(), arguments.into_iter().map(str::to_owned).collect(), None)
            },
            "cmd" => ("cmd".to_owned(), Vec::new(), Some(command.to_owned())),
            "sh" | "bash" => (shell.to_owned(), vec!["-c".into(), command.to_owned()], None),
            _ => return Err(invalid("shell must be pwsh, powershell, cmd, sh or bash")),
        }
    };
    Ok((LaunchSpec { program, arguments, cwd, cmd_command }, wait))
}

fn valid_session_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    bytes.len() == 36 && [8, 13, 18, 23].iter().all(|&index| bytes[index] == b'-')
        && bytes[14] == b'4' && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        && bytes.iter().enumerate().all(|(index, byte)| {
            [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit()
        })
}

fn session_id(args: &Map<String, Value>) -> ProcessResult<&str> {
    let id = string(args, "session_id", 36)?;
    if !valid_session_id(id) { return Err("PROCESS_SESSION_UNKNOWN: invalid owned session capability".into()); }
    Ok(id)
}

fn new_session_id() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| io::Error::other("OS session randomness unavailable"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..]))
}

#[derive(Default)]
struct OutputBuffer {
    bytes: Vec<u8>,
    dropped: u64,
    eof: bool,
}
impl OutputBuffer {
    fn push(&mut self, chunk: &[u8]) {
        let keep = chunk.len().min(MAX_STREAM_BYTES.saturating_sub(self.bytes.len()));
        self.bytes.extend_from_slice(&chunk[..keep]);
        self.dropped = self.dropped.saturating_add((chunk.len() - keep) as u64);
    }
    fn complete_prefix(&self, limit: usize) -> usize {
        let end = self.bytes.len().min(limit);
        if self.eof && end == self.bytes.len() { return end; }
        let mut offset = 0;
        while offset < end {
            match std::str::from_utf8(&self.bytes[offset..end]) {
                Ok(_) => return end,
                Err(error) => match error.error_len() {
                    None => return offset + error.valid_up_to(),
                    Some(length) => offset += error.valid_up_to() + length,
                },
            }
        }
        end
    }
    fn has_output(&self) -> bool { self.complete_prefix(MAX_REPLY_BYTES) > 0 }
    fn drain(&mut self, limit: usize) -> String {
        let end = self.complete_prefix(limit);
        let text = String::from_utf8_lossy(&self.bytes[..end]).into_owned();
        self.bytes.drain(..end);
        text
    }
}

#[derive(Default)]
struct Capture {
    history: Option<history::History>,
    output_changed: Option<Instant>,
    launch: Option<LaunchReceipt>,
    lease_placed: bool,
    lease_error: Option<String>,
    temp_cleanup_error: Option<String>,
    stdout: OutputBuffer,
    stderr: OutputBuffer,
    finished: bool,
    finished_at: Option<Instant>,
    exit_code: Option<i32>,
    stop_requested: bool,
    worker_error: Option<String>,
    cleanup_error: Option<String>,
    stdin_closed: bool,
    input_completed: u64,
    input_error: Option<String>,
}
type SharedCapture = Arc<(Mutex<Capture>, Condvar)>;

struct LaunchReceipt {
    visible: bool,
    short_temp: bool,
    cwd_warning: Option<String>,
    lease_id: Option<String>,
}

struct OwnedLaunch {
    process: platform::Process,
    temp: Option<unified::TemporaryDirectory>,
}

struct InputFrame {
    id: u64,
    bytes: Vec<u8>,
    eof: bool,
}
struct InputQueue {
    sender: Option<SyncSender<InputFrame>>,
    next_id: u64,
    eof_queued: bool,
}

struct Session {
    id: String,
    program: String,
    command: Option<Arc<crate::client_sessions::CommandRecord>>,
    cwd: PathBuf,
    started: Instant,
    capture: SharedCapture,
    input: Mutex<InputQueue>,
    stop: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
    retained: Arc<Mutex<Option<OwnedLaunch>>>,
}

impl Session {
    fn start(
        id: String, spec: LaunchSpec, profile: Arc<RwLock<DesktopProfile>>, retain_history: bool,
        launch: Option<unified::Launch>, wait: Duration,
    ) -> io::Result<Arc<Self>> {
        let launch_receipt = launch.as_ref().map(|launch| LaunchReceipt {
            visible: launch.presentation.visible,
            short_temp: launch.presentation.temp.is_some(),
            cwd_warning: launch.presentation.cwd_warning.clone(),
            lease_id: launch.lease.as_ref().map(|lease| lease.id.clone()),
        });
        let stdin_closed = launch_receipt.as_ref().is_some_and(|launch| launch.visible);
        let state = Capture {
            history: retain_history.then(history::History::default),
            launch: launch_receipt, stdin_closed, ..Capture::default()
        };
        let capture: SharedCapture = Arc::new((Mutex::new(state), Condvar::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let retained = Arc::new(Mutex::new(None));
        let (sender, queue) = mpsc::sync_channel(INPUT_QUEUE_FRAMES);
        let (started, started_rx) = mpsc::sync_channel(1);
        let worker_capture = Arc::clone(&capture);
        let worker_stop = Arc::clone(&stop);
        let worker_retained = Arc::clone(&retained);
        let (program, cwd) = (spec.program.clone(), spec.cwd.clone());
        let command = crate::client_sessions::CommandRecord::for_request("Process");
        let worker_command = command.clone();
        // Start the worker before creating any child. A thread-creation
        // failure therefore never drops an owner without observing cleanup.
        let worker = thread::Builder::new().name("agent-bridge-unlocked-process".into()).spawn(move || {
            #[cfg(windows)]
            let process = match launch.as_ref() {
                Some(launch) => platform::Process::spawn_unified(&spec, &launch.presentation),
                None => platform::Process::spawn(&spec),
            };
            #[cfg(not(windows))]
            let process = platform::Process::spawn(&spec);
            let process = match process {
                Ok(process) => process,
                Err(error) => { let _ = started.send(Err(error)); return; }
            };
            let (temp, lease) = launch.map_or((None, None), |launch| (launch.presentation.temp, launch.lease));
            let mut owned = OwnedLaunch { process, temp };
            if started.send(Ok(())).is_err() { worker_stop.store(true, Ordering::Release); }

            #[cfg(windows)]
            if let Some(lease) = lease.as_ref() {
                let placement = lease.place(owned.process.owned_child(), wait);
                let mut state = worker_capture.0.lock().unwrap_or_else(|error| error.into_inner());
                match placement {
                    Ok(()) => state.lease_placed = true,
                    Err(error) => {
                        state.lease_error = Some(error);
                        worker_stop.store(true, Ordering::Release);
                    }
                }
                worker_capture.1.notify_all();
            }
            #[cfg(not(windows))]
            let _ = wait;

            let result = run_worker(&mut owned.process, queue, &worker_stop, &worker_capture,
                Some(&profile), lease.as_ref(), CLEANUP_TIMEOUT);
            let mut state = worker_capture.0.lock().unwrap_or_else(|error| error.into_inner());
            state.finished = true;
            state.finished_at = Some(Instant::now());
            state.stdin_closed = true;
            match result {
                Ok(()) => {
                    if let Some(command) = &worker_command {
                        command.finish(state.exit_code);
                    }
                    state.temp_cleanup_error = owned.temp.take()
                        .and_then(|temp| temp.cleanup().err().map(|error| error.to_string()));
                }
                Err(error) => {
                    *worker_retained.lock().unwrap_or_else(|error| error.into_inner()) = Some(owned);
                    state.cleanup_error = Some(error.to_string());
                }
            }
            worker_capture.1.notify_all();
        })?;
        let launch_result = started_rx.recv()
            .unwrap_or_else(|_| Err(io::Error::other("Owned process worker exited during launch")));
        if let Err(error) = launch_result {
            let _ = worker.join();
            return Err(error);
        }
        Ok(Arc::new(Self {
            id, program, command, cwd, started: Instant::now(), capture,
            input: Mutex::new(InputQueue { sender: Some(sender), next_id: 1, eof_queued: false }),
            stop, worker: Mutex::new(Some(worker)), retained,
        }))
    }

    fn cleanup_confirmed(&self) -> bool {
        let state = self.capture.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        state.finished && state.cleanup_error.is_none()
    }

    fn queue_input(&self, bytes: Vec<u8>, eof: bool) -> ProcessResult<(u64, u64)> {
        let state = self.capture.0.lock().map_err(|_| "PROCESS_STDIN_UNAVAILABLE".to_owned())?;
        if state.launch.as_ref().is_some_and(|launch| launch.visible) {
            return Err("PROCESS_STDIN_UNAVAILABLE: use physical input in the visible console".into());
        }
        if state.finished || state.stdin_closed || self.stop.load(Ordering::Acquire) {
            return Err("PROCESS_STDIN_CLOSED: owned session has stopped".into());
        }
        let mark = state.history.as_ref().map_or(0, history::History::end);
        drop(state);
        let mut input = self.input.lock().map_err(|_| "PROCESS_STDIN_UNAVAILABLE".to_owned())?;
        if input.eof_queued { return Err("PROCESS_STDIN_CLOSED: EOF already queued".into()); }
        let sender = input.sender.as_ref().ok_or("PROCESS_STDIN_CLOSED")?;
        let id = input.next_id;
        match sender.try_send(InputFrame { id, bytes, eof }) {
            Ok(()) => {
                input.next_id += 1;
                input.eof_queued = eof;
                Ok((id, mark))
            },
            Err(TrySendError::Full(_)) => Err("PROCESS_INPUT_BUSY: input was not queued".into()),
            Err(TrySendError::Disconnected(_)) => Err("PROCESS_STDIN_CLOSED".into()),
        }
    }

    fn request_stop(&self) {
        self.stop.store(true, Ordering::Release);
        self.input.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).sender.take();
        self.capture.1.notify_all();
    }

    fn wait(&self, duration: Duration) {
        let deadline = Instant::now() + duration;
        let (lock, changed) = &*self.capture;
        let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        while !state.finished && !state.stdout.has_output() && !state.stderr.has_output()
            && state.input_error.is_none() && Instant::now() < deadline
        {
            let remaining = deadline.saturating_duration_since(Instant::now());
            state = changed.wait_timeout(state, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner()).0;
        }
    }

    fn await_placement(&self, wait: Duration) -> ProcessResult<()> {
        let state = self.capture.0.lock().map_err(|_| "PROCESS_CAPTURE_UNAVAILABLE")?;
        if !state.launch.as_ref().is_some_and(|launch| launch.lease_id.is_some()) {
            return Ok(());
        }
        let state = self.capture.1.wait_timeout_while(state, wait, |state| {
            !state.lease_placed && state.lease_error.is_none() && !state.finished
                && !self.stop.load(Ordering::Acquire)
        }).map_err(|_| "PROCESS_CAPTURE_UNAVAILABLE")?.0;
        if let Some(error) = &state.lease_error { return Err(error.clone()); }
        if state.lease_placed { return Ok(()); }
        Err("OWNED_WINDOW_PLACEMENT_UNVERIFIED".into())
    }

    fn interaction_receipt(&self, id: u64, mark: u64, wait_for_prompt: bool, wait: Duration) -> Value {
        const QUIET: Duration = Duration::from_millis(100);
        let deadline = Instant::now() + wait;
        let (lock, changed) = &*self.capture;
        let mut state = lock.lock().unwrap_or_else(|error| error.into_inner());
        let mut timed_out = false;
        if wait_for_prompt {
            while !state.finished && state.input_error.is_none() && !self.stop.load(Ordering::Acquire) {
                let now = Instant::now();
                let quiet_at = state.output_changed.unwrap_or(now) + QUIET;
                let fresh = state.input_completed >= id
                    && state.history.as_ref().is_some_and(|history| history.end() > mark);
                if fresh && now >= quiet_at { break; }
                if now >= deadline { timed_out = true; break; }
                let until = if fresh { quiet_at.min(deadline) } else { deadline };
                state = changed.wait_timeout(state, until.saturating_duration_since(now))
                    .unwrap_or_else(|error| error.into_inner()).0;
            }
        }
        let (stdout, stderr, truncated) = if wait_for_prompt {
            state.history.as_ref().map_or_else(Default::default, |history| history.since(mark))
        } else { (String::new(), String::new(), false) };
        let mut receipt = self.receipt(&state, stdout, stderr);
        receipt["prompt_wait_timed_out"] = json!(timed_out);
        receipt["input_output_truncated"] = json!(truncated);
        receipt
    }

    fn join_until(&self, deadline: Instant) -> io::Result<()> {
        let (lock, changed) = &*self.capture;
        let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        while !state.finished {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "Owned process cleanup has not completed"));
            }
            state = changed.wait_timeout(state, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner()).0;
        }
        let error = state.cleanup_error.clone();
        drop(state);
        if let Some(worker) = self.worker.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take() {
            worker.join().map_err(|_| io::Error::other("Owned process worker panicked"))?;
        }
        let Some(previous_error) = error else { return Ok(()); };
        let mut retained = self.retained.lock().unwrap_or_else(|error| error.into_inner());
        let Some(owned) = retained.as_mut() else {
            let state = lock.lock().unwrap_or_else(|error| error.into_inner());
            return state.cleanup_error.as_ref().map_or(Ok(()), |_| Err(io::Error::other(previous_error)));
        };
        let time_left = deadline.saturating_duration_since(Instant::now());
        if time_left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "Owned process cleanup remains unverified"));
        }
        let (sender, input) = mpsc::sync_channel(1);
        drop(sender);
        // A failed cleanup leaves the owner open. Retrying does not touch
        // the live-profile lock, which the revoker may already hold.
        let retry = run_worker(&mut owned.process, input, &self.stop, &self.capture, None, None, time_left);
        let mut state = lock.lock().unwrap_or_else(|error| error.into_inner());
        match retry {
            Ok(()) => {
                if let Some(command) = &self.command {
                    command.finish(state.exit_code);
                }
                state.temp_cleanup_error = owned.temp.take()
                    .and_then(|temp| temp.cleanup().err().map(|error| error.to_string()));
                state.cleanup_error = None;
                retained.take();
            }
            Err(ref error) => { state.cleanup_error = Some(error.to_string()); }
        }
        self.capture.1.notify_all();
        retry
    }

    fn snapshot(&self) -> Value {
        let mut state = self.capture.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let stdout = state.stdout.drain(MAX_REPLY_BYTES);
        let stderr = state.stderr.drain(MAX_REPLY_BYTES);
        self.receipt(&state, stdout, stderr)
    }

    fn receipt(&self, state: &Capture, stdout: String, stderr: String) -> Value {
        let (status, running) = if state.cleanup_error.is_some() {
            ("cleanup_incomplete", None)
        } else if state.finished {
            ("exited", Some(false))
        } else {
            ("running", Some(true))
        };
        let mut receipt = json!({
            "session_id":self.id, "program":self.program, "cwd":self.cwd,
            "status":status, "running":running, "exit_code":state.exit_code,
            "elapsed_ms":self.started.elapsed().as_millis() as u64,
            "stdout":stdout, "stderr":stderr,
            "stdout_truncated":state.stdout.dropped > 0,
            "stderr_truncated":state.stderr.dropped > 0,
            "stdout_dropped_bytes":state.stdout.dropped,
            "stderr_dropped_bytes":state.stderr.dropped,
            "stdout_eof":state.stdout.eof, "stderr_eof":state.stderr.eof,
            "output_complete":state.stdout.eof && state.stderr.eof && state.worker_error.is_none(),
            "has_more":!state.stdout.bytes.is_empty() || !state.stderr.bytes.is_empty(),
            "stop_requested":state.stop_requested,
            "stdin_closed":state.stdin_closed,
            "input_completed_through":state.input_completed,
            "input_error":state.input_error,
            "process_error":state.worker_error,
            "cleanup_error":state.cleanup_error,
        });
        if let Some(launch) = &state.launch {
            if let Some(finished) = state.finished_at {
                receipt["elapsed_ms"] = json!(finished.saturating_duration_since(self.started).as_millis() as u64);
            }
            receipt["window_mode"] = json!(if launch.visible { "visible" } else { "hidden" });
            receipt["capture_mode"] = json!(if launch.visible { "visible_console" } else { "pipes" });
            receipt["output_capture"] = json!(!launch.visible);
            receipt["stdin_available"] = json!(!launch.visible && !state.stdin_closed);
            receipt["temp_mode"] = json!(if launch.short_temp { "short" } else { "inherit" });
            receipt["cwd_warning"] = json!(launch.cwd_warning);
            receipt["temp_cleanup_error"] = json!(state.temp_cleanup_error);
            receipt["agent_desktop_lease_id"] = json!(launch.lease_id);
            receipt["agent_desktop_placed"] = json!(launch.lease_id.as_ref().map(|_| state.lease_placed));
            receipt["agent_desktop_error"] = json!(state.lease_error);
            if launch.visible {
                receipt["stdout_eof"] = Value::Null;
                receipt["stderr_eof"] = Value::Null;
                receipt["output_complete"] = json!(false);
            }
        }
        receipt
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.request_stop();
        // The worker uses only nonblocking pipe operations and a bounded
        // cleanup loop. Do not detach it even on an earlier timeout/error.
        if let Some(worker) = self.worker.get_mut().unwrap_or_else(|poisoned| poisoned.into_inner()).take() {
            let _ = worker.join();
        }
    }
}

fn drain_output(process: &mut platform::Process, capture: &SharedCapture, stdout: bool) -> io::Result<()> {
    {
        let state = capture.0.lock().unwrap_or_else(|error| error.into_inner());
        if (stdout && state.stdout.eof) || (!stdout && state.stderr.eof) { return Ok(()); }
    }
    let mut bytes = [0u8; 4096];
    // Bound work per tick so a flooding child cannot starve kill or stdin.
    for _ in 0..16 {
        let read = if stdout { process.read_stdout(&mut bytes) } else { process.read_stderr(&mut bytes) };
        match read {
            Ok(count) => {
                let (lock, changed) = &**capture;
                let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(history) = &mut state.history {
                    let previous = history.end();
                    history.push(stdout, &bytes[..count], count == 0);
                    if history.end() > previous { state.output_changed = Some(Instant::now()); }
                }
                let output = if stdout { &mut state.stdout } else { &mut state.stderr };
                if count == 0 { output.eof = true; } else { output.push(&bytes[..count]); }
                changed.notify_all();
                if count == 0 { break; }
            },
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn run_worker(
    process: &mut platform::Process, input: Receiver<InputFrame>, stop: &AtomicBool,
    capture: &SharedCapture, profile: Option<&RwLock<DesktopProfile>>,
    lease: Option<&unified::LeaseBinding>, cleanup_timeout: Duration,
) -> io::Result<()> {
    let mut pending: Option<(InputFrame, usize)> = None;
    let mut stopping: Option<Instant> = None;
    let mut root_exit: Option<Option<i32>> = None;
    let mut fault: Option<io::Error> = None;
    let mut cleanup_done: Option<Option<i32>> = None;
    let mut next_lease_check = Instant::now() + Duration::from_millis(500);
    loop {
        if stopping.is_none() {
            match process.try_exit() {
                Ok(Some(exit)) => { root_exit = Some(exit); stopping = Some(Instant::now()); },
                Ok(None) => {},
                Err(error) => { fault = Some(error); stopping = Some(Instant::now()); },
            }
            if stop.load(Ordering::Acquire) { stopping.get_or_insert_with(Instant::now); }
            else if let Some(lease) = lease.filter(|_| Instant::now() >= next_lease_check && stopping.is_none()) {
                if !check_lease(lease, stop, capture) { stopping = Some(Instant::now()); }
                next_lease_check = Instant::now() + Duration::from_millis(500);
            }
        }
        if stopping.is_some() {
            process.close_stdin();
            pending = None;
            {
                let mut state = capture.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                state.stdin_closed = true;
                state.stop_requested |= stop.load(Ordering::Acquire);
            }
            if let Err(error) = process.terminate() { fault.get_or_insert(error); }
        }
        for stdout in [true, false] {
            if let Err(error) = drain_output(process, capture, stdout) {
                fault.get_or_insert(error);
                let mut state = capture.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                // An irrecoverably failed pipe is closed for capture purposes.
                // Its separate process_error prevents claiming complete output.
                if stdout { state.stdout.eof = true; } else { state.stderr.eof = true; }
                stopping.get_or_insert_with(Instant::now);
            }
        }
        if let Some(started) = stopping {
            if cleanup_done.is_none() {
                match process.finish() {
                    Ok(Some(code)) => { cleanup_done = Some(code); },
                    Ok(None) => {},
                    Err(error) => { fault.get_or_insert(error); },
                }
            }
            if let Some(code) = cleanup_done {
                let mut state = capture.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                // Unix descendants can close their inherited pipes one tick
                // after the root is reaped. Preserve ownership until real EOF.
                if state.stdout.eof && state.stderr.eof {
                    state.exit_code = root_exit.unwrap_or(code);
                    state.worker_error = fault.map(|error| error.to_string());
                    return Ok(());
                }
            }
            if started.elapsed() >= cleanup_timeout {
                return Err(fault.unwrap_or_else(|| io::Error::new(io::ErrorKind::TimedOut,
                    "Owned process tree cleanup deadline exceeded")));
            }
        } else {
            if pending.is_none() {
                match input.try_recv() {
                    Ok(frame) => pending = Some((frame, 0)),
                    Err(TryRecvError::Empty) => {},
                    Err(TryRecvError::Disconnected) => { process.close_stdin(); },
                }
            }
            if let Some((frame, written)) = pending.as_mut() {
                if let Some(lease) = lease.filter(|_| *written == 0 && !stop.load(Ordering::Acquire)) {
                    if !check_lease(lease, stop, capture) { continue; }
                }
                // A revoker holds the write lock while joining this worker.
                // Never block waiting for its read lock; stop stays observable.
                let Some(profile) = profile else {
                    stop.store(true, Ordering::Release);
                    continue;
                };
                match profile.try_read() {
                    Ok(active) if *active == DesktopProfile::FullyUnlocked && !stop.load(Ordering::Acquire) => {
                        let write = if *written == frame.bytes.len() { Ok(0) }
                            else { process.write_stdin(&frame.bytes[*written..]) };
                        match write {
                            Ok(count) => {
                                *written += count;
                                if *written == frame.bytes.len() {
                                    if frame.eof { process.close_stdin(); }
                                    let mut state = capture.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                                    state.input_completed = frame.id;
                                    state.stdin_closed |= frame.eof;
                                    capture.1.notify_all();
                                    pending = None;
                                }
                            },
                            Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {},
                            Err(error) => {
                                process.close_stdin();
                                let mut state = capture.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                                state.stdin_closed = true;
                                state.input_error = Some(format!("PROCESS_STDIN_WRITE_FAILED: {error}"));
                                capture.1.notify_all();
                                pending = None;
                            },
                        }
                    },
                    Ok(_) | Err(TryLockError::Poisoned(_)) => { stop.store(true, Ordering::Release); },
                    Err(TryLockError::WouldBlock) => {},
                }
            }
        }
        thread::sleep(WORKER_TICK);
    }
}

fn check_lease(lease: &unified::LeaseBinding, stop: &AtomicBool, capture: &SharedCapture) -> bool {
    if let Err(error) = lease.verify() {
        capture.0.lock().unwrap_or_else(|error| error.into_inner()).lease_error = Some(error);
        stop.store(true, Ordering::Release);
        capture.1.notify_all();
        return false;
    }
    true
}

#[derive(Default)]
struct Registry {
    sessions: BTreeMap<String, Arc<Session>>,
    revoking: bool,
    closed: bool,
}
struct Manager {
    root: PathBuf,
    profile: Arc<RwLock<DesktopProfile>>,
    registry: Mutex<Registry>,
    unified: Option<unified::Configuration>,
}
impl Manager {
    fn authorized(&self) -> ProcessResult<RwLockReadGuard<'_, DesktopProfile>> {
        match self.profile.read() {
            Ok(guard) if *guard == DesktopProfile::FullyUnlocked => Ok(guard),
            _ => Err("PROFILE_RESTRICTED_BY_OPERATOR: fully-unlocked is not active".into()),
        }
    }
    fn lookup(&self, id: &str) -> ProcessResult<Arc<Session>> {
        let registry = self.registry.lock().map_err(|_| "PROCESS_MANAGER_UNAVAILABLE".to_owned())?;
        if registry.closed || registry.revoking { return Err("PROCESS_MANAGER_STOPPING".into()); }
        registry.sessions.get(id).cloned().ok_or_else(|| "PROCESS_SESSION_UNKNOWN: session is not owned or has expired".into())
    }
    fn start(&self, args: &Map<String, Value>) -> ProcessResult<Value> {
        self.start_with_history(args, false)
    }

    fn start_with_history(&self, args: &Map<String, Value>, retain_history: bool) -> ProcessResult<Value> {
        let session;
        let wait;
        {
            let _authorized = self.authorized()?;
            let (spec, requested_wait) = parse_start(args, &self.root, self.unified.is_some())?;
            wait = requested_wait;
            if !spec.cwd.is_dir() { return Err("PROCESS_CWD_UNAVAILABLE: working directory does not exist".into()); }
            let mut registry = self.registry.lock().map_err(|_| "PROCESS_MANAGER_UNAVAILABLE".to_owned())?;
            if registry.closed || registry.revoking { return Err("PROCESS_MANAGER_STOPPING".into()); }
            while registry.sessions.len() >= MAX_SESSIONS {
                let oldest = registry.sessions.iter().filter(|(_, session)| session.cleanup_confirmed())
                    .min_by_key(|(_, session)| session.started).map(|(id, _)| id.clone());
                if let Some(id) = oldest { registry.sessions.remove(&id); }
                else { return Err("PROCESS_LIMIT_REACHED: terminate an owned session before starting another".into()); }
            }
            let mut id = new_session_id().map_err(|error| format!("PROCESS_ID_UNAVAILABLE: {error}"))?;
            while registry.sessions.contains_key(&id) {
                id = new_session_id().map_err(|error| format!("PROCESS_ID_UNAVAILABLE: {error}"))?;
            }
            let launch = self.unified.as_ref().map(|config| config.prepare(args, &spec.cwd, &id)).transpose()?;
            session = Session::start(id.clone(), spec, Arc::clone(&self.profile), retain_history, launch, wait)
                .map_err(|error| format!("PROCESS_START_FAILED: {error}"))?;
            registry.sessions.insert(id, Arc::clone(&session));
        }
        crate::client_sessions::link_command(session.command.as_ref());
        if let Err(error) = session.await_placement(wait) {
            session.request_stop();
            // Keep the owned Job and its diagnostics registered while the
            // worker stops it or until a verified cleanup can be retried.
            return Err(format!("PROCESS_AGENT_DESKTOP_PLACEMENT_FAILED: {error}; session_id={}", session.id));
        }
        let wait = if self.unified.is_some() { wait.saturating_sub(session.started.elapsed()) } else { wait };
        session.wait(wait);
        let _authorized = self.authorized()?;
        if self.unified.is_some() { self.require_current(&session)?; }
        Ok(session.snapshot())
    }

    fn require_current(&self, session: &Arc<Session>) -> ProcessResult<()> {
        if !Arc::ptr_eq(&self.lookup(&session.id)?, session) {
            return Err("PROCESS_SESSION_UNKNOWN: session is no longer owned".into());
        }
        Ok(())
    }

    fn read(&self, args: &Map<String, Value>) -> ProcessResult<Value> {
        let (session, wait) = {
            let _authorized = self.authorized()?;
            fields(args, &["session_id", "timeout_ms"])?;
            (self.lookup(session_id(args)?)?, timeout(args, 1000, 30_000)?)
        };
        session.wait(wait);
        let _authorized = self.authorized()?;
        Ok(session.snapshot())
    }
    fn read_history(&self, args: &Map<String, Value>) -> ProcessResult<Value> {
        let (session, offset, length, wait) = {
            let _authorized = self.authorized()?;
            fields(args, &["session_id", "offset", "length", "timeout_ms"])?;
            let offset = match args.get("offset") {
                None => 0,
                Some(value) => value.as_i64().filter(|v| (-100_000..=100_000).contains(v))
                    .ok_or_else(|| invalid("offset must be an integer from -100000 to 100000"))?,
            };
            let length = match args.get("length") {
                None => 1000,
                Some(value) => value.as_u64().filter(|v| (1..=5000).contains(v))
                    .ok_or_else(|| invalid("length must be an integer from 1 to 5000"))? as usize,
            };
            (self.lookup(session_id(args)?)?, offset, length, timeout(args, 1000, 30_000)?)
        };
        let (lock, changed) = &*session.capture;
        let state = lock.lock().map_err(|_| "PROCESS_CAPTURE_UNAVAILABLE")?;
        if state.history.is_none() { return Err("PROCESS_HISTORY_UNAVAILABLE".into()); }
        if offset == 0 && !wait.is_zero() {
            let (guard, _) = changed.wait_timeout_while(state, wait, |s| {
                !s.finished && s.input_error.is_none() && s.history.as_ref().is_some_and(|h| !h.unread())
            }).map_err(|_| "PROCESS_CAPTURE_UNAVAILABLE")?;
            drop(guard);
        } else { drop(state); }
        let _authorized = self.authorized()?;
        // A full downgrade/re-upgrade can finish during the wait. Its old
        // Arc remains alive here even if revocation removed the capability.
        self.require_current(&session)?;
        let mut state = lock.lock().map_err(|_| "PROCESS_CAPTURE_UNAVAILABLE")?;
        let mut receipt = session.receipt(&state, String::new(), String::new());
        let page = state.history.as_mut().ok_or("PROCESS_HISTORY_UNAVAILABLE")?.read(offset, length);
        if let Value::Object(fields) = page {
            receipt.as_object_mut().expect("session receipt").extend(fields);
        }
        Ok(receipt)
    }
    fn interact(&self, args: &Map<String, Value>) -> ProcessResult<Value> {
        let unified = self.unified.is_some();
        let (session, wait, wait_for_prompt, input_id, output_mark, input_bytes) = {
            let _authorized = self.authorized()?;
            let wait_for_prompt = if unified {
                fields(args, &["session_id", "input", "eof", "timeout_ms", "wait_for_prompt"])?;
                match args.get("wait_for_prompt") {
                    None => true,
                    Some(Value::Bool(value)) => *value,
                    _ => return Err(invalid("wait_for_prompt must be boolean")),
                }
            } else {
                fields(args, &["session_id", "input", "eof", "timeout_ms"])?;
                true
            };
            let eof = match args.get("eof") {
                None => false,
                Some(Value::Bool(value)) => *value,
                _ => return Err(invalid("eof must be boolean")),
            };
            let text = match args.get("input") {
                None if eof => "",
                Some(Value::String(text)) if text.len() <= MAX_INPUT_BYTES => text,
                _ => return Err(invalid("input must be a string of at most 65536 bytes, or eof must be true")),
            };
            if text.is_empty() && !eof { return Err(invalid("provide nonempty input or eof:true")); }
            let wait = timeout(args, if unified { 8000 } else { 1000 }, 30_000)?;
            let session = self.lookup(session_id(args)?)?;
            let (input_id, output_mark) = session.queue_input(text.as_bytes().to_vec(), eof)?;
            (session, wait, wait_for_prompt, input_id, output_mark, text.len())
        };
        let mut result = if unified {
            session.interaction_receipt(input_id, output_mark, wait_for_prompt, wait)
        } else {
            session.wait(wait);
            Value::Null
        };
        let _authorized = self.authorized()?;
        if unified { self.require_current(&session)?; } else { result = session.snapshot(); }
        result["input_queued"] = json!(true);
        result["input_id"] = json!(input_id);
        result["input_bytes"] = json!(input_bytes);
        Ok(result)
    }
    fn terminate(&self, args: &Map<String, Value>) -> ProcessResult<Value> {
        let session = {
            let _authorized = self.authorized()?;
            fields(args, &["session_id"])?;
            let session = self.lookup(session_id(args)?)?;
            session.request_stop();
            session
        };
        session.join_until(Instant::now() + CLEANUP_TIMEOUT + Duration::from_secs(1))
            .map_err(|error| format!("PROCESS_TERMINATION_INCOMPLETE: {error}"))?;
        let _authorized = self.authorized()?;
        Ok(session.snapshot())
    }
    fn revoke(&self, permanently: bool) -> io::Result<()> {
        let sessions = {
            let mut registry = self.registry.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.revoking = true;
            registry.closed |= permanently;
            registry.sessions.values().cloned().collect::<Vec<_>>()
        };
        // Signal all children before waiting for any of them. No profile lock
        // is acquired here; the caller may already hold its write guard.
        for session in &sessions { session.request_stop(); }
        let deadline = Instant::now() + CLEANUP_TIMEOUT + Duration::from_secs(1);
        let mut error = None;
        for session in &sessions {
            if let Err(failure) = session.join_until(deadline) { error.get_or_insert(failure); }
        }
        if let Some(error) = error { return Err(error); }
        let mut registry = self.registry.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        registry.sessions.clear();
        registry.revoking = false;
        Ok(())
    }
}

pub(crate) struct SessionSupervisor {
    manager: Arc<Manager>,
}
impl SessionSupervisor {
    pub(super) fn shutdown(&mut self) -> io::Result<()> { self.manager.revoke(true) }
    pub(super) fn revoker(&self) -> Arc<dyn Fn() -> Result<(), RuntimeError> + Send + Sync> {
        let manager = Arc::clone(&self.manager);
        Arc::new(move || manager.revoke(false).map_err(Into::into))
    }
}
impl Drop for SessionSupervisor {
    fn drop(&mut self) { let _ = self.shutdown(); }
}

fn result(response: ProcessResult<Value>) -> ToolCallResult {
    match response {
        Ok(value) => ToolCallResult::text(value.to_string()),
        Err(error) => ToolCallResult::tool_error(error),
    }
}

pub(super) fn attach(
    root: &Path, catalog: &mut Vec<ToolDefinition>, handlers: &mut ToolMapHandler,
    profile: Arc<RwLock<DesktopProfile>>,
) -> Result<SessionSupervisor, RuntimeError> {
    attach_manager(root, catalog, handlers, profile, None)
}

pub(super) fn attach_unified(
    root: &Path, catalog: &mut Vec<ToolDefinition>, handlers: &mut ToolMapHandler,
    profile: Arc<RwLock<DesktopProfile>>, desktops: crate::agent_desktop::AgentDesktopHandle,
    private_root: &Path,
) -> Result<SessionSupervisor, RuntimeError> {
    attach_manager(root, catalog, handlers, profile, Some(unified::Configuration {
        desktops, private_root: private_root.to_owned(),
    }))
}

fn attach_manager(
    root: &Path, catalog: &mut Vec<ToolDefinition>, handlers: &mut ToolMapHandler,
    profile: Arc<RwLock<DesktopProfile>>, unified: Option<unified::Configuration>,
) -> Result<SessionSupervisor, RuntimeError> {
    let use_history = unified.is_some();
    let manager = Arc::new(Manager {
        root: root.to_owned(), profile, registry: Mutex::new(Registry::default()), unified,
    });
    let starts = Arc::clone(&manager);
    handlers.register("desktop_start_process", move |args| Ok(result(if use_history {
        starts.start_with_history(&args, true)
    } else { starts.start(&args) })));
    catalog.push(ToolDefinition::new("desktop_start_process", Some(
        "Start a current-user shell command or literal program+args only in this startup-authorized Fully Unlocked session. Shells: pwsh, powershell, cmd, sh, bash. The session ends with its root program and stops descendants in its owned Windows Job or Unix process group. Use a persistent root program for long-running work. timeout_ms bounds the response wait, not program lifetime; later reads consume progressive output. No external PID, elevation or implicit shell fallback.".into()),
        json!({"type":"object","additionalProperties":false,
            "oneOf":[{"required":["command"]},{"required":["program"]}],
            "properties":{
                "command":{"type":"string","minLength":1,"maxLength":65536},
                "shell":{"type":"string","enum":["pwsh","powershell","cmd","sh","bash"]},
                "program":{"type":"string","minLength":1,"maxLength":8192},
                "args":{"type":"array","maxItems":128,"items":{"type":"string","maxLength":65536}},
                "cwd":{"type":"string","minLength":1,"maxLength":8192,
                    "description":"Defaults to project root. Windows cmd requires an equivalent ordinary DOS directory; UNC, long or verbatim-only cwd are refused before launch."},
                "timeout_ms":{"type":"integer","minimum":0,"maximum":30000,"default":1000}
            }})));
    let reads = Arc::clone(&manager);
    handlers.register("desktop_read_process", move |args| Ok(result(if use_history {
        reads.read_history(&args)
    } else { reads.read(&args) })));
    catalog.push(ToolDefinition::new("desktop_read_process", Some(
        "Consume new UTF-8 stdout/stderr from this gateway's owned session, with bounded output, truncation, exit and EOF status. timeout_ms waits for output or completion without holding the operator profile lock.".into()),
        json!({"type":"object","additionalProperties":false,"required":["session_id"],
            "properties":{"session_id":{"type":"string","format":"uuid"},
                "timeout_ms":{"type":"integer","minimum":0,"maximum":30000,"default":1000}}})));
    let interacts = Arc::clone(&manager);
    handlers.register("desktop_interact_process", move |args| Ok(result(interacts.interact(&args))));
    catalog.push(ToolDefinition::new("desktop_interact_process", Some(
        "Queue at most 65536 UTF-8 bytes to owned stdin without blocking the dispatcher, optionally followed by EOF. input_queued confirms acceptance, not completion: do not resend an accepted frame. No newline is added. Read input_completed_through/input_error and progressive stdout/stderr in the result.".into()),
        json!({"type":"object","additionalProperties":false,"required":["session_id"],
            "anyOf":[{"required":["input"]},{"required":["eof"],"properties":{"eof":{"const":true}}}],
            "properties":{"session_id":{"type":"string","format":"uuid"},
                "input":{"type":"string","maxLength":65536},"eof":{"type":"boolean"},
                "timeout_ms":{"type":"integer","minimum":0,"maximum":30000,"default":1000}}})));
    handlers.register("desktop_terminate_process", {
        let manager = Arc::clone(&manager);
        move |args| Ok(result(manager.terminate(&args)))
    });
    catalog.push(ToolDefinition::new("desktop_terminate_process", Some(
        "Stop and join this gateway's owned process tree and pipes. Only its opaque session capability is accepted; no external PID is discoverable or targetable.".into()),
        json!({"type":"object","additionalProperties":false,"required":["session_id"],
            "properties":{"session_id":{"type":"string","format":"uuid"}}})));
    if use_history {
        let first = catalog.len() - 4;
        unified::describe(&mut catalog[first..]);
    }
    Ok(SessionSupervisor { manager })
}
