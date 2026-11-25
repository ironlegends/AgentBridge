//! Operator-approved, instance-owned diagnostic process sessions.
//! No shell, arbitrary argv, elevation, public PID, or shared process discovery.
//! All launches consume the same exact pinned-command policy as terminal::run.

#[cfg(windows)]
use super::{operator_confirmation, private_files};
use agent_bridge_commands::{
    CommandDecisionEngine, CommandRequest, EngineLimits, EnvironmentVerifier,
    ExecutionGate, ExecutionOutcome, ExecutionPermit, FsEnvironmentVerifier,
    OperatorPolicy, RequestId, RequesterContext, SubmissionOutcome,
};
use agent_bridge_gateway::{ToolCallResult, ToolDefinition, ToolMapHandler};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;
#[cfg(windows)]
use agent_bridge_lifecycle::git_revision_windows::{
    RestrictedProjectProcess, ProjectProcessSnapshot,
};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex, mpsc::{self, Receiver, SyncSender, TrySendError, RecvTimeoutError}, atomic::{AtomicBool, Ordering}};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

type ProcessResult<T> = Result<T, &'static str>;

const MAX_SESSIONS: usize = 4;
const MAX_STREAM_BYTES: usize = 64 * 1024;
const MAX_SESSION_AGE: Duration = Duration::from_secs(120);
const COMPLETED_RETENTION: Duration = Duration::from_secs(30);
const TOMBSTONE_RETENTION: Duration = Duration::from_secs(300);
const MAX_TOMBSTONES: usize = 32;
const WATCHDOG_TICK: Duration = Duration::from_millis(250);
const MAX_METADATA_REQUESTS: usize = 32;
const MAX_METADATA_INPUT: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Diagnostic { GitVersion, RustVersion, WorkspaceFileInfo, ProjectProgram }
impl Diagnostic {
    fn parse(raw: &str) -> ProcessResult<Self> {
        match raw {
            "git-version" => Ok(Self::GitVersion),
            "rust-version" => Ok(Self::RustVersion),
            "workspace-file-info" => Ok(Self::WorkspaceFileInfo),
            _ => Err("PROCESS_NOT_PREDEFINED: only fixed version or workspace-file-info diagnostics are supported"),
        }
    }
    fn id(self) -> &'static str {
        match self {
            Self::GitVersion => "git-version",
            Self::RustVersion => "rust-version",
            Self::WorkspaceFileInfo => "workspace-file-info",
            Self::ProjectProgram => "project-program",
        }
    }
    fn image(self) -> ProcessResult<String> {
        if self.metadata() {
            // The private helper is this exact host executable, including a
            // native desktop host name. The catalog SHA, canonical path and
            // current-process identity are independently checked below.
            let host = std::env::current_exe()
                .map_err(|_| "PROCESS_IMAGE_DENIED: current Agent Bridge image unavailable")?;
            return host.file_stem().and_then(|name| name.to_str()).map(str::to_owned)
                .ok_or("PROCESS_IMAGE_DENIED: current image name is unavailable");
        }
        Ok(match self {
            Self::GitVersion => "git",
            Self::RustVersion => "rustc",
            Self::ProjectProgram => "project-program",
            Self::WorkspaceFileInfo => unreachable!("metadata host was selected above"),
        }.to_owned())
    }
    fn metadata(self) -> bool { matches!(self, Self::WorkspaceFileInfo) }
    fn argv(self, root: &Path, binding: &str) -> ProcessResult<Vec<String>> {
        if self.metadata() {
            let path = root.to_str()
                .ok_or("PROCESS_WORKSPACE_UNAVAILABLE: workspace path is not UTF-8")?;
            Ok(vec!["__workspace-file-info-child-v1".into(), path.into(), binding.into()])
        } else {
            Ok(vec!["--version".into()])
        }
    }
}

// Derived from the cryptographically random command request ID, but formatted
// as a fresh opaque UUIDv4-shaped session identifier. Never exposes a PID.
fn session_uuid(request: &RequestId) -> ProcessResult<String> {
    let raw = request.as_str();
    if raw.len() != 32 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("PROCESS_ID_UNAVAILABLE: invalid internal random identifier");
    }
    Ok(format!("{}-{}-4{}-8{}-{}", &raw[..8], &raw[8..12],
        &raw[13..16], &raw[17..20], &raw[20..32]))
}

fn valid_session_id(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == 36 && [8,13,18,23].iter().all(|&i| b[i] == b'-')
        && b[14] == b'4' && b[19] == b'8'
        && b.iter().enumerate().all(|(i,&x)| {
            [8,13,18,23].contains(&i) || x.is_ascii_hexdigit()
        })
}

#[derive(Default)]
struct Captured {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
    stdout_eof: bool,
    stderr_eof: bool,
}
type SharedCapture = Arc<(Mutex<Captured>, Condvar)>;

fn drain_stream<R: Read + Send + 'static>(
    mut pipe: R, shared: SharedCapture, is_stdout: bool,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new().name("agent-bridge-diagnostic-drain".into()).spawn(move || {
        let mut block = [0u8; 4096];
        loop {
            let read = pipe.read(&mut block);
            let (lock, changed) = &*shared;
            let Ok(mut captured) = lock.lock() else { return; };
            match read {
                Ok(0) => {
                    if is_stdout { captured.stdout_eof = true; }
                    else { captured.stderr_eof = true; }
                    changed.notify_all();
                    break;
                }
                Ok(n) => {
                    if is_stdout {
                        let keep = n.min(MAX_STREAM_BYTES.saturating_sub(captured.stdout.len()));
                        captured.stdout.extend_from_slice(&block[..keep]);
                        captured.stdout_truncated |= keep != n;
                    } else {
                        let keep = n.min(MAX_STREAM_BYTES.saturating_sub(captured.stderr.len()));
                        captured.stderr.extend_from_slice(&block[..keep]);
                        captured.stderr_truncated |= keep != n;
                    }
                    changed.notify_all();
                }
                Err(_) => {
                    if is_stdout {
                        captured.stdout_truncated = true;
                        captured.stdout_eof = true;
                    } else {
                        captured.stderr_truncated = true;
                        captured.stderr_eof = true;
                    }
                    changed.notify_all();
                    break;
                }
            }
        }
    })
}

// The only stdin writer is an isolated worker. It consumes typed JSON frames
// from a bounded, nonblocking queue; session locks never cover pipe I/O.
struct MetadataJob {
    frame: Vec<u8>,
    reply: SyncSender<ProcessResult<Value>>,
}
fn metadata_worker(
    mut stdin: Box<dyn Write + Send>,
    stdout: ChildStdout,
    queue: Receiver<MetadataJob>,
    stop: Arc<AtomicBool>,
    capture: SharedCapture,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new().name("agent-bridge-metadata-ipc".into()).spawn(move || {
        let mut reader = BufReader::new(stdout);
        while !stop.load(Ordering::SeqCst) {
            let job = match queue.recv_timeout(Duration::from_millis(50)) {
                Ok(job) => job,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break,
            };
            if stop.load(Ordering::SeqCst) { break; }
            let reply = (|| -> ProcessResult<Value> {
                // The exact bytes come from a locally validated operation/path,
                // not from an arbitrary remote stdin string.
                stdin.write_all(&job.frame)
                    .map_err(|_| "PROCESS_PIPE_CLOSED: metadata child input closed")?;
                stdin.flush()
                    .map_err(|_| "PROCESS_PIPE_CLOSED: metadata child input failed")?;
                let bytes = super::metadata_child::bounded_line(&mut reader)
                    .map_err(|_| "PROCESS_PROTOCOL_INVALID: child response exceeds limit")?
                    .ok_or("PROCESS_CHILD_EOF: metadata child closed output")?;
                let reply = serde_json::from_slice::<Value>(&bytes)
                    .map_err(|_| "PROCESS_PROTOCOL_INVALID: child returned invalid JSON")?;
                if !reply["ok"].is_boolean()
                    || (reply["ok"] == true && (
                        reply["operation"] != "get_file_info"
                        || reply["metadata"]["kind"] != "file"
                    ))
                {
                    return Err("PROCESS_PROTOCOL_INVALID: unexpected child response");
                }
                let (lock, changed) = &*capture;
                let mut state = lock.lock()
                    .map_err(|_| "PROCESS_OUTPUT_UNAVAILABLE: output lock poisoned")?;
                let keep = (bytes.len() + 1)
                    .min(MAX_STREAM_BYTES.saturating_sub(state.stdout.len()));
                if keep > 0 {
                    let written = keep.min(bytes.len());
                    state.stdout.extend_from_slice(&bytes[..written]);
                    if keep > written { state.stdout.push(b'\n'); }
                }
                state.stdout_truncated |= keep < bytes.len() + 1;
                changed.notify_all();
                Ok(reply)
            })();
            let failed = reply.is_err();
            let _ = job.reply.try_send(reply);
            if failed { break; }
        }
        drop(stdin); // EOF is cooperative shutdown for this dedicated child.
        let (lock, changed) = &*capture;
        if let Ok(mut state) = lock.lock() {
            state.stdout_eof = true;
            changed.notify_all();
        }
    })
}

struct Session {
    diagnostic: Diagnostic,
    child: Child,
    capture: SharedCapture,
    metadata_queue: Option<SyncSender<MetadataJob>>,
    worker_stop: Arc<AtomicBool>,
    pending_deadline: Option<Instant>,
    shutdown_deadline: Option<Instant>,
    requests_started: usize,
    stdout_reader: Option<JoinHandle<()>>,
    stderr_reader: Option<JoinHandle<()>>,
    gate: ExecutionGate,
    permit: Option<ExecutionPermit>,
    // None: running. Some(None): terminated without a normal exit code.
    exit: Option<Option<i32>>,
    stop_requested: bool,
    started: Instant,
    last_used: Instant,
    #[cfg(windows)]
    _image_guard: fs::File,
}

impl Session {
    fn new(
        diagnostic: Diagnostic, child: Child,
        gate: ExecutionGate, permit: ExecutionPermit,
        #[cfg(windows)] image_guard: fs::File,
        #[cfg(unix)] metadata_input: Option<fs::File>,
    ) -> ProcessResult<Self> {
        let shared: SharedCapture = Arc::new((Mutex::new(Captured::default()), Condvar::new()));
        let mut owned = Self {
            diagnostic, child, capture: shared,
            metadata_queue: None, worker_stop: Arc::new(AtomicBool::new(false)),
            pending_deadline: None, shutdown_deadline: None, requests_started: 0,
            stdout_reader: None, stderr_reader: None,
            gate, permit: Some(permit), exit: None,
            stop_requested: false, started: Instant::now(),
            last_used: Instant::now(),
            #[cfg(windows)]
            _image_guard: image_guard,
        };
        let out = owned.child.stdout.take()
            .ok_or("PROCESS_PIPE_UNAVAILABLE: stdout pipe missing")?;
        if diagnostic.metadata() {
            #[cfg(unix)]
            let stdin: Box<dyn Write + Send> = Box::new(metadata_input
                .ok_or("PROCESS_PIPE_UNAVAILABLE: private metadata capability channel missing")?);
            #[cfg(not(unix))]
            let stdin: Box<dyn Write + Send> = Box::new(owned.child.stdin.take()
                .ok_or("PROCESS_PIPE_UNAVAILABLE: child metadata stdin missing")?);
            let (sender, queue) = mpsc::sync_channel::<MetadataJob>(1);
            owned.stdout_reader = Some(metadata_worker(
                stdin, out, queue, Arc::clone(&owned.worker_stop),
                Arc::clone(&owned.capture),
            ).map_err(|_| "PROCESS_PIPE_UNAVAILABLE: cannot start metadata worker")?);
            owned.metadata_queue = Some(sender);
        } else {
            owned.stdout_reader = Some(drain_stream(out, Arc::clone(&owned.capture), true)
                .map_err(|_| "PROCESS_PIPE_UNAVAILABLE: cannot start stdout reader")?);
        }
        if let Some(err) = owned.child.stderr.take() {
            owned.stderr_reader = Some(drain_stream(err, Arc::clone(&owned.capture), false)
                .map_err(|_| "PROCESS_PIPE_UNAVAILABLE: cannot start stderr reader")?);
        } else {
            let (lock, changed) = &*owned.capture;
            let mut output = lock.lock().map_err(|_| "PROCESS_OUTPUT_UNAVAILABLE: lock failed")?;
            output.stderr_eof = true;
            changed.notify_all();
        }
        Ok(owned)
    }

    fn poll(&mut self) -> ProcessResult<()> {
        if self.exit.is_some() { return Ok(()); }
        let status = self.child.try_wait()
            .map_err(|_| "PROCESS_STATUS_UNAVAILABLE: cannot inspect owned child")?;
        let Some(status) = status else { return Ok(()); };
        let code = status.code();
        self.exit = Some(code);
        if let Some(permit) = self.permit.take() {
            let outcome = match code {
                Some(exit_code) => ExecutionOutcome::Completed {
                    exit_code, summary: None,
                },
                None => ExecutionOutcome::Uncertain {
                    reason_code: "exit_status_unavailable".into(),
                },
            };
            self.gate.finish(permit, outcome)
                .map_err(|_| "PROCESS_RECEIPT_UNAVAILABLE: owned child exited")?;
        }
        Ok(())
    }

    fn read(&mut self, id: &str, offset: i64, length: usize) -> ProcessResult<Value> {
        self.poll()?;
        self.last_used = Instant::now();
        let (lock, _) = &*self.capture;
        let captured = lock.lock()
            .map_err(|_| "PROCESS_OUTPUT_UNAVAILABLE: capture lock failed")?;
        let stdout = String::from_utf8_lossy(&captured.stdout);
        let stderr = String::from_utf8_lossy(&captured.stderr);
        // Count lines without allocating one JSON object per captured line.
        // Even a stream consisting entirely of newlines stays bounded.
        let total = stdout.lines().count() + stderr.lines().count();
        let start = if offset < 0 {
            total.saturating_sub(offset.unsigned_abs() as usize)
        } else {
            (offset as usize).min(total)
        };
        let end = start.saturating_add(length).min(total);
        let lines = stdout.lines()
            .map(|line| json!({"stream":"stdout","text":line}))
            .chain(stderr.lines()
                .map(|line| json!({"stream":"stderr","text":line})))
            .skip(start).take(end - start).collect::<Vec<_>>();
        let content = lines.iter()
            .filter_map(|row| row.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>().join("\n");
        Ok(json!({
            "session_id":id, "diagnostic":self.diagnostic.id(),
            "running":self.exit.is_none(), "exit_code":self.exit.flatten(),
            "stop_requested":self.stop_requested,
            "offset":start, "length":end-start, "total_lines":total,
            "has_more":end<total, "content":content, "lines":lines,
            "stdout_truncated":captured.stdout_truncated,
            "stderr_truncated":captured.stderr_truncated,
            "output_complete":captured.stdout_eof && captured.stderr_eof,
        }))
    }
    // Request EOF to the dedicated child's worker before force-stopping only
    // our owned child. No potentially blocking pipe read/write runs here.
    fn close_owned(&mut self) -> bool {
        self.worker_stop.store(true, Ordering::SeqCst);
        self.metadata_queue.take();
        self.pending_deadline = None;
        if self.diagnostic.metadata() && self.exit.is_none() {
            let grace = Instant::now() + Duration::from_millis(200);
            while self.exit.is_none() && Instant::now() < grace {
                let _ = self.poll();
                if self.exit.is_none() { thread::sleep(Duration::from_millis(10)); }
            }
        }
        if self.exit.is_none() {
            self.stop_requested = true;
            let _ = self.child.kill();
            let deadline = Instant::now() + Duration::from_millis(300);
            while self.exit.is_none() && Instant::now() < deadline {
                let _ = self.poll();
                if self.exit.is_none() { thread::sleep(Duration::from_millis(10)); }
            }
        }
        if self.exit.is_none() { return false; }
        let readers_done = || {
            self.stdout_reader.as_ref().is_none_or(JoinHandle::is_finished)
                && self.stderr_reader.as_ref().is_none_or(JoinHandle::is_finished)
        };
        let deadline = Instant::now() + Duration::from_millis(300);
        while !readers_done() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        if !readers_done() { return false; }
        if let Some(reader) = self.stdout_reader.take() { let _ = reader.join(); }
        if let Some(reader) = self.stderr_reader.take() { let _ = reader.join(); }
        true
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        // Error paths during process registration must not detach an output
        // reader. Drop waits until this owned child is reaped and both workers
        // have been joined, including when initialization fails halfway.
        while !self.close_owned() {
            thread::sleep(Duration::from_millis(25));
        }
    }
}

struct EndedSession {
    diagnostic: Diagnostic,
    reason: &'static str,
    exit_code: Option<i32>,
    finished_at: Instant,
}
impl EndedSession {
    fn view(&self, id: &str) -> Value {
        json!({
            "session_id": id, "diagnostic": self.diagnostic.id(),
            "running": false, "closed": true, "exit_code": self.exit_code,
            "end_reason": self.reason, "output_retained": false,
            "child_reaped": true, "readers_closed": true,
        })
    }
}

/// A live, locally approved, restricted project session. The owned Windows Job
/// and all private path pins are kept until terminate, watchdog expiry or EOF.
#[cfg(all(windows, not(test)))]
type ProjectProcessOwner = RestrictedProjectProcess;
#[cfg(all(windows, test))]
type ProjectProcessOwner = tests::ProjectProcessUnderTest;

#[cfg(windows)]
struct LiveProject {
    native: ProjectProcessOwner,
    gate: ExecutionGate,
    permit: Option<ExecutionPermit>,
    // Only the exact locally predefined public-echo program can accept typed
    // stdin; all other human-confirmed binaries default to stdin DENIED.
    typed_stdin: bool,
    started: Instant,
    last_used: Instant,
    completed_at: Option<Instant>,
}
#[cfg(windows)]
impl LiveProject {
    fn finish(&mut self, outcome: ExecutionOutcome) -> ProcessResult<()> {
        if let Some(permit)=self.permit.take() {
            self.gate.finish(permit,outcome).map_err(|_|
                "PROCESS_RECEIPT_UNAVAILABLE: cannot record owned project outcome")?;
        }
        Ok(())
    }
    fn snapshot(&mut self)->ProcessResult<ProjectProcessSnapshot> {
        let output=match self.native.snapshot() {
            Ok(output)=>output,
            Err(_)=>{
                let _=self.finish(ExecutionOutcome::Uncertain{
                    reason_code:"project_observation_uncertain".into(),
                });
                return Err("PROCESS_RESTRICTED_UNCERTAIN: owned Job observation failed");
            }
        };
        if !output.running {
            self.completed_at.get_or_insert_with(Instant::now);
            self.finish(ExecutionOutcome::Completed{
                exit_code:output.exit_code.unwrap_or(1) as i32,summary:None,
            })?;
        }
        Ok(output)
    }
    fn read(&mut self,id:&str,offset:i64,length:usize,timeout:Duration)->ProcessResult<Value> {
        let mut output=self.snapshot()?;
        let until=Instant::now()+timeout;
        // Wait only for the FIRST output or process completion, never for a
        // program to exit. All later reads are nonblocking snapshots.
        while output.running && output.stdout.is_empty() && output.stderr.is_empty()
            && Instant::now()<until {
            thread::sleep(Duration::from_millis(20));
            output=self.snapshot()?;
        }
        self.last_used=Instant::now();
        let total=output.stdout.lines().count()+output.stderr.lines().count();
        let start=if offset<0 {
            total.saturating_sub(offset.unsigned_abs() as usize)
        } else {(offset as usize).min(total)};
        let end=start.saturating_add(length).min(total);
        let lines=output.stdout.lines().map(|line|json!({"stream":"stdout","text":line}))
            .chain(output.stderr.lines().map(|line|json!({"stream":"stderr","text":line})))
            .skip(start).take(end-start).collect::<Vec<_>>();
        let content=lines.iter().filter_map(|line|line["text"].as_str())
            .collect::<Vec<_>>().join("\n");
        Ok(json!({
            "session_id":id,"diagnostic":"project-program",
            "running":output.running,"exit_code":output.exit_code,
            "offset":start,"length":end-start,"total_lines":total,"has_more":end<total,
            "content":content,"lines":lines,
            "stdout_truncated":output.stdout_truncated,
            "stderr_truncated":output.stderr_truncated,
            "output_complete":output.output_complete,
            "process_owned":true,"child_reaped":!output.running,
        }))
    }
    fn interact(&mut self,id:&str,input:&str,timeout:Duration,wait_for_output:bool)
        ->ProcessResult<Value>
    {
        if !self.typed_stdin {
            return Err("PROCESS_INPUT_DENIED: only an exact predefined public-echo protocol can receive stdin");
        }
        let value:Value=serde_json::from_str(input)
            .map_err(|_|"PROCESS_INPUT_DENIED: expected a typed public JSON request")?;
        let obj=value.as_object()
            .ok_or("PROCESS_INPUT_DENIED: expected a JSON object")?;
        if obj.len()!=3 || obj["operation"]!="echo" {
            return Err("PROCESS_OPERATION_DENIED: public echo operation only");
        }
        let phrase=obj["phrase"].as_str()
            .ok_or("PROCESS_INPUT_DENIED: public echo phrase must be text")?;
        let delay=obj["delay_ms"].as_u64()
            .ok_or("PROCESS_INPUT_DENIED: public echo delay must be an integer")?;
        if phrase.is_empty() || phrase.len()>96 || delay>3000
            || !phrase.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c,' '|'_'|'-')) {
            return Err("PROCESS_INPUT_DENIED: public echo values outside fixed local contract");
        }
        let initial=self.snapshot()?;
        if !initial.running {
            return Err("PROCESS_SESSION_CLOSED: project process already finished");
        }
        let before=initial.stdout.len()+initial.stderr.len();
        let mut frame=serde_json::to_vec(&json!({
            "operation":"echo","phrase":phrase,"delay_ms":delay,
        })).map_err(|_|"PROCESS_INPUT_DENIED: cannot encode public echo request")?;
        frame.push(b'\n');
        self.native.input(&frame).map_err(|_|
            "PROCESS_PIPE_CLOSED: restricted child refused bounded typed input")?;
        self.last_used=Instant::now();
        let mut new_bytes=false;
        if wait_for_output {
            let until=Instant::now()+timeout;
            while Instant::now()<until {
                let state=self.snapshot()?;
                if state.stdout.len()+state.stderr.len()>before || !state.running {
                    new_bytes=true;break;
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
        Ok(json!({
            "session_id":id,"accepted":true,"operation":"echo",
            "input_bytes":frame.len(),"stdin_validated":true,
            "waited_for_output":wait_for_output,
            "new_output_observed":new_bytes,
            "read_with":"desktop_read_process"
        }))
    }
    fn terminate(&mut self)->ProcessResult<Option<i32>> {
        let output=self.native.terminate().map_err(|_| {
            let _=self.finish(ExecutionOutcome::Uncertain{
                reason_code:"project_termination_uncertain".into()
            });
            "PROCESS_CLEANUP_PENDING: owned restricted Job termination unconfirmed"
        })?;
        self.completed_at.get_or_insert_with(Instant::now);
        self.finish(ExecutionOutcome::Uncertain{
            reason_code:"project_terminated_by_owner".into(),
        })?;
        Ok(output.exit_code.map(|v|v as i32))
    }
}
#[cfg(windows)]
impl Drop for LiveProject {
    fn drop(&mut self) {
        if let Some(permit)=self.permit.take() {
            let _=self.gate.finish(permit,ExecutionOutcome::Uncertain{
                reason_code:"project_session_closed".into(),
            });
        }
        // native drop kills ONLY its own Job and closes all three stdio pipes.
    }
}

#[derive(Default)]
struct Registry {
    sessions: HashMap<String, Arc<Mutex<Session>>>,
    #[cfg(windows)]
    project_sessions: HashMap<String, Arc<Mutex<LiveProject>>>,
    ended: HashMap<String, EndedSession>,
}
impl Registry {
    fn active_count(&self)->usize {
        let count=self.sessions.len();
        #[cfg(windows)]
        {count+self.project_sessions.len()}
        #[cfg(not(windows))]
        {count}
    }
    fn remember_end(&mut self, id: String, diagnostic: Diagnostic,
        reason: &'static str, exit_code: Option<i32>)
    {
        if self.ended.len() >= MAX_TOMBSTONES {
            if let Some(oldest) = self.ended.iter()
                .min_by_key(|(_, mark)| mark.finished_at)
                .map(|(id, _)| id.clone()) {
                self.ended.remove(&oldest);
            }
        }
        self.ended.insert(id, EndedSession {
            diagnostic, reason, exit_code, finished_at: Instant::now(),
        });
    }
    fn prune(&mut self) {
        self.ended.retain(|_, mark| mark.finished_at.elapsed() < TOMBSTONE_RETENTION);
        #[cfg(windows)]
        {
            let mut expired=Vec::new();
            for (id,handle) in &self.project_sessions {
                let Ok(mut project)=handle.lock() else {continue;};
                let status=project.snapshot();
                let reason=if status.is_err() {
                    Some("restricted_uncertain")
                } else if project.started.elapsed() >= MAX_SESSION_AGE {
                    Some("expired")
                } else if project.completed_at.is_some()
                    && project.last_used.elapsed()>=COMPLETED_RETENTION {
                    Some("completed_retention")
                } else {None};
                if let Some(reason)=reason {
                    // An error or kill request is not proof that the owned
                    // Job is empty. Retain it for prune/Stop to retry.
                    if let Ok(exit)=project.terminate() {
                        expired.push((id.clone(),reason,exit));
                    }
                }
            }
            for (id,reason,exit) in expired {
                // Publish the tombstone only after verified termination,
                // even when another operation still retains this session.
                self.project_sessions.remove(&id);
                self.remember_end(id,Diagnostic::ProjectProgram,reason,exit);
            }
        }
        let mut completed = Vec::new();
        for (id, handle) in &self.sessions {
            let Ok(mut session) = handle.lock() else { continue; };
            let _ = session.poll();
            let now = Instant::now();
            let reason = if session.started.elapsed() >= MAX_SESSION_AGE {
                Some("expired")
            } else if session.pending_deadline.is_some_and(|deadline| now >= deadline) {
                Some("interaction_deadline")
            } else if session.shutdown_deadline.is_some_and(|deadline| now >= deadline) {
                Some("cooperative_shutdown")
            } else if session.exit.is_some()
                && session.last_used.elapsed() >= COMPLETED_RETENTION
            {
                Some("completed_retention")
            } else { None };
            if let Some(reason) = reason {
                if session.close_owned() {
                    completed.push((id.clone(), session.diagnostic,
                        reason, session.exit.flatten()));
                }
            }
        }
        for (id, diagnostic, reason, code) in completed {
            self.sessions.remove(&id);
            self.remember_end(id, diagnostic, reason, code);
        }
    }
    fn lookup(&self, id: &str) -> ProcessResult<Arc<Mutex<Session>>> {
        if !valid_session_id(id) {
            return Err("PROCESS_SESSION_UNKNOWN: invalid session capability");
        }
        self.sessions.get(id).cloned()
            .ok_or("PROCESS_SESSION_UNKNOWN: session is not owned or has expired")
    }
    fn ended_view(&self, id: &str) -> Option<Value> {
        self.ended.get(id).map(|mark| mark.view(id))
    }
}

// The stdio caller owns this supervisor explicitly, independently of all MCP
// handler Arcs. Shutdown joins the watchdog and waits for every owned child,
// output reader and IPC worker to finish before stdio may return.
pub(crate) struct SessionSupervisor {
    registry: Arc<Mutex<Registry>>,
    stop: Arc<AtomicBool>,
    watchdog: Option<JoinHandle<()>>,
}
impl SessionSupervisor {
    fn start(registry: Arc<Mutex<Registry>>) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker_registry = Arc::clone(&registry);
        let watchdog = thread::Builder::new()
            .name("agent-bridge-diagnostic-watchdog".into())
            .spawn(move || {
                while !worker_stop.load(Ordering::Acquire) {
                    thread::sleep(WATCHDOG_TICK);
                    if worker_stop.load(Ordering::Acquire) { break; }
                    // Poison is not an excuse to abandon still-owned children.
                    let mut owner = worker_registry.lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    owner.prune();
                }
            })?;
        Ok(Self { registry, stop, watchdog: Some(watchdog) })
    }

    /// The caller holds the Workstation live-profile write guard. Keep the
    /// watchdog alive so a later locally permitted mode can start sessions.
    pub(crate) fn revoker(&self) -> Arc<
        dyn Fn() -> Result<(), crate::runtime::RuntimeError> + Send + Sync,
    > {
        let registry = Arc::clone(&self.registry);
        Arc::new(move || revoke_owned_sessions(&registry).map_err(Into::into))
    }

    pub(crate) fn shutdown(&mut self) -> io::Result<()> {
        // This path is called at stdio EOF or failure, even if the client has
        // remained idle. The watchdog cannot outlive a completed stdio server.
        self.stop.store(true, Ordering::Release);
        let watchdog_failed = self.watchdog.take()
            .is_some_and(|thread| thread.join().is_err());
        cleanup_owned_sessions(&self.registry, "stdio_shutdown")?;
        if watchdog_failed {
            return Err(io::Error::other("Diagnostic watchdog thread failed during shutdown"));
        }
        Ok(())
    }
}
// Reuse each restricted session's verified cleanup, without stopping its
// supervisor. This is invoked under the runtime's admission write lock; no
// new MCP call can enter while the selected profile is being downgraded.
fn revoke_owned_sessions(registry: &Arc<Mutex<Registry>>) -> io::Result<()> {
    cleanup_owned_sessions(registry, "profile_revoked")
}

fn cleanup_owned_sessions(registry: &Arc<Mutex<Registry>>, reason: &'static str) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let sessions = {
            let owner = registry.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            owner.sessions.iter().map(|(id, handle)| (id.clone(), Arc::clone(handle)))
                .collect::<Vec<_>>()
        };
        for (id, handle) in sessions {
            let mut session = handle.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if session.close_owned() {
                let diagnostic = session.diagnostic;
                let exit = session.exit.flatten();
                drop(session);
                let mut owner = registry.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                owner.sessions.remove(&id);
                owner.remember_end(id, diagnostic, reason, exit);
            }
        }
        #[cfg(windows)]
        {
            let projects = {
                let owner = registry.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                owner.project_sessions.iter().map(|(id, handle)| (id.clone(), Arc::clone(handle)))
                    .collect::<Vec<_>>()
            };
            for (id, handle) in projects {
                let mut project = handle.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                let exit = project.terminate().map_err(io::Error::other)?;
                drop(project);
                let mut owner = registry.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                owner.project_sessions.remove(&id);
                owner.remember_end(id, Diagnostic::ProjectProgram, reason, exit);
            }
        }
        {
            let owner = registry.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if owner.active_count() == 0 { return Ok(()); }
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut,
                "Restricted process cleanup incomplete; owned sessions are retained"));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

impl Drop for SessionSupervisor {
    fn drop(&mut self) {
        // Covers errors and unwinding before the explicit stdio shutdown call;
        // never silently detach a watchdog JoinHandle.
        let _ = self.shutdown();
    }
}

fn fixed_start(
    settings: &Path, root: &Path, database: &Path, diagnostic: Diagnostic,
    workspace: Option<&agent_bridge_desktop::DesktopFiles>,
) -> ProcessResult<(String, Session)> {
    fixed_start_with_snapshot(settings,root,database,diagnostic,workspace,None)
}

fn fixed_start_with_snapshot(
    settings:&Path,root:&Path,database:&Path,diagnostic:Diagnostic,
    workspace:Option<&agent_bridge_desktop::DesktopFiles>,commands:Option<&super::CommandCatalogueSnapshot>,
)->ProcessResult<(String,Session)> {
    let entry = super::configured_command_with_snapshot(settings, root, diagnostic.id(), &diagnostic.image()?, true,commands)
        .map_err(|_| "PROCESS_NOT_LOCALLY_APPROVED: missing, disabled, or changed executable pin")?;
    let verifier = FsEnvironmentVerifier;
    let canonical_root = root.canonicalize()
        .map_err(|_| "PROCESS_WORKSPACE_UNAVAILABLE: project root cannot be verified")?;
    // Windows canonicalize can return a verbatim DOS path while the qualified
    // operator selection is a normal drive path. Recheck the physical root
    // through the existing pinned-directory mechanism instead of comparing
    // those two distinct path spellings.
    #[cfg(windows)]
    let _project_sid = agent_bridge_lifecycle::workspace_access::project_read_sid(root)
        .map_err(|_| "PROCESS_WORKSPACE_CHANGED: physical project pin unavailable")?;
    #[cfg(unix)]
    let project_handle = if diagnostic.metadata() {
        let files = workspace
            .ok_or("PROCESS_WORKSPACE_UNAVAILABLE: bound workspace handle missing")?;
        let handle = files.clone_workspace_root_handle()
            .map_err(|_| "PROCESS_WORKSPACE_CHANGED: selected path differs from the owned root")?;
        Some(agent_bridge_lifecycle::unix_project_handle::PreparedProjectDirectory::new(handle)
            .map_err(|_| "PROCESS_WORKSPACE_UNAVAILABLE: private capability transfer failed")?)
    } else { None };
    #[cfg(not(unix))]
    let _ = workspace;
    let binding = if diagnostic.metadata() {
        #[cfg(unix)]
        { project_handle.as_ref().expect("metadata capability was prepared").binding().to_owned() }
        #[cfg(not(unix))]
        { super::metadata_project_binding(root)
            .map_err(|_| "PROCESS_WORKSPACE_CHANGED: cannot bind selected physical project")? }
    } else { String::new() };
    let args = diagnostic.argv(root, &binding)?;
    let limits = EngineLimits::default();
    let policy = OperatorPolicy::builder(root)
        .add_predefined(diagnostic.id(), &entry.executable, entry.sha256, args.clone(), root)
        .build(&verifier, &limits)
        .map_err(|_| "PROCESS_PIN_VERIFICATION_FAILED: fixed diagnostic was not verified")?;
    let (client, _local_only_owner, gate) = CommandDecisionEngine::with_fs_verifier(
        policy, limits,
    ).split();
    let requester = RequesterContext::new("local-stdio")
        .map_err(|_| "PROCESS_POLICY_UNAVAILABLE: requester not available")?;
    let decision = client.submit(
        &requester, CommandRequest::new(&entry.executable, args, root),
    ).map_err(|_| "PROCESS_NOT_PREDEFINED: fixed diagnostic request refused")?;
    let request_id = match decision {
        SubmissionOutcome::PredefinedApproved { request_id, .. } => request_id,
        SubmissionOutcome::PendingLocalConfirmation { .. } => return Err(
            "PROCESS_NOT_PREDEFINED: interactive approval is not available through Web",
        ),
    };
    let session_id = session_uuid(&request_id)?;
    let permit = gate.consume(&request_id)
        .map_err(|_| "PROCESS_POLICY_REFUSED: pinned command permit unavailable")?;
    let verified = permit.command();
    let image = verified.executable.canonical_path.clone();
    let checked_args = verified.args.clone();
    if diagnostic.metadata() {
        // The distinct private commands.json entry must pin this exact running
        // Agent Bridge image, not a replacement executable with the same name.
        let running = std::env::current_exe()
            .map_err(|_| "PROCESS_IMAGE_DENIED: current Agent Bridge image unavailable")?;
        let image_now = verifier.verify_executable(&running)
            .map_err(|_| "PROCESS_IMAGE_DENIED: current image cannot be verified")?;
        if image_now != verified.executable {
            return Err("PROCESS_IMAGE_DENIED: catalog pin is not this Agent Bridge executable");
        }
    }

    #[cfg(windows)]
    let image_guard = {
        use std::os::windows::fs::OpenOptionsExt;
        let file = fs::OpenOptions::new().read(true).share_mode(1).open(&image)
            .map_err(|_| "PROCESS_PIN_LOST: cannot hold the pinned executable")?;
        if verifier.verify_executable(&image)
            .map_err(|_| "PROCESS_PIN_LOST: executable changed")? != verified.executable
        {
            return Err("PROCESS_PIN_LOST: executable identity changed after approval");
        }
        file
    };

    let mut cmd = Command::new(&image);
    cmd.args(&checked_args).env_clear().stdout(Stdio::piped());
    #[cfg(unix)]
    let metadata_input = if let Some(prepared) = project_handle {
        let (input, writer) = prepared.into_stdio();
        cmd.stdin(input).stderr(Stdio::null());
        Some(writer)
    } else {
        cmd.stdin(Stdio::null()).stderr(Stdio::piped());
        None
    };
    #[cfg(not(unix))]
    if diagnostic.metadata() {
        cmd.stdin(Stdio::piped()).stderr(Stdio::null());
    } else {
        cmd.stdin(Stdio::null()).stderr(Stdio::piped());
    }
    if diagnostic == Diagnostic::GitVersion {
        cmd.env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", if cfg!(windows) { "NUL" } else { "/dev/null" })
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_NO_OPTIONAL_LOCKS", "1")
            .env("GIT_CEILING_DIRECTORIES", canonical_root.parent().unwrap_or(&canonical_root));
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let directory = image.parent()
            .ok_or("PROCESS_PIN_LOST: diagnostic image directory not available")?;
        cmd.current_dir(directory).creation_flags(0x08000000);
    }
    #[cfg(not(windows))]
    {
        let _ = database;
        let directory = image.parent()
            .ok_or("PROCESS_PIN_LOST: diagnostic image directory not available")?;
        cmd.current_dir(directory);
    }
    #[cfg(windows)]
    let _ = database;

    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(_) => {
            let _ = gate.finish(permit, ExecutionOutcome::FailedBeforeStart {
                reason_code: "diagnostic_spawn_failed".into(),
            });
            return Err("PROCESS_START_FAILED: approved diagnostic could not start");
        }
    };
    #[cfg(windows)]
    let session = Session::new(
        diagnostic, child, gate, permit, image_guard,
    )?;
    #[cfg(unix)]
    let session = Session::new(
        diagnostic, child, gate, permit, metadata_input,
    )?;
    #[cfg(not(any(unix, windows)))]
    let session = Session::new(diagnostic, child, gate, permit)?;
    Ok((session_id, session))
}

/// One pinned restricted project .exe. Exact locally configured predefined
/// commands are admitted without impersonating a human; all other commands
/// require their own native local confirmation and receive NO stdin grant.
#[cfg(windows)]
fn project_start(settings:&Path,root:&Path,database:&Path,
    a:&Map<String,Value>,deadline:Duration)->ProcessResult<(String,LiveProject,bool)>
{
    project_start_with_snapshot(settings,root,database,a,deadline,None)
}

#[cfg(windows)]
fn project_start_with_snapshot(settings:&Path,root:&Path,database:&Path,
    a:&Map<String,Value>,deadline:Duration,commands:Option<&super::CommandCatalogueSnapshot>)
    ->ProcessResult<(String,LiveProject,bool)>
{
    use agent_bridge_lifecycle::git_revision_windows::{
        prepare_project_command,ProjectCommandSpec,GitRevisionError,
        require_project_launch_qualification,PROJECT_LOW_IL_UNQUALIFIED,
    };
    let executable=PathBuf::from(str_field(a,"executable")?);
    let cwd=PathBuf::from(str_field(a,"cwd")?);
    let requested=a.get("arguments").and_then(Value::as_array)
        .ok_or("PROCESS_INVALID_ARGUMENT: project arguments must be an array")?;
    if requested.len()>64 {
        return Err("PROCESS_INVALID_ARGUMENT: excessive project argument count");
    }
    let args=requested.iter().map(|v|v.as_str().map(str::to_owned)
        .ok_or("PROCESS_INVALID_ARGUMENT: each argument must be a literal string"))
        .collect::<ProcessResult<Vec<_>>>()?;
    // Only a *private* operator settings file can make a fixed exact command
    // predefined; the MCP request never supplies a digest or a grant.
    let bytes=match commands {
        Some(commands)=>std::borrow::Cow::Borrowed(commands.bytes()
            .map_err(|_|"PROCESS_CATALOG_UNAVAILABLE: bound command catalogue unavailable")?),
        None=>std::borrow::Cow::Owned(agent_bridge_lifecycle::read_operator_setting(settings,"commands.json")
            .map_err(|_|"PROCESS_CATALOG_UNAVAILABLE: private local command settings denied")?),
    };
    let catalog:super::Catalog=serde_json::from_slice(&bytes)
        .map_err(|_|"PROCESS_CATALOG_INVALID: invalid local command settings")?;
    if catalog.version!=1 {
        return Err("PROCESS_CATALOG_INVALID: unsupported local catalog version");
    }
    let grant=catalog.programs.get("project-program").filter(|entry|
        entry.executable==executable
            && entry.cwd.as_deref()==Some(cwd.as_path())
            && entry.arguments.as_deref()==Some(args.as_slice())
    );
    if grant.is_some_and(|entry|!entry.preapproved) {
        return Err("PROCESS_NOT_LOCALLY_APPROVED: preapproved:false expressly denies this project command");
    }
    if let Some(entry)=grant {
        if entry.stdin_protocol.as_deref().is_some_and(|s|s!="public-echo-v1") {
            return Err("PROCESS_INPUT_POLICY_DENIED: unknown private stdin protocol");
        }
    }
    // Keep local catalogue denials above. Compatibility is not a local
    // consent question: even an exact predefined grant cannot admit an
    // unqualified Low-IL launcher. Refuse before policy verification, a
    // pending confirmation, one-use permit or creation of an owned process.
    require_project_launch_qualification().map_err(|_|PROJECT_LOW_IL_UNQUALIFIED)?;
    let verifier=FsEnvironmentVerifier;
    let limits=EngineLimits::default();
    let builder=OperatorPolicy::builder(root);
    let builder=if let Some(entry)=grant {
        builder.add_predefined(
            "project-program",&entry.executable,entry.sha256,
            args.clone(),&cwd,
        )
    } else {builder};
    let policy=builder.build(&verifier,&limits)
        .map_err(|_|"PROCESS_POLICY_UNAVAILABLE: project or executable pin refused")?;
    let (web,operator,gate)=CommandDecisionEngine::with_fs_verifier(policy,limits).split();
    let requester=RequesterContext::new("local-stdio")
        .map_err(|_|"PROCESS_POLICY_UNAVAILABLE: requester not available")?;
    let decision=web.submit(&requester,CommandRequest::new(&executable,args.clone(),&cwd))
        .map_err(|_|"PROCESS_COMMAND_REJECTED: executable, argv, shell or cwd outside policy")?;
    let (request_id,display,hash,preapproved)=match decision {
        SubmissionOutcome::PendingLocalConfirmation{request_id,..}=>{
            let displayed=operator.inspect_pending(&request_id)
                .map_err(|_|"PROCESS_APPROVAL_UNAVAILABLE: exact pending decision lost")?;
            if displayed.args!=args || displayed.cwd.is_empty() {
                return Err("PROCESS_APPROVAL_UNAVAILABLE: displayed values changed");
            }
            let hash=*displayed.executable_sha256.as_bytes();
            (request_id,Some(displayed),hash,false)
        },
        SubmissionOutcome::PredefinedApproved{request_id,..}=>{
            let pin=grant.ok_or("PROCESS_POLICY_UNAVAILABLE: unexpected predefined command")?;
            (request_id,None,*pin.sha256.as_bytes(),true)
        },
    };
    let mut private=private_files(database,settings)
        .map_err(|_|"PROCESS_PRIVATE_BOUNDARY_UNAVAILABLE: cannot qualify database/settings")?;
    for key in ["APPDATA","LOCALAPPDATA"] {
        let path=std::env::var_os(key).map(PathBuf::from)
            .ok_or("PROCESS_PRIVATE_BOUNDARY_UNAVAILABLE: private profile path unknown")?;
        if !path.is_absolute() {
            return Err("PROCESS_PRIVATE_BOUNDARY_UNAVAILABLE: invalid private profile path");
        }
        if !private.contains(&path) {private.push(path);}
    }
    // The workspace's .git file/directory must remain inaccessible under
    // the same low-integrity restricted token used for the child.
    let git_control=root.join(".git");
    match fs::symlink_metadata(&git_control) {
        Ok(meta) if meta.is_file() || meta.is_dir()=>private.push(git_control),
        Ok(_)=>return Err("PROCESS_PRIVATE_BOUNDARY_UNAVAILABLE: unsafe Git control path"),
        Err(error) if error.kind()==io::ErrorKind::NotFound=>{},
        Err(_)=>return Err("PROCESS_PRIVATE_BOUNDARY_UNAVAILABLE: cannot pin Git control"),
    }
    let private_paths=private.iter().map(PathBuf::as_path).collect::<Vec<_>>();
    let prepared=prepare_project_command(&ProjectCommandSpec {
        executable:&executable,expected_sha256:hash,
        workspace:root,cwd:&cwd,args:&args,
        operator_catalog_file:&settings.join("commands.json"),
        database_file:database,additional_private_paths:&private_paths,
        deadline,
    }).map_err(|_|{
        eprintln!(
            "agent-bridge LOCAL: project command confinement refused for [{}]; \
             no project ACL was changed; owner review needed before any grant.",
            root.display()
        );
        "PROCESS_CONFINEMENT_REFUSED: exact project access or denial of Bridge private state unavailable"
    })?;
    if let Some(displayed)=display {
        let yes=operator_confirmation::confirm(&displayed)?;
        if !yes {
            let _=operator.deny(&request_id,Some("local_operator_refused".into()));
            return Err("PROCESS_LOCAL_OPERATOR_REFUSED: no program was launched");
        }
        operator.approve(&request_id,displayed.confirmation_digest)
            .map_err(|_|"PROCESS_APPROVAL_STALE: local consent expired or exact command changed")?;
    }
    let permit=gate.consume(&request_id)
        .map_err(|_|"PROCESS_APPROVAL_STALE: one-use project permit no longer available")?;
    let id=session_uuid(&request_id)?;
    let native=match prepared.start() {
        Ok(child)=>child,
        Err(GitRevisionError::Refused(reason)) if reason==PROJECT_LOW_IL_UNQUALIFIED=>{
            let _=gate.finish(permit,ExecutionOutcome::FailedBeforeStart{
                reason_code:"restricted_project_startup_unqualified".into(),
            });
            return Err(PROJECT_LOW_IL_UNQUALIFIED);
        },
        Err(_)=>{
            let _=gate.finish(permit,ExecutionOutcome::Uncertain{
                reason_code:"restricted_launch_unavailable".into(),
            });
            return Err("PROCESS_RESTRICTED_UNCERTAIN: no unrestricted spawn fallback");
        },
    };
    let typed_stdin=preapproved && grant.is_some_and(|entry|
        entry.stdin_protocol.as_deref()==Some("public-echo-v1"));
    Ok((id,LiveProject{
        native:native.into(),gate,permit:Some(permit),typed_stdin,
        started:Instant::now(),last_used:Instant::now(),completed_at:None,
    },preapproved))
}

fn no_extra(a: &Map<String, Value>, allowed: &[&str]) -> ProcessResult<()> {
    if a.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("PROCESS_INVALID_ARGUMENT: unexpected field");
    }
    Ok(())
}
fn str_field<'a>(a: &'a Map<String, Value>, field: &str) -> ProcessResult<&'a str> {
    a.get(field).and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("PROCESS_INVALID_ARGUMENT: nonempty string required")
}
fn number(a: &Map<String, Value>, field: &str, default: i64, min: i64, max: i64)
    -> ProcessResult<i64>
{
    let value = match a.get(field) {
        None => default,
        Some(value) => value.as_i64()
            .ok_or("PROCESS_INVALID_ARGUMENT: integer required")?,
    };
    if value < min || value > max {
        return Err("PROCESS_INVALID_ARGUMENT: integer outside contract bounds");
    }
    Ok(value)
}
fn bool_field(a: &Map<String, Value>, field: &str, default: bool) -> ProcessResult<bool> {
    match a.get(field) {
        None => Ok(default),
        Some(Value::Bool(v)) => Ok(*v),
        _ => Err("PROCESS_INVALID_ARGUMENT: boolean required"),
    }
}

fn start(
    registry: &Arc<Mutex<Registry>>, settings: &Path, root: &Path, database: &Path,
    workspace: Option<&agent_bridge_desktop::DesktopFiles>,
    a: &Map<String, Value>,
) -> ProcessResult<Value> {
    start_with_snapshot(registry,settings,root,database,workspace,a,None)
}

fn start_with_snapshot(
    registry:&Arc<Mutex<Registry>>,settings:&Path,root:&Path,database:&Path,
    workspace:Option<&agent_bridge_desktop::DesktopFiles>,a:&Map<String,Value>,
    commands:Option<&super::CommandCatalogueSnapshot>,
)->ProcessResult<Value> {
    no_extra(a, &["command", "cwd", "timeout_ms", "shell", "elevation",
        "temp_mode", "window_mode", "agent_desktop_lease_id",
        "executable", "arguments"])?;
    if a.contains_key("shell") {
        return Err("PROCESS_SHELL_FORBIDDEN: process sessions never launch an interpreter");
    }
    if a.contains_key("agent_desktop_lease_id") {
        return Err("PROCESS_AGENT_DESKTOP_UNAVAILABLE: background GUI placement unsupported");
    }
    if a.contains_key("temp_mode") {
        return Err("PROCESS_TEMP_MODE_UNAVAILABLE: diagnostic environment is fixed");
    }
    if a.get("elevation").is_some_and(|v| v.as_str() != Some("standard")) {
        return Err("PROCESS_ELEVATION_DENIED: diagnostic sessions never elevate");
    }
    if a.get("window_mode").is_some_and(|v| v.as_str() != Some("hidden")) {
        return Err("PROCESS_VISIBLE_WINDOW_DENIED: diagnostics have no interactive console");
    }
    let wait = number(a, "timeout_ms", 3000, 250, 30_000)? as u64;
    let command = str_field(a, "command")?;
    if command == "project-program" {
        {
            let mut owner=registry.lock()
                .map_err(|_|"PROCESS_REGISTRY_UNAVAILABLE: session lock failed")?;
            owner.prune();
            if owner.active_count()>=MAX_SESSIONS {
                return Err("PROCESS_CAPACITY_REACHED: too many owned processes");
            }
        }
        #[cfg(windows)]
        {
            // This may require an actual local human Yes. Do not hold the
            // registry lock while displaying the approval dialog.
            let (id,project,preapproved)=project_start_with_snapshot(
                settings,root,database,a,Duration::from_millis(wait),commands,
            )?;
            let mut owner=registry.lock()
                .map_err(|_|"PROCESS_REGISTRY_UNAVAILABLE: session lock failed")?;
            owner.prune();
            if owner.active_count()>=MAX_SESSIONS || owner.project_sessions.contains_key(&id) {
                // Dropping the owner kills the exact restricted Job. No
                // capacity race may allow an untracked child to survive.
                return Err("PROCESS_CAPACITY_REACHED: no slot for owned restricted process");
            }
            owner.project_sessions.insert(id.clone(),Arc::new(Mutex::new(project)));
            return Ok(json!({
                "session_id":id,"diagnostic":"project-program",
                "started":true,"process_owned":true,"running":true,
                "restricted_token":true,
                "predefined":preapproved,
                "operator_confirmation_required":!preapproved,
                "stdin":"approved_typed_protocol_only",
                "read_with":"desktop_read_process",
                "stop_with":"desktop_terminate_process",
            }));
        }
        #[cfg(not(windows))]
        return Err("PROCESS_PROJECT_PROGRAM_UNSUPPORTED: restricted Windows token required");
    }
    if a.contains_key("executable") || a.contains_key("arguments") {
        return Err("PROCESS_INVALID_ARGUMENT: project executable fields require project-program");
    }
    if let Some(cwd) = a.get("cwd") {
        if cwd.as_str() != root.to_str() {
            return Err("PROCESS_CWD_DENIED: only the operator-selected project is supported");
        }
    }
    let diagnostic = Diagnostic::parse(command)?;
    let mut owned = registry.lock()
        .map_err(|_| "PROCESS_REGISTRY_UNAVAILABLE: session lock failed")?;
    owned.prune();
    if owned.active_count() >= MAX_SESSIONS {
        return Err("PROCESS_CAPACITY_REACHED: too many active diagnostic sessions");
    }
    let (id, session) = fixed_start_with_snapshot(settings, root, database, diagnostic, workspace,commands)?;
    if owned.sessions.contains_key(&id) {
        return Err("PROCESS_ID_UNAVAILABLE: random session identifier collision");
    }
    let output = Arc::clone(&session.capture);
    owned.sessions.insert(id.clone(), Arc::new(Mutex::new(session)));
    drop(owned);
    // Start is nonblocking except for a small best-effort first-output wait.
    if !diagnostic.metadata() {
        wait_output(&output, 0, Duration::from_millis(wait.min(250)));
    }
    Ok(json!({
        "session_id":id, "diagnostic":diagnostic.id(),
        "started":true, "process_owned":true,
        "interactive":diagnostic.metadata(),
        "read_with":"desktop_read_process"
    }))
}

fn wait_output(shared: &SharedCapture, previous: usize, wait: Duration) {
    if wait.is_zero() { return; }
    let (lock, condvar) = &**shared;
    let Ok(guard) = lock.lock() else { return; };
    if let Ok((guard, _)) = condvar.wait_timeout_while(guard, wait, |data| {
        data.stdout.len() + data.stderr.len() <= previous
            && !(data.stdout_eof && data.stderr_eof)
    }) {
        drop(guard);
    }
}

fn read(registry: &Arc<Mutex<Registry>>, a: &Map<String, Value>) -> ProcessResult<Value> {
    no_extra(a, &["session_id", "offset", "length", "timeout_ms"])?;
    let id = str_field(a, "session_id")?;
    let offset = number(a, "offset", 0, -100_000, 100_000)?;
    let length = number(a, "length", 1000, 1, 5000)? as usize;
    let timeout = number(a, "timeout_ms", 1000, 0, 30_000)? as u64;
    #[cfg(windows)]
    {
        let project = {
            let mut owner=registry.lock()
                .map_err(|_|"PROCESS_REGISTRY_UNAVAILABLE: session lock failed")?;
            owner.prune();
            if let Some(ended)=owner.ended_view(id) {return Ok(ended);}
            owner.project_sessions.get(id).cloned()
        };
        if let Some(project)=project {
            let mut project=project.lock()
                .map_err(|_|"PROCESS_SESSION_UNAVAILABLE: project lock failed")?;
            return project.read(id,offset,length,Duration::from_millis(timeout));
        }
    }
    let handle = {
        let mut owner = registry.lock()
            .map_err(|_| "PROCESS_REGISTRY_UNAVAILABLE: session lock failed")?;
        owner.prune();
        if let Some(ended) = owner.ended_view(id) { return Ok(ended); }
        owner.lookup(id)?
    };
    let shared = {
        let session = handle.lock()
            .map_err(|_| "PROCESS_SESSION_UNAVAILABLE: session lock failed")?;
        Arc::clone(&session.capture)
    };
    let previous = {
        let (lock, _) = &*shared;
        let captured = lock.lock()
            .map_err(|_| "PROCESS_OUTPUT_UNAVAILABLE: capture lock failed")?;
        captured.stdout.len() + captured.stderr.len()
    };
    // Only await initial output; once bytes exist, reading is an immediate,
    // bounded snapshot and never blocks another session interaction.
    if previous == 0 {
        wait_output(&shared, 0, Duration::from_millis(timeout));
    }
    let mut session = handle.lock()
        .map_err(|_| "PROCESS_SESSION_UNAVAILABLE: session lock failed")?;
    session.read(id, offset, length)
}

// Interactions remain a published but intentionally unavailable operation
// until a dedicated, locally approved Agent Bridge metadata executable exists.
// Never pass input to Git, Rust, a shell, or an untrusted process.
// Only the dedicated Agent Bridge metadata child accepts requests. Parent
// validates the exact typed operation and path before placing a canonical JSON
// frame on a one-slot queue. Pipe writes and reads happen on a separate worker.
fn interact(registry: &Arc<Mutex<Registry>>, a: &Map<String, Value>) -> ProcessResult<Value> {
    no_extra(a, &["session_id", "input", "timeout_ms", "wait_for_prompt"])?;
    let id = str_field(a, "session_id")?;
    #[cfg(windows)]
    {
        let project={
            let mut owner=registry.lock()
                .map_err(|_|"PROCESS_REGISTRY_UNAVAILABLE: session lock failed")?;
            owner.prune();
            if owner.ended.contains_key(id) {
                return Err("PROCESS_SESSION_CLOSED: restricted project session has ended");
            }
            owner.project_sessions.get(id).cloned()
        };
        if let Some(project)=project {
            let input=str_field(a,"input")?;
            let timeout=number(a,"timeout_ms",8000,0,30000)? as u64;
            let wait_for_output=bool_field(a,"wait_for_prompt",true)?;
            let mut project=project.lock()
                .map_err(|_|"PROCESS_SESSION_UNAVAILABLE: restricted project lock failed")?;
            return project.interact(
                id,input,Duration::from_millis(timeout),wait_for_output,
            );
        }
    }
    let input = str_field(a, "input")?;
    if input.len() > MAX_METADATA_INPUT {
        return Err("PROCESS_INPUT_DENIED: typed JSON request exceeds protocol size");
    }
    let timeout = number(a, "timeout_ms", 8000, 0, 30_000)? as u64;
    if timeout == 0 {
        return Err("PROCESS_TIMEOUT_REQUIRED: metadata request requires a positive deadline");
    }
    // "wait_for_prompt" is accepted for legacy callers but this child has no
    // terminal prompt. The wait applies only to its single bounded JSON reply.
    let _ = bool_field(a, "wait_for_prompt", true)?;
    let value = serde_json::from_str::<Value>(input)
        .map_err(|_| "PROCESS_INPUT_DENIED: expected typed JSON request")?;
    let Some(request) = value.as_object() else {
        return Err("PROCESS_INPUT_DENIED: expected JSON object");
    };
    if request.len() != 2
        || request.get("operation").and_then(Value::as_str) != Some("get_file_info")
    {
        return Err("PROCESS_OPERATION_DENIED: only get_file_info is supported");
    }
    let path = request.get("path").and_then(Value::as_str)
        .ok_or("PROCESS_PATH_DENIED: path is required")?;
    if !super::metadata_child::valid_relative_path(path) {
        return Err("PROCESS_PATH_DENIED: validated relative file path required");
    }
    let mut frame = serde_json::to_vec(&json!({"operation":"get_file_info","path":path}))
        .map_err(|_| "PROCESS_INPUT_DENIED: cannot serialize typed request")?;
    frame.push(b'\n');
    if frame.len() > MAX_METADATA_INPUT {
        return Err("PROCESS_INPUT_DENIED: serialized request exceeds protocol size");
    }
    let handle = {
        let mut owner = registry.lock()
            .map_err(|_| "PROCESS_REGISTRY_UNAVAILABLE: session lock failed")?;
        owner.prune();
        if owner.ended.contains_key(id) {
            return Err("PROCESS_SESSION_CLOSED: diagnostic session has ended");
        }
        owner.lookup(id)?
    };
    let (reply_tx, reply_rx) = mpsc::sync_channel::<ProcessResult<Value>>(1);
    {
        let mut session = handle.lock()
            .map_err(|_| "PROCESS_SESSION_UNAVAILABLE: session lock failed")?;
        session.poll()?;
        if !session.diagnostic.metadata() {
            return Err("PROCESS_INTERACTION_UNSUPPORTED: version-only diagnostic has no stdin");
        }
        if session.exit.is_some() || session.stop_requested
            || session.started.elapsed() >= MAX_SESSION_AGE
        {
            return Err("PROCESS_SESSION_CLOSED: metadata child is unavailable");
        }
        if session.pending_deadline.is_some() {
            return Err("PROCESS_BUSY: a metadata request is already outstanding");
        }
        if session.requests_started >= MAX_METADATA_REQUESTS {
            return Err("PROCESS_INPUT_LIMIT: metadata request quota reached");
        }
        let Some(queue) = session.metadata_queue.as_ref() else {
            return Err("PROCESS_PIPE_CLOSED: metadata child input is closed");
        };
        match queue.try_send(MetadataJob { frame, reply: reply_tx }) {
            Ok(()) => {},
            Err(TrySendError::Full(_)) => {
                return Err("PROCESS_QUEUE_FULL: metadata input queue is bounded");
            }
            Err(TrySendError::Disconnected(_)) => {
                return Err("PROCESS_PIPE_CLOSED: metadata worker is unavailable");
            }
        }
        session.requests_started += 1;
        session.last_used = Instant::now();
        session.pending_deadline = Some(Instant::now() + Duration::from_millis(timeout));
    }
    // The session lock is deliberately RELEASED before waiting for the worker.
    // Both deadline and watchdog independently prevent infinite requests.
    let result = reply_rx.recv_timeout(Duration::from_millis(timeout));
    let mut session = handle.lock()
        .map_err(|_| "PROCESS_SESSION_UNAVAILABLE: session lock failed")?;
    let expired = session.started.elapsed() >= MAX_SESSION_AGE || session.stop_requested;
    session.pending_deadline = None;
    match result {
        Ok(Ok(response)) if !expired => {
            if response["ok"] == true
                && response["metadata"]["path"].as_str() != Some(path)
            {
                session.stop_requested = true;
                session.shutdown_deadline = Some(Instant::now());
                return Err("PROCESS_PROTOCOL_INVALID: response path does not match request");
            }
            session.last_used = Instant::now();
            Ok(json!({
                "session_id":id, "accepted":true, "operation":"get_file_info",
                "path":path, "response":response, "read_with":"desktop_read_process",
            }))
        }
        Ok(Ok(_)) => Err("PROCESS_SESSION_CLOSED: result arrived after expiry"),
        Ok(Err(problem)) => {
            session.stop_requested = true;
            session.shutdown_deadline = Some(Instant::now());
            Err(problem)
        }
        Err(RecvTimeoutError::Timeout) => {
            session.stop_requested = true;
            session.shutdown_deadline = Some(Instant::now());
            Err("PROCESS_INTERACTION_TIMEOUT: metadata child request exceeded deadline")
        }
        Err(RecvTimeoutError::Disconnected) => {
            session.stop_requested = true;
            session.shutdown_deadline = Some(Instant::now());
            Err("PROCESS_CHILD_EOF: metadata worker closed before responding")
        }
    }
}

fn terminate(registry: &Arc<Mutex<Registry>>, a: &Map<String, Value>) -> ProcessResult<Value> {
    no_extra(a, &["session_id"])?;
    let id = str_field(a, "session_id")?;
    #[cfg(windows)]
    {
        let project={
            let mut owner=registry.lock()
                .map_err(|_|"PROCESS_REGISTRY_UNAVAILABLE: session lock failed")?;
            owner.prune();
            if let Some(ended)=owner.ended_view(id) {return Ok(ended);}
            owner.project_sessions.get(id).cloned()
        };
        if let Some(project)=project {
            let code={
                let mut session=project.lock()
                    .map_err(|_|"PROCESS_SESSION_UNAVAILABLE: project lock failed")?;
                session.terminate()?
            };
            let mut owner=registry.lock()
                .map_err(|_|"PROCESS_REGISTRY_UNAVAILABLE: session lock failed")?;
            owner.project_sessions.remove(id);
            owner.remember_end(id.to_string(),Diagnostic::ProjectProgram,"released",code);
            return owner.ended_view(id)
                .ok_or("PROCESS_SESSION_UNKNOWN: restricted project tombstone unavailable");
        }
    }
    let handle = {
        let mut owner = registry.lock()
            .map_err(|_| "PROCESS_REGISTRY_UNAVAILABLE: session lock failed")?;
        owner.prune();
        if let Some(result) = owner.ended_view(id) { return Ok(result); }
        owner.lookup(id)?
    };
    let (diagnostic, code) = {
        let mut session = handle.lock()
            .map_err(|_| "PROCESS_SESSION_UNAVAILABLE: session lock failed")?;
        session.poll()?;
        if session.exit.is_none() && session.diagnostic.metadata() {
            // Drop the queue and signal its worker; it releases child stdin
            // without ANY pipe I/O under this session mutex. The autonomous
            // watchdog owns the bounded grace period, kill, reap and joins.
            session.stop_requested = true;
            session.worker_stop.store(true, Ordering::SeqCst);
            session.metadata_queue.take();
            session.shutdown_deadline = Some(Instant::now() + Duration::from_millis(750));
            return Ok(json!({
                "session_id":id, "termination_requested":true,
                "cooperative":true, "running":true, "closed":false,
                "cleanup":"autonomous_watchdog",
            }));
        }
        if session.exit.is_none() {
            return Err(
                "PROCESS_COOPERATIVE_STOP_UNAVAILABLE: version diagnostics have no stop channel",
            );
        }
        if !session.close_owned() {
            return Err("PROCESS_CLEANUP_PENDING: child or readers have not closed");
        }
        (session.diagnostic, session.exit.flatten())
    };
    let mut owner = registry.lock()
        .map_err(|_| "PROCESS_REGISTRY_UNAVAILABLE: session lock failed")?;
    owner.sessions.remove(id);
    owner.remember_end(id.to_string(), diagnostic, "released", code);
    owner.ended_view(id)
        .ok_or("PROCESS_SESSION_UNKNOWN: closed session record unavailable")
}

fn result(response: ProcessResult<Value>) -> ToolCallResult {
    match response {
        Ok(value) => ToolCallResult::text(value.to_string()),
        Err(message) => ToolCallResult::tool_error(message.to_string()),
    }
}

pub(super) fn attach(
    settings: &Path, project: &Path, database: &Path,
    catalog: &mut Vec<ToolDefinition>, handlers: &mut ToolMapHandler,
    process_enabled: bool,
    workspace: Option<Arc<agent_bridge_desktop::DesktopFiles>>,
) -> Result<Option<SessionSupervisor>, crate::runtime::RuntimeError> {
    attach_with_snapshot(settings,project,database,catalog,handlers,process_enabled,workspace,None)
}

pub(super) fn attach_with_snapshot(
    settings:&Path,project:&Path,database:&Path,catalog:&mut Vec<ToolDefinition>,handlers:&mut ToolMapHandler,
    process_enabled:bool,workspace:Option<Arc<agent_bridge_desktop::DesktopFiles>>,
    commands:Option<Arc<super::CommandCatalogueSnapshot>>,
)->Result<Option<SessionSupervisor>,crate::runtime::RuntimeError> {
    let registry = Arc::new(Mutex::new(Registry::default()));
    // The returned supervisor belongs to stdio, never to a detached handler.
    // Starting a process-capable router without a joinable watchdog fails.
    let supervisor = if process_enabled {
        Some(SessionSupervisor::start(Arc::clone(&registry))?)
    } else {
        None
    };
    let (settings, project, database) =
        (settings.to_owned(), project.to_owned(), database.to_owned());

    let starts = Arc::clone(&registry);
    handlers.register("desktop_start_process", move |args| {
        if !process_enabled {
            return Ok(ToolCallResult::tool_error(
                "PROCESS_DISABLED_BY_LOCAL_PROFILE: Full Control or Fully Unlocked required",
            ));
        }
        Ok(result(start_with_snapshot(&starts, &settings, &project, &database, workspace.as_deref(), &args,commands.as_deref())))
    });
    catalog.push(ToolDefinition::new(
        "desktop_start_process",
        Some("Fixed locally pinned diagnostics: git-version, rust-version, workspace-file-info; or project-program with exact executable, JSON argument array and project cwd, subject to a native one-use human consent dialog and a verified Low-integrity restricted token. No shell, full-token fallback, elevation, private Bridge state or external PID.".into()),
        json!({"type":"object","additionalProperties":false,"required":["command"],
            "properties":{
                "command":{"type":"string","enum":["git-version","rust-version","workspace-file-info","project-program"]},
                "executable":{"type":"string","minLength":1,"maxLength":4096},
                "arguments":{"type":"array","maxItems":64,"items":{"type":"string","maxLength":4096}},
                "cwd":{"type":"string","minLength":1,"maxLength":4096},
                "timeout_ms":{"type":"integer","minimum":250,"maximum":30000,"default":3000},
                "shell":{"type":"string"},
                "elevation":{"type":"string","enum":["standard","admin"]},
                "window_mode":{"type":"string","enum":["hidden","visible"]},
                "temp_mode":{"type":"string","enum":["inherit","short"]},
                "agent_desktop_lease_id":{"type":"string"}
            }}),
    ));

    let reads = Arc::clone(&registry);
    handlers.register("desktop_read_process", move |args| {
        if !process_enabled {
            return Ok(ToolCallResult::tool_error(
                "PROCESS_DISABLED_BY_LOCAL_PROFILE: process sessions are not enabled",
            ));
        }
        Ok(result(read(&reads, &args)))
    });
    catalog.push(ToolDefinition::new(
        "desktop_read_process",
        Some("Read progressive bounded stdout/stderr of a live, owned restricted project .exe or fixed diagnostic, with running/exit/truncation/EOF status; never an external PID.".into()),
        json!({"type":"object","additionalProperties":false,"required":["session_id"],
            "properties":{
                "session_id":{"type":"string","format":"uuid"},
                "offset":{"type":"integer","minimum":-100000,"maximum":100000,"default":0},
                "length":{"type":"integer","minimum":1,"maximum":5000,"default":1000},
                "timeout_ms":{"type":"integer","minimum":0,"maximum":30000,"default":1000}
            }}),
    ));

    let interacts = Arc::clone(&registry);
    handlers.register("desktop_interact_process", move |args| {
        if !process_enabled {
            return Ok(ToolCallResult::tool_error(
                "PROCESS_DISABLED_BY_LOCAL_PROFILE: process sessions are not enabled",
            ));
        }
        Ok(result(interact(&interacts, &args)))
    });
    catalog.push(ToolDefinition::new(
        "desktop_interact_process",
        Some("Send a bounded typed JSON request to the pinned metadata child or the exact locally predefined public-echo project .exe. Unrecognized programs, shell interpreters and raw/unvalidated stdin are always refused.".into()),
        json!({"type":"object","additionalProperties":false,
            "required":["session_id","input"],"properties":{
                "session_id":{"type":"string","format":"uuid"},
                "input":{"type":"string","minLength":1,"maxLength":8192},
                "timeout_ms":{"type":"integer","minimum":0,"maximum":30000,"default":8000},
                "wait_for_prompt":{"type":"boolean","default":true}
            }}),
    ));

    handlers.register("desktop_terminate_process", move |args| {
        if !process_enabled {
            return Ok(ToolCallResult::tool_error(
                "PROCESS_DISABLED_BY_LOCAL_PROFILE: process sessions are not enabled",
            ));
        }
        Ok(result(terminate(&registry, &args)))
    });
    catalog.push(ToolDefinition::new(
        "desktop_terminate_process",
        Some("Cooperatively close an owned metadata child, terminate and reap the exact restricted project Job, or release an exited diagnostic. External PIDs and global signals are forbidden.".into()),
        json!({"type":"object","additionalProperties":false,"required":["session_id"],
            "properties":{"session_id":{"type":"string","format":"uuid"}}}),
    ));
    Ok(supervisor)
}
#[cfg(all(test, windows))]
#[path = "sessions_tests.rs"]
mod tests;
