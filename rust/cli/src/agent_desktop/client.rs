use crate::owned_children::{ChildSpec, OwnedChild};
use crate::runtime::RuntimeError;
use crate::windows_tools::bundle::{self, Resources};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::fs::{File,OpenOptions};
use std::io::{self,Write};
use std::path::{Path,PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant,SystemTime,UNIX_EPOCH};

const FRAME_LIMIT: usize = 1024 * 1024;
const HEARTBEAT: Duration = Duration::from_millis(450);
pub(super) const EXPIRY: Duration = Duration::from_millis(2500);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeWindow {
    pub hwnd: u64, pub pid: u32, pub tid: u32, pub birth: u64,
    pub image: String, pub class_name: String, pub title: String,
    pub left: i32, pub top: i32, pub width: i32, pub height: i32, pub foreground: bool,
    pub desktop_id: String, pub desktop_number: u32, pub visible: bool, pub is_hud: bool,
}
impl NativeWindow {
    pub(crate) fn same_process_window(&self, other: &Self) -> bool {
        self.hwnd == other.hwnd && self.pid == other.pid && self.tid == other.tid && self.birth == other.birth
            && self.image.eq_ignore_ascii_case(&other.image) && self.class_name == other.class_name
    }
    pub(crate) fn same_target(&self, other: &Self) -> bool {
        self.same_process_window(other) && self.desktop_id == other.desktop_id && self.desktop_number == other.desktop_number
    }
    fn validate(&self) -> Result<(), RuntimeError> {
        if self.hwnd == 0 || self.pid == 0 || self.tid == 0 || self.birth == 0 || self.image.is_empty() || self.image.len() > 131072
            || self.class_name.len() > 2048 || self.title.len() > 16384 || !bundle::valid_uuid(&self.desktop_id)
            || !(1..=128).contains(&self.desktop_number) || !(0..=100000).contains(&self.width) || !(0..=100000).contains(&self.height)
            || !(-100000..=100000).contains(&self.left) || !(-100000..=100000).contains(&self.top) {
            return Err("NATIVE_WINDOW_IDENTITY_INVALID".into());
        }
        Ok(())
    }
}

struct Pending { id: u64, response: Option<Result<Value, String>> }
struct State {
    child: Option<OwnedChild>, connected: bool, input: Vec<u8>, writes: VecDeque<Vec<u8>>, write_offset: usize,
    stderr_bytes: usize, last_sent: Instant, last_heartbeat: Option<Instant>, sequence: u64,
    current_desktop: Option<String>, leases: BTreeMap<String, Value>, revoked:VecDeque<(String,String)>, pending: Option<Pending>, next_id: u64,
}
impl State {
    fn new() -> Self { Self { child: None, connected: false, input: vec![], writes: VecDeque::new(), write_offset: 0,
        stderr_bytes: 0, last_sent: Instant::now(), last_heartbeat: None, sequence: 0,
        current_desktop: None, leases: BTreeMap::new(), revoked:VecDeque::new(), pending: None, next_id: 1 } }
    fn enqueue(&mut self, value: Value) -> Result<(), RuntimeError> {
        let bytes = serde_json::to_vec(&value)?;
        if bytes.is_empty() || bytes.len() > FRAME_LIMIT || self.writes.len() >= 16 { return Err("NATIVE_FRAME_LIMIT".into()); }
        let mut frame = (bytes.len() as u32).to_le_bytes().to_vec(); frame.extend(bytes); self.writes.push_back(frame); Ok(())
    }
    fn reset(&mut self) {
        self.connected = false; self.input.clear(); self.writes.clear(); self.write_offset = 0;
        self.stderr_bytes = 0; self.last_heartbeat = None; self.sequence = 0; self.current_desktop = None;
        self.leases.clear(); self.revoked.clear(); self.pending = None;
    }
    fn accept(&mut self, value: Value) -> Result<(), RuntimeError> {
        let object = value.as_object().ok_or("NATIVE_PROTOCOL_INVALID")?;
        if value["v"] != 1 { return Err("NATIVE_PROTOCOL_INVALID".into()); }
        if let Some(event) = value.get("event").and_then(Value::as_str) {
            if value.get("id").is_some() { return Err("NATIVE_PROTOCOL_INVALID".into()); }
            match event {
                "heartbeat" => {
                    if object.keys().any(|key| !matches!(key.as_str(), "v"|"event"|"sequence"|"current_desktop_id"|"leases")) { return Err("NATIVE_PROTOCOL_INVALID".into()); }
                    let sequence = value["sequence"].as_u64().ok_or("NATIVE_PROTOCOL_INVALID")?;
                    let current = value["current_desktop_id"].as_str().ok_or("NATIVE_PROTOCOL_INVALID")?;
                    let leases = value["leases"].as_array().ok_or("NATIVE_PROTOCOL_INVALID")?;
                    if sequence <= self.sequence || !bundle::valid_uuid(current) || leases.len() > 16 { return Err("NATIVE_PROTOCOL_INVALID".into()); }
                    let mut next = BTreeMap::new();
                    for lease in leases {
                        let id = lease["lease_id"].as_str().filter(|id| bundle::valid_uuid(id)).ok_or("NATIVE_PROTOCOL_INVALID")?;
                        if next.insert(id.to_owned(), lease.clone()).is_some() { return Err("NATIVE_PROTOCOL_INVALID".into()); }
                    }
                    self.sequence = sequence; self.last_heartbeat = Some(Instant::now()); self.current_desktop = Some(current.to_owned()); self.leases = next;
                }
                "revoked" => {
                    if object.keys().any(|key| !matches!(key.as_str(), "v"|"event"|"lease_id"|"generation"|"reason")) { return Err("NATIVE_PROTOCOL_INVALID".into()); }
                    let id = value["lease_id"].as_str().filter(|id| bundle::valid_uuid(id)).ok_or("NATIVE_PROTOCOL_INVALID")?;
                    self.leases.remove(id);
                    let reason=value["reason"].as_str().filter(|reason|reason.len()<=64&&reason.bytes().all(|c|c.is_ascii_alphabetic()||c==b'_')).ok_or("NATIVE_PROTOCOL_INVALID")?;
                    if self.revoked.len()==32 {self.revoked.pop_front();}self.revoked.push_back((id.to_owned(),reason.to_owned()));
                }
                _ => return Err("NATIVE_PROTOCOL_INVALID".into()),
            }
            return Ok(());
        }
        let id = value["id"].as_u64().ok_or("NATIVE_PROTOCOL_INVALID")?;
        let pending = self.pending.as_mut().filter(|pending| pending.id == id && pending.response.is_none()).ok_or("NATIVE_RESPONSE_MISMATCH")?;
        let result = match value["ok"].as_bool() {
            Some(true) if object.keys().all(|key| matches!(key.as_str(), "v"|"id"|"ok"|"result")) && value.get("result").is_some() => Ok(value["result"].clone()),
            Some(false) if object.keys().all(|key| matches!(key.as_str(), "v"|"id"|"ok"|"error"|"diagnostic")) => {
                let code = value["error"].as_str().filter(|code| !code.is_empty() && code.len() <= 64
                    && code.bytes().all(|c| c.is_ascii_uppercase() || c == b'_')).ok_or("NATIVE_PROTOCOL_INVALID")?;
                Err(code.to_owned())
            }
            _ => return Err("NATIVE_PROTOCOL_INVALID".into()),
        };
        pending.response = Some(result); Ok(())
    }
    fn pump(&mut self) -> Result<(), RuntimeError> {
        if !self.connected { return Ok(()); }
        if self.last_sent.elapsed() >= HEARTBEAT {
            self.enqueue(json!({"v":1,"id":0,"op":"owner_heartbeat","args":{}}))?;
            self.last_sent = Instant::now();
        }
        let child = self.child.as_mut().ok_or("NATIVE_OWNER_MISSING")?;
        while let Some(frame) = self.writes.front() {
            match child.write_stdin(&frame[self.write_offset..]) {
                Ok(0) => return Err("NATIVE_PIPE_CLOSED".into()),
                Ok(count) => { self.write_offset += count; if self.write_offset == frame.len() { self.writes.pop_front(); self.write_offset = 0; } },
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return Err("NATIVE_PIPE_FAILED".into()),
            }
        }
        let mut buffer = [0u8; 16384];
        for _ in 0..128 {
            match child.read_stdout(&mut buffer) {
                Ok(0) => return Err("NATIVE_PIPE_CLOSED".into()),
                Ok(count) => { self.input.extend_from_slice(&buffer[..count]); if self.input.len() > FRAME_LIMIT * 2 { return Err("NATIVE_FRAME_LIMIT".into()); } },
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return Err("NATIVE_PIPE_FAILED".into()),
            }
        }
        for _ in 0..8 {
            match child.read_stderr(&mut buffer) {
                Ok(0) => break,
                Ok(count) => { self.stderr_bytes += count; if self.stderr_bytes > 65536 { return Err("NATIVE_DIAGNOSTIC_LIMIT".into()); } },
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return Err("NATIVE_PIPE_FAILED".into()),
            }
        }
        if child.try_exit()?.is_some() { return Err("NATIVE_HELPER_EXITED".into()); }
        while self.input.len() >= 4 {
            let length = u32::from_le_bytes(self.input[..4].try_into().unwrap()) as usize;
            if length == 0 || length > FRAME_LIMIT { return Err("NATIVE_FRAME_LIMIT".into()); }
            if self.input.len() < length + 4 { break; }
            let value: Value = serde_json::from_slice(&self.input[4..length+4]).map_err(|_| "NATIVE_FRAME_INVALID")?;
            self.input.drain(..length+4); self.accept(value)?;
        }
        if self.last_heartbeat.is_some_and(|beat| beat.elapsed() > EXPIRY) { return Err("NATIVE_HEARTBEAT_STALE".into()); }
        Ok(())
    }
}

pub(crate) struct NativeClient {
    _resources: Arc<Resources>, spec: ChildSpec, _state_pins: Vec<File>, state: Mutex<State>, serial: Mutex<()>,
    final_stop: AtomicBool, epoch: AtomicU64, thread: Mutex<Option<JoinHandle<()>>>,
    diagnostic_path:PathBuf, diagnostics:Mutex<()>,
}
impl NativeClient {
    pub(crate) fn new(resources: Arc<Resources>, state_root: &Path) -> Result<Arc<Self>, RuntimeError> {
        let (root, mut pins) = bundle::private_directory(state_root)?;
        let (extract, extract_pins) = bundle::private_directory(&root.join("native-extract"))?; pins.extend(extract_pins);
        let spec = ChildSpec { executable: resources.native.clone(), arguments: vec![], cwd: resources.root.clone(),
            env_overrides: BTreeMap::from([
                ("DOTNET_BUNDLE_EXTRACT_BASE_DIR".into(), Some(extract.into_os_string())),
                ("DOTNET_CLI_TELEMETRY_OPTOUT".into(), Some("1".into())),
                ("DOTNET_NOLOGO".into(), Some("1".into())),
            ]) };
        Ok(Arc::new(Self { _resources: resources, spec, _state_pins: pins, state: Mutex::new(State::new()), serial: Mutex::new(()),
            final_stop: AtomicBool::new(false), epoch: AtomicU64::new(1), thread: Mutex::new(None),
            diagnostic_path:root.join("native-diagnostics.jsonl"),diagnostics:Mutex::new(()) }))
    }
    pub(crate) fn start_monitor(self: &Arc<Self>) -> Result<(), RuntimeError> {
        let mut slot = self.thread.lock().map_err(|_| "NATIVE_THREAD_STATE_UNAVAILABLE")?;
        let weak = Arc::downgrade(self);
        let join = std::thread::Builder::new().name("agent-bridge-native-heartbeat".to_owned()).spawn(move || {
            loop {
                let Some(client) = weak.upgrade() else { break; };
                if client.final_stop.load(Ordering::Acquire) { break; }
                if let Ok(mut state) = client.state.try_lock() {
                    if let Err(error)=state.pump() {
                        let _=client.record(json!({"phase":"transport_error","code":error.to_string()}));client.lose(&mut state);
                    }
                }
                drop(client); std::thread::sleep(Duration::from_millis(40));
            }
        })?;
        *slot = Some(join); Ok(())
    }
    fn lose(&self, state: &mut State) {
        if state.connected {
            self.epoch.fetch_add(1, Ordering::AcqRel);
            let _=self.record(json!({"phase":"connection_lost","pid":state.child.as_ref().map(OwnedChild::root_pid),"stderr_bytes":state.stderr_bytes}));
        }
        state.connected = false; state.leases.clear(); state.last_heartbeat = None;
        if let Some(child) = state.child.as_mut() { let _ = child.terminate(); }
    }
    pub(crate) fn epoch(&self) -> u64 { self.epoch.load(Ordering::Acquire) }
    pub(crate) fn revocation_reason(&self,id:&str)->Option<String>{
        self.state.lock().ok()?.revoked.iter().rev().find(|(lease,_)|lease==id).map(|(_,reason)|reason.to_ascii_uppercase())
    }
    fn record(&self,mut value:Value)->Result<(),RuntimeError>{
        let _guard=self.diagnostics.lock().map_err(|_|"NATIVE_DIAGNOSTICS_UNAVAILABLE")?;
        value["unix_ms"]=json!(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis());value["epoch"]=json!(self.epoch());
        if self.diagnostic_path.exists(){
            bundle::check_physical(&self.diagnostic_path)?;
            if std::fs::metadata(&self.diagnostic_path)?.len()>1024*1024 {
                let previous=self.diagnostic_path.with_file_name("native-diagnostics.previous.jsonl");
                if previous.exists(){bundle::check_physical(&previous)?;std::fs::remove_file(&previous)?;}
                std::fs::rename(&self.diagnostic_path,previous)?;
            }
        }
        let mut options=OpenOptions::new();options.create(true).append(true);
        #[cfg(windows)]{use std::os::windows::fs::OpenOptionsExt;options.share_mode(1).custom_flags(0x00200000);}
        let mut file=options.open(&self.diagnostic_path)?;if !file.metadata()?.is_file(){return Err("NATIVE_DIAGNOSTICS_TYPE_INVALID".into());}
        writeln!(file,"{value}")?;file.flush()?;Ok(())
    }
    pub(crate) fn fresh(&self) -> bool {
        self.state.lock().map(|state| state.connected && state.last_heartbeat.is_some_and(|beat| beat.elapsed() <= EXPIRY)).unwrap_or(false)
    }
    pub(crate) fn current_desktop(&self) -> Result<String, RuntimeError> {
        let value = self.call("desktops", json!({}), Duration::from_secs(2))?;
        Ok(value["current_desktop_id"].as_str().filter(|id| bundle::valid_uuid(id)).ok_or("NATIVE_DESKTOP_INVALID")?.to_owned())
    }
    pub(crate) fn call(&self, operation: &str, args: Value, timeout: Duration) -> Result<Value, RuntimeError> {
        let _serial = self.serial.lock().map_err(|_| "NATIVE_CALL_STATE_UNAVAILABLE")?;
        if self.final_stop.load(Ordering::Acquire) { return Err("NATIVE_PROVIDER_CLOSED".into()); }
        let id;
        {
            let mut state = self.state.lock().map_err(|_| "NATIVE_STATE_UNAVAILABLE")?;
            if self.final_stop.load(Ordering::Acquire) { return Err("NATIVE_PROVIDER_CLOSED".into()); }
            if !state.connected {
                if let Some(child) = state.child.as_mut() {
                    if child.finish()?.is_none() { return Err("NATIVE_CLEANUP_PENDING".into()); }
                    state.child.take();
                }
                state.reset();
                self.record(json!({"phase":"starting"}))?;
                // Publication precedes every fallible handshake operation.
                state.child = Some(OwnedChild::spawn(&self.spec)?);
                state.connected = true; state.last_sent = Instant::now() - HEARTBEAT;
                self.epoch.fetch_add(1, Ordering::AcqRel);
            }
            id = state.next_id; state.next_id = state.next_id.checked_add(1).ok_or("NATIVE_REQUEST_ID_EXHAUSTED")?;
            state.pending = Some(Pending { id, response: None });
            if let Err(error)=self.record(json!({"phase":"request","operation":operation,"id":id})) {self.lose(&mut state);return Err(error);}
            state.enqueue(json!({"v":1,"id":id,"op":operation,"args":args}))?;
        }
        let epoch = self.epoch(); let deadline = Instant::now() + timeout;
        loop {
            {
                let mut state = self.state.lock().map_err(|_| "NATIVE_STATE_UNAVAILABLE")?;
                if !state.connected || epoch != self.epoch() { return Err("NATIVE_CONNECTION_LOST".into()); }
                if let Err(error) = state.pump() { let _=self.record(json!({"phase":"transport_error","code":error.to_string()}));self.lose(&mut state); return Err(error); }
                if let Some(result) = state.pending.as_mut().and_then(|pending| pending.response.take()) {
                    state.pending.take();
                    if let Err(code)=&result {self.record(json!({"phase":"domain_error","operation":operation,"id":id,"code":code}))?;}
                    return result.map_err(Into::into);
                }
                if Instant::now() >= deadline { self.lose(&mut state); return Err("NATIVE_IPC_DEADLINE".into()); }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    pub(crate) fn qualify(&self) -> Result<(), RuntimeError> {
        let hello = self.call("hello", json!({}), Duration::from_secs(5))?;
        let pid = self.state.lock().map_err(|_| "NATIVE_STATE_UNAVAILABLE")?.child.as_ref().map(OwnedChild::root_pid).ok_or("NATIVE_OWNER_MISSING")?;
        if hello["pid"] != pid || hello["console"] != false || hello["virtual_desktops"] != true || hello["protocol"] != 1 {
            return Err("NATIVE_HELPER_QUALIFICATION_FAILED".into());
        }
        let until = Instant::now() + EXPIRY;
        while !self.fresh() {
            if Instant::now() >= until { return Err("NATIVE_HEARTBEAT_MISSING".into()); }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
    pub(crate) fn window(&self, hwnd: u64) -> Result<NativeWindow, RuntimeError> {
        let value = self.call("window_identity", json!({"hwnd":hwnd}), Duration::from_secs(2))?;
        let window: NativeWindow = serde_json::from_value(value)?; window.validate()?; Ok(window)
    }
    pub(crate) fn close(&self, final_close: bool) -> Result<(), RuntimeError> {
        if final_close { self.final_stop.store(true, Ordering::Release); }
        self.epoch.fetch_add(1, Ordering::AcqRel);
        let deadline = Instant::now() + Duration::from_secs(3);
        {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            self.lose(&mut state);
            if let Some(child) = state.child.as_mut() {
                child.close_stdin(); child.terminate()?;
                loop {
                    if let Some(exit)=child.finish()? {self.record(json!({"phase":"stopped","pid":child.root_pid(),"exit_code":exit.code}))?;break; }
                    if Instant::now() >= deadline { return Err("NATIVE_CLEANUP_PENDING".into()); }
                    let mut buffer = [0u8; 16384]; let _ = child.read_stdout(&mut buffer); let _ = child.read_stderr(&mut buffer);
                    std::thread::sleep(Duration::from_millis(10));
                }
                state.child.take();
            }
            state.reset();
        }
        if final_close {
            let mut monitor = self.thread.lock().unwrap_or_else(|error| error.into_inner());
            if let Some(join) = monitor.as_ref() {
                while !join.is_finished() {
                    if Instant::now() >= deadline { return Err("NATIVE_MONITOR_DRAIN_PENDING".into()); }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            if let Some(join) = monitor.take() { let _ = join.join(); }
        }
        Ok(())
    }
}
