use super::bundle::{self, Resources};
use crate::owned_children::{ChildSpec, OwnedChild};
use crate::runtime::RuntimeError;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
fn backend_code(stderr: &[u8], fallback: String) -> String {
    let Ok(value) = serde_json::from_slice::<Value>(stderr) else { return fallback; };
    let Some(code) = value["error"]["code"].as_str() else { return fallback; };
    if code == "internal_error" {
        match value["error"]["message"].as_str() {
            Some("Passive window capture is unavailable while the window is minimized; it was not restored.") => return "UI_CAPTURE_WINDOW_MINIMIZED".to_owned(),
            Some("Passive window capture is unavailable; focus was not changed.") => return "UI_PASSIVE_CAPTURE_UNAVAILABLE".to_owned(),
            Some(message) if message.starts_with("No UIA window found for ") => return "UI_CAPTURE_ROOT_UNAVAILABLE".to_owned(),
            Some(message) if message.starts_with("No native window handle for ") => return "UI_CAPTURE_HWND_UNAVAILABLE".to_owned(),
            Some("Window has zero size. Is it minimized?") => return "UI_CAPTURE_ZERO_SIZE".to_owned(),
            Some("Passive window capture target changed.") => return "UI_CAPTURE_TARGET_CHANGED".to_owned(),
            _ => {}
        }
    }
    if code == "background_target_unavailable" { return "UI_BACKGROUND_TARGET_UNAVAILABLE".to_owned(); }
    if matches!(code,"missing_app"|"missing_selector"|"element_not_found"|"stale_element"|"invalid_arguments"|
        "internal_error"|"zero_size_element"|"foreground_not_target"|"no_interactive_desktop"|"target_moved"|
        "no_target"|"injection_unsupported"|"ambiguous_selector") {
        return format!("UI_BACKEND_{}",code.to_ascii_uppercase());
    }
    fallback
}
pub(super) struct Runner {
    resources: Arc<Resources>, pub root: PathBuf, _pins: Vec<File>,
    child: Mutex<Option<OwnedChild>>, gate: Mutex<()>, log: Mutex<()>,
    captures: Mutex<BTreeSet<PathBuf>>,
    closed: AtomicBool, epoch: AtomicU64,
}
impl Runner {
    pub(super) fn new(resources: Arc<Resources>, root: &Path) -> Result<Self, RuntimeError> {
        let (root, pins) = bundle::private_directory(root)?;
        Ok(Self { resources, root, _pins: pins, child: Mutex::new(None), gate: Mutex::new(()), log: Mutex::new(()), captures: Mutex::new(BTreeSet::new()),
            closed: AtomicBool::new(false), epoch: AtomicU64::new(1) })
    }
    pub(super) fn epoch(&self) -> u64 { self.epoch.load(Ordering::Acquire) }
    pub(super) fn admitted(&self, epoch: u64) -> Result<(), RuntimeError> {
        if self.closed.load(Ordering::Acquire) || epoch != self.epoch() { Err("UI_PROVIDER_REVOKED".into()) } else { Ok(()) }
    }
    pub(super) fn require_exact_passive_capture(&self)->Result<(),RuntimeError>{
        if !self.resources.exact_passive_capture_qualified(){return Err("UI_EXACT_PASSIVE_UNQUALIFIED".into());}
        Ok(())
    }
    pub(super) fn capture_path(&self) -> Result<PathBuf,RuntimeError> {
        self.require_exact_passive_capture()?;
        let mut captures = self.captures.lock().map_err(|_| "UI_CAPTURE_STATE_UNAVAILABLE")?;
        if captures.len() >= 64 { return Err("UI_CAPTURE_CLEANUP_PENDING".into()); }
        let path = self.root.join(format!("{}.png",bundle::uuid()?));
        if path.exists() { return Err("UI_CAPTURE_COLLISION".into()); }
        captures.insert(path.clone()); Ok(path)
    }
    pub(super) fn finish_capture(&self, path: &Path) -> Result<(),RuntimeError> {
        let mut captures = self.captures.lock().map_err(|_| "UI_CAPTURE_STATE_UNAVAILABLE")?;
        if !captures.contains(path) { return Err("UI_CAPTURE_NOT_OWNED".into()); }
        if path.exists() { bundle::check_physical(path)?; std::fs::remove_file(path)?; }
        captures.remove(path); Ok(())
    }
    fn record(&self, value: Value) -> Result<(), RuntimeError> {
        let _log = self.log.lock().map_err(|_| "UI_DIAGNOSTIC_UNAVAILABLE")?;
        let path = self.root.join("diagnostics.jsonl");
        if path.exists() {
            bundle::check_physical(&path)?;
            if std::fs::metadata(&path)?.len() > 1024 * 1024 {
                let previous = self.root.join("diagnostics.previous.jsonl");
                if previous.exists() { bundle::check_physical(&previous)?; std::fs::remove_file(&previous)?; }
                std::fs::rename(&path, previous)?;
            }
        }
        let mut options = OpenOptions::new(); options.create(true).append(true);
        #[cfg(windows)] { use std::os::windows::fs::OpenOptionsExt; options.share_mode(1).custom_flags(0x00200000); }
        let mut file = options.open(&path)?;
        if !file.metadata()?.is_file() { return Err("UI_DIAGNOSTIC_TYPE_INVALID".into()); }
        writeln!(file, "{value}")?; file.flush()?; Ok(())
    }
    pub(super) fn run(&self, arguments: Vec<String>, timeout: Duration) -> Result<Value, RuntimeError> {
        let _gate = self.gate.lock().map_err(|_| "UI_COMMAND_STATE_UNAVAILABLE")?;
        let epoch = self.epoch(); self.admitted(epoch)?;
        if self.child.lock().map_err(|_| "UI_CHILD_STATE_UNAVAILABLE")?.is_some() { return Err("UI_CLEANUP_PENDING".into()); }
        let operation = arguments.get(1).cloned().unwrap_or_else(|| "unknown".to_owned());
        if operation=="screenshot" {
            self.require_exact_passive_capture()?;
            if !arguments.iter().any(|arg|arg=="--exact-passive")
                || arguments.iter().any(|arg|arg=="--focus"||arg.starts_with("--focus=")
                    ||arg=="--capture-screen"||arg.starts_with("--capture-screen=")) {
                return Err("UI_CAPTURE_PASSIVE_MODE_REQUIRED".into());
            }
        }
        let command_id = bundle::uuid()?;
        self.record(json!({"id":command_id,"phase":"start","operation":operation,
            "unix_ms":SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()}))?;
        let mut args: Vec<OsString> = arguments.into_iter().map(Into::into).collect();
        let separator=args.iter().position(|argument|argument=="--").unwrap_or(args.len());
        args.insert(separator,"--json".into());
        let spec = ChildSpec::new(self.resources.winapp.clone(), args,
            self.resources.winapp.parent().ok_or("UI_RESOURCE_PARENT_MISSING")?.to_path_buf(),
            BTreeMap::from([("WINAPP_CLI_TELEMETRY_OPTOUT".into(), Some("1".into())), ("NO_COLOR".into(), Some("1".into()))]));
        #[cfg(windows)] {
            let mut command_units=crate::owned_children::quote_argument(spec.executable.as_os_str())?.len()+1;
            for argument in &spec.arguments {command_units=command_units.checked_add(crate::owned_children::quote_argument(argument)?.len()+1).ok_or("UI_WINDOWS_COMMAND_LINE_LIMIT")?;}
            if command_units>32767 {self.record(json!({"id":command_id,"phase":"end","operation":operation,"result":"UI_WINDOWS_COMMAND_LINE_LIMIT"}))?;return Err("UI_WINDOWS_COMMAND_LINE_LIMIT".into());}
        }
        let started = Instant::now(); let deadline = started + timeout;
        let mut stdout = Vec::new(); let mut stderr = Vec::new(); let mut exit_code = None; let mut pid = None;
        let result = (|| -> Result<Value, RuntimeError> {
            self.admitted(epoch)?;
            {
                let mut slot = self.child.lock().map_err(|_| "UI_CHILD_STATE_UNAVAILABLE")?;
                self.admitted(epoch)?;
                let child = OwnedChild::spawn(&spec)?; pid = Some(child.root_pid());
                *slot = Some(child);
            }
            loop {
                self.admitted(epoch)?;
                {
                    let mut child_guard = self.child.lock().map_err(|_| "UI_CHILD_STATE_UNAVAILABLE")?;
                    let child = child_guard.as_mut().ok_or("UI_COMMAND_REVOKED")?;
                    let mut buffer = [0u8; 16384];
                    for _ in 0..256 {
                        match child.read_stdout(&mut buffer) {
                            Ok(0) => break,
                            Ok(count) => { stdout.extend_from_slice(&buffer[..count]); if stdout.len() + stderr.len() > OUTPUT_LIMIT { return Err("UI_OUTPUT_LIMIT".into()); } },
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                            Err(_) => return Err("UI_STDOUT_FAILED".into()),
                        }
                    }
                    for _ in 0..256 {
                        match child.read_stderr(&mut buffer) {
                            Ok(0) => break,
                            Ok(count) => { stderr.extend_from_slice(&buffer[..count]); if stdout.len() + stderr.len() > OUTPUT_LIMIT { return Err("UI_OUTPUT_LIMIT".into()); } },
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                            Err(_) => return Err("UI_STDERR_FAILED".into()),
                        }
                    }
                    if let Some(exit) = child.try_exit()? {
                        exit_code = exit.code;
                        if child.finish()?.is_some() {
                            child_guard.take();
                            if exit_code != Some(0) { return Err(backend_code(&stderr,format!("UI_BACKEND_EXIT_{}", exit_code.map(|code| code.to_string()).unwrap_or_else(|| "UNKNOWN".to_owned()))).into()); }
                            break;
                        }
                        child.terminate()?;
                    }
                }
                if Instant::now() >= deadline { return Err("UI_COMMAND_DEADLINE".into()); }
                std::thread::sleep(Duration::from_millis(5));
            }
            let text = std::str::from_utf8(&stdout).map_err(|_| "UI_OUTPUT_ENCODING")?;
            let start = text.find(['{', '[']).ok_or("UI_OUTPUT_JSON_MISSING")?;
            serde_json::from_str(&text[start..]).map_err(|_| "UI_OUTPUT_JSON_INVALID".into())
        })();
        let cleanup = self.cleanup_child();
        let code = if cleanup.is_err() { "cleanup_pending" } else if result.is_ok() { "success" } else { "failed" };
        let error_code=result.as_ref().err().map(ToString::to_string).filter(|value|
            value.len()<=80 && value.bytes().all(|byte|byte.is_ascii_uppercase()||byte.is_ascii_digit()||byte==b'_'));
        let receipt = self.record(json!({"id":command_id,"phase":"end","operation":operation,"pid":pid,
            "exit_code":exit_code,"result":code,"error_code":error_code,"stdout_bytes":stdout.len(),"stderr_bytes":stderr.len(),"duration_ms":started.elapsed().as_millis()}));
        cleanup?; receipt?; result
    }
    fn cleanup_child(&self) -> Result<(), RuntimeError> {
        let mut guard = self.child.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(child) = guard.as_mut() {
            child.close_stdin(); child.terminate()?;
            let until = Instant::now() + Duration::from_secs(3);
            loop {
                if child.finish()?.is_some() { break; }
                if Instant::now() >= until { return Err("UI_CLEANUP_PENDING".into()); }
                let mut bytes = [0u8; 16384]; let _ = child.read_stdout(&mut bytes); let _ = child.read_stderr(&mut bytes);
                std::thread::sleep(Duration::from_millis(10));
            }
            guard.take();
        }
        Ok(())
    }
    pub(super) fn close(&self, final_close: bool) -> Result<(), RuntimeError> {
        if final_close { self.closed.store(true, Ordering::Release); }
        self.epoch.fetch_add(1, Ordering::AcqRel); self.cleanup_child()?;
        let paths: Vec<_> = self.captures.lock().unwrap_or_else(|error|error.into_inner()).iter().cloned().collect();
        for path in paths { self.finish_capture(&path)?; }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn code(value:Value)->String {backend_code(value.to_string().as_bytes(),"UI_BACKEND_EXIT_1".to_owned())}
    #[test]fn passive_capture_failures_remain_specific_without_exposing_messages(){
        assert_eq!(code(json!({"error":{"code":"internal_error","message":"Passive window capture is unavailable while the window is minimized; it was not restored."}})),"UI_CAPTURE_WINDOW_MINIMIZED");
        assert_eq!(code(json!({"error":{"code":"internal_error","message":"Passive window capture is unavailable; focus was not changed."}})),"UI_PASSIVE_CAPTURE_UNAVAILABLE");
        assert_eq!(code(json!({"error":{"code":"internal_error","message":"must-not-leak"}})),"UI_BACKEND_INTERNAL_ERROR");
    }
    /// Requires existing independently pinned diagnostic native bundle; no screenshot is launched.
    #[cfg(all(windows, feature = "qualification"))]
    #[test]
    fn unqualified_native_bundle_refuses_capture_before_child_or_file_creation(){
        let bundle=PathBuf::from(std::env::var_os("AGENT_BRIDGE_NATIVE_TEST_BUNDLE").expect("explicit diagnostic bundle"));
        let seal=std::env::var("AGENT_BRIDGE_NATIVE_TEST_MANIFEST_SHA256").expect("explicit seal");
        let resources=Arc::new(Resources::verify(&bundle,&seal).unwrap());
        let root=std::env::temp_dir().join(format!("ab-passive-refusal-{}",bundle::uuid().unwrap()));
        let runner=Runner::new(resources,&root).unwrap();
        assert_eq!(runner.capture_path().unwrap_err().to_string(),"UI_EXACT_PASSIVE_UNQUALIFIED");
        let response=runner.run(vec!["ui".into(),"screenshot".into(),"-w".into(),"1".into(),"--exact-passive".into()],Duration::from_secs(1));
        assert_eq!(response.unwrap_err().to_string(),"UI_EXACT_PASSIVE_UNQUALIFIED");
        assert!(runner.child.lock().unwrap().is_none());
        assert!(runner.captures.lock().unwrap().is_empty());
        assert!(!root.join("diagnostics.jsonl").exists());
        runner.close(true).unwrap();drop(runner);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]fn known_passive_identity_errors_are_distinct_and_redacted(){
        assert_eq!(code(json!({"error":{"code":"internal_error","message":"No UIA window found for private-fixture (PID 1234)."}})),"UI_CAPTURE_ROOT_UNAVAILABLE");
        assert_eq!(code(json!({"error":{"code":"internal_error","message":"No native window handle for private-fixture. Is the window visible?"}})),"UI_CAPTURE_HWND_UNAVAILABLE");
        assert_eq!(code(json!({"error":{"code":"internal_error","message":"Window has zero size. Is it minimized?"}})),"UI_CAPTURE_ZERO_SIZE");
        assert_eq!(code(json!({"error":{"code":"internal_error","message":"unrelated private error"}})),"UI_BACKEND_INTERNAL_ERROR");
    }
    #[test]fn background_target_failures_remain_specific_without_echoing_selectors(){
        assert_eq!(code(json!({"error":{"code":"background_target_unavailable","message":"must-not-leak","selector":"private-canary"}})),"UI_BACKGROUND_TARGET_UNAVAILABLE");
        assert_eq!(code(json!({"error":{"code":"element_not_found","selector":"private-canary"}})),"UI_BACKEND_ELEMENT_NOT_FOUND");
        assert_eq!(code(json!({"error":{"code":"private-canary"}})),"UI_BACKEND_EXIT_1");
    }
}
