use super::wire::FrameDecoder;
use crate::owned_children::{ChildExit, ChildSpec, OwnedChild};
use crate::runtime::RuntimeError;
use serde_json::{json, Value};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(super) const REQUEST_LIMIT: usize = 1024 * 1024;
pub(super) const RESPONSE_LIMIT: usize = 48 * 1024 * 1024;
const DIAGNOSTIC_LIMIT: u64 = 256 * 1024;

#[derive(Debug)]
pub(super) struct Failure {
    pub error: Value,
    pub transport: bool,
    pub receipt: Option<Value>,
    pub download: Option<AuthorizedDownload>,
}
impl Failure {
    fn transport(code: &'static str) -> Self {
        Self { error: json!({"code":code,"message":"Owned browser transport failed; the session is revoked",
            "details":{"session_usable":false,"effect_uncertain":true}}), transport: true, receipt: None, download: None }
    }
}

#[derive(Clone, Debug)]
pub(super) struct AuthorizedDownload(Value);
impl AuthorizedDownload { pub(super) fn into_value(self) -> Value { self.0 } }
#[derive(Debug)]
pub(super) struct Reply { pub result: Value, pub receipt: Value, pub download: Option<AuthorizedDownload> }
#[derive(Clone)]
struct ViewRequest {
    mode: String, screenshot: bool, page_id: Option<String>, max_text: u64, max_elements: u64, max_find: u64,
}
impl ViewRequest {
    fn from_params(params: &Value, bind_page: bool) -> Self {
        Self { mode:params["mode"].as_str().unwrap_or("full").to_owned(), screenshot:params["screenshot"].as_bool().unwrap_or(true),
            page_id:if bind_page { params["page_id"].as_str().map(str::to_owned) } else { None },
            max_text:params["max_text_chars"].as_u64().unwrap_or(8000),
            max_elements:params["max_interactive_elements"].as_u64().unwrap_or(100),
            max_find:params["max_find_results"].as_u64().unwrap_or(20) }
    }
}
#[derive(Clone)]
struct Mutation { kind: String, index: u64 }
#[derive(Clone)]
struct Reservation { id: String, page_id: String, action_count: u64, mutation: Option<Mutation>, view: ViewRequest }
fn admitted_mutation(params: &Value) -> Option<Option<Mutation>> {
    let actions=params["actions"].as_array().filter(|actions|!actions.is_empty() && actions.len()<=20)?;
    let mut mutation=None;
    for (index,action) in actions.iter().enumerate() {
        let kind=action["type"].as_str()?;
        match kind {
            "wait"|"wait_selector"|"wait_url"|"wait_text"=>{},
            "goto"|"click"|"hover"|"drag"|"fill"|"type_text"|"set_checked"|"press"|"select"|"set_files"|"download"|"scroll"|"navigation"=>{
                if mutation.is_some() || (kind=="download" && actions.len()!=1) { return None; }
                mutation=Some(Mutation { kind:kind.to_owned(),index:index as u64 });
            }
            _=>return None,
        }
    }
    Some(mutation)
}

pub(super) struct Worker {
    child: OwnedChild,
    next: u64,
    session_id: Option<String>,
    reservation: Option<Reservation>,
    revoked: bool,
    cancel: Arc<AtomicBool>,
    diagnostics: File,
    diagnostic_bytes: u64,
    stderr: Vec<u8>,
    dropped_stderr: u64,
    pub exit: Option<ChildExit>,
}

impl Worker {
    pub(super) fn spawn(spec: &ChildSpec, directory: &Path, cancel: Arc<AtomicBool>) -> Result<Self, RuntimeError> {
        let diagnostics = OpenOptions::new().create_new(true).write(true).open(directory.join("diagnostic.jsonl"))?;
        let child = OwnedChild::spawn(spec)?;
        let mut value = Self { child, next: 0, session_id: None, reservation: None, revoked: false, cancel, diagnostics,
            diagnostic_bytes: 0, stderr: Vec::new(), dropped_stderr: 0, exit: None };
        value.log(json!({"event":"worker_spawned","pid":value.child.root_pid()}));
        Ok(value)
    }
    pub(super) fn child(&self) -> &OwnedChild { &self.child }
    pub(super) fn revoked(&self) -> bool { self.revoked }
    fn log(&mut self, value: Value) {
        let Ok(mut line) = serde_json::to_vec(&value) else { return; };
        line.push(b'\n');
        if self.diagnostic_bytes.saturating_add(line.len() as u64) <= DIAGNOSTIC_LIMIT {
            if self.diagnostics.write_all(&line).is_ok() { self.diagnostic_bytes += line.len() as u64; }
        }
    }
    pub(super) fn cleanup_diagnostic(&mut self, stage: &'static str, error: &RuntimeError) {
        let os = error.downcast_ref::<io::Error>();
        self.log(json!({"event":"cleanup_pending","stage":stage,
            "os_error":os.and_then(io::Error::raw_os_error),
            "io_kind":os.map(|e|format!("{:?}",e.kind()))}));
    }
    fn drain_stderr(&mut self) -> io::Result<()> {
        let mut buffer = [0u8; 8192];
        for _ in 0..32 {
            match self.child.read_stderr(&mut buffer) {
                Ok(0) => return Ok(()),
                Ok(count) => {
                    for byte in &buffer[..count] {
                        if *byte == b'\n' {
                            let line = std::mem::take(&mut self.stderr);
                            if let Ok(value) = serde_json::from_slice::<Value>(&line) {
                                if value["component"] == "browser-worker" {
                                    let code = value["code"].as_str().filter(|s| s.len() <= 80 && s.bytes().all(|c| c.is_ascii_uppercase() || c == b'_'));
                                    if let Some(code) = code {
                                        let id = value["request_id"].as_str().filter(|s| s.len() <= 20 && s.starts_with('r') && s[1..].bytes().all(|c| c.is_ascii_digit()));
                                        self.log(json!({"event":"worker_diagnostic","code":code,
                                            "request_id":id,"session_usable":value["session_usable"].as_bool()}));
                                        continue;
                                    }
                                }
                            }
                            self.dropped_stderr = self.dropped_stderr.saturating_add(line.len() as u64);
                        } else if self.stderr.len() < 8192 { self.stderr.push(*byte); }
                        else { self.dropped_stderr = self.dropped_stderr.saturating_add(1); }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    pub(super) fn rpc(&mut self, method: &str, params: Value, budget: Duration) -> Result<Reply, Failure> {
        self.rpc_inner(method, params, budget, false)
    }
    fn rpc_inner(&mut self, method: &str, params: Value, budget: Duration, closing: bool) -> Result<Reply, Failure> {
        if self.revoked || self.exit.is_some() { return Err(Failure::transport("WORKER_REVOKED")); }
        self.next = self.next.checked_add(1).filter(|value| *value <= 9_999_999_999_999_999)
            .ok_or_else(|| Failure::transport("PROTOCOL_SEQUENCE_EXHAUSTED"))?;
        let id = format!("r{}", self.next);
        let body = serde_json::to_vec(&json!({"v":2,"id":id,"method":method,"params":params}))
            .map_err(|_| Failure::transport("PROTOCOL_REQUEST_INVALID"))?;
        if body.len() > REQUEST_LIMIT { return Err(Failure { error:json!({"code":"REQUEST_LIMIT","message":"Browser request exceeds 1 MiB"}),transport:false, receipt:None, download:None }); }
        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&(body.len() as u32).to_le_bytes()); frame.extend_from_slice(&body);
        let deadline = Instant::now() + budget;
        let mut written = 0;
        let mut decoder = FrameDecoder::new(RESPONSE_LIMIT);
        let mut buffer = [0u8; 65536];
        let reservation = self.reservation.clone();
        if matches!(method, "act" | "cancel_act") { self.reservation = None; }
        let outcome = (|| {
            loop {
                if !closing && self.cancel.load(Ordering::Acquire) { return Err(Failure::transport("PROVIDER_CLOSING")); }
                if Instant::now() >= deadline { return Err(Failure::transport("WORKER_IPC_DEADLINE")); }
                if written < frame.len() {
                    match self.child.write_stdin(&frame[written..]) {
                        Ok(0) => return Err(Failure::transport("WORKER_PIPE_CLOSED")),
                        Ok(count) => written += count,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {},
                        Err(_) => return Err(Failure::transport("WORKER_PIPE_WRITE")),
                    }
                }
                self.drain_stderr().map_err(|_| Failure::transport("WORKER_DIAGNOSTIC_PIPE"))?;
                match self.child.read_stdout(&mut buffer) {
                    Ok(0) => { let _ = decoder.eof(); return Err(Failure::transport("WORKER_PIPE_EOF")); },
                    Ok(count) => {
                        if written != frame.len() { return Err(Failure::transport("WORKER_UNSOLICITED_REPLY")); }
                        if let Some(bytes) = decoder.push(&buffer[..count]).map_err(|_| Failure::transport("WORKER_FRAME_INVALID"))? {
                            let value: Value = serde_json::from_slice(&bytes).map_err(|_| Failure::transport("WORKER_JSON_INVALID"))?;
                            return validate_reply(value, &id, method, &params, self.session_id.as_deref(), reservation.as_ref());
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {},
                    Err(_) => return Err(Failure::transport("WORKER_PIPE_READ")),
                }
                if self.child.try_exit().map_err(|_| Failure::transport("WORKER_PROCESS_STATE"))?.is_some() {
                    return Err(Failure::transport("WORKER_EXITED"));
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        })();
        if let Ok(reply) = &outcome {
            if method == "init" { self.session_id = reply.result["session_id"].as_str().map(str::to_owned); }
            if method == "reserve_act" {
                self.reservation = Some(Reservation { id: reply.result["reservation_id"].as_str().unwrap().to_owned(),
                    page_id: reply.result["page_id"].as_str().unwrap().to_owned(), action_count: reply.result["action_count"].as_u64().unwrap(),
                    mutation:admitted_mutation(&params).expect("method-validated action kinds"), view:ViewRequest::from_params(&params,false) });
            }
        }
        if let Err(failure) = &outcome {
            if failure.transport { self.revoked = true; }
            self.log(json!({"event":"rpc_failed","request_id":id,"transport":failure.transport,"code":failure.error["code"]}));
        }
        outcome
    }
    pub(super) fn revoke(&mut self) { self.revoked = true; self.reservation = None; }
    // A request for another healthy session must not wait for this owner's drain.
    // Admission closes first; the retained owner is polled or explicitly retried.
    pub(super) fn poll_cleanup(&mut self) -> Result<bool, RuntimeError> {
        if self.exit.is_some() { return Ok(true); }
        self.revoke(); self.child.close_stdin(); self.child.terminate()?;
        let _ = self.drain_stderr();
        let mut buffer = [0u8;65536];
        for _ in 0..4 { match self.child.read_stdout(&mut buffer) { Ok(n) if n > 0 => {}, _ => break } }
        if let Some(exit) = self.child.finish()? {
            self.exit = Some(exit);
            self.log(json!({"event":"job_empty","exit_code":exit.code,"unstructured_diagnostic_bytes":self.dropped_stderr}));
            let _ = self.diagnostics.sync_all(); return Ok(true);
        }
        Ok(false)
    }
    pub(super) fn root_exited(&mut self) -> Result<bool, RuntimeError> { Ok(self.child.try_exit()?.is_some()) }
    fn drain_until(&mut self, deadline: Instant) -> Result<bool, RuntimeError> {
        let mut buffer = [0u8; 65536];
        loop {
            let _ = self.drain_stderr();
            for _ in 0..32 {
                match self.child.read_stdout(&mut buffer) { Ok(n) if n > 0 => {}, _ => break }
            }
            if let Some(exit) = self.child.finish()? {
                self.exit = Some(exit);
                self.log(json!({"event":"job_empty","exit_code":exit.code,"unstructured_diagnostic_bytes":self.dropped_stderr}));
                let _ = self.diagnostics.sync_all();
                return Ok(true);
            }
            if Instant::now() >= deadline { return Ok(false); }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    pub(super) fn close(&mut self, graceful: bool) -> Result<(), RuntimeError> {
        if self.exit.is_some() { return Ok(()); }
        if graceful && !self.revoked {
            let _ = self.rpc_inner("close", json!({}), Duration::from_secs(5), true);
            self.child.close_stdin();
            if self.drain_until(Instant::now() + Duration::from_secs(2))? { self.revoked = true; return Ok(()); }
        }
        self.revoked = true;
        self.child.close_stdin();
        self.child.terminate()?;
        if self.drain_until(Instant::now() + Duration::from_secs(5))? { Ok(()) }
        else { Err("BROWSER_CLEANUP_PENDING: owned Job is not verified empty".into()) }
    }
}

fn bounded_text(value: &Value, maximum: usize) -> bool {
    value.as_str().is_some_and(|text| !text.is_empty() && text.len() <= maximum)
}
fn uuid(value: &Value) -> bool {
    value.as_str().is_some_and(|text| text.len() == 36 && text.bytes().enumerate().all(|(i,b)|
        if [8,13,18,23].contains(&i) { b == b'-' } else { b.is_ascii_hexdigit() && !b.is_ascii_uppercase() })
        && &text[14..15] == "4" && matches!(text.as_bytes()[19], b'8'|b'9'|b'a'|b'b'))
}
fn pages(value: &Value) -> bool {
    value.as_array().is_some_and(|rows| rows.len() <= 1024 && rows.iter().all(|row|
        bounded_text(&row["page_id"],512) && row["url"].is_string() && row["title"].is_string() && row["active"].is_boolean()))
}
fn summary(value: &Value, session_id: &str) -> bool {
    value["session_id"] == session_id && value["headless"].is_boolean() && value["active"].is_boolean()
        && pages(&value["pages"]) && value["pages"].as_array().is_some_and(|rows| rows.is_empty()
            || (bounded_text(&value["page_id"],512) && rows.iter().any(|page|page["page_id"] == value["page_id"])))
}
fn snapshot(value: &Value, receipt: &Value, session_id: &str, request: &ViewRequest) -> bool {
    if value["session_id"]!=session_id || !bounded_text(&value["page_id"],512) || !uuid(&value["browser_observation_id"])
        || !pages(&value["pages"]) || receipt["observation_page_id"]!=value["page_id"]
        || receipt["browser_observation_id"]!=value["browser_observation_id"]
        || !value["url"].is_string() || !value["title"].is_string()
        || request.page_id.as_ref().is_some_and(|page|value["page_id"]!=*page)
        || !value["pages"].as_array().unwrap().iter().any(|page|page["page_id"]==value["page_id"]) { return false; }
    let image=value.get("_screenshot_png_base64");
    if request.mode=="find" {
        return image.is_none() && value["matches"].as_array().is_some_and(|rows|rows.len() as u64<=request.max_find);
    }
    (if request.screenshot { image.is_some_and(|v|bounded_text(v,(32*1024*1024+2)/3*4)) } else { image.is_none() })
        && value["text"].as_str().is_some_and(|text|text.encode_utf16().count() as u64<=request.max_text)
        && value["interactive_elements"].as_array().is_some_and(|rows|rows.len() as u64<=request.max_elements)
}
fn valid_receipt(value: &Value, method: &str, session_id: &str, reservation: Option<&Reservation>) -> bool {
    let Some(object) = value.as_object() else { return false; };
    if serde_json::to_vec(value).map_or(true, |bytes|bytes.len() > 16*1024)
        || value["operation"] != method || value["session_id"] != session_id
        || !bounded_text(&value["phase"],64) || !value["session_usable"].is_boolean()
        || !value["effect_uncertain"].is_boolean() || !value["upload_effect_started"].is_boolean()
        || !value["completed_actions"].as_u64().is_some_and(|n|n <= 20)
        || !object.contains_key("failed_action_index")
        || !(value["failed_action_index"].is_null() || value["failed_action_index"].as_u64().is_some_and(|n|n < 20))
        || object.keys().any(|key| !matches!(key.as_str(),"operation"|"session_id"|"page_id"|"observation_page_id"|"browser_observation_id"|"reservation_id"|"created_page_id"|"phase"|"previous_phase"|"completed_actions"|"failed_action_index"|"session_usable"|"effect_uncertain"|"upload_effect_started"|"download")) { return false; }
    for field in ["page_id","created_page_id","observation_page_id","previous_phase"] {
        if object.contains_key(field) && !bounded_text(&value[field],512) { return false; }
    }
    for field in ["browser_observation_id","reservation_id"] {
        if object.contains_key(field) && !uuid(&value[field]) { return false; }
    }
    let completed=value["completed_actions"].as_u64().unwrap();
    let failed=value["failed_action_index"].as_u64();
    let mut download_completed=false;
    if method=="act" {
        if let Some(reserved)=reservation {
            if value.get("reservation_id").is_some() && value["reservation_id"]!=reserved.id { return false; }
            if value.get("page_id").is_some() && value["page_id"]!=reserved.page_id { return false; }
            if completed>reserved.action_count || failed.is_some_and(|index|index!=completed || index>=reserved.action_count) { return false; }
            if completed>0 || value["effect_uncertain"]==true || value["upload_effect_started"]==true || object.contains_key("download") {
                if value["reservation_id"]!=reserved.id || value["page_id"]!=reserved.page_id { return false; }
            }
            if let Some(mutation)=&reserved.mutation {
                download_completed=mutation.kind=="download" && completed>mutation.index;
                if value["upload_effect_started"]==true && (mutation.kind!="set_files" || completed<mutation.index) { return false; }
                if value["effect_uncertain"]==true && completed!=mutation.index { return false; }
            } else if value["upload_effect_started"]==true || value["effect_uncertain"]==true { return false; }
        } else if object.contains_key("download") || value["upload_effect_started"]==true { return false; }
    } else if object.contains_key("download") || value["upload_effect_started"]==true { return false; }
    if download_completed!=object.contains_key("download") { return false; }
    if let Some(download)=object.get("download") {
        if value["effect_uncertain"]!=false || !value["failed_action_index"].is_null()
            || !download.as_object().is_some_and(|d|d.len()==4 && d.keys().all(|key|matches!(key.as_str(),"path"|"suggested_filename"|"bytes"|"sha256")))
            || !bounded_text(&download["path"],4096) || !bounded_text(&download["suggested_filename"],720)
            || !download["bytes"].as_u64().is_some_and(|n|n<=64*1024*1024)
            || !download["sha256"].as_str().is_some_and(|hash|hash.len()==64 && hash.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) { return false; }
    }
    true
}
fn validate_reply(value: Value, expected_id: &str, method: &str, params: &Value,
    expected_session: Option<&str>, reservation: Option<&Reservation>) -> Result<Reply, Failure>
{
    let object = value.as_object().ok_or_else(|| Failure::transport("WORKER_ENVELOPE_INVALID"))?;
    if value["v"] != 2 || value["id"] != expected_id || !value["ok"].is_boolean() || object.len() != 5
        || object.keys().any(|key| !matches!(key.as_str(), "v" | "id" | "ok" | "result" | "error" | "receipt")) {
        return Err(Failure::transport("WORKER_ENVELOPE_INVALID"));
    }
    let session_id = expected_session.or_else(||params["session_id"].as_str()).unwrap_or("");
    let receipt = &value["receipt"];
    if session_id.is_empty() || (method=="act" && reservation.is_some_and(|reserved|params["reservation_id"]!=reserved.id))
        || !valid_receipt(receipt, method, session_id, reservation) { return Err(Failure::transport("WORKER_RECEIPT_INVALID")); }
    let download=receipt.get("download").cloned().map(AuthorizedDownload);
    let invalid_payload = |code| {
        let mut failure=Failure::transport(code);
        // Identity and prefix have already passed independent receipt validation.
        // Revoke an invalid view without erasing the separately valid effect record.
        failure.receipt=Some(receipt.clone()); failure.download=download.clone(); failure
    };
    if value["ok"] == true {
        let result = &value["result"];
        let valid = result.is_object() && !object.contains_key("error") && match method {
            "init" => summary(result,session_id) && result["protocol_version"] == 2 && result["playwright_version"] == "1.63.0"
                && result["node_version"] == "24.14.0" && result["worker_pid"].as_u64().is_some_and(|pid|pid > 0)
                && result["session_usable"] == true && receipt["session_usable"] == true,
            "start" | "session" => summary(result,session_id) && receipt["session_usable"] == true
                && (method != "session" || params["action"] != "new_page" || (bounded_text(&receipt["created_page_id"],512) && receipt["created_page_id"] == result["page_id"])),
            "snapshot" => snapshot(result,receipt,session_id,&ViewRequest::from_params(params,true)) && receipt["session_usable"] == true,
            "reserve_act" => admitted_mutation(params).is_some() && result["session_id"] == session_id && uuid(&result["reservation_id"]) && receipt["reservation_id"] == result["reservation_id"]
                && bounded_text(&result["page_id"],512) && receipt["page_id"] == result["page_id"] && receipt["session_usable"] == true
                && params["actions"].as_array().is_some_and(|actions| result["action_count"].as_u64() == Some(actions.len() as u64)
                    && result["upload_file_count"].as_u64() == Some(actions.iter().find(|a|a["type"] == "set_files")
                        .and_then(|a|a["files"].as_array()).map_or(0,|files|files.len() as u64))),
            "cancel_act" => result["session_id"] == session_id && result["reservation_id"] == params["reservation_id"] && result["cancelled"].is_boolean(),
            "act" => reservation.is_some_and(|reserved|params["reservation_id"] == reserved.id
                && snapshot(result,receipt,session_id,&reserved.view) && receipt["session_usable"] == true
                && receipt["reservation_id"] == reserved.id && receipt["page_id"] == reserved.page_id
                && result["completed_actions"].as_u64() == Some(reserved.action_count) && receipt["completed_actions"] == result["completed_actions"]),
            "close" => result["session_id"] == session_id && result["closed"] == true && receipt["session_usable"] == false,
            _ => false,
        };
        if !valid { return Err(invalid_payload("WORKER_RESULT_INVALID")); }
        Ok(Reply { result:result.clone(), receipt:receipt.clone(), download })
    } else {
        let error = &value["error"];
        if object.contains_key("result") || !error.is_object() || !bounded_text(&error["code"],80) || !bounded_text(&error["message"],8192)
            || !error.as_object().is_some_and(|e|e.len()==3 && e.keys().all(|key|matches!(key.as_str(),"code"|"message"|"details")))
            || !error["details"].is_object() || serde_json::to_vec(&error["details"]).map_or(true,|bytes|bytes.len()>16*1024)
            || !error["details"]["session_usable"].is_boolean()
            || error["details"]["session_usable"] != receipt["session_usable"] {
            return Err(invalid_payload("WORKER_ERROR_INVALID"));
        }
        Err(Failure { error:error.clone(), transport:false, receipt:Some(receipt.clone()), download })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn receipt(method: &str) -> Value { json!({"operation":method,"session_id":"s1","phase":"action","completed_actions":1,
        "failed_action_index":1,"effect_uncertain":false,"session_usable":true,"upload_effect_started":false}) }
    fn validate(value: Value, method: &str) -> Result<Reply,Failure> { validate_reply(value,"r7",method,&json!({}),Some("s1"),None) }
    #[test]
    fn review_empty_success_is_not_a_browser_observation() {
        for method in ["snapshot","act","session","start","reserve_act","cancel_act","close"] {
            let failure=validate(json!({"v":2,"id":"r7","ok":true,"result":{},"receipt":receipt(method)}),method).unwrap_err();
            assert!(failure.transport);
            assert_eq!(failure.receipt.unwrap()["completed_actions"],1,"invalid views must not erase an independently validated prefix");
        }
    }
    #[test]
    fn review_timeout_without_positive_session_usability_revokes_authority() {
        for state in [Value::Null,json!(false),json!("true")] {
            let mut error=json!({"code":"PLAYWRIGHT_TIMEOUT","message":"Timed out","details":{"completed_actions":1}});
            if !state.is_null() { error["details"]["session_usable"]=state; }
            assert!(validate(json!({"v":2,"id":"r7","ok":false,"error":error,"receipt":receipt("act")}),"act").unwrap_err().transport);
        }
    }
    #[test]
    fn correlation_and_protocol_errors_cannot_be_mistaken_for_domain_timeouts() {
        let ordinary=validate(json!({"v":2,"id":"r7","ok":false,"error":{"code":"PLAYWRIGHT_TIMEOUT","message":"Timed out","details":{"session_usable":true,"completed_actions":1}},"receipt":receipt("act")}),"act").unwrap_err();
        assert!(!ordinary.transport); assert_eq!(ordinary.receipt.unwrap()["completed_actions"],1);
        for (version,id) in [(1,"r7"),(2,"r6")] {
            assert!(validate(json!({"v":version,"id":id,"ok":true,"result":{},"receipt":receipt("snapshot")}),"snapshot").unwrap_err().transport);
        }
        for code in ["INVALID_ARGUMENT","OBSERVATION_INVALID","OBSERVATION_STALE"] {
            assert!(!validate(json!({"v":2,"id":"r7","ok":false,"error":{"code":code,"message":"Expected domain failure","details":{"session_usable":true}},"receipt":receipt("reserve_act")}),"reserve_act").unwrap_err().transport);
        }
    }
    #[test]
    fn completed_prefix_and_page_identity_are_checked_against_the_reserved_request() {
        let reserved=Reservation { id:"a3e96910-6e46-4386-8bc3-45006033ff49".into(),page_id:"p1".into(),action_count:1,mutation:None,view:ViewRequest::from_params(&json!({"screenshot":false}),false) };
        let mut r=receipt("act"); r["reservation_id"]=json!(reserved.id); r["page_id"]=json!("p2");
        assert!(!valid_receipt(&r,"act","s1",Some(&reserved)));
        r["page_id"]=json!("p1"); r["completed_actions"]=json!(2);
        assert!(!valid_receipt(&r,"act","s1",Some(&reserved)));
        r["completed_actions"]=json!(1); r["failed_action_index"]=Value::Null; assert!(valid_receipt(&r,"act","s1",Some(&reserved)));
    }
    fn round2_reservation() -> Reservation {
        Reservation { id:"a3e96910-6e46-4386-8bc3-45006033ff49".into(),page_id:"p1".into(),action_count:1,mutation:Some(Mutation { kind:"download".into(),index:0 }),view:ViewRequest::from_params(&json!({"screenshot":false}),false) }
    }
    fn round2_view(page: &str) -> Value {
        json!({"session_id":"s1","page_id":page,"browser_observation_id":"9a6a5f4b-019e-4cd8-a5d8-81d20e686e58",
            "pages":[{"page_id":page,"url":"http://fixture/","title":"Witness","active":true}],"url":"http://fixture/","title":"Witness","text":"Observed","interactive_elements":[],"completed_actions":1})
    }
    fn round2_receipt(method: &str, page: &str) -> Value {
        let mut r=receipt(method); r["phase"]=json!("complete"); r["failed_action_index"]=Value::Null;
        r["page_id"]=json!(page); r["observation_page_id"]=json!(page);
        r["browser_observation_id"]=round2_view(page)["browser_observation_id"].clone();
        if method=="act" { r["reservation_id"]=json!(round2_reservation().id); } else { r["completed_actions"]=json!(0); }
        r
    }
    fn round2_download() -> Value { json!({"path":"C:/private/owned.bin","suggested_filename":"owned.bin","bytes":17,"sha256":"a".repeat(64)}) }
    #[test]
    fn round2_download_descriptor_is_not_authority_for_an_unrequested_transfer() {
        let mut r=round2_receipt("snapshot","p1"); r["download"]=round2_download();
        let reply=validate_reply(json!({"v":2,"id":"r7","ok":true,"result":round2_view("p1"),"receipt":r}),"r7","snapshot",&json!({"screenshot":false}),Some("s1"),None);
        assert!(reply.is_err(),"snapshot cannot authorize artifact publication");
        let failure=reply.unwrap_err(); assert!(failure.receipt.is_none(),"unauthorized download must not survive as a publishable receipt");
        assert!(failure.download.is_none());
        let reserved=round2_reservation(); let mut r=round2_receipt("act","p1"); r["download"]=round2_download();
        let failure=validate_reply(json!({"v":2,"id":"r7","ok":true,"result":{},"receipt":r}),"r7","act",&json!({"reservation_id":"wrong-reservation"}),Some("s1"),Some(&reserved)).unwrap_err();
        assert!(failure.download.is_none(),"a reply cannot borrow authority from a different reservation");
    }
    #[test]
    fn round2_successful_download_requires_its_completed_descriptor() {
        let reserved=round2_reservation();
        let reply=validate_reply(json!({"v":2,"id":"r7","ok":true,"result":round2_view("p1"),"receipt":round2_receipt("act","p1")}),"r7","act",&json!({"reservation_id":reserved.id}),Some("s1"),Some(&reserved));
        assert!(reply.is_err(),"a completed admitted download without descriptor cannot be successful");
    }
    #[test]
    fn round2_snapshot_checks_the_requested_page_and_image_policy() {
        for (params,page) in [(json!({"page_id":"p1","screenshot":false}),"p2"),(json!({"page_id":"p1","screenshot":true}),"p1"),(json!({"page_id":"p1"}),"p1")] {
            assert!(validate_reply(json!({"v":2,"id":"r7","ok":true,"result":round2_view(page),"receipt":round2_receipt("snapshot",page)}),"r7","snapshot",&params,Some("s1"),None).is_err());
        }
    }
    #[test]
    fn round2_timeout_false_false_preserves_the_domain_cause_and_prefix() {
        let mut r=receipt("act"); r["session_usable"]=json!(false);
        let failure=validate(json!({"v":2,"id":"r7","ok":false,"error":{"code":"PLAYWRIGHT_TIMEOUT","message":"Timed out","details":{"session_usable":false,"completed_actions":1}},"receipt":r}),"act").unwrap_err();
        assert!(!failure.transport,"coherent closed timeout is a domain failure, followed by revocation");
        assert_eq!(failure.error["code"],"PLAYWRIGHT_TIMEOUT"); assert_eq!(failure.receipt.unwrap()["completed_actions"],1);
    }
    #[test]
    fn round2_private_errors_cannot_smuggle_fields_outside_the_bounded_error_contract() {
        let failure=validate(json!({"v":2,"id":"r7","ok":false,"error":{"code":"PLAYWRIGHT_FAILED","message":"Failed","details":{"session_usable":true},"unbounded_extra":"must never be copied to the public envelope"},"receipt":receipt("snapshot")}),"snapshot").unwrap_err();
        assert!(failure.transport); assert!(failure.error.get("unbounded_extra").is_none());
    }
    #[test]
    fn round2_view_policy_keeps_compact_find_and_after_action_popup_semantics() {
        let view=round2_view("p1"); let r=round2_receipt("snapshot","p1");
        assert!(validate_reply(json!({"v":2,"id":"r7","ok":true,"result":view,"receipt":r}),"r7","snapshot",&json!({"page_id":"p1","screenshot":false}),Some("s1"),None).is_ok());
        let mut found=round2_view("p1"); found["matches"]=json!([]);
        assert!(validate_reply(json!({"v":2,"id":"r7","ok":true,"result":found,"receipt":r}),"r7","snapshot",&json!({"page_id":"p1","mode":"find","find_query":"witness"}),Some("s1"),None).is_ok(),"compact find never requires a screenshot");
        let reserved=Reservation { id:round2_reservation().id,page_id:"p1".into(),action_count:1,mutation:Some(Mutation{kind:"click".into(),index:0}),view:ViewRequest::from_params(&json!({"screenshot":false}),false) };
        let mut receipt=round2_receipt("act","p1"); receipt["observation_page_id"]=json!("p2");
        assert!(validate_reply(json!({"v":2,"id":"r7","ok":true,"result":round2_view("p2"),"receipt":receipt}),"r7","act",&json!({"reservation_id":reserved.id}),Some("s1"),Some(&reserved)).is_ok(),"an after-action popup is a fresh observation, not the mutation target");
    }

}
