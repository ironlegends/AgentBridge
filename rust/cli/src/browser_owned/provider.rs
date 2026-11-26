#[cfg(windows)]
use super::{BrowserConfig, BrowserTransferCallbacks};
#[cfg(windows)]
use super::profiles::{opaque_id, physical_directory, profile_id, remove_physical_tree, Profiles, SessionPaths};
#[cfg(windows)]
use super::resources::{digest, node_path, pin, Resources};
#[cfg(windows)]
use super::worker::{AuthorizedDownload, Failure, Reply, Worker, REQUEST_LIMIT};
use super::worker::RESPONSE_LIMIT;
#[cfg(windows)]
use crate::agent_desktop::AgentDesktopHandle;
#[cfg(windows)]
use crate::owned_children::ChildSpec;
#[cfg(windows)]
use crate::provider_owner::ProviderOwner;
use crate::runtime::RuntimeError;
#[cfg(windows)]
use crate::session_profile::{rank, ProfileControl};
#[cfg(windows)]
use agent_bridge_desktop::DesktopProfile;
use agent_bridge_gateway::{ToolCallResult, ToolContent};
#[cfg(windows)]
use agent_bridge_gateway::{ToolDefinition, ToolMapHandler};
use serde_json::{json, Map, Value};
#[cfg(windows)]
use std::collections::{BTreeMap, HashMap};
#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use std::fs::{self, File};
use std::io::{self, Write};
#[cfg(windows)]
use std::path::PathBuf;
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(windows)]
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(windows)]
struct Session {
    id: String,
    cleanup_error: Option<Value>,
    worker: Worker,
    paths: SessionPaths,
    profile_id: Option<String>,
    lease_id: Option<String>,
    headless: bool,
    timeout_ms: u64,
}
#[cfg(windows)]
struct State {
    resources: Option<Resources>,
    profiles: Option<Profiles>,
    sessions: HashMap<String, Session>,
}
#[cfg(windows)]
struct Provider {
    state: Mutex<State>,
    closing: AtomicBool,
    cancel: Arc<AtomicBool>,
    desktops: AgentDesktopHandle,
    transfers: BrowserTransferCallbacks,
}
#[cfg(windows)]
enum DownloadFailure {
    Invalid(RuntimeError),
    Publication(RuntimeError, bool),
    Cleanup(RuntimeError),
}

#[cfg(windows)]
fn tool_failure(error: Value) -> ToolCallResult { tool_failure_with_limit(error,RESPONSE_LIMIT-1024) }
fn error_result(error: Value) -> ToolCallResult {
    let mut result=ToolCallResult::structured(error.to_string(),json!({"error":error})); result.is_error=true; result
}
fn compact_error(error: &Value, minimal: bool) -> Value {
    let mut details=Map::new();
    for field in ["session_id","page_id","created_page_id","observation_page_id","completed_actions","failed_action_index","phase","previous_phase",
        "effect_uncertain","session_usable","artifact_committed","cleanup_verified","job_cleanup_verified","cleanup_pending","upload_effect_started",
        "staging_cleanup_verified","cause_code","cause_os_error","postprocessing_error","download_disposition"] {
        if let Some(value)=error["details"].get(field) {
            if value.is_boolean() || value.is_null() || value.is_number() || value.as_str().is_some_and(|text|text.len()<=512) { details.insert(field.into(),value.clone()); }
        }
    }
    if let Some(artifact)=error["details"].get("artifact") {
        if minimal {
            let mut identity=Map::new();
            for field in ["artifact_id","file_id","id","sha256","bytes","size"] {
                if let Some(value)=artifact.get(field) { if value.is_number() || value.as_str().is_some_and(|text|text.len()<=512) { identity.insert(field.into(),value.clone()); } }
            }
            details.insert("artifact".into(),Value::Object(identity));
        } else { details.insert("artifact".into(),compact_artifact(artifact)); }
    }
    details.insert("response_truncated".into(),json!(true));
    let code=error["code"].as_str().filter(|text|text.len()<=80).unwrap_or("BROWSER_ERROR_RESPONSE_LIMIT");
    let message=if minimal { "Browser error details exceeded the response budget; execution receipt retained" }
        else { error["message"].as_str().filter(|text|text.len()<=8192).unwrap_or("Browser error details exceeded the response budget") };
    json!({"code":code,"message":message,"details":details})
}
fn tool_failure_with_limit(error: Value, limit: usize) -> ToolCallResult {
    let result=error_result(error.clone());
    if serde_json::to_writer(BudgetWriter(0,limit),&result).is_ok() { return result; }
    for minimal in [false,true] {
        let result=error_result(compact_error(&error,minimal));
        if serde_json::to_writer(BudgetWriter(0,limit),&result).is_ok() { return result; }
    }
    // Production reserves almost 48 MiB; this final envelope has bounded scalar
    // fields and protects even a smaller test/integration boundary.
    let details=&error["details"];
    let result=error_result(json!({"code":"BROWSER_ERROR_RESPONSE_LIMIT","message":"Browser error exceeded the response budget",
        "details":{"completed_actions":details["completed_actions"].as_u64(),"session_usable":details["session_usable"].as_bool(),
            "phase":"encode_mcp_error","effect_uncertain":details["effect_uncertain"].as_bool()}}));
    debug_assert!(serde_json::to_writer(BudgetWriter(0,limit),&result).is_ok());
    result
}

#[cfg(windows)]
fn failure(code: &str) -> ToolCallResult {
    tool_failure(json!({"code":code.split(':').next().unwrap_or("BROWSER_FAILED"),"message":code}))
}
#[cfg(windows)]
fn text_field<'a>(arguments: &'a Map<String, Value>, name: &str) -> Result<&'a str, RuntimeError> {
    arguments.get(name).and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or_else(|| format!("INVALID_ARGUMENT: {name} is required").into())
}
#[cfg(windows)]
fn optional_text(arguments: &Map<String, Value>, name: &str) -> Option<String> {
    arguments.get(name).and_then(Value::as_str).map(str::to_owned)
}
#[cfg(windows)]
fn timeout(arguments: &Map<String, Value>) -> u64 { arguments.get("timeout_ms").and_then(Value::as_u64).unwrap_or(15_000) }
#[cfg(windows)]
fn child_environment() -> BTreeMap<OsString, Option<OsString>> {
    let mut env = BTreeMap::new();
    for name in ["NODE_OPTIONS", "NODE_PATH", "NODE_EXTRA_CA_CERTS", "NODE_DEBUG", "NODE_DEBUG_NATIVE", "NODE_REPL_HISTORY", "NODE_REDIRECT_WARNINGS", "NODE_V8_COVERAGE", "NODE_ICU_DATA", "NODE_TLS_REJECT_UNAUTHORIZED", "OPENSSL_CONF", "OPENSSL_MODULES", "DEBUG", "PWDEBUG", "PW_TEST_DEBUG", "PLAYWRIGHT_BROWSERS_PATH", "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH", "CHROME_LOG_FILE", "SSLKEYLOGFILE", "ELECTRON_RUN_AS_NODE"] {
        env.insert(name.into(), None);
    }
    env.insert("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD".into(), Some("1".into()));
    env.insert("NODE_ENV".into(), Some("production".into()));
    env
}

#[cfg(windows)]
pub(super) fn attach(config: BrowserConfig, profile: Arc<ProfileControl>, desktops: AgentDesktopHandle,
    transfers: BrowserTransferCallbacks, catalog: &mut Vec<ToolDefinition>, handlers: &mut ToolMapHandler)
    -> Result<ProviderOwner, RuntimeError>
{
    let resources = Resources::verify(&config.bundle_root, &config.manifest_sha256)?;
    let profiles = Profiles::open(&config.state_root)?;
    if profiles.root.starts_with(&resources.root) || resources.root.starts_with(&profiles.root) {
        return Err("BROWSER_STATE_AND_RESOURCES_MUST_BE_SEPARATE".into());
    }
    let definitions: Vec<ToolDefinition> = serde_json::from_str(include_str!("../../../../contracts/browser-tools-v1.json"))?;
    let provider = Arc::new(Provider { state:Mutex::new(State { resources:Some(resources), profiles:Some(profiles), sessions:HashMap::new() }),
        closing:AtomicBool::new(false), cancel:Arc::new(AtomicBool::new(false)), desktops, transfers });
    let revoke = Arc::clone(&provider); let shutdown = Arc::clone(&provider);
    let owner = ProviderOwner::new(Arc::new(move || revoke.cleanup(false)), Arc::new(move || shutdown.cleanup(true)));
    profile.register_revoker(DesktopProfile::FullControl, owner.revoker())?;
    for definition in definitions {
        let shared = Arc::clone(&provider); let live_profile = Arc::clone(&profile);
        let name = definition.name.clone(); let schema = definition.input_schema.clone();
        handlers.register(definition.name.clone(), move |arguments| {
            if let Err(error) = validate_schema(&Value::Object(arguments.clone()), &schema) { return Ok(failure(&error.to_string())); }
            let current = match live_profile.read() { Ok(value) => value, Err(error) => return Ok(failure(&error.to_string())) };
            if rank(*current) < rank(DesktopProfile::FullControl) { return Ok(failure("BROWSER_PROFILE_REQUIRED: Full Control is required")); }
            // Keep the live read guard through every child/file effect and callback.
            Ok(match shared.call(*current, &name, arguments) { Ok(result) => result, Err(error) => failure(&error.to_string()) })
        });
        catalog.push(definition);
    }
    Ok(owner)
}

#[cfg(windows)]
impl Provider {
    fn cleanup(&self, final_shutdown: bool) -> Result<(), RuntimeError> {
        if final_shutdown { self.closing.store(true, Ordering::Release); }
        self.cancel.store(true, Ordering::Release);
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let ids: Vec<_> = state.sessions.keys().cloned().collect();
        let mut pending = false;
        for id in ids {
            let session = state.sessions.get_mut(&id).expect("owned session");
            match session.worker.close(true) {
                Err(error) => { session.worker.cleanup_diagnostic("job_close", &error); pending = true; }
                Ok(()) => {
                    let paths = &session.paths;
                    let worker = &mut session.worker;
                    let result = super::profiles::retire_after_verified_drain(
                        || Profiles::retire(paths),
                        |error| worker.cleanup_diagnostic("private_retire", error),
                    );
                    if result.is_ok() { state.sessions.remove(&id); }
                    else { pending = true; }
                },
            }
        }
        if pending { return Err("BROWSER_CLEANUP_PENDING: retained owners require another cleanup attempt".into()); }
        if final_shutdown { state.resources.take(); state.profiles.take(); }
        // The live-profile write guard prevents admission until revocation completes.
        if !final_shutdown { self.cancel.store(false, Ordering::Release); }
        Ok(())
    }
    fn pending(session: &mut Session, code: &str) {
        session.worker.revoke();
        let closed = session.worker.poll_cleanup().unwrap_or(false);
        session.cleanup_error = Some(json!({"code":code,"message":"Owned browser session is revoked; cleanup is retained",
            "details":{"session_id":session.id,"session_usable":false,"job_cleanup_verified":closed}}));
    }
    fn retire(session: &mut Session, graceful: bool) -> Result<(), RuntimeError> {
        if let Err(error) = session.worker.close(graceful).and_then(|()|Profiles::retire(&session.paths)) {
            Self::pending(session,"BROWSER_CLEANUP_PENDING"); return Err(error);
        }
        session.cleanup_error = None;
        Ok(())
    }
    fn reap(state: &mut State) {
        let mut finished = Vec::new();
        for (id, session) in &mut state.sessions {
            if session.cleanup_error.is_some() || session.worker.revoked() || session.worker.root_exited().unwrap_or(true) {
                if session.worker.poll_cleanup().unwrap_or(false) && Profiles::retire(&session.paths).is_ok() { finished.push(id.clone()); }
                else if session.cleanup_error.is_none() { Self::pending(session,"BROWSER_CLEANUP_PENDING"); }
            }
        }
        for id in finished { state.sessions.remove(&id); }
    }
    fn unavailable(session: &Session) -> Value {
        json!({"session_id":session.id,"active":false,"revoked":true,"cleanup_pending":true,
            "job_cleanup_verified":session.worker.exit.is_some(),"error":session.cleanup_error})
    }
    fn place(&self, session: &Session) -> Result<(), RuntimeError> {
        if let Some(id) = &session.lease_id {
            let lease = self.desktops.verify_lease(id)?;
            self.desktops.place_owned_tree(&lease, session.worker.child(), Duration::from_secs(3))?;
        }
        Ok(())
    }
    fn call(&self, profile: DesktopProfile, name: &str, arguments: Map<String, Value>) -> Result<ToolCallResult, RuntimeError> {
        if self.closing.load(Ordering::Acquire) || self.cancel.load(Ordering::Acquire) { return Err("BROWSER_PROVIDER_CLOSED".into()); }
        if serde_json::to_vec(&arguments)?.len() > REQUEST_LIMIT - 256 { return Err("BROWSER_REQUEST_LIMIT".into()); }
        let mut state = self.state.lock().map_err(|_| "BROWSER_STATE_UNAVAILABLE")?;
        if self.closing.load(Ordering::Acquire) || self.cancel.load(Ordering::Acquire) { return Err("BROWSER_PROVIDER_CLOSED".into()); }
        Self::reap(&mut state);
        let action = arguments.get("action").and_then(Value::as_str).unwrap_or_default().to_owned();
        if name == "desktop_browser_session" {
            let active: Vec<_> = state.sessions.values().filter_map(|s| s.profile_id.clone()).collect();
            match action.as_str() {
                "start" => return self.start(profile,&mut state, arguments),
                "list_profiles" => return public_result(state.profiles.as_ref().ok_or("BROWSER_PROVIDER_CLOSED")?.list(&active)?),
                "delete_profile" => return public_result(state.profiles.as_ref().ok_or("BROWSER_PROVIDER_CLOSED")?.delete(text_field(&arguments, "profile_id")?, &active)?),
                "list" => {
                    let mut rows = Vec::new();
                    for session in state.sessions.values_mut() {
                        if session.cleanup_error.is_some() || session.worker.revoked() { rows.push(Self::unavailable(session)); continue; }
                        if self.place(session).is_err() {
                            Self::pending(session,"BROWSER_DESKTOP_PLACEMENT_FAILED"); rows.push(Self::unavailable(session)); continue;
                        }
                        match session.worker.rpc("session", json!({"action":"list"}), Duration::from_secs(15)) {
                            Ok(mut reply) => { add_session_metadata(&mut reply.result, session); rows.push(reply.result); },
                            Err(error) => {
                                Self::pending(session,"BROWSER_SESSION_UNAVAILABLE");
                                let mut row=Self::unavailable(session); row["error"]=error.error; rows.push(row);
                            }
                        }
                    }
                    return public_result(json!({"count":rows.len(),"sessions":rows}));
                }
                _ => {},
            }
        }
        let id = text_field(&arguments, "session_id")?.to_owned();
        let session = state.sessions.get_mut(&id).ok_or("BROWSER_SESSION_NOT_FOUND")?;
        // Closing a failed lease/session remains available and never requires placement.
        if name == "desktop_browser_session" && action == "close" {
            if Self::retire(session,true).is_err() { return Ok(tool_failure(session.cleanup_error.clone().unwrap())); }
            state.sessions.remove(&id);
            return public_result(json!({"session_id":id,"closed":true}));
        }
        if session.cleanup_error.is_some() || session.worker.revoked() { return Ok(tool_failure(session.cleanup_error.clone().unwrap_or_else(||json!({"code":"BROWSER_SESSION_REVOKED","message":"Owned browser session is revoked"})))); }
        if self.place(session).is_err() {
            Self::pending(session,"BROWSER_DESKTOP_PLACEMENT_FAILED"); return Ok(tool_failure(session.cleanup_error.clone().unwrap()));
        }
        let method = match name { "desktop_browser_act" => "act", "desktop_browser_snapshot" => "snapshot", "desktop_browser_session" => "session", _ => return Err("BROWSER_TOOL_UNKNOWN".into()) };
        let budget = rpc_budget(method, &arguments, session.timeout_ms);
        let mut params = Value::Object(arguments.clone());
        let mut stage_directory = None;
        let mut stage_pins: Vec<File> = Vec::new();
        if name == "desktop_browser_act" {
            let reserved = match session.worker.rpc("reserve_act",params,Duration::from_millis(timeout(&arguments)+5000)) {
                Ok(value) => value,
                Err(error) => return Ok(self.finish(profile,session,Err(error))),
            };
            let reservation_id=reserved.result["reservation_id"].as_str().expect("method-validated reservation");
            params=json!({"reservation_id":reservation_id});
            if reserved.result["upload_file_count"].as_u64().unwrap_or(0) > 0 {
                let directory=session.paths.session.join("uploads").join(reservation_id);
                stage_directory=Some(directory.clone());
                match self.stage_uploads(profile,session,&arguments,&directory) {
                    Ok((files,pins)) => { params["staged_files"]=json!(files); stage_pins=pins; },
                    Err(error) => {
                        let cancelled=session.worker.rpc("cancel_act",json!({"reservation_id":reservation_id}),Duration::from_secs(5));
                        let removed=remove_physical_tree(&directory).is_ok();
                        let uncertain=cancelled.is_err() || !removed;
                        let mut receipt=reserved.receipt; receipt["phase"]=json!("stage_uploads"); receipt["session_usable"]=json!(!uncertain);
                        receipt["staging_cleanup_verified"]=json!(removed);
                        let failure=Failure { error:json!({"code":"BROWSER_UPLOAD_STAGING_FAILED","message":"Authorized upload staging failed",
                            "details":{"cause_code":safe_diagnostic_code(error.as_ref())}}), transport:uncertain,receipt:Some(receipt),download:None };
                        return Ok(self.finish(profile,session,Err(failure)));
                    }
                }
            }
        }
        let mut outcome=session.worker.rpc(method,params,budget);
        drop(stage_pins);
        if let Some(directory)=stage_directory {
            let effect_started=match &outcome {
                Ok(reply) => reply.receipt["upload_effect_started"] == true,
                Err(error) => error.transport || error.receipt.as_ref().is_none_or(|r|r["upload_effect_started"] == true),
            };
            if !effect_started && remove_physical_tree(&directory).is_err() {
                let receipt=match &mut outcome { Ok(reply)=>&mut reply.receipt,Err(error)=>error.receipt.get_or_insert_with(||base_receipt(session,"cleanup_uploads")) };
                receipt["staging_cleanup_verified"]=json!(false); receipt["session_usable"]=json!(false);
                Self::pending(session,"BROWSER_UPLOAD_CLEANUP_PENDING");
            }
        }
        Ok(self.finish(profile,session,outcome))
    }
    fn finish(&self, profile: DesktopProfile, session: &mut Session, outcome: Result<Reply,Failure>) -> ToolCallResult {
        let (mut value, mut receipt, mut failure, mut revoke, download)=match outcome {
            Ok(reply) => (reply.result,reply.receipt,None,false,reply.download),
            Err(error) => (json!({}),error.receipt.unwrap_or_else(||base_receipt(session,"transport")),Some(error.error),error.transport,error.download),
        };
        if receipt["session_usable"] != true { revoke=true; }
        if let Err(error)=self.publish_download(profile,session,download,&mut receipt,&mut value) {
            let (code,phase,invalid,source,cleanup_pending)=match error {
                DownloadFailure::Invalid(e)=>("BROWSER_DOWNLOAD_INVALID","verify_download",true,e,true),
                DownloadFailure::Publication(e,pending)=>("BROWSER_DOWNLOAD_PUBLICATION_FAILED","publish_download",false,e,pending),
                DownloadFailure::Cleanup(e)=>("BROWSER_DOWNLOAD_CLEANUP_PENDING","cleanup_download",false,e,true),
            };
            revoke |= invalid || cleanup_pending;
            receipt["previous_phase"]=receipt["phase"].clone(); receipt["phase"]=json!(phase);
            receipt["artifact_committed"]=json!(receipt.get("artifact").is_some());
            receipt["cause_code"]=json!(safe_diagnostic_code(source.as_ref()));
            receipt["cause_os_error"]=json!(source.downcast_ref::<io::Error>().and_then(io::Error::raw_os_error));
            if failure.is_none() { failure=Some(json!({"code":code,"message":"Browser effect completed; download post-processing failed"})); }
            else { receipt["postprocessing_error"]=json!(code); }
        }
        if !revoke && self.place(session).is_err() {
            revoke=true; receipt["previous_phase"]=receipt["phase"].clone(); receipt["phase"]=json!("placement_after");
            if failure.is_none() { failure=Some(json!({"code":"BROWSER_DESKTOP_PLACEMENT_FAILED","message":"Owned browser placement could not be verified after the operation"})); }
            else { receipt["postprocessing_error"]=json!("BROWSER_DESKTOP_PLACEMENT_FAILED"); }
        }
        if revoke {
            Self::pending(session,"BROWSER_SESSION_REVOKED");
            receipt["session_usable"]=json!(false); receipt["job_cleanup_verified"]=json!(session.worker.exit.is_some()); receipt["cleanup_verified"]=json!(false);
            receipt["cleanup_pending"]=json!(true);
            if failure.is_none() { failure=Some(json!({"code":"BROWSER_SESSION_REVOKED","message":"Browser session is revoked; cleanup owner retained"})); }
        }
        if let Some(error)=failure { return receipt_failure(error,&receipt); }
        add_session_metadata(&mut value,session);
        value["execution_receipt"]=public_receipt(&receipt);
        match public_result(value) {
            Ok(result)=>result,
            Err(error)=>{
                receipt["previous_phase"]=receipt["phase"].clone(); receipt["phase"]=json!("encode_mcp");
                receipt_failure(json!({"code":"BROWSER_RESPONSE_ENCODING_FAILED","message":"Browser effect completed; MCP response encoding failed",
                    "details":{"cause_code":safe_diagnostic_code(error.as_ref())}}),&receipt)
            }
        }
    }
    fn start(&self, profile: DesktopProfile, state: &mut State, arguments: Map<String, Value>) -> Result<ToolCallResult, RuntimeError> {
        if state.sessions.len() >= 32 { return Err("BROWSER_SESSION_LIMIT: 32 owned sessions are already active".into()); }
        let persistent = optional_text(&arguments, "profile_id");
        if let Some(id) = &persistent {
            profile_id(id)?;
            if state.sessions.values().any(|s| s.profile_id.as_ref().is_some_and(|other| other.eq_ignore_ascii_case(id))) { return Err("BROWSER_PROFILE_IN_USE".into()); }
        }
        let lease_id = optional_text(&arguments, "agent_desktop_lease_id");
        if let Some(lease) = &lease_id { self.desktops.verify_lease(lease)?; }
        let headless = arguments.get("headless").and_then(Value::as_bool).unwrap_or(true);
        if headless && lease_id.is_some() { return Err("INVALID_ARGUMENT: a desktop lease requires an explicitly visible browser".into()); }
        let id = opaque_id()?;
        let paths = state.profiles.as_ref().ok_or("BROWSER_PROVIDER_CLOSED")?.prepare(&id, persistent.as_deref())?;
        let resources = state.resources.as_ref().ok_or("BROWSER_PROVIDER_CLOSED")?;
        let spec = ChildSpec { executable:resources.node.clone(), arguments:vec![node_path(&resources.worker)?.into_os_string()],
            cwd:resources.root.clone(), env_overrides:child_environment() };
        let limit = timeout(&arguments);
        let mut init = json!({"session_id":id,"executable_path":node_path(&resources.chromium)?,"session_dir":node_path(&paths.session)?,
            "profile_dir":node_path(&paths.profile)?,"headless":headless,"timeout_ms":limit});
        if let Some(viewport) = arguments.get("viewport") { init["viewport"] = viewport.clone(); }
        let worker = match Worker::spawn(&spec, &paths.session, Arc::clone(&self.cancel)) { Ok(worker) => worker,
            Err(error) => { let _ = Profiles::retire(&paths); return Err(error); } };
        state.sessions.insert(id.clone(), Session { id:id.clone(), cleanup_error:None, worker, paths, profile_id:persistent, lease_id, headless, timeout_ms:limit });
        let session = state.sessions.get_mut(&id).expect("registered owner before initialization");
        let result = (|| {
            let reply = session.worker.rpc("init", init, Duration::from_millis(limit + 15_000))?;
            let value = &reply.result;
            if value["protocol_version"] != 2 || value["playwright_version"] != "1.63.0" || value["node_version"] != "24.14.0"
                || value["worker_pid"].as_u64() != Some(u64::from(session.worker.child().root_pid())) || value["session_id"] != id {
                return Err(Failure { error:json!({"code":"BROWSER_WORKER_HANDSHAKE_MISMATCH","message":"Owned browser handshake failed"}), transport:true,receipt:Some(reply.receipt),download:reply.download });
            }
            let placement_failure = |receipt: &Value| Failure { error:json!({"code":"BROWSER_DESKTOP_PLACEMENT_FAILED","message":"Owned browser desktop placement could not be verified"}),transport:true,receipt:Some(receipt.clone()),download:None };
            self.place(session).map_err(|_|placement_failure(&reply.receipt))?;
            let mut params = Map::new();
            if let Some(url) = arguments.get("url") { params.insert("url".into(),url.clone()); }
            let reply = session.worker.rpc("start",Value::Object(params),Duration::from_millis(limit + 15_000))?;
            self.place(session).map_err(|_|placement_failure(&reply.receipt))?;
            Ok(reply)
        })();
        match result {
            Ok(reply) => Ok(self.finish(profile,session,Ok(reply))),
            Err(mut failure) => {
                let job_closed = session.worker.close(false).is_ok();
                let cleaned = job_closed && Profiles::retire(&session.paths).is_ok();
                if !failure.error["details"].is_object() { failure.error["details"] = json!({}); }
                failure.error["details"]["session_usable"] = json!(false);
                failure.error["details"]["phase"] = json!("start");
                failure.error["details"]["effect_uncertain"] = json!(true);
                failure.error["cleanup_verified"] = json!(cleaned);
                failure.error["job_cleanup_verified"] = json!(job_closed);
                failure.error["worker_exit_code"] = json!(session.worker.exit.and_then(|exit|exit.code));
                let mut receipt=failure.receipt.unwrap_or_else(||base_receipt(session,"start"));
                receipt["phase"]=json!("start"); receipt["session_usable"]=json!(false);
                let result=receipt_failure(failure.error,&receipt);
                if cleaned { state.sessions.remove(&id); }
                Ok(result)
            }
        }
    }
    fn stage_uploads(&self, profile: DesktopProfile, session: &Session, arguments: &Map<String, Value>, directory: &std::path::Path)
        -> Result<(Vec<PathBuf>,Vec<File>),RuntimeError>
    {
        let uploads=physical_directory(&session.paths.session.join("uploads"))?;
        fs::create_dir(directory)?;
        let directory=physical_directory(directory)?;
        if directory.parent() != Some(uploads.as_path()) { return Err("BROWSER_UPLOAD_STAGING_REFUSED".into()); }
        let mut pins=vec![pin(&directory,true)?];
        let upload=arguments["actions"].as_array().and_then(|actions|actions.iter().find(|a|a["type"]=="set_files")).ok_or("INVALID_ARGUMENT: upload action required")?;
        let originals:Vec<String>=upload["files"].as_array().ok_or("INVALID_ARGUMENT: files required")?.iter()
            .map(|value|value.as_str().map(str::to_owned).ok_or("INVALID_ARGUMENT: file path required")).collect::<Result<_,_>>()?;
        let staged=(self.transfers.stage_uploads)(profile,&originals,&directory)?;
        if staged.len()!=originals.len() { return Err("BROWSER_UPLOAD_STAGING_MISMATCH".into()); }
        let mut paths=Vec::new();
        for path in staged {
            let file=pin(&path,false)?;
            if !path.canonicalize()?.starts_with(&directory) || file.metadata()?.len()>64*1024*1024 { return Err("BROWSER_UPLOAD_STAGING_REFUSED".into()); }
            paths.push(node_path(&path)?); pins.push(file);
        }
        Ok((paths,pins))
    }
    fn publish_download(&self, profile: DesktopProfile, session: &Session, authorized: Option<AuthorizedDownload>, receipt: &mut Value, value: &mut Value) -> Result<(), DownloadFailure> {
        receipt.as_object_mut().map(|object|object.remove("download"));
        let Some(authorized)=authorized else { return Ok(()); };
        let download=authorized.into_value();
        let (path,file,name)=(|| -> Result<_,RuntimeError> {
            let path=PathBuf::from(download["path"].as_str().ok_or("BROWSER_DOWNLOAD_PATH_INVALID")?);
            let root=physical_directory(&session.paths.session.join("downloads"))?;
            let mut file=pin(&path,false)?;
            if !path.canonicalize()?.starts_with(&root) { return Err("BROWSER_DOWNLOAD_OUTSIDE_SESSION".into()); }
            let (bytes,hash)=digest(&mut file,64*1024*1024)?;
            if download["bytes"].as_u64()!=Some(bytes) || download["sha256"]!=hash { return Err("BROWSER_DOWNLOAD_CHANGED".into()); }
            let name=download["suggested_filename"].as_str().ok_or("BROWSER_DOWNLOAD_NAME_INVALID")?;
            if name.is_empty() || name.len()>720 || name.chars().any(|c|c.is_control() || "/\\<>:\"|?*".contains(c)) { return Err("BROWSER_DOWNLOAD_NAME_INVALID".into()); }
            Ok((path,file,name.to_owned()))
        })().map_err(DownloadFailure::Invalid)?;
        let published=(self.transfers.publish_download)(profile,&path,&name);
        drop(file);
        match published {
            Ok(artifact)=>{
                receipt["artifact_committed"]=json!(true); receipt["artifact"]=compact_artifact(&artifact);
                value["download"]=artifact;
                fs::remove_file(&path).map_err(|error|DownloadFailure::Cleanup(error.into()))?;
                receipt["download_disposition"]=json!("published");
            }
            Err(error)=>{
                let removed=fs::remove_file(&path).is_ok();
                receipt["artifact_committed"]=json!(false); receipt["download_disposition"]=json!(if removed {"discarded"} else {"cleanup_pending"});
                return Err(DownloadFailure::Publication(error,!removed));
            }
        }
        Ok(())
    }

}

#[cfg(windows)]
fn base_receipt(session: &Session, phase: &str) -> Value {
    json!({"session_id":session.id,"phase":phase,"completed_actions":0,"failed_action_index":null,
        "effect_uncertain":true,"session_usable":false,"upload_effect_started":false})
}
fn compact_artifact(value: &Value) -> Value {
    if serde_json::to_vec(value).is_ok_and(|bytes|bytes.len()<=8192) { return value.clone(); }
    let mut result=Map::new();
    for field in ["artifact_id","file_id","id","uri","resource_uri","name","filename","bytes","size","sha256","expires_at"] {
        if let Some(value)=value.get(field) {
            if value.is_number() || value.is_boolean() || value.as_str().is_some_and(|s|s.len()<=1024) { result.insert(field.into(),value.clone()); }
        }
    }
    Value::Object(result)
}
#[cfg(windows)]
fn public_receipt(receipt: &Value) -> Value {
    let mut result=receipt.as_object().cloned().unwrap_or_default();
    for field in ["download","reservation_id","operation","browser_observation_id"] { result.remove(field); }
    Value::Object(result)
}
#[cfg(windows)]
fn receipt_failure(mut error: Value, receipt: &Value) -> ToolCallResult {
    if !error["details"].is_object() { error["details"]=json!({}); }
    for field in ["download","reservation_id","operation","browser_observation_id"] { error["details"].as_object_mut().unwrap().remove(field); }
    if let Some(fields)=public_receipt(receipt).as_object() {
        for (key,value) in fields { error["details"][key]=value.clone(); }
    }
    tool_failure(error)
}

#[cfg(windows)]
fn safe_diagnostic_code(error: &(dyn std::error::Error + Send + Sync)) -> String {
    let message = error.to_string();
    let candidate = message.split(':').next().unwrap_or_default();
    if !candidate.is_empty() && candidate.len() <= 80 && candidate.bytes().all(|c|c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_') {
        candidate.to_owned()
    } else { "PROVIDER_IO_FAILURE".into() }
}

#[cfg(windows)]
fn add_session_metadata(value: &mut Value, session: &Session) {
    if let Some(profile) = &session.profile_id { value["profile_id"] = json!(profile); }
    if let Some(lease) = &session.lease_id { value["agent_desktop_lease_id"] = json!(lease); }
    value["headless"] = json!(session.headless);
}

fn rpc_budget(method: &str, arguments: &Map<String, Value>, default_timeout: u64) -> Duration {
    let limit = arguments.get("timeout_ms").and_then(Value::as_u64).unwrap_or(default_timeout);
    // AX capture and after-action observation have separate Playwright deadlines.
    let mut millis = 15_000 + 4 * limit;
    if method == "act" {
        if let Some(actions) = arguments.get("actions").and_then(Value::as_array) {
            for action in actions {
                let action_timeout = action["timeout_ms"].as_u64().unwrap_or(limit);
                millis += if action["type"] == "wait" { action["duration_ms"].as_u64().unwrap_or(0) } else { 2 * action_timeout };
            }
        }
    }
    Duration::from_millis(millis)
}

#[cfg(windows)]
fn validate_schema(value: &Value, schema: &Value) -> Result<(), RuntimeError> {
    let invalid = || -> RuntimeError { "INVALID_ARGUMENT: browser argument violates the published contract".into() };
    if let Some(values) = schema["enum"].as_array() { if !values.contains(value) { return Err(invalid()); } }
    match schema["type"].as_str() {
        Some("object") => {
            let object = value.as_object().ok_or_else(invalid)?;
            if let Some(required) = schema["required"].as_array() { for field in required { if !object.contains_key(field.as_str().ok_or_else(invalid)?) { return Err(invalid()); } } }
            if let Some(properties) = schema["properties"].as_object() { for (key,value) in object { if let Some(child) = properties.get(key) { validate_schema(value, child)?; } } }
        }
        Some("array") => {
            let values = value.as_array().ok_or_else(invalid)?;
            if values.len() < schema["minItems"].as_u64().unwrap_or(0) as usize || values.len() > schema["maxItems"].as_u64().unwrap_or(u64::MAX) as usize { return Err(invalid()); }
            for value in values { validate_schema(value, &schema["items"])?; }
        }
        Some("string") => {
            let text = value.as_str().ok_or_else(invalid)?;
            let length = text.encode_utf16().count() as u64;
            if length < schema["minLength"].as_u64().unwrap_or(0) || length > schema["maxLength"].as_u64().unwrap_or(u64::MAX) { return Err(invalid()); }
            if let Some(pattern) = schema["pattern"].as_str() { if !regex::Regex::new(pattern)?.is_match(text) { return Err(invalid()); } }
            if schema["format"] == "uri" && !(text.starts_with("http://") || text.starts_with("https://")) { return Err("INVALID_ARGUMENT: browser navigation permits HTTP(S) only".into()); }
        }
        Some("integer") => { let number = value.as_i64().ok_or_else(invalid)?; if number < schema["minimum"].as_i64().unwrap_or(i64::MIN) || number > schema["maximum"].as_i64().unwrap_or(i64::MAX) { return Err(invalid()); } }
        Some("boolean") if !value.is_boolean() => return Err(invalid()),
        _ => {},
    }
    Ok(())
}

fn validate_png(encoded: &str) -> Result<(), RuntimeError> {
    const MAX: usize = 32 * 1024 * 1024;
    if encoded.is_empty() || encoded.len() % 4 != 0 || encoded.len() > (MAX + 2) / 3 * 4 { return Err("BROWSER_PNG_BUDGET".into()); }
    let mut header = Vec::with_capacity(24); let mut decoded = 0usize;
    let groups = encoded.len() / 4;
    for (index, group) in encoded.as_bytes().chunks_exact(4).enumerate() {
        let mut n = [0u8;4]; let mut padding = 0;
        for i in 0..4 {
            n[i] = match group[i] { b'A'..=b'Z' => group[i]-b'A', b'a'..=b'z' => group[i]-b'a'+26,
                b'0'..=b'9' => group[i]-b'0'+52, b'+' => 62, b'/' => 63,
                b'=' if index + 1 == groups && i >= 2 => { padding += 1; 0 }, _ => return Err("BROWSER_PNG_ENCODING".into()) };
            if padding > 0 && group[i] != b'=' { return Err("BROWSER_PNG_ENCODING".into()); }
        }
        if (padding == 1 && n[2] & 3 != 0) || (padding == 2 && n[1] & 15 != 0) { return Err("BROWSER_PNG_ENCODING".into()); }
        let bytes = [(n[0]<<2)|(n[1]>>4), (n[1]<<4)|(n[2]>>2), (n[2]<<6)|n[3]];
        for byte in &bytes[..3-padding] { if header.len() < 24 { header.push(*byte); } decoded += 1; }
    }
    if decoded > MAX || header.len() != 24 || header[..8] != [137,80,78,71,13,10,26,10] || header[8..16] != [0,0,0,13,73,72,68,82] { return Err("BROWSER_PNG_INVALID".into()); }
    let width = u32::from_be_bytes(header[16..20].try_into()?); let height = u32::from_be_bytes(header[20..24].try_into()?);
    if width == 0 || height == 0 || width > 32768 || height > 32768 || u64::from(width)*u64::from(height) > 12_000_000 { return Err("BROWSER_PNG_DIMENSION_LIMIT".into()); }
    Ok(())
}
struct BudgetWriter(usize, usize);
impl Write for BudgetWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self.0.checked_add(bytes.len()).filter(|size| *size <= self.1).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,"browser MCP response exceeds its byte budget"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
fn public_result(mut value: Value) -> Result<ToolCallResult, RuntimeError> {
    let image = value.as_object_mut().and_then(|object| object.remove("_screenshot_png_base64"));
    let mut content = vec![ToolContent::Text { text:value.to_string() }];
    if let Some(image) = image {
        let encoded = image.as_str().ok_or("BROWSER_PNG_ENCODING")?; validate_png(encoded)?;
        content.push(ToolContent::Image { data:encoded.to_owned(), mime_type:"image/png".into() });
    }
    let result = ToolCallResult { content, is_error:false, structured_content:Some(value) };
    serde_json::to_writer(BudgetWriter(0,RESPONSE_LIMIT-1024), &result)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn batch_deadline_allows_real_waits_and_is_not_an_arbitrary_short_rpc_timeout() {
        let args = json!({"timeout_ms":1000,"actions":[{"type":"wait","duration_ms":30000},{"type":"wait_text","timeout_ms":60000}]});
        assert!(rpc_budget("act", args.as_object().unwrap(), 15000) >= Duration::from_millis(150000));
    }
    #[test]
    fn malformed_images_never_become_mcp_image_blocks() {
        for bad in ["", "====", "aGVsbG8=", "aGVsbG8=oops", "data:image/png;base64,abc"] { assert!(validate_png(bad).is_err()); }
        let result = public_result(json!({"session_id":"synthetic","text":"bounded"})).unwrap();
        assert_eq!(result.content.len(),1);
        assert_eq!(result.structured_content.unwrap()["text"],"bounded");
    }
    #[cfg(windows)]
    /// Requires the explicitly pinned offline Windows browser bundle.
    #[cfg(feature = "qualification")]
    #[test]
    fn review_cleanup_and_lost_lease_are_isolated_from_healthy_sessions() {
        use std::os::windows::fs::OpenOptionsExt;
        let root=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../workers/browser-playwright/.test-state").join(format!("isolation-{}",opaque_id().unwrap()));
        fs::create_dir_all(&root).unwrap(); let root=root.canonicalize().unwrap();
        let bundle=PathBuf::from(std::env::var_os("AGENT_BRIDGE_BROWSER_BUNDLE").unwrap());
        let hash=std::env::var("AGENT_BRIDGE_BROWSER_MANIFEST_SHA256").unwrap();
        let provider=Provider { state:Mutex::new(State { resources:Some(Resources::verify(&bundle,&hash).unwrap()), profiles:Some(Profiles::open(&root).unwrap()), sessions:HashMap::new() }),
            closing:AtomicBool::new(false),cancel:Arc::new(AtomicBool::new(false)),desktops:AgentDesktopHandle::disabled(),
            transfers:BrowserTransferCallbacks { stage_uploads:Arc::new(|_,_,_|Err("unused".into())),publish_download:Arc::new(|_,_,_|Err("unused".into())) } };
        let call=|name,args:Value|provider.call(DesktopProfile::FullControl,name,args.as_object().unwrap().clone());
        let started=call("desktop_browser_session",json!({"action":"start"})).unwrap().structured_content.unwrap();
        let broken=started["session_id"].as_str().unwrap().to_owned();
        let second=call("desktop_browser_session",json!({"action":"start"})).unwrap().structured_content.unwrap();
        let healthy=second["session_id"].as_str().unwrap().to_owned();
        let path=root.join("sessions").join(&broken).join("uploads/held.txt");
        let held=fs::OpenOptions::new().write(true).create_new(true).share_mode(0).open(&path).unwrap();
        let closed=call("desktop_browser_session",json!({"action":"close","session_id":broken}));
        assert!(closed.is_err() || closed.as_ref().is_ok_and(|r|r.is_error));
        assert!(provider.state.lock().unwrap().sessions.contains_key(&broken),"uncertain private cleanup must retain its owner");
        assert!(!call("desktop_browser_snapshot",json!({"session_id":healthy,"screenshot":false})).unwrap().is_error);
        let listed=call("desktop_browser_session",json!({"action":"list","session_id":healthy})).unwrap().structured_content.unwrap();
        assert_eq!(listed["count"],2);
        assert!(listed["sessions"].as_array().unwrap().iter().any(|r|r["session_id"]==broken && r["cleanup_pending"]==true));
        assert!(!call("desktop_browser_session",json!({"action":"close","session_id":healthy})).unwrap().is_error);
        drop(held);
        assert_eq!(call("desktop_browser_session",json!({"action":"list"})).unwrap().structured_content.unwrap()["count"],0);
        let one=call("desktop_browser_session",json!({"action":"start"})).unwrap().structured_content.unwrap()["session_id"].as_str().unwrap().to_owned();
        let two=call("desktop_browser_session",json!({"action":"start"})).unwrap().structured_content.unwrap()["session_id"].as_str().unwrap().to_owned();
        provider.state.lock().unwrap().sessions.get_mut(&one).unwrap().lease_id=Some("deliberately-unavailable-lease".into());
        let listed=call("desktop_browser_session",json!({"action":"list"})).unwrap().structured_content.unwrap();
        let rows=listed["sessions"].as_array().unwrap();
        assert!(rows.iter().any(|r|r["session_id"]==one && r["active"]==false && r["revoked"]==true));
        assert!(rows.iter().any(|r|r["session_id"]==two && r["active"]==true));
        assert!(!call("desktop_browser_snapshot",json!({"session_id":two,"screenshot":false})).unwrap().is_error);
        {
            let mut state=provider.state.lock().unwrap(); let session=state.sessions.get_mut(&two).unwrap();
            let real_wait=|session: &mut Session| {
                let before=session.worker.rpc("snapshot",json!({"screenshot":false}),Duration::from_secs(30)).unwrap();
                let reserved=session.worker.rpc("reserve_act",json!({"browser_observation_id":before.result["browser_observation_id"],"actions":[{"type":"wait","duration_ms":0}],"screenshot":false}),Duration::from_secs(30)).unwrap();
                session.worker.rpc("act",json!({"reservation_id":reserved.result["reservation_id"]}),Duration::from_secs(30)).unwrap()
            };
            let mut reply=real_wait(session); reply.result["_screenshot_png_base64"]=json!("invalid PNG");
            let failed=provider.finish(DesktopProfile::FullControl,session,Ok(reply));
            assert!(failed.is_error); let error=&failed.structured_content.unwrap()["error"];
            assert_eq!(error["details"]["completed_actions"],1); assert_eq!(error["details"]["phase"],"encode_mcp");
            assert_eq!(error["details"]["session_id"],two); assert_eq!(error["details"]["session_usable"],true);
            let reply=real_wait(session); session.lease_id=Some("lost-after-completed-operation".into());
            let failed=provider.finish(DesktopProfile::FullControl,session,Ok(reply));
            assert!(failed.is_error); let error=&failed.structured_content.unwrap()["error"];
            assert_eq!(error["details"]["completed_actions"],1); assert_eq!(error["details"]["phase"],"placement_after");
            assert_eq!(error["details"]["session_usable"],false); assert!(session.worker.revoked());
        }
        provider.cleanup(true).unwrap(); drop(provider); fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn round2_error_budget_measures_both_public_copies_and_keeps_the_compact_receipt() {
        let error=json!({"code":"PLAYWRIGHT_FAILED","message":"Browser failed after an effect","details":{
            "session_id":"owned-session","page_id":"p1","completed_actions":1,"phase":"observe_after","session_usable":true,
            "artifact_committed":true,"artifact":{"artifact_id":"committed-witness"},"diagnostic_extra":"x".repeat(9000)}});
        assert!(serde_json::to_vec(&error).unwrap().len()<16*1024,"the private error alone fits this boundary");
        let result=tool_failure_with_limit(error,16*1024);
        assert!(result.is_error);
        assert!(serde_json::to_vec(&result).unwrap().len()<=16*1024,"text plus structuredContent must fit the public budget together");
        let details=&result.structured_content.unwrap()["error"]["details"];
        assert_eq!(details["completed_actions"],1); assert_eq!(details["session_id"],"owned-session");
        assert_eq!(details["artifact"]["artifact_id"],"committed-witness");
    }
    #[cfg(windows)]
    /// Requires the explicitly pinned offline Windows browser bundle.
    #[cfg(feature = "qualification")]
    #[test]
    fn round2_real_mcp_replies_cannot_publish_unrequested_files_and_closed_timeout_keeps_its_cause() {
        use agent_bridge_gateway::{GatewayConfig,McpGateway};
        use std::sync::atomic::AtomicUsize;
        let root=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../workers/browser-playwright/.test-state").join(format!("protocol-authority-{}",opaque_id().unwrap()));
        fs::create_dir_all(&root).unwrap(); let root=root.canonicalize().unwrap();
        let bundle=PathBuf::from(std::env::var_os("AGENT_BRIDGE_BROWSER_BUNDLE").unwrap());
        let hash=std::env::var("AGENT_BRIDGE_BROWSER_MANIFEST_SHA256").unwrap();
        let resources=Resources::verify(&bundle,&hash).unwrap();
        let node=resources.node.clone(); let protocol=node_path(&resources.root.join("protocol.mjs")).unwrap();
        let publications=Arc::new(AtomicUsize::new(0)); let count=Arc::clone(&publications);
        let provider=Arc::new(Provider { state:Mutex::new(State { resources:Some(resources),profiles:Some(Profiles::open(&root).unwrap()),sessions:HashMap::new() }),
            closing:AtomicBool::new(false),cancel:Arc::new(AtomicBool::new(false)),desktops:AgentDesktopHandle::disabled(),
            transfers:BrowserTransferCallbacks { stage_uploads:Arc::new(|_,_,_|Err("unexpected upload".into())),publish_download:Arc::new(move |_,path,_|{
                assert_eq!(fs::read(path)?,b"download witness\n"); count.fetch_add(1,Ordering::SeqCst);
                Ok(json!({"artifact_id":"authorized-witness","bytes":17})) }) } });
        let catalog:Vec<ToolDefinition>=serde_json::from_str(include_str!("../../../../contracts/browser-tools-v1.json")).unwrap();
        let mut handlers=ToolMapHandler::new();
        for definition in &catalog {
            let shared=Arc::clone(&provider); let name=definition.name.clone(); let schema=definition.input_schema.clone();
            handlers.register(name.clone(),move |arguments| {
                validate_schema(&Value::Object(arguments.clone()),&schema).unwrap();
                Ok(shared.call(DesktopProfile::FullControl,&name,arguments).unwrap())
            });
        }
        let gateway=McpGateway::new(GatewayConfig::new("browser-private-reply-fixture","1"),catalog,handlers);
        for case in ["snapshot","click","wait","download_missing","snapshot_wrong_page","snapshot_missing_image","closed_timeout","download_bad_view"] {
            let id=opaque_id().unwrap();
            let paths=provider.state.lock().unwrap().profiles.as_ref().unwrap().prepare(&id,None).unwrap();
            let private=paths.session.join("downloads/witness.bin"); fs::write(&private,b"download witness\n").unwrap();
            let mut file=fs::File::open(&private).unwrap(); let (_,sha)=digest(&mut file,64*1024*1024).unwrap(); drop(file);
            let config=json!({"case":case,"id":id,"protocol":protocol,"download":{"path":node_path(&private).unwrap(),"suggested_filename":"witness.txt","bytes":17,"sha256":sha}});
            let script=paths.session.join("reply-fixture.mjs");
            fs::write(&script,r#"import {pathToFileURL} from 'node:url';
const cfg=__CONFIG__;
const {readFrames,writeFrame}=await import(pathToFileURL(cfg.protocol).href);
const reservation='a3e96910-6e46-4386-8bc3-45006033ff49',observation='9a6a5f4b-019e-4cd8-a5d8-81d20e686e58';
const summary={session_id:cfg.id,headless:true,active:true,page_id:'p1',url:'about:blank',title:'Fixture',pages:[{page_id:'p1',url:'about:blank',title:'Fixture',active:true}]};
for await(const req of readFrames(process.stdin)) {
 const receipt={operation:req.method,session_id:cfg.id,phase:'complete',completed_actions:0,failed_action_index:null,effect_uncertain:false,session_usable:true,upload_effect_started:false};
 let result,ok=true,error;
 if(req.method==='init')result={...summary,protocol_version:2,playwright_version:'1.63.0',node_version:process.versions.node,worker_pid:process.pid,session_usable:true};
 if(req.method==='reserve_act'){result={session_id:cfg.id,page_id:'p1',reservation_id:reservation,action_count:req.params.actions.length,upload_file_count:0};receipt.page_id='p1';receipt.reservation_id=reservation;}
 if(req.method==='snapshot'||req.method==='act'){
   Object.assign(receipt,{page_id:'p1',observation_page_id:'p1',browser_observation_id:observation});
   result={...summary,browser_observation_id:observation,text:'Fixture',interactive_elements:[]};
   if(req.method==='act'){receipt.reservation_id=reservation;receipt.completed_actions=1;result.completed_actions=1;}
   if(['snapshot','click','wait','download_bad_view'].includes(cfg.case))receipt.download=cfg.download;
   if(cfg.case==='snapshot_wrong_page'){receipt.page_id='p2';receipt.observation_page_id='p2';result.page_id='p2';result.pages[0].page_id='p2';}
   if(cfg.case==='download_bad_view')result={};
   if(cfg.case==='closed_timeout'){ok=false;result=undefined;receipt.phase='action';receipt.failed_action_index=1;receipt.session_usable=false;error={code:'PLAYWRIGHT_TIMEOUT',message:'Synthetic closed timeout',details:{session_usable:false,completed_actions:1}};}
 }
 if(req.method==='close'){receipt.session_usable=false;result={session_id:cfg.id,closed:true};}
 await writeFrame(process.stdout,{v:2,id:req.id,ok,...(ok?{result}:{error}),receipt});
 if(req.method==='close')break;
}
process.stdin.destroy();
"#.replace("__CONFIG__",&config.to_string())).unwrap();
            let spec=ChildSpec { executable:node.clone(),arguments:vec![node_path(&script).unwrap().into_os_string()],cwd:paths.session.clone(),env_overrides:child_environment() };
            let mut worker=Worker::spawn(&spec,&paths.session,Arc::clone(&provider.cancel)).unwrap();
            worker.rpc("init",json!({"session_id":id}),Duration::from_secs(5)).unwrap();
            provider.state.lock().unwrap().sessions.insert(id.clone(),Session { id:id.clone(),cleanup_error:None,worker,paths,profile_id:None,lease_id:None,headless:true,timeout_ms:1000 });
            let (name,args)=if case.starts_with("snapshot") { ("desktop_browser_snapshot",json!({"session_id":id,"page_id":"p1","screenshot":case=="snapshot_missing_image"})) }
                else { let actions=match case { "click"=>json!([{"type":"click","selector":"button"}]),"wait"=>json!([{"type":"wait","duration_ms":0}]),
                    "closed_timeout"=>json!([{"type":"wait","duration_ms":0},{"type":"wait","duration_ms":1}]),_=>json!([{"type":"download","selector":"a"}]) };
                    ("desktop_browser_act",json!({"session_id":id,"browser_observation_id":"9a6a5f4b-019e-4cd8-a5d8-81d20e686e58","actions":actions,"screenshot":false})) };
            let result=gateway.handle_value(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}})).unwrap().result.unwrap();
            assert_eq!(publications.load(Ordering::SeqCst),usize::from(case=="download_bad_view"),"{case}: only an admitted completed download can publish");
            assert_eq!(result["isError"],true,"{case}: invalid response must not become success");
            let error=&result["structuredContent"]["error"];
            if case=="closed_timeout" { assert_eq!(error["code"],"PLAYWRIGHT_TIMEOUT"); assert_eq!(error["details"]["completed_actions"],1); assert_eq!(error["details"]["session_usable"],false); }
            if case=="download_bad_view" { assert_eq!(error["details"]["artifact"]["artifact_id"],"authorized-witness"); assert_eq!(error["details"]["completed_actions"],1); }
            provider.cleanup(false).unwrap();
            assert!(provider.state.lock().unwrap().sessions.is_empty(),"{case}: revoked Job and session cleanup must be verified");
        }
        provider.cleanup(true).unwrap(); drop(gateway); drop(provider); fs::remove_dir_all(root).unwrap();
    }

}
