//! Windows Virtual Desktops selected locally, with revocable HUD-backed leases.
mod client;
pub(crate) use client::NativeWindow;
use client::NativeClient;
use crate::owned_children::OwnedChild;
use crate::provider_owner::ProviderOwner;
use crate::runtime::RuntimeError;
use crate::session_profile::{rank, ProfileControl};
use crate::windows_tools::{self, bundle::{self, Resources}};
use agent_bridge_desktop::DesktopProfile;
use agent_bridge_gateway::{ToolDefinition, ToolMapHandler, ToolCallResult, ToolDispatchError};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub(crate) struct AgentDesktopConfig {
    pub(crate) bundle_root: PathBuf,
    pub(crate) manifest_sha256: String,
    pub(crate) state_root: PathBuf,
    pub(crate) desktops: Vec<DesktopBinding>,
}
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DesktopBinding {
    pub(crate) desktop_id: String,
    pub(crate) desktop_number: u32,
}
pub(crate) type TaskBindingValidator = Arc<dyn Fn(&str, &str) -> Result<(), RuntimeError> + Send + Sync>;

#[derive(Clone)]
pub(crate) struct AgentDesktopHandle { runtime: Option<Arc<DesktopRuntime>> }
#[derive(Clone)]
pub(crate) struct DesktopLease {
    id: String, generation: u64, connection: u64,
    pub(crate) desktop: DesktopBinding,
    authority: Arc<()>,
}
#[derive(Clone)]
struct LeaseRecord { lease: DesktopLease, ready: bool, task: Option<(String, String)> }
struct DesktopRuntime {
    client: Arc<NativeClient>, config: AgentDesktopConfig, profile: Arc<std::sync::RwLock<DesktopProfile>>,
    validator: TaskBindingValidator, leases: Mutex<BTreeMap<String, LeaseRecord>>, operations: Mutex<()>,
    generation: AtomicU64, closed: AtomicBool,
}

fn bindings_valid(bindings: &[DesktopBinding]) -> Result<(), RuntimeError> {
    let mut ids = BTreeSet::new(); let mut numbers = BTreeSet::new();
    if bindings.len() > 16 { return Err("AGENT_DESKTOP_POOL_LIMIT".into()); }
    for item in bindings {
        if !bundle::valid_uuid(&item.desktop_id) || !(2..=128).contains(&item.desktop_number)
            || !ids.insert(item.desktop_id.to_ascii_lowercase()) || !numbers.insert(item.desktop_number) {
            return Err("AGENT_DESKTOP_BINDING_INVALID".into());
        }
    }
    Ok(())
}
pub(crate) fn validate_bundle(config: &AgentDesktopConfig) -> Result<(), RuntimeError> {
    bindings_valid(&config.desktops)?;
    Resources::verify(&config.bundle_root, &config.manifest_sha256).map(|_| ())
}
impl AgentDesktopHandle {
    pub(crate) fn disabled() -> Self { Self { runtime: None } }
    fn runtime(&self) -> Result<&Arc<DesktopRuntime>, RuntimeError> {
        self.runtime.as_ref().ok_or_else(|| "AGENT_DESKTOP_UNAVAILABLE".into())
    }
    pub(crate) fn verify_lease(&self, id: &str) -> Result<DesktopLease, RuntimeError> {
        self.runtime()?.verify(id)
    }
    pub(crate) fn window(&self, hwnd: u64) -> Result<NativeWindow, RuntimeError> {
        self.runtime()?.client.window(hwnd)
    }
    pub(crate) fn current_desktop(&self) -> Result<String, RuntimeError> {
        self.runtime()?.client.current_desktop()
    }
    pub(crate) fn assert_window(&self, window: &NativeWindow, lease: &DesktopLease) -> Result<(), RuntimeError> {
        let current = self.verify_lease(&lease.id)?;
        if !Arc::ptr_eq(&current.authority, &lease.authority) || window.desktop_id != lease.desktop.desktop_id
            || window.desktop_number != lease.desktop.desktop_number || window.is_hud {
            return Err("WINDOW_OUTSIDE_AGENT_DESKTOP".into());
        }
        Ok(())
    }
    pub(crate) fn place_owned_tree(&self, lease: &DesktopLease, child: &OwnedChild, timeout: Duration) -> Result<(), RuntimeError> {
        let runtime = self.runtime()?;
        let deadline = Instant::now() + timeout.min(Duration::from_secs(15));
        loop {
            let active = self.verify_lease(&lease.id)?;
            if !Arc::ptr_eq(&active.authority, &lease.authority) { return Err("AGENT_DESKTOP_LEASE_EXPIRED".into()); }
            let candidates = runtime.client.call("window_candidates", json!({}), Duration::from_secs(2))?;
            let candidates = candidates["windows"].as_array().filter(|items| items.len() <= 2048).ok_or("NATIVE_WINDOW_CANDIDATES_INVALID")?;
            let mut placed = 0; let mut pending = false;
            for candidate in candidates {
                let pid = candidate["pid"].as_u64().filter(|pid| *pid > 0 && *pid <= u32::MAX as u64).ok_or("NATIVE_WINDOW_CANDIDATES_INVALID")? as u32;
                if !child.owns_process(pid)? { continue; }
                let hwnd = candidate["hwnd"].as_u64().filter(|hwnd| *hwnd > 0).ok_or("NATIVE_WINDOW_CANDIDATES_INVALID")?;
                let window = match runtime.client.window(hwnd) { Ok(window) => window, Err(_) => { pending = true; continue; } };
                if window.pid != pid || window.is_hud || !child.owns_process(window.pid)? { continue; }
                self.verify_lease(&lease.id)?;
                let final_window = if window.desktop_id == lease.desktop.desktop_id && window.desktop_number == lease.desktop.desktop_number {
                    window.clone()
                } else {
                    // Caller PIDs are never accepted: this membership comes from the retained Job.
                    if !child.owns_process(window.pid)? { return Err("OWNED_WINDOW_PROCESS_CHANGED".into()); }
                    let value = runtime.client.call("move_window", json!({"lease_id":lease.id,"generation":lease.generation,"window":window}), Duration::from_secs(2))?;
                    serde_json::from_value::<NativeWindow>(value)?
                };
                if !window.same_process_window(&final_window) || !child.owns_process(final_window.pid)? { return Err("OWNED_WINDOW_PROCESS_CHANGED".into()); }
                let verified = runtime.client.window(hwnd)?;
                if !final_window.same_target(&verified) { return Err("OWNED_WINDOW_PLACEMENT_CHANGED".into()); }
                self.assert_window(&verified, lease)?; placed += 1;
            }
            if placed > 0 && !pending { self.verify_lease(&lease.id)?; return Ok(()); }
            if Instant::now() >= deadline { return Err("OWNED_WINDOW_PLACEMENT_DEADLINE".into()); }
            std::thread::sleep(Duration::from_millis(40));
        }
    }

    // These are local operator operations, never registered as MCP tools. They
    // return candidate GUIDs; changing the selected pool requires a new seal.
    pub(crate) fn local_pool_candidates(&self) -> Result<Vec<DesktopBinding>, RuntimeError> {
        let runtime = self.runtime()?; let profile = runtime.profile.read().map_err(|_| "PROFILE_STATE_UNAVAILABLE")?;
        if rank(*profile) < rank(DesktopProfile::FullControl) { return Err("PROFILE_FULL_CONTROL_REQUIRED".into()); }
        Ok(runtime.actual_desktops()?.into_iter().filter(|item| item.desktop_number != 1).collect())
    }
    pub(crate) fn local_create_desktop(&self) -> Result<DesktopBinding, RuntimeError> {
        let runtime = self.runtime()?; let profile = runtime.profile.read().map_err(|_| "PROFILE_STATE_UNAVAILABLE")?;
        if rank(*profile) < rank(DesktopProfile::FullControl) { return Err("PROFILE_FULL_CONTROL_REQUIRED".into()); }
        let _operation = runtime.operations.lock().map_err(|_| "AGENT_DESKTOP_STATE_UNAVAILABLE")?;
        let result = runtime.client.call("create_desktop", json!({}), Duration::from_secs(3))?;
        let binding: DesktopBinding = serde_json::from_value(result)?; bindings_valid(std::slice::from_ref(&binding))?; Ok(binding)
    }
    pub(crate) fn local_remove_desktop(&self, binding: &DesktopBinding) -> Result<(), RuntimeError> {
        bindings_valid(std::slice::from_ref(binding))?;
        let runtime = self.runtime()?; let profile = runtime.profile.read().map_err(|_| "PROFILE_STATE_UNAVAILABLE")?;
        if rank(*profile) < rank(DesktopProfile::FullControl) { return Err("PROFILE_FULL_CONTROL_REQUIRED".into()); }
        let _operation = runtime.operations.lock().map_err(|_| "AGENT_DESKTOP_STATE_UNAVAILABLE")?;
        if runtime.leases.lock().map_err(|_| "AGENT_DESKTOP_STATE_UNAVAILABLE")?.values().any(|record| record.lease.desktop == *binding) {
            return Err("AGENT_DESKTOP_OCCUPIED".into());
        }
        runtime.client.call("remove_desktop", serde_json::to_value(binding)?, Duration::from_secs(3)).map(|_| ())
    }
}
impl DesktopRuntime {
    fn actual_desktops(&self) -> Result<Vec<DesktopBinding>, RuntimeError> {
        let value = self.client.call("desktops", json!({}), Duration::from_secs(2))?;
        let items: Vec<DesktopBinding> = serde_json::from_value(value["desktops"].clone())?;
        if items.is_empty() || items.len() > 128 || items.iter().enumerate().any(|(index, item)| item.desktop_number as usize != index + 1 || !bundle::valid_uuid(&item.desktop_id)) {
            return Err("NATIVE_DESKTOP_LIST_INVALID".into());
        }
        Ok(items)
    }
    fn remove_authority(&self, id: &str) {
        self.leases.lock().unwrap_or_else(|error| error.into_inner()).remove(id);
    }
    fn verify(&self, id: &str) -> Result<DesktopLease, RuntimeError> {
        if self.closed.load(Ordering::Acquire) { return Err("AGENT_DESKTOP_CLOSED".into()); }
        let record = self.leases.lock().map_err(|_| "AGENT_DESKTOP_STATE_UNAVAILABLE")?.get(id).cloned().ok_or("AGENT_DESKTOP_LEASE_EXPIRED")?;
        if !record.ready || record.lease.connection != self.client.epoch() || !self.client.fresh() {
            let reason=if record.lease.connection!=self.client.epoch(){"AGENT_DESKTOP_CONNECTION_CHANGED"}else if !self.client.fresh(){"AGENT_DESKTOP_HEARTBEAT_EXPIRED"}else{"AGENT_DESKTOP_NOT_READY"};
            self.remove_authority(id); return Err(reason.into());
        }
        if let Some((task_id, handle)) = &record.task {
            if (self.validator)(task_id, handle).is_err() {
                self.remove_authority(id);
                let _ = self.client.call("stop_lease", json!({"lease_id":id}), Duration::from_secs(2));
                return Err("AGENT_DESKTOP_TASK_BINDING_INVALID".into());
            }
        }
        let value = match self.client.call("lease_status", json!({"lease_id":id}), Duration::from_secs(2)) {
            Ok(value) => value, Err(error) => { self.remove_authority(id); return Err(error); }
        };
        if value["active"] != true || value["hud_ready"] != true || value["generation"] != record.lease.generation
            || value["desktop_id"] != record.lease.desktop.desktop_id || value["desktop_number"] != record.lease.desktop.desktop_number
            || record.lease.connection != self.client.epoch() || !self.client.fresh() {
            let reason=self.client.revocation_reason(id).unwrap_or_else(||"LEASE_STATE_CHANGED".to_owned());
            self.remove_authority(id); return Err(format!("AGENT_DESKTOP_REVOKED_{reason}").into());
        }
        let records = self.leases.lock().map_err(|_| "AGENT_DESKTOP_STATE_UNAVAILABLE")?;
        if !records.get(id).is_some_and(|current| Arc::ptr_eq(&current.lease.authority, &record.lease.authority)) { return Err("AGENT_DESKTOP_LEASE_EXPIRED".into()); }
        Ok(record.lease)
    }
    fn status(&self, own: Option<&str>) -> Result<Value, RuntimeError> {
        let actual = self.actual_desktops()?;
        let ids: Vec<_> = self.leases.lock().map_err(|_| "AGENT_DESKTOP_STATE_UNAVAILABLE")?.keys().cloned().collect();
        for id in ids { let _ = self.verify(&id); }
        let records = self.leases.lock().map_err(|_| "AGENT_DESKTOP_STATE_UNAVAILABLE")?;
        let mut available = Vec::new(); let mut desktops = Vec::new();
        for binding in &self.config.desktops {
            let status = if !actual.contains(binding) { "unavailable" }
                else if records.values().any(|record| record.lease.desktop == *binding) { "occupied" }
                else { available.push(binding.desktop_number); "free" };
            desktops.push(json!({"desktop_number":binding.desktop_number,"status":status}));
        }
        let mut result = json!({"configured":!self.config.desktops.is_empty(),"desktops":desktops,"available_desktops":available});
        if let Some(record) = own.and_then(|id| records.get(id)) {
            result["control"] = json!({"lease_id":record.lease.id,"desktop_number":record.lease.desktop.desktop_number,
                "hud_ready":true,"hud_visible":self.client.current_desktop()? == record.lease.desktop.desktop_id});
        }
        Ok(result)
    }
    fn dispatch(&self, args: Map<String, Value>) -> Result<Value, RuntimeError> {
        let profile = self.profile.read().map_err(|_| "PROFILE_STATE_UNAVAILABLE")?;
        if rank(*profile) < rank(DesktopProfile::FullControl) { return Err("PROFILE_FULL_CONTROL_REQUIRED".into()); }
        if self.closed.load(Ordering::Acquire) { return Err("AGENT_DESKTOP_CLOSED".into()); }
        let _operation = self.operations.lock().map_err(|_| "AGENT_DESKTOP_STATE_UNAVAILABLE")?;
        match args.get("action").and_then(Value::as_str) {
            Some("status") => self.status(args.get("lease_id").and_then(Value::as_str)),
            Some("stop") => {
                let id = args.get("lease_id").and_then(Value::as_str).ok_or("AGENT_DESKTOP_LEASE_REQUIRED")?;
                self.verify(id)?; self.remove_authority(id);
                self.client.call("stop_lease", json!({"lease_id":id}), Duration::from_secs(2))?;
                let mut value = self.status(None)?; value["stopped"] = json!(true); Ok(value)
            }
            Some("start") => {
                let number = args.get("desktop_number").and_then(Value::as_u64).ok_or("AGENT_DESKTOP_SELECTION_REQUIRED")?;
                let binding = self.config.desktops.iter().find(|item| item.desktop_number as u64 == number).ok_or("AGENT_DESKTOP_NOT_CONFIGURED")?.clone();
                let task = match (args.get("task_id").and_then(Value::as_str), args.get("context_handle").and_then(Value::as_str)) {
                    (None, None) => None,
                    (Some(task), Some(handle)) if !task.is_empty() && !handle.is_empty() => { (self.validator)(task, handle)?; Some((task.to_owned(), handle.to_owned())) },
                    _ => return Err("AGENT_DESKTOP_TASK_BINDING_REQUIRED".into()),
                };
                if !self.actual_desktops()?.contains(&binding) { return Err("AGENT_DESKTOP_BINDING_CHANGED".into()); }
                if !self.client.fresh() { self.client.qualify()?; }
                let previous: Vec<_> = self.leases.lock().map_err(|_| "AGENT_DESKTOP_STATE_UNAVAILABLE")?.values()
                    .filter(|record| record.lease.desktop == binding).map(|record|record.lease.id.clone()).collect();
                for id in previous { let _ = self.verify(&id); }
                let occupied = self.leases.lock().map_err(|_| "AGENT_DESKTOP_STATE_UNAVAILABLE")?.values().any(|record| record.lease.desktop == binding);
                if occupied { return Err("AGENT_DESKTOP_OCCUPIED".into()); }
                let generation = self.generation.fetch_add(1, Ordering::AcqRel);
                if generation == u64::MAX { self.closed.store(true, Ordering::Release); return Err("AGENT_DESKTOP_GENERATION_EXHAUSTED".into()); }
                let lease = DesktopLease { id: bundle::uuid()?, generation, connection: self.client.epoch(), desktop: binding, authority: Arc::new(()) };
                let label = args.get("task_label").and_then(Value::as_str).map(str::to_owned)
                    .unwrap_or_else(|| task.as_ref().map(|(id,_)| format!("Task {id}")).unwrap_or_else(|| "Agent Bridge".to_owned()));
                self.leases.lock().map_err(|_| "AGENT_DESKTOP_STATE_UNAVAILABLE")?.insert(lease.id.clone(), LeaseRecord { lease: lease.clone(), ready: false, task });
                let ready = self.client.call("start_lease", json!({"lease_id":lease.id,"generation":lease.generation,
                    "desktop_id":lease.desktop.desktop_id,"desktop_number":lease.desktop.desktop_number,"task_label":label}), Duration::from_millis(3500));
                let valid = ready.as_ref().is_ok_and(|value| value["active"] == true && value["hud_ready"] == true
                    && value["lease_id"] == lease.id && value["generation"] == lease.generation
                    && value["desktop_id"] == lease.desktop.desktop_id && value["desktop_number"] == lease.desktop.desktop_number)
                    && lease.connection == self.client.epoch() && self.client.fresh();
                if !valid {
                    self.remove_authority(&lease.id); let _ = self.client.call("stop_lease", json!({"lease_id":lease.id}), Duration::from_secs(2));
                    return Err("AGENT_DESKTOP_HUD_NOT_READY".into());
                }
                if let Some(record) = self.leases.lock().map_err(|_| "AGENT_DESKTOP_STATE_UNAVAILABLE")?.get_mut(&lease.id) { record.ready = true; }
                self.verify(&lease.id)?; self.status(Some(&lease.id))
            }
            _ => Err("AGENT_DESKTOP_ACTION_INVALID".into()),
        }
    }
    fn close(&self, final_close: bool) -> Result<(), RuntimeError> {
        if final_close { self.closed.store(true, Ordering::Release); }
        self.leases.lock().unwrap_or_else(|error| error.into_inner()).clear(); self.client.close(final_close)
    }
}

pub(crate) fn attach(mut config: AgentDesktopConfig, profile: ProfileControl, binding_validator: TaskBindingValidator,
    catalog: &mut Vec<ToolDefinition>, handlers: &mut ToolMapHandler) -> Result<(AgentDesktopHandle, ProviderOwner), RuntimeError> {
    bindings_valid(&config.desktops)?;
    for item in &mut config.desktops { item.desktop_id.make_ascii_lowercase(); }
    let resources = Arc::new(Resources::verify(&config.bundle_root, &config.manifest_sha256)?);
    let client = NativeClient::new(resources, &config.state_root)?;
    let runtime = Arc::new(DesktopRuntime { client: client.clone(), config, profile: profile.shared(), validator: binding_validator,
        leases: Mutex::new(BTreeMap::new()), operations: Mutex::new(()), generation: AtomicU64::new(1), closed: AtomicBool::new(false) });
    let revoke = runtime.clone(); let shutdown = runtime.clone();
    let owner = ProviderOwner::new(Arc::new(move || revoke.close(false)), Arc::new(move || shutdown.close(true)));
    client.start_monitor()?; client.qualify()?;
    let definition = windows_tools::definitions()?.into_iter().find(|item| item.name == "desktop_agent_desktop").ok_or("NATIVE_CONTRACT_MISSING")?;
    let handler = runtime.clone(); let schema=definition.input_schema.clone();
    handlers.register(definition.name.clone(), move |args| {
        let args=windows_tools::validate_arguments(&schema,args)?;
        handler.dispatch(args).map(|value|ToolCallResult::text(value.to_string())).map_err(|error|ToolDispatchError::tool_error(error.to_string()))
    });
    catalog.push(definition);
    Ok((AgentDesktopHandle { runtime: Some(runtime) }, owner))
}
