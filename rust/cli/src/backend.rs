//! Owned in-process workstation runtime. This module creates only the OAuth/MCP
//! listener; native operator operations never enter that HTTP router.
use crate::{browser_docs, gemini, runtime, ui, window_inspection, USAGE};
use agent_bridge_desktop::DesktopProfile;
use serde::Serialize;
use serde_json::Value;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{watch, RwLock};
use tokio::task::JoinHandle;

pub type BackendError = Box<dyn std::error::Error + Send + Sync>;

/// Local launch configuration. It is neither deserializable nor obtainable
/// from MCP; the native host supplies the same validated arguments as the CLI.
pub struct WorkstationConfig {
    database_boundary: PathBuf,
    workstation_state: PathBuf,
    workstation_origin: String,
    port: u16,
    project: PathBuf,
    missions_state: PathBuf,
    missions_origin: String,
    settings_dir: PathBuf,
    lifecycle_dir: PathBuf,
    permitted: runtime::WebWorkstationCapabilities,
    local_window: Option<window_inspection::DedicatedWindow>,
    local_doc_pages: Vec<String>,
    local_learn_url: Option<String>,
    local_chrome_pages: Vec<String>,
    local_chrome_origins: Vec<String>,
    ui_port: Option<u16>,
    ui_open: bool,
    unified_v1: bool,
}
impl WorkstationConfig {
    pub fn from_cli_args(args: &[String]) -> Result<Self, BackendError> {
        parse_cli(&args.iter().map(OsString::from).collect::<Vec<_>>())
    }

    fn validate_options(&self) -> Result<(), BackendError> {
        runtime::check_port(self.port)?;
        for path in [&self.database_boundary, &self.workstation_state, &self.project,
            &self.missions_state, &self.settings_dir, &self.lifecycle_dir] {
            if !path.is_absolute() { return Err("Workstation configuration requires absolute paths".into()); }
        }
        if gemini::canonical_web_origin(&self.workstation_origin)?
            == gemini::canonical_web_origin(&self.missions_origin)? {
            return Err("Missions and Workstation require separate HTTPS OAuth resources".into());
        }
        if self.permitted.profile == DesktopProfile::ReadOnly
            && (self.permitted.task_rooms || self.permitted.settings_tools || self.permitted.processes) {
            return Err("Read-only Web cannot grant settings, Task Rooms or process execution".into());
        }
        if self.permitted.processes && !self.permitted.profile.permits_processes() {
            return Err("Web process tools require explicit local full-control or fully-unlocked".into());
        }
        if !self.local_chrome_origins.is_empty() && self.local_chrome_pages.is_empty() {
            return Err("Native Chrome origins require locally selected pages".into());
        }
        Ok(())
    }

    pub(crate) fn take_start(&mut self) -> gemini::WorkstationStart<'_> {
        gemini::WorkstationStart {
            database_boundary: &self.database_boundary,
            workstation_state: &self.workstation_state,
            workstation_origin: &self.workstation_origin,
            port: self.port,
            project: &self.project,
            missions_state: &self.missions_state,
            missions_origin: &self.missions_origin,
            settings_dir: &self.settings_dir,
            lifecycle_dir: &self.lifecycle_dir,
            permitted: self.permitted,
            local_window: self.local_window.take(),
            local_doc_pages: std::mem::take(&mut self.local_doc_pages),
            local_learn_url: self.local_learn_url.take(),
            local_chrome_pages: std::mem::take(&mut self.local_chrome_pages),
            local_chrome_origins: std::mem::take(&mut self.local_chrome_origins),
            ui_port: self.ui_port,
            ui_open: self.ui_open,
            unified_v1: self.unified_v1,
        }
    }
}

#[derive(Clone, Serialize)]
pub struct BackendDescriptor {
    pub generation: u64,
    pub pid: u32,
    pub listen_addr: String,
    pub public_mcp_url: String,
    pub startup_profile: String,
}
#[derive(Clone, Serialize)]
pub struct ShutdownReport { pub clean: bool }
#[derive(Serialize)]
pub struct OperatorReply { pub status: u16, pub body: Value }
#[derive(Clone, Copy)]
pub enum OperatorRead { Overview, Profile, Missions, OAuth, Extensions, Skills, Diagnostics }
#[derive(Clone, Copy)]
pub enum OperatorWrite { SetProfile, OAuthEnroll, OAuthApprove, ExtensionsDecide, SkillsAction }

struct OperatorShared {
    accepting: AtomicBool,
    effects: crate::operation_admission::OperationAdmission,
    oauth_owner: crate::extensions::UiOAuthOwner,
    state: Arc<RwLock<Option<ui::NativeOperator>>>,
}

/// Opaque, generation-bound local capability. No token or HTTP address is
/// exported. Old clones retain only an empty, closed admission container.
#[derive(Clone)]
pub struct OperatorControl { shared: Arc<OperatorShared> }
impl OperatorControl {
    pub async fn get(&self, operation: OperatorRead) -> Result<OperatorReply, BackendError> {
        let shared = Arc::clone(&self.shared);
        // The async guard protects the adapter. Each real blocking worker
        // additionally owns an effect permit that outlives executor loss.
        tokio::spawn(async move {
            let guard = shared.state.read().await;
            if !shared.accepting.load(Ordering::Acquire) {
                return Err("Workstation operator generation is stopping or stopped".into());
            }
            let operator = guard.as_ref().ok_or("Workstation operator is unavailable")?;
            operator.get(operation).await
        }).await.map_err(|_| -> BackendError { "Native operator task failed".into() })?
    }

    pub async fn post(&self, operation: OperatorWrite, body: Value) -> Result<OperatorReply, BackendError> {
        let shared = Arc::clone(&self.shared);
        tokio::spawn(async move {
            let guard = shared.state.read().await;
            if !shared.accepting.load(Ordering::Acquire) {
                return Err("Workstation operator generation is stopping or stopped".into());
            }
            let operator = guard.as_ref().ok_or("Workstation operator is unavailable")?;
            operator.post(operation, body).await
        }).await.map_err(|_| -> BackendError { "Native operator task failed".into() })?
    }
}

struct StopOnServerExit {
    shared: Arc<OperatorShared>,
    shutdown: watch::Sender<bool>,
}
impl Drop for StopOnServerExit {
    fn drop(&mut self) {
        self.shared.accepting.store(false, Ordering::Release);
        self.shared.effects.close();
        self.shared.oauth_owner.close_admission();
        self.shutdown.send_replace(true);
    }
}

pub struct RunningWorkstation {
    descriptor: BackendDescriptor,
    operator: OperatorControl,
    shutdown: watch::Sender<bool>,
    server: Option<JoinHandle<Result<(), BackendError>>>,
    owner: Option<gemini::PreparedWorkstation>,
    server_error: Option<String>,
}
impl RunningWorkstation {
    pub fn descriptor(&self) -> &BackendDescriptor { &self.descriptor }
    pub fn operator(&self) -> OperatorControl { self.operator.clone() }

    /// True means the serving task ended, not that cleanup or ownership
    /// release succeeded. Only a successful join/shutdown proves the latter.
    pub fn is_finished(&self) -> bool {
        self.server.as_ref().map(JoinHandle::is_finished).unwrap_or(true)
    }

    pub fn request_shutdown(&self) -> Result<(), BackendError> {
        self.operator.shared.accepting.store(false, Ordering::Release);
        self.operator.shared.effects.close();
        self.operator.shared.oauth_owner.close_admission();
        self.shutdown.send_replace(true);
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<ShutdownReport, BackendError> {
        self.request_shutdown()?;
        self.join().await
    }

    /// Cancellation-safe: a pending join handle and all resource owners stay
    /// in self across every await. A failed cleanup can be retried.
    pub async fn join(&mut self) -> Result<ShutdownReport, BackendError> {
        if let Some(server) = self.server.as_mut() {
            let result = server.await;
            self.server = None;
            self.server_error = match result {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some(error.to_string()),
                Err(_) => Some("Workstation HTTP task failed".to_owned()),
            };
        }
        self.request_shutdown()?;
        if let Some(owner) = self.owner.as_ref() { owner.drain_requests().await?; }
        let mut operator = self.operator.shared.state.write().await;
        self.operator.shared.oauth_owner.drain().await?;
        if let Some(owner) = self.owner.as_mut() {
            owner.cleanup()?;
        }
        // No admitted IPC operation or HTTP request remains. Release every
        // live database/router/profile clone before the exclusive OAuth owner.
        operator.take();
        self.owner.take();
        if let Some(error) = self.server_error.take() { return Err(error.into()); }
        Ok(ShutdownReport { clean: true })
    }
}

struct DeferredResources {
    owner: gemini::PreparedWorkstation,
    server: Option<JoinHandle<Result<(), BackendError>>>,
    shared: Arc<OperatorShared>,
}
fn defer_resources(resources:DeferredResources)
    -> Arc<std::sync::Mutex<Option<DeferredResources>>>
{
        let retained=Arc::new(std::sync::Mutex::new(Some(resources)));
        let cleanup_slot=Arc::clone(&retained);
        let cleanup:crate::provider_owner::Cleanup=Arc::new(move || {
            let mut slot=cleanup_slot.lock().unwrap_or_else(|poisoned|poisoned.into_inner());
            let Some(resources)=slot.as_mut() else {return Ok(());};
            if resources.server.as_ref().is_some_and(|server|!server.is_finished()) {
                return Err("WORKSTATION_SERVER_DRAIN_PENDING".into());
            }
            if resources.owner.requests.available_permits()!=32 {
                return Err("WORKSTATION_HTTP_DRAIN_PENDING".into());
            }
            if !resources.shared.effects.is_drained() {
                return Err("WORKSTATION_EFFECT_DRAIN_PENDING".into());
            }
            let shared=Arc::clone(&resources.shared);
            let mut operator=shared.state.try_write().map_err(|_|"WORKSTATION_IPC_DRAIN_PENDING")?;
            if !shared.oauth_owner.try_drain()? {
                return Err("WORKSTATION_OPERATOR_OAUTH_DRAIN_PENDING".into());
            }
            resources.owner.cleanup()?;
            operator.take();
            drop(operator);
            slot.take();
            Ok(())
        });
        crate::provider_owner::ProviderOwner::new(Arc::new(||Ok(())),cleanup).defer();
        retained
}
impl Drop for RunningWorkstation {
    fn drop(&mut self) {
        let _=self.request_shutdown();
        let Some(owner)=self.owner.take() else {return;};
        // Publish before scheduling anything: a live executor is not an
        // alternative owner registry and must not admit a new generation.
        let retained=defer_resources(DeferredResources {
            owner,server:self.server.take(),shared:Arc::clone(&self.operator.shared),
        });
        if let Ok(runtime)=tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                loop {
                    let gates={
                        let slot=retained.lock().unwrap_or_else(|error|error.into_inner());
                        let Some(resources)=slot.as_ref() else {return;};
                        if resources.server.as_ref().is_some_and(|server|!server.is_finished()) {
                            None
                        } else {
                            Some((Arc::clone(&resources.owner.requests),resources.shared.effects.clone()))
                        }
                    };
                    if let Some((requests,effects))=gates {
                        match requests.acquire_many(32).await {
                            Ok(permit)=>drop(permit),Err(_)=>return,
                        }
                        effects.drain().await;
                        // The registry remains authoritative if this task,
                        // executor or cleanup attempt is cancelled or fails.
                        let _=tokio::task::spawn_blocking(
                            crate::provider_owner::ProviderOwner::reconcile_rollbacks).await;
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            });
        }
    }
}

static GENERATION: AtomicU64 = AtomicU64::new(1);

pub async fn start_backend(mut config: WorkstationConfig) -> Result<RunningWorkstation, BackendError> {
    // Compatibility arguments remain parseable, but native control has no
    // HTTP console, bootstrap URL or browser-opening side effect.
    config.ui_port = None;
    config.ui_open = false;
    let port = config.port;
    let startup_profile = serde_json::to_value(config.permitted.profile)?.as_str()
        .ok_or("Invalid serialized startup profile")?.to_owned();
    let mut owner = gemini::prepare_workstation(config.take_start()).await?;
    let listener = owner.listener.take().ok_or("Workstation listener unavailable")?;
    let public_mcp_url = format!("{}/mcp", owner.ui_config.oauth_origin.as_ref()
        .ok_or("Workstation origin unavailable")?);
    let descriptor = BackendDescriptor {
        generation: GENERATION.fetch_add(1, Ordering::Relaxed),
        pid: std::process::id(), listen_addr: format!("127.0.0.1:{port}"),
        public_mcp_url, startup_profile,
    };
    let native = ui::NativeOperator::with_admission(
        owner.ui_config.clone(), owner.profile.clone(), owner.database.clone(),owner.effects.clone(),
    );
    let shared = Arc::new(OperatorShared {
        accepting: AtomicBool::new(true),
        effects: owner.effects.clone(),
        oauth_owner: native.oauth_owner(),
        state: Arc::new(RwLock::new(Some(native))),
    });
    let operator = OperatorControl { shared: Arc::clone(&shared) };
    let (shutdown, received) = watch::channel(false);
    let on_exit = StopOnServerExit { shared, shutdown: shutdown.clone() };
    let service = owner.service.clone();
    // No await after spawning: cancellation cannot detach a ready runtime
    // before its RunningWorkstation owner is returned to the host.
    let server = tokio::spawn(async move {
        let _on_exit = on_exit;
        axum::serve(listener, service)
            .with_graceful_shutdown(ui::wait_for_shutdown(received)).await?;
        Ok(())
    });
    Ok(RunningWorkstation { descriptor, operator, shutdown,
        server: Some(server), owner: Some(owner), server_error: None })
}

/// Runs only the existing private helper protocols. A recognized but
/// malformed helper never falls through into GUI or single-instance startup.
pub fn dispatch_private_child(args: &[OsString]) -> Result<Option<i32>, BackendError> {
    // Reserved elevation roles must never fall through to the ordinary app
    // while the real consent-bound broker remains unqualified.
    if args.first().is_some_and(|mode| mode == "__terminal-elevation-broker-v1"
        || mode == "__terminal-elevated-command-v1") {
        return Err("ELEVATION_PROVIDER_UNAVAILABLE".into());
    }
    if args.first().is_some_and(|mode| mode == "__workspace-file-info-child-v1") {
        let [_, workspace, binding] = args else { return Err("Malformed metadata child invocation".into()); };
        crate::terminal::serve_metadata_child(Path::new(workspace),
            binding.to_str().ok_or("Invalid metadata binding")?)?;
        return Ok(Some(0));
    }
    if let Some(invocation) = agent_bridge_lifecycle::parse_host_invocation(args)? {
        agent_bridge_lifecycle::serve_host(invocation, crate::lifecycle::MissionHost::default())?;
        return Ok(Some(0));
    }
    Ok(None)
}

pub(crate) fn parse_cli(args: &[OsString]) -> Result<WorkstationConfig, BackendError> {
    let config = match args {
        // Only the local operator can select this Web workstation profile.
        // The OAuth resource/state are separate from the historical four-tool
        // project-read gateway. An MCP request cannot change these flags.
        [cmd, action, db, state, origin, port,
         project_flag, project, profile_flag, profile_raw,
         missions_state_flag, missions_state, missions_origin_flag, missions_origin,
         settings_flag, settings_dir, lifecycle_flag, lifecycle_dir, extras @ ..]
          if cmd == "gemini" && action == "workstation"
             && project_flag == "--project" && profile_flag == "--profile"
             && missions_state_flag == "--missions-state"
             && missions_origin_flag == "--missions-origin"
             && settings_flag == "--settings-dir" && lifecycle_flag == "--lifecycle-dir" =>
        {
            let profile: agent_bridge_desktop::DesktopProfile =
                profile_raw.to_str().ok_or(USAGE)?.parse()?;
            let mut task_rooms=false;
            let mut settings_tools=false;
            let mut processes=false;
            let mut ui_port=None;
            let mut ui_open=false;
            let mut unified_v1=false;
            let mut local_window=None;
            let mut local_doc_pages:Vec<String>=Vec::new();
            let mut local_learn_url:Option<String>=None;
            let mut local_chrome_pages:Vec<String>=Vec::new();
            let mut local_chrome_origins:Vec<String>=Vec::new();
            let mut rest=extras.iter();
            while let Some(flag)=rest.next() {
                match flag.to_str() {
                    Some("--enable-task-rooms") if !task_rooms=>task_rooms=true,
                    Some("--enable-settings-tools") if !settings_tools=>settings_tools=true,
                    Some("--enable-processes") if !processes=>processes=true,
                    Some("--unified-v1") if !unified_v1=>unified_v1=true,
                    Some("--ui-port") if ui_port.is_none()=>{
                        ui_port=Some(rest.next().and_then(|value|value.to_str())
                            .ok_or(USAGE)?.parse::<u16>()?);
                    }
                    Some("--ui-open") if !ui_open=>ui_open=true,
                    Some("--local-doc-page") if local_learn_url.is_none()
                        && local_chrome_pages.is_empty() => {
                        let page=rest.next().and_then(|value|value.to_str()).ok_or(USAGE)?;
                        if local_doc_pages.len()>=browser_docs::MAX_APPROVED_PAGES {
                            return Err("Too many locally selected Chrome documentation pages".into());
                        }
                        local_doc_pages.push(page.to_owned());
                    }
                    Some("--local-learn-url") if local_learn_url.is_none()
                        && local_doc_pages.is_empty() && local_chrome_pages.is_empty()=>{
                        crate::warn_deprecated("--local-learn-url");
                        local_learn_url=Some(rest.next().and_then(|v|v.to_str())
                            .ok_or(USAGE)?.to_owned());
                    }
                    Some("--local-chrome-page") if local_doc_pages.is_empty()
                        && local_learn_url.is_none() && local_chrome_pages.len()<8=>{
                        local_chrome_pages.push(rest.next().and_then(|v|v.to_str())
                            .ok_or(USAGE)?.to_owned());
                    }
                    Some("--local-chrome-origin") if local_chrome_origins.len()<4=>{
                        crate::warn_deprecated("--local-chrome-origin");
                        local_chrome_origins.push(rest.next().and_then(|v|v.to_str())
                            .ok_or(USAGE)?.to_owned());
                    }
                    Some("--local-window-read") if local_window.is_none()=>{
                        let desktop=rest.next().and_then(|s|s.to_str()).ok_or(USAGE)?;
                        let executable=rest.next().ok_or(USAGE)?;
                        let class=rest.next().and_then(|s|s.to_str()).ok_or(USAGE)?;
                        let title=rest.next().and_then(|s|s.to_str()).ok_or(USAGE)?;
                        local_window=Some(window_inspection::DedicatedWindow{
                            desktop_name:desktop.to_owned(),
                            executable:Path::new(executable).to_path_buf(),
                            class_name:class.to_owned(),
                            title:title.to_owned(),
                        });
                    }
                    _=>return Err(USAGE.into()),
                }
            }
            if ui_open && ui_port.is_none() {
                return Err("--ui-open requires --ui-port".into());
            }
            Ok::<_, BackendError>(WorkstationConfig{
                database_boundary:Path::new(db).to_owned(),
                workstation_state:Path::new(state).to_owned(),
                workstation_origin:origin.to_str().ok_or(USAGE)?.to_owned(),
                port:port.to_str().ok_or(USAGE)?.parse()?,
                project:Path::new(project).to_owned(),
                missions_state:Path::new(missions_state).to_owned(),
                missions_origin:missions_origin.to_str().ok_or(USAGE)?.to_owned(),
                settings_dir:Path::new(settings_dir).to_owned(),
                lifecycle_dir:Path::new(lifecycle_dir).to_owned(),
                permitted:runtime::WebWorkstationCapabilities {
                    profile,task_rooms,settings_tools,processes,
                },
                local_window,
                local_doc_pages,
                local_learn_url,
                local_chrome_pages,
                local_chrome_origins,
                ui_port,
                ui_open,
                unified_v1,
            })
        }
        _ => Err(USAGE.into()),
    }?;
    config.validate_options()?;
    Ok(config)
}

#[cfg(test)]
#[path = "backend_tests.rs"]
mod tests;
