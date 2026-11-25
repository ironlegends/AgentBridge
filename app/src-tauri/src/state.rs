//! Persistent desktop panel settings and managed local gateway process state.

use crate::operator_connection::OperatorAttachment;
use crate::native_config::NativeConfig;
use crate::native_runtime::NativeRuntime;
use crate::supervisor::LifecycleController;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

pub const DEFAULT_GATEWAY_PORT: u16 = 18855;
const MAX_RECENT_WORKSPACES: usize = 3;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PanelSettings {
    pub theme: String,
    pub profile: String,
    pub workspace: String,
    pub recent_workspaces: Vec<String>,
    pub database_path: String,
    pub settings_dir: String,
    pub lifecycle_dir: String,
    pub oauth_state_dir: String,
    pub oauth_origin: String,
    pub oauth_audience: String,
    pub gateway_port: u16,
    pub onboarding_completed: bool,
}

impl Default for PanelSettings {
    fn default() -> Self {
        let base = default_app_data_root();
        Self {
            theme: "system".to_owned(),
            profile: "read-only".to_owned(),
            workspace: String::new(),
            recent_workspaces: Vec::new(),
            database_path: base.join("missions.sqlite").display().to_string(),
            settings_dir: base.join("settings").display().to_string(),
            lifecycle_dir: base.join("lifecycle").display().to_string(),
            oauth_state_dir: String::new(),
            oauth_origin: String::new(),
            oauth_audience: "workstation".to_owned(),
            gateway_port: DEFAULT_GATEWAY_PORT,
            onboarding_completed: false,
        }
    }
}

impl PanelSettings {
    pub fn normalize(&mut self) {
        if !matches!(self.theme.as_str(), "system" | "light" | "dark") {
            self.theme = "system".to_owned();
        }
        if !matches!(
            self.profile.as_str(),
            "read-only" | "workspace-write" | "full-control" | "fully-unlocked"
        ) {
            self.profile = "read-only".to_owned();
        }
        if !matches!(self.oauth_audience.as_str(), "missions" | "workstation") {
            self.oauth_audience = "workstation".to_owned();
        }
        if self.gateway_port == 0 {
            self.gateway_port = DEFAULT_GATEWAY_PORT;
        }
        self.workspace = self.workspace.trim().to_owned();
        self.database_path = self.database_path.trim().to_owned();
        self.settings_dir = self.settings_dir.trim().to_owned();
        self.lifecycle_dir = self.lifecycle_dir.trim().to_owned();
        self.oauth_state_dir = self.oauth_state_dir.trim().to_owned();
        self.oauth_origin = self.oauth_origin.trim().to_owned();

        if !self.workspace.is_empty() {
            let ws = self.workspace.clone();
            self.recent_workspaces.retain(|item| !item.eq_ignore_ascii_case(&ws));
            self.recent_workspaces.insert(0, ws);
        }
        self.recent_workspaces.retain(|item| !item.trim().is_empty());
        self.recent_workspaces.truncate(MAX_RECENT_WORKSPACES);
    }
}

pub fn default_app_data_root() -> PathBuf {
    #[cfg(windows)]
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local).join("AgentBridge");
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("AgentBridge");
    }
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(xdg).join("agent-bridge");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".agent-bridge");
    }
    std::env::temp_dir().join("agent-bridge")
}

pub fn settings_file_path(root: &Path) -> PathBuf {
    root.join("panel-settings.json")
}

pub fn load_settings(root: &Path) -> PanelSettings {
    let path = settings_file_path(root);
    let Ok(bytes) = fs::read(&path) else {
        return PanelSettings::default();
    };
    let mut parsed = serde_json::from_slice::<PanelSettings>(&bytes).unwrap_or_default();
    parsed.normalize();
    parsed
}

pub fn save_settings_to_disk(root: &Path, settings: &PanelSettings) -> Result<(), String> {
    fs::create_dir_all(root).map_err(|e| format!("Cannot create app config dir: {e}"))?;
    let path = settings_file_path(root);
    let tmp = root.join(".panel-settings.tmp");
    let body = serde_json::to_vec_pretty(settings)
        .map_err(|e| format!("Cannot serialize panel settings: {e}"))?;
    fs::write(&tmp, body).map_err(|e| format!("Cannot write temporary settings: {e}"))?;
    fs::rename(&tmp, &path).map_err(|e| format!("Cannot replace settings file: {e}"))?;
    Ok(())
}

pub struct ManagedGateway {
    child: Option<Child>,
    port: u16,
    last_error: Option<String>,
}

impl Default for ManagedGateway {
    fn default() -> Self {
        Self {
            child: None,
            port: DEFAULT_GATEWAY_PORT,
            last_error: None,
        }
    }
}

impl ManagedGateway {
    pub fn refresh_child_status(&mut self) -> bool {
        let Some(child) = self.child.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(None) => true,
            Ok(Some(status)) => {
                if !status.success() {
                    self.last_error = Some(format!("Gateway process exited with {status}"));
                }
                self.child = None;
                false
            }
            Err(err) => {
                self.last_error = Some(err.to_string());
                false
            }
        }
    }

    pub fn is_owned_running(&mut self) -> bool {
        self.refresh_child_status()
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn stop(&mut self) -> Result<(), String> {
        if let Some(child) = self.child.as_mut() {
            if child.try_wait().map_err(|e| format!("Cannot inspect the owned gateway: {e}"))?.is_none() {
                child.kill().map_err(|e| format!("Cannot stop the owned gateway: {e}"))?;
            }
            child.wait().map_err(|e| format!("Cannot confirm gateway cleanup: {e}"))?;
        }
        self.child = None;
        self.last_error = None;
        Ok(())
    }

    pub fn start(&mut self, settings: &PanelSettings) -> Result<(), String> {
        self.stop()?;
        if settings.database_path.is_empty() {
            return Err("Configure and initialize missions.sqlite before starting the gateway.".to_owned());
        }
        let db_path = Path::new(&settings.database_path);
        if !db_path.is_file() {
            return Err("Database file does not exist yet. Click Initialize State in Settings first.".to_owned());
        }
        let bin = locate_cli_binary()?;
        let port = if settings.gateway_port == 0 {
            DEFAULT_GATEWAY_PORT
        } else {
            settings.gateway_port
        };

        let mut cmd = Command::new(&bin);
        cmd.args(["serve", &settings.database_path, "--port", &port.to_string()])
            .env("AGENT_BRIDGE_DESKTOP_PROFILE", &settings.profile)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        let child = cmd
            .spawn()
            .map_err(|e| format!("Failed to start {}: {e}", bin.display()))?;
        self.child = Some(child);
        self.port = port;
        self.last_error = None;
        Ok(())
    }
}

pub fn locate_cli_binary() -> Result<PathBuf, String> {
    if let Ok(explicit) = std::env::var("AGENT_BRIDGE_BIN") {
        let p = PathBuf::from(explicit);
        if p.is_file() {
            return Ok(p);
        }
    }
    let exe_name = if cfg!(windows) {
        "agent-bridge.exe"
    } else {
        "agent-bridge"
    };
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(dir) = current_exe.parent() {
            let sibling = dir.join(exe_name);
            if sibling.is_file() {
                return Ok(sibling);
            }
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(exe_name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(format!(
        "Could not locate {exe_name}. Build the CLI binary or set AGENT_BRIDGE_BIN."
    ))
}

pub struct AppRuntime {
    pub config_root: PathBuf,
    pub settings: Mutex<PanelSettings>,
    pub gateway: Mutex<ManagedGateway>,
    pub operator: OperatorAttachment,
    pub native_config: NativeConfig,
    pub native_runtime: NativeRuntime,
    pub lifecycle: LifecycleController,
    #[cfg(test)]
    pub checkpoints: Mutex<std::collections::BTreeMap<&'static str, Box<dyn FnOnce() + Send>>>,
}

impl AppRuntime {
    #[cfg(test)]
    pub fn checkpoint(&self, name: &'static str) {
        let action = self.checkpoints.lock().unwrap().remove(name);
        if let Some(action) = action { action(); }
    }

    pub fn record_event(&self, kind: &str) {
        if !kind.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') { return; }
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .map(|v| v.as_secs()).unwrap_or(0);
        eprintln!("{now} pid={} {kind}", std::process::id());
    }

    pub fn is_live(&self) -> bool {
        self.native_config.is_configured() || self.operator.is_configured()
    }

    #[cfg(test)]
    pub fn new(config_root: PathBuf) -> Self {
        Self::with_native_config(config_root, None)
    }

    pub fn with_native_config(config_root: PathBuf, explicit: Option<&Path>) -> Self {
        let settings = load_settings(&config_root);
        let operator = OperatorAttachment::load(&config_root);
        let native_config = NativeConfig::load(&config_root, explicit);
        Self {
            config_root,
            settings: Mutex::new(settings),
            gateway: Mutex::new(ManagedGateway::default()),
            operator,
            native_config,
            native_runtime: NativeRuntime::default(),
            lifecycle: LifecycleController::default(),
            #[cfg(test)]
            checkpoints: Mutex::default(),
        }
    }
}
