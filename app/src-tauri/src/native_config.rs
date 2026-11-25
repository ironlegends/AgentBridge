use agent_bridge_runtime::backend::WorkstationConfig;
use serde::Deserialize;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const CONFIG_FILE: &str = "workstation-app.json";
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppConfig {
    pub version: u32,
    pub arguments: Vec<String>,
    #[serde(default)]
    pub tunnel: Option<TunnelConfig>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TunnelConfig {
    pub program: PathBuf,
    pub sha256: String,
    pub profile: String,
    pub profile_dir: PathBuf,
    pub state_dir: PathBuf,
    pub dpapi_key_path: PathBuf,
    pub expected_mcp_url: String,
    pub expected_origin: String,
}

impl TunnelConfig {
    pub fn validate(&self) -> Result<(), String> {
        for path in [&self.program, &self.profile_dir, &self.state_dir, &self.dpapi_key_path] {
            if !crate::operator_connection::local_absolute_path(path) {
                return Err("Tunnel paths must be absolute local paths without traversal.".into());
            }
        }
        if self.program.extension().and_then(|v| v.to_str()).is_none_or(|v| !v.eq_ignore_ascii_case("exe"))
            || self.sha256.len() != 64 || !self.sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("The tunnel requires an explicit executable and its SHA-256.".into());
        }
        if self.profile.is_empty() || self.profile.len() > 80 || matches!(self.profile.as_str(), "." | "..")
            || !self.profile.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err("The tunnel profile name is invalid.".into());
        }
        let origin = url::Url::parse(&self.expected_origin).map_err(|_| "The tunnel HTTPS origin is invalid.")?;
        if origin.scheme() != "https" || origin.host_str().is_none()
            || !origin.username().is_empty() || origin.password().is_some()
            || origin.query().is_some() || origin.fragment().is_some()
            || origin.path() != "/" || origin.origin().ascii_serialization() != self.expected_origin
            || self.expected_mcp_url != format!("{}/mcp", self.expected_origin)
        {
            return Err("The tunnel target must preserve its exact HTTPS origin and MCP path.".into());
        }
        Ok(())
    }
}

pub enum NativeConfig {
    Absent,
    Configured(AppConfig),
    Invalid(String),
}

impl NativeConfig {
    pub fn load(root: &Path, explicit: Option<&Path>) -> Self {
        let default = root.join(CONFIG_FILE);
        let path = explicit.unwrap_or(&default);
        if explicit.is_none() && matches!(std::fs::symlink_metadata(path), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound) {
            return Self::Absent;
        }
        match read_config(path) {
            Ok(config) => Self::Configured(config),
            Err(error) => Self::Invalid(error),
        }
    }

    pub fn is_configured(&self) -> bool { !matches!(self, Self::Absent) }

    pub fn require(&self) -> Result<&AppConfig, String> {
        match self {
            Self::Configured(config) => Ok(config),
            Self::Invalid(error) => Err(error.clone()),
            Self::Absent => Err("No native workstation configuration is selected.".into()),
        }
    }
}

fn read_config(path: &Path) -> Result<AppConfig, String> {
    if !crate::operator_connection::local_absolute_path(path) {
        return Err("The native configuration must be an absolute local file.".into());
    }
    let file = crate::operator_connection::open_regular_file(path)
        .map_err(|_| "The native workstation configuration is unavailable or not a regular local file.")?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes)
        .map_err(|_| "The native workstation configuration cannot be read.")?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err("The native workstation configuration exceeds its size limit.".into());
    }
    let config: AppConfig = serde_json::from_slice(&bytes)
        .map_err(|_| "The native workstation configuration is invalid.")?;
    if config.version != 1 || config.arguments.is_empty() || config.arguments.len() > 256
        || config.arguments.iter().any(|arg| arg.contains('\0'))
    {
        return Err("The native workstation configuration version or arguments are invalid.".into());
    }
    WorkstationConfig::from_cli_args(&config.arguments)
        .map_err(|_| "The native configuration requires valid Workstation arguments.")?;
    if let Some(tunnel) = &config.tunnel {
        tunnel.validate()?;
        // Mirror the shared parser's textual DNS identity, without URL IP-alias normalization.
        let supplied = config.arguments.get(4).ok_or("The native HTTPS origin is missing.")?;
        let authority = supplied.strip_suffix('/').unwrap_or(supplied)
            .strip_prefix("https://").ok_or("The native HTTPS origin is invalid.")?;
        let (hostname, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, port.parse::<u16>().map_err(|_| "The native HTTPS port is invalid.")?),
            None => (authority, 443),
        };
        let resource = if port == 443 {
            format!("https://{}/mcp", hostname.to_ascii_lowercase())
        } else {
            format!("https://{}:{port}/mcp", hostname.to_ascii_lowercase())
        };
        if resource != tunnel.expected_mcp_url {
            return Err("The native backend and tunnel must preserve the same HTTPS MCP resource.".into());
        }
    }
    Ok(config)
}
