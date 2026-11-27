use crate::supervisor::{SessionMarker, SupervisorConfig, Workstation};
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

const CONFIG_FILE: &str = "operator-connection.json";
const MAX_CONFIG_BYTES: u64 = 8 * 1024;
const MAX_LOG_BYTES: u64 = 256 * 1024;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const PROFILES: [&str; 4] = ["read-only", "workspace-write", "full-control", "fully-unlocked"];

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConnectionConfig {
    version: u32,
    control_port: u16,
    #[serde(default)]
    gateway_port: u16,
    stdout_log: PathBuf,
    #[serde(default)]
    session_view_only: bool,
    #[serde(default)]
    supervisor: Option<SupervisorConfig>,
}

pub enum OperatorAttachment {
    Detached,
    Configured(OperatorClient),
    Invalid,
}

impl OperatorAttachment {
    pub fn load(root: &Path) -> Self {
        let path = root.join(CONFIG_FILE);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::Detached,
            Err(_) => Self::Invalid,
            Ok(_) => match read_config(&path) {
                Ok(config) => Self::Configured(OperatorClient { config }),
                Err(_) => Self::Invalid,
            },
        }
    }

    pub fn is_configured(&self) -> bool {
        !matches!(self, Self::Detached)
    }

    pub fn client(&self) -> Result<&OperatorClient, String> {
        match self {
            Self::Configured(client) => Ok(client),
            Self::Invalid => Err("The local operator connection configuration is invalid or unreadable.".to_owned()),
            Self::Detached => Err("No running workstation is attached.".to_owned()),
        }
    }

    pub fn gateway_port(&self) -> Option<u16> {
        self.client().ok().map(OperatorClient::gateway_port)
    }
}

pub struct OperatorClient {
    config: ConnectionConfig,
}

struct SessionRecord {
    token: String,
    shutdown_control: bool,
}

pub(crate) fn local_absolute_path(path: &Path) -> bool {
    if !path.is_absolute() || path.components().any(|part| matches!(part, Component::ParentDir | Component::CurDir)) {
        return false;
    }
    #[cfg(windows)]
    {
        let value = path.to_string_lossy();
        if value.starts_with(r"\\") || value.starts_with("//") {
            return false;
        }
    }
    true
}

pub(crate) fn open_regular_file(path: &Path) -> Result<File, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "The selected local file is unavailable.")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("The selected local file must be a regular file.".to_owned());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("Reparse points are not accepted for operator connection files.".to_owned());
        }
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0x1 | 0x2 | 0x4).custom_flags(0x0020_0000);
    }
    let file = options.open(path).map_err(|_| "The selected local file cannot be read.")?;
    let metadata = file.metadata().map_err(|_| "The selected local file cannot be inspected.")?;
    if !metadata.is_file() {
        return Err("The selected local file must be a regular file.".to_owned());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("Reparse points are not accepted for operator connection files.".to_owned());
        }
    }
    Ok(file)
}

fn read_config(path: &Path) -> Result<ConnectionConfig, String> {
    let file = open_regular_file(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes)
        .map_err(|_| "Cannot read operator connection configuration.")?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err("Operator connection configuration exceeds its size limit.".to_owned());
    }
    let config: ConnectionConfig = serde_json::from_slice(&bytes)
        .map_err(|_| "Invalid operator connection configuration.")?;
    if config.version != 1 || config.control_port == 0
        || (!config.session_view_only && config.gateway_port == 0)
        || (config.session_view_only && config.supervisor.is_some())
        || config.control_port == config.gateway_port || !local_absolute_path(&config.stdout_log)
    {
        return Err("Invalid operator connection configuration.".to_owned());
    }
    if let Some(supervisor) = &config.supervisor { supervisor.validate()?; }
    Ok(config)
}

impl OperatorClient {
    pub fn gateway_port(&self) -> u16 {
        self.config.gateway_port
    }

    pub fn supervisor(&self) -> Option<&SupervisorConfig> { self.config.supervisor.as_ref() }

    pub fn supports_shutdown(&self) -> bool {
        !self.config.session_view_only && self.session_record().is_ok_and(|record| record.shutdown_control)
    }

    fn session_token(&self) -> Result<String, String> { Ok(self.session_record()?.token) }

    fn session_record(&self) -> Result<SessionRecord, String> {
        let mut file = open_regular_file(&self.config.stdout_log)?;
        let length = file.metadata().map_err(|_| "Cannot inspect the selected operator log.")?.len();
        let start = length.saturating_sub(MAX_LOG_BYTES);
        file.seek(SeekFrom::Start(start)).map_err(|_| "Cannot read the selected operator log.")?;
        let mut bytes = Vec::new();
        file.take(MAX_LOG_BYTES).read_to_end(&mut bytes)
            .map_err(|_| "Cannot read the selected operator log.")?;
        if start != 0 {
            let boundary = bytes.iter().position(|byte| *byte == b'\n')
                .ok_or("No complete operator session record is available in the selected log.")?;
            bytes.drain(..=boundary);
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| "The selected operator log is not valid UTF-8.")?;
        let record = text.lines().rev().filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .find(|record| record["service"] == "agent-bridge-ui")
            .ok_or("No operator session record is available in the selected log.")?;
        let listen = format!("127.0.0.1:{}", self.config.control_port);
        let matching_mode = if self.config.session_view_only {
            record["session_view_only"] == true
                && record["live_profile_control"] == false
                && record["workstation_shutdown_control"] == false
        } else {
            record["live_profile_control"] == true && record["session_view_only"] != true
        };
        if record["listen"].as_str() != Some(listen.as_str())
            || record["token_required"] != true
            || record["loopback_only"] != true
            || !matching_mode
        {
            return Err("The latest operator session does not match the attached workstation.".to_owned());
        }
        let prefix = format!("http://{listen}/?token=");
        let token = record["ui_url"].as_str().and_then(|url| url.strip_prefix(&prefix))
            .filter(|token| token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or("The latest operator session has an invalid local control URL.")?;
        Ok(SessionRecord {
            token: token.to_owned(),
            shutdown_control: record["workstation_shutdown_control"].as_bool().unwrap_or(false),
        })
    }

    pub fn session_history(&self, boot: u128, session: u128) -> Result<Value, String> {
        self.request("GET", &format!("/api/sessions/history/{boot:032x}/{session:032x}"), None)
    }

    pub fn get(&self, path: &'static str) -> Result<Value, String> {
        if !matches!(path, "/api/profile" | "/api/overview" | "/api/missions" | "/api/oauth"
            | "/api/extensions" | "/api/skills" | "/api/diagnostics" | "/api/sessions")
        {
            return Err("Unsupported local operator read operation.".to_owned());
        }
        self.request("GET", path, None)
    }

    pub fn post(&self, path: &'static str, body: Value) -> Result<Value, String> {
        if !matches!(path, "/api/profile" | "/api/oauth/enroll" | "/api/oauth/approve"
            | "/api/skills/action" | "/api/extensions/decide" | "/api/shutdown") {
            return Err("Unsupported local operator action.".to_owned());
        }
        self.request("POST", path, Some(body))
    }

    pub fn profile(&self) -> Result<Value, String> {
        profile_snapshot(self.get("/api/profile")?)
    }

    fn request(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
        if self.config.session_view_only && (method != "GET" || path != "/api/sessions") {
            return Err("This local attachment only provides the session view.".to_owned());
        }
        let token = self.session_token()?;
        let payload = body.map(|value| value.to_string()).unwrap_or_default();
        if payload.len() > MAX_REQUEST_BYTES {
            return Err("The local operator request exceeds its size limit.".to_owned());
        }
        let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.config.control_port);
        let mut stream = TcpStream::connect_timeout(&address.into(), Duration::from_millis(500))
            .map_err(|_| "The attached workstation is unavailable. Its process has not been restarted.")?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))
            .map_err(|_| "Cannot configure the local operator connection.")?;
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {address}\r\nOrigin: http://{address}\r\nX-Agent-Bridge-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
        stream.write_all(request.as_bytes()).map_err(|_| "The local operator request could not be sent.")?;
        let timeout = if method == "POST" { Duration::from_secs(30) } else { Duration::from_secs(3) };
        let (status, bytes) = read_response(&mut stream, timeout)?;
        if !(200..300).contains(&status) {
            let code = serde_json::from_slice::<Value>(&bytes).ok()
                .and_then(|value| value["error"].as_str().map(str::to_owned));
            return Err(response_error(status, code.as_deref()));
        }
        let mut value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| "The attached workstation returned invalid JSON.")?;
        if path == "/api/shutdown" && (status != 202 || value["status"] != "shutting_down") {
            return Err("The workstation did not acknowledge a cooperative shutdown.".into());
        }
        redact_token(&mut value, &token);
        Ok(value)
    }
}

// Windows loopback can take about two seconds to refuse a closed port.
const PORT_PROBE_TIMEOUT: Duration = if cfg!(windows) {
    Duration::from_secs(3)
} else {
    Duration::from_millis(100)
};

fn closed_loopback_port(port: u16, deadline: Instant) -> bool {
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() { return false; }
    matches!(
        TcpStream::connect_timeout(&address.into(), remaining),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused
    ) && Instant::now() < deadline
}

impl Workstation for &OperatorClient {
    fn session(&mut self) -> Result<SessionMarker, String> {
        let before = self.session_token()?;
        self.profile()?;
        if before != self.session_token()? {
            return Err("The local operator session changed during authentication. Retry its state.".into());
        }
        Ok(SessionMarker::new(before))
    }

    fn ready_session(&mut self) -> Result<SessionMarker, String> {
        let session = self.session()?;
        let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.config.gateway_port);
        let mut stream = TcpStream::connect_timeout(&address.into(), Duration::from_millis(500))
            .map_err(|_| "The workstation MCP listener is not ready.")?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))
            .map_err(|_| "Cannot configure the workstation health connection.")?;
        write!(stream, "GET /health HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
            .map_err(|_| "Cannot query workstation health.")?;
        let (status, body) = read_response(&mut stream, Duration::from_secs(3))?;
        let health: Value = serde_json::from_slice(&body).map_err(|_| "Invalid workstation health response.")?;
        if status != 200 || health["ok"] != true || health["name"] != "agent-bridge-gemini-access" {
            return Err("The workstation MCP listener is not ready.".into());
        }
        Ok(session)
    }

    fn shutdown(&mut self) -> Result<(), String> {
        if !self.supports_shutdown() {
            return Err("The attached workstation does not advertise cooperative shutdown. Use its external owner.".into());
        }
        self.post("/api/shutdown", json!({})).map(|_| ())
    }

    fn ports_closed(&mut self, deadline: Option<Instant>) -> bool {
        let probe_deadline = Instant::now() + PORT_PROBE_TIMEOUT;
        let deadline = deadline.map_or(probe_deadline, |deadline| deadline.min(probe_deadline));
        let control = self.config.control_port;
        let gateway = self.config.gateway_port;
        std::thread::scope(|scope| {
            let gateway_probe = std::thread::Builder::new()
                .spawn_scoped(scope, || closed_loopback_port(gateway, deadline));
            let control_closed = closed_loopback_port(control, deadline);
            let gateway_closed = gateway_probe.map_or_else(
                |_| closed_loopback_port(gateway, deadline),
                |probe| probe.join().unwrap_or(false),
            );
            control_closed && gateway_closed
        })
    }
}

pub(crate) fn profile_snapshot(value: Value) -> Result<Value, String> {
    let active = value["active_profile"].as_str().ok_or("No active workstation mode is available.")?;
    let maximum = value["max_profile"].as_str().ok_or("No startup profile limit is available.")?;
    let active_rank = PROFILES.iter().position(|candidate| *candidate == active)
        .ok_or("The workstation returned an invalid active mode.")?;
    let maximum_rank = PROFILES.iter().position(|candidate| *candidate == maximum)
        .ok_or("The workstation returned an invalid startup limit.")?;
    let expected: Vec<Value> = PROFILES[..=maximum_rank].iter().map(|profile| json!(profile)).collect();
    if value["configured"] != true || active_rank > maximum_rank
        || value["available_profiles"].as_array() != Some(&expected)
    {
        return Err("The workstation returned inconsistent live profile limits.".to_owned());
    }
    Ok(json!({
        "configured": true,
        "connected": true,
        "activeProfile": active,
        "maxProfile": maximum,
        "availableProfiles": expected,
        "error": null,
    }))
}

pub(crate) fn response_error(status: u16, code: Option<&str>) -> String {
    match (status, code) {
        (401, _) => "Operator authentication expired or was refused. Reconnect to the current local session; OAuth does not need to be renewed.",
        (403, Some("PROFILE_ABOVE_STARTUP_LIMIT")) => "This mode exceeds the maximum authorized when the workstation started.",
        (403, _) => "The attached workstation refused this local operator action.",
        (409, Some("LIVE_PROFILE_UNAVAILABLE")) => "The selected operator console is not attached to a live workstation.",
        (409 | 503, Some("WORKSTATION_SHUTDOWN_UNAVAILABLE")) => "The selected operator console cannot stop its workstation.",
        (503, Some("PROFILE_UNAVAILABLE")) => "The live profile could not be changed or read. Refresh its state before trying again.",
        (400, Some("OAUTH_APPROVE_FAILED")) => "OAuth approval failed. Check the exact callback URL and whether the request has expired.",
        (409, Some("EXTENSION_DECISION_FAILED")) => "An extension authorization is already running. Refresh its status before another decision.",
        (400, Some("EXTENSION_DECISION_FAILED")) => "The extension decision could not be confirmed. Refresh the exact proposal before trying again.",
        (400, Some("SKILL_ACTION_FAILED")) => "The workstation could not apply the requested skill action.",
        _ => "The attached workstation refused or could not complete the operator request.",
    }.to_owned()
}

fn redact_token(value: &mut Value, token: &str) {
    match value {
        Value::String(text) => *text = text.replace(token, "[redacted]"),
        Value::Array(values) => values.iter_mut().for_each(|value| redact_token(value, token)),
        Value::Object(values) => {
            let original = std::mem::take(values);
            for (key, mut value) in original {
                redact_token(&mut value, token);
                values.insert(key.replace(token, "[redacted]"), value);
            }
        }
        _ => {}
    }
}

fn response_head(bytes: &[u8]) -> Result<Option<(u16, usize, usize)>, String> {
    let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
        if bytes.len() > MAX_HEADER_BYTES {
            return Err("The local operator response headers exceed their size limit.".to_owned());
        }
        return Ok(None);
    };
    let offset = end + 4;
    if offset > MAX_HEADER_BYTES {
        return Err("The local operator response headers exceed their size limit.".to_owned());
    }
    let head = std::str::from_utf8(&bytes[..end]).map_err(|_| "Invalid local operator HTTP headers.")?;
    let mut lines = head.split("\r\n");
    let mut status_line = lines.next().unwrap_or_default().split_ascii_whitespace();
    if !matches!(status_line.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err("Invalid local operator HTTP status.".to_owned());
    }
    let status = status_line.next().and_then(|value| value.parse::<u16>().ok())
        .filter(|status| (100..=599).contains(status)).ok_or("Invalid local operator HTTP status.")?;
    let mut length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("Invalid local operator HTTP header.")?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("Unsupported local operator HTTP transfer encoding.".to_owned());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err("Ambiguous local operator response length.".to_owned());
            }
            length = Some(value.trim().parse::<usize>().map_err(|_| "Invalid local operator response length.")?);
        }
    }
    let length = length.ok_or("The local operator response has no bounded length.")?;
    if length > MAX_RESPONSE_BYTES {
        return Err("The local operator response exceeds its size limit.".to_owned());
    }
    Ok(Some((status, offset, length)))
}

fn read_response(stream: &mut TcpStream, timeout: Duration) -> Result<(u16, Vec<u8>), String> {
    let deadline = Instant::now() + timeout;
    let mut bytes = Vec::new();
    loop {
        if let Some((status, offset, length)) = response_head(&bytes)? {
            if bytes.len() >= offset + length {
                if bytes.len() != offset + length {
                    return Err("The local operator response contains unexpected trailing bytes.".to_owned());
                }
                return Ok((status, bytes[offset..].to_vec()));
            }
        }
        let remaining = deadline.checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or("The local operator request timed out. Refresh state to check its outcome.")?;
        stream.set_read_timeout(Some(remaining)).map_err(|_| "Cannot configure the local operator response timeout.")?;
        let mut chunk = [0u8; 8192];
        let count = stream.read(&mut chunk)
            .map_err(|_| "The local operator request timed out or disconnected. Refresh state to check its outcome.")?;
        if count == 0 {
            return Err("The local operator response was interrupted.".to_owned());
        }
        if bytes.len() + count > MAX_HEADER_BYTES + MAX_RESPONSE_BYTES {
            return Err("The local operator response exceeds its size limit.".to_owned());
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
}

#[cfg(test)]
#[path = "operator_connection_tests.rs"]
mod tests;
