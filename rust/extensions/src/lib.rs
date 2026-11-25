//! Locally configured and individually approved MCP extensions.
//! The operator vouches for the server implementation. A descriptor pin detects
//! interface changes. It does not attest the code behind an unchanged interface.

pub mod oauth;
mod transport;
pub use oauth::{ClientAuthMethod, OAuthServerConfig, OAuthTokenStore, TokenStatusSummary};
pub use transport::fetch_https_bytes;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io;

pub type Result<T> = io::Result<T>;

/// Qualified operator-only activation or revocation for one exact server
/// configuration. A changed server cannot inherit a previous enable.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerControl {
    pub enabled: bool,
    pub config_sha256: String,
}
fn error(message: &'static str) -> io::Error { io::Error::other(message) }

/// Hash of exact private registry bytes; no network or credential access.
pub fn config_sha256(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }

/// Only validates an inert proposed destination; never opens a connection.
pub fn validate_proposed_endpoint(url: &str) -> Result<()> {
    transport::endpoint(url).map(|_| ())
}

/// Validate names and references without reading a secret or making a request.
pub fn validate_header_env(address: &str, references: &BTreeMap<String, String>, bearer: bool) -> Result<()> {
    let endpoint = transport::endpoint(address)?;
    // The public Learn host must never receive private credentials, including
    // under its DNS absolute-name spelling. Match the parsed host (not an
    // endpoint string), regardless of path or port; do not rewrite the endpoint
    // or broaden the exact supported-operation allowlist.
    let public_learn_host = endpoint.host_str().is_some_and(|host|
        host.strip_suffix('.').unwrap_or(host).eq_ignore_ascii_case("learn.microsoft.com"));
    if public_learn_host && (bearer || !references.is_empty()) {
        return Err(error("Public Microsoft Learn search forbids credentials"));
    }
    if references.len() > 16 || (!references.is_empty()
        && endpoint.scheme() != "https") {
        return Err(error("Extension header references require an approved private HTTPS destination and at most16 entries"));
    }
    let mut names = std::collections::BTreeSet::new();
    for (name, variable) in references {
        let normalized = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| error("Invalid extension header name"))?;
        let lower = normalized.as_str();
        if name.len() > 128 || !names.insert(lower.to_owned())
            || matches!(lower, "host" | "content-length" | "transfer-encoding" | "connection"
                | "proxy-authorization" | "proxy-connection" | "te" | "trailer" | "upgrade"
                | "accept" | "content-type" | "mcp-session-id" | "mcp-protocol-version")
            || (bearer && lower == "authorization")
            || !oauth::valid_secret_env_name(variable) {
            return Err(error("Invalid, duplicate or transport-owned extension header reference"));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    version: u8,
    servers: BTreeMap<String, Server>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Server {
    endpoint: String,
    #[serde(default)]
    bearer_env: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    header_env: BTreeMap<String, String>,
    tools: BTreeMap<String, Approval>,
    // Operator-only revocation overlay; never serialized into extensions.json.
    #[serde(skip)]
    disabled: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    descriptor_sha256: String,
    /// Optional descriptor captured during local approval. Inspection is offline.
    #[serde(default)]
    descriptor: Option<Value>,
    /// Every variable argument must have a locally chosen data constraint.
    parameters: BTreeMap<String, Parameter>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Parameter {
    Identifier,
    Integer { minimum: i64, maximum: i64 },
    Boolean,
    Choice { values: Vec<String> },
    SearchTerms,
}

pub fn valid_server_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 96 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn data_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    const FORBIDDEN: &[&str] = &["terminal", "shell", "exec", "script", "command", "powershell",
        "stdin", "subprocess", "process", "console", "interpreter", "dispatch", "tool_call",
        "call_tool", "proxy", "evaluate", "run_code", "registry", "ssh", "pipeline"];
    valid_server_name(name) && !FORBIDDEN.iter().any(|word| lower.contains(word))
        && !matches!(lower.as_str(),"run"|"eval"|"tool"|"method"|"arguments"|"args"|"argv"|"code"|"url"|"headers"|"env"|"cwd")
}

fn data_tool(name: &str) -> bool {
    // Register domain operations with explicit data arguments. Trampolines,
    // command runners and browser/desktop controllers are not adapters.
    let lower = name.to_ascii_lowercase();
    let words: Vec<_> = lower.split(['_', '-', '.']).collect();
    data_name(name) && words.iter().any(|w| matches!(*w,
        "list"|"get"|"lookup"|"search"|"read"|"find"|"count"|"update"|"create"|"assign"))
        && !words.iter().any(|w| matches!(*w,
            "mcp"|"api"|"http"|"browser"|"desktop"|"tool"|"tools"|"program"|"interact"|"launch"|
            "file"|"files"|"system"|"request"|"plugin"|"pipeline"|"session"|"windows"|"job"|"jobs"))
}

impl Parameter {
    fn valid(&self) -> bool {
        match self {
            Self::Integer { minimum, maximum } => minimum <= maximum,
            Self::Choice { values } => !values.is_empty() && values.len() <= 64 && values.iter().all(|s| valid_server_name(s)),
            _ => true,
        }
    }
    fn allows(&self, value: &Value) -> bool {
        match self {
            Self::Identifier => value.as_str().is_some_and(valid_server_name),
            Self::Integer { minimum, maximum } => value.as_i64().is_some_and(|v| (*minimum..=*maximum).contains(&v)),
            Self::Boolean => value.is_boolean(),
            Self::Choice { values } => value.as_str().is_some_and(|v| values.iter().any(|allowed| v == allowed)),
            Self::SearchTerms => value.as_str().is_some_and(|v| !v.is_empty() && v.len() <= 256 &&
                v.chars().all(|c| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_' | '\'' | '’'))),
        }
    }
    fn json_type(&self) -> &'static str {
        match self { Self::Integer {..} => "integer", Self::Boolean => "boolean", _ => "string" }
    }
}

fn descriptor_hash(value: &Value) -> String {
    let mut canonical = value.clone();
    canonical.sort_all_objects();
    hex::encode(Sha256::digest(canonical.to_string().as_bytes()))
}

// An operator's grant narrows a supported adapter. A generic endpoint cannot
// confer its own authority by returning a harmless-looking name or schema.
// The installed profile has no upstream servers. Populate this list only
// with an independently verified service endpoint and a fixed data operation.
// Public, tokenless Microsoft Learn documentation search only. Do not
// authorize docs_fetch, code-sample search, arbitrary MCP tools or destinations.
// The operator still pins the exact live descriptor and constrains `query`.
const MICROSOFT_LEARN_ENDPOINT: &str = "https://learn.microsoft.com/api/mcp";
const MICROSOFT_DOCS_SEARCH: &str = "microsoft_docs_search";
const SUPPORTED_OPERATIONS: &[(&str, &str)] = &[
    (MICROSOFT_LEARN_ENDPOINT, MICROSOFT_DOCS_SEARCH),
];

fn supported(endpoint: &str, name: &str) -> bool {
    SUPPORTED_OPERATIONS.contains(&(endpoint, name))
}

impl Registry {
    pub fn has_server(&self, name: &str) -> bool { self.servers.contains_key(name) }

    pub fn server_endpoint(&self, name: &str) -> Option<&str> {
        self.servers.get(name).map(|s| s.endpoint.as_str())
    }

    pub fn header_authorization_configured(&self, name: &str) -> bool {
        self.servers.get(name).is_some_and(|server|
            server.header_env.keys().any(|key| key.eq_ignore_ascii_case("authorization")))
    }

    /// Stable digest of the *complete* parsed server entry, including endpoint,
    /// credential reference and all individual tool pins/parameter constraints.
    /// The locally controlled disabled bit is excluded from serialization.
    pub fn server_sha256(&self, name: &str) -> Result<Option<String>> {
        self.servers.get(name).map(|server| {
            let value = serde_json::to_value(server)
                .map_err(|_| error("Cannot fingerprint extension server"))?;
            Ok(descriptor_hash(&value))
        }).transpose()
    }

    /// A local decision cannot revive a different server after a registry edit.
    /// Unknown removed server names remain pinned in private state, so that a
    /// later name reuse also fails closed until a new local decision.
    pub fn with_controls(mut self, controls: &BTreeMap<String, ServerControl>) -> Result<Self> {
        for (name, control) in controls {
            if let Some(server) = self.servers.get_mut(name) {
                let value = serde_json::to_value(&*server)
                    .map_err(|_| error("Cannot fingerprint extension server"))?;
                // A changed server needs a new local decision. The other
                // servers and the built-in workstation tools stay available.
                server.disabled = !control.enabled || descriptor_hash(&value) != control.config_sha256;
            }
        }
        Ok(self)
    }

    /// The CLI supplies bytes from its private operator-owned settings file.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 128 * 1024 { return Err(error("Extension registry exceeds limit")); }
        let registry: Self = serde_json::from_slice(bytes).map_err(|_| error("Invalid extension registry"))?;
        if registry.version != 1 || registry.servers.len() > 32 { return Err(error("Unsupported extension registry")); }
        for (id, server) in &registry.servers {
            transport::endpoint(&server.endpoint)?;
            validate_header_env(&server.endpoint, &server.header_env, server.bearer_env.is_some())?;
            if !valid_server_name(id) || server.tools.len() > 64 { return Err(error("Invalid extension server entry")); }
            // Microsoft Learn's public search requires no credentials. Never
            // read an environment bearer value for this one pinned endpoint.
            if server.endpoint == MICROSOFT_LEARN_ENDPOINT && server.bearer_env.is_some() {
                return Err(error("Public Microsoft Learn search forbids bearer credentials"));
            }
            if let Some(key) = &server.bearer_env {
                if !key.starts_with("AGENT_BRIDGE_EXTENSION_") || key.len() > 128 ||
                   !key.bytes().all(|b| b == b'_' || b.is_ascii_uppercase() || b.is_ascii_digit()) {
                    return Err(error("Invalid local credential reference"));
                }
            }
            for (name, tool) in &server.tools {
                if let Some(descriptor) = &tool.descriptor {
                    if descriptor.get("name").and_then(Value::as_str) != Some(name)
                        || descriptor_hash(descriptor) != tool.descriptor_sha256 {
                        return Err(error("Cached extension descriptor does not match its approval"));
                    }
                    check_schema(descriptor)?;
                }
                if !supported(&server.endpoint, name) {
                    return Err(error("No verified adapter for this extension operation"));
                }
                // The remote schema currently treats query as optional, but
                // this operator grant permits exactly ONE constrained public
                // search string, never an empty or unrestricted payload.
                if server.endpoint == MICROSOFT_LEARN_ENDPOINT
                    && (name != MICROSOFT_DOCS_SEARCH
                        || tool.parameters.len() != 1
                        || !matches!(tool.parameters.get("query"), Some(Parameter::SearchTerms)))
                {
                    return Err(error("Microsoft Learn requires one bounded query approval"));
                }
                if !data_tool(name) || tool.descriptor_sha256.len() != 64 ||
                    !tool.descriptor_sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) ||
                    tool.parameters.len() > 32 || !tool.parameters.iter().all(|(p,s)| data_name(p) && s.valid()) {
                    return Err(error("Invalid individual tool approval or forbidden bridge"));
                }
            }
        }
        Ok(registry)
    }

    /// Revalidate ONLY the explicitly selected public Microsoft Learn
    /// server using its existing Streamable HTTP MCP transport. This cannot
    /// modify a server, extend a tool grant, contact another host, or import
    /// the returned schemas into the registry. A changed descriptor remains
    /// blocked by the pinned hash on the next normal tool call.
    pub fn refresh_microsoft_learn(&self, name: &str) -> Result<Value> {
        if name != "microsoft_learn" {
            return Err(error("Remote refresh is not supported for this server"));
        }
        let server = self.servers.get(name)
            .ok_or_else(|| error("Microsoft Learn server is not configured"))?;
        if server.endpoint != MICROSOFT_LEARN_ENDPOINT || server.bearer_env.is_some() {
            return Err(error("Microsoft Learn refresh requires the exact public tokenless endpoint"));
        }
        let mut session = transport::Session::open(MICROSOFT_LEARN_ENDPOINT, None, &BTreeMap::new())?;
        let live = session.catalog()?;
        let mut live_hashes = BTreeMap::<String, String>::new();
        for tool in &live {
            let name = tool.get("name").and_then(Value::as_str)
                .ok_or_else(|| error("Remote catalog entry has no tool name"))?;
            live_hashes.insert(name.to_owned(), descriptor_hash(tool));
        }
        let mut approved = Vec::new();
        let mut drift = false;
        for (tool_name, approval) in &server.tools {
            let observed = live_hashes.get(tool_name);
            let status = match observed {
                None => "missing",
                Some(sha) if *sha == approval.descriptor_sha256 => "unchanged",
                Some(_) => "descriptor_changed",
            };
            drift |= status != "unchanged";
            approved.push(json!({
                "tool_name": tool_name,
                "status": status,
                "approved_sha256": approval.descriptor_sha256,
                "observed_sha256": observed
            }));
        }
        let unapproved: Vec<_> = live_hashes.keys()
            .filter(|tool_name| !server.tools.contains_key(*tool_name))
            .map(|tool_name| tool_name.to_owned())
            .collect();
        drift |= !unapproved.is_empty();
        Ok(json!({
            "server":name,
            "endpoint":MICROSOFT_LEARN_ENDPOINT,
            "remote_refreshed":true,
            "transport":"mcp_streamable_http_tools_list",
            "live_tool_count":live_hashes.len(),
            "approved_tool_count":server.tools.len(),
            "approved_tools":approved,
            "unapproved_live_tool_names":unapproved,
            "catalog_changes_detected":drift,
            "operator_approval_required_for_any_new_scope":true,
            "approved_grants_changed":false,
            "registry_changed":false,
            "oauth_used":false,
            "tool_invoked":false,
            "remote_session_close":"best_effort"
        }))
    }

    /// Administrative discovery only. No configuration or grant is written.
    pub fn describe_for_operator(&self, server_id: &str, name: &str) -> Result<Value> {
        if !data_tool(name) { return Err(error("Terminal, generic dispatcher or unsupported domain operation")); }
        let server = self.servers.get(server_id).ok_or_else(|| error("Unknown configured extension"))?;
        if !supported(&server.endpoint, name) { return Err(error("No verified adapter for this operation")); }
        if server.disabled { return Err(error("Extension disabled by the operator")); }
        let mut session = transport::Session::open(&server.endpoint, server.bearer_env.as_deref(), &server.header_env)?;
        let descriptor = session.tool(name)?;
        check_schema(&descriptor)?;
        Ok(json!({"descriptor_sha256":descriptor_hash(&descriptor),"descriptor":descriptor}))
    }

    /// Only show identifiers and tool names. Connection and credential
    /// settings stay with the operator.
    pub fn servers(&self, selected: Option<&str>) -> Result<Value> {
        let summary = |id: &str, server: &Server| {
            json!({"id":id, "enabled":!server.disabled, "tools":server.tools.keys().collect::<Vec<_>>()})
        };
        if let Some(id) = selected {
            let server = self.servers.get(id).ok_or_else(|| error("Unknown extension server"))?;
            return Ok(json!({"action":"inspect", "server":summary(id, server)}));
        }
        let servers: Vec<_> = self.servers.iter().map(|(id,s)| summary(id,s)).collect();
        Ok(json!({"action":"list", "count":servers.len(), "servers":servers}))
    }

    /// Offline authentication status for a configured server, after the CLI
    /// has read the private journal and applied its controls to this registry.
    /// The supplied control is a LOCAL decision, not an OAuth credential.
    /// No environment value, secret store, personal profile or network is read.
    ///
    /// In particular, an unpinned server must never be described as locally
    /// activated just because its registry entry is present.
    pub fn auth_status(
        &self,
        name: &str,
        control: Option<&ServerControl>,
    ) -> Result<Option<Value>> {
        let Some(server) = self.servers.get(name) else { return Ok(None); };
        let fingerprint = self.server_sha256(name)?
            .ok_or_else(|| error("Extension server identity unavailable"))?;
        let local_control = match control {
            None => "no_local_decision",
            Some(pin) if pin.config_sha256 != fingerprint => "configuration_changed",
            Some(pin) if !pin.enabled => "disabled",
            Some(_) if server.disabled => "not_applied",
            Some(_) => "enabled",
        };
        Ok(Some(json!({
            "server": name,
            "bearer_reference_configured": server.bearer_env.is_some(),
            "local_control": local_control,
            "outbound_oauth": "not_implemented",
            "remote_oauth_state": "unknown"
        })))
    }

    /// Truthful offline status combining local server controls, non-secret
    /// OAuth 2.1 configuration, and OS-protected (DPAPI) token store status.
    /// Never exposes token values, refresh tokens, or client secrets, and
    /// never fakes a remote introspection check.
    pub fn auth_status_with_oauth(
        &self,
        name: &str,
        control: Option<&ServerControl>,
        oauth_cfg: Option<&OAuthServerConfig>,
        token_status: Option<&TokenStatusSummary>,
    ) -> Result<Option<Value>> {
        let Some(server) = self.servers.get(name) else { return Ok(None); };
        let fingerprint = self.server_sha256(name)?
            .ok_or_else(|| error("Extension server identity unavailable"))?;
        let local_control = match control {
            None => "no_local_decision",
            Some(pin) if pin.config_sha256 != fingerprint => "configuration_changed",
            Some(pin) if !pin.enabled => "disabled",
            Some(_) if server.disabled => "not_applied",
            Some(_) => "enabled",
        };
        let oauth_enabled = oauth_cfg.is_some_and(|c| c.enabled);
        let outbound_oauth = match oauth_cfg {
            Some(c) if c.enabled => "configured",
            Some(_) => "disabled",
            None => "not_configured",
        };
        let token_stored = token_status.is_some_and(|s| s.token_stored);
        let token_expired = token_status.is_some_and(|s| s.token_expired);
        let has_refresh = token_status.is_some_and(|s| s.has_refresh_token);
        let expires_at = token_status.and_then(|s| s.expires_at_unix_secs);
        let granted_scope = token_status.and_then(|s| s.granted_scope.clone());
        let storage_protection = token_status
            .map(|s| s.storage_protection)
            .unwrap_or_else(oauth::storage_protection_label);
        Ok(Some(json!({
            "server": name,
            "bearer_reference_configured": server.bearer_env.is_some(),
            "local_control": local_control,
            "oauth_configured": oauth_enabled,
            "outbound_oauth": outbound_oauth,
            "oauth_client_id": oauth_cfg.and_then(|c| c.client_id.clone()),
            "oauth_scope": oauth_cfg.and_then(|c| c.scope.clone()),
            "oauth_client_auth_method": oauth_cfg.and_then(|c| c.client_auth_method),
            "oauth_client_secret_env_configured": oauth_cfg.is_some_and(|c| c.client_secret_env.is_some()),
            "token_stored": token_stored,
            "token_expired": token_expired,
            "has_refresh_token": has_refresh,
            "expires_at_unix_secs": expires_at,
            "granted_scope": granted_scope,
            "storage_protection": storage_protection,
            "remote_oauth_state": "unknown"
        })))
    }

    pub fn inspect_cached(&self, qualified: &str) -> Result<Value> {
        let (server, name) = qualified.split_once(':').ok_or_else(||error("Expected server:tool"))?;
        let entry = self.servers.get(server).ok_or_else(||error("Unknown extension server"))?;
        if entry.disabled { return Err(error("Extension disabled by the operator")); }
        let tool = entry.tools.get(name)
            .ok_or_else(||error("Unknown locally approved extension tool"))?;
        let descriptor = tool.descriptor.as_ref().ok_or_else(||error("No cached descriptor for this approval"))?;
        Ok(json!({"name":qualified,"tool":descriptor}))
    }

    pub fn list(&self) -> Vec<String> {
        self.servers.iter().filter(|(_, s)| !s.disabled)
            .flat_map(|(server,s)| s.tools.keys().map(move |t| format!("{server}:{t}"))).collect()
    }

    /// Search approved entries in memory. Missing cached descriptors do not
    /// trigger discovery; neither the registry nor the network is modified.
    pub fn search_cached(&self, query: &str, server: Option<&str>, limit: usize) -> Result<Value> {
        if query.is_empty() || query.encode_utf16().count() > 1024 || !(1..=100).contains(&limit) {
            return Err(error("Invalid extension search"));
        }
        let normalized_query = query.trim().to_lowercase();
        if normalized_query.is_empty() {
            return Err(error("Invalid extension search"));
        }
        let server_filter = match server {
            Some(raw) if !raw.is_empty() => {
                if raw.encode_utf16().count() > 64 {
                    return Err(error("Invalid extension search server"));
                }
                let name = raw.trim().to_ascii_lowercase();
                let mut chars = name.bytes();
                if !chars.next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                    || !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
                {
                    return Err(error("Invalid extension search server"));
                }
                Some(name)
            }
            _ => None,
        };
        let tokens: Vec<&str> = normalized_query.split_whitespace().collect();
        let mut scored: Vec<(usize, String, Value)> = Vec::new();
        for (server_id, entry) in &self.servers {
            if entry.disabled { continue; }
            if server_filter.as_deref().is_some_and(|name| !server_id.eq_ignore_ascii_case(name)) {
                continue;
            }
            for (tool_name, approval) in &entry.tools {
                let qualified = format!("{server_id}:{tool_name}");
                let title = approval.descriptor.as_ref()
                    .and_then(|descriptor| descriptor.get("title"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty());
                let description = approval.descriptor.as_ref()
                    .and_then(|descriptor| descriptor.get("description"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty());
                let searchable = format!("{qualified} {} {}",
                    title.unwrap_or(""), description.unwrap_or("")).to_lowercase();
                if !tokens.iter().all(|token| searchable.contains(*token)) {
                    continue;
                }
                let lower_name = tool_name.to_lowercase();
                let lower_title = title.unwrap_or("").to_lowercase();
                let score: usize = tokens.iter().map(|token| {
                    if lower_name == *token { 100 }
                    else if lower_name.contains(*token) { 20 }
                    else if lower_title.contains(*token) { 10 }
                    else { 1 }
                }).sum();
                let mut summary = json!({
                    "qualified_name": &qualified,
                    "server": server_id,
                    "tool_name": tool_name
                });
                if let Some(title) = title {
                    summary["title"] = json!(title);
                }
                if let Some(description) = description {
                    summary["description"] = json!(description);
                }
                scored.push((score, qualified, summary));
            }
        }
        scored.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
        let tools: Vec<Value> = scored.into_iter().take(limit).map(|(_, _, tool)| tool).collect();
        let count = tools.len();
        let mut response = json!({"query":query, "tools":tools, "count":count});
        if let Some(raw) = server.filter(|value| !value.is_empty()) {
            response["server"] = json!(raw);
        }
        Ok(response)
    }

    pub fn call(&self, qualified: &str, args: &Map<String,Value>) -> Result<Value> {
        let (server_id, name) = qualified.split_once(':').ok_or_else(||error("An exact qualified tool name is required"))?;
        let (server, approval) = self.servers.get(server_id).and_then(|s| s.tools.get(name).map(|a|(s,a)))
            .ok_or_else(|| error("Individual tool approval required"))?;
        if !args.iter().all(|(key,value)| approval.parameters.get(key).is_some_and(|p|p.allows(value))) {
            return Err(error("Arguments outside the operator-approved contract"));
        }
        if server.endpoint == MICROSOFT_LEARN_ENDPOINT
            && (name != MICROSOFT_DOCS_SEARCH || args.len() != 1
                || !args.get("query").is_some_and(|query|
                    matches!(approval.parameters.get("query"), Some(Parameter::SearchTerms))
                        && approval.parameters["query"].allows(query)))
        {
            return Err(error("Microsoft Learn search requires one approved public query"));
        }
        if server.disabled { return Err(error("Extension disabled by the operator")); }
        let mut session = transport::Session::open(&server.endpoint, server.bearer_env.as_deref(), &server.header_env)?;
        let descriptor = session.tool(name)?;
        if descriptor_hash(&descriptor) != approval.descriptor_sha256 { return Err(error("Extension descriptor changed; local reapproval required")); }
        let properties = check_schema(&descriptor)?;
        for (key, parameter) in &approval.parameters {
            if properties.get(key).and_then(|p| p.get("type")).and_then(Value::as_str) != Some(parameter.json_type()) {
                return Err(error("Local argument approval does not match the extension schema"));
            }
        }
        if let Some(required) = descriptor["inputSchema"]["required"].as_array() {
            if !required.iter().all(|r| r.as_str().is_some_and(|k| args.contains_key(k))) { return Err(error("Required extension argument missing")); }
        }
        // There is exactly one effectful request, including on disconnect.
        let response = session.request("tools/call", json!({"name":name,"arguments":args}))
            .map_err(|_| error("Extension outcome uncertain; do not replay the request"))?;
        Ok(response)
    }
}

fn check_schema(descriptor: &Value) -> Result<&Map<String,Value>> {
    let schema = &descriptor["inputSchema"];
    let properties = schema["properties"].as_object().ok_or_else(|| error("Extension needs an explicit data schema"))?;
    if schema["type"] != "object" || properties.len() > 32 || !properties.iter().all(|(key,p)|
        data_name(key) && matches!(p["type"].as_str(),Some("string"|"integer"|"boolean"))) ||
        ["$ref","oneOf","allOf","anyOf","patternProperties"].iter().any(|k| schema.get(*k).is_some()) {
        return Err(error("Generic dispatchers and opaque payloads cannot be approved"));
    }
    Ok(properties)
}
