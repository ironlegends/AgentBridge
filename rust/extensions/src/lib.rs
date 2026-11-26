//! Locally configured and individually approved MCP extensions.
//! The operator vouches for the server implementation. A descriptor pin detects
//! interface changes. It does not attest the code behind an unchanged interface.

pub mod oauth;
mod pool;
pub mod stdio;
mod transport;
pub use oauth::{ClientAuthMethod, OAuthServerConfig, OAuthTokenStore, TokenStatusSummary};
pub use pool::SessionPool;
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
    // Public documentation hosts must never receive private
    // credentials, including under a DNS absolute-name spelling. Match the parsed host (not an
    // endpoint string), regardless of path or port; do not rewrite the endpoint
    // or broaden the exact supported-operation allowlist.
    let public_docs_host = endpoint.host_str().is_some_and(|host| PUBLIC_DOCS.iter().any(|docs|
        host.strip_suffix('.').unwrap_or(host).eq_ignore_ascii_case(docs.host)));
    if public_docs_host && (bearer || !references.is_empty()) {
        return Err(error("Public documentation search forbids credentials"));
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
    /// Process seam for stdio servers, attached by the CLI; never parsed.
    #[serde(skip)]
    stdio_launcher: Option<std::sync::Arc<dyn stdio::StdioLauncher>>,
    /// Reusable sessions for tool calls, attached by the CLI; never parsed.
    #[serde(skip)]
    session_pool: Option<std::sync::Arc<SessionPool>>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Server {
    /// Exactly one of `endpoint` and `stdio`. Both are omitted when absent,
    /// so an HTTP entry serializes, and therefore fingerprints, as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stdio: Option<stdio::StdioSpec>,
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
    /// A finite number in an inclusive range.
    Number { minimum: f64, maximum: f64 },
    /// An `https` URL whose host is a public DNS name.
    PublicHttpsUrl,
}

/// Which granted tools the active profile may call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolScope {
    /// The read-only profile, and a route without a profile: named data
    /// operations only.
    DataOperations,
    /// Higher profiles: any tool the operator granted.
    AnyGranted,
}

/// A public `https` URL: no credentials, no port other than 443, and a DNS
/// host that is neither an address literal nor a local or reserved name.
/// Name resolution is not checked here; a server that fetches the URL must
/// still refuse private addresses itself.
fn public_https_url(raw: &str) -> bool {
    let Some(rest) = raw.strip_prefix("https://") else { return false };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = match authority.rsplit_once(':') {
        Some((host, "443")) => host,
        Some(_) => return false,
        None => authority,
    };
    let labels: Vec<_> = host.split('.').collect();
    let top = labels.last().copied().unwrap_or_default().to_ascii_lowercase();
    raw.len() <= 2048 && !raw.chars().any(|c| c.is_control() || c.is_whitespace())
        && host.len() <= 253 && labels.len() >= 2
        && labels.iter().all(|label| !label.is_empty() && label.len() <= 63
            && !label.starts_with('-') && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        // WHATWG reads a host whose last label is decimal or `0x` hex as
        // IPv4 (`127.0.0.0x1`), so the top label must start with a letter.
        && top.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
        && !matches!(top.as_str(), "localhost" | "local" | "internal" | "lan" | "home" | "corp"
            | "intranet" | "private" | "test" | "invalid" | "example" | "arpa" | "localdomain")
}

/// A granted parameter name. `url` names a generic fetch target, so it is
/// granted only as a public `https` URL.
fn grant_parameter(name: &str, parameter: &Parameter) -> bool {
    parameter.valid() && (data_name(name) || (name == "url" && matches!(parameter, Parameter::PublicHttpsUrl)))
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
            // Above 2^53 an `f64` no longer holds every integer, so a JSON
            // integer could round into the range.
            Self::Number { minimum, maximum } => minimum.abs() <= 9_007_199_254_740_992.0
                && maximum.abs() <= 9_007_199_254_740_992.0 && minimum <= maximum,
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
            Self::Number { minimum, maximum } =>
                value.as_f64().is_some_and(|v| v.is_finite() && (*minimum..=*maximum).contains(&v)),
            Self::PublicHttpsUrl => value.as_str().is_some_and(public_https_url),
        }
    }
    fn json_type(&self) -> &'static str {
        match self {
            Self::Integer {..} => "integer",
            Self::Number {..} => "number",
            Self::Boolean => "boolean",
            _ => "string",
        }
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
// Public, tokenless documentation search only: the MCP documentation
// (2026-07-28) and Microsoft Learn (legacy lifecycle). Do not authorize page
// fetches, code-sample search, feedback submission, arbitrary MCP tools or
// destinations. The operator still pins the exact live descriptor and
// constrains `query`.
struct PublicDocs {
    server: &'static str,
    endpoint: &'static str,
    host: &'static str,
    search: &'static str,
}
const PUBLIC_DOCS: &[PublicDocs] = &[
    PublicDocs { server: "mcp_docs", endpoint: "https://modelcontextprotocol.io/mcp",
        host: "modelcontextprotocol.io", search: "search_model_context_protocol" },
    PublicDocs { server: "microsoft_learn", endpoint: "https://learn.microsoft.com/api/mcp",
        host: "learn.microsoft.com", search: "microsoft_docs_search" },
];

fn public_docs(endpoint: &str) -> Option<&'static PublicDocs> {
    PUBLIC_DOCS.iter().find(|docs| docs.endpoint == endpoint)
}

/// True for the server names whose read-only remote catalog probe is supported.
pub fn public_docs_server(name: &str) -> bool {
    PUBLIC_DOCS.iter().any(|docs| docs.server == name)
}

fn supported(endpoint: &str, name: &str) -> bool {
    public_docs(endpoint).is_some_and(|docs| docs.search == name)
}

impl Registry {
    /// Attaches the contained process launcher used by stdio servers.
    pub fn with_stdio_launcher(mut self, launcher: std::sync::Arc<dyn stdio::StdioLauncher>) -> Self {
        self.stdio_launcher = Some(launcher);
        self
    }

    /// Reuses tool-call sessions through `pool`. Operator probes, such as
    /// the refresh check and describe, still open their own session.
    pub fn with_session_pool(mut self, pool: std::sync::Arc<SessionPool>) -> Self {
        self.session_pool = Some(pool);
        self
    }

    /// The pool key of one server: its name and its exact fingerprint.
    fn session_key(&self, name: &str) -> Result<String> {
        let fingerprint = self.server_sha256(name)?.ok_or_else(|| error("Unknown extension server"))?;
        Ok(format!("{name}:{fingerprint}"))
    }

    /// The keys of every enabled server in this registry.
    fn session_keys(&self) -> Result<std::collections::BTreeSet<String>> {
        self.servers.iter().filter(|(_, server)| !server.disabled)
            .map(|(name, _)| self.session_key(name)).collect()
    }

    /// The pinned launch specification of a stdio server.
    pub fn server_stdio(&self, name: &str) -> Option<&stdio::StdioSpec> {
        self.servers.get(name).and_then(|server| server.stdio.as_ref())
    }

    /// Read-only catalog probe of one enabled stdio server: one contained
    /// child, one tools/list traversal, no tool call and no registry change.
    /// A changed descriptor stays blocked by its pin on the next call.
    pub fn refresh_stdio(&self, name: &str) -> Result<Value> {
        let server = self.servers.get(name).ok_or_else(|| error("Stdio extension is not configured"))?;
        let spec = server.stdio.as_ref().ok_or_else(|| error("Remote refresh is not supported for this server"))?;
        if server.disabled { return Err(error("Extension disabled by the operator")); }
        let mut session = self.open_session(server)?;
        let live = session.catalog()?;
        let mut report = catalog_report(server, &live)?;
        report.extend([
            ("server".to_owned(), json!(name)),
            ("transport".to_owned(), json!("stdio")),
            ("executable_sha256".to_owned(), json!(spec.executable_sha256)),
            ("stderr_bytes".to_owned(), json!(session.stderr_bytes().unwrap_or(0))),
            ("protocol_version".to_owned(), json!(session.protocol_version())),
        ]);
        Ok(Value::Object(report))
    }

    /// One session over the server's own transport. A stdio server needs
    /// the launcher the CLI attaches; nothing is started without it.
    fn open_session(&self, server: &Server) -> Result<transport::Session> {
        match (&server.endpoint, &server.stdio) {
            (Some(endpoint), None) =>
                transport::Session::open(endpoint, server.bearer_env.as_deref(), &server.header_env),
            (None, Some(spec)) => {
                let launcher = self.stdio_launcher.as_deref()
                    .ok_or_else(|| error("Stdio extensions are unavailable in this context"))?;
                // An idle pooled child yields its slot to any new session.
                if stdio::slots_exhausted() { pool::evict_idle_stdio(); }
                transport::Session::open_stdio(spec, launcher, &|name| std::env::var_os(name))
            }
            _ => Err(error("Invalid extension server entry")),
        }
    }

    pub fn has_server(&self, name: &str) -> bool { self.servers.contains_key(name) }

    pub fn server_endpoint(&self, name: &str) -> Option<&str> {
        self.servers.get(name).and_then(|s| s.endpoint.as_deref())
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
    /// A stdio server starts disabled: only an enabled local control that
    /// matches its exact fingerprint activates it (see `with_controls`).
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 128 * 1024 { return Err(error("Extension registry exceeds limit")); }
        let mut registry: Self = serde_json::from_slice(bytes).map_err(|_| error("Invalid extension registry"))?;
        if registry.version != 1 || registry.servers.len() > 32 { return Err(error("Unsupported extension registry")); }
        for (id, server) in &registry.servers {
            match (&server.endpoint, &server.stdio) {
                (Some(endpoint), None) => {
                    transport::endpoint(endpoint)?;
                    validate_header_env(endpoint, &server.header_env, server.bearer_env.is_some())?;
                }
                // The executable pin replaces the verified-adapter allowlist
                // for stdio only. Secrets never live in the registry, and a
                // public documentation name keeps its HTTP meaning.
                (None, Some(spec)) => {
                    if server.bearer_env.is_some() || !server.header_env.is_empty() || public_docs_server(id) {
                        return Err(error("A stdio extension forbids credential references and reserved names"));
                    }
                    spec.validate()?;
                }
                _ => return Err(error("An extension server needs exactly one endpoint or stdio launch")),
            }
            if !valid_server_name(id) || server.tools.len() > 64 { return Err(error("Invalid extension server entry")); }
            let docs = server.endpoint.as_deref().and_then(public_docs);
            // Public documentation search requires no credentials. Never read
            // an environment bearer value for these pinned endpoints.
            if docs.is_some() && server.bearer_env.is_some() {
                return Err(error("Public documentation search forbids bearer credentials"));
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
                    check_schema(descriptor, &tool.parameters)?;
                }
                if server.stdio.is_none() && !server.endpoint.as_deref().is_some_and(|e| supported(e, name)) {
                    return Err(error("No verified adapter for this extension operation"));
                }
                // A remote schema may offer optional filters, but this
                // operator grant permits exactly ONE constrained public
                // search string, never an empty or unrestricted payload.
                if docs.is_some_and(|docs| name != docs.search
                        || tool.parameters.len() != 1
                        || !matches!(tool.parameters.get("query"), Some(Parameter::SearchTerms)))
                {
                    return Err(error("Public documentation search requires one bounded query approval"));
                }
                // Code runners and dispatchers are never granted. Whether a
                // granted tool is a named data operation is checked per call,
                // against the active profile.
                if !data_name(name) || tool.descriptor_sha256.len() != 64 ||
                    !tool.descriptor_sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) ||
                    tool.parameters.len() > 32 || !tool.parameters.iter().all(|(p,s)| grant_parameter(p, s)) {
                    return Err(error("Invalid individual tool approval or forbidden bridge"));
                }
            }
        }
        for server in registry.servers.values_mut() {
            server.disabled |= server.stdio.is_some();
        }
        Ok(registry)
    }

    /// Revalidate ONLY the explicitly selected public documentation
    /// server using its existing Streamable HTTP MCP transport. This cannot
    /// modify a server, extend a tool grant, contact another host, or import
    /// the returned schemas into the registry. A changed descriptor remains
    /// blocked by the pinned hash on the next normal tool call.
    pub fn refresh_public_docs(&self, name: &str) -> Result<Value> {
        let docs = PUBLIC_DOCS.iter().find(|docs| docs.server == name)
            .ok_or_else(|| error("Remote refresh is not supported for this server"))?;
        let server = self.servers.get(name)
            .ok_or_else(|| error("Public documentation server is not configured"))?;
        if server.endpoint.as_deref() != Some(docs.endpoint) || server.bearer_env.is_some() {
            return Err(error("Documentation refresh requires the exact public tokenless endpoint"));
        }
        let mut session = transport::Session::open(docs.endpoint, None, &BTreeMap::new())?;
        let live = session.catalog()?;
        let mut report = catalog_report(server, &live)?;
        report.extend([
            ("server".to_owned(), json!(name)),
            ("endpoint".to_owned(), json!(docs.endpoint)),
            ("transport".to_owned(), json!("mcp_streamable_http_tools_list")),
            ("protocol_version".to_owned(), json!(session.protocol_version())),
        ]);
        Ok(Value::Object(report))
    }

    /// Administrative discovery only. No configuration or grant is written.
    pub fn describe_for_operator(&self, server_id: &str, name: &str) -> Result<Value> {
        if !data_name(name) { return Err(error("Terminal, generic dispatcher or unsupported domain operation")); }
        let server = self.servers.get(server_id).ok_or_else(|| error("Unknown configured extension"))?;
        if server.stdio.is_none() && !server.endpoint.as_deref().is_some_and(|e| supported(e, name)) {
            return Err(error("No verified adapter for this operation"));
        }
        if server.disabled { return Err(error("Extension disabled by the operator")); }
        let mut session = self.open_session(server)?;
        let descriptor = session.tool(name)?;
        check_schema(&descriptor, &BTreeMap::new())?;
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

    pub fn call(&self, qualified: &str, args: &Map<String,Value>, scope: ToolScope) -> Result<Value> {
        // Idle sessions of removed, disabled or changed servers close first,
        // even when this call is refused.
        if let Some(pool) = &self.session_pool { pool.retain(&self.session_keys()?); }
        let (server_id, name) = qualified.split_once(':').ok_or_else(||error("An exact qualified tool name is required"))?;
        let (server, approval) = self.servers.get(server_id).and_then(|s| s.tools.get(name).map(|a|(s,a)))
            .ok_or_else(|| error("Individual tool approval required"))?;
        if scope == ToolScope::DataOperations && !data_tool(name) {
            return Err(error("The active profile allows only named data operations"));
        }
        if !args.iter().all(|(key,value)| approval.parameters.get(key).is_some_and(|p|p.allows(value))) {
            return Err(error("Arguments outside the operator-approved contract"));
        }
        if server.endpoint.as_deref().and_then(public_docs).is_some_and(|docs| name != docs.search || args.len() != 1
                || !args.get("query").is_some_and(|query|
                    matches!(approval.parameters.get("query"), Some(Parameter::SearchTerms))
                        && approval.parameters["query"].allows(query)))
        {
            return Err(error("Public documentation search requires one approved public query"));
        }
        if server.disabled { return Err(error("Extension disabled by the operator")); }
        // A pooled child is reused only where a new one could be launched.
        if server.stdio.is_some() && self.stdio_launcher.is_none() {
            return Err(error("Stdio extensions are unavailable in this context"));
        }
        let pool = self.session_pool.as_ref();
        let key = pool.map(|_| self.session_key(server_id)).transpose()?;
        // A reused session that fails before the tool call is replaced once.
        // Listing is read-only, so the replacement cannot repeat an effect.
        let reused = pool.zip(key.as_deref()).and_then(|(pool, key)| pool.take(key));
        let (mut session, descriptor) = match reused.map(|mut session| (session.tool(name), session)) {
            Some((Ok(descriptor), session)) => (session, descriptor),
            stale => {
                // The broken child closes before its replacement takes a slot.
                drop(stale);
                let mut session = self.open_session(server)?;
                let descriptor = session.tool(name)?;
                (session, descriptor)
            }
        };
        let give_back = |session: transport::Session| {
            if let (Some(pool), Some(key)) = (pool, &key) { pool.put(key.clone(), server.stdio.is_some(), session); }
        };
        if let Err(refusal) = admit(&descriptor, approval, args) {
            give_back(session);
            return Err(refusal);
        }
        // There is exactly one effectful request, including on disconnect.
        // A failed call drops its session; only a confirmed reply returns it.
        let response = session.call_tool(name, args.clone())
            .map_err(|_| error("Extension outcome uncertain; do not replay the request"))?;
        give_back(session);
        Ok(response)
    }
}

/// The live descriptor must match its pin and grant before the one call.
fn admit(descriptor: &Value, approval: &Approval, args: &Map<String, Value>) -> Result<()> {
    if descriptor_hash(descriptor) != approval.descriptor_sha256 { return Err(error("Extension descriptor changed; local reapproval required")); }
    check_schema(descriptor, &approval.parameters)?;
    if transport::declares_parameter_headers(descriptor) {
        return Err(error("Extension tool requires parameter headers that this client does not send"));
    }
    if let Some(required) = descriptor["inputSchema"]["required"].as_array() {
        if !required.iter().all(|r| r.as_str().is_some_and(|k| args.contains_key(k))) { return Err(error("Required extension argument missing")); }
    }
    Ok(())
}

/// Compares one live catalog with the pinned grants. Nothing is approved,
/// imported or written; the operator decides on any new scope.
fn catalog_report(server: &Server, live: &[Value]) -> Result<Map<String, Value>> {
    let mut live_hashes = BTreeMap::<String, String>::new();
    for tool in live {
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
    let report = json!({
        "remote_refreshed":true,
        "live_tool_count":live_hashes.len(),
        "approved_tool_count":server.tools.len(),
        "approved_tools":approved,
        "unapproved_live_tool_names":unapproved,
        "catalog_changes_detected":drift,
        "operator_approval_required_for_any_new_scope":true,
        "approved_grants_changed":false,
        "registry_changed":false,
        "oauth_used":false,
        "tool_invoked":false
    });
    Ok(report.as_object().cloned().unwrap_or_default())
}

/// Only granted parameters are ever sent, so only they must be plain data
/// of the granted type. Optional properties the operator did not grant may
/// have any shape: they are never forwarded.
fn check_schema(descriptor: &Value, granted: &BTreeMap<String, Parameter>) -> Result<()> {
    let schema = &descriptor["inputSchema"];
    let properties = schema["properties"].as_object().ok_or_else(|| error("Extension needs an explicit data schema"))?;
    if schema["type"] != "object"
        || ["$ref","oneOf","allOf","anyOf","patternProperties"].iter().any(|k| schema.get(*k).is_some()) {
        return Err(error("Generic dispatchers and opaque payloads cannot be approved"));
    }
    if !granted.iter().all(|(key, parameter)|
        properties.get(key).and_then(|p| p["type"].as_str()) == Some(parameter.json_type())) {
        return Err(error("Local argument approval does not match the extension schema"));
    }
    Ok(())
}
