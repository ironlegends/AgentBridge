//! Locally configured and individually approved MCP extensions.
//! The operator vouches for the server implementation. A descriptor pin detects
//! interface changes. It does not attest the code behind an unchanged interface.

pub mod oauth;
mod result_policy;
mod pool;
pub mod reload;
mod result_cache;
pub use result_cache::CacheRequest;
pub mod status;
pub mod stdio;
mod transport;
pub use oauth::{ClientAuthMethod, OAuthServerConfig, OAuthTokenStore, TokenStatusSummary};
pub use pool::{PoolSummary, SessionPool};
pub use reload::{AdmittedCall, AdmittedProbe, InFlightTracker, LiveExtensionRegistry, PreparedReload, ReloadAuditRecord, ReloadMode};
pub use status::{StatusTracker, UpstreamState};
pub use transport::{fetch_https_bytes, CancellationToken};

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

#[derive(Clone, Deserialize)]
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
    /// Redacted upstream status tracker, attached by the CLI; never parsed.
    #[serde(skip)]
    status_tracker: Option<std::sync::Arc<StatusTracker>>,
}

#[derive(Clone, Deserialize, Serialize)]
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

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    descriptor_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    result_filter: Option<result_policy::ResultPolicy>,
    /// Local operator opt-in, never inferred from remote annotations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    result_cache: Option<result_cache::Policy>,
    /// Optional descriptor captured during local approval. Inspection is offline.
    #[serde(default)]
    descriptor: Option<Value>,
    /// Every variable argument must have a locally chosen data constraint.
    parameters: BTreeMap<String, Parameter>,
}

#[derive(Clone, PartialEq, Deserialize, Serialize)]
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
    fn is_subset_of(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Identifier, Self::Identifier) => true,
            (Self::Boolean, Self::Boolean) => true,
            (Self::SearchTerms, Self::SearchTerms) => true,
            (Self::PublicHttpsUrl, Self::PublicHttpsUrl) => true,
            (Self::Integer { minimum: min_a, maximum: max_a }, Self::Integer { minimum: min_b, maximum: max_b }) => {
                min_a >= min_b && max_a <= max_b
            }
            (Self::Number { minimum: min_a, maximum: max_a }, Self::Number { minimum: min_b, maximum: max_b }) => {
                min_a >= min_b && max_a <= max_b
            }
            (Self::Choice { values: vals_a }, Self::Choice { values: vals_b }) => {
                vals_a.iter().all(|v| vals_b.iter().any(|allowed| allowed == v))
            }
            _ => false,
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

    /// Attaches a bounded, redacted upstream execution status tracker.
    pub fn with_status_tracker(mut self, tracker: std::sync::Arc<StatusTracker>) -> Self {
        self.status_tracker = Some(tracker);
        self
    }

    /// Configured server identifiers in deterministic order.
    pub fn server_names(&self) -> Vec<String> {
        self.servers.keys().cloned().collect()
    }

    pub fn is_server_enabled(&self, name: &str) -> bool {
        self.servers.get(name).is_some_and(|server| !server.disabled)
    }

    /// Returns a cloned registry with `name` marked disabled for live revocation.
    pub(crate) fn with_server_disabled(&self, name: &str) -> Self {
        let mut cloned = self.clone();
        if let Some(server) = cloned.servers.get_mut(name) {
            server.disabled = true;
        }
        cloned
    }

    /// Narrow a validated snapshot using the current private journal.
    /// No new/changed entry or enabled grant can become active this way.
    pub(crate) fn restricted_to(&self, effective: &Self) -> Result<Self> {
        let mut next = self.clone();
        for name in self.server_names() {
            if !effective.has_server(&name) {
                next.servers.remove(&name);
            } else if !effective.is_server_enabled(&name)
                || self.server_sha256(&name)? != effective.server_sha256(&name)? {
                next.servers.get_mut(&name).expect("existing server").disabled = true;
            }
        }
        Ok(next)
    }

    /// Qualification uses the actual executable and upstream catalogue,
    /// not just well-formed hash strings. No tools/call is issued. Disabled
    /// entries cannot execute and must not prevent a revocation.
    pub fn validate_replacement(&self, previous: Option<&Self>) -> Result<()> {
        for (name, server) in &self.servers {
            if server.disabled { continue; }
            if let Some(spec) = &server.stdio {
                stdio::verify_executable(std::path::Path::new(&spec.executable), &spec.executable_sha256)?;
            }
            if server.tools.is_empty() { continue; }
            if let Some(old) = previous {
                if old.is_server_enabled(name) && old.server_sha256(name)? == self.server_sha256(name)? {
                    continue;
                }
            }
            let mut session = self.open_session(server)?;
            let catalog = session.catalog()?;
            for (tool, approval) in &server.tools {
                let mut matches = catalog.iter().filter(|descriptor| descriptor["name"].as_str() == Some(tool.as_str()));
                let descriptor = matches.next().ok_or_else(|| error("Approved descriptor missing during reload"))?;
                if matches.next().is_some() || descriptor_hash(descriptor) != approval.descriptor_sha256 {
                    return Err(error("Approved descriptor pin changed during reload"));
                }
                check_schema(descriptor, &approval.parameters)?;
                if transport::declares_parameter_headers(descriptor) {
                    return Err(error("Approved descriptor requires unsupported parameter headers"));
                }
            }
        }
        Ok(())
    }

    /// True if both registries have identical configured servers, enabled
    /// states, and exact server configuration digests.
    pub fn matches_fingerprints(&self, other: &Self) -> Result<bool> {
        let names = self.server_names();
        if names != other.server_names() {
            return Ok(false);
        }
        for name in names {
            if self.is_server_enabled(&name) != other.is_server_enabled(&name) {
                return Ok(false);
            }
            if self.server_sha256(&name)? != other.server_sha256(&name)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The pool key of one server: its name and its exact fingerprint.
    fn session_key(&self, name: &str) -> Result<String> {
        let fingerprint = self.server_sha256(name)?.ok_or_else(|| error("Unknown extension server"))?;
        Ok(format!("{name}:{fingerprint}"))
    }

    /// The keys of every enabled server in this registry.
    pub(crate) fn session_keys(&self) -> Result<std::collections::BTreeSet<String>> {
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
        let started = std::time::Instant::now();
        let mut session = self.open_session(server)?;
        let live = session.catalog()?;
        let latency_ms = started.elapsed().as_millis() as u64;
        let mut report = catalog_report(server, &live)?;
        let drift = has_approved_descriptor_drift(&report);
        report.extend([
            ("server".to_owned(), json!(name)),
            ("transport".to_owned(), json!("stdio")),
            ("executable_sha256".to_owned(), json!(spec.executable_sha256)),
            ("stderr_bytes".to_owned(), json!(session.stderr_bytes().unwrap_or(0))),
            ("protocol_version".to_owned(), json!(session.protocol_version())),
            ("latency_ms".to_owned(), json!(latency_ms)),
            ("ok".to_owned(), json!(!drift)),
            ("status".to_owned(), json!(if drift { "descriptor_drift" } else { "ok" })),
            ("error_class".to_owned(), if drift { json!("descriptor_hash_drift") } else { Value::Null }),
        ]);
        Ok(Value::Object(report))
    }

    /// Read-only connection test for any locally approved, enabled extension
    /// server (HTTP or stdio). Uses the exact configured pins and approvals,
    /// performs discovery/initialize + tools/list + pinned descriptor hash
    /// comparison, never invokes any tool, and never grants new permissions.
    pub fn test_connection(&self, name: &str) -> Result<Value> {
        self.test_connection_inner(name, None, None)
    }

    pub fn test_connection_cancellable(&self, name: &str, cancel: Option<&CancellationToken>) -> Result<Value> {
        self.test_connection_inner(name, cancel, None)
    }

    pub(crate) fn test_connection_managed(
        &self,
        name: &str,
        cancel: &CancellationToken,
        generation: u64,
    ) -> Result<Value> {
        self.test_connection_inner(name, Some(cancel), Some(generation))
    }

    fn test_connection_inner(
        &self,
        name: &str,
        cancel: Option<&CancellationToken>,
        generation: Option<u64>,
    ) -> Result<Value> {
        let server = self.servers.get(name).ok_or_else(|| error("Extension server is not configured"))?;
        if server.disabled {
            return Err(error("Extension disabled by the operator"));
        }
        if let Some(docs) = PUBLIC_DOCS.iter().find(|docs| docs.server == name) {
            if server.endpoint.as_deref() != Some(docs.endpoint) || server.bearer_env.is_some() {
                return Err(error("Documentation refresh requires the exact public tokenless endpoint"));
            }
        }
        if server.stdio.is_some() && self.stdio_launcher.is_none() {
            return Err(error("Stdio extensions are unavailable in this context"));
        }
        if cancel.is_some_and(CancellationToken::is_cancelled) {
            return Err(error("Extension call cancelled due to revocation"));
        }
        let transport_label = if server.stdio.is_some() { "stdio" } else { "http" };
        let config_sha256 = self.server_sha256(name)?;
        let status_guard = self.status_tracker.as_ref()
            .map(|tracker| tracker.begin_starting_for(name, config_sha256.as_deref(), cancel));
        let started = std::time::Instant::now();
        let mut session = match self.open_session_cancellable(server, cancel) {
            Ok(session) => session,
            Err(err) => {
                let cancelled = cancel.is_some_and(CancellationToken::is_cancelled)
                    || err.to_string().contains("cancelled due to revocation");
                let elapsed = started.elapsed();
                if cancelled {
                    drop(status_guard);
                    return Err(error("Extension call cancelled due to revocation"));
                }
                if let Some(guard) = status_guard {
                    guard.finish_error(transport::classify_error(&err), Some(elapsed.as_millis() as u64));
                }
                return Ok(connection_error_report(
                    name,
                    transport_label,
                    None,
                    None,
                    server.stdio.as_ref().map(|s| s.executable_sha256.as_str()),
                    &err,
                    elapsed,
                ));
            }
        };
        let protocol_version = session.protocol_version();
        let live = match session.catalog_cancellable(cancel) {
            Ok(live) => live,
            Err(err) => {
                let cancelled = cancel.is_some_and(CancellationToken::is_cancelled)
                    || err.to_string().contains("cancelled due to revocation");
                let elapsed = started.elapsed();
                drop(session);
                if cancelled {
                    drop(status_guard);
                    return Err(error("Extension call cancelled due to revocation"));
                }
                if let Some(guard) = status_guard {
                    guard.finish_error(transport::classify_error(&err), Some(elapsed.as_millis() as u64));
                }
                return Ok(connection_error_report(
                    name,
                    transport_label,
                    Some(protocol_version),
                    None,
                    server.stdio.as_ref().map(|s| s.executable_sha256.as_str()),
                    &err,
                    elapsed,
                ));
            }
        };
        if cancel.is_some_and(CancellationToken::is_cancelled) {
            drop(session);
            drop(status_guard);
            return Err(error("Extension call cancelled due to revocation"));
        }
        let latency_ms = started.elapsed().as_millis() as u64;
        let mut report = match catalog_report(server, &live) {
            Ok(report) => report,
            Err(err) => {
                if let Some(guard) = status_guard {
                    guard.finish_error(transport::classify_error(&err), Some(latency_ms));
                }
                return Err(err);
            }
        };
        let drift = has_approved_descriptor_drift(&report);
        if let Some(guard) = status_guard {
            if drift {
                guard.finish_error("descriptor_hash_drift", Some(latency_ms));
            } else {
                guard.finish_ready(latency_ms);
            }
        }
        report.extend([
            ("server".to_owned(), json!(name)),
            ("transport".to_owned(), json!(transport_label)),
            ("protocol_version".to_owned(), json!(protocol_version)),
            ("latency_ms".to_owned(), json!(latency_ms)),
            ("ok".to_owned(), json!(!drift)),
            ("status".to_owned(), json!(if drift { "descriptor_drift" } else { "ok" })),
            ("error_class".to_owned(), if drift { json!("descriptor_hash_drift") } else { Value::Null }),
            ("config_sha256".to_owned(), json!(config_sha256)),
        ]);
        if let Some(gen_id) = generation {
            report.insert("generation".to_owned(), json!(gen_id));
        }
        if let Some(spec) = &server.stdio {
            report.insert("executable_sha256".to_owned(), json!(spec.executable_sha256));
            report.insert("stderr_bytes".to_owned(), json!(session.stderr_bytes().unwrap_or(0)));
        }
        Ok(Value::Object(report))
    }

    /// One session over the server's own transport. A stdio server needs
    /// the launcher the CLI attaches; nothing is started without it.
    fn open_session(&self, server: &Server) -> Result<transport::Session> {
        self.open_session_cancellable(server, None)
    }

    fn open_session_cancellable(
        &self,
        server: &Server,
        cancel: Option<&CancellationToken>,
    ) -> Result<transport::Session> {
        match (&server.endpoint, &server.stdio) {
            (Some(endpoint), None) =>
                transport::Session::open_cancellable(endpoint, server.bearer_env.as_deref(), &server.header_env, cancel),
            (None, Some(spec)) => {
                let launcher = self.stdio_launcher.as_deref()
                    .ok_or_else(|| error("Stdio extensions are unavailable in this context"))?;
                // An idle pooled child yields its slot to any new session.
                if stdio::slots_exhausted() { pool::evict_idle_stdio(); }
                transport::Session::open_stdio_cancellable(spec, launcher, &|name| std::env::var_os(name), cancel)
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
                if let Some(policy) = &tool.result_filter { policy.validate()?; }
                if let Some(cache)=tool.result_cache {
                    if !tool.descriptor.as_ref().is_some_and(|d|cache.valid(d)) {
                        return Err(error("Result cache requires a pinned read-only descriptor and local read-only policy"));
                    }
                    // A mutable outbound credential can change outside the
                    // inbound grant. Do not retain results for those HTTP
                    // configurations until outbound identity is fenced.
                    if server.bearer_env.is_some() || !server.header_env.is_empty() ||
                        server.stdio.as_ref().is_some_and(|spec|!spec.env.is_empty() || spec.inherit_path) {
                        return Err(error("Result cache requires a fixed extension without mutable credential or PATH references"));
                    }
                }
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
        let started = std::time::Instant::now();
        let mut session = transport::Session::open(docs.endpoint, None, &BTreeMap::new())?;
        let live = session.catalog()?;
        let latency_ms = started.elapsed().as_millis() as u64;
        let mut report = catalog_report(server, &live)?;
        let drift = has_approved_descriptor_drift(&report);
        report.extend([
            ("server".to_owned(), json!(name)),
            ("endpoint".to_owned(), json!(docs.endpoint)),
            ("transport".to_owned(), json!("mcp_streamable_http_tools_list")),
            ("protocol_version".to_owned(), json!(session.protocol_version())),
            ("latency_ms".to_owned(), json!(latency_ms)),
            ("ok".to_owned(), json!(!drift)),
            ("status".to_owned(), json!(if drift { "descriptor_drift" } else { "ok" })),
            ("error_class".to_owned(), if drift { json!("descriptor_hash_drift") } else { Value::Null }),
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
        self.call_cancellable(qualified, args, scope, None)
    }

    pub fn call_cancellable(
        &self,
        qualified: &str,
        args: &Map<String,Value>,
        scope: ToolScope,
        cancel: Option<&CancellationToken>,
    ) -> Result<Value> {
        self.call_inner(qualified, args, scope, cancel, false, None)
    }

    pub(crate) fn call_managed(
        &self, qualified: &str, args: &Map<String, Value>, scope: ToolScope,
        cancel: &CancellationToken, cache: Option<&CacheRequest>,
    ) -> Result<Value> {
        self.call_inner(qualified, args, scope, Some(cancel), true, cache)
    }

    fn call_inner(
        &self, qualified: &str, args: &Map<String, Value>, scope: ToolScope,
        cancel: Option<&CancellationToken>, managed: bool, cache: Option<&CacheRequest>,
    ) -> Result<Value> {
        // Only the live registry owns its pool's eviction policy. An old
        // snapshot must never prune the new generation's idle entries.
        if !managed {
            if let Some(pool) = &self.session_pool { let _ = pool.retain(&self.session_keys()?); }
        }
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
        if cancel.is_some_and(CancellationToken::is_cancelled) {
            return Err(error("Extension call cancelled due to revocation"));
        }
        // A pooled child is reused only where a new one could be launched.
        if server.stdio.is_some() && self.stdio_launcher.is_none() {
            return Err(error("Stdio extensions are unavailable in this context"));
        }
        let server_sha = self.server_sha256(server_id)?;
        let status_guard = self.status_tracker.as_ref()
            .map(|tracker| tracker.begin_starting_for(server_id, server_sha.as_deref(), cancel));
        let started = std::time::Instant::now();
        let pool = self.session_pool.as_ref();
        let key = pool.map(|_| self.session_key(server_id)).transpose()?;
        // A reused session that fails before the tool call is replaced once.
        // Listing is read-only, so the replacement cannot repeat an effect.
        let reused = pool.zip(key.as_deref()).and_then(|(pool, key)| pool.take(key, cancel));
        let (mut session, descriptor) = match reused.map(|mut session| (session.tool_cancellable(name, cancel), session)) {
            Some((Ok(descriptor), session)) => (session, descriptor),
            stale => {
                // The broken child closes before its replacement takes a slot.
                drop(stale);
                let mut session = match self.open_session_cancellable(server, cancel) {
                    Ok(session) => session,
                    Err(err) => {
                        if let Some(guard) = status_guard {
                            guard.finish_error(transport::classify_error(&err), Some(started.elapsed().as_millis() as u64));
                        }
                        return Err(err);
                    }
                };
                let descriptor = match session.tool_cancellable(name, cancel) {
                    Ok(descriptor) => descriptor,
                    Err(err) => {
                        if let Some(guard) = status_guard {
                            guard.finish_error(transport::classify_error(&err), Some(started.elapsed().as_millis() as u64));
                        }
                        return Err(err);
                    }
                };
                (session, descriptor)
            }
        };
        let give_back = |session: transport::Session| {
            if cancel.is_some_and(CancellationToken::is_cancelled) {
                drop(session);
                return;
            }
            if let (Some(pool), Some(key)) = (pool, &key) { pool.put(key.clone(), server.stdio.is_some(), session, cancel); }
        };
        if let Err(refusal) = admit(&descriptor, approval, args) {
            let class = if descriptor_hash(&descriptor) != approval.descriptor_sha256 {
                "descriptor_hash_drift"
            } else {
                "catalog_failed"
            };
            if let Some(guard) = status_guard {
                guard.finish_error(class, Some(started.elapsed().as_millis() as u64));
            }
            give_back(session);
            return Err(refusal);
        }
        // Cache is strictly downstream of the real admission, journal and
        // fresh upstream descriptor pin/schema checks, never a substitute.
        let flight=cache.zip(approval.result_cache)
            .filter(|(_,policy)|managed && policy.valid(&descriptor))
            .and_then(|(request,policy)|request.tool(server_id,name,&approval.descriptor_sha256,args,policy));
        if let Some(value)=flight.as_ref().and_then(|f|f.get(std::time::Instant::now(),cancel)){
            if let Some(guard)=status_guard {
                guard.finish_ready(started.elapsed().as_millis() as u64);
            }
            give_back(session);
            if cancel.is_some_and(CancellationToken::is_cancelled){
                return Err(error("Extension call cancelled due to revocation"));
            }
            return Ok(value);
        }
        // There is exactly one effectful request, including on disconnect.
        // A failed call drops its session; only a confirmed reply returns it.
        let response = match session.call_tool_cancellable(name, args.clone(), cancel) {
            Ok(response) => {
                if let Some(guard) = status_guard {
                    guard.finish_ready(started.elapsed().as_millis() as u64);
                }
                response
            }
            Err(err) => {
                let cancelled = cancel.is_some_and(CancellationToken::is_cancelled)
                    || err.to_string().contains("cancelled due to revocation");
                if let Some(guard) = status_guard {
                    let class = if cancelled { "revoked_cancelled" } else { transport::classify_error(&err) };
                    guard.finish_error(class, Some(started.elapsed().as_millis() as u64));
                }
                if cancelled {
                    return Err(error("Extension call cancelled due to revocation"));
                }
                return Err(error("Extension outcome uncertain; do not replay the request"));
            }
        };
        give_back(session);
        if cancel.is_some_and(CancellationToken::is_cancelled) {
            // A response observed during revocation is not permission to
            // repeat a possibly completed upstream effect.
            return Err(error("Extension call cancelled due to revocation; outcome may be uncertain; do not replay"));
        }
        // Remember only the upstream success bit, before a result policy
        // can remove fields. Never cache errors even if a filter masks them.
        let success=response.as_object().is_some_and(|r|
            r.get("isError").is_none_or(|v|v==&Value::Bool(false)) &&
            !r.contains_key("error") && !r.contains_key("is_error"));
        // Never store the upstream response. Only this final, successful
        // #186 policy result may enter the bounded cache.
        let filtered=approval.result_filter.as_ref().unwrap_or(&result_policy::ResultPolicy::default()).apply(response)?;
        if success {
            if let Some(flight)=flight {
                flight.publish_filtered(&filtered,std::time::Instant::now(),cancel);
            }
        }
        Ok(filtered)
    }
}

/// Returns `true` if `new` grants any server, enabled state, tool, transport
/// endpoint/pin/credential reference, or parameter range beyond `old`.
pub(crate) fn authority_widens(old: &Registry, new: &Registry) -> Result<bool> {
    for (name, new_srv) in &new.servers {
        if new_srv.disabled {
            continue;
        }
        let Some(old_srv) = old.servers.get(name) else {
            return Ok(true);
        };
        if old_srv.disabled {
            return Ok(true);
        }
        if new_srv.endpoint != old_srv.endpoint
            || new_srv.stdio != old_srv.stdio
            || new_srv.bearer_env != old_srv.bearer_env
            || new_srv.header_env != old_srv.header_env
        {
            return Ok(true);
        }
        for (tool_name, new_app) in &new_srv.tools {
            let Some(old_app) = old_srv.tools.get(tool_name) else {
                return Ok(true);
            };
            if new_app.result_cache != old_app.result_cache { return Ok(true); }
            if serde_json::to_value(&new_app.result_filter).map_err(|_|error("Invalid result policy"))?
                != serde_json::to_value(&old_app.result_filter).map_err(|_|error("Invalid result policy"))? {
                return Ok(true);
            }
            if new_app.descriptor_sha256 != old_app.descriptor_sha256 {
                return Ok(true);
            }
            for (param_name, new_param) in &new_app.parameters {
                let Some(old_param) = old_app.parameters.get(param_name) else {
                    return Ok(true);
                };
                if !new_param.is_subset_of(old_param) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
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

fn has_approved_descriptor_drift(report: &Map<String, Value>) -> bool {
    report.get("approved_tools")
        .and_then(Value::as_array)
        .is_some_and(|tools| tools.iter().any(|entry| entry.get("status").and_then(Value::as_str) != Some("unchanged")))
}

fn connection_error_report(
    name: &str,
    transport: &str,
    protocol_version: Option<String>,
    stderr_bytes: Option<u64>,
    executable_sha256: Option<&str>,
    err: &io::Error,
    elapsed: std::time::Duration,
) -> Value {
    let mut report = json!({
        "ok": false,
        "status": "error",
        "error_class": transport::classify_error(err),
        "latency_ms": elapsed.as_millis() as u64,
        "server": name,
        "transport": transport,
        "protocol_version": protocol_version,
        "remote_refreshed": false,
        "operator_approval_required_for_any_new_scope": true,
        "approved_grants_changed": false,
        "registry_changed": false,
        "oauth_used": false,
        "tool_invoked": false
    });
    if let Some(sha) = executable_sha256 {
        report["executable_sha256"] = json!(sha);
    }
    if let Some(bytes) = stderr_bytes {
        report["stderr_bytes"] = json!(bytes);
    }
    report
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
