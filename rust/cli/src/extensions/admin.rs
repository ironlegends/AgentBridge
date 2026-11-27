//! A Web extension administration call is an inert, typed proposal.
//! Only an interactive operator CLI can decide it. The private journal is
//! separate from extensions.json and cannot grant or imply any tool access.

#[path = "admin_platform.rs"]
mod admin_platform;
#[path = "import.rs"]
mod import;

use agent_bridge_extensions::oauth::{
    self, valid_secret_env_name, ClientAuthMethod, OAuthServerConfig, OAuthTokenStore,
};
use agent_bridge_extensions::stdio::StdioSpec;
use agent_bridge_extensions::{
    config_sha256, validate_proposed_endpoint, validate_header_env, valid_server_name, Registry, ServerControl,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, IsTerminal, Read, Write, BufRead};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const JOURNAL: &str = ".extensions-admin.json";
const LOCK: &str = ".extensions-admin.lock";
const MAX_JOURNAL: usize = 128 * 1024;
const MAX_PROPOSAL: usize = 16 * 1024;
const MAX_REQUESTS: usize = 256;
const REASON_STALE: &str = "configuration_or_operator_state_changed";

fn denied(message: &'static str) -> io::Error { io::Error::other(message) }
fn hex_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
// Shared with Registry::parse; existing 65–96-byte names are valid.
fn valid_name(name: &str) -> bool { valid_server_name(name) }
fn bound_text(value: &Option<String>, maximum: usize) -> bool {
    value.as_ref().is_none_or(|s| !s.is_empty() && s.len() <= maximum)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Origin {
    Web,
    LocalCli,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VerifyError {
    Changed,
    Unavailable,
}

trait ParsedRegistryView {
    fn has_server(&self, name: &str) -> bool;
    fn server_endpoint(&self, name: &str) -> Option<&str>;
    fn server_stdio(&self, name: &str) -> Option<&StdioSpec>;
    fn header_authorization_configured(&self, name: &str) -> bool;
    fn server_sha256(&self, name: &str) -> io::Result<Option<String>>;
    fn refresh_public_docs(&self, name: &str) -> io::Result<Value>;
    fn auth_status_with_oauth(
        &self,
        name: &str,
        control: Option<&ServerControl>,
        oauth_cfg: Option<&OAuthServerConfig>,
        token_status: Option<&oauth::TokenStatusSummary>,
    ) -> io::Result<Option<Value>>;
    fn servers_overview(&self) -> io::Result<Value>;
    fn approved_tools_list(&self) -> Vec<String>;
}

impl ParsedRegistryView for Registry {
    fn has_server(&self, name: &str) -> bool { Registry::has_server(self, name) }
    fn server_endpoint(&self, name: &str) -> Option<&str> { Registry::server_endpoint(self, name) }
    fn server_stdio(&self, name: &str) -> Option<&StdioSpec> { Registry::server_stdio(self, name) }
    fn header_authorization_configured(&self, name: &str) -> bool {
        Registry::header_authorization_configured(self, name)
    }
    fn server_sha256(&self, name: &str) -> io::Result<Option<String>> {
        Registry::server_sha256(self, name)
    }
    fn refresh_public_docs(&self, name: &str) -> io::Result<Value> {
        Registry::refresh_public_docs(self, name)
    }
    fn auth_status_with_oauth(
        &self,
        name: &str,
        control: Option<&ServerControl>,
        oauth_cfg: Option<&OAuthServerConfig>,
        token_status: Option<&oauth::TokenStatusSummary>,
    ) -> io::Result<Option<Value>> {
        Registry::auth_status_with_oauth(self, name, control, oauth_cfg, token_status)
    }
    fn servers_overview(&self) -> io::Result<Value> { Registry::servers(self, None) }
    fn approved_tools_list(&self) -> Vec<String> { Registry::list(self) }
}

trait ExtBackend {
    type Reg: ParsedRegistryView;
    fn validate_stdio_spec(&self, spec: &StdioSpec) -> io::Result<()>;
    fn valid_child_env_name(&self, name: &str) -> bool;
    fn observe_executable(&self, path: &Path) -> io::Result<String>;
    fn verify_executable(&self, path: &Path, expected_sha256: &str) -> Result<(), VerifyError>;
    fn parse_registry(
        &self,
        effective_bytes: &[u8],
        controls: Option<&BTreeMap<String, ServerControl>>,
    ) -> io::Result<Self::Reg>;
    // The real in-process owner applies committed restrictions before
    // releasing the journal lock. Synthetic backends have no live routes.
    fn committed(&self, _settings: &Path, _journal: &Journal) -> io::Result<super::RevocationAckReceipt> {
        Ok(super::RevocationAckReceipt::default())
    }
}

struct RealBackend;

impl ExtBackend for RealBackend {
    type Reg = Registry;
    fn committed(&self, settings: &Path, journal: &Journal) -> io::Result<super::RevocationAckReceipt> {
        super::journal_committed(settings, journal)
    }
    fn validate_stdio_spec(&self, spec: &StdioSpec) -> io::Result<()> {
        spec.validate()
    }
    fn valid_child_env_name(&self, name: &str) -> bool {
        agent_bridge_extensions::stdio::valid_child_env_name(name)
    }
    fn observe_executable(&self, path: &Path) -> io::Result<String> {
        agent_bridge_extensions::stdio::observe_executable(path)
    }
    fn verify_executable(&self, path: &Path, expected_sha256: &str) -> Result<(), VerifyError> {
        let observed = agent_bridge_extensions::stdio::observe_executable(path)
            .map_err(|_| VerifyError::Unavailable)?;
        if observed != expected_sha256 {
            return Err(VerifyError::Changed);
        }
        agent_bridge_extensions::stdio::verify_executable(path, expected_sha256)
            .map_err(|_| VerifyError::Changed)
    }
    fn parse_registry(
        &self,
        effective_bytes: &[u8],
        controls: Option<&BTreeMap<String, ServerControl>>,
    ) -> io::Result<Self::Reg> {
        let parsed = Registry::parse(effective_bytes)?;
        match controls {
            Some(controls) => parsed.with_controls(controls),
            None => Ok(parsed),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Proposal {
    Add {
        name: String,
        url: String,
        description: Option<String>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        header_env: BTreeMap<String, String>,
        enabled: Option<bool>,
        oauth: Option<bool>,
        oauth_scope: Option<String>,
        oauth_client_id: Option<String>,
        oauth_client_auth_method: Option<ClientAuthMethod>,
        oauth_client_secret_env: Option<String>,
    },
    AddStdio {
        name: String,
        executable: String,
        executable_sha256: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        env: BTreeMap<String, String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        import_source_sha256: Option<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        inherit_path: bool,
    },
    Remove { name: String },
    Enable { name: String },
    Disable { name: String },
    SetOauth {
        name: String,
        oauth: bool,
        oauth_scope: Option<String>,
        oauth_client_id: Option<String>,
        oauth_client_auth_method: Option<ClientAuthMethod>,
        oauth_client_secret_env: Option<String>,
    },
    AuthStart { name: String, force: Option<bool> },
    AuthStatus { name: String },
    AuthDisconnect { name: String },
    Refresh { name: String, timeout_ms: Option<u32> },
}

impl Proposal {
    fn requires_acknowledged_base(&self) -> bool {
        match self {
            Self::Disable { .. } | Self::Remove { .. } | Self::AuthDisconnect { .. }
            | Self::AuthStatus { .. } | Self::SetOauth { oauth: false, .. } => false,
            Self::Add { .. } | Self::AddStdio { .. } | Self::Enable { .. }
            | Self::SetOauth { oauth: true, .. } | Self::AuthStart { .. }
            | Self::Refresh { .. } => true,
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Add { name, .. } | Self::AddStdio { name, .. } | Self::Remove { name }
            | Self::Enable { name } | Self::Disable { name }
            | Self::SetOauth { name, .. } | Self::AuthStart { name, .. }
            | Self::AuthStatus { name } | Self::AuthDisconnect { name }
            | Self::Refresh { name, .. } => name,
        }
    }

    fn support(&self) -> &'static str {
        match self {
            Self::Add { description: Some(_), .. } => "unsupported_parameters_not_applied",
            Self::Add { .. } | Self::Remove { .. } => "local_registry_overlay_after_approval",
            Self::AddStdio { .. } => "local_stdio_registry_overlay_after_approval",
            Self::Enable { .. } | Self::Disable { .. } => "local_state_change_after_approval",
            Self::SetOauth { .. } => "local_oauth_config_change_after_approval",
            Self::AuthStart { .. } => "outbound_oauth_pkce_flow_after_approval",
            Self::AuthDisconnect { .. } => "local_oauth_token_disconnect_after_approval",
            Self::AuthStatus { .. } => "local_auth_and_dpapi_token_status_after_approval",
            Self::Refresh { name, timeout_ms: None } if agent_bridge_extensions::public_docs_server(name) =>
                "remote_catalog_refresh_after_local_approval",
            Self::Refresh { .. } => "unsupported_remote_refresh_not_implemented",
        }
    }
}

/// Preserve old journal records for audit but NEVER silently ignore a
/// parameter on a new proposal.
fn validate_actionable_inputs(request: &Proposal) -> io::Result<()> {
    match request {
        Proposal::Add { description: Some(_), .. } => {
            Err(denied("Add does not persist description; omit description"))
        }
        Proposal::Refresh { timeout_ms: Some(_), .. } =>
            Err(denied("Refresh has fixed bounded timeout; timeout_ms would be ignored")),
        _ => Ok(()),
    }
}

fn proposal_with<B: ExtBackend>(backend: &B, value: &Value) -> io::Result<Proposal> {
    let bytes = serde_json::to_vec(value).map_err(|_| denied("Cannot encode extension proposal"))?;
    if bytes.len() > MAX_PROPOSAL { return Err(denied("Extension proposal is too large")); }
    // serde's tagged enum rejects fields belonging to a different action,
    // all unknown fields, and all untyped secret/header/command parameters.
    let p: Proposal = serde_json::from_slice(&bytes)
        .map_err(|_| denied("Invalid typed extension proposal"))?;
    if !valid_name(p.name()) { return Err(denied("Invalid extension name")); }
    match &p {
        Proposal::Add {
            url, description, header_env, oauth, oauth_scope, oauth_client_id,
            oauth_client_auth_method, oauth_client_secret_env, ..
        } => {
            validate_header_env(url, header_env, *oauth == Some(true))?;
            if url.len() > 4096 || validate_proposed_endpoint(url).is_err()
                || !bound_text(description, 1024)
                || !bound_text(oauth_scope, 8192)
                || !bound_text(oauth_client_id, 1024)
                || oauth_client_secret_env.as_deref().is_some_and(|e| !valid_secret_env_name(e))
                || (*oauth != Some(true) && (
                    oauth_scope.is_some() || oauth_client_id.is_some()
                    || oauth_client_auth_method.is_some()
                    || oauth_client_secret_env.is_some()))
            {
                return Err(denied("Invalid inert extension addition proposal"));
            }
        }
        Proposal::AddStdio {
            name, executable, executable_sha256, args, env, cwd, import_source_sha256, inherit_path, ..
        } => {
            if agent_bridge_extensions::public_docs_server(name)
                || import_source_sha256.as_deref().is_some_and(|s| !hex_digest(s))
            {
                return Err(denied("Invalid inert stdio extension addition proposal"));
            }
            let spec = StdioSpec {
                executable: executable.clone(),
                executable_sha256: executable_sha256.clone(),
                args: args.clone(),
                env: env.clone(),
                cwd: cwd.clone(),
                inherit_path: *inherit_path,
            };
            backend.validate_stdio_spec(&spec)?;
        }
        Proposal::SetOauth {
            oauth, oauth_scope, oauth_client_id, oauth_client_auth_method,
            oauth_client_secret_env, ..
        } => {
            if !bound_text(oauth_scope, 8192) || !bound_text(oauth_client_id, 1024)
                || oauth_client_secret_env.as_deref().is_some_and(|e| !valid_secret_env_name(e))
                || (!*oauth && (oauth_scope.is_some() || oauth_client_id.is_some()
                    || oauth_client_auth_method.is_some()
                    || oauth_client_secret_env.is_some()))
            {
                return Err(denied("Invalid inert OAuth proposal"));
            }
        }
        Proposal::Refresh { timeout_ms, .. } => {
            if timeout_ms.is_some_and(|ms| !(250..=300_000).contains(&ms)) {
                return Err(denied("Invalid refresh timeout"));
            }
        }
        _ => {}
    }
    Ok(p)
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Decision { Pending, Refused, Unsupported, Approved }

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    config_sha256: String,
    control_sha256: String,
    revision: u64,
    payload: Value,
    status: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    /// Durable comparison receipt for an approved read-only MCP refresh.
    /// Repeated local decisions return this without recontacting the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_receipt: Option<Value>,
}

const REASON_EXISTS: &str = "server_already_exists";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum ServerEntry {
    // Generation-bound local opt-in: an old base approval cannot survive a
    // remove/re-add of the same server name.
    Added {
        endpoint: String,
        grant_nonce: String,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        header_env: BTreeMap<String, String>,
    },
    AddedStdio {
        stdio: StdioSpec,
        grant_nonce: String,
    },
    Removed { config_sha256: String },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    version: u8,
    revision: u64,
    controls: BTreeMap<String, ServerControl>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    entries: BTreeMap<String, ServerEntry>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    oauth_configs: BTreeMap<String, OAuthServerConfig>,
    requests: BTreeMap<String, Record>,
}
impl Default for Journal {
    fn default() -> Self {
        Self {
            version: 1,
            revision: 0,
            controls: BTreeMap::new(),
            entries: BTreeMap::new(),
            oauth_configs: BTreeMap::new(),
            requests: BTreeMap::new(),
        }
    }
}

fn control_hash(controls: &BTreeMap<String, ServerControl>) -> io::Result<String> {
    Ok(config_sha256(&serde_json::to_vec(controls)
        .map_err(|_| denied("Cannot encode operator state"))?))
}

fn state_hash(journal: &Journal) -> io::Result<String> {
    if journal.entries.is_empty() && journal.oauth_configs.is_empty() {
        return control_hash(&journal.controls);
    }
    if journal.oauth_configs.is_empty() {
        return Ok(config_sha256(&serde_json::to_vec(&(&journal.controls, &journal.entries))
            .map_err(|_| denied("Cannot encode operator state"))?));
    }
    Ok(config_sha256(
        &serde_json::to_vec(&(&journal.controls, &journal.entries, &journal.oauth_configs))
            .map_err(|_| denied("Cannot encode operator state"))?,
    ))
}

/// Build one effective Registry. An added server starts with NO tools.
/// An operator can later hand-author a pinned approval in extensions.json
/// only by placing this server's exact bridge_grant_nonce alongside its tools.
/// A remove/re-add changes the nonce: old tool grants cannot revive.
/// The marker is stripped before the strict Registry::parse call.
fn effective_registry_bytes(base_bytes: &[u8], journal: &Journal) -> io::Result<Vec<u8>> {
    let mut root: Value = serde_json::from_slice(base_bytes)
        .map_err(|_| denied("Invalid extension registry"))?;
    let servers = root.get_mut("servers")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| denied("Invalid extension registry"))?;
    for (name, value) in servers.iter() {
        if value.as_object().is_some_and(|obj| obj.contains_key("stdio")) {
            let bound = matches!(
                journal.entries.get(name),
                Some(ServerEntry::AddedStdio { grant_nonce, .. })
                    if value.get("bridge_grant_nonce").and_then(Value::as_str) == Some(grant_nonce.as_str())
            );
            if !bound {
                return Err(denied("Base extension registry cannot define unapproved stdio server"));
            }
        }
    }
    if journal.entries.is_empty() { return Ok(base_bytes.to_vec()); }
    for (name, entry) in &journal.entries {
        match entry {
            ServerEntry::Added { endpoint, grant_nonce, header_env } => {
                let approved_tools = match servers.get(name).and_then(Value::as_object) {
                    Some(base) if base.get("bridge_grant_nonce").and_then(Value::as_str)
                        == Some(grant_nonce.as_str()) =>
                    {
                        // The manual, generation-bound grant must use the exact
                        // locally approved endpoint and only recognized fields.
                        if base.keys().any(|field|
                            !matches!(field.as_str(), "bridge_grant_nonce" | "endpoint" | "tools"))
                            || base.get("endpoint").and_then(Value::as_str) != Some(endpoint)
                        {
                            return Err(denied("Invalid locally granted extension entry"));
                        }
                        base.get("tools").and_then(Value::as_object)
                            .cloned().ok_or_else(|| denied("Granted tools must be an object"))?
                    }
                    _ => Map::new(), // Old or unmatched grants remain dormant.
                };
                let mut effective = json!({"endpoint":endpoint, "tools":approved_tools});
                if !header_env.is_empty() { effective["header_env"] = json!(header_env); }
                servers.insert(name.clone(), effective);
            }
            ServerEntry::AddedStdio { stdio, grant_nonce } => {
                let approved_tools = match servers.get(name).and_then(Value::as_object) {
                    Some(base) if base.get("bridge_grant_nonce").and_then(Value::as_str)
                        == Some(grant_nonce.as_str()) =>
                    {
                        if base.keys().any(|field|
                            !matches!(field.as_str(), "bridge_grant_nonce" | "tools"))
                        {
                            return Err(denied("Invalid locally granted extension entry"));
                        }
                        base.get("tools").and_then(Value::as_object)
                            .cloned().ok_or_else(|| denied("Granted tools must be an object"))?
                    }
                    _ => Map::new(),
                };
                servers.insert(name.clone(), json!({"stdio": stdio, "tools": approved_tools}));
            }
            ServerEntry::Removed { .. } => {
                // Tombstone hides stale registry entries until a distinct add.
                servers.remove(name);
            }
        }
    }
    serde_json::to_vec(&root).map_err(|_| denied("Cannot encode effective extension registry"))
}
fn request_id(config: &str, control: &str, revision: u64, payload: &Value) -> String {
    let mut sorted = payload.clone();
    sorted.sort_all_objects();
    config_sha256(format!(
        "agent-bridge/extension-proposal/v1\0{config}\0{control}\0{revision}\0{sorted}"
    ).as_bytes())
}

fn qualified_registry(settings: &Path) -> io::Result<Vec<u8>> {
    qualified_registry_with(&RealBackend, settings)
}

fn qualified_registry_with<B: ExtBackend>(backend: &B, settings: &Path) -> io::Result<Vec<u8>> {
    // This lifecycle read validates the whole private settings root, nofollow
    // components, Windows owner-only ACL (or Unix permissions), and registry file.
    let bytes = agent_bridge_lifecycle::read_operator_setting(settings, "extensions.json")
        .map_err(|_| denied("Qualified private operator settings required"))?;
    // Only locally approved Added/AddedStdio entries may contain bridge_grant_nonce.
    // Everything else must satisfy the existing strict Registry parser.
    let journal = load_with(backend, settings)?;
    let effective = effective_registry_bytes(&bytes, &journal)?;
    let _ = backend.parse_registry(&effective, None)?;
    Ok(bytes)
}

fn check_private_file(meta: &Metadata) -> io::Result<()> {
    if !meta.is_file() || meta.len() > MAX_JOURNAL as u64 {
        return Err(denied("Unsafe extension administration state file"));
    }
    // File identity, hard links, owner and ACL are checked on the opened
    // handle by admin_platform, never from this pre-open metadata.
    Ok(())
}

pub(super) fn apply_private_open_options(options: &mut OpenOptions) {
    admin_platform::options(options);
}

pub(super) fn check_private_handle(file: &File) -> io::Result<()> {
    admin_platform::check(file)
}

fn private_options(options: &mut OpenOptions) {
    apply_private_open_options(options);
}

fn existing_private(path: &Path) -> io::Result<Option<File>> {
    let before = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if before.file_type().is_symlink() { return Err(denied("Linked administration state refused")); }
    check_private_file(&before)?;
    let mut options = OpenOptions::new();
    options.read(true);
    private_options(&mut options);
    let file = options.open(path)?;
    check_private_file(&file.metadata()?)?;
    admin_platform::check(&file)?;
    Ok(Some(file))
}

fn validate_journal_with<B: ExtBackend>(backend: &B, journal: &Journal) -> io::Result<()> {
    if journal.version != 1 || journal.requests.len() > MAX_REQUESTS
        || journal.controls.len() > 256 || journal.entries.len() > 256
        || journal.oauth_configs.len() > 256
        || journal.oauth_configs.iter().any(|(name, cfg)| !valid_name(name) || cfg.validate().is_err())
        || journal.controls.iter().any(|(name, pin)| {
            !valid_name(name) || !hex_digest(&pin.config_sha256)
        })
        || journal.entries.iter().any(|(name, entry)| {
            !valid_name(name) || match entry {
                ServerEntry::Added { endpoint, grant_nonce, header_env } => {
                    endpoint.len() > 4096 || validate_proposed_endpoint(endpoint).is_err()
                        || !hex_digest(grant_nonce)
                        || validate_header_env(endpoint, header_env, false).is_err()
                }
                ServerEntry::AddedStdio { stdio, grant_nonce } => {
                    agent_bridge_extensions::public_docs_server(name)
                        || !hex_digest(grant_nonce)
                        || backend.validate_stdio_spec(stdio).is_err()
                }
                ServerEntry::Removed { config_sha256 } => !hex_digest(config_sha256),
            }
        })
    {
        return Err(denied("Invalid private extension administration journal"));
    }
    for (id, record) in &journal.requests {
        if !hex_digest(id) || !hex_digest(&record.config_sha256)
            || !hex_digest(&record.control_sha256)
            || record.revision > journal.revision
            || request_id(&record.config_sha256, &record.control_sha256, record.revision, &record.payload) != *id
            || proposal_with(backend, &record.payload).is_err()
            || record.reason.as_deref().is_some_and(|reason| !matches!(
                reason, "operator_refused" | "unsupported_operation"
                    | "server_not_configured" | REASON_EXISTS | REASON_STALE
                    | "remote_refresh_not_implemented" | "outbound_oauth_not_implemented"
                    | "oauth_not_configured" | "oauth_flow_failed"
                    | "unapplied_parameters"
                    | "executable_changed" | "executable_unavailable"
                    | "stdio_transport_unsupported_operation"
            ))
        {
            return Err(denied("Invalid or unbound extension administration record"));
        }
    }
    Ok(())
}

fn load(settings: &Path) -> io::Result<Journal> {
    load_with(&RealBackend, settings)
}

fn load_with<B: ExtBackend>(backend: &B, settings: &Path) -> io::Result<Journal> {
    let Some(mut file) = existing_private(&settings.join(JOURNAL))? else {
        return Ok(Journal::default());
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if bytes.len() > MAX_JOURNAL { return Err(denied("Extension journal too large")); }
    let state: Journal = serde_json::from_slice(&bytes)
        .map_err(|_| denied("Invalid private extension administration journal"))?;
    validate_journal_with(backend, &state)?;
    Ok(state)
}

fn save(settings: &Path, state: &Journal) -> io::Result<()> {
    save_with(&RealBackend, settings, state)
}

fn save_with<B: ExtBackend>(backend: &B, settings: &Path, state: &Journal) -> io::Result<()> {
    validate_journal_with(backend, state)?;
    let bytes = serde_json::to_vec(state).map_err(|_| denied("Cannot encode extension journal"))?;
    if bytes.len() > MAX_JOURNAL { return Err(denied("Extension administration journal full")); }
    let target = settings.join(JOURNAL);
    let _ = existing_private(&target)?;
    let digest = config_sha256(&bytes);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| denied("Clock unavailable for private staging"))?
        .as_nanos();
    let stage = settings.join(format!(
        "{JOURNAL}.pending-{}-{}-{nonce}", &digest[..16], std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    private_options(&mut options);
    let mut file = options.open(&stage)?;
    // Verify the freshly created private HANDLE before any journal bytes.
    if let Err(error) = admin_platform::check(&file) {
        drop(file);
        let _ = fs::remove_file(&stage);
        return Err(error);
    }
    let result = (|| {
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        // The one private lock serializes all of this module's writers.
        fs::rename(&stage, &target)
    })();
    if result.is_err() { let _ = fs::remove_file(&stage); }
    result
}

struct OperatorLock {
    _guard: admin_platform::OsLock,
}
impl OperatorLock {
    fn acquire(settings: &Path) -> io::Result<Self> {
        let path = settings.join(LOCK);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        private_options(&mut options);
        // A persistent private lock inode/file cannot be stolen during a
        // decision; the kernel releases the actual file lock at process exit.
        let file = options.open(&path)?;
        Ok(Self { _guard: admin_platform::OsLock::acquire(file)? })
    }
}

/// Applied on every new admission. Produces one effective Registry from
/// `extensions.json` plus local journal entries and controls, without
/// modifying `extensions.json`.
pub(super) fn apply_local(settings: &Path, base_bytes: &[u8]) -> io::Result<Registry> {
    let journal = load(settings)?;
    apply_journal(base_bytes, &journal)
}

pub(super) fn apply_journal(base_bytes: &[u8], journal: &Journal) -> io::Result<Registry> {
    let effective = effective_registry_bytes(base_bytes, journal)?;
    Registry::parse(&effective)?.with_controls(&journal.controls)
}

pub(super) fn journal_stamp(journal: &Journal) -> io::Result<(u64, String)> {
    Ok((journal.revision, state_hash(journal)?))
}

/// The same OS lock as local decisions. Check the private settings boundary
/// before creating/opening the lock. Parsing the base is deliberately left
/// to the caller so an invalid candidate cannot hide a valid revocation.
pub(super) fn with_current<T>(
    settings: &Path, f: impl FnOnce(&[u8], &Journal) -> io::Result<T>,
) -> io::Result<T> {
    let read = || agent_bridge_lifecycle::read_operator_setting(settings, "extensions.json")
        .map_err(|_| denied("Qualified private operator settings required"));
    let _ = read().map_err(|err| { super::journal_unavailable(settings); err })?;
    let _lock = OperatorLock::acquire(settings)?;
    let bytes = read().map_err(|err| { super::journal_unavailable(settings); err })?;
    let journal = load(settings).map_err(|err| { super::journal_unavailable(settings); err })?;
    f(&bytes, &journal)
}

/// Read the already-committed private journal without acquiring `OperatorLock`
/// (used by attached peers while the operator holds `OperatorLock` waiting for acks).
pub(super) fn read_committed_for_reconcile(settings: &Path) -> io::Result<Journal> {
    let _ = agent_bridge_lifecycle::read_operator_setting(settings, "extensions.json")
        .map_err(|_| denied("Qualified private operator settings required"))?;
    load(settings)
}

/// Web may *only* enqueue. All operation variants, including read-like
/// auth_status, require the same local decision boundary.
pub(super) fn submit(settings: &Path, args: &Map<String, Value>) -> io::Result<Value> {
    if args.contains_key("header_env") { return Err(denied("Header references require the locally selected unified capability")); }
    enqueue(settings, args, Origin::Web)
}

fn enqueue(settings: &Path, args: &Map<String, Value>, origin: Origin) -> io::Result<Value> {
    enqueue_with(&RealBackend, settings, args, origin)
}

fn enqueue_with<B: ExtBackend>(
    backend: &B,
    settings: &Path,
    args: &Map<String, Value>,
    origin: Origin,
) -> io::Result<Value> {
    if origin != Origin::LocalCli
        && args.get("action").and_then(Value::as_str) == Some("add_stdio")
    {
        return Err(denied("Stdio extension proposals require local CLI import"));
    }
    let mut payload = Value::Object(args.clone());
    payload.sort_all_objects();
    let request = proposal_with(backend, &payload)?;
    if matches!(request, Proposal::AddStdio { .. }) && origin != Origin::LocalCli {
        return Err(denied("Stdio extension proposals require local CLI import"));
    }
    validate_actionable_inputs(&request)?;
    let _ = qualified_registry_with(backend, settings)?;
    let _lock = OperatorLock::acquire(settings)?;
    let current = qualified_registry_with(backend, settings)?;
    let config = config_sha256(&current);
    let mut journal = load_with(backend, settings)?;
    if let Proposal::SetOauth { name, oauth: true, .. } = &request {
        let effective = backend.parse_registry(&effective_registry_bytes(&current, &journal)?, None)?;
        if let Some(endpoint) = effective.server_endpoint(name) {
            validate_header_env(endpoint, &BTreeMap::new(), true)?;
        }
    }
    let control = state_hash(&journal)?;
    let revision = journal.revision;
    let id = request_id(&config, &control, revision, &payload);
    let existing = journal.requests.contains_key(&id);
    if !existing {
        if journal.requests.len() >= MAX_REQUESTS {
            return Err(denied("Extension proposal journal full; operator action required"));
        }
        journal.requests.insert(id.clone(), Record {
            config_sha256: config,
            control_sha256: control,
            revision,
            payload,
            status: Decision::Pending,
            reason: None,
            refresh_receipt: None,
        });
        save_with(backend, settings, &journal)?;
    }
    Ok(json!({
        "request_id":id,
        "submission": if existing { "previously_recorded" } else { "queued_for_local_decision" },
        "executed_by_web":false,
        "configuration_changed":false,
        "operator_decision_required":true,
        "support":request.support()
    }))
}

pub(super) fn submit_unified(settings: &Path, args: &Map<String, Value>) -> io::Result<Value> {
    enqueue(settings, args, Origin::Web)
}

#[cfg(all(test, windows))]
mod unified_header_admin_tests {
    use super::*;
    struct Temporary(PathBuf);
    impl Drop for Temporary { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

    #[test]
    fn unified_oauth_try_drain_never_waits_for_a_live_worker_and_joins_completion() {
        let owner = UiOAuthOwner::default();
        let (send, receive) = std::sync::mpsc::channel();
        owner.state.lock().unwrap().worker = Some(std::thread::spawn(move || { receive.recv().unwrap(); }));
        assert!(!owner.try_drain().unwrap());
        assert!(owner.state.lock().unwrap().closing);
        send.send(()).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !owner.state.lock().unwrap().worker.as_ref().unwrap().is_finished() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert!(owner.try_drain().unwrap());
        assert!(owner.state.lock().unwrap().worker.is_none());
        assert!(owner.try_drain().unwrap());
    }

    #[test]
    fn unified_oauth_try_drain_reports_busy_lock_and_preserves_panic_failure() {
        let owner = UiOAuthOwner::default();
        let guard = owner.state.lock().unwrap();
        assert!(!owner.try_drain().unwrap(), "busy state must not block the UI thread");
        drop(guard);
        let worker = std::thread::spawn(|| panic!("fixture worker panic"));
        while !worker.is_finished() { std::thread::yield_now(); }
        owner.state.lock().unwrap().worker = Some(worker);
        assert!(owner.try_drain().is_err());
        assert!(owner.try_drain().is_err(), "failure must survive its first observation");
    }

    #[test]
    fn public_docs_set_oauth_proposals_are_refused_without_local_decision() {
        let root = Temporary(std::env::temp_dir().join(format!("ab-public-oauth-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos())));
        fs::create_dir_all(&root.0).unwrap();
        let settings = root.0.join("settings");
        agent_bridge_lifecycle::initialize_operator_settings(&settings).unwrap();
        // Inert, test-owned registry only. No approvals or OAuth flow occur.
        fs::write(settings.join("extensions.json"), serde_json::to_vec(&json!({"version":1,"servers":{
            "docs_fixture":{"endpoint":"https://modelcontextprotocol.io./mcp","tools":{}},
            "private_fixture":{"endpoint":"https://example.invalid/mcp","tools":{}}
        }})).unwrap()).unwrap();
        let request = json!({"action":"set_oauth","name":"docs_fixture","oauth":true});
        for submitter in [submit, submit_unified] {
            let failure = submitter(&settings, request.as_object().unwrap()).unwrap_err();
            assert_eq!(failure.to_string(), "Public documentation search forbids credentials");
        }
        assert!(load(&settings).unwrap().requests.is_empty());
        let private = json!({"action":"set_oauth","name":"private_fixture","oauth":true});
        let queued = submit_unified(&settings, private.as_object().unwrap()).unwrap();
        assert_eq!(queued["operator_decision_required"], true);
        assert_eq!(queued["configuration_changed"], false);
        assert!(load(&settings).unwrap().oauth_configs.is_empty());
    }

    #[test]
    fn unified_header_proposal_requires_local_decision_and_binds_the_exact_map() {
        let root = Temporary(std::env::temp_dir().join(format!("ab-header-admin-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos())));
        fs::create_dir_all(&root.0).unwrap();
        let settings = root.0.join("settings");
        agent_bridge_lifecycle::initialize_operator_settings(&settings).unwrap();
        let proposal = json!({"action":"add","name":"header_fixture","url":"https://example.invalid/mcp",
            "header_env":{"X-Api-Key":"AGENT_BRIDGE_EXTENSION_HEADER_FIXTURE_A"}});
        assert!(submit(&settings, proposal.as_object().unwrap()).is_err(), "legacy contract must not expand");
        let submitted = submit_unified(&settings, proposal.as_object().unwrap()).expect("unified inert header proposal");
        let base = agent_bridge_lifecycle::read_operator_setting(&settings, "extensions.json").unwrap();
        assert!(!apply_local(&settings, &base).unwrap().has_server("header_fixture"));
        let id = submitted["request_id"].as_str().unwrap();
        let approved = decide_inner(&settings, id, true, false, |_| Ok(())).unwrap();
        assert_eq!(approved["decision"], "approved");
        let journal = load(&settings).unwrap();
        let effective: Value = serde_json::from_slice(&effective_registry_bytes(&base, &journal).unwrap()).unwrap();
        assert_eq!(effective["servers"]["header_fixture"]["header_env"]["X-Api-Key"], "AGENT_BRIDGE_EXTENSION_HEADER_FIXTURE_A");
        assert!(apply_local(&settings, &base).unwrap().list().is_empty(), "adding a server never grants any tools");
        let mut changed = proposal.clone();
        changed["header_env"]["X-Api-Key"] = json!("AGENT_BRIDGE_EXTENSION_HEADER_FIXTURE_B");
        let submitted = submit_unified(&settings, changed.as_object().unwrap()).unwrap();
        let refused = decide_inner(&settings, submitted["request_id"].as_str().unwrap(), true, false, |_| Ok(())).unwrap();
        assert_eq!(refused["decision"], "refused", "changed references cannot be treated as an identical add");
        assert_eq!(refused["reason"], "server_already_exists");
        let mut invalid = proposal;
        invalid["header_env"]["X-Api-Key"] = json!("HOME");
        assert!(submit_unified(&settings, invalid.as_object().unwrap()).is_err());
    }
}

/// Keep the CURRENT finalized decision and its effect together in one
/// atomic journal replacement. Old finalized records may be compacted, but
/// never discard the current receipt to squeeze in an unrecorded effect.
fn persist_decision_with<B: ExtBackend>(
    backend: &B,
    settings: &Path,
    state: &mut Journal,
    ids: &[&str],
) -> io::Result<super::RevocationAckReceipt> {
    let size = |state: &Journal| -> io::Result<usize> {
        Ok(serde_json::to_vec(state)
            .map_err(|_| denied("Cannot encode extension journal"))?.len())
    };
    if !ids.iter().all(|id| state.requests.get(*id).is_some_and(|record| record.status != Decision::Pending)) {
        return Err(denied("Final decision record must be retained"));
    }
    if size(state)? > MAX_JOURNAL {
        state.requests.retain(|key, record|
            ids.contains(&key.as_str()) || record.status == Decision::Pending);
    }
    if size(state)? > MAX_JOURNAL {
        return Err(denied("Private journal full: cannot commit decision and effect atomically"));
    }
    save_with(backend, settings, state)?;
    backend.committed(settings, state)
}

/// While the operator holds the writer lock, all live views must observe the
/// last durable restrictions before a grant or remote action can supersede them.
/// Reading the journal also covers a prior writer that exited before sending IPC.
fn acknowledge_base<B: ExtBackend>(backend: &B, settings: &Path, journal: &Journal) -> io::Result<()> {
    if journal.revision != 0 {
        backend.committed(settings, journal)?;
    }
    Ok(())
}

/// Manual recovery: finished requests only. Pending requests and every
/// server-specific pin survive verbatim. No administration effect occurs here.
fn compact(settings: &Path) -> io::Result<Value> {
    let _lock = OperatorLock::acquire(settings)?;
    let journal = load(settings)?;
    let finalized = journal.requests.values().filter(|r| r.status != Decision::Pending).count();
    if finalized == 0 {
        return Ok(json!({"compacted":0,"pending":journal.requests.len(),
            "server_controls_preserved":journal.controls.len(),
            "local_entries_preserved":journal.entries.len(),"effect_now":"none"}));
    }
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err(denied("Interactive local operator terminal required to compact"));
    }
    eprintln!("Private extension journal: discard {finalized} FINALIZED records only;");
    eprintln!("pending proposals, local server entries, and all disable/enable pins remain unchanged.");
    eprintln!("Type COMPACT to confirm local compaction:");
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    if line.trim_end_matches(['\r', '\n']) != "COMPACT" {
        return Err(denied("Operator refused extension journal compaction"));
    }
    // Requalify even for recovery; no registry change is applied.
    let _ = qualified_registry(settings)?;
    let mut journal = load(settings)?;
    let before = journal.requests.len();
    journal.requests.retain(|_, r| r.status == Decision::Pending);
    let removed = before - journal.requests.len();
    if removed != 0 {
        save(settings, &journal)?;
    }
    Ok(json!({"compacted":removed,"pending":journal.requests.len(),
        "server_controls_preserved":journal.controls.len(),
        "local_entries_preserved":journal.entries.len(),
        "effect_now":"none","executed_network_operation":false}))
}

fn forget_absent(settings: &Path, name: &str) -> io::Result<Value> {
    if !valid_name(name) || !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err(denied("A valid server name and interactive local terminal are required"));
    }
    let _lock = OperatorLock::acquire(settings)?;
    let registry_bytes = qualified_registry(settings)?;
    let mut journal = load(settings)?;
    // Revocation tombstones from remove must NOT be erasable by this legacy
    // recovery action: they are what prevent old base grants from reviving.
    if journal.entries.contains_key(name) {
        return Err(denied("Server generation/revocation is managed by add/remove, not forget-absent"));
    }
    let source: Value = serde_json::from_slice(&registry_bytes)
        .map_err(|_| denied("Invalid private extension registry"))?;
    if source.get("servers").and_then(Value::as_object)
        .is_some_and(|servers| servers.contains_key(name))
    {
        return Err(denied("Remove the server locally before forgetting its control"));
    }
    let pin = journal.controls.get(name)
        .ok_or_else(|| denied("No saved control for this absent server"))?;
    let confirmation = format!("FORGET {name} {}", pin.config_sha256);
    let fingerprint = state_hash(&journal)?;
    eprintln!("Retire the LEGACY saved control for absent server {name}? No revoked server generation will be erased.");
    eprintln!("Type {confirmation} to confirm:");
    let mut answer = String::new();
    io::stdin().lock().take(256).read_line(&mut answer)?;
    if answer.trim_end_matches(['\r','\n']) != confirmation
        || qualified_registry(settings)? != registry_bytes
        || state_hash(&load(settings)?)? != fingerprint
    {
        return Err(denied("Confirmation or server configuration changed"));
    }
    acknowledge_base(&RealBackend, settings, &journal)?;
    journal.controls.remove(name);
    journal.revision = journal.revision.checked_add(1)
        .ok_or_else(|| denied("Decision revision exhausted"))?;
    save(settings, &journal)?;
    let revocation_ack = RealBackend.committed(settings, &journal)?;
    Ok(json!({"forgotten":name,"configuration_changed":false,
        "executed_network_operation":false,"revocation_ack":revocation_ack}))
}

fn confirm_locally(verb: &str, id: &str, record: &Record) -> io::Result<()> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err(denied("Interactive operator terminal required for a decision"));
    }
    eprintln!("PRIVATE extension request {id}:");
    eprintln!("{}", serde_json::to_string_pretty(record)
        .map_err(|_| denied("Cannot display extension request"))?);
    eprintln!("Type exactly '{verb} {id}' in this local terminal to confirm:");
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    if line.trim_end_matches(['\r', '\n']) != format!("{verb} {id}") {
        return Err(denied("Local operator confirmation did not match"));
    }
    Ok(())
}

fn decide(settings: &Path, id: &str, approve: bool) -> io::Result<Value> {
    decide_inner(settings, id, approve, true, |auth_url| {
        eprintln!("Open this OAuth authorization URL in your browser to complete authorization:");
        eprintln!("{auth_url}");
        Ok(())
    })
}

fn server_stdio_spec<'a, R: ParsedRegistryView>(
    registry: &'a R,
    journal: &'a Journal,
    name: &str,
) -> Option<&'a StdioSpec> {
    if !registry.has_server(name) {
        return None;
    }
    registry.server_stdio(name).or_else(|| match journal.entries.get(name) {
        Some(ServerEntry::AddedStdio { stdio, .. }) => Some(stdio),
        _ => None,
    })
}

fn decide_inner<F>(
    settings: &Path,
    id: &str,
    approve: bool,
    require_tty_confirm: bool,
    open_auth_url: F,
) -> io::Result<Value>
where
    F: FnOnce(&str) -> io::Result<()>,
{
    decide_inner_with(&RealBackend, settings, id, approve, require_tty_confirm, open_auth_url)
}

fn decide_inner_with<B, F>(
    backend: &B,
    settings: &Path,
    id: &str,
    approve: bool,
    require_tty_confirm: bool,
    open_auth_url: F,
) -> io::Result<Value>
where
    B: ExtBackend,
    F: FnOnce(&str) -> io::Result<()>,
{
    if !hex_digest(id) { return Err(denied("Expected exact 64-character request id")); }
    let _ = qualified_registry_with(backend, settings)?;
    let _lock = OperatorLock::acquire(settings)?;
    let mut journal = load_with(backend, settings)?;
    let record = journal.requests.get(id).ok_or_else(|| denied("Unknown local proposal"))?;
    if record.status != Decision::Pending {
        let revocation_ack = backend.committed(settings, &journal)?;
        let mut answer = json!({"request_id":id,"decision":record.status,
            "effect_now":"none","reason":record.reason,"already_decided":true,
            "revocation_ack":revocation_ack});
        if let Some(receipt) = &record.refresh_receipt {
            answer["refresh"] = receipt.clone();
            answer["remote_refreshed"] = json!(receipt.get("remote_refreshed")
                .and_then(Value::as_bool).unwrap_or(false));
        }
        return Ok(answer);
    }
    if require_tty_confirm {
        confirm_locally(if approve { "APPROVE" } else { "REFUSE" }, id, record)?;
    }

    // Everything below is behind the private operator OS lock. A proposal
    // binds both exact base settings bytes and the journal revision/state.
    let current = qualified_registry_with(backend, settings)?;
    journal = load_with(backend, settings)?;
    if journal.requests.get(id).is_none_or(|r| r.status != Decision::Pending) {
        return Err(denied("Extension request changed during local confirmation"));
    }
    let _ = backend.parse_registry(&effective_registry_bytes(&current, &journal)?, Some(&journal.controls))?;
    let (config, state, revision, payload) = {
        let r = journal.requests.get(id).ok_or_else(||denied("Unknown local proposal"))?;
        (r.config_sha256.clone(), r.control_sha256.clone(), r.revision, r.payload.clone())
    };
    let Applied { status, reason, effect, authentication, oauth_receipt, refresh_receipt } = if !approve {
        Applied::refused("operator_refused")
    } else if config != config_sha256(&current)
        || state != state_hash(&journal)?
        || revision != journal.revision
    {
        Applied::refused(REASON_STALE)
    } else {
        let proposal = proposal_with(backend, &payload)?;
        if proposal.requires_acknowledged_base() {
            acknowledge_base(backend, settings, &journal)?;
        }
        apply_approved(backend, settings, &current, &mut journal, id, revision, proposal, open_auth_url)?
    };
    let record = journal.requests.get_mut(id).ok_or_else(|| denied("Unknown local proposal"))?;
    record.status = status;
    record.reason = reason.map(str::to_owned);
    record.refresh_receipt = refresh_receipt.clone();
    journal.revision = journal.revision.checked_add(1)
        .ok_or_else(|| denied("Operator decision revision exhausted"))?;
    // The decision and its effective registry change are one durable journal
    // replacement. A failed write cannot acknowledge the operator's approval.
    let revocation_ack = persist_decision_with(backend, settings, &mut journal, &[id])?;
    let mut response = json!({
        "request_id":id,
        "decision_recorded":true,
        "decision":status,
        "effect_now":effect,
        "reason":reason,
        "revocation_ack":revocation_ack,
        "executed_network_operation":refresh_receipt.is_some() || oauth_receipt.is_some(),
        "remote_refreshed":refresh_receipt.is_some(),
        "outbound_oauth_executed":oauth_receipt.is_some()
    });
    if let Some(local_auth) = authentication {
        response["auth_status"] = local_auth;
    }
    if let Some(oauth_info) = oauth_receipt {
        response["oauth"] = oauth_info;
    }
    if let Some(report) = refresh_receipt {
        response["refresh"] = report;
    }
    if let Some(handoff) = grant_handoff(&journal, &payload, effect) {
        response["local_grant_handoff"] = handoff;
    }
    Ok(response)
}

fn grant_handoff(journal: &Journal, payload: &Value, effect: &str) -> Option<Value> {
    if !matches!(effect, "added_without_tools" | "added_stdio_without_tools") {
        return None;
    }
    let name = payload.get("name").and_then(Value::as_str)?;
    match journal.entries.get(name)? {
        // Only the local operator receives the handoff marker. A
        // Web request cannot supply this state or grant any tool.
        ServerEntry::Added { grant_nonce, .. } | ServerEntry::AddedStdio { grant_nonce, .. } => Some(json!({
            "server": name,
            "private_setting": "extensions.json",
            "bridge_grant_nonce": grant_nonce,
            "tools_approved": 0,
            "manual_tool_approval_required": true,
            "new_enable_approval_after_tool_edit_required": true
        })),
        _ => None,
    }
}

/// The outcome of one approved proposal, before it is recorded.
struct Applied {
    status: Decision,
    reason: Option<&'static str>,
    effect: &'static str,
    authentication: Option<Value>,
    oauth_receipt: Option<Value>,
    refresh_receipt: Option<Value>,
}

impl Applied {
    fn refused(reason: &'static str) -> Self {
        Self { status: Decision::Refused, reason: Some(reason), effect: "none",
            authentication: None, oauth_receipt: None, refresh_receipt: None }
    }
}

/// Applies one proposal whose binding the caller has already checked, under
/// the operator lock. The journal is changed in memory only.
#[allow(clippy::too_many_arguments)]
fn apply_approved<B, F>(
    backend: &B,
    settings: &Path,
    current: &[u8],
    journal: &mut Journal,
    id: &str,
    revision: u64,
    proposal: Proposal,
    open_auth_url: F,
) -> io::Result<Applied>
where
    B: ExtBackend,
    F: FnOnce(&str) -> io::Result<()>,
{
    let effective_bytes = effective_registry_bytes(current, journal)?;
    let registry = backend.parse_registry(&effective_bytes, Some(&journal.controls))?;
    let mut effect = "none";
    let mut authentication = None;
    let mut oauth_receipt: Option<Value> = None;
    let mut refresh_receipt: Option<Value> = None;
    let (status, reason) = match proposal {
        Proposal::Add { description: Some(_), .. } =>
            (Decision::Unsupported, Some("unapplied_parameters")),
        Proposal::Add {
            name, url, header_env, enabled, oauth, oauth_scope, oauth_client_id,
            oauth_client_auth_method, oauth_client_secret_env, ..
        } => {
            let desired_enabled = enabled.unwrap_or(true);
            if registry.has_server(&name) {
                // Retrying the same add does not change its generation.
                let same_added = matches!(journal.entries.get(&name),
                    Some(ServerEntry::Added { endpoint, header_env:current_headers, .. })
                        if endpoint == &url && current_headers == &header_env);
                let current_enabled = journal.controls.get(&name)
                    .is_some_and(|control| control.enabled);
                if same_added && current_enabled == desired_enabled {
                    effect = "already_in_requested_state";
                    (Decision::Approved, None)
                } else {
                    (Decision::Refused, Some(REASON_EXISTS))
                }
            } else {
                if (!journal.entries.contains_key(&name) && journal.entries.len() >= 256)
                    || (!journal.controls.contains_key(&name) && journal.controls.len() >= 256)
                {
                    return Err(denied("Local extension definition limit reached"));
                }
                // Each approved creation has its own fingerprint, even
                // when a removed name and endpoint are later reused.
                let grant_nonce = config_sha256(
                    format!("agent-bridge/server-grant/v1/{id}/{revision}").as_bytes(),
                );
                journal.entries.insert(name.clone(), ServerEntry::Added {
                    endpoint: url, grant_nonce, header_env,
                });
                if let Some(oauth_enabled) = oauth {
                    let cfg = OAuthServerConfig {
                        enabled: oauth_enabled,
                        scope: oauth_scope,
                        client_id: oauth_client_id,
                        client_auth_method: oauth_client_auth_method,
                        client_secret_env: oauth_client_secret_env,
                    };
                    cfg.validate()?;
                    journal.oauth_configs.insert(name.clone(), cfg);
                }
                let updated_bytes = effective_registry_bytes(&current, &journal)?;
                let updated = backend.parse_registry(&updated_bytes, None)?;
                let server_hash = updated.server_sha256(&name)?
                    .ok_or_else(|| denied("Cannot pin added extension"))?;
                journal.controls.insert(name, ServerControl {
                    enabled: desired_enabled,
                    config_sha256: server_hash,
                });
                let _ = backend.parse_registry(&updated_bytes, Some(&journal.controls))?;
                effect = "added_without_tools";
                (Decision::Approved, None)
            }
        }
        Proposal::AddStdio {
            name, executable, executable_sha256, args, env, cwd, enabled, inherit_path, ..
        } => {
            let desired_enabled = enabled.unwrap_or(true);
            let spec = StdioSpec {
                executable,
                executable_sha256,
                args,
                env,
                cwd,
                inherit_path,
            };
            if registry.has_server(&name) {
                let same_added = matches!(journal.entries.get(&name),
                    Some(ServerEntry::AddedStdio { stdio, .. }) if stdio == &spec);
                let current_enabled = journal.controls.get(&name)
                    .is_some_and(|control| control.enabled);
                if same_added && current_enabled == desired_enabled {
                    effect = "already_in_requested_state";
                    (Decision::Approved, None)
                } else {
                    (Decision::Refused, Some(REASON_EXISTS))
                }
            } else {
                if (!journal.entries.contains_key(&name) && journal.entries.len() >= 256)
                    || (!journal.controls.contains_key(&name) && journal.controls.len() >= 256)
                {
                    return Err(denied("Local extension definition limit reached"));
                }
                // Approval verifies the pinned executable hash and never spawns.
                match backend.verify_executable(Path::new(&spec.executable), &spec.executable_sha256) {
                    Err(VerifyError::Changed) => (Decision::Refused, Some("executable_changed")),
                    Err(VerifyError::Unavailable) => (Decision::Refused, Some("executable_unavailable")),
                    Ok(()) => {
                        let grant_nonce = config_sha256(
                            format!("agent-bridge/server-grant/v1/{id}/{revision}").as_bytes(),
                        );
                        journal.oauth_configs.remove(&name);
                        journal.entries.insert(name.clone(), ServerEntry::AddedStdio {
                            stdio: spec,
                            grant_nonce,
                        });
                        let updated_bytes = effective_registry_bytes(&current, &journal)?;
                        let updated = backend.parse_registry(&updated_bytes, None)?;
                        let server_hash = updated.server_sha256(&name)?
                            .ok_or_else(|| denied("Cannot pin added stdio extension"))?;
                        journal.controls.insert(name, ServerControl {
                            enabled: desired_enabled,
                            config_sha256: server_hash,
                        });
                        let _ = backend.parse_registry(&updated_bytes, Some(&journal.controls))?;
                        effect = "added_stdio_without_tools";
                        (Decision::Approved, None)
                    }
                }
            }
        }
        Proposal::Remove { name } => {
            if let Some(fingerprint) = registry.server_sha256(&name)? {
                if !journal.entries.contains_key(&name) && journal.entries.len() >= 256 {
                    return Err(denied("Local extension definition limit reached"));
                }
                journal.controls.remove(&name);
                journal.oauth_configs.remove(&name);
                let _ = OAuthTokenStore::delete_token(settings, &name);
                // Always keep a tombstone, even if this server originated
                // solely in the local journal. No old base tool can revive.
                journal.entries.insert(name, ServerEntry::Removed {
                    config_sha256: fingerprint,
                });
                let updated = effective_registry_bytes(&current, &journal)?;
                let _ = backend.parse_registry(&updated, Some(&journal.controls))?;
                effect = "removed_and_revoked";
                (Decision::Approved, None)
            } else if matches!(journal.entries.get(&name), Some(ServerEntry::Removed { .. })) {
                effect = "already_in_requested_state";
                (Decision::Approved, None)
            } else {
                (Decision::Unsupported, Some("server_not_configured"))
            }
        }
        // Explicit operator approval permits one remote, read-only
        // tools/list comparison for an exact public documentation
        // endpoint. No returned descriptor is installed or granted.
        Proposal::Refresh { name, timeout_ms } => {
            if timeout_ms.is_some() {
                (Decision::Unsupported, Some("unapplied_parameters"))
            } else if server_stdio_spec(&registry, &journal, &name).is_some() {
                (Decision::Unsupported, Some("stdio_transport_unsupported_operation"))
            } else if !agent_bridge_extensions::public_docs_server(&name) {
                (Decision::Unsupported, Some("remote_refresh_not_implemented"))
            } else if !registry.has_server(&name) {
                (Decision::Unsupported, Some("server_not_configured"))
            } else {
                let report = registry.refresh_public_docs(&name)?;
                // A concurrently replaced settings file must not be
                // accepted after the remote observation was produced.
                if qualified_registry_with(backend, settings)? != current {
                    return Err(denied("Extension settings changed during remote refresh"));
                }
                refresh_receipt = Some(report);
                effect = "remote_catalog_observed_no_grants_changed";
                (Decision::Approved, None)
            }
        }
        Proposal::AuthStatus { name } => {
            // Offline, local-only status combining server controls,
            // non-secret OAuth config, and DPAPI token store presence.
            let token_status = if registry.has_server(&name) {
                Some(OAuthTokenStore::load_status(settings, &name)?)
            } else {
                None
            };
            authentication = registry.auth_status_with_oauth(
                &name,
                journal.controls.get(&name),
                journal.oauth_configs.get(&name),
                token_status.as_ref(),
            )?;
            if authentication.is_some() {
                (Decision::Approved, None)
            } else {
                (Decision::Unsupported, Some("server_not_configured"))
            }
        }
        Proposal::SetOauth {
            name, oauth, oauth_scope, oauth_client_id,
            oauth_client_auth_method, oauth_client_secret_env,
        } => {
            if !registry.has_server(&name) {
                (Decision::Unsupported, Some("server_not_configured"))
            } else if server_stdio_spec(&registry, &journal, &name).is_some() {
                (Decision::Unsupported, Some("stdio_transport_unsupported_operation"))
            } else if !oauth {
                journal.oauth_configs.remove(&name);
                let _ = OAuthTokenStore::delete_token(settings, &name)?;
                effect = "oauth_disabled";
                (Decision::Approved, None)
            } else {
                // Recheck at local decision even for a previously queued proposal.
                let endpoint = registry.server_endpoint(&name)
                    .ok_or_else(|| denied("Extension server is no longer configured"))?;
                validate_header_env(endpoint, &BTreeMap::new(), true)?;
                if registry.header_authorization_configured(&name) {
                    return Err(denied("An explicit Authorization header conflicts with outbound OAuth"));
                }
                if !journal.oauth_configs.contains_key(&name) && journal.oauth_configs.len() >= 256 {
                    return Err(denied("Local extension OAuth configuration limit reached"));
                }
                let cfg = OAuthServerConfig {
                    enabled: true,
                    scope: oauth_scope,
                    client_id: oauth_client_id,
                    client_auth_method: oauth_client_auth_method,
                    client_secret_env: oauth_client_secret_env,
                };
                cfg.validate()?;
                journal.oauth_configs.insert(name, cfg);
                effect = "oauth_configured";
                (Decision::Approved, None)
            }
        }
        Proposal::AuthStart { name, force } => {
            if !registry.has_server(&name) {
                (Decision::Unsupported, Some("server_not_configured"))
            } else if server_stdio_spec(&registry, &journal, &name).is_some() {
                (Decision::Unsupported, Some("stdio_transport_unsupported_operation"))
            } else if let Some(endpoint) = registry.server_endpoint(&name) {
                if let Some(cfg) = journal.oauth_configs.get(&name).filter(|c| c.enabled) {
                    match oauth::run_oauth_flow(
                        settings,
                        &name,
                        endpoint,
                        cfg,
                        force.unwrap_or(false),
                        open_auth_url,
                    ) {
                        Ok(receipt) => {
                            oauth_receipt = Some(receipt);
                            effect = "oauth_authorized";
                            (Decision::Approved, None)
                        }
                        Err(_) => (Decision::Refused, Some("oauth_flow_failed")),
                    }
                } else {
                    (Decision::Refused, Some("oauth_not_configured"))
                }
            } else {
                (Decision::Unsupported, Some("server_not_configured"))
            }
        }
        Proposal::AuthDisconnect { name } => {
            if !registry.has_server(&name) {
                (Decision::Unsupported, Some("server_not_configured"))
            } else {
                let removed = OAuthTokenStore::delete_token(settings, &name)?;
                effect = if removed { "oauth_disconnected" } else { "already_disconnected" };
                (Decision::Approved, None)
            }
        }
        Proposal::Enable { name } => {
            if let Some(server_hash) = registry.server_sha256(&name)? {
                if let Some(spec) = server_stdio_spec(&registry, &journal, &name) {
                    if backend.verify_executable(Path::new(&spec.executable), &spec.executable_sha256).is_err() {
                        // Fail closed with executable_changed before pinning.
                        (Decision::Refused, Some("executable_changed"))
                    } else {
                        let pin = ServerControl { enabled: true, config_sha256: server_hash };
                        let prior = journal.controls.insert(name, pin.clone());
                        effect = if prior.as_ref() == Some(&pin) {
                            "already_in_requested_state"
                        } else { "enabled_and_pinned" };
                        (Decision::Approved, None)
                    }
                } else {
                    let pin = ServerControl { enabled: true, config_sha256: server_hash };
                    let prior = journal.controls.insert(name, pin.clone());
                    effect = if prior.as_ref() == Some(&pin) {
                        "already_in_requested_state"
                    } else { "enabled_and_pinned" };
                    (Decision::Approved, None)
                }
            } else {
                (Decision::Unsupported, Some("server_not_configured"))
            }
        }
        Proposal::Disable { name } => {
            if let Some(server_hash) = registry.server_sha256(&name)? {
                let pin = ServerControl { enabled: false, config_sha256: server_hash };
                let prior = journal.controls.insert(name, pin.clone());
                effect = if prior.as_ref() == Some(&pin) {
                    "already_in_requested_state"
                } else { "disabled_and_pinned" };
                (Decision::Approved, None)
            } else {
                (Decision::Unsupported, Some("server_not_configured"))
            }
        }
    };
    Ok(Applied { status, reason, effect, authentication, oauth_receipt, refresh_receipt })
}

const MAX_BATCH: usize = 64;

/// Approves the pending add proposals of one import together. An import
/// queues every proposal at the same journal revision, so one decision makes
/// the others stale. The batch checks that binding once, applies each member
/// in order under one lock and commits one journal replacement. It is all or
/// nothing: an error, or a member that would not be approved, leaves the
/// journal unchanged.
fn decide_batch_with<B: ExtBackend>(
    backend: &B,
    settings: &Path,
    ids: &[&str],
    require_tty_confirm: bool,
) -> io::Result<Value> {
    let distinct: BTreeSet<&str> = ids.iter().copied().collect();
    if ids.len() < 2 || ids.len() > MAX_BATCH || distinct.len() != ids.len()
        || !ids.iter().all(|id| hex_digest(id))
    {
        return Err(denied("Expected 2 to 64 distinct 64-character request ids"));
    }
    let _ = qualified_registry_with(backend, settings)?;
    let _lock = OperatorLock::acquire(settings)?;
    let members = |journal: &Journal| -> io::Result<Vec<(String, String, u64, Value)>> {
        let mut names = BTreeSet::new();
        ids.iter().map(|id| {
            let record = journal.requests.get(*id).ok_or_else(|| denied("Unknown local proposal"))?;
            if record.status != Decision::Pending {
                return Err(denied("Batch approval accepts only pending proposals"));
            }
            let name = match proposal_with(backend, &record.payload)? {
                Proposal::Add { name, .. } | Proposal::AddStdio { name, .. } => name,
                _ => return Err(denied("Batch approval accepts only add proposals")),
            };
            // Two proposals for one server would let the order decide.
            if !names.insert(name) {
                return Err(denied("Batch approval accepts one proposal per server"));
            }
            Ok((record.config_sha256.clone(), record.control_sha256.clone(),
                record.revision, record.payload.clone()))
        }).collect()
    };
    if require_tty_confirm {
        let journal = load_with(backend, settings)?;
        let _ = members(&journal)?;
        let records: Vec<&Record> = ids.iter().filter_map(|id| journal.requests.get(*id)).collect();
        confirm_batch_locally(ids, &records)?;
    }

    let current = qualified_registry_with(backend, settings)?;
    let mut journal = load_with(backend, settings)?;
    let records = members(&journal)?;
    let _ = backend.parse_registry(&effective_registry_bytes(&current, &journal)?, Some(&journal.controls))?;
    let state = state_hash(&journal)?;
    let config = config_sha256(&current);
    if records.iter().any(|(c, s, r, _)| c != &config || s != &state || *r != journal.revision) {
        return Err(denied("A proposal of this batch is stale; import again and approve the new proposals"));
    }
    let revision = journal.revision;
    acknowledge_base(backend, settings, &journal)?;
    let mut decisions = Vec::new();
    for (id, (_, _, _, payload)) in ids.iter().zip(&records) {
        let proposal = proposal_with(backend, payload)?;
        let applied = apply_approved(backend, settings, &current, &mut journal, id, revision, proposal,
            |_| Err(denied("A batch approval never starts an OAuth flow")))?;
        if applied.status != Decision::Approved {
            let name = payload.get("name").and_then(Value::as_str).unwrap_or_default();
            return Err(io::Error::other(format!("Batch not recorded: {name} would be {} ({}); approve the others separately",
                serde_json::to_value(applied.status).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default(),
                applied.reason.unwrap_or("none"))));
        }
        let record = journal.requests.get_mut(*id).ok_or_else(|| denied("Unknown local proposal"))?;
        record.status = applied.status;
        record.reason = applied.reason.map(str::to_owned);
        let mut item = json!({"request_id": id, "decision": applied.status,
            "effect_now": applied.effect, "reason": applied.reason});
        if let Some(handoff) = grant_handoff(&journal, payload, applied.effect) {
            item["local_grant_handoff"] = handoff;
        }
        decisions.push(item);
    }
    journal.revision = journal.revision.checked_add(1)
        .ok_or_else(|| denied("Operator decision revision exhausted"))?;
    let revocation_ack = persist_decision_with(backend, settings, &mut journal, ids)?;
    Ok(json!({"decision_recorded": true, "decisions": decisions,
        "revocation_ack": revocation_ack,
        "executed_network_operation": false}))
}

fn confirm_batch_locally(ids: &[&str], records: &[&Record]) -> io::Result<()> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err(denied("Interactive operator terminal required for a decision"));
    }
    for (id, record) in ids.iter().zip(records) {
        eprintln!("PRIVATE extension request {id}:");
        eprintln!("{}", serde_json::to_string_pretty(record)
            .map_err(|_| denied("Cannot display extension request"))?);
    }
    let digest = config_sha256(ids.join("\n").as_bytes());
    let expected = format!("APPROVE {} {digest}", ids.len());
    eprintln!("Type exactly '{expected}' in this local terminal to approve these {} requests:", ids.len());
    let mut line = String::new();
    io::stdin().lock().take(256).read_line(&mut line)?;
    if line.trim_end_matches(['\r', '\n']) != expected {
        return Err(denied("Local operator confirmation did not match"));
    }
    Ok(())
}

pub(super) fn approve_batch(settings: &Path, ids: &[&str]) -> io::Result<Value> {
    let _ = qualified_registry(settings)?;
    decide_batch_with(&RealBackend, settings, ids, true)
}

pub(super) fn ui_overview(owner: &UiOAuthOwner, settings: &Path) -> io::Result<Value> {
    ui_overview_with(&RealBackend, owner, settings)
}

fn ui_overview_with<B: ExtBackend>(backend: &B, owner: &UiOAuthOwner, settings: &Path) -> io::Result<Value> {
    let base_bytes = qualified_registry_with(backend, settings)?;
    let journal = load_with(backend, settings)?;
    let effective = effective_registry_bytes(&base_bytes, &journal)?;
    let registry = backend.parse_registry(&effective, Some(&journal.controls))?;
    let mut servers = registry.servers_overview()?;
    if let Some(items) = servers.get_mut("servers").and_then(Value::as_array_mut) {
        for server in items {
            let id = server.get("id").and_then(Value::as_str);
            let endpoint = id.and_then(|id| registry.server_endpoint(id));
            let stdio = id.and_then(|id| server_stdio_spec(&registry, &journal, id));
            let config_sha256 = id.and_then(|id| registry.server_sha256(id).ok().flatten());
            server["transport"] = json!(if stdio.is_some() { "stdio" } else { "http" });
            server["endpoint"] = json!(endpoint);
            server["executable"] = json!(stdio.map(|s| s.executable.as_str()));
            server["executable_sha256"] = json!(stdio.map(|s| s.executable_sha256.as_str()));
            server["config_sha256"] = json!(config_sha256);
        }
    }
    let mut oauth_summary = Map::new();
    for (name, cfg) in &journal.oauth_configs {
        let token_meta = OAuthTokenStore::load_status(settings, name).ok();
        oauth_summary.insert(name.clone(), json!({
            "enabled": cfg.enabled,
            "scope": cfg.scope,
            "client_id": cfg.client_id,
            "client_auth_method": cfg.client_auth_method,
            "has_client_secret_env": cfg.client_secret_env.is_some(),
            "token_status": token_meta,
        }));
    }
    let requests: Vec<Value> = journal.requests.iter().map(|(id, r)| json!({
        "request_id": id,
        "action": r.payload["action"],
        "name": r.payload["name"],
        "payload": r.payload,
        "config_sha256": r.config_sha256,
        "control_sha256": r.control_sha256,
        "revision": r.revision,
        "decision": r.status,
        "reason": r.reason,
        "refresh_receipt": r.refresh_receipt,
    })).collect();
    let pending_count = journal.requests.values().filter(|r| r.status == Decision::Pending).count();
    Ok(json!({
        "journal_revision": journal.revision,
        "pending_count": pending_count,
        "total_requests": requests.len(),
        "approved_tools": registry.approved_tools_list(),
        "servers": servers.get("servers").cloned().unwrap_or_else(|| json!([])),
        "server_controls": journal.controls,
        "local_entries": journal.entries,
        "outbound_oauth": oauth_summary,
        "oauth_operation": ui_oauth_operation(owner, settings),
        "requests": requests,
    }))
}

// One owner-only, in-memory operation per UI generation. The durable journal
// remains the authority for decisions; accepting a job grants nothing.
struct UiOAuthOperation {
    settings: PathBuf,
    request_id: String,
    status: &'static str,
    auth_url: Option<String>,
    result: Option<Value>,
    error: Option<&'static str>,
}

impl UiOAuthOperation {
    fn active(&self) -> bool {
        matches!(self.status, "starting" | "awaiting_authorization")
    }

    fn snapshot(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "status": self.status,
            "auth_url": self.auth_url,
            "result": self.result,
            "error": self.error,
            "callback_timeout_seconds": 120,
        })
    }
}

#[derive(Clone, Default)]
pub(crate) struct UiOAuthOwner {
    state: std::sync::Arc<Mutex<UiOAuthState>>,
}
#[derive(Default)]
struct UiOAuthState {
    closing: bool,
    operation: Option<UiOAuthOperation>,
    worker: Option<std::thread::JoinHandle<()>>,
    join_failed: bool,
}
impl UiOAuthOwner {
    pub(crate) fn try_drain(&self) -> io::Result<bool> {
        let mut guard = match self.state.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(false),
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(denied("OAuth worker state is unavailable")),
        };
        guard.closing = true;
        if guard.join_failed { return Err(denied("OAuth worker cleanup could not be confirmed")); }
        if guard.worker.as_ref().is_some_and(|worker| worker.is_finished()) {
            if guard.worker.take().expect("observed completed worker").join().is_err() {
                guard.join_failed = true;
                return Err(denied("OAuth worker cleanup could not be confirmed"));
            }
        }
        Ok(guard.worker.is_none())
    }

    pub(crate) fn close_admission(&self) {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).closing = true;
    }

    // A callback already in progress keeps its existing bounded deadline.
    // Cancellation of the caller drops only this wait, never the worker handle.
    pub(crate) async fn drain(&self) -> io::Result<()> {
        loop {
            if self.try_drain()? { return Ok(()); }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}

fn ui_oauth_operation(owner: &UiOAuthOwner, settings: &Path) -> Option<Value> {
    let guard = owner.state.lock().unwrap_or_else(|p| p.into_inner());
    guard.operation.as_ref().filter(|op| op.settings == settings).map(UiOAuthOperation::snapshot)
}

fn existing_ui_oauth_operation(owner: &UiOAuthOwner, settings: &Path, id: &str, approve: bool) -> io::Result<Option<Value>> {
    let guard = owner.state.lock().unwrap_or_else(|p| p.into_inner());
    if guard.closing { return Err(denied("Operator generation is stopping")); }
    if let Some(op) = guard.operation.as_ref() {
        if approve && op.settings == settings && op.request_id == id {
            return Ok(Some(json!({"oauth_operation": op.snapshot()})));
        }
        if op.active() {
            return Err(io::Error::new(io::ErrorKind::WouldBlock,
                "An OAuth authorization is already running. Inspect its result before another decision."));
        }
    }
    Ok(None)
}

fn finish_ui_oauth_operation(owner: &UiOAuthOwner, settings: &Path, id: &str, result: Result<Value, &'static str>) {
    let mut guard = owner.state.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(op) = guard.operation.as_mut().filter(|op| op.settings == settings && op.request_id == id) {
        op.auth_url = None;
        match result {
            Ok(value) => {
                op.status = "completed";
                op.result = Some(value);
            }
            Err(message) => {
                op.status = "failed";
                op.error = Some(message);
            }
        }
    }
}

fn start_ui_oauth_operation(owner: &UiOAuthOwner, settings: &Path, id: &str) -> io::Result<Value> {
    // Admission, operation state and the actual thread handle are published
    // under one mutex. Stop cannot miss a worker between admission and 202.
    let mut guard = owner.state.lock().unwrap_or_else(|p| p.into_inner());
    if guard.closing || guard.join_failed { return Err(denied("Operator generation is stopping")); }
    if let Some(op) = guard.operation.as_ref() {
        if op.settings == settings && op.request_id == id {
            return Ok(json!({"oauth_operation": op.snapshot()}));
        }
        if op.active() {
            return Err(io::Error::new(io::ErrorKind::WouldBlock,
                "An OAuth authorization is already running. Inspect its result before another decision."));
        }
    }
    if let Some(worker) = guard.worker.as_ref() {
        if !worker.is_finished() {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "Previous OAuth worker is still finishing"));
        }
        if guard.worker.take().expect("observed worker").join().is_err() {
            guard.join_failed = true;
            return Err(denied("OAuth worker cleanup could not be confirmed"));
        }
    }
    let op = UiOAuthOperation {
        settings: settings.to_owned(), request_id: id.to_owned(),
        status: "starting", auth_url: None, result: None, error: None,
    };
    let receipt = json!({"oauth_operation": op.snapshot()});
    guard.operation = Some(op);
    let worker_settings = settings.to_owned();
    let worker_id = id.to_owned();
    let worker_owner = owner.clone();
    let spawned = std::thread::Builder::new().name("operator-ui-oauth".into()).spawn(move || {
        // Preserve decide_inner's OS lock, stale checks and atomic journal
        // decision. Its HTTP requests and callback wait already have deadlines.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            decide_inner(&worker_settings, &worker_id, true, false, |url| {
                let mut guard = worker_owner.state.lock().unwrap_or_else(|p| p.into_inner());
                if guard.closing { return Err(denied("Operator generation is stopping")); }
                let op = guard.operation.as_mut()
                    .filter(|op| op.settings == worker_settings && op.request_id == worker_id)
                    .ok_or_else(|| denied("OAuth operation is no longer available"))?;
                op.auth_url = Some(url.to_owned());
                op.status = "awaiting_authorization";
                Ok(())
            })
        }));
        let result = match outcome {
            Ok(Ok(receipt)) => Ok(receipt),
            Ok(Err(_)) => Err("OAuth decision could not be confirmed. Inspect local state before retrying."),
            Err(_) => Err("OAuth worker stopped unexpectedly. Inspect local state before retrying."),
        };
        finish_ui_oauth_operation(&worker_owner, &worker_settings, &worker_id, result);
    });
    match spawned {
        Ok(worker) => guard.worker = Some(worker),
        Err(_) => {
            if let Some(op) = guard.operation.as_mut() {
                op.status = "failed";
                op.error = Some("Could not start the OAuth authorization worker.");
            }
            return Err(denied("Could not start the OAuth authorization worker"));
        }
    }
    Ok(receipt)
}

pub(super) fn decide_from_operator_ui(owner: &UiOAuthOwner, settings: &Path, id: &str, approve: bool) -> io::Result<Value> {
    if !hex_digest(id) { return Err(denied("Expected exact 64-character request id")); }
    let _ = qualified_registry(settings)?;
    if let Some(receipt) = existing_ui_oauth_operation(owner, settings, id, approve)? {
        return Ok(receipt);
    }
    let journal = load(settings)?;
    let record = journal.requests.get(id).ok_or_else(|| denied("Unknown local proposal"))?;
    if approve && record.status == Decision::Pending
        && matches!(proposal_with(&RealBackend, &record.payload)?, Proposal::AuthStart { .. })
    {
        return start_ui_oauth_operation(owner, settings, id);
    }
    decide_inner(settings, id, approve, false, |_| {
        Err(denied("OAuth authorization requires an asynchronous operator operation"))
    })
}

pub(super) fn import(settings: &Path, mcp_json: &Path, inherit_path: &BTreeSet<String>) -> io::Result<Value> {
    let _ = qualified_registry(settings)?;
    import::run(settings, mcp_json, inherit_path)
}

pub(super) fn local(settings: &Path, action: &str, id: Option<&str>) -> io::Result<Value> {
    let _ = qualified_registry(settings)?;
    match (action, id) {
        ("compact", None) => compact(settings),
        ("requests", None) => {
            let journal = load(settings)?;
            let requests: Vec<Value> = journal.requests.iter().map(|(id,r)| json!({
                "request_id":id,"action":r.payload["action"],"name":r.payload["name"],
                "config_sha256":r.config_sha256,"control_sha256":r.control_sha256,
                "revision":r.revision,
                "decision":r.status,"reason":r.reason
            })).collect();
            Ok(json!({"requests":requests,"server_controls":journal.controls,
                "local_entries":journal.entries,"count":requests.len()}))
        }
        ("request", Some(id)) if hex_digest(id) => {
            let journal = load(settings)?;
            let record = journal.requests.get(id).ok_or_else(|| denied("Unknown local proposal"))?;
            Ok(json!({"request_id":id,"proposal":record}))
        }
        ("approve", Some(id)) => decide(settings, id, true),
        ("refuse", Some(id)) => decide(settings, id, false),
        ("forget-absent", Some(name)) => forget_absent(settings, name),
        ("import", Some(path)) => import::run(settings, Path::new(path), &BTreeSet::new()),
        _ => Err(denied("Expected extensions requests|request|approve|refuse|compact|forget-absent|import and exact request id")),
    }
}


#[cfg(all(test, windows))]
mod oauth_admin_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
    use std::thread;

    #[test]
    fn admin_set_oauth_auth_status_auth_start_and_disconnect_lifecycle() {
        let root = std::env::temp_dir().join(format!("ab-admin-oauth-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let settings = root.join("settings");
        agent_bridge_lifecycle::initialize_operator_settings(&settings).expect("init settings");

        // Start mock loopback OAuth 2.1 server
        let listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .expect("bind mock oauth");
        let port = listener.local_addr().unwrap().port();
        let base = format!("{}://{}:{port}", "http", "127.0.0.1");
        let endpoint = format!("{base}/mcp");
        let base_srv = base.clone();

        let srv = thread::spawn(move || {
            for _ in 0..4 {
                let Ok((mut s, _)) = listener.accept() else { break };
                let mut buf = [0u8; 8192];
                let Ok(n) = s.read(&mut buf) else { continue };
                let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                let path = req.lines().next().unwrap_or("").split_whitespace().nth(1).unwrap_or("");
                if path == "/.well-known/oauth-protected-resource" {
                    let body = json!({"authorization_servers": [base_srv]}).to_string();
                    let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
                } else if path == "/.well-known/oauth-authorization-server" {
                    let body = json!({
                        "authorization_endpoint": format!("{base_srv}/authorize"),
                        "token_endpoint": format!("{base_srv}/token"),
                        "code_challenge_methods_supported": ["S256"]
                    }).to_string();
                    let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
                } else if path == "/token" {
                    let body = json!({"access_token": "adm_tok_987", "refresh_token": "adm_ref_654", "expires_in": 3600}).to_string();
                    let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
                    break;
                }
            }
        });

        let submit_and_approve = |args: Value| -> Value {
            let sub = submit(&settings, args.as_object().unwrap()).expect("submit");
            let id = sub["request_id"].as_str().unwrap().to_owned();
            decide_inner(&settings, &id, true, false, |_| Ok(())).expect("decide_inner")
        };

        // 1. Add server
        let r_add = submit_and_approve(json!({"action": "add", "name": "local_oauth_srv", "url": endpoint}));
        assert_eq!(r_add["decision"], "approved");

        // 2. auth_start before set_oauth fails closed with oauth_not_configured
        let r_early = submit_and_approve(json!({"action": "auth_start", "name": "local_oauth_srv"}));
        assert_eq!(r_early["decision"], "refused");
        assert_eq!(r_early["reason"], "oauth_not_configured");

        // 3. set_oauth enables PKCE client config
        let r_set = submit_and_approve(json!({
            "action": "set_oauth",
            "name": "local_oauth_srv",
            "oauth": true,
            "oauth_client_id": "cli-test",
            "oauth_scope": "read",
            "oauth_client_auth_method": "none"
        }));
        assert_eq!(r_set["decision"], "approved");
        assert_eq!(r_set["effect_now"], "oauth_configured");

        // 4. auth_status before auth_start shows oauth_configured=true, token_stored=false
        let r_st1 = submit_and_approve(json!({"action": "auth_status", "name": "local_oauth_srv"}));
        assert_eq!(r_st1["auth_status"]["oauth_configured"], true);
        assert_eq!(r_st1["auth_status"]["token_stored"], false);

        // 5. auth_start executes real loopback PKCE flow and stores DPAPI token
        let sub_start = submit(&settings, json!({"action": "auth_start", "name": "local_oauth_srv"}).as_object().unwrap()).unwrap();
        let id_start = sub_start["request_id"].as_str().unwrap().to_owned();
        let r_start = decide_inner(&settings, &id_start, true, false, |auth_url| {
            let q = auth_url.split_once('?').unwrap().1;
            let mut redir = String::new();
            let mut state = String::new();
            for pair in q.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    let dec = v.replace("%3A", ":").replace("%2F", "/");
                    if k == "redirect_uri" { redir = dec; } else if k == "state" { state = dec; }
                }
            }
            let cb_port: u16 = redir.split("://").nth(1).unwrap().split('/').next().unwrap().split(':').nth(1).unwrap().parse().unwrap();
            thread::spawn(move || {
                let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, cb_port)).unwrap();
                let req = format!("GET /callback?code=ok_code&state={state} HTTP/1.1\r\nHost: 127.0.0.1:{cb_port}\r\nConnection: close\r\n\r\n");
                let _ = s.write_all(req.as_bytes());
                let mut sink = [0u8; 256];
                let _ = s.read(&mut sink);
            });
            Ok(())
        }).expect("auth_start approve");
        let _ = srv.join();
        assert_eq!(r_start["decision"], "approved");
        assert_eq!(r_start["effect_now"], "oauth_authorized");
        assert_eq!(r_start["outbound_oauth_executed"], true);
        assert_eq!(r_start["oauth"]["token_stored"], true);

        // Journal itself MUST NOT contain any token string
        let journal_raw = fs::read_to_string(settings.join(JOURNAL)).unwrap();
        assert!(!journal_raw.contains("adm_tok_987"));
        assert!(!journal_raw.contains("adm_ref_654"));

        // 6. auth_status now reflects token_stored=true
        let r_st2 = submit_and_approve(json!({"action": "auth_status", "name": "local_oauth_srv"}));
        assert_eq!(r_st2["auth_status"]["token_stored"], true);
        assert_eq!(r_st2["auth_status"]["has_refresh_token"], true);

        // 7. auth_disconnect removes DPAPI token idempotently
        let r_disc1 = submit_and_approve(json!({"action": "auth_disconnect", "name": "local_oauth_srv"}));
        assert_eq!(r_disc1["decision"], "approved");
        assert_eq!(r_disc1["effect_now"], "oauth_disconnected");

        let r_st3 = submit_and_approve(json!({"action": "auth_status", "name": "local_oauth_srv"}));
        assert_eq!(r_st3["auth_status"]["token_stored"], false);

        let _ = fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod stdio_admin_tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::Component;
    use std::sync::atomic::{AtomicU64, Ordering};

    static STDIO_TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);
    impl TestDir {
        fn new(label: &str) -> Self {
            let n = STDIO_TEST_SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = crate::test_state_base().join(format!(
                "ab-stdio-admin-{label}-{}-{n}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(dir)
        }

        fn settings(&self) -> PathBuf {
            let s = self.0.join("settings");
            if !s.exists() {
                agent_bridge_lifecycle::initialize_operator_settings(&s).unwrap();
            }
            s
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Writes an inert native binary header (never spawned) so hash and native
    /// magic checks inspect real file bytes on disk without circular mocks.
    pub(super) fn native_fixture_executable(dir: &Path, stem: &str) -> PathBuf {
        #[cfg(windows)]
        {
            let path = dir.join(format!("{stem}.exe"));
            let mut image = vec![0u8; 256];
            image[0..2].copy_from_slice(b"MZ");
            image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
            image[0x80..0x84].copy_from_slice(b"PE\0\0");
            // COFF FileHeader (20 bytes at 0x84): SizeOfOptionalHeader = 0x70 at 0x94.
            image[0x94..0x96].copy_from_slice(&0x70u16.to_le_bytes());
            // OptionalHeader PE32+ magic 0x020b at 0x98, Subsystem = 3 (CUI) at 0x98 + 0x44 = 0xdc.
            image[0x98..0x9a].copy_from_slice(&0x020bu16.to_le_bytes());
            image[0xdc..0xde].copy_from_slice(&3u16.to_le_bytes());
            image.extend_from_slice(stem.as_bytes());
            fs::write(&path, &image).unwrap();
            path
        }
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = dir.join(stem);
            let mut image = vec![0u8; 64];
            image[0..4].copy_from_slice(b"\x7fELF");
            image.extend_from_slice(stem.as_bytes());
            fs::write(&path, &image).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            path
        }
    }

    fn is_native_executable_bytes(path: &Path, bytes: &[u8]) -> bool {
        if bytes.starts_with(b"#!") || bytes.len() > 512 * 1024 * 1024 {
            return false;
        }
        #[cfg(windows)]
        {
            if !path
                .to_str()
                .is_some_and(|s| s.to_ascii_lowercase().ends_with(".exe"))
            {
                return false;
            }
            if bytes.len() < 0xdf || &bytes[0..2] != b"MZ" {
                return false;
            }
            let pe_off = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
            if bytes.len() < pe_off + 24 + 0x46 || &bytes[pe_off..pe_off + 4] != b"PE\0\0" {
                return false;
            }
            let opt = pe_off + 24;
            let magic = u16::from_le_bytes(bytes[opt..opt + 2].try_into().unwrap());
            let sub_off = match magic {
                0x010b | 0x020b => opt + 0x44,
                _ => return false,
            };
            bytes.len() >= sub_off + 2
                && u16::from_le_bytes(bytes[sub_off..sub_off + 2].try_into().unwrap()) == 3
        }
        #[cfg(not(windows))]
        {
            let _ = path;
            bytes.starts_with(b"\x7fELF")
                || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
                || bytes.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
                || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
                || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        }
    }

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct StdioServerRecord {
        stdio: StdioSpec,
        tools: BTreeMap<String, Value>,
    }

    pub(super) struct TestRegistry {
        http: Registry,
        stdio_servers: BTreeMap<String, (StdioSpec, BTreeMap<String, Value>, String, bool)>,
    }

    impl ParsedRegistryView for TestRegistry {
        fn has_server(&self, name: &str) -> bool {
            self.http.has_server(name) || self.stdio_servers.contains_key(name)
        }
        fn server_endpoint(&self, name: &str) -> Option<&str> {
            self.http.server_endpoint(name)
        }
        fn server_stdio(&self, name: &str) -> Option<&StdioSpec> {
            self.stdio_servers.get(name).map(|(spec, _, _, _)| spec)
        }
        fn header_authorization_configured(&self, name: &str) -> bool {
            self.http.header_authorization_configured(name)
        }
        fn server_sha256(&self, name: &str) -> io::Result<Option<String>> {
            if let Some((_, _, sha, _)) = self.stdio_servers.get(name) {
                return Ok(Some(sha.clone()));
            }
            self.http.server_sha256(name)
        }
        fn refresh_public_docs(&self, name: &str) -> io::Result<Value> {
            self.http.refresh_public_docs(name)
        }
        fn auth_status_with_oauth(
            &self,
            name: &str,
            control: Option<&ServerControl>,
            oauth_cfg: Option<&OAuthServerConfig>,
            token_status: Option<&oauth::TokenStatusSummary>,
        ) -> io::Result<Option<Value>> {
            if let Some((_, _, sha, disabled)) = self.stdio_servers.get(name) {
                let local_control = match control {
                    None => "no_local_decision",
                    Some(pin) if &pin.config_sha256 != sha => "configuration_changed",
                    Some(pin) if !pin.enabled => "disabled",
                    Some(_) if *disabled => "not_applied",
                    Some(_) => "enabled",
                };
                return Ok(Some(json!({
                    "server": name,
                    "bearer_reference_configured": false,
                    "local_control": local_control,
                    "oauth_configured": oauth_cfg.is_some_and(|c| c.enabled),
                    "token_stored": token_status.is_some_and(|s| s.token_stored),
                    "remote_oauth_state": "unknown",
                })));
            }
            self.http
                .auth_status_with_oauth(name, control, oauth_cfg, token_status)
        }
        fn servers_overview(&self) -> io::Result<Value> {
            let mut base = self.http.servers(None)?;
            let mut merged: BTreeMap<String, Value> = base["servers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| (item["id"].as_str().unwrap().to_owned(), item.clone()))
                .collect();
            for (id, (_, tools, _, disabled)) in &self.stdio_servers {
                merged.insert(
                    id.clone(),
                    json!({
                        "id": id,
                        "enabled": !disabled,
                        "tools": tools.keys().collect::<Vec<_>>(),
                    }),
                );
            }
            let items: Vec<Value> = merged.into_values().collect();
            base["count"] = json!(items.len());
            base["servers"] = json!(items);
            Ok(base)
        }
        fn approved_tools_list(&self) -> Vec<String> {
            let mut out = self.http.list();
            for (server, (_, tools, _, disabled)) in &self.stdio_servers {
                if !disabled {
                    for tool in tools.keys() {
                        out.push(format!("{server}:{tool}"));
                    }
                }
            }
            out.sort();
            out
        }
    }

    #[derive(Default)]
    pub(super) struct TestBackend;

    impl ExtBackend for TestBackend {
        type Reg = TestRegistry;

        fn validate_stdio_spec(&self, spec: &StdioSpec) -> io::Result<()> {
            let valid_path = |raw: &str, require_exe: bool| -> bool {
                if raw.is_empty()
                    || raw.len() > 1024
                    || raw.contains('\0')
                    || raw.starts_with("\\\\")
                {
                    return false;
                }
                let p = Path::new(raw);
                if !p.is_absolute()
                    || p.components()
                        .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
                {
                    return false;
                }
                #[cfg(windows)]
                if require_exe && !raw.to_ascii_lowercase().ends_with(".exe") {
                    return false;
                }
                let _ = require_exe;
                true
            };
            if !valid_path(&spec.executable, true)
                || !hex_digest(&spec.executable_sha256)
                || spec.args.len() > 64
                || spec.args.iter().any(|a| a.len() > 4096 || a.contains('\0'))
                || spec.args.iter().map(String::len).sum::<usize>() > 16 * 1024
                || spec.env.len() > 32
                || spec.cwd.as_deref().is_some_and(|c| !valid_path(c, false))
            {
                return Err(denied("Invalid stdio spec"));
            }
            let mut seen_ci = BTreeSet::new();
            for (k, v) in &spec.env {
                if !import::is_allowed_child_env_name(k)
                    || !valid_secret_env_name(v)
                    || !seen_ci.insert(k.to_ascii_uppercase())
                {
                    return Err(denied("Invalid stdio env mapping"));
                }
            }
            Ok(())
        }

        fn valid_child_env_name(&self, name: &str) -> bool {
            import::is_allowed_child_env_name(name)
        }

        fn observe_executable(&self, path: &Path) -> io::Result<String> {
            let meta = fs::symlink_metadata(path)?;
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(denied("Non-regular executable"));
            }
            let bytes = fs::read(path)?;
            if !is_native_executable_bytes(path, &bytes) {
                return Err(denied("Non-native executable"));
            }
            Ok(config_sha256(&bytes))
        }

        fn verify_executable(
            &self,
            path: &Path,
            expected_sha256: &str,
        ) -> Result<(), VerifyError> {
            let actual = self
                .observe_executable(path)
                .map_err(|_| VerifyError::Unavailable)?;
            if actual != expected_sha256 {
                return Err(VerifyError::Changed);
            }
            Ok(())
        }

        fn parse_registry(
            &self,
            effective_bytes: &[u8],
            controls: Option<&BTreeMap<String, ServerControl>>,
        ) -> io::Result<Self::Reg> {
            let mut root: Value = serde_json::from_slice(effective_bytes)
                .map_err(|_| denied("Invalid extension registry"))?;
            let servers = root
                .get_mut("servers")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| denied("Invalid extension registry"))?;
            let mut stdio_raw = BTreeMap::new();
            let names: Vec<String> = servers
                .iter()
                .filter(|(_, v)| v.as_object().is_some_and(|o| o.contains_key("stdio")))
                .map(|(k, _)| k.clone())
                .collect();
            for name in names {
                let val = servers.remove(&name).unwrap();
                stdio_raw.insert(name, val);
            }
            let http_bytes =
                serde_json::to_vec(&root).map_err(|_| denied("Invalid extension registry"))?;
            let mut http = Registry::parse(&http_bytes)?;
            if let Some(ctrls) = controls {
                http = http.with_controls(ctrls)?;
            }
            let mut stdio_servers = BTreeMap::new();
            for (name, val) in stdio_raw {
                if !valid_name(&name) || agent_bridge_extensions::public_docs_server(&name) {
                    return Err(denied("Invalid stdio server name"));
                }
                let parsed: StdioServerRecord = serde_json::from_value(val)
                    .map_err(|_| denied("Invalid stdio server entry"))?;
                self.validate_stdio_spec(&parsed.stdio)?;
                let mut canonical = serde_json::to_value(&parsed)
                    .map_err(|_| denied("Cannot fingerprint stdio server"))?;
                canonical.sort_all_objects();
                let sha = config_sha256(canonical.to_string().as_bytes());
                // Default-deny: stdio without an enabled matching control stays disabled.
                let enabled = controls
                    .and_then(|c| c.get(&name))
                    .is_some_and(|pin| pin.enabled && pin.config_sha256 == sha);
                stdio_servers.insert(name, (parsed.stdio, parsed.tools, sha, !enabled));
            }
            Ok(TestRegistry {
                http,
                stdio_servers,
            })
        }
    }

    #[test]
    fn add_stdio_is_refused_from_web_submit_paths() {
        let dir = TestDir::new("web-refuse");
        let settings = dir.settings();
        let exe = native_fixture_executable(&dir.0, "web-refused");
        let sha = TestBackend.observe_executable(&exe).unwrap();
        let payload = json!({
            "action": "add_stdio",
            "name": "stdio_srv",
            "executable": exe.to_str().unwrap(),
            "executable_sha256": sha,
            "args": ["--stdio"],
            "env": {"EXAMPLE_TOKEN": "AGENT_BRIDGE_EXTENSION_STDIO_SRV_EXAMPLE_TOKEN"}
        });
        let map = payload.as_object().unwrap();

        for web_submit in [submit, submit_unified] {
            let err = web_submit(&settings, map).unwrap_err();
            assert!(err.to_string().contains("local CLI import"));
        }
        assert!(enqueue_with(&TestBackend, &settings, map, Origin::Web).is_err());
        assert!(load_with(&TestBackend, &settings).unwrap().requests.is_empty());

        let queued = enqueue_with(&TestBackend, &settings, map, Origin::LocalCli).unwrap();
        assert_eq!(queued["submission"], "queued_for_local_decision");
        assert_eq!(queued["support"], "local_stdio_registry_overlay_after_approval");
        assert_eq!(queued["configuration_changed"], false);
        assert_eq!(queued["operator_decision_required"], true);
    }

    #[test]
    fn add_stdio_approval_verifies_hash_grants_no_tools_and_never_spawns() {
        let dir = TestDir::new("approve-stdio");
        let settings = dir.settings();
        let exe = native_fixture_executable(&dir.0, "pinned-stdio");
        let backend = TestBackend;
        let original_sha = backend.observe_executable(&exe).unwrap();

        // The real backend refuses the synthetic Windows image, which is not
        // a loadable console image. The Unix fixture is an owner-only ELF
        // image that it verifies, and a different pin is a change.
        #[cfg(windows)]
        assert_eq!(
            RealBackend.verify_executable(&exe, &original_sha),
            Err(VerifyError::Unavailable)
        );
        #[cfg(not(windows))]
        {
            assert_eq!(RealBackend.verify_executable(&exe, &original_sha), Ok(()));
            assert_eq!(RealBackend.verify_executable(&exe, &"0".repeat(64)), Err(VerifyError::Changed));
        }

        let make_proposal = |name: &str, path: &Path, sha: &str, args: Vec<&str>| -> Value {
            json!({
                "action": "add_stdio",
                "name": name,
                "executable": path.to_str().unwrap(),
                "executable_sha256": sha,
                "args": args,
                "env": {"EXAMPLE_TOKEN": "AGENT_BRIDGE_EXTENSION_EXAMPLE_EXAMPLE_TOKEN"}
            })
        };

        // 1. Missing executable refuses with executable_unavailable.
        let missing = dir.0.join(if cfg!(windows) { "absent.exe" } else { "absent" });
        let q_missing = enqueue_with(
            &backend,
            &settings,
            make_proposal("missing_srv", &missing, &original_sha, vec![]).as_object().unwrap(),
            Origin::LocalCli,
        )
        .unwrap();
        let r_missing = decide_inner_with(
            &backend,
            &settings,
            q_missing["request_id"].as_str().unwrap(),
            true,
            false,
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(r_missing["decision"], "refused");
        assert_eq!(r_missing["reason"], "executable_unavailable");
        assert!(load_with(&backend, &settings).unwrap().entries.is_empty());

        // 2. Modified executable refuses with executable_changed.
        let wrong_sha = "0".repeat(64);
        let q_changed = enqueue_with(
            &backend,
            &settings,
            make_proposal("changed_srv", &exe, &wrong_sha, vec![]).as_object().unwrap(),
            Origin::LocalCli,
        )
        .unwrap();
        let r_changed = decide_inner_with(
            &backend,
            &settings,
            q_changed["request_id"].as_str().unwrap(),
            true,
            false,
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(r_changed["decision"], "refused");
        assert_eq!(r_changed["reason"], "executable_changed");
        assert!(load_with(&backend, &settings).unwrap().entries.is_empty());

        // 3. Matching hash approves with nonce, zero tools, and never spawns.
        let q_ok = enqueue_with(
            &backend,
            &settings,
            make_proposal("example", &exe, &original_sha, vec!["stdio"]).as_object().unwrap(),
            Origin::LocalCli,
        )
        .unwrap();
        let r_ok = decide_inner_with(
            &backend,
            &settings,
            q_ok["request_id"].as_str().unwrap(),
            true,
            false,
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(r_ok["decision"], "approved");
        assert_eq!(r_ok["effect_now"], "added_stdio_without_tools");
        assert_eq!(r_ok["executed_network_operation"], false);
        assert_eq!(r_ok["local_grant_handoff"]["tools_approved"], 0);
        let nonce = r_ok["local_grant_handoff"]["bridge_grant_nonce"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(hex_digest(&nonce));

        let overview = ui_overview_with(&backend, &UiOAuthOwner::default(), &settings).unwrap();
        assert!(overview["approved_tools"].as_array().unwrap().is_empty());
        let srv = &overview["servers"][0];
        assert_eq!(srv["id"], "example");
        assert_eq!(srv["transport"], "stdio");
        assert!(srv["endpoint"].is_null());
        assert_eq!(srv["executable"], exe.to_str().unwrap());
        assert_eq!(srv["executable_sha256"], original_sha);

        // 4. Identical re-add is idempotent; altered args for same name refuses server_already_exists.
        let q_same = enqueue_with(
            &backend,
            &settings,
            make_proposal("example", &exe, &original_sha, vec!["stdio"]).as_object().unwrap(),
            Origin::LocalCli,
        )
        .unwrap();
        let r_same = decide_inner_with(
            &backend,
            &settings,
            q_same["request_id"].as_str().unwrap(),
            true,
            false,
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(r_same["decision"], "approved");
        assert_eq!(r_same["effect_now"], "already_in_requested_state");

        let q_diff = enqueue_with(
            &backend,
            &settings,
            make_proposal("example", &exe, &original_sha, vec!["other"]).as_object().unwrap(),
            Origin::LocalCli,
        )
        .unwrap();
        let r_diff = decide_inner_with(
            &backend,
            &settings,
            q_diff["request_id"].as_str().unwrap(),
            true,
            false,
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(r_diff["decision"], "refused");
        assert_eq!(r_diff["reason"], "server_already_exists");
    }

    #[test]
    fn base_registry_stdio_without_journal_or_with_extra_fields_refused() {
        let dir = TestDir::new("base-refuse");
        let exe = native_fixture_executable(&dir.0, "base-stdio");
        let sha = TestBackend.observe_executable(&exe).unwrap();
        let spec = StdioSpec {
            executable: exe.to_str().unwrap().to_owned(),
            executable_sha256: sha,
            args: Vec::new(),
            env: BTreeMap::new(),
            cwd: None,
            inherit_path: false,
        };

        // 1. Base extensions.json with stdio and empty journal is refused before early return.
        let unbound_base = serde_json::to_vec(&json!({
            "version": 1,
            "servers": {
                "rogue": {
                    "stdio": &spec,
                    "tools": {}
                }
            }
        }))
        .unwrap();
        assert!(effective_registry_bytes(&unbound_base, &Journal::default()).is_err());

        // 2. Nonce-bound journal entry still refuses stdio or extra fields in base grant.
        let nonce = "a".repeat(64);
        let mut journal = Journal::default();
        journal.entries.insert(
            "bound_srv".into(),
            ServerEntry::AddedStdio {
                stdio: spec.clone(),
                grant_nonce: nonce.clone(),
            },
        );
        for invalid_base in [
            json!({"version": 1, "servers": {"bound_srv": {"stdio": &spec, "tools": {}}}}),
            json!({"version": 1, "servers": {"bound_srv": {"bridge_grant_nonce": &nonce, "stdio": &spec, "tools": {}}}}),
            json!({"version": 1, "servers": {"bound_srv": {"bridge_grant_nonce": &nonce, "endpoint": "https://example.invalid/mcp", "tools": {}}}}),
            json!({"version": 1, "servers": {"bound_srv": {"bridge_grant_nonce": &nonce, "tools": {}, "extra": true}}}),
            json!({"version": 1, "servers": {"bound_srv": {"bridge_grant_nonce": &nonce, "tools": "not_an_object"}}}),
        ] {
            let bytes = serde_json::to_vec(&invalid_base).unwrap();
            assert!(
                effective_registry_bytes(&bytes, &journal).is_err(),
                "expected refusal for base: {invalid_base}"
            );
        }

        // 3. Exact bridge_grant_nonce + tools object is accepted and marker is stripped.
        let valid_grant = serde_json::to_vec(&json!({
            "version": 1,
            "servers": {
                "bound_srv": {
                    "bridge_grant_nonce": &nonce,
                    "tools": {
                        "search_items": {
                            "descriptor_sha256": "b".repeat(64),
                            "parameters": {"query": {"type": "search_terms"}}
                        }
                    }
                }
            }
        }))
        .unwrap();
        let out: Value = serde_json::from_slice(
            &effective_registry_bytes(&valid_grant, &journal).unwrap(),
        )
        .unwrap();
        assert!(out["servers"]["bound_srv"].get("bridge_grant_nonce").is_none());
        assert!(out["servers"]["bound_srv"]["stdio"].is_object());
        assert!(out["servers"]["bound_srv"]["tools"]["search_items"].is_object());
    }

    #[test]
    fn remove_readd_stdio_rotates_nonce() {
        let dir = TestDir::new("rotate-nonce");
        let settings = dir.settings();
        let backend = TestBackend;
        let exe = native_fixture_executable(&dir.0, "rotatable");
        let sha = backend.observe_executable(&exe).unwrap();
        let add_payload = json!({
            "action": "add_stdio",
            "name": "rot_srv",
            "executable": exe.to_str().unwrap(),
            "executable_sha256": sha,
            "args": []
        });

        let q1 = enqueue_with(&backend, &settings, add_payload.as_object().unwrap(), Origin::LocalCli).unwrap();
        let r1 = decide_inner_with(&backend, &settings, q1["request_id"].as_str().unwrap(), true, false, |_| Ok(())).unwrap();
        let nonce_1 = r1["local_grant_handoff"]["bridge_grant_nonce"].as_str().unwrap().to_owned();

        // Author tool grant in extensions.json bound to nonce_1.
        crate::write_private(
            settings.join("extensions.json"),
            serde_json::to_vec(&json!({
                "version": 1,
                "servers": {
                    "rot_srv": {
                        "bridge_grant_nonce": &nonce_1,
                        "tools": {
                            "search_items": {
                                "descriptor_sha256": "c".repeat(64),
                                "parameters": {"query": {"type": "search_terms"}}
                            }
                        }
                    }
                }
            }))
            .unwrap(),
        );

        // Remove server: tombstone hides it.
        let q_rem = enqueue_with(
            &backend,
            &settings,
            json!({"action": "remove", "name": "rot_srv"}).as_object().unwrap(),
            Origin::Web,
        )
        .unwrap();
        let r_rem = decide_inner_with(&backend, &settings, q_rem["request_id"].as_str().unwrap(), true, false, |_| Ok(())).unwrap();
        assert_eq!(r_rem["effect_now"], "removed_and_revoked");

        // Re-add server: nonce rotates and old nonce_1 grant stays dormant.
        let q2 = enqueue_with(&backend, &settings, add_payload.as_object().unwrap(), Origin::LocalCli).unwrap();
        let r2 = decide_inner_with(&backend, &settings, q2["request_id"].as_str().unwrap(), true, false, |_| Ok(())).unwrap();
        let nonce_2 = r2["local_grant_handoff"]["bridge_grant_nonce"].as_str().unwrap().to_owned();
        assert_ne!(nonce_1, nonce_2);

        let base = fs::read(settings.join("extensions.json")).unwrap();
        let journal = load_with(&backend, &settings).unwrap();
        let effective: Value = serde_json::from_slice(&effective_registry_bytes(&base, &journal).unwrap()).unwrap();
        assert_eq!(effective["servers"]["rot_srv"]["tools"], json!({}));
    }

    #[test]
    fn enable_stdio_reverifies_executable() {
        let dir = TestDir::new("enable-reverify");
        let settings = dir.settings();
        let backend = TestBackend;
        let exe = native_fixture_executable(&dir.0, "reverify-bin");
        let original_bytes = fs::read(&exe).unwrap();
        let sha = backend.observe_executable(&exe).unwrap();

        let q_add = enqueue_with(
            &backend,
            &settings,
            json!({
                "action": "add_stdio",
                "name": "rev_srv",
                "executable": exe.to_str().unwrap(),
                "executable_sha256": sha,
                "args": []
            })
            .as_object()
            .unwrap(),
            Origin::LocalCli,
        )
        .unwrap();
        let r_add = decide_inner_with(&backend, &settings, q_add["request_id"].as_str().unwrap(), true, false, |_| Ok(())).unwrap();
        assert_eq!(r_add["decision"], "approved");

        // Disable first, then tamper with the executable on disk.
        let q_dis = enqueue_with(
            &backend,
            &settings,
            json!({"action": "disable", "name": "rev_srv"}).as_object().unwrap(),
            Origin::Web,
        )
        .unwrap();
        let r_dis = decide_inner_with(&backend, &settings, q_dis["request_id"].as_str().unwrap(), true, false, |_| Ok(())).unwrap();
        assert_eq!(r_dis["effect_now"], "disabled_and_pinned");

        let mut tampered = original_bytes.clone();
        tampered.push(0x90);
        fs::write(&exe, &tampered).unwrap();

        let q_en_bad = enqueue_with(
            &backend,
            &settings,
            json!({"action": "enable", "name": "rev_srv"}).as_object().unwrap(),
            Origin::Web,
        )
        .unwrap();
        let r_en_bad = decide_inner_with(&backend, &settings, q_en_bad["request_id"].as_str().unwrap(), true, false, |_| Ok(())).unwrap();
        assert_eq!(r_en_bad["decision"], "refused");
        assert_eq!(r_en_bad["reason"], "executable_changed");
        assert!(!load_with(&backend, &settings).unwrap().controls["rev_srv"].enabled);

        // Restore original pinned bytes; enable now succeeds.
        fs::write(&exe, &original_bytes).unwrap();
        let q_en_ok = enqueue_with(
            &backend,
            &settings,
            json!({"action": "enable", "name": "rev_srv"}).as_object().unwrap(),
            Origin::Web,
        )
        .unwrap();
        let r_en_ok = decide_inner_with(&backend, &settings, q_en_ok["request_id"].as_str().unwrap(), true, false, |_| Ok(())).unwrap();
        assert_eq!(r_en_ok["decision"], "approved");
        assert_eq!(r_en_ok["effect_now"], "enabled_and_pinned");
        assert!(load_with(&backend, &settings).unwrap().controls["rev_srv"].enabled);
    }

    #[test]
    fn stdio_oauth_and_refresh_proposals_unsupported() {
        let dir = TestDir::new("stdio-unsupported");
        let settings = dir.settings();
        let backend = TestBackend;
        let exe = native_fixture_executable(&dir.0, "no-oauth");
        let sha = backend.observe_executable(&exe).unwrap();

        let q_add = enqueue_with(
            &backend,
            &settings,
            json!({
                "action": "add_stdio",
                "name": "stdio_only",
                "executable": exe.to_str().unwrap(),
                "executable_sha256": sha,
                "args": []
            })
            .as_object()
            .unwrap(),
            Origin::LocalCli,
        )
        .unwrap();
        decide_inner_with(&backend, &settings, q_add["request_id"].as_str().unwrap(), true, false, |_| Ok(())).unwrap();

        for proposal_json in [
            json!({"action": "set_oauth", "name": "stdio_only", "oauth": true, "oauth_client_id": "cid"}),
            json!({"action": "set_oauth", "name": "stdio_only", "oauth": false}),
            json!({"action": "auth_start", "name": "stdio_only"}),
            json!({"action": "refresh", "name": "stdio_only"}),
        ] {
            let queued = enqueue_with(&backend, &settings, proposal_json.as_object().unwrap(), Origin::Web).unwrap();
            let decided = decide_inner_with(
                &backend,
                &settings,
                queued["request_id"].as_str().unwrap(),
                true,
                false,
                |_| panic!("OAuth browser callback must never start for stdio"),
            )
            .unwrap();
            assert_eq!(decided["decision"], "unsupported", "for {proposal_json}");
            assert_eq!(decided["reason"], "stdio_transport_unsupported_operation");
        }
    }

    #[test]
    fn new_reasons_survive_journal_validation() {
        let dir = TestDir::new("reason-allowlist");
        let settings = dir.settings();
        let base = qualified_registry(&settings).unwrap();
        let cfg_hash = config_sha256(&base);

        for (idx, reason) in [
            "executable_changed",
            "executable_unavailable",
            "stdio_transport_unsupported_operation",
        ]
        .into_iter()
        .enumerate()
        {
            let mut journal = load(&settings).unwrap();
            journal.revision = (idx + 1) as u64;
            let ctrl_hash = state_hash(&journal).unwrap();
            let mut payload = json!({"action": "enable", "name": format!("srv_{idx}")});
            payload.sort_all_objects();
            let id = request_id(&cfg_hash, &ctrl_hash, journal.revision, &payload);
            journal.requests.insert(
                id,
                Record {
                    config_sha256: cfg_hash.clone(),
                    control_sha256: ctrl_hash,
                    revision: journal.revision,
                    payload,
                    status: Decision::Refused,
                    reason: Some(reason.to_owned()),
                    refresh_receipt: None,
                },
            );
            save(&settings, &journal).expect("new allowlisted reason must save");
            let reloaded = load(&settings).expect("new allowlisted reason must reload");
            assert_eq!(reloaded.requests.len(), idx + 1);
        }

        // Unknown reason string must still fail journal validation.
        let mut bad = load(&settings).unwrap();
        bad.revision += 1;
        let ctrl_hash = state_hash(&bad).unwrap();
        let mut payload = json!({"action": "enable", "name": "srv_bad"});
        payload.sort_all_objects();
        let id = request_id(&cfg_hash, &ctrl_hash, bad.revision, &payload);
        bad.requests.insert(
            id,
            Record {
                config_sha256: cfg_hash,
                control_sha256: ctrl_hash,
                revision: bad.revision,
                payload,
                status: Decision::Refused,
                reason: Some("unlisted_custom_reason".into()),
                refresh_receipt: None,
            },
        );
        assert!(save(&settings, &bad).is_err());
    }
}
