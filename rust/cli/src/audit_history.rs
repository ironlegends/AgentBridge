//! Owner-private bounded durable history for audited MCP, OAuth, and lifecycle events.

use crate::capability_manifest::audit_tool_name;
use agent_bridge_missions::ActivityAttribution;
use agent_bridge_lifecycle::{private_store, LifecycleError};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering as CmpOrdering;
use std::collections::{BinaryHeap, HashMap};
use std::fmt;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};

mod retention;
use retention::{retain_segments, SegmentAge};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) const SCHEMA_VERSION: u32 = 1;
pub(crate) const DEFAULT_QUEUE_CAPACITY: usize = 1024;
pub(crate) const DEFAULT_MAX_SEGMENT_BYTES: u64 = 1024 * 1024;
pub(crate) const DEFAULT_MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const DEFAULT_MAX_SEGMENTS: usize = 32;
pub(crate) const DEFAULT_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
pub(crate) const DEFAULT_QUERY_LIMIT: usize = 200;
pub(crate) const MAX_QUERY_LIMIT: usize = 2048;
pub(crate) const MAX_LINE_BYTES: usize = 4096;

const MAX_META_BYTES: u64 = 16 * 1024;
const WRITE_BATCH_LIMIT: usize = 64;
const LOCK_FILE_NAME: &str = "audit.lock";
const META_FILE_NAME: &str = "audit-meta.json";

const ALLOWED_MCP_METHODS: &[&str] = &[
    "initialize",
    "notifications/initialized",
    "ping",
    "server/discover",
    "tools/list",
    "tools/call",
    "other",
];

const ALLOWED_MCP_OUTCOMES: &[&str] = &[
    "success",
    "tool_error",
    "jsonrpc_error",
    "http_refusal",
    "transport_error",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AuditEventKind {
    McpRequest,
    #[serde(rename = "oauth", alias = "o_auth")]
    OAuth,
    Lifecycle,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum PersistedErrorCode {
    Named(String),
    Rpc(i64),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedAuditRecord {
    pub(crate) schema_version: u32,
    pub(crate) event_kind: AuditEventKind,
    pub(crate) timestamp_unix_ms: u64,
    pub(crate) sequence: u64,
    pub(crate) boot_id: String,
    pub(crate) session_id: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) client_id_sha256: Option<String>,
    pub(crate) catalogue_sha256: Option<String>,
    pub(crate) method: String,
    pub(crate) tool_name: Option<String>,
    pub(crate) outcome: String,
    pub(crate) http_status: Option<u16>,
    pub(crate) error_code: Option<PersistedErrorCode>,
    pub(crate) duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) context_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mission_id: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditHistoryFilter {
    pub(crate) since_unix_ms: Option<u64>,
    pub(crate) until_unix_ms: Option<u64>,
    pub(crate) boot_id: Option<String>,
    pub(crate) session_id: Option<String>,
    pub(crate) context_id: Option<String>,
    pub(crate) mission_id: Option<String>,
    pub(crate) event_kind: Option<AuditEventKind>,
    pub(crate) provider: Option<String>,
    pub(crate) client_id_sha256: Option<String>,
    pub(crate) method: Option<String>,
    pub(crate) tool_name: Option<String>,
    pub(crate) outcome: Option<String>,
    pub(crate) http_status: Option<u16>,
    pub(crate) error_code: Option<String>,
    pub(crate) limit: Option<usize>,
    pub(crate) newest_first: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AuditHistoryDiagnostics {
    pub(crate) available: bool,
    pub(crate) lost: u64,
    pub(crate) records: Vec<PersistedAuditRecord>,
}

impl AuditHistoryDiagnostics {
    pub(crate) fn unavailable() -> Self {
        Self {
            available: false,
            lost: 0,
            records: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuditHistoryQueryResult {
    pub(crate) available: bool,
    pub(crate) lost: u64,
    pub(crate) corrupt_lines: u64,
    pub(crate) truncated: bool,
    pub(crate) records: Vec<PersistedAuditRecord>,
}

impl AuditHistoryQueryResult {
    pub(crate) fn into_diagnostics(self) -> AuditHistoryDiagnostics {
        AuditHistoryDiagnostics {
            available: self.available,
            lost: self.lost,
            records: self.records,
        }
    }
}

#[derive(Clone)]
pub(crate) struct AuditHistoryConfig {
    pub(crate) queue_capacity: usize,
    pub(crate) max_segment_bytes: u64,
    pub(crate) max_total_bytes: u64,
    pub(crate) max_segments: usize,
    pub(crate) max_age: Duration,
    pub(crate) clock: Option<Arc<dyn Fn() -> u64 + Send + Sync>>,
}

impl fmt::Debug for AuditHistoryConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditHistoryConfig")
            .field("queue_capacity", &self.queue_capacity)
            .field("max_segment_bytes", &self.max_segment_bytes)
            .field("max_total_bytes", &self.max_total_bytes)
            .field("max_segments", &self.max_segments)
            .field("max_age", &self.max_age)
            .field("clock", &self.clock.is_some())
            .finish()
    }
}

impl Default for AuditHistoryConfig {
    fn default() -> Self {
        Self {
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            max_segment_bytes: DEFAULT_MAX_SEGMENT_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_segments: DEFAULT_MAX_SEGMENTS,
            max_age: DEFAULT_MAX_AGE,
            clock: None,
        }
    }
}

impl AuditHistoryConfig {
    fn now_unix_ms(&self) -> u64 {
        match &self.clock {
            Some(clock) => clock(),
            None => system_unix_ms(),
        }
    }

    fn normalized(mut self) -> Self {
        self.queue_capacity = self.queue_capacity.max(1);
        self.max_segment_bytes = self.max_segment_bytes.max(256);
        self.max_total_bytes = self.max_total_bytes.max(self.max_segment_bytes);
        self.max_segments = self.max_segments.max(1);
        self
    }
}

#[derive(Debug)]
pub(crate) struct AuditHistoryError {
    message: String,
}

impl AuditHistoryError {
    fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

impl fmt::Display for AuditHistoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AuditHistoryError {}

impl From<std::io::Error> for AuditHistoryError {
    fn from(error: std::io::Error) -> Self {
        Self::new(error.to_string())
    }
}

impl From<serde_json::Error> for AuditHistoryError {
    fn from(error: serde_json::Error) -> Self {
        Self::new(error.to_string())
    }
}

impl From<LifecycleError> for AuditHistoryError {
    fn from(error: LifecycleError) -> Self {
        Self::new(error.to_string())
    }
}

pub(crate) fn is_opaque_hex_id(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

pub(crate) fn is_valid_session_id(value: &str) -> bool {
    is_opaque_hex_id(value, 32)
}

fn is_valid_provider(value: &str) -> bool {
    matches!(value, "gemini" | "chatgpt" | "local")
}

fn is_valid_error_name(value: &str) -> bool {
    matches!(value,
          "approval_invalid"
        | "authorization_expired_or_revoked"
        | "authorization_limit"
        | "body_timeout"
        | "capability_authority_changed"
        | "capability_unavailable"
        | "confidential_client_required"
        | "connector_busy"
        | "duplicate_parameter"
        | "extension_authority_changed"
        | "host_refused"
        | "invalid_client"
        | "invalid_client_metadata"
        | "invalid_client_or_redirect"
        | "invalid_grant"
        | "invalid_http_headers"
        | "invalid_mcp_content_or_replay"
        | "invalid_mcp_payload"
        | "invalid_oauth_response"
        | "invalid_or_oversized_body"
        | "invalid_redirect_uri"
        | "invalid_request"
        | "invalid_scope"
        | "invalid_target"
        | "invalid_token"
        | "local_enrollment_required"
        | "mcp_preflight_refused"
        | "not_found"
        | "oauth_refused"
        | "oauth_state_uncertain"
        | "oauth_unavailable"
        | "origin_refused"
        | "other"
        | "pkce_required"
        | "post_required"
        | "registration_limit"
        | "request_capacity_busy"
        | "request_interrupted"
        | "request_limit"
        | "request_too_large"
        | "response_capacity_busy"
        | "response_exceeds_limit"
        | "service_start_failed"
        | "service_stop_failed"
        | "state_required"
        | "tool_error"
        | "tunnel_cleanup_failed"
        | "tunnel_exited"
        | "tunnel_start_failed"
        | "unauthorized"
        | "unsupported_content_type"
        | "unsupported_grant_type"
        | "workstation_stopping"
    )
}

fn sanitize_error_code(code: Option<PersistedErrorCode>) -> Option<PersistedErrorCode> {
    code.map(|code| match code {
        PersistedErrorCode::Rpc(rpc) => PersistedErrorCode::Rpc(rpc),
        PersistedErrorCode::Named(name) => {
            if is_valid_error_name(&name) {
                PersistedErrorCode::Named(name)
            } else {
                PersistedErrorCode::Named("other".to_owned())
            }
        }
    })
}

fn allowlisted_mcp_method(method: &str) -> &'static str {
    ALLOWED_MCP_METHODS
        .iter()
        .copied()
        .find(|allowed| *allowed == method)
        .unwrap_or("other")
}

fn classify_method(method: &str) -> (AuditEventKind, &'static str) {
    if let Some(event) = crate::request_audit::OAuthEvent::from_method(method) {
        return (AuditEventKind::OAuth, event.method());
    }
    if let Some(label) = crate::request_audit::LifecycleEvent::known_method(method) {
        return (AuditEventKind::Lifecycle, label);
    }
    (AuditEventKind::McpRequest, allowlisted_mcp_method(method))
}

fn valid_outcome(kind: AuditEventKind, outcome: &str) -> bool {
    match kind {
        AuditEventKind::McpRequest => ALLOWED_MCP_OUTCOMES.contains(&outcome),
        AuditEventKind::OAuth => matches!(outcome, "success" | "http_refusal"),
        AuditEventKind::Lifecycle => matches!(outcome, "success" | "lifecycle_error"),
    }
}

/// Only first-party tools whose authorized handlers emit mission receipts.
pub(crate) fn is_activity_tool(tool: &str) -> bool {
    matches!(tool,
        "agent_bridge_context_create" | "agent_bridge_task_import" |
        "agent_bridge_mission_create" | "agent_bridge_mission_get" |
        "agent_bridge_mission_list" | "agent_bridge_mission_observe" |
        "agent_bridge_mission_grant" | "agent_bridge_mission_attach" |
        "agent_bridge_mission_transfer" | "agent_bridge_mission_checkpoint" |
        "agent_bridge_mission_checkpoints" | "agent_bridge_mission_complete" |
        "agent_bridge_mission_subtask_create" | "agent_bridge_mission_subtask_assign" |
        "agent_bridge_mission_subtask_update" | "agent_bridge_mission_subtask_list" |
        "agent_bridge_mission_handoff" | crate::attempt_maintenance::TOOL_NAME)
}

fn is_mission_activity_tool(tool: &str) -> bool {
    is_activity_tool(tool) && !matches!(tool, "agent_bridge_context_create" |
        "agent_bridge_task_import" | "agent_bridge_mission_list")
}

fn zero_boot_id() -> String {
    "0".repeat(32)
}

impl PersistedAuditRecord {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_fields(
        timestamp_unix_ms: u64,
        sequence: u64,
        boot_id: &str,
        session_id: Option<&str>,
        provider: Option<&str>,
        client_id_sha256: Option<&str>,
        catalogue_sha256: Option<&str>,
        method: &str,
        tool_name: Option<&str>,
        outcome: &str,
        http_status: Option<u16>,
        error_code: Option<PersistedErrorCode>,
        duration_ms: u64,
    ) -> Self {
        let (event_kind, method) = classify_method(method);
        let tool_name = (method == "tools/call").then(|| audit_tool_name(tool_name).to_owned());
        Self {
            schema_version: SCHEMA_VERSION,
            event_kind,
            timestamp_unix_ms,
            sequence,
            boot_id: if is_opaque_hex_id(boot_id, 32) {
                boot_id.to_owned()
            } else {
                zero_boot_id()
            },
            session_id: session_id.filter(|id| is_valid_session_id(id)).map(str::to_owned),
            provider: provider.filter(|p| is_valid_provider(p)).map(str::to_owned),
            client_id_sha256: client_id_sha256
                .filter(|hash| is_opaque_hex_id(hash, 64))
                .map(str::to_owned),
            catalogue_sha256: catalogue_sha256
                .filter(|hash| is_opaque_hex_id(hash, 64))
                .map(str::to_owned),
            method: method.to_owned(),
            tool_name,
            outcome: if valid_outcome(event_kind, outcome) { outcome } else { "http_refusal" }.to_owned(),
            http_status,
            error_code: sanitize_error_code(error_code),
            duration_ms,
            context_id: None,
            mission_id: None,
        }
    }

    /// The only producer-side attribution API accepts a typed server receipt.
    pub(crate) fn with_activity(mut self, activity: Option<&ActivityAttribution>) -> Self {
        if let Some(activity) = activity {
            self.context_id = Some(activity.context_id().to_owned());
            self.mission_id = activity.mission_id().map(str::to_owned);
            if !self.valid_activity() {
                self.context_id = None;
                self.mission_id = None;
            }
        }
        self
    }

    fn valid_activity(&self) -> bool {
        let Some(context) = self.context_id.as_deref() else { return self.mission_id.is_none(); };
        let Some(tool) = self.tool_name.as_deref() else { return false; };
        self.event_kind == AuditEventKind::McpRequest && self.method == "tools/call"
            && self.outcome == "success" && self.error_code.is_none()
            && self.provider.is_some()
            && (self.http_status.is_some_and(|code| (200..300).contains(&code))
                || (self.provider.as_deref() == Some("local") && self.http_status.is_none()
                    && self.session_id.is_some()))
            && is_activity_tool(tool) && agent_bridge_missions::valid_id("ctx", context)
            && self.mission_id.as_deref().is_none_or(|id|
                is_mission_activity_tool(tool) && agent_bridge_missions::valid_id("mis", id))
    }

    pub(crate) fn validate_persisted_record(&self) -> bool {
        if !self.valid_activity() { return false; }
        if self.schema_version != SCHEMA_VERSION || !is_opaque_hex_id(&self.boot_id, 32) {
            return false;
        }
        if self.session_id.as_deref().is_some_and(|id| !is_valid_session_id(id)) {
            return false;
        }
        if self.provider.as_deref().is_some_and(|p| !is_valid_provider(p)) {
            return false;
        }
        if self
            .client_id_sha256
            .as_deref()
            .is_some_and(|h| !is_opaque_hex_id(h, 64))
        {
            return false;
        }
        if self
            .catalogue_sha256
            .as_deref()
            .is_some_and(|h| !is_opaque_hex_id(h, 64))
        {
            return false;
        }
        if let Some(PersistedErrorCode::Named(name)) = &self.error_code {
            if !is_valid_error_name(name) {
                return false;
            }
        }
        match self.event_kind {
            AuditEventKind::McpRequest => {
                if !ALLOWED_MCP_METHODS.contains(&self.method.as_str()) {
                    return false;
                }
                if self.method == "tools/call" {
                    let Some(tool) = self.tool_name.as_deref() else {
                        return false;
                    };
                    if tool != audit_tool_name(Some(tool)) {
                        return false;
                    }
                } else if self.tool_name.is_some() {
                    return false;
                }
                ALLOWED_MCP_OUTCOMES.contains(&self.outcome.as_str())
                    && (self.outcome != "transport_error"
                        || (self.provider.as_deref() == Some("local") && self.http_status.is_none()
                            && self.error_code.is_some()))
            }
            AuditEventKind::OAuth | AuditEventKind::Lifecycle => {
                classify_method(&self.method).0 == self.event_kind
                    && self.tool_name.is_none()
                    && self.catalogue_sha256.is_none()
                    && valid_outcome(self.event_kind, &self.outcome)
            }
        }
    }
}

pub(crate) fn default_history_dir(base: &Path) -> PathBuf {
    base.join("audit-history")
}

fn system_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn duration_ms_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedMeta {
    schema_version: u32,
    lost: u64,
}

enum SinkCommand {
    Record(PersistedAuditRecord),
    Flush(mpsc::Sender<()>),
}

pub(crate) struct AuditHistorySink {
    dir: Option<PathBuf>,
    config: AuditHistoryConfig,
    sender: Option<SyncSender<SinkCommand>>,
    worker: Option<JoinHandle<()>>,
    available: Arc<AtomicBool>,
    prior_lost: Arc<AtomicU64>,
    session_lost: Arc<AtomicU64>,
}

impl fmt::Debug for AuditHistorySink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditHistorySink")
            .field("dir", &self.dir)
            .field("available", &self.available())
            .field("lost", &self.lost())
            .finish()
    }
}

impl AuditHistorySink {
    pub(crate) fn open(dir: &Path, config: AuditHistoryConfig) -> Result<Self, AuditHistoryError> {
        let config = config.normalized();
        let validated = private_store::ensure_private_dir(dir)?;
        let initial_meta = read_meta(&validated)?;
        let prior_lost_val = initial_meta.as_ref().map(|meta| meta.lost).unwrap_or(0);
        // Ensure lock file exists and is owner-private before accepting writes.
        let _lock_file = private_store::open_private_file(
            &validated.join(LOCK_FILE_NAME),
            private_store::OpenMode::CreateOrReadWrite,
        )?;

        let (tx, rx) = mpsc::sync_channel(config.queue_capacity);
        let available = Arc::new(AtomicBool::new(true));
        let prior_lost = Arc::new(AtomicU64::new(prior_lost_val));
        let session_lost = Arc::new(AtomicU64::new(0));

        let thread_dir = validated.clone();
        let thread_config = config.clone();
        let thread_available = Arc::clone(&available);
        let thread_prior = Arc::clone(&prior_lost);
        let thread_session = Arc::clone(&session_lost);

        let worker = thread::Builder::new()
            .name("ab-audit-history".to_owned())
            .spawn(move || {
                writer_loop(
                    &thread_dir,
                    &thread_config,
                    rx,
                    &thread_available,
                    &thread_prior,
                    &thread_session,
                );
            })?;

        Ok(Self {
            dir: Some(validated),
            config,
            sender: Some(tx),
            worker: Some(worker),
            available,
            prior_lost,
            session_lost,
        })
    }

    pub(crate) fn unavailable() -> Self {
        Self {
            dir: None,
            config: AuditHistoryConfig::default(),
            sender: None,
            worker: None,
            available: Arc::new(AtomicBool::new(false)),
            prior_lost: Arc::new(AtomicU64::new(0)),
            session_lost: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(crate) fn enqueue(&self, record: PersistedAuditRecord) {
        if !record.validate_persisted_record() {
            self.session_lost.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Some(sender) = &self.sender else {
            self.session_lost.fetch_add(1, Ordering::Relaxed);
            return;
        };
        match sender.try_send(SinkCommand::Record(record)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.session_lost.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub(crate) fn flush(&self, timeout: Duration) -> bool {
        let Some(sender) = &self.sender else {
            return false;
        };
        let (ack_tx, ack_rx) = mpsc::channel();
        let deadline = Instant::now() + timeout;
        let mut cmd = SinkCommand::Flush(ack_tx);
        loop {
            match sender.try_send(cmd) {
                Ok(()) => break,
                Err(TrySendError::Full(returned)) => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    cmd = returned;
                    thread::sleep(Duration::from_millis(1));
                }
                Err(TrySendError::Disconnected(_)) => return false,
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        ack_rx.recv_timeout(remaining).is_ok()
    }

    pub(crate) fn available(&self) -> bool {
        self.available.load(Ordering::Acquire)
    }

    pub(crate) fn lost(&self) -> u64 {
        self.prior_lost
            .load(Ordering::Acquire)
            .saturating_add(self.session_lost.load(Ordering::Acquire))
    }

    #[allow(dead_code)]
    pub(crate) fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }

    pub(crate) fn query(&self, filter: &AuditHistoryFilter) -> AuditHistoryDiagnostics {
        let Some(dir) = &self.dir else {
            return AuditHistoryDiagnostics {
                available: false,
                lost: self.lost(),
                records: Vec::new(),
            };
        };
        match read_history(dir, filter, &self.config) {
            Ok(mut result) => {
                result.available = self.available();
                result.lost = self.lost().max(result.lost).saturating_add(result.corrupt_lines);
                result.into_diagnostics()
            }
            Err(_) => AuditHistoryDiagnostics {
                available: false,
                lost: self.lost(),
                records: Vec::new(),
            },
        }
    }
}

impl Drop for AuditHistorySink {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn writer_loop(
    dir: &Path,
    config: &AuditHistoryConfig,
    rx: mpsc::Receiver<SinkCommand>,
    available: &AtomicBool,
    prior_lost: &AtomicU64,
    session_lost: &AtomicU64,
) {
    let mut saved_local_losses = 0;
    let mut ages: HashMap<String, SegmentAge> = HashMap::new();
    let mut startup = true;
    loop {
        let first = if startup {
            startup = false;
            None
        } else if let Some(oldest) = ages.values().map(|age| age.oldest).min() {
            let expires = oldest.saturating_add(duration_ms_u64(config.max_age));
            let wait = Duration::from_millis(expires.saturating_sub(config.now_unix_ms()).max(1000));
            match rx.recv_timeout(wait) {
                Ok(command) => Some(command),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        } else {
            match rx.recv() { Ok(command) => Some(command), Err(_) => break }
        };
        let mut batch = Vec::new();
        let mut flushes = Vec::new();
        match first {
            Some(SinkCommand::Record(record)) => batch.push(record),
            Some(SinkCommand::Flush(ack)) => flushes.push(ack),
            None => {}
        }
        while batch.len() < WRITE_BATCH_LIMIT {
            match rx.try_recv() {
                Ok(SinkCommand::Record(record)) => batch.push(record),
                Ok(SinkCommand::Flush(ack)) => flushes.push(ack),
                Err(_) => break,
            }
        }

        let result = persist_batch(dir, config, &batch, prior_lost, session_lost,
            &mut saved_local_losses, &mut ages);
        available.store(result.is_ok(), Ordering::Release);

        for ack in flushes {
            let _ = ack.send(());
        }
    }
}

// Count only records whose durable write could not be confirmed, including partial batches.
struct Unwritten<'a> {
    count: usize,
    lost: &'a AtomicU64,
}

impl Drop for Unwritten<'_> {
    fn drop(&mut self) {
        self.lost.fetch_add(self.count as u64, Ordering::Relaxed);
    }
}

fn persist_batch(
    dir: &Path,
    config: &AuditHistoryConfig,
    batch: &[PersistedAuditRecord],
    prior_lost: &AtomicU64,
    session_lost: &AtomicU64,
    saved_local_losses: &mut u64,
    ages: &mut HashMap<String, SegmentAge>,
) -> Result<(), AuditHistoryError> {
    let mut unwritten = Unwritten { count: batch.len(), lost: session_lost };
    private_store::verify_private_dir(dir)?;
    let lock_path = dir.join(LOCK_FILE_NAME);
    // Give other writers time to finish rotating a segment. Retry only acquisition,
    // before any persistent state changes. Permanent errors still fail immediately.
    let mut retries = 2;
    let _lock = loop {
        match private_store::lock_exclusive(&lock_path, true) {
            Err(LifecycleError::Busy) if retries > 0 => retries -= 1,
            result => break result?,
        }
    };

    // The file lock serializes local deltas from every process sharing this store.
    let disk_losses = read_meta(dir)?.map_or(0, |meta| meta.lost);
    let external_losses = disk_losses.checked_sub(*saved_local_losses)
        .ok_or_else(|| AuditHistoryError::new("audit loss counter regressed"))?;
    prior_lost.store(external_losses, Ordering::Release);

    let now_ms = config.now_unix_ms();
    let max_age_ms = duration_ms_u64(config.max_age);
    let mut segments = list_segments(dir)?;
    retain_segments(dir, &mut segments, now_ms, max_age_ms, ages)?;

    let mut rows = Vec::with_capacity(batch.len());
    for record in batch {
        if record.validate_persisted_record() {
            if record.timestamp_unix_ms.saturating_add(max_age_ms) <= now_ms {
                unwritten.count -= 1;
                continue;
            }
            let mut line = serde_json::to_vec(record)?;
            line.push(b'\n');
            if line.len() <= MAX_LINE_BYTES && line.len() as u64 <= config.max_segment_bytes {
                rows.push((record.timestamp_unix_ms, line));
                continue;
            }
        }
        session_lost.fetch_add(1, Ordering::Relaxed);
        unwritten.count -= 1;
    }

    // A torn final line stays independently countable after a crash. Start a new
    // segment before appending any complete event to that unterminated stream.
    let mut new_segment = !rows.is_empty() && match segments.last() {
        Some(segment) if segment.size > 0 => {
            let mut file = private_store::open_private_file(&segment.path, private_store::OpenMode::Read)?;
            file.seek(SeekFrom::End(-1))?;
            let mut last = [0u8];
            file.read_exact(&mut last)?;
            last[0] != b'\n'
        }
        _ => false,
    };
    let mut rows = rows.into_iter().peekable();
    while let Some((stamp, first)) = rows.peek() {
        if new_segment || segments.last().is_none_or(|s| s.size.saturating_add(first.len() as u64) > config.max_segment_bytes) {
            let stamp_ms = segments.last().map_or(*stamp, |s| s.stamp_ms.max(*stamp));
            let path = create_next_segment(dir, stamp_ms, &segments)?;
            let name = path.file_name().and_then(|n| n.to_str())
                .ok_or_else(|| AuditHistoryError::new("invalid audit segment name"))?.to_owned();
            segments.push(SegmentInfo { path, name, stamp_ms, size: 0 });
            new_segment = false;
        }
        let active = segments.last_mut().expect("a segment was opened for the first record");
        let remaining = config.max_segment_bytes - active.size;
        let mut bytes = Vec::new();
        let mut count = 0;
        let mut oldest = u64::MAX;
        while let Some((stamp, line)) = rows.next_if(|(_, line)| bytes.len() as u64 + line.len() as u64 <= remaining) {
            oldest = oldest.min(stamp);
            bytes.extend_from_slice(&line);
            count += 1;
        }
        let mut file = private_store::open_private_file(&active.path, private_store::OpenMode::Append)?;
        if let Err(error) = file.write_all(&bytes).and_then(|_| file.sync_data()) {
            let _ = file.set_len(active.size);
            return Err(error.into());
        }
        active.size += bytes.len() as u64;
        unwritten.count -= count;
        if let Some(previous) = ages.get(&active.name) { oldest = oldest.min(previous.oldest); }
        ages.insert(active.name.clone(), SegmentAge::from_file(&file, oldest)?);
    }

    prune_excess_segments(&mut segments, config, ages)?;

    let local_losses = session_lost.load(Ordering::Acquire);
    if local_losses > *saved_local_losses {
        write_meta_atomic(dir, external_losses.saturating_add(local_losses))?;
        *saved_local_losses = local_losses;
    }

    Ok(())
}

fn prune_excess_segments(
    segments: &mut Vec<SegmentInfo>,
    config: &AuditHistoryConfig,
    ages: &mut HashMap<String, SegmentAge>,
) -> Result<(), AuditHistoryError> {
    let mut total_bytes: u64 = segments.iter().map(|s| s.size).sum();
    while segments.len() > 1
        && (total_bytes > config.max_total_bytes || segments.len() > config.max_segments)
    {
        let oldest = segments.remove(0);
        total_bytes = total_bytes.saturating_sub(oldest.size);
        remove_verified_segment(&oldest.path)?;
        ages.remove(&oldest.name);
    }
    Ok(())
}

fn remove_verified_segment(path: &Path) -> Result<(), AuditHistoryError> {
    let file = private_store::open_private_file(path, private_store::OpenMode::Read)?;
    drop(file);
    fs::remove_file(path)?;
    Ok(())
}

#[derive(Clone, Debug)]
struct SegmentInfo {
    path: PathBuf,
    name: String,
    stamp_ms: u64,
    size: u64,
}

fn parse_segment_name(name: &str) -> Option<(u64, u32)> {
    let inner = name.strip_prefix("audit-")?.strip_suffix(".jsonl")?;
    let (ts_str, seq_str) = inner.split_once('-')?;
    if ts_str.len() != 20
        || seq_str.len() != 6
        || !ts_str.bytes().all(|b| b.is_ascii_digit())
        || !seq_str.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    Some((ts_str.parse().ok()?, seq_str.parse().ok()?))
}

fn format_segment_name(stamp_ms: u64, seq: u32) -> String {
    format!("audit-{stamp_ms:020}-{seq:06}.jsonl")
}

fn create_next_segment(
    dir: &Path,
    stamp_ms: u64,
    existing: &[SegmentInfo],
) -> Result<PathBuf, AuditHistoryError> {
    let mut seq = existing
        .iter()
        .filter(|s| s.stamp_ms == stamp_ms)
        .filter_map(|s| parse_segment_name(&s.name).map(|(_, seq)| seq.saturating_add(1)))
        .max()
        .unwrap_or(0);
    for _ in 0..1000 {
        let candidate = dir.join(format_segment_name(stamp_ms, seq));
        match private_store::open_private_file(&candidate, private_store::OpenMode::CreateNew) {
            Ok(file) => {
                drop(file);
                return Ok(candidate);
            }
            Err(LifecycleError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                seq = seq.saturating_add(1);
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(AuditHistoryError::new("exhausted audit segment sequence"))
}

fn list_segments(dir: &Path) -> Result<Vec<SegmentInfo>, AuditHistoryError> {
    let mut segments = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Some((stamp_ms, _)) = parse_segment_name(name) else {
            continue;
        };
        let path = entry.path();
        let md = fs::symlink_metadata(&path)?;
        if !md.is_file() || md.file_type().is_symlink() || private_store::is_reparse(&md) {
            return Err(AuditHistoryError::new("unsafe audit segment file"));
        }
        segments.push(SegmentInfo {
            path,
            name: name.to_owned(),
            stamp_ms,
            size: md.len(),
        });
    }
    segments.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(segments)
}

fn read_meta(dir: &Path) -> Result<Option<PersistedMeta>, AuditHistoryError> {
    let path = dir.join(META_FILE_NAME);
    match fs::symlink_metadata(&path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
        Ok(md) => {
            if !md.is_file()
                || md.file_type().is_symlink()
                || private_store::is_reparse(&md)
                || md.len() > MAX_META_BYTES
            {
                return Err(AuditHistoryError::new("unsafe audit metadata file"));
            }
        }
    }
    let file = private_store::open_private_file(&path, private_store::OpenMode::Read)?;
    let mut bytes = Vec::new();
    file.take(MAX_META_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_META_BYTES {
        return Err(AuditHistoryError::new("audit metadata exceeds limit"));
    }
    let meta: PersistedMeta = serde_json::from_slice(&bytes)?;
    if meta.schema_version != SCHEMA_VERSION {
        return Err(AuditHistoryError::new("unsupported audit metadata schema"));
    }
    Ok(Some(meta))
}

fn write_meta_atomic(dir: &Path, lost: u64) -> Result<(), AuditHistoryError> {
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce)
        .map_err(|_| AuditHistoryError::new("randomness unavailable for metadata write"))?;
    let hex_nonce: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let tmp = dir.join(format!("audit-meta.tmp.{hex_nonce}"));
    let target = dir.join(META_FILE_NAME);
    let payload = serde_json::to_vec(&PersistedMeta {
        schema_version: SCHEMA_VERSION,
        lost,
    })?;
    {
        let mut file = private_store::open_private_file(&tmp, private_store::OpenMode::CreateNew)?;
        file.write_all(&payload)?;
        file.sync_all()?;
    }
    if let Err(err) = fs::rename(&tmp, &target) {
        let _ = fs::remove_file(&tmp);
        return Err(err.into());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HeapRecord {
    newest_first: bool,
    record: PersistedAuditRecord,
}

impl HeapRecord {
    fn key(&self) -> (u64, &str, u64) {
        (
            self.record.timestamp_unix_ms,
            self.record.boot_id.as_str(),
            self.record.sequence,
        )
    }
}

impl Ord for HeapRecord {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        let ord = self.key().cmp(&other.key());
        if self.newest_first {
            ord.reverse()
        } else {
            ord
        }
    }
}

impl PartialOrd for HeapRecord {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

struct BoundedRecordCollector {
    limit: usize,
    newest_first: bool,
    heap: BinaryHeap<HeapRecord>,
    truncated: bool,
    max_retained: usize,
}

impl BoundedRecordCollector {
    fn new(limit: usize, newest_first: bool) -> Self {
        Self {
            limit,
            newest_first,
            heap: BinaryHeap::with_capacity(limit),
            truncated: false,
            max_retained: 0,
        }
    }

    fn push(&mut self, record: PersistedAuditRecord) {
        if self.heap.len() < self.limit {
            self.heap.push(HeapRecord {
                newest_first: self.newest_first,
                record,
            });
            self.max_retained = self.max_retained.max(self.heap.len());
            return;
        }
        self.truncated = true;
        let incoming = HeapRecord {
            newest_first: self.newest_first,
            record,
        };
        if let Some(top) = self.heap.peek() {
            let replace = if self.newest_first {
                incoming.key() > top.key()
            } else {
                incoming.key() < top.key()
            };
            if replace {
                self.heap.pop();
                self.heap.push(incoming);
            }
        }
    }

    fn finish(self) -> (Vec<PersistedAuditRecord>, bool) {
        let records = self
            .heap
            .into_sorted_vec()
            .into_iter()
            .map(|entry| entry.record)
            .collect();
        (records, self.truncated)
    }
}

pub(crate) fn read_history(
    dir: &Path,
    filter: &AuditHistoryFilter,
    config: &AuditHistoryConfig,
) -> Result<AuditHistoryQueryResult, AuditHistoryError> {
    let config = config.clone().normalized();
    let validated = private_store::verify_private_dir(dir)?;
    let _lock_guard = private_store::lock_shared(&validated.join(LOCK_FILE_NAME))?;

    let meta_lost = read_meta(&validated)?.map_or(0, |meta| meta.lost);
    let segments = list_segments(&validated)?;
    let now_ms = config.now_unix_ms();
    let max_age_ms = duration_ms_u64(config.max_age);
    let limit = filter
        .limit
        .unwrap_or(DEFAULT_QUERY_LIMIT)
        .clamp(1, MAX_QUERY_LIMIT);
    let newest_first = filter.newest_first.unwrap_or(true);

    let mut collector = BoundedRecordCollector::new(limit, newest_first);
    let mut corrupt_lines = 0u64;
    for seg in segments {
        let file = private_store::open_private_file(&seg.path, private_store::OpenMode::Read)?;
        let mut reader = BufReader::new(file);
        read_bounded_lines(&mut reader, MAX_LINE_BYTES, |outcome| {
            match outcome {
                LineRead::Line(line) => {
                    if line.trim().is_empty() {
                        return Ok(());
                    }
                    match serde_json::from_str::<PersistedAuditRecord>(line) {
                        Ok(record) if record.validate_persisted_record() => {
                            if record.timestamp_unix_ms.saturating_add(max_age_ms) <= now_ms {
                                return Ok(());
                            }
                            if matches_filter(&record, filter) {
                                collector.push(record);
                            }
                        }
                        _ => {
                            corrupt_lines = corrupt_lines.saturating_add(1);
                        }
                    }
                }
                LineRead::Oversized | LineRead::InvalidUtf8 => {
                    corrupt_lines = corrupt_lines.saturating_add(1);
                }
            }
            Ok(())
        })?;
    }

    let (records, truncated) = collector.finish();

    Ok(AuditHistoryQueryResult {
        available: true,
        lost: meta_lost,
        corrupt_lines,
        truncated,
        records,
    })
}

#[allow(dead_code)]
pub(crate) fn read_history_diagnostics(
    dir: &Path,
    filter: &AuditHistoryFilter,
) -> AuditHistoryDiagnostics {
    match read_history(dir, filter, &AuditHistoryConfig::default()) {
        Ok(mut result) => {
            result.lost = result.lost.saturating_add(result.corrupt_lines);
            result.into_diagnostics()
        }
        Err(_) => AuditHistoryDiagnostics::unavailable(),
    }
}

fn matches_filter(record: &PersistedAuditRecord, filter: &AuditHistoryFilter) -> bool {
    if let Some(since) = filter.since_unix_ms {
        if record.timestamp_unix_ms < since {
            return false;
        }
    }
    if let Some(until) = filter.until_unix_ms {
        if record.timestamp_unix_ms > until {
            return false;
        }
    }
    if let Some(boot_id) = &filter.boot_id {
        if &record.boot_id != boot_id {
            return false;
        }
    }
    if let Some(session_id) = &filter.session_id {
        if record.session_id.as_ref() != Some(session_id) {
            return false;
        }
    }
    if filter.context_id.as_ref().is_some_and(|id| record.context_id.as_ref() != Some(id))
        || filter.mission_id.as_ref().is_some_and(|id| record.mission_id.as_ref() != Some(id)) {
        return false;
    }
    if let Some(event_kind) = filter.event_kind {
        if record.event_kind != event_kind {
            return false;
        }
    }
    if let Some(provider) = &filter.provider {
        if record.provider.as_ref() != Some(provider) {
            return false;
        }
    }
    if let Some(client_hash) = &filter.client_id_sha256 {
        if record.client_id_sha256.as_ref() != Some(client_hash) {
            return false;
        }
    }
    if let Some(method) = &filter.method {
        if &record.method != method {
            return false;
        }
    }
    if let Some(tool_name) = &filter.tool_name {
        if record.tool_name.as_ref() != Some(tool_name) {
            return false;
        }
    }
    if let Some(outcome) = &filter.outcome {
        if &record.outcome != outcome {
            return false;
        }
    }
    if let Some(http_status) = filter.http_status {
        if record.http_status != Some(http_status) {
            return false;
        }
    }
    if let Some(error_code) = &filter.error_code {
        let matches = match &record.error_code {
            Some(PersistedErrorCode::Named(name)) => name == error_code,
            Some(PersistedErrorCode::Rpc(code)) => code.to_string() == *error_code,
            None => false,
        };
        if !matches {
            return false;
        }
    }
    true
}

enum LineRead<'a> {
    Line(&'a str),
    Oversized,
    InvalidUtf8,
}

fn read_bounded_lines(
    reader: &mut BufReader<File>,
    max_bytes: usize,
    mut on_event: impl FnMut(LineRead<'_>) -> Result<(), AuditHistoryError>,
) -> Result<(), AuditHistoryError> {
    let mut buf = Vec::with_capacity(512);
    loop {
        buf.clear();
        let mut oversized = false;
        let mut ended_with_newline = false;
        loop {
            let chunk = reader.fill_buf()?;
            if chunk.is_empty() {
                break;
            }
            if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
                let take = &chunk[..pos];
                if !oversized && buf.len() + take.len() <= max_bytes {
                    buf.extend_from_slice(take);
                } else {
                    oversized = true;
                }
                reader.consume(pos + 1);
                ended_with_newline = true;
                break;
            } else {
                if !oversized && buf.len() + chunk.len() <= max_bytes {
                    buf.extend_from_slice(chunk);
                } else {
                    oversized = true;
                }
                let len = chunk.len();
                reader.consume(len);
            }
        }
        if buf.is_empty() && !oversized {
            if ended_with_newline { continue; }
            break;
        }
        if oversized {
            on_event(LineRead::Oversized)?;
            continue;
        }
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
        match std::str::from_utf8(&buf) {
            Ok(text) => on_event(LineRead::Line(text)),
            Err(_) => on_event(LineRead::InvalidUtf8),
        }?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
