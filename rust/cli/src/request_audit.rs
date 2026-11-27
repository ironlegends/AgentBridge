//! Operator-only diagnostics for requests reaching the OAuth MCP listener.

use crate::audit_history::{
    is_valid_session_id, AuditHistoryConfig, AuditHistoryDiagnostics, AuditHistoryFilter,
    AuditHistorySink, PersistedAuditRecord, PersistedErrorCode,
};
use crate::capability_manifest::audit_tool_name;
use crate::client_sessions::{Client, ClientSessions};
use crate::runtime::RuntimeError;
use agent_bridge_missions::ActivityAttribution;
use agent_bridge_http::modern::ResponseMetadata;
use agent_bridge_oauth_server::{AuthorizedIdentity, ConnectorClient, VerifiedOAuthClient};
use axum::http::StatusCode;
use serde::de::{value::MapAccessDeserializer, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::VecDeque;
use std::fmt;
use std::marker::PhantomData;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CAPACITY: usize = 2048;
const UNVERIFIED_CAPACITY: usize = 256;
const VERIFIED_CAPACITY: usize = CAPACITY - UNVERIFIED_CAPACITY;
const MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);
/// Closed endpoint labels: never retain the supplied path or query.
#[derive(Clone, Copy)]
pub(crate) enum OAuthEvent {
    Register,
    Authorize,
    Token,
    Revoke,
}

impl OAuthEvent {
    pub(crate) fn from_path(path: &str) -> Option<Self> {
        Self::from_method(path.strip_prefix('/')?)
    }

    pub(crate) fn from_method(method: &str) -> Option<Self> {
        [Self::Register, Self::Authorize, Self::Token, Self::Revoke]
            .into_iter().find(|event| event.method() == method)
    }

    pub(crate) fn method(self) -> &'static str {
        match self {
            Self::Register => "oauth/register",
            Self::Authorize => "oauth/authorize",
            Self::Token => "oauth/token",
            Self::Revoke => "oauth/revoke",
        }
    }
}

/// Local lifecycle outcomes; never accept error strings, URLs or process arguments.
#[derive(Clone, Copy)]
pub(crate) enum LifecycleEvent {
    ServiceStarted,
    ServiceStartFailed,
    ServiceStopped,
    ServiceStopFailed,
    TunnelStarted,
    TunnelStartFailed,
    TunnelExited,
    TunnelCleanupFailed,
    TunnelStopped,
}

impl LifecycleEvent {
    pub(crate) fn known_method(method: &str) -> Option<&'static str> {
        use LifecycleEvent::*;
        [ServiceStarted, ServiceStopped, TunnelStarted, TunnelExited, TunnelCleanupFailed, TunnelStopped]
            .into_iter().map(|event| event.fields().0).find(|label| *label == method)
    }

    fn fields(self) -> (&'static str, Outcome, Option<ErrorCode>) {
        use LifecycleEvent::*;
        let (method, error) = match self {
            ServiceStarted => ("service/start", None),
            ServiceStartFailed => ("service/start", Some("service_start_failed")),
            ServiceStopped => ("service/stop", None),
            ServiceStopFailed => ("service/stop", Some("service_stop_failed")),
            TunnelStarted => ("tunnel/start", None),
            TunnelStartFailed => ("tunnel/start", Some("tunnel_start_failed")),
            TunnelExited => ("tunnel/exit", Some("tunnel_exited")),
            TunnelCleanupFailed => ("tunnel/cleanup", Some("tunnel_cleanup_failed")),
            TunnelStopped => ("tunnel/stop", None),
        };
        let outcome = if error.is_some() { Outcome::LifecycleError } else { Outcome::Success };
        (method, outcome, error.map(ErrorCode::Named))
    }
}

/// Records a startup attempt once, including early return or cancellation,
/// after the caller has selected the qualified audit owner.
pub(crate) struct StartupObservation {
    audit: Arc<RequestAudit>,
    started: Instant,
    succeeded: bool,
}

impl StartupObservation {
    pub(crate) fn new(audit: Arc<RequestAudit>, started: Instant) -> Self {
        Self { audit, started, succeeded: false }
    }

    pub(crate) fn complete(mut self) { self.succeeded = true; }
}

impl Drop for StartupObservation {
    fn drop(&mut self) {
        self.audit.record_lifecycle(if self.succeeded {
            LifecycleEvent::ServiceStarted
        } else {
            LifecycleEvent::ServiceStartFailed
        }, self.started);
    }
}

const METHODS: &[&str] = &[
    "initialize",
    "notifications/initialized",
    "ping",
    "server/discover",
    "tools/list",
    "tools/call",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Outcome {
    Success,
    ToolError,
    JsonrpcError,
    HttpRefusal,
    LifecycleError,
    TransportError,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::ToolError => "tool_error",
            Self::JsonrpcError => "jsonrpc_error",
            Self::HttpRefusal => "http_refusal",
            Self::LifecycleError => "lifecycle_error",
            Self::TransportError => "transport_error",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum ErrorCode {
    Named(&'static str),
    Rpc(i64),
}

#[derive(Clone, Debug, Serialize)]
struct Record {
    timestamp_unix_ms: u64,
    sequence: u64,
    boot_id: String,
    session_id: Option<String>,
    provider: Option<&'static str>,
    client_id_sha256: Option<String>,
    catalogue_sha256: Option<String>,
    method: &'static str,
    tool_name: Option<&'static str>,
    outcome: Outcome,
    http_status: Option<u16>,
    error_code: Option<ErrorCode>,
    duration_ms: u64,
    #[serde(flatten)]
    activity: Option<ActivityAttribution>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Snapshot {
    boot_id: String,
    evicted: u64,
    evicted_verified: u64,
    evicted_unverified: u64,
    in_flight: usize,
    records: Vec<Record>,
}

#[derive(Debug)]
struct RecordBuffer {
    records: VecDeque<(Instant, Record)>,
    capacity: usize,
    evicted: u64,
}

impl RecordBuffer {
    fn new(capacity: usize) -> Self {
        Self { records: VecDeque::with_capacity(capacity), capacity, evicted: 0 }
    }

    fn prune(&mut self, now: Instant) {
        while self.records.front().is_some_and(|(when, _)| now.duration_since(*when) >= MAX_AGE) {
            self.records.pop_front();
            self.evicted += 1;
        }
    }

    fn push(&mut self, now: Instant, record: Record) {
        if self.records.len() == self.capacity {
            self.records.pop_front();
            self.evicted += 1;
        }
        self.records.push_back((now, record));
    }
}

#[derive(Debug)]
struct Ring {
    verified: RecordBuffer,
    unverified: RecordBuffer,
    last_sequence: u64,
    in_flight: usize,
}

impl Ring {
    fn prune(&mut self, now: Instant) {
        self.verified.prune(now);
        self.unverified.prune(now);
    }
}

#[derive(Debug)]
pub(crate) struct RequestAudit {
    pub(crate) boot_id: String,
    pub(crate) sessions: ClientSessions,
    ring: Mutex<Ring>,
    history: Option<Arc<AuditHistorySink>>,
}

impl RequestAudit {
    pub(crate) fn new() -> Result<Self, RuntimeError> {
        Self::with_optional_history(None)
    }

    pub(crate) fn with_history_sink(sink: AuditHistorySink) -> Result<Self, RuntimeError> {
        Self::with_optional_history(Some(Arc::new(sink)))
    }

    #[cfg(test)]
    pub(crate) fn open_with_history_dir(
        dir: &Path,
        config: AuditHistoryConfig,
    ) -> Result<Self, RuntimeError> {
        let sink = AuditHistorySink::open(dir, config)?;
        Self::with_history_sink(sink)
    }

    pub(crate) fn open_with_optional_history_dir(dir: Option<&Path>) -> Result<Self, RuntimeError> {
        match dir {
            None => Self::new(),
            Some(path) => {
                let sink = AuditHistorySink::open(path, AuditHistoryConfig::default())
                    .unwrap_or_else(|_| AuditHistorySink::unavailable());
                Self::with_history_sink(sink)
            }
        }
    }

    fn with_optional_history(history: Option<Arc<AuditHistorySink>>) -> Result<Self, RuntimeError> {
        let mut boot_bytes = [0u8; 16];
        getrandom::fill(&mut boot_bytes).map_err(|_| "Request audit randomness unavailable")?;
        Ok(Self {
            boot_id: boot_bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
            sessions: ClientSessions::default(),
            ring: Mutex::new(Ring {
                verified: RecordBuffer::new(VERIFIED_CAPACITY),
                unverified: RecordBuffer::new(UNVERIFIED_CAPACITY),
                last_sequence: 0,
                in_flight: 0,
            }),
            history,
        })
    }

    pub(crate) fn record_lifecycle(&self, event: LifecycleEvent, started: Instant) {
        let (method, outcome, error_code) = event.fields();
        self.begin();
        self.finish(Record {
            timestamp_unix_ms: 0,
            sequence: 0,
            boot_id: self.boot_id.clone(),
            session_id: None,
            activity: None,
            provider: None,
            client_id_sha256: None,
            catalogue_sha256: None,
            method,
            tool_name: None,
            outcome,
            http_status: None,
            error_code,
            duration_ms: 0,
        }, started);
    }

    pub(crate) fn snapshot(&self) -> Snapshot {
        self.snapshot_at(Instant::now())
    }

    fn snapshot_at(&self, now: Instant) -> Snapshot {
        let mut ring = self.ring.lock().unwrap_or_else(|error| error.into_inner());
        ring.prune(now);
        let mut records: Vec<_> = ring.verified.records.iter()
            .chain(&ring.unverified.records)
            .map(|(_, record)| record.clone())
            .collect();
        records.sort_unstable_by_key(|record| record.sequence);
        Snapshot {
            boot_id: self.boot_id.clone(),
            evicted: ring.verified.evicted + ring.unverified.evicted,
            evicted_verified: ring.verified.evicted,
            evicted_unverified: ring.unverified.evicted,
            in_flight: ring.in_flight,
            records,
        }
    }

    pub(crate) fn query_history(&self, filter: &AuditHistoryFilter) -> AuditHistoryDiagnostics {
        match &self.history {
            Some(history) => history.query(filter),
            None => AuditHistoryDiagnostics::unavailable(),
        }
    }

    pub(crate) fn history_diagnostics(&self) -> AuditHistoryDiagnostics {
        self.query_history(&AuditHistoryFilter::default())
    }

    pub(crate) fn flush_history(&self, timeout: Duration) -> bool {
        self.history
            .as_ref()
            .is_some_and(|history| history.flush(timeout))
    }

    #[allow(dead_code)]
    pub(crate) fn history_lost(&self) -> u64 {
        self.history.as_ref().map_or(0, |history| history.lost())
    }

    #[allow(dead_code)]
    pub(crate) fn history_available(&self) -> bool {
        self.history
            .as_ref()
            .is_some_and(|history| history.available())
    }

    fn begin(&self) {
        let mut ring = self.ring.lock().unwrap_or_else(|error| error.into_inner());
        ring.in_flight += 1;
    }

    fn finish_silent(&self) {
        // A notification without a response has no admitted activity.
        let mut ring = self.ring.lock().unwrap_or_else(|error| error.into_inner());
        ring.in_flight -= 1;
    }

    fn finish(&self, mut record: Record, started: Instant) {
        let persisted = {
            let mut ring = self.ring.lock().unwrap_or_else(|error| error.into_inner());
            ring.in_flight -= 1;
            let now = Instant::now();
            ring.prune(now);
            ring.last_sequence += 1;
            record.sequence = ring.last_sequence;
            record.timestamp_unix_ms = SystemTime::now().duration_since(UNIX_EPOCH)
                .unwrap_or_default().as_millis() as u64;
            record.duration_ms = now.duration_since(started).as_millis() as u64;
            let persisted = self.history.as_ref().map(|_| to_persisted_record(&record));
            // Identity metadata is set only by the verified transport: OAuth
            // authorization, or the process-owned local stdio connection.
            let buffer = if record.provider.is_some() {
                &mut ring.verified
            } else {
                &mut ring.unverified
            };
            buffer.push(now, record);
            persisted
        };
        if let (Some(history), Some(persisted)) = (&self.history, persisted) {
            history.enqueue(persisted);
        }
    }
}

fn to_persisted_record(record: &Record) -> PersistedAuditRecord {
    let error_code = record.error_code.map(|code| match code {
        ErrorCode::Named(name) => PersistedErrorCode::Named(name.to_owned()),
        ErrorCode::Rpc(rpc) => PersistedErrorCode::Rpc(rpc),
    });
    PersistedAuditRecord::from_fields(
        record.timestamp_unix_ms,
        record.sequence,
        &record.boot_id,
        record.session_id.as_deref(),
        record.provider,
        record.client_id_sha256.as_deref(),
        record.catalogue_sha256.as_deref(),
        record.method,
        record.tool_name,
        record.outcome.as_str(),
        record.http_status,
        error_code,
        record.duration_ms,
    ).with_activity(record.activity.as_ref())
}

// Deserialize only maps while still letting the field structs skip unused values.
struct JsonObject<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for JsonObject<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor<T>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
            type Value = JsonObject<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                T::deserialize(MapAccessDeserializer::new(map)).map(JsonObject)
            }
        }

        deserializer.deserialize_map(ObjectVisitor(PhantomData))
    }
}

#[derive(Deserialize)]
struct Frame<'a> {
    #[serde(borrow)]
    method: Option<Cow<'a, str>>,
}

#[derive(Deserialize)]
struct CallFrame<'a> {
    #[serde(borrow)]
    params: Option<JsonObject<CallParams<'a>>>,
}

#[derive(Deserialize)]
struct CallParams<'a> {
    #[serde(borrow)]
    name: Option<Cow<'a, str>>,
}

pub(crate) fn requested_tool(frame: &str) -> Option<String> {
    let JsonObject(call) = serde_json::from_str::<JsonObject<CallFrame<'_>>>(frame).ok()?;
    call.params?.0.name.map(Cow::into_owned)
}

fn allowlisted(value: Option<&str>, names: &[&'static str]) -> &'static str {
    names.iter().copied().find(|name| Some(*name) == value).unwrap_or("other")
}

pub(crate) struct RequestObservation {
    audit: Option<Arc<RequestAudit>>,
    started: Instant,
    details: RequestDetails,
    completion: Completion,
}

#[derive(Clone, Copy)]
enum Completion {
    Pending,
    Http(StatusCode),
    Stdio,
    Silent,
}

// The worker can add metadata, but only the transport owns finalization.
#[derive(Clone)]
pub(crate) struct RequestDetails(Option<Arc<Mutex<Option<Record>>>>);

impl RequestObservation {
    pub(crate) fn new(audit: Option<Arc<RequestAudit>>) -> Self {
        let started = Instant::now();
        if let Some(audit) = &audit {
            audit.begin();
        }
        let details = RequestDetails(audit.as_ref().map(|audit| {
            Arc::new(Mutex::new(Some(Record {
                timestamp_unix_ms: 0,
                sequence: 0,
                boot_id: audit.boot_id.clone(),
                session_id: None,
                provider: None,
                client_id_sha256: None,
                catalogue_sha256: None,
                method: "other",
                tool_name: None,
                outcome: Outcome::HttpRefusal,
                http_status: None,
                error_code: Some(ErrorCode::Named("request_interrupted")),
                duration_ms: 0,
                activity: None,
            })))
        }));
        Self { audit, started, details, completion: Completion::Pending }
    }

    pub(crate) fn oauth(audit: Arc<RequestAudit>, event: OAuthEvent) -> Self {
        let observation = Self::new(Some(audit));
        observation.details.update(|record| record.method = event.method());
        observation
    }

    pub(crate) fn details(&self) -> &RequestDetails {
        &self.details
    }

    pub(crate) fn complete(mut self, status: StatusCode) {
        self.completion = Completion::Http(status);
    }

    pub(crate) fn complete_stdio(mut self) {
        self.completion = Completion::Stdio;
    }

    pub(crate) fn discard_silent(mut self) {
        self.completion = Completion::Silent;
    }
}

impl RequestDetails {
    fn update(&self, update: impl FnOnce(&mut Record)) {
        if let Some(record) = &self.0 {
            let mut record = record.lock().unwrap_or_else(|error| error.into_inner());
            if let Some(record) = record.as_mut() {
                update(record);
            }
        }
    }

    pub(crate) fn observe_frame(&self, bytes: &[u8]) {
        if self.0.is_none() {
            return;
        }
        if let Ok(JsonObject(frame)) = serde_json::from_slice::<JsonObject<Frame<'_>>>(bytes) {
            let method = allowlisted(frame.method.as_deref(), METHODS);
            let tool_name = (method == "tools/call").then(|| {
                let params = serde_json::from_slice::<JsonObject<CallFrame<'_>>>(bytes)
                    .ok()
                    .and_then(|JsonObject(call)| call.params);
                let name = params.as_ref().and_then(|JsonObject(params)| params.name.as_deref());
                audit_tool_name(name)
            });
            self.update(|record| {
                record.method = method;
                record.tool_name = tool_name;
            });
        }
    }

    pub(crate) fn observe_oauth_client(&self, identity: &VerifiedOAuthClient) {
        let provider = match identity.provider() {
            ConnectorClient::Gemini => "gemini",
            ConnectorClient::ChatGpt => "chatgpt",
        };
        self.update(|record| {
            record.provider = Some(provider);
            record.client_id_sha256 = Some(identity.client_id_sha256().to_owned());
        });
    }

    pub(crate) fn observe_identity(&self, identity: &AuthorizedIdentity, catalogue_sha256: Option<&str>) -> Client {
        let provider = match identity.provider {
            ConnectorClient::Gemini => "gemini",
            ConnectorClient::ChatGpt => "chatgpt",
        };
        let client_hash: String = Sha256::digest(identity.client_id.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
        self.update(|record| {
            record.provider = Some(provider);
            record.client_id_sha256 = Some(client_hash.clone());
            record.catalogue_sha256 = catalogue_sha256.map(str::to_owned);
        });
        Client::OAuth { provider, client_hash }
    }

    /// Called only by the process-owned stdio transport, never from a frame.
    pub(crate) fn observe_stdio(&self) -> Client {
        self.update(|record| {
            record.provider = Some("local");
            record.client_id_sha256 = None;
            record.catalogue_sha256 = None;
        });
        Client::Local("stdio")
    }

    pub(crate) fn observe_session_id(&self, session_id: String) {
        if !is_valid_session_id(&session_id) {
            return;
        }
        self.update(|record| {
            record.session_id = Some(session_id);
        });
    }

    pub(crate) fn observe_activity(&self, activity: Option<ActivityAttribution>) {
        self.update(|record| { record.activity = activity; });
    }

    pub(crate) fn refuse(&self, code: ErrorCode) {
        self.update(|record| {
            record.outcome = Outcome::HttpRefusal;
            record.error_code = Some(code);
        });
    }

    pub(crate) fn stdio_failed(&self, code: ErrorCode) {
        self.update(|record| {
            record.outcome = Outcome::TransportError;
            record.error_code = Some(code);
        });
    }

    pub(crate) fn routed(&self, response: ResponseMetadata) {
        let (outcome, error_code) = if let Some(code) = response.error_code {
            (Outcome::JsonrpcError, Some(ErrorCode::Rpc(code)))
        } else if response.is_tool_error {
            (Outcome::ToolError, Some(ErrorCode::Named("tool_error")))
        } else {
            (Outcome::Success, None)
        };
        self.update(|record| {
            record.outcome = outcome;
            record.error_code = error_code;
        });
    }
}

impl Drop for RequestObservation {
    fn drop(&mut self) {
        if let (Some(audit), Some(record)) = (&self.audit, &self.details.0) {
            let mut record = record.lock().unwrap_or_else(|error| error.into_inner()).take()
                .expect("request observation owns one record");
            let delivered = match self.completion {
                Completion::Http(status) => {
                    record.http_status = Some(status.as_u16());
                    status.is_success()
                }
                Completion::Stdio => record.provider == Some("local"),
                Completion::Silent => {
                    audit.finish_silent();
                    return;
                }
                Completion::Pending => {
                    record.outcome = if record.provider == Some("local") {
                        Outcome::TransportError
                    } else {
                        Outcome::HttpRefusal
                    };
                    record.error_code = Some(ErrorCode::Named("request_interrupted"));
                    false
                }
            };
            // Only a completed, authorized tool success may carry attribution.
            // An interrupted transport must not persist a tentative receipt.
            if record.outcome != Outcome::Success || !delivered
                || record.provider.is_none() || record.method != "tools/call"
                || !record.tool_name.is_some_and(crate::audit_history::is_activity_tool) {
                record.activity = None;
            }
            audit.finish(record, self.started);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_bridge_oauth_server::{Audience, CapabilityIdentity};

    fn complete_verified_request(audit: &Arc<RequestAudit>) {
        let observation = RequestObservation::new(Some(audit.clone()));
        observation.details().observe_identity(&AuthorizedIdentity {
            client_id: "audit-test-client".to_owned(),
            provider: ConnectorClient::Gemini,
            audience: Audience::Workstation,
            scope: "mcp".to_owned(),
            resource: "https://workstation.example/mcp".to_owned(),
            capability: CapabilityIdentity::Legacy,
        }, None);
        observation.details().routed(ResponseMetadata::default());
        observation.complete(StatusCode::OK);
    }

    #[test]
    fn request_audit_classifies_methods_independently_of_the_tool_name() {
        let audit = Arc::new(RequestAudit::new().unwrap());
        for method in ["ping", "tools/list", "tools/call"] {
            let observation = RequestObservation::new(Some(audit.clone()));
            let frame = serde_json::json!({"jsonrpc":"2.0", "id":1,
                "method":method, "params":{"name":7}});
            observation.details().observe_frame(frame.to_string().as_bytes());
        }

        let snapshot = audit.snapshot();
        assert_eq!(snapshot.records.len(), 3);
        assert_eq!(snapshot.records[0].method, "ping");
        assert_eq!(snapshot.records[0].tool_name, None);
        assert_eq!(snapshot.records[1].method, "tools/list");
        assert_eq!(snapshot.records[1].tool_name, None);
        assert_eq!(snapshot.records[2].method, "tools/call");
        assert_eq!(snapshot.records[2].tool_name, Some("other"));
    }

    #[test]
    fn request_audit_requires_objects_for_request_and_tool_params() {
        let audit = Arc::new(RequestAudit::new().unwrap());
        for (frame, expected_method, expected_tool) in [
            (r#"["ping"]"#, "other", None),
            (r#"{"method":"tools/call","params":["agent_bridge_status"]}"#,
                "tools/call", Some("other")),
            (r#"{"method":"tools/call","params":{"name":"agent_bridge_status"}}"#,
                "tools/call", Some("agent_bridge_status")),
        ] {
            let observation = RequestObservation::new(Some(audit.clone()));
            observation.details().observe_frame(frame.as_bytes());
            observation.complete(StatusCode::OK);

            let snapshot = audit.snapshot();
            let record = snapshot.records.last().unwrap();
            assert_eq!(record.method, expected_method, "{frame}");
            assert_eq!(record.tool_name, expected_tool, "{frame}");
        }
    }

    #[test]
    fn request_audit_filters_names_and_classifies_a_tool_error_with_http_200() {
        let audit = Arc::new(RequestAudit::new().unwrap());
        let observation = RequestObservation::new(Some(audit.clone()));
        observation.details().observe_frame(br#"{
            "method":"tools/call","params":{"name":"private-tool","arguments":{"value":"private-argument"}}
        }"#);
        observation.details().routed(ResponseMetadata::read(r#"{
            "result":{"isError":true,"content":[{"type":"text","text":"private-result"}]}
        }"#));
        observation.complete(StatusCode::OK);

        let snapshot = serde_json::to_value(audit.snapshot()).unwrap();
        let record = &snapshot["records"][0];
        assert_eq!(record["method"], "tools/call");
        assert_eq!(record["tool_name"], "other");
        assert_eq!(record["outcome"], "tool_error");
        assert_eq!(record["http_status"], 200);
        assert!(!snapshot.to_string().contains("private-"));
    }

    #[test]
    fn request_audit_lifecycle_outcomes_are_closed_and_have_no_http_status() {
        let audit = Arc::new(RequestAudit::new().unwrap());
        drop(StartupObservation::new(audit.clone(), Instant::now()));
        StartupObservation::new(audit.clone(), Instant::now()).complete();
        audit.record_lifecycle(LifecycleEvent::ServiceStopped, Instant::now());
        audit.record_lifecycle(LifecycleEvent::TunnelExited, Instant::now());

        let snapshot = serde_json::to_value(audit.snapshot()).unwrap();
        let records = snapshot["records"].as_array().unwrap();
        assert_eq!(records.len(), 4);
        assert_eq!(records[0]["method"], "service/start");
        assert_eq!(records[0]["outcome"], "lifecycle_error");
        assert_eq!(records[0]["error_code"], "service_start_failed");
        assert_eq!(records[1]["method"], "service/start");
        assert_eq!(records[1]["outcome"], "success");
        assert!(records[1]["error_code"].is_null());
        assert_eq!(records[2]["method"], "service/stop");
        assert_eq!(records[3]["method"], "tunnel/exit");
        assert_eq!(records[3]["error_code"], "tunnel_exited");
        for (index, record) in records.iter().enumerate() {
            assert_eq!(record["sequence"], serde_json::json!(index + 1));
            for key in ["http_status", "provider", "client_id_sha256", "catalogue_sha256", "tool_name"] {
                assert!(record[key].is_null());
            }
        }
        assert_eq!(snapshot["in_flight"], 0);
    }

    #[test]
    fn request_audit_snapshot_accounts_for_unfinished_requests() {
        let audit = Arc::new(RequestAudit::new().unwrap());
        let observation = RequestObservation::new(Some(audit.clone()));
        let snapshot = audit.snapshot();
        assert_eq!(snapshot.in_flight, 1);
        assert!(snapshot.records.is_empty());

        observation.details().routed(ResponseMetadata::default());
        observation.complete(StatusCode::OK);

        let snapshot = audit.snapshot();
        assert_eq!(snapshot.in_flight, 0);
        assert_eq!(snapshot.records.len(), 1);
        assert_eq!(snapshot.records[0].sequence, 1);

        drop(RequestObservation::new(Some(audit.clone())));
        let snapshot = serde_json::to_value(audit.snapshot()).unwrap();
        assert_eq!(snapshot["in_flight"], 0);
        assert_eq!(snapshot["records"][1]["error_code"], "request_interrupted");
        assert!(snapshot["records"][1]["http_status"].is_null());
    }

    #[test]
    fn request_audit_preserves_verified_records_during_unauthenticated_refusals() {
        let audit = Arc::new(RequestAudit::new().unwrap());
        complete_verified_request(&audit);

        for _ in 0..2048 {
            let observation = RequestObservation::new(Some(audit.clone()));
            observation.details().refuse(ErrorCode::Named("unauthorized"));
            observation.complete(StatusCode::UNAUTHORIZED);
        }
        complete_verified_request(&audit);

        let snapshot = serde_json::to_value(audit.snapshot()).unwrap();
        let records = snapshot["records"].as_array().unwrap();
        assert_eq!(records[0]["sequence"], 1);
        assert_eq!(records[0]["provider"], "gemini");
        assert_eq!(records.len(), 258);
        assert_eq!(records[1]["sequence"], 1794);
        assert_eq!(records[1]["http_status"], 401);
        assert_eq!(records[257]["sequence"], 2050);
        assert_eq!(records[257]["provider"], "gemini");
        assert_eq!(snapshot["evicted_verified"], 0);
        assert_eq!(snapshot["evicted_unverified"], 1792);
        assert_eq!(snapshot["evicted"], 1792);
    }

    #[test]
    fn request_audit_evicts_by_count_and_monotonic_age_on_read() {
        let audit = Arc::new(RequestAudit::new().unwrap());
        let start = Instant::now();
        for _ in 0..=VERIFIED_CAPACITY {
            complete_verified_request(&audit);
        }
        for _ in 0..UNVERIFIED_CAPACITY {
            drop(RequestObservation::new(Some(audit.clone())));
        }
        let snapshot = audit.snapshot();
        assert_eq!(snapshot.records.len(), 2048);
        assert_eq!(snapshot.evicted, 1);
        assert_eq!(snapshot.evicted_verified, 1);
        assert_eq!(snapshot.evicted_unverified, 0);
        assert_eq!(snapshot.records.first().unwrap().sequence, 2);
        assert_eq!(snapshot.records.last().unwrap().sequence, 2049);

        let late = Instant::now();
        let snapshot = audit.snapshot_at(start + Duration::from_secs(23 * 60 * 60));
        assert_eq!(snapshot.records.len(), 2048);
        let snapshot = audit.snapshot_at(late + Duration::from_secs(24 * 60 * 60));
        assert!(snapshot.records.is_empty());
        assert_eq!(snapshot.evicted, 2049);
        assert_eq!(snapshot.evicted_verified, 1793);
        assert_eq!(snapshot.evicted_unverified, 256);
        assert_eq!(snapshot.boot_id, audit.snapshot().boot_id);
    }

    #[test]
    fn request_audit_persists_mcp_and_restricted_events_across_restart() {
        use crate::audit_history::AuditEventKind;
        use std::sync::atomic::{AtomicU64, Ordering};

        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = crate::test_state_base().join(format!(
            "ab-req-audit-restart-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let history_dir = root.join("audit-history");
        let opaque_sid = "0123456789abcdef0123456789abcdef".to_owned();

        let boot1 = {
            let audit = Arc::new(
                RequestAudit::open_with_history_dir(&history_dir, AuditHistoryConfig::default())
                    .unwrap(),
            );
            let obs = RequestObservation::new(Some(audit.clone()));
            obs.details().observe_frame(
                br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"agent_bridge_status","arguments":{"secret":"private-arg"}}}"#,
            );
            obs.details().observe_session_id("raw-client-id-must-be-rejected".to_owned());
            obs.details().observe_session_id(opaque_sid.clone());
            obs.details().routed(ResponseMetadata::default());
            obs.complete(StatusCode::OK);

            let token = RequestObservation::oauth(Arc::clone(&audit), OAuthEvent::Token);
            token.details().routed(ResponseMetadata::default());
            token.complete(StatusCode::OK);
            assert!(audit.flush_history(Duration::from_secs(2)));
            audit.boot_id.clone()
        };

        let audit2 = Arc::new(
            RequestAudit::open_with_history_dir(&history_dir, AuditHistoryConfig::default())
                .unwrap(),
        );
        audit2.record_lifecycle(LifecycleEvent::ServiceStopFailed, Instant::now());
        assert!(audit2.flush_history(Duration::from_secs(2)));

        let diag = audit2.history_diagnostics();
        assert!(diag.available);
        assert_eq!(diag.lost, 0);
        assert_eq!(diag.records.len(), 3);
        assert!(diag.records.iter().any(|row| row.event_kind == AuditEventKind::OAuth
            && row.method == "oauth/token" && row.outcome == "success"));
        assert!(diag.records.iter().any(|row| row.event_kind == AuditEventKind::Lifecycle
            && row.method == "service/stop" && row.outcome == "lifecycle_error"));
        let serialized = serde_json::to_string(&diag).unwrap();
        assert!(!serialized.contains("private-arg"));
        assert!(!serialized.contains("raw-client-id"));
        assert!(!serialized.contains("raw-oauth-client-id"));

        let mcp_only = audit2.query_history(&AuditHistoryFilter {
            boot_id: Some(boot1),
            event_kind: Some(AuditEventKind::McpRequest),
            ..AuditHistoryFilter::default()
        });
        assert_eq!(mcp_only.records.len(), 1);
        assert_eq!(mcp_only.records[0].session_id.as_deref(), Some(opaque_sid.as_str()));
        assert_eq!(mcp_only.records[0].tool_name.as_deref(), Some("agent_bridge_status"));

        drop(audit2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn request_audit_optional_history_degrades_safely_on_unusable_dir() {
        let bad_dir = Path::new("relative/unsafe/audit-history");
        let audit = RequestAudit::open_with_optional_history_dir(Some(bad_dir)).unwrap();
        assert!(!audit.history_available());
        let obs = RequestObservation::new(Some(Arc::new(audit)));
        obs.details().routed(ResponseMetadata::default());
        obs.complete(StatusCode::OK);
    }
}


#[cfg(test)]
mod activity_correlation_tests {
    use super::*;
    use agent_bridge_oauth_server::{Audience, CapabilityIdentity};
    use serde_json::{json, Value};

    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    fn invoke(
        audit: &Arc<RequestAudit>, router: &crate::runtime::Router, client_id: &str,
        tool: &str, args: Value, response_limit: usize, complete: bool,
    ) -> Value {
        let observation = RequestObservation::new(Some(audit.clone()));
        let frame = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":tool,"arguments":args}}).to_string();
        observation.details().observe_frame(frame.as_bytes());
        let client = observation.details().observe_identity(&AuthorizedIdentity {
            client_id: client_id.to_owned(), provider: ConnectorClient::ChatGpt,
            audience: Audience::Workstation, scope: "mcp".into(),
            resource: "https://fixture.invalid/mcp".into(),
            capability: CapabilityIdentity::Legacy,
        }, Some(&"a".repeat(64)));
        let (response, session, activity) = audit.sessions.dispatch_observed(
            client, router, &frame, response_limit, || router.handle_str(&frame));
        if let Some(session) = session {
            observation.details().observe_session_id(session);
        }
        observation.details().observe_activity(activity);
        let response = response.expect("fixture produces a reply");
        if response.len() > response_limit {
            observation.details().refuse(ErrorCode::Named("response_exceeds_limit"));
            if complete { observation.complete(StatusCode::INTERNAL_SERVER_ERROR); }
        } else {
            observation.details().routed(ResponseMetadata::read(&response));
            if complete { observation.complete(StatusCode::OK); }
        }
        let result: Value = serde_json::from_str(&response).unwrap();
        if result["result"]["isError"] == true || result.get("error").is_some() {
            return Value::Null;
        }
        serde_json::from_str(result["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
    }

    #[test]
    fn activity_is_server_confirmed_per_request_and_survives_history_reopen() {
        let root = crate::test_state_base().join(format!("correlation-{}",
            agent_bridge_missions::operator::random_token_hex(16)));
        let _cleanup = Cleanup(root.clone());
        std::fs::create_dir_all(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let db = root.join("core.sqlite");
        drop(agent_bridge_core::CoreDatabase::initialize_new(&db).unwrap());
        let router = crate::runtime::missions(&db).unwrap();
        let history = root.join("history");
        let audit = Arc::new(RequestAudit::open_with_history_dir(&history, AuditHistoryConfig::default()).unwrap());
        let call = |client, tool, args| invoke(&audit, &router, client, tool, args, usize::MAX, true);
        let a = call("synthetic-client-a", "agent_bridge_context_create", json!({}));
        let b = call("synthetic-client-b", "agent_bridge_context_create", json!({}));
        let ha = a["context_handle"].as_str().unwrap();
        let hb = b["context_handle"].as_str().unwrap();
        let ca = a["context_id"].as_str().unwrap();
        let cb = b["context_id"].as_str().unwrap();
        let fake = format!("mis_{}", "f".repeat(32));
        let ma = call("synthetic-client-a", "agent_bridge_mission_create", json!({
            "actor_context_handle":ha,"goal":format!("{fake} {hb} private-goal"),
            "idempotency_key":"private-create-a"
        }));
        let mb = call("synthetic-client-b", "agent_bridge_mission_create", json!({
            "actor_context_handle":hb,"goal":format!("{ca} private-goal"),
            "idempotency_key":"private-create-b"
        }));
        let mid_a = ma["mission_id"].as_str().unwrap();
        let mid_b = mb["mission_id"].as_str().unwrap();
        let read_a = json!({"actor_context_handle":ha,"mission_id":mid_a});
        let read_b = json!({"actor_context_handle":hb,"mission_id":mid_b});
        assert!(call("synthetic-client-a","agent_bridge_mission_get",read_a.clone()).is_object());
        assert!(call("synthetic-client-b","agent_bridge_mission_get",read_b.clone()).is_object());
        assert!(call("synthetic-client-a","agent_bridge_mission_get",json!({
            "actor_context_handle":ha,"mission_id":mid_b})).is_null());
        assert!(call("synthetic-client-b","agent_bridge_mission_get",json!({
            "actor_context_handle":cb,"mission_id":mid_b})).is_null());
        assert!(call("synthetic-client-a","agent_bridge_mission_checkpoints",read_a.clone()).is_array());
        assert!(call("synthetic-client-b","agent_bridge_mission_subtask_list",read_b.clone()).is_object());
        assert!(call("synthetic-client-a","agent_bridge_mission_list",json!({"actor_context_handle":ha})).is_array());
        // No admission for an oversized response, even though the handler
        // completed its authorization and produced a valid internal receipt.
        invoke(&audit,&router,"synthetic-client-a","agent_bridge_mission_get",read_a.clone(),1,true);
        // No durable attribution if the HTTP owner disappears before finalization.
        invoke(&audit,&router,"synthetic-client-b","agent_bridge_mission_get",read_b.clone(),usize::MAX,false);
        let snapshot=serde_json::to_value(audit.snapshot()).unwrap();
        let records=snapshot["records"].as_array().unwrap();
        assert_eq!(records.len(),13);
        assert_eq!(records[0]["context_id"],ca);
        assert!(records[0].get("mission_id").is_none());
        assert_eq!(records[2]["mission_id"],mid_a);
        assert_eq!(records[3]["mission_id"],mid_b);
        assert_eq!(records[4]["context_id"],ca);
        assert_eq!(records[5]["context_id"],cb);
        for index in [6,7,11,12] {
            assert!(records[index].get("context_id").is_none(), "refusal/interruption was attributed");
            assert!(records[index].get("mission_id").is_none());
        }
        assert_eq!(records[8]["mission_id"],mid_a, "empty checkpoint list still has a confirmed target");
        assert_eq!(records[9]["mission_id"],mid_b, "empty subtask page still has a confirmed target");
        assert_eq!(records[10]["context_id"],ca);
        assert!(records[10].get("mission_id").is_none(), "multi-mission listing is not a unique target");
        assert_ne!(records[4]["session_id"],records[5]["session_id"]);
        let sessions=audit.sessions.snapshot(&audit.boot_id,None,None).unwrap();
        let sessions=sessions["sessions"].as_array().unwrap();
        assert_eq!(sessions.len(),2);
        for (context,mission,foreign) in [(ca,mid_a,mid_b),(cb,mid_b,mid_a)] {
            let session=sessions.iter().find(|s| s["context_ids"].as_array().unwrap()
                .iter().any(|id| id==context)).unwrap();
            assert!(session["tool_calls"].as_array().unwrap().iter().any(|t| t["mission_id"]==mission));
            assert!(!session["tool_calls"].as_array().unwrap().iter().any(|t| t["mission_id"]==foreign));
            assert!(session["tool_calls"].as_array().unwrap().iter().all(|t| t["context_id"]==context));
        }
        let boot=audit.boot_id.clone();
        assert!(audit.flush_history(Duration::from_secs(2)));
        let history_before=audit.history_diagnostics();
        assert_eq!(history_before.records.len(),13);
        assert_eq!(history_before.lost,0);
        for forbidden in [ha,hb,fake.as_str(),"private-goal","private-create-a","synthetic-client-a"] {
            assert!(!snapshot.to_string().contains(forbidden));
            assert!(!serde_json::to_string(&history_before).unwrap().contains(forbidden));
        }
        drop(audit);
        let reopened=Arc::new(RequestAudit::open_with_history_dir(&history,AuditHistoryConfig::default()).unwrap());
        assert_ne!(reopened.boot_id,boot);
        let old=reopened.query_history(&AuditHistoryFilter {
            boot_id:Some(boot), context_id:Some(ca.to_owned()), mission_id:Some(mid_a.to_owned()),
            ..AuditHistoryFilter::default()
        });
        assert!(old.available);
        assert_eq!(old.records.len(),3);
        assert!(old.records.iter().all(|row| row.context_id.as_deref()==Some(ca)
            && row.mission_id.as_deref()==Some(mid_a)));
        let resumed=invoke(&reopened,&router,"synthetic-client-a","agent_bridge_mission_get",read_a,usize::MAX,true);
        assert_eq!(resumed["mission_id"],mid_a);
        let latest=serde_json::to_value(reopened.snapshot()).unwrap();
        assert_eq!(latest["records"][0]["context_id"],ca);
        assert_eq!(latest["records"][0]["mission_id"],mid_a);
        assert_ne!(latest["records"][0]["session_id"],records[4]["session_id"]);
    }

    #[test]
    fn activity_history_accepts_old_records_and_rejects_impossible_attribution() {
        let record=PersistedAuditRecord::from_fields(
            1,1,&"a".repeat(32),None,Some("chatgpt"),Some(&"b".repeat(64)),None,
            "tools/call",Some("agent_bridge_mission_get"),"success",Some(200),None,1);
        let old=serde_json::to_value(&record).unwrap();
        assert!(old.get("context_id").is_none() && old.get("mission_id").is_none());
        let decoded: PersistedAuditRecord=serde_json::from_value(old.clone()).unwrap();
        assert!(decoded.validate_persisted_record());
        let mut invalid=old.clone();
        invalid["mission_id"]=json!(format!("mis_{}", "a".repeat(32)));
        assert!(!serde_json::from_value::<PersistedAuditRecord>(invalid).unwrap().validate_persisted_record());
        let mut invalid=old;
        invalid["context_id"]=json!(format!("ctx_{}", "b".repeat(32)));
        invalid["outcome"]=json!("tool_error");
        assert!(!serde_json::from_value::<PersistedAuditRecord>(invalid).unwrap().validate_persisted_record());
    }
}
