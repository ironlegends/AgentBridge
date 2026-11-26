//! Operator-only diagnostics for requests reaching the OAuth MCP listener.

use crate::capability_manifest::COMPLETE_TOOL_NAMES;
use crate::runtime::RuntimeError;
use agent_bridge_http::modern::ResponseMetadata;
use agent_bridge_oauth_server::{AuthorizedIdentity, ConnectorClient};
use axum::http::StatusCode;
use serde::de::{value::MapAccessDeserializer, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::VecDeque;
use std::fmt;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CAPACITY: usize = 2048;
const UNVERIFIED_CAPACITY: usize = 256;
const VERIFIED_CAPACITY: usize = CAPACITY - UNVERIFIED_CAPACITY;
const MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);
const METHODS: &[&str] = &[
    "initialize",
    "notifications/initialized",
    "ping",
    "server/discover",
    "tools/list",
    "tools/call",
];

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Success,
    ToolError,
    JsonrpcError,
    HttpRefusal,
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
    provider: Option<&'static str>,
    client_id_sha256: Option<String>,
    catalogue_sha256: Option<String>,
    method: &'static str,
    tool_name: Option<&'static str>,
    outcome: Outcome,
    http_status: Option<u16>,
    error_code: Option<ErrorCode>,
    duration_ms: u64,
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
    boot_id: String,
    ring: Mutex<Ring>,
}

impl RequestAudit {
    pub(crate) fn new() -> Result<Self, RuntimeError> {
        let mut boot_bytes = [0u8; 16];
        getrandom::getrandom(&mut boot_bytes).map_err(|_| "Request audit randomness unavailable")?;
        Ok(Self {
            boot_id: boot_bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
            ring: Mutex::new(Ring {
                verified: RecordBuffer::new(VERIFIED_CAPACITY),
                unverified: RecordBuffer::new(UNVERIFIED_CAPACITY),
                last_sequence: 0,
                in_flight: 0,
            }),
        })
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

    fn begin(&self) {
        let mut ring = self.ring.lock().unwrap_or_else(|error| error.into_inner());
        ring.in_flight += 1;
    }

    fn finish(&self, mut record: Record, started: Instant) {
        let mut ring = self.ring.lock().unwrap_or_else(|error| error.into_inner());
        ring.in_flight -= 1;
        let now = Instant::now();
        ring.prune(now);
        ring.last_sequence += 1;
        record.sequence = ring.last_sequence;
        record.timestamp_unix_ms = SystemTime::now().duration_since(UNIX_EPOCH)
            .unwrap_or_default().as_millis() as u64;
        record.duration_ms = now.duration_since(started).as_millis() as u64;
        // Identity metadata is set only after OAuth verifies the client.
        let buffer = if record.provider.is_some() {
            &mut ring.verified
        } else {
            &mut ring.unverified
        };
        buffer.push(now, record);
    }
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

fn allowlisted(value: Option<&str>, names: &[&'static str]) -> &'static str {
    names.iter().copied().find(|name| Some(*name) == value).unwrap_or("other")
}

pub(crate) struct RequestObservation {
    audit: Option<Arc<RequestAudit>>,
    started: Instant,
    details: RequestDetails,
    status: Option<StatusCode>,
}

// The worker can add metadata, but only the HTTP handler owns finalization.
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
                provider: None,
                client_id_sha256: None,
                catalogue_sha256: None,
                method: "other",
                tool_name: None,
                outcome: Outcome::HttpRefusal,
                http_status: None,
                error_code: Some(ErrorCode::Named("request_interrupted")),
                duration_ms: 0,
            })))
        }));
        Self { audit, started, details, status: None }
    }

    pub(crate) fn details(&self) -> &RequestDetails {
        &self.details
    }

    pub(crate) fn complete(mut self, status: StatusCode) {
        self.status = Some(status);
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
                allowlisted(
                    params.as_ref().and_then(|JsonObject(params)| params.name.as_deref()),
                    COMPLETE_TOOL_NAMES,
                )
            });
            self.update(|record| {
                record.method = method;
                record.tool_name = tool_name;
            });
        }
    }

    pub(crate) fn observe_identity(&self, identity: &AuthorizedIdentity, catalogue_sha256: Option<&str>) {
        self.update(|record| {
            record.provider = Some(match identity.provider {
                ConnectorClient::Gemini => "gemini",
                ConnectorClient::ChatGpt => "chatgpt",
            });
            record.client_id_sha256 = Some(format!("{:x}", Sha256::digest(identity.client_id.as_bytes())));
            record.catalogue_sha256 = catalogue_sha256.map(str::to_owned);
        });
    }

    pub(crate) fn refuse(&self, code: ErrorCode) {
        self.update(|record| {
            record.outcome = Outcome::HttpRefusal;
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
            if let Some(status) = self.status {
                record.http_status = Some(status.as_u16());
            } else {
                record.outcome = Outcome::HttpRefusal;
                record.error_code = Some(ErrorCode::Named("request_interrupted"));
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
}
