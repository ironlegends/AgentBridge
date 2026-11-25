// Copyright 2026 agent-bridge contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Local IPv4 loopback HTTP transport for MCP (`127.0.0.1` only).
//!
//! Exposes `POST /mcp` (JSON-RPC requests and notifications dispatched via a
//! caller-provided gateway callback) and `GET /health` (injected health
//! status), without event replay, content logging, tool implementations, or
//! non-loopback network binding.

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use http_body_util::BodyExt;
use serde::Serialize;
use serde_json::{json, Value};
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};

/// Default maximum request and response payload size in bytes (1 MiB).
pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

/// Default maximum number of concurrent in-flight `/mcp` dispatches.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 64;

const CONTENT_TYPE_JSON_UTF8: &str = "application/json; charset=utf-8";

/// Callback bridging HTTP `/mcp` payloads to the synchronous MCP gateway.
pub type DispatchFn = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Callback returning the current health state for `GET /health`.
pub type HealthFn = Arc<dyn Fn() -> HealthStatus + Send + Sync>;

/// Policy applied when an HTTP request carries an `Origin` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginPolicy {
    /// Reject every request carrying an `Origin` header.
    RejectAll,
    /// Allow only `http://127.0.0.1[:port]` and `http://localhost[:port]` origins.
    LoopbackHttp,
    /// Allow only exact origins listed by the caller.
    AllowList(Vec<String>),
}

impl Default for OriginPolicy {
    fn default() -> Self {
        Self::LoopbackHttp
    }
}

/// Configuration for the local MCP HTTP transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpServerConfig {
    /// Maximum accepted bytes for a `POST /mcp` request body.
    pub max_request_body_bytes: usize,
    /// Maximum emitted bytes for a `POST /mcp` response body.
    pub max_response_body_bytes: usize,
    /// Maximum concurrent in-flight `/mcp` dispatch calls.
    pub max_in_flight: usize,
    /// Validation policy for requests including an `Origin` header.
    pub origin_policy: OriginPolicy,
    /// Optional upper bound for waiting on in-flight operations during shutdown.
    /// `None` waits until all admitted operations finish.
    pub shutdown_timeout: Option<Duration>,
}

impl Default for HttpServerConfig {
    fn default() -> Self {
        Self {
            max_request_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_response_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            origin_policy: OriginPolicy::default(),
            shutdown_timeout: None,
        }
    }
}

impl HttpServerConfig {
    pub fn with_max_request_body_bytes(mut self, max_bytes: usize) -> Self {
        self.max_request_body_bytes = max_bytes;
        self
    }

    pub fn with_max_response_body_bytes(mut self, max_bytes: usize) -> Self {
        self.max_response_body_bytes = max_bytes;
        self
    }

    pub fn with_max_in_flight(mut self, max_in_flight: usize) -> Self {
        self.max_in_flight = max_in_flight.max(1);
        self
    }

    pub fn with_origin_policy(mut self, origin_policy: OriginPolicy) -> Self {
        self.origin_policy = origin_policy;
        self
    }

    pub fn with_shutdown_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.shutdown_timeout = timeout;
        self
    }
}

/// Health payload injected into `GET /health`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HealthStatus {
    pub healthy: bool,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl HealthStatus {
    pub fn ok() -> Self {
        Self {
            healthy: true,
            status: "ok".to_string(),
            details: None,
        }
    }

    pub fn unhealthy(status: impl Into<String>) -> Self {
        Self {
            healthy: false,
            status: status.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// Binds a TCP listener exclusively on IPv4 loopback `127.0.0.1:<port>`.
///
/// The caller must supply an explicit non-zero port; the bound listener is
/// returned to the supervisor before serving starts.
pub async fn bind_loopback(port: u16) -> io::Result<TcpListener> {
    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "port must be explicitly specified and non-zero",
        ));
    }

    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    TcpListener::bind(addr).await
}

/// Validates that an already-bound listener is strictly IPv4 `127.0.0.1` on a
/// non-zero port.
pub fn validate_loopback_listener(listener: &TcpListener) -> io::Result<SocketAddrV4> {
    match listener.local_addr()? {
        SocketAddr::V4(addr) if *addr.ip() == Ipv4Addr::LOCALHOST && addr.port() != 0 => Ok(addr),
        SocketAddr::V4(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MCP HTTP listener must be bound strictly to IPv4 loopback 127.0.0.1 on a non-zero port",
        )),
        SocketAddr::V6(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MCP HTTP listener must use IPv4 loopback 127.0.0.1 only; IPv6 listeners are rejected",
        )),
    }
}

/// Serves `/mcp` and `/health` using an already-bound IPv4 loopback listener.
///
/// Refuses any listener not bound to `127.0.0.1`. When `shutdown` resolves,
/// admission is closed immediately (`503 Service Unavailable` on new requests),
/// no new TCP connections are accepted, and the server waits for in-flight
/// operations to finish (or until `config.shutdown_timeout` expires).
pub async fn serve<D, H, S>(
    listener: TcpListener,
    config: HttpServerConfig,
    dispatch: D,
    health: H,
    shutdown: S,
) -> io::Result<()>
where
    D: Fn(&str) -> Option<String> + Send + Sync + 'static,
    H: Fn() -> HealthStatus + Send + Sync + 'static,
    S: Future<Output = ()> + Send + 'static,
{
    serve_managed(listener, config, ServiceActivity::default(), dispatch, health, shutdown).await
}

/// Use the same activity counter for stop admission and for dispatch, including
/// payload reads and blocking work that outlives a client disconnect.
#[derive(Clone)]
pub struct ServiceActivity(Arc<AdmissionGate>);

impl Default for ServiceActivity {
    fn default() -> Self {
        Self(Arc::new(AdmissionGate::new()))
    }
}

impl ServiceActivity {
    pub fn is_idle(&self) -> bool {
        self.0.inner.lock().is_ok_and(|state| !state.closing && state.in_flight == 0)
    }
}

pub async fn serve_managed<D, H, S>(
    listener: TcpListener,
    config: HttpServerConfig,
    activity: ServiceActivity,
    dispatch: D,
    health: H,
    shutdown: S,
) -> io::Result<()>
where
    D: Fn(&str) -> Option<String> + Send + Sync + 'static,
    H: Fn() -> HealthStatus + Send + Sync + 'static,
    S: Future<Output = ()> + Send + 'static,
{
    let bound_addr = validate_loopback_listener(&listener)?;
    let max_in_flight = config.max_in_flight.max(1);
    let shutdown_timeout = config.shutdown_timeout;
    let gate = activity.0;

    let state = Arc::new(AppState {
        bound_port: bound_addr.port(),
        config,
        dispatch: Arc::new(dispatch),
        health: Arc::new(health),
        gate: Arc::clone(&gate),
        concurrency: Arc::new(Semaphore::new(max_in_flight)),
    });

    let app = Router::new()
        .route(
            "/mcp",
            post(handle_mcp_post).fallback(handle_mcp_method_not_allowed),
        )
        .route(
            "/health",
            get(handle_health_get).fallback(handle_health_method_not_allowed),
        )
        .fallback(handle_not_found)
        .with_state(state);

    let gate_for_shutdown = Arc::clone(&gate);
    let shutdown_signal = async move {
        shutdown.await;
        gate_for_shutdown.close();
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    // Ensure admission is closed even if the listener stopped before `shutdown`.
    gate.close();

    match shutdown_timeout {
        Some(limit) => tokio::time::timeout(limit, gate.wait_drained())
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for in-flight MCP HTTP operations to drain",
                )
            }),
        None => {
            gate.wait_drained().await;
            Ok(())
        }
    }
}

/// Convenience helper that binds `127.0.0.1:<port>` and serves `/mcp` and `/health`.
pub async fn serve_on_port<D, H, S>(
    port: u16,
    config: HttpServerConfig,
    dispatch: D,
    health: H,
    shutdown: S,
) -> io::Result<()>
where
    D: Fn(&str) -> Option<String> + Send + Sync + 'static,
    H: Fn() -> HealthStatus + Send + Sync + 'static,
    S: Future<Output = ()> + Send + 'static,
{
    let listener = bind_loopback(port).await?;
    serve(listener, config, dispatch, health, shutdown).await
}

struct AppState {
    bound_port: u16,
    config: HttpServerConfig,
    dispatch: DispatchFn,
    health: HealthFn,
    gate: Arc<AdmissionGate>,
    concurrency: Arc<Semaphore>,
}

struct GateInner {
    closing: bool,
    in_flight: usize,
}

struct AdmissionGate {
    inner: Mutex<GateInner>,
    in_flight_tx: watch::Sender<usize>,
}

impl AdmissionGate {
    fn new() -> Self {
        let (in_flight_tx, _) = watch::channel(0usize);
        Self {
            inner: Mutex::new(GateInner {
                closing: false,
                in_flight: 0,
            }),
            in_flight_tx,
        }
    }

    fn is_closing(&self) -> bool {
        match self.inner.lock() {
            Ok(guard) => guard.closing,
            Err(poisoned) => poisoned.into_inner().closing,
        }
    }

    fn close(&self) {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.closing = true;
    }

    fn try_acquire(self: &Arc<Self>) -> Option<InFlightGuard> {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.closing {
            return None;
        }
        guard.in_flight += 1;
        self.in_flight_tx.send_replace(guard.in_flight);
        Some(InFlightGuard {
            gate: Arc::clone(self),
        })
    }

    async fn wait_drained(&self) {
        let mut rx = self.in_flight_tx.subscribe();
        let _ = rx.wait_for(|&count| count == 0).await;
    }
}

struct InFlightGuard {
    gate: Arc<AdmissionGate>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let mut guard = match self.gate.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.in_flight = guard.in_flight.saturating_sub(1);
        self.gate.in_flight_tx.send_replace(guard.in_flight);
    }
}

#[derive(Debug, Clone, Copy)]
struct HttpError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    allow: Option<&'static str>,
}

impl HttpError {
    fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
            allow: None,
        }
    }

    fn method_not_allowed(allow: &'static str, message: &'static str) -> Self {
        Self {
            status: StatusCode::METHOD_NOT_ALLOWED,
            code: "method_not_allowed",
            message,
            allow: Some(allow),
        }
    }

    fn into_response(self) -> Response {
        let payload = json!({
            "error": {
                "code": self.code,
                "message": self.message,
            }
        });
        let body = serde_json::to_vec(&payload).unwrap_or_else(|_| {
            br#"{"error":{"code":"internal_error","message":"failed to serialize error"}}"#.to_vec()
        });
        build_response(
            self.status,
            Some(CONTENT_TYPE_JSON_UTF8),
            self.allow,
            Body::from(body),
        )
    }
}

async fn handle_mcp_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Err(err) = validate_host_header(&headers, state.bound_port) {
        return err.into_response();
    }
    if let Err(err) = validate_origin_header(&headers, &state.config.origin_policy) {
        return err.into_response();
    }
    if headers.contains_key("last-event-id") {
        return HttpError::new(
            StatusCode::BAD_REQUEST,
            "replay_not_supported",
            "event replay via Last-Event-ID is not supported",
        )
        .into_response();
    }
    if let Err(err) = validate_content_type_header(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_accept_header(&headers) {
        return err.into_response();
    }
    if let Err(err) = validate_content_length_header(&headers, state.config.max_request_body_bytes)
    {
        return err.into_response();
    }

    let in_flight_guard = match state.gate.try_acquire() {
        Some(guard) => guard,
        None => {
            return HttpError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_shutting_down",
                "server is shutting down and no longer accepting new requests",
            )
            .into_response();
        }
    };

    let permit = match Arc::clone(&state.concurrency).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return HttpError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_busy",
                "maximum concurrent in-flight MCP requests reached",
            )
            .into_response();
        }
    };

    let raw_bytes = match read_bounded_body(body, state.config.max_request_body_bytes).await {
        Ok(bytes) => bytes,
        Err(BodyReadError::TooLarge) => {
            return HttpError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "request body exceeds maximum allowed byte limit",
            )
            .into_response();
        }
        Err(BodyReadError::ReadFailed) => {
            return HttpError::new(
                StatusCode::BAD_REQUEST,
                "body_read_error",
                "failed to read HTTP request body",
            )
            .into_response();
        }
    };

    let body_text = match String::from_utf8(raw_bytes) {
        Ok(text) => text,
        Err(_) => {
            return HttpError::new(
                StatusCode::BAD_REQUEST,
                "invalid_utf8",
                "request body must be valid UTF-8",
            )
            .into_response();
        }
    };

    if body_text.trim().is_empty() {
        return HttpError::new(
            StatusCode::BAD_REQUEST,
            "empty_body",
            "request body must contain a JSON-RPC message",
        )
        .into_response();
    }

    let dispatch = Arc::clone(&state.dispatch);
    let dispatch_result = tokio::task::spawn_blocking(move || {
        let _guard = in_flight_guard;
        let _permit = permit;
        (dispatch)(&body_text)
    })
    .await;

    match dispatch_result {
        Ok(None) => build_response(StatusCode::ACCEPTED, None, None, Body::empty()),
        Ok(Some(response_json)) => {
            if response_json.len() > state.config.max_response_body_bytes {
                return HttpError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "response_too_large",
                    "gateway response exceeds maximum allowed byte limit",
                )
                .into_response();
            }
            build_response(
                StatusCode::OK,
                Some(CONTENT_TYPE_JSON_UTF8),
                None,
                Body::from(response_json),
            )
        }
        Err(_) => HttpError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "gateway_dispatch_error",
            "internal gateway dispatch failure",
        )
        .into_response(),
    }
}

async fn handle_mcp_method_not_allowed(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(err) = validate_host_header(&headers, state.bound_port) {
        return err.into_response();
    }
    if let Err(err) = validate_origin_header(&headers, &state.config.origin_policy) {
        return err.into_response();
    }
    HttpError::method_not_allowed(
        "POST",
        "only POST is supported on /mcp; SSE streams and event replay are disabled",
    )
    .into_response()
}

async fn handle_health_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(err) = validate_host_header(&headers, state.bound_port) {
        return err.into_response();
    }
    if let Err(err) = validate_origin_header(&headers, &state.config.origin_policy) {
        return err.into_response();
    }

    let (http_status, health_payload) = if state.gate.is_closing() {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            HealthStatus::unhealthy("shutting_down"),
        )
    } else {
        let status = (state.health)();
        let code = if status.healthy {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        (code, status)
    };

    match serde_json::to_vec(&health_payload) {
        Ok(bytes) => build_response(
            http_status,
            Some(CONTENT_TYPE_JSON_UTF8),
            None,
            Body::from(bytes),
        ),
        Err(_) => HttpError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "health_serialization_error",
            "failed to serialize health status",
        )
        .into_response(),
    }
}

async fn handle_health_method_not_allowed(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(err) = validate_host_header(&headers, state.bound_port) {
        return err.into_response();
    }
    if let Err(err) = validate_origin_header(&headers, &state.config.origin_policy) {
        return err.into_response();
    }
    HttpError::method_not_allowed("GET", "only GET is supported on /health").into_response()
}

async fn handle_not_found(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(err) = validate_host_header(&headers, state.bound_port) {
        return err.into_response();
    }
    if let Err(err) = validate_origin_header(&headers, &state.config.origin_policy) {
        return err.into_response();
    }
    HttpError::new(StatusCode::NOT_FOUND, "not_found", "endpoint not found").into_response()
}

fn build_response(
    status: StatusCode,
    content_type: Option<&'static str>,
    allow: Option<&'static str>,
    body: Body,
) -> Response {
    let mut builder = Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))
        .header(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );

    if let Some(ct) = content_type {
        builder = builder.header(header::CONTENT_TYPE, HeaderValue::from_static(ct));
    }
    if let Some(allow_val) = allow {
        builder = builder.header(header::ALLOW, HeaderValue::from_static(allow_val));
    }

    builder.body(body).unwrap_or_else(|_| {
        let mut fallback = Response::new(Body::from(
            r#"{"error":{"code":"internal_error","message":"failed to construct HTTP response"}}"#,
        ));
        *fallback.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        fallback
    })
}

enum BodyReadError {
    TooLarge,
    ReadFailed,
}

async fn read_bounded_body(mut body: Body, max_bytes: usize) -> Result<Vec<u8>, BodyReadError> {
    let mut buf = Vec::new();

    while let Some(frame_result) = body.frame().await {
        let frame = frame_result.map_err(|_| BodyReadError::ReadFailed)?;
        if let Ok(data) = frame.into_data() {
            let new_len = buf
                .len()
                .checked_add(data.len())
                .filter(|&len| len <= max_bytes)
                .ok_or(BodyReadError::TooLarge)?;

            if new_len > buf.capacity() {
                let target_cap = buf
                    .capacity()
                    .max(256)
                    .saturating_mul(2)
                    .max(new_len)
                    .min(max_bytes);
                buf.reserve_exact(target_cap - buf.len());
            }

            buf.extend_from_slice(&data);
        }
    }

    Ok(buf)
}

fn validate_host_header(headers: &HeaderMap, bound_port: u16) -> Result<(), HttpError> {
    let mut values = headers.get_all(header::HOST).iter();
    let Some(first) = values.next() else {
        return Err(HttpError::new(
            StatusCode::BAD_REQUEST,
            "missing_host",
            "missing Host header",
        ));
    };
    if values.next().is_some() {
        return Err(HttpError::new(
            StatusCode::BAD_REQUEST,
            "duplicate_host",
            "duplicate Host header",
        ));
    }

    let raw = first.to_str().map_err(|_| {
        HttpError::new(
            StatusCode::BAD_REQUEST,
            "invalid_host",
            "invalid Host header encoding",
        )
    })?;

    let (host, port) = parse_loopback_authority(raw).ok_or_else(|| {
        HttpError::new(
            StatusCode::FORBIDDEN,
            "forbidden_host",
            "Host header is not allowed for IPv4 loopback server",
        )
    })?;

    let effective_port = port.unwrap_or(80);
    if !is_loopback_hostname(host) || effective_port != bound_port {
        return Err(HttpError::new(
            StatusCode::FORBIDDEN,
            "forbidden_host",
            "Host header does not match bound IPv4 loopback endpoint",
        ));
    }

    Ok(())
}

fn validate_origin_header(headers: &HeaderMap, policy: &OriginPolicy) -> Result<(), HttpError> {
    let mut values = headers.get_all(header::ORIGIN).iter();
    let Some(first) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(HttpError::new(
            StatusCode::BAD_REQUEST,
            "duplicate_origin",
            "duplicate Origin header",
        ));
    }

    let raw = first.to_str().map_err(|_| {
        HttpError::new(
            StatusCode::BAD_REQUEST,
            "invalid_origin",
            "invalid Origin header encoding",
        )
    })?;

    if raw.is_empty() || raw.eq_ignore_ascii_case("null") {
        return Err(HttpError::new(
            StatusCode::FORBIDDEN,
            "forbidden_origin",
            "Origin header is not allowed",
        ));
    }

    let allowed = match policy {
        OriginPolicy::RejectAll => false,
        OriginPolicy::LoopbackHttp => is_loopback_http_origin(raw),
        OriginPolicy::AllowList(origins) => origins.iter().any(|allowed| allowed == raw),
    };

    if !allowed {
        return Err(HttpError::new(
            StatusCode::FORBIDDEN,
            "forbidden_origin",
            "Origin header is not allowed",
        ));
    }

    Ok(())
}

fn validate_content_type_header(headers: &HeaderMap) -> Result<(), HttpError> {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(first) = values.next() else {
        return Err(HttpError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "missing_content_type",
            "Content-Type header must be application/json",
        ));
    };
    if values.next().is_some() {
        return Err(HttpError::new(
            StatusCode::BAD_REQUEST,
            "duplicate_content_type",
            "duplicate Content-Type header",
        ));
    }

    let raw = first.to_str().map_err(|_| {
        HttpError::new(
            StatusCode::BAD_REQUEST,
            "invalid_content_type",
            "invalid Content-Type header encoding",
        )
    })?;

    let mut parts = raw.split(';');
    let media_type = parts.next().map(str::trim).unwrap_or("");
    if !media_type.eq_ignore_ascii_case("application/json") {
        return Err(HttpError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "Content-Type must be application/json",
        ));
    }

    for param in parts {
        let param = param.trim();
        if param.is_empty() {
            continue;
        }
        let Some((name, val)) = param.split_once('=') else {
            return Err(HttpError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "invalid_content_type",
                "malformed Content-Type parameter",
            ));
        };
        if name.trim().eq_ignore_ascii_case("charset") {
            let val = val.trim();
            let unquoted = val
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(val);
            if !unquoted.eq_ignore_ascii_case("utf-8") {
                return Err(HttpError::new(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "unsupported_charset",
                    "Content-Type charset must be utf-8",
                ));
            }
        }
    }

    Ok(())
}

fn validate_accept_header(headers: &HeaderMap) -> Result<(), HttpError> {
    let mut header_count = 0usize;
    let mut best_specificity: u8 = 0;
    let mut best_q: u16 = 0;

    for value in headers.get_all(header::ACCEPT) {
        header_count += 1;
        let raw = value.to_str().map_err(|_| {
            HttpError::new(
                StatusCode::BAD_REQUEST,
                "invalid_accept",
                "invalid Accept header encoding",
            )
        })?;

        for item in raw.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let mut parts = item.split(';');
            let media_range = parts.next().map(str::trim).unwrap_or("");
            let specificity = if media_range.eq_ignore_ascii_case("application/json") {
                3
            } else if media_range.eq_ignore_ascii_case("application/*") {
                2
            } else if media_range == "*/*" {
                1
            } else {
                0
            };

            let mut q: u16 = 1000;
            let mut seen_q = false;
            for param in parts {
                let param = param.trim();
                if param.is_empty() {
                    continue;
                }
                if let Some((name, val)) = param.split_once('=') {
                    if name.trim().eq_ignore_ascii_case("q") {
                        if seen_q {
                            return Err(HttpError::new(
                                StatusCode::NOT_ACCEPTABLE,
                                "invalid_accept",
                                "duplicate quality factor in Accept header",
                            ));
                        }
                        seen_q = true;
                        q = parse_qvalue(val.trim()).ok_or_else(|| {
                            HttpError::new(
                                StatusCode::NOT_ACCEPTABLE,
                                "invalid_accept",
                                "invalid quality factor in Accept header",
                            )
                        })?;
                    }
                }
            }

            if specificity > best_specificity {
                best_specificity = specificity;
                best_q = q;
            } else if specificity == best_specificity && q > best_q {
                best_q = q;
            }
        }
    }

    if header_count == 0 {
        return Err(HttpError::new(
            StatusCode::NOT_ACCEPTABLE,
            "missing_accept",
            "Accept header is required and must allow application/json",
        ));
    }

    if best_specificity == 0 || best_q == 0 {
        return Err(HttpError::new(
            StatusCode::NOT_ACCEPTABLE,
            "not_acceptable",
            "Accept header must allow application/json",
        ));
    }

    Ok(())
}

fn validate_content_length_header(headers: &HeaderMap, max_bytes: usize) -> Result<(), HttpError> {
    let mut values = headers.get_all(header::CONTENT_LENGTH).iter();
    let Some(first) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(HttpError::new(
            StatusCode::BAD_REQUEST,
            "duplicate_content_length",
            "duplicate Content-Length header",
        ));
    }

    let raw = first.to_str().map_err(|_| {
        HttpError::new(
            StatusCode::BAD_REQUEST,
            "invalid_content_length",
            "invalid Content-Length header encoding",
        )
    })?;

    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(HttpError::new(
            StatusCode::BAD_REQUEST,
            "invalid_content_length",
            "Content-Length header must be a non-negative integer",
        ));
    }

    let len = raw.parse::<usize>().map_err(|_| {
        HttpError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "Content-Length exceeds maximum allowed byte limit",
        )
    })?;

    if len > max_bytes {
        return Err(HttpError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "Content-Length exceeds maximum allowed byte limit",
        ));
    }

    Ok(())
}

fn is_loopback_http_origin(origin: &str) -> bool {
    if origin.len() < 7 || !origin[..7].eq_ignore_ascii_case("http://") {
        return false;
    }
    let authority = &origin[7..];
    match parse_loopback_authority(authority) {
        Some((host, _port)) => is_loopback_hostname(host),
        None => false,
    }
}

fn parse_loopback_authority(authority: &str) -> Option<(&str, Option<u16>)> {
    if authority.is_empty()
        || authority.starts_with('[')
        || authority
            .bytes()
            .any(|b| b.is_ascii_whitespace() || matches!(b, b'/' | b'\\' | b'?' | b'#' | b'@'))
    {
        return None;
    }

    match authority.split_once(':') {
        None => Some((authority, None)),
        Some((host, port_str)) => {
            if port_str.contains(':')
                || port_str.is_empty()
                || (port_str.len() > 1 && port_str.starts_with('0'))
                || !port_str.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            let port = port_str.parse::<u16>().ok()?;
            if port == 0 {
                return None;
            }
            Some((host, Some(port)))
        }
    }
}

fn is_loopback_hostname(host: &str) -> bool {
    host == "127.0.0.1" || host.eq_ignore_ascii_case("localhost")
}

fn parse_qvalue(raw: &str) -> Option<u16> {
    if raw == "0" {
        return Some(0);
    }
    if raw == "1" {
        return Some(1000);
    }
    if let Some(frac) = raw.strip_prefix("0.") {
        if frac.len() > 3 || !frac.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let mut value: u16 = 0;
        let mut scale: u16 = 100;
        for b in frac.bytes() {
            value += u16::from(b - b'0') * scale;
            scale /= 10;
        }
        return Some(value);
    }
    if let Some(frac) = raw.strip_prefix("1.") {
        if frac.len() > 3 || !frac.bytes().all(|b| b == b'0') {
            return None;
        }
        return Some(1000);
    }
    None
}
