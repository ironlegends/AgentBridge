use crate::{error, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Url;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, ClientCapabilities, ClientConfig, Implementation,
    PaginatedRequestParams, ProtocolVersion,
};
use crate::stdio::{self, StdioChild, StdioLaunch, StdioLauncher, StdioSpec, StderrTail};
use rmcp::service::{ClientLifecycleMode, ClientServiceExt, RoleClient, RunningService};
use rmcp::transport::async_rw::AsyncRwTransport;
use rmcp::transport::common::client_side_sse::NeverRetry;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::{IntoTransport, StreamableHttpClientTransport};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::future::Future;
use std::io::Read;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_BYTES: usize = 1024 * 1024;
/// Bound on each discovery, listing or tool call, including the transport.
const REQUEST_DEADLINE: Duration = Duration::from_secs(12);
/// Bound on opening a session: one discovery and one legacy handshake. Over
/// HTTP an unanswered `server/discover` ends the single-request worker at the
/// request deadline, so the SDK's 10-second fallback never sends `initialize`.
const OPEN_DEADLINE: Duration = Duration::from_secs(24);

/// The session runtime. Dropping it never waits for blocking work, such as a
/// system DNS lookup, so every close stays bounded.
struct Runtime(Option<tokio::runtime::Runtime>);

impl std::ops::Deref for Runtime {
    type Target = tokio::runtime::Runtime;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("the runtime lives until drop")
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() { runtime.shutdown_background(); }
    }
}

/// TLS for every outbound HTTPS client in this crate: ring and the bundled
/// webpki roots. The operating system certificate store is not trusted.
pub(crate) fn https_tls() -> Result<rustls::ClientConfig> {
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| error("Cannot initialize TLS"))?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// One extension connection through the official MCP SDK (rmcp). It probes
/// `server/discover` for 2026-07-28 first. Only a server the SDK classifies as
/// legacy gets the `initialize` handshake and a session. There is no retry.
pub(crate) struct Session {
    service: Option<RunningService<RoleClient, ClientConfig>>,
    runtime: Runtime,
    /// The contained child of a stdio session; shut down after the service.
    child: Option<StdioOwner>,
}

/// True when a descriptor asks the client to mirror arguments into
/// `Mcp-Param-*` headers. Such tools stay refused.
pub(crate) fn declares_parameter_headers(descriptor: &Value) -> bool {
    fn walk(value: &Value) -> bool {
        match value {
            Value::Object(map) => map.contains_key("x-mcp-header") || map.values().any(walk),
            Value::Array(items) => items.iter().any(walk),
            _ => false,
        }
    }
    walk(&descriptor["inputSchema"])
}

pub(crate) fn endpoint(raw: &str) -> Result<Url> {
    let url = Url::parse(raw).map_err(|_| error("Invalid extension address"))?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some()
        || url.query().is_some() || url.host().is_none() {
        return Err(error("Extension address must have a fixed host and path"));
    }
    match (url.scheme(), url.host_str()) {
        ("https", _) | ("http", Some("127.0.0.1" | "[::1]")) => Ok(url),
        _ => Err(error("An extension requires HTTPS or literal loopback HTTP")),
    }
}

fn valid_tool_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 128
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

impl Session {
    pub fn open(address: &str, bearer_env: Option<&str>, header_env: &BTreeMap<String, String>) -> Result<Self> {
        let endpoint = endpoint(address)?;
        crate::validate_header_env(address, header_env, bearer_env.is_some())?;
        if bearer_env.is_some() && endpoint.scheme() != "https" {
            return Err(error("A credential requires an authenticated HTTPS endpoint"));
        }
        let bearer = bearer_env.map(|key| std::env::var(key)
            .map_err(|_| error("Configured extension credential is unavailable"))).transpose()?;
        let headers = resolve_headers(header_env, |name| std::env::var(name).ok())?;
        Self::connect(endpoint, bearer, headers)
    }

    fn connect(endpoint: Url, bearer: Option<String>, headers: HeaderMap) -> Result<Self> {
        let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never()).no_proxy()
            .tls_backend_preconfigured(https_tls()?)
            .connect_timeout(Duration::from_secs(4)).timeout(REQUEST_DEADLINE).build()
            .map_err(|_| error("Cannot initialize the extension transport"))?;
        let mut config = StreamableHttpClientTransportConfig::with_uri(endpoint.as_str())
            .max_concurrent_requests(1)
            .reinit_on_expired_session(false)
            .max_json_response_size(MAX_BYTES)
            .max_sse_event_size(MAX_BYTES)
            .max_error_response_size(4096)
            .custom_headers(headers.into_iter()
                .filter_map(|(name, value)| Some((name?, value)))
                .collect::<HashMap<_, _>>());
        config.retry_config = Arc::new(NeverRetry::default());
        if let Some(secret) = bearer { config = config.auth_header(secret); }
        let mut this = Self { service: None, runtime: runtime()?, child: None };
        // The SDK transport spawns its worker, so it is built inside the runtime.
        this.serve(|| StreamableHttpClientTransport::with_client(client, config))?;
        Ok(this)
    }

    /// One contained child per session. The executable is hashed through a
    /// held handle and compared with the pin before launch, then re-checked
    /// after launch. At most four stdio sessions are live; a fifth is
    /// refused, never queued.
    pub fn open_stdio(spec: &StdioSpec, launcher: &dyn StdioLauncher,
        resolve: &dyn Fn(&str) -> Option<OsString>) -> Result<Self> {
        spec.validate()?;
        let slot = stdio::SessionSlot::acquire()?;
        let environment = stdio::child_environment(spec, resolve)?;
        let executable = Path::new(&spec.executable);
        let cwd = match spec.cwd.as_deref() {
            Some(cwd) => Path::new(cwd),
            None => executable.parent().ok_or_else(|| error("Stdio extension executable has no directory"))?,
        };
        stdio::check_ancestors(cwd)?;
        let mut pin = stdio::PinnedExecutable::open(executable)?;
        if pin.sha256()? != spec.executable_sha256 {
            return Err(error("Stdio extension executable changed; local reapproval required"));
        }
        let launch = StdioLaunch { executable, arguments: &spec.args, cwd, environment: &environment };
        let child = launcher.launch(&launch).map_err(|_| error("Cannot start the stdio extension"))?;
        let owner = StdioOwner { child: Arc::new(Mutex::new(child)), stderr: Arc::default(), _slot: slot };
        // On failure the owner is dropped here, which stops the child.
        pin.verify_unchanged()?;
        drop(pin);
        let (reader, writer) = (owner.reader(), owner.writer());
        let mut this = Self { service: None, runtime: runtime()?, child: Some(owner) };
        this.serve(|| AsyncRwTransport::new_client(reader, writer).with_max_line_length(MAX_BYTES))?;
        Ok(this)
    }

    /// The shared handshake for every transport: discovery first, then one
    /// legacy `initialize` only for a server the SDK classifies as legacy.
    /// Discovery and initialization are read-only, so the fallback cannot
    /// repeat an effect.
    fn serve<T, E, A>(&mut self, transport: impl FnOnce() -> T) -> Result<()>
    where T: IntoTransport<RoleClient, E, A>, E: std::error::Error + Send + Sync + 'static {
        let identity = ClientConfig::new(ClientCapabilities::default(),
            Implementation::new("agent-bridge", env!("CARGO_PKG_VERSION")))
            .with_protocol_version(ProtocolVersion::V_2026_07_28);
        let lifecycle = ClientLifecycleMode::Auto {
            preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            legacy_version: Some(ProtocolVersion::LATEST_WITH_INITIALIZE),
        };
        let service = self.runtime.block_on(async {
            tokio::time::timeout(OPEN_DEADLINE, identity.serve_with_lifecycle(transport(), lifecycle)).await
        }).map_err(|_| error("Extension did not complete the MCP handshake in time"))?
            .map_err(|_| error("Extension refused or failed the MCP handshake"))?;
        self.service = Some(service);
        let served = self.service()?.peer_info()
            .is_some_and(|info| ProtocolVersion::KNOWN_VERSIONS.contains(&info.protocol_version)
                && info.capabilities.tools.is_some());
        if !served {
            return Err(error("Extension protocol version or tool capability unsupported"));
        }
        Ok(())
    }

    /// Bytes the stdio child wrote to stderr so far; never their content.
    pub fn stderr_bytes(&self) -> Option<u64> {
        self.child.as_ref().map(|owner| lock(&owner.stderr).bytes)
    }

    /// The protocol version negotiated with the extension.
    pub fn protocol_version(&self) -> String {
        self.service.as_ref().and_then(|service| service.peer_info())
            .map(|info| info.protocol_version.to_string()).unwrap_or_default()
    }

    fn service(&self) -> Result<&RunningService<RoleClient, ClientConfig>> {
        self.service.as_ref().ok_or_else(|| error("Extension session closed"))
    }

    fn run<T, F>(&self, future: F) -> Result<T>
    where F: Future<Output = std::result::Result<T, rmcp::ServiceError>> {
        self.runtime.block_on(async { tokio::time::timeout(REQUEST_DEADLINE, future).await })
            .map_err(|_| error("Extension did not return a confirmed response"))?
            .map_err(|_| error("Extension returned an error or an unconfirmed reply"))
    }

    /// Lists one page. Every descriptor is returned as JSON for pinning.
    fn page(&self, cursor: Option<String>) -> Result<(Vec<Value>, Option<String>)> {
        let params = cursor.map(|c| PaginatedRequestParams::default().with_cursor(Some(c)));
        let listed = self.run(self.service()?.list_tools(params))?;
        let tools = listed.tools.iter().map(serde_json::to_value).collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| error("Invalid remote MCP descriptor"))?;
        Ok((tools, listed.next_cursor.map(|cursor| cursor.to_string())))
    }

    /// One confirmed MCP tools/list traversal, without tool invocation or
    /// registry mutation. Bounded to 16 pages and 256 unique tool names.
    pub fn catalog(&mut self) -> Result<Vec<Value>> {
        use std::collections::BTreeSet;
        let mut cursor = None;
        let mut seen_cursors = BTreeSet::<String>::new();
        let mut names = BTreeSet::<String>::new();
        let mut entries = Vec::new();
        for _ in 0..16 {
            let (tools, next) = self.page(cursor)?;
            for tool in tools {
                let name = tool.get("name").and_then(Value::as_str)
                    .ok_or_else(|| error("Remote MCP tool has no name"))?;
                if !valid_tool_name(name) || !names.insert(name.to_owned()) || entries.len() >= 256 {
                    return Err(error("Remote MCP catalog is ambiguous or too large"));
                }
                if serde_json::to_vec(&tool).map_err(|_| error("Invalid remote MCP descriptor"))?.len() > 64 * 1024 {
                    return Err(error("Remote MCP descriptor exceeds bound"));
                }
                entries.push(tool);
            }
            match next {
                None => return Ok(entries),
                Some(next) if !next.is_empty() && next.len() <= 4096 && seen_cursors.insert(next.clone()) => {
                    cursor = Some(next);
                }
                Some(_) => return Err(error("Invalid or repeated MCP pagination cursor")),
            }
        }
        Err(error("Remote MCP tool catalog exceeds pagination limit"))
    }

    pub fn tool(&mut self, name: &str) -> Result<Value> {
        let mut cursor = None;
        let mut found = None;
        for _ in 0..16 {
            let (tools, next) = self.page(cursor)?;
            for entry in tools {
                if entry["name"].as_str() == Some(name) && found.replace(entry).is_some() {
                    return Err(error("Ambiguous extension tool name"));
                }
            }
            match next {
                None => return found.ok_or_else(|| error("Extension tool not found")),
                Some(next) if !next.is_empty() && next.len() <= 4096 => cursor = Some(next),
                Some(_) => return Err(error("Invalid extension pagination")),
            }
        }
        Err(error("Extension catalog exceeds pagination limit"))
    }

    /// Sends exactly one `tools/call`. Only a completed result is accepted:
    /// an input request or a task is refused and nothing is resent.
    pub fn call_tool(&mut self, name: &str, arguments: Map<String, Value>) -> Result<Value> {
        if !valid_tool_name(name) { return Err(error("Extension request name cannot be routed")); }
        let params = CallToolRequestParams::new(name.to_owned()).with_arguments(arguments);
        match self.run(self.service()?.call_tool_once(params))? {
            CallToolResponse::Complete(result) => serde_json::to_value(result)
                .map_err(|_| error("Invalid extension tool result")),
            _ => Err(error("Extension reply is not a completed result")),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // A bounded close lets the SDK end a legacy session with DELETE.
        if let Some(mut service) = self.service.take() {
            self.runtime.block_on(async {
                let _ = service.close_with_timeout(Duration::from_secs(3)).await;
            });
        }
        // Then stdin is closed and the child gets a bounded grace period
        // before the contained tree is terminated.
        drop(self.child.take());
    }
}

fn runtime() -> Result<Runtime> {
    Ok(Runtime(Some(tokio::runtime::Builder::new_current_thread().enable_all().build()
        .map_err(|_| error("Cannot initialize the extension transport"))?)))
}

fn lock<T: ?Sized>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

type SharedChild = Arc<Mutex<Box<dyn StdioChild>>>;

/// Owns one launched child and its live-session slot.
struct StdioOwner {
    child: SharedChild,
    stderr: Arc<Mutex<StderrTail>>,
    _slot: stdio::SessionSlot,
}

impl StdioOwner {
    fn reader(&self) -> PipeReader {
        PipeReader { child: self.child.clone(), stderr: self.stderr.clone(), idle: Idle::default() }
    }

    fn writer(&self) -> PipeWriter { PipeWriter { child: self.child.clone(), idle: Idle::default() } }

    fn finished_within(&self, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        loop {
            {
                let mut child = lock(&self.child);
                drain_stderr(&mut **child, &self.stderr);
                if child.finish().unwrap_or(false) { return true; }
            }
            if Instant::now() >= deadline { return false; }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for StdioOwner {
    /// Close stdin, wait up to 2 s, terminate the contained tree, wait up to
    /// 2 s more. Termination also runs after a clean exit so that no
    /// descendant outlives the session.
    fn drop(&mut self) {
        lock(&self.child).close_stdin();
        let exited = self.finished_within(Duration::from_secs(2));
        let _ = lock(&self.child).terminate();
        if !exited { self.finished_within(Duration::from_secs(2)); }
    }
}

fn drain_stderr(child: &mut dyn StdioChild, tail: &Mutex<StderrTail>) {
    let mut buffer = [0u8; 4096];
    for _ in 0..16 {
        match child.read_stderr(&mut buffer) {
            Ok(0) | Err(_) => return,
            Ok(read) => lock(tail).push(&buffer[..read]),
        }
    }
}

/// Polls an idle pipe again after a short timer: 1 ms, doubling to 10 ms.
#[derive(Default)]
struct Idle {
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    backoff_ms: u64,
}

impl Idle {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if let Some(sleep) = self.sleep.as_mut() {
            ready!(sleep.as_mut().poll(cx));
            self.sleep = None;
        }
        Poll::Ready(())
    }

    fn arm(&mut self) {
        self.backoff_ms = (self.backoff_ms * 2).clamp(1, 10);
        self.sleep = Some(Box::pin(tokio::time::sleep(Duration::from_millis(self.backoff_ms))));
    }

    fn reset(&mut self) { self.backoff_ms = 0; }
}

/// Child stdout as an async reader. `Ok(0)` from the child is end of file.
/// Each read also drains stderr into the bounded tail.
struct PipeReader {
    child: SharedChild,
    stderr: Arc<Mutex<StderrTail>>,
    idle: Idle,
}

impl AsyncRead for PipeReader {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 { return Poll::Ready(Ok(())); }
        loop {
            ready!(self.idle.poll_ready(cx));
            let this = &mut *self;
            let result = {
                let mut child = lock(&this.child);
                drain_stderr(&mut **child, &this.stderr);
                child.read_stdout(buf.initialize_unfilled())
            };
            match result {
                Ok(read) => {
                    buf.advance(read);
                    this.idle.reset();
                    return Poll::Ready(Ok(()));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => this.idle.arm(),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

/// Child stdin as an async writer; shutdown closes stdin.
struct PipeWriter {
    child: SharedChild,
    idle: Idle,
}

impl AsyncWrite for PipeWriter {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() { return Poll::Ready(Ok(0)); }
        loop {
            ready!(self.idle.poll_ready(cx));
            let this = &mut *self;
            let result = lock(&this.child).write_stdin(buf);
            match result {
                Ok(0) => this.idle.arm(),
                Ok(written) => {
                    this.idle.reset();
                    return Poll::Ready(Ok(written));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => this.idle.arm(),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> { Poll::Ready(Ok(())) }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        lock(&self.child).close_stdin();
        Poll::Ready(Ok(()))
    }
}

fn resolve_headers(references: &BTreeMap<String, String>, mut resolve: impl FnMut(&str) -> Option<String>) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    let mut total = 0usize;
    for (name, variable) in references {
        let secret = resolve(variable).ok_or_else(|| error("Configured extension header credential is unavailable"))?;
        total = total.saturating_add(name.len()).saturating_add(secret.len());
        if secret.is_empty() || secret.len() > 8192 || total > 16 * 1024 {
            return Err(error("Configured extension header credential exceeds its byte budget"));
        }
        let mut value = HeaderValue::from_str(&secret).map_err(|_| error("Configured extension header credential is invalid"))?;
        value.set_sensitive(true);
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| error("Invalid extension header name"))?;
        headers.insert(name, value);
    }
    Ok(headers)
}

#[cfg(test)]
mod header_tests {
    use super::*;

    #[test]
    fn header_env_values_are_sensitive_and_redacted_from_debug() {
        let references = BTreeMap::from([("X-Api-Key".into(), "AGENT_BRIDGE_EXTENSION_TEST_KEY".into())]);
        crate::validate_header_env("https://example.invalid/mcp", &references, false).unwrap();
        let headers = resolve_headers(&references, |name| {
            assert_eq!(name, "AGENT_BRIDGE_EXTENSION_TEST_KEY"); Some("fixture-only-key".into())
        }).unwrap();
        assert_eq!(headers["x-api-key"], "fixture-only-key");
        assert!(headers["x-api-key"].is_sensitive());
        assert!(!format!("{headers:?}").contains("fixture-only-key"));
        // This fixture never sends a request or reads a real environment secret.
    }

    #[test]
    fn silent_extension_server_fails_within_the_request_deadline() {
        // The listener accepts the connection and never answers.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://127.0.0.1:{}/mcp", listener.local_addr().unwrap().port());
        let holder = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_secs(20));
            drop(stream);
        });
        let started = std::time::Instant::now();
        let error = Session::open(&address, None, &BTreeMap::new()).err().expect("a silent server must fail");
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_secs(11), "the deadline must bound the wait, not skip it: {elapsed:?}");
        assert!(elapsed < Duration::from_secs(18), "the request deadline was not enforced: {elapsed:?}");
        assert!(!error.to_string().contains("127.0.0.1"), "{error}");
        drop(holder);
    }

    #[test]
    fn header_env_missing_injected_and_oversized_values_fail_before_network() {
        let references = BTreeMap::from([("X-Api-Key".into(), "AGENT_BRIDGE_EXTENSION_TEST_KEY".into())]);
        assert!(resolve_headers(&references, |_| None).is_err());
        for value in ["".to_owned(), "key\r\nX-Injected: value".into(), "x".repeat(8193)] {
            let error = resolve_headers(&references, |_| Some(value.clone())).unwrap_err();
            assert!(!error.to_string().contains(&value) || value.is_empty());
        }
        let too_many_bytes = BTreeMap::from([
            ("X-Key-One".into(), "AGENT_BRIDGE_EXTENSION_TEST_ONE".into()),
            ("X-Key-Two".into(), "AGENT_BRIDGE_EXTENSION_TEST_TWO".into()),
            ("X-Key-Three".into(), "AGENT_BRIDGE_EXTENSION_TEST_THREE".into()),
        ]);
        assert!(resolve_headers(&too_many_bytes, |_| Some("x".repeat(6000))).is_err());
    }
}

/// Bounded, redirect-free, proxy-free HTTPS GET reader for explicitly
/// allowlisted documentary archives (e.g. remote Agent Skills ZIPs).
pub fn fetch_https_bytes(raw_url: &str, max_bytes: usize) -> Result<Vec<u8>> {
    if max_bytes == 0 || max_bytes > 32 * 1024 * 1024 {
        return Err(error("Invalid maximum remote archive byte limit"));
    }
    let url = Url::parse(raw_url).map_err(|_| error("Invalid remote HTTPS URL"))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.host().is_none()
    {
        return Err(error("Remote download requires a clean HTTPS URL without credentials or fragment"));
    }
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_proxy()
        .tls_backend_preconfigured(https_tls()?)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|_| error("Cannot initialize HTTPS download client"))?;
    let response = client
        .get(url)
        .send()
        .map_err(|_| error("Remote HTTPS archive request failed"))?;
    if response.status().is_redirection() {
        return Err(error("Remote HTTPS redirects are forbidden"));
    }
    if !response.status().is_success() {
        return Err(error("Remote HTTPS server returned non-success status"));
    }
    if let Some(len) = response.content_length() {
        if len > max_bytes as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Remote HTTPS archive exceeds maximum byte limit",
            ));
        }
    }
    let mut bytes = Vec::new();
    response
        .take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| error("Incomplete remote HTTPS archive download"))?;
    if bytes.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Remote HTTPS archive exceeds maximum byte limit",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod modern_tests {
    use super::*;
    use serde_json::json;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::thread;
    use std::time::Instant;

    const VERSION: &str = "2026-07-28";

    struct Incoming {
        headers: String,
        body: Value,
    }

    fn receive(stream: &mut TcpStream) -> Incoming {
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut reader = BufReader::new(stream);
        let mut headers = String::new();
        let mut length = None;
        loop {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            assert!(headers.len() + line.len() < 16384);
            if line == "\r\n" { break; }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    length = Some(value.trim().parse::<usize>().unwrap());
                }
            }
            headers.push_str(&line);
        }
        // GET and DELETE carry no body; the request line starts `headers`.
        let length = length.unwrap_or(0);
        assert!(length < 16384);
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        let body = if body.is_empty() { Value::Null } else { serde_json::from_slice(&body).unwrap() };
        Incoming { headers: headers.to_ascii_lowercase(), body }
    }

    fn reply(stream: &mut TcpStream, status: &str, body: &str, content_type: &str) {
        reply_with(stream, status, body, content_type, "");
    }

    fn reply_with(stream: &mut TcpStream, status: &str, body: &str, content_type: &str, extra: &str) {
        write!(stream, "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n{body}", body.len()).unwrap();
        stream.flush().unwrap();
    }

    fn accept_before(listener: &TcpListener, deadline: Instant) -> Option<TcpStream> {
        loop {
            match listener.accept() {
                Ok((stream, _)) => { stream.set_nonblocking(false).unwrap(); return Some(stream); }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                    thread::sleep(Duration::from_millis(5)),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return None,
                Err(e) => panic!("Fixture accept failed: {e}"),
            }
        }
    }

    /// Serves one legacy server and returns each request as (method or HTTP
    /// verb, lowercase headers, body). It stops after the session DELETE.
    fn legacy_server(listener: TcpListener, refusal: &'static str) -> Vec<(String, String, Value)> {
        let mut seen = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(20);
        while let Some(mut stream) = accept_before(&listener, deadline) {
            // A connection the closing client opened but never used is not a request.
            if matches!(stream.peek(&mut [0u8; 1]), Ok(0)) { continue; }
            let incoming = receive(&mut stream);
            let verb = incoming.headers.split(' ').next().unwrap_or_default().to_ascii_uppercase();
            let method = incoming.body["method"].as_str().map(str::to_owned).unwrap_or(verb.clone());
            let id = incoming.body["id"].clone();
            match method.as_str() {
                "server/discover" => match refusal {
                    "400" => reply(&mut stream, "400 Bad Request", "", "text/plain"),
                    "404" => reply(&mut stream, "404 Not Found", "", "text/plain"),
                    _ => {
                        let body = json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"Method is not available."}});
                        reply(&mut stream, "200 OK", &format!("event: message\ndata: {body}\n\n"), "text/event-stream");
                    }
                },
                "initialize" => reply_with(&mut stream, "200 OK", &success(&id, json!({"protocolVersion":"2025-11-25",
                    "capabilities": if refusal == "no-tools" { json!({}) } else { json!({"tools":{}}) },
                    "serverInfo":{"name":"legacy-fixture","version":"0"}})),
                    "application/json", "Mcp-Session-Id: legacy-session\r\n"),
                "notifications/initialized" => reply(&mut stream, "202 Accepted", "", "text/plain"),
                "tools/list" => reply(&mut stream, "200 OK", &success(&id, json!({"tools":[
                    {"name":"echo","inputSchema":{"type":"object"}}]})), "application/json"),
                "tools/call" => reply(&mut stream, "200 OK", &success(&id, json!({"content":[
                    {"type":"text","text":"legacy"}]})), "application/json"),
                "GET" => reply(&mut stream, "405 Method Not Allowed", "", "text/plain"),
                "DELETE" if refusal == "silent-delete" => thread::sleep(Duration::from_secs(8)),
                "DELETE" => reply(&mut stream, "200 OK", "", "text/plain"),
                other => panic!("Unexpected legacy request: {other}"),
            }
            let done = method == "DELETE";
            seen.push((method, incoming.headers, incoming.body));
            if done {
                expect_silence(&listener, "Unexpected request after the session DELETE");
                break;
            }
        }
        seen
    }

    fn accept(listener: &TcpListener) -> TcpStream {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            match listener.accept() {
                Ok((stream, _)) => { stream.set_nonblocking(false).unwrap(); return stream; }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                    thread::sleep(Duration::from_millis(5)),
                Err(e) => panic!("Fixture accept failed: {e}"),
            }
        }
    }

    /// Fails the fixture if the client opens any further connection.
    fn expect_silence(listener: &TcpListener, why: &str) {
        let deadline = Instant::now() + Duration::from_millis(350);
        while Instant::now() < deadline {
            match listener.accept() {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(5)),
                _ => panic!("{why}"),
            }
        }
    }

    fn fixture() -> (TcpListener, String) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = format!("http://127.0.0.1:{}/mcp", listener.local_addr().unwrap().port());
        (listener, address)
    }

    fn success(id: &Value, result: Value) -> String {
        json!({"jsonrpc":"2.0","id":id,"result":result}).to_string()
    }

    fn discovered(id: &Value) -> String {
        success(id, json!({"resultType":"complete","supportedVersions":[VERSION],"capabilities":{"tools":{}},
            "ttlMs":0,"cacheScope":"private","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"fixture","version":"0"}}}))
    }

    fn open(address: &str) -> Result<Session> { Session::open(address, None, &BTreeMap::new()) }

    #[test]
    fn modern_probe_and_call_use_metadata_without_legacy_session() {
        let (listener, address) = fixture();
        let server = thread::spawn(move || {
            for method in ["server/discover", "tools/list", "tools/call"] {
                let mut stream = accept(&listener);
                let incoming = receive(&mut stream);
                assert_eq!(incoming.body["method"], method);
                assert!(incoming.headers.contains("mcp-protocol-version: 2026-07-28"), "{}", incoming.headers);
                assert!(incoming.headers.contains(&format!("mcp-method: {method}")), "{}", incoming.headers);
                assert!(incoming.headers.contains("x-api-key: fixture-only-key"));
                assert!(!incoming.headers.contains("mcp-session-id:"));
                assert!(!incoming.headers.contains("authorization:"));
                assert_eq!(incoming.body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"], VERSION);
                assert!(incoming.body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"].is_object());
                let response = match method {
                    "server/discover" => discovered(&incoming.body["id"]),
                    "tools/list" => success(&incoming.body["id"], json!({"resultType":"complete","ttlMs":0,"cacheScope":"private",
                        "tools":[{"name":"echo","inputSchema":{"type":"object"}}]})),
                    _ => {
                        assert!(incoming.headers.contains("mcp-name: echo"));
                        assert_eq!(incoming.body["params"]["arguments"], json!({"value":1}));
                        success(&incoming.body["id"], json!({"resultType":"complete","content":[{"type":"text","text":"fixture"}]}))
                    }
                };
                if method == "tools/call" {
                    let note = json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"t","progress":1}});
                    reply(&mut stream, "200 OK", &format!(": keepalive\n\ndata: {note}\n\ndata: {response}\n\n"), "text/event-stream");
                } else {
                    reply(&mut stream, "200 OK", &response, "application/json");
                }
            }
            expect_silence(&listener, "Unexpected request after the tool call");
        });
        let mut headers = HeaderMap::new();
        let mut key = HeaderValue::from_static("fixture-only-key");
        key.set_sensitive(true);
        headers.insert("x-api-key", key);
        let mut session = Session::connect(endpoint(&address).unwrap(), None, headers).unwrap();
        assert_eq!(session.catalog().unwrap()[0]["name"], "echo");
        let arguments = json!({"value":1}).as_object().unwrap().clone();
        let called = session.call_tool("echo", arguments).unwrap();
        assert_eq!(called["content"][0]["text"], "fixture");
        server.join().unwrap();
    }

    /// Legacy servers answer `server/discover` with an empty 400 or 404 (a
    /// session server) or a 200 SSE "method not available" (a public legacy
    /// server). Each one gets exactly one `initialize`, then the session id
    /// on every later request, one tool call without replay and a closing
    /// DELETE.
    #[test]
    fn legacy_extensions_fall_back_to_one_initialize_and_keep_their_session() {
        for refusal in ["400", "404", "sse"] {
            let (listener, address) = fixture();
            let server = thread::spawn(move || legacy_server(listener, refusal));
            let mut session = open(&address).unwrap_or_else(|e| panic!("{refusal}: {e}"));
            assert_eq!(session.protocol_version(), "2025-11-25");
            assert_eq!(session.catalog().unwrap()[0]["name"], "echo");
            let called = session.call_tool("echo", Map::new()).unwrap();
            assert_eq!(called["content"][0]["text"], "legacy");
            drop(session);
            let seen = server.join().unwrap();
            let methods: Vec<&str> = seen.iter().map(|(m, _, _)| m.as_str()).filter(|m| *m != "GET").collect();
            assert_eq!(methods, ["server/discover", "initialize", "notifications/initialized",
                "tools/list", "tools/call", "DELETE"], "{refusal}");
            let initialize = &seen.iter().find(|(m, _, _)| m == "initialize").unwrap().2;
            assert_eq!(initialize["params"]["protocolVersion"], "2025-11-25");
            for (method, headers, _) in seen.iter().skip_while(|(m, _, _)| m != "notifications/initialized") {
                assert!(headers.contains("mcp-session-id: legacy-session"), "{refusal} {method}: {headers}");
            }
        }
    }

    /// A legacy server that never answers the closing DELETE cannot hold the
    /// client past the close bound, and a legacy server without a `tools`
    /// capability is refused before any listing or call.
    #[test]
    fn legacy_close_is_bounded_and_toolless_legacy_servers_are_refused() {
        let (listener, address) = fixture();
        let server = thread::spawn(move || legacy_server(listener, "silent-delete"));
        let session = open(&address).unwrap();
        let started = Instant::now();
        drop(session);
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_millis(4500), "the close bound was not enforced: {elapsed:?}");
        assert_eq!(server.join().unwrap().last().unwrap().0, "DELETE");

        let (listener, address) = fixture();
        let server = thread::spawn(move || legacy_server(listener, "no-tools"));
        assert!(open(&address).is_err());
        let seen = server.join().unwrap();
        assert!(seen.iter().all(|(method, _, _)| !method.starts_with("tools/")), "{seen:?}");
    }

    #[test]
    fn discovery_refusals_and_unserved_versions_fail_closed() {
        let refusals: Vec<(&str, Box<dyn Fn(&Value) -> String + Send>)> = vec![
            ("401 Unauthorized", Box::new(|_| String::new())),
            ("403 Forbidden", Box::new(|_| String::new())),
            ("429 Too Many Requests", Box::new(|_| String::new())),
            ("500 Internal Server Error", Box::new(|_| String::new())),
            ("307 Temporary Redirect", Box::new(|_| String::new())),
            ("400 Bad Request", Box::new(|id| json!({"jsonrpc":"2.0","id":id,
                "error":{"code":-32022,"message":"unsupported","data":{"supported":["2099-01-01"]}}}).to_string())),
            ("200 OK", Box::new(|id| json!({"jsonrpc":"2.0","id":id,
                "error":{"code":-32022,"message":"unsupported","data":{"supported":["2099-01-01"]}}}).to_string())),
            ("200 OK", Box::new(|id| success(&json!(id.as_u64().unwrap_or(0) + 7), json!({"resultType":"complete",
                "supportedVersions":[VERSION],"capabilities":{"tools":{}},"ttlMs":0,"cacheScope":"private"})))),
            ("200 OK", Box::new(|id| success(id, json!({"resultType":"complete",
                "supportedVersions":["2099-01-01"],"capabilities":{"tools":{}},"ttlMs":0,"cacheScope":"private"})))),
            ("200 OK", Box::new(|id| success(id, json!({"resultType":"complete",
                "supportedVersions":[VERSION],"capabilities":{},"ttlMs":0,"cacheScope":"private"})))),
        ];
        for (index, (status, body)) in refusals.into_iter().enumerate() {
            let (listener, address) = fixture();
            let server = thread::spawn(move || {
                let mut stream = accept(&listener);
                let incoming = receive(&mut stream);
                assert_eq!(incoming.body["method"], "server/discover");
                let text = body(&incoming.body["id"]);
                let kind = if text.is_empty() { "text/plain" } else { "application/json" };
                reply(&mut stream, status, &text, kind);
                drop(stream);
                expect_silence(&listener, "Unexpected request after a refused discovery");
            });
            assert!(open(&address).is_err(), "case {index}: {status}");
            server.join().unwrap();
        }
        // Refused addresses are never probed.
        assert!(open("http://example.com/mcp").is_err());
    }

    #[test]
    fn ambiguous_tool_failure_is_not_replayed_or_downgraded() {
        let (listener, address) = fixture();
        let server = thread::spawn(move || {
            let mut discover = accept(&listener);
            let incoming = receive(&mut discover);
            reply(&mut discover, "200 OK", &discovered(&incoming.body["id"]), "application/json");
            drop(discover);
            let mut call = accept(&listener);
            let incoming = receive(&mut call);
            assert_eq!(incoming.body["method"], "tools/call");
            // Simulate a tool that may have executed but whose reply was lost.
            drop(call);
            expect_silence(&listener, "Unexpected replay or legacy fallback");
        });
        let mut session = open(&address).unwrap();
        assert!(session.call_tool("echo", Map::new()).is_err());
        server.join().unwrap();
    }

    /// An input request or a task is refused after the single call; the
    /// client never answers it or polls, so the tool is not run twice.
    #[test]
    fn input_requests_and_tasks_are_refused_without_a_second_call() {
        for kind in ["input_required", "task"] {
            let (listener, address) = fixture();
            let server = thread::spawn(move || {
                let mut discover = accept(&listener);
                let incoming = receive(&mut discover);
                reply(&mut discover, "200 OK", &discovered(&incoming.body["id"]), "application/json");
                drop(discover);
                let mut call = accept(&listener);
                let incoming = receive(&mut call);
                assert_eq!(incoming.body["method"], "tools/call");
                let result = if kind == "task" {
                    json!({"resultType":"task","taskId":"fixture-task","status":"working",
                        "createdAt":"2026-11-25T00:00:00Z","lastUpdatedAt":"2026-11-25T00:00:00Z","ttlMs":null})
                } else {
                    json!({"resultType":"input_required","inputRequests":{"confirm":{"method":"elicitation/create",
                        "params":{"mode":"form","message":"Confirm?","requestedSchema":{"type":"object","properties":{}}}}},
                        "requestState":"fixture-state"})
                };
                reply(&mut call, "200 OK", &success(&incoming.body["id"], result), "application/json");
                drop(call);
                expect_silence(&listener, "Unexpected continuation, poll or replay");
            });
            let mut session = open(&address).unwrap();
            assert!(session.call_tool("echo", Map::new()).is_err(), "{kind}");
            server.join().unwrap();
        }
    }

    #[test]
    fn unroutable_names_and_parameter_headers_are_refused() {
        let annotated = json!({"inputSchema":{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}}}});
        assert!(declares_parameter_headers(&annotated));
        assert!(!declares_parameter_headers(&json!({"inputSchema":{"type":"object","properties":{"q":{"type":"string"}}}})));
        assert!(!valid_tool_name("echo\r\nx"));
        assert!(!valid_tool_name(""));
        assert!(valid_tool_name("search_model_context_protocol"));
    }
}
