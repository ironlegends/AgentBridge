use crate::{error, Result};
use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, CONTENT_TYPE};
use reqwest::{Method, StatusCode, Url};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read};
use std::time::Duration;
use std::collections::BTreeMap;

const MAX_BYTES: usize = 1024 * 1024;
const VERSION: &str = "2025-06-18";

pub(crate) struct Session {
    client: Client,
    endpoint: Url,
    bearer: Option<String>,
    headers: HeaderMap,
    session: Option<String>,
    version: Option<String>,
    sequence: u64,
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
        let client = Client::builder().redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never()).no_proxy()
            .connect_timeout(Duration::from_secs(4)).timeout(Duration::from_secs(12)).build()
            .map_err(|_| error("Cannot initialize the extension transport"))?;
        let mut this = Self { client, endpoint, bearer, headers, session: None, version: None, sequence: 0 };
        let hello = this.request("initialize", json!({"protocolVersion":VERSION,"capabilities":{},
            "clientInfo":{"name":"agent-bridge","version":env!("CARGO_PKG_VERSION")}}))?;
        let version = hello["protocolVersion"].as_str().ok_or_else(|| error("Missing MCP version"))?;
        if !matches!(version, "2025-03-26" | "2025-06-18") || !hello["capabilities"]["tools"].is_object() {
            return Err(error("Extension protocol version or tool capability unsupported"));
        }
        this.version = Some(version.to_owned());
        let accepted = this.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))?;
        if accepted.status() != StatusCode::ACCEPTED {
            return Err(error("Extension did not acknowledge initialization"));
        }
        Ok(this)
    }

    fn builder(&self, method: Method) -> reqwest::blocking::RequestBuilder {
        let mut request = self.client.request(method,self.endpoint.clone())
            .headers(self.headers.clone())
            .header(ACCEPT,"application/json, text/event-stream");
        if let Some(secret) = &self.bearer { request = request.bearer_auth(secret); }
        if let Some(id) = &self.session { request = request.header("Mcp-Session-Id",id); }
        if let Some(version) = &self.version { request = request.header("MCP-Protocol-Version",version); }
        request
    }

    fn send(&self, message: Value) -> Result<Response> {
        self.builder(Method::POST).json(&message).send()
            .map_err(|_| error("Extension did not return a confirmed response"))
    }

    pub fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        self.sequence += 1;
        let id = self.sequence;
        let response = self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))?;
        if !response.status().is_success() { return Err(error("Extension refused the request")); }
        if method == "initialize" {
            if let Some(header) = response.headers().get("Mcp-Session-Id") {
                let value = header.to_str().map_err(|_| error("Invalid extension session"))?;
                if value.is_empty() || value.len() > 256 || !value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
                    return Err(error("Invalid extension session"));
                }
                self.session = Some(value.to_owned());
            }
        }
        let sse = match response.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next()).map(str::trim) {
            Some("application/json") => false,
            Some("text/event-stream") => true,
            _ => return Err(error("Unsupported extension response type")),
        };
        let reader = response.take((MAX_BYTES+1) as u64);
        let message: Value = if sse {
            let mut data = String::new();
            let mut found = None;
            for line in BufReader::new(reader).lines() {
                let line = line.map_err(|_| error("Invalid extension event stream"))?;
                if line.is_empty() && !data.is_empty() {
                    let event: Value = serde_json::from_str(&data).map_err(|_| error("Invalid extension event"))?;
                    if event["id"].as_u64() == Some(id) { found = Some(event); break; }
                    data.clear();
                } else if let Some(part) = line.strip_prefix("data:") {
                    data.push_str(part.strip_prefix(' ').unwrap_or(part)); data.push('\n');
                }
            }
            found.ok_or_else(|| error("Extension reply missing or too large"))?
        } else {
            let mut bytes = Vec::new();
            let mut reader = reader;
            reader.read_to_end(&mut bytes).map_err(|_| error("Incomplete extension reply"))?;
            if bytes.len() > MAX_BYTES { return Err(error("Extension reply exceeds limit")); }
            serde_json::from_slice(&bytes).map_err(|_| error("Invalid extension JSON"))?
        };
        if message["jsonrpc"] != "2.0" || message["id"].as_u64() != Some(id)
            || message.get("error").is_some() || !message["result"].is_object() {
            return Err(error("Extension returned an error or mismatched reply"));
        }
        Ok(message["result"].clone())
    }

    /// One confirmed MCP tools/list traversal, without tool invocation or
    /// registry mutation. Bounded to 16 pages and 256 unique tool names.
    pub fn catalog(&mut self) -> Result<Vec<Value>> {
        use std::collections::BTreeSet;
        let mut params = json!({});
        let mut seen_cursors = BTreeSet::<String>::new();
        let mut names = BTreeSet::<String>::new();
        let mut entries = Vec::new();
        for _ in 0..16 {
            let response = self.request("tools/list", params)?;
            let tools = response["tools"].as_array()
                .ok_or_else(|| error("Invalid remote MCP tool catalog"))?;
            for tool in tools {
                let name = tool.get("name").and_then(Value::as_str)
                    .ok_or_else(|| error("Remote MCP tool has no name"))?;
                if name.is_empty() || name.len() > 128
                    || !name.bytes().all(|b| b.is_ascii_alphanumeric()
                        || matches!(b, b'_' | b'-' | b'.'))
                    || !names.insert(name.to_owned())
                    || entries.len() >= 256
                {
                    return Err(error("Remote MCP catalog is ambiguous or too large"));
                }
                if serde_json::to_vec(tool).map_err(|_| error("Invalid remote MCP descriptor"))?.len() > 64 * 1024 {
                    return Err(error("Remote MCP descriptor exceeds bound"));
                }
                entries.push(tool.clone());
            }
            match response.get("nextCursor") {
                None | Some(Value::Null) => return Ok(entries),
                Some(Value::String(cursor))
                    if !cursor.is_empty() && cursor.len() <= 4096
                        && seen_cursors.insert(cursor.clone()) =>
                {
                    params = json!({"cursor":cursor});
                }
                _ => return Err(error("Invalid or repeated MCP pagination cursor")),
            }
        }
        Err(error("Remote MCP tool catalog exceeds pagination limit"))
    }

    pub fn tool(&mut self, name: &str) -> Result<Value> {
        let mut params = json!({});
        let mut found = None;
        for _ in 0..16 {
            let result = self.request("tools/list", params)?;
            for entry in result["tools"].as_array().ok_or_else(|| error("Invalid tools list"))? {
                if entry["name"].as_str() == Some(name) && found.replace(entry.clone()).is_some() {
                    return Err(error("Ambiguous extension tool name"));
                }
            }
            match result.get("nextCursor") {
                None | Some(Value::Null) => return found.ok_or_else(|| error("Extension tool not found")),
                Some(Value::String(c)) if !c.is_empty() && c.len() <= 4096 => params = json!({"cursor":c}),
                _ => return Err(error("Invalid extension pagination")),
            }
        }
        Err(error("Extension catalog exceeds pagination limit"))
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
    fn header_env_reaches_the_http_request_but_is_redacted_from_debug() {
        let references = BTreeMap::from([("X-Api-Key".into(), "AGENT_BRIDGE_EXTENSION_TEST_KEY".into())]);
        crate::validate_header_env("https://example.invalid/mcp", &references, false).unwrap();
        let headers = resolve_headers(&references, |name| {
            assert_eq!(name, "AGENT_BRIDGE_EXTENSION_TEST_KEY"); Some("fixture-only-key".into())
        }).unwrap();
        let session = Session { client:Client::new(), endpoint:endpoint("https://example.invalid/mcp").unwrap(),
            bearer:None, headers, session:Some("owned-session".into()), version:Some(VERSION.into()), sequence:0 };
        let request = session.builder(Method::POST).build().unwrap();
        assert_eq!(request.headers()["x-api-key"], "fixture-only-key");
        assert!(request.headers()["x-api-key"].is_sensitive());
        assert_eq!(request.headers()["mcp-session-id"], "owned-session");
        assert_eq!(request.headers()["mcp-protocol-version"], VERSION);
        assert!(!format!("{request:?}").contains("fixture-only-key"));
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

impl Drop for Session {
    fn drop(&mut self) {
        if self.session.is_some() {
            let _ = self.builder(Method::DELETE).timeout(Duration::from_secs(2)).send();
        }
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
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_proxy()
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
