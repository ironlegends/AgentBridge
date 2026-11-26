// Copyright 2026 agent-bridge contributors
// SPDX-License-Identifier: Apache-2.0

//! Streamable HTTP rules for MCP 2026-07-28 requests. The request body is the
//! source of truth; routing headers can only cause a refusal and never
//! authorize or modify a tool call. Legacy requests are left unchanged.

use axum::http::{HeaderMap, StatusCode};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};

const VERSION_KEY: &str = "io.modelcontextprotocol/protocolVersion";
const VERSION_HEADER: &str = "mcp-protocol-version";
const METHOD_HEADER: &str = "mcp-method";
const NAME_HEADER: &str = "mcp-name";

fn modern_intent(headers: &HeaderMap, message: &Value) -> bool {
    let modern_body = agent_bridge_gateway::modern::has_modern_marker(message);
    // A legacy `initialize` precedes any negotiated version header, so its
    // version is negotiated from the body as the legacy spec requires.
    let legacy_initialize = !modern_body
        && message.get("method").and_then(Value::as_str) == Some("initialize");
    let modern_version = match single(headers, VERSION_HEADER) {
        // Several version lines are ambiguous and refused as modern.
        Err(()) => true,
        Ok(Some(version)) => !legacy_initialize
            && !agent_bridge_gateway::DEFAULT_SUPPORTED_PROTOCOL_VERSIONS.contains(&version),
        Ok(None) => false,
    };
    headers.contains_key(METHOD_HEADER)
        || headers.contains_key(NAME_HEADER)
        || headers.keys().any(|name| name.as_str().starts_with("mcp-param-"))
        || modern_version
        || modern_body
}

/// Read one header only. Multiple field lines are ambiguous and rejected.
/// Optional whitespace around a field value is not part of the value.
fn single<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, ()> {
    let mut values = headers.get_all(name).iter();
    let first = values.next().map(|v| v.to_str().map(|v| v.trim_matches([' ', '\t'])).map_err(|_| ())).transpose()?;
    if values.next().is_some() {
        return Err(());
    }
    Ok(first)
}

fn decode_name(value: &str) -> Result<String, ()> {
    if let Some(inner) = value
        .strip_prefix("=?base64?")
        .and_then(|s| s.strip_suffix("?="))
    {
        String::from_utf8(STANDARD.decode(inner).map_err(|_| ())?).map_err(|_| ())
    } else if value.is_ascii() && !value.is_empty()
        && value == value.trim()
        && !value.bytes().any(|b| b < 0x20 && b != b'\t' || b == 0x7f)
    {
        Ok(value.to_owned())
    } else {
        Err(())
    }
}

fn error(message: &Value, code: i64, reason: &'static str) -> Value {
    let id = message.get("id").filter(|id| id.is_string() || id.is_i64() || id.is_u64());
    json!({"jsonrpc":"2.0", "id":id, "error":{"code":code,"message":reason}})
}

/// Validate the supported routing surface before any gateway dispatch.
/// Parameter headers are intentionally refused until schema mapping is qualified.
fn validate(headers: &HeaderMap, message: &Value) -> Result<(), Value> {
    let mismatch = |reason| error(message, -32020, reason);
    if message.get("id").is_none() {
        return Err(error(message, -32600, "client notifications are not defined for modern Streamable HTTP"));
    }
    let version = message.pointer(&format!("/params/_meta/{}", VERSION_KEY.replace('/', "~1")))
        .and_then(Value::as_str);
    let method = message.get("method").and_then(Value::as_str);
    let version_header = single(headers, VERSION_HEADER).map_err(|_| mismatch("ambiguous protocol version header"))?;
    let method_header = single(headers, METHOD_HEADER).map_err(|_| mismatch("ambiguous method header"))?;
    // A body without its protocol version is invalid params rather than a
    // header mismatch; a present version must match its header.
    if version.is_none() && version_header.is_some() {
        return Err(error(message, -32602, "missing or invalid params._meta protocolVersion"));
    }
    if version.is_none() || version_header.is_none() || version_header != version {
        return Err(mismatch("protocol version header is missing or disagrees with body"));
    }
    if method.is_none() || method_header.is_none() || method_header != method {
        return Err(mismatch("method header is missing or disagrees with body"));
    }
    let expected_name = match method {
        Some("tools/call" | "prompts/get") => Some(message.pointer("/params/name")),
        // Mcp-Name is defined only for these core methods in 2026-07-28.
        Some("resources/read") => Some(message.pointer("/params/uri")),
        _ => None,
    };
    let name = single(headers, NAME_HEADER).map_err(|_| mismatch("ambiguous name header"))?;
    if let Some(expected) = expected_name {
        let expected = expected.and_then(Value::as_str).ok_or_else(|| mismatch("missing body name"))?;
        let decoded = name.ok_or_else(|| mismatch("missing name header"))
            .and_then(|s| decode_name(s).map_err(|_| mismatch("invalid name encoding")))?;
        if decoded != expected {
            return Err(mismatch("name header disagrees with body"));
        }
    } else if name.is_some() {
        return Err(mismatch("unexpected name header"));
    }
    if headers.keys().any(|name| name.as_str().starts_with("mcp-param-")) {
        // No published tool designates x-mcp-header parameters, so a
        // parameter header cannot be validated against the body.
        return Err(mismatch("parameter headers are not designated by this server"));
    }
    Ok(())
}

/// Outcome of the modern checks that precede any dispatch.
#[derive(Debug)]
pub enum Preflight {
    /// Not a modern request: keep the existing legacy transport behavior.
    Legacy,
    /// A modern request whose headers agree with its unambiguous body.
    Modern,
    /// Refuse without dispatch, with this status and JSON-RPC error body.
    Reject(StatusCode, String),
}

/// Classify one POST body and validate modern routing headers. A request with
/// any modern marker in its headers or body is never downgraded to legacy.
pub fn preflight(headers: &HeaderMap, body: &str) -> Preflight {
    let message = match serde_json::from_str::<Value>(body) {
        Ok(message) => message,
        // Legacy parsing reports its own error for invalid JSON.
        Err(_) if !headers_mark_modern(headers) => return Preflight::Legacy,
        Err(_) => return Preflight::Reject(StatusCode::BAD_REQUEST, parse_error()),
    };
    // Duplicate keys are refused in both eras: the parser keeps the last
    // duplicate, which could hide a modern marker and downgrade the request.
    if agent_bridge_gateway::modern::parse_unique(body).is_err() {
        return Preflight::Reject(StatusCode::BAD_REQUEST, parse_error());
    }
    if !modern_intent(headers, &message) {
        return Preflight::Legacy;
    }
    match validate(headers, &message) {
        Ok(()) => Preflight::Modern,
        Err(error) => Preflight::Reject(StatusCode::BAD_REQUEST, error.to_string()),
    }
}

fn parse_error() -> String {
    json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"invalid or ambiguous JSON request"}}).to_string()
}

fn headers_mark_modern(headers: &HeaderMap) -> bool {
    modern_intent(headers, &Value::Null)
}

/// HTTP status for a modern response: protocol errors are 400 and an
/// unknown method is 404, so a dual-era client never mistakes them for a
/// legacy server.
pub fn response_status(response: &str) -> StatusCode {
    match serde_json::from_str::<Value>(response).ok()
        .and_then(|v| v.pointer("/error/code").and_then(Value::as_i64)) {
        Some(-32601) => StatusCode::NOT_FOUND,
        Some(-32020 | -32021 | -32022 | -32602 | -32600 | -32700) => StatusCode::BAD_REQUEST,
        _ => StatusCode::OK,
    }
}

/// Audit metadata only. Content, messages, IDs and tool results are skipped.
#[derive(Default)]
pub struct ResponseMetadata {
    pub error_code: Option<i64>,
    pub is_tool_error: bool,
}

impl ResponseMetadata {
    pub fn read(response: &str) -> Self {
        #[derive(serde::Deserialize)]
        struct Envelope {
            error: Option<Error>,
            result: Option<ResultFields>,
        }
        #[derive(serde::Deserialize)]
        struct Error {
            code: Option<i64>,
        }
        #[derive(serde::Deserialize)]
        struct ResultFields {
            #[serde(rename = "isError")]
            is_error: Option<bool>,
        }
        let Ok(envelope) = serde_json::from_str::<Envelope>(response) else {
            return Self::default();
        };
        Self {
            error_code: envelope.error.and_then(|error| error.code),
            is_tool_error: envelope.result.and_then(|result| result.is_error).unwrap_or(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn fixture(name: &str) -> (HeaderMap, Value) {
        let body = json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
            "name":name,"_meta":{(VERSION_KEY):"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":{}}
        }});
        let mut headers = HeaderMap::new();
        headers.insert(VERSION_HEADER, HeaderValue::from_static("2026-07-28"));
        headers.insert(METHOD_HEADER, HeaderValue::from_static("tools/call"));
        headers.insert(NAME_HEADER, HeaderValue::from_static("echo"));
        (headers, body)
    }

    #[test]
    fn routing_headers_require_exact_agreement_and_uniqueness() {
        let (h, b) = fixture("echo");
        assert!(validate(&h, &b).is_ok());
        for field in [VERSION_HEADER, METHOD_HEADER, NAME_HEADER] {
            let mut missing = h.clone();
            missing.remove(field);
            assert!(validate(&missing, &b).is_err());
            let mut duplicate = h.clone();
            duplicate.append(field, h.get(field).unwrap().clone());
            assert!(validate(&duplicate, &b).is_err());
            let mut wrong = h.clone();
            wrong.insert(field, HeaderValue::from_static("wrong"));
            let err = validate(&wrong, &b).unwrap_err();
            assert_eq!(err["error"]["code"], -32020);
            assert_eq!(err["id"], 3);
        }
    }

    #[test]
    fn encoded_names_are_decoded_before_comparison() {
        let (mut h, b) = fixture("Hello, 世界");
        h.insert(NAME_HEADER, HeaderValue::from_static("=?base64?SGVsbG8sIOS4lueVjA==?="));
        assert!(validate(&h, &b).is_ok());
        h.insert(NAME_HEADER, HeaderValue::from_static("=?base64?bad!?="));
        assert!(validate(&h, &b).is_err());
    }

    #[test]
    fn modern_intent_cannot_be_hidden_by_malformed_or_legacy_headers() {
        let (h, mut b) = fixture("echo");
        b["params"].as_object_mut().unwrap().remove("_meta");
        assert!(modern_intent(&h, &b));
        assert!(validate(&h, &b).is_err());
        let (mut h, b) = fixture("echo");
        h.clear();
        assert!(modern_intent(&h, &b));
        assert!(validate(&h, &b).is_err());
        h.insert(VERSION_HEADER, HeaderValue::from_static("2025-06-18"));
        assert!(modern_intent(&h, &b));
        assert!(validate(&h, &b).is_err());
    }

    #[test]
    fn unqualified_parameter_headers_are_refused() {
        let (mut h, b) = fixture("echo");
        h.insert("mcp-param-region", HeaderValue::from_static("test"));
        assert!(validate(&h, &b).is_err());
    }

    #[test]
    fn protocol_errors_map_to_modern_http_status() {
        for code in [-32020, -32021, -32022, -32602] {
            assert_eq!(response_status(&json!({"error":{"code":code}}).to_string()), StatusCode::BAD_REQUEST);
        }
        assert_eq!(response_status(&json!({"error":{"code":-32601}}).to_string()), StatusCode::NOT_FOUND);
        assert_eq!(response_status(&json!({"result":{"resultType":"complete"}}).to_string()), StatusCode::OK);
    }

    #[test]
    fn response_status_reads_only_the_error_code_path() {
        assert_eq!(response_status(r#"{"error":[-32601]}"#), StatusCode::OK);
        assert_eq!(response_status(r#"[{"code":-32601}]"#), StatusCode::OK);
        assert_eq!(response_status(r#"{"error":{"code":-32601},"result":false}"#), StatusCode::NOT_FOUND);
    }

    #[test]
    fn header_whitespace_is_ignored_but_value_case_is_not() {
        let (mut h, b) = fixture("echo");
        h.insert(METHOD_HEADER, HeaderValue::from_static("  tools/call\t"));
        h.insert(NAME_HEADER, HeaderValue::from_static(" echo "));
        assert!(validate(&h, &b).is_ok());
        h.insert(METHOD_HEADER, HeaderValue::from_static("Tools/Call"));
        assert_eq!(validate(&h, &b).unwrap_err()["error"]["code"], -32020);
    }

    #[test]
    fn preflight_refuses_before_dispatch_and_keeps_legacy_untouched() {
        let (h, b) = fixture("echo");
        assert!(matches!(preflight(&h, &b.to_string()), Preflight::Modern));
        let duplicate = b.to_string().replacen("\"name\":\"echo\"", "\"name\":\"echo\",\"name\":\"echo\"", 1);
        assert!(matches!(preflight(&h, &duplicate), Preflight::Reject(StatusCode::BAD_REQUEST, _)));
        assert!(matches!(preflight(&h, "{not json"), Preflight::Reject(StatusCode::BAD_REQUEST, _)));
        let legacy = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}).to_string();
        assert!(matches!(preflight(&HeaderMap::new(), &legacy), Preflight::Legacy));
        assert!(matches!(preflight(&HeaderMap::new(), "{not json"), Preflight::Legacy));
        let mut old = HeaderMap::new();
        old.insert(VERSION_HEADER, HeaderValue::from_static("2025-06-18"));
        assert!(matches!(preflight(&old, &legacy), Preflight::Legacy));

        // A later duplicate key cannot hide a modern marker from the router.
        let hidden = r#"{"jsonrpc":"2.0","id":1,"method":"server/discover","method":"tools/call","params":{"name":"echo"}}"#;
        assert!(matches!(preflight(&HeaderMap::new(), hidden), Preflight::Reject(StatusCode::BAD_REQUEST, _)));
        // Whitespace around a legacy version is not part of it; several
        // version lines are ambiguous.
        let mut padded = HeaderMap::new();
        padded.insert(VERSION_HEADER, HeaderValue::from_static("2025-11-25 "));
        assert!(matches!(preflight(&padded, &legacy), Preflight::Legacy));
        let mut twice = old.clone();
        twice.append(VERSION_HEADER, HeaderValue::from_static("2024-11-05"));
        assert!(matches!(preflight(&twice, &legacy), Preflight::Reject(StatusCode::BAD_REQUEST, _)));
        // A legacy initialize negotiates from its body, whatever version
        // header precedes the negotiation.
        let initialize = json!({"jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2025-09-01","capabilities":{}}}).to_string();
        let mut unknown = HeaderMap::new();
        unknown.insert(VERSION_HEADER, HeaderValue::from_static("2025-09-01"));
        assert!(matches!(preflight(&unknown, &initialize), Preflight::Legacy));
        assert!(matches!(preflight(&unknown, &legacy), Preflight::Reject(StatusCode::BAD_REQUEST, _)));
    }

    #[test]
    fn removed_methods_reach_the_router_as_unknown_methods() {
        for method in ["resources/subscribe", "resources/unsubscribe", "tasks/get"] {
            let body = json!({"jsonrpc":"2.0","id":5,"method":method,"params":{"uri":"x",
                "_meta":{(VERSION_KEY):"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}});
            let mut h = HeaderMap::new();
            h.insert(VERSION_HEADER, HeaderValue::from_static("2026-07-28"));
            h.insert(METHOD_HEADER, HeaderValue::from_str(method).unwrap());
            assert!(validate(&h, &body).is_ok(), "{method}");
        }
    }
}
