// Copyright 2026 agent-bridge contributors
// SPDX-License-Identifier: Apache-2.0

//! Stateless MCP 2026-07-28 routing alongside the legacy `initialize` era.
//!
//! A request selects the modern era only through explicit markers: the
//! `server/discover` method or reserved `io.modelcontextprotocol/*` keys in
//! `params._meta`. A request with modern markers is never served under legacy
//! semantics, even when its metadata is malformed. Self-reported client
//! metadata is never an authenticated identity or an authorization input;
//! transports keep their own authentication in front of this router.
//!
//! Only `server/discover`, `tools/list` and `tools/call` are served. Tasks,
//! Multi Round-Trip Requests, subscriptions, resources and prompts are not
//! advertised, and their continuation fields are refused before dispatch.

use super::{parse_request_id, JsonRpcError, JsonRpcId, JsonRpcResponse, McpGateway, ToolDefinition, ToolHandler};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// The only modern protocol revision served per request.
pub const VERSION: &str = "2026-07-28";
/// Modern revisions accepted in `params._meta`, newest first.
pub const MODERN_VERSIONS: &[&str] = &[VERSION];

pub const VERSION_KEY: &str = "io.modelcontextprotocol/protocolVersion";
pub const CAPABILITIES_KEY: &str = "io.modelcontextprotocol/clientCapabilities";
pub const CLIENT_INFO_KEY: &str = "io.modelcontextprotocol/clientInfo";
pub const SERVER_INFO_KEY: &str = "io.modelcontextprotocol/serverInfo";
/// SHA-256 of the listed catalog, returned in discovery and listing `_meta`.
/// It changes whenever a tool name, description or schema changes, so a
/// client can tell that a cached listing no longer matches this server.
pub const CATALOG_REVISION_KEY: &str = "io.github.ironlegends/catalogRevision";

/// Header and body disagree, or a required routing header is missing.
pub const HEADER_MISMATCH: i64 = -32020;
/// A request needs a client capability that it did not declare.
pub const MISSING_REQUIRED_CLIENT_CAPABILITY: i64 = -32021;
/// The requested protocol revision is not served.
pub const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;

/// Continuation and task fields belong to extensions this server does not
/// advertise. They are refused so that a forged state never reaches a tool.
const UNSUPPORTED_CONTINUATIONS: &[&str] = &["inputResponses", "requestState", "inputRequestState", "task"];

fn validate_metadata(params: &Map<String, Value>) -> Result<(), JsonRpcError> {
    let meta = params
        .get("_meta")
        .and_then(Value::as_object)
        .ok_or_else(|| JsonRpcError::invalid_params("missing or invalid params._meta"))?;
    let requested = meta
        .get(VERSION_KEY)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| JsonRpcError::invalid_params("missing or invalid protocolVersion"))?;
    if !MODERN_VERSIONS.contains(&requested) {
        return Err(JsonRpcError::new(
            UNSUPPORTED_PROTOCOL_VERSION,
            "Unsupported protocol version",
            Some(json!({"supported": MODERN_VERSIONS, "requested": crate::echoed_version(requested)})),
        ));
    }
    if !meta.get(CAPABILITIES_KEY).is_some_and(Value::is_object) {
        return Err(JsonRpcError::invalid_params(
            "missing or invalid clientCapabilities",
        ));
    }
    if let Some(info) = meta.get(CLIENT_INFO_KEY) {
        if !info.is_object()
            || !info.get("name").is_some_and(Value::is_string)
            || !info.get("version").is_some_and(Value::is_string)
        {
            return Err(JsonRpcError::invalid_params("invalid clientInfo"));
        }
    }
    Ok(())
}

/// Remove `x-mcp-header` annotations from a published schema. This server
/// designates no parameter headers, so a modern HTTP client never mirrors
/// arguments into headers that the transport would have to trust. A schema
/// forwarded from an extension keeps its other keywords unchanged.
fn strip_parameter_headers(schema: &mut Value) {
    match schema {
        Value::Object(map) => {
            map.remove("x-mcp-header");
            map.values_mut().for_each(strip_parameter_headers);
        }
        Value::Array(items) => items.iter_mut().for_each(strip_parameter_headers),
        _ => {}
    }
}

impl<H: ToolHandler> McpGateway<H> {
    /// Serve one request under the stateless 2026-07-28 rules. Notifications
    /// never dispatch and never produce a response.
    pub fn handle_modern(&self, message: Value) -> Option<JsonRpcResponse> {
        let Some(obj) = message.as_object() else {
            return Some(JsonRpcResponse::error(
                JsonRpcId::Null,
                JsonRpcError::invalid_request("JSON-RPC payload must be an object"),
            ));
        };
        let id = match obj.get("id") {
            Some(id) => match parse_request_id(id) {
                Ok(id) => id,
                Err(error) => return Some(JsonRpcResponse::error(JsonRpcId::Null, error)),
            },
            None => return None,
        };
        if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Some(JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_request("jsonrpc must be 2.0"),
            ));
        }
        let Some(method) = obj.get("method").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
            return Some(JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_request("method must be a non-empty string"),
            ));
        };
        let Some(params) = obj.get("params").and_then(Value::as_object) else {
            return Some(JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_params("modern requests require params._meta"),
            ));
        };
        if let Err(error) = validate_metadata(params) {
            return Some(JsonRpcResponse::error(id, error));
        }
        if UNSUPPORTED_CONTINUATIONS.iter().any(|key| params.contains_key(*key)) {
            return Some(JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_params("continuations and tasks are not supported by this server"),
            ));
        }
        let allowed: &[&str] = match method {
            "server/discover" => &["_meta"],
            "tools/list" => &["_meta", "cursor"],
            "tools/call" => &["_meta", "name", "arguments"],
            _ => &[],
        };
        if !allowed.is_empty() && params.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Some(JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_params("unexpected modern request parameter"),
            ));
        }
        let mut response = match method {
            "server/discover" => {
                let mut result = json!({
                    "supportedVersions": MODERN_VERSIONS,
                    "capabilities": {"tools": {}},
                });
                if let Some(instructions) = &self.config.instructions {
                    result["instructions"] = json!(instructions);
                }
                JsonRpcResponse::success(id, result)
            }
            "tools/list" => {
                // The whole authorized catalog is returned at once, so no
                // cursor is ever issued and any presented cursor is unknown.
                if params.get("cursor").is_some_and(|v| !v.is_null()) {
                    return Some(JsonRpcResponse::error(
                        id, JsonRpcError::invalid_params("unknown catalog cursor"),
                    ));
                }
                JsonRpcResponse::success(id, json!({"tools": self.modern_catalog.tools}))
            }
            "tools/call" => self.handle_tools_call(id, Some(Value::Object(params.clone()))),
            _ => JsonRpcResponse::error(
                id,
                JsonRpcError::method_not_found(format!("method not found: {method}")),
            ),
        };
        if let Some(Value::Object(result)) = &mut response.result {
            result.insert("resultType".into(), json!("complete"));
            let catalog_result = matches!(method, "server/discover" | "tools/list");
            if catalog_result {
                // Each router serves one authorization view, so its catalog
                // may differ per access token: never shareable across callers.
                result.insert("ttlMs".into(), json!(self.config.catalog_ttl_ms));
                result.insert("cacheScope".into(), json!("private"));
            }
            // A tool result may carry its own _meta; add identity beside it.
            let meta = result.entry("_meta").or_insert_with(|| json!({}));
            if let Some(meta) = meta.as_object_mut() {
                meta.insert(SERVER_INFO_KEY.into(), json!(self.config.server_info));
                if catalog_result {
                    meta.insert(CATALOG_REVISION_KEY.into(), json!(self.modern_catalog.revision));
                }
            }
        }
        Some(response)
    }

    /// Route one parsed message to the era its markers select. This is the
    /// stateless per-request rule used by HTTP: both eras share an endpoint.
    pub fn handle_dual_era(&self, message: Value) -> Option<JsonRpcResponse> {
        if has_modern_marker(&message) {
            self.handle_modern(message)
        } else {
            self.handle_value(message)
        }
    }
}

/// The modern listing of a router's published catalog, sorted by name with
/// parameter-header annotations removed, and its revision digest.
#[derive(Debug, Clone)]
pub(crate) struct Catalog {
    tools: Value,
    revision: String,
}

impl Catalog {
    pub(crate) fn new(published: &[ToolDefinition]) -> Self {
        let mut tools: Vec<Value> = published.iter()
            .map(|tool| serde_json::to_value(tool).unwrap_or(Value::Null))
            .collect();
        tools.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        for tool in tools.iter_mut() {
            for key in ["inputSchema", "outputSchema"] {
                if let Some(schema) = tool.get_mut(key) {
                    strip_parameter_headers(schema);
                }
            }
        }
        let tools = Value::Array(tools);
        let digest = Sha256::digest(tools.to_string().as_bytes());
        let revision = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        Self { tools, revision }
    }
}

/// Recognize an explicit modern request even when its metadata is malformed.
/// A transport must not silently downgrade a request with modern markers.
pub fn has_modern_marker(message: &Value) -> bool {
    message.get("method").and_then(Value::as_str) == Some("server/discover")
        || message
            .get("params")
            .and_then(|p| p.get("_meta"))
            .and_then(Value::as_object)
            .is_some_and(|meta| {
                [VERSION_KEY, CAPABILITIES_KEY, CLIENT_INFO_KEY]
                    .iter()
                    .any(|key| meta.contains_key(*key))
            })
}

/// Parse one frame and report whether it selects the modern era. No frame
/// may contain duplicate object keys: the ordinary parser keeps the last
/// duplicate, so a later key could hide a modern marker and downgrade the
/// frame, and intermediaries could read a different method, version, name
/// or arguments from the same bytes.
pub fn classify(raw: &str) -> Result<(Value, bool), serde_json::Error> {
    let message = parse_unique(raw)?;
    let modern = has_modern_marker(&message);
    Ok((message, modern))
}

/// The stdio era is fixed by the first successful `server/discover` or
/// modern request, or by a successful `initialize`. Afterwards a frame from
/// the other era is refused. Before either, a legacy frame other than
/// `initialize` is refused, so a malformed first frame never enables tools.
/// This is a framing guard, not an authorization or conversation identity.
#[derive(Default)]
pub struct StdioEra {
    modern: Option<bool>,
}

impl StdioEra {
    pub fn dispatch<H: ToolHandler>(
        &mut self,
        gateway: &McpGateway<H>,
        raw: &str,
    ) -> Option<String> {
        let (message, modern) = match classify(raw) {
            Ok(classified) => classified,
            Err(_) => return parse_failure(),
        };
        let method = message.get("method").and_then(Value::as_str);
        let response = match self.modern {
            Some(true) if modern => gateway.handle_modern(message),
            Some(false) if !modern => gateway.handle_value(message),
            None if modern => {
                let response = gateway.handle_modern(message);
                if response.as_ref().is_some_and(|r| r.result.is_some()) {
                    self.modern = Some(true);
                }
                response
            }
            None if method == Some("initialize") => {
                let response = gateway.handle_value(message);
                if response.as_ref().is_some_and(|r| r.result.is_some()) {
                    self.modern = Some(false);
                }
                response
            }
            _ => {
                let id = match message.get("id") {
                    None => return None,
                    Some(id) => match parse_request_id(id) {
                        Ok(id) => id,
                        Err(error) => return serde_json::to_string(
                            &JsonRpcResponse::error(JsonRpcId::Null, error),
                        ).ok(),
                    },
                };
                Some(JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params("protocol era not established or mixed"),
                ))
            }
        };
        response.and_then(|r| serde_json::to_string(&r).ok())
    }
}

/// Reject duplicate JSON object keys before the ordinary Value parser can
/// discard them.
pub fn parse_unique(raw: &str) -> Result<Value, serde_json::Error> {
    serde_json::from_str::<UniqueKeys>(raw)?;
    serde_json::from_str(raw)
}

struct UniqueKeys;

impl<'de> serde::Deserialize<'de> for UniqueKeys {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Check;
        impl<'de> serde::de::Visitor<'de> for Check {
            type Value = UniqueKeys;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON with unique object keys")
            }
            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> { Ok(UniqueKeys) }
            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> { Ok(UniqueKeys) }
            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> { Ok(UniqueKeys) }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> { Ok(UniqueKeys) }
            fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self::Value, E> { Ok(UniqueKeys) }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> { Ok(UniqueKeys) }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                while seq.next_element::<UniqueKeys>()?.is_some() {}
                Ok(UniqueKeys)
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut keys = std::collections::HashSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !keys.insert(key) {
                        return Err(serde::de::Error::custom("duplicate JSON object key"));
                    }
                    map.next_value::<UniqueKeys>()?;
                }
                Ok(UniqueKeys)
            }
        }
        d.deserialize_any(Check)
    }
}

pub(crate) fn ambiguous_json() -> JsonRpcResponse {
    JsonRpcResponse::error(
        JsonRpcId::Null,
        JsonRpcError::new(-32700, "invalid or ambiguous JSON request", None),
    )
}

fn parse_failure() -> Option<String> {
    serde_json::to_string(&ambiguous_json()).ok()
}
