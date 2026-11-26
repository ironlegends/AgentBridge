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

//! Pure JSON-RPC 2.0 / MCP gateway router for `agent-bridge`.
//!
//! This crate performs stateless MCP JSON-RPC routing (`initialize`, `ping`,
//! notifications without responses, `tools/list`, `tools/call`) without
//! binding sockets, spawning commands, or accessing sessions or secrets.
//! Requests with MCP 2026-07-28 per-request metadata, and `server/discover`,
//! are served by [`modern`] instead of the legacy `initialize` era.

pub mod stdio;
pub mod modern;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Number, Value};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

/// JSON-RPC protocol version mandated by MCP.
pub const JSONRPC_VERSION: &str = "2.0";

/// Default MCP protocol versions supported by this router, ordered from newest
/// (preferred) to oldest.
pub const DEFAULT_SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
];

/// A client-supplied protocol version as it may be echoed in an error: only
/// a short string, so arbitrary client data is never reflected.
pub(crate) fn echoed_version(requested: &str) -> Value {
    if requested.len() <= 32 { Value::from(requested) } else { Value::Null }
}

/// Standard JSON-RPC 2.0 error codes.
pub mod error_codes {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL_ERROR: i64 = -32603;
}

/// JSON-RPC message identifier.
///
/// Incoming MCP requests must carry either `String` or integer `Number`.
/// `Null` is only emitted on protocol errors where no valid request ID could
/// be extracted (such as parse errors or malformed envelopes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum JsonRpcId {
    String(String),
    Number(Number),
    Null,
}

/// JSON-RPC 2.0 protocol error object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    pub fn new(code: i64, message: impl Into<String>, data: Option<Value>) -> Self {
        Self {
            code,
            message: message.into(),
            data,
        }
    }

    pub fn parse_error(message: impl Into<String>) -> Self {
        Self::new(error_codes::PARSE_ERROR, message, None)
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(error_codes::INVALID_REQUEST, message, None)
    }

    pub fn method_not_found(message: impl Into<String>) -> Self {
        Self::new(error_codes::METHOD_NOT_FOUND, message, None)
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(error_codes::INVALID_PARAMS, message, None)
    }

    pub fn invalid_params_with_data(message: impl Into<String>, data: Value) -> Self {
        Self::new(error_codes::INVALID_PARAMS, message, Some(data))
    }

    pub fn internal_error(message: impl Into<String>) -> Self {
        Self::new(error_codes::INTERNAL_ERROR, message, None)
    }
}

impl fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JSON-RPC error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for JsonRpcError {}

/// JSON-RPC 2.0 response envelope.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    pub id: JsonRpcId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub fn success(id: JsonRpcId, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION,
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: JsonRpcId, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION,
            id,
            result: None,
            error: Some(error),
        }
    }
}

/// Server identity metadata advertised during `initialize`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

impl ServerInfo {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }
}

/// Configuration for [`McpGateway`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayConfig {
    pub server_info: ServerInfo,
    /// Ordered list of supported MCP protocol versions (first entry is preferred).
    pub supported_protocol_versions: Vec<String>,
    /// Optional server usage instructions returned during `initialize`.
    pub instructions: Option<String>,
    /// Freshness hint, in milliseconds, for `server/discover` and
    /// `tools/list`. The default `0` means "re-fetch every time". A positive
    /// value is safe only when the published catalog cannot change for the
    /// lifetime of this router; results stay `cacheScope: private`.
    pub catalog_ttl_ms: u64,
    /// When `false` (default, standard MCP behavior), an unknown client version
    /// negotiates down to the server's preferred version. When `true`, an
    /// unsupported version returns a `-32602` Invalid Params protocol error.
    pub strict_version_negotiation: bool,
}

impl GatewayConfig {
    pub fn new(server_name: impl Into<String>, server_version: impl Into<String>) -> Self {
        Self {
            server_info: ServerInfo::new(server_name, server_version),
            supported_protocol_versions: DEFAULT_SUPPORTED_PROTOCOL_VERSIONS
                .iter()
                .map(|v| (*v).to_string())
                .collect(),
            instructions: None,
            catalog_ttl_ms: 0,
            strict_version_negotiation: false,
        }
    }

    pub fn with_supported_protocol_versions<I, S>(mut self, versions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.supported_protocol_versions = versions
            .into_iter()
            .map(Into::into)
            .filter(|v| !v.trim().is_empty())
            .collect();
        self
    }

    pub fn with_instructions(mut self, instructions: impl Into<String>) -> Self {
        self.instructions = Some(instructions.into());
        self
    }

    /// Sets the `ttlMs` freshness hint for discovery and catalog listings.
    pub fn with_catalog_ttl_ms(mut self, ttl_ms: u64) -> Self {
        self.catalog_ttl_ms = ttl_ms;
        self
    }

    pub fn with_strict_version_negotiation(mut self, strict: bool) -> Self {
        self.strict_version_negotiation = strict;
        self
    }
}

/// MCP tool catalog entry supplied by the caller.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDefinition {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub input_schema: Value,
}

impl ToolDefinition {
    pub fn new(
        name: impl Into<String>,
        description: Option<String>,
        input_schema: Value,
    ) -> Self {
        Self {
            name: name.into(),
            title: None,
            description,
            input_schema,
        }
    }

    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }
}

/// Content item returned by `tools/call`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ToolContent {
    Text {
        text: String,
    },
    Image {
        data: String,
        #[serde(rename = "mimeType")]
        mime_type: String,
    },
    Resource {
        resource: Value,
    },
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Result payload returned for a `tools/call` invocation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCallResult {
    pub content: Vec<ToolContent>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_error: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured_content: Option<Value>,
}

impl ToolCallResult {
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![ToolContent::Text { text: text.into() }],
            is_error: false,
            structured_content: None,
        }
    }

    pub fn structured(text: impl Into<String>, structured_content: Value) -> Self {
        Self {
            content: vec![ToolContent::Text { text: text.into() }],
            is_error: false,
            structured_content: Some(structured_content),
        }
    }

    pub fn tool_error(message: impl Into<String>) -> Self {
        Self {
            content: vec![ToolContent::Text {
                text: message.into(),
            }],
            is_error: true,
            structured_content: None,
        }
    }
}

/// Distinguishes domain tool failures from JSON-RPC protocol errors.
#[derive(Debug, Clone, PartialEq)]
pub enum ToolDispatchError {
    /// Tool execution failed: serialized as a JSON-RPC `result` with `isError: true`.
    ToolError {
        message: String,
        content: Vec<ToolContent>,
    },
    /// Protocol-level error: serialized as a JSON-RPC `error` object.
    Protocol(JsonRpcError),
}

impl ToolDispatchError {
    pub fn tool_error(message: impl Into<String>) -> Self {
        let message = message.into();
        Self::ToolError {
            content: vec![ToolContent::Text {
                text: message.clone(),
            }],
            message,
        }
    }

    pub fn tool_error_with_content(
        message: impl Into<String>,
        content: Vec<ToolContent>,
    ) -> Self {
        Self::ToolError {
            message: message.into(),
            content,
        }
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::Protocol(JsonRpcError::invalid_params(message))
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Protocol(JsonRpcError::internal_error(message))
    }

    pub fn protocol(error: JsonRpcError) -> Self {
        Self::Protocol(error)
    }
}

impl fmt::Display for ToolDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ToolError { message, .. } => write!(f, "tool error: {message}"),
            Self::Protocol(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ToolDispatchError {}

/// Caller-provided handler bound to the gateway.
///
/// The gateway never executes commands directly and never publishes or
/// dispatches a catalog tool unless [`ToolHandler::has_handler`] returns `true`.
pub trait ToolHandler: Send + Sync {
    /// Returns `true` only when an actual handler exists for `tool_name`.
    fn has_handler(&self, tool_name: &str) -> bool;

    /// Executes `tool_name` with validated JSON object `arguments`.
    fn call(
        &self,
        tool_name: &str,
        arguments: Map<String, Value>,
    ) -> Result<ToolCallResult, ToolDispatchError>;
}

/// Boxed closure type accepted by [`ToolMapHandler`].
pub type ToolFn = Arc<
    dyn Fn(Map<String, Value>) -> Result<ToolCallResult, ToolDispatchError> + Send + Sync,
>;

/// In-memory [`ToolHandler`] mapping tool names to caller-supplied closures.
#[derive(Default, Clone)]
pub struct ToolMapHandler {
    handlers: HashMap<String, ToolFn>,
}

impl ToolMapHandler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<F>(&mut self, tool_name: impl Into<String>, handler: F) -> &mut Self
    where
        F: Fn(Map<String, Value>) -> Result<ToolCallResult, ToolDispatchError>
            + Send
            + Sync
            + 'static,
    {
        let name = tool_name.into();
        if !name.trim().is_empty() {
            self.handlers.insert(name, Arc::new(handler));
        }
        self
    }

    pub fn remove(&mut self, tool_name: &str) -> bool {
        self.handlers.remove(tool_name).is_some()
    }
}

impl ToolHandler for ToolMapHandler {
    fn has_handler(&self, tool_name: &str) -> bool {
        self.handlers.contains_key(tool_name)
    }

    fn call(
        &self,
        tool_name: &str,
        arguments: Map<String, Value>,
    ) -> Result<ToolCallResult, ToolDispatchError> {
        match self.handlers.get(tool_name) {
            Some(handler) => handler(arguments),
            None => Err(ToolDispatchError::invalid_params(format!(
                "unknown or unavailable tool: {tool_name}"
            ))),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InitializeResult {
    protocol_version: String,
    capabilities: ServerCapabilities,
    server_info: ServerInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    instructions: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ServerCapabilities {
    tools: ToolsCapability,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolsCapability {
    list_changed: bool,
}

/// Pure, transport-agnostic MCP JSON-RPC router.
pub struct McpGateway<H: ToolHandler> {
    config: GatewayConfig,
    supported_versions: Vec<String>,
    catalog: Vec<ToolDefinition>,
    published_names: HashSet<String>,
    /// The 2026-07-28 listing, built once: the catalog and its handlers are
    /// fixed for the lifetime of this router, so each router (one per
    /// authorization view) holds its own listing.
    modern_catalog: modern::Catalog,
    handler: H,
}

impl<H: ToolHandler> McpGateway<H> {
    /// Builds a gateway from `config`, a caller-supplied tool `catalog`, and a
    /// [`ToolHandler`].
    ///
    /// Catalog entries that have an empty name, a non-object `inputSchema`, a
    /// duplicate name, or no backing handler (`!handler.has_handler(&name)`)
    /// are excluded from publication.
    pub fn new(config: GatewayConfig, catalog: Vec<ToolDefinition>, handler: H) -> Self {
        let supported_versions = if config.supported_protocol_versions.is_empty() {
            DEFAULT_SUPPORTED_PROTOCOL_VERSIONS
                .iter()
                .map(|v| (*v).to_string())
                .collect()
        } else {
            config.supported_protocol_versions.clone()
        };

        let mut filtered_catalog = Vec::with_capacity(catalog.len());
        let mut published_names = HashSet::with_capacity(catalog.len());

        for tool in catalog {
            if tool.name.trim().is_empty() {
                continue;
            }
            if !tool.input_schema.is_object() {
                continue;
            }
            if !handler.has_handler(&tool.name) {
                continue;
            }
            if published_names.insert(tool.name.clone()) {
                filtered_catalog.push(tool);
            }
        }

        let modern_catalog = modern::Catalog::new(&filtered_catalog);
        Self {
            config,
            supported_versions,
            catalog: filtered_catalog,
            published_names,
            modern_catalog,
            handler,
        }
    }

    /// Returns the currently publishable tools (filtering out any tool whose
    /// handler is absent).
    pub fn published_tools(&self) -> Vec<&ToolDefinition> {
        self.catalog
            .iter()
            .filter(|tool| self.handler.has_handler(&tool.name))
            .collect()
    }

    /// Returns `true` if `tool_name` is both in the published catalog and
    /// backed by a live handler.
    pub fn has_published_tool(&self, tool_name: &str) -> bool {
        self.published_names.contains(tool_name) && self.handler.has_handler(tool_name)
    }

    /// Returns the ordered MCP protocol versions accepted by this gateway.
    pub fn supported_protocol_versions(&self) -> &[String] {
        &self.supported_versions
    }

    /// Routes a raw JSON-RPC text frame to the protocol era it selects.
    ///
    /// A frame with modern markers is served by [`McpGateway::handle_modern`]
    /// and must not contain duplicate object keys; any other frame keeps the
    /// legacy routing of [`McpGateway::handle_value`]. Returns `None` for valid
    /// JSON-RPC notifications (no response must be sent) and `Some(json)` for
    /// requests or protocol errors.
    pub fn handle_str(&self, raw_json: &str) -> Option<String> {
        let response = match modern::classify(raw_json) {
            Ok((value, true)) => self.handle_modern(value)?,
            Ok((value, false)) => self.handle_value(value)?,
            Err(_) if serde_json::from_str::<Value>(raw_json).is_ok() => modern::ambiguous_json(),
            Err(err) => JsonRpcResponse::error(
                JsonRpcId::Null,
                JsonRpcError::parse_error(format!("invalid JSON payload: {err}")),
            ),
        };

        Some(serde_json::to_string(&response).unwrap_or_else(|_| {
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"failed to serialize JSON-RPC response"}}"#
                .to_string()
        }))
    }

    /// Routes a parsed JSON value as a single JSON-RPC 2.0 message.
    ///
    /// Returns `None` for valid notifications and `Some(JsonRpcResponse)` for
    /// requests or malformed envelopes.
    pub fn handle_value(&self, message: Value) -> Option<JsonRpcResponse> {
        let mut obj = match message {
            Value::Object(map) => map,
            _ => {
                return Some(JsonRpcResponse::error(
                    JsonRpcId::Null,
                    JsonRpcError::invalid_request("JSON-RPC payload must be a JSON object"),
                ));
            }
        };

        let request_id = match obj.remove("id") {
            None => None,
            Some(raw_id) => match parse_request_id(&raw_id) {
                Ok(id) => Some(id),
                Err(err) => return Some(JsonRpcResponse::error(JsonRpcId::Null, err)),
            },
        };

        match obj.get("jsonrpc") {
            Some(Value::String(version)) if version == JSONRPC_VERSION => {}
            _ => {
                return Some(JsonRpcResponse::error(
                    request_id.unwrap_or(JsonRpcId::Null),
                    JsonRpcError::invalid_request("jsonrpc field must be \"2.0\""),
                ));
            }
        }

        let method = match obj.remove("method") {
            Some(Value::String(method)) if !method.trim().is_empty() => method,
            _ => {
                return Some(JsonRpcResponse::error(
                    request_id.unwrap_or(JsonRpcId::Null),
                    JsonRpcError::invalid_request("method field must be a non-empty string"),
                ));
            }
        };

        let params = obj.remove("params");

        // JSON-RPC 2.0: valid messages without an `id` are notifications and
        // MUST NOT produce a response.
        let id = request_id?;

        let response = match method.as_str() {
            "initialize" => self.handle_initialize(id, params),
            "ping" => self.handle_ping(id, params),
            "tools/list" => self.handle_tools_list(id, params),
            "tools/call" => self.handle_tools_call(id, params),
            _ => JsonRpcResponse::error(
                id,
                JsonRpcError::method_not_found(format!("method not found: {method}")),
            ),
        };

        Some(response)
    }

    fn handle_initialize(&self, id: JsonRpcId, params: Option<Value>) -> JsonRpcResponse {
        let map = match params {
            Some(Value::Object(map)) => map,
            _ => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params("initialize requires a params object"),
                );
            }
        };

        let requested_version = match map.get("protocolVersion") {
            Some(Value::String(v)) if !v.trim().is_empty() => v.as_str(),
            _ => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(
                        "initialize params.protocolVersion must be a non-empty string",
                    ),
                );
            }
        };

        if let Some(capabilities) = map.get("capabilities") {
            if !capabilities.is_null() && !capabilities.is_object() {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(
                        "initialize params.capabilities must be a JSON object",
                    ),
                );
            }
        }

        if let Some(client_info) = map.get("clientInfo") {
            if !client_info.is_null() && !client_info.is_object() {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(
                        "initialize params.clientInfo must be a JSON object",
                    ),
                );
            }
        }

        let negotiated_version = if self
            .supported_versions
            .iter()
            .any(|supported| supported == requested_version)
        {
            requested_version.to_string()
        } else if self.config.strict_version_negotiation {
            return JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_params_with_data(
                    "unsupported MCP protocolVersion",
                    json!({
                        "requestedProtocolVersion": echoed_version(requested_version),
                        "supportedProtocolVersions": self.supported_versions,
                    }),
                ),
            );
        } else {
            self.supported_versions[0].clone()
        };

        let result = InitializeResult {
            protocol_version: negotiated_version,
            capabilities: ServerCapabilities {
                tools: ToolsCapability {
                    list_changed: false,
                },
            },
            server_info: self.config.server_info.clone(),
            instructions: self.config.instructions.clone(),
        };

        serialize_success(id, result)
    }

    fn handle_ping(&self, id: JsonRpcId, params: Option<Value>) -> JsonRpcResponse {
        match params {
            None | Some(Value::Null) | Some(Value::Object(_)) => {
                JsonRpcResponse::success(id, Value::Object(Map::new()))
            }
            Some(_) => JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_params("ping params must be a JSON object or omitted"),
            ),
        }
    }

    fn handle_tools_list(&self, id: JsonRpcId, params: Option<Value>) -> JsonRpcResponse {
        match params {
            None | Some(Value::Null) => {}
            Some(Value::Object(map)) => {
                // The list is never paginated, so no cursor was issued.
                if map.get("cursor").is_some_and(|cursor| !cursor.is_null()) {
                    return JsonRpcResponse::error(
                        id,
                        JsonRpcError::invalid_params("tools/list params.cursor was not issued"),
                    );
                }
            }
            Some(_) => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(
                        "tools/list params must be a JSON object or omitted",
                    ),
                );
            }
        }

        let tools = self.published_tools();
        serialize_success(id, json!({ "tools": tools }))
    }

    fn handle_tools_call(&self, id: JsonRpcId, params: Option<Value>) -> JsonRpcResponse {
        let mut map = match params {
            Some(Value::Object(map)) => map,
            _ => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params("tools/call requires a params object"),
                );
            }
        };

        let name = match map.remove("name") {
            Some(Value::String(name)) if !name.trim().is_empty() => name,
            _ => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(
                        "tools/call params.name must be a non-empty string",
                    ),
                );
            }
        };

        let arguments = match map.remove("arguments") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(args)) => args,
            Some(_) => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params(
                        "tools/call params.arguments must be a JSON object",
                    ),
                );
            }
        };

        if !self.has_published_tool(&name) {
            return JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_params(format!("unknown or unavailable tool: {name}")),
            );
        }

        match self.handler.call(&name, arguments) {
            Ok(result) => serialize_success(id, result),
            Err(ToolDispatchError::ToolError { message, content }) => {
                let resolved_content = if content.is_empty() {
                    vec![ToolContent::Text { text: message }]
                } else {
                    content
                };
                serialize_success(
                    id,
                    ToolCallResult {
                        content: resolved_content,
                        is_error: true,
                        structured_content: None,
                    },
                )
            }
            Err(ToolDispatchError::Protocol(err)) => JsonRpcResponse::error(id, err),
        }
    }
}

fn parse_request_id(value: &Value) -> Result<JsonRpcId, JsonRpcError> {
    match value {
        Value::String(s) => Ok(JsonRpcId::String(s.clone())),
        Value::Number(n) if n.is_i64() || n.is_u64() => Ok(JsonRpcId::Number(n.clone())),
        _ => Err(JsonRpcError::invalid_request(
            "JSON-RPC request id must be a string or integer",
        )),
    }
}

fn serialize_success<T: Serialize>(id: JsonRpcId, value: T) -> JsonRpcResponse {
    match serde_json::to_value(value) {
        Ok(json_value) => JsonRpcResponse::success(id, json_value),
        Err(err) => JsonRpcResponse::error(
            id,
            JsonRpcError::internal_error(format!("failed to serialize result: {err}")),
        ),
    }
}
