mod admin;
pub(crate) use admin::UiOAuthOwner;

use agent_bridge_extensions::Registry;
use agent_bridge_gateway::{ToolCallResult, ToolDefinition, ToolMapHandler};
use serde_json::{json, Value};
use std::path::Path;
use crate::runtime::RuntimeError;

pub fn read(settings: &Path) -> Result<Registry, RuntimeError> {
    let bytes = agent_bridge_lifecycle::read_operator_setting(settings, "extensions.json")?;
    // The private journal supplies server tombstones and generation-bound
    // additions. A matching local tool grant marker is stripped by admin
    // before the strict Registry parser verifies each individual approval.
    Ok(admin::apply_local(settings, &bytes)?)
}

/// Explicitly selected, *read-only* local CLI catalog probe. Unlike a Web
/// administration proposal this does not change the private journal. The
/// only supported destination is public Microsoft Learn; no OAuth or new
/// tool approval is conferred by discovery.
pub fn refresh_check(settings: &Path, server: &str) -> Result<(), RuntimeError> {
    if server != "microsoft_learn" {
        return Err("Only the exact Microsoft Learn staging server supports this read-only probe".into());
    }
    let report = read(settings)?.refresh_microsoft_learn(server)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

/// Operator-only terminal path. No Web handler can invoke this function.
pub fn local(settings: &Path, action: &str, id: Option<&str>) -> Result<(), RuntimeError> {
    let answer = admin::local(settings, action, id)?;
    println!("{}", serde_json::to_string_pretty(&answer)?);
    if answer.get("decision").and_then(Value::as_str) == Some("unsupported") {
        return Err("Extension operation explicitly refused: not implemented by the local adapter".into());
    }
    Ok(())
}

/// Operator-only local loopback UI read view (never exposed to Web MCP).
pub(crate) fn ui_overview(owner: &UiOAuthOwner, settings: &Path) -> Result<Value, RuntimeError> {
    Ok(admin::ui_overview(owner, settings)?)
}

/// Operator-only local loopback UI decision path (never exposed to Web MCP).
pub(crate) fn decide_from_operator_ui(
    owner: &UiOAuthOwner,
    settings: &Path,
    id: &str,
    approve: bool,
) -> Result<Value, RuntimeError> {
    Ok(admin::decide_from_operator_ui(owner, settings, id, approve)?)
}

pub fn attach(settings: &Path, catalog: &mut Vec<ToolDefinition>, handlers: &mut ToolMapHandler)
    -> Result<(), RuntimeError>
{
    attach_inner(settings, catalog, handlers, false)
}

pub(crate) fn attach_unified(settings: &Path, catalog: &mut Vec<ToolDefinition>, handlers: &mut ToolMapHandler)
    -> Result<(), RuntimeError>
{
    attach_inner(settings, catalog, handlers, true)
}

fn attach_inner(settings: &Path, catalog: &mut Vec<ToolDefinition>, handlers: &mut ToolMapHandler, unified: bool)
    -> Result<(), RuntimeError>
{
    // Read now to report configuration errors to the operator; read again
    // for each call so local revocation applies to the next admission.
    let _ = read(settings)?;
    let settings = settings.to_owned();
    for name in ["desktop_mcp_manage", "desktop_mcp_tool_inspect"] {
        let directory = settings.clone();
        handlers.register(name, move |args| {
            if name == "desktop_mcp_manage" && matches!(
                args.get("action").and_then(Value::as_str),
                Some("add" | "remove" | "enable" | "disable" | "set_oauth"
                    | "auth_start" | "auth_status" | "auth_disconnect" | "refresh")
            ) {
                let proposed = if unified { admin::submit_unified(&directory, &args) }
                    else { admin::submit(&directory, &args) };
                return Ok(match proposed {
                    Ok(receipt) => ToolCallResult::text(receipt.to_string()),
                    Err(_) => ToolCallResult::tool_error("Extension proposal refused or local journal unavailable"),
                });
            }
            let Ok(registry) = read(&directory) else {
                return Ok(ToolCallResult::tool_error("Local extension configuration unavailable"));
            };
            let result = match (name, args.get("action").and_then(Value::as_str)) {
                ("desktop_mcp_manage", Some("list")) if args.len() == 1 => registry.servers(None),
                ("desktop_mcp_manage", Some("inspect")) if args.len() == 2 => match args.get("name").and_then(Value::as_str) {
                    Some(server) => registry.servers(Some(server)),
                    None => return Ok(ToolCallResult::tool_error("Expected a server identifier")),
                },
                ("desktop_mcp_tool_inspect", None) if args.len() == 1 => match args.get("name").and_then(Value::as_str) {
                    Some(tool) => registry.inspect_cached(tool),
                    None => return Ok(ToolCallResult::tool_error("Expected a qualified tool name")),
                },
                _ => return Ok(ToolCallResult::tool_error("Unsupported extension inspection request")),
            };
            Ok(match result {
                Ok(value) => ToolCallResult::text(value.to_string()),
                Err(error) => ToolCallResult::tool_error(error.to_string()),
            })
        });
    }
    let mut manage_schema = json!({"type":"object","required":["action"],"additionalProperties":false,"properties":{
            "action":{"enum":["list","inspect","add","remove","enable","disable",
                "set_oauth","auth_start","auth_status","auth_disconnect","refresh"]},
            "name":{"type":"string","minLength":1,"maxLength":96},
            "description":{"type":"string","maxLength":1024},
            "url":{"type":"string","maxLength":4096},
            "enabled":{"type":"boolean"},
            "oauth":{"type":"boolean"},
            "oauth_scope":{"type":"string","maxLength":8192},
            "oauth_client_id":{"type":"string","maxLength":1024},
            "oauth_client_auth_method":{"enum":["client_secret_basic","client_secret_post","none"]},
            "oauth_client_secret_env":{"type":"string","maxLength":128},
            "force":{"type":"boolean"},
            "timeout_ms":{"type":"integer","minimum":250,"maximum":300000}}});
    if unified {
        manage_schema["properties"]["header_env"] = json!({"type":"object","maxProperties":16,
            "propertyNames":{"type":"string","minLength":1,"maxLength":128},
            "additionalProperties":{"type":"string","minLength":1,"maxLength":128,
                "pattern":"^AGENT_BRIDGE_EXTENSION_[A-Z0-9_]+$"},
            "description":"Add only: HTTP header names mapped to local secret environment variable names. Values are never accepted. Requires local approval; transport headers cannot be overridden."});
    }
    catalog.push(ToolDefinition::new("desktop_mcp_manage", Some("Inspect local extensions or submit a typed administration proposal. Web never executes the proposal; only an interactive operator can decide locally.".into()), manage_schema));
    catalog.push(ToolDefinition::new("desktop_mcp_tool_inspect", Some("Read the cached descriptor for an approved extension tool.".into()),
        json!({"type":"object","required":["name"],"additionalProperties":false,"properties":{"name":{"type":"string","maxLength":193}}})));
    let list = settings.clone();
    handlers.register("desktop_mcp_tool_search", move |args| {
        if args.keys().any(|key| !matches!(key.as_str(), "query" | "server" | "limit")) {
            return Ok(ToolCallResult::tool_error("Invalid extension search"));
        }
        let Some(query) = args.get("query").and_then(Value::as_str) else {
            return Ok(ToolCallResult::tool_error("Invalid extension search"));
        };
        let server = match args.get("server") {
            None => None,
            Some(Value::String(value)) => Some(value.as_str()),
            _ => return Ok(ToolCallResult::tool_error("Invalid extension search")),
        };
        let limit = match args.get("limit") {
            None => 10,
            Some(value) => match value.as_u64() {
                Some(value @ 1..=100) => value as usize,
                _ => return Ok(ToolCallResult::tool_error("Invalid extension search")),
            },
        };
        Ok(match read(&list) {
            Ok(registry) => match registry.search_cached(query, server, limit) {
                Ok(value) => ToolCallResult::text(value.to_string()),
                Err(error) => ToolCallResult::tool_error(error.to_string()),
            },
            Err(_) => ToolCallResult::tool_error("Local extension configuration unavailable"),
        })
    });
    handlers.register("desktop_mcp_tool_call", move |args| {
        let Some(name) = args.get("name").and_then(Value::as_str) else {
            return Ok(ToolCallResult::tool_error("An approved tool name is required"));
        };
        let empty = serde_json::Map::new();
        let arguments = match args.get("arguments") {
            None => &empty,
            Some(Value::Object(map)) => map,
            _ => return Ok(ToolCallResult::tool_error("Expected an arguments object")),
        };
        if args.keys().any(|k| !matches!(k.as_str(), "name" | "arguments")) || name.len() > 193 {
            return Ok(ToolCallResult::tool_error("Unexpected extension input"));
        }
        let Ok(registry) = read(&settings) else {
            return Ok(ToolCallResult::tool_error("Local extension configuration unavailable"));
        };
        Ok(match registry.call(name, arguments) {
            Ok(value) => {
                // Third-party content is data. It cannot register tools or
                // trigger another action, and resources are never auto-read.
                let mut answer = ToolCallResult::text(value.to_string());
                answer.is_error = value.get("isError").and_then(Value::as_bool).unwrap_or(false);
                answer
            }
            Err(error) => ToolCallResult::tool_error(error.to_string()),
        })
    });
    catalog.push(ToolDefinition::new("desktop_mcp_tool_search", Some("Search cached metadata for locally approved extension tools without contacting upstream servers.".into()),
        json!({"type":"object","required":["query"],"additionalProperties":false,"properties":{
            "query":{"type":"string","minLength":1,"maxLength":1024},
            "server":{"type":"string","maxLength":64},
            "limit":{"type":"integer","minimum":1,"maximum":100}}})));
    catalog.push(ToolDefinition::new("desktop_mcp_tool_call", Some("Call one locally approved extension operation.".into()),
        json!({"type":"object","additionalProperties":false,"required":["name"],"properties":{
            "name":{"type":"string","maxLength":193},"arguments":{"type":"object"}}})));
    Ok(())
}
