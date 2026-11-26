// Copyright 2026 agent-bridge contributors
// SPDX-License-Identifier: Apache-2.0

use agent_bridge_gateway::{modern::VERSION, GatewayConfig, McpGateway, ToolCallResult, ToolDefinition, ToolMapHandler};
use serde_json::{json, Value};
use std::sync::{atomic::{AtomicUsize, Ordering}, Arc};

const VERSION_KEY: &str = "io.modelcontextprotocol/protocolVersion";
const CAP_KEY: &str = "io.modelcontextprotocol/clientCapabilities";
const INFO_KEY: &str = "io.modelcontextprotocol/serverInfo";

fn gateway() -> (McpGateway<ToolMapHandler>, Arc<AtomicUsize>) {
    let count = Arc::new(AtomicUsize::new(0));
    let observed = count.clone();
    let mut handlers = ToolMapHandler::new();
    handlers.register("echo", move |_| {
        observed.fetch_add(1, Ordering::SeqCst);
        Ok(ToolCallResult::text("synthetic"))
    });
    let catalog = vec![ToolDefinition::new("echo", None, json!({"type":"object"}))];
    (McpGateway::new(GatewayConfig::new("fixture", "1").with_instructions("test"), catalog, handlers), count)
}

fn req(method: &str, params: Value) -> Value {
    let mut p = params;
    p["_meta"] = json!({(VERSION_KEY): VERSION, (CAP_KEY): {}});
    json!({"jsonrpc":"2.0", "id": 1, "method":method, "params":p})
}

#[test]
fn discovery_and_list_are_stateless() {
    let (gw, count) = gateway();
    let listed = gw.handle_modern(req("tools/list", json!({}))).unwrap().result.unwrap();
    assert_eq!(listed["tools"][0]["name"], "echo");
    assert_eq!(listed["resultType"], "complete");
    assert_eq!(listed["_meta"][INFO_KEY]["name"], "fixture");
    assert_eq!(listed["ttlMs"], 0);
    assert_eq!(listed["cacheScope"], "private");
    let discovered = gw.handle_modern(req("server/discover", json!({}))).unwrap().result.unwrap();
    assert_eq!(discovered["supportedVersions"], json!([VERSION]));
    assert_eq!(discovered["capabilities"], json!({"tools":{}}));
    assert_eq!(discovered["instructions"], "test");
    assert_eq!(discovered["ttlMs"], 0);
    assert_eq!(discovered["cacheScope"], "private");
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[test]
fn valid_call_reuses_existing_handler_and_catalog() {
    let (gw, count) = gateway();
    let response = gw.handle_modern(req("tools/call", json!({"name":"echo"}))).unwrap().result.unwrap();
    assert_eq!(response["resultType"], "complete");
    assert_eq!(response["content"][0]["text"], "synthetic");
    let unknown = gw.handle_modern(req("tools/call", json!({"name":"not-published"}))).unwrap();
    assert_eq!(unknown.error.unwrap().code, -32602);
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn malformed_metadata_never_dispatches() {
    let (gw, count) = gateway();
    for meta in [Value::Null, json!({}), json!({(VERSION_KEY): VERSION}), json!({(VERSION_KEY): VERSION, (CAP_KEY): []}), json!({(VERSION_KEY): VERSION, (CAP_KEY): {}, "io.modelcontextprotocol/clientInfo": {"name":"spoof"}})] {
        let mut call = req("tools/call", json!({"name":"echo"}));
        call["params"]["_meta"] = meta;
        assert_eq!(gw.handle_modern(call).unwrap().error.unwrap().code, -32602);
    }
    let mut call = req("tools/call", json!({"name":"echo"}));
    call["params"].as_object_mut().unwrap().remove("_meta");
    assert_eq!(gw.handle_modern(call).unwrap().error.unwrap().code, -32602);
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[test]
fn wrong_version_returns_structured_error_without_dispatch() {
    let (gw, count) = gateway();
    let mut call = req("tools/call", json!({"name":"echo"}));
    call["params"]["_meta"][VERSION_KEY] = json!("2025-06-18");
    let error = gw.handle_modern(call).unwrap().error.unwrap();
    assert_eq!(error.code, -32022);
    assert_eq!(error.data.unwrap(), json!({"supported":[VERSION], "requested":"2025-06-18"}));
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[test]
fn modern_rejects_legacy_methods_and_unimplemented_continuations() {
    let (gw, count) = gateway();
    for method in ["initialize", "ping", "tasks/get", "subscriptions/listen"] {
        assert_eq!(gw.handle_modern(req(method, json!({}))).unwrap().error.unwrap().code, -32601);
    }
    for key in ["inputResponses", "inputRequestState", "task"] {
        assert_eq!(gw.handle_modern(req("tools/call", json!({"name":"echo", (key): {}}))).unwrap().error.unwrap().code, -32602);
    }
    let mut notification = req("tools/call", json!({"name":"echo"}));
    notification.as_object_mut().unwrap().remove("id");
    assert!(gw.handle_modern(notification).is_none());
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[test]
fn legacy_route_does_not_advertise_modern_version() {
    let (gw, count) = gateway();
    assert!(!gw.supported_protocol_versions().iter().any(|v| v == VERSION));
    assert_eq!(gw.handle_value(req("server/discover", json!({}))).unwrap().error.unwrap().code, -32601);
    let init = gw.handle_value(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":VERSION}})).unwrap().result.unwrap();
    assert_ne!(init["protocolVersion"], VERSION);
    assert!(init.get("resultType").is_none());
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[test]
fn request_state_never_reaches_a_legacy_tool_handler() {
    let (gw, count) = gateway();
    for key in ["requestState", "inputResponses", "inputRequestState", "task", "unexpected"] {
        let response = gw.handle_modern(req("tools/call", json!({"name":"echo", (key): "untrusted"}))).unwrap();
        assert_eq!(response.error.unwrap().code, -32602);
    }
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[test]
fn stdio_modern_and_legacy_use_the_same_bounded_framing_without_downgrade() {
    use agent_bridge_gateway::{modern::StdioEra, stdio};
    use std::io::Cursor;
    let (gw, count) = gateway();
    let legacy_call = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo"}});
    let frames = [
        req("server/discover", json!({})),
        legacy_call.clone(),
        req("tools/call", json!({"name":"echo"})),
    ];
    let input = frames.iter().map(Value::to_string).collect::<Vec<_>>().join("\n") + "\n";
    let mut output = Vec::new();
    let mut route = StdioEra::default();
    stdio::serve(Cursor::new(input), &mut output, |raw| route.dispatch(&gw, raw)).unwrap();
    let replies: Vec<Value> = String::from_utf8(output).unwrap().lines()
        .map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(replies.len(), 3);
    assert_eq!(replies[0]["result"]["resultType"], "complete");
    assert_eq!(replies[1]["error"]["code"], -32602);
    assert_eq!(replies[2]["result"]["content"][0]["text"], "synthetic");

    let mut legacy = StdioEra::default();
    let denied: Value = serde_json::from_str(&legacy.dispatch(&gw, &legacy_call.to_string()).unwrap()).unwrap();
    assert_eq!(denied["error"]["code"], -32602);
    let init = json!({"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2025-06-18"}});
    let init: Value = serde_json::from_str(&legacy.dispatch(&gw, &init.to_string()).unwrap()).unwrap();
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    let mixed: Value = serde_json::from_str(&legacy.dispatch(&gw, &req("tools/call", json!({"name":"echo"})).to_string()).unwrap()).unwrap();
    assert_eq!(mixed["error"]["code"], -32602);
    let legacy_ok: Value = serde_json::from_str(&legacy.dispatch(&gw, &legacy_call.to_string()).unwrap()).unwrap();
    assert_eq!(legacy_ok["result"]["content"][0]["text"], "synthetic");
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[test]
fn explicit_modern_marker_with_invalid_metadata_does_not_downgrade() {
    let (gw, count) = gateway();
    let mut request = req("tools/call", json!({"name":"echo"}));
    request["params"]["_meta"].as_object_mut().unwrap().remove(VERSION_KEY);
    let reply: Value = serde_json::from_str(&gw.handle_str(&request.to_string()).unwrap()).unwrap();
    assert_eq!(reply["error"]["code"], -32602);
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[test]
fn duplicate_json_keys_are_rejected_before_dispatch() {
    let (gw, count) = gateway();
    let mut raw = req("tools/call", json!({"name":"echo","arguments":{"value":1}})).to_string();
    raw = raw.replace("\"value\":1", "\"value\":1,\"value\":2");
    assert!(agent_bridge_gateway::modern::parse_unique(&raw).is_err());
    let reply: Value = serde_json::from_str(&gw.handle_str(&raw).unwrap()).unwrap();
    assert_eq!(reply["error"]["code"], -32700);
    let mut route = agent_bridge_gateway::modern::StdioEra::default();
    let reply: Value = serde_json::from_str(&route.dispatch(&gw, &raw).unwrap()).unwrap();
    assert_eq!(reply["error"]["code"], -32700);

    // A later duplicate cannot hide a modern marker and fix the legacy era:
    // the frame is refused and the next legacy call still needs initialize.
    let hidden = r#"{"jsonrpc":"2.0","id":1,"method":"server/discover","method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#;
    let reply: Value = serde_json::from_str(&gw.handle_str(hidden).unwrap()).unwrap();
    assert_eq!(reply["error"]["code"], -32700);
    let mut route = agent_bridge_gateway::modern::StdioEra::default();
    let reply: Value = serde_json::from_str(&route.dispatch(&gw, hidden).unwrap()).unwrap();
    assert_eq!(reply["error"]["code"], -32700);
    let call = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo"}}).to_string();
    let reply: Value = serde_json::from_str(&route.dispatch(&gw, &call).unwrap()).unwrap();
    assert_eq!(reply["error"]["code"], -32602);
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[test]
fn legacy_listing_refuses_unissued_cursors_and_errors_never_echo_long_versions() {
    let (gw, _) = gateway();
    let list = json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"cursor":"unissued"}});
    assert_eq!(gw.handle_value(list).unwrap().error.unwrap().code, -32602);
    let long = "9".repeat(600);
    let mut call = req("tools/call", json!({"name":"echo"}));
    call["params"]["_meta"][VERSION_KEY] = json!(long);
    let reply = gw.handle_str(&call.to_string()).unwrap();
    assert!(!reply.contains(&long[..64]), "{reply}");
}


#[test]
fn modern_catalog_order_is_stable_and_cache_hints_are_not_legacy_fields() {
    let catalog = vec![
        ToolDefinition::new("zeta", None, json!({"type":"object"})),
        ToolDefinition::new("alpha", None, json!({"type":"object"})),
    ];
    let mut handlers = ToolMapHandler::new();
    handlers.register("zeta", |_| Ok(ToolCallResult::text("z")));
    handlers.register("alpha", |_| Ok(ToolCallResult::text("a")));
    let gw = McpGateway::new(GatewayConfig::new("fixture", "1"), catalog, handlers);
    let listed = gw.handle_modern(req("tools/list", json!({}))).unwrap().result.unwrap();
    assert_eq!(listed["tools"][0]["name"], "alpha");
    assert_eq!(listed["tools"][1]["name"], "zeta");
    assert_eq!(listed["ttlMs"], 0);
    assert_eq!(listed["cacheScope"], "private");
    let invalid = gw.handle_modern(req("tools/list", json!({"cursor":"unissued"}))).unwrap();
    assert_eq!(invalid.error.unwrap().code, -32602);
    let legacy = gw.handle_value(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})).unwrap().result.unwrap();
    assert!(legacy.get("ttlMs").is_none());
    assert!(legacy.get("cacheScope").is_none());
}

fn revision_gateway(description: &str, ttl_ms: u64) -> McpGateway<ToolMapHandler> {
    let mut handlers = ToolMapHandler::new();
    handlers.register("echo", |_| Ok(ToolCallResult::text("synthetic")));
    McpGateway::new(GatewayConfig::new("fixture", "1").with_catalog_ttl_ms(ttl_ms),
        vec![ToolDefinition::new("echo", Some(description.into()), json!({"type":"object"}))], handlers)
}

#[test]
fn configured_ttl_stays_private_and_revision_tracks_the_listed_catalog() {
    const REVISION: &str = "io.github.ironlegends/catalogRevision";
    let gw = revision_gateway("first", 300_000);
    let listed = gw.handle_modern(req("tools/list", json!({}))).unwrap().result.unwrap();
    let discovered = gw.handle_modern(req("server/discover", json!({}))).unwrap().result.unwrap();
    for result in [&listed, &discovered] {
        assert_eq!(result["ttlMs"], 300_000);
        assert_eq!(result["cacheScope"], "private", "a per-grant catalog is never public");
    }
    let revision = listed["_meta"][REVISION].as_str().unwrap();
    assert_eq!(revision.len(), 64);
    assert_eq!(discovered["_meta"][REVISION], revision);
    let same = revision_gateway("first", 0).handle_modern(req("tools/list", json!({}))).unwrap().result.unwrap();
    assert_eq!(same["_meta"][REVISION], revision, "the revision depends on the catalog, not the TTL");
    let changed = revision_gateway("second", 300_000).handle_modern(req("tools/list", json!({}))).unwrap().result.unwrap();
    assert_ne!(changed["_meta"][REVISION], revision);
    let called = gw.handle_modern(req("tools/call", json!({"name":"echo"}))).unwrap().result.unwrap();
    assert!(called.get("ttlMs").is_none() && called.get("cacheScope").is_none());
    assert!(called["_meta"].get(REVISION).is_none(), "tool results are not cacheable");
}
#[test]
fn handle_str_routes_each_frame_to_its_own_era() {
    let (gw, count) = gateway();
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}});
    let init: Value = serde_json::from_str(&gw.handle_str(&init.to_string()).unwrap()).unwrap();
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    let legacy = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo"}});
    let legacy: Value = serde_json::from_str(&gw.handle_str(&legacy.to_string()).unwrap()).unwrap();
    assert!(legacy["result"].get("resultType").is_none());
    assert!(legacy["result"].get("_meta").is_none());
    let modern: Value = serde_json::from_str(&gw.handle_str(&req("tools/call", json!({"name":"echo"})).to_string()).unwrap()).unwrap();
    assert_eq!(modern["result"]["resultType"], "complete");
    assert_eq!(modern["result"]["_meta"][INFO_KEY]["name"], "fixture");
    let removed: Value = serde_json::from_str(&gw.handle_str(&req("ping", json!({})).to_string()).unwrap()).unwrap();
    assert_eq!(removed["error"]["code"], -32601);
    assert_eq!(removed["id"], 1);
    let notification = json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,
        "_meta":{(VERSION_KEY):VERSION,(CAP_KEY):{}}}});
    assert!(gw.handle_str(&notification.to_string()).is_none());
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[test]
fn parameter_header_annotations_are_not_republished_to_modern_clients() {
    let schema = json!({"type":"object","properties":{
        "region":{"type":"string","x-mcp-header":"Region"},
        "nested":{"type":"object","properties":{"zone":{"type":"string","x-mcp-header":"Zone"}}}}});
    let mut handlers = ToolMapHandler::new();
    handlers.register("echo", |_| Ok(ToolCallResult::text("synthetic")));
    let gw = McpGateway::new(GatewayConfig::new("fixture", "1"),
        vec![ToolDefinition::new("echo", None, schema.clone())], handlers);
    let listed = gw.handle_modern(req("tools/list", json!({}))).unwrap().result.unwrap();
    let published = listed["tools"][0]["inputSchema"].to_string();
    assert!(!published.contains("x-mcp-header"), "{published}");
    assert_eq!(listed["tools"][0]["inputSchema"]["properties"]["nested"]["properties"]["zone"]["type"], "string");
    let legacy = gw.handle_value(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})).unwrap().result.unwrap();
    assert_eq!(legacy["tools"][0]["inputSchema"], schema);
}

#[test]
fn tool_errors_remain_complete_results_in_the_modern_era() {
    let mut handlers = ToolMapHandler::new();
    handlers.register("fails", |_| Ok(ToolCallResult::tool_error("intentional")));
    let gw = McpGateway::new(GatewayConfig::new("fixture", "1"),
        vec![ToolDefinition::new("fails", None, json!({"type":"object"}))], handlers);
    let result = gw.handle_modern(req("tools/call", json!({"name":"fails"}))).unwrap().result.unwrap();
    assert_eq!(result["isError"], true);
    assert_eq!(result["resultType"], "complete");
}
