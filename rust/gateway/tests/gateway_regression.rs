use agent_bridge_gateway::{
    GatewayConfig, McpGateway, ToolCallResult, ToolDefinition, ToolMapHandler,
};
use serde_json::{json, Value};

fn build_gateway(strict: bool) -> McpGateway<ToolMapHandler> {
    let mut handlers = ToolMapHandler::new();
    handlers.register("ping_tool", |args| {
        let msg = args.get("msg").and_then(Value::as_str).unwrap_or("pong");
        Ok(ToolCallResult::text(json!({"echo": msg}).to_string()))
    });
    let catalog = vec![ToolDefinition::new(
        "ping_tool",
        Some("Echo test tool".into()),
        json!({"type": "object", "properties": {"msg": {"type": "string"}}}),
    )];
    let config = GatewayConfig::new("test-gw", "1.0.0")
        .with_supported_protocol_versions(["2025-03-26"])
        .with_strict_version_negotiation(strict);
    McpGateway::new(config, catalog, handlers)
}

#[test]
fn gateway_initialize_tools_dispatch_errors_and_notifications_regressions() {
    let gw = build_gateway(true);
    assert!(gw.has_published_tool("ping_tool"));
    assert!(!gw.has_published_tool("unknown_tool"));

    // Parse error on malformed JSON
    let parse_err: Value = serde_json::from_str(&gw.handle_str("{bad json").unwrap()).unwrap();
    assert_eq!(parse_err["error"]["code"], -32700);

    // Strict protocol negotiation rejects unsupported version
    let bad_ver = gw
        .handle_value(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "1999-01-01", "capabilities": {}, "clientInfo": {"name": "c", "version": "1"}}
        }))
        .unwrap();
    assert!(bad_ver.error.is_some());

    // Valid initialize
    let ok_init = gw
        .handle_value(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "c", "version": "1"}}
        }))
        .unwrap();
    assert!(ok_init.error.is_none());
    assert_eq!(ok_init.result.unwrap()["protocolVersion"], "2025-03-26");

    // Notification returns None (no JSON-RPC reply)
    assert!(gw
        .handle_value(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .is_none());

    // tools/list returns catalog
    let list = gw
        .handle_value(json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}))
        .unwrap();
    let tools = list.result.unwrap()["tools"].as_array().unwrap().clone();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "ping_tool");

    // tools/call dispatches registered tool
    let called = gw
        .handle_value(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "ping_tool", "arguments": {"msg": "hello"}}
        }))
        .unwrap();
    let text = called.result.unwrap()["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(text.contains("hello"));

    // Unknown tool fails closed
    let missing = gw
        .handle_value(json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "nonexistent_tool", "arguments": {}}
        }))
        .unwrap();
    assert!(missing.error.is_some());

    // Unknown JSON-RPC method returns method_not_found (-32601)
    let bad_method = gw
        .handle_value(json!({"jsonrpc": "2.0", "id": 6, "method": "no/such"}))
        .unwrap();
    assert_eq!(bad_method.error.unwrap().code, -32601);
}
