// Copyright 2026 agent-bridge contributors
// SPDX-License-Identifier: Apache-2.0

use agent_bridge_gateway::{GatewayConfig, McpGateway, ToolCallResult, ToolDefinition, ToolMapHandler};
use agent_bridge_http::{serve_managed, HealthStatus, HttpServerConfig, ServiceActivity};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::sync::{atomic::{AtomicUsize, Ordering}, Arc};
use std::time::Duration;
use tokio::{net::TcpListener, sync::oneshot};

fn send(port: u16, headers: &str, body: String) -> (u16, Value) {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(stream, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n{body}", body.len()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, serde_json::from_str(body).unwrap())
}

fn request(method: &str, mut params: Value) -> String {
    params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}});
    json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string()
}

#[test]
fn live_loopback_dual_era_validates_headers_and_preserves_legacy_dispatch() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let mut handlers = ToolMapHandler::new();
        handlers.register("echo", move |_| {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(ToolCallResult::text("fixture"))
        });
        let gateway = McpGateway::new(
            GatewayConfig::new("fixture", "1"),
            vec![ToolDefinition::new("echo", None, json!({"type":"object"}))],
            handlers,
        );
        let config = HttpServerConfig::default();
        let (stop, stopped) = oneshot::channel();
        let server = tokio::spawn(serve_managed(
            listener, config, ServiceActivity::default(),
            move |body| gateway.handle_str(body),
            HealthStatus::ok, async { let _ = stopped.await; },
        ));
        let results = tokio::task::spawn_blocking(move || {
            const VERSION: &str = "MCP-Protocol-Version: 2026-07-28\r\n";
            let discover = send(port, &format!("{VERSION}Mcp-Method: server/discover\r\n"), request("server/discover", json!({})));
            let list = send(port, &format!("{VERSION}Mcp-Method: tools/list\r\n"), request("tools/list", json!({})));
            let call = request("tools/call", json!({"name":"echo","arguments":{"value":1}}));
            let missing = send(port, &format!("{VERSION}Mcp-Method: tools/call\r\n"), call.clone());
            let wrong = send(port, &format!("{VERSION}Mcp-Method: tools/call\r\nMcp-Name: other\r\n"), call.clone());
            let duplicate = send(port, &format!("{VERSION}Mcp-Method: tools/call\r\nMcp-Name: echo\r\nMcp-Name: echo\r\n"), call.clone());
            let duplicate_body = send(port, &format!("{VERSION}Mcp-Method: tools/call\r\nMcp-Name: echo\r\n"), call.replace("\"value\":1", "\"value\":1,\"value\":2"));
            let accepted = send(port, &format!("{VERSION}Mcp-Method: tools/call\r\nMcp-Name: echo\r\n"), call);
            let unknown = send(port, &format!("{VERSION}Mcp-Method: not/a/method\r\n"), request("not/a/method", json!({})));
            let unsupported = send(port, "MCP-Protocol-Version: 2099-01-01\r\nMcp-Method: server/discover\r\n", request("server/discover", json!({})).replace("2026-07-28","2099-01-01"));
            let legacy = send(port, "", json!({"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}).to_string());
            let legacy_call = send(port, "MCP-Protocol-Version: 2025-06-18\r\n", json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo"}}).to_string());
            let no_meta = send(port, &format!("{VERSION}Mcp-Method: tools/list\r\n"), json!({"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}).to_string());
            let no_version_header = send(port, "Mcp-Method: tools/list\r\n", request("tools/list", json!({})));
            [discover,list,missing,wrong,duplicate,duplicate_body,accepted,unknown,unsupported,legacy,legacy_call,no_meta,no_version_header]
        }).await.unwrap();
        assert_eq!(results[0].0, 200);
        assert_eq!(results[0].1["result"]["supportedVersions"], json!(["2026-07-28"]));
        assert_eq!(results[1].1["result"]["tools"][0]["name"], "echo");
        for (status, body) in &results[2..5] {
            assert_eq!(*status, 400);
            assert_eq!(body["error"]["code"], -32020);
        }
        assert_eq!(results[5].0, 400);
        assert_eq!(results[5].1["error"]["code"], -32700);
        assert_eq!(results[6].0, 200);
        assert_eq!(results[6].1["result"]["content"][0]["text"], "fixture");
        assert_eq!(results[7].0, 404);
        assert_eq!(results[7].1["error"]["code"], -32601);
        assert_eq!(results[8].0, 400);
        assert_eq!(results[8].1["error"]["code"], -32022);
        assert_eq!(results[9].1["result"]["protocolVersion"], "2025-06-18");
        assert!(results[10].1["result"].get("resultType").is_none());
        assert_eq!(results[11].0, 400);
        assert_eq!(results[11].1["error"]["code"], -32602);
        assert_eq!(results[11].1["id"], 4);
        assert_eq!(results[12].0, 400);
        assert_eq!(results[12].1["error"]["code"], -32020);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
    });
}
