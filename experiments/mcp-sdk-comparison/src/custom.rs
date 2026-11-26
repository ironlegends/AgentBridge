// Copyright 2026 agent-bridge contributors
// SPDX-License-Identifier: Apache-2.0
use agent_bridge_gateway::{
    modern::StdioPreview, stdio, GatewayConfig, McpGateway, ToolCallResult,
    ToolDefinition, ToolMapHandler,
};
use serde_json::json;
use std::io;

fn main() -> io::Result<()> {
    let mut handlers = ToolMapHandler::new();
    handlers.register("echo", |_| Ok(ToolCallResult::text("fixture")));
    let gateway = McpGateway::new(
        GatewayConfig::new("benchmark-fixture", "1"),
        vec![ToolDefinition::new(
            "echo",
            Some("Synthetic echo fixture".into()),
            json!({"type": "object"}),
        )],
        handlers,
    );
    let mut route = StdioPreview::default();
    stdio::serve(io::stdin().lock(), io::stdout().lock(), |frame| {
        route.dispatch(&gateway, frame)
    })
}
