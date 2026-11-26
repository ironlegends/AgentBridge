// Copyright 2026 agent-bridge contributors
// SPDX-License-Identifier: Apache-2.0
use rmcp::{tool, tool_router, tool_handler, ServerHandler, ServiceExt, transport::stdio};

#[derive(Clone)]
struct Fixture;

#[tool_router]
impl Fixture {
    #[tool(description = "Synthetic echo fixture")]
    fn echo(&self) -> String {
        "fixture".into()
    }
}

#[tool_handler(name = "benchmark-fixture", version = "1")]
impl ServerHandler for Fixture {}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = Fixture.serve(stdio()).await?;
    server.waiting().await?;
    Ok(())
}
