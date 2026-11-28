# Agent Bridge 2.3.3

Agent Bridge 2.3.3 fixes OAuth discovery for operators who connect an external MCP server to their workstation.

## Security fix

When an extension delegates authentication, Agent Bridge checks each discovered URL against the origin that supplied it. Remote providers must use HTTPS. For local development, HTTP is supported on the same literal loopback address and effective port. An HTTP service that delegates to a different port should use HTTPS for its authorization server.

## Upgrade and compatibility

Verify the Windows x64 archive before extracting it into a new directory. Stop the current application, point the launcher to the new executable, and restart with the existing configuration and OAuth store. Existing ChatGPT and Gemini connections can use the same MCP endpoint. Check the version with `agent_bridge_status`.

The Windows workstation exposes 46 tools under the unified catalogue. The public read-only workspace exposes 22. This update changes outbound extension authentication. The desktop panel uses WebView2, and the Windows bundle includes the Playwright browser worker.

## Downloads and verification

Download the Windows archive, the Rust source archive, the MPL source companion and the two checksum files from the [release page](https://github.com/ironlegends/AgentBridge/releases/tag/v2.3.3). Verify the detached signature with the trusted release public key, then match the SHA-256 of your archive to its entry in `SHA256SUMS`.

## Source and changes

[OAuth fix and validation](https://github.com/ironlegends/AgentBridge/pull/40) · [Changes since 2.3.2](https://github.com/ironlegends/AgentBridge/compare/v2.3.2...v2.3.3)
