# Agent Bridge

**Turn web-based AI assistants into local agents with Claude Code and Codex-like capabilities.**

[![Release](https://img.shields.io/github/v/release/ironlegends/AgentBridge)](https://github.com/ironlegends/AgentBridge/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Windows](https://img.shields.io/badge/Windows-x64%20stable-blue)](docs/RELEASE-v2.1.0.md)

Agent Bridge turns ChatGPT Web, Gemini Web, and other compatible AI chats into local coding and automation agents. Keep using the chat you already know while your AI works directly on your computer.

**Same AI. Same chat interface. Real local capabilities.**

## Why Agent Bridge?

- Use everyday AI web chats as local agents, without switching to a dedicated coding agent.
- Make better use of your existing AI subscriptions and web usage allowances.
- Work on your computer from supported AI chats, including on your phone.
- Collaborate across web and local AI agents, while controlling access on your machine.

### Use your existing AI subscription

Agent Bridge connects your existing AI chat to local tools through MCP, rather than calling a separate model API. For example, when Gemini Web has its own usage allowance, local coding and automation through that chat use the web allowance instead of Antigravity's dedicated agent quota.

No separate model API key is required for these web connections. Agent Bridge does not add quota or bypass usage limits. Allowances depend on your provider and plan; products may share limits, including ChatGPT and Codex.

## What can your AI do?

| Feature | Capabilities |
|---|---|
| Coding | Read, edit, debug, build, and test code |
| Terminal | Run commands and manage processes |
| Files | Browse, search, create, and modify files |
| Browser | Navigate and automate websites in isolated sessions |
| Desktop | Interact with supported windows and applications (experimental) |
| Multi-agent | Share tasks, checkpoints, and progress |
| Skills and extensions | Add reusable instructions and MCP tools |

## How it works

**AI web chat -> Agent Bridge -> Your computer**

Your AI reasons in its original chat interface. Agent Bridge runs authorized operations locally using the Model Context Protocol (MCP). No separate coding agent is required.

| Client | Connection |
|---|---|
| ChatGPT Web | Secure MCP Tunnel and authenticated OAuth route |
| Gemini Web | HTTPS / OAuth |
| Other compatible web chats | Custom MCP integration, where supported |
| Claude Code, Codex, Cursor and other local clients | MCP over stdio or supported local HTTP |

## Getting started

1. Download the Windows portable ZIP from [Releases](https://github.com/ironlegends/AgentBridge/releases).
2. Verify the signed checksums and extract the application.
3. Follow the setup guide to configure your workspace, permissions, and connection.
4. Connect your AI chat through MCP and approve its access locally.
5. Start using your web chat as a local agent.

See the [Quick Start Guide](docs/QUICKSTART.md) for the required configuration, including Secure MCP Tunnel for ChatGPT Web and the authenticated HTTPS route for Gemini Web. Your AI plan must support custom MCP integrations.

## Your computer, your permissions

| Mode | Access |
|---|---|
| Read Only | Inspect workspace files |
| Workspace Write | Read and modify workspace files |
| Full Control | Extended tools and approved commands |
| Fully Unlocked | Direct commands when explicitly enabled, with your OS account permissions |

Permissions are controlled locally and cannot be escalated through MCP. Fully Unlocked processes can access resources permitted by your OS account; choose this mode only for trusted work.

## Platform support

| Platform | Status |
|---|---|
| Windows 10/11 x64 | Stable portable desktop release |
| macOS | Experimental |
| Linux | Experimental |

Built with Rust and Tauri, Agent Bridge offers a native desktop app and a headless CLI (build from source). The Windows unified catalogue exposes up to 46 MCP tools. The core runtime does not require a separately installed Node.js, Python or Electron runtime; the qualified Windows browser bundle includes its own pinned dependencies.

Some desktop automation features are experimental. Restricted Low-IL processes are unsupported. The portable release is not Authenticode-signed and has no installer or automatic updater. See [release notes](docs/RELEASE-v2.1.0.md) for the supported scope.

## Documentation

- [Quick Start](docs/QUICKSTART.md)
- [Desktop Application](docs/UNIFIED-DESKTOP.md)
- [MCP Tools](docs/TOOLS.md)
- [Permissions and Security](docs/WORKSTATION-MODES.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Unix Platform Parity](docs/UNIX-PARITY.md)
- [MCP Modernization](docs/MCP-MODERNIZATION.md)
- [Public Release Scope](docs/PUBLIC-RELEASE-SCOPE.md)
- [Release Notices](docs/RELEASE-NOTICES.md)
- [Security Policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## License

Open source under the [Apache 2.0 License](LICENSE). See [NOTICE](NOTICE) for third-party attributions.
