# Security Policy

## Supported Versions

Security fixes are applied to the latest commit on `main` and the most recent tagged `v2.x` release.

| Version | Platform | Supported |
| --- | --- | --- |
| 2.0.x | Windows 10/11 x64 (portable desktop ZIP; headless CLI built from source, no prebuilt CLI binary) | Yes |
| 2.0.x | Linux, macOS | Experimental; reports are welcome, no release binaries |
| < 2.0 | Any | No |

## Security Model & Scope

Agent Bridge is designed as a **fail-closed** local MCP gateway connecting untrusted web prompts (ChatGPT Web, Gemini Web) or local MCP clients to an operator's machine.

The following invariants are treated as security boundaries; any bypass is considered a security vulnerability:

1. **Local-only capability escalation:** An MCP client must never widen its own workspace root, desktop profile (`read-only` -> `workspace-write` -> `full-control`), pinned command catalog, browser origin allowlist, or target window selection.
2. **Workspace confinement:** File operations must stay strictly within the operator-selected workspace root and reject path traversal (`..`), absolute paths, symlinks, NTFS junctions/reparse points, and hard links.
   - **Explicit operator opt-in, unified catalogue:** the owner may select a wider file scope (`allowed-roots` or `os-user`) only in the operator-private `unified-v1.json` manifest. An MCP client can never select or widen that scope. `os-user` scope applies only while the active mode is Fully Unlocked; lower modes revert to the workspace policy. File tools still refuse protected authority roots and private state, and still require fresh write observations and filesystem identity checks. Changing the scope changes the authority seal and requires a new OAuth authorization; existing grants are not transplanted.
3. **Single-use observations:** Mutating file, browser, and desktop UI actions must consume a fresh single-use observation token and re-verify target identity before acting.
4. **Secret protection:**
   - Outbound extension OAuth 2.1 tokens must never be written in plaintext to `extensions.json`, `.extensions-admin.json`, logs, or tool responses.
   - Tokens must be protected by OS-native storage (Windows DPAPI, macOS Keychain, or Linux Secret Service) and fail closed if OS secret storage is unavailable.
   - Pre-registered client secrets and optional bearer tokens are referenced only by `AGENT_BRIDGE_EXTENSION_*` environment variable names.
5. **No arbitrary remote shell:** Process tools must execute only operator-pinned SHA-256 entries from private `commands.json`, and must refuse rather than fall back to current-user execution when restricted (Low-IL) launching is unavailable.
   - **Explicit operator opt-in, Fully Unlocked:** direct shell or program sessions exist only when the operator starts the workstation with both `--profile fully-unlocked` and `--enable-processes`. They run with the current user's existing OS permissions, without elevation or a different token. An MCP client can never enable them, and lowering the active mode revokes every owned session before the lower mode is confirmed.
6. **Documentary-only Agent Skills:** Bundled scripts inside skill packages must never be auto-executed.
7. **Isolated browser & desktop scope:** Native Chrome sessions must never access personal Chrome profiles, expose a TCP CDP port, or allow arbitrary agent-supplied JavaScript; desktop UI actions must never inject global foreground mouse/keyboard input.

## Reporting a Vulnerability

**Please do not report security vulnerabilities in public GitHub issues.**

Instead, please use GitHub's **Private Vulnerability Reporting** ("Security" tab -> "Report a vulnerability") on this repository.

Include in your report:
- Affected crate, tool name, or CLI subcommand
- Platform and OS version (Windows / macOS / Linux)
- Minimal reproduction steps or proof-of-concept
- Expected vs. actual security boundary behavior

We aim to acknowledge reports within 72 hours and coordinate a fix before public disclosure.
