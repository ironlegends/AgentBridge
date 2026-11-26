# Quick Start Guide

Use ChatGPT Web or Gemini Web as a local agent with Agent Bridge. Your AI stays in its web chat and uses your provider's applicable subscription allowance; Agent Bridge runs authorized local tools without a separate model API key. Quotas are provider-controlled and may be shared with other products.

**Windows users:** start with the [portable release](https://github.com/ironlegends/AgentBridge/releases) and [installation instructions](#install-the-windows-release-portable-zip). Developers can build the headless CLI or desktop app from source. Local MCP clients are also supported.

---

## 1. Prerequisites & Build

- **Rust toolchain.** Rust and Cargo 1.99.1 were used for Windows x86-64 MSVC qualification. The minimum supported Rust version is undetermined. Use `--locked` for both Cargo workspaces.
- **Native desktop app.** Windows build and test qualification uses the MSVC build tools and WebView2 Runtime. The platform WebViews are WKWebView on macOS and WebKitGTK on Linux. Current desktop build and test evidence covers Windows.
- **Optional browser tools:** the qualified Windows portable app ships a pinned browser bundle. The separate native Chrome CDP CLI mode uses a qualified Chrome installation; see [browser modes](#native-chrome-browser-mode-windows-macos-and-linux).

Build the single standalone CLI executable:

```sh
cargo build --locked --release -p agent-bridge
```

Verify the CLI binary:

```sh
./target/release/agent-bridge --version
./target/release/agent-bridge --help
```

---

## 2. Native Desktop Application (Tauri v2)

The native panel opens in its own window and hides to the system tray. The repository and source ZIP include its independent Cargo workspace.

```sh
cargo test --locked --manifest-path app/src-tauri/Cargo.toml
cargo build --locked --manifest-path app/src-tauri/Cargo.toml
```

An ordinary `cargo test` has no ignored tests. Tests that need resources outside the repository are compiled only behind a Cargo feature and fail if a resource is missing:

- `cargo test --locked -p agent-bridge --features qualification`: Windows-only release qualification tests with the pinned browser and native bundles (`AGENT_BRIDGE_BROWSER_BUNDLE`, `AGENT_BRIDGE_NATIVE_TEST_BUNDLE` and their manifest digests), the reviewed `search_model_context_protocol` descriptor file (`AGENT_BRIDGE_EXTENSION_TEST_DESCRIPTOR`), the WPF fixture and dedicated Virtual Desktops. It shows windows and sends synthetic input on the current session.
- `cargo test --locked -p agent-bridge-lifecycle --features low-il-specimen`: the approved local Low-IL specimen (`AB_LOW_IL_SPECIMEN`). Low-IL execution is unsupported; these tests stay for diagnosis only.

Run `app/src-tauri/target/debug/agent-bridge-desktop-app` from the repository or extracted source root (append `.exe` on Windows). If you set `--target-dir` or `CARGO_TARGET_DIR`, use the `debug/` directory below that target instead. A `--release` build uses `release/`.

### Install the Windows release (portable ZIP)

1. Download `agent-bridge-<version>-windows-x64-<commit>.zip`, `SHA256SUMS` and `SHA256SUMS.sig` from the GitHub release.
2. Verify the signature with the public key committed in this repository (`licenses/agent-bridge-release-public.pem`), then the checksum, before extracting:

   ```powershell
   openssl dgst -sha256 -verify licenses/agent-bridge-release-public.pem -signature SHA256SUMS.sig SHA256SUMS
   (Get-FileHash .\agent-bridge-<version>-windows-x64-<commit>.zip -Algorithm SHA256).Hash.ToLower()
   ```

3. Extract the archive into a new, user-writable versioned directory, for example `%LOCALAPPDATA%\Programs\AgentBridge\<version>`. Do not extract over a previous version. `release-manifest.json` lists every member with its SHA-256.
4. Point the native configuration (below) at the bundled resources under `resources/automation/` and start `agent-bridge-desktop-app.exe --config <absolute-path>`.

**Update:** extract the new version side by side, stop the running application (Quit, or Stop then exit), repoint the login task and shortcut to the new executable, and start it. **Rollback:** stop the new version and repoint the task and shortcut to the previous directory. The private state directories are not inside the installation directory, so neither operation copies or rewrites them. A change of the unified capability identity (for example a new resource bundle) requires a new OAuth authorization; see [UNIFIED-DESKTOP.md](UNIFIED-DESKTOP.md).

### Run a unified native Workstation

Prepare the private state directories below, then create a versioned `workstation-app.json` with the existing workstation arguments. Launch the desktop executable with `--config <absolute-path>`. It owns the embedded Rust runtime and optional tunnel; the interface uses native IPC and requires no separate operator HTTP listener.

Use one current-user login task with `--background` and a foreground shortcut to the same executable and config. Close hides the window; explicit Quit stops the managed stack. Existing installations need a controlled handoff from the prior owner before this app starts. Follow [the native configuration and migration guide](UNIFIED-DESKTOP.md).

### Attach to a Workstation

1. Reuse the existing Workstation or [start one with `--ui-port`](#51-prepare-the-authenticated-workstation-relay). The owner selects the project, startup profile ceiling, database, settings and OAuth roots. Use `--ui-open` only if you want the optional browser console to open automatically.
2. Keep the Workstation's stdout in an owner-private log. Its ready record contains an operator token. Create `operator-connection.json` in the native panel's configuration directory with the exact ports and absolute log path. See [the connection file and directory examples](WORKSTATION-MODES.md#attach-the-native-desktop-application).
3. Launch the native panel. Once authenticated, it shows the current mode, startup ceiling, Tasks and Approvals. Project, storage and initialization settings are disabled when an attachment is configured. Compatible restarts reuse the same SQLite database and OAuth state. Approve new OAuth enrollment or individual requests through the local operator workflow.

**Stop** requests cooperative shutdown and waits for the service ports to close. **Start** and **Restart** require a supported and validated Windows scheduled task. If the task cannot be reached or validated, **Stop** remains available when the Workstation is connected and advertises shutdown. The panel shows the pending phase immediately and reconciles the confirmed state or reports an error. [Attached lifecycle details](WORKSTATION-MODES.md#control-an-attached-workstation).

### Set up a standalone panel

Use the panel without native `workstation-app.json` or `operator-connection.json` to set up its own local gateway. Choose your project and private paths, initialize SQLite and settings, and save a mode preference. Saving **Full** or **Unlock** in standalone mode requires confirmation. The local gateway has its own Start, Restart and Stop controls. Use the attached setup above for live Workstation mode or lifecycle control.

---

## 3. Directory Layout (Three Disjoint Roots)

Agent Bridge enforces a strict separation between **code**, **private database**, and **private operator settings**:

```text
/path/to/your-project/             <- Workspace the agent is allowed to inspect or edit
/path/to/private/database/missions.sqlite   <- SQLite v7 database (Missions + Task Rooms)
/path/to/private/settings/         <- Operator-only settings (extensions, skills, commands, browser profiles)
/path/to/private/lifecycle/        <- Cooperative start/stop lock and session receipts
```

Create these directories before starting a Workstation relay; it canonicalizes every protected root during startup. Keep the database in its own `database/` subdirectory: putting `missions.sqlite` directly in the common private parent would make that database boundary overlap the OAuth directories and startup would be refused.

For a **new Windows installation**, create a fresh private root from an ordinary, non-elevated PowerShell console. This example refuses an existing root and applies owner/SYSTEM-only protected ACLs only to the new directories:

```powershell
$privateRoot = Join-Path $env:LOCALAPPDATA 'AgentBridgePrivate'
if (Test-Path -LiteralPath $privateRoot) { throw 'Reuse the existing configuration or choose a fresh private root' }
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$acl = [System.Security.AccessControl.DirectorySecurity]::new()
$acl.SetSecurityDescriptorSddlForm("O:${sid}D:P(A;OICI;FA;;;${sid})(A;OICI;FA;;;SY)")
$paths = @($privateRoot) + @('database', 'settings', 'lifecycle', 'oauth-missions', 'oauth-workstation')
foreach ($path in $paths) {
  $directory = if ($path -eq $privateRoot) { $path } else { Join-Path $privateRoot $path }
  New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
  Set-Acl -LiteralPath $directory -AclObject $acl -ErrorAction Stop
}
```

On macOS/Linux, create the corresponding directories with owner-only permissions (`0700`) under a private parent; keep OAuth state initially empty. For an existing installation, retain its paths, ownership and grants rather than rerunning first-time directory setup. Substitute your chosen root for `/path/to/private` and the Windows placeholder paths throughout this guide.

Initialize the database and private settings once. In standalone mode, the panel also offers **Initialize** in **Settings → Advanced settings**.

```sh
agent-bridge db init /path/to/private/database/missions.sqlite
agent-bridge db inspect /path/to/private/database/missions.sqlite
agent-bridge settings init /path/to/private/settings
```

---

## 4. Local Coding Harness (`stdio`)

Any MCP client that speaks JSON-RPC over `stdio` (Claude Code, Codex CLI, Cursor, Windsurf, or custom harnesses) can launch `agent-bridge stdio` directly.

### Read-Only Workspace Inspection

```sh
agent-bridge stdio /path/to/private/database/missions.sqlite \
  --workspace /path/to/your-project
```

### Writable Coding Agent + Task Rooms + Skills + Extensions

```sh
agent-bridge stdio /path/to/private/database/missions.sqlite \
  --write-workspace /path/to/your-project \
  --settings /path/to/private/settings
```

### Enabling Pinned Processes or Remote HTTPS Skill Imports

Set the startup profile explicitly in the local launcher environment:

```sh
# Linux / macOS
export AGENT_BRIDGE_DESKTOP_PROFILE=full-control
export AGENT_BRIDGE_SKILL_ALLOWED_HTTPS_ORIGINS="<your-approved-https-origin>"

# PowerShell (Windows)
$env:AGENT_BRIDGE_DESKTOP_PROFILE = "full-control"
$env:AGENT_BRIDGE_SKILL_ALLOWED_HTTPS_ORIGINS = "<your-approved-https-origin>"
```

Pinned commands are defined exclusively by the operator in `<settings>/commands.json` (each entry pinned by executable path and SHA-256). This restricted provider remains in place for `stdio` and full-control workstations. A workstation started explicitly with `--profile fully-unlocked --enable-processes` uses the separate direct process provider described in [WORKSTATION-MODES.md](WORKSTATION-MODES.md).

---

## 5. Connecting ChatGPT Web and Gemini Web

These connections use your existing web chat, not a separate model API. Where providers keep web and local-agent allowances separate (for example Gemini Web and Antigravity), the applicable web allowance is used. Agent Bridge neither grants additional quota nor changes provider limits.

**For ChatGPT Web, use the official Secure MCP Tunnel connection.** Gemini Web continues to use the authenticated HTTPS relay. The `gemini workstation` command serves both clients; its name does not restrict it to Gemini.

| Client | Connection | Local boundary |
| --- | --- | --- |
| ChatGPT Web | **Plugins → Add custom MCP server → Connection: Tunnel** | Official `tunnel-client` forwards calls to the OAuth-protected Workstation relay. |
| Gemini Web | Custom MCP connection to `<https-workstation-origin>/mcp` | HTTPS reverse proxy forwards to the same OAuth-protected relay. |
| Local MCP harness | `stdio`, or the local mission HTTP service | No Secure MCP Tunnel account or runtime key is required. |

### 5.1 Prepare the authenticated Workstation relay

Reuse an already running relay with the intended project, startup profile, private state and HTTPS origin. Do not launch a second owner against its OAuth directory. For a new installation, initialize the database and settings as described above, then start this process in its own terminal or operating-system supervisor:

```sh
agent-bridge gemini workstation \
  /path/to/private/database/missions.sqlite \
  /path/to/private/oauth-workstation \
  <https-workstation-origin> \
  18856 \
  --project /path/to/your-project \
  --profile workspace-write \
  --missions-state /path/to/private/oauth-missions \
  --missions-origin <https-missions-origin> \
  --settings-dir /path/to/private/settings \
  --lifecycle-dir /path/to/private/lifecycle \
  --enable-task-rooms \
  --enable-settings-tools \
  --ui-port 18890
```

Use absolute, disjoint private paths and distinct Missions/Workstation OAuth origins and state directories. The Workstation and operator listeners bind to `127.0.0.1` on distinct ports. Direct the owner's stdout to a private log, then attach the native panel through `operator-connection.json`. Add `--ui-open` only to open the optional local browser console.

Agent Bridge currently advertises HTTPS OAuth endpoints from `<https-workstation-origin>`. Keep that origin reachable through your chosen HTTPS reverse proxy (for example Tailscale Funnel, Cloudflare Tunnel, or a proxy you operate). **Secure MCP Tunnel can carry OAuth discovery, but it does not automatically publish the browser-facing authorization endpoint.** Keep required OAuth reachability in place when migrating an existing Gemini installation; switching ChatGPT to Tunnel does not justify removing Gemini's HTTPS route.

The tunnel example below targets this existing HTTPS relay, retaining its resource origin and OAuth grants. ChatGPT selects the tunnel ID rather than registering that URL as a public MCP connection. A different local/private upstream topology needs its own verification of advertised OAuth URLs, discovery trust and forwarding.

### 5.2 Install and configure the official Secure MCP Tunnel client

1. In [OpenAI Platform Tunnels](https://platform.openai.com/settings/organization/tunnels), create or select a tunnel. Associate it with the intended Platform organization **and the ChatGPT workspace** where the plugin will be installed.
2. Create a separate [runtime API key](https://platform.openai.com/settings/organization/api-keys) restricted to **Tunnels: Read + Use**. The person managing tunnel definitions needs Read + Manage; that administrative privilege is not needed by the running client. ChatGPT custom-MCP access is also subject to the workspace's permissions.
3. Install the supported binary from Platform or the [official `openai/tunnel-client` releases](https://github.com/openai/tunnel-client/releases/latest). Check its published provenance and use `tunnel-client --version` and `tunnel-client help quickstart` to confirm the installed CLI.

The following PowerShell example uses a dedicated profile directory and runtime state directory outside the repository. Replace the placeholder paths, tunnel ID and HTTPS origin. The flags were checked against `tunnel-client` 0.0.21; consult the installed binary's help when upgrading.

```powershell
$tunnel = 'C:\Tools\tunnel-client\tunnel-client.exe'
$tunnelRoot = 'C:\AgentBridge\private\secure-mcp-tunnel'
$profileDir = Join-Path $tunnelRoot 'profiles'
$env:TUNNEL_CLIENT_STATE_DIR = Join-Path $tunnelRoot 'state'
$origin = 'https://bridge.example.com'
$tunnelId = '<your-tunnel-id>'

# Exact HTTPS origins only: these are separate discovery/forwarding permissions.
$env:MCP_OAUTH_TRUSTED_ORIGINS = $origin
$env:HARPOON_OAUTH_FORWARD_ORIGINS = $origin
$env:HARPOON_ALLOW_PLAINTEXT_HTTP = 'false'

& $tunnel init --sample sample_mcp_with_dcr `
  --profile agent-bridge-chatgpt --profile-dir $profileDir `
  --tunnel-id $tunnelId --mcp-server-url "$origin/mcp" `
  --control-plane-api-key-ref env:AGENT_BRIDGE_TUNNEL_API_KEY `
  --health-listen-addr 127.0.0.1:0
if ($LASTEXITCODE -ne 0) { throw 'Tunnel profile creation failed' }

# Enter the runtime key locally; never paste it into a command or chat.
$runtimeKey = Read-Host 'Tunnel runtime key' -AsSecureString
try {
  $env:AGENT_BRIDGE_TUNNEL_API_KEY =
    [System.Net.NetworkCredential]::new('', $runtimeKey).Password
  & $tunnel doctor --profile agent-bridge-chatgpt --profile-dir $profileDir --explain
  if ($LASTEXITCODE -ne 0) { throw 'Tunnel validation failed' }
  & $tunnel run --profile agent-bridge-chatgpt --profile-dir $profileDir
  if ($LASTEXITCODE -ne 0) { throw 'Tunnel runtime exited with an error' }
} finally {
  Remove-Item Env:AGENT_BRIDGE_TUNNEL_API_KEY -ErrorAction SilentlyContinue
  $runtimeKey.Dispose()
}
```

`init` is a first-time operation; reuse the existing profile on later starts. Do not use `--force` to overwrite an unrelated installation. The YAML stores the environment-variable reference, not the key. A runtime key grants tunnel access; it is not a model API key or the Agent Bridge OAuth credential.

Keep all profile, state and secret material outside the shared project. Protect persistent credentials with the OS account's secret storage (for example CurrentUser DPAPI on Windows); decrypt only into the supervised child process environment. Do not use a machine-wide environment variable, a literal key in YAML, a committed `.env`, or raw HTTP/payload logging.

`run` stays in the foreground: its terminal must remain alive until an operating-system supervisor owns the process. For unattended startup, launch it through the user's Task Scheduler/service with the same private directories and process environment, and wait for its exit so supervision remains active. A launcher that starts a child and immediately exits can lose that child when an automation job closes. Verify readiness and a real tool call after the setup terminal is closed.

If using the official managed-runtime commands instead, use `runtimes connect --help`, then verify `runtimes status <alias> --json`. Supply the same `TUNNEL_CLIENT_STATE_DIR` on every lifecycle command. A successful launch alone is not proof of readiness.

### 5.3 Enroll, add the ChatGPT plugin and approve OAuth

Keep Agent Bridge and `tunnel-client` running. In a separate **interactive local terminal**, enable the ten-minute enrollment window:

```powershell
$bridge = 'C:\Tools\AgentBridge\agent-bridge.exe'
$oauthState = 'C:\AgentBridge\private\oauth-workstation'
$origin = 'https://bridge.example.com'
& $bridge oauth enroll $oauthState $origin workstation
```

Type `APPROVE` at the local prompt. This permits registration temporarily; it does not approve an individual client request.

In [ChatGPT Plugins](https://chatgpt.com/plugins):

1. Select **+ → Add custom MCP server**.
2. Enter a recognizable name, such as **Agent Bridge**.
3. Under **Connection**, choose **Tunnel** and select your tunnel (or enter its ID). Use the tunnel connection, not the public URL connection.
4. Configure OAuth authentication with the server's discovery flow, review the permission notice and choose **Create as a plugin**.
5. When the authorization flow is pending, inspect and approve the exact request locally:

```powershell
& $bridge oauth requests $oauthState $origin workstation
& $bridge oauth approve $oauthState $origin workstation '<request-id>' '<exact-callback-from-the-ChatGPT-interface>'
```

Compare the callback with the actual ChatGPT connection interface; do not guess it or accept a callback supplied only by a remote tool request. The local prompt shows the client, resource, scope and expiry. Type `APPROVE` for that single request, then finish the browser authorization flow. The native Tauri **Approvals** view can perform the corresponding local operation.

### 5.4 Verify actual tools and retain the authorization

Confirm the Tunnel client's reported loopback health URL shows readiness and active polling. An unauthenticated `/mcp` probe returning **401** is expected for this OAuth-protected server; metadata discovery should still succeed.

Then select the new plugin in a ChatGPT conversation and request:

```text
Use Agent Bridge. Call desktop_policy_status, then desktop_read_file
with path="README.md", offset=0 and length=3.
Report the actual returned text and SHA-256, and whether observation_id is present.
Do not use a terminal or another plugin.
```

Choose an existing text file relative to the selected project. For authenticated ChatGPT Workstation file reads, the business text field is `file_content`; Gemini retains `content`. The outer MCP content envelope is unchanged. A displayed `{}` is a failed native-read check even if a shell fallback can read the file.

If write access is intended, use one dedicated disposable project file: read it, rewrite it with the returned single-use `observation_id`, then reread and compare the bytes/hash. Test direct processes separately only when the server was explicitly started with `--profile fully-unlocked --enable-processes`. This verifies the requested capabilities without treating installation or catalogue discovery as a successful tool call.

Mode changes in the attached Tauri panel stay within the startup ceiling and preserve the listener, OAuth state and existing grants. They do **not** require OAuth approval at every click. Keep the same state on a compatible restart. A different project identity, origin, startup authority, enabled tool catalogue or protected settings can require a **new owner-private OAuth state and fresh authorization**; never delete or alter the scope seal to force reuse. See [WORKSTATION-MODES.md](WORKSTATION-MODES.md).

| Symptom | Check |
| --- | --- |
| Tunnel absent in ChatGPT | Correct ChatGPT workspace association and the operator's Tunnels Read + Use permission. |
| Runtime starts but calls fail | Keep the supervisor alive; inspect readiness, polling and `doctor --explain` with the same profile/state. |
| Registration returns 403 | Open a new local enrollment window and retry registration; do not reset OAuth state. |
| OAuth browser step fails | Verify the advertised authorization endpoint is reachable and approve only the exact pending callback. |
| Native file result is `{}` | Use a current Agent Bridge build and test `desktop_read_file` itself; a process-based fallback does not prove the native path. |

### 5.5 Gemini Web and optional Missions-only connections

Gemini Web uses the same authenticated Workstation relay at `<https-workstation-origin>/mcp`. Keep its existing connection and grants when migrating ChatGPT to Secure MCP Tunnel. For a new Gemini connection, open enrollment, add that URL in Gemini's custom connection interface, and approve the exact Gemini callback with the same `oauth requests` / `oauth approve` workflow.

For a separate Missions-only relay, keep its audience, origin and state distinct:

```sh
agent-bridge gemini serve \
  /path/to/private/database/missions.sqlite \
  /path/to/private/oauth-missions \
  <https-missions-origin> \
  18855
```

Use audience `missions` for its local OAuth commands. Verify `agent_bridge_status` for that service; use `desktop_policy_status` for a Workstation connection.

The unauthenticated `agent-bridge start` / `serve` mission HTTP listener is local-only and is not the upstream for this Web connection guide. Local MCP clients can continue using it without a tunnel.

### 5.6 Other local and read-only modes

The strict four-tool project reader remains available with its own origin and state:

```sh
agent-bridge gemini project-read \
  /path/to/private/database/missions.sqlite \
  /path/to/private/oauth-project-read \
  <https-readonly-origin> \
  18857 \
  --read-project /path/to/your-project \
  --missions-state /path/to/private/oauth-missions \
  --missions-origin <https-missions-origin> \
  --settings-dir /path/to/private/settings \
  --lifecycle-dir /path/to/private/lifecycle
```

Local-only mission HTTP clients can use the separate lifecycle service:

```sh
agent-bridge start \
  --state-dir /path/to/private/lifecycle \
  --database /path/to/private/database/missions.sqlite \
  --port 18855

agent-bridge stop --state-dir /path/to/private/lifecycle
```

`stop` above controls that local Missions service, not a `gemini workstation` process. Do not run it on the same port as the OAuth Missions relay.

### Official references

- [OpenAI Secure MCP Tunnel: setup, workspace association, ChatGPT UI and OAuth boundary](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
- [Official tunnel-client onboarding](https://github.com/openai/tunnel-client/blob/master/docs/onboarding.md)
- [Official tunnel-client configuration](https://github.com/openai/tunnel-client/blob/master/docs/configuration.md)
- [Official tunnel-client permission model](https://github.com/openai/tunnel-client/blob/master/docs/permissions.md)

---

## 6. Optional Local Opt-In Modes

### Native Chrome Browser Mode (Windows, macOS and Linux)

Attach the Rust-only Chrome provider over private inherited stdio CDP pipes (mutually exclusive with `--local-doc-page` and `--local-learn-url`):

```sh
agent-bridge stdio /path/to/private/database/missions.sqlite \
  --write-workspace /path/to/your-project \
  --settings /path/to/private/settings \
  --local-chrome-page path/to/page.html
```

- `--local-learn-url` and the optional `--local-chrome-origin https://learn.microsoft.com` for Chrome page mode are deprecated in 2.x and reserved for removal in 3.0.0.
- Ephemeral private profiles are created and cleaned up automatically when `profile_id` is omitted.
- When `--settings` is provided, agents can also manage isolated persistent profiles under `<settings>/mcp-browser-profiles` via `profile_id`, `list_profiles`, and `delete_profile`.

### Read-Only Documentary Chrome Reader

```sh
agent-bridge stdio /path/to/private/database/missions.sqlite \
  --workspace /path/to/your-project \
  --local-doc-page README.md
```

Interactive Chrome uses private inherited handles on Windows and descriptors 3/4 on Unix. The separate documentary reader uses a bounded native document-rendering path. A qualified Chrome installation is required. On Unix, browser file upload and download are refused until project-handle transfer parity is implemented. See [UNIX-PARITY.md](UNIX-PARITY.md) for installation requirements and the supported surface.

### Dedicated Work-Window Inspection (Windows)

Requires an existing dedicated Windows desktop and an interactive local Yes/No dialog (defaulting to **No**):

```sh
agent-bridge stdio /path/to/private/database/missions.sqlite \
  --workspace /path/to/your-project \
  --local-window-read <desktop-name> <absolute-exe-path> <window-class> <exact-window-title>
```

---

### Scoped Work-Window Inspection (macOS and Linux X11)

Use the same four local selection arguments, with `macos` or `x11:<display>` as the backend. The selected application must already be in the foreground, and an interactive local consent dialog must be accepted. macOS requires Accessibility permission granted through system settings; Linux requires a local X11 session with XRes 1.2. Wayland, remote X11 and headless sessions are refused.

```sh
agent-bridge stdio /path/to/private/database/missions.sqlite \
  --workspace /path/to/your-project \
  --local-window-read macos \
  /System/Applications/TextEdit.app/Contents/MacOS/TextEdit \
  com.apple.TextEdit "Notes.txt"

agent-bridge stdio /path/to/private/database/missions.sqlite \
  --workspace /path/to/your-project \
  --local-window-read x11:0 /physical/path/to/app WMClassExact "Exact title"
```

Replace every criterion with the exact identity of the window you selected. Linux snapshots describe X11 child windows; they do not claim a complete accessibility tree. macOS screenshots are unavailable. Detailed actions, capture prerequisites and revocation behavior are in [UNIX-PARITY.md](UNIX-PARITY.md).

---

## 7. Operator Extension Administration & Outbound OAuth 2.1

Remote/Web agents calling `desktop_mcp_manage` with mutating actions (`add`, `remove`, `enable`, `disable`, `set_oauth`, `auth_start`, `auth_status`, `auth_disconnect`, `refresh`) **only queue a typed proposal** in `<settings>/.extensions-admin.json`. Review and decide locally:

```sh
agent-bridge extensions import   /path/to/private/settings <mcp-json-path> [--inherit-path <stdio-server>]...
agent-bridge extensions requests /path/to/private/settings
agent-bridge extensions request  /path/to/private/settings <request-id>
agent-bridge extensions approve  /path/to/private/settings <request-id>
agent-bridge extensions approve  /path/to/private/settings <request-id> <request-id>...
agent-bridge extensions refuse   /path/to/private/settings <request-id>
agent-bridge extensions refresh-check /path/to/private/settings <mcp_docs|microsoft_learn|stdio-server>
agent-bridge extensions describe /path/to/private/settings <server> <tool>
agent-bridge extensions compact  /path/to/private/settings
agent-bridge extensions forget-absent /path/to/private/settings <server-name>
```

Several ids approve the pending `add` and `add_stdio` proposals of one `extensions import` together (its `approve_together` list): one terminal confirmation, one journal change.

When `auth_start` is approved locally, Agent Bridge runs a standard **OAuth 2.1 PKCE S256** flow over a temporary `127.0.0.1` callback listener and protects the token using **Windows DPAPI**, **macOS Keychain**, or **Linux Secret Service**. Authorization fails closed if the required OS secret storage is unavailable.

---

## 8. Importing Historical Task Room Snapshots

```sh
agent-bridge import /path/to/private/database/missions.sqlite /path/to/snapshot.json
```

Imported missions stay `blocked` with `actor_context_handle="legacy-import"` and read-only historical steps/events; they never auto-execute or replay side effects.

---

## 9. Local Operator Console (`agent-bridge ui`)

Agent Bridge includes an embedded, zero-dependency local web console compiled directly into the Rust binary (no Node.js, no Electron, no external CDNs). It binds exclusively to `127.0.0.1` and enforces a per-session 256-bit token plus strict `Host`, `Origin`, `Sec-Fetch-Site`, and `Content-Security-Policy` headers.

```sh
agent-bridge ui \
  --port 18890 \
  --database /path/to/private/database/missions.sqlite \
  --settings-dir /path/to/private/settings \
  --oauth-state /path/to/private/oauth-workstation \
  --oauth-origin <https-workstation-origin> \
  --oauth-audience workstation \
  --project /path/to/your-project \
  --open
```

All flags are optional. Run `agent-bridge ui --open` for a quick diagnostics & quickstart view, or attach any combination of `--database`, `--settings-dir`, `--oauth-*`, and `--project` to manage:

- **Overview & Quickstart:** live counts and copy-ready CLI commands pre-filled with your local paths.
- **Missions & Task Rooms:** read-only SQLite v7 inspection (secret context handles are strictly redacted).
- **OAuth 2.1 Approvals:** open a 10-minute enrollment window or approve individual pending ChatGPT/Gemini requests after pasting the exact callback URI from the client UI.
- **Extensions & Skills:** review and approve/refuse queued `desktop_mcp_manage` proposals, inspect outbound OAuth metadata (never secret values), and inspect or roll back documentary skills.
- **Profiles & Diagnostics:** OS capability matrix, security guard verification, isolated Chrome profiles, and workspace access boundaries.

### Keep the console attached to the workstation

Add `--ui-port 18890` to the Workstation command to enable the operator listener for either panel. Add `--ui-open` to open the browser console automatically. Both attached surfaces show the same live profile and stay connected while modes change. Start at the maximum authority you intend to allow; a button cannot exceed it. Direct shells require `--profile fully-unlocked --enable-processes` at startup. A successful downgrade below fully-unlocked stops its owned direct processes before the new mode is reported.

Use a new OAuth state directory when widening the startup authority; retain the old one for rollback and re-enroll the exact client against the new state. Mode changes made inside the startup ceiling do not require re-pairing. The complete command, mode matrix and shell examples are in [WORKSTATION-MODES.md](WORKSTATION-MODES.md).

### Diagnose Gemini Web approvals and tool quota

In the desktop app, open **Settings > Advanced settings > Diagnostics & Skills** to see the MCP request
audit summary and the 20 most recent records, newest first. An embedded desktop
workstation shows the audit without an operator listener.

Read `mcp_request_audit` from `GET /api/diagnostics` on the workstation's
authenticated local operator listener. Use the port from `--ui-port` and the
token from the current private `ui_url` startup record. For example, in
PowerShell 7 with `--ui-port 18890`:

```powershell
$operatorToken = Read-Host 'Local operator token' -MaskInput
try {
    $headers = @{ 'X-Agent-Bridge-Token' = $operatorToken }
    $audit = (Invoke-RestMethod 'http://127.0.0.1:18890/api/diagnostics' -Headers $headers).mcp_request_audit
    $audit | ConvertTo-Json -Depth 6
} finally {
    Remove-Variable operatorToken, headers -ErrorAction SilentlyContinue
}
```

The snapshot is tied to the running workstation and covers its `/mcp` route in
both unified and legacy OAuth modes. Audit diagnostics for standalone and
managed local listeners, including `gemini serve` and `gemini project-read`, are
deferred to issue #160. A standalone `agent-bridge ui` has no request audit.

1. Read a baseline snapshot. Note `boot_id`, the latest `sequence`, and the
   counters `evicted`, `evicted_verified`, and `evicted_unverified`. Ask Gemini
   once to call only `agent_bridge_status` with `{}`. This tool reads status
   without changing workstation or mission state.
2. If Gemini displays an **Allow once** card, note the time and approve only
   if you intend that call. The card belongs to the client. After approval,
   look for a new `tools/call` record for `agent_bridge_status`.
3. If Gemini reports **0 remaining**, stop the attempt and read diagnostics
   again. With the same `boot_id`, no intervening eviction, and `in_flight`
   at zero, an unchanged sequence in an isolated probe means no MCP request
   reached Agent Bridge. The client message identifies the quota. A missing
   record alone can also mean an approval is waiting or the transport failed.
   Check new rows even when `provider` is null or `method` is `other`, since
   early refusals can precede authentication or body inspection. A nonzero
   `in_flight` count means the snapshot still has unfinished requests.
4. A matching record proves the request reached Agent Bridge. `http_refusal`
   with `429` and `request_limit` identifies the server's own rate limit.
   `jsonrpc_error` reports a protocol or dispatch error. `tool_error` reports
   `result.isError: true`, which can arrive with HTTP `200`. `success` with
   HTTP `200` on `agent_bridge_status` confirms the status call completed.
   `request_interrupted` with HTTP `500` records a worker failure. A null
   status records cancellation before the handler returned a response.

Use `provider`, `client_id_sha256`, and `catalogue_sha256` to match discovery
(`initialize` or `server/discover`), `tools/list`, and `tools/call` for the
same verified client and tool view. When comparing repeated approval cards,
those fields show whether the completed requests used the same registration
and catalogue. An unverified request has null identity fields. The in-memory
snapshot retains up to 2,048 completed requests from the past 24 hours, with
separate quotas of 1,792 verified and 256 unverified records. When a group is
full, a new record replaces its oldest entry. Expired entries are removed on the
next read or insertion. `evicted_verified` and `evicted_unverified` count both
capacity and age evictions since startup. `evicted` is their sum. A restart
starts a new boot ID, sequence and counters. The audit stores allowlisted method
and tool names, completion time, elapsed milliseconds and error codes. It omits
credentials, request arguments, results, and mission handles.

If the quota prevents the assigned agent from continuing, the attached
mission owner can release the subtask through an already authorized client.
Read the latest subtask revision, then call `agent_bridge_mission_subtask_update`
with that `if_revision`, `status: "blocked"`, a nonblank `summary` giving the
reason (up to 4,096 UTF-16 code units), and a fresh `idempotency_key`. When the
owner releases another context's `in_progress` subtask, the status becomes
`blocked` and the assignment is cleared. The previous `summary` is preserved
and the reason is stored separately as `release_reason`. Reassignment preserves
both fields, and later assignee updates can replace `summary` while keeping the
last `release_reason`. Use the returned revision for a separate
`agent_bridge_mission_subtask_assign` to an attached context.
Have that context read the mission and its last checkpoint before continuing.
Existing OAuth grants and local approvals still apply to the handoff.
