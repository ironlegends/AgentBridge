# Live Workstation Modes and Direct Processes

The native Tauri v2 application can own an embedded Rust workstation and control it through native IPC, using the same live state as MCP without a second operator HTTP port. An attached-panel configuration remains available for an externally owned workstation through its private IPv4 loopback API. In both live paths the four mode buttons change active permissions within the startup ceiling without resetting OAuth. The browser operator console and standalone local gateway remain optional operating paths.

## Run a unified native workstation

Configure `workstation-app.json` and launch the desktop executable with its absolute `--config` path. The app owns the backend and optional tunnel, provides serialized Start/Stop/Restart, hides on window close and stops the managed stack on explicit Quit. One login task can launch the same executable with `--background`.

The permanent MCP/OAuth listener remains on the configured port. The native interface does not use `--ui-port` or an operator token. A present invalid native configuration reports an error and never selects another database or a legacy fallback. See [the complete native configuration and migration guide](UNIFIED-DESKTOP.md).

## Attach the native desktop application

Build the desktop application's independent Cargo workspace:

```sh
cargo test --locked --offline --manifest-path app/src-tauri/Cargo.toml
cargo build --locked --offline --release --manifest-path app/src-tauri/Cargo.toml
```

Start the workstation with `--ui-port` to enable its private control API. `--ui-open` opens the browser console and is not required by the desktop application. Keep the service's stdout in an owner-controlled local log. In the desktop app's configuration directory, create `operator-connection.json`:

```json
{
  "version": 1,
  "controlPort": 18890,
  "gatewayPort": 18856,
  "stdoutLog": "/absolute/private/path/workstation.stdout.log"
}
```

Use an absolute path on the host, with JSON escaping or forward slashes for Windows paths. The configuration directory is `%LOCALAPPDATA%/AgentBridge` on Windows, `~/Library/Application Support/AgentBridge` on macOS, or `$XDG_DATA_HOME/agent-bridge` on Linux (`~/.agent-bridge` when XDG_DATA_HOME is unset).

Launch `agent-bridge-desktop-app` from the independent workspace's `app/src-tauri/target/release/` by default, or from `release/` under your custom target directory. Add `.exe` on Windows. Its native Rust backend reads only the bounded tail of the explicitly configured log, validates the workstation's operator ready record and contacts `127.0.0.1` on the configured port. The connection file contains no token. The per-process control token remains in the Rust backend; it is not sent through Tauri IPC to JavaScript or stored in panel preferences.

The panel displays the confirmed active mode and the session's startup ceiling. A mode change within that ceiling takes one click. Modes above the ceiling, disconnected controls and duplicate in-flight changes are disabled. A failed change does not display a new mode as applied.

The attached panel uses the running service for missions, approvals, skills and diagnostics. Its lifecycle buttons and tray actions follow the authenticated service capabilities and the configured startup supervisor. Initialization and runtime path settings remain unavailable while attached. Quitting the desktop app leaves the external service running; hiding the window leaves its tray icon available. Stop leaves the desktop application open. If the connection file is invalid or the service is unavailable, the panel reports that state and does not fall back to an unrelated local gateway.

Keep the log private because the original operator ready record contains a bearer token. Only configure logs and connection files controlled by the local operator. A workstation restart rotates that token; the native backend reads the latest matching record from the configured log. Update the explicit log path when deployment switches to a different log file.

### Control an attached workstation

The version 1 connection file above remains valid without a supervisor. It can stop a connected Workstation that advertises cooperative shutdown. Use the external launcher to start the Workstation again. Older Workstation builds without that capability have no attached lifecycle controls.

On Windows, an existing scheduled task can provide explicit start and restart ownership. Add its exact local task path to the same connection file:

```json
{
  "version": 1,
  "controlPort": 18890,
  "gatewayPort": 18856,
  "stdoutLog": "/absolute/private/path/workstation.stdout.log",
  "supervisor": {
    "kind": "windows-task",
    "taskName": "\\AgentBridge-Workstation"
  }
}
```

Replace the example task name with the existing task that launches this workstation and writes the configured log. The task must be enabled, belong to the current Windows user, use least privilege, allow on-demand starts and ignore duplicate instances. The desktop application validates these conditions through Task Scheduler before enabling the corresponding action. It does not create or rewrite the task.

| Connection and runtime state | Available lifecycle actions |
| --- | --- |
| Authenticated session with cooperative shutdown and a validated Windows task in the Running state | Stop and Restart |
| Authenticated session with cooperative shutdown and an absent, unsupported, inaccessible or unvalidated supervisor | Stop |
| Authenticated session with cooperative shutdown and a validated Windows task outside the Running state | Stop |
| Disconnected service, validated Windows task in the Ready state and both service ports free | Start |
| Authenticated session without cooperative shutdown | Use the external owner |
| A lifecycle action is pending | Wait for confirmation or an error. Other lifecycle, mode and settings changes are disabled. |

Stop uses the authenticated operator API and waits for both configured ports to close after the service acknowledges the request. Restart also waits for the task to become Ready before running it without extra arguments. Start and Restart finish when the task is Running and the panel has authenticated to the new operator session.

The panel displays **Starting**, **Stopping** or **Restarting** as soon as an action begins. It reconciles the result against the current backend state, refreshes on failure and suppresses stale responses. A timeout reports the unresolved operation so the operator can check the service or startup owner.

**Starting or restarting uses the task's configured startup profile.** A lower active mode chosen for the previous process is not preserved automatically. Reusing the same OAuth state and startup authority keeps the existing grants; the local operator token rotates with the process. A live mode change within the startup ceiling does not restart the service.

### Windows OAuth ownership after process exit

The Windows OAuth store keeps its newly created `running.lock` marker open with `FILE_FLAG_DELETE_ON_CLOSE`. Windows removes that exact file object when its last handle closes, including process termination that skips Rust destructors. The writer lock remains held until the gate closes during normal cleanup. Cooperative Stop remains the preferred way to drain admitted work before exiting.

This applies only when creating a new marker. A pre-existing marker still blocks startup; the service does not guess its owner or delete it automatically. Markers retained by an older build or an uncertain failure require targeted local recovery after proving the prior owner has exited and obtaining exclusive access to the writer lock. Keep OAuth data, grants and authority seals intact.

Readers inspecting the live marker must share delete access. Kernel failure or power loss is outside this process-exit guarantee. Unix marker lifetime is unchanged.

### Review connection and extension requests

The native Approvals screen supports local enrollment and approval of incoming ChatGPT or Gemini OAuth requests. Review the client and paste its exact callback before approving. Callback drafts remain in memory across automatic refreshes and are cleared after approval or when their request disappears.

For an attached workstation, the same screen shows each extension request's endpoint and complete proposal. Approve requires acknowledging that exact proposal; Refuse is a separate explicit action. Duplicate decisions are disabled while a decision is being processed.

An extension OAuth authorization can remain pending after the local decision is accepted. Its status is refreshed without resubmitting the decision, and durable approval is shown only after the provider flow completes. An authorization page opens only when the operator clicks its button. The URL must use HTTPS or literal loopback HTTP; only the default browser is allowed by the Tauri URL permission. The application does not automatically open that page or log its authorization URL.

## Start with a deliberate authority ceiling

```sh
agent-bridge gemini workstation \
  /path/to/private/database/missions.sqlite \
  /path/to/private/oauth-workstation-unlocked \
  <https-workstation-origin> \
  18856 \
  --project /path/to/your-project \
  --profile fully-unlocked \
  --missions-state /path/to/private/oauth-missions \
  --missions-origin <https-missions-origin> \
  --settings-dir /path/to/private/settings \
  --lifecycle-dir /path/to/private/lifecycle \
  --enable-processes \
  --enable-task-rooms \
  --enable-settings-tools \
  --ui-port 18890
```

The UI binds only to `127.0.0.1`. The process prints its local token URL. Add `--ui-open` to open the optional console in the operator's default browser. Keep this URL private and keep the UI port out of public tunnel configuration. The public relay continues to expose the authenticated MCP endpoint on its separate port.

The startup profile is the maximum available mode. `--ui-open` requires `--ui-port`; the UI and MCP ports must differ. Port `0` requests an ephemeral UI port for local tooling.

| Active mode | Files and local capabilities | Processes |
| --- | --- | --- |
| `read-only` | Restricted web project reads; mutations rejected. Explicitly approved inspection capabilities keep their own target restrictions. | Rejected |
| `workspace-write` | Workspace file mutations and explicitly enabled local capability families | Rejected |
| `full-control` | Full-control capability admission, including separately approved extensions and allowed remote skill sources | Restricted provider for a full-control startup; pinned project diagnostic remains available for an unlocked startup |
| `fully-unlocked` | Full-control capability admission; workspace file tools retain their confinement and observation rules | Direct provider only when startup was fully-unlocked **and** `--enable-processes` was supplied |

A workstation started without `--enable-processes` does not gain process tools when a mode button is clicked. A direct provider does not switch its schema to a restricted provider during downgrade: its four tools reject requests until fully-unlocked is active again.

Direct programs can access resources outside the project wherever the current OS account has permission. They do not request elevation, obtain a different user token, or change UAC settings. This authority is an explicit local startup choice.

### Unified capability: explicit OS-user file scope

The legacy workstation file provider remains workspace-scoped. The unified 46-tool catalogue is selected by an operator-private manifest, `<settings-dir>/unified-v1.json`, and enabled by adding `--unified-v1` to the `gemini workstation` arguments. The file is at most 128 KiB, unknown fields are rejected, and MCP clients can neither read nor change it. A complete example with placeholder paths:

```json
{
  "version": 1,
  "policy_version": 1,
  "catalogue_sha256": "7603bc547b696a3c45e4cd3f5b0b98bbf0f51c9cad66bc31f5a75ae5259c349c",
  "private_root": "C:/path/to/AgentBridge/private/automation",
  "file_scope": {"kind": "workspace"},
  "allow_import": false,
  "browser": {
    "bundle_root": "C:/path/to/AgentBridge/2.0.0/resources/automation/browser",
    "manifest_sha256": "<64 lowercase hex: components.browser.manifest_sha256>",
    "state_root": "C:/path/to/AgentBridge/private/automation/browser"
  },
  "windows": {
    "bundle_root": "C:/path/to/AgentBridge/2.0.0/resources/automation/native",
    "manifest_sha256": "<64 lowercase hex: components.native.manifest_sha256>",
    "state_root": "C:/path/to/AgentBridge/private/automation/windows"
  },
  "agent_desktop": {
    "bundle_root": "C:/path/to/AgentBridge/2.0.0/resources/automation/native",
    "manifest_sha256": "<64 lowercase hex: components.native.manifest_sha256>",
    "state_root": "C:/path/to/AgentBridge/private/automation/desktops",
    "desktops": []
  }
}
```

Field rules:

- `version` and `policy_version` must be `1`. Every digest is exactly 64 lowercase hexadecimal characters.
- `catalogue_sha256` must match the executable catalogue. For 2.0.0 it is `7603bc547b696a3c45e4cd3f5b0b98bbf0f51c9cad66bc31f5a75ae5259c349c`; any other value refuses startup with `UNIFIED_CATALOGUE_CHANGED`.
- `file_scope` is one of `{"kind": "workspace"}`, `{"kind": "allowed-roots", "roots": ["<absolute directory>", ...]}` (1 to 32 distinct directories, none inside `private_root`, a protected root or a bundle) or `{"kind": "os-user"}`.
- `allow_import` enables the historical `agent_bridge_task_import` tool; keep it `false` unless you need it. Import still requires an active write-capable mode.
- Each `manifest_sha256` comes from the `release-manifest.json` at the root of the extracted desktop ZIP: `components.browser.manifest_sha256` for `browser`, and `components.native.manifest_sha256` for `windows` and `agent_desktop`.
- `private_root` must already exist and be disjoint from the workspace and from the existing private roots (database, settings, OAuth and lifecycle directories). A sibling such as `private/automation` satisfies this.
- The three `state_root` directories must already exist and be separate physical children of `private_root`. They must not overlap each other or any bundle root.
- Bundle roots must not overlap the workspace or any protected root. Point them at the extracted, read-only release directory.
- `agent_desktop.desktops` is the experimental Agent Desktop pool: up to 16 entries of the form `{"desktop_id": "<Windows virtual desktop GUID>", "desktop_number": <2 or higher>}`, each GUID and number unique. Desktop 1 is never accepted. Leave it empty unless you are qualifying that feature.

The selection is bound into new OAuth grants. When you first enable `--unified-v1`, or change any field later, use a fresh private OAuth state directory and authorize the client again. Grants are bound to the exact capability and are never transplanted.

For a deliberately unlocked workstation, select the startup profile `fully-unlocked` and set `"file_scope": {"kind": "os-user"}`. OS-user scope applies only while Fully Unlocked is active; lower modes revert to the workspace policy. File tools continue to enforce protected authority roots, fresh write observations and filesystem identity checks. Direct programs operate under normal OS-user permissions rather than a restricted Low-IL token.

The fixed Windows `git-revision` diagnostic in active Fully Unlocked uses the pinned executable and fixed argument vector with an owned, hidden current-user process, bounded output and verified Job cleanup. Lower profiles retain the restricted diagnostic provider; a secure Low-IL refusal is not a successful functional run. No automatic fallback widens a restricted profile. Neither path bypasses UAC or runs as SYSTEM. Ordinary administrative operations, where separately supported by the unified provider, require the normal Windows consent mechanism.

Changing a workspace-scoped capability to OS-user scope changes the unified authority seal. Qualify the new manifest and enroll the client with a new private OAuth state when required; do not transplant old grants or change the running legacy service in place. Keep the previous selection and state for rollback.

## Switch modes without interrupting clients

Click one of the four buttons in the attached console. Choices above the startup ceiling are disabled and rejected by the server. The interface reports the server's actual mode after each request.

A successful downgrade revokes process authority before reporting the lower mode. Owned processes are stopped and old session identifiers become invalid; returning to a higher allowed mode permits new sessions. If cleanup cannot be confirmed, the console reports an error and keeps the prior mode visible. Mutating requests already admitted complete before a mode change takes effect. Process output waits do not hold the profile lock.

The process, TCP listener, tool catalog, OAuth resource, scope marker and grants remain unchanged. An existing bearer can continue to make calls permitted by the newly active mode.

## Widening startup authority requires new OAuth state

The startup capability seal deliberately differs when authority is widened. Keep the previous state intact for rollback and choose a new owner-private OAuth directory. Enroll and approve the exact client against the new directory:

```sh
agent-bridge oauth enroll /path/to/private/oauth-workstation-unlocked <https-workstation-origin> workstation
agent-bridge oauth requests /path/to/private/oauth-workstation-unlocked <https-workstation-origin> workstation
agent-bridge oauth approve /path/to/private/oauth-workstation-unlocked <https-workstation-origin> workstation <request-id> <exact-callback-url>
```

The console's OAuth page provides the same local enrollment and approval workflow. Review the pending client and its exact callback. A live mode change inside an existing startup ceiling does not require these steps again.

## Direct process requests

### Run a shell command

```json
{
  "command": "Get-Date",
  "shell": "powershell",
  "cwd": "C:/my-project",
  "timeout_ms": 1000
}
```

Accepted shell names are `pwsh`, `powershell`, `cmd`, `sh` and `bash`. The selected executable must exist on the host. The default is `powershell` on Windows and `sh` on Unix.

### Run a program with literal arguments

```json
{
  "program": "my-program.exe",
  "args": ["argument with spaces", "--option"],
  "cwd": "C:/my-project",
  "timeout_ms": 1000
}
```

Use exactly one form. Arguments are passed without implicit shell interpretation. Windows uses the standard MSCRT argument encoding; a target program may apply its own parser. Use the explicit command/shell form for composed CMD command lines. On Windows, direct programs must be `.exe` or `.com`; use an explicit shell for scripts such as `.cmd` and `.bat`. Relative working directories resolve against the configured project; omitted working directories use that project. Windows canonical directory paths are converted to an ordinary spelling only after verifying that both identify the same directory. CMD requires a compatible ordinary DOS working directory; UNC or verbatim-only paths are rejected before launch because CMD would otherwise fall back to a different directory.

`timeout_ms` is between 0 and 30,000, with a default of 1,000. It limits the response wait, not the running program's lifetime.

### Read output

```json
{
  "session_id": "opaque-session-capability",
  "timeout_ms": 1000
}
```

`desktop_read_process` consumes incremental stdout and stderr. Its receipt includes status, exit code, EOF indicators, truncation/lost-byte information and `has_more`. A caller may read again to drain buffered output. Session identifiers belong only to the gateway that created them; arbitrary PID lookup or targeting is unavailable.

### Send input and close stdin

```json
{
  "session_id": "opaque-session-capability",
  "input": "text\n",
  "eof": true,
  "timeout_ms": 1000
}
```

`desktop_interact_process` does not append a newline. A frame may contain both final text and EOF. `input_queued: true` confirms queue admission, not completed delivery; check `input_id`, `input_completed_through` and `input_error`. Do not resend an accepted frame automatically. `PROCESS_INPUT_BUSY` means the bounded queue rejected the frame before acceptance.

`desktop_terminate_process` takes the same opaque `session_id` and stops the owned session. It never targets an unrelated process.

## Ownership, cleanup and limits

A session belongs to its root program. When that root exits, the supervisor stops descendants in its Windows Job or Unix process group and drains remaining output. Keep the root alive for a long-running service. Gateway shutdown and successful live revocation also clean up owned sessions.

Windows associates the Job during process creation and limits inherited handles to the child's three standard streams. Unix retains the leader's identity until it signals the owned process group; it does not signal a potentially reused process-group ID after reaping. Unix supervision covers that group and does not claim to contain a program that deliberately moves itself into a different group or session.

| Resource | Limit |
| --- | ---: |
| Retained sessions | 32 |
| Buffered output per stream | 256 KiB |
| Output returned per stream and call | 64 KiB |
| UTF-8 input per frame | 64 KiB |
| Pending stdin frames | 4 |
| Direct arguments | 128 |
| Combined direct arguments | 256 KiB, also subject to native launch limits |

Output consumption frees buffer capacity. Incomplete UTF-8 sequences are retained until more bytes or EOF arrive. Session cleanup is bounded; an unconfirmed cleanup is reported as an error rather than a successful downgrade.
