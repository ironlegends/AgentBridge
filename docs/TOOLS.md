# MCP Tool Reference (43 Tools)

Agent Bridge exposes **16 Mission & Subtask tools** plus **27 Workstation tools** across MCP protocol versions `2025-03-26` and `2025-06-18`.

Only the tools enabled by your local startup profile and explicit CLI flags are published in `tools/list`. The embedded workstation console changes handler admission within that immutable startup catalog; lowering the active profile does not change OAuth authority or tool schemas. `fully-unlocked` retains file-tool confinement and adds direct processes only when explicitly enabled at startup.

---

## 1. Missions & Shared Subtasks (16 Tools)

Backed by SQLite schema v7 (`contracts/mission-tools-v1.json`). Available in `stdio`, local HTTP (`start`/`serve`), and `gemini serve`.

| Tool | Purpose |
| --- | --- |
| `agent_bridge_status` | Health and active gateway/backend metadata. |
| `agent_bridge_context_create` | Creates an isolated actor context handle (`ctx_...`) and public context ID. |
| `agent_bridge_mission_create` | Creates a durable mission with a stable `idempotency_key`. |
| `agent_bridge_mission_get` | Reads mission details visible to the caller's context handle. |
| `agent_bridge_mission_list` | Lists up to 100 missions visible to the context handle. |
| `agent_bridge_mission_observe` | Returns current owner context ID, caller role/invitation state, and current `revision`. |
| `agent_bridge_mission_grant` | Owner invites another context ID at the observed `if_revision`. |
| `agent_bridge_mission_attach` | Invitee accepts an invitation at the observed `if_revision`. |
| `agent_bridge_mission_transfer` | Owner transfers ownership to an attached member at `if_revision`. |
| `agent_bridge_mission_checkpoint` | Persists a durable result summary at `if_revision`. |
| `agent_bridge_mission_checkpoints` | Reads bounded durable result checkpoints without replay. |
| `agent_bridge_mission_complete` | Completes a mission at `if_revision` with a stable `idempotency_key`. |
| `agent_bridge_mission_subtask_create` | Creates a shared subtask under a mission at `if_revision`. |
| `agent_bridge_mission_subtask_assign` | Assigns a subtask to a target context ID at `if_revision`. |
| `agent_bridge_mission_subtask_update` | Updates subtask status/result summary with optimistic concurrency. |
| `agent_bridge_mission_subtask_list` | Lists subtasks for a mission. |

---

## 2. Workspace Files & Policy (9 Tools)

All paths are strictly workspace-relative (`..`, absolute paths, symlinks, reparse points, and hard links are rejected).

| Tool | Profiles | Notes |
| --- | --- | --- |
| `desktop_policy_status` | All workspace profiles | Reports active profile and workspace boundary. |
| `desktop_get_file_info` | All workspace profiles | Metadata (kind, byte size, line count). |
| `desktop_list_directory` | All workspace profiles | Directory listing (`depth` 1–4; locked to `1` in `gemini project-read`). |
| `desktop_read_file` | All workspace profiles | Bounded line-range UTF-8 reader; issues a fresh one-time `observation_id`. |
| `desktop_search` | All workspace profiles | Bounded file-name or content search (locked to file-name search in `gemini project-read`). |
| `desktop_create_directory` | `workspace-write`, `full-control` | Creates directories strictly inside the workspace root. |
| `desktop_write_file` | `workspace-write`, `full-control` | Creates new files, or `rewrite`/`append` existing files using a fresh `observation_id`. |
| `desktop_edit_file` | `workspace-write`, `full-control` | Exact string replacement requiring a fresh `observation_id`. |
| `desktop_move_file` | `workspace-write`, `full-control` | Moves an observed regular file to a non-existent destination inside the workspace. |

---

## 3. Temporary Checksum-Verified Artifacts (1 Tool · 5 Actions)

`desktop_artifact_manage` publishes workspace files into temporary, in-instance, SHA-256 verified artifacts:

| Action | Profiles | Notes |
| --- | --- | --- |
| `list` | `read-only`, `workspace-write`, `full-control` | Lists live non-expired artifacts. |
| `get` | `read-only`, `workspace-write`, `full-control` | Returns artifact metadata and SHA-256 digest. |
| `read` | `read-only`, `workspace-write`, `full-control` | Reads bounded chunks in `utf8` (automatically trims cleanly at multi-byte UTF-8 boundaries; returns `INVALID_UTF8_BOUNDARY` or `INVALID_UTF8` when applicable) or `base64` (binary-safe). |
| `publish` | `workspace-write`, `full-control` | Publishes a policy-approved workspace file (`READ_ONLY` refused in read-only profiles). |
| `delete` | `workspace-write`, `full-control` | Deletes an artifact; subsequent `get`/`read` returns `ARTIFACT_NOT_FOUND`. |

---

## 4. Versioned Documentary Agent Skills (1 Tool · 7 Actions)

`desktop_skill_manage` manages versioned, **documentary-only** skill packages under `<settings>/skills`. Bundled scripts are treated strictly as readable documentation and are **never auto-executed**.

| Action | Profiles | Notes |
| --- | --- | --- |
| `list`, `get`, `read`, `validate` | `read-only`, `workspace-write`, `full-control` | Inspect installed revisions, read bounded resource files, or validate local folders/ZIPs. |
| `install`, `activate`, `rollback` | `workspace-write`, `full-control` | Install versioned packages from workspace directories or local plain ZIP archives, switch active revision, or roll back safely. |
| Remote `source_url` (`validate`/`install`) | `full-control` + `AGENT_BRIDGE_SKILL_ALLOWED_HTTPS_ORIGINS` | Bounded, redirect-free, proxy-free HTTPS ZIP fetch verified against required 64-hex `expected_sha256`. |

---

## 5. Persistent Task Rooms (1 Tool · 11 Actions)

`desktop_task_manage` (`contracts/task-room-v1.json`) persists multi-step work across sessions inside a workspace-bound Task Room backed by SQLite:

| Action | Purpose |
| --- | --- |
| `context_create` | Mints an opaque capability handle bound to the current workspace. |
| `context_discover` | Read-only discovery of Task Rooms scoped to the current workspace. |
| `context_reattach` | Rotates and reattaches a context handle (invalidates the prior handle). |
| `create`, `list`, `get` | Creates tasks with ordered steps, lists goal/summary/blocker, reads full task + ordered history events. |
| `checkpoint` | Persists progress, verified facts, open risks, and step status updates. |
| `block`, `resume` | Explicitly marks a task blocked (preventing premature completion) and resumes work. |
| `final_review`, `complete` | Records a `pass`/`failed` review and enforces completion gates (rejects `complete` while blocked or with remaining `missing_checks`). |

---

## 6. Native Chrome Browser Automation (3 Tools)

Rust-only automation over private inherited CDP pipes (`--remote-debugging-pipe`), using Windows handles or Unix descriptors 3/4, with zero Node.js, zero Playwright, and zero exposed TCP debugging ports. The tool schemas are shared; Unix project file upload/download currently return `UNIX_PROJECT_BROWSER_TRANSFERS_UNAVAILABLE`. See [UNIX-PARITY.md](UNIX-PARITY.md) for qualified installations and native coverage.

| Tool | Actions / Modes | Security Boundaries |
| --- | --- | --- |
| `desktop_browser_session` | **9/9 actions:** `start`, `list`, `close`, `new_page`, `select_page`, `close_page`, `handle_dialog`, `list_profiles`, `delete_profile` | Never touches personal Chrome profiles. Ephemeral profile by default; optional persistent `profile_id` confined to `<settings>/mcp-browser-profiles` (rejects symlinks, traversal, and deleting an active profile). Up to 3 Bridge-owned tabs. |
| `desktop_browser_snapshot` | `mode: "full"` or `"find"`, optional viewport PNG `screenshot`, `blocking_dialog` detection | Bounded to 80 interactive elements and 50,000 text chars. Issues a fresh single-use 30-second `browser_observation_id`. Password/sensitive fields excluded. |
| `desktop_browser_act` | **17/17 action types:** `goto`, `click`, `hover`, `drag`, `fill`, `type_text`, `set_checked`, `press`, `wait`, `wait_selector`, `wait_url`, `wait_text`, `select`, `set_files`, `download`, `scroll`, `navigation` | Consumes a fresh `browser_observation_id` and re-verifies tab URL, document loader, and DOM node identity before acting. |

---

## 7. Streamable HTTP MCP Extensions & Outbound OAuth 2.1 (4 Tools)

| Tool | Actions / Capabilities | Notes |
| --- | --- | --- |
| `desktop_mcp_manage` | **11/11 actions:** `list`, `inspect`, `add`, `remove`, `enable`, `disable`, `set_oauth`, `auth_start`, `auth_status`, `auth_disconnect`, `refresh` | `list`/`inspect` run immediately; all 9 mutating/auth actions queue a typed proposal in `<settings>/.extensions-admin.json` for explicit local operator approval (`agent-bridge extensions approve`). Outbound OAuth 2.1 tokens use PKCE `S256` with OS-protected storage (**Windows DPAPI**, **macOS Keychain**, or **Linux Secret Service**). Client secrets are referenced only by env var name (`AGENT_BRIDGE_EXTENSION_*`). |
| `desktop_mcp_tool_search` | Local cached descriptor search | Never contacts upstream servers. |
| `desktop_mcp_tool_inspect` | Inspect cached tool schema | Reads locally pinned descriptor only. |
| `desktop_mcp_tool_call` | Invoke individually approved upstream tool | Verifies live descriptor hash against local pin before execution. |

---

## 8. Owned Process Sessions (4 Tools)

A workstation requires `--enable-processes` plus startup `full-control` or `fully-unlocked`. `stdio` retains its existing restricted provider. Provider selection is fixed at startup, so one tool name always has one matching schema and handler.

### Restricted provider

Used by full-control workstations and the existing `stdio` path:

| Tool | Purpose |
| --- | --- |
| `desktop_start_process` | Accepts only a SHA-256 pinned executable from `<settings>/commands.json`; arbitrary shells are refused. Restricted Low-IL launching is unsupported in 2.0.0: on Windows the request is refused with `PROCESS_LOW_IL_UNQUALIFIED` before any process is created, and it never falls back to current-user execution. |
| `desktop_read_process` | Reads bounded stdout/stderr chunks from an owned process session. |
| `desktop_interact_process` | Sends bounded input to a compatible owned process session. |
| `desktop_terminate_process` | Terminates only a process session started by this gateway. |

### Direct provider

Used only by a workstation started with `--profile fully-unlocked --enable-processes`. `desktop_start_process` accepts either `command` with an explicit shell (`pwsh`, `powershell`, `cmd`, `sh`, `bash`) or `program` with literal `args`. It runs at the current account's OS permissions. The other three tools address only opaque sessions owned by this gateway. All four reject requests whenever the active mode is below fully-unlocked; lowering the mode revokes the owned sessions synchronously.

This provider does not turn into the restricted provider during a live downgrade. The separate pinned project diagnostic remains governed by full-control. A shell/program response timeout bounds the response wait, not the program lifetime. See [WORKSTATION-MODES.md](WORKSTATION-MODES.md) for complete examples, stdin acknowledgement semantics, cleanup and bounded-output limits.

---

## 9. Scoped Desktop UI (up to 4 Tools)

### Windows

Enabled only when `--local-window-read` is passed on the local CLI and confirmed via the native Win32 Yes/No dialog (defaulting to **No**). This Windows surface is preserved unchanged by the Unix adapters.

| Tool | Supported Operations | Refused by Design |
| --- | --- | --- |
| `desktop_agent_desktop` | **Experimental.** `status`, `start` (by `desktop_number`, optionally bound to a Task Room) and `stop` (by `lease_id`) on a pool of up to 16 dedicated Windows virtual desktops selected locally in the private `unified-v1.json`. Requires active `full-control` or higher. Each lease is revocable, shows a visible blue safety HUD heartbeat and is revoked when the heartbeat or connection is lost. | Never uses or switches to the user's `Desktop 1`, never lets the client change the pool, and never spawns privileged processes. |
| `desktop_ui_windows` | Lists only the single operator-approved foreground window (opaque `window_id`). | Never enumerates unrelated user windows. |
| `desktop_ui_snapshot` | Bounded Win32 native control tree + optional window-only `WM_PRINT` PNG capture; mints single-use `computer_observation_id`. | No full-desktop screen capture. |
| `desktop_ui_action` | **5 background-safe actions:** `wait`, `invoke` (`Button`), `set_value` (non-password `Edit`), semantic `scroll` (`WM_VSCROLL`/`WM_HSCROLL`), and bounded post-message `send_keys` (non-password `Edit`, `allow_system_keys` refused). | `click`, `hover`, `drag` return `REQUIRES_FOREGROUND_INPUT` instead of stealing the user's cursor or keyboard. |

### macOS and Linux X11

Both adapters expose `desktop_ui_windows`, `desktop_ui_snapshot` and `desktop_ui_action` for one locally approved foreground window. `desktop_agent_desktop` remains Windows-specific.

| Backend | Inspection | Actions | Capture |
| --- | --- | --- | --- |
| macOS | Bounded AX tree, retained AX identity, process incarnation, physical executable and bundle identity | `wait`, `invoke` through AXPress, `set_value` on writable non-sensitive AX text controls | Unavailable; no unproven AX-to-window capture mapping |
| Linux X11 | Bounded child-window tree, XRes PID ownership and process incarnation | `wait`, centered left `click`, `send_keys` for Enter/Escape/Tab/arrows | Window-owned XComposite pixmap only when already composited and in a supported TrueColor format |

Linux input receipts confirm dispatch (`dispatched: true`, `effect_verified: false`); applications may ignore synthetic events. Neither Unix adapter injects global input, accepts scripts from MCP, changes the selected target, or falls back to a whole-desktop screenshot. Snapshot/action identity changes and expired observations are refused. See [UNIX-PARITY.md](UNIX-PARITY.md).
