# Architecture & Workspace Guide

The root **14-crate Rust workspace** builds the `agent-bridge` CLI and its reusable workstation library without a separate scripting runtime for its core. The qualified Windows portable browser provider includes a pinned Node.js/Playwright/Chromium worker bundle; the separate native Chrome CDP provider remains available. The native Tauri application at `app/src-tauri` has an independent Cargo manifest and lockfile. In unified mode it embeds that library and calls native operator controls in process. Deliberate legacy configurations retain the attached operator API and standalone local gateway paths.

---

## 1. Crate Map (14 Crates)

| Crate | Path | Responsibility |
| --- | --- | --- |
| `agent-bridge` | `rust/cli` | CLI and reusable workstation library: commands (`stdio`, `start`/`stop`, `serve`, `db`, `settings`, `oauth`, `extensions`, `gemini`, `web`, `import`, `workspace`, `ui`), native Chrome CDP pipe provider, scoped Win32/macOS AX/Linux X11 window adapters, operator extension journal, and terminal process supervisor. |
| `agent-bridge-core` | `rust/core` | SQLite v7 schema initialization, transactional migrations (`contracts/sqlite/001..007`), SHA-256 migration checksum verification, and WAL sidecar safety checks. |
| `agent-bridge-missions` | `rust/missions` | 16 durable Mission & Shared Subtask MCP handlers + persistent project-bound Task Rooms (`task_room.rs`) with optimistic revision checks and capability rotation. |
| `agent-bridge-desktop` | `rust/desktop` | Workspace-confined filesystem tools (`cap-std`), single-use `observation_id` store, chunked SHA-256 artifacts (`artifacts.rs`), and documentary Agent Skills manager (`skills.rs` + `zip_import.rs`). |
| `agent-bridge-extensions` | `rust/extensions` | Streamable HTTP and `stdio` child MCP client (`transport.rs` + `stdio.rs`) on the official rmcp SDK (`transport-async-rw` for contained child pipes) that probes 2026-07-28 through `server/discover` and falls back to one `initialize` session only for a legacy server, handle-pinned SHA-256 executable verification and exact environment resolution, pinned extension registry, bounded HTTPS archive fetcher (`fetch_https_bytes`), and outbound OAuth 2.1 PKCE `S256` with DPAPI, Keychain or Secret Service token storage (`oauth.rs`). |
| `agent-bridge-gateway` | `rust/gateway` | Pure JSON-RPC 2.0 MCP router: legacy `initialize` versions `2024-11-05` through `2025-11-25`, stateless `2026-07-28` per-request metadata, a modern catalog cached per router, strict schema dispatch, and `stdio` framing. Live discovery and listings advertise `ttlMs: 300000`, `cacheScope: "private"`, and the `io.github.ironlegends/catalogRevision` metadata key. |
| `agent-bridge-http` | `rust/http` | Loopback-only (`127.0.0.1`) Axum HTTP transport for `/mcp` and `/health` with concurrency limits, `Accept` header enforcement, and graceful drain on shutdown. |
| `agent-bridge-oauth-server` | `rust/oauth-server` | Inbound OAuth 2.1 + PKCE `S256` authorization core for Web relays (`gemini serve`, `gemini project-read`, `gemini workstation`) with local-only enrollment and individual human approval. |
| `agent-bridge-oauth-compat` | `rust/oauth-compat` | Read-only lossless inspector for historical OAuth state snapshots (duplicate-key rejection, audience/revocation diagnostics, secret redaction). |
| `agent-bridge-commands` | `rust/commands` | Local command decision engine: predefined SHA-256 rules, single-use confirmation permits, and tamper detection between approval and execution. |
| `agent-bridge-leases` | `rust/leases` | SQLite resource lease coordinator (`BEGIN IMMEDIATE`) with monotonic fencing tokens and mutual exclusion. |
| `agent-bridge-lifecycle` | `rust/lifecycle` | Fail-closed single-instance `start`/`stop` lifecycle with HMAC-signed receipts, OS file locks, private directory ACL qualification, Windows restricted-token project sessions, and verified Unix directory-handle transport for the fixed metadata child. |
| `agent-bridge-import` | `rust/import` | Explicit operator-supplied historical Task Room JSON importer into SQLite v7 (idempotent replays, conflict detection, non-executable `blocked` missions). |
| `agent-bridge-web-launch` | `rust/web-launch` | Operator-approved Chrome launcher for opening dedicated ChatGPT project or Gemini notebook profiles without touching personal browser profiles. |

---

## 2. Core Security Invariants

1. **Local-Only Capability Selection:**
   The local workstation configuration chooses the workspace, startup profile ceiling (`read-only`, `workspace-write`, `full-control`, `fully-unlocked`), browser provider, target window and capability flags. Private operator settings choose pinned commands. The native operator controls or explicitly enabled local operator API can change the active profile up to that ceiling through a shared `Arc<RwLock<DesktopProfile>>`. MCP callers have no access to the operator controls. Explicitly enabled fully-unlocked process sessions may select shell commands, executables and working directories at the current account's OS permissions.

2. **Disjoint Trust Boundaries:**
   - **Workspace root:** The project repository the agent works on.
   - **Database & lifecycle state:** Stored outside the workspace; rejected if overlapping.
   - **Operator settings:** Owner-private directory holding `extensions.json`, `.extensions-admin.json`, `.extensions-oauth-tokens.json`, `commands.json`, `skills/`, and `mcp-browser-profiles/`.
   - **Web OAuth relays:** Missions (`gemini serve`) and Workstation (`gemini project-read` / `gemini workstation`) require distinct HTTPS origins and disjoint OAuth state directories.

3. **Secret Hygiene & OS Token Protection:**
   - Outbound extension OAuth tokens are never stored in `extensions.json` or `.extensions-admin.json`.
   - Token records are protected by OS-native secret storage: **Windows DPAPI** (`CryptProtectData` with `CRYPTPROTECT_UI_FORBIDDEN` and server-bound entropy), **macOS Keychain** (`/usr/bin/security`), or **Linux Secret Service** (`/usr/bin/secret-tool`). Platforms without an active OS keyring fail closed rather than falling back to plaintext.
   - Pre-registered OAuth client secrets and optional bearer tokens are referenced only by environment variable name (`AGENT_BRIDGE_EXTENSION_*`) and read strictly at request time.

4. **Handle-Pinned I/O & Single-Use Observations:**
   - Workspace file operations use capability-based directory handles (`cap-std`) and reject symlinks, junctions, reparse points, and hard links.
   - Destructive or mutating file, browser, and scoped UI calls require a fresh, single-use observation token (`observation_id`, `browser_observation_id`, `computer_observation_id`) and re-verify target identity before acting.

5. **Live Mode Revocation:**
   A mode change takes the profile write lock, revokes any process authority that the new mode removes, then publishes that mode. Any downgrade also closes idle pooled extension sessions before publishing the lower mode. Handlers synchronize admission with the same lock; output waits release it. Failure to confirm cleanup leaves the old mode visible and reports an error. The startup catalog and OAuth scope marker remain unchanged, so an active mode switch preserves existing clients. The direct process provider exists only for workstation startup fully-unlocked plus `--enable-processes`; other entry points preserve their existing provider.

---

## 3. Native Platform Boundaries

### Unified native workstation ownership

The desktop executable starts the shared workstation runtime in process and owns its lifecycle. Native operator commands use a bounded, typed facade over the same live profile and database. No operator HTTP listener is created in this mode and no operator route is added to the MCP/OAuth router.

A runtime generation controls admission and shutdown. Stop closes admission, drains admitted operations and retains ownership until cleanup is confirmed; an interrupted wait can resume without losing its owner. The desktop serializes lifecycle changes. The optional pinned tunnel companion belongs to the same application generation and receives its credential only in its private child environment.

Private self-executable helper protocols run before Tauri or single-instance setup. A second foreground launch shows the existing interface; a background launch preserves its visibility. Closing the window hides it, while explicit Quit awaits the managed stack's shutdown. See [native mode and migration](UNIFIED-DESKTOP.md).

### Attached Workstation control

The native panel authenticates to the Workstation's IPv4 loopback operator API. Its Rust backend reads a bounded ready record from an explicitly configured private log and keeps the per-process token out of the frontend and panel preferences. The Workstation retains the project, database and OAuth state ownership.

**Stop** signals cooperative shutdown through that API and waits for the service ports to close. **Start** and **Restart** use an existing validated Windows scheduled task with the current user, least privilege, on-demand starts and duplicate-instance suppression. Restart waits for the old session to drain before running the task and confirming a new authenticated session. An inaccessible task disables Start and Restart while authenticated Stop stays eligible. See [attached lifecycle](WORKSTATION-MODES.md#control-an-attached-workstation).

### Scoped window and browser tools

The platform facade keeps the existing Windows backend separate from macOS Accessibility and Linux X11. Unix adapters attach only after exact local foreground selection and consent. Observation tokens remain opaque, bounded and single-use. They never turn an MCP-supplied PID, window ID or script into authority. Supported actions and screenshots are backend-specific, as described in [UNIX-PARITY.md](UNIX-PARITY.md).

Unix Chrome starts with `posix_spawn`, private process-group ownership and CDP descriptors 3/4. Descriptor remapping is collision-safe and unrelated descriptors are closed. Required spawn extensions are resolved before launch; absence is a browser capability refusal rather than a CLI-wide runtime failure. Chrome profiles are private, handle-relative directories with identity checks during bounded cleanup.

The Unix fixed project diagnostic receives a clone of the actual workspace directory handle over a private Unix socket using `SCM_RIGHTS`. The child validates the descriptor's type, read-only access, device/inode identity and close-on-exec state. The path remains an identity witness, not a replacement authority. This does not introduce arbitrary program execution into the restricted provider.

### Contained outbound `stdio` MCP extensions

Locally approved `stdio` MCP extension servers run one contained child per session under an operator-pinned native executable SHA-256, exact argument vector, and `AGENT_BRIDGE_EXTENSION_*` environment variable references (never literal secrets in `extensions.json` or `.extensions-admin.json`, and never queued from Web MCP). Windows launches children through `OwnedChild` with a restricted handle inheritance list, `CREATE_NO_WINDOW`, a `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` Job object, authenticated pipes, and an exact environment block built from an OS safe set plus resolved extension references. Unix launches children in a dedicated process group (`process_group(0)`) with non-blocking pipes, `waitid(..., WNOWAIT)` leader retention before group `SIGKILL`, and the same non-inherited safe environment policy. The per-server `inherit_path` opt-in appends the bridge's `PATH` after the fixed directories. Approve pending additions from one import together with `extensions approve <dir> <id> <id>...`.

The active profile gates extension tool calls. Calls reuse an idle session of the same exact server (name and configuration fingerprint) and close it after 120 seconds without a call. The pool also closes on a profile downgrade, or when the call handler detects unavailable configuration or a changed OAuth authority. Operator probes open their own session.

---

## 4. SQLite Schema v7

The embedded SQL migrations live under `contracts/sqlite/`:

- `001_initial.sql` - `missions`, `events`, `schema_migrations`
- `002_execution.sql` - `resource_leases`, execution tracking
- `003_collaboration.sql` - `mission_memberships`, shared `subtasks`
- `004_scheduler.sql` - scheduling metadata
- `005_legacy_import.sql` - `imports`, `legacy_import_steps`
- `006_legacy_events.sql` - `legacy_import_events`
- `007_legacy_mission_owners.sql` - owner membership invariants

`agent-bridge-core` verifies all 7 migration SHA-256 checksums before opening an existing database and refuses to inspect a database with live uncheckpointed WAL sidecars.

---

## 5. Packaging & Deterministic Releases

Release tooling lives under `scripts/`:

- `scripts/rust/source-release.py` builds a deterministic source ZIP from the exact Git index. The allowlist includes both Cargo workspaces and the two desktop documentation images.
- `scripts/rust/release-notices.py` inventories locked target-specific third-party crate metadata and notice files in `notices/index.json`. Review its findings even when it exits successfully.
- `scripts/rust/package-rust.py` checks the notice review and incorporates the operator-supplied standard-library notice for the exact compiler. It performs an isolated locked CLI build and assembles the binary archive with attribution and recorded file hashes.
- `scripts/rust/package-desktop.py` builds the separate desktop ZIP. Both binary packagers accept `--release-channel` and scan for private paths, including compressed archive members and embedded payloads. The desktop packager scans the Tauri frontend sources and refuses `TAURI_CONFIG`; `app/src-tauri/build.rs` also refuses it when `AGENT_BRIDGE_RELEASE_CHANNEL` is set.
- `scripts/rust/repository_hygiene.py --repo .` checks tracked files and product version consistency. `scripts/rust/test_build_winapp_passive.py` verifies the pinned WinApp input hashes and sizes.
- `scripts/windows/sign-release.ps1` generates `SHA256SUMS` for explicitly listed archives and a detached Windows CNG signature, `SHA256SUMS.sig`. Verify the signature with `licenses/agent-bridge-release-public.pem`.

The independent desktop workspace needs its own notice inventory and distribution qualification. See [archive privacy and provenance](PUBLIC-RELEASE-SCOPE.md#archive-privacy-and-provenance), the [release checks](RELEASE-v2.1.0.md#reproduce-the-gates), and the [release notice review](RELEASE-NOTICES.md).
