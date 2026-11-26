# MCP modernization (Agent Bridge 2.1)

Tracking: #125 (epic), #126 (gateway), #127 (extension client), #128 (cache/search), #129 (skills), #130 (Tasks/MRTR), #131 (files), #132 (Apps), #133 (qualification).

## Isolation and scope

Branch feat/mcp-2026-07-28, initial baseline 66e2b9646d8c4d40909fb3e0193e2252c7a553ac (local origin/main). Do not merge active parity branches or deploy/restart the running workstation. Reconcile with #91, #93, #95, #100, #112, #115 and #120–#123 after independent qualification. No GitHub CI runs requested.

The initial experiment used the existing gateway with no new dependencies, behind a disabled modern-preview feature. The fourth slice below replaces that feature with dual-era routing in the production gateway and transports; rollout to a running workstation still waits for the owner and #115. Compare the official rmcp 3.x implementation before choosing a production strategy; measure isolated builds, RSS, latency and handler compatibility. Keep one engine and the existing operator/OAuth/security boundaries.

## Initial prototype (#126)

- Explicit per-request params._meta with protocolVersion and clientCapabilities required; clientInfo optional and untrusted.
- Discovery with supportedVersions and identity in result._meta; resultType complete.
- Direct reuse of existing catalog and dispatch in synthetic tests; invalid metadata and unsupported continuation fail before any dispatch.
- No cache TTL, MRTR, Tasks, subscriptions, resources, transport claims or capability additions in the live catalog.
- Existing initialize path and supported version list remain unchanged.

## Integration gates

1. Compare official SDK vs adapter: feature-level dependency and license inventory, locked builds and measured runtime footprint; choose only after evidence.
2. Dual-era HTTP and stdio routing: validate version and routing headers (including encoded names and duplicate headers), error status mapping, no modern-to-legacy implicit dispatch, no replay of uncertain mutations. Review protocol error envelope, request cancellation, subscription semantics, schema dialect and validation. Preserve OAuth gates before any handler. Qualify modern and legacy with official conformance.
3. Outbound client discovery and version fallback on safe probe only; carry per-request metadata. Retain pinned transport/security from #100.
4. Catalog cache isolation and capabilities, Skills, Tasks/MRTR, then optional file/App extensions. Do not claim unsupported capabilities. Use separate tickets.
5. Cross-client and three-OS integration after parity; no production rollout without owner approval. Use local targeted tests first and avoid redundant full builds.

References:
- https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning
- https://modelcontextprotocol.io/specification/2026-07-28/basic/index
- https://modelcontextprotocol.io/specification/2026-07-28/server/discover
- https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
- https://github.com/modelcontextprotocol/rust-sdk
- https://github.com/modelcontextprotocol/conformance

## Initial validation status

The targeted Cargo test was attempted with the existing portable Cargo 1.99.1, but stopped before compilation: rustc -vV could not execute (program not found, exit 101). Six new fixture tests are written, not executed. No toolchain was installed or changed. The initial commit is an unqualified local prototype; run the locked targeted tests before any integration.

## Dual-era transport qualification (second local slice)

The existing Windows build wrapper was located and reused without installation or global environment changes. Cargo and rustc are 1.99.1. Tests run in the dedicated worktree target/mcp-preview with two build jobs. The shared wrapper configures MSVC and the existing registry cache; the target is explicitly overridden. The old toolchain does not include rustfmt.

The opt-in transport prototype uses the existing bounded stdio framing and Axum loopback server. The stdio fixture locks its wire era after successful discovery or initialization; the HTTP fixture accepts both eras on the same temporary endpoint. Modern version, method, and name headers must match the body; duplicate headers, invalid Base64 sentinel encodings, ambiguous JSON keys, and unsupported MRTR continuations are rejected before dispatch. The preview supports only the synthetic catalog with no x-mcp-header annotations; annotated schemas and parameter routing remain unqualified. No production entry point opts into this feature. Existing authentication and operator admission are separate and not inferred from metadata.

Validation command (run from the dedicated worktree):

    cargo-local.cmd test --locked --offline -p agent-bridge-gateway -p agent-bridge-http --features agent-bridge-gateway/modern-preview,agent-bridge-http/modern-preview --target-dir target/mcp-preview

Result: 18/18 passed, zero failed/ignored (10 modern gateway, 5 header validation, 1 real loopback dual-era fixture, 2 legacy regression tests). The loopback fixture uses an OS-assigned port and a synthetic counting handler, verifies two admitted calls and no dispatch for header mismatches or duplicate JSON, then shuts down. This is not official conformance or client qualification. Production wiring, strict schema validation, notification/cancellation behavior, x-mcp-header support, and OAuth integration remain open.

### SDK comparison (initial evidence)

The official Rust SDK release rmcp 3.11.0 supports modern discovery, the legacy lifecycle, stateless Streamable HTTP, stdio, header validation, MRTR, caching, subscriptions, and feature-gated Skills/Tasks. It does not implement the removed two-endpoint 2024-11-05 HTTP+SSE binding. Agent Bridge has a small serde/serde_json gateway and an Axum transport; this preview adds only an already locked Base64 version plus an optional workspace gateway dependency. Evaluate the SDK as a protocol adapter rather than a replacement for authorization, catalog, leases, process supervision, and SQLite missions. Pin the SDK version in an isolated experiment and compare equivalent traces, process footprint and latency before selecting the production strategy. No SDK runtime measurement is claimed here.

Sources: https://docs.rs/crate/rmcp/3.11.0 ; https://github.com/modelcontextprotocol/rust-sdk ; https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http ; https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio.

## English-only deliverables

All new project code, comments, docs, descriptions, issues, commits, and pull requests must be in English. This rule also applies to ongoing updates to issues #125–#133.

## Outbound adapter and conservative cache contract (third local slice)

The extension crate now contains a test-only opt-in client for literal IPv4 loopback fixtures. Discovery selects the modern era on a confirmed modern result; explicit legacy-like discovery failures may select the existing legacy transport. Authentication challenges, recognized modern protocol errors, rate limits, redirects, server failures, mismatched responses and ambiguous tool failures never cause a tool call to be replayed or downgraded. Requests carry version/client metadata and routing headers; response size and timeouts are bounded. No registry, remote endpoint, credential store or production extension call path selects this adapter. The existing #100 transport and OAuth work must be reconciled before generalization.

Modern discovery and tool listing now emit the required ttlMs=0 and cacheScope=private, and tool listings are sorted by name. Unissued cursors are rejected. Legacy responses remain unchanged. These are conservative wire hints, not a cache implementation. Positive TTL and progressive discovery require authenticated partition keys, revision invalidation, capability-aware clients and real provider token measurements (#128).

Combined local validation: 30 passed, 0 failed, 0 ignored (22 modern fixture tests and 8 existing regression tests across gateway, HTTP and extensions). The first catalog-order test failed because its synthetic tools were missing registered handlers; the fixture was corrected without weakening catalog authorization. An earlier outbound fixture failure was corrected by switching accepted Windows sockets to blocking mode; the final rerun passed. No external services or live agent tools were used. The Windows toolchain wrapper continues to emit preexisting AutoRun/PATH warnings but exits successfully. The build does not contain rustfmt.

Command:

    cargo-local.cmd test --locked --offline -p agent-bridge-gateway -p agent-bridge-http -p agent-bridge-extensions --features agent-bridge-gateway/modern-preview,agent-bridge-http/modern-preview,agent-bridge-extensions/modern-preview --target-dir target/mcp-preview

Reference: https://py.sdk.modelcontextprotocol.io/client/caching/

## Dual-era production routing (fourth slice)

Branch feat/mcp-2026-07-28-integration merges the prototype onto current main and removes the gateway and HTTP modern-preview features. The extensions crate keeps its test-only feature for the outbound client (#127).

- `McpGateway::handle_str` classifies each frame. A `server/discover` method or any reserved `io.modelcontextprotocol/*` key in `params._meta` selects stateless 2026-07-28 handling; everything else, including `initialize`, keeps the unchanged legacy path (2025-06-18, 2025-03-26, 2024-11-05). Modern frames are parsed with duplicate-key refusal.
- Stdio locks its era on the first successful discovery-era request or `initialize`; mixed frames are refused with -32602.
- HTTP (`agent-bridge-http` and the OAuth workstation route) runs `modern::preflight` after authorization and before dispatch. Modern requests need matching `MCP-Protocol-Version` and `Mcp-Method` headers, plus `Mcp-Name` for `tools/call`, `prompts/get` and `resources/read`. Mismatches return HTTP 400 with -32020, a missing body version returns -32602, an unsupported version returns -32022 with `supported` and `requested`, and unknown or removed methods return HTTP 404 with -32601. Legacy requests keep HTTP 200 and their existing envelopes.
- No tool declares `x-mcp-header`; the annotation is stripped from modern listings and every `Mcp-Param-*` header is refused. Discovery advertises only `tools`. Lists stay at `ttlMs=0` and `cacheScope=private`.
- OAuth stays ahead of era selection: a modern request without a valid bearer is refused with 401, and each grant still sees only its sealed catalogue.

Local validation on Windows x64 (debug build, isolated SQLite fixture on 127.0.0.1):

- Gateway modern tests 14/14, HTTP crate 10/10 (8 unit, 2 integration including the live loopback dual-era test), OAuth route tests 9/9 including the new modern route test.
- Pinned-bundle catalogue tests (`integration_real_catalogue_46_*`, both filesystem scopes): a 2026-07-28 `tools/list` returns the same 46 schemas as the legacy list, ordered by name. Workspace suite: 297 passed, 0 failed, 35 ignored.
- Official runner `@modelcontextprotocol/conformance` 0.2.0-alpha.12, `--spec-version 2026-07-28`, scenarios server-stateless, caching, http-header-validation, tools-list and dns-rebinding-protection: 45 checks passed, 6 skipped (subscriptions), 7 not applicable. Four of those need the runner's diagnostic tools (`test_missing_capability`, `test_streaming_elicitation`, `test_logging_tool`), which a production catalogue does not publish. Three are caching checks for `prompts/list`, `resources/list` and `resources/templates/list`, which the server does not advertise and correctly answers with -32601.
- The same runner with `--spec-version 2025-06-18` (server-initialize, ping, tools-list, server-session-lifecycle): 6 passed, 2 informational.
- The first stateless run found that `resources/subscribe` and `resources/unsubscribe` were refused as header mismatches. `Mcp-Name` is now required only for the three core methods above, so removed methods reach the router and return 404 with -32601; a regression test covers it.

Still open before closing #126 and #133: real-client qualification, resource and token measurements on the 46-tool catalogue, independent review, and rollout after #115.

## Outbound extension client (fifth slice, #127)

The test-only outbound preview is removed. The production extension transport (`rust/extensions/src/transport.rs`) now opens every session with one `server/discover` probe that carries 2026-07-28 metadata, `MCP-Protocol-Version` and `Mcp-Method`, plus the configured bearer and header credentials from #100.

- A completed discovery result that lists 2026-07-28 and a `tools` capability selects the modern era. Later requests carry per-request metadata, `Mcp-Method` and, for `tools/call`, `Mcp-Name`; only `resultType: complete` results are used. There is no session and no DELETE.
- A 4xx without a modern error body, or a JSON-RPC error that is not -32020, -32021 or -32022, selects the unchanged `initialize` handshake. This matches the spec's HTTP backward-compatibility rule. The public Microsoft Learn server answers the probe with HTTP 200, an SSE event and -32601, so it stays on 2025-06-18.
- Modern errors, 401, 403, 407, 429, redirects, 5xx, timeouts and mismatched ids stop the session; none of them trigger a fallback. The probe is read-only, and an uncertain `tools/call` is still never replayed in either era.
- Caller metadata and MRTR continuations are refused. A tool whose descriptor declares `x-mcp-header` is refused before the call, because this client does not send `Mcp-Param-*` headers. Descriptor pins and operator approvals are unchanged.

Validation: extensions crate 19/19 (five new loopback and unit tests for the modern probe, both fallback shapes, refusals and no replay). Pinned-bundle `integration_every_46_tool_has_an_observed_real_effect_*` 2/2, including one real Microsoft Learn search that went through the probe and the legacy fallback.

## 2026-07-28 only (sixth slice)

The owner chose to serve only 2026-07-28. Clients that still use the `initialize` handshake lose access to this server until they migrate. The tenth slice below restores the legacy handshake and supersedes this section. The outbound extension client keeps its legacy fallback, because qualified extensions such as Microsoft Learn do not yet answer `server/discover`.

- `McpGateway::handle_str` parses every frame with duplicate-key refusal and serves it under 2026-07-28. A legacy `initialize` (no `params._meta`) returns -32022 with `{"supported":["2026-07-28"],"requested":<its protocolVersion>}`, as the spec recommends for a modern-only server. A modern-shaped `initialize` and `ping` return -32601 like any removed method. Any other frame without valid metadata returns -32602 before dispatch.
- The legacy version list, version negotiation, `InitializeResult`, the stdio era lock (`StdioEra`) and per-frame era classification are removed. Stdio now calls `handle_str` directly. `handle_value` remains an in-process `tools/list` and `tools/call` dispatcher for internal providers; it is not a wire entry point and serves no handshake.
- HTTP `modern::preflight` validates every request after authorization: invalid or ambiguous JSON returns 400 with -32700, a legacy `initialize` returns 400 with -32022, and missing or disagreeing routing headers return 400 with -32020 (or -32602 when only the body version is missing). Response status mapping (400 for protocol errors, 404 for -32601) now applies to every response, including -32602 for an unavailable tool.
- OAuth still runs first: a legacy `initialize` without a bearer gets 401, not the version refusal.
- Test fixtures and helpers that used `initialize` and legacy frames now use `server/discover` and per-request metadata with routing headers. No safety assertion was removed; the dual-era assertions were replaced by refusal assertions.

Local validation on Windows x64 (debug build, isolated SQLite fixture on 127.0.0.1):

- Workspace suite: 302 passed, 0 failed, 35 ignored. Pinned-bundle `integration_real_catalogue_46_*` and `integration_every_46_tool_has_an_observed_real_effect_*`: 4/4, including a real Microsoft Learn search through the outbound legacy fallback.
- Official runner 0.2.0-alpha.12, `--spec-version 2026-07-28` (same five scenarios): 45 passed, 6 skipped, 7 not applicable, unchanged from the fourth slice.
- The same runner with `--spec-version 2025-06-18` (server-initialize, ping, tools-list): the legacy handshake is refused with HTTP 400 and -32022 naming 2026-07-28, as intended.

Rollout to the running workstation still waits for #115 with the owner. Before that, confirm which connected clients (ChatGPT, Claude, Gemini) already send 2026-07-28; any that do not will be refused.

## Catalog cache hints and progressive discovery (#128)

Each router serves one authorization view: the OAuth route picks the router from the grant, and a router's catalog and handlers are fixed for its lifetime. Its 2026-07-28 listing is therefore built once, when the router is constructed.

- `GatewayConfig::with_catalog_ttl_ms` sets `ttlMs` for `server/discover` and `tools/list`; the gateway default stays `0`. Production routers (stdio, the workstation and unified OAuth routes, the project-read route) use `CATALOG_TTL_MS = 300000` (five minutes).
- `cacheScope` stays `private`. The catalog depends on the access token, so the spec forbids sharing a cached listing across authorization contexts. Changing the desktop profile does not change the listed catalog; the live profile tests already assert this.
- Discovery and listing results carry `_meta["io.github.ironlegends/catalogRevision"]`, the SHA-256 of the listed catalog. It changes whenever a tool name, description or schema changes. Tool results carry no cache hints.
- Invalidation: the catalog changes only when the process restarts. A sealed unified grant is refused when its catalogue digest no longer matches, and authorization is checked on every call. A stale cached listing can therefore show a retired tool for at most the TTL, but can never authorize a call. Revoking a token takes effect on the next request, whatever the client has cached.
- Pagination is not added. Progressive tool discovery and Tool Search are host features in 2026-07-28: the host fetches `tools/list` once and defers definitions behind its own search tool. Paging the server's list would add round trips without reducing the model's context. Unissued cursors are still refused.

Measurements on the real 46-tool unified catalog (Windows x64, from the pinned-bundle `integration_real_catalogue_46_*` run):

- One `tools/list` result is 34,176 bytes of compact JSON: 24,770 bytes of input schemas and 5,885 characters of descriptions. Every tool has a description. The largest entry is `desktop_browser_act` (3,215 bytes); the median is 567 bytes.
- About 8,500 tokens, estimated as bytes divided by four. No provider tokenizer was run, so this is not a measured token count (#120).
- Building the listing takes about 0.5 ms once per router. In a release build, answering `tools/list` takes 0.29 ms, compared with 0.81 ms when the listing is serialized and sorted on every call (2,000 iterations, in process, transport excluded).
- With the five-minute TTL, a compliant client re-fetches the catalog at most once per five minutes per token, instead of before each use.

Validation: workspace 303 passed, 0 failed, 35 ignored, including a new gateway test that covers the configured TTL, the private scope, the revision and the absence of hints on tool results. Pinned-bundle `integration_real_catalogue_46_*` 2/2 now also assert the production TTL and scope.

## Modern-only outbound client and Microsoft Learn removal (seventh slice, #127)

The owner extended "2026-07-28 only" to the outbound extension client and removed Microsoft Learn, whose public MCP server still requires `initialize`. This supersedes the legacy fallback described in the fifth and sixth slices.

- The outbound client is the official Rust SDK, rmcp `=3.11.0` (Apache-2.0), with only the `client` and reqwest Streamable HTTP client features. Agent Bridge keeps its own guards around it: endpoint and credential validation, sensitive header resolution, catalog bounds, descriptor pinning and approvals.
- `transport::Session::open` serves the SDK client in `ClientLifecycleMode::Discover` with 2026-07-28 as the only preferred version, so it sends one `server/discover` and has no `initialize` fallback. The session then requires that the server negotiated 2026-07-28 and declares a `tools` capability. Any other status, a JSON-RPC error (including the -32601 of a legacy server), a missing required discovery field or an unserved version is refused. The client never sends `initialize`, `notifications/initialized`, `Mcp-Session-Id` or a closing DELETE.
- The SDK adds 2026-07-28 metadata, `MCP-Protocol-Version`, `Mcp-Method` and, where routed, `Mcp-Name` to every request. The transport runs with one concurrent request, `NeverRetry` for SSE, `reinit_on_expired_session(false)`, 1 MiB JSON and SSE event limits, and a 12-second deadline around each discovery, listing and call. The reqwest client keeps no redirects, no retries, no proxy and a 4-second connect timeout.
- A tool call uses `call_tool_once`, never the SDK `call_tool` loop. Only a completed result is accepted. An `input_required` result or a task is refused without answering, polling or resending. `x-mcp-header` descriptors stay refused. An uncertain `tools/call` is still never replayed.
- TLS for the SDK client, the archive fetcher and outbound OAuth is an explicit rustls configuration with the ring provider and the bundled webpki roots, as with reqwest 0.12. The operating system certificate store is not trusted, and aws-lc is not built. reqwest 0.13 still compiles its platform verifier, but no client uses it.
- Descriptor hashes are computed on the SDK's serialized `Tool`. The live `search_model_context_protocol` descriptor keeps the same hash through that round trip.
- The single verified adapter is now the public, tokenless MCP documentation server: endpoint `https://modelcontextprotocol.io/mcp`, operation `search_model_context_protocol`, server name `mcp_docs`. It answers `server/discover` with 2026-07-28. The grant still allows exactly one `query` of type `search_terms`; the optional `version` filter, `query_docs_filesystem_model_context_protocol` and `submit_feedback` are not authorized. Credentials for that host are refused under every spelling, as before.
- `extensions refresh-check <private-directory> mcp_docs` and the `refresh` proposal replace the Learn-only probe. The refresh report no longer has `remote_session_close`; it states `protocol_version`.
- The browser Learn reader is removed: `--local-learn-url`, the `learn` provider, its example and `--local-chrome-origin`. Native Chrome reaches only the operator's selected project files. The sealed Web workstation authority keeps `public_learn_home_url: null` and `native_chrome_origins: []`, so existing version 2 seals still compare equal. Both options were later [restored as deprecated for 2.x](#browser-learn-reader-restored-for-2x-compatibility).

Operators who still have a `microsoft_learn` entry in `extensions.json` will see its calls refused at discovery. Replace it with an `mcp_docs` entry that pins the reviewed `search_model_context_protocol` descriptor.

## Legacy outbound compatibility and Microsoft Learn (eighth slice, #127)

The owner allowed the legacy protocol again for outbound connections, for compatibility. This supersedes the modern-only outbound rule of the seventh slice. The tenth slice restores the legacy handshake for inbound clients too.

- `transport::Session::open` now runs the SDK client in `ClientLifecycleMode::Auto`. It sends one `server/discover` for 2026-07-28 first. Only a server the SDK classifies as legacy gets one `initialize` with `2025-11-25` (`LATEST_WITH_INITIALIZE`), then `notifications/initialized`. The SDK treats as legacy a correlated JSON-RPC error that is not a modern rejection (for example -32601), including one carried by a non-success status such as a 500 or 307 with a JSON-RPC error body, and any other 4xx without a session except 401, 403 and 429 (for example an empty 400 or 404). Redirects are never followed, so the fallback `initialize` goes to the same endpoint, and both requests are read-only. Over HTTP a discovery that never answers is refused at the 12-second request deadline without a fallback: the single-request worker is still waiting when the SDK's 10-second probe timer ends.
- Refusals stay closed: 401, 403, 429, a 5xx or redirect without a JSON-RPC error body, -32022 with no common version, a discovery result naming no served version, a missing `tools` capability, and a failed legacy handshake. The negotiated version must be one the SDK knows. Opening a session is bounded by 24 seconds (the 10-second probe and one 12-second handshake); each listing and call keeps its 12-second deadline.
- In a legacy session the SDK carries `Mcp-Session-Id` on every request, and the session ends with a DELETE when the client closes, bounded to 3 seconds. The session runtime shuts down in the background, so a pending system DNS lookup cannot extend the close. The session is never re-initialized after expiry. Tool calls keep `call_tool_once`, completed results only and no replay.
- The `microsoft_learn` adapter is restored next to `mcp_docs`: endpoint `https://learn.microsoft.com/api/mcp`, operation `microsoft_docs_search`, one `query` of type `search_terms`. `microsoft_docs_fetch`, code-sample search and every other tool stay unauthorized. Credentials for `learn.microsoft.com` are refused under every spelling, as for `modelcontextprotocol.io`.
- `extensions refresh-check <private-directory> <mcp_docs|microsoft_learn>` and the `refresh` proposal accept both public documentation servers. The report states the negotiated `protocol_version`. Learn answered the `2025-11-25` initialize with `2025-06-18` in the live check.
- The browser Learn reader (`--local-learn-url`) stayed removed in this slice. See the later [2.x compatibility restoration](#browser-learn-reader-restored-for-2x-compatibility).

Existing `mcp_docs` entries keep working unchanged. A `microsoft_learn` entry that pins the reviewed `microsoft_docs_search` descriptor works again.

## Outbound stdio extensions and mcp.json import (ninth slice, #127)

Operators can now register locally approved outbound `stdio` MCP extension servers and import pending extension proposals from a local `mcp.json` file without exposing secret values or weakening process containment.

### Registry schema and default-deny controls

- Each entry in `extensions.json` chooses either `endpoint` (Streamable HTTP) or `stdio` (`StdioSpec` with `deny_unknown_fields`), never both. HTTP serialization, `server_sha256`, `ServerControl` pins, and workstation OAuth authority seals remain byte-identical.
- `StdioSpec` fields: normalized absolute `executable` (at most 1024 bytes, no `.` or `..` components, no UNC or `\\?\` prefix, no NUL; Windows requires `.exe` and refuses `.cmd`, `.bat`, and `.ps1`), lowercase 64-hex `executable_sha256`, optional `args` (at most 64 arguments, 4096 bytes each, 16 KiB total, never passed through a shell), optional `env` (at most 32 mappings from validated child variable names to `AGENT_BRIDGE_EXTENSION_*` source variable names, never literal values), and optional `cwd` (same path rules, defaulting to the executable's parent directory).
- `stdio` entries forbid `bearer_env`, `header_env`, and the reserved `PUBLIC_DOCS` server names. A `stdio` server in `extensions.json` is refused unless nonce-bound (`bridge_grant_nonce`) to an approved `AddedStdio` entry in `.extensions-admin.json`, and `with_controls` defaults any `stdio` server without an enabled hash-matching `ServerControl` to disabled.
- The pinned executable hash replaces only the `PUBLIC_DOCS` host allowlist for `stdio` servers. Individual tool approvals still enforce 64-hex descriptor SHA-256 pins, cached descriptor verification, `x-mcp-header` refusal, and `check_schema` data-parameter gates. Since the twelfth slice, the `data_tool` naming rule applies per call to the read-only profile only.

### Three fail-closed executable verification points

1. **Import (`observe_executable`):** Pins the file handle without following symlinks or reparse points on any ancestor, verifies a regular native executable image within the 512 MiB cap (Windows `MZ`/`PE` with CUI subsystem `3`; Unix `ELF` or `Mach-O` regular file owned by `0` or `euid`, executable bit set, not group or world writable, opened with `O_NOFOLLOW | O_NONBLOCK` so a FIFO cannot block; every Unix ancestor directory owned by `0` or `euid` and not world writable unless sticky; `#!` scripts refused), and records its lowercase SHA-256 in the pending `add_stdio` proposal.
2. **Operator decision (`verify_executable`):** Approving `add_stdio` and every `enable` decision on a `stdio` server re-verifies the native executable and its pinned SHA-256 before writing controls, failing closed with `executable_unavailable` or `executable_changed` and never spawning the binary.
3. **Every session spawn (`Session::open_stdio`):** Opens `PinnedExecutable`, hashes through the held handle, compares against `executable_sha256`, launches the contained child, runs `pin.verify_unchanged()` (the named path must still designate the same file: device and inode on Unix, volume serial number and file index on Windows), and only then releases the handle pin. The working directory passes the same ancestor checks.

### SDK transport rationale and session bounds

- Outbound `stdio` uses only the `rmcp` `transport-async-rw` feature (`AsyncRwTransport::new_client(r, w).with_max_line_length(1 MiB)`) with `ClientLifecycleMode::Auto` (`server/discover` for `2026-07-28` first, falling back to one `initialize` handshake for legacy servers) and `call_tool_once` with no replay on ambiguous failures.
- `rmcp` `transport-child-process` is intentionally not enabled: it would pull `process-wrap` outside `Cargo.lock`, rely on `tokio::spawn` cleanup that can be lost on `current_thread` runtimes, and inherit `stderr`.
- Bounds: 512 MiB executable hash cap; 24 s session open deadline; 12 s `tools/list` and `tools/call` deadline; 1 MiB maximum JSON-RPC line length; at most 4 concurrent live `stdio` sessions per process (a fifth is refused immediately without queueing, after an idle pooled session has yielded its slot); one child process per session; bounded drop sequence (`close_with_timeout(3 s)`, up to 2 s exit poll, `terminate()`, up to 2 s reap poll). Child `stderr` is drained into a 4 KiB tail and byte counter that never enters tool results or the journal; only local `extensions refresh-check` reports `stderr_bytes`.

### Process containment and exact child environment

- **Windows:** Reuses `OwnedChild` with an explicit handle inheritance list, a dedicated Job object configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, `CREATE_NO_WINDOW`, authenticated pipes, an exact environment block (`spawn_with_environment`), and `CreateProcessW` under the current non-elevated token.
- **Unix:** Spawns in a dedicated process group (`process_group(0)`, no `pre_exec`), sets non-blocking pipes, retains the group leader via `waitid(..., WNOWAIT)` so PID/PGID reuse cannot misdirect `kill(-pgid, SIGKILL)`, and reaps within bounded deadlines.
- **Exact environment:** Starts empty rather than inheriting the bridge environment. Copies only present OS safe-set variables (`SystemRoot`, `SystemDrive`, `windir`, `TEMP`, `TMP`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `ProgramData`, `NUMBER_OF_PROCESSORS`, `PROCESSOR_ARCHITECTURE`, `OS` on Windows; `HOME`, `USER`, `LOGNAME`, `TMPDIR`, `LANG`, `LC_ALL` on Unix) plus a fixed `PATH` (executable directory plus `%SystemRoot%\System32` and `%SystemRoot%` on Windows, or `/usr/bin` and `/bin` on Unix). A server approved with `inherit_path` gets the bridge's own `PATH` appended after these directories, so system directories still resolve first; a missing, empty, NUL-bearing or over-32-KiB bridge `PATH` refuses the launch. Denylists loader and runtime injection variables (`PATH`, `PATHEXT`, `COMSPEC`, `LD_*`, `DYLD_*`, `NODE_OPTIONS`, `NODE_PATH`, `PYTHONPATH`, `PYTHONHOME`, `PYTHONSTARTUP`, `PERL5OPT`, `PERL5LIB`, `RUBYOPT`, `RUBYLIB`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`, `CLASSPATH`, `BASH_ENV`, `ENV`, `ELECTRON_RUN_AS_NODE`, `GLIBC_TUNABLES`, `DOTNET_*`, `COR_*`, `CORECLR_*`, and the safe-set names). On Windows a missing or non-absolute `SystemRoot` refuses the launch. Configured `AGENT_BRIDGE_EXTENSION_*` references must resolve at launch to non-empty NUL-free values (at most 8192 bytes each, 64 KiB total); failures never echo variable names or values.

### `mcp.json` import rules and operator workflow

- `agent-bridge extensions import <private-directory> <mcp-json-path> [--inherit-path <stdio-server>]...` reads a regular file up to 256 KiB, rejects duplicate JSON keys at every depth, and accepts only top-level `mcpServers`. It performs no process spawn, no network I/O, and no direct edit to `extensions.json`.
- `command` entries must use an absolute path (`command_not_absolute` otherwise; never `PATH` lookup). On Windows a `command` or `cwd` written with forward slashes, as Claude Code writes them, is stored with backslashes and pass `observe_executable` to queue a pending `add_stdio` proposal (`Origin::LocalCli` only; Web `desktop_mcp_manage` refuses `add_stdio`). `env` values are never copied: each variable maps to `AGENT_BRIDGE_EXTENSION_<SERVER>_<VAR>` (uppercased, sanitized, at most 128 chars), reporting `literal_value_dropped`, `operator_must_export` (variable names only), and `${VAR}` / `${env:VAR}` source hints. Each `--inherit-path` names a stdio entry of the file whose proposal carries `inherit_path: true`, which the operator sees before approving; a name that is absent or not a stdio entry refuses the whole import before anything is queued.
- `args` with `--name=value` secret flags, non-path values following `--token` or `--api-key` style flags, known token prefixes (GitHub, GitLab, OpenAI-style, Slack, AWS and Google API keys, and JWTs), high-entropy tokens of 32+ characters, or `${...}` placeholders are refused with `literal_secret_in_args` or `variable_interpolation_in_args`. Entries using `type: "sse"`, both `command` and `url`, `${input:...}`, denylisted child `env` names, or invalid server names are refused. Reports never echo URLs, arguments, or secret values, and the command exits non-zero when zero proposals are queued.
- `url` (`http` or `streamable-http`) entries queue normal `add` proposals with `header_env` references validated by `validate_header_env`. `disabled: true` entries are skipped, and `autoApprove` / `alwaysAllow` are ignored with a note (`auto_approve_ignored_no_tool_grants_imported`).
- **Workflow:** Run `extensions import`, export the listed `AGENT_BRIDGE_EXTENSION_*` secrets in the bridge host environment, approve the listed `approve_together` ids in one `extensions approve <private-directory> <request-id> <request-id>...` decision (or one server at a time via `extensions approve` or the local loopback UI, re-running `extensions import` to queue the remaining servers at the new journal revision; deterministic request IDs; identical already-approved servers are skipped). Use `extensions refresh-check <private-directory> <server>` for local read-only catalog inspection, bind reviewed tool grants with `bridge_grant_nonce` in `extensions.json`, and approve `enable`. `set_oauth`, `auth_start`, and Web `refresh` proposals on `stdio` servers return `unsupported` (`stdio_transport_unsupported_operation`).

### Known limits

- **Interpreter-only pin:** Approving a native interpreter binary (such as `node.exe` or `python.exe`) with a script path in `args` pins only the interpreter executable's SHA-256, not the script or modules it loads.
- **Unix check-to-exec gap:** Portable POSIX spawn/`execve` executes by path rather than file descriptor, leaving a narrow window between handle verification and `execve`; post-launch `lstat` re-checks identity before MCP exchange.
- **Same-user launch race (Windows):** A process of the same user that redefines a drive letter in its logon session during the launch window, and restores it before the post-launch check, is not detected. Such a process can already alter the bridge and is inside its trust boundary.
- **Unix session escape:** A descendant that calls `setsid` or `setpgid` leaves the process group and is not killed with it. A leader stuck in uninterruptible sleep past the reap deadlines stays a zombie until the bridge exits.
- **Unix sudden host crash:** Unlike Windows Job objects (`KILL_ON_JOB_CLOSE`), a `SIGKILL` of the bridge process itself cannot run user-space drop handlers to signal the child's process group.
- **Stale-revision batch UX:** The [fourteenth slice](#import-proposals-are-approved-together-fourteenth-slice-127) resolves this for CLI operators with `extensions approve <dir> <id> <id>...`. The operator UIs still decide one proposal at a time; re-run `extensions import` to queue remaining proposals at the new journal revision.

## Inbound legacy compatibility restored (tenth slice, #126)

The owner requires backward compatibility in both directions. This supersedes the sixth slice: the Agent Bridge server again accepts clients that open with `initialize`, next to stateless 2026-07-28 clients. Connected agents (ChatGPT, Gemini, Claude Code, Codex, Antigravity, Cursor, Copilot) keep access whichever revision they send.

- Both eras share each endpoint. A request selects 2026-07-28 only through explicit markers: the `server/discover` method or reserved `io.modelcontextprotocol/*` keys in `params._meta`. A request with modern markers is never served under legacy semantics, even when its metadata is malformed, and it is parsed with duplicate-key refusal.
- Legacy `initialize` negotiates `2025-11-25`, `2025-06-18`, `2025-03-26` or `2024-11-05`. An unknown version negotiates down to `2025-11-25`, as the legacy spec requires. `ping` is served in the legacy era.
- Stdio fixes the era with the first successful `server/discover`, modern request or `initialize`; a frame from the other era is then refused. Before either, a legacy frame other than `initialize` is refused, so a malformed first frame never enables tools. HTTP routes each request by its markers.
- OAuth still runs first on HTTP, and authorization is checked on every call in both eras. The catalog cache hints (#128) apply to 2026-07-28 listings; legacy listings carry no cache hints.
- Duplicate JSON object keys are refused in both eras, before routing, so a later key cannot hide a modern marker. A legacy `initialize` negotiates from its body whatever `MCP-Protocol-Version` header precedes it; afterwards several version lines, or a version this server does not serve, are refused. A legacy `tools/list` refuses any cursor, since none is issued, and errors echo a requested version only when it is at most 32 bytes.
- Self-reported client metadata is never an authenticated identity or an authorization input.

The reverted modern-only commit is `b01a592`; its refusal tests are replaced by the dual-era assertions it had replaced. Real-client qualification of each connected agent on the deployed build is still tracked in #126.

## Real extension qualification (eleventh slice, #127)

Two third-party stdio servers used daily on the workstation were run through the bridge's own launcher, pinned executable and outbound session, then their live catalogs were checked against the approval gates. No grant was written and no tool was called.

- **Obscura 0.2.7** (`obscura.exe mcp`): the session opens through the legacy fallback (`2024-11-05`) in about 1 second, with 38 tools and no stderr output.
- **Firecrawl Local 0.1.0** (`firecrawl-local.exe mcp --public-only`): the handshake fails, because the launcher starts `npx -y firecrawl-mcp` and the fixed child `PATH` has no Node.js directory. With the Node.js directory added, the server answers `initialize` with `2025-11-25` after about 3.6 seconds and lists 31 tools, through a chain of five processes (the launcher, `cmd`, `npx`, `cmd` and `node`).
- **Approval gates:** none of the 38 Obscura tools can be granted, because `data_tool` refuses the `browser` word. Firecrawl `firecrawl_scrape`, `firecrawl_map` and `firecrawl_crawl` fail both gates: their names carry no allowed verb, and `check_schema` refuses their optional `array`, `object` and `number` properties and the `url` property name. No grant parameter type accepts a URL.
- **Import:** `extensions import` refused the Claude Code entry for Obscura with `executable_unavailable`, because the path used forward slashes. This slice stores such paths with backslashes; both servers now queue as `add_stdio` proposals.

Slices 12 to 15 below delivered the follow-ups: live-profile tool gates, per-server `PATH` opt-in, grouped import approvals, and idle session reuse.

## Extension gates follow the active profile (twelfth slice, #127)

The owner chose to keep the operator's per-tool grant and let the four existing profiles decide what a granted tool may be. No new permission system is added.

- **Grant floor, every profile:** a tool is granted only by the operator, pinned to its descriptor SHA-256. Code runners and dispatchers (`data_name`: names with `shell`, `exec`, `command`, `evaluate`, `proxy`, `call_tool` and the like) are refused at parse time, as before.
- **Registry scope and workstation admission:** `ToolScope::DataOperations` limits the registry to individually granted operations that pass `data_tool`. The extension handler selects it for `read-only` or when it has no readable profile. Higher profiles select `ToolScope::AnyGranted`, which still requires individual grants. The unified workstation admits `desktop_mcp_tool_call` only in `full-control` or `fully-unlocked` (`LIVE_PROFILE_REFUSED` below that floor). The legacy Web workstation admits that tool from `workspace-write` upward when published (`PROFILE_DENIED` in `read-only`). A profile change applies to the next call.
- **Schema check on granted parameters only:** the bridge forwards only granted arguments, so `check_schema` now requires each granted parameter to exist with the granted JSON type and ignores optional properties that are not granted, whatever their shape. Top-level `$ref`, `oneOf`, `allOf`, `anyOf` and `patternProperties` stay refused.
- **Two parameter types:** `number` (`minimum` and `maximum`, finite, inclusive) and `public_https_url`. The URL type accepts `https` only, no credentials, port 443 at most, and a DNS host that is neither an address literal nor a local or reserved name (`localhost`, `.local`, `.internal`, `.lan`, `.test` and the like). Name resolution is not checked, so the extension server must still refuse private addresses. A parameter named `url` can be granted only with this type.

Validation: Windows workspace 332 passed, 0 failed, 36 ignored. A real Obscura `browser_navigate` grant, described through the bridge and called through the contained launcher, was refused under read-only, answered for `https://example.com/` in about 1.4 seconds under a higher profile, and refused `https://localhost/` before any launch.

## Browser Learn reader restored for 2.x compatibility

Agent Bridge 2.0.0 documented `--local-learn-url` and `--local-chrome-origin`. The seventh slice removed them, which would break the 2.x command line, so the next stable release could not be 2.1.0 under Semantic Versioning. The owner chose to restore them as deprecated.

- The browser Learn reader, the `learn` provider, its example and `--local-chrome-origin` work again as in 2.0.0, on `stdio` and `gemini workstation`.
- Using either option prints a deprecation notice on stderr, never on the MCP stdout stream. Removal is reserved for 3.0.0.
- The sealed Web workstation authority carries the selected Learn home URL and Chrome origins again, as in 2.0.0.
- The `microsoft_learn` extension adapter is unrelated and stays supported.

## Stdio servers can inherit the bridge PATH (thirteenth slice, #127)

Firecrawl Local starts `npx -y firecrawl-mcp`, which the fixed child `PATH` cannot resolve. The owner chose a per-server opt-in that inherits the full `PATH`.

- `StdioSpec.inherit_path` (default `false`, omitted when false, so existing pins are unchanged). When set, the bridge's own `PATH` is appended after the executable and system directories; a missing, empty, NUL-bearing or over-32-KiB bridge `PATH`, or a combined value above the Windows limit of 32 767 characters, refuses the launch. `PATHEXT`, `COMSPEC` and the other loader variables stay denied.
- `extensions import <private-directory> <mcp-json-path> --inherit-path <stdio-server>` sets it on that server's proposal, which the operator sees as `inherit_path: true` before approving. A name that is absent from the file or not an importable stdio entry (disabled, typed as another transport, carrying `url` or `headers`, reserved or invalid) refuses the whole import before anything is queued. Changing the flag on re-import queues a new proposal; it never alters an approved server silently.
- Risk accepted per server: the child resolves programs through every directory of the bridge `PATH`, including user-writable ones. The pinned executable itself is still opened by absolute path and SHA-256.

Validation: Windows workspace 335 passed, 0 failed, 36 ignored. Real Firecrawl Local through the contained launcher, with the `FIRECRAWL_*` variables passed as `AGENT_BRIDGE_EXTENSION_*` references: with the fixed `PATH` the catalog request failed; with `inherit_path` it answered in about 2.9 seconds; a `firecrawl_scrape` grant with `url: public_https_url` was refused under read-only and returned the Markdown of `https://example.com/` in about 3.1 seconds under a higher profile.

## Import proposals are approved together (fourteenth slice, #127)

Every proposal binds the journal revision and state it was queued at, and every decision advances the revision. An import of several servers therefore needed one approval, one re-import and one more approval per server.

- `extensions import` adds `approve_together`, the ids it queued, when there are at least two.
- `extensions approve <private-directory> <request-id> <request-id>...` (2 to 64 distinct ids) shows every record, then asks for `APPROVE <count> <digest>` in the local terminal, where the digest is the SHA-256 of the ids joined by newlines. No flag or piped answer can approve.
- Only pending `add` and `add_stdio` proposals can be grouped, one per server. Each must still match the current settings bytes, journal state and revision; one stale member refuses the whole batch with no change.
- Members are applied in order under the operator lock with the same rules as a single approval (fresh grant nonce, executable hash check, no tools granted, no network). Their decisions and the revision change are one journal replacement. The batch is all or nothing: an error, or a member that would be refused or unsupported (for example `executable_changed`), records nothing and names that member.
- Web clients and the loopback UI still decide one proposal at a time.

Validation: Windows workspace 336 passed, 0 failed, 36 ignored. The import test covers a stale member refusing the batch without change, a three-server approval with distinct nonces and one revision step, repeated or decided ids, a batch mixing an add with a `disable` proposal, two proposals for one server, and a changed executable that leaves every member pending.

## Tool calls reuse idle sessions (fifteenth slice, #127)

Each `desktop_mcp_tool_call` used to open a session: a new contained child and handshake for `stdio`, a new discovery for HTTP. Agents call the same server in bursts, so most of each call was start-up.

- Each route scope owns one `SessionPool`, shared by its `desktop_mcp_tool_call` handlers, including the Web handler bound to an OAuth authority. A session is reused only for the same server name and the same server fingerprint, so a registry edit, a grant change, a new pin, a removal or a disable opens a new session. The next call, even a refused one, first closes idle sessions that no longer match.
- Idle sessions also close when the configuration cannot be read, when the tool call handler sees a changed OAuth authority, and when a live profile is lowered (a profile revoker, like the other processes the bridge owns). A Web request that the authority guard refuses before dispatch reaches no session; those sessions close at the idle bound. A pooled `stdio` child is reused only by a registry that could launch one.
- Every call still re-lists the tool and checks its descriptor pin, schema and arguments before the single `tools/call`. The profile and the disabled overlay are checked first, as before.
- A reused session that fails before the call is closed, then replaced once by a fresh session; listing is read-only, so nothing is repeated. A call without a confirmed reply drops its session and is never replayed. A refused descriptor or argument leaves a healthy session in the pool.
- One reaper thread runs only while the pool holds a session. It closes each session after 120 seconds without a call, with the existing bounded drop (close, stdin end, `terminate()`). When the four `stdio` slots are taken, the longest idle pooled child of any pool yields its slot to a new session of any caller. Dropping the scope closes every idle child, on a plain thread so that it also works from an async context. On Windows the Job object also ends children when the bridge exits; on Unix they get end of input.
- `extensions refresh-check`, `describe` and the public documentation refresh still open their own session. No new process, service or setting is added.

Validation: Windows workspace 342 passed, 0 failed, 0 ignored. The stdio regression covers reuse with one handshake, idle shutdown, a changed entry, a refused call to a disabled server, a registry without launcher, the replaced broken session with a single `tools/call` and no other child evicted, a call without reply, pool drop, and the slot yield to a fifth server through a caller without a pool. Linux (WSL Ubuntu 24.04): extensions crate passed, 0 ignored. Real Obscura through the contained launcher (`browser_navigate` on `https://example.com/`): about 2 seconds per call without the pool; with it, 2.0 seconds, then 150 ms and 80 ms; the child was closed after the idle bound.
