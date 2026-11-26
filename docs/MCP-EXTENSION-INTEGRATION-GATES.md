# Modern MCP extension integration gates

The live gateway serves MCP `2026-07-28` alongside legacy MCP and advertises only `tools`. Modern discovery and catalog listings advertise a private freshness hint of `300,000` ms. Skills, Tasks, transfer, and Apps (#129 to #132) remain design-only. Do not modify the other agents' parity branches. Keep the current protocol adapter separate from the engine until the selected SDK has been qualified.

| Issue | Integration boundary | Required negative tests |
| --- | --- | --- |
| #128 | Derive a cache partition from verified authorization identity, audience, policy/profile revision, catalog generation and protocol version. Use a bounded monotonic TTL and clear entries on revocation or catalog mutation. These gates apply to a future shared cache or descriptor search. The current router catalog is fixed for the life of the router and advertises `cacheScope: "private"` and a catalog revision. Search over authorized descriptors only; tool execution still uses the same admission path. | Same names under different users, audiences or profiles; revoke during TTL; catalog change; reconnect; denied descriptors and stale cursors; missing identity. |
| #129 | Pin the published Skills extension revision. Map discovery and bounded resource reads to the existing skill inventory and approved roots. Return provenance and hashes; do not run scripts as a side effect of discovery or reading. | Unadvertised extension, path traversal, link/reparse substitution, oversize files, unauthorized roots, invalid metadata, legacy behavior. |
| #130 | Pin Tasks extension and core MRTR schemas. Reuse SQLite mission/task ownership, leases and idempotency records. Continuation state is opaque, bounded, expiring, bound to the authenticated subject, request and tool arguments; consume it atomically. Confirmation never increases permissions. | Forged or expired state, concurrent replay, identity mismatch, changed arguments, lost response, canceled work, restart, revoked permission, unknown outcome. |
| #131 | Pin the actual transfer extension revision and map only scoped artifacts to the existing transfer engine. Enforce byte quotas, content hash, expiry, immutable identity, and explicit destinations. Do not send secrets, auto-execute files, or accept arbitrary upload URLs. | Mismatch/hash failure, quota, replacement/link traversal, unauthorized recipient, expired artifact, interrupted transfer, unsupported client. |
| #132 | Pin MCP Apps version; expose a read-only view over the existing engine through a compatible host, not a second production listener. Isolate iframe origins/CSP and require ordinary server authorization and consent for any operator action. | Unsupported host/mobile client, untrusted origin/message, forged capability, expired authorization, action replay, denial with no side effects. |
| #133 | Pin the official conformance runner; use revision-specific requirements for legacy and 2026-07-28, not a moving suite without a recorded revision. Qualify synthetic server/client first, then the integrated runtime with the complete tool catalog and separate profiles. | Auth/transport routing, cancellation, bounded frames, invalid schema, revoked admission, unknown modern version, no implicit replay, all 46 tool contracts after #91. |

## Conformance command reference

Run the frozen revision requirements from a pinned runner, using a **temporary fixture** URL only:

    npx @modelcontextprotocol/conformance list --requirements 2026-07-28
    npx @modelcontextprotocol/conformance server --url http://127.0.0.1:<fixture-port>/mcp --requirements 2026-07-28

The dual-era gateway now runs behind the existing OAuth and transport checks; see MCP-MODERNIZATION.md for the recorded runner results. Record required, optional, failing and skipped cases separately. Do not treat unit tests or the SDK's own conformance as Agent Bridge conformance. Do not use the active workstation tunnel or production service as a fixture.

Source: https://github.com/modelcontextprotocol/conformance

## Rollout boundary

Qualify Skills, Tasks, transfer, and Apps before advertising them in the live runtime. Keep legacy transports and clients working. Reconcile the exact validated parity baseline and review the selected adapter independently. Use the existing service and operator/security boundaries; no merge, deploy, restart, or GitHub CI without the owner's decision.
