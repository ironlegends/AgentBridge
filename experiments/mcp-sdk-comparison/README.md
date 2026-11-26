# MCP SDK comparison (experimental)

Historical record of the 2026-11-24 comparison. The build command below
describes the experimental checkout. It fails against the current gateway,
which replaced `StdioPreview` with `StdioEra` and removed the
`modern-preview` feature. Production outbound extensions now use
rmcp `=3.11.0`.

This standalone Cargo workspace is not part of Agent Bridge's production dependency graph. It compares two synthetic stdio fixtures, each exposing exactly one constant-result echo tool, using the same modern MCP request sequence. The official SDK is pinned to rmcp 3.11.0; the custom fixture uses the local opt-in gateway preview. There are no private files, external endpoints, credentials, operator actions, or actual Agent Bridge tools in either fixture.

Build with the existing Rust/MSVC environment, an isolated target directory, and a private Cargo home if dependency fetching is required. Example:

    cargo build --release --locked --manifest-path experiments/mcp-sdk-comparison/Cargo.toml --target-dir target/mcp-sdk-build
    python experiments/mcp-sdk-comparison/benchmark.py --custom target/mcp-sdk-build/release/custom-preview.exe --sdk target/mcp-sdk-build/release/rmcp-preview.exe

The benchmark alternates fixture order over three rounds, performs discovery/list and twenty warmup calls, then measures 300 confirmed sequential calls per round. Windows working set/peak are sampled from only the owned child process; every child is closed and joined. No official conformance claim follows from these numbers. This is a small stdio protocol overhead comparison, not a complete HTTP, OAuth, cancellation, extension, or full-application benchmark. Run the official conformance suite and representative HTTP and production-like workloads before choosing an integration.

## First measured comparison (reference Windows workstation, 2026-11-24)

Source data: results/reference-stdio-20261124.json (captured from the successful benchmark process). Locked release builds used Rust/Cargo 1.99.1 and MSVC; the SDK experiment used its own Cargo home and target directory. The fresh build finished in 2m 45s with one Cargo build job. rmcp 3.11.0 is pinned; the crates.io registry record was not yanked and specifies Rust 1.88 minimum. Its direct dependency tree includes 18 entries (including proc-macro and Tokio); the standalone lockfile resolves the shared dependency graph. No SDK dependency was added to the production workspace lockfile.

| Metric (median of three rounds) | Custom | rmcp 3.11.0 |
| --- | ---: | ---: |
| Release executable bytes | 365056 | 2997248 |
| Startup to discovery, ms | 26.0216 | 16.9999 |
| Median tool RTT, ms | 0.0253 | 0.1166 |
| p95 tool RTT, ms | 0.056 | 0.1402 |
| Idle working set, bytes | 4182016 | 5525504 |
| Final working set, bytes | 4190208 | 5570560 |
| Confirmed tool calls, all rounds | 960 | 960 |

Both fixtures passed the modern discovery, catalog and tool reply assertions, and exited normally. The custom fixture is smaller and its sequential synthetic RTT is lower; the official SDK implements substantially more protocol behavior. Startup varied markedly and the machine was shared with other active work. These are neither whole-application nor HTTP/OAuth benchmarks and do not measure provider tokens, CPU, end-to-end task latency or official conformance. Do not extrapolate the binary-size ratio to the production application. The sub-millisecond difference in this fixture is not sufficient reason to maintain an entire evolving protocol independently.

Recommendation: retain the qualified opt-in custom adapter as a fallback and comparison baseline, and prototype an rmcp-backed protocol layer over the same authoritative engine. Select production architecture after a representative HTTP/stdio benchmark and conformance, preserving existing leases, catalog/profile filtering, authorization and operator admission. Do not integrate or deploy this standalone experiment.

Default-feature regression suite (gateway, HTTP and extensions): 8 passed, 0 failed, 0 ignored. Combined opt-in suite: 30 passed, 0 failed, 0 ignored. Full revision-specific official conformance and extension qualification remain open.
