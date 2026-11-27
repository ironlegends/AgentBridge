# v2.1.0 Release

This historical record describes the 2.1.0 release. Later releases have their own notes; the [README](../README.md) links the current one.

## Status

The Rust CLI and native desktop manifests are aligned at **2.1.0**, the current stable release for **Windows x64**. It follows the `2.1.0-alpha.1`, `2.1.0-beta.1` and `2.1.0-rc.1` pre-releases; the release candidate ran on the operator workstation before this release. The release comprises the portable desktop ZIP (application, pinned browser and native resource bundles, notices and `release-manifest.json`), the canonical source ZIP, the MPL-2.0 source companion and a detached ECDSA P-256 signature over their SHA-256 checksums, made with the same release key as 2.0.0 (`licenses/agent-bridge-release-public.pem`). The packaged build reports `"channel":"stable"`. The executables are not Authenticode-signed. No prebuilt CLI binary is published; build the CLI from source. Linux and macOS remain experimental. Exact artifact hashes are published with the GitHub release.

2.1.0 adds and deprecates; it removes nothing from the 2.0.0 public API. The browser Learn reader options are deprecated and reserved for removal in 3.0.0. See [versioning](PUBLIC-RELEASE-SCOPE.md#versioning).

## Changes since 2.0.0

- MCP protocol 2026-07-28 for inbound clients, with the legacy `initialize` handshake kept. Outbound connections to external MCP servers use Streamable HTTP or stdio; they probe `server/discover` first and fall back to one `initialize` for a legacy server. The removed two-endpoint HTTP+SSE transport is not supported.
- Imported MCP extensions: data tool and schema gates per profile, grouped import approvals, session reuse with idle shutdown and bounded stdio slots, Windows import paths. A stdio server starts with a fixed default `PATH`; a per-server `inherit_path` opt-in appends the bridge's own `PATH`.
- A bounded, redacted request audit for the workstation `/mcp` route. It is read through the authenticated local operator diagnostics or in the desktop app under **Settings > Advanced settings > Diagnostics & Skills**. With the procedure in the [quick start](QUICKSTART.md), it helps tell a request that never reached Agent Bridge apart from a server refusal.
- The mission owner can release a stuck `in_progress` subtask to `blocked` with a reason, then reassign it.
- One product version for the CLI and the desktop app. The release channel reads `stable` only for a build compiled with `AGENT_BRIDGE_RELEASE_CHANNEL=stable`, which the desktop packager sets with `--release-channel stable`.
- Distribution and reproducibility fixes, dead code removed and documentation aligned.
- Zero ignored tests in the default Rust suites, the qualification features and the Unix fixtures; all 46 tools are exercised.

The unified catalogue is unchanged: 46 tools with digest `7603bc547b696a3c45e4cd3f5b0b98bbf0f51c9cad66bc31f5a75ae5259c349c`. Existing grants and the `unified-v1.json` manifest keep working.

## Windows qualification

Observed on the `2.1.0-beta.1` source. Executable source and dependency pins are unchanged since then. The `2.1.0-rc.1` and `2.1.0` commits change the product version in the two Cargo manifests and the two lockfiles, and the documentation: these release notes, the security policy, the versioning table and version references.

| Verified scope | Evidence |
| --- | --- |
| Toolchain | Rust and Cargo 1.99.1, target `x86_64-pc-windows-msvc` |
| Root Cargo workspace | `agent-bridge`, `agent-bridge-http`, `agent-bridge-missions`, `agent-bridge-gateway` and `agent-bridge-oauth-server`: all pass, 0 ignored (203 in the `agent-bridge` library) |
| Qualification features | `--features qualification` with the 2.0.0 browser and native bundles: every test passes except two exact-passive Windows UI tests, which refuse with `UI_EXACT_PASSIVE_UNQUALIFIED` as documented for that experimental capture |
| Independent desktop workspace | 55 Tauri Rust tests and 57 frontend tests pass |
| Python release and maintenance tools | 116 run; 29 platform or native-symlink tests skipped on Windows |
| Linux (experimental) | Ubuntu 24.04: 187 library tests pass; isolated X11 window tests 15/15 |
| Live client | On the deployed release candidate, Gemini Web called `agent_bridge_status` in the Hydrogen and Neon modes; the request audit recorded each `initialize`, `tools/list` and `tools/call` |
| Desktop ZIP and signature | The packager's private-path and notice gates pass; `openssl dgst -sha256 -verify` prints `Verified OK` |

A successful build and test run does not qualify an installer, Authenticode signing, an updater or post-reboot logon behavior.

## Verify a download

```sh
openssl dgst -sha256 -verify licenses/agent-bridge-release-public.pem -signature SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

The first command must print `Verified OK`. The second must print `OK` for the exact archive you install; `--ignore-missing` silently skips listed files that are not in the directory. `SHA256SUMS.sig` signs the checksum list; it is not an Authenticode signature, and Windows may warn on the first launch of the unsigned executable.

## Remaining gates

- [ ] Observe post-reboot startup and logon in a new Windows session.
- [ ] Exercise macOS TCC consent and a real AX action in an operator-approved graphical session.
- [ ] Qualify CLI packages for Windows, macOS and Linux with their target-specific notice reviews and the private-path guard.
- [ ] Qualify Tauri installers, Authenticode or platform signing, and updater behavior.
- [ ] Qualify exact-passive window capture and the Agent Desktop pool with isolated fixtures before enabling them.

## Known limitations

Gemini Web asks for its own per-tool approval before the first call. On the release candidate, during a Neon attempt the request audit recorded successful `initialize` and `tools/list` requests and no `tools/call`, while Gemini answered that no tool was available. The Hydrogen mode showed the approval card; after **Always allow**, `agent_bridge_status` succeeded in Hydrogen and then in Neon. The audit recorded no server refusal for either mode. During the Neon attempt the audit kept the same boot ID, with no eviction and nothing in flight. To diagnose a client that reports no tool or a quota, follow the [quick start](QUICKSTART.md) procedure; a missing record alone can also mean a pending approval or a transport failure.

The runtime limitations listed for [2.0.0](RELEASE-v2.0.0.md#known-limitations) still apply: Unix browser project transfer, macOS window screenshots, the Linux X11 window automation boundary, refused Chrome installations with unsafe ancestors, and the required native spawn extensions and OS keyrings. The main Rust workspace does not test the independent desktop Cargo workspace; run both suites.

## Reproduce the gates

Run every command from the repository root:

```sh
cargo test --locked --offline --workspace
cargo test --locked --offline -p agent-bridge --features qualification --no-fail-fast -- --test-threads=1
cargo test --locked --offline --manifest-path app/src-tauri/Cargo.toml
node --test app/tests/live-profile.test.cjs
python3 -m unittest discover -s scripts/rust -p "test_*.py"
python3 scripts/rust/source-release.py --repo . --out-dir <new-existing-output-directory>
```

The qualification run is Windows-only. It needs the packaged browser and native bundles and the native test fixture, each with its pinned SHA-256 (`AGENT_BRIDGE_BROWSER_BUNDLE`, `AGENT_BRIDGE_BROWSER_MANIFEST_SHA256`, `AGENT_BRIDGE_NATIVE_TEST_BUNDLE`, `AGENT_BRIDGE_NATIVE_TEST_MANIFEST_SHA256`, `AGENT_BRIDGE_NATIVE_TEST_FIXTURE`, `AGENT_BRIDGE_NATIVE_TEST_FIXTURE_SHA256`), the reviewed `search_model_context_protocol` descriptor file (`AGENT_BRIDGE_EXTENSION_TEST_DESCRIPTOR`) which must match the live schema of https://modelcontextprotocol.io/mcp, HTTPS access to that server, and Git for Windows at `C:\Program Files\Git`. It runs in an interactive session with the WPF fixture and dedicated Virtual Desktops, shows windows and sends synthetic input. See the [quick start](QUICKSTART.md). On Windows, run the desktop tests from a shell whose `PSModulePath` is not inherited from PowerShell 7.

Packaging follows [2.0.0](RELEASE-v2.0.0.md#reproduce-the-gates). `scripts/rust/package-desktop.py --release-channel stable` sets `AGENT_BRIDGE_RELEASE_CHANNEL=stable` for the compiler; any build compiled with that variable set to exactly `stable` reports `"channel":"stable"`, so pass it only for a build that will be published. Signing is a separate step: run `scripts/windows/sign-release.ps1 -Mode Sign` with the desktop, source and MPL companion ZIPs, then verify `SHA256SUMS.sig`.
