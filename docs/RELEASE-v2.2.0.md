# v2.2.0 Release

## Status

The Rust CLI and native desktop manifests are aligned at **2.2.0**, the current stable release for **Windows x64**. It is published directly as a stable release, without pre-releases. Every change since 2.1.0 went through a pull request with an independent Codex review, and the source checks below ran on the release commit. The release comprises the portable desktop ZIP (application, pinned browser and native resource bundles, notices and `release-manifest.json`), the canonical source ZIP, the MPL-2.0 source companion and a detached ECDSA P-256 signature over their SHA-256 checksums, made with the same release key as 2.0.0 and 2.1.0 (`licenses/agent-bridge-release-public.pem`). The packaged build reports `"channel":"stable"`. The executables are not Authenticode-signed. No prebuilt CLI binary is published; build the CLI from source. Linux and macOS remain experimental. Exact artifact hashes are published with the GitHub release.

2.2.0 adds; it removes nothing from the 2.1.0 public API. The additions are two optional `stdio` and `serve` options and an optional `sessionViewOnly` field in `operator-connection.json`. See [versioning](PUBLIC-RELEASE-SCOPE.md#versioning).

## Changes since 2.1.0

- A simpler desktop app: one status card, an Access control for the four existing profiles, and bottom navigation to Sessions, Approvals and Settings. Existing tasks and Task Rooms stay under **Sessions**, in its Tasks section. Settings starts with connecting an AI client; storage and diagnostics sit in two collapsible sections. Web relay errors, the session's profile ceiling and full approval origins stay visible.
- A **Sessions** page. It lists the AI clients admitted since the bridge started, for a Workstation the panel embeds or attaches to, or a `stdio` or `serve` process attached with the options below. The standalone panel alone does not populate the client list. The page shows clients live first, then up to 20 stored mission contexts that still hold an active or blocked mission. Each session opens on its missions, subtasks, commands and up to 10 successful tool calls.
- A client is admitted on its first successful reply; a request still in progress before that is not shown. An admitted client is live while a request is in progress or within 120 seconds of its last successful reply. OAuth web clients appear per client; each local transport (`stdio`, the local mission HTTP service) appears as one shared entry.
- The snapshot is computed in Rust and read through the authenticated local operator surface and the new `get_sessions` desktop command. It keeps at most 64 client sessions per boot; a new client then replaces the idle session with the oldest activity, and is skipped when all 64 have requests in flight. Link, row and byte limits can truncate the details of a session. When the bridge is stopped, the standalone panel still reads earlier mission contexts from its configured database; a stopped embedded or attached Workstation shows none through this fallback.
- The page shows short client hashes, tool names and, for process sessions, fixed process labels such as `git-version` and `project-program`, or `Process`; a one-shot `agent_bridge_project_command` appears only under recent tool calls; the snapshot also carries display-only command IDs. It never shows tool arguments, output, tokens or OAuth subjects. Mission goals and subtask titles are shown as written, truncated to 200 characters and not redacted; do not put secrets in them.
- Mission contexts record a best-effort `last_seen` time after successful mission operations, and on the calling context after a successful Task Room import, at most about once a minute.
- `agent-bridge stdio` and `agent-bridge serve` accept `--ui-port <port> --ui-session-file <private-json-path>`. The desktop attaches with an `operator-connection.json` that sets `"sessionViewOnly": true`; see [Show a harness in the desktop Sessions page](QUICKSTART.md#show-a-harness-in-the-desktop-sessions-page). The attachment answers only the sessions read, cannot change profiles and cannot stop the process. A clean shutdown removes the session file.

The unified catalogue is unchanged: 46 tools with digest `7603bc547b696a3c45e4cd3f5b0b98bbf0f51c9cad66bc31f5a75ae5259c349c`. Existing grants and the `unified-v1.json` manifest keep working.

## Windows qualification

Observed on the `2.2.0` source. Dependency pins are unchanged since 2.1.0.

| Verified scope | Evidence |
| --- | --- |
| Toolchain | Rust and Cargo 1.99.1, target `x86_64-pc-windows-msvc` |
| Root Cargo workspace | `cargo test --locked --offline --workspace`: 374 passed, 0 failed, 0 ignored (216 in the `agent-bridge` library) |
| Unified catalogue | `--features qualification`, `integration_real_catalogue_46`: 46 tools, digest unchanged |
| Independent desktop workspace | 56 Tauri Rust tests and 58 frontend tests pass |
| Python release and maintenance tools | 116 run; 29 platform or native-symlink tests skipped on Windows |
| Linux (experimental) | Ubuntu 24.04: `agent-bridge-lifecycle` 5 tests and the 21 session tests of the `agent-bridge` library pass; the full Linux suite was not rerun |
| Desktop ZIP and signature | The packager's private-path and notice gates pass; `openssl dgst -sha256 -verify` prints `Verified OK` |

The full interactive qualification run (WPF fixture, Virtual Desktops, synthetic input) was not repeated for 2.2.0; its last run was on the `2.1.0-beta.1` source. The 2.2.0 changes record session activity around tool calls; they do not change the inputs, results or approvals of the interactive desktop tools that run covers.

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

The [2.1.0 limitations](RELEASE-v2.1.0.md#known-limitations) still apply, including the Gemini Web per-tool approval and the Neon mode behavior. The Sessions page shows only clients of the bridge process it is attached to; each `stdio` or `serve` process is its own boot and needs its own session-view attachment. Session history is kept in memory for the current boot only. With a session-view-only attachment, the home screen shows **Unavailable** because the profile route is refused; the Sessions page still works.

## Reproduce the gates

The workspace, Tauri, frontend and Python commands are the same as for [2.1.0](RELEASE-v2.1.0.md#reproduce-the-gates). Check the catalogue with `cargo test --locked --offline -p agent-bridge --features qualification --lib -- --test-threads=1 integration_real_catalogue_46`, with the pinned browser and native bundles described there. The full interactive suite listed there is historical qualification and was not rerun for 2.2.0. Packaging is unchanged: follow the [2.0.0 packaging instructions](RELEASE-v2.0.0.md#reproduce-the-gates) with `--release-channel stable` and one `--ack-review` per item in [release notices](RELEASE-NOTICES.md#explicit-review-items). Then sign with `scripts/windows/sign-release.ps1 -Mode Sign -ArchivePaths @('<desktop-zip>', '<source-zip>', '<mpl-companion-zip>') -OutputDirectory '<new-signature-directory>'` from PowerShell 7, and verify from the repository root with `openssl dgst -sha256 -verify licenses/agent-bridge-release-public.pem -signature <new-signature-directory>/SHA256SUMS.sig <new-signature-directory>/SHA256SUMS`.
