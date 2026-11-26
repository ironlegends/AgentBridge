# v2.0.0 Release

This historical record describes the 2.0.0 release and its qualification
results. The current development manifests are at `2.1.0-alpha.1`. The
default Rust suites now have zero ignored tests. See the
[contributor test guide](../CONTRIBUTING.md#build--test) for opt-in tests.

## Status

The Rust CLI and native desktop manifests are aligned at **2.0.0**, the first stable release for **Windows x64**. The release comprises the portable desktop ZIP (application, pinned browser and native resource bundles, notices and `release-manifest.json`), the canonical source ZIP, the MPL-2.0 source companion and a detached ECDSA P-256 signature over their SHA-256 checksums. The release key is a non-exportable local CNG key; its public half is `licenses/agent-bridge-release-public.pem`. The executables are not Authenticode-signed. No prebuilt CLI binary is published; build the CLI from source. Linux and macOS remain experimental. Exact artifact hashes are published with the GitHub release rather than in this file, because the source archive cannot contain its own checksum.

### 2.0.0 changes since 2.0.0-rc.1

- The unified 46-tool catalogue (27 desktop, 16 missions including status, 1 project command, 2 historical utilities) is selected by the owner-controlled `unified-v1.json` manifest and bound into new OAuth grants.
- Native provider directory pins allow ordinary sibling-file mutations (`FILE_SHARE_READ | FILE_SHARE_WRITE`) and still deny directory replacement; immutable resource pins are unchanged.
- Rust path remapping uses absolute virtual Windows roots (`C:/agent-bridge-build/...`). The desktop packager refuses any staged file that contains a private build, checkout, profile or bundle source path, in absolute, resolved, 8.3 short and MSYS spellings, in UTF-8 and UTF-16, independent of letter case.
- The desktop app enables Tauri's `custom-protocol` feature, so a plain `cargo build` produces a production Tauri context. Earlier builds used the development context, which embedded the checkout directory.
- The bundled WinApp derivative `0.5.0-agentbridge.2` is rebuilt from the same upstream source, three reviewed patches and pinned dependencies with `NativeDebugSymbols=false`, so no PDB path is linked. The experimental `0.5.0-agentbridge.3` exact-passive profile stays opt-in and unqualified.
- Pinned upstream license fallbacks and the WebView2 SDK notices are packaged; five MPL-2.0 crates are covered by the source companion.
- The Windows CI test account receives a random password for each run.

## Release notes

### Live Rust operator console

- Embeds the complete local console in `gemini workstation` with `--ui-port <port> [--ui-open]`, alongside the native Tauri application.
- Adds one-click active profiles bounded by the startup ceiling.
- Preserves the MCP process, listener, catalog, OAuth resource and existing grants across live mode changes.
- Shares the Task Rooms database owner with the embedded UI, avoiding a second offline-style open while the runtime owns SQLite WAL state.

### Native Tauri live workstation control

- Connects the Tauri v2 desktop window and four-mode selector to the running workstation through native IPC.
- Displays the confirmed active profile and startup ceiling, with one-click changes that preserve MCP and OAuth continuity.
- Keeps operator tokens in the native backend, reads only an explicitly configured bounded log tail, and refuses invalid attachment or authentication without falling back to unrelated local state.
- Routes the Tasks, Approvals, Skills and Diagnostics screens through the running service; never reopens its live database from the desktop app.
- Prevents stale refreshes from overwriting a confirmed mode and preserves unsaved settings fields.
- Adds cooperative Stop for an authenticated session even if its startup supervisor is unavailable. Start and Restart require a validated current-user Windows scheduled task. See [WORKSTATION-MODES.md](WORKSTATION-MODES.md) for the attachment contract.

### Explicit fully-unlocked process sessions

- Accepts `--profile fully-unlocked --enable-processes` on the workstation command.
- Provides shell commands or literal program/argument execution at the current account's permissions.
- Keeps opaque gateway-owned session capabilities, bounded output/input, incremental reads and explicit input acknowledgements.
- Revokes owned sessions before confirming a lower active mode.
- Preserves the existing read-only, workspace-write and restricted full-control providers.
- Supervises Windows Jobs and Unix process groups without claiming containment of Unix programs that deliberately leave their group.

### Native Unix work (experimental)

- Implements Chrome CDP on Unix descriptors 3/4 with collision-safe remapping, private profile ownership and native process cleanup.
- Replaces blanket Unix workspace-metadata and fixed-project-child handle refusals with verified directory-handle implementations.
- Adds local-consent macOS Accessibility and Linux X11 adapters while preserving the Windows backend.
- Refuses unsupported transfers, screenshots, displays and input operations explicitly. See [UNIX-PARITY.md](UNIX-PARITY.md) for the capability matrix.

### Verified browser cleanup

- Waits only for native Windows delete-sharing conflicts within one five-second cleanup budget, shared by explicit close and fallback destructors.
- Retains handle identity, parent/reparse/hardlink checks and deletion through qualified handles.
- Preserves the private profile when owned-process shutdown cannot be confirmed, releasing pins without allowing nested destructors to delete it.

### Maintenance and packaging

- Adds a Rust comment inventory and a fingerprint-based ratchet against new deferred-work markers and decorative dividers.
- Includes the standalone CLI and independent Tauri workspace in the source archive, with both Cargo lockfiles, native sources/tests, desktop configuration, frontend assets and icons.
- Builds the extracted source archive in Linux CI and checks deterministic ZIP contents.
- Retains the two nested once_cell licenses referenced by ring, validates declared license paths before resolution, and verifies the official Rust compiler/standard-library notice provenance. See [RELEASE-NOTICES.md](RELEASE-NOTICES.md).
- Local paths, secrets and host state are excluded from source releases.

## Windows qualification

| Verified scope | Evidence |
| --- | --- |
| Toolchain | Rust and Cargo 1.99.1, target `x86_64-pc-windows-msvc` |
| Root Cargo workspace | `cargo test --locked --offline --workspace`: 271 passed, zero failed, 33 ignored (explicit child-process and opt-in fixtures) across 54 test binaries |
| Unified catalogue | 46 tools with digest `7603bc547b696a3c45e4cd3f5b0b98bbf0f51c9cad66bc31f5a75ae5259c349c` for both the `workspace` and `os-user` file scopes |
| Native bundle | The packaged preflight is read-only and rejects wrong seals; four native handlers cross the real MCP schema boundary; an unqualified bundle refuses capture before any child or file is created |
| Independent desktop workspace | 53 Tauri Rust tests passed, 2 ignored; 53 frontend state tests passed |
| Python release and maintenance tools | 109 passed; 29 platform or native-symlink tests skipped on Windows |
| Desktop ZIP | CRC check, every member matches `release-manifest.json`, GUI subsystem x64 executable, no private path in any member, PDB referenced by file name only |
| Signature | `openssl dgst -sha256 -verify` with the committed public key prints `Verified OK`; the listed hashes match the assets |

A successful build and test run does not qualify an installer, Authenticode signing, an updater or post-reboot logon behavior.

## Verify a download

```sh
openssl dgst -sha256 -verify licenses/agent-bridge-release-public.pem -signature SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

The first command must print `Verified OK`. `SHA256SUMS.sig` signs the checksum list; it is not an Authenticode signature, and Windows may warn on the first launch of the unsigned executable.

## Remaining gates

- [ ] Observe post-reboot startup and logon in a new Windows session for each release.
- [ ] Exercise macOS TCC consent and a real AX action in an operator-approved graphical session.
- [ ] Qualify CLI packages for Windows, macOS and Linux with their target-specific notice reviews and the private-path guard.
- [ ] Qualify Tauri installers, Authenticode or platform signing, and updater behavior.
- [ ] Qualify exact-passive window capture and the Agent Desktop pool with isolated fixtures before enabling them.

## Known limitations

Unix browser project upload/download is unavailable. macOS window screenshots are unavailable. Linux window automation requires local X11, XRes ownership proof and the declared action support; Wayland/XWayland, remote X11 and global input are unsupported. X11 synthetic input confirms dispatch, not application acceptance.

Chrome installations with unsafe writable ancestors are refused. Required native spawn extensions and OS keyrings must be available for their respective capabilities; no plaintext secret or ambient-path fallback is introduced.

The `build_script` hash in `WINAPP-BUILD-PROVENANCE.json` was computed over a CRLF checkout of the script, so it does not match the LF bytes in the source ZIP. It is informational; the pinned WinApp output hashes are the enforced values.

Since 2.0.0, the source archive has been changed to preserve the pinned CRLF
bytes. The current provenance test checks both the SHA-256 and byte length of
the build script and other pinned inputs. See
[archive privacy and provenance](PUBLIC-RELEASE-SCOPE.md#archive-privacy-and-provenance).

The main Rust workspace does not test the independent desktop Cargo workspace; run both suites.

## Reproduce the gates

```sh
cargo test --locked --offline --workspace
cargo build --locked --offline --release -p agent-bridge
cargo test --locked --offline --manifest-path app/src-tauri/Cargo.toml
cargo build --locked --offline --release --manifest-path app/src-tauri/Cargo.toml
node --test app/tests/live-profile.test.cjs
cd scripts/rust && python3 -m unittest discover -p "test_*.py"
python3 scripts/rust/source-release.py --repo . --out-dir <new-existing-output-directory>
```

On Windows, run the desktop tests from a shell whose `PSModulePath` is not inherited from PowerShell 7; the DPAPI fixtures call Windows PowerShell 5.1. Use a separate release target directory so a running executable remains untouched.

`scripts/rust/package-desktop.py` builds the desktop ZIP offline in a new isolated target directory from a clean checkout. It takes the browser and native bundles with their manifest SHA-256 values, a new existing output directory and one `--ack-review` per reviewed notice item, and refuses before writing an archive if a staged file contains a private path. See [release notices and package decisions](RELEASE-NOTICES.md). Pass `--release-channel stable` only for a build that will be signed and published. The packager always sets `AGENT_BRIDGE_RELEASE_CHANNEL` for the compiler, so `agent_bridge_status` reports `"channel":"stable","production":true` only for that build. Other packaged builds report `development`, and so does a plain `cargo build` unless its environment sets that variable to exactly `stable`.

On the current tree, pass `--build-dir <new-target-directory>` to the desktop
packager. Packaged builds, and any desktop build with
`AGENT_BRIDGE_RELEASE_CHANNEL` set, refuse `TAURI_CONFIG`. The private-path scan also
covers compressed and embedded archive members and the Tauri frontend sources.

Run `scripts/windows/sign-release.ps1 -Mode Sign` with the desktop, source and MPL companion ZIPs as the explicit archive list. It writes `SHA256SUMS` and the detached CNG signature `SHA256SUMS.sig`. Verify the signature, then compare the listed hashes with the released downloads.
