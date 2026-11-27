# Public release scope and qualification

This document defines the minimum supported release boundary, not a claim that the current development revision is stable.

## Target

The initial supported distribution is Windows x86-64, running as a standard interactive Windows user with the locally configured native Tauri application owning the MCP listener and optional secure tunnel. Linux and macOS components remain under development until their own release matrices are satisfied. They must not be advertised as fully equivalent Windows distributions.

| Capability | Release boundary |
| --- | --- |
| MCP transport, OAuth authorization and revocation | Required; verify exact schema/capability binding and reject authority drift. |
| Files, tasks, missions, artifacts, skills and extensions | Required for their documented local configuration and supported profiles. Preserve observation guards, private-state protection and explicit approvals. |
| Fully Unlocked terminal and fixed diagnostics | Required at the normal account's authority, owned processes, hidden console by default, bounded outputs and verified shutdown. No implicit elevation. |
| Explicit os-user file scope | Required for the selected Fully Unlocked configuration. Confirm read, create, rewrite, append, edit, move, revocation and protected boundaries using real fixtures. |
| Browser | Qualify each supported action with isolated fixtures; persistent-profile reopen and resource cleanup are release-relevant. Any remaining experimental operation must be clearly marked and fail safely. |
| Restricted process execution | A known unsupported Low-IL configuration must refuse explicitly, never fall back to current-user execution. This does not constitute functional Low-IL support. |
| Native capture, Agent Desktop and visible input | Experimental until exact packaged resources, consent and observable effects are qualified. Unsupported operations must explicitly refuse. |
| Linux/macOS and updater distribution | Independently qualify each advertised target; unsupported platforms/features are not release blockers for a Windows-only distribution. |

## Versioning

Agent Bridge follows Semantic Versioning 2.0.0. The public API is the documented command line, the MCP tool names and input schemas, and the documented configuration files.

| Version | Use |
| --- | --- |
| `2.0.0` | First public stable release. Never rebuilt or retagged. |
| `2.1.0` | Stable release. Never rebuilt or retagged. |
| `2.2.0` | Current stable release. Never rebuilt or retagged. |
| `2.2.N` | Backward-compatible fixes only. |
| `2.3.0-alpha.N` | New features under development. |
| `2.3.0-beta.N` | Features complete, qualification in progress. |
| `2.3.0-rc.N` | Qualified candidate, deployed on the operator workstation. |
| `2.3.0` | Next stable release, published after validation. |
| `3.0.0` | Removals or changes that break the 2.x public API. |

A 2.x minor release adds or deprecates; it does not remove. A deprecated option keeps working and prints a notice on stderr until the next major release. The browser Learn reader options are deprecated in 2.1.0 and reserved for removal in 3.0.0.

The product version is set only in `rust/cli/Cargo.toml` and `app/src-tauri/Cargo.toml`, with the same value. `tauri.conf.json` has no version, so Tauri reads the app manifest. The MCP status, build metadata and archive names read it from Cargo. `scripts/rust/repository_hygiene.py` refuses two different values, a version that is not `X.Y.Z` or `X.Y.Z-alpha|beta|rc.N`, and a version in `tauri.conf.json`. A release tag is `v` followed by that version.

## Archive privacy and provenance

- `package-desktop.py` and `package-rust.py` (the CLI archive) refuse to publish when a staged file contains a private build root: the profile, checkout, output, build and Cargo directories, in every spelling (absolute, resolved, 8.3, `/c/...`, escaped, UTF-8 and UTF-16, any case).
- The scanned roots also include the Rust sysroot, and each spelling is matched in JSON-escaped form.
- Zip (stored or deflated, also after a preamble) and gzip (all members, as one stream) content is opened and scanned up to three levels deep, within 2 GiB of decompressed bytes for the whole release. A deeper, larger, truncated, encrypted, otherwise compressed or CRC-mismatched member is refused.
- Tauri compresses the frontend into the executable, so the `frontendDist` sources are scanned as well. `TAURI_CONFIG` (also from Cargo's `[env]`, refused by `build.rs` in release builds) and platform Tauri configuration files are refused, so the scanned frontend is the embedded one.
- `scripts/rust/build-winapp-passive.py` is stored with the CRLF bytes pinned by `WINAPP-BUILD-PROVENANCE.json` (`-text`), so a checkout on any platform and the source archive reproduce the recorded hash. A test compares the build script, patches and contract sources with the committed provenance; changing one requires a rebuild of the WinApp derivative.

## Promotion gates

1. Freeze a clean source commit, record the real tool catalogue and exact schema seal, and qualify the supported operation matrix. Do not confuse registration with functional success. Track unexecuted cases separately.
2. Review security and privacy, including Git history and all branches/tags, issue and pull request content, reviews, wiki, workflow logs and artifacts, and existing release assets. A clean current tree alone is insufficient. Keep private test receipts outside published sources. Preserve legal attribution and do not rewrite or disclose historical records without an approved migration.
3. Build canonical source and binary packages from the reviewed revision. Verify resource manifests, notices, hashes, GUI subsystem, release signature, clean install and rollback. A development package is not a stable installer.
4. Qualify the actual application owner and secure tunnel in an isolated installation first. Migrate the existing operator installation only with a verified independent recovery channel, the original binaries/configuration retained and explicit OAuth reauthorization where scope changes. Check automatic startup, hidden operation, restart, client continuity and post-reboot behavior.
5. Change repository visibility or publish distribution assets only after the stable support scope and privacy review both pass. Publication of code does not imply every development feature is stable.

The exact candidate receipt must record source commit, binary and resource hashes, OS/architecture, commands and real outcomes. Never present an explicit refusal, filtered-out test, historical green result, or fixture-only result as evidence of an unsupported product feature.
