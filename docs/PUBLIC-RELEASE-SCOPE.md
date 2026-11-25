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

## Promotion gates

1. Freeze a clean source commit, record the real tool catalogue and exact schema seal, and qualify the supported operation matrix. Do not confuse registration with functional success. Track unexecuted cases separately.
2. Review security and privacy, including Git history and all branches/tags, issue and pull request content, reviews, wiki, workflow logs and artifacts, and existing release assets. A clean current tree alone is insufficient. Keep private test receipts outside published sources. Preserve legal attribution and do not rewrite or disclose historical records without an approved migration.
3. Build canonical source and binary packages from the reviewed revision. Verify resource manifests, notices, hashes, GUI subsystem, release signature, clean install and rollback. A development package is not a stable installer.
4. Qualify the actual application owner and secure tunnel in an isolated installation first. Migrate the existing operator installation only with a verified independent recovery channel, the original binaries/configuration retained and explicit OAuth reauthorization where scope changes. Check automatic startup, hidden operation, restart, client continuity and post-reboot behavior.
5. Change repository visibility or publish distribution assets only after the stable support scope and privacy review both pass. Publication of code does not imply every development feature is stable.

The exact candidate receipt must record source commit, binary and resource hashes, OS/architecture, commands and real outcomes. Never present an explicit refusal, filtered-out test, historical green result, or fixture-only result as evidence of an unsupported product feature.
