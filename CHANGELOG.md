# Changelog

User-visible changes are grouped by version and dated using the UTC publication date. Prereleases are identified explicitly. See each tagged GitHub release for downloads, checksums, qualification, and limitations.

## [Unreleased]

## [2.3.1] - 2026-11-27

### Changed

- The foreground workspace now tells MCP clients whether project files are writable, how temporary artifacts differ from project files, and which mission tools record or read progress. Existing Windows workstation tool definitions are unchanged.

### Security

- The desktop GTK3 dependency graph now uses the upstream fix for GHSA-wrw7-89jp-8q8g, backported to the pinned glib 0.18.5 crate. The Windows x64 binary does not link glib.

## [2.3.0] - 2026-11-27

### Added

- **Agent coordination and visibility:** The Windows desktop adds mission handoff and redacted audit history; session status is computed in Rust.
- **Specialized MCP catalogues:** Five optional startup views let operators select a smaller overlapping tool set. The default workstation exposes 46 tools and the foreground workspace exposes 22.
- **Documentary skills and extension results:** Operators can import and revoke skills and filter, mask, and cache approved extension reads. Optional locally approved revision checks extend the workstation catalogue.

### Changed

- **Tool discovery and compatibility:** Tool and parameter descriptions are clearer. Selecting an updated or optional catalogue requires fresh OAuth consent; the previous catalogue remains selectable. [#32](https://github.com/ironlegends/AgentBridge/pull/32), [#33](https://github.com/ironlegends/AgentBridge/pull/33)
- **Desktop and browser:** Pointer/touch setup and updated bundled Playwright 1.65.1/Chromium.
- **Dependencies:** Dependabot tracks Rust, browser worker, and GitHub Actions dependencies. [#21](https://github.com/ironlegends/AgentBridge/pull/21), [#24](https://github.com/ironlegends/AgentBridge/pull/24), [#34](https://github.com/ironlegends/AgentBridge/pull/34), [#35](https://github.com/ironlegends/AgentBridge/pull/35)

[Release notes](https://github.com/ironlegends/AgentBridge/releases/tag/v2.3.0) | [Technical notes](docs/RELEASE-v2.3.0.md) | [Full comparison](https://github.com/ironlegends/AgentBridge/compare/v2.2.0...v2.3.0)

## [2.2.0] - 2026-11-27

### Added

- **Session visibility:** The Sessions page displays admitted clients, missions, process labels and recent successful tool calls through a bounded Rust-computed snapshot.
- **CLI attachment:** Optional session-view attachment for local CLI transports and best-effort mission last-seen tracking.

### Changed

- **Desktop navigation:** A simpler interface presents the four access profiles and dedicated Sessions, Approvals and Settings pages. The unified 46-tool catalogue and existing grants remain unchanged. [#20](https://github.com/ironlegends/AgentBridge/pull/20)

[Release notes](https://github.com/ironlegends/AgentBridge/releases/tag/v2.2.0) | [Technical notes](docs/RELEASE-v2.2.0.md) | [Full comparison](https://github.com/ironlegends/AgentBridge/compare/v2.1.0...v2.2.0)

## [2.1.0] - 2026-11-26

### Changed

- **Stable promotion:** Publishes the qualified Windows x64 portable release after the 2.1.0 alpha, beta and release candidate. Modern and legacy MCP compatibility, extension management and request diagnostics are retained. The 46-tool catalogue and documented 2.0 public API remain compatible. [#19](https://github.com/ironlegends/AgentBridge/pull/19)

### Deprecated

- **Browser-based Microsoft Learn reader:** Existing options remain available in 2.x and are reserved for removal in 3.0.0.

[Release notes](https://github.com/ironlegends/AgentBridge/releases/tag/v2.1.0) | [Technical notes](docs/RELEASE-v2.1.0.md) | [Full comparison](https://github.com/ironlegends/AgentBridge/compare/v2.0.0...v2.1.0)

## [2.1.0-rc.1] - 2026-11-26

### Changed

- **Release candidate:** Publishes the Windows x64 candidate for workstation qualification before stable promotion. [#18](https://github.com/ironlegends/AgentBridge/pull/18)

[Prerelease notes](https://github.com/ironlegends/AgentBridge/releases/tag/v2.1.0-rc.1)

## [2.1.0-beta.1] - 2026-11-26

### Added

- **Desktop diagnostics:** Settings exposes the bounded MCP request audit. [#17](https://github.com/ironlegends/AgentBridge/pull/17)

[Prerelease notes](https://github.com/ironlegends/AgentBridge/releases/tag/v2.1.0-beta.1)

## [2.1.0-alpha.1] - 2026-11-26

### Added

- **Protocol compatibility:** Supports MCP 2026-07-28 discovery and the legacy initialization handshake.
- **External MCP extensions:** Streamable HTTP and stdio, profile-aware approvals, grouped imports and bounded session reuse.
- **Diagnostics and recovery:** Redacted request audit and release of stuck mission subtasks.

### Changed

- **Distribution:** Aligned CLI and desktop versioning, release-channel reporting and reproducibility. [#16](https://github.com/ironlegends/AgentBridge/pull/16)

[Prerelease notes](https://github.com/ironlegends/AgentBridge/releases/tag/v2.1.0-alpha.1)

## [2.0.0] - 2026-11-25

### Added

- **Windows portable desktop:** First stable Windows 10/11 x64 release with a native Tauri application and unified Rust MCP workstation.
- **Unified 46-tool catalogue:** Mission, desktop and diagnostic capabilities in one owner-controlled OAuth-bound catalogue.
- **Local operator controls:** Live access profiles within the startup ceiling, explicitly enabled direct process sessions, qualified isolated browser automation and optional Secure MCP Tunnel supervision.

[Release notes](https://github.com/ironlegends/AgentBridge/releases/tag/v2.0.0) | [Technical notes](docs/RELEASE-v2.0.0.md)
