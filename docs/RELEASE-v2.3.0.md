# Agent Bridge 2.3.0 for Windows x64

The desktop runs in Tauri and uses the system WebView2 runtime. The portable ZIP includes Node.js, Playwright 1.65.1, Chromium and the native Windows browser helpers. The setup uses standard HTML controls and supports pointer and touch input.

## What changed

- The desktop computes session status in Rust. Mission members can copy a handoff. Operators can inspect redacted request history.
- Operators can import and revoke documentary skills. Approved extension results support field filtering, credential masking and a bounded cache for reads. Revocation waits for affected backends.
- The foreground workspace exposes 22 tools. The authenticated unified Windows workstation exposes 46. Operators can select a smaller startup catalogue for core, code, desktop, automation or extensions. These catalogues overlap.
- The documented workstation catalogue has a new fingerprint. Select it locally and grant fresh OAuth consent on each client. The previous catalogue remains selectable for compatibility. See [the tool reference](TOOLS.md).
- Dependabot tracks the Rust workspaces, browser worker and GitHub Actions. The portable package updates its Rust dependencies and pinned browser runtime.

## Distribution and verification

Windows x64 portable is the supported target. Linux and macOS remain experimental. Windows ARM64 and the installer lack distribution qualification. This public snapshot excludes the experimental mobile controls and unattended provider review.

Verify the detached signature on the checksum list with the project's release public key. Then compare each archive you downloaded with its signed entry. See the [verification commands](RELEASE-v2.2.0.md#verify-a-download).
