# Rust Platform Coverage

This guide covers the CLI's Unix browser transport, workspace handles and scoped window adapters, plus the separate native operator panel. Availability depends on startup choices, installed software, graphical session and OS permissions. Interactive permission flows have their own qualification gates.

## Capability matrix

| Capability | Windows | macOS | Linux |
| --- | --- | --- | --- |
| Workspace file metadata | Handle-based implementation | Verified directory-handle implementation | Verified directory-handle implementation |
| Fixed project metadata child | Restricted-token child with qualified handles | Private Unix socket and SCM_RIGHTS directory descriptor | Private Unix socket and SCM_RIGHTS directory descriptor |
| Direct shell/program sessions | Explicit fully-unlocked workstation; owned Job | Explicit fully-unlocked workstation; owned process group | Explicit fully-unlocked workstation; owned process group |
| Chrome interactive DOM | Private inherited handles | Private CDP descriptors 3/4 | Private CDP descriptors 3/4 |
| Chrome document reader | Bounded document renderer | Native --dump-dom with bounded stdout | Native --dump-dom with bounded stdout |
| Chrome project upload/download | Existing verified project transfer implementation | Explicitly unavailable | Explicitly unavailable |
| Scoped desktop inspection | Existing Win32 backend | Accessibility (AX) backend | Local X11 backend |
| Window-only screenshot | Existing WM_PRINT capture | Unavailable | Existing XComposite window pixmap, with supported TrueColor format |
| Dedicated Agent Desktop for scoped automation | Existing Win32 desktop capability | Unavailable | Unavailable |
| Authenticated Workstation operator API | IPv4 loopback with cooperative Stop | Same API when enabled | Same API when enabled |
| Tauri operator panel | Native build and test evidence on Windows | WKWebView platform prerequisite. Native panel qualification pending. | WebKitGTK platform prerequisite. Native panel qualification pending. |
| Attached panel Start / Restart | Requires an existing validated current-user Windows task. Authenticated Stop remains available if the supervisor is unavailable. | Use the external launcher. The API supports authenticated Stop. | Use the external launcher. The API supports authenticated Stop. |
| Binary distribution preparation | Standalone CLI ZIP receives separate qualification. Native panel installers are pending. | Native package and installer qualification pending | Native package and installer qualification pending |

The restricted process provider does not acquire arbitrary Unix shell or program execution. The fixed metadata diagnostic receives a clone of the actual workspace root handle and reconstructs only its read-only facade. Its former blanket Unix project-handle refusal is removed. Direct processes are a separate startup opt-in described in [WORKSTATION-MODES.md](WORKSTATION-MODES.md).

## Native Chrome

The Unix interactive transport launches Chrome with `posix_spawn`, passes CDP requests on descriptor 3 and reads responses on descriptor 4. It uses NUL-delimited protocol messages and does not expose a TCP debugging port. The separate documentary reader uses native `--dump-dom` with bounded stdout instead of the CDP descriptors. Descriptor remapping handles overlapping source descriptors, closes unrelated inherited descriptors and keeps process-group ownership until cleanup is verified.

Chrome must be available at a supported installation path:

- macOS: `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome` or `/Applications/Chromium.app/Contents/MacOS/Chromium`.
- Linux: `/opt/google/chrome/chrome`, `/usr/lib/chromium/chromium` or `/usr/lib/chromium-browser/chromium-browser`.

The executable and its ancestors must pass ownership, type and permission checks. Any non-sticky ancestor writable by its group or by everyone is refused; the implementation does not change installation permissions. A macOS `/Applications` directory in mode `0775` is refused even when its group is `admin`; there is no privileged-group allowlist. Required platform spawn extensions are resolved before launching a browser. If an extension is absent, the browser capability fails closed while the rest of the CLI remains usable.

Profiles are Bridge-owned directories, separate from personal profiles. Temporary profiles are private; persistent profile IDs stay under the private settings directory. Cleanup uses retained directory identities and relative operations, never follows Chrome singleton symlinks, and refuses a replaced root or exceeded traversal/time budget.

Interactive DOM operations, page scope, observation consumption, dialogs and capture use the common browser implementation. Unix project file upload and download return `UNIX_PROJECT_BROWSER_TRANSFERS_UNAVAILABLE`; they do not silently substitute ambient pathname access. A browser test's local skip because Chrome is absent is not a successful native-browser qualification.

## Local window selection

Scoped window selection uses the operating-system adapter and its local approval flow. The Tauri operator panel, the Workstation's local operator listener and the Win32 Dedicated Agent Desktop are distinct capabilities. See [the panel attachment and lifecycle contract](WORKSTATION-MODES.md).

Pass `--local-window-read <backend> <absolute-executable> <class-or-bundle> <exact-title>` at local startup. The target must already exist in the foreground. Its executable, process incarnation, class or bundle and exact title are verified before native consent. The agent cannot choose a different PID, window identifier or script through MCP.

Both Unix backends expose:

- `desktop_ui_windows`: only the selected window, represented by an opaque identifier.
- `desktop_ui_snapshot`: a bounded tree of at most 200 nodes and a single-use observation valid for 30 seconds.
- `desktop_ui_action`: only the operations advertised by that backend, after fresh identity validation.

A changed target, foreign child, expired observation or revoked connection is refused. There is no fallback to enumerating unrelated windows, taking a full-desktop screenshot or injecting global keyboard/pointer input.

### macOS Accessibility and TCC

Example for a locally selected TextEdit window:

```sh
agent-bridge stdio /path/to/private/missions.sqlite \
  --workspace /path/to/your-project \
  --local-window-read macos \
  /System/Applications/TextEdit.app/Contents/MacOS/TextEdit \
  com.apple.TextEdit "Notes.txt"
```

Use the actual physical executable path, exact `CFBundleIdentifier` from the application bundle and exact foreground title. Accessibility permission must already be granted to the local agent through macOS settings. Missing permission returns `WINDOW_TCC_ACCESSIBILITY_REQUIRED`; the adapter does not bypass TCC or automatically prompt for that OS grant.

After target verification, a fixed AppleScript asks for local consent with Deny as the default. Selection values are literal arguments, never interpolated script source. The adapter retains the AX element, validates Core Foundation types before calling AX APIs, and verifies process/bundle identity again at use. Bundle metadata is read once from a bounded regular file without following a final symlink or blocking on a FIFO.

Supported operations are `wait`, `invoke` via AXPress, and `set_value` on writable, non-sensitive AXTextField/AXTextArea controls. Screenshots are unavailable because the candidate does not establish a proven AX-to-native-window capture identity. No screen-recording permission is requested for a nonexistent capture capability.

Native CI covers the macOS build, Core Foundation type refusals, bounded bundle-file reads and AppleScript argument/compiler behavior. A real operator-consented TCC session and visible AX action must still be exercised before claiming interactive macOS qualification.

### Linux X11

Example for a selected application on the local display:

```sh
agent-bridge stdio /path/to/private/missions.sqlite \
  --workspace /path/to/your-project \
  --local-window-read x11:0 /physical/path/to/app WMClassExact "Exact title"
```

The backend display must match `DISPLAY`; `x11:0.1` selects screen 1 of display 0. Only a local Unix-domain X11 connection is accepted. A Wayland session, remote X server, missing graphical session or mismatched display is refused before consent. The adapter requires XRes 1.2 to obtain server-verified client PID ownership, then checks the process incarnation and executable through `/proc`. It does not trust a client-written `_NET_WM_PID` property.

The snapshot is an X11 child-window hierarchy, not a general accessibility tree. A child belonging to another process is refused. Capture requires an already composited, window-owned XComposite pixmap with a supported TrueColor pixel format. Agent Bridge does not redirect the window or read root-window pixels; absent capture support is reported as absent.

Supported actions are `wait`, a centered left `click` on the selected control window, and `send_keys` for Enter, Escape, Tab and the four arrows. These are targeted XSendEvent messages. Receipts state `dispatched: true` and `effect_verified: false`: applications may ignore synthetic events. XTest and global input are not used.

Critical X operations use a bounded server grab. An independent deadline watchdog closes the owned connection if the operation cannot finish, releasing the grab and permanently revoking that connection. CPU-heavy image conversion happens after the grab is released.

Common refusals include `WINDOW_WAYLAND_UNSUPPORTED`, `WINDOW_GRAPHICAL_SESSION_REQUIRED`, `WINDOW_LOCAL_X11_REQUIRED`, `WINDOW_DISPLAY_MISMATCH`, `WINDOW_FOREGROUND_REQUIRED`, `WINDOW_IDENTITY_CHANGED` and `WINDOW_FOREIGN_CHILD_REFUSED`.

## Native validation

Linux tests use a disposable Xvfb server, not the operator's display. They exercise window-only capture while another window overlaps it, targeted input, XID replacement, foreign-PID children, missing composite capture, connection timeouts and independent server-grab expiration. Xvfb, XKB utilities and base fonts must be installed for the full Linux suite.

On WSL, the user-session X11 socket mount may be unsuitable for a disposable Xvfb server. Development validation used a separate mount namespace with a private socket directory, then dropped back to the ordinary user for Cargo and Xvfb. It did not alter WSLg, the user's display or its sockets.

The hosted images used during qualification contain deliberately writable system browser paths: the Ubuntu image exposes `/opt`, Chrome's directory and its executable as `0777`, while the macOS image exposes `/Applications` as `0775`. Production qualification correctly refuses those installations. On macOS, CI therefore copies the existing browser into a new private directory, verifies copy bounds and internal symlinks, and restricts only the copy's permissions. Linux prepares the entire browser and sandbox helper from one Google Chrome package authenticated by APT against the pinned Google signing primary. It downloads and extracts that package without installing it or executing its maintenance scripts. Neither path repairs the global installation or changes Chrome's sandbox arguments.

The Linux preparation uses fresh root-private staging and APT configuration; it does not load global APT hooks, add a trust key to the host or update global package state. Acquisition runs as root inside that private configuration so the stage and signing material remain inaccessible to other users; this deliberately forgoes APT's `_apt` separation only for the ephemeral fixture preparation. The browser tests themselves still run as the ordinary test user. Only the authenticated package's sandbox helper receives root ownership and mode `4755`, through its newly created and verified file descriptor. Publication refuses replacement of an existing name, revalidates the parent identities and revokes the helper's setuid mode if final publication checks fail. Package version and SHA-256, signing primary and helper SHA-256 are recorded in the CI log.

The private executable is selected only by a scoped, thread-local guard compiled with `cfg(test)` on Unix. The production CLI and release binary contain no environment override. A requested invalid fixture fails instead of falling back, and separate tests keep checking the original system qualification and guard isolation. This qualifies the native transport against a real private Chrome installation; it does not claim the hosted image's unsafe system path is acceptable.

CI sets `AGENT_BRIDGE_REQUIRE_NATIVE_CHROME=1` for Unix workspace tests. Missing or refused Chrome is then a failure, ensuring that an apparently green matrix cannot hide two locally skipped browser tests. See the current evidence and remaining release gates in [RELEASE-v2.2.0.md](RELEASE-v2.2.0.md).
