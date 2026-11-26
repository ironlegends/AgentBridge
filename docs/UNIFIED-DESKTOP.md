# Unified native desktop workstation

The configured Agent Bridge desktop application owns the workstation runtime and its optional secure tunnel. The Tauri interface calls the operator controls in process. It does not need an operator HTTP listener.

The MCP/OAuth listener remains on the configured loopback port (18856 in the example below). The native interface has no separate TCP port. WebView processes and the optional tunnel client are managed components of the application; they do not represent additional independently configured Agent Bridge services.

## Using the desktop interface

The home screen shows the local bridge state, current access mode, workspace, and
pending activity. The displayed web configuration and tunnel process state do
not by themselves prove remote connectivity.

Tasks, Approvals, and Settings diagnostics refresh automatically while their
page is open. The home state refreshes independently. Use the refresh icon for
an immediate manual read. Automatic reads do not submit approval or extension
decisions, and unsaved settings and OAuth callback drafts are preserved. An
updated proposal requires a fresh review. Task Room progress uses the reported
completed and total steps; it is not estimated. The interface honors the
system's reduced-motion preference.

## Choose the operating mode

| Configuration | Owner and operator transport |
| --- | --- |
| Valid native `workstation-app.json` | Desktop owns the embedded workstation; native IPC controls the same live state as MCP. |
| Explicit `--config` missing or invalid, or default native config present but invalid | Startup fails with a diagnostic. It does not fall back to another database or legacy gateway. |
| Default native config absent; explicit legacy operator connection present | Existing attached-panel mode connects to an externally owned workstation. |
| Neither native nor attached configuration selected | Existing standalone local gateway mode remains available. |

Do not start native mode while the previous CLI owns the same database, OAuth state or port. Stop the previous owner first. A port collision does not authorize the application to adopt or terminate another process.

## Native configuration

The default native file is `%LOCALAPPDATA%/AgentBridge/workstation-app.json` on Windows. An explicit absolute path can be selected:

```powershell
& 'C:/path/to/agent-bridge-desktop-app.exe' --config 'C:/path/to/workstation-app.json'
```

Add `--background` for a login task. A foreground second launch shows the existing window; a background second launch preserves its visibility. Neither starts a second backend nor replaces the running instance's configuration.

The versioned configuration contains the existing workstation CLI arguments without the executable name. Unknown configuration fields are rejected. Paths should be absolute; keep private state outside the project repository.

```json
{
  "version": 1,
  "arguments": [
    "gemini",
    "workstation",
    "C:/Users/you/AgentBridge/private/database/missions.sqlite",
    "C:/Users/you/AgentBridge/private/oauth-workstation",
    "https://bridge.example",
    "18856",
    "--project",
    "C:/Users/you/src/project",
    "--profile",
    "read-only",
    "--missions-state",
    "C:/Users/you/AgentBridge/private/oauth-missions",
    "--missions-origin",
    "https://missions.example",
    "--settings-dir",
    "C:/Users/you/AgentBridge/private/settings",
    "--lifecycle-dir",
    "C:/Users/you/AgentBridge/private/lifecycle"
  ],
  "tunnel": null
}
```

For a new installation, prepare the disjoint database, settings, lifecycle and OAuth directories using the [private-state setup](QUICKSTART.md#3-directory-layout-three-disjoint-roots). Keep the database in its own subdirectory so its protected boundary does not contain the other state roots.

Use the startup profile and capability flags approved for your existing workstation. The native interface can change the active profile only within that startup ceiling. Migrating the owner does not imply a change of project, authority or enabled tools.

Native mode does not open the operator listener, including when a migrated argument vector still contains a legacy `--ui-port`. Omit that option in a new native configuration. Headless CLI users can continue to request the authenticated HTTP operator console explicitly.

## Optional managed tunnel

For an existing secure tunnel, replace `null` with the validated local connection details:

```json
{
  "program": "C:/path/to/tunnel-client.exe",
  "sha256": "<64 hexadecimal characters for that executable>",
  "profile": "your-existing-profile",
  "profileDir": "C:/path/to/profiles",
  "stateDir": "C:/path/to/tunnel-state",
  "dpapiKeyPath": "C:/path/to/credentials/runtime-key.dpapi",
  "expectedMcpUrl": "https://bridge.example/mcp",
  "expectedOrigin": "https://bridge.example"
}
```

This is a reference to an existing connection, not a request to create or register a remote tunnel. The foreground client uses `run --profile <name> --profile-dir <directory>`. Preserve the profile's remote identity and the HTTPS route needed for OAuth and Gemini.

The profile must match the expected MCP URL and origin and refer to the key by `env:AGENT_BRIDGE_TUNNEL_API_KEY`. The application reads the user-protected DPAPI credential in native code and supplies it only to the tunnel child's environment. No plaintext credential belongs in this configuration, the renderer or a command line. The child also receives its state directory and the explicit HTTPS OAuth forwarding settings.

Backend readiness, a live tunnel process and a successful remote client call are separate facts. A live child does not by itself prove that ChatGPT or Gemini can connect. Recovery after a network interruption must remain tied to the current runtime generation; Stop cancels further launches before releasing ownership.

## Window and lifecycle behavior

| Action | Result in native mode |
| --- | --- |
| Close or minimize main window | Hide the window; the running workstation continues. |
| Foreground second launch | Show the existing instance; preserve its runtime, configuration and tunnel. |
| Background second launch | Preserve existing visibility and ownership. |
| Stop | Stop the managed tunnel and workstation; keep the interface available. |
| Start | Start a new generation only after the prior owner has fully released its resources. |
| Restart | Serialize Stop and Start; do not overlap generations. |
| Quit Agent Bridge | Request the same orderly shutdown and exit only when cleanup is confirmed. |

An incomplete stop remains visible as an error or transition. It must not be represented as a successful Stop that permits another owner. Startup or tunnel errors should remain diagnosable when the application was launched in background mode.

Internal metadata and lifecycle helper invocations are validated and handled before UI or single-instance initialization. Restricted process catalogues still require exact executable identity and SHA-256. If a catalogue already authorizes a self-executable diagnostic, qualify and update that existing entry for the actual deployed desktop image. An empty catalogue stays empty.

## Migrate an existing Windows installation

Use a recorded, reversible handoff. The source worktree used to build the application is not necessarily the project directory authorized by the running workstation.

1. Build and qualify the exact executable and record its source commit and SHA-256. Exercise the real desktop executable's private helper protocols with isolated state.
2. Preserve the existing argument vector, database, OAuth state, public origin, MCP port, mission origin, settings, capability flags and startup ceiling. Record task definitions, configuration bytes and permissions, relevant shortcuts, and logical SQLite state. Keep logs containing operator tokens private.
3. Stop the old workstation through its authenticated operator action. Verify that its exact process has exited and both old listener ports have closed.
4. Stop the project tunnel through its verified local owner, then close the old attached panel. Disable the old project startup tasks after preserving their definitions.
5. With previous owners absent, install the new configuration and one current-user, non-elevated login task pointing to the desktop executable with `--config` and `--background`. Use the same executable and configuration in the foreground shortcut.
6. Start once. Confirm that the desktop executable owns MCP port 18856 and that no operator listener remains on port 18890. Verify the native interface, second launch, hide, Stop/Start and Restart behavior.
7. Exercise actual ChatGPT and Gemini native tools, including an independently checked UTF-8 file. Compare logical database contents and confirm that existing OAuth grants still work.
8. Perform the next real Windows reboot deliberately and verify the single startup task after login. Local lifecycle tests do not substitute for this last observation.

A managed tunnel may use its own loopback health socket. An outbound extension authorization can also need a temporary callback listener. These do not create a second permanent Agent Bridge operator port.

## Rollback

Keep the prior binaries, original native-config presence or absence, legacy connection file, task definitions and shortcut targets. Stop the unified application and confirm the embedded runtime and owned tunnel have fully exited before restoring the old startup arrangement. Never delete an unknown ownership marker to force progress.

Restore a previously authorized command catalogue if it was changed during the migration. Do not overwrite the database or OAuth state simply because ownership changes back; verify their continuity first. Restore the absence of the native config when returning to an attached-panel installation that previously had no such file.

Keep an independently working local recovery channel available until the new application and remote connections are verified.

## Build and verify

The CLI workspace and native desktop workspace have separate lockfiles:

```sh
cargo test --locked --workspace
cargo test --locked --manifest-path app/src-tauri/Cargo.toml
node --test app/tests/live-profile.test.cjs
cargo build --locked --release -p agent-bridge
cargo build --locked --release --manifest-path app/src-tauri/Cargo.toml
```

On Windows, tests must run as a standard non-elevated user because lifecycle policy deliberately rejects elevated execution. Use the repository's required CI gates and include the desktop dependency closure in any packaged third-party notices. Record actual platform and executable evidence; a successful library test alone does not qualify Windows login behavior or private child dispatch in the shipped GUI executable.

## Windows operation without visible consoles

The login task launches the GUI executable directly with --background. Normal operation, private helpers and automatic tunnel recovery must remain free of visible command windows or transient console flashes. Required WebView and tunnel children remain managed by the application; unnecessary shell wrappers are removed from the product launch path.

An explicit foreground launch or operator action may show the native interface. Background startup, a second background invocation and recovery preserve visibility. Failures must remain available in private logs and native diagnostics, including child exit codes and redirected output, without opening a console as a fallback.

Before accepting a migration, verify these properties with the actual deployed executable and native window/process observations during startup and recovery. Preserve the existing MCP/tunnel route and OAuth sessions used from the iPhone. A successful remote MCP call establishes the tested route; an iPhone-side interaction and a real Windows reboot are separate observations and should be reported separately when not yet performed.
