# Agent Bridge native resources

The native helper is an owned, private IPC child of Agent Bridge. It does not run
the DeskMCP application, gateway, control panel or file-based coordinator.

`Hud.cs` adapts the window mover and safety overlay from DeskMCP's
`control-panel/wpf/AgentDesktopControl.cs`. `NativeApi.cs` adapts desktop API
bindings from `agent-desktop-host/Program.cs`. Baseline: DeskMCP 0.9.17,
commit `e614f938db7f592566384c87a86af2f4ec74cca7`, Apache-2.0. The Apache license is
included in `notices/DESKMCP-APACHE-2.0.txt`. Agent Bridge supplies the private
bounded protocol, owner heartbeat, identity validation and lease authority.

The WinApp executable is a derivative of WinApp CLI v0.5.0, Microsoft Corporation
and Contributors, source commit `fd7cb6f235fa54dd2c6e26386e65e967a2c8797a`, under
the included MIT license. It is labelled **WinApp 0.5.0 + Agent Bridge fixes**,
not the unchanged official archive. Three reviewed source patches remove implicit
focus/restoration from passive captures, add an explicitly requested,
HWND-bound background PostMessage path, and disable UIA AutoSetFocus before
explicit background semantic actions. The normal foreground behavior is preserved. Their source files,
hashes, SDK 10.0.402, NativeAOT/runtime 10.0.13 and effective build dependencies
are recorded in `WINAPP-BUILD-PROVENANCE.json`.

`libSkiaSharp.dll` is unchanged from the pinned official v0.5.0 distribution.
`WINAPP-THIRD-PARTY-NOTICES.txt` and `WINAPP-DEPENDENCIES.json` preserve the complete
qualified WinApp/Skia notices and their provenance. The package also includes
the license and third-party notices from the effective .NET 10.0.13 runtime and
AOT packages. Build-only debugging packages are excluded from the runtime
bundle. Executable and DLL hashes are enforced by `package-native-tools.py`
and the Rust resource loader.

VirtualDesktopAccessor, Ciantic and contributors, is MIT-licensed. Source commit:
`8172097993b1194e3d5e2ff38421ebb06f867b6c`. The package includes the upstream MIT
license, source commit and fixed DLL pin. Desktop 1 is never leased or removed.

The helper is a self-contained .NET 10.0.12 WPF WinExe. Its package includes the
.NET license and third-party notices from the selected SDK. It exposes no network
listener and requests the ordinary caller token (`asInvoker`, `uiAccess=false`).
