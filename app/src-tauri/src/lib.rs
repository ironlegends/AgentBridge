mod backend;
mod launch;
mod native_config;
mod native_runtime;
mod native_tunnel;
#[cfg(windows)]
mod native_windows;
mod operator_connection;
mod state;
mod status_card;
mod supervisor;
#[cfg(test)]
mod opener_permissions_tests;

use backend::GatewayIntent;
use serde_json::Value;
use state::{default_app_data_root, AppRuntime, PanelSettings};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, PhysicalPosition, State, WebviewWindow, WindowEvent};

pub fn initialize_native_diagnostics() -> Result<(), String> {
    #[cfg(windows)]
    native_windows::initialize_diagnostics(&default_app_data_root())?;
    eprintln!("native-entry pid={}", std::process::id());
    Ok(())
}

struct QuitFlag(AtomicBool);
struct QuitInProgress(AtomicBool);

struct TrayControls {
    start: MenuItem<tauri::Wry>,
    restart: MenuItem<tauri::Wry>,
    stop: MenuItem<tauri::Wry>,
}

fn update_tray_controls(app: &AppHandle, panel: &Value) {
    let Some(items) = app.try_state::<TrayControls>() else { return; };
    let external = panel["gateway"]["external"] == true || panel["gateway"]["native"] == true;
    let controls = &panel["gateway"]["controls"];
    let _ = items.start.set_enabled(external && controls["canStart"] == true);
    let _ = items.restart.set_enabled(!external || controls["canRestart"] == true);
    let _ = items.stop.set_enabled(!external || controls["canStop"] == true);
    if let Some(tray) = app.tray_by_id("agent-bridge-tray") {
        let attention = panel["gateway"]["lastError"].is_string() || panel["tunnel"]["error"].is_string();
        let _ = tray.set_tooltip(Some(if attention { "Agent Bridge — attention required" } else { "Agent Bridge" }));
    }
}

fn spawn_tray_lifecycle(app: &AppHandle, runtime: &Arc<AppRuntime>, intent: Option<GatewayIntent>) {
    let app = app.clone();
    let runtime = Arc::clone(runtime);
    tauri::async_runtime::spawn(async move {
        let result = run_backend(move || {
            if let Some(intent) = intent { backend::start_or_restart_gateway(&runtime, intent) }
            else { backend::stop_gateway(&runtime) }
        }).await;
        match result {
            Ok(panel) => {
                update_tray_controls(&app, &panel);
                let _ = app.emit("workstation-state", &panel);
            }
            Err(error) => { let _ = app.emit("workstation-error", error); }
        }
    });
}

async fn run_backend<T: Send + 'static>(
    action: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(action).await
        .map_err(|_| "Native operator task failed.".to_owned())?
}

#[tauri::command]
async fn get_panel_state(app: AppHandle, runtime: State<'_, Arc<AppRuntime>>) -> Result<Value, String> {
    let runtime = Arc::clone(runtime.inner());
    let panel = run_backend(move || backend::get_panel_state(&runtime)).await?;
    update_tray_controls(&app, &panel);
    Ok(panel)
}

#[tauri::command]
async fn save_panel_settings(
    runtime: State<'_, Arc<AppRuntime>>,
    settings: PanelSettings,
) -> Result<Value, String> {
    let runtime = Arc::clone(runtime.inner());
    run_backend(move || backend::save_panel_settings(&runtime, settings)).await
}

#[tauri::command]
async fn set_permission_profile(
    runtime: State<'_, Arc<AppRuntime>>,
    profile: String,
    confirmed: bool,
) -> Result<Value, String> {
    let runtime = Arc::clone(runtime.inner());
    run_backend(move || backend::set_permission_profile(&runtime, &profile, confirmed)).await
}

#[tauri::command]
async fn initialize_local_state(runtime: State<'_, Arc<AppRuntime>>) -> Result<Value, String> {
    let runtime = Arc::clone(runtime.inner());
    run_backend(move || backend::initialize_local_state(&runtime)).await
}

#[tauri::command]
async fn start_or_restart_gateway(
    app: AppHandle, runtime: State<'_, Arc<AppRuntime>>, intent: Option<GatewayIntent>,
) -> Result<Value, String> {
    let runtime = Arc::clone(runtime.inner());
    // Older clients omit intent. Only an explicit restart may shut down an attached service.
    let panel = run_backend(move || backend::start_or_restart_gateway(&runtime, intent.unwrap_or_default())).await?;
    update_tray_controls(&app, &panel);
    Ok(panel)
}

#[tauri::command]
async fn stop_gateway(app: AppHandle, runtime: State<'_, Arc<AppRuntime>>) -> Result<Value, String> {
    let runtime = Arc::clone(runtime.inner());
    let panel = run_backend(move || backend::stop_gateway(&runtime)).await?;
    update_tray_controls(&app, &panel);
    Ok(panel)
}

#[tauri::command]
async fn get_missions_snapshot(runtime: State<'_, Arc<AppRuntime>>) -> Result<Value, String> {
    let runtime = Arc::clone(runtime.inner());
    run_backend(move || backend::get_missions_snapshot(&runtime)).await
}

#[tauri::command]
async fn get_mission_handoff(runtime: State<'_, Arc<AppRuntime>>, mission_id: String, revision: i64) -> Result<Value, String> {
    let runtime = Arc::clone(runtime.inner());
    run_backend(move || backend::get_mission_handoff(&runtime, &mission_id, revision)).await
}

#[tauri::command]
async fn get_oauth_pending(runtime: State<'_, Arc<AppRuntime>>) -> Result<Value, String> {
    let runtime = Arc::clone(runtime.inner());
    run_backend(move || backend::get_oauth_pending(&runtime)).await
}

#[tauri::command]
async fn enable_oauth_enrollment(runtime: State<'_, Arc<AppRuntime>>) -> Result<Value, String> {
    let runtime = Arc::clone(runtime.inner());
    run_backend(move || backend::enable_oauth_enrollment(&runtime)).await
}

#[tauri::command]
async fn approve_oauth_request(
    runtime: State<'_, Arc<AppRuntime>>,
    request_id: String,
    expected_callback: String,
    expected_capability: Option<Value>,
) -> Result<Value, String> {
    let runtime = Arc::clone(runtime.inner());
    run_backend(move || backend::approve_oauth_request(&runtime, &request_id, &expected_callback, expected_capability)).await
}

#[tauri::command]
async fn decide_extension_request(
    runtime: State<'_, Arc<AppRuntime>>,
    request_id: String,
    approve: bool,
    reviewed: bool,
) -> Result<Value, String> {
    let runtime = Arc::clone(runtime.inner());
    run_backend(move || backend::decide_extension_request(&runtime, &request_id, approve, reviewed)).await
}

#[tauri::command]
async fn test_extension_connection(
    runtime: State<'_, Arc<AppRuntime>>,
    server: String,
) -> Result<Value, String> {
    let runtime = Arc::clone(runtime.inner());
    run_backend(move || backend::test_extension_connection(&runtime, &server)).await
}

#[tauri::command]
async fn reload_extensions(runtime: State<'_, Arc<AppRuntime>>) -> Result<Value, String> {
    let runtime = Arc::clone(runtime.inner());
    run_backend(move || backend::reload_extensions(&runtime)).await
}

#[tauri::command]
async fn get_skills_overview(runtime: State<'_, Arc<AppRuntime>>) -> Result<Value, String> {
    let runtime = Arc::clone(runtime.inner());
    run_backend(move || backend::get_skills_overview(&runtime)).await
}

#[tauri::command]
async fn run_skill_action(
    runtime: State<'_, Arc<AppRuntime>>,
    action: String,
    name: String,
    version: Option<String>,
) -> Result<Value, String> {
    let runtime = Arc::clone(runtime.inner());
    run_backend(move || backend::run_skill_action(&runtime, &action, &name, version)).await
}

#[tauri::command]
async fn get_session_history(runtime: State<'_, Arc<AppRuntime>>, boot_id: String, session_id: String) -> Result<Value, String> {
    let runtime = Arc::clone(runtime.inner());
    run_backend(move || backend::get_session_history(&runtime, &boot_id, &session_id)).await
}

#[tauri::command]
async fn get_sessions(runtime: State<'_, Arc<AppRuntime>>) -> Result<Value, String> {
    let runtime = Arc::clone(runtime.inner());
    run_backend(move || backend::get_sessions(&runtime)).await
}

#[tauri::command]
async fn get_diagnostics(runtime: State<'_, Arc<AppRuntime>>) -> Result<Value, String> {
    let runtime = Arc::clone(runtime.inner());
    run_backend(move || backend::get_diagnostics(&runtime)).await
}

async fn finish_exit(app: AppHandle, runtime: Arc<AppRuntime>, exit_code: i32) -> Result<(), String> {
    let pending = app.state::<QuitInProgress>();
    if pending.0.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return Err("Agent Bridge is already stopping. Wait for cleanup to finish.".into());
    }
    runtime.native_runtime.set_closing(true);
    let owned = Arc::clone(&runtime);
    let result = run_backend(move || {
        if owned.native_config.is_configured() {
            owned.native_runtime.stop()?;
        } else if !owned.operator.is_configured() {
            backend::stop_gateway(&owned)?;
        }
        Ok(Value::Null)
    }).await;
    if let Err(error) = result {
        runtime.native_runtime.set_closing(false);
        pending.0.store(false, Ordering::Release);
        report_runtime_error(&app, &runtime, "quit-incomplete", &error);
        return Err(error);
    }
    app.state::<QuitFlag>().0.store(true, Ordering::Release);
    runtime.record_event("quit-clean");
    app.exit(exit_code);
    Ok(())
}

fn request_quit(app: &AppHandle, runtime: &Arc<AppRuntime>) {
    let app = app.clone();
    let runtime = Arc::clone(runtime);
    tauri::async_runtime::spawn(async move { let _ = finish_exit(app, runtime, 0).await; });
}

#[tauri::command]
async fn quit_app(app: AppHandle, runtime: State<'_, Arc<AppRuntime>>) -> Result<(), String> {
    finish_exit(app, Arc::clone(runtime.inner()), 0).await
}

fn report_runtime_error(app: &AppHandle, runtime: &AppRuntime, kind: &str, error: &str) {
    runtime.record_event(kind);
    eprintln!("native-error: {error}");
    if let Some(tray) = app.tray_by_id("agent-bridge-tray") {
        let _ = tray.set_tooltip(Some("Agent Bridge — attention required"));
    }
    let _ = app.emit("workstation-error", error);
}

fn start_native_monitor(app: AppHandle, runtime: Arc<AppRuntime>) {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if app.state::<QuitFlag>().0.load(Ordering::Acquire) { break; }
            let current = Arc::clone(&runtime);
            let observed = tauri::async_runtime::spawn_blocking(move || {
                if current.native_runtime.observe_termination() {
                    current.record_event("native-state-changed");
                    backend::get_panel_state(&current).ok()
                } else { None }
            }).await;
            if let Ok(Some(panel)) = observed {
                update_tray_controls(&app, &panel);
                if panel["gateway"]["lastError"].is_string() || panel["tunnel"]["error"].is_string() {
                    if let Some(tray) = app.tray_by_id("agent-bridge-tray") {
                        let _ = tray.set_tooltip(Some("Agent Bridge — attention required"));
                    }
                }
                let _ = app.emit("workstation-state", panel);
            }
        }
    });
}

fn position_bottom_right_above_taskbar(window: &WebviewWindow) {
    let monitor = window
        .current_monitor()
        .ok()
        .flatten()
        .or_else(|| window.primary_monitor().ok().flatten());
    let Some(monitor) = monitor else {
        return;
    };
    let work = monitor.work_area();
    let scale = monitor.scale_factor();
    let margin = (12.0 * scale).round() as i32;
    let size = window.outer_size().unwrap_or(tauri::PhysicalSize {
        width: (356.0 * scale).round() as u32,
        height: (516.0 * scale).round() as u32,
    });
    let x = work.position.x + (work.size.width as i32) - (size.width as i32) - margin;
    let y = work.position.y + (work.size.height as i32) - (size.height as i32) - margin;
    let _ = window.set_position(PhysicalPosition::new(
        x.max(work.position.x),
        y.max(work.position.y),
    ));
}

fn show_main_window(window: &WebviewWindow) {
    let _ = window.unminimize();
    position_bottom_right_above_taskbar(window);
    let _ = window.show();
    let _ = window.set_focus();
}

fn toggle_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let visible = window.is_visible().unwrap_or(false);
        let minimized = window.is_minimized().unwrap_or(false);
        if visible && !minimized {
            let _ = window.hide();
        } else {
            show_main_window(&window);
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            if launch::foreground_activation(&args) {
                if let Some(window) = app.get_webview_window("main") { show_main_window(&window); }
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(QuitFlag(AtomicBool::new(false)))
        .manage(QuitInProgress(AtomicBool::new(false)))
        .setup(move |app| {
            let parsed = launch::parse(&args);
            let background = args.iter().any(|arg| arg == "--background");
            let mut selected = AppRuntime::with_native_config(default_app_data_root(),
                parsed.as_ref().ok().and_then(|options| options.config.as_deref()));
            if let Err(error) = parsed { selected.native_config = native_config::NativeConfig::Invalid(error); }
            let runtime = Arc::new(selected);
            let manages_gateway = !runtime.is_live();
            app.manage(Arc::clone(&runtime));
            let show_item = MenuItem::with_id(app, "show", "Open Agent Bridge", true, None::<&str>)?;
            let hide_item = MenuItem::with_id(app, "hide", "Hide to Tray", true, None::<&str>)?;
            let sep1 = PredefinedMenuItem::separator(app)?;
            let start_item = MenuItem::with_id(app, "start", "Start Workstation", false, None::<&str>)?;
            let restart_label = if manages_gateway { "Restart Gateway" } else { "Restart Workstation" };
            let restart_item = MenuItem::with_id(app, "restart", restart_label, manages_gateway, None::<&str>)?;
            let stop_item = MenuItem::with_id(app, "stop", "Stop Gateway", manages_gateway, None::<&str>)?;
            app.manage(TrayControls { start: start_item.clone(), restart: restart_item.clone(), stop: stop_item.clone() });
            let sep2 = PredefinedMenuItem::separator(app)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit Agent Bridge", true, None::<&str>)?;

            let menu = Menu::with_items(app, &[&show_item, &hide_item, &sep1])?;
            if !manages_gateway { menu.append(&start_item)?; }
            menu.append_items(&[&restart_item, &stop_item, &sep2, &quit_item])?;

            let tray_runtime = Arc::clone(&runtime);
            let mut tray_builder = TrayIconBuilder::with_id("agent-bridge-tray")
                .tooltip("Agent Bridge")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(move |app_handle, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app_handle.get_webview_window("main") {
                            show_main_window(&w);
                        }
                    }
                    "hide" => {
                        if let Some(w) = app_handle.get_webview_window("main") {
                            let _ = w.hide();
                        }
                    }
                    "start" => spawn_tray_lifecycle(app_handle, &tray_runtime, Some(GatewayIntent::Start)),
                    "restart" => spawn_tray_lifecycle(app_handle, &tray_runtime, Some(GatewayIntent::Restart)),
                    "stop" => spawn_tray_lifecycle(app_handle, &tray_runtime, None),
                    "quit" => request_quit(app_handle, &tray_runtime),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        toggle_main_window(tray.app_handle());
                    }
                });

            if let Some(icon) = app.default_window_icon() {
                tray_builder = tray_builder.icon(icon.clone());
            }
            let _tray = tray_builder.build(app)?;

            if !background {
                if let Some(main_window) = app.get_webview_window("main") { show_main_window(&main_window); }
            }
            if runtime.native_config.is_configured() {
                let handle = app.handle().clone();
                let automatic = Arc::clone(&runtime);
                tauri::async_runtime::spawn(async move {
                    let owned = Arc::clone(&automatic);
                    let result = run_backend(move ||
                        backend::initialize_native_for_app(&owned)).await;
                    match result {
                        Ok(started) => {
                            automatic.record_event("native-started");
                            match started.panel {
                                Ok(panel) => {
                                    update_tray_controls(&handle, &panel);
                                    let _ = handle.emit("workstation-state", panel);
                                }
                                Err(error) => report_runtime_error(
                                    &handle, &automatic, "native-state-deferred", &error),
                            }
                        }
                        Err(error) => {
                            report_runtime_error(&handle, &automatic, "native-start-failed", &error);
                            if background {
                                let _ = finish_exit(handle.clone(), Arc::clone(&automatic), 1).await;
                            }
                        },
                    }
                    start_native_monitor(handle, automatic);
                });
            }
            Ok(())
        })
        .on_window_event(|window, event| match event {
            WindowEvent::CloseRequested { api, .. } => {
                let quitting = window
                    .app_handle()
                    .try_state::<QuitFlag>()
                    .map(|f| f.0.load(Ordering::SeqCst))
                    .unwrap_or(false);
                if !quitting {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
            WindowEvent::Resized(_) => {
                if window.is_minimized().unwrap_or(false) {
                    let _ = window.hide();
                }
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            get_panel_state,
            save_panel_settings,
            set_permission_profile,
            initialize_local_state,
            start_or_restart_gateway,
            stop_gateway,
            get_missions_snapshot,
            get_mission_handoff,
            get_oauth_pending,
            enable_oauth_enrollment,
            approve_oauth_request,
            decide_extension_request,
            test_extension_connection,
            reload_extensions,
            get_skills_overview,
            run_skill_action,
            get_diagnostics,
            get_sessions,
            get_session_history,
            quit_app,
        ])
        .build(tauri::generate_context!())
        .unwrap_or_else(|error| {
            eprintln!("native-tauri-build-failed: {error}");
            std::process::exit(1);
        })
        .run(|app, event| {
            if let tauri::RunEvent::ExitRequested { api, .. } = event {
                if !app.state::<QuitFlag>().0.load(Ordering::Acquire) {
                    api.prevent_exit();
                    if let Some(runtime) = app.try_state::<Arc<AppRuntime>>() { request_quit(app, runtime.inner()); }
                }
            }
        });
}

#[cfg(test)]
mod native_tests;
