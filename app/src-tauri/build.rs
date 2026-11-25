const COMMANDS: &[&str] = &[
    "get_panel_state", "save_panel_settings", "set_permission_profile",
    "initialize_local_state", "start_or_restart_gateway", "stop_gateway",
    "get_missions_snapshot", "get_oauth_pending", "enable_oauth_enrollment",
    "approve_oauth_request", "decide_extension_request", "get_skills_overview",
    "run_skill_action", "get_diagnostics", "quit_app",
];

fn main() {
    tauri_build::try_build(tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)))
        .expect("desktop command permission manifest");
}
