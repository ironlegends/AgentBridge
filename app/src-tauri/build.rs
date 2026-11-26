const COMMANDS: &[&str] = &[
    "get_panel_state", "save_panel_settings", "set_permission_profile",
    "initialize_local_state", "start_or_restart_gateway", "stop_gateway",
    "get_missions_snapshot", "get_oauth_pending", "enable_oauth_enrollment",
    "approve_oauth_request", "decide_extension_request", "get_skills_overview",
    "run_skill_action", "get_diagnostics", "quit_app",
];

fn main() {
    // Release packaging scans the frontend named by tauri.conf.json. A merged
    // TAURI_CONFIG, also one set through Cargo's [env], could embed another.
    println!("cargo:rerun-if-env-changed=TAURI_CONFIG");
    println!("cargo:rerun-if-env-changed=AGENT_BRIDGE_RELEASE_CHANNEL");
    if std::env::var_os("AGENT_BRIDGE_RELEASE_CHANNEL").is_some() && std::env::var_os("TAURI_CONFIG").is_some() {
        panic!("TAURI_CONFIG is not admitted for release packaging");
    }
    tauri_build::try_build(tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)))
        .expect("desktop command permission manifest");
}
