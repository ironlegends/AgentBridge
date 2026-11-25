#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    match agent_bridge_runtime::backend::dispatch_private_child(&args) {
        Ok(Some(code)) => std::process::exit(code),
        Ok(None) => {
            if agent_bridge_desktop_app_lib::initialize_native_diagnostics().is_err() {
                std::process::exit(1);
            }
            agent_bridge_desktop_app_lib::run();
        }
        Err(error) => {
            eprintln!("agent-bridge private child failed: {error}");
            std::process::exit(2);
        },
    }
}
