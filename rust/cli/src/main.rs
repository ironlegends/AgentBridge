use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match agent_bridge::run_cli(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("agent-bridge: {error}");
            ExitCode::FAILURE
        }
    }
}
