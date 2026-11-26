//! One authorized preparation-only public documentation walkthrough.
//! No MCP service, OAuth, terminal session, personal profile or publication.
use agent_bridge::walkthroughs::preparation_once;

fn main() -> std::process::ExitCode {
    let mut args = std::env::args();
    let _program = args.next();
    let Some(home_url) = args.next() else {
        eprintln!("Usage: cargo run -p agent-bridge --example public_learn_navigation -- <explicit-learn-url>");
        return std::process::ExitCode::FAILURE;
    };
    if args.next().is_some() {
        eprintln!("Exactly one locally approved public documentation URL is required.");
        return std::process::ExitCode::FAILURE;
    }
    match preparation_once(&home_url) {
        Ok(result) => {
            println!("{}", result);
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Public documentation walkthrough failed: {:?}", error.kind());
            std::process::ExitCode::FAILURE
        }
    }
}
