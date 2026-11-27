//! Non-shipped Windows subprocess witnesses used by the actual test parents.
//! Build with cargo build -p agent-bridge --example agent_bridge_process_fixture.
//! Not a libtest target or product private role. A watchdog bounds orphan life.
#[cfg(not(windows))]
fn main() { eprintln!("Windows-only subprocess fixture"); std::process::exit(2); }

#[cfg(windows)]
fn main() {
    use windows_fixture::*;
    let role=std::env::args().nth(1).unwrap_or_default();
    // No default execution and no general command dispatcher.
    let entry:fn()=match role.as_str(){
        "terminal-child"=>child_fixture,
        "terminal-heartbeat"=>heartbeat_fixture,
        "terminal-argv"=>argv_fixture,
        "terminal-no-console"=>no_console_child_fixture,
        "terminal-console"=>console_handles_fixture,
        "owned-protocol"=>protocol_fixture,
        "owned-heartbeat"=>owned_heartbeat_fixture,
        "owned-job-idle"=>owned_job_child_fixture,
        "mcp-stall-fixture"=>mcp_stall_fixture,
        _=>{eprintln!("unknown subprocess fixture role");std::process::exit(2);}
    };
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(90));
        std::process::exit(124);
    });
    entry();
}

#[cfg(windows)]
mod windows_fixture {
use serde_json::{json, Value};
use std::{io::{BufRead,Write},path::Path,thread,time::{Duration,Instant}};
pub(super) fn child_fixture() {
    let mut descendants = Vec::new();
    println!("fixture-ready");
    std::io::stdout().flush().unwrap();
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        if line == "exit" { break; }
        if line == "do-not-read" {
            println!("stdin-blocked");
            std::io::stdout().flush().unwrap();
            loop { std::thread::sleep(Duration::from_secs(1)); }
        }
        if line == "flood" {
            std::io::stdout().write_all(&vec![b'x'; 700_000]).unwrap();
            println!("flood-done");
        } else if let Some(path) = line.strip_prefix("spawn ") {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            #[cfg(windows)] {
                use std::os::windows::process::CommandExt;
                command.creation_flags(0x08000000);
            }
            let mut child = command.args(["terminal-heartbeat"])
                .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null()).spawn().unwrap();
            writeln!(child.stdin.take().unwrap(), "{path}").unwrap();
            descendants.push(child);
            println!("descendant-started");
        } else {
            println!("echo:{line}");
            eprintln!("err:{line}");
        }
        std::io::stdout().flush().unwrap();
    }
}

pub(super) fn heartbeat_fixture() {
    let mut path = String::new();
    std::io::stdin().read_line(&mut path).unwrap();
    let mut output = std::fs::OpenOptions::new().create_new(true).write(true).open(path.trim()).unwrap();
    loop {
        output.write_all(b".").unwrap();
        output.flush().unwrap();
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub(super) fn argv_fixture() {
    println!("argv:{}", serde_json::to_string(&std::env::args().collect::<Vec<_>>()).unwrap());
}

pub(super) fn no_console_child_fixture() {
    #[link(name="kernel32")]
    extern "system" {fn GetConsoleWindow()->*mut std::ffi::c_void;}
    println!("console={}",unsafe{!GetConsoleWindow().is_null()});
    eprintln!("hidden-stderr-witness");
    std::io::stdout().flush().unwrap();
    std::io::stderr().flush().unwrap();
    std::process::exit(7);
}

pub(super) fn console_handles_fixture() {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetConsoleWindow() -> *mut std::ffi::c_void;
        fn GetStdHandle(which: u32) -> *mut std::ffi::c_void;
        fn GetConsoleMode(handle: *mut std::ffi::c_void, mode: *mut u32) -> i32;
    }
    let console = unsafe { !GetConsoleWindow().is_null() };
    let handles = [(-10i32) as u32, (-11i32) as u32, (-12i32) as u32]
        .map(|which| unsafe { GetConsoleMode(GetStdHandle(which), &mut 0) != 0 });
    let witness = format!("{console} {handles:?}");
    std::fs::write("console-witness", &witness).unwrap();
    println!("{witness}");
    eprintln!("console-probe-stderr");
    if console {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !Path::new("complete-console-probe").is_file() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
    }
    std::process::exit(7);
}

pub(super) fn protocol_fixture() {
    let mut descendants = Vec::new();
    println!("fixture-ready");
    std::io::stdout().flush().unwrap();
    for line in std::io::stdin().lock().lines() {
        let command: Value = serde_json::from_str(&line.unwrap()).unwrap();
        match command["action"].as_str().unwrap() {
            "probe" => {
                #[link(name="kernel32")]
                extern "system" { fn GetConsoleWindow() -> *mut std::ffi::c_void; }
                println!("probe:{}", json!({
                    "pid": std::process::id(),
                    "console": unsafe { !GetConsoleWindow().is_null() },
                    "argv": std::env::args().collect::<Vec<_>>(),
                    "marker": std::env::var_os("AGENT_BRIDGE_OWNED_TEST_MARKER")
                        .map(|value| value.to_string_lossy().into_owned()),
                    "cargo_manifest_dir": std::env::var_os("CARGO_MANIFEST_DIR")
                        .map(|value| value.to_string_lossy().into_owned()),
                }));
                eprintln!("owned-child-stderr");
            }
            "spawn" => {
                use std::os::windows::process::CommandExt;
                let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["owned-heartbeat"])
                    .creation_flags(0x08000000)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn().unwrap();
                writeln!(child.stdin.take().unwrap(), "{}", command["path"].as_str().unwrap()).unwrap();
                println!("descendant:{}", child.id());
                descendants.push(child);
            }
            "block-input" => {
                println!("input-blocked");
                std::io::stdout().flush().unwrap();
                loop { std::thread::sleep(Duration::from_secs(1)); }
            }
            "exit" => std::process::exit(command["code"].as_i64().unwrap() as i32),
            _ => panic!("unexpected fixture command"),
        }
        std::io::stdout().flush().unwrap();
    }
}

pub(super) fn owned_heartbeat_fixture() {
    let mut path = String::new();
    std::io::stdin().read_line(&mut path).unwrap();
    let mut output = std::fs::OpenOptions::new().create_new(true).write(true)
        .open(path.trim()).unwrap();
    loop {
        output.write_all(b".").unwrap();
        output.flush().unwrap();
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub(super) fn owned_job_child_fixture() {
    loop {thread::sleep(Duration::from_secs(1));}
}

pub(super) fn mcp_stall_fixture() {
    let state_dir = std::env::args().nth(2).unwrap_or_else(|| {
        eprintln!("missing state_dir");
        std::process::exit(2);
    });
    let state_dir = Path::new(&state_dir);
    let mut lines = std::io::stdin().lock().lines();
    let mut stdout = std::io::stdout().lock();
    while let Some(Ok(line)) = lines.next() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(req) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        let Some(id) = req.get("id").cloned() else {
            // Notification: ignore without replying.
            continue;
        };
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let resp = match method {
            "server/discover" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "resultType": "complete",
                    "supportedVersions": ["2026-07-28"],
                    "capabilities": {"tools": {}},
                    "ttlMs": 0,
                    "cacheScope": "private"
                }
            }),
            "tools/list" => {
                if state_dir.join("stall-list").exists() {
                    let _ = std::fs::write(state_dir.join("list-stalled.marker"), b"list-stalled\n");
                    while let Some(Ok(_)) = lines.next() {}
                    std::process::exit(0);
                }
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "resultType": "complete",
                        "ttlMs": 0,
                        "cacheScope": "private",
                        "tools": [{
                            "name": "search_items",
                            "description": "Simulated search",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"query": {"type": "string"}},
                                "required": ["query"]
                            }
                        }]
                    }
                })
            }
            "tools/call" => {
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(state_dir.join("calls.log"))
                {
                    let _ = writeln!(f, "call");
                }
                let _ = std::fs::write(state_dir.join("call-stalled.marker"), b"call-stalled\n");
                while let Some(Ok(_)) = lines.next() {}
                std::process::exit(0);
            }
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": "Method not found"}
            }),
        };
        let _ = writeln!(stdout, "{resp}");
        let _ = stdout.flush();
    }
}

}
