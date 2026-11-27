//! Real owned-child regression tests. No operator settings, network or service.
use super::*;
use agent_bridge_gateway::ToolHandler;
#[cfg(not(windows))]
use std::io::{BufRead, Write};
use crate::test_process_fixture::{program as fixture_program, args as fixture_args};

struct Harness {
    catalog: Vec<ToolDefinition>,
    handlers: ToolMapHandler,
    profile: Arc<RwLock<DesktopProfile>>,
    supervisor: SessionSupervisor,
}
impl Harness {
    fn new() -> Self {
        let profile = Arc::new(RwLock::new(DesktopProfile::FullyUnlocked));
        let mut catalog = Vec::new();
        let mut handlers = ToolMapHandler::new();
        let supervisor = attach(&std::env::temp_dir(), &mut catalog, &mut handlers,
            Arc::clone(&profile)).unwrap();
        assert_eq!(catalog.len(), 4);
        Self { catalog, handlers, profile, supervisor }
    }
    fn call(&self, name: &str, arguments: Value) -> (bool, Value) {
        let result = self.handlers.call(name, arguments.as_object().unwrap().clone()).unwrap();
        let value = serde_json::to_value(&result).unwrap();
        let text = value["content"][0]["text"].as_str().unwrap();
        (result.is_error, serde_json::from_str(text).unwrap_or_else(|_| json!({"error":text})))
    }
    fn start_fixture(&self) -> String {
        let (error, result) = self.call("desktop_start_process", json!({
            "program": fixture_program(),
            "args": fixture_args("terminal::unrestricted::tests::child_fixture",&[]),
            "timeout_ms": 2000
        }));
        assert!(!error, "{result}");
        let sid = result["session_id"].as_str().unwrap().to_owned();
        if !result["stdout"].as_str().unwrap().contains("fixture-ready") {
            self.read_until(&sid, "fixture-ready");
        }
        sid
    }
    fn read_until(&self, sid: &str, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut text = String::new();
        while Instant::now() < deadline {
            let (error, result) = self.call("desktop_read_process",
                json!({"session_id":sid,"timeout_ms":250}));
            assert!(!error, "{result}");
            text.push_str(result["stdout"].as_str().unwrap());
            if text.contains(needle) { return text; }
        }
        panic!("missing {needle:?} in {text:?}");
    }
    fn start_descendant(&self, sid: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("agent-bridge-heartbeat-{}", new_session_id().unwrap()));
        let (error, response) = self.call("desktop_interact_process", json!({
            "session_id":sid,"input":format!("spawn {}\n",path.display()),"timeout_ms":1000
        }));
        assert!(!error, "{response}");
        let deadline = Instant::now() + Duration::from_secs(5);
        while std::fs::metadata(&path).map(|metadata| metadata.len()).unwrap_or(0) < 3 {
            assert!(Instant::now() < deadline, "descendant did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
        path
    }
}

#[test]
fn connected_sessions_shows_fixed_process_label_without_launch_details() {
    use crate::client_sessions::{Client, ClientSessions};
    use agent_bridge_gateway::{GatewayConfig, McpGateway};

    let mut harness = Harness::new();
    let router = McpGateway::new(
        GatewayConfig::new("example", "1"), harness.catalog.clone(), harness.handlers.clone(),
    );
    let registry = ClientSessions::default();
    let program = fixture_program();
    let frame = json!({
        "jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{
            "name":"desktop_start_process", "arguments":{
                "program":program,
                "args":fixture_args("terminal::unrestricted::tests::child_fixture", &["--skip", "example-argument-marker"]),
                "timeout_ms":2000,
            }
        }
    }).to_string();
    let result = registry.dispatch(Client::Local("stdio"), &router, &frame, usize::MAX,
        || router.handle_str(&frame)).unwrap();
    let response: Value = serde_json::from_str(&result).unwrap();
    assert_ne!(response["result"]["isError"], true, "{response}");
    let result: Value = serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    let id = result["session_id"].as_str().unwrap();
    let snapshot = registry.snapshot("example-boot", None, None).unwrap();
    let session = &snapshot["sessions"][0];
    assert_eq!(session["commands"][0]["program"], "Process");
    let display_id = session["commands"][0]["id"].as_str().unwrap();
    assert_eq!(session["terminal_session_ids"], json!([display_id]));
    assert_ne!(display_id, id);
    assert!(!valid_session_id(display_id));
    assert_eq!(session["commands"][0]["state"], "running");
    let basename = Path::new(&program).file_name().unwrap().to_str().unwrap();
    assert!(session["commands"][0]["started_at"].as_str().unwrap().ends_with('Z'));
    let text = snapshot.to_string();
    assert!(!text.contains(program.to_str().unwrap()));
    assert!(!text.contains(basename));
    assert!(!text.contains(id));
    assert!(!text.contains("example-argument-marker"));
    assert!(!text.contains("fixture-ready"));

    harness.supervisor.shutdown().unwrap();
    let snapshot = registry.snapshot("example-boot", None, None).unwrap();
    assert_eq!(snapshot["sessions"][0]["commands"][0]["id"], display_id);
    assert_eq!(snapshot["sessions"][0]["commands"][0]["state"], "ended");
    assert!(snapshot["sessions"][0]["commands"][0]["ended_at"].as_str().unwrap().ends_with('Z'));
}

// A fixture runs only as a child selected by the exact test name; an
// ordinary run returns at once. It is never an alternative production
// subcommand or public tool.
#[cfg(not(windows))]
#[test]
fn child_fixture() {
    if !crate::test_process_fixture::selected("terminal::unrestricted::tests::child_fixture") { return; }
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
            let mut child = command.args(["--exact", "terminal::unrestricted::tests::heartbeat_fixture", "--nocapture"])
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

#[cfg(not(windows))]
#[test]
fn heartbeat_fixture() {
    if !crate::test_process_fixture::selected("terminal::unrestricted::tests::heartbeat_fixture") { return; }
    let mut path = String::new();
    std::io::stdin().read_line(&mut path).unwrap();
    let mut output = std::fs::OpenOptions::new().create_new(true).write(true).open(path.trim()).unwrap();
    loop {
        output.write_all(b".").unwrap();
        output.flush().unwrap();
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(not(windows))]
#[test]
fn argv_fixture() {
    if !crate::test_process_fixture::selected("terminal::unrestricted::tests::argv_fixture") { return; }
    println!("argv:{}", serde_json::to_string(&std::env::args().collect::<Vec<_>>()).unwrap());
}

#[test]
fn strict_arguments_reject_unknown_ambiguous_and_wrong_typed_requests() {
    let h = Harness::new();
    for arguments in [
        json!({}),
        json!({"command":"echo hello","program":"missing"}),
        json!({"command":"echo hello","shell":"missing-shell"}),
        json!({"command":"echo hello","args":[]}),
        json!({"program":"missing","shell":"sh"}),
        json!({"program":"missing","args":"not-an-array"}),
        json!({"program":"missing","args":[1]}),
        json!({"program":"missing","timeout_ms":-1}),
        json!({"program":"missing","elevation":"admin"}),
        json!({"program":"missing\u{0}"}),
    ] {
        let (error, response) = h.call("desktop_start_process", arguments);
        assert!(error, "unexpected start acceptance: {response}");
        assert!(response["error"].as_str().unwrap().starts_with("PROCESS_INVALID_ARGUMENT"), "{response}");
    }
    for name in ["desktop_read_process", "desktop_interact_process", "desktop_terminate_process"] {
        let (error, _) = h.call(name, json!({"pid":1}));
        assert!(error, "PID accepted by {name}");
    }
}

#[test]
fn owned_session_history_replays_both_streams_after_legacy_snapshots() {
    let h = Harness::new();
    let start = json!({
        "program":fixture_program(),
        "args":fixture_args("terminal::unrestricted::tests::child_fixture",&[]),
        "timeout_ms":2000
    });
    let receipt = h.supervisor.manager.start_with_history(start.as_object().unwrap(), true).unwrap();
    let sid = receipt["session_id"].as_str().unwrap().to_owned();
    let (error, receipt) = h.call("desktop_interact_process", json!({
        "session_id":sid, "input":"historique-été\n", "eof":true, "timeout_ms":100
    }));
    assert!(!error, "{receipt}");
    let manager = &h.supervisor.manager;
    let deadline = Instant::now() + Duration::from_secs(8);
    let history = loop {
        let args = json!({"session_id":sid,"offset":-1000,"length":1000,"timeout_ms":0});
        let receipt = manager.read_history(args.as_object().unwrap()).unwrap();
        if receipt["status"] == "exited" { break receipt; }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(history["exit_code"], 0);
    assert!(history["stdout"].as_str().unwrap().contains("echo:historique-été"));
    assert!(history["stderr"].as_str().unwrap().contains("err:historique-été"));
    let args = json!({"session_id":sid,"offset":0,"length":1,"timeout_ms":0});
    let first = manager.read_history(args.as_object().unwrap()).unwrap();
    let second = manager.read_history(args.as_object().unwrap()).unwrap();
    assert_eq!(first["offset"], 0);
    assert_eq!(second["offset"], 1);
    assert_eq!(first["length"], 1);
    assert_eq!(second["length"], 1);
}

#[test]
fn waiting_history_reader_cannot_use_a_revoked_session_reference() {
    let h = Harness::new();
    let manager = Arc::clone(&h.supervisor.manager);
    let start = json!({
        "program":fixture_program(),
        "args":fixture_args("terminal::unrestricted::tests::child_fixture",&[]),
        "timeout_ms":2000
    });
    let receipt = manager.start_with_history(start.as_object().unwrap(), true).unwrap();
    let sid = receipt["session_id"].as_str().unwrap().to_owned();
    let args = json!({"session_id":sid,"timeout_ms":5000});
    let mut output = String::new();
    while !output.contains("fixture-ready") {
        let page = manager.read_history(args.as_object().unwrap()).unwrap();
        let text = page["stdout"].as_str().unwrap();
        assert!(!text.is_empty(), "fixture readiness deadline elapsed");
        output.push_str(text);
    }
    let session = manager.lookup(&sid).unwrap();
    let initial_refs = Arc::strong_count(&session);
    let reader_manager = Arc::clone(&manager);
    let reader = thread::spawn(move || reader_manager.read_history(args.as_object().unwrap()));
    let deadline = Instant::now() + Duration::from_secs(2);
    while Arc::strong_count(&session) == initial_refs {
        assert!(Instant::now() < deadline, "reader did not acquire the session");
        thread::yield_now();
    }
    // The operator can reactivate FullyUnlocked before the read handler
    // reacquires a live guard. Its original registry entry is gone.
    let guard = h.profile.write().unwrap();
    manager.revoke(false).unwrap();
    drop(guard);
    assert!(reader.join().unwrap().unwrap_err().starts_with("PROCESS_SESSION_UNKNOWN"));
}

#[test]
fn cleanup_failure_is_not_a_confirmed_exit() {
    let harness = Harness::new();
    let id = new_session_id().unwrap();
    let capture = Capture {
        finished: true,
        cleanup_error: Some("owned process tree cleanup timed out".into()),
        ..Capture::default()
    };
    let session = Arc::new(Session {
        id: id.clone(),
        program: "fixture".into(),
        command: None,
        cwd: std::env::temp_dir(),
        started: Instant::now(),
        capture: Arc::new((Mutex::new(capture), Condvar::new())),
        input: Mutex::new(InputQueue { sender: None, next_id: 1, eof_queued: false }),
        stop: Arc::new(AtomicBool::new(true)),
        worker: Mutex::new(None),
        retained: Arc::new(Mutex::new(None)),
    });
    harness.supervisor.manager.registry.lock().unwrap().sessions.insert(id.clone(), session);
    let (error, receipt) = harness.call("desktop_read_process", json!({"session_id":id,"timeout_ms":0}));
    assert!(!error, "{receipt}");
    assert_eq!(receipt["status"], "cleanup_incomplete");
    assert_eq!(receipt.get("running"), Some(&Value::Null));
    assert!(receipt["exit_code"].is_null());
    assert_eq!(receipt["cleanup_error"], "owned process tree cleanup timed out");
}

#[test]
fn utf8_buffer_retains_partial_characters_and_reuses_consumed_capacity() {
    let mut output = OutputBuffer::default();
    output.push(&[0xe2, 0x82]);
    assert_eq!(output.drain(100), "");
    output.push(&[0xac, b'!']);
    assert_eq!(output.drain(3), "€");
    assert_eq!(output.drain(100), "!");
    output.push(&vec![b'x'; MAX_STREAM_BYTES + 5]);
    assert_eq!(output.dropped, 5);
    while output.has_output() { output.drain(MAX_REPLY_BYTES); }
    output.push(b"later");
    assert_eq!(output.drain(100), "later");
    output.push(&[0xf0, 0x9f]);
    output.eof = true;
    assert_eq!(output.drain(100), "�");
}

#[test]
fn owned_direct_child_has_progressive_output_literal_stdin_and_eof() {
    let h = Harness::new();
    let sid = h.start_fixture();
    assert!(valid_session_id(&sid));
    let (error, result) = h.call("desktop_interact_process", json!({
        "session_id":sid,"input":"hello \"quoted\" ; $literal €\n","timeout_ms":1000
    }));
    assert!(!error, "{result}");
    let mut out = result["stdout"].as_str().unwrap().to_owned();
    if !out.contains("echo:hello") { out += &h.read_until(&sid, "echo:hello"); }
    assert!(out.contains("echo:hello \"quoted\" ; $literal €"), "{out}");
    let (error, result) = h.call("desktop_interact_process", json!({
        "session_id":sid,"input":"last-before-eof\n","eof":true,"timeout_ms":1000
    }));
    assert!(!error, "{result}");
    let mut final_output = result["stdout"].as_str().unwrap().to_owned();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let (error, result) = h.call("desktop_read_process", json!({"session_id":sid,"timeout_ms":100}));
        assert!(!error, "{result}");
        final_output.push_str(result["stdout"].as_str().unwrap());
        if result["status"] == "exited" {
            assert_eq!(result["exit_code"], 0);
            assert_eq!(result["output_complete"], true);
            break;
        }
        assert!(Instant::now() < deadline, "child did not exit");
    }
    assert!(final_output.contains("echo:last-before-eof"), "last input was discarded: {final_output}");
}

#[test]
fn revocation_under_profile_write_lock_closes_busy_stdin_and_allows_reactivation() {
    let h = Harness::new();
    let sid = h.start_fixture();
    let (error, response) = h.call("desktop_interact_process", json!({
        "session_id":sid,"input":"do-not-read\n","timeout_ms":1000
    }));
    assert!(!error, "{response}");
    if !response["stdout"].as_str().unwrap().contains("stdin-blocked") {
        h.read_until(&sid, "stdin-blocked");
    }
    for _ in 0..8 {
        let _ = h.call("desktop_interact_process", json!({
            "session_id":sid,"input":"x".repeat(MAX_INPUT_BYTES),"timeout_ms":0
        }));
    }
    std::thread::sleep(Duration::from_millis(50));
    let started = Instant::now();
    {
        let mut profile = h.profile.write().unwrap();
        (h.supervisor.revoker())().unwrap();
        *profile = DesktopProfile::FullControl;
    }
    assert!(started.elapsed() < Duration::from_secs(5));
    for (name, arguments) in [
        ("desktop_start_process", json!({"command":"echo forbidden"})),
        ("desktop_read_process", json!({"session_id":sid})),
        ("desktop_interact_process", json!({"session_id":sid,"input":"x"})),
        ("desktop_terminate_process", json!({"session_id":sid})),
    ] {
        let (error, result) = h.call(name, arguments);
        assert!(error && result["error"].as_str().unwrap().starts_with("PROFILE_RESTRICTED_BY_OPERATOR"),
            "{name} after downgrade: {result}");
    }
    *h.profile.write().unwrap() = DesktopProfile::FullyUnlocked;
    let next = h.start_fixture();
    assert_ne!(sid, next);
    let (error, result) = h.call("desktop_terminate_process", json!({"session_id":next}));
    assert!(!error, "{result}");
    assert_eq!(result["status"], "exited");
}

#[test]
fn every_direct_handler_checks_live_profile_before_touching_an_existing_session() {
    let h = Harness::new();
    let sid = h.start_fixture();
    // Bypass only the local callback to isolate the handlers' admission check.
    // The idle fixture is still present, so UNKNOWN_SESSION cannot mask a gap.
    *h.profile.write().unwrap() = DesktopProfile::WorkspaceWrite;
    for (name, arguments) in [
        ("desktop_start_process", json!({"command":"echo forbidden"})),
        ("desktop_read_process", json!({"session_id":sid})),
        ("desktop_interact_process", json!({"session_id":sid,"input":"forbidden\n"})),
        ("desktop_terminate_process", json!({"session_id":sid})),
    ] {
        let (error, response) = h.call(name, arguments);
        assert!(error && response["error"].as_str().unwrap().starts_with("PROFILE_RESTRICTED_BY_OPERATOR"),
            "{name}: {response}");
    }
    *h.profile.write().unwrap() = DesktopProfile::FullyUnlocked;
    let (error, response) = h.call("desktop_read_process", json!({"session_id":sid,"timeout_ms":0}));
    assert!(!error && response["status"] == "running", "gate refusal changed the session: {response}");
}

#[test]
fn session_wait_does_not_block_profile_revocation() {
    let h = Harness::new();
    let sid = h.start_fixture();
    // Empty previously produced output before starting a long wait.
    let _ = h.call("desktop_read_process", json!({"session_id":sid,"timeout_ms":0}));
    let handlers = h.handlers.clone();
    let reader = std::thread::spawn(move || handlers.call("desktop_read_process",
        json!({"session_id":sid,"timeout_ms":30000}).as_object().unwrap().clone()).unwrap());
    std::thread::sleep(Duration::from_millis(50));
    let started = Instant::now();
    {
        let mut profile = h.profile.write().unwrap();
        (h.supervisor.revoker())().unwrap();
        *profile = DesktopProfile::ReadOnly;
    }
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(reader.join().unwrap().is_error);
}

#[test]
fn root_exit_stops_owned_descendants_even_when_their_output_is_redirected() {
    let h = Harness::new();
    let sid = h.start_fixture();
    let heartbeat = h.start_descendant(&sid);
    let (error, response) = h.call("desktop_interact_process", json!({
        "session_id":sid,"input":"exit\n","timeout_ms":1000
    }));
    assert!(!error, "{response}");
    let deadline = Instant::now() + Duration::from_secs(7);
    loop {
        let (error, response) = h.call("desktop_read_process", json!({"session_id":sid,"timeout_ms":100}));
        assert!(!error, "{response}");
        if response["status"] == "exited" {
            assert!(response["cleanup_error"].is_null(), "{response}");
            break;
        }
        assert!(Instant::now() < deadline, "owned descendants did not finish");
    }
    let size = std::fs::metadata(&heartbeat).unwrap().len();
    std::thread::sleep(Duration::from_millis(150));
    assert_eq!(std::fs::metadata(&heartbeat).unwrap().len(), size, "descendant survived root exit");
    std::fs::remove_file(heartbeat).unwrap();
}

#[test]
fn native_shells_preserve_cwd_and_report_nonzero_exit() {
    let h = Harness::new();
    #[cfg(windows)]
    let shells = [("cmd", "echo native-shell-ok & cd & exit /b 7"),
        ("powershell", "[Console]::Out.WriteLine('native-shell-ok'); [Console]::Out.WriteLine((Get-Location).Path); exit 7")];
    #[cfg(unix)]
    let shells = [("sh", "printf 'native-shell-ok\\n'; pwd; exit 7"),
        ("bash", "printf 'native-shell-ok\\n'; pwd; exit 7")];
    let selected_cwd = std::env::temp_dir().canonicalize().unwrap();
    for (shell, command) in shells {
        let (error, mut result) = h.call("desktop_start_process", json!({
            "command":command,"shell":shell,"timeout_ms":1000,
            "cwd":selected_cwd,
        }));
        assert!(!error, "{shell}: {result}");
        let sid = result["session_id"].as_str().unwrap().to_owned();
        let mut output = result["stdout"].as_str().unwrap().to_owned();
        let mut errors = result["stderr"].as_str().unwrap().to_owned();
        let deadline = Instant::now() + Duration::from_secs(5);
        while result["status"] != "exited" {
            let (error, next) = h.call("desktop_read_process", json!({"session_id":sid,"timeout_ms":100}));
            assert!(!error, "{next}");
            result = next;
            output.push_str(result["stdout"].as_str().unwrap());
            errors.push_str(result["stderr"].as_str().unwrap());
            assert!(Instant::now() < deadline, "shell did not exit");
        }
        assert!(output.contains("native-shell-ok"), "shell={shell} output={output:?} stderr={errors:?} result={result}");
        let observed_cwd = output.lines().map(str::trim).find(|line| Path::new(line).is_absolute())
            .unwrap_or_else(|| panic!("shell={shell} did not report cwd: output={output:?} stderr={errors:?}"));
        assert_eq!(Path::new(observed_cwd).canonicalize().unwrap(), selected_cwd,
            "shell={shell} ran in a different cwd: output={output:?} stderr={errors:?}");
        assert_eq!(result["exit_code"], 7, "{shell}: {result}");
        assert!(result["cleanup_error"].is_null(), "{result}");
    }
}

#[test]
fn direct_arguments_reach_the_child_without_shell_interpretation() {
    let h = Harness::new();
    let literal = "a value \"quoted\" \\tail\\ ; $HOME & literal €";
    let (error, result) = h.call("desktop_start_process", json!({
        "program":fixture_program(),
        "args":fixture_args("terminal::unrestricted::tests::argv_fixture",&["--skip",literal]),
        "timeout_ms":1000,
    }));
    assert!(!error, "{result}");
    let sid = result["session_id"].as_str().unwrap();
    let mut output = result["stdout"].as_str().unwrap().to_owned();
    if !output.contains("argv:") { output += &h.read_until(sid, "argv:"); }
    let line = output.lines().find_map(|line| line.split_once("argv:").map(|(_, args)| args))
        .expect("argument fixture did not print its argv");
    let argv: Vec<String> = serde_json::from_str(line).unwrap();
    assert_eq!(argv.last().unwrap(), literal);
}

#[cfg(windows)]
#[test]
fn direct_cmd_preserves_cwd_and_rejects_verbatim_only_directory() {
    let h = Harness::new();
    let selected = std::env::temp_dir().canonicalize().unwrap();
    let (error, mut result) = h.call("desktop_start_process", json!({
        "program":"cmd.exe","args":["/D","/S","/C","cd"],
        "cwd":selected,"timeout_ms":1000,
    }));
    assert!(!error, "{result}");
    let sid = result["session_id"].as_str().unwrap().to_owned();
    let mut output = result["stdout"].as_str().unwrap().to_owned();
    let mut errors = result["stderr"].as_str().unwrap().to_owned();
    let deadline = Instant::now() + Duration::from_secs(5);
    while result["status"] != "exited" {
        let (error, next) = h.call("desktop_read_process", json!({"session_id":sid,"timeout_ms":100}));
        assert!(!error, "{next}");
        result = next;
        output.push_str(result["stdout"].as_str().unwrap());
        errors.push_str(result["stderr"].as_str().unwrap());
        assert!(Instant::now() < deadline, "direct cmd did not exit: {result}");
    }
    assert_eq!(result["exit_code"], 0, "stdout={output:?} stderr={errors:?}");
    let observed = output.lines().map(str::trim).find(|line| Path::new(line).is_absolute())
        .unwrap_or_else(|| panic!("direct cmd cwd missing: stdout={output:?} stderr={errors:?}"));
    assert_eq!(Path::new(observed).canonicalize().unwrap(), selected);

    let root = std::env::temp_dir().join(format!("agent-bridge-direct-cwd-{}", new_session_id().unwrap()));
    std::fs::create_dir(&root).unwrap();
    let canonical = root.canonicalize().unwrap();
    let normal = canonical.join("special");
    let verbatim = canonical.join("special.");
    std::fs::create_dir(&normal).unwrap();
    std::fs::create_dir(&verbatim).unwrap();
    let (error, response) = h.call("desktop_start_process", json!({
        "program":"cmd.exe","args":["/D","/S","/C","cd"],
        "cwd":verbatim,"timeout_ms":0,
    }));
    std::fs::remove_dir(verbatim).unwrap();
    std::fs::remove_dir(normal).unwrap();
    std::fs::remove_dir(root).unwrap();
    assert!(error && response["error"].as_str().unwrap().contains("cmd requires an equivalent ordinary DOS working directory"),
        "direct cmd must refuse before silently changing cwd: {response}");
}

#[test]
fn supervisor_drop_stops_children_even_while_handlers_are_still_owned() {
    let h = Harness::new();
    let sid = h.start_fixture();
    let heartbeat = h.start_descendant(&sid);
    let Harness { handlers, supervisor, .. } = h;
    drop(supervisor);
    // Retained handler Arcs must not keep the owned process running or admit
    // another process after the lifetime owner has stopped the host.
    let result = handlers.call("desktop_start_process",
        json!({"command":"echo should-not-run","timeout_ms":0}).as_object().unwrap().clone()).unwrap();
    let value = serde_json::to_value(result).unwrap();
    assert_eq!(value["isError"], true);
    assert!(value["content"][0]["text"].as_str().unwrap().contains("PROCESS_MANAGER_STOPPING"));
    let result = handlers.call("desktop_read_process",
        json!({"session_id":sid,"timeout_ms":0}).as_object().unwrap().clone()).unwrap();
    assert!(result.is_error);
    let size = std::fs::metadata(&heartbeat).unwrap().len();
    std::thread::sleep(Duration::from_millis(150));
    assert_eq!(std::fs::metadata(&heartbeat).unwrap().len(), size, "descendant survived supervisor Drop");
    std::fs::remove_file(heartbeat).unwrap();
}

#[test]
fn failed_cleanup_survives_capacity_pressure_and_blocks_revocation() {
    let h = Harness::new();
    let manager = &h.supervisor.manager;
    let started = Instant::now();
    {
        let mut registry = manager.registry.lock().unwrap();
        for index in 0..MAX_SESSIONS {
            let id = format!("completed-{index}");
            let capture = Capture {
                finished: true,
                cleanup_error: (index == 0).then(|| "fixture cleanup unconfirmed".to_owned()),
                ..Default::default()
            };
            registry.sessions.insert(id.clone(), Arc::new(Session {
                id, program: String::new(), command: None, cwd: manager.root.clone(),
                started: started + Duration::from_millis(index as u64),
                capture: Arc::new((Mutex::new(capture), Condvar::new())),
                input: Mutex::new(InputQueue { sender: None, next_id: 1, eof_queued: false }),
                stop: Arc::new(AtomicBool::new(false)), worker: Mutex::new(None),
                retained: Arc::new(Mutex::new(None)),
            }));
        }
    }
    let args = json!({"program": std::env::current_exe().unwrap(), "args":["--list"], "timeout_ms":0});
    manager.start(args.as_object().unwrap()).unwrap();
    let revoke = h.supervisor.revoker();
    let _guard = h.profile.write().unwrap();
    assert!(revoke().unwrap_err().to_string().contains("fixture cleanup unconfirmed"));
    assert!(manager.registry.lock().unwrap().sessions.contains_key("completed-0"));
}
#[cfg(windows)]
#[test]
fn default_direct_child_has_no_console_and_retains_stdout_stderr_and_exit_code() {
    let h=Harness::new();
    let (error,mut result)=h.call("desktop_start_process",json!({
        "program":fixture_program(),
        "args":fixture_args("terminal::unrestricted::tests::no_console_child_fixture",&[]),
        "timeout_ms":2000
    }));
    assert!(!error,"{result}");
    let sid=result["session_id"].as_str().unwrap().to_owned();
    let mut stdout=String::new();
    let mut stderr=String::new();
    let until=Instant::now()+Duration::from_secs(5);
    loop {
        stdout.push_str(result["stdout"].as_str().unwrap());
        stderr.push_str(result["stderr"].as_str().unwrap());
        if result["status"]=="exited" && result["output_complete"]==true {
            assert_eq!(result["exit_code"],7);
            break;
        }
        assert!(Instant::now()<until,"hidden child did not complete");
        let (error,next)=h.call("desktop_read_process",json!({"session_id":sid,"timeout_ms":100}));
        assert!(!error,"{next}");
        result=next;
    }
    assert!(stdout.contains("console=false"),"{stdout}");
    assert!(stderr.contains("hidden-stderr-witness"),"{stderr}");
}

#[test]
fn revocation_and_shutdown_stop_real_descendants_while_neighbor_survives() {
    use std::io::Write;
    use std::process::{Child, Command, Stdio};

    struct NeighborGuard(Child, PathBuf);
    impl Drop for NeighborGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
            let _ = std::fs::remove_file(&self.1);
        }
    }

    fn assert_neighbor_progress(neighbor: &mut NeighborGuard, size: u64, action: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(neighbor.0.try_wait().unwrap().is_none(), "neighbor died on {action}");
            if std::fs::File::open(&neighbor.1).unwrap().metadata().unwrap().len() > size {
                return;
            }
            assert!(Instant::now() < deadline, "neighbor heartbeat stopped on {action}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    let neighbor_path = std::env::temp_dir().join(format!(
        "agent-bridge-neighbor-heartbeat-{}", new_session_id().unwrap()
    ));
    #[cfg(windows)]
    let mut neighbor_cmd = {
        use std::os::windows::process::CommandExt;
        let mut cmd = Command::new(fixture_program());
        cmd.args(["terminal-heartbeat"]).creation_flags(0x0800_0000);
        cmd
    };
    #[cfg(unix)]
    let mut neighbor_cmd = {
        use std::os::unix::process::CommandExt;
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", "terminal::unrestricted::tests::heartbeat_fixture", "--nocapture"])
            .process_group(0);
        cmd
    };
    let mut neighbor_child = neighbor_cmd
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().unwrap();
    writeln!(neighbor_child.stdin.take().unwrap(), "{}", neighbor_path.display()).unwrap();
    let mut neighbor = NeighborGuard(neighbor_child, neighbor_path.clone());
    let deadline = Instant::now() + Duration::from_secs(5);
    while std::fs::metadata(&neighbor_path).map(|m| m.len()).unwrap_or(0) < 3 {
        assert!(Instant::now() < deadline, "neighbor heartbeat did not start");
        std::thread::sleep(Duration::from_millis(20));
    }

    let mut h = Harness::new();
    let sid1 = h.start_fixture();
    let desc1 = h.start_descendant(&sid1);
    {
        let mut profile = h.profile.write().unwrap();
        (h.supervisor.revoker())().unwrap();
        *profile = DesktopProfile::FullControl;
    }
    let desc1_size = std::fs::metadata(&desc1).unwrap().len();
    let neighbor_before_downgrade = std::fs::File::open(&neighbor_path).unwrap().metadata().unwrap().len();
    std::thread::sleep(Duration::from_millis(150));
    assert_neighbor_progress(&mut neighbor, neighbor_before_downgrade, "downgrade");
    assert_eq!(std::fs::metadata(&desc1).unwrap().len(), desc1_size, "descendant survived downgrade");
    std::fs::remove_file(desc1).unwrap();

    *h.profile.write().unwrap() = DesktopProfile::FullyUnlocked;
    let sid2 = h.start_fixture();
    assert_ne!(sid1, sid2);
    let desc2 = h.start_descendant(&sid2);
    h.supervisor.shutdown().unwrap();
    let desc2_size = std::fs::metadata(&desc2).unwrap().len();
    let neighbor_before_shutdown = std::fs::File::open(&neighbor_path).unwrap().metadata().unwrap().len();
    std::thread::sleep(Duration::from_millis(150));
    assert_neighbor_progress(&mut neighbor, neighbor_before_shutdown, "shutdown");
    assert_eq!(std::fs::metadata(&desc2).unwrap().len(), desc2_size, "descendant survived shutdown");
    std::fs::remove_file(desc2).unwrap();
}


#[cfg(windows)]
mod unified_windows {
    use super::*;
    use agent_bridge_desktop::{DesktopConfig, DesktopFiles};
    use agent_bridge_gateway::{GatewayConfig, McpGateway};
    use crate::session_profile::ProfileControl;

    struct FixtureDir(PathBuf);
    impl FixtureDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("ab-terminal-{}", new_session_id().unwrap()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for FixtureDir {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    struct Unified {
        router: McpGateway<ToolMapHandler>,
        _supervisor: crate::terminal::SessionSupervisor,
        profile: ProfileControl,
        root: FixtureDir,
    }
    impl Unified {
        fn new(startup: DesktopProfile) -> Self {
            Self::build(FixtureDir::new(), ProfileControl::new(startup),
                crate::agent_desktop::AgentDesktopHandle::disabled(), Vec::new(), ToolMapHandler::new())
        }
        fn build(
            root: FixtureDir, profile: ProfileControl,
            desktops: crate::agent_desktop::AgentDesktopHandle,
            mut catalog: Vec<ToolDefinition>, mut handlers: ToolMapHandler,
        ) -> Self {
            let settings = root.0.join("settings");
            let private = root.0.join("private");
            agent_bridge_lifecycle::initialize_operator_settings(&settings).unwrap();
            std::fs::create_dir(&private).unwrap();
            let files = Arc::new(DesktopFiles::open(DesktopConfig::new(&root.0)).unwrap());
            let supervisor = crate::terminal::attach_unified(
                &settings, &root.0, &root.0.join("catalog.sqlite"),
                &mut catalog, &mut handlers, true, files, profile.shared(), desktops, &private,
                Arc::new(crate::command_catalogue::CommandCatalogueSnapshot::load(&settings).unwrap()),
            ).unwrap().expect("unified process supervisor");
            profile.register_revoker(supervisor.minimum_profile(), supervisor.revoker()).unwrap();
            let router = McpGateway::new(GatewayConfig::new("unified-terminal-fixture", "1"), catalog, handlers);
            Self { router, _supervisor: supervisor, profile, root }
        }
        fn call(&self, target: &str, args: Value) -> Value {
            let frame = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                "params":{"name":target,"arguments":args}});
            let value: Value = serde_json::from_str(&self.router.handle_str(&frame.to_string()).unwrap()).unwrap();
            assert!(value["error"].is_null(), "{value}");
            value["result"].clone()
        }
        fn ok(&self, target: &str, args: Value) -> Value {
            let result = self.call(target, args);
            assert_ne!(result["isError"], true, "{target}: {result}");
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap()
        }
        fn refused(&self, target: &str, args: Value, error: &str) {
            let result = self.call(target, args);
            assert_eq!(result["isError"], true, "{target}: {result}");
            assert!(result["content"][0]["text"].as_str().unwrap().contains(error), "{result}");
        }
        fn finished(&self, id: &str, offset: i64) -> Value {
            let deadline = Instant::now() + Duration::from_secs(7);
            loop {
                let output = self.ok("desktop_read_process", json!({
                    "session_id":id,"offset":offset,"length":100,"timeout_ms":200
                }));
                if output["running"] == false { return output; }
                assert!(Instant::now() < deadline, "session {id}: {output}");
                thread::sleep(Duration::from_millis(10));
            }
        }
        fn fixture(&self, name: &str, extra: Value) -> Value {
            let mut arguments = json!({
                 "program":fixture_program(),
                "args":fixture_args(name,&[]),"timeout_ms":250
            });
            arguments.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            self.ok("desktop_start_process", arguments)
        }
    }

    #[test]
    fn unified_gateway_windows_shell_aliases_preserve_cwd_temp_and_exit() {
        let h = Unified::new(DesktopProfile::FullyUnlocked);
        let cases = [
            ("cmd.exe", "echo short=%TEMP%& echo also=%TMP%& cd& exit /b 7", None),
            ("powershell.exe", "[Console]::Out.WriteLine('short='+$env:TEMP); [Console]::Out.WriteLine('also='+$env:TMP); [Console]::Out.WriteLine((Get-Location).Path); exit 7", Some("inherit")),
        ];
        for (shell, command, mode) in cases {
            let mut arguments = json!({"shell":shell,"command":command,"cwd":h.root.0,"timeout_ms":250});
            if let Some(mode) = mode { arguments["temp_mode"] = json!(mode); }
            let start = h.ok("desktop_start_process", arguments);
            assert_eq!(start["output_capture"], true, "{start}");
            let result = h.finished(start["session_id"].as_str().unwrap(), -100);
            let stdout = result["stdout"].as_str().unwrap();
            assert_eq!(result["exit_code"], 7, "{shell}: {result}");
            let paths = stdout.lines().map(str::trim).collect::<Vec<_>>();
            assert!(paths.iter().any(|line| Path::new(line).canonicalize().ok() == h.root.0.canonicalize().ok()), "{shell}: {stdout}");
            let temp = paths.iter().find_map(|line| line.strip_prefix("short=")).unwrap();
            let tmp = paths.iter().find_map(|line| line.strip_prefix("also=")).unwrap();
            if mode == Some("inherit") {
                assert_eq!(std::ffi::OsStr::new(temp), std::env::var_os("TEMP").unwrap(), "{stdout}");
                assert_eq!(std::ffi::OsStr::new(tmp), std::env::var_os("TMP").unwrap(), "{stdout}");
            } else {
                assert_eq!(temp, tmp, "{stdout}");
                assert_ne!(std::ffi::OsStr::new(temp), std::env::var_os("TEMP").unwrap(), "{stdout}");
                assert!(Path::new(temp).is_absolute() && temp.encode_utf16().count() < 160, "{temp}");
            }
        }
    }

    #[test]
    fn unified_gateway_literal_argv_has_no_shell_and_oversized_line_is_refused() {
        let h = Unified::new(DesktopProfile::FullyUnlocked);
        let literal = [
            r#"& | %PATH% ^ "quoted""#,
            r"C:\directory with spaces\",
            "",
            "été",
        ];
        let args=fixture_args("terminal::unrestricted::tests::argv_fixture",&literal);
        let start = h.ok("desktop_start_process", json!({
            "program":fixture_program(),"args":args,"timeout_ms":250
        }));
        let result = h.finished(start["session_id"].as_str().unwrap(), -100);
        let output = result["stdout"].as_str().unwrap();
        let observed = output.lines().find_map(|line| line.split_once("argv:").map(|(_, argv)| argv))
            .unwrap_or_else(|| panic!("missing argv output: {result}"));
        let observed: Vec<String> = serde_json::from_str(observed).unwrap();
        assert_eq!(observed[observed.len() - literal.len()..], literal);
        h.refused("desktop_start_process", json!({
            "program":std::env::current_exe().unwrap(),"args":["x".repeat(33_000)]
        }), "Windows command line exceeds 32767 UTF-16 units");
        h.refused("desktop_start_process", json!({"shell":"cmd.exe","command":format!("echo {}", "x".repeat(8191))}),
            "cmd.exe command line exceeds 8191 UTF-16 units");
        h.refused("desktop_start_process", json!({"command":"echo must-not-run","timeout_ms":249}),
            "PROCESS_INVALID_ARGUMENT");
    }

    #[test]
    fn unified_gateway_waits_for_fresh_prompt_and_replays_its_output_after_eof() {
        let h = Unified::new(DesktopProfile::FullyUnlocked);
        let start = h.fixture("terminal::unrestricted::tests::child_fixture", json!({}));
        let id = start["session_id"].as_str().unwrap();
        assert_eq!(start["running"], true, "{start}");
        let accepted = h.ok("desktop_interact_process", json!({
            "session_id":id,"input":"partial", "wait_for_prompt":false
        }));
        assert_eq!(accepted["input_queued"], true, "{accepted}");
        assert_eq!(accepted["stdout"], "", "{accepted}");
        let response = h.ok("desktop_interact_process", json!({
            "session_id":id,"input":"-été\n","timeout_ms":2000
        }));
        assert_eq!(response["input_completed_through"], 2, "{response}");
        assert!(response["stdout"].as_str().unwrap().contains("echo:partial-été"), "{response}");
        assert!(response["stderr"].as_str().unwrap().contains("err:partial-été"), "{response}");
        h.ok("desktop_interact_process", json!({"session_id":id,"eof":true}));
        let tail = h.finished(id, -100);
        let stdout = tail["stdout"].as_str().unwrap();
        assert!(stdout.contains("fixture-ready") && stdout.contains("echo:partial-été"), "{tail}");
        assert!(tail["stderr"].as_str().unwrap().contains("err:partial-été"), "{tail}");
        let first_page = h.ok("desktop_read_process", json!({"session_id":id,"length":1,"timeout_ms":0}));
        assert_eq!(first_page["length"], 1, "{first_page}");
        assert_eq!(first_page["has_more"], true, "{first_page}");
        let second_page = h.ok("desktop_read_process", json!({"session_id":id,"length":1,"timeout_ms":0}));
        assert_eq!(second_page["offset"], 1, "{second_page}");
    }

    fn verify_hidden_console_fixture(h:&Unified) {
        let fixture = "terminal::unrestricted::tests::unified_windows::console_handles_fixture";
        let start = h.fixture(fixture, json!({}));
        let hidden = h.finished(start["session_id"].as_str().unwrap(), -100);
        assert!(hidden["stdout"].as_str().unwrap().contains("false [false, false, false]"), "{hidden}");
        assert!(hidden["stderr"].as_str().unwrap().contains("console-probe-stderr"), "{hidden}");
        assert_eq!(hidden["exit_code"], 7);
        assert_eq!(hidden["output_complete"], true);
        let witness = h.root.0.join("console-witness");
        std::fs::remove_file(&witness).unwrap();
    }
    #[test]
    fn unified_gateway_hidden_console_stdio_and_complete_capture() {
        verify_hidden_console_fixture(&Unified::new(DesktopProfile::FullyUnlocked));
    }
    /// Requires explicit operator permission to display a real console window.
    #[cfg(feature = "qualification")]
    #[test]
    fn unified_gateway_visible_opt_in_has_console_stdio_and_no_false_capture() {
        let h = Unified::new(DesktopProfile::FullyUnlocked);
        verify_hidden_console_fixture(&h);
        let fixture = "terminal::unrestricted::tests::unified_windows::console_handles_fixture";
        let witness=h.root.0.join("console-witness");
        let start = h.fixture(fixture, json!({"window_mode":"visible"}));
        let id = start["session_id"].as_str().unwrap();
        assert_eq!(start["window_mode"], "visible", "{start}");
        assert_eq!(start["output_capture"], false, "{start}");
        assert_eq!(start["output_complete"], false, "{start}");
        h.refused("desktop_interact_process", json!({"session_id":id,"input":"must not reach console"}),
            "PROCESS_STDIN_UNAVAILABLE");
        let deadline = Instant::now() + Duration::from_secs(5);
        let observed = loop {
            if let Ok(text) = std::fs::read_to_string(&witness) {
                if !text.is_empty() { break text; }
            }
            assert!(Instant::now() < deadline, "visible fixture did not report its console handles");
            thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(observed, "true [true, true, true]");
        std::fs::write(h.root.0.join("complete-console-probe"), b"exit").unwrap();
        let visible = h.finished(id, -100);
        assert_eq!(visible["exit_code"], 7, "{visible}");
        assert_eq!(visible["output_complete"], false, "{visible}");
        assert_eq!(visible["stdout"], "", "{visible}");
    }

    #[test]
    fn unified_gateway_checks_lease_before_launch_and_revokes_direct_sessions() {
        let h = Unified::new(DesktopProfile::FullyUnlocked);
        h.refused("desktop_start_process", json!({
            "command":"echo launched > lease-refusal-marker","shell":"cmd.exe",
            "agent_desktop_lease_id":"b32609af-7166-43dc-ab4d-13f37a3abd0e"
        }), "AGENT_DESKTOP_UNAVAILABLE");
        h.refused("desktop_start_process", json!({
            "command":"echo launched > lease-refusal-marker","shell":"cmd.exe","window_mode":"visible",
            "agent_desktop_lease_id":"b32609af-7166-43dc-ab4d-13f37a3abd0e"
        }), "PROCESS_VISIBLE_AGENT_DESKTOP_UNSUPPORTED");
        h.refused("desktop_start_process", json!({
            "command":"echo launched > lease-refusal-marker","shell":"cmd.exe","elevation":"admin",
            "agent_desktop_lease_id":"b32609af-7166-43dc-ab4d-13f37a3abd0e"
        }), "PROCESS_ADMIN_AGENT_DESKTOP_UNSUPPORTED");
        assert!(!h.root.0.join("lease-refusal-marker").exists());
        let start = h.fixture("terminal::unrestricted::tests::child_fixture", json!({}));
        let id = start["session_id"].as_str().unwrap();
        let blocker = h.ok("desktop_interact_process", json!({
            "session_id":id,"input":"do-not-read\n"
        }));
        assert!(blocker["stdout"].as_str().unwrap().contains("stdin-blocked"), "{blocker}");
        h.profile.set(DesktopProfile::FullControl).unwrap();
        h.refused("desktop_read_process", json!({"session_id":id}), "PROFILE_RESTRICTED_BY_OPERATOR");
        h.profile.set(DesktopProfile::WorkspaceWrite).unwrap();
        h.refused("agent_bridge_project_command", json!({"command":"git-version"}),
            "PROFILE_RESTRICTED_BY_OPERATOR");
        h.profile.set(DesktopProfile::FullyUnlocked).unwrap();
        h.refused("desktop_read_process", json!({"session_id":id}), "PROCESS_SESSION_UNKNOWN");

        let restricted = Unified::new(DesktopProfile::FullControl);
        let response = restricted.call("desktop_start_process", json!({
            "command":"echo launched > restricted-refusal-marker","shell":"cmd.exe"
        }));
        assert_eq!(response["isError"], true, "{response}");
        assert!(!restricted.root.0.join("restricted-refusal-marker").exists());
        restricted.profile.set(DesktopProfile::WorkspaceWrite).unwrap();
        for (tool, args) in [
            ("desktop_start_process", json!({"command":"git-version"})),
            ("desktop_read_process", json!({"session_id":id})),
            ("desktop_interact_process", json!({"session_id":id,"input":"{}"})),
            ("desktop_terminate_process", json!({"session_id":id})),
            ("agent_bridge_project_command", json!({"command":"git-version"})),
        ] {
            restricted.refused(tool, args, "PROFILE_RESTRICTED_BY_OPERATOR");
        }
    }

    /// Requires the packaged native helper and an isolated synthetic Virtual Desktop.
    #[cfg(feature = "qualification")]
    #[test]
    fn unified_gateway_places_owned_gui_on_lease_and_stops_it_on_revocation() {
        use crate::agent_desktop::{self, AgentDesktopConfig, AgentDesktopHandle, DesktopBinding};
        use sha2::{Digest, Sha256};

        struct DedicatedDesktop(AgentDesktopHandle, DesktopBinding);
        impl Drop for DedicatedDesktop {
            fn drop(&mut self) { let _ = self.0.local_remove_desktop(&self.1); }
        }

        let bundle = PathBuf::from(std::env::var_os("AGENT_BRIDGE_NATIVE_TEST_BUNDLE").unwrap());
        let (executable,_fixture_pin)=crate::test_process_fixture::native_gui_fixture();
        let manifest = std::fs::read(bundle.join("manifest.json")).unwrap();
        let seal: String = Sha256::digest(manifest).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(seal,std::env::var("AGENT_BRIDGE_NATIVE_TEST_MANIFEST_SHA256").expect("externally pinned manifest"));
        let _bundle_pin=crate::windows_tools::bundle::Resources::verify(&bundle,&seal).unwrap();
        #[link(name="user32")]
        extern "system" {fn GetForegroundWindow()->isize;}
        let foreground=unsafe{GetForegroundWindow()};
        assert_ne!(foreground,0,"no independent foreground witness; do not launch");
        let root = FixtureDir::new();
        let profile = ProfileControl::new(DesktopProfile::FullyUnlocked);
        let native = AgentDesktopConfig {
            bundle_root: bundle, manifest_sha256: seal,
            state_root: root.0.join("desktop-creator"), desktops: Vec::new(),
        };
        let (creator, mut creator_owner) = agent_desktop::attach(native.clone(), profile.clone(),
            Arc::new(|_, _| Ok(())), &mut Vec::new(), &mut ToolMapHandler::new()).unwrap();
        let current = creator.current_desktop().unwrap();
        let binding = creator.local_create_desktop().unwrap();
        let dedicated = DedicatedDesktop(creator.clone(), binding.clone());
        assert_eq!(creator.current_desktop().unwrap(),current,"test desktop creation switched desktop");
        assert_eq!(unsafe{GetForegroundWindow()},foreground,"desktop creation changed foreground");

        let mut catalog = Vec::new();
        let mut handlers = ToolMapHandler::new();
        let (desktops, mut desktop_owner) = agent_desktop::attach(AgentDesktopConfig {
            desktops: vec![binding.clone()], state_root: root.0.join("desktop-lease"), ..native
        }, profile.clone(), Arc::new(|_, _| Ok(())), &mut catalog, &mut handlers).unwrap();
        let h = Unified::build(FixtureDir::new(), profile, desktops.clone(), catalog, handlers);
        let started = h.ok("desktop_agent_desktop", json!({
            "action":"start","desktop_number":binding.desktop_number,"task_label":"Agent Bridge terminal fixture"
        }));
        let lease = started["control"]["lease_id"].as_str().unwrap();
        let witness = h.root.0.join("gui-state.json");
        let started = h.ok("desktop_start_process", json!({
            "program":executable,"args":[witness,"--passive"],"agent_desktop_lease_id":lease,"timeout_ms":5000
        }));
        assert_eq!(started["agent_desktop_placed"], true, "{started}");
        assert_eq!(started["window_mode"], "hidden", "{started}");
        let id = started["session_id"].as_str().unwrap();
        let until=Instant::now()+Duration::from_secs(3);
        let witness:Value=loop{
            if let Ok(bytes)=std::fs::read(&witness){
                if let Ok(value)=serde_json::from_slice::<Value>(&bytes){
                    if value["rendered"]==true&&value["hwnd"].as_u64().is_some_and(|n|n>0){break value;}
                }
            }
            assert!(Instant::now()<until,"passive fixture did not render");
            thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(witness["console"],false);
        assert_eq!(unsafe{GetForegroundWindow()},foreground,"passive fixture changed foreground");
        let hwnd = witness["hwnd"].as_u64().unwrap();
        assert_eq!(desktops.window(hwnd).unwrap().desktop_id, binding.desktop_id);
        assert_eq!(creator.current_desktop().unwrap(), current);

        h.ok("desktop_agent_desktop", json!({"action":"stop","lease_id":lease}));
        let stopped = h.finished(id, -100);
        assert!(stopped["agent_desktop_error"].is_string(), "{stopped}");
        assert!(stopped["cleanup_error"].is_null(), "{stopped}");
        assert!(desktops.window(hwnd).is_err(), "the GUI window outlived its owned Job");
        assert_eq!(creator.current_desktop().unwrap(), current);
        assert_eq!(unsafe{GetForegroundWindow()},foreground,"lease revoke changed foreground");
        desktop_owner.shutdown().unwrap();
        drop(dedicated);
        assert!(!creator.local_pool_candidates().unwrap().contains(&binding));
        creator_owner.shutdown().unwrap();
    }

}
