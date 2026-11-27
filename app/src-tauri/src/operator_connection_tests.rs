use super::*;
use crate::backend;
use crate::state::{save_settings_to_disk, settings_file_path, AppRuntime, PanelSettings};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

const TEST_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "agent-bridge-native-attach-{}-{}",
            std::process::id(), SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        Self(fs::canonicalize(root).unwrap())
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn session_record(port: u16, token: &str) -> Value {
    json!({
        "service": "agent-bridge-ui", "version": "fixture",
        "listen": format!("127.0.0.1:{port}"),
        "ui_url": format!("http://127.0.0.1:{port}/?token={token}"),
        "token_required": true, "loopback_only": true, "live_profile_control": true,
    })
}

fn config(root: &Path, port: u16) -> OperatorClient {
    let log = root.join("operator.stdout.log");
    fs::write(&log, format!("{}\n", session_record(port, TEST_TOKEN))).unwrap();
    let log = {
        let raw = log.display().to_string();
        #[cfg(windows)]
        let raw = raw.strip_prefix(r"\\?\").unwrap_or(&raw).to_owned();
        PathBuf::from(raw)
    };
    let gateway_port = if port == 18856 { 18857 } else { 18856 };
    fs::write(root.join(CONFIG_FILE), json!({
        "version": 1, "controlPort": port, "gatewayPort": gateway_port,
        "stdoutLog": log,
    }).to_string()).unwrap();
    OperatorClient {
        config: ConnectionConfig {
            version: 1, control_port: port, gateway_port, stdout_log: log,
            session_view_only: false, supervisor: None,
        },
    }
}

#[derive(Default)]
struct MockState {
    requests: Vec<(String, String, Value)>,
    active: String,
    ceiling: String,
    failure: Option<(u16, Value)>,
    extension_operation: Option<Value>,
}

struct MockService {
    port: u16,
    gateway_port: Option<u16>,
    state: Arc<Mutex<MockState>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

fn profile_payload(state: &MockState) -> Value {
    let maximum = PROFILES.iter().position(|profile| *profile == state.ceiling).unwrap();
    json!({
        "configured": true, "active_profile": state.active,
        "max_profile": state.ceiling, "available_profiles": &PROFILES[..=maximum],
    })
}

fn fixture_route(state: &mut MockState, method: &str, path: &str, body: Value) -> (u16, Value) {
    state.requests.push((method.to_owned(), path.to_owned(), body.clone()));
    if let Some(failure) = &state.failure {
        return failure.clone();
    }
    match (method, path) {
        ("GET", "/api/profile") => (200, profile_payload(state)),
        ("POST", "/api/shutdown") => (202, json!({ "status": "shutting_down" })),
        ("POST", "/api/profile") => {
            let requested = body["profile"].as_str().unwrap_or("");
            let requested_rank = PROFILES.iter().position(|profile| *profile == requested).unwrap();
            let ceiling_rank = PROFILES.iter().position(|profile| *profile == state.ceiling).unwrap();
            if requested_rank > ceiling_rank {
                return (403, json!({ "error": "PROFILE_ABOVE_STARTUP_LIMIT" }));
            }
            state.active = requested.to_owned();
            (200, profile_payload(state))
        }
        ("GET", "/api/overview") => (200, json!({
            "version": "fixture", "os": "fixture-os", "arch": "fixture-arch",
            "project": { "configured": true, "path": "/live/project" },
            "database": {
                "configured": true, "exists": true, "path": "/live/missions.sqlite",
                "schema_version": 7, "pending_migrations": 0,
                "counts": { "missions": { "active": 3, "total": 8 }, "task_rooms": 2 },
            },
            "oauth": {
                "configured": true, "state_dir": "/live/oauth", "public_origin": "https://example.invalid",
                "audience": "Workstation", "pending_count": 1,
            },
            "extensions": { "configured": true, "settings_dir": "/live/settings", "pending_count": 2 },
            "skills": { "installed_count": 4 },
            "quickstart_commands": { "stdio_read_only": "fixture-read", "stdio_workspace_write": "fixture-write" },
        })),
        ("GET", "/api/extensions") => (200, json!({
            "configured": true, "settings_dir": "/live/settings", "pending_count": 2,
            "servers": [{ "id": "fixture", "enabled": true, "endpoint": "https://mcp.example.invalid/api" }],
            "requests": [{
                "request_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "action": "install", "name": "fixture", "decision": "pending", "revision": 3,
                "payload": { "action": "install", "name": "fixture", "url": "https://mcp.example.invalid/api",
                    "secret_env": { "AUTH_TOKEN": "FIXTURE_TOKEN_ENV" } },
            }],
            "oauth_operation": state.extension_operation,
            "outbound_oauth": { "fixture": { "token_status": { "token_stored": true } } },
        })),
        ("POST", "/api/extensions/decide") => {
            let approve = body["approve"].as_bool().expect("decision boolean");
            assert_eq!(body["confirm"], if approve { "APPROVE" } else { "REFUSE" });
            if let Some(operation) = &state.extension_operation {
                (202, json!({ "oauth_operation": operation }))
            } else {
                (200, json!({ "request_id": body["request_id"],
                    "decision": if approve { "approved" } else { "refused" },
                    "effect_now": approve }))
            }
        }
        ("GET", "/api/missions") => (200, json!({
            "configured": true, "missions": [{ "mission_id": "live-mission", "goal": "fixture", "status": "active" }],
            "task_rooms": [{ "title": "room", "steps_completed": 1, "steps_total": 2 }],
        })),
        ("GET", "/api/oauth") => (200, json!({
            "configured": true, "public_origin": "https://example.invalid", "audience": "Workstation",
            "pending": [{ "id": "fixture-request", "client_id": "chatgpt_fixture", "provider": "chatgpt",
                "redirect_uri": "https://chatgpt.com/connector_platform_oauth_redirect" }],
        })),
        ("POST", "/api/oauth/enroll") => {
            assert_eq!(body["confirm"], "APPROVE");
            (200, json!({ "local_oauth_enrollment": "enabled", "expires_epoch_ms": 42, "duration_max_seconds": 600 }))
        }
        ("POST", "/api/oauth/approve") => {
            assert_eq!(body["confirm"], "APPROVE");
            (200, json!({ "local_oauth_request": "approved", "id": body["request_id"] }))
        }
        ("GET", "/api/skills") => (200, json!({ "configured": true, "skills": [{ "name": "fixture-skill" }] })),
        ("POST", "/api/skills/action") => (200, json!({ "action": body["action"], "name": body["name"], "ok": true })),
        ("GET", "/api/diagnostics") => (200, json!({
            "os": "fixture-os", "arch": "fixture-arch", "version": "fixture",
            "capabilities": { "outbound_oauth_keystore": "Fixture keystore", "missions_and_task_rooms": true },
            "browser_profiles": { "mcp_persistent_profiles": ["fixture-profile"] },
        })),
        ("GET", "/api/sessions") => (200, json!({
            "available": true, "boot_id": "example-boot", "live_window_seconds": 120,
            "sessions": [{
                "session_id": "example-session", "terminal_session_ids": ["example-command"],
                "contexts": [{"missions": [{"mission_id": "example-mission", "subtasks": [
                    {"id": "example-subtask", "assigned_to_context": true}
                ]}]}],
                "tool_calls": [{"tool_name": "agent_bridge_status"}],
                "commands": [{"id": "example-command", "exit_code": 0}],
            }],
        })),
        _ => (404, json!({ "error": "UNEXPECTED_ROUTE" })),
    }
}

impl MockService {
    fn start() -> Self {
        Self::start_with_shutdown(false)
    }

    fn start_with_shutdown(close_on_shutdown: bool) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let gateway = close_on_shutdown.then(|| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap());
        let gateway_port = gateway.as_ref().map(|listener| listener.local_addr().unwrap().port());
        let state = Arc::new(Mutex::new(MockState {
            active: "fully-unlocked".to_owned(),
            ceiling: "fully-unlocked".to_owned(),
            ..MockState::default()
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_state = Arc::clone(&state);
        let thread_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("Fixture listener failed: {error}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut request = Vec::new();
                let (head, body) = loop {
                    let mut bytes = [0u8; 4096];
                    let count = stream.read(&mut bytes).unwrap();
                    assert_ne!(count, 0);
                    request.extend_from_slice(&bytes[..count]);
                    if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                        let head = std::str::from_utf8(&request[..end]).unwrap();
                        let length = head.lines().find_map(|line| line.strip_prefix("Content-Length: "))
                            .unwrap().parse::<usize>().unwrap();
                        if request.len() >= end + 4 + length {
                            break (head.to_owned(), request[end + 4..end + 4 + length].to_vec());
                        }
                    }
                };
                assert!(head.contains(&format!("Host: 127.0.0.1:{port}\r\n")));
                assert!(head.contains(&format!("Origin: http://127.0.0.1:{port}\r\n")));
                assert!(head.contains(&format!("X-Agent-Bridge-Token: {TEST_TOKEN}\r\n")));
                let mut words = head.lines().next().unwrap().split_ascii_whitespace();
                let method = words.next().unwrap();
                let path = words.next().unwrap();
                let payload = if body.is_empty() { Value::Null } else { serde_json::from_slice(&body).unwrap() };
                let (status, value) = fixture_route(&mut thread_state.lock().unwrap(), method, path, payload);
                let body = value.to_string();
                write!(stream, "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                if close_on_shutdown && method == "POST" && path == "/api/shutdown" && status == 202 {
                    break;
                }
            }
            drop(gateway);
        });
        Self { port, gateway_port, state, stop, worker: Some(worker) }
    }
}

impl Drop for MockService {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

#[test]
fn attachment_is_explicit_and_invalid_configuration_never_falls_back() {
    let root = TestRoot::new();
    assert!(!OperatorAttachment::load(&root.0).is_configured());
    fs::write(root.0.join(CONFIG_FILE), b"{invalid").unwrap();
    let runtime = AppRuntime::new(root.0.clone());
    assert!(runtime.operator.is_configured());
    let database = root.0.join("existing.sqlite");
    fs::write(&database, b"database sentinel: must never be opened").unwrap();
    {
        let mut settings = runtime.settings.lock().unwrap();
        settings.database_path = database.display().to_string();
        settings.settings_dir = root.0.join("private-settings-must-not-be-created").display().to_string();
        settings.oauth_state_dir = root.0.join("oauth-must-not-be-created").display().to_string();
        settings.oauth_origin = "https://example.invalid".to_owned();
    }
    let panel = backend::get_panel_state(&runtime).unwrap();
    assert_eq!(panel["gateway"]["external"], true);
    assert_eq!(panel["gateway"]["live"], false);
    assert_eq!(panel["liveProfile"]["configured"], true);
    assert!(backend::get_missions_snapshot(&runtime).is_err());
    assert!(backend::get_oauth_pending(&runtime).is_err());
    assert!(backend::get_skills_overview(&runtime).is_err());
    assert!(backend::get_diagnostics(&runtime).is_err());
    assert!(backend::enable_oauth_enrollment(&runtime).is_err());
    assert!(backend::approve_oauth_request(&runtime, "request", "https://example.invalid", None).is_err());
    assert!(backend::run_skill_action(&runtime, "rollback", "fixture", None).is_err());
    assert!(backend::initialize_local_state(&runtime).is_err());
    assert!(backend::start_or_restart_gateway(&runtime, backend::GatewayIntent::default()).is_err());
    assert!(backend::set_permission_profile(&runtime, "fully-unlocked", true).is_err());
    assert!(backend::stop_gateway(&runtime).is_err());
    assert_eq!(fs::read(&database).unwrap(), b"database sentinel: must never be opened");
    assert!(!root.0.join("private-settings-must-not-be-created").exists());
    assert!(!root.0.join("oauth-must-not-be-created").exists());
    assert!(!settings_file_path(&root.0).exists());
}

#[test]
fn log_selection_is_bounded_and_uses_only_the_latest_matching_session_record() {
    let root = TestRoot::new();
    let client = config(&root.0, 18890);
    assert_eq!(client.session_token().unwrap(), TEST_TOKEN);
    let log = &client.config.stdout_log;
    let old = session_record(18890, TEST_TOKEN);
    let mut replacement = session_record(18891, TEST_TOKEN);
    fs::write(log, format!("{old}\n{replacement}\n")).unwrap();
    assert!(client.session_token().is_err());
    replacement = session_record(18890, TEST_TOKEN);
    replacement["live_profile_control"] = json!(false);
    fs::write(log, format!("{old}\n{replacement}\n")).unwrap();
    assert!(client.session_token().is_err());
    replacement = session_record(18890, TEST_TOKEN);
    replacement["ui_url"] = json!(format!("http://example.invalid:18890/?token={TEST_TOKEN}"));
    fs::write(log, format!("{replacement}\n")).unwrap();
    assert!(client.session_token().is_err());
    replacement["ui_url"] = json!(format!("http://127.0.0.1:18890/?token={TEST_TOKEN}&extra=true"));
    fs::write(log, format!("{replacement}\n")).unwrap();
    assert!(client.session_token().is_err());
    fs::write(log, format!("{}\n{old}\n", "x".repeat(MAX_LOG_BYTES as usize + 1024))).unwrap();
    assert_eq!(client.session_token().unwrap(), TEST_TOKEN);
    assert!(client.get("https://example.invalid").is_err());
    assert!(client.post("/api/extensions/delete-all", json!({})).is_err());
}

#[test]
fn session_view_only_attachment_accepts_local_sessions_and_refuses_other_reads_and_writes() {
    let service = MockService::start();
    let root = TestRoot::new();
    let client = config(&root.0, service.port);
    let mut record = session_record(service.port, TEST_TOKEN);
    record["session_view_only"] = json!(true);
    record["live_profile_control"] = json!(false);
    record["workstation_shutdown_control"] = json!(false);
    fs::write(&client.config.stdout_log, format!("{record}\n")).unwrap();
    assert!(client.get("/api/sessions").is_err());
    fs::write(root.0.join(CONFIG_FILE), json!({
        "version": 1, "controlPort": service.port, "sessionViewOnly": true,
        "stdoutLog": client.config.stdout_log,
    }).to_string()).unwrap();
    let runtime = AppRuntime::new(root.0.clone());
    let client = runtime.operator.client().unwrap();
    assert_eq!(backend::get_sessions(&runtime).unwrap()["bootId"], "example-boot");
    assert!(client.get("/api/diagnostics").is_err());
    assert!(client.post("/api/profile", json!({"profile":"fully-unlocked"})).is_err());
    assert!(!client.supports_shutdown());
}

#[test]
fn http_parser_rejects_unbounded_ambiguous_or_oversized_responses() {
    for head in [
        "HTTP/1.1 200 OK\r\n\r\n".to_owned(),
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n".to_owned(),
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n".to_owned(),
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", MAX_RESPONSE_BYTES + 1),
        "NOT-HTTP 200 OK\r\nContent-Length: 0\r\n\r\n".to_owned(),
        format!("HTTP/1.1 200 OK\r\nX: {}", "x".repeat(MAX_HEADER_BYTES)),
    ] {
        assert!(response_head(head.as_bytes()).is_err());
    }
    assert_eq!(response_head(b"HTTP/1.1 200").unwrap(), None);
    assert!(response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap().is_some());
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}").unwrap();
    });
    let mut stream = TcpStream::connect(address).unwrap();
    assert!(read_response(&mut stream, Duration::from_secs(1)).is_err());
    worker.join().unwrap();
}

#[test]
fn live_modes_obey_server_ceiling_and_auth_errors_do_not_change_local_preferences() {
    let service = MockService::start();
    let root = TestRoot::new();
    config(&root.0, service.port);
    let local = PanelSettings { profile: "workspace-write".to_owned(), ..PanelSettings::default() };
    save_settings_to_disk(&root.0, &local).unwrap();
    let before = fs::read(settings_file_path(&root.0)).unwrap();
    let runtime = AppRuntime::new(root.0.clone());
    let result = backend::set_permission_profile(&runtime, "read-only", false).unwrap();
    assert_eq!(result["liveProfile"]["activeProfile"], "read-only");
    assert_eq!(result["liveProfile"]["maxProfile"], "fully-unlocked");
    assert_eq!(fs::read(settings_file_path(&root.0)).unwrap(), before);
    assert!(!runtime.gateway.lock().unwrap().is_owned_running());
    {
        let mut state = service.state.lock().unwrap();
        state.ceiling = "workspace-write".to_owned();
    }
    let error = backend::set_permission_profile(&runtime, "fully-unlocked", true).unwrap_err();
    assert!(error.contains("maximum"));
    assert_eq!(service.state.lock().unwrap().active, "read-only");
    {
        let mut state = service.state.lock().unwrap();
        state.failure = Some((401, json!({ "error": "TOKEN_INVALID", "message": TEST_TOKEN })));
    }
    let unavailable = backend::get_panel_state(&runtime).unwrap();
    assert_eq!(unavailable["liveProfile"]["connected"], false);
    assert_eq!(unavailable["gateway"]["external"], true);
    let error = backend::set_permission_profile(&runtime, "read-only", true).unwrap_err();
    assert!(!error.contains(TEST_TOKEN));
    assert!(!unavailable.to_string().contains(TEST_TOKEN));
    assert_eq!(fs::read(settings_file_path(&root.0)).unwrap(), before);
}

#[test]
fn attached_screens_use_operator_apis_and_theme_does_not_replace_local_runtime_settings() {
    let service = MockService::start();
    let root = TestRoot::new();
    config(&root.0, service.port);
    let database = root.0.join("local.sqlite");
    fs::write(&database, b"not a sqlite database; no live command may open it").unwrap();
    let mut local = PanelSettings::default();
    local.workspace = "/stored/project".to_owned();
    local.database_path = database.display().to_string();
    local.settings_dir = root.0.join("do-not-create-settings").display().to_string();
    local.oauth_state_dir = root.0.join("do-not-open-oauth").display().to_string();
    local.oauth_origin = "https://stored.invalid".to_owned();
    save_settings_to_disk(&root.0, &local).unwrap();
    let runtime = AppRuntime::new(root.0.clone());
    let panel = backend::get_panel_state(&runtime).unwrap();
    assert_eq!(panel["settings"]["workspace"], "/live/project");
    assert_eq!(panel["settings"]["databasePath"], "/live/missions.sqlite");
    assert_eq!(panel["database"]["activeMissions"], 3);
    assert_eq!(panel["pendingApprovalsTotal"], 3);
    assert_eq!(panel["extensions"]["requests"][0]["status"], "pending");
    assert_eq!(panel["extensions"]["outboundOauth"]["fixture"]["tokenStatus"]["token_stored"], true);
    assert!(!panel.to_string().contains(TEST_TOKEN));
    let missions = backend::get_missions_snapshot(&runtime).unwrap();
    assert_eq!(missions["exists"], true);
    assert_eq!(missions["missions"][0]["mission_id"], "live-mission");
    let oauth = backend::get_oauth_pending(&runtime).unwrap();
    assert_eq!(oauth["pending"][0]["clientId"], "chatgpt_fixture");
    assert_eq!(oauth["origin"], "https://example.invalid");
    assert_eq!(backend::get_skills_overview(&runtime).unwrap()["skills"][0]["name"], "fixture-skill");
    let diagnostics = backend::get_diagnostics(&runtime).unwrap();
    assert_eq!(diagnostics["oauthKeystore"], "Fixture keystore");
    assert_eq!(diagnostics["mcpBrowserProfiles"][0], "fixture-profile");
    let sessions = backend::get_sessions(&runtime).unwrap();
    assert_eq!(sessions["bootId"], "example-boot");
    assert_eq!(sessions["liveWindowSeconds"], 120);
    let session = &sessions["sessions"][0];
    assert_eq!(session["sessionId"], "example-session");
    assert_eq!(session["terminalSessionIds"][0], "example-command");
    assert_eq!(session["toolCalls"][0]["toolName"], "agent_bridge_status");
    assert_eq!(session["commands"][0]["exitCode"], 0);
    assert_eq!(session["contexts"][0]["missions"][0]["subtasks"][0]["assignedToContext"], true);
    assert!(session.get("session_id").is_none());
    assert_eq!(backend::enable_oauth_enrollment(&runtime).unwrap()["enabled"], true);
    assert_eq!(backend::approve_oauth_request(&runtime, "fixture-request", "https://chatgpt.com/connector_platform_oauth_redirect", None).unwrap()["approved"], true);
    assert_eq!(backend::run_skill_action(&runtime, "rollback", "fixture-skill", None).unwrap()["ok"], true);
    let mut displayed: PanelSettings = serde_json::from_value(panel["settings"].clone()).unwrap();
    displayed.theme = "dark".to_owned();
    let updated = backend::save_panel_settings(&runtime, displayed.clone()).unwrap();
    assert_eq!(updated["settings"]["theme"], "dark");
    let persisted: PanelSettings = serde_json::from_slice(&fs::read(settings_file_path(&root.0)).unwrap()).unwrap();
    assert_eq!(persisted.workspace, local.workspace);
    assert_eq!(persisted.database_path, local.database_path);
    assert_eq!(persisted.oauth_state_dir, local.oauth_state_dir);
    assert_eq!(persisted.theme, "dark");
    displayed.workspace = "/attempted/change".to_owned();
    assert!(backend::save_panel_settings(&runtime, displayed).is_err());
    assert_eq!(fs::read(&database).unwrap(), b"not a sqlite database; no live command may open it");
    assert!(!Path::new(&local.settings_dir).exists());
    assert!(!Path::new(&local.oauth_state_dir).exists());
    assert!(!runtime.gateway.lock().unwrap().is_owned_running());
    let requests = &service.state.lock().unwrap().requests;
    assert!(requests.iter().any(|(method, path, body)| method == "POST" && path == "/api/oauth/approve"
        && body["request_id"] == "fixture-request" && body["capability"]["kind"] == "legacy"));
}

#[test]
fn reflected_session_credentials_are_never_returned_to_the_webview() {
    let service = MockService::start();
    let root = TestRoot::new();
    let client = config(&root.0, service.port);
    {
        let mut state = service.state.lock().unwrap();
        let mut reflected = json!({ "nested": [format!("prefix {TEST_TOKEN} suffix")] });
        reflected[TEST_TOKEN] = json!("fixture");
        state.failure = Some((200, reflected));
    }
    let response = client.get("/api/diagnostics").unwrap().to_string();
    assert!(!response.contains(TEST_TOKEN));
    assert!(response.contains("[redacted]"));
}

#[test]
fn live_profile_contract_rejects_inconsistent_or_unknown_limits() {
    for value in [
        json!({ "configured": false, "active_profile": "read-only", "max_profile": "read-only", "available_profiles": ["read-only"] }),
        json!({ "configured": true, "active_profile": "fully-unlocked", "max_profile": "read-only", "available_profiles": ["read-only"] }),
        json!({ "configured": true, "active_profile": "root", "max_profile": "fully-unlocked", "available_profiles": PROFILES }),
        json!({ "configured": true, "active_profile": "read-only", "max_profile": "fully-unlocked", "available_profiles": ["read-only"] }),
    ] {
        assert!(profile_snapshot(value).is_err());
    }
}

#[test]
fn attached_extension_review_preserves_the_exact_proposal_and_pending_oauth_status() {
    let service = MockService::start();
    let root = TestRoot::new();
    config(&root.0, service.port);
    service.state.lock().unwrap().extension_operation = Some(json!({
        "request_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "status": "awaiting_authorization",
        "auth_url": "https://auth.example.invalid/authorize?state=fixture",
        "result": null, "error": null, "callback_timeout_seconds": 120,
    }));
    let runtime = AppRuntime::new(root.0.clone());
    let panel = backend::get_panel_state(&runtime).unwrap();
    let extensions = &panel["extensions"];
    assert_eq!(extensions["canDecide"], true);
    assert_eq!(extensions["requests"][0]["payload"]["url"], "https://mcp.example.invalid/api");
    assert_eq!(extensions["requests"][0]["payload"]["secret_env"]["AUTH_TOKEN"], "FIXTURE_TOKEN_ENV");
    assert_eq!(extensions["oauthOperation"]["status"], "awaiting_authorization");
    assert_eq!(extensions["oauthOperation"]["result"], Value::Null);
}

#[test]
fn extension_decision_route_preserves_approval_refusal_and_async_receipts() {
    let service = MockService::start();
    let root = TestRoot::new();
    let client = config(&root.0, service.port);
    let id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    for (approve, confirm, decision) in [(true, "APPROVE", "approved"), (false, "REFUSE", "refused")] {
        let receipt = client.post("/api/extensions/decide", json!({
            "request_id": id, "approve": approve, "confirm": confirm,
        })).expect("existing authenticated decision route");
        assert_eq!(receipt["request_id"], id);
        assert_eq!(receipt["decision"], decision);
    }
    service.state.lock().unwrap().extension_operation = Some(json!({
        "request_id": id, "status": "starting", "auth_url": null, "result": null,
        "error": null, "callback_timeout_seconds": 120,
    }));
    let pending = client.post("/api/extensions/decide", json!({
        "request_id": id, "approve": true, "confirm": "APPROVE",
    })).unwrap();
    assert_eq!(pending["oauth_operation"]["status"], "starting");
    assert_eq!(pending["decision"], Value::Null);
}

#[test]
fn native_extension_decisions_require_review_and_a_valid_attached_request() {
    let service = MockService::start();
    let root = TestRoot::new();
    config(&root.0, service.port);
    let runtime = AppRuntime::new(root.0.clone());
    let id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    assert!(backend::decide_extension_request(&runtime, id, true, false).is_err());
    for invalid in ["", "pending", "bbbb\r\nInjected: value"] {
        assert!(backend::decide_extension_request(&runtime, invalid, false, false).is_err());
    }
    assert!(service.state.lock().unwrap().requests.is_empty());
    assert_eq!(backend::decide_extension_request(&runtime, id, true, true).unwrap()["decision"], "approved");
    assert_eq!(backend::decide_extension_request(&runtime, id, false, false).unwrap()["decision"], "refused");
    let requests = service.state.lock().unwrap().requests.clone();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], ("POST".to_owned(), "/api/extensions/decide".to_owned(),
        json!({ "request_id": id, "approve": true, "confirm": "APPROVE" })));
    assert_eq!(requests[1].2, json!({ "request_id": id, "approve": false, "confirm": "REFUSE" }));
    service.state.lock().unwrap().failure = Some((409, json!({
        "error": "EXTENSION_DECISION_FAILED", "message": TEST_TOKEN,
    })));
    let error = backend::decide_extension_request(&runtime, id, true, true).unwrap_err();
    assert!(!error.contains(TEST_TOKEN));
    let detached_root = TestRoot::new();
    let detached = AppRuntime::new(detached_root.0.clone());
    assert!(backend::decide_extension_request(&detached, id, false, false).is_err());
    assert!(!settings_file_path(&detached_root.0).exists());
}

#[test]
fn legacy_attachment_has_no_lifecycle_authority_without_advertised_shutdown() {
    let service = MockService::start();
    let root = TestRoot::new();
    let client = config(&root.0, service.port);
    let runtime = AppRuntime::new(root.0.clone());
    let panel = backend::get_panel_state(&runtime).unwrap();
    assert_eq!(panel["gateway"]["controls"]["canStart"], false);
    assert_eq!(panel["gateway"]["controls"]["canRestart"], false);
    assert_eq!(panel["gateway"]["controls"]["canStop"], false);
    assert!(backend::stop_gateway(&runtime).is_err());
    assert!(!service.state.lock().unwrap().requests.iter().any(|(_, path, _)| path == "/api/shutdown"));

    let mut record = session_record(service.port, TEST_TOKEN);
    record["workstation_shutdown_control"] = json!(true);
    fs::write(&client.config.stdout_log, format!("{record}\n")).unwrap();
    let panel = backend::get_panel_state(&runtime).unwrap();
    assert_eq!(panel["gateway"]["controls"]["canStop"], true);
    assert_eq!(panel["gateway"]["controls"]["canRestart"], false);
    assert!(panel["gateway"]["controls"]["reason"].as_str().unwrap().contains("external owner"));
    assert!(!panel.to_string().contains(TEST_TOKEN));
}

#[test]
fn shutdown_requires_the_accepted_acknowledgement_and_reports_errors_without_tokens() {
    let service = MockService::start();
    let root = TestRoot::new();
    let client = config(&root.0, service.port);
    assert_eq!(client.post("/api/shutdown", json!({})).unwrap()["status"], "shutting_down");
    for (status, body) in [
        (200, json!({"status":"shutting_down"})),
        (202, json!({"status":"wrong"})),
        (409, json!({"error":"WORKSTATION_SHUTDOWN_UNAVAILABLE", "message":TEST_TOKEN})),
        (503, json!({"error":"WORKSTATION_SHUTDOWN_UNAVAILABLE", "message":TEST_TOKEN})),
    ] {
        service.state.lock().unwrap().failure = Some((status, body));
        let error = client.post("/api/shutdown", json!({})).unwrap_err();
        assert!(!error.contains(TEST_TOKEN));
    }
}

fn attached_with_unavailable_supervisor() -> (TestRoot, MockService, AppRuntime) {
    let service = MockService::start_with_shutdown(true);
    let root = TestRoot::new();
    let client = config(&root.0, service.port);
    let mut record = session_record(service.port, TEST_TOKEN);
    record["workstation_shutdown_control"] = json!(true);
    fs::write(&client.config.stdout_log, format!("{record}\n")).unwrap();

    let path = root.0.join(CONFIG_FILE);
    let mut connection: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    connection["gatewayPort"] = json!(service.gateway_port.unwrap());
    connection["supervisor"] = json!({
        "kind": "windows-task",
        "taskName": format!(r"\{}\MissingWorkstation", root.0.file_name().unwrap().to_string_lossy()),
    });
    fs::write(path, connection.to_string()).unwrap();
    let runtime = AppRuntime::new(root.0.clone());
    (root, service, runtime)
}

#[test]
fn unavailable_supervisor_disables_start_and_restart_but_keeps_authenticated_stop() {
    let (_root, service, runtime) = attached_with_unavailable_supervisor();
    let panel = backend::get_panel_state(&runtime).unwrap();
    assert_eq!(panel["gateway"]["live"], true);
    let controls = &panel["gateway"]["controls"];
    assert_eq!(controls["canStart"], false);
    assert_eq!(controls["canRestart"], false);
    assert!(controls["reason"].as_str().is_some());
    assert_eq!(controls["canStop"], true);

    // An omitted IPC intent takes the safe Start path, even for a live service.
    let legacy_intent = Option::<backend::GatewayIntent>::None.unwrap_or_default();
    assert!(matches!(legacy_intent, backend::GatewayIntent::Start));
    assert!(backend::start_or_restart_gateway(&runtime, legacy_intent).is_err());
    assert!(backend::start_or_restart_gateway(&runtime, backend::GatewayIntent::Restart).is_err());
    assert!(!service.state.lock().unwrap().requests.iter().any(|(_, path, _)| path == "/api/shutdown"));
}

#[test]
fn authenticated_stop_shuts_down_with_an_unavailable_supervisor() {
    let (_root, service, runtime) = attached_with_unavailable_supervisor();
    let panel = backend::stop_gateway(&runtime).expect("cooperative stop with an unavailable supervisor");
    assert_eq!(panel["gateway"]["live"], false);
    assert_eq!(panel["gateway"]["controls"]["canStop"], false);
    assert_eq!(panel["gateway"]["controls"]["canStart"], false);
    assert!(backend::start_or_restart_gateway(&runtime, backend::GatewayIntent::Start).is_err());
    let state = service.state.lock().unwrap();
    let shutdown_requests: Vec<_> = state.requests.iter().filter(|(_, path, _)| path == "/api/shutdown").collect();
    assert_eq!(shutdown_requests.len(), 1);
    assert_eq!(shutdown_requests[0].0, "POST");
    assert_eq!(shutdown_requests[0].2, json!({}));
}

#[test]
fn loopback_probe_distinguishes_a_listener_from_a_closed_port() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    assert!(!closed_loopback_port(port, Instant::now() + PORT_PROBE_TIMEOUT));
    drop(listener);
    assert!(!closed_loopback_port(port, Instant::now()));
    assert!(closed_loopback_port(port, Instant::now() + PORT_PROBE_TIMEOUT));
}

#[test]
fn supervisor_is_optional_and_only_a_typed_local_task_can_be_configured() {
    let root = TestRoot::new();
    config(&root.0, 18890);
    let path = root.0.join(CONFIG_FILE);
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert!(read_config(&path).is_ok());
    value["supervisor"] = json!({"kind":"windows-task","taskName":"\\Fixture-Workstation"});
    fs::write(&path, value.to_string()).unwrap();
    assert!(read_config(&path).is_ok());
    for supervisor in [
        json!({"kind":"shell","command":"anything"}),
        json!({"kind":"windows-task","taskName":"\\Fixture","command":"anything"}),
        json!({"kind":"windows-task","taskName":"\\\\remote\\Fixture"}),
    ] {
        value["supervisor"] = supervisor;
        fs::write(&path, value.to_string()).unwrap();
        assert!(read_config(&path).is_err());
    }
}
