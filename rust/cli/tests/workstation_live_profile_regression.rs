use agent_bridge_core::CoreDatabase;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

static SEQ: AtomicU64 = AtomicU64::new(0);
const WORKSTATION_ORIGIN: &str = "https://live-workstation.example.invalid";
const CHATGPT_CALLBACK: &str = "https://chatgpt.com/connector_platform_oauth_redirect";
const GEMINI_CALLBACK: &str = "https://oauth-redirect.googleusercontent.com/r/agent-bridge-fixture";
const DIRECT_PROCESS_TOOLS: [&str; 4] = [
    "desktop_start_process", "desktop_read_process",
    "desktop_interact_process", "desktop_terminate_process",
];

struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        #[cfg(unix)]
        let base = {
            use std::os::unix::fs::PermissionsExt;
            let root = std::env::var_os("HOME").map(PathBuf::from).unwrap()
                .join(".ab-live-profile-tests");
            fs::create_dir_all(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            root
        };
        #[cfg(not(unix))]
        let base = {
            let root = std::env::temp_dir();
            let root = fs::canonicalize(&root).unwrap_or(root);
            root.to_str().and_then(|path| path.strip_prefix("\\\\?\\"))
                .map(PathBuf::from).unwrap_or(root)
        };
        let path = base.join(format!("live-profile-{}-{}", std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir_all(&path).unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(path)
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

fn private_empty_directory(path: &Path) {
    agent_bridge_lifecycle::initialize_operator_settings(path).unwrap();
    for entry in fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() { fs::remove_file(path).unwrap(); }
    }
}

struct Response {
    status: u16,
    headers: BTreeMap<String, String>,
    body: String,
}
impl Response {
    fn json(&self) -> Value { serde_json::from_str(&self.body).expect("HTTP JSON response") }
}

// Keep one TCP connection through every profile change. Restarting the MCP
// listener or losing initialized router state cannot satisfy this fixture.
struct Connection {
    port: u16,
    stream: BufReader<TcpStream>,
}
impl Connection {
    fn open(port: u16) -> Self {
        let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
        Self { port, stream: BufReader::new(stream) }
    }

    fn request(&mut self, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Response {
        let mut request = format!("{method} {path} HTTP/1.1\r\n");
        if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("host")) {
            request.push_str(&format!("Host: 127.0.0.1:{}\r\n", self.port));
        }
        request.push_str(&format!("Connection: keep-alive\r\nContent-Length: {}\r\n", body.len()));
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        request.push_str(body);
        self.stream.get_mut().write_all(request.as_bytes()).unwrap();
        let mut line = String::new();
        self.stream.read_line(&mut line).unwrap();
        let status = line.split_whitespace().nth(1).expect("HTTP status").parse().unwrap();
        let mut response_headers = BTreeMap::new();
        loop {
            line.clear();
            assert!(self.stream.read_line(&mut line).unwrap() > 0, "complete HTTP headers");
            if line == "\r\n" { break; }
            let (name, value) = line.trim_end().split_once(':').expect("HTTP header");
            response_headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
        }
        let length: usize = response_headers.get("content-length").expect("bounded HTTP body").parse().unwrap();
        assert!(length <= 1024 * 1024);
        let mut bytes = vec![0; length];
        self.stream.read_exact(&mut bytes).unwrap();
        Response { status, headers: response_headers, body: String::from_utf8(bytes).unwrap() }
    }
}

struct LiveWorkstation {
    child: Child,
    ui_port: u16,
    token: String,
    mcp_port: u16,
}
impl LiveWorkstation {
    fn start(root: &Path, profile: &str, enable_processes: bool) -> Self {
        let flags: &[&str] = if enable_processes { &["--enable-processes"] } else { &[] };
        Self::start_with_flags(root, profile, flags)
    }

    fn start_with_flags(root: &Path, profile: &str, flags: &[&str]) -> Self {
        let project = root.join("project");
        let db_dir = root.join("db");
        let db = db_dir.join("missions.sqlite");
        let settings = root.join("settings");
        let workstation = root.join("oauth-workstation");
        let missions = root.join("oauth-missions");
        let lifecycle = root.join("lifecycle");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&db_dir).unwrap();
        drop(CoreDatabase::initialize_new(&db).unwrap());
        agent_bridge_lifecycle::initialize_operator_settings(&settings).unwrap();
        for directory in [&workstation, &missions, &lifecycle] {
            private_empty_directory(directory);
        }
        let free_port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mcp_port = free_port.local_addr().unwrap().port();
        drop(free_port);
        Self::start_existing(root, profile, flags, mcp_port)
    }

    fn start_existing(root: &Path, profile: &str, flags: &[&str], mcp_port: u16) -> Self {
        let project = root.join("project");
        let db = root.join("db/missions.sqlite");
        let settings = root.join("settings");
        let workstation = root.join("oauth-workstation");
        let missions = root.join("oauth-missions");
        let lifecycle = root.join("lifecycle");
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-bridge"));
        command.args(["gemini", "workstation"])
            .arg(&db).arg(&workstation).arg(WORKSTATION_ORIGIN).arg(mcp_port.to_string())
            .arg("--project").arg(&project)
            .args(["--profile", profile])
            .arg("--missions-state").arg(&missions)
            .args(["--missions-origin", "https://live-missions.example.invalid"])
            .arg("--settings-dir").arg(&settings)
            .arg("--lifecycle-dir").arg(&lifecycle)
            .args(["--ui-port", "0"])
            .env_remove("AGENT_BRIDGE_DESKTOP_PROFILE")
            .env_remove("AGENT_BRIDGE_DESKTOP_PROFILE_LOCK")
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::inherit());
        command.args(flags);
        Self::spawn(command, mcp_port)
    }

    fn standalone_ui(database: &Path) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-bridge"));
        command.args(["ui", "--port", "0"]).arg("--database").arg(database)
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::inherit());
        Self::spawn(command, 0)
    }

    fn spawn(mut command: Command, mcp_port: u16) -> Self {
        let mut child = command.spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                let Ok(value) = serde_json::from_str::<Value>(&line) else { continue };
                if value["service"] == "agent-bridge-ui" {
                    let _ = sender.send(value);
                    break;
                }
            }
        });
        let startup = match receiver.recv_timeout(Duration::from_secs(10)) {
            Ok(value) => value,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("workstation must start its embedded operator UI: {error}");
            }
        };
        let ui_port = startup["listen"].as_str().unwrap().rsplit(':').next().unwrap().parse().unwrap();
        let token = startup["ui_url"].as_str().unwrap().split_once("?token=").unwrap().1.to_owned();
        Self { child, ui_port, token, mcp_port }
    }

    fn wait_for_successful_exit(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "cooperative workstation shutdown failed: {status}");
                return;
            }
            assert!(Instant::now() < deadline, "workstation did not finish cooperative shutdown");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn ui(&self, method: &str, path: &str, body: Option<Value>) -> Response {
        Connection::open(self.ui_port).request(method, path,
            &[("X-Agent-Bridge-Token", &self.token), ("Content-Type", "application/json")],
            &body.map(|value| value.to_string()).unwrap_or_default())
    }
}
impl Drop for LiveWorkstation {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn form(pairs: &[(&str, &str)]) -> String {
    fn encode(value: &str) -> String {
        value.bytes().map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                char::from(byte).to_string()
            } else { format!("%{byte:02X}") }
        }).collect()
    }
    pairs.iter().map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>().join("&")
}

fn authorize(live: &LiveWorkstation, connection: &mut Connection, callback: &str) -> String {
    let enrollment = live.ui("POST", "/api/oauth/enroll", Some(json!({"confirm":"APPROVE"})));
    assert_eq!(enrollment.status, 200, "{}", enrollment.body);
    let registration = connection.request("POST", "/oauth/register",
        &[("Content-Type", "application/json")], &json!({
            "redirect_uris":[callback], "token_endpoint_auth_method":"client_secret_post",
            "grant_types":["authorization_code", "refresh_token"], "response_types":["code"]
        }).to_string());
    assert_eq!(registration.status, 201);
    let client = registration.json();
    let client_id = client["client_id"].as_str().unwrap();
    let client_secret = client["client_secret"].as_str().unwrap();
    let resource = format!("{WORKSTATION_ORIGIN}/mcp");
    // RFC 7636's S256 test vector, independent of the server implementation.
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let query = form(&[
        ("response_type", "code"), ("client_id", client_id), ("redirect_uri", callback),
        ("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
        ("code_challenge_method", "S256"), ("state", "live-profile-fixture"),
        ("resource", &resource), ("scope", "mcp"),
    ]);
    let authorize_path = format!("/oauth/authorize?{query}");
    let pending = connection.request("GET", &authorize_path, &[], "");
    assert_eq!(pending.status, 200, "{}", pending.body);
    let listed = live.ui("GET", "/api/oauth", None);
    assert_eq!(listed.status, 200);
    let requests = listed.json();
    let request_id = requests["pending"][0]["id"].as_str().unwrap();
    let approved = live.ui("POST", "/api/oauth/approve",
        Some(json!({"request_id":request_id, "redirect_uri":callback, "confirm":"APPROVE"})));
    assert_eq!(approved.status, 200, "{}", approved.body);
    let redirect = connection.request("GET", &authorize_path, &[], "");
    assert_eq!(redirect.status, 302, "{}", redirect.body);
    let location = &redirect.headers["location"];
    assert!(location.starts_with(&format!("{callback}?")));
    let code = location.split_once('?').unwrap().1.split('&')
        .filter_map(|pair| pair.split_once('=')).find(|(key, _)| *key == "code").unwrap().1;
    let exchange = connection.request("POST", "/oauth/token",
        &[("Content-Type", "application/x-www-form-urlencoded")], &form(&[
            ("grant_type", "authorization_code"), ("client_id", client_id),
            ("client_secret", client_secret), ("code", code), ("redirect_uri", callback),
            ("code_verifier", verifier), ("resource", &resource),
        ]));
    assert_eq!(exchange.status, 200);
    exchange.json()["access_token"].as_str().unwrap().to_owned()
}

fn mcp(connection: &mut Connection, bearer: &str, user_agent: &str, frame: Value) -> Value {
    let response = connection.request("POST", "/mcp",
        &[("Content-Type", "application/json"), ("Authorization", bearer), ("User-Agent", user_agent)],
        &frame.to_string());
    assert!(matches!(response.status, 200 | 202), "MCP authorization/listener lost: {}", response.body);
    if response.body.is_empty() { Value::Null } else { response.json() }
}

struct AuthenticatedMcp {
    connection: Connection,
    bearer: String,
    user_agent: &'static str,
    next_id: u64,
}
impl AuthenticatedMcp {
    fn connect(live: &LiveWorkstation) -> Self {
        Self::connect_as(live, CHATGPT_CALLBACK, "live-profile-fixture/1")
    }

    fn connect_as(live: &LiveWorkstation, callback: &str, user_agent: &'static str) -> Self {
        let mut connection = Connection::open(live.mcp_port);
        let bearer = format!("Bearer {}", authorize(live, &mut connection, callback));
        Self::from_bearer(connection, bearer, user_agent)
    }

    fn from_bearer(connection: Connection, bearer: String, user_agent: &'static str) -> Self {
        let mut session = Self { connection, bearer, user_agent, next_id: 1 };
        let initialized = session.request("initialize", json!({
            "protocolVersion":"2025-03-26", "capabilities":{},
            "clientInfo":{"name":"live-profile-fixture", "version":"1"}
        }));
        assert!(initialized["result"].is_object(), "{initialized}");
        mcp(&mut session.connection, &session.bearer, session.user_agent,
            json!({"jsonrpc":"2.0", "method":"notifications/initialized"}));
        session
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        mcp(&mut self.connection, &self.bearer, self.user_agent,
            json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params}))
    }

    fn call(&mut self, name: &str, arguments: Value) -> Value {
        self.request("tools/call", json!({"name":name, "arguments":arguments}))
    }

    fn call_json(&mut self, name: &str, arguments: Value) -> Value {
        let response = self.call(name, arguments);
        assert!(succeeded(&response), "{name}: {response}");
        let text = response["result"]["content"][0]["text"].as_str()
            .expect("tool must return a text result");
        serde_json::from_str(text).expect("tool must return JSON")
    }

    fn catalog(&mut self) -> Vec<Value> {
        let response = self.request("tools/list", json!({}));
        response["result"]["tools"].as_array().expect("MCP tool catalog").clone()
    }
}

fn succeeded(response: &Value) -> bool {
    response.get("error").is_none() && response["result"].is_object()
        && response["result"]["isError"].as_bool() != Some(true)
}

#[test]
fn file_read_result_chatgpt_uses_file_content_with_a_gemini_user_agent() {
    assert_file_read_result(CHATGPT_CALLBACK, "Gemini/1.0", "file_content", "content");
}

#[test]
fn file_read_result_gemini_keeps_content_with_a_chatgpt_user_agent() {
    assert_file_read_result(GEMINI_CALLBACK, "ChatGPT/1.0", "content", "file_content");
}

fn assert_file_read_result(
    callback: &str,
    user_agent: &'static str,
    expected: &str,
    absent: &str,
) {
    const FILE_TEXT: &str = r#"{"content":"nested text"}"#;
    let sandbox = Sandbox::new();
    let live = LiveWorkstation::start(&sandbox.0, "workspace-write", false);
    let path = sandbox.0.join("project/fixture.txt");
    fs::write(&path, FILE_TEXT).unwrap();
    let marker = sandbox.0.join("oauth-workstation/.agent-bridge-workstation-scope-v2.json");
    let initial_marker = fs::read(&marker).unwrap();
    let mut mcp = AuthenticatedMcp::connect_as(&live, callback, user_agent);

    let catalog = mcp.catalog();
    assert!(catalog.iter().any(|tool| tool["name"] == "desktop_read_file"));
    let policy = mcp.call_json("desktop_policy_status", json!({}));
    assert_eq!(policy["profile"], "workspace-write");

    let id = mcp.next_id;
    let response = mcp.call("desktop_read_file", json!({"path":"fixture.txt"}));
    assert!(succeeded(&response));
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], id);
    let blocks = response["result"]["content"].as_array().expect("MCP result content array");
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0]["type"], "text");
    let business: Value = serde_json::from_str(blocks[0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        business.get(expected).and_then(Value::as_str),
        Some(FILE_TEXT),
        "authenticated file response must contain the business key {expected}"
    );
    assert!(business.get(absent).is_none());
    assert_eq!(business["path"], "fixture.txt");
    assert_eq!(business["offset"], 0);
    assert_eq!(business["length"], 1);
    assert_eq!(business["total_lines"], 1);
    assert_eq!(business["truncated"], false);
    assert_eq!(
        business["sha256"],
        "19d147cfe46868190147298a0d506033162522a37af506d92c126ace072dbf90"
    );
    assert_eq!(business["observation_ttl_seconds"], 300);
    let observation = business["observation_id"].as_str().expect("observation capability");

    let refused = mcp.call("desktop_read_file", json!({"path":"/outside-fixture.txt"}));
    assert_eq!(refused["result"]["isError"], true);
    let error: Value = serde_json::from_str(
        refused["result"]["content"][0]["text"].as_str().unwrap(),
    ).unwrap();
    assert_eq!(error, json!({"code":"INVALID_PATH","message":"Absolute path is refused"}));

    let rewrite = mcp.call("desktop_write_file", json!({
        "path":"fixture.txt", "mode":"rewrite", "content":"updated text",
        "observation_id":observation
    }));
    assert!(succeeded(&rewrite));
    assert_eq!(fs::read_to_string(path).unwrap(), "updated text");
    let updated = mcp.call_json("desktop_read_file", json!({"path":"fixture.txt"}));
    assert_eq!(updated[expected], "updated text");
    assert!(updated.get(absent).is_none());

    assert_eq!(mcp.call_json("desktop_policy_status", json!({})), policy);
    assert_eq!(mcp.catalog(), catalog);
    assert_eq!(fs::read(marker).unwrap(), initial_marker);
}

#[test]
fn live_profile_changes_apply_to_one_authenticated_listener_without_rebinding_its_scope() {
    let sandbox = Sandbox::new();
    let mut live = LiveWorkstation::start(&sandbox.0, "workspace-write", false);
    let marker = sandbox.0.join("oauth-workstation").join(".agent-bridge-workstation-scope-v2.json");
    let marker_before = fs::read(&marker).expect("immutable workstation scope");
    let original_pid = live.child.id();
    let initial = live.ui("GET", "/api/profile", None);
    assert_eq!(initial.status, 200);
    let initial = initial.json();
    assert_eq!(initial["configured"], true);
    assert_eq!(initial["active_profile"], "workspace-write");
    assert_eq!(initial["max_profile"], "workspace-write");
    let available = initial["available_profiles"].as_array().unwrap();
    assert_eq!(available.len(), 2);
    assert!(available.contains(&json!("read-only")));
    assert!(available.contains(&json!("workspace-write")));

    let unauthenticated = Connection::open(live.ui_port).request("GET", "/api/profile", &[], "");
    assert_eq!(unauthenticated.status, 401);
    let bad_token = Connection::open(live.ui_port).request("POST", "/api/profile",
        &[("X-Agent-Bridge-Token", "invalid"), ("Content-Type", "application/json")],
        r#"{"profile":"read-only"}"#);
    assert_eq!(bad_token.status, 401);
    let foreign_origin = Connection::open(live.ui_port).request("POST", "/api/profile",
        &[("X-Agent-Bridge-Token", &live.token), ("Origin", "https://evil.example.invalid"),
          ("Content-Type", "application/json")], r#"{"profile":"read-only"}"#);
    assert_eq!(foreign_origin.status, 403);
    for invalid in [
        json!({"profile":"admin"}), json!({"profile":"read-only", "confirm":true}),
        json!({"profile":null}), json!({})
    ] {
        assert_eq!(live.ui("POST", "/api/profile", Some(invalid)).status, 400);
    }
    for unavailable in ["full-control", "fully-unlocked"] {
        assert_eq!(live.ui("POST", "/api/profile", Some(json!({"profile":unavailable}))).status, 403);
    }
    assert_eq!(live.ui("GET", "/api/profile", None).json()["active_profile"], "workspace-write");

    let mut mcp = AuthenticatedMcp::connect(&live);

    let before = mcp.call("desktop_write_file",
        json!({"path":"before.txt", "content":"authorized before switch", "mode":"rewrite"}));
    assert!(succeeded(&before), "{before}");
    assert_eq!(fs::read_to_string(sandbox.0.join("project/before.txt")).unwrap(), "authorized before switch");

    let read_only = live.ui("POST", "/api/profile", Some(json!({"profile":"read-only"})));
    assert_eq!(read_only.status, 200, "{}", read_only.body);
    assert_eq!(read_only.json()["active_profile"], "read-only");
    let denied = mcp.call("desktop_write_file",
        json!({"path":"denied.txt", "content":"must not exist", "mode":"rewrite"}));
    assert!(!succeeded(&denied), "write must be denied immediately after lowering the live profile");
    assert!(!sandbox.0.join("project/denied.txt").exists());
    let read = mcp.call("desktop_read_file", json!({"path":"before.txt"}));
    assert!(succeeded(&read), "same OAuth bearer must retain reads: {read}");

    let resumed = live.ui("POST", "/api/profile", Some(json!({"profile":"workspace-write"})));
    assert_eq!(resumed.status, 200, "{}", resumed.body);
    let after = mcp.call("desktop_write_file",
        json!({"path":"after.txt", "content":"authorized after switch", "mode":"rewrite"}));
    assert!(succeeded(&after), "same authenticated TCP/MCP session must resume writes: {after}");
    assert_eq!(fs::read_to_string(sandbox.0.join("project/after.txt")).unwrap(), "authorized after switch");
    assert_eq!(live.child.id(), original_pid);
    assert!(live.child.try_wait().unwrap().is_none(), "gateway process must remain alive");
    assert_eq!(fs::read(marker).unwrap(), marker_before, "profile clicks must not rewrite the OAuth scope marker");
}

fn assert_process_catalog(catalog: &[Value], enabled: bool) {
    let names: Vec<_> = catalog.iter().map(|tool| tool["name"].as_str().unwrap()).collect();
    assert_eq!(names.iter().copied().collect::<BTreeSet<_>>().len(), names.len(),
        "the startup catalog must not attach duplicate providers");
    for name in DIRECT_PROCESS_TOOLS {
        assert_eq!(names.iter().filter(|actual| **actual == name).count(), usize::from(enabled),
            "unexpected catalog exposure for {name}");
    }
    if enabled {
        let start = catalog.iter().find(|tool| tool["name"] == "desktop_start_process").unwrap();
        for argument in ["command", "shell", "program", "args"] {
            assert!(start["inputSchema"]["properties"].get(argument).is_some(),
                "Fully Unlocked must expose the direct process contract: {start}");
        }
    }
}

fn change_profile(live: &LiveWorkstation, profile: &str) {
    let response = live.ui("POST", "/api/profile", Some(json!({"profile":profile})));
    assert_eq!(response.status, 200, "switch to {profile}: {}", response.body);
    assert_eq!(response.json()["active_profile"], profile);
}

fn assert_same_workstation(live: &mut LiveWorkstation, root: &Path, pid: u32, marker: &[u8]) {
    assert_eq!(live.child.id(), pid);
    assert!(live.child.try_wait().unwrap().is_none(), "gateway process must remain alive");
    assert_eq!(fs::read(root.join("oauth-workstation/.agent-bridge-workstation-scope-v2.json")).unwrap(),
        marker, "profile changes must preserve the original OAuth scope");
}

fn run_native_shell(mcp: &mut AuthenticatedMcp, project: &Path, label: &str) {
    #[cfg(windows)]
    let (shell, command) = ("cmd",
        format!("echo {label}> {label}.txt & echo {label} & exit /b 7"));
    #[cfg(unix)]
    let (shell, command) = ("sh",
        format!("printf '%s\\n' '{label}' > '{label}.txt'; printf '%s\\n' '{label}'; exit 7"));
    let mut result = mcp.call_json("desktop_start_process", json!({
        "shell":shell, "command":command, "cwd":project, "timeout_ms":1000
    }));
    let sid = result["session_id"].as_str().unwrap().to_owned();
    let mut output = result["stdout"].as_str().unwrap().to_owned();
    let mut errors = result["stderr"].as_str().unwrap().to_owned();
    let deadline = Instant::now() + Duration::from_secs(5);
    while result["status"] != "exited" {
        assert!(Instant::now() < deadline, "native shell did not exit: {result}");
        result = mcp.call_json("desktop_read_process", json!({"session_id":sid,"timeout_ms":100}));
        output.push_str(result["stdout"].as_str().unwrap());
        errors.push_str(result["stderr"].as_str().unwrap());
    }
    assert_eq!(result["exit_code"], 7, "shell result: {result}; stderr: {errors}");
    assert_eq!(result["output_complete"], true, "{result}");
    assert!(output.contains(label), "shell stdout: {output:?}; stderr: {errors:?}");
    assert_eq!(fs::read_to_string(project.join(format!("{label}.txt"))).unwrap().trim(), label,
        "shell must execute in the requested cwd");
}

fn start_owned_fixture(mcp: &mut AuthenticatedMcp, heartbeat: &Path) -> String {
    let started = mcp.call_json("desktop_start_process", json!({
        "program":std::env::current_exe().unwrap(),
        "args":["--ignored", "--exact", "owned_process_fixture", "--nocapture"],
        "timeout_ms":1000
    }));
    let sid = started["session_id"].as_str().unwrap().to_owned();
    let message = "literal stdin \"quoted\" ; $value & UTF-8 €";
    let response = mcp.call_json("desktop_interact_process", json!({
        "session_id":sid, "input":format!("{}\n", json!({"heartbeat":heartbeat,"echo":message})),
        "timeout_ms":1000
    }));
    assert_eq!(response["input_queued"], true);
    let mut output = format!("{}{}", started["stdout"].as_str().unwrap(), response["stdout"].as_str().unwrap());
    let deadline = Instant::now() + Duration::from_secs(5);
    while !output.contains(&format!("echo:{message}")) {
        assert!(Instant::now() < deadline, "owned program did not echo stdin: {output:?}");
        let response = mcp.call_json("desktop_read_process", json!({"session_id":sid,"timeout_ms":100}));
        assert_eq!(response["running"], true, "persistent fixture exited: {response}");
        output.push_str(response["stdout"].as_str().unwrap());
    }
    assert!(output.contains("live-owned-ready"), "the literal program must execute: {output}");
    while fs::metadata(heartbeat).map(|file| file.len()).unwrap_or(0) < 3 {
        assert!(Instant::now() < deadline, "owned program did not write its heartbeat");
        std::thread::sleep(Duration::from_millis(20));
    }
    let response = mcp.call_json("desktop_read_process", json!({"session_id":sid,"timeout_ms":0}));
    assert_eq!(response["running"], true, "heartbeat must come from a durable owned child: {response}");
    sid
}

fn process_requests(sid: &str) -> [(&'static str, Value); 4] {
    [
        ("desktop_start_process", json!({"command":"echo forbidden-process","timeout_ms":0})),
        ("desktop_read_process", json!({"session_id":sid,"timeout_ms":0})),
        ("desktop_interact_process", json!({"session_id":sid,"input":"forbidden\n","timeout_ms":0})),
        ("desktop_terminate_process", json!({"session_id":sid})),
    ]
}

fn assert_heartbeat_stopped(path: &Path) {
    let stopped_size = fs::metadata(path).unwrap().len();
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(fs::metadata(path).unwrap().len(), stopped_size,
        "owned child continued running after the profile change returned");
}

// This ignored test is launched only as the literal child of the MCP fixture.
// Its only effects are stdout and a bounded heartbeat file in that fixture's sandbox.
#[test]
#[ignore]
fn owned_process_fixture() {
    println!("live-owned-ready");
    std::io::stdout().flush().unwrap();
    for line in std::io::stdin().lock().lines() {
        let request: Value = serde_json::from_str(&line.unwrap()).unwrap();
        if let Some(path) = request["heartbeat"].as_str() {
            let mut file = fs::OpenOptions::new().create_new(true).write(true).open(path).unwrap();
            std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(30);
                while Instant::now() < deadline {
                    file.write_all(b".").unwrap();
                    file.flush().unwrap();
                    std::thread::sleep(Duration::from_millis(20));
                }
            });
        }
        if let Some(message) = request["echo"].as_str() {
            println!("echo:{message}");
            std::io::stdout().flush().unwrap();
        }
    }
}

#[test]
fn fully_unlocked_processes_revoke_and_resume_on_the_same_oauth_workstation() {
    let sandbox = Sandbox::new();
    let mut live = LiveWorkstation::start(&sandbox.0, "fully-unlocked", true);
    let project = sandbox.0.join("project");
    let marker = fs::read(sandbox.0.join("oauth-workstation/.agent-bridge-workstation-scope-v2.json")).unwrap();
    let pid = live.child.id();
    let profile = live.ui("GET", "/api/profile", None).json();
    assert_eq!(profile["active_profile"], "fully-unlocked");
    assert_eq!(profile["max_profile"], "fully-unlocked");
    assert_eq!(profile["available_profiles"].as_array().unwrap().len(), 4);

    let mut mcp = AuthenticatedMcp::connect(&live);
    let catalog = mcp.catalog();
    assert_process_catalog(&catalog, true);
    run_native_shell(&mut mcp, &project, "initial-native-shell");

    let mut previous_sid = None;
    for (lower, label) in [("full-control", "after-full-control"), ("read-only", "after-read-only")] {
        let heartbeat = project.join(format!("{lower}-heartbeat.txt"));
        let sid = start_owned_fixture(&mut mcp, &heartbeat);
        assert_ne!(previous_sid.as_deref(), Some(sid.as_str()), "reactivation must create a new owned session");
        change_profile(&live, lower);
        assert_heartbeat_stopped(&heartbeat);
        for (name, arguments) in process_requests(&sid) {
            let denied = mcp.call(name, arguments);
            assert!(!succeeded(&denied) && denied.to_string().contains("PROFILE_RESTRICTED_BY_OPERATOR"),
                "{name} must enforce the live {lower} profile before accessing a session: {denied}");
        }
        assert_eq!(mcp.catalog(), catalog, "lowering the profile must not replace the startup catalog");
        assert_same_workstation(&mut live, &sandbox.0, pid, &marker);

        change_profile(&live, "fully-unlocked");
        let stale = mcp.call("desktop_read_process", json!({"session_id":sid,"timeout_ms":0}));
        assert!(!succeeded(&stale) && stale.to_string().contains("PROCESS_SESSION_UNKNOWN"),
            "reactivation must not revive a revoked process capability: {stale}");
        run_native_shell(&mut mcp, &project, label);
        assert_same_workstation(&mut live, &sandbox.0, pid, &marker);
        previous_sid = Some(sid);
    }
}

#[test]
fn fully_unlocked_without_process_flag_never_exposes_or_enables_direct_processes() {
    let sandbox = Sandbox::new();
    let mut live = LiveWorkstation::start(&sandbox.0, "fully-unlocked", false);
    let marker = fs::read(sandbox.0.join("oauth-workstation/.agent-bridge-workstation-scope-v2.json")).unwrap();
    let pid = live.child.id();
    let mut mcp = AuthenticatedMcp::connect(&live);
    let catalog = mcp.catalog();
    assert_process_catalog(&catalog, false);
    for cycle in 0..2 {
        for (name, arguments) in process_requests("00000000-0000-4000-8000-000000000000") {
            let denied = mcp.call(name, arguments);
            assert!(!succeeded(&denied), "{name} must remain unavailable without --enable-processes: {denied}");
        }
        assert_eq!(mcp.catalog(), catalog);
        assert_same_workstation(&mut live, &sandbox.0, pid, &marker);
        if cycle == 0 {
            change_profile(&live, "read-only");
            change_profile(&live, "fully-unlocked");
        }
    }
}

#[test]
fn live_console_reads_the_task_room_store_with_all_flags_and_wal_present() {
    let sandbox = Sandbox::new();
    let mut live = LiveWorkstation::start_with_flags(&sandbox.0, "fully-unlocked",
        &["--enable-task-rooms", "--enable-settings-tools", "--enable-processes"]);
    let database = sandbox.0.join("db/missions.sqlite");
    let wal = sandbox.0.join("db/missions.sqlite-wal");
    assert!(fs::metadata(&wal).unwrap().len() > 0, "Task Rooms must hold a real WAL database");
    assert!(sandbox.0.join("db/missions.sqlite-shm").is_file());
    assert!(agent_bridge_core::inspect_existing(&database).unwrap_err().to_string()
        .contains("SQLite sidecar present"), "offline Core inspection must still fail closed");
    let marker = fs::read(sandbox.0.join("oauth-workstation/.agent-bridge-workstation-scope-v2.json")).unwrap();
    let pid = live.child.id();

    let mut mcp = AuthenticatedMcp::connect(&live);
    let catalog = mcp.catalog();
    assert_process_catalog(&catalog, true);
    for name in ["desktop_task_manage", "desktop_mcp_manage"] {
        assert!(catalog.iter().any(|tool| tool["name"] == name), "missing authorized family: {name}");
    }
    let context = mcp.call_json("desktop_task_manage", json!({
        "action":"context_create", "context_label":"Live console fixture",
        "project":"live-ui-project", "device":"fixture-only"
    }));
    let handle = context["context_handle"].as_str().unwrap();
    let task = mcp.call_json("desktop_task_manage", json!({
        "action":"create", "context_handle":handle,
        "title":"Visible through the shared live store", "goal":"Observe committed MCP changes in the console",
        "steps":[{"id":"witness", "title":"Verify the live snapshot", "phase":"verify"}]
    }));
    let task_id = task["task"]["task_id"].as_str().unwrap();
    let snapshot = live.ui("GET", "/api/missions", None);
    assert_eq!(snapshot.status, 200, "live UI must use the already qualified Core connection: {}", snapshot.body);
    let initial = snapshot.json();
    assert_eq!(initial["task_room_schema_present"], true);
    assert_eq!(initial["total_task_rooms"], 1);
    assert_eq!(initial["task_rooms"][0]["task_id"], task_id);
    assert_eq!(initial["task_rooms"][0]["title"], "Visible through the shared live store");
    assert!(!snapshot.body.contains(handle), "operator snapshots must not expose Task Room capabilities");
    assert!(!snapshot.body.contains("handle_hash"));

    let overview = live.ui("GET", "/api/overview", None);
    assert_eq!(overview.status, 200);
    let overview = overview.json();
    assert!(overview["database"].get("error").is_none(), "{overview}");
    assert_eq!(overview["database"]["schema_version"], agent_bridge_core::CURRENT_SCHEMA_VERSION);
    assert_eq!(overview["database"]["counts"]["task_rooms"], 1);
    assert_eq!(overview["database"]["counts"]["missions"]["total"], 0);

    mcp.call_json("desktop_task_manage", json!({
        "action":"checkpoint", "context_handle":handle, "task_id":task_id,
        "completed_step_ids":["witness"], "summary":"MCP checkpoint visible immediately in the live console"
    }));
    change_profile(&live, "read-only");
    let refreshed = live.ui("GET", "/api/missions", None);
    assert_eq!(refreshed.status, 200, "operator reads must survive a live downgrade: {}", refreshed.body);
    let refreshed = refreshed.json();
    assert_eq!(refreshed["task_rooms"][0]["summary"], "MCP checkpoint visible immediately in the live console");
    assert_eq!(refreshed["task_rooms"][0]["steps_completed"], 1);
    let denied = mcp.call("desktop_task_manage", json!({
        "action":"create", "context_handle":handle, "title":"Must not be created in Read Only"
    }));
    assert!(!succeeded(&denied), "the shared UI reader must not expand remote Task Room permissions");
    change_profile(&live, "fully-unlocked");
    let readback = mcp.call_json("desktop_task_manage",
        json!({"action":"get", "context_handle":handle, "task_id":task_id}));
    assert_eq!(readback["task"]["summary"], refreshed["task_rooms"][0]["summary"]);
    assert!(wal.is_file(), "the UI must not checkpoint or remove the live WAL");
    assert_same_workstation(&mut live, &sandbox.0, pid, &marker);

    let standalone = LiveWorkstation::standalone_ui(&database);
    let refused = standalone.ui("GET", "/api/missions", None);
    assert_eq!(refused.status, 400, "standalone must retain offline database qualification");
    assert_eq!(refused.json()["error"], "DATABASE_UNAVAILABLE");
    assert!(refused.body.contains("SQLite sidecar present"));
    assert_eq!(standalone.ui("GET", "/api/profile", None).json()["configured"], false);
}

#[test]
fn local_shutdown_rejects_unauthorized_and_cross_site_requests() {
    let sandbox = Sandbox::new();
    let mut live = LiveWorkstation::start(&sandbox.0, "workspace-write", false);
    let owner = sandbox.0.join("oauth-workstation/running.lock");
    let nonce = fs::read(&owner).unwrap();
    let origin = format!("http://127.0.0.1:{}", live.ui_port);
    let cases: Vec<(Vec<(&str, &str)>, u16, &str)> = vec![
        (vec![], 401, "TOKEN_REQUIRED"),
        (vec![("X-Agent-Bridge-Token", "wrong-token")], 401, "TOKEN_INVALID"),
        (vec![("X-Agent-Bridge-Token", &live.token), ("Origin", "https://untrusted.example.invalid")],
            403, "ORIGIN_REJECTED"),
        (vec![("X-Agent-Bridge-Token", &live.token), ("Origin", &origin), ("Sec-Fetch-Site", "cross-site")],
            403, "FETCH_SITE_REJECTED"),
        (vec![("X-Agent-Bridge-Token", &live.token), ("Host", "untrusted.example.invalid")],
            403, "HOST_REJECTED"),
    ];
    for (headers, status, error) in cases {
        let response = Connection::open(live.ui_port).request("POST", "/api/shutdown", &headers, "");
        assert_eq!(response.status, status, "{error}: {}", response.body);
        assert_eq!(response.json()["error"], error);
        assert!(live.child.try_wait().unwrap().is_none(), "a rejected request stopped the service");
        assert_eq!(fs::read(&owner).unwrap(), nonce);
        assert_eq!(live.ui("GET", "/api/profile", None).status, 200);
        assert_eq!(Connection::open(live.mcp_port).request("GET", "/health", &[], "").status, 200);
    }
}

#[test]
fn local_shutdown_releases_resources_and_preserves_oauth_on_restart() {
    let sandbox = Sandbox::new();
    let mut live = LiveWorkstation::start(&sandbox.0, "fully-unlocked", true);
    let state = sandbox.0.join("oauth-workstation");
    let owner = state.join("running.lock");
    let nonce = fs::read(&owner).unwrap();
    let scope_path = state.join(".agent-bridge-workstation-scope-v2.json");
    let scope = fs::read(&scope_path).unwrap();
    let mut mcp = AuthenticatedMcp::connect(&live);
    let catalog = mcp.catalog();
    let bearer = mcp.bearer.clone();
    let heartbeat = sandbox.0.join("project/shutdown-heartbeat.txt");
    let _session = start_owned_fixture(&mut mcp, &heartbeat);
    let oauth_before: Value = serde_json::from_slice(&fs::read(state.join("oauth-workstation.json")).unwrap()).unwrap();
    let origin = format!("http://127.0.0.1:{}", live.ui_port);
    let acknowledged = Connection::open(live.ui_port).request("POST", "/api/shutdown",
        &[("X-Agent-Bridge-Token", &live.token), ("Origin", &origin), ("Sec-Fetch-Site", "same-origin")], "");
    assert_eq!(acknowledged.status, 202, "{}", acknowledged.body);
    assert_eq!(acknowledged.json()["status"], "shutting_down");
    live.wait_for_successful_exit();
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, live.ui_port)).is_err(), "operator listener survived shutdown");
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, live.mcp_port)).is_err(), "MCP listener survived shutdown");
    assert!(!owner.exists(), "the exited OAuth owner must release its own nonce");
    assert_eq!(fs::read(&scope_path).unwrap(), scope);
    assert_heartbeat_stopped(&heartbeat);
    drop(mcp);

    let mut restarted = LiveWorkstation::start_existing(&sandbox.0, "fully-unlocked",
        &["--enable-processes"], live.mcp_port);
    assert_ne!(fs::read(&owner).unwrap(), nonce, "the new process must own a fresh nonce");
    assert_eq!(fs::read(&scope_path).unwrap(), scope);
    let oauth_after: Value = serde_json::from_slice(&fs::read(state.join("oauth-workstation.json")).unwrap()).unwrap();
    for key in ["clients", "grants", "access"] {
        assert_eq!(oauth_after[key], oauth_before[key], "restart must preserve OAuth {key}");
    }
    let mut resumed = AuthenticatedMcp::from_bearer(Connection::open(restarted.mcp_port),
        bearer, "live-profile-fixture/1");
    assert_eq!(resumed.catalog(), catalog);
    assert_eq!(resumed.call_json("desktop_policy_status", json!({}))["profile"], "fully-unlocked");
    let acknowledged = restarted.ui("POST", "/api/shutdown", None);
    assert_eq!(acknowledged.status, 202, "{}", acknowledged.body);
    restarted.wait_for_successful_exit();
    assert!(!owner.exists());
    assert_eq!(fs::read(&scope_path).unwrap(), scope);
}
