use agent_bridge_core::CoreDatabase;
use agent_bridge_oauth_server::{Audience, OAuthConfig, OAuthServer};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

static SEQ: AtomicU64 = AtomicU64::new(0);
const LOOPBACK_IP: &str = "127.0.0.1";

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-bridge"))
}

struct TempSandbox {
    dir: PathBuf,
}

impl TempSandbox {
    fn new(label: &str) -> Self {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        #[cfg(unix)]
        let base = {
            use std::os::unix::fs::PermissionsExt;
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(std::env::temp_dir);
            let root = home.join(".ab-ui-tests");
            let _ = fs::create_dir_all(&root);
            let _ = fs::set_permissions(&root, fs::Permissions::from_mode(0o700));
            root
        };
        #[cfg(not(unix))]
        let base = {
            let t = std::env::temp_dir();
            let resolved = fs::canonicalize(&t).unwrap_or(t);
            if let Some(s) = resolved.to_str().and_then(|s| s.strip_prefix("\\\\?\\")) {
                PathBuf::from(s)
            } else {
                resolved
            }
        };

        let dir = base.join(format!("ab-ui-test-{label}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create sandbox dir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
        Self { dir }
    }

    fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for TempSandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

struct UiChild {
    child: Child,
    port: u16,
    token: String,
}

impl Drop for UiChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_ui(args: &[String]) -> UiChild {
    let mut cmd = Command::new(bin());
    cmd.arg("ui")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().expect("spawn agent-bridge ui");
    let stdout = child.stdout.take().expect("ui stdout");
    let mut reader = BufReader::new(stdout);
    let mut first_line = String::new();
    reader
        .read_line(&mut first_line)
        .expect("read ui startup json");
    let startup: Value = serde_json::from_str(first_line.trim())
        .unwrap_or_else(|e| panic!("invalid startup json '{first_line}': {e}"));
    assert_eq!(startup["service"], "agent-bridge-ui");
    assert_eq!(startup["token_required"], true);
    assert_eq!(startup["loopback_only"], true);

    let listen = startup["listen"].as_str().expect("listen field");
    let port: u16 = listen
        .rsplit(':')
        .next()
        .expect("port in listen")
        .parse()
        .expect("numeric port");
    let ui_url = startup["ui_url"].as_str().expect("ui_url field");
    let token = ui_url
        .split("?token=")
        .nth(1)
        .expect("token in ui_url")
        .to_owned();
    assert_eq!(token.len(), 64, "256-bit hex token expected");

    UiChild { child, port, token }
}

struct HttpResp {
    status: u16,
    headers: String,
    body: String,
}

fn send_http(
    port: u16,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: Option<&str>,
) -> HttpResp {
    let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let mut stream = TcpStream::connect(addr).expect("connect loopback ui");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .expect("set write timeout");

    let has_host = extra_headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("host"));
    let mut raw = format!("{method} {path} HTTP/1.1\r\n");
    if !has_host {
        raw.push_str(&format!("Host: {LOOPBACK_IP}:{port}\r\n"));
    }
    raw.push_str("Connection: close\r\n");
    for (k, v) in extra_headers {
        raw.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(b) = body {
        raw.push_str("Content-Type: application/json\r\n");
        raw.push_str(&format!("Content-Length: {}\r\n", b.len()));
        raw.push_str("\r\n");
        raw.push_str(b);
    } else {
        raw.push_str("\r\n");
    }
    stream.write_all(raw.as_bytes()).expect("write request");

    let mut resp_bytes = Vec::new();
    stream.read_to_end(&mut resp_bytes).expect("read response");
    let resp_str = String::from_utf8_lossy(&resp_bytes).into_owned();
    let (head, body_part) = resp_str
        .split_once("\r\n\r\n")
        .unwrap_or((resp_str.as_str(), ""));
    let status_line = head.lines().next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    HttpResp {
        status,
        headers: head.to_owned(),
        body: body_part.to_owned(),
    }
}

fn queue_extension_proposal_via_stdio(
    db: &Path, project: &Path, settings: &Path, arguments: Value,
) -> String {
    let mut child = Command::new(bin())
        .args([
            "stdio",
            db.to_str().unwrap(),
            "--workspace",
            project.to_str().unwrap(),
            "--settings",
            settings.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn stdio for extension proposal");
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    let init = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "ui-test", "version": "1.0"}
        }
    });
    writeln!(stdin, "{init}").unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    let n = reader.read_line(&mut line).unwrap();
    assert!(n > 0, "stdio exited during initialize");

    let notif = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    writeln!(stdin, "{notif}").unwrap();
    stdin.flush().unwrap();

    let call = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "desktop_mcp_manage",
            "arguments": arguments
        }
    });
    writeln!(stdin, "{call}").unwrap();
    stdin.flush().unwrap();
    line.clear();
    let n = reader.read_line(&mut line).unwrap();
    assert!(n > 0, "stdio exited during tools/call");
    let resp: Value = serde_json::from_str(line.trim()).expect("stdio tool call json");
    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("proposal receipt text");
    let receipt: Value = serde_json::from_str(text).expect("receipt json");
    let req_id = receipt["request_id"]
        .as_str()
        .expect("queued request_id")
        .to_owned();

    drop(stdin);
    let _ = child.wait();
    req_id
}

#[test]
fn operator_ui_security_guards_and_full_api_lifecycle() {
    let sb = TempSandbox::new("full");
    let db_dir = sb.path().join("db");
    let db_path = db_dir.join("missions.sqlite");
    let settings_dir = sb.path().join("settings");
    let oauth_dir = sb.path().join("oauth-state");
    let project_dir = sb.path().join("project");

    fs::create_dir_all(&db_dir).expect("create db dir");
    fs::create_dir_all(&project_dir).expect("create project");
    // Create owner-private directory with strict OS ACL (0700 on Unix, protected owner DACL on Windows)
    agent_bridge_lifecycle::initialize_operator_settings(&oauth_dir).expect("create private oauth dir");
    for entry in fs::read_dir(&oauth_dir).expect("read oauth dir") {
        let path = entry.expect("entry").path();
        if path.is_file() {
            let _ = fs::remove_file(path);
        }
    }

    // 1. Initialize database and seed a mission + checkpoint
    let mut core = CoreDatabase::initialize_new(&db_path).expect("init core db");
    let ctx = agent_bridge_missions::create_context(core.connection_mut()).expect("create ctx");
    let created = agent_bridge_missions::dispatch_tool(
        core.connection_mut(),
        "agent_bridge_mission_create",
        &json!({
            "actor_context_handle": ctx.context_handle,
            "goal": "Verify Operator UI dashboard",
            "idempotency_key": "ui-reg-01"
        }),
    )
    .expect("create mission");
    let mission_id = created["mission_id"].as_str().unwrap().to_owned();
    let _ = agent_bridge_missions::dispatch_tool(
        core.connection_mut(),
        "agent_bridge_mission_checkpoint",
        &json!({
            "actor_context_handle": ctx.context_handle,
            "mission_id": mission_id,
            "if_revision": 1,
            "summary": "Initial UI test checkpoint"
        }),
    )
    .expect("checkpoint mission");
    drop(core);

    // 2. Initialize settings and queue one extension proposal via real stdio MCP
    agent_bridge_lifecycle::initialize_operator_settings(&settings_dir).expect("init settings");
    let queued_req_id = queue_extension_proposal_via_stdio(
        &db_path, &project_dir, &settings_dir,
        json!({"action":"add", "name":"ui_test_upstream", "url":"https://mcp.example.invalid/v1"}),
    );

    // 3. Initialize private OAuth state directory cleanly via OAuthServer::open then drop lock
    let oauth_origin = "https://ui-test.example.invalid";
    {
        let _srv = OAuthServer::open(OAuthConfig {
            state_dir: oauth_dir.clone(),
            public_origin: oauth_origin.to_owned(),
            audience: Audience::Workstation,
        })
        .expect("init oauth state");
    }

    // 4. Launch `agent-bridge ui`
    let ui = spawn_ui(&[
        "--port".into(),
        "0".into(),
        "--database".into(),
        db_path.to_str().unwrap().into(),
        "--settings-dir".into(),
        settings_dir.to_str().unwrap().into(),
        "--oauth-state".into(),
        oauth_dir.to_str().unwrap().into(),
        "--oauth-origin".into(),
        oauth_origin.into(),
        "--oauth-audience".into(),
        "workstation".into(),
        "--project".into(),
        project_dir.to_str().unwrap().into(),
    ]);

    // 5. Health and HTML index with strict security headers
    let health = send_http(ui.port, "GET", "/health", &[], None);
    assert_eq!(health.status, 200);
    let health_json: Value = serde_json::from_str(&health.body).unwrap();
    assert_eq!(health_json["ok"], true);
    assert_eq!(health_json["loopback_port"], ui.port);

    let index = send_http(ui.port, "GET", "/", &[], None);
    assert_eq!(index.status, 200);
    assert!(index.body.contains("Agent Bridge Operator Console"));
    let head_lc = index.headers.to_ascii_lowercase();
    assert!(head_lc.contains("content-security-policy:"));
    assert!(head_lc.contains("x-frame-options: deny"));
    assert!(head_lc.contains("x-content-type-options: nosniff"));
    assert!(head_lc.contains("cache-control: no-store"));

    // 6. Security rejections: missing token, wrong token, foreign Host, foreign Origin, cross-site
    let no_tok = send_http(ui.port, "GET", "/api/overview", &[], None);
    assert_eq!(no_tok.status, 401);

    let bad_tok = send_http(
        ui.port,
        "GET",
        "/api/overview",
        &[("X-Agent-Bridge-Token", "0000")],
        None,
    );
    assert_eq!(bad_tok.status, 401);

    let bad_host = send_http(
        ui.port,
        "GET",
        "/api/overview",
        &[
            ("Host", "evil.example:9999"),
            ("X-Agent-Bridge-Token", &ui.token),
        ],
        None,
    );
    assert_eq!(bad_host.status, 403);

    let bad_origin = send_http(
        ui.port,
        "GET",
        "/api/overview",
        &[
            ("Origin", "https://evil.example"),
            ("X-Agent-Bridge-Token", &ui.token),
        ],
        None,
    );
    assert_eq!(bad_origin.status, 403);

    let cross_site = send_http(
        ui.port,
        "GET",
        "/api/overview",
        &[
            ("Sec-Fetch-Site", "cross-site"),
            ("X-Agent-Bridge-Token", &ui.token),
        ],
        None,
    );
    assert_eq!(cross_site.status, 403);

    let auth = [("X-Agent-Bridge-Token", ui.token.as_str())];

    // 7. Authenticated /api/overview
    let ov = send_http(ui.port, "GET", "/api/overview", &auth, None);
    assert_eq!(ov.status, 200);
    let ov_json: Value = serde_json::from_str(&ov.body).unwrap();
    assert_eq!(ov_json["database"]["configured"], true);
    assert_eq!(ov_json["database"]["counts"]["missions"]["total"], 1);
    assert_eq!(ov_json["extensions"]["pending_count"], 1);
    assert_eq!(ov_json["oauth"]["configured"], true);

    // 8. Authenticated /api/missions - verifies mission + checkpoint AND zero secret leakage
    let ms = send_http(ui.port, "GET", "/api/missions", &auth, None);
    assert_eq!(ms.status, 200);
    assert!(
        !ms.body.contains(&ctx.context_handle),
        "raw context handle MUST never appear in UI snapshot"
    );
    assert!(
        !ms.body.contains("actor_context_handle") && !ms.body.contains("handle_hash"),
        "handle columns MUST never appear in UI snapshot"
    );
    let ms_json: Value = serde_json::from_str(&ms.body).unwrap();
    assert_eq!(ms_json["missions"][0]["mission_id"], mission_id);
    assert_eq!(
        ms_json["missions"][0]["recent_checkpoints"][0]["summary"],
        "Initial UI test checkpoint"
    );

    // 9. OAuth list + enroll requires explicit confirm='APPROVE'
    let oa = send_http(ui.port, "GET", "/api/oauth", &auth, None);
    assert_eq!(oa.status, 200);
    let oa_json: Value = serde_json::from_str(&oa.body).unwrap();
    assert_eq!(oa_json["configured"], true);
    assert_eq!(oa_json["count"], 0);

    let enroll_denied = send_http(
        ui.port,
        "POST",
        "/api/oauth/enroll",
        &auth,
        Some(r#"{"confirm":"NO"}"#),
    );
    assert_eq!(enroll_denied.status, 403);

    let enroll_ok = send_http(
        ui.port,
        "POST",
        "/api/oauth/enroll",
        &auth,
        Some(r#"{"confirm":"APPROVE"}"#),
    );
    assert_eq!(enroll_ok.status, 200);
    let enroll_json: Value = serde_json::from_str(&enroll_ok.body).unwrap();
    assert_eq!(enroll_json["local_oauth_enrollment"], "enabled");

    // 10. Extensions list + decide (deny without confirm, then approve queued proposal)
    let ext = send_http(ui.port, "GET", "/api/extensions", &auth, None);
    assert_eq!(ext.status, 200);
    let ext_json: Value = serde_json::from_str(&ext.body).unwrap();
    assert_eq!(ext_json["pending_count"], 1);
    assert_eq!(ext_json["requests"][0]["payload"]["url"], "https://mcp.example.invalid/v1");

    let dec_denied = send_http(
        ui.port,
        "POST",
        "/api/extensions/decide",
        &auth,
        Some(&json!({"request_id": queued_req_id, "approve": true, "confirm": "WRONG"}).to_string()),
    );
    assert_eq!(dec_denied.status, 403);

    let dec_ok = send_http(
        ui.port,
        "POST",
        "/api/extensions/decide",
        &auth,
        Some(&json!({"request_id": queued_req_id, "approve": true, "confirm": "APPROVE"}).to_string()),
    );
    assert_eq!(dec_ok.status, 200, "body: {}", dec_ok.body);
    let dec_json: Value = serde_json::from_str(&dec_ok.body).unwrap();
    assert_eq!(dec_json["decision"], "approved");
    assert_eq!(dec_json["effect_now"], "added_without_tools");

    let ext_after = send_http(ui.port, "GET", "/api/extensions", &auth, None);
    let ext_after_json: Value = serde_json::from_str(&ext_after.body).unwrap();
    assert_eq!(ext_after_json["pending_count"], 0);
    let added_server = ext_after_json["servers"].as_array().unwrap().iter()
        .find(|server| server["id"] == "ui_test_upstream").expect("added server");
    assert_eq!(added_server["endpoint"], "https://mcp.example.invalid/v1",
        "operator must be able to review the exact extension endpoint");

    // 11. Skills & Diagnostics endpoints
    let skills = send_http(ui.port, "GET", "/api/skills", &auth, None);
    assert_eq!(skills.status, 200);
    let skills_json: Value = serde_json::from_str(&skills.body).unwrap();
    assert_eq!(skills_json["configured"], true);

    let diag = send_http(ui.port, "GET", "/api/diagnostics", &auth, None);
    assert_eq!(diag.status, 200);
    let diag_json: Value = serde_json::from_str(&diag.body).unwrap();
    assert_eq!(diag_json["capabilities"]["operator_loopback_ui"], true);
    assert_eq!(diag_json["security_guards"]["per_session_256bit_token"], true);
}


#[test]
fn operator_ui_minimal_mode_and_cli_validation() {
    // 1. Incomplete OAuth flags must fail closed
    let bad = Command::new(bin())
        .args(["ui", "--oauth-state", "C:/nonexistent"])
        .output()
        .expect("run bad ui args");
    assert!(!bad.status.success(), "incomplete oauth flags must fail closed");

    // 2. Minimal mode (no optional flags) starts cleanly and reports unconfigured panels
    let ui = spawn_ui(&["--port".into(), "0".into()]);
    let auth = [("X-Agent-Bridge-Token", ui.token.as_str())];

    let profile = send_http(ui.port, "GET", "/api/profile", &auth, None);
    assert_eq!(profile.status, 200, "standalone UI must explicitly report no live control");
    let profile: Value = serde_json::from_str(&profile.body).unwrap();
    assert_eq!(profile["configured"], false);
    assert!(profile["active_profile"].is_null());
    assert_eq!(profile["available_profiles"], json!([]));
    let change = send_http(ui.port, "POST", "/api/profile", &auth,
        Some(r#"{"profile":"workspace-write"}"#));
    assert_eq!(change.status, 409, "standalone UI must not pretend to change a live profile");

    let ms = send_http(ui.port, "GET", "/api/missions", &auth, None);
    assert_eq!(ms.status, 200);
    let ms_json: Value = serde_json::from_str(&ms.body).unwrap();
    assert_eq!(ms_json["configured"], false);

    let oa = send_http(ui.port, "GET", "/api/oauth", &auth, None);
    assert_eq!(oa.status, 200);
    let oa_json: Value = serde_json::from_str(&oa.body).unwrap();
    assert_eq!(oa_json["configured"], false);

    let ext = send_http(ui.port, "GET", "/api/extensions", &auth, None);
    assert_eq!(ext.status, 200);
    let ext_json: Value = serde_json::from_str(&ext.body).unwrap();
    assert_eq!(ext_json["configured"], false);

    let diag = send_http(ui.port, "GET", "/api/diagnostics", &auth, None);
    assert_eq!(diag.status, 200);
    let diag_json: Value = serde_json::from_str(&diag.body).unwrap();
    assert_eq!(diag_json["capabilities"]["operator_loopback_ui"], true);
}

// A real loopback metadata server; the UI and Rust OAuth flow are not mocked.
struct OAuthMetadataFixture {
    endpoint: String,
    requests: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl OAuthMetadataFixture {
    fn start() -> Self {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let endpoint = format!("{base}/mcp");
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicU64::new(0));
        let thread_stop = Arc::clone(&stop);
        let thread_requests = Arc::clone(&requests);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(err) => panic!("metadata listener: {err}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut request = [0u8; 4096];
                let count = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..count]);
                let path = request.lines().next().unwrap().split_whitespace().nth(1).unwrap();
                thread_requests.fetch_add(1, Ordering::Relaxed);
                let body = match path {
                    "/.well-known/oauth-protected-resource" =>
                        json!({"authorization_servers":[base]}),
                    "/.well-known/oauth-authorization-server" => json!({
                        "issuer":base,
                        "authorization_endpoint":format!("{base}/authorize"),
                        "token_endpoint":format!("{base}/token"),
                        "code_challenge_methods_supported":["S256"]
                    }),
                    _ => panic!("unexpected OAuth fixture request: {path}"),
                }.to_string();
                write!(stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()).unwrap();
            }
        });
        Self { endpoint, requests, stop, thread: Some(thread) }
    }
}

impl Drop for OAuthMetadataFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[test]
fn operator_ui_publishes_oauth_url_before_callback_and_retains_terminal_result() {
    let sb = TempSandbox::new("outbound-oauth");
    let db_dir = sb.path().join("db");
    let db_path = db_dir.join("missions.sqlite");
    let settings_dir = sb.path().join("settings");
    let project_dir = sb.path().join("project");
    fs::create_dir_all(&db_dir).unwrap();
    fs::create_dir_all(&project_dir).unwrap();
    drop(CoreDatabase::initialize_new(&db_path).unwrap());
    agent_bridge_lifecycle::initialize_operator_settings(&settings_dir).unwrap();
    let fixture = OAuthMetadataFixture::start();
    let add_id = queue_extension_proposal_via_stdio(
        &db_path, &project_dir, &settings_dir, json!({
            "action":"add", "name":"ui_oauth", "url":fixture.endpoint,
            "oauth":true, "oauth_client_id":"ui-public-client", "oauth_scope":"mcp:read"
        }),
    );
    let ui = spawn_ui(&[
        "--port".into(), "0".into(), "--settings-dir".into(),
        settings_dir.to_str().unwrap().into(), "--project".into(),
        project_dir.to_str().unwrap().into(),
    ]);
    let auth = [("X-Agent-Bridge-Token", ui.token.as_str())];
    let added = send_http(ui.port, "POST", "/api/extensions/decide", &auth,
        Some(&json!({"request_id":add_id, "approve":true, "confirm":"APPROVE"}).to_string()));
    assert_eq!(added.status, 200, "{}", added.body);

    let request_id = queue_extension_proposal_via_stdio(
        &db_path, &project_dir, &settings_dir,
        json!({"action":"auth_start", "name":"ui_oauth", "force":true}),
    );
    let other_id = queue_extension_proposal_via_stdio(
        &db_path, &project_dir, &settings_dir,
        json!({"action":"auth_start", "name":"ui_oauth", "force":false}),
    );
    let payload = json!({"request_id":request_id, "approve":true, "confirm":"APPROVE"}).to_string();
    let (sender, receiver) = mpsc::channel();
    let request_token = ui.token.clone();
    let request_port = ui.port;
    let start_payload = payload.clone();
    thread::spawn(move || {
        let response = send_http(request_port, "POST", "/api/extensions/decide",
            &[("X-Agent-Bridge-Token", &request_token)], Some(&start_payload));
        let _ = sender.send(response);
    });
    let accepted = receiver.recv_timeout(Duration::from_secs(3))
        .expect("OAuth start must respond before the browser returns its callback");
    assert_eq!(accepted.status, 202, "{}", accepted.body);

    let deadline = Instant::now() + Duration::from_secs(3);
    let operation = loop {
        let response = send_http(ui.port, "GET", "/api/extensions", &auth, None);
        assert_eq!(response.status, 200, "{}", response.body);
        let snapshot: Value = serde_json::from_str(&response.body).unwrap();
        let operation = snapshot["oauth_operation"].clone();
        if operation["auth_url"].is_string() { break operation; }
        assert!(Instant::now() < deadline, "OAuth URL must be visible before callback: {snapshot}");
        thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(operation["request_id"], request_id);
    assert_eq!(operation["status"], "awaiting_authorization");
    assert!(operation["result"].is_null(), "flow cannot finish before callback");
    assert_eq!(send_http(ui.port, "GET", "/api/extensions", &[], None).status, 401);

    let duplicate = send_http(ui.port, "POST", "/api/extensions/decide", &auth, Some(&payload));
    assert_eq!(duplicate.status, 202, "duplicate must join the pending operation");
    let other = send_http(ui.port, "POST", "/api/extensions/decide", &auth,
        Some(&json!({"request_id":other_id, "approve":true, "confirm":"APPROVE"}).to_string()));
    assert_eq!(other.status, 409, "a second OAuth operation must not start");
    assert_eq!(fixture.requests.load(Ordering::Relaxed), 2,
        "repeating a decision must not repeat metadata discovery");

    let auth_url = operation["auth_url"].as_str().unwrap();
    assert!(auth_url.contains("code_challenge_method=S256"));
    let params: std::collections::BTreeMap<_, _> = auth_url.split_once('?').unwrap().1
        .split('&').filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (key, value.replace("%3A", ":").replace("%2F", "/"))).collect();
    let callback_port: u16 = params["redirect_uri"].split("://").nth(1).unwrap()
        .split('/').next().unwrap().rsplit(':').next().unwrap().parse().unwrap();
    // Simulate a declined grant. No token or OS keystore dependency is needed.
    let _ = send_http(callback_port, "GET",
        &format!("/callback?error=access_denied&state={}", params["state"]), &[], None);

    let deadline = Instant::now() + Duration::from_secs(3);
    let terminal = loop {
        let response = send_http(ui.port, "GET", "/api/extensions", &auth, None);
        let snapshot: Value = serde_json::from_str(&response.body).unwrap();
        let operation = snapshot["oauth_operation"].clone();
        if operation["status"] == "completed" { break operation; }
        assert!(Instant::now() < deadline, "operation must expose its terminal result: {snapshot}");
        thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(terminal["result"]["decision"], "refused");
    assert_eq!(terminal["result"]["reason"], "oauth_flow_failed");
    assert!(terminal["auth_url"].is_null(), "authorization URL must be removed after completion");
    let repeated = send_http(ui.port, "POST", "/api/extensions/decide", &auth, Some(&payload));
    assert_eq!(repeated.status, 200);
    let repeated: Value = serde_json::from_str(&repeated.body).unwrap();
    assert_eq!(repeated["oauth_operation"]["result"]["decision"], "refused");
    assert_eq!(fixture.requests.load(Ordering::Relaxed), 2, "terminal result must not replay OAuth");
}
#[test]
fn standalone_shutdown_does_not_claim_an_external_workstation() {
    let mut ui = spawn_ui(&[]);
    let origin = format!("http://127.0.0.1:{}", ui.port);
    let response = send_http(ui.port, "POST", "/api/shutdown",
        &[("X-Agent-Bridge-Token", &ui.token), ("Origin", &origin), ("Sec-Fetch-Site", "same-origin")], None);
    assert_eq!(response.status, 409, "{}", response.body);
    let value: Value = serde_json::from_str(&response.body).unwrap();
    assert_eq!(value["error"], "WORKSTATION_SHUTDOWN_UNAVAILABLE");
    assert!(ui.child.try_wait().unwrap().is_none());
    assert_eq!(send_http(ui.port, "GET", "/health", &[], None).status, 200);
}
