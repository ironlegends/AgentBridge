use agent_bridge_core::CoreDatabase;
use agent_bridge_extensions::config_sha256;
use agent_bridge_lifecycle::private_store::ensure_private_dir;
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-bridge"))
}

fn fixture_bin() -> PathBuf {
    let test = std::env::current_exe().expect("test executable");
    let exe_name = if cfg!(windows) {
        "agent_bridge_process_fixture.exe"
    } else {
        "agent_bridge_process_fixture"
    };
    let fixture = test
        .parent()
        .and_then(|p| p.parent())
        .expect("Cargo target debug path")
        .join("examples")
        .join(exe_name);
    assert!(
        fixture.is_file(),
        "missing subprocess witness: cargo build -p agent-bridge --example agent_bridge_process_fixture"
    );
    let resolved = fs::canonicalize(&fixture).unwrap_or(fixture);
    strip_verbatim(&resolved)
}

fn strip_verbatim(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(stripped) = path.to_str().and_then(|s| s.strip_prefix(r"\\?\")) {
            return PathBuf::from(stripped);
        }
    }
    path.to_path_buf()
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
            let root = home.join(".ab-revocation-ack-tests");
            let _ = fs::create_dir_all(&root);
            let _ = fs::set_permissions(&root, fs::Permissions::from_mode(0o700));
            root
        };
        #[cfg(not(unix))]
        let base = strip_verbatim(&fs::canonicalize(std::env::temp_dir()).unwrap());

        let dir = base.join(format!("ab-rev-ack-{label}-{}-{n}", std::process::id()));
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

fn write_private(path: impl AsRef<Path>, bytes: impl AsRef<[u8]>) {
    let path = path.as_ref();
    fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn private_empty_dir(path: &Path) {
    agent_bridge_lifecycle::initialize_operator_settings(path).unwrap();
    for entry in fs::read_dir(path).unwrap() {
        let p = entry.unwrap().path();
        if p.is_file() {
            fs::remove_file(p).unwrap();
        }
    }
}

struct HttpResp {
    status: u16,
    body: String,
}

fn send_http(
    port: u16,
    method: &str,
    path: &str,
    token: &str,
    body: Option<&str>,
) -> HttpResp {
    let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let mut stream = TcpStream::connect(addr).expect("connect loopback ui");
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    let mut raw = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nX-Agent-Bridge-Token: {token}\r\n"
    );
    if let Some(b) = body {
        raw.push_str("Content-Type: application/json\r\n");
        raw.push_str(&format!("Content-Length: {}\r\n", b.len()));
        raw.push_str("\r\n");
        raw.push_str(b);
    } else {
        raw.push_str("\r\n");
    }
    stream.write_all(raw.as_bytes()).unwrap();

    let mut resp_bytes = Vec::new();
    stream.read_to_end(&mut resp_bytes).unwrap();
    let resp_str = String::from_utf8_lossy(&resp_bytes).into_owned();
    let (head, body_part) = resp_str
        .split_once("\r\n\r\n")
        .unwrap_or((resp_str.as_str(), ""));
    let status = head
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    HttpResp {
        status,
        body: body_part.to_owned(),
    }
}

struct UiHandle {
    child: Child,
    port: u16,
    token: String,
}

impl UiHandle {
    fn shutdown(mut self) {
        let resp = send_http(self.port, "POST", "/api/shutdown", &self.token, Some("{}"));
        assert_eq!(resp.status, 202, "shutdown failed: {}", resp.body);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "cooperative shutdown failed: {status}");
                return;
            }
            assert!(Instant::now() < deadline, "backend did not finish cooperative shutdown");
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for UiHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_ui_process(settings: &Path) -> UiHandle {
    let mut cmd = Command::new(bin());
    cmd.args(["ui", "--port", "0", "--settings-dir"])
        .arg(settings)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().expect("spawn operator ui");
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            let Ok(val) = serde_json::from_str::<Value>(&line) else { continue };
            if val["service"] == "agent-bridge-ui" {
                let _ = tx.send(val);
                break;
            }
        }
    });
    let startup = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("operator ui startup json");
    let port: u16 = startup["listen"]
        .as_str()
        .unwrap()
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let token = startup["ui_url"]
        .as_str()
        .unwrap()
        .split_once("?token=")
        .unwrap()
        .1
        .to_owned();
    UiHandle { child, port, token }
}

fn spawn_workstation_backend(root: &Path, db: &Path, settings: &Path) -> UiHandle {
    let project = root.join("project");
    let workstation = root.join("oauth-workstation");
    let missions = root.join("oauth-missions");
    let lifecycle = root.join("lifecycle");
    fs::create_dir_all(&project).unwrap();
    for dir in [&workstation, &missions, &lifecycle] {
        private_empty_dir(dir);
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let mcp_port = listener.local_addr().unwrap().port();
    drop(listener);

    let mut cmd = Command::new(bin());
    cmd.args(["gemini", "workstation"])
        .arg(db)
        .arg(&workstation)
        .arg("https://rev-ack-ws.example.invalid")
        .arg(mcp_port.to_string())
        .arg("--project")
        .arg(&project)
        .args(["--profile", "workspace-write"])
        .arg("--missions-state")
        .arg(&missions)
        .args(["--missions-origin", "https://rev-ack-missions.example.invalid"])
        .arg("--settings-dir")
        .arg(settings)
        .arg("--lifecycle-dir")
        .arg(&lifecycle)
        .args(["--enable-settings-tools", "--ui-port", "0"])
        .env_remove("AGENT_BRIDGE_DESKTOP_PROFILE")
        .env_remove("AGENT_BRIDGE_DESKTOP_PROFILE_LOCK")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().expect("spawn workstation backend");
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            let Ok(val) = serde_json::from_str::<Value>(&line) else { continue };
            if val["service"] == "agent-bridge-ui" {
                let _ = tx.send(val);
                break;
            }
        }
    });
    let startup = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("workstation backend startup json");
    let port: u16 = startup["listen"]
        .as_str()
        .unwrap()
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let token = startup["ui_url"]
        .as_str()
        .unwrap()
        .split_once("?token=")
        .unwrap()
        .1
        .to_owned();
    UiHandle { child, port, token }
}

struct StdioBackend {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl StdioBackend {
    fn spawn(db: &Path, settings: &Path) -> Self {
        let mut child = Command::new(bin())
            .args(["stdio"])
            .arg(db)
            .args(["--settings"])
            .arg(settings)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn stdio backend");
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut this = Self {
            child,
            stdin,
            stdout,
        };
        let init = this.rpc(
            1,
            "initialize",
            json!({
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "rev-ack-test", "version": "1.0"}
            }),
        );
        assert!(init["result"].is_object(), "init failed: {init}");
        this.notify("notifications/initialized", json!({}));
        this
    }

    fn notify(&mut self, method: &str, params: Value) {
        let msg = json!({"jsonrpc": "2.0", "method": method, "params": params});
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{msg}").unwrap();
        stdin.flush().unwrap();
    }

    fn send_rpc(&mut self, id: u64, method: &str, params: Value) {
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{msg}").unwrap();
        stdin.flush().unwrap();
    }

    fn read_rpc(&mut self) -> Value {
        let mut line = String::new();
        let n = self.stdout.read_line(&mut line).unwrap();
        assert!(n > 0, "stdio backend closed stdout unexpectedly");
        serde_json::from_str(line.trim()).expect("valid rpc json")
    }

    fn rpc(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send_rpc(id, method, params);
        self.read_rpc()
    }

    fn tool_call(&mut self, id: u64, name: &str, arguments: Value) -> Value {
        self.rpc(
            id,
            "tools/call",
            json!({"name": name, "arguments": arguments}),
        )
    }

    fn shutdown(mut self) {
        drop(self.stdin.take());
        let _ = self.child.wait();
    }
}

impl Drop for StdioBackend {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(20));
    }
}

fn decide_from_operator(settings: &Path, request_id: &str, approve: bool) -> HttpResp {
    let ui = spawn_ui_process(settings);
    let confirm = if approve { "APPROVE" } else { "REFUSE" };
    send_http(
        ui.port,
        "POST",
        "/api/extensions/decide",
        &ui.token,
        Some(&json!({"request_id": request_id, "approve": approve, "confirm": confirm}).to_string()),
    )
}

#[test]
fn cross_process_operator_revocation_cancels_active_call_and_probe_across_two_backends_with_ack() {
    let sb = TempSandbox::new("two-backends");
    let root = sb.path();
    let settings = root.join("settings");
    agent_bridge_lifecycle::initialize_operator_settings(&settings).unwrap();

    let db1_dir = root.join("db1");
    let db2_dir = root.join("db2");
    fs::create_dir_all(&db1_dir).unwrap();
    fs::create_dir_all(&db2_dir).unwrap();
    let db1 = db1_dir.join("missions.sqlite");
    let db2 = db2_dir.join("missions.sqlite");
    drop(CoreDatabase::initialize_new(&db1).unwrap());
    drop(CoreDatabase::initialize_new(&db2).unwrap());

    let fixture_state = root.join("mcp-fixture-state");
    fs::create_dir_all(&fixture_state).unwrap();
    let fixture_exe = fixture_bin();

    // 1. Import simulated stdio MCP server and approve via a separate operator CLI process.
    let mcp_json = root.join("mcp.json");
    write_private(
        &mcp_json,
        serde_json::to_vec(&json!({
            "mcpServers": {
                "sim_stdio": {
                    "command": fixture_exe.to_str().unwrap(),
                    "args": ["mcp-stall-fixture", fixture_state.to_str().unwrap()]
                }
            }
        }))
        .unwrap(),
    );
    let imported = Command::new(bin())
        .args(["extensions", "import"])
        .arg(&settings)
        .arg(&mcp_json)
        .output()
        .expect("extensions import");
    assert!(imported.status.success(), "import failed: {:?}", imported);
    let import_json: Value = serde_json::from_slice(&imported.stdout).unwrap();
    let add_id = import_json["proposals"][0]["request_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let add_resp = decide_from_operator(&settings, &add_id, true);
    assert_eq!(add_resp.status, 200, "add decide failed: {}", add_resp.body);
    let add_json: Value = serde_json::from_str(&add_resp.body).unwrap();
    let nonce = add_json["local_grant_handoff"]["bridge_grant_nonce"]
        .as_str()
        .unwrap()
        .to_owned();

    // 2. Author exact generation-bound tool grant in extensions.json and enable via operator decision.
    let descriptor = json!({
        "name": "search_items",
        "description": "Simulated search",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"]
        }
    });
    let mut canonical_desc = descriptor.clone();
    canonical_desc.sort_all_objects();
    let desc_sha = config_sha256(canonical_desc.to_string().as_bytes());
    write_private(
        settings.join("extensions.json"),
        serde_json::to_vec(&json!({
            "version": 1,
            "servers": {
                "sim_stdio": {
                    "bridge_grant_nonce": nonce,
                    "tools": {
                        "search_items": {
                            "descriptor_sha256": desc_sha,
                            "descriptor": descriptor,
                            "parameters": {"query": {"type": "search_terms"}}
                        }
                    }
                }
            }
        }))
        .unwrap(),
    );

    let enable_req_id = {
        let mut setup_stdio = StdioBackend::spawn(&db1, &settings);
        let q = setup_stdio.tool_call(
            2,
            "desktop_mcp_manage",
            json!({"action": "enable", "name": "sim_stdio"}),
        );
        let text = q["result"]["content"][0]["text"].as_str().unwrap();
        let v: Value = serde_json::from_str(text).unwrap();
        let id = v["request_id"].as_str().unwrap().to_owned();
        setup_stdio.shutdown();
        id
    };
    let enable_resp = decide_from_operator(&settings, &enable_req_id, true);
    assert_eq!(enable_resp.status, 200, "enable decide: {}", enable_resp.body);

    // 3. Start two real auxiliary backend processes attached to the same settings root.
    let mut backend1 = StdioBackend::spawn(&db1, &settings);
    let b1_list = backend1.tool_call(2, "desktop_mcp_manage", json!({"action": "list"}));
    let b1_list_json: Value =
        serde_json::from_str(b1_list["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(b1_list_json["servers"][0]["id"], "sim_stdio");
    assert_eq!(b1_list_json["servers"][0]["enabled"], true);

    let ws_root = root.join("ws-backend2");
    fs::create_dir_all(&ws_root).unwrap();
    let backend2 = spawn_workstation_backend(&ws_root, &db2, &settings);
    let diag_before = send_http(backend2.port, "GET", "/api/diagnostics", &backend2.token, None);
    assert_eq!(diag_before.status, 200);
    let diag_before_json: Value = serde_json::from_str(&diag_before.body).unwrap();
    assert_eq!(
        diag_before_json["extension_status"]["servers"][0]["server"],
        "sim_stdio"
    );
    assert_eq!(
        diag_before_json["extension_status"]["servers"][0]["enabled"],
        true
    );

    // 4. Queue a pending disable proposal (not yet decided).
    let q_disable = backend1.tool_call(
        3,
        "desktop_mcp_manage",
        json!({"action": "disable", "name": "sim_stdio"}),
    );
    let disable_payload: Value =
        serde_json::from_str(q_disable["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    let disable_id = disable_payload["request_id"].as_str().unwrap().to_owned();

    // 5. Start an active tool call on Backend 1 (stalls in tools/call) and an active probe on Backend 2 (stalls in tools/list).
    backend1.send_rpc(
        4,
        "tools/call",
        json!({
            "name": "desktop_mcp_tool_call",
            "arguments": {"name": "sim_stdio:search_items", "arguments": {"query": "alpha"}}
        }),
    );
    wait_until("backend1 active tool call stalled", || {
        fixture_state.join("call-stalled.marker").is_file()
    });
    assert_eq!(
        fs::read_to_string(fixture_state.join("calls.log"))
            .unwrap()
            .lines()
            .count(),
        1
    );

    fs::write(fixture_state.join("stall-list"), b"1").unwrap();
    let b2_port = backend2.port;
    let b2_token = backend2.token.clone();
    let probe_thread = thread::spawn(move || {
        send_http(
            b2_port,
            "POST",
            "/api/extensions/test",
            &b2_token,
            Some(r#"{"server":"sim_stdio"}"#),
        )
    });
    wait_until("backend2 active probe stalled", || {
        fixture_state.join("list-stalled.marker").is_file()
    });

    // 6. From a separate second operator CLI process, decide the disable proposal.
    let started = Instant::now();
    let decide_resp = decide_from_operator(&settings, &disable_id, true);
    let elapsed = started.elapsed();
    assert_eq!(
        decide_resp.status, 200,
        "operator decide failed: {}",
        decide_resp.body
    );
    assert!(
        elapsed < Duration::from_secs(4),
        "revocation took too long: {elapsed:?}"
    );
    let decide_json: Value = serde_json::from_str(&decide_resp.body).unwrap();
    assert_eq!(decide_json["decision"], "approved");
    assert_eq!(decide_json["effect_now"], "disabled_and_pinned");
    assert_eq!(
        decide_json["revocation_ack"]["remote_backends_acknowledged"],
        2
    );
    assert_eq!(decide_json["revocation_ack"]["cancelled_in_flight"], 2);

    // 7. Verify both in-flight operations aborted quickly and upstream call was NOT repeated.
    let call_reply = backend1.read_rpc();
    assert_eq!(call_reply["id"], 4);
    assert_eq!(call_reply["result"]["isError"], true);
    let call_err = call_reply["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("");
    assert!(
        call_err.contains("cancelled due to revocation"),
        "unexpected call reply: {call_reply}"
    );

    let probe_resp = probe_thread.join().unwrap();
    assert_eq!(probe_resp.status, 400, "probe body: {}", probe_resp.body);
    assert!(
        probe_resp.body.contains("cancelled due to revocation"),
        "unexpected probe reply: {}",
        probe_resp.body
    );

    assert_eq!(
        fs::read_to_string(fixture_state.join("calls.log"))
            .unwrap()
            .lines()
            .count(),
        1,
        "already-performed upstream call must never be repeated"
    );

    // 8. Verify subsequent calls and probes are refused and diagnostics reflect disabled state.
    let blocked_call = backend1.tool_call(
        5,
        "desktop_mcp_tool_call",
        json!({"name": "sim_stdio:search_items", "arguments": {"query": "beta"}}),
    );
    assert_eq!(blocked_call["result"]["isError"], true);
    let blocked_probe = send_http(
        backend2.port,
        "POST",
        "/api/extensions/test",
        &backend2.token,
        Some(r#"{"server":"sim_stdio"}"#),
    );
    assert_eq!(blocked_probe.status, 400);

    let diag_after = send_http(backend2.port, "GET", "/api/diagnostics", &backend2.token, None);
    assert_eq!(diag_after.status, 200);
    let diag_after_json: Value = serde_json::from_str(&diag_after.body).unwrap();
    assert_eq!(
        diag_after_json["extension_status"]["servers"][0]["enabled"],
        false
    );
    assert_eq!(
        diag_after_json["extension_status"]["servers"][0]["state"],
        "disabled"
    );
    assert!(diag_after_json["extension_status"]["servers"][0]["last_latency_ms"].is_null());
    let audit_records = diag_after_json["extension_reload_audit"]["records"]
        .as_array()
        .unwrap();
    assert!(audit_records
        .iter()
        .any(|rec| rec["cancelled_in_flight"] == 1));

    // 9. Replaying the same decision is idempotent: effect_now="none", acks=2, calls.log still 1.
    let replay_resp = decide_from_operator(&settings, &disable_id, true);
    assert_eq!(replay_resp.status, 200);
    let replay_json: Value = serde_json::from_str(&replay_resp.body).unwrap();
    assert_eq!(replay_json["already_decided"], true);
    assert_eq!(replay_json["effect_now"], "none");
    assert_eq!(
        replay_json["revocation_ack"]["remote_backends_acknowledged"],
        2
    );
    assert_eq!(
        fs::read_to_string(fixture_state.join("calls.log"))
            .unwrap()
            .lines()
            .count(),
        1
    );

    // 10. Clean exit leaves no live peer files.
    backend1.shutdown();
    backend2.shutdown();
    let peers_dir = settings.join(".extensions-peers");
    if peers_dir.exists() {
        let entries: Vec<_> = fs::read_dir(&peers_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            entries.is_empty(),
            "expected no leftover peer files after clean exit, found: {entries:?}"
        );
    }
}

#[test]
fn cross_process_revocation_fails_closed_without_ack_and_refuses_widened_or_unknown_authority() {
    let sb = TempSandbox::new("fail-closed");
    let root = sb.path();
    let settings = root.join("settings");
    agent_bridge_lifecycle::initialize_operator_settings(&settings).unwrap();

    let db = root.join("db.sqlite");
    drop(CoreDatabase::initialize_new(&db).unwrap());

    write_private(
        settings.join("extensions.json"),
        serde_json::to_vec(&json!({
            "version": 1,
            "servers": {
                "sim_http": {
                    "endpoint": "https://example.invalid/mcp",
                    "tools": {}
                }
            }
        }))
        .unwrap(),
    );

    let queue_action = |action: &str| -> String {
        let mut s = StdioBackend::spawn(&db, &settings);
        let resp = s.tool_call(
            2,
            "desktop_mcp_manage",
            json!({"action": action, "name": "sim_http"}),
        );
        let payload: Value =
            serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        let id = payload["request_id"].as_str().unwrap().to_owned();
        s.shutdown();
        id
    };

    // Part A: A live peer holding its lock without acknowledging must fail the operator decision closed.
    let disable_id = queue_action("disable");
    let peers_dir = ensure_private_dir(&settings.join(".extensions-peers")).unwrap();
    let canonical_settings = fs::canonicalize(&settings).unwrap();
    let settings_sha = config_sha256(canonical_settings.to_string_lossy().as_bytes());
    let silent_peer_id = "0".repeat(32);
    let silent_lock_path = peers_dir.join(format!("peer-{silent_peer_id}.lock"));
    let silent_json_path = peers_dir.join(format!("peer-{silent_peer_id}.json"));
    let mut lock_opts = OpenOptions::new();
    lock_opts.read(true).write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        lock_opts.share_mode(0x1 | 0x2);
    }
    let silent_lock = lock_opts.open(&silent_lock_path).unwrap();
    silent_lock.try_lock().unwrap();
    write_private(
        &silent_json_path,
        serde_json::to_vec(&json!({
            "version": 1,
            "peer_id": silent_peer_id,
            "settings_sha256": settings_sha,
            "pid": std::process::id(),
            "ack_key": "a".repeat(64)
        }))
        .unwrap(),
    );

    let failed_decide = decide_from_operator(&settings, &disable_id, true);
    assert_eq!(
        failed_decide.status, 400,
        "missing ack must fail closed, got: {}",
        failed_decide.body
    );

    // Durable journal still persisted the disable decision on disk.
    let journal_raw: Value =
        serde_json::from_slice(&fs::read(settings.join(".extensions-admin.json")).unwrap()).unwrap();
    assert_eq!(journal_raw["controls"]["sim_http"]["enabled"], false);

    // A new approval must leave the restricted revision intact while a live peer
    // still owes its acknowledgement. The pending proposal remains retryable.
    let enable_id = queue_action("enable");
    let waiting = decide_from_operator(&settings, &enable_id, true);
    assert_eq!(waiting.status, 400);
    let restricted: Value = serde_json::from_slice(
        &fs::read(settings.join(".extensions-admin.json")).unwrap(),
    ).unwrap();
    assert_eq!(restricted["revision"], journal_raw["revision"]);
    assert_eq!(restricted["controls"]["sim_http"]["enabled"], false);
    assert_eq!(restricted["requests"][&enable_id]["status"], "pending");

    // Once the unresponsive peer exits (lock drops), replaying the request_id succeeds cleanly with effect_now="none".
    drop(silent_lock);
    let recovered = decide_from_operator(&settings, &disable_id, true);
    assert_eq!(
        recovered.status, 200,
        "replay after peer exit should succeed: {}",
        recovered.body
    );
    let recovered_json: Value = serde_json::from_str(&recovered.body).unwrap();
    assert_eq!(recovered_json["already_decided"], true);
    assert_eq!(recovered_json["effect_now"], "none");
    assert_eq!(
        recovered_json["revocation_ack"]["remote_backends_acknowledged"],
        0
    );
    assert!(!silent_lock_path.exists());
    assert!(!silent_json_path.exists());

    // Part B: Attached backend refuses forged/widened/unknown requests and never widens via restrict_to.
    let mut backend = StdioBackend::spawn(&db, &settings);
    let initial_inspect = backend.tool_call(
        2,
        "desktop_mcp_manage",
        json!({"action": "inspect", "name": "sim_http"}),
    );
    let initial_json: Value = serde_json::from_str(
        initial_inspect["result"]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(initial_json["server"]["enabled"], false);

    let forged_requests = [
        (
            "1".repeat(64),
            json!({
                "version": 1,
                "action": "enable",
                "settings_sha256": settings_sha,
                "request_nonce": "1".repeat(64),
                "journal_revision": 1,
                "state_hash": "0".repeat(64)
            }),
        ),
        (
            "2".repeat(64),
            json!({
                "version": 1,
                "action": "restrict",
                "settings_sha256": settings_sha,
                "request_nonce": "2".repeat(64),
                "journal_revision": 1,
                "state_hash": "0".repeat(64),
                "extra": true
            }),
        ),
        (
            "3".repeat(64),
            json!({
                "version": 1,
                "action": "restrict",
                "settings_sha256": "f".repeat(64),
                "request_nonce": "3".repeat(64),
                "journal_revision": 1,
                "state_hash": "0".repeat(64)
            }),
        ),
    ];

    for (nonce, payload) in &forged_requests {
        write_private(
            peers_dir.join("request.json"),
            serde_json::to_vec(payload).unwrap(),
        );
        thread::sleep(Duration::from_millis(120));
        for entry in fs::read_dir(&peers_dir).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".ack.json") {
                let raw = fs::read_to_string(entry.path()).unwrap();
                assert!(
                    !raw.contains(nonce),
                    "forged request {nonce} must never be acknowledged: {raw}"
                );
            }
        }
    }
    let _ = fs::remove_file(peers_dir.join("request.json"));

    // Legitimate enable by separate operator updates the journal, but the already-attached backend
    // never widens its live registry via restrict_to (remains disabled until explicit reload/re-attach).
    let enable_resp = decide_from_operator(&settings, &enable_id, true);
    assert_eq!(enable_resp.status, 200, "enable decide: {}", enable_resp.body);
    let enable_json: Value = serde_json::from_str(&enable_resp.body).unwrap();
    assert_eq!(enable_json["effect_now"], "enabled_and_pinned");
    assert_eq!(
        enable_json["revocation_ack"]["remote_backends_acknowledged"],
        1
    );

    let after_enable = backend.tool_call(
        3,
        "desktop_mcp_manage",
        json!({"action": "inspect", "name": "sim_http"}),
    );
    let after_json: Value = serde_json::from_str(
        after_enable["result"]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        after_json["server"]["enabled"], false,
        "restrict_to must never widen an already-attached backend"
    );

    backend.shutdown();

    // Part C: An unexpected file inside .extensions-peers must fail closed.
    let disable_id_rogue = queue_action("disable");
    let rogue_path = peers_dir.join("rogue.json");
    write_private(&rogue_path, b"{}");
    let rogue_resp = decide_from_operator(&settings, &disable_id_rogue, true);
    assert_eq!(
        rogue_resp.status, 400,
        "rogue peer file must be refused: {}",
        rogue_resp.body
    );
    fs::remove_file(&rogue_path).unwrap();
}
