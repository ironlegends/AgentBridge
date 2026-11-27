use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-bridge"))
}

#[test]
fn audit_history_cli_checks_filters_before_opening_the_store() {
    let owner = TempSandbox::new("audit-cli");
    let absent = owner.path().join("no-history");
    for options in [
        &["--limit", "0"][..],
        &["--client-hash", "private-client"][..],
        &["--since-ms", "11", "--until-ms", "10"][..],
        &["--method", "ping", "--method", "ping"][..],
        &["--context-id", "unverified"][..],
        &["--mission-id", "ctx_invalid"][..],
    ] {
        let result = Command::new(bin()).args(["audit", "recent"]).arg(&absent)
            .args(options).output().unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("Invalid audit filter"));
        assert!(result.stdout.is_empty());
        assert!(!absent.exists());
    }
}

struct TempSandbox {
    dir: PathBuf,
}

#[test]
fn audit_recent_reads_a_completed_local_call_after_the_stdio_process_exits() {
    let sandbox = TempSandbox::new("audit-local-call");
    let (workspace, database, settings) = init_env(&sandbox);
    let mut bridge = StdioMcp::spawn(&[
        "stdio", database.to_str().unwrap(), "--workspace", workspace.to_str().unwrap(),
        "--settings", settings.to_str().unwrap(),
    ], &workspace, "full-control");
    let (failed, _) = bridge.call_tool("agent_bridge_status", json!({}));
    assert!(!failed);
    assert_eq!(bridge.close(), 0);

    let result = Command::new(bin()).args(["audit", "recent"]).arg(&settings)
        .args(["--provider", "local", "--method", "tools/call", "--outcome", "success", "--limit", "8"])
        .output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let history: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(history["available"], true);
    let rows = history["records"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["tool_name"], "agent_bridge_status");
    assert_eq!(rows[0]["provider"], "local");
    assert_eq!(rows[0]["session_id"].as_str().unwrap().len(), 32);
    assert!(rows[0].get("arguments").is_none());
    assert!(rows[0].get("result").is_none());
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
            let root = home.join(".ab-cli-tests");
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

        let dir = base.join(format!(
            "ab-cli-test-{}-{}-{}",
            label,
            std::process::id(),
            n
        ));
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

fn sha256_file(path: &Path) -> String {
    let bytes = fs::read(path).expect("read binary for sha256");
    Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect()
}

struct StdioMcp {
    child: Child,
    stdin: Option<ChildStdin>,
    reader: BufReader<ChildStdout>,
    next_id: u64,
}

impl StdioMcp {
    fn spawn(args: &[&str], cwd: &Path, profile: &str) -> Self {
        Self::spawn_image(&bin(), args, cwd, profile)
    }

    fn spawn_image(image: &Path, args: &[&str], cwd: &Path, profile: &str) -> Self {
        let mut cmd = Command::new(image);
        cmd.args(args)
            .current_dir(cwd)
            .env("AGENT_BRIDGE_DESKTOP_PROFILE", profile)
            .env_remove("AGENT_BRIDGE_DESKTOP_PROFILE_LOCK")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(if image == bin().as_path() { Stdio::piped() } else { Stdio::inherit() });
        let mut child = cmd.spawn().expect("spawn agent-bridge stdio");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        let mut client = Self {
            child,
            stdin: Some(stdin),
            reader: BufReader::new(stdout),
            next_id: 0,
        };
        let init = client.rpc(
            "initialize",
            Some(json!({
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "rust-cli-regression", "version": "1.0"}
            })),
        );
        assert!(init.get("result").is_some(), "initialize failed: {init}");
        client.notify("notifications/initialized");
        client
    }

    fn notify(&mut self, method: &str) {
        let line = json!({"jsonrpc": "2.0", "method": method}).to_string();
        let stdin = self.stdin.as_mut().expect("stdin open");
        writeln!(stdin, "{line}").expect("write notify");
        stdin.flush().expect("flush notify");
    }

    fn rpc(&mut self, method: &str, params: Option<Value>) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let mut req = json!({"jsonrpc": "2.0", "id": id, "method": method});
        if let Some(p) = params {
            req["params"] = p;
        }
        let stdin = self.stdin.as_mut().expect("stdin open");
        writeln!(stdin, "{}", req).expect("write rpc");
        stdin.flush().expect("flush rpc");

        let mut line = String::new();
        loop {
            line.clear();
            let n = self.reader.read_line(&mut line).expect("read rpc line");
            assert!(n > 0, "unexpected EOF waiting for response id={id}");
            let v: Value = serde_json::from_str(&line).expect("parse rpc json");
            if v.get("id").and_then(Value::as_u64) == Some(id) {
                return v;
            }
        }
    }

    fn tools_list(&mut self) -> Vec<String> {
        let r = self.rpc("tools/list", None);
        r["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_owned())
            .collect()
    }

    fn call_tool(&mut self, name: &str, arguments: Value) -> (bool, Value) {
        let r = self.rpc(
            "tools/call",
            Some(json!({"name": name, "arguments": arguments})),
        );
        if let Some(err) = r.get("error") {
            return (true, json!({"jsonrpc_error": err}));
        }
        let res = &r["result"];
        let is_err = res.get("isError").and_then(Value::as_bool).unwrap_or(false);
        let text = res["content"][0]["text"].as_str().unwrap_or("");
        let parsed = serde_json::from_str(text).unwrap_or_else(|_| json!({"raw_text": text}));
        (is_err, parsed)
    }

    #[cfg(windows)]
    fn fail_with_operator_diagnostics(&mut self, phase: &str, response: &Value) -> ! {
        use std::io::Read;
        self.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        let mut diagnostics = Vec::new();
        if let Some(stderr) = self.child.stderr.take() {
            let _ = stderr.take(64 * 1024).read_to_end(&mut diagnostics);
        }
        panic!("{phase}: {response}; owned MCP stderr: {}",
            String::from_utf8_lossy(&diagnostics));
    }

    fn close(mut self) -> i32 {
        self.stdin.take();
        let status = self.child.wait().expect("wait child");
        status.code().unwrap_or(-1)
    }
}

impl Drop for StdioMcp {
    fn drop(&mut self) {
        self.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn connected_sessions_stdio_is_visible_only_through_its_authenticated_read() {
    use std::io::Read;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::time::Duration;

    let sandbox = TempSandbox::new("local-session-view");
    let path = sandbox.path().join("missions.sqlite");
    drop(agent_bridge_core::CoreDatabase::initialize_new(&path).unwrap());
    let private = sandbox.path().join("operator");
    agent_bridge_lifecycle::initialize_operator_settings(&private).unwrap();
    let descriptor = private.join("session-view.json");
    let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let port = address.port().to_string();
    let mut mcp = StdioMcp::spawn(
        &["stdio", path.to_str().unwrap(), "--ui-port", &port,
            "--ui-session-file", descriptor.to_str().unwrap()], sandbox.path(), "read-only",
    );
    let report: Value = serde_json::from_slice(&fs::read(descriptor).unwrap()).unwrap();
    assert_eq!(report["session_view_only"], true);
    let token = report["ui_url"].as_str().unwrap().split_once("?token=").unwrap().1;
    let (failed, context) = mcp.call_tool("agent_bridge_context_create", json!({}));
    assert!(!failed, "{context}");
    let read = |authorization: &str| {
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(3)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        write!(stream, "GET /api/sessions HTTP/1.1\r\nHost: {address}\r\n{authorization}Connection: close\r\n\r\n").unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    };
    let refused = read("");
    assert!(refused.starts_with("HTTP/1.1 401 "));
    assert!(!refused.contains("\"sessions\""));
    let response = read(&format!("X-Agent-Bridge-Token: {token}\r\n"));
    assert!(response.starts_with("HTTP/1.1 200 "));
    let body: Value = serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body["totals"], json!({"connected":1,"live":1}));
    assert_eq!(body["sessions"][0]["provider"], "local");
    assert_eq!(body["sessions"][0]["transport"], "stdio");
    assert_eq!(body["sessions"][0]["contexts"][0]["context_id"], context["context_id"]);
    assert!(!response.contains(token));
    assert!(!response.contains(context["context_handle"].as_str().unwrap()));
    let mut stderr = mcp.child.stderr.take().unwrap();
    assert_eq!(mcp.close(), 0);
    let mut diagnostics = String::new();
    stderr.read_to_string(&mut diagnostics).unwrap();
    assert!(!diagnostics.contains(token));
    assert!(TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err());
}

fn init_env(sb: &TempSandbox) -> (PathBuf, PathBuf, PathBuf) {
    let ws = sb.path().join("workspace");
    let db_dir = sb.path().join("db");
    let settings = sb.path().join("settings");
    fs::create_dir_all(&ws).unwrap();
    fs::create_dir_all(&db_dir).unwrap();
    let db = db_dir.join("missions.sqlite");

    let out = Command::new(bin())
        .args(["db", "init", db.to_str().unwrap()])
        .output()
        .expect("db init");
    assert!(out.status.success(), "db init failed: {:?}", out);

    let out = Command::new(bin())
        .args(["settings", "init", settings.to_str().unwrap()])
        .output()
        .expect("settings init");
    assert!(out.status.success(), "settings init failed: {:?}", out);

    (ws, db, settings)
}

#[test]
fn cli_basics_and_window_consent_gap_regressions() {
    let sb = TempSandbox::new("cli-basics");
    let (ws, db, settings) = init_env(&sb);

    // --version
    let v = Command::new(bin()).arg("--version").output().unwrap();
    assert!(v.status.success());
    assert!(String::from_utf8_lossy(&v.stdout).contains("agent-bridge"));

    // db inspect
    let insp = Command::new(bin())
        .args(["db", "inspect", db.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(insp.status.success());
    let insp_out = String::from_utf8_lossy(&insp.stdout);
    assert!(insp_out.contains("schema_version") && insp_out.contains("pending_migrations"));

    // workspace inspect (Windows-only direct directory access probe; unsupported on Unix)
    let wi = Command::new(bin())
        .args(["workspace", "inspect", ws.to_str().unwrap()])
        .output()
        .unwrap();
    #[cfg(windows)]
    assert!(wi.status.success(), "workspace inspect failed: {:?}", wi);
    #[cfg(not(windows))]
    {
        assert!(!wi.status.success(), "workspace inspect must report unsupported on Unix");
        let err_out = String::from_utf8_lossy(&wi.stderr);
        assert!(
            err_out.contains("only supported on Windows") || err_out.contains("Unsupported"),
            "unexpected unix workspace inspect stderr: {err_out}"
        );
    }

    // Gap/security: --local-window-read without --workspace must be rejected
    let no_ws = Command::new(bin())
        .args([
            "stdio",
            db.to_str().unwrap(),
            "--local-window-read",
            "AgentBridge-Preparation",
            bin().to_str().unwrap(),
            "FakeClass",
            "FakeTitle",
        ])
        .output()
        .unwrap();
    assert!(!no_ws.status.success(), "window read without workspace must fail");

    // Gap/security: --local-window-read without interactive local operator confirmation must fail closed
    let non_interactive = Command::new(bin())
        .args([
            "stdio",
            db.to_str().unwrap(),
            "--workspace",
            ws.to_str().unwrap(),
            "--local-window-read",
            "AgentBridge-Preparation",
            bin().to_str().unwrap(),
            "FakeClass",
            "FakeTitle",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        !non_interactive.status.success(),
        "window read must fail closed without local operator confirmation"
    );

    // Gap/security: extensions approve without interactive TTY fails closed
    let approve = Command::new(bin())
        .args([
            "extensions",
            "approve",
            settings.to_str().unwrap(),
            &"0".repeat(64),
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!approve.status.success());
    // Several ids reach the batch decision, which also fails closed.
    let batch = Command::new(bin())
        .args(["extensions", "approve", settings.to_str().unwrap(), &"0".repeat(64), &"1".repeat(64)])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!batch.status.success());
    assert!(String::from_utf8_lossy(&batch.stderr).contains("Unknown local proposal"));

    // Gap: extensions refresh-check refuses any server other than the public documentation servers
    let rc = Command::new(bin())
        .args(["extensions", "refresh-check", settings.to_str().unwrap(), "other_server"])
        .output()
        .unwrap();
    assert!(!rc.status.success());
}

#[test]
fn stdio_extension_admin_and_outbound_oauth_gap_regressions() {
    let sb = TempSandbox::new("ext-gaps");
    let (ws, db, settings) = init_env(&sb);

    let mut mcp = StdioMcp::spawn(
        &[
            "stdio",
            db.to_str().unwrap(),
            "--write-workspace",
            ws.to_str().unwrap(),
            "--settings",
            settings.to_str().unwrap(),
        ],
        &ws,
        "workspace-write",
    );

    let tools = mcp.tools_list();
    // Window, browser, and process tools must NOT leak into workspace-write without explicit flags/profile
    for (ptool, pargs) in [
        ("desktop_start_process", json!({"command": "workspace-file-info"})),
        ("desktop_read_process", json!({"session_id": "00000000-0000-0000-0000-000000000000"})),
        ("desktop_interact_process", json!({"session_id": "00000000-0000-0000-0000-000000000000", "input": "x"})),
        ("desktop_terminate_process", json!({"session_id": "00000000-0000-0000-0000-000000000000"})),
        ("agent_bridge_project_command", json!({"command": "git-version"})),
    ] {
        let (err, resp) = mcp.call_tool(ptool, pargs);
        assert!(err && resp.to_string().contains("PROCESS_DISABLED_BY_LOCAL_PROFILE"), "{ptool} must refuse in workspace-write: {resp}");
    }
    for absent in [
        "desktop_agent_desktop",
        "desktop_ui_windows",
        "desktop_ui_snapshot",
        "desktop_ui_action",
        "desktop_browser_session",
        "desktop_browser_snapshot",
        "desktop_browser_act",
    ] {
        assert!(!tools.contains(&absent.to_owned()), "unexpected tool exposed: {absent}");
    }

    // list works
    let (err, list) = mcp.call_tool("desktop_mcp_manage", json!({"action": "list"}));
    assert!(!err && list["action"] == "list", "{list}");

    // add queues inert proposal without altering registry directly
    let (err, add) = mcp.call_tool(
        "desktop_mcp_manage",
        json!({"action": "add", "name": "mcp_docs", "url": "https://modelcontextprotocol.io/mcp"}),
    );
    assert!(
        !err && add["executed_by_web"] == false && add["operator_decision_required"] == true,
        "{add}"
    );

    // Ignored parameters on add must be refused
    let (err, ignored) = mcp.call_tool(
        "desktop_mcp_manage",
        json!({
            "action": "add",
            "name": "srv2",
            "url": "https://example.com/mcp",
            "description": "must be refused",
            "oauth": true
        }),
    );
    assert!(err, "add with ignored description/oauth must be refused: {ignored}");

    // Outbound OAuth actions (set_oauth, auth_start incl. force, auth_disconnect, auth_status)
    // must queue cleanly with accurate support labels and never execute directly from Web.
    for (action, expected_support, payload) in [
        (
            "set_oauth",
            "local_oauth_config_change_after_approval",
            json!({
                "action": "set_oauth",
                "name": "mcp_docs",
                "oauth": true,
                "oauth_client_id": "client-1",
                "oauth_client_auth_method": "client_secret_basic",
                "oauth_client_secret_env": "AGENT_BRIDGE_EXTENSION_DEMO_SECRET"
            }),
        ),
        (
            "auth_start",
            "outbound_oauth_pkce_flow_after_approval",
            json!({"action": "auth_start", "name": "mcp_docs", "force": true}),
        ),
        (
            "auth_disconnect",
            "local_oauth_token_disconnect_after_approval",
            json!({"action": "auth_disconnect", "name": "mcp_docs"}),
        ),
        (
            "auth_status",
            "local_auth_and_dpapi_token_status_after_approval",
            json!({"action": "auth_status", "name": "mcp_docs"}),
        ),
    ] {
        let (err, resp) = mcp.call_tool("desktop_mcp_manage", payload);
        assert!(!err, "{action} proposal failed: {resp}");
        assert_eq!(resp["executed_by_web"], false, "{action} must never execute from Web: {resp}");
        assert_eq!(resp["operator_decision_required"], true, "{action} must require operator: {resp}");
        assert_eq!(resp["support"], expected_support, "{action} support mismatch: {resp}");
    }

    // Invalid oauth_client_secret_env (non AGENT_BRIDGE_EXTENSION_* or raw secret value) MUST fail closed
    let (err, bad_env) = mcp.call_tool(
        "desktop_mcp_manage",
        json!({
            "action": "set_oauth",
            "name": "mcp_docs",
            "oauth": true,
            "oauth_client_secret_env": "RAW_SECRET_NOT_ALLOWED"
        }),
    );
    assert!(err, "invalid oauth_client_secret_env must be refused: {bad_env}");

    // refresh with ignored timeout_ms refused
    let (err, ref_bad) = mcp.call_tool(
        "desktop_mcp_manage",
        json!({"action": "refresh", "name": "mcp_docs", "timeout_ms": 5000}),
    );
    assert!(err, "refresh.timeout_ms must be refused: {ref_bad}");

    // Unknown tool inspect & call refused
    let (err, _) = mcp.call_tool("desktop_mcp_tool_inspect", json!({"name": "mcp_docs:unknown"}));
    assert!(err);
    let (err, _) = mcp.call_tool("desktop_mcp_tool_call", json!({"name": "mcp_docs:unknown"}));
    assert!(err);

    // Web MCP manage must refuse add_stdio proposals
    let (err, add_stdio_web) = mcp.call_tool(
        "desktop_mcp_manage",
        json!({
            "action": "add_stdio",
            "name": "web_stdio_attempt",
            "executable": bin().to_str().unwrap(),
            "executable_sha256": sha256_file(&bin()),
            "args": ["stdio"]
        }),
    );
    assert!(err, "add_stdio from Web MCP must be refused: {add_stdio_web}");

    // CLI mcp.json import: invalid-only file exits non-zero without echoing secrets or URLs
    let bad_import_path = sb.path().join("bad-mcp.json");
    let bad_arg_secret = "secret_cli_inline_arg_998877";
    let bad_sse_url = "https://sse-private.example.invalid/stream";
    fs::write(
        &bad_import_path,
        serde_json::to_vec_pretty(&json!({
            "mcpServers": {
                "rel_srv": {
                    "command": "npx",
                    "args": ["-y", "example-mcp"]
                },
                "secret_arg_srv": {
                    "command": bin().to_str().unwrap(),
                    "args": [format!("--api-key={bad_arg_secret}")]
                },
                "sse_srv": {
                    "type": "sse",
                    "url": bad_sse_url
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let bad_import = Command::new(bin())
        .args([
            "extensions",
            "import",
            settings.to_str().unwrap(),
            bad_import_path.to_str().unwrap(),
        ])
        .output()
        .expect("run extensions import bad");
    assert!(!bad_import.status.success(), "import with nothing queued must exit non-zero");
    let bad_stdout = String::from_utf8_lossy(&bad_import.stdout);
    let bad_stderr = String::from_utf8_lossy(&bad_import.stderr);
    assert!(!bad_stdout.contains(bad_arg_secret) && !bad_stderr.contains(bad_arg_secret));
    assert!(!bad_stdout.contains(bad_sse_url) && !bad_stderr.contains(bad_sse_url));
    let bad_report: Value = serde_json::from_str(&bad_stdout).expect("bad import json report");
    assert_eq!(bad_report["proposals"].as_array().unwrap().len(), 0);
    assert_eq!(bad_report["refused"].as_array().unwrap().len(), 3);

    // CLI mcp.json import: valid URL entry queues inert add proposal and drops header secret value
    let good_import_path = sb.path().join("good-mcp.json");
    let raw_header_secret = "cli_imported_header_secret_554433";
    let imported_url = "https://imported-upstream.example.invalid/mcp";
    fs::write(
        &good_import_path,
        serde_json::to_vec_pretty(&json!({
            "mcpServers": {
                "imported_http": {
                    "type": "streamable-http",
                    "url": imported_url,
                    "headers": {
                        "X-Api-Key": raw_header_secret
                    }
                },
                "skipped_disabled": {
                    "disabled": true,
                    "url": "https://disabled.example.invalid/mcp"
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let good_import = Command::new(bin())
        .args([
            "extensions",
            "import",
            settings.to_str().unwrap(),
            good_import_path.to_str().unwrap(),
        ])
        .output()
        .expect("run extensions import good");
    assert!(good_import.status.success(), "valid import failed: {:?}", good_import);
    let good_stdout = String::from_utf8_lossy(&good_import.stdout);
    assert!(!good_stdout.contains(raw_header_secret));
    assert!(!good_stdout.contains(imported_url));
    let good_report: Value = serde_json::from_str(&good_stdout).expect("good import json report");
    assert_eq!(good_report["configuration_changed"], false);
    assert_eq!(good_report["operator_decision_required"], true);
    assert_eq!(good_report["proposals"].as_array().unwrap().len(), 1);
    assert_eq!(good_report["proposals"][0]["name"], "imported_http");
    assert_eq!(good_report["proposals"][0]["kind"], "add");
    assert_eq!(good_report["proposals"][0]["literal_value_dropped"], true);
    let admin_journal_raw = fs::read_to_string(settings.join(".extensions-admin.json")).unwrap();
    assert!(!admin_journal_raw.contains(raw_header_secret));

    assert_eq!(mcp.close(), 0);
}

#[test]
fn stdio_process_tools_confinement_and_shell_gap_regressions() {
    let sb = TempSandbox::new("proc-gaps");
    let (ws, db, settings) = init_env(&sb);
    fs::write(ws.join("hello.txt"), "hello\n").unwrap();

    let mut mcp = StdioMcp::spawn(
        &[
            "stdio",
            db.to_str().unwrap(),
            "--workspace",
            ws.to_str().unwrap(),
            "--settings",
            settings.to_str().unwrap(),
        ],
        &ws,
        "full-control",
    );

    let tools = mcp.tools_list();
    for expected in [
        "desktop_start_process",
        "desktop_read_process",
        "desktop_interact_process",
        "desktop_terminate_process",
    ] {
        assert!(tools.contains(&expected.to_owned()), "missing {expected}");
    }

    // Gap/security: arbitrary shell commands are refused
    for bad_cmd in ["cmd.exe /c echo hi", "powershell.exe -Command 1", "whoami"] {
        let (err, resp) = mcp.call_tool(
            "desktop_start_process",
            json!({"command": bad_cmd, "cwd": ws.to_str().unwrap()}),
        );
        assert!(err, "arbitrary shell command must be refused: {bad_cmd} -> {resp}");
    }

    // A real workspace handle never substitutes for local executable approval.
    let (err, unpinned) = mcp.call_tool(
        "desktop_start_process",
        json!({"command": "workspace-file-info", "cwd": ws.to_str().unwrap()}),
    );
    assert!(
        err && unpinned.to_string().contains("PROCESS_NOT_LOCALLY_APPROVED"),
        "expected PROCESS_NOT_LOCALLY_APPROVED, got: {unpinned}"
    );

    {
        // Pin exact EXE sha256 in sandbox commands.json and verify full 4-tool lifecycle
        let pin = json!({
            "version": 1,
            "programs": {
                "workspace-file-info": {
                    "executable": bin().to_str().unwrap(),
                    "sha256": sha256_file(&bin())
                }
            }
        });
        fs::write(
            settings.join("commands.json"),
            serde_json::to_vec_pretty(&pin).unwrap(),
        )
        .unwrap();

        let (err, started) = mcp.call_tool(
            "desktop_start_process",
            json!({"command": "workspace-file-info", "cwd": ws.to_str().unwrap()}),
        );
        assert!(!err, "pinned workspace-file-info start failed: {started}");
        let sid = started["session_id"].as_str().expect("session_id").to_owned();

        let (err, inter) = mcp.call_tool(
            "desktop_interact_process",
            json!({
                "session_id": sid,
                "input": "{\"operation\":\"get_file_info\",\"path\":\"hello.txt\"}\n",
                "timeout_ms": 5000
            }),
        );
        assert!(!err, "interact failed: {inter}");
        assert_eq!(inter["response"]["ok"], true, "{inter}");
        assert_eq!(inter["response"]["metadata"]["path"], "hello.txt", "{inter}");
        assert_eq!(inter["response"]["metadata"]["bytes"], 6, "{inter}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let outside = sb.path().join("outside");
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("secret.txt"), "private metadata must stay outside\n").unwrap();
            symlink(outside.join("secret.txt"), ws.join("linked.txt")).unwrap();
            symlink(&outside, ws.join("linked-dir")).unwrap();
            fs::hard_link(outside.join("secret.txt"), ws.join("hardlinked.txt")).unwrap();
            for path in ["linked.txt", "linked-dir/secret.txt", "hardlinked.txt"] {
                let frame = json!({"operation":"get_file_info","path":path}).to_string() + "\n";
                let (err, denied) = mcp.call_tool("desktop_interact_process", json!({
                    "session_id":sid,"input":frame,"timeout_ms":5000,
                }));
                assert!(!err, "safe protocol should return a bounded refusal: {denied}");
                assert_eq!(denied["response"]["ok"], false, "unsafe entry was inspected: {denied}");
                assert_eq!(denied["response"]["error"], "METADATA_UNAVAILABLE", "{denied}");
            }
            for frame in [
                json!({"operation":"get_file_info","path":"../outside/secret.txt"}),
                json!({"operation":"read_file","path":"hello.txt"}),
                json!({"operation":"write_file","path":"hello.txt","content":"changed"}),
            ] {
                let (err, denied) = mcp.call_tool("desktop_interact_process", json!({
                    "session_id":sid,"input":frame.to_string()+"\n","timeout_ms":5000,
                }));
                assert!(err, "metadata-only input policy was bypassed: {denied}");
            }
            assert_eq!(fs::read_to_string(ws.join("hello.txt")).unwrap(), "hello\n");
        }

        let (err, read) = mcp.call_tool(
            "desktop_read_process",
            json!({"session_id": sid, "timeout_ms": 1000}),
        );
        assert!(!err, "read failed: {read}");

        let (err, term) = mcp.call_tool("desktop_terminate_process", json!({"session_id": sid}));
        assert!(!err, "terminate failed: {term}");

        #[cfg(unix)]
        {
            let (err, second) = mcp.call_tool("desktop_start_process", json!({
                "command":"workspace-file-info","cwd":ws,
            }));
            assert!(!err, "{second}");
            let second_id = second["session_id"].as_str().unwrap().to_owned();
            let moved = sb.path().join("original-workspace");
            fs::rename(&ws, &moved).unwrap();
            fs::create_dir(&ws).unwrap();
            fs::write(ws.join("hello.txt"), "replacement must never be inspected\n").unwrap();
            let (err, denied) = mcp.call_tool("desktop_start_process", json!({
                "command":"workspace-file-info","cwd":ws,
            }));
            assert!(err, "replacement workspace acquired a new capability: {denied}");
            let (err, denied) = mcp.call_tool("desktop_interact_process", json!({
                "session_id":second_id,
                "input":"{\"operation\":\"get_file_info\",\"path\":\"hello.txt\"}\n",
                "timeout_ms":5000,
            }));
            assert!(err || denied["response"]["ok"] == false,
                "child followed a replacement workspace: {denied}");
            assert_eq!(fs::read_to_string(moved.join("hello.txt")).unwrap(), "hello\n");
        }
    }

    assert_eq!(mcp.close(), 0);
}

#[cfg(windows)]
fn has_installed_chrome() -> bool {
    Path::new(r"C:\Program Files\Google\Chrome\Application\chrome.exe").is_file()
}

/// `extensions import` options come in `--inherit-path <server>` pairs.
#[test]
fn extensions_import_refuses_malformed_inherit_path_options() {
    let sb = TempSandbox::new("import-options");
    let settings = sb.path().join("settings");
    let mcp = sb.path().join("mcp.json");
    for options in [&["--inherit-path"][..], &["--inherit"; 2][..], &["--inherit-path", "a", "--bogus"][..]] {
        let out = Command::new(bin())
            .args(["extensions", "import", settings.to_str().unwrap(), mcp.to_str().unwrap()])
            .args(options)
            .output()
            .expect("extensions import");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{options:?}");
        assert!(stderr.contains("[--inherit-path <stdio-server>]"), "{options:?}: {stderr}");
    }
    assert!(!settings.exists());
}

/// 2.0.0 documented `--local-learn-url`; 2.x keeps parsing it, warns that
/// it is deprecated, and still admits only an exact Learn URL.
#[test]
fn deprecated_learn_reader_option_is_still_parsed() {
    let sb = TempSandbox::new("learn-compat");
    let (ws, db, _) = init_env(&sb);
    let out = Command::new(bin())
        .args(["stdio", db.to_str().unwrap(), "--workspace", ws.to_str().unwrap(),
            "--local-learn-url", "https://example.com/"])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("stdio with --local-learn-url");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "a non-Learn URL must be refused: {stderr}");
    assert!(stderr.contains("--local-learn-url is deprecated since 2.1.0"), "{stderr}");
    assert!(stderr.contains("BRIDGE_LEARN_BROWSER_DENIED"), "{stderr}");
    assert!(!stderr.contains("agent-bridge start ["), "the option must not fall back to usage: {stderr}");
}

#[cfg(windows)]
#[test]
fn stdio_browser_doc_mode_and_missing_actions_gap_regressions() {
    if !has_installed_chrome() {
        eprintln!("skipping browser doc test: installed Chrome not present");
        return;
    }
    let sb = TempSandbox::new("browser-gaps");
    let (ws, db, _) = init_env(&sb);
    fs::write(ws.join("p1.md"), "# Doc 1\nNeedleOne marker\n").unwrap();
    fs::write(ws.join("p2.md"), "# Doc 2\nNeedleTwo marker\n").unwrap();

    let mut mcp = StdioMcp::spawn(
        &[
            "stdio",
            db.to_str().unwrap(),
            "--workspace",
            ws.to_str().unwrap(),
            "--local-doc-page",
            "p1.md",
            "--local-doc-page",
            "p2.md",
        ],
        &ws,
        "read-only",
    );

    // Gap regressions: missing session actions refused
    for unsupported in ["handle_dialog", "list_profiles", "delete_profile", "new_page"] {
        let (err, resp) = mcp.call_tool("desktop_browser_session", json!({"action": unsupported}));
        assert!(err, "unsupported browser session action {unsupported} must fail: {resp}");
    }

    // Extra url parameter on local-doc start refused
    let (err, _) = mcp.call_tool(
        "desktop_browser_session",
        json!({"action": "start", "url": "bridge-doc:///p1.md"}),
    );
    assert!(err, "local-doc start with extra url key must be refused");

    // Valid start
    let (err, st) = mcp.call_tool("desktop_browser_session", json!({"action": "start"}));
    if err { mcp.fail_with_operator_diagnostics("document session start failed", &st); }
    let sid = st["session_id"].as_str().expect("session_id").to_owned();

    // Gap regressions: full_page, include_console, include_network refused
    for flag in ["full_page", "include_console", "include_network"] {
        let mut args = json!({"session_id": sid, "mode": "full"});
        args[flag] = json!(true);
        let (err, resp) = mcp.call_tool("desktop_browser_snapshot", args);
        assert!(err, "snapshot flag {flag}=true must be refused: {resp}");
    }

    // Valid find snapshot
    let (err, snap) = mcp.call_tool(
        "desktop_browser_snapshot",
        json!({"session_id": sid, "mode": "find", "find_query": "NeedleOne"}),
    );
    if err || snap["match_count"].as_u64().unwrap_or(0) < 1 {
        mcp.fail_with_operator_diagnostics("document find snapshot failed", &snap);
    }
    let obs = snap["browser_observation_id"]
        .as_str()
        .expect("browser_observation_id")
        .to_owned();

    // Gap regression: arbitrary external URL refused in act
    let (err, _) = mcp.call_tool(
        "desktop_browser_act",
        json!({
            "session_id": sid,
            "browser_observation_id": obs,
            "actions": [{"type": "goto", "url": "https://example.com"}]
        }),
    );
    assert!(err, "external URL must be refused in local-doc mode");

    // Fresh snapshot -> valid goto p2.md -> reuse observation fails
    let (err, snap2) = mcp.call_tool(
        "desktop_browser_snapshot",
        json!({"session_id": sid, "mode": "full"}),
    );
    assert!(!err, "{snap2}");
    let obs2 = snap2["browser_observation_id"].as_str().unwrap().to_owned();

    let (err, act) = mcp.call_tool(
        "desktop_browser_act",
        json!({
            "session_id": sid,
            "browser_observation_id": obs2,
            "actions": [{"type": "goto", "url": "bridge-doc:///p2.md"}]
        }),
    );
    assert!(!err && act.to_string().contains("NeedleTwo"), "goto p2 failed: {act}");

    let (err, reuse) = mcp.call_tool(
        "desktop_browser_act",
        json!({
            "session_id": sid,
            "browser_observation_id": obs2,
            "actions": [{"type": "goto", "url": "bridge-doc:///p1.md"}]
        }),
    );
    assert!(err, "reusing consumed browser_observation_id must fail: {reuse}");

    let (err, closed) = mcp.call_tool(
        "desktop_browser_session",
        json!({"action": "close", "session_id": sid}),
    );
    assert!(!err && closed["closed"] == true, "{closed}");

    assert_eq!(mcp.close(), 0);
}

#[cfg(windows)]
#[test]
fn stdio_interactive_chrome_handle_dialog_and_profile_gap_regressions() {
    if !has_installed_chrome() {
        eprintln!("skipping interactive Chrome dialog test: installed Chrome not present");
        return;
    }
    let sb = TempSandbox::new("chrome-dialog");
    let (ws, db, _) = init_env(&sb);
    let html = r#"<!doctype html>
<html>
<head><meta charset="utf-8"><title>Dialog Fixture</title></head>
<body>
  <button id="btn-confirm" aria-label="Trigger confirm" onclick="document.getElementById('out').textContent = 'confirm=' + confirm('Confirm bridge action?')">Confirm</button>
  <button id="btn-prompt" aria-label="Trigger prompt" onclick="document.getElementById('out').textContent = 'prompt=' + prompt('Enter label', 'default')">Prompt</button>
  <div id="out">initial</div>
</body>
</html>"#;
    fs::write(ws.join("dialog.html"), html).unwrap();

    let mut mcp = StdioMcp::spawn(
        &[
            "stdio",
            db.to_str().unwrap(),
            "--workspace",
            ws.to_str().unwrap(),
            "--local-chrome-page",
            "dialog.html",
        ],
        &ws,
        "read-only",
    );

    // Explicit gap regressions: persistent profile management remains refused
    for unsupported in ["list_profiles", "delete_profile"] {
        let (err, resp) = mcp.call_tool("desktop_browser_session", json!({"action": unsupported}));
        assert!(err, "{unsupported} must remain refused: {resp}");
    }

    let (err, started) = mcp.call_tool(
        "desktop_browser_session",
        json!({"action": "start"}),
    );
    if err { mcp.fail_with_operator_diagnostics("interactive Chrome start failed", &started); }
    let sid = started["session_id"].as_str().expect("session_id").to_owned();

    // handle_dialog with no active dialog must fail closed
    let (err, no_dlg) = mcp.call_tool(
        "desktop_browser_session",
        json!({"action": "handle_dialog", "session_id": sid, "accept": true}),
    );
    assert!(err, "handle_dialog without open dialog must fail: {no_dlg}");

    // Snapshot & find confirm/prompt button refs
    let (err, snap1) = mcp.call_tool(
        "desktop_browser_snapshot",
        json!({"session_id": sid, "mode": "full"}),
    );
    assert!(!err, "snapshot 1 failed: {snap1}");
    let obs1 = snap1["browser_observation_id"].as_str().unwrap().to_owned();
    let elems = snap1["interactive_elements"].as_array().unwrap();
    let confirm_ref = elems
        .iter()
        .find(|e| e["name"] == "Trigger confirm")
        .expect("confirm button")["ref"]
        .as_str()
        .unwrap()
        .to_owned();

    // 1. Click confirm button -> returns dialog_open=true without hanging
    let (err, act1) = mcp.call_tool(
        "desktop_browser_act",
        json!({
            "session_id": sid,
            "browser_observation_id": obs1,
            "actions": [{"type": "click", "ref": confirm_ref}]
        }),
    );
    assert!(!err, "click confirm failed: {act1}");
    assert_eq!(act1["dialog_open"], true, "{act1}");
    assert_eq!(act1["blocking_dialog"]["type"], "confirm", "{act1}");
    assert_eq!(act1["blocking_dialog"]["message"], "Confirm bridge action?", "{act1}");

    // Snapshot while dialog is open reports dialog_open=true without hanging
    let (err, snap_open) = mcp.call_tool(
        "desktop_browser_snapshot",
        json!({"session_id": sid, "mode": "full"}),
    );
    assert!(!err && snap_open["dialog_open"] == true, "{snap_open}");

    // Handle confirm dialog (accept=true)
    let (err, hd1) = mcp.call_tool(
        "desktop_browser_session",
        json!({"action": "handle_dialog", "session_id": sid, "accept": true}),
    );
    assert!(!err && hd1["handled"] == true && hd1["accept"] == true, "{hd1}");

    // Verify DOM reflects confirm=true and locate prompt button
    let (err, snap2) = mcp.call_tool(
        "desktop_browser_snapshot",
        json!({"session_id": sid, "mode": "full"}),
    );
    assert!(!err, "snapshot 2 failed: {snap2}");
    assert!(
        snap2["text"].as_str().unwrap_or("").contains("confirm=true"),
        "expected confirm=true in page text: {snap2}"
    );
    let obs2 = snap2["browser_observation_id"].as_str().unwrap().to_owned();
    let prompt_ref = snap2["interactive_elements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "Trigger prompt")
        .expect("prompt button")["ref"]
        .as_str()
        .unwrap()
        .to_owned();

    // 2. Click prompt button -> handle_dialog with prompt_text
    let (err, act2) = mcp.call_tool(
        "desktop_browser_act",
        json!({
            "session_id": sid,
            "browser_observation_id": obs2,
            "actions": [{"type": "click", "ref": prompt_ref}]
        }),
    );
    assert!(!err && act2["dialog_open"] == true && act2["blocking_dialog"]["type"] == "prompt", "{act2}");

    let (err, hd2) = mcp.call_tool(
        "desktop_browser_session",
        json!({"action": "handle_dialog", "session_id": sid, "accept": true, "prompt_text": "BridgeOK"}),
    );
    assert!(!err && hd2["handled"] == true, "{hd2}");

    let (err, snap3) = mcp.call_tool(
        "desktop_browser_snapshot",
        json!({"session_id": sid, "mode": "full"}),
    );
    assert!(!err, "snapshot 3 failed: {snap3}");
    assert!(
        snap3["text"].as_str().unwrap_or("").contains("prompt=BridgeOK"),
        "expected prompt=BridgeOK in page text: {snap3}"
    );

    let close_started = std::time::Instant::now();
    let (err, closed) = mcp.call_tool(
        "desktop_browser_session",
        json!({"action": "close", "session_id": sid}),
    );
    let close_elapsed = close_started.elapsed();
    if err {
        // The public MCP error deliberately hides native details. Preserve the
        // operator-only stage and OS error from this fixture's stderr so a Job
        // timeout or private-profile cleanup failure cannot masquerade as a
        // navigation/DOM regression. Do not retry a failed close.
        mcp.stdin.take();
        let _ = mcp.child.kill();
        let _ = mcp.child.wait();
        let mut diagnostics = String::new();
        if let Some(mut stderr) = mcp.child.stderr.take() {
            let _ = std::io::Read::read_to_string(&mut stderr, &mut diagnostics);
        }
        panic!("owned Chrome close failed after {close_elapsed:?}: {closed}; stderr: {diagnostics}");
    }
    assert!(closed["closed"] == true && closed["owned_chrome_exited"] == true
        && closed["temporary_profile_removed"] == true,
        "close must verify child exit and private-profile removal after {close_elapsed:?}: {closed}");
    assert_eq!(mcp.close(), 0);
}

#[cfg(windows)]
#[test]
fn stdio_interactive_chrome_persistent_profiles_lifecycle_and_safety_regressions() {
    if !has_installed_chrome() {
        eprintln!("skipping interactive Chrome profiles test: installed Chrome not present");
        return;
    }
    let sb = TempSandbox::new("chrome-profiles");
    let (ws, db, settings) = init_env(&sb);
    let html = "<!doctype html><html><head><title>Profile Fixture</title></head><body><p>ProfileOK</p></body></html>";
    fs::write(ws.join("profile.html"), html).unwrap();

    let mut mcp = StdioMcp::spawn(
        &[
            "stdio",
            db.to_str().unwrap(),
            "--workspace",
            ws.to_str().unwrap(),
            "--settings",
            settings.to_str().unwrap(),
            "--local-chrome-page",
            "profile.html",
        ],
        &ws,
        "read-only",
    );

    // 1. Initially empty profile list
    let (err, l0) = mcp.call_tool("desktop_browser_session", json!({"action": "list_profiles"}));
    assert!(!err && l0["count"] == 0, "initial list_profiles failed: {l0}");

    // 2. Traversal / invalid profile_id rejected
    for bad in ["../escape", "bad/slash", "has space"] {
        let (err, resp) = mcp.call_tool(
            "desktop_browser_session",
            json!({"action": "delete_profile", "profile_id": bad}),
        );
        assert!(err, "invalid profile_id {bad} must fail: {resp}");
    }

    // 3. Start with persistent profile_id -> active profile listed, cannot be deleted while active
    let (err, st) = mcp.call_tool(
        "desktop_browser_session",
        json!({"action": "start", "profile_id": "work_profile_1"}),
    );
    if err || st["profile"] != "work_profile_1" || st["profile_persistent"] != true {
        mcp.fail_with_operator_diagnostics("persistent Chrome start failed", &st);
    }
    let sid = st["session_id"].as_str().unwrap().to_owned();

    let (err, l1) = mcp.call_tool("desktop_browser_session", json!({"action": "list_profiles"}));
    assert!(!err && l1["count"] == 1 && l1["profiles"][0]["profile_id"] == "work_profile_1" && l1["profiles"][0]["active"] == true, "{l1}");

    let (err, del_active) = mcp.call_tool(
        "desktop_browser_session",
        json!({"action": "delete_profile", "profile_id": "work_profile_1"}),
    );
    assert!(err, "deleting active profile must fail closed: {del_active}");

    // Verify rendered content works inside persistent profile
    let (err, snap) = mcp.call_tool("desktop_browser_snapshot", json!({"session_id": sid, "mode": "full"}));
    assert!(!err && snap["text"].as_str().unwrap_or("").contains("ProfileOK"), "{snap}");

    // 4. Close session -> persistent profile still exists on disk & listed as inactive
    let (err, closed) = mcp.call_tool("desktop_browser_session", json!({"action": "close", "session_id": sid}));
    assert!(!err && closed["closed"] == true, "{closed}");

    let (err, l2) = mcp.call_tool("desktop_browser_session", json!({"action": "list_profiles"}));
    assert!(!err && l2["count"] == 1 && l2["profiles"][0]["active"] == false, "{l2}");

    // 5. Delete inactive persistent profile -> removed cleanly
    let (err, del_ok) = mcp.call_tool(
        "desktop_browser_session",
        json!({"action": "delete_profile", "profile_id": "work_profile_1"}),
    );
    if err {
        mcp.stdin.take();
        let _ = mcp.child.kill();
        let _ = mcp.child.wait();
        let mut diagnostics = String::new();
        if let Some(mut stderr) = mcp.child.stderr.take() {
            let _ = std::io::Read::read_to_string(&mut stderr, &mut diagnostics);
        }
        panic!("inactive Chrome profile deletion failed: {del_ok}; stderr: {diagnostics}");
    }
    assert_eq!(del_ok["deleted"], true, "{del_ok}");

    let (err, l3) = mcp.call_tool("desktop_browser_session", json!({"action": "list_profiles"}));
    assert!(!err && l3["count"] == 0, "{l3}");

    assert_eq!(mcp.close(), 0);
}

#[test]
fn metadata_diagnostic_uses_the_exact_renamed_host_image() {
    let sandbox = TempSandbox::new("renamed-host");
    let (workspace, database, settings) = init_env(&sandbox);
    fs::write(workspace.join("hello.txt"), "hello\n").unwrap();
    let image_dir = sandbox.path().join("host");
    fs::create_dir(&image_dir).unwrap();
    let image = image_dir.join(format!("agent-bridge-desktop-app{}", std::env::consts::EXE_SUFFIX));
    fs::copy(bin(), &image).unwrap();
    let other_dir = sandbox.path().join("other-host");
    fs::create_dir(&other_dir).unwrap();
    let other = other_dir.join(image.file_name().unwrap());
    fs::copy(&image, &other).unwrap();
    let mut mcp = StdioMcp::spawn_image(&image, &[
        "stdio", database.to_str().unwrap(), "--workspace", workspace.to_str().unwrap(),
        "--settings", settings.to_str().unwrap(),
    ], &workspace, "full-control");
    let pin = |path: &Path, digest: String| {
        fs::write(settings.join("commands.json"), serde_json::to_vec_pretty(&json!({
            "version":1, "programs":{"workspace-file-info":{"executable":path, "sha256":digest}}
        })).unwrap()).unwrap();
    };
    pin(&other, sha256_file(&other));
    let (failed, _) = mcp.call_tool("desktop_start_process",
        json!({"command":"workspace-file-info","cwd":workspace}));
    assert!(failed, "same bytes and basename at a different path are not the running host");
    pin(&image, "00".repeat(32));
    let (failed, _) = mcp.call_tool("desktop_start_process",
        json!({"command":"workspace-file-info","cwd":workspace}));
    assert!(failed, "renaming must not bypass the executable SHA pin");
    pin(&image, sha256_file(&image));
    let (failed, started) = mcp.call_tool("desktop_start_process",
        json!({"command":"workspace-file-info","cwd":workspace}));
    assert!(!failed, "exact renamed host must serve its private metadata child: {started}");
    let session = started["session_id"].as_str().unwrap();
    let (failed, reply) = mcp.call_tool("desktop_interact_process", json!({
        "session_id":session, "input":"{\"operation\":\"get_file_info\",\"path\":\"hello.txt\"}\n",
        "timeout_ms":5000
    }));
    assert!(!failed, "{reply}");
    assert_eq!(reply["response"]["metadata"]["bytes"],6, "{reply}");
    let (failed, reply) = mcp.call_tool("desktop_terminate_process",json!({"session_id":session}));
    assert!(!failed, "{reply}");
    assert_eq!(mcp.close(),0);
}
