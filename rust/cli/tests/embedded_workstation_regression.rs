use agent_bridge::backend::{
    dispatch_private_child, start_backend, OperatorControl, OperatorRead, OperatorWrite,
    WorkstationConfig,
};
use agent_bridge_core::CoreDatabase;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const ORIGIN: &str = "https://embedded-workstation.example.invalid";
const CALLBACK: &str = "https://oauth-redirect.googleusercontent.com/r/agent-bridge-fixture";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Fixture { root: PathBuf, port: u16, ui_reservation: TcpListener }
impl Fixture {
    fn new() -> Self {
        #[cfg(unix)]
        let base = {
            use std::os::unix::fs::PermissionsExt;
            let base = PathBuf::from(std::env::var_os("HOME").unwrap()).join(".ab-embedded-tests");
            fs::create_dir_all(&base).unwrap();
            fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
            base
        };
        #[cfg(not(unix))]
        let base = {
            let base = fs::canonicalize(std::env::temp_dir()).unwrap();
            base.to_str().and_then(|s| s.strip_prefix("\\\\?\\"))
                .map(PathBuf::from).unwrap_or(base)
        };
        let root = base.join(format!("embedded-{}-{}", std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir_all(&root).unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::create_dir(root.join("project")).unwrap();
        fs::create_dir(root.join("db")).unwrap();
        drop(CoreDatabase::initialize_new(&root.join("db/missions.sqlite")).unwrap());
        agent_bridge_lifecycle::initialize_operator_settings(&root.join("settings")).unwrap();
        for name in ["oauth-workstation", "oauth-missions", "lifecycle"] {
            let path = root.join(name);
            agent_bridge_lifecycle::initialize_operator_settings(&path).unwrap();
            for entry in fs::read_dir(&path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_file() { fs::remove_file(path).unwrap(); }
            }
        }
        let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let ui_reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        Self { root, port, ui_reservation }
    }
    fn args(&self) -> Vec<String> {
        vec![
            "gemini".into(), "workstation".into(),
            self.root.join("db/missions.sqlite").display().to_string(),
            self.root.join("oauth-workstation").display().to_string(),
            ORIGIN.into(), self.port.to_string(),
            "--project".into(), self.root.join("project").display().to_string(),
            "--profile".into(), "workspace-write".into(),
            "--missions-state".into(), self.root.join("oauth-missions").display().to_string(),
            "--missions-origin".into(), "https://embedded-missions.example.invalid".into(),
            "--settings-dir".into(), self.root.join("settings").display().to_string(),
            "--lifecycle-dir".into(), self.root.join("lifecycle").display().to_string(),
            "--enable-task-rooms".into(),
            "--ui-port".into(), self.ui_reservation.local_addr().unwrap().port().to_string(),
        ]
    }
    fn config(&self) -> WorkstationConfig { WorkstationConfig::from_cli_args(&self.args()).unwrap() }
    fn scope(&self) -> Vec<u8> {
        fs::read(self.root.join("oauth-workstation/.agent-bridge-workstation-scope-v2.json")).unwrap()
    }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); } }

struct Response { status: u16, headers: BTreeMap<String, String>, body: String }
impl Response { fn json(&self) -> Value { serde_json::from_str(&self.body).unwrap() } }
struct Connection { port: u16, stream: BufReader<TcpStream> }
impl Connection {
    fn open(port: u16) -> Self {
        let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
        Self { port, stream: BufReader::new(stream) }
    }
    fn request(&mut self, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Response {
        let mut request = format!("{method} {path} HTTP/1.1\r\n");
        if !headers.iter().any(|(key, _)| key.eq_ignore_ascii_case("host")) {
            request.push_str(&format!("Host: 127.0.0.1:{}\r\n", self.port));
        }
        request.push_str(&format!("Connection: keep-alive\r\nContent-Length: {}\r\n", body.len()));
        for (key, value) in headers { request.push_str(&format!("{key}: {value}\r\n")); }
        request.push_str("\r\n");
        request.push_str(body);
        self.stream.get_mut().write_all(request.as_bytes()).unwrap();
        let mut line = String::new();
        self.stream.read_line(&mut line).unwrap();
        let status = line.split_whitespace().nth(1).expect("HTTP status").parse().unwrap();
        let mut headers = BTreeMap::new();
        loop {
            line.clear();
            assert!(self.stream.read_line(&mut line).unwrap() > 0);
            if line == "\r\n" { break; }
            let (key, value) = line.trim_end().split_once(':').unwrap();
            headers.insert(key.to_ascii_lowercase(), value.trim().to_owned());
        }
        let length: usize = headers.get("content-length").expect("bounded response").parse().unwrap();
        assert!(length <= 1024 * 1024);
        let mut bytes = vec![0; length];
        self.stream.read_exact(&mut bytes).unwrap();
        Response { status, headers, body: String::from_utf8(bytes).unwrap() }
    }
}
fn form(pairs: &[(&str, &str)]) -> String {
    fn encode(value: &str) -> String {
        value.bytes().map(|byte| if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'.' | b'_' | b'~') { char::from(byte).to_string() }
            else { format!("%{byte:02X}") }).collect()
    }
    pairs.iter().map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>().join("&")
}
async fn authorize(operator: &OperatorControl, connection: &mut Connection) -> String {
    assert_eq!(operator.post(OperatorWrite::OAuthEnroll, json!({"confirm":"APPROVE"}))
        .await.unwrap().status, 200);
    let registration = connection.request("POST", "/oauth/register",
        &[("Content-Type", "application/json")], &json!({
            "redirect_uris":[CALLBACK], "token_endpoint_auth_method":"client_secret_post",
            "grant_types":["authorization_code","refresh_token"], "response_types":["code"]
        }).to_string());
    assert_eq!(registration.status, 201, "{}", registration.body);
    let client = registration.json();
    let client_id = client["client_id"].as_str().unwrap();
    let client_secret = client["client_secret"].as_str().unwrap();
    let resource = format!("{ORIGIN}/mcp");
    let query = form(&[
        ("response_type","code"), ("client_id",client_id), ("redirect_uri",CALLBACK),
        ("code_challenge","E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
        ("code_challenge_method","S256"), ("state","embedded-fixture"),
        ("resource",&resource), ("scope","mcp"),
    ]);
    let path = format!("/oauth/authorize?{query}");
    assert_eq!(connection.request("GET", &path, &[], "").status, 200);
    let pending = operator.get(OperatorRead::OAuth).await.unwrap();
    let request_id = pending.body["pending"][0]["id"].as_str().unwrap();
    assert_eq!(operator.post(OperatorWrite::OAuthApprove, json!({
        "request_id":request_id, "redirect_uri":CALLBACK, "confirm":"APPROVE"
    })).await.unwrap().status, 200);
    let redirect = connection.request("GET", &path, &[], "");
    assert_eq!(redirect.status, 302);
    let location = &redirect.headers["location"];
    let code = location.split_once('?').unwrap().1.split('&')
        .filter_map(|pair| pair.split_once('=')).find(|(key, _)| *key == "code").unwrap().1;
    let exchange = connection.request("POST", "/oauth/token",
        &[("Content-Type","application/x-www-form-urlencoded")], &form(&[
            ("grant_type","authorization_code"), ("client_id",client_id), ("client_secret",client_secret),
            ("code",code), ("redirect_uri",CALLBACK),
            ("code_verifier","dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), ("resource",&resource),
        ]));
    assert_eq!(exchange.status, 200);
    format!("Bearer {}", exchange.json()["access_token"].as_str().unwrap())
}
fn mcp(connection: &mut Connection, bearer: &str, id: u64, method: &str, params: Value) -> Value {
    let response = connection.request("POST", "/mcp",
        &[("Content-Type","application/json"),("Authorization",bearer)],
        &json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}).to_string());
    assert_eq!(response.status, 200, "{}", response.body);
    response.json()
}
fn policy(connection: &mut Connection, bearer: &str, id: u64) -> Value {
    let response = mcp(connection,bearer,id,"tools/call",
        json!({"name":"desktop_policy_status","arguments":{}}));
    assert_ne!(response["result"]["isError"], true, "{response}");
    serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

#[tokio::test(flavor="multi_thread", worker_threads=2)]
async fn embedded_runtime_has_one_listener_and_operator_changes_the_same_authenticated_profile() {
    let fixture = Fixture::new();
    let mut runtime = start_backend(fixture.config()).await.expect("embedded runtime is implemented");
    assert_eq!(runtime.descriptor().pid, std::process::id());
    assert_eq!(runtime.descriptor().listen_addr, format!("127.0.0.1:{}",fixture.port));
    assert!(!runtime.is_finished());
    let operator = runtime.operator();
    assert_eq!(operator.post(OperatorWrite::OAuthEnroll,json!({"confirm":"approve"}))
        .await.unwrap().status,403);
    assert_eq!(operator.post(OperatorWrite::OAuthApprove,json!({
        "request_id":"not-approved","redirect_uri":CALLBACK,"confirm":"yes"
    })).await.unwrap().status,403);
    assert_eq!(operator.post(OperatorWrite::ExtensionsDecide,json!({
        "request_id":"not-approved","approve":true,"confirm":"yes"
    })).await.unwrap().status,403);
    assert_eq!(operator.post(OperatorWrite::SetProfile,json!({"profile":"x".repeat(70*1024)}))
        .await.unwrap().status,413);
    let scope = fixture.scope();
    let mut connection = Connection::open(fixture.port);
    assert_eq!(connection.request("GET","/health",&[],"").status,200);
    let bearer = authorize(&operator,&mut connection).await;
    let init = mcp(&mut connection,&bearer,1,"initialize",
        json!({"protocolVersion":"2025-03-26","capabilities":{},
            "clientInfo":{"name":"embedded-fixture","version":"1"}}));
    assert!(init["result"].is_object());
    assert_eq!(policy(&mut connection,&bearer,2)["profile"],"workspace-write");
    let changed = operator.post(OperatorWrite::SetProfile,json!({"profile":"read-only"})).await.unwrap();
    assert_eq!(changed.status,200);
    assert_eq!(policy(&mut connection,&bearer,3)["profile"],"read-only");
    assert_eq!(operator.post(OperatorWrite::SetProfile,json!({"profile":"fully-unlocked"}))
        .await.unwrap().status,403);
    assert_eq!(operator.post(OperatorWrite::SetProfile,json!({"profile":"workspace-write","extra":true}))
        .await.unwrap().status,400);
    let overview = operator.get(OperatorRead::Overview).await.unwrap();
    assert_eq!(overview.status,200);
    assert!(overview.body["database"].get("error").is_none(),"{:?}",overview.body);
    assert_eq!(operator.get(OperatorRead::Missions).await.unwrap().status,200);
    for path in ["/", "/api/profile", "/api/shutdown", "/api/oauth/enroll",
        "/api/oauth/approve", "/api/extensions/decide"] {
        for host in [format!("127.0.0.1:{}", fixture.port),
            "embedded-workstation.example.invalid".into()] {
            let response=connection.request("POST",path,
                &[("Host",&host),("Authorization",&bearer),("X-Agent-Bridge-Token","forged"),
                  ("Forwarded","for=127.0.0.1;host=localhost"),
                  ("X-Forwarded-Host","localhost"),("Content-Type","application/json")],"{}");
            assert_eq!(response.status,404,"operator route exposed: {path}");
        }
    }
    assert_eq!(connection.request("GET","/health",&[("Host","evil.invalid")],"").status,403);
    assert_eq!(connection.request("GET","/health",&[("Origin","https://evil.invalid")],"").status,403);
    assert_eq!(fixture.scope(),scope);
    let descriptor=serde_json::to_string(runtime.descriptor()).unwrap();
    assert!(!descriptor.contains(&bearer));
    assert!(!descriptor.contains("token"));
    drop(connection);
    assert!(runtime.shutdown().await.unwrap().clean);
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST,fixture.port)).is_err());
    assert!(operator.get(OperatorRead::Profile).await.is_err());
}

#[tokio::test(flavor="multi_thread", worker_threads=2)]
async fn shutdown_keeps_exclusive_ownership_until_join_and_old_controls_cannot_reenter() {
    let fixture=Fixture::new();
    let mut runtime=start_backend(fixture.config()).await.expect("embedded runtime is implemented");
    let old=runtime.operator();
    let generation=runtime.descriptor().generation;
    assert!(start_backend(fixture.config()).await.is_err(),"second owner must be refused");
    runtime.request_shutdown().unwrap();
    assert!(old.post(OperatorWrite::SetProfile,json!({"profile":"read-only"})).await.is_err());
    assert!(start_backend(fixture.config()).await.is_err(),"ownership remains until joined cleanup");
    assert!(runtime.join().await.unwrap().clean);
    assert!(runtime.is_finished());
    let mut replacement=start_backend(fixture.config()).await.unwrap();
    assert_ne!(replacement.descriptor().generation,generation);
    assert!(old.get(OperatorRead::Profile).await.is_err(),"old clone never attaches to replacement");
    assert_eq!(replacement.operator().get(OperatorRead::Profile).await.unwrap()
        .body["active_profile"],"workspace-write");
    assert!(replacement.shutdown().await.unwrap().clean);
}

#[test]
fn native_config_and_child_dispatch_fail_closed_before_ui_initialization() {
    assert!(WorkstationConfig::from_cli_args(&["serve".into(),"db".into(),"--port".into(),"18856".into()]).is_err());
    assert!(WorkstationConfig::from_cli_args(&["gemini".into(),"workstation".into()]).is_err());
    assert_eq!(dispatch_private_child(&[OsString::from("--background")]).unwrap(),None);
    for args in [
        vec!["__workspace-file-info-child-v1"],
        vec!["__workspace-file-info-child-v1","root"],
        vec!["__workspace-file-info-child-v1","root","binding","extra"],
        vec!["--agent-bridge-lifecycle-host"],
    ] {
        let args=args.into_iter().map(OsString::from).collect::<Vec<_>>();
        assert!(dispatch_private_child(&args).is_err(),"malformed private child must not fall through");
    }
}


#[tokio::test(flavor="multi_thread", worker_threads=2)]
async fn cancelling_shutdown_wait_retains_the_owner_until_requests_drain() {
    let fixture=Fixture::new();
    let mut runtime=start_backend(fixture.config()).await.unwrap();
    let mut stream=TcpStream::connect((Ipv4Addr::LOCALHOST,fixture.port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(stream, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: 10\r\nExpect: 100-continue\r\n\r\n", fixture.port).unwrap();
    let mut reader=BufReader::new(stream);
    let mut line=String::new();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("100 Continue"),"request body has been admitted: {line}");
    let cancelled=tokio::time::timeout(Duration::from_millis(50),runtime.shutdown()).await;
    assert!(cancelled.is_err(),"shutdown must wait for the admitted request");
    assert!(start_backend(fixture.config()).await.is_err(),"cancelled wait cannot release ownership");
    drop(reader);
    assert!(runtime.join().await.unwrap().clean,"join must remain usable after cancellation");
    let mut replacement=start_backend(fixture.config()).await.unwrap();
    assert!(replacement.shutdown().await.unwrap().clean);
}

#[tokio::test(flavor="multi_thread", worker_threads=2)]
async fn failed_listener_start_releases_only_its_own_prepared_resources() {
    let fixture=Fixture::new();
    let busy=TcpListener::bind((Ipv4Addr::LOCALHOST,fixture.port)).unwrap();
    assert!(start_backend(fixture.config()).await.is_err());
    assert!(busy.local_addr().is_ok(),"startup must not stop the unrelated listener");
    drop(busy);
    let mut runtime=start_backend(fixture.config()).await.unwrap();
    assert_eq!(runtime.operator().get(OperatorRead::Profile).await.unwrap().status,200);
    assert!(runtime.shutdown().await.unwrap().clean);
}

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread;

#[tokio::test(flavor="multi_thread", worker_threads=2)]
async fn accepted_extension_oauth_worker_is_drained_and_never_reused_by_the_next_generation() {
    let fixture=Fixture::new();
    let metadata=OAuthMetadataFixture::start();
    let db=fixture.root.join("db/missions.sqlite");
    let project=fixture.root.join("project");
    let settings=fixture.root.join("settings");
    let add_id=queue_extension_proposal_via_stdio(&db,&project,&settings,json!({
        "action":"add","name":"ui_oauth","url":metadata.endpoint,
        "oauth":true,"oauth_client_id":"ui-public-client","oauth_scope":"mcp:read"
    }));
    let mut args=fixture.args();
    args.retain(|argument|argument!="--enable-task-rooms");
    let config=||WorkstationConfig::from_cli_args(&args).unwrap();
    let mut runtime=start_backend(config()).await.unwrap();
    let operator=runtime.operator();
    let added=operator.post(OperatorWrite::ExtensionsDecide,json!({
        "request_id":add_id,"approve":true,"confirm":"APPROVE"
    })).await.unwrap();
    assert_eq!(added.status,200,"{:?}",added.body);
    let id=queue_extension_proposal_via_stdio(&db,&project,&settings,
        json!({"action":"auth_start","name":"ui_oauth","force":true}));
    let accepted=operator.post(OperatorWrite::ExtensionsDecide,json!({
        "request_id":id,"approve":true,"confirm":"APPROVE"
    })).await.unwrap();
    assert_eq!(accepted.status,202,"{:?}",accepted.body);
    let operation=tokio::time::timeout(Duration::from_secs(3),async {
        loop {
            let value=operator.get(OperatorRead::Extensions).await.unwrap().body;
            if value["oauth_operation"]["auth_url"].is_string() {break value["oauth_operation"].clone();}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("real OAuth worker publishes its callback before returning");
    assert_eq!(metadata.requests.load(Ordering::Relaxed),2);
    let url=operation["auth_url"].as_str().unwrap();
    let params:BTreeMap<_,_>=url.split_once('?').unwrap().1.split('&')
        .filter_map(|pair|pair.split_once('='))
        .map(|(key,value)|(key,value.replace("%3A",":").replace("%2F","/"))).collect();
    let callback_port:u16=params["redirect_uri"].split("://").nth(1).unwrap()
        .split('/').next().unwrap().rsplit(':').next().unwrap().parse().unwrap();
    runtime.request_shutdown().unwrap();
    let pending=tokio::time::timeout(Duration::from_millis(50),runtime.join()).await.is_err();
    let retained=if pending {start_backend(config()).await.is_err()} else {false};
    // Release the real callback wait even when asserting the old faulty behavior.
    let mut callback=TcpStream::connect((Ipv4Addr::LOCALHOST,callback_port)).unwrap();
    callback.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    write!(callback,"GET /callback?error=access_denied&state={} HTTP/1.1\r\nHost: 127.0.0.1:{callback_port}\r\nConnection: close\r\n\r\n",params["state"]).unwrap();
    let mut response=String::new(); callback.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1"));
    assert!(runtime.join().await.unwrap().clean);
    assert!(pending,"Stop returned clean after 202 while the actual OAuth worker awaited a callback");
    assert!(retained,"cancelled drain must retain generation ownership");
    assert!(operator.get(OperatorRead::Extensions).await.is_err());
    let mut next=start_backend(config()).await.unwrap();
    let snapshot=next.operator().get(OperatorRead::Extensions).await.unwrap().body;
    assert!(snapshot["oauth_operation"].is_null(),"a new generation must not inherit old OAuth operation state");
    assert!(snapshot["requests"].as_array().unwrap().iter()
        .any(|request|request["request_id"]==id && request["decision"]=="refused"));
    assert!(next.shutdown().await.unwrap().clean);
}

fn queue_extension_proposal_via_stdio(
    db: &Path, project: &Path, settings: &Path, arguments: Value,
) -> String {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-bridge"));
    #[cfg(windows)] {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.args([
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
