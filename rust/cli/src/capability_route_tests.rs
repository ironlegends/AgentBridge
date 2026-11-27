use super::*;
use agent_bridge_gateway::{GatewayConfig, McpGateway, ToolCallResult, ToolDefinition, ToolMapHandler};
use agent_bridge_oauth_server::LocalOwner;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const ORIGIN: &str = "https://router-capability.example.invalid";
const CALLBACK: &str = "https://oauth-redirect.googleusercontent.com/r/router-capability";
static NEXT: AtomicU64 = AtomicU64::new(0);
struct TestRoot(PathBuf);
impl Drop for TestRoot { fn drop(&mut self) { let _=std::fs::remove_dir_all(&self.0); } }
struct Fixture {
    app: Gateway,
    _root: TestRoot,
    legacy_access: String,
    unified_access: String,
    unified_client_id: String,
}
fn identity() -> CapabilityIdentity {
    CapabilityIdentity::UnifiedV1 {
        manifest_sha256: "ab".repeat(32),
        catalogue_sha256: router_catalogue_digest(&fixture_router(true)).unwrap().to_string(),
        policy_version: 1,
    }
}
fn b64url(bytes:&[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output=String::new();
    for chunk in bytes.chunks(3) {
        let a=chunk[0] as usize;
        let b=chunk.get(1).copied().unwrap_or(0) as usize;
        let c=chunk.get(2).copied().unwrap_or(0) as usize;
        output.push(ALPHABET[a>>2] as char);
        output.push(ALPHABET[((a&3)<<4)|(b>>4)] as char);
        if chunk.len()>1 { output.push(ALPHABET[((b&15)<<2)|(c>>6)] as char); }
        if chunk.len()>2 { output.push(ALPHABET[c&63] as char); }
    }
    output
}
fn oauth_reply(server:&mut OAuthServer, method:&str, target:&str, body:&[u8],
               content_type:Option<&str>) -> agent_bridge_oauth_server::HttpResponse {
    match server.handle_http(HttpRequest {method,target,body,content_type,
        origin:None,authorization:None}) {
        HttpAction::Reply(reply)=>reply,
        _=>panic!("OAuth-only synthetic request unexpectedly dispatched MCP"),
    }
}
fn issue_access(server:&mut OAuthServer,root:&Path,label:&str) -> (String, String) {
    issue_provider_access(server, root, label, CALLBACK)
}

fn issue_provider_access(server:&mut OAuthServer,root:&Path,label:&str,callback:&str) -> (String, String) {
    let owner=LocalOwner::open(OAuthConfig {state_dir:root.into(), public_origin:ORIGIN.into(),
        audience:Audience::Workstation}).unwrap();
    owner.enable_enrollment(||true).unwrap();
    let registration=serde_json::to_vec(&json!({"redirect_uris":[callback],
        "token_endpoint_auth_method":"client_secret_post"})).unwrap();
    let reply=oauth_reply(server,"POST","/oauth/register",&registration,Some("application/json"));
    assert!((200..300).contains(&reply.status));
    let client:Value=serde_json::from_slice(&reply.body).unwrap();
    let id=client["client_id"].as_str().unwrap();
    let secret=client["client_secret"].as_str().unwrap();
    let verifier="V".repeat(43);
    let challenge=b64url(&Sha256::digest(verifier.as_bytes()));
    let target=format!("/oauth/authorize?response_type=code&client_id={id}&redirect_uri={callback}&code_challenge_method=S256&code_challenge={challenge}&state={label}");
    assert_eq!(oauth_reply(server,"GET",&target,b"",None).status,200);
    let pending=owner.pending_requests().unwrap().into_iter().find(|r|r.client_id==id).unwrap();
    owner.approve_request(&pending.id,|_|true).unwrap();
    let approved=oauth_reply(server,"GET",&target,b"",None);
    assert_eq!(approved.status,302);
    let location=&approved.headers.iter().find(|(name,_)|name=="location").unwrap().1;
    let code=location.split_once('?').unwrap().1.split('&')
        .find_map(|part|part.strip_prefix("code=")).unwrap();
    let form=format!("grant_type=authorization_code&client_id={id}&client_secret={secret}&redirect_uri={callback}&code={code}&code_verifier={verifier}");
    let reply=oauth_reply(server,"POST","/oauth/token",form.as_bytes(),
        Some("application/x-www-form-urlencoded"));
    assert_eq!(reply.status,200);
    let tokens:Value=serde_json::from_slice(&reply.body).unwrap();
    (tokens["access_token"].as_str().unwrap().to_owned(), id.to_owned())
}
fn fixture_router(unified:bool) -> MissionRouter {
    let argument=if unified {"unified_arg"}else{"legacy_arg"};
    let properties=serde_json::Map::from_iter([
        (argument.into(),json!({"type":"boolean"})),("large".into(),json!({"type":"boolean"}))]);
    let mut catalog=vec![ToolDefinition::new("shared_contract",Some("Synthetic contract boundary".into()),
        json!({"type":"object","properties":properties,"required":[argument],"additionalProperties":false}))];
    let mut handlers=ToolMapHandler::new();
    handlers.register("shared_contract",move |arguments| {
        // Production providers validate their own exact input contract. The
        // generic gateway handles JSON-RPC routing, not arbitrary JSON Schema.
        if !arguments.get(argument).is_some_and(Value::is_boolean)
            || arguments.keys().any(|key| key != argument && key != "large")
            || arguments.get("large").is_some_and(|value| !value.is_boolean())
        {
            return Err(agent_bridge_gateway::ToolDispatchError::invalid_params(
                "synthetic selected contract mismatch"));
        }
        Ok(ToolCallResult::text(if arguments.get("large")==Some(&json!(true)) {
            "x".repeat(1024*1024+512)
        }else{if unified {"unified"}else{"legacy"}.into()}))
    });
    if unified {
        catalog.push(ToolDefinition::new("unified_only",None,
            json!({"type":"object","properties":{},"additionalProperties":false})));
        handlers.register("unified_only",|_|Ok(ToolCallResult::text("unified-only")));
    }
    McpGateway::new(GatewayConfig::new("synthetic-boundary","1"),catalog,handlers)
}
impl Fixture {
    fn new() -> Self {
        let base=crate::test_state_base();
        let root=TestRoot(base.join(format!("capability-route-{}-{}",std::process::id(),
            NEXT.fetch_add(1,Ordering::Relaxed))));
        agent_bridge_lifecycle::initialize_operator_settings(&root.0).unwrap();
        for entry in std::fs::read_dir(&root.0).unwrap() {
            let path=entry.unwrap().path();
            if path.is_file(){std::fs::remove_file(path).unwrap();}
        }
        let config=OAuthConfig{state_dir:root.0.clone(),public_origin:ORIGIN.into(),audience:Audience::Workstation};
        let mut legacy=OAuthServer::open(config.clone()).unwrap();
        let (legacy_access, _)=issue_access(&mut legacy,&root.0,"legacy");
        drop(legacy);
        let mut oauth=OAuthServer::open_with_capability(config,identity()).unwrap();
        let (unified_access, unified_client_id)=issue_access(&mut oauth,&root.0,"unified");
        let legacy_router = fixture_router(false);
        let app=Gateway { oauth:Arc::new(Mutex::new(oauth)),
            legacy_catalogue_sha256: router_catalogue_digest(&legacy_router).unwrap(),
            router:Arc::new(legacy_router),
            request_audit: Arc::new(RequestAudit::new().unwrap()),
            unified:Some(Arc::new(UnifiedRoute {catalogue:crate::catalogue_selection::CatalogueSelection::Unified,identity:identity(),router:Arc::new(fixture_router(true)),
                extension_guard:None,manifest_guard:Arc::new(||Ok(())),
                response_permits:Arc::new(Semaphore::new(2))})),
            audience:Audience::Workstation,expected_resource:Some(format!("{ORIGIN}/mcp")),
            public_host:"router-capability.example.invalid".into(),loopback_host:"127.0.0.1:18856".into(),
            requests:Arc::new(Semaphore::new(32)),effects:OperationAdmission::default(),extension_guard:None };
        Self{app,_root:root,legacy_access,unified_access,unified_client_id}
    }
}
async fn mcp(app:Gateway,access:&str,frame:Value)->(u16,Value) {
    let request=Request::builder().method("POST").uri("/mcp")
        .header("host","127.0.0.1:18856").header("authorization",format!("Bearer {access}"))
        .header("content-type","application/json").body(Body::from(frame.to_string())).unwrap();
    let response=handle(State(app),request).await;
    let status=response.status().as_u16();
    let bytes=to_bytes(response.into_body(),50*1024*1024).await.unwrap();
    (status,serde_json::from_slice(&bytes).unwrap_or_else(|_|json!({"transport_error":true})))
}
fn list()->Value{json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})}
fn call(name:&str,arguments:Value)->Value {
    json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":arguments}})
}

fn assert_audit_refusal(app: &Gateway, count: usize, status: Option<u16>, code: &str) -> Value {
    let snapshot = serde_json::to_value(app.request_audit.snapshot()).unwrap();
    assert_eq!(snapshot["in_flight"], 0);
    let records = snapshot["records"].as_array().unwrap();
    assert_eq!(records.len(), count);
    let record = &records[count - 1];
    assert_eq!(record["sequence"], count);
    assert_eq!(record["outcome"], "http_refusal");
    assert_eq!(record["http_status"], json!(status));
    assert_eq!(record["error_code"], code);
    record.clone()
}

#[tokio::test]
async fn request_audit_records_admission_header_and_body_refusals_once() {
    let fixture = Fixture::new();
    let app = &fixture.app;
    let request = || Request::builder().method("POST").uri("/mcp")
        .header("host", "127.0.0.1:18856");

    let permits = app.requests.try_acquire_many(32).unwrap();
    let response = handle(State(app.clone()), request().body(Body::empty()).unwrap()).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_audit_refusal(app, 1, Some(503), "request_capacity_busy");
    drop(permits);

    let malformed = request().header("authorization", "Bearer first")
        .header("authorization", "Bearer second").body(Body::empty()).unwrap();
    let response = handle(State(app.clone()), malformed).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_audit_refusal(app, 2, Some(400), "invalid_http_headers");

    let oversized = request().body(Body::from(vec![b'x'; 1024 * 1024 + 1])).unwrap();
    let response = handle(State(app.clone()), oversized).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_audit_refusal(app, 3, Some(413), "invalid_or_oversized_body");

    app.effects.close();
    let response = handle(State(app.clone()), request().body(Body::empty()).unwrap()).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_audit_refusal(app, 4, Some(503), "workstation_stopping");
}

#[tokio::test]
async fn request_audit_records_worker_panic_with_returned_status_once() {
    let mut fixture = Fixture::new();
    Arc::get_mut(fixture.app.unified.as_mut().unwrap()).unwrap().manifest_guard =
        Arc::new(|| panic!("synthetic MCP worker panic"));

    assert_eq!(mcp(fixture.app.clone(), &fixture.unified_access, list()).await.0, 500);
    let record = assert_audit_refusal(&fixture.app, 1, Some(500), "request_interrupted");
    assert_eq!(record["method"], "tools/list");
    assert_eq!(record["provider"], "gemini");
}

#[tokio::test]
async fn request_audit_records_cancellation_while_worker_is_running_once() {
    let mut fixture = Fixture::new();
    let entered = Arc::new(tokio::sync::Notify::new());
    let (release, wait) = std::sync::mpsc::channel();
    let wait = Mutex::new(wait);
    let worker_entered = Arc::clone(&entered);
    Arc::get_mut(fixture.app.unified.as_mut().unwrap()).unwrap().manifest_guard = Arc::new(move || {
        worker_entered.notify_one();
        wait.lock().unwrap().recv_timeout(Duration::from_secs(10)).unwrap();
        Ok(())
    });
    let app = fixture.app.clone();
    let token = fixture.unified_access.clone();
    let task = tokio::spawn(async move { mcp(app, &token, list()).await });
    tokio::time::timeout(Duration::from_secs(5), entered.notified()).await.unwrap();
    let snapshot = serde_json::to_value(fixture.app.request_audit.snapshot()).unwrap();
    assert_eq!(snapshot["in_flight"], 1);
    assert_eq!(snapshot["records"], json!([]));

    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let record = assert_audit_refusal(&fixture.app, 1, None, "request_interrupted");
    assert_eq!(record["method"], "tools/list");
    assert_eq!(record["provider"], "gemini");
    assert_eq!(fixture.app.requests.available_permits(), 31, "worker retains its admission");

    release.send(()).unwrap();
    let _drained = tokio::time::timeout(Duration::from_secs(5), fixture.app.requests.acquire_many(32))
        .await.unwrap().unwrap();
    assert_audit_refusal(&fixture.app, 1, None, "request_interrupted");
}

#[tokio::test]
async fn request_audit_correlates_status_with_discovery_and_verified_oauth_identity() {
    let mut fixture = Fixture::new();
    let db_path = fixture._root.0.join("audit-missions.sqlite");
    drop(agent_bridge_core::CoreDatabase::initialize_new(&db_path).unwrap());
    let router = runtime::missions(&db_path).unwrap();
    fixture.app.legacy_catalogue_sha256 = router_catalogue_digest(&router).unwrap();
    fixture.app.router = Arc::new(router);
    // Reopen in Legacy mode so both providers use the catalogue under test.
    // A fresh owner also clears the fixture's registration throttle.
    drop(fixture.app.oauth);
    fixture.app.oauth = Arc::new(Mutex::new(OAuthServer::open(
        OAuthConfig { state_dir: fixture._root.0.clone(), public_origin: ORIGIN.into(),
            audience: Audience::Workstation },
    ).unwrap()));
    let (chatgpt_access, gemini_id, chatgpt_id) = {
        let mut oauth = fixture.app.oauth.lock().unwrap();
        let (chatgpt_access, chatgpt_id) = issue_provider_access(
            &mut oauth, &fixture._root.0, "chatgpt",
            "https://chatgpt.com/connector_platform_oauth_redirect",
        );
        let client = |token| oauth.authorize_mcp(Some(&format!("Bearer {token}"))).unwrap().client_id;
        let gemini_id = client(&fixture.legacy_access);
        (chatgpt_access, gemini_id, chatgpt_id)
    };
    let initialize = json!({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion":"2025-11-25","capabilities":{}}});
    assert_eq!(mcp(fixture.app.clone(), &fixture.legacy_access, initialize).await.0, 200);
    let (status, listing) = mcp(fixture.app.clone(), &fixture.legacy_access, list()).await;
    assert_eq!(status, 200);
    let definitions: Vec<ToolDefinition> = serde_json::from_value(listing["result"]["tools"].clone()).unwrap();
    let digest = crate::capability_manifest::catalogue_digest(&definitions).unwrap();
    for token in [&fixture.legacy_access, &chatgpt_access] {
        let (status, response) = mcp(fixture.app.clone(), token, call("agent_bridge_status", json!({}))).await;
        assert_eq!(status, 200);
        assert_ne!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"].as_str()
            .unwrap_or_else(|| panic!("expected status text: {response}"));
        let report: Value = serde_json::from_str(text).unwrap();
        assert_eq!(report["ok"], true);
    }
    let snapshot = serde_json::to_value(fixture.app.request_audit.snapshot()).unwrap();
    let records = snapshot["records"].as_array().unwrap();
    assert_eq!(records.len(), 4);
    let gemini_hash: String = Sha256::digest(gemini_id.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    let chatgpt_hash: String = Sha256::digest(chatgpt_id.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    for (index, (record, method)) in records.iter().zip(["initialize", "tools/list", "tools/call", "tools/call"]).enumerate() {
        assert_eq!(record["sequence"], index + 1);
        assert!(record["timestamp_unix_ms"].as_u64().unwrap() > 0);
        assert!(record["duration_ms"].is_u64());
        assert_eq!(record["boot_id"], snapshot["boot_id"]);
        assert_eq!(record["method"], method);
        assert_eq!(record["outcome"], "success");
        assert_eq!(record["http_status"], 200);
        assert_eq!(record["error_code"], Value::Null);
        assert_eq!(record["catalogue_sha256"], digest);
        if index == 3 {
            assert_eq!(record["provider"], "chatgpt");
            assert_eq!(record["client_id_sha256"], chatgpt_hash);
        } else {
            assert_eq!(record["provider"], "gemini");
            assert_eq!(record["client_id_sha256"], gemini_hash);
        }
    }
    assert_eq!(records[2]["tool_name"], "agent_bridge_status");
    let serialized = snapshot.to_string();
    for private in [&fixture.legacy_access, &chatgpt_access, &gemini_id, &chatgpt_id] {
        assert!(!serialized.contains(private.as_str()));
    }

    let sessions = fixture.app.request_audit.sessions.snapshot(
        &fixture.app.request_audit.boot_id, None, None,
    ).unwrap();
    assert_eq!(sessions["totals"], json!({"live": 2, "connected": 2}));
    for (provider, hash, count) in [("gemini", &gemini_hash, 3), ("chatgpt", &chatgpt_hash, 1)] {
        let session = sessions["sessions"].as_array().unwrap().iter()
            .find(|session| session["provider"] == provider).unwrap();
        assert_eq!(session["client_label"], &hash[..8]);
        assert_eq!(session["request_count"], count);
        assert_eq!(session["transport"], "http");
        assert_eq!(session["tool_calls"][0]["tool_name"], "agent_bridge_status");
        let session_id = session["session_id"].as_str().unwrap();
        assert!(crate::audit_history::is_valid_session_id(session_id));
        if provider == "gemini" {
            for record in &records[..3] {
                assert_eq!(record["session_id"], session_id);
            }
        } else {
            assert_eq!(records[3]["session_id"], session_id);
        }
    }
    assert_ne!(records[0]["session_id"], records[3]["session_id"]);
    let serialized = sessions.to_string();
    for private in [&fixture.legacy_access, &chatgpt_access, &gemini_id, &chatgpt_id, &gemini_hash, &chatgpt_hash] {
        assert!(!serialized.contains(private.as_str()));
    }
}

#[tokio::test]
async fn connected_sessions_ignores_unverified_and_refused_requests() {
    let fixture = Fixture::new();
    let status = call("agent_bridge_status", json!({}));
    assert_eq!(mcp(fixture.app.clone(), "example-invalid-token", status).await.0, 401);
    let (status, response) = mcp(
        fixture.app.clone(), &fixture.legacy_access, call("example-unknown-tool", json!({})),
    ).await;
    assert_eq!(status, 200);
    assert_eq!(response["error"]["code"], -32602);
    let audit = &fixture.app.request_audit;
    assert_eq!(audit.sessions.snapshot(&audit.boot_id, None, None).unwrap()["sessions"], json!([]));
}

#[test]
fn connected_sessions_joins_only_resolved_contexts_and_redacted_mission_fields() {
    use crate::client_sessions::{Client, ClientSessions};
    let root = TestRoot(crate::test_state_base().join(format!(
        "session-missions-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
    )));
    std::fs::create_dir_all(&root.0).unwrap();
    let path = root.0.join("missions.sqlite");
    let mut db = agent_bridge_core::CoreDatabase::initialize_new(&path).unwrap();
    let earlier = agent_bridge_missions::create_context(db.connection_mut()).unwrap();
    agent_bridge_missions::dispatch_tool(db.connection_mut(), "agent_bridge_mission_create", &json!({
        "actor_context_handle":earlier.context_handle, "goal":"Example earlier mission",
        "idempotency_key":"example-earlier-key",
    })).unwrap();
    drop(db);
    let router = runtime::missions(&path).unwrap();
    let registry = ClientSessions::default();
    let refused = call("example-unknown-tool", json!({})).to_string();
    let response = registry.dispatch(Client::Local("http"), &router, &refused, usize::MAX,
        || router.handle_str(&refused)).unwrap();
    assert_eq!(serde_json::from_str::<Value>(&response).unwrap()["error"]["code"], -32602);
    assert_eq!(registry.snapshot("example-boot", None, None).unwrap()["sessions"], json!([]));
    let invoke = |name, args| -> Value {
        let frame = call(name, args).to_string();
        let result = registry.dispatch(Client::Local("http"), &router, &frame, usize::MAX,
            || router.handle_str(&frame)).unwrap();
        let response: Value = serde_json::from_str(&result).unwrap();
        assert_ne!(response["result"]["isError"], true, "{response}");
        serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
    };
    let context = invoke("agent_bridge_context_create", json!({}));
    let goal = "é".repeat(205);
    let mission = invoke("agent_bridge_mission_create", json!({
        "goal":goal, "actor_context_handle":context["context_handle"], "idempotency_key":"example-mission-key",
    }));
    let subtask = invoke("agent_bridge_mission_subtask_create", json!({
        "goal":"Example subtask", "actor_context_handle":context["context_handle"],
        "mission_id":mission["mission_id"], "assignee_context_id":context["context_id"],
        "idempotency_key":"example-subtask-key",
    }));
    drop(router);
    let db = Arc::new(Mutex::new(agent_bridge_core::CoreDatabase::open_existing(&path).unwrap()));
    let snapshot = registry.snapshot("example-boot", Some(&db), None).unwrap();
    let joined = &snapshot["sessions"][0]["contexts"][0];
    assert_eq!(joined["context_id"], context["context_id"]);
    assert_eq!(joined["missions"][0]["mission_id"], mission["mission_id"]);
    assert_eq!(joined["missions"][0]["goal"].as_str().unwrap().chars().count(), 200);
    assert_eq!(joined["missions"][0]["subtasks"][0], json!({
        "id":subtask["subtask"]["subtask_id"], "title":"Example subtask", "status":"pending",
        "assigned_to_context":true,
    }));
    assert_eq!(snapshot["earlier"].as_array().unwrap().len(), 1);
    assert_eq!(snapshot["earlier"][0]["context_id"], earlier.context_id);
    assert_eq!(snapshot["earlier"][0]["missions"][0]["goal"], "Example earlier mission");
    let text = snapshot.to_string();
    for private in [context["context_handle"].as_str().unwrap(), "example-mission-key", "example-subtask-key"] {
        assert!(!text.contains(private));
    }
}

#[tokio::test]
async fn request_audit_records_early_oauth_protocol_and_tool_refusals_without_payloads() {
    let mut fixture = Fixture::new();
    let mut handlers = ToolMapHandler::new();
    handlers.register("agent_bridge_status", |_| {
        Ok(ToolCallResult::tool_error("private-result-marker"))
    });
    fixture.app.router = Arc::new(McpGateway::new(GatewayConfig::new("audit", "1"),
        vec![ToolDefinition::new("agent_bridge_status", None, json!({"type":"object"}))], handlers));
    let frame = call("agent_bridge_status", json!({"marker":"private-argument-marker"}));
    let (status, response) = mcp(fixture.app.clone(), &fixture.legacy_access, frame.clone()).await;
    assert_eq!(status, 200);
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(response["result"]["content"][0]["text"], "private-result-marker");
    assert_eq!(mcp(fixture.app.clone(), "invalid-token-marker", frame.clone()).await.0, 401);
    let unknown = call("private-tool-marker", json!({}));
    let (status, response) = mcp(fixture.app.clone(), &fixture.legacy_access, unknown).await;
    assert_eq!(status, 200);
    assert_eq!(response["error"]["code"], -32602);
    let (status, response) = mcp(fixture.app.clone(), &fixture.legacy_access,
        json!({"jsonrpc":"2.0","id":1,"method":"private-method-marker"})).await;
    assert_eq!(status, 200);
    assert_eq!(response["error"]["code"], -32601);

    let early = Request::builder().method("POST").uri("/mcp")
        .header("host", "untrusted.example.invalid").body(Body::empty()).unwrap();
    assert_eq!(handle(State(fixture.app.clone()), early).await.status(), 403);
    let metadata = Request::builder().uri("/health")
        .header("host", "127.0.0.1:18856").body(Body::empty()).unwrap();
    assert_eq!(handle(State(fixture.app.clone()), metadata).await.status(), 200);

    // Fill the private budget, which already includes the token exchange and MCP calls.
    // Health probes exercise the same limiter without adding MCP audit records.
    {
        let mut oauth = fixture.app.oauth.lock().unwrap();
        let authorization = format!("Bearer {}", fixture.legacy_access);
        for _ in 0..1000 {
            let HttpAction::Reply(reply) = oauth.handle_http(HttpRequest {
                method: "GET", target: "/health", authorization: Some(&authorization),
                origin: None, content_type: None, body: b"",
            }) else { panic!("health cannot dispatch MCP") };
            if reply.status == 429 {
                let response: Value = serde_json::from_slice(&reply.body).unwrap();
                assert_eq!(response["error"], "request_limit");
                break;
            }
            assert_eq!(reply.status, 200);
        }
    }
    let (status, response) = mcp(fixture.app.clone(), &fixture.legacy_access, frame).await;
    assert_eq!(status, 429);
    assert_eq!(response["error"], "request_limit");

    let snapshot = serde_json::to_value(fixture.app.request_audit.snapshot()).unwrap();
    let records = snapshot["records"].as_array().unwrap();
    assert_eq!(records.len(), 6);
    assert_eq!(records[0]["outcome"], "tool_error");
    assert_eq!(records[0]["http_status"], 200);
    assert_eq!(records[0]["tool_name"], "agent_bridge_status");
    assert_eq!(records[1]["outcome"], "http_refusal");
    assert_eq!(records[1]["error_code"], "invalid_token");
    assert_eq!(records[1]["provider"], Value::Null);
    assert_eq!(records[1]["client_id_sha256"], Value::Null);
    assert_eq!(records[1]["catalogue_sha256"], Value::Null);
    assert_eq!(records[2]["outcome"], "jsonrpc_error");
    assert_eq!(records[2]["error_code"], -32602);
    assert_eq!(records[2]["tool_name"], "other");
    assert_eq!(records[3]["method"], "other");
    assert_eq!(records[4]["error_code"], "host_refused");
    assert_eq!(records[4]["provider"], Value::Null);
    assert_eq!(records[5]["outcome"], "http_refusal");
    assert_eq!(records[5]["error_code"], "request_limit");
    assert_eq!(records[5]["http_status"], 429);
    assert_eq!(records[5]["provider"], "gemini");
    assert_eq!(records[5]["client_id_sha256"], records[0]["client_id_sha256"]);
    assert!(!snapshot.to_string().contains("private-"));
    assert!(!snapshot.to_string().contains("invalid-token-marker"));
}

#[tokio::test]
async fn request_audit_records_oauth_endpoint_outcomes_without_credentials() {
    let base = crate::test_state_base();
    let root = TestRoot(base.join(format!("oauth-audit-{}-{}", std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed))));
    agent_bridge_lifecycle::initialize_operator_settings(&root.0).unwrap();
    for entry in std::fs::read_dir(&root.0).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() { std::fs::remove_file(path).unwrap(); }
    }
    let config = OAuthConfig { state_dir: root.0.clone(), public_origin: ORIGIN.into(),
        audience: Audience::Workstation };
    let oauth = OAuthServer::open(config.clone()).unwrap();
    let owner = LocalOwner::open(config).unwrap();
    owner.enable_enrollment(|| true).unwrap();
    let router = fixture_router(false);
    let app = Gateway {
        oauth: Arc::new(Mutex::new(oauth)),
        legacy_catalogue_sha256: router_catalogue_digest(&router).unwrap(),
        router: Arc::new(router),
        request_audit: Arc::new(RequestAudit::new().unwrap()),
        unified: None,
        audience: Audience::Workstation,
        expected_resource: Some(format!("{ORIGIN}/mcp")),
        public_host: "router-capability.example.invalid".into(),
        loopback_host: "127.0.0.1:18856".into(),
        requests: Arc::new(Semaphore::new(32)),
        effects: OperationAdmission::default(),
        extension_guard: None,
    };
    async fn send(app: &Gateway, method: &str, target: &str, ct: &str, body: &str) -> Response {
        let request = Request::builder().method(method).uri(target)
            .header("host", "127.0.0.1:18856").header("content-type", ct)
            .body(Body::from(body.to_owned())).unwrap();
        handle(State(app.clone()), request).await
    }
    assert_eq!(send(&app, "POST", "/oauth/register?marker=private-query", "text/plain",
        r#"{"method":"tools/call","params":{"name":"agent_bridge_status","marker":"private-body"}}"#)
        .await.status(), 415);
    let registration = json!({"redirect_uris":[CALLBACK],
        "token_endpoint_auth_method":"client_secret_post","client_name":"private-registration"});
    let registered = send(&app, "POST", "/oauth/register", "application/json", &registration.to_string()).await;
    assert_eq!(registered.status(), 201);
    let client: Value = serde_json::from_slice(&to_bytes(registered.into_body(), 65536).await.unwrap()).unwrap();
    let id = client["client_id"].as_str().unwrap();
    let secret = client["client_secret"].as_str().unwrap();
    assert_eq!(send(&app, "GET", "/oauth/authorize?client_id=private-invalid-client", "text/plain", "")
        .await.status(), 400);
    let verifier = "V".repeat(43);
    let challenge = b64url(&Sha256::digest(verifier.as_bytes()));
    let target = format!("/oauth/authorize?response_type=code&client_id={id}&redirect_uri={CALLBACK}&code_challenge_method=S256&code_challenge={challenge}&state=private-state");
    assert_eq!(send(&app, "GET", &target, "text/plain", "").await.status(), 200);
    let pending = owner.pending_requests().unwrap().into_iter()
        .find(|request| request.client_id == id).unwrap();
    owner.approve_request(&pending.id, |_| true).unwrap();
    let approved = send(&app, "GET", &target, "text/plain", "").await;
    assert_eq!(approved.status(), 302);
    let code = approved.headers().get("location").unwrap().to_str().unwrap()
        .split_once('?').unwrap().1.split('&')
        .find_map(|part| part.strip_prefix("code=")).unwrap();
    let form = format!("grant_type=authorization_code&client_id={id}&client_secret={secret}&redirect_uri={CALLBACK}&code={code}&code_verifier={verifier}");
    let ct = "application/x-www-form-urlencoded";
    assert_eq!(send(&app, "POST", "/oauth/token", ct,
        &format!("client_id={id}&client_secret=private-wrong-secret")).await.status(), 401);
    assert_eq!(send(&app, "POST", "/oauth/token", ct,
        &format!("grant_type=refresh_token&client_id={id}&client_secret={secret}&refresh_token=private-invalid-grant")).await.status(), 400);
    let issued = send(&app, "POST", "/oauth/token", ct, &form).await;
    assert_eq!(issued.status(), 200);
    let tokens: Value = serde_json::from_slice(&to_bytes(issued.into_body(), 65536).await.unwrap()).unwrap();
    let access = tokens["access_token"].as_str().unwrap();
    let refresh = tokens["refresh_token"].as_str().unwrap();
    assert_eq!(send(&app, "POST", "/oauth/revoke", ct,
        &format!("client_id={id}&client_secret=private-wrong-secret&token={access}")).await.status(), 401);
    assert_eq!(send(&app, "POST", "/oauth/revoke", ct,
        &format!("client_id={id}&client_secret={secret}&token={access}")).await.status(), 200);
    assert_eq!(mcp(app.clone(), access, list()).await.0, 401);

    let snapshot = serde_json::to_value(app.request_audit.snapshot()).unwrap();
    let records = snapshot["records"].as_array().unwrap();
    let expected = [
        ("oauth/register", 415, "http_refusal", Some("unsupported_content_type"), false),
        ("oauth/register", 201, "success", None, false),
        ("oauth/authorize", 400, "http_refusal", Some("invalid_client_or_redirect"), false),
        ("oauth/authorize", 200, "success", None, false),
        ("oauth/authorize", 302, "success", None, false),
        ("oauth/token", 401, "http_refusal", Some("invalid_client"), false),
        ("oauth/token", 400, "http_refusal", Some("invalid_grant"), true),
        ("oauth/token", 200, "success", None, true),
        ("oauth/revoke", 401, "http_refusal", Some("invalid_client"), false),
        ("oauth/revoke", 200, "success", None, true),
        ("tools/list", 401, "http_refusal", Some("invalid_token"), false),
    ];
    assert_eq!(records.len(), expected.len());
    let digest = hex::encode(Sha256::digest(id.as_bytes()));
    for (index, (record, (method, status, outcome, error, verified))) in
        records.iter().zip(expected).enumerate()
    {
        assert_eq!(record["sequence"], json!(index + 1));
        assert_eq!(record["method"], method);
        assert_eq!(record["http_status"], status);
        assert_eq!(record["outcome"], outcome);
        assert_eq!(record["error_code"], json!(error));
        assert_eq!(record["provider"], if verified { json!("gemini") } else { Value::Null });
        assert_eq!(record["client_id_sha256"], if verified { json!(digest) } else { Value::Null });
        assert!(record["catalogue_sha256"].is_null());
        assert!(record["tool_name"].is_null());
        assert!(record["timestamp_unix_ms"].as_u64().is_some());
        assert!(record["duration_ms"].as_u64().is_some());
    }
    assert_eq!(snapshot["in_flight"], 0);
    let encoded = snapshot.to_string();
    for secret_value in [id, secret, code, &verifier, &challenge, access, refresh, CALLBACK, "private-"] {
        assert!(!encoded.contains(secret_value));
    }
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn capability_route_selects_whole_catalogue_schema_and_dispatch_for_each_grant() {
    let fixture=Fixture::new();
    let (status,legacy)=mcp(fixture.app.clone(),&fixture.legacy_access,list()).await;
    assert_eq!(status,200);
    assert_eq!(legacy["result"]["tools"].as_array().unwrap().len(),1);
    let (status,unified)=mcp(fixture.app.clone(),&fixture.unified_access,list()).await;
    assert_eq!(status,200);
    assert_eq!(unified["result"]["tools"].as_array().unwrap().len(),2,
        "unified grant must see its actual router's catalogue");
    assert!(legacy["result"]["tools"][0]["inputSchema"]["properties"].get("legacy_arg").is_some());
    assert!(unified["result"]["tools"].as_array().unwrap().iter()
        .find(|tool|tool["name"]=="shared_contract").unwrap()["inputSchema"]["properties"]
        .get("unified_arg").is_some());
    for (access,args,label) in [
        (&fixture.legacy_access,json!({"legacy_arg":true}),"legacy"),
        (&fixture.unified_access,json!({"unified_arg":true}),"unified"),
    ] {
        let (status,reply)=mcp(fixture.app.clone(),access,call("shared_contract",args)).await;
        assert_eq!(status,200);
        assert_eq!(reply["result"]["content"][0]["text"],label);
    }
    for (access,args) in [
        (&fixture.legacy_access,json!({"unified_arg":true})),
        (&fixture.unified_access,json!({"legacy_arg":true})),
    ] {
        let (_,reply)=mcp(fixture.app.clone(),access,call("shared_contract",args)).await;
        assert!(reply.get("error").is_some(),"same-name tools must retain their own schema validator");
    }
    let (_,reply)=mcp(fixture.app.clone(),&fixture.legacy_access,call("unified_only",json!({}))).await;
    assert!(reply.get("error").is_some(),"direct tools/call cannot cross catalogues");
}

#[tokio::test]
async fn specialized_catalogue_http_refuses_legacy_grant_and_excluded_direct_calls() {
    use crate::catalogue_selection::CatalogueSelection;
    let Fixture{mut app,_root,legacy_access,unified_access,..}=Fixture::new();
    let selected=CatalogueSelection::Extensions;
    let mut handlers=ToolMapHandler::new();
    for name in ["agent_bridge_status","desktop_mcp_tool_search","desktop_start_process"] {
        handlers.register(name,move |_|Ok(ToolCallResult::text(name)));
    }
    let mut definitions=["agent_bridge_status","desktop_mcp_tool_search","desktop_start_process"]
        .into_iter().map(|name|ToolDefinition::new(name,None,json!({"type":"object"}))).collect::<Vec<_>>();
    selected.restrict(&mut definitions,&mut handlers);
    let digest=crate::capability_manifest::catalogue_digest(&definitions).unwrap();
    let router=McpGateway::new(selected.configure(GatewayConfig::new("fixture","1"),&digest),
        definitions,handlers);
    // Issue two real synthetic grants for the exact selected manifest.
    // Deliberately retain earlier legacy/full tokens to test defense in
    // depth beyond the separate startup-marker refusal.
    let mut manifest=json!({"policy_version":1,"catalogue_sha256":digest,"catalogue":"extensions"});
    manifest.sort_all_objects();
    let capability=CapabilityIdentity::UnifiedV1{
        manifest_sha256:crate::capability_manifest::canonical_digest(&manifest).unwrap(),
        catalogue_sha256:digest,policy_version:1,
    };
    drop(app.oauth);
    let mut oauth=OAuthServer::open_with_capability(OAuthConfig{
        state_dir:_root.0.clone(),public_origin:ORIGIN.into(),audience:Audience::Workstation,
    },capability.clone()).unwrap();
    oauth.bind_capability_manifest(&serde_json::to_vec(&manifest).unwrap()).unwrap();
    let (gemini_access,_)=issue_access(&mut oauth,&_root.0,"narrow-gemini");
    // The running OAuth server spaces registrations by one second.
    tokio::time::sleep(std::time::Duration::from_millis(1001)).await;
    let (chatgpt_access,_)=issue_provider_access(&mut oauth,&_root.0,"narrow-chatgpt",
        "https://chatgpt.com/connector_platform_oauth_redirect");
    app.oauth=Arc::new(Mutex::new(oauth));
    app.unified=Some(Arc::new(UnifiedRoute{
        catalogue:selected,identity:capability,router:Arc::new(router),
        extension_guard:None,manifest_guard:Arc::new(||Ok(())),
        response_permits:Arc::new(Semaphore::new(2)),
    }));
    assert_eq!(mcp(app.clone(),&legacy_access,list()).await.0,401);
    assert_eq!(mcp(app.clone(),&unified_access,list()).await.0,401);
    for access in [&gemini_access,&chatgpt_access] {
        let (status,listed)=mcp(app.clone(),access,list()).await;
        assert_eq!(status,200);
        assert_eq!(listed["result"]["tools"].as_array().unwrap().len(),2);
        let (_,denied)=mcp(app.clone(),access,call("desktop_start_process",json!({}))).await;
        assert_eq!(denied["error"]["code"],-32602);
        let (_,allowed)=mcp(app.clone(),access,call("desktop_mcp_tool_search",json!({}))).await;
        assert_eq!(allowed["result"]["content"][0]["text"],"desktop_mcp_tool_search");
        let (status,modern_list)=mcp_modern(app.clone(),Some(access),
            modern("tools/list",json!({}),"2026-07-28"),
            &[("mcp-protocol-version","2026-07-28"),("mcp-method","tools/list")]).await;
        assert_eq!(status,200);
        assert_eq!(modern_list["result"]["cacheScope"],"private");
        assert_eq!(modern_list["result"]["tools"].as_array().unwrap().len(),2);
    }
}

#[tokio::test]
async fn capability_route_refuses_exact_manifest_drift() {
    let mut fixture=Fixture::new();
    fixture.app.unified=Some(Arc::new(UnifiedRoute {catalogue:crate::catalogue_selection::CatalogueSelection::Unified,identity:identity(),
        router:Arc::new(fixture_router(true)),extension_guard:None,
        manifest_guard:Arc::new(||Err("synthetic manifest drift".into())),
        response_permits:Arc::new(Semaphore::new(2))}));
    assert_eq!(mcp(fixture.app.clone(),&fixture.unified_access,list()).await.0,403);
    assert_eq!(mcp(fixture.app.clone(),&fixture.legacy_access,list()).await.0,200);
}

#[tokio::test]
async fn capability_fix_http_uses_selected_commands_after_successful_hash_check() {
    use crate::command_catalogue::CommandCatalogueSnapshot;
    use crate::session_profile::ProfileControl;
    use agent_bridge_core::CoreDatabase;
    use agent_bridge_desktop::DesktopProfile;
    let mut fixture=Fixture::new();
    let settings=fixture._root.0.join("commands-settings");
    let project=fixture._root.0.join("project");
    agent_bridge_lifecycle::initialize_operator_settings(&settings).unwrap();
    std::fs::create_dir(&project).unwrap();
    let original=json!({"version":1,"programs":{"sealed-command":{}}});
    let replacement=json!({"version":1,"programs":{"replacement-command":{}}});
    std::fs::write(settings.join("commands.json"),original.to_string()).unwrap();
    let selected=Arc::new(CommandCatalogueSnapshot::load(&settings).unwrap());
    let selected_digest=selected.digest().unwrap().to_owned();
    let database=Arc::new(Mutex::new(CoreDatabase::initialize_new(
        fixture._root.0.join("commands-core.sqlite")).unwrap()));
    let mut catalogue=Vec::new();let mut handlers=ToolMapHandler::new();
    crate::unified_core::attach(database,&std::fs::canonicalize(&project).unwrap(),selected,
        ProfileControl::new(DesktopProfile::FullControl),false,false,&mut catalogue,&mut handlers).unwrap();
    let checked=Arc::new(AtomicBool::new(false));
    let observed=Arc::clone(&checked);
    fixture.app.unified=Some(Arc::new(UnifiedRoute {catalogue:crate::catalogue_selection::CatalogueSelection::Unified,identity:identity(),
        router:Arc::new(McpGateway::new(GatewayConfig::new("bound-commands","1"),catalogue,handlers)),
        extension_guard:None,response_permits:Arc::new(Semaphore::new(2)),
        manifest_guard:Arc::new(move || {
            // The real command snapshot hash is valid, then the local file
            // changes at the exact HTTP validation/dispatch boundary.
            if CommandCatalogueSnapshot::load(&settings)?.digest()!=Some(selected_digest.as_str()) {
                return Err("synthetic authority changed before validation".into());
            }
            std::fs::write(settings.join("commands.json"),replacement.to_string())?;
            observed.store(true,Ordering::Release);
            Ok(())
        })}));
    let (status,response)=mcp(fixture.app.clone(),&fixture.unified_access,
        call("desktop_list_allowed_commands",json!({}))).await;
    assert!(checked.load(Ordering::Acquire));
    assert_eq!(status,200,"{response}");
    let output:Value=serde_json::from_str(
        response["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(output["commands"],json!(["sealed-command"]));
}

#[tokio::test]
async fn capability_route_keeps_legacy_response_limit_and_bounded_unified_budget() {
    let fixture=Fixture::new();
    assert_eq!(mcp(fixture.app.clone(),&fixture.legacy_access,
        call("shared_contract",json!({"legacy_arg":true,"large":true}))).await.0,500);
    let (status,reply)=mcp(fixture.app.clone(),&fixture.unified_access,
        call("shared_contract",json!({"unified_arg":true,"large":true}))).await;
    assert_eq!(status,200);
    assert!(reply["result"]["content"][0]["text"].as_str().unwrap().len()>1024*1024);
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn capability_route_slow_handler_releases_global_oauth_mutex() {
    let mut fixture=Fixture::new();
    let entered=Arc::new(tokio::sync::Notify::new());
    let release=Arc::new(AtomicBool::new(false));
    let enter=Arc::clone(&entered);let released=Arc::clone(&release);
    let mut handlers=ToolMapHandler::new();
    handlers.register("slow",move |_|{
        enter.notify_one();
        let deadline=std::time::Instant::now()+Duration::from_secs(3);
        while !released.load(Ordering::Acquire) && std::time::Instant::now()<deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(ToolCallResult::text("completed"))
    });
    fixture.app.router=Arc::new(McpGateway::new(GatewayConfig::new("slow-fixture","1"),
        vec![ToolDefinition::new("slow",None,json!({"type":"object","properties":{},"additionalProperties":false}))],handlers));
    let app=fixture.app.clone();let token=fixture.legacy_access.clone();
    let slow=tokio::spawn(async move {mcp(app,&token,call("slow",json!({}))).await});
    tokio::time::timeout(Duration::from_secs(2),entered.notified()).await.unwrap();
    let metadata=Request::builder().method("GET").uri("/.well-known/oauth-authorization-server")
        .header("host","127.0.0.1:18856").body(Body::empty()).unwrap();
    let result=tokio::time::timeout(Duration::from_millis(400),handle(State(fixture.app.clone()),metadata)).await;
    release.store(true,Ordering::Release);
    assert_eq!(slow.await.unwrap().0,200);
    assert!(result.is_ok(),"slow MCP handler must not lock unrelated OAuth operations");
    assert_eq!(result.unwrap().status(),StatusCode::OK);
}

#[tokio::test]
async fn capability_response_budget_stays_owned_until_body_is_consumed_or_dropped() {
    let fixture=Fixture::new();
    let request=|| Request::builder().method("POST").uri("/mcp")
        .header("host","127.0.0.1:18856")
        .header("authorization",format!("Bearer {}",fixture.unified_access))
        .header("content-type","application/json").body(Body::from(
            call("shared_contract",json!({"unified_arg":true,"large":true})).to_string())).unwrap();
    let first=handle(State(fixture.app.clone()),request()).await;
    let second=handle(State(fixture.app.clone()),request()).await;
    assert_eq!(first.status(),StatusCode::OK);
    assert_eq!(second.status(),StatusCode::OK);
    let third=handle(State(fixture.app.clone()),request()).await;
    assert_eq!(third.status(),StatusCode::SERVICE_UNAVAILABLE,
        "a slow client still owns its allocated response budget");
    drop(first);
    let next=handle(State(fixture.app.clone()),request()).await;
    assert_eq!(next.status(),StatusCode::OK);
    let bytes=to_bytes(second.into_body(),50*1024*1024).await.unwrap();
    let transport_clone=bytes.clone();
    let held_after_eof=handle(State(fixture.app.clone()),request()).await;
    assert_eq!(held_after_eof.status(),StatusCode::SERVICE_UNAVAILABLE,
        "EOF does not release bytes still retained by the transport");
    drop(bytes);
    let held_clone=handle(State(fixture.app.clone()),request()).await;
    assert_eq!(held_clone.status(),StatusCode::SERVICE_UNAVAILABLE);
    drop(transport_clone);
    let after_consumed=handle(State(fixture.app.clone()),request()).await;
    assert_eq!(after_consumed.status(),StatusCode::OK);
}

#[test]
fn capability_unified_preserves_historical_extension_base_but_not_other_scope_drift() {
    let fixture=Fixture::new();
    let current=json!({"schema":2,"purpose":"synthetic exact legacy scope","settings_tools":true,
        "physical_project":{"identity":"original"},"effective_extension_authority":{"servers":["new"]}});
    let mut historical=current.clone();
    historical["effective_extension_authority"]=json!({"servers":["old"]});
    historical["executable_catalog"]=serde_json::to_value(fixture.app.router.published_tools()).unwrap();
    let path=fixture._root.0.join(WORKSTATION_SCOPE_FILE);
    let bytes=serde_json::to_vec(&historical).unwrap();
    std::fs::write(&path,&bytes).unwrap();
    let selected=legacy_base_for_unified(&fixture._root.0,false,&current).unwrap();
    assert_eq!(selected["effective_extension_authority"],json!({"servers":["old"]}));
    assert_eq!(std::fs::read(&path).unwrap(),bytes,"historical marker must not be rewritten");
    let mut drift=current.clone(); drift["physical_project"]["identity"]=json!("replacement");
    assert!(legacy_base_for_unified(&fixture._root.0,false,&drift).is_err());
    std::fs::write(&path,b"{\"schema\":2}").unwrap();
    assert!(legacy_base_for_unified(&fixture._root.0,false,&current).is_err());
    std::fs::remove_file(&path).unwrap();
    assert!(legacy_base_for_unified(&fixture._root.0,false,&current).is_err());
}

#[test]
fn specialized_catalogue_startup_marker_refuses_preset_change_or_legacy_reuse() {
    let fixture=Fixture::new();
    let base=json!({"schema":2,"purpose":"synthetic exact scope","settings_tools":false,
        "effective_extension_authority":null,"catalogue_selection":"core"});
    let sealed=workstation_scope(&base,&fixture.app.router).unwrap();
    let path=fixture._root.0.join(WORKSTATION_SCOPE_FILE);
    std::fs::write(&path,serde_json::to_vec(&sealed).unwrap()).unwrap();
    assert_eq!(legacy_base_for_unified(&fixture._root.0,false,&base).unwrap(),base);
    let mut changed=base.clone();changed["catalogue_selection"]=json!("code");
    assert!(legacy_base_for_unified(&fixture._root.0,false,&changed).is_err());
    changed.as_object_mut().unwrap().remove("catalogue_selection");
    assert!(preflight_workstation_scope(&fixture._root.0,false,&changed).is_err());
    assert!(legacy_base_for_unified(&fixture._root.0,false,&changed).is_err());
}

#[tokio::test]
async fn capability_changed_extension_policy_refuses_old_grant_while_exact_new_view_works() {
    let mut fixture=Fixture::new();
    let settings=fixture._root.0.join("synthetic-extension-settings");
    agent_bridge_lifecycle::initialize_operator_settings(&settings).unwrap();
    let current=runtime::workstation_extension_authority(&settings).unwrap();
    fixture.app.extension_guard=Some(ExtensionGuard{settings:settings.clone(),scope:None,
        authority:json!({"synthetic_historical_authority":"different"})});
    fixture.app.unified=Some(Arc::new(UnifiedRoute {catalogue:crate::catalogue_selection::CatalogueSelection::Unified,
        identity:identity(),router:Arc::new(fixture_router(true)),
        extension_guard:Some(ExtensionGuard{settings,authority:current,scope:None}),
        manifest_guard:Arc::new(||Ok(())),response_permits:Arc::new(Semaphore::new(2)),
    }));
    assert_eq!(mcp(fixture.app.clone(),&fixture.legacy_access,list()).await.0,403);
    let (status,value)=mcp(fixture.app.clone(),&fixture.unified_access,list()).await;
    assert_eq!(status,200);
    assert_eq!(value["result"]["tools"].as_array().unwrap().len(),2);
}

async fn mcp_modern(app:Gateway,access:Option<&str>,frame:Value,headers:&[(&str,&str)])->(u16,Value) {
    let mut request=Request::builder().method("POST").uri("/mcp")
        .header("host","127.0.0.1:18856").header("content-type","application/json");
    if let Some(access)=access { request=request.header("authorization",format!("Bearer {access}")); }
    for (name,value) in headers { request=request.header(*name,*value); }
    let response=handle(State(app),request.body(Body::from(frame.to_string())).unwrap()).await;
    let status=response.status().as_u16();
    let bytes=to_bytes(response.into_body(),50*1024*1024).await.unwrap();
    (status,serde_json::from_slice(&bytes).unwrap_or_else(|_|json!({"transport_error":true})))
}
fn modern(method:&str,mut params:Value,version:&str)->Value {
    params["_meta"]=json!({"io.modelcontextprotocol/protocolVersion":version,
        "io.modelcontextprotocol/clientCapabilities":{}});
    json!({"jsonrpc":"2.0","id":7,"method":method,"params":params})
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn modern_requests_keep_oauth_and_selected_catalogue_and_refuse_mismatched_headers() {
    let fixture=Fixture::new();
    const V:(&str,&str)=("mcp-protocol-version","2026-07-28");
    let modern_list=modern("tools/list",json!({}),"2026-07-28");
    let (status,_)=mcp_modern(fixture.app.clone(),None,modern_list.clone(),&[V,("mcp-method","tools/list")]).await;
    assert_eq!(status,401,"modern metadata never bypasses OAuth");
    let (status,listed)=mcp_modern(fixture.app.clone(),Some(&fixture.unified_access),modern_list,
        &[V,("mcp-method","tools/list")]).await;
    assert_eq!(status,200);
    assert_eq!(listed["result"]["resultType"],"complete");
    assert_eq!(listed["result"]["tools"].as_array().unwrap().len(),2,"modern list keeps the granted catalogue");
    let call=modern("tools/call",json!({"name":"shared_contract","arguments":{"unified_arg":true}}),"2026-07-28");
    let (status,reply)=mcp_modern(fixture.app.clone(),Some(&fixture.unified_access),call.clone(),
        &[V,("mcp-method","tools/call"),("mcp-name","shared_contract")]).await;
    assert_eq!(status,200);
    assert_eq!(reply["result"]["content"][0]["text"],"unified");
    for headers in [vec![V,("mcp-method","tools/call")], vec![V,("mcp-method","tools/call"),("mcp-name","unified_only")],
        vec![("mcp-method","tools/call"),("mcp-name","shared_contract")]] {
        let (status,reply)=mcp_modern(fixture.app.clone(),Some(&fixture.unified_access),call.clone(),&headers).await;
        assert_eq!(status,400);
        assert_eq!(reply["error"]["code"],-32020);
    }
    let (status,reply)=mcp_modern(fixture.app.clone(),Some(&fixture.legacy_access),
        modern("server/discover",json!({}),"2099-01-01"),&[("mcp-protocol-version","2099-01-01"),("mcp-method","server/discover")]).await;
    assert_eq!(status,400);
    assert_eq!(reply["error"]["code"],-32022);
    let (status,reply)=mcp_modern(fixture.app.clone(),Some(&fixture.legacy_access),
        modern("initialize",json!({}),"2026-07-28"),&[V,("mcp-method","initialize")]).await;
    assert_eq!(status,404);
    assert_eq!(reply["error"]["code"],-32601);
    let (status,legacy)=mcp(fixture.app.clone(),&fixture.legacy_access,list()).await;
    assert_eq!(status,200);
    assert!(legacy["result"].get("resultType").is_none(),"legacy responses are unchanged");

    let definitions: Vec<ToolDefinition> = serde_json::from_value(listed["result"]["tools"].clone()).unwrap();
    let digest = crate::capability_manifest::catalogue_digest(&definitions).unwrap();
    let snapshot = serde_json::to_value(fixture.app.request_audit.snapshot()).unwrap();
    let records = snapshot["records"].as_array().unwrap();
    assert_eq!(records.len(), 9);
    assert_eq!(records[0]["provider"], Value::Null);
    let expected_client_hash: String = Sha256::digest(fixture.unified_client_id.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    for record in &records[1..6] {
        assert_eq!(record["provider"], "gemini");
        assert_eq!(record["client_id_sha256"], expected_client_hash);
        assert_eq!(record["catalogue_sha256"], digest);
    }
    assert_eq!(records[1]["method"], "tools/list");
    assert_eq!(records[2]["method"], "tools/call");
    assert_eq!(records[3]["outcome"], "http_refusal");
    assert_eq!(records[3]["error_code"], -32020);
    assert_ne!(records[8]["client_id_sha256"], records[1]["client_id_sha256"]);
    assert_ne!(records[8]["catalogue_sha256"], records[1]["catalogue_sha256"]);
}

#[cfg(all(windows, feature = "qualification"))]
pub(crate) async fn assert_audited_unified_status(
    state_dir: &Path,
    settings: &Path,
    extension_authority: &Value,
    manifest: crate::capability_manifest::QualifiedManifest,
    router: MissionRouter,
    expected_digest: &str,
) {
    let identity = manifest.identity().unwrap();
    let mut oauth = OAuthServer::open_with_capability(OAuthConfig {
        state_dir: state_dir.to_owned(), public_origin: ORIGIN.into(), audience: Audience::Workstation,
    }, identity.clone()).unwrap();
    oauth.bind_capability_manifest(&manifest.authority_bytes().unwrap()).unwrap();
    let (access, client_id) = issue_access(&mut oauth, state_dir, "real-unified-status");
    let legacy = fixture_router(false);
    let app = Gateway {
        oauth: Arc::new(Mutex::new(oauth)),
        legacy_catalogue_sha256: router_catalogue_digest(&legacy).unwrap(),
        router: Arc::new(legacy),
        request_audit: Arc::new(RequestAudit::new().unwrap()),
        unified: Some(Arc::new(UnifiedRoute {catalogue:crate::catalogue_selection::CatalogueSelection::Unified,
            identity: identity.clone(),
            router: Arc::new(router),
            extension_guard: Some(ExtensionGuard {
                settings: settings.to_owned(), authority: extension_authority.clone(),scope:None,
            }),
            manifest_guard: Arc::new(move || manifest.verify()),
            response_permits: Arc::new(Semaphore::new(2)),
        })),
        audience: Audience::Workstation,
        expected_resource: Some(format!("{ORIGIN}/mcp")),
        public_host: "router-capability.example.invalid".into(),
        loopback_host: "127.0.0.1:18856".into(),
        requests: Arc::new(Semaphore::new(32)),
        effects: OperationAdmission::default(),
        extension_guard: None,
    };

    let (status, response) = mcp(app.clone(), &access, call("agent_bridge_status", json!({}))).await;
    assert_eq!(status, 200);
    assert_ne!(response["result"]["isError"], true, "{response}");
    let result: Value = serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(result["ok"], true);
    assert_eq!(result["total_tools"], 46);
    assert_eq!(result["capability"], serde_json::to_value(identity).unwrap());

    let snapshot = serde_json::to_value(app.request_audit.snapshot()).unwrap();
    assert_eq!(snapshot["in_flight"], 0);
    let records = snapshot["records"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record["provider"], "gemini");
    assert_eq!(record["client_id_sha256"], Sha256::digest(client_id.as_bytes()).iter().map(|b| format!("{b:02x}")).collect::<String>());
    assert_eq!(record["catalogue_sha256"], expected_digest);
    assert_eq!(record["method"], "tools/call");
    assert_eq!(record["tool_name"], "agent_bridge_status");
    assert_eq!(record["outcome"], "success");
    assert_eq!(record["http_status"], 200);
    assert_eq!(record["error_code"], Value::Null);
}


#[tokio::test]
async fn attached_extension_route_keeps_valid_base_and_revokes_before_next_admission() {
    let mut fixture=Fixture::new();
    let settings=fixture._root.0.join("extension-reload-route");
    agent_bridge_lifecycle::initialize_operator_settings(&settings).unwrap();
    let raw=serde_json::to_vec(&json!({"version":1,"servers":{
        "mcp_docs":{"endpoint":"https://modelcontextprotocol.io/mcp","tools":{
            "search_model_context_protocol":{"descriptor_sha256":"a".repeat(64),
                "parameters":{"query":{"type":"search_terms"}}}
        }}
    }})).unwrap();
    crate::write_private(settings.join("extensions.json"),&raw);
    let profile=crate::session_profile::ProfileControl::new(agent_bridge_desktop::DesktopProfile::FullControl);
    let scope=crate::extensions::ExtensionScope::live(&profile).unwrap();
    let mut definitions=Vec::new();
    let mut handlers=ToolMapHandler::new();
    crate::extensions::attach(&settings,&mut definitions,&mut handlers,scope.clone()).unwrap();
    let live=scope.bind_live(&settings).unwrap();
    let bound=runtime::workstation_extension_authority(&settings).unwrap();
    let router=Arc::new(McpGateway::new(GatewayConfig::new("extension-route-fixture","1"),definitions,handlers));
    fixture.app.router=router;
    fixture.app.extension_guard=Some(ExtensionGuard{settings:settings.clone(),authority:bound.clone(),scope:Some(scope.clone())});
    // This exact invalid argument fails locally, before network access.
    let request=call("desktop_mcp_tool_call",json!({"name":"mcp_docs:search_model_context_protocol",
        "arguments":{"query":"not allowed!"}}));
    let (status,before)=mcp(fixture.app.clone(),&fixture.legacy_access,request.clone()).await;
    assert_eq!(status,200);
    assert_eq!(before["result"]["isError"],true);
    assert!(before.to_string().contains("Arguments outside the operator-approved contract"));
    crate::write_private(settings.join("extensions.json"),b"{invalid");
    assert!(scope.reload_from_disk(&settings).is_err());
    let (status,after)=mcp(fixture.app.clone(),&fixture.legacy_access,request.clone()).await;
    assert_eq!(status,200,"sealed old configuration remains usable");
    assert_eq!(after,before);
    assert_eq!(live.generation(),1);
    assert!(live.audit_snapshot()["records"][0]["ok"]==false);

    // A real native journal decision must cancel old registered receipts
    // immediately, not wait for the next MCP call or configuration reload.
    crate::write_private(settings.join("extensions.json"),&raw);
    let receipt=live.admit("mcp_docs:search_model_context_protocol",
        agent_bridge_extensions::ToolScope::DataOperations, |_|Ok(())).unwrap();
    let (status,proposed)=mcp(fixture.app.clone(),&fixture.legacy_access,
        call("desktop_mcp_manage",json!({"action":"disable","name":"mcp_docs"}))).await;
    assert_eq!(status,200);
    let proposal:Value=serde_json::from_str(proposed["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    let id=proposal["request_id"].as_str().unwrap();
    let decided=crate::extensions::decide_from_operator_ui(
        &crate::extensions::UiOAuthOwner::default(),&settings,id,true).unwrap();
    assert_eq!(decided["effect_now"],"disabled_and_pinned");
    assert!(!live.current().is_server_enabled("mcp_docs"));
    assert_eq!(live.audit_snapshot()["records"][1]["cancelled_in_flight"],1);
    // The old bearer remains sealed to the old exact extension authority.
    crate::write_private(settings.join("extensions.json"),b"{invalid again");
    assert_eq!(mcp(fixture.app.clone(),&fixture.legacy_access,request).await.0,403);
    assert!(receipt.execute(json!({"query":"safe"}).as_object().unwrap()).is_err());
    assert_eq!(live.in_flight().active_count(),0);
}

#[tokio::test]
async fn result_cache_scope_requires_authenticated_http_and_ignores_caller_metadata() {
    let mut fixture=Fixture::new();
    let settings=fixture._root.0.join("result-cache-http-route");
    agent_bridge_lifecycle::initialize_operator_settings(&settings).unwrap();
    let profile=crate::session_profile::ProfileControl::new(agent_bridge_desktop::DesktopProfile::FullControl);
    let scope=crate::extensions::ExtensionScope::live(&profile).unwrap();
    scope.bind_live(&settings).unwrap();
    let bound=runtime::workstation_extension_authority(&settings).unwrap();
    let calls=Arc::new(AtomicU64::new(0));
    let witness=calls.clone();
    let mut handlers=ToolMapHandler::new();
    handlers.register("cache_scope_witness",move |_|{
        witness.fetch_add(1,Ordering::Relaxed);
        Ok(ToolCallResult::text(if crate::extensions::test_cache_scope_present(){"authenticated"}else{"unscoped"}))
    });
    let router=Arc::new(McpGateway::new(GatewayConfig::new("cache-scope-fixture","1"),
        vec![ToolDefinition::new("cache_scope_witness",None,json!({"type":"object"}))],handlers));
    fixture.app.legacy_catalogue_sha256=router_catalogue_digest(&router).unwrap();
    fixture.app.router=router.clone();
    fixture.app.extension_guard=Some(ExtensionGuard{settings,authority:bound,scope:Some(scope)});
    let mut request=call("cache_scope_witness",json!({}));
    request["params"]["_meta"]=json!({"caller_id":"forged","profile":"read-only","token_hash":"forged"});
    let (status,reply)=mcp(fixture.app.clone(),&fixture.legacy_access,request.clone()).await;
    assert_eq!(status,200);
    assert_eq!(reply["result"]["content"][0]["text"],"authenticated");
    assert_eq!(mcp(fixture.app.clone(),"invalid-bearer",request.clone()).await.0,401);
    assert_eq!(calls.load(Ordering::Relaxed),1);
    let local=router.handle_str(&request.to_string()).unwrap();
    let local:Value=serde_json::from_str(&local).unwrap();
    assert_eq!(local["result"]["content"][0]["text"],"unscoped");
    assert_eq!(calls.load(Ordering::Relaxed),2);
}
