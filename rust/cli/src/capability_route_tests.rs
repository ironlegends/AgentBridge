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
}
fn identity() -> CapabilityIdentity {
    CapabilityIdentity::UnifiedV1 { manifest_sha256:"ab".repeat(32),
        catalogue_sha256:"cd".repeat(32),policy_version:1 }
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
fn issue_access(server:&mut OAuthServer,root:&Path,label:&str) -> String {
    let owner=LocalOwner::open(OAuthConfig {state_dir:root.into(), public_origin:ORIGIN.into(),
        audience:Audience::Workstation}).unwrap();
    owner.enable_enrollment(||true).unwrap();
    let registration=serde_json::to_vec(&json!({"redirect_uris":[CALLBACK],
        "token_endpoint_auth_method":"client_secret_post"})).unwrap();
    let reply=oauth_reply(server,"POST","/oauth/register",&registration,Some("application/json"));
    assert!((200..300).contains(&reply.status));
    let client:Value=serde_json::from_slice(&reply.body).unwrap();
    let id=client["client_id"].as_str().unwrap();
    let secret=client["client_secret"].as_str().unwrap();
    let verifier="V".repeat(43);
    let challenge=b64url(&Sha256::digest(verifier.as_bytes()));
    let target=format!("/oauth/authorize?response_type=code&client_id={id}&redirect_uri={CALLBACK}&code_challenge_method=S256&code_challenge={challenge}&state={label}");
    assert_eq!(oauth_reply(server,"GET",&target,b"",None).status,200);
    let pending=owner.pending_requests().unwrap().into_iter().find(|r|r.client_id==id).unwrap();
    owner.approve_request(&pending.id,|_|true).unwrap();
    let approved=oauth_reply(server,"GET",&target,b"",None);
    assert_eq!(approved.status,302);
    let location=&approved.headers.iter().find(|(name,_)|name=="location").unwrap().1;
    let code=location.split_once('?').unwrap().1.split('&')
        .find_map(|part|part.strip_prefix("code=")).unwrap();
    let form=format!("grant_type=authorization_code&client_id={id}&client_secret={secret}&redirect_uri={CALLBACK}&code={code}&code_verifier={verifier}");
    let reply=oauth_reply(server,"POST","/oauth/token",form.as_bytes(),
        Some("application/x-www-form-urlencoded"));
    assert_eq!(reply.status,200);
    let tokens:Value=serde_json::from_slice(&reply.body).unwrap();
    tokens["access_token"].as_str().unwrap().to_owned()
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
        let legacy_access=issue_access(&mut legacy,&root.0,"legacy");
        drop(legacy);
        let mut oauth=OAuthServer::open_with_capability(config,identity()).unwrap();
        let unified_access=issue_access(&mut oauth,&root.0,"unified");
        let app=Gateway { oauth:Arc::new(Mutex::new(oauth)),
            router:Arc::new(fixture_router(false)),
            unified:Some(Arc::new(UnifiedRoute {identity:identity(),router:Arc::new(fixture_router(true)),
                extension_guard:None,manifest_guard:Arc::new(||Ok(())),
                response_permits:Arc::new(Semaphore::new(2))})),
            audience:Audience::Workstation,expected_resource:Some(format!("{ORIGIN}/mcp")),
            public_host:"router-capability.example.invalid".into(),loopback_host:"127.0.0.1:18856".into(),
            requests:Arc::new(Semaphore::new(32)),effects:OperationAdmission::default(),extension_guard:None };
        Self{app,_root:root,legacy_access,unified_access}
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
async fn capability_route_refuses_exact_manifest_drift() {
    let mut fixture=Fixture::new();
    fixture.app.unified=Some(Arc::new(UnifiedRoute {identity:identity(),
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
        ProfileControl::new(DesktopProfile::FullControl),false,&mut catalogue,&mut handlers).unwrap();
    let checked=Arc::new(AtomicBool::new(false));
    let observed=Arc::clone(&checked);
    fixture.app.unified=Some(Arc::new(UnifiedRoute {identity:identity(),
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

#[tokio::test]
async fn capability_changed_extension_policy_refuses_old_grant_while_exact_new_view_works() {
    let mut fixture=Fixture::new();
    let settings=fixture._root.0.join("synthetic-extension-settings");
    agent_bridge_lifecycle::initialize_operator_settings(&settings).unwrap();
    let current=runtime::workstation_extension_authority(&settings).unwrap();
    fixture.app.extension_guard=Some(ExtensionGuard{settings:settings.clone(),
        authority:json!({"synthetic_historical_authority":"different"})});
    fixture.app.unified=Some(Arc::new(UnifiedRoute {
        identity:identity(),router:Arc::new(fixture_router(true)),
        extension_guard:Some(ExtensionGuard{settings,authority:current}),
        manifest_guard:Arc::new(||Ok(())),response_permits:Arc::new(Semaphore::new(2)),
    }));
    assert_eq!(mcp(fixture.app.clone(),&fixture.legacy_access,list()).await.0,403);
    let (status,value)=mcp(fixture.app.clone(),&fixture.unified_access,list()).await;
    assert_eq!(status,200);
    assert_eq!(value["result"]["tools"].as_array().unwrap().len(),2);
}
