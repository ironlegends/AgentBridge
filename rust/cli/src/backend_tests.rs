use super::*;
use agent_bridge_core::CoreDatabase;
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::time::Duration;
const ORIGIN: &str = "https://embedded-workstation.example.invalid";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
static BACKEND_TEST_OWNER: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
}
impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); } }


#[tokio::test(flavor="multi_thread", worker_threads=2)]
async fn disconnected_http_worker_must_drain_before_shutdown_releases_ownership() {
    let _serial = BACKEND_TEST_OWNER.lock().unwrap_or_else(|p|p.into_inner());
    let fixture=Fixture::new();
    let mut runtime=start_backend(fixture.config()).await.unwrap();
    let oauth=Arc::clone(&runtime.owner.as_ref().unwrap()._oauth);
    let requests=Arc::clone(&runtime.owner.as_ref().unwrap().requests);
    let guard=oauth.lock().unwrap();
    let mut stream=TcpStream::connect((Ipv4Addr::LOCALHOST,fixture.port)).unwrap();
    write!(stream,"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}",fixture.port).unwrap();
    tokio::time::timeout(Duration::from_secs(2),async {
        while requests.available_permits()==32 { tokio::time::sleep(Duration::from_millis(5)).await; }
    }).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(stream);
    runtime.request_shutdown().unwrap();
    tokio::time::timeout(Duration::from_secs(2),async {
        while !runtime.is_finished() { tokio::time::sleep(Duration::from_millis(5)).await; }
    }).await.unwrap();
    assert_eq!(requests.available_permits(),31,"detached blocking worker still owns admission");
    let result=tokio::time::timeout(Duration::from_millis(50),runtime.shutdown()).await;
    drop(guard);
    let premature=result.is_ok();
    runtime.join().await.unwrap();
    drop(oauth);
    assert!(!premature,"Stop reported clean while the disconnected gateway worker was blocked");
    let mut next=start_backend(fixture.config()).await.unwrap();
    assert!(next.shutdown().await.unwrap().clean);
}

#[test]
fn capability_local_unified_flag_is_explicit_and_preserves_legacy_arguments() {
    let fixture = Fixture::new();
    assert!(WorkstationConfig::from_cli_args(&fixture.args()).is_ok());
    let mut args = fixture.args();
    args.push("--unified-v1".into());
    assert!(WorkstationConfig::from_cli_args(&args).is_ok(),
        "the native local configuration must be able to select unified-v1 explicitly");
    args.push("--unified-v1".into());
    assert!(WorkstationConfig::from_cli_args(&args).is_err(), "duplicate local selection is ambiguous");
}

#[test]
fn capability_selection_uses_private_operator_setting_reader() {
    let fixture = Fixture::new();
    let settings = fixture.root.join("settings");
    let expected = b"{\"version\":1,\"policy_version\":1}";
    crate::write_private(settings.join("unified-v1.json"), expected);
    let actual = agent_bridge_lifecycle::read_operator_setting(&settings, "unified-v1.json")
        .expect("unified selection must use the existing private handle/ACL reader");
    assert_eq!(actual, expected);
    assert!(agent_bridge_lifecycle::read_operator_setting(&settings, "../unified-v1.json").is_err());
}

#[test]
fn capability_dropped_owner_remains_reconcilable_without_executor_or_ui_wait() {
    let _serial = BACKEND_TEST_OWNER.lock().unwrap_or_else(|p|p.into_inner());
    crate::provider_owner::ProviderOwner::reconcile_rollbacks().unwrap();
    let fixture = Fixture::new();
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let running = runtime.block_on(start_backend(fixture.config())).unwrap();
    let oauth = Arc::downgrade(&running.owner.as_ref().unwrap()._oauth);
    let requests = running.owner.as_ref().unwrap().requests.clone();
    // Represents an already-admitted blocking operation retained after its
    // caller/runtime disappears; the existing regression covers real HTTP.
    let admitted = requests.try_acquire_owned().unwrap();
    drop(runtime);
    let before = std::time::Instant::now();
    drop(running);
    assert!(before.elapsed() < Duration::from_millis(250), "abandoning ownership must not block the UI");
    assert!(crate::provider_owner::ProviderOwner::rollback_status().unwrap().pending > 0,
        "the last owner must remain reachable after the host executor disappears");
    assert!(oauth.upgrade().is_some(), "exclusive OAuth gate was released before the admitted operation");
    assert!(crate::provider_owner::ProviderOwner::reconcile_rollbacks().is_err());
    let next_runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let refused = next_runtime.block_on(start_backend(fixture.config())).err()
        .expect("a pending rollback must prevent any new generation");
    assert!(refused.to_string().contains("PROVIDER_ROLLBACK_PENDING"));
    drop(admitted);
    crate::provider_owner::ProviderOwner::reconcile_rollbacks().unwrap();
    assert!(oauth.upgrade().is_none(), "reconciliation did not release the confirmed owner");
    let mut next = next_runtime.block_on(start_backend(fixture.config())).unwrap();
    assert!(next_runtime.block_on(next.shutdown()).unwrap().clean);
}


#[tokio::test]
async fn capability_selected_unified_requires_local_qualification_before_oauth_or_listener() {
    let _serial = BACKEND_TEST_OWNER.lock().unwrap_or_else(|p|p.into_inner());
    let fixture=Fixture::new();
    let mut args=fixture.args(); args.push("--unified-v1".into());
    let config=WorkstationConfig::from_cli_args(&args).unwrap();
    match start_backend(config).await {
        Err(_)=>{},
        Ok(mut running)=>{
            running.shutdown().await.unwrap();
            panic!("selected unified-v1 must not silently start a legacy runtime without qualification");
        }
    }
    let entries:Vec<_>=fs::read_dir(fixture.root.join("oauth-workstation")).unwrap().collect();
    assert!(entries.is_empty(),"failed local selection must not open the OAuth owner or create state");
    let reservation=TcpListener::bind((Ipv4Addr::LOCALHOST,fixture.port)).unwrap();
    drop(reservation);
}
fn fixed_unlock(fixture: &Fixture) -> WorkstationConfig {
    let mut config=fixture.config();
    config.permitted.profile=DesktopProfile::FullyUnlocked;
    config
}

struct BlockedProfile {
    release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    entered: std::sync::mpsc::Receiver<()>,
}
impl BlockedProfile {
    fn install(profile:&crate::session_profile::ProfileControl)->Self {
        let release=Arc::new((std::sync::Mutex::new(false),std::sync::Condvar::new()));
        let waiting=Arc::clone(&release);
        let (sent,entered)=std::sync::mpsc::sync_channel(1);
        profile.register_revoker(DesktopProfile::FullControl,Arc::new(move || {
            let _=sent.try_send(());
            let (lock,changed)=&*waiting;
            let released=lock.lock().unwrap();
            let (released,timeout)=changed.wait_timeout_while(released,Duration::from_secs(10),|value|!*value).unwrap();
            if timeout.timed_out() && !*released {return Err("synthetic worker wait timed out".into());}
            Ok(())
        })).unwrap();
        Self {release,entered}
    }
    fn release(&self) {
        let (lock,changed)=&*self.release;
        *lock.lock().unwrap()=true;
        changed.notify_all();
    }
}
impl Drop for BlockedProfile {fn drop(&mut self){self.release();}}

fn reconcile_until_released(owner:&std::sync::Weak<std::sync::Mutex<agent_bridge_oauth_server::OAuthServer>>) {
    let deadline=std::time::Instant::now()+Duration::from_secs(3);
    while owner.upgrade().is_some() && std::time::Instant::now()<deadline {
        let _=crate::provider_owner::ProviderOwner::reconcile_rollbacks();
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(owner.upgrade().is_none(),"confirmed worker completion must eventually release its owner");
}

#[test]
fn capability_fix_live_executor_drop_is_registered_before_another_generation() {
    let _serial=BACKEND_TEST_OWNER.lock().unwrap_or_else(|p|p.into_inner());
    crate::provider_owner::ProviderOwner::reconcile_rollbacks().unwrap();
    let fixture=Fixture::new(); let other=Fixture::new();
    let runtime=tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let running=runtime.block_on(start_backend(fixed_unlock(&fixture))).unwrap();
    let oauth=Arc::downgrade(&running.owner.as_ref().unwrap()._oauth);
    let blocked=BlockedProfile::install(&running.owner.as_ref().unwrap().profile);
    let operator=running.operator();
    let pending=runtime.spawn(async move {operator.post(OperatorWrite::SetProfile,serde_json::json!({"profile":"read-only"})).await});
    blocked.entered.recv_timeout(Duration::from_secs(2)).unwrap();
    {
        let _entered=runtime.enter();
        drop(running);
    }
    let visible=crate::provider_owner::ProviderOwner::rollback_status().unwrap().pending>0;
    let replacement=runtime.block_on(start_backend(other.config()));
    let refused=replacement.as_ref().err().is_some_and(|error|error.to_string().contains("PROVIDER_ROLLBACK_PENDING"));
    blocked.release();
    let _=runtime.block_on(pending);
    if let Ok(mut replacement)=replacement {runtime.block_on(replacement.shutdown()).unwrap();}
    reconcile_until_released(&oauth);
    assert!(visible,"a live executor must not hide the abandoned generation outside the registry");
    assert!(refused,"a different private OAuth directory must not bypass pending generation cleanup");
}

#[test]
fn capability_fix_executor_loss_retains_real_blocking_ipc_worker() {
    let _serial=BACKEND_TEST_OWNER.lock().unwrap_or_else(|p|p.into_inner());
    crate::provider_owner::ProviderOwner::reconcile_rollbacks().unwrap();
    let fixture=Fixture::new();
    let runtime=tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let running=runtime.block_on(start_backend(fixed_unlock(&fixture))).unwrap();
    let oauth=Arc::downgrade(&running.owner.as_ref().unwrap()._oauth);
    let blocked=BlockedProfile::install(&running.owner.as_ref().unwrap().profile);
    let operator=running.operator();
    runtime.spawn(async move {operator.post(OperatorWrite::SetProfile,serde_json::json!({"profile":"read-only"})).await});
    // This signal comes from inside the real profile effect invoked by
    // ui::handle_set_profile's spawn_blocking worker, not its waiting task.
    blocked.entered.recv_timeout(Duration::from_secs(2)).unwrap();
    runtime.shutdown_background();
    // Wait until both detached async containers are demonstrably gone.
    // The profile revoker still blocks the actual worker at this point.
    let deadline=std::time::Instant::now()+Duration::from_secs(2);
    loop {
        let server_finished=running.server.as_ref().unwrap().is_finished();
        let ipc_task_gone=running.operator.shared.state.try_write().is_ok();
        if server_finished && ipc_task_gone {break;}
        assert!(std::time::Instant::now()<deadline,"executor did not cancel async containers");
        std::thread::sleep(Duration::from_millis(1));
    }
    drop(running);
    let refused=crate::provider_owner::ProviderOwner::reconcile_rollbacks().is_err();
    let retained=oauth.upgrade().is_some();
    let reopened=agent_bridge_oauth_server::OAuthServer::open(agent_bridge_oauth_server::OAuthConfig {
        state_dir:fixture.root.join("oauth-workstation"),public_origin:ORIGIN.into(),
        audience:agent_bridge_oauth_server::Audience::Workstation,
    });
    let exclusive=reopened.is_err(); drop(reopened);
    blocked.release();
    reconcile_until_released(&oauth);
    assert!(refused,"the still-running blocking IPC effect must prevent reconciliation");
    assert!(retained && exclusive,"runtime cancellation must not release OAuth while the actual IPC worker runs");
}

#[tokio::test]
async fn capability_fix_cli_failed_cleanup_retains_collective_authority() {
    let _serial=BACKEND_TEST_OWNER.lock().unwrap_or_else(|p|p.into_inner());
    crate::provider_owner::ProviderOwner::reconcile_rollbacks().unwrap();
    let fixture=Fixture::new(); let mut config=fixture.config();
    let mut prepared=gemini::prepare_workstation(config.take_start()).await.unwrap();
    prepared.listener.take();
    let oauth=Arc::downgrade(&prepared._oauth);
    let release=Arc::new(AtomicBool::new(false)); let gate=Arc::clone(&release);
    prepared.providers.push(crate::provider_owner::ProviderOwner::new(Arc::new(||Ok(())),Arc::new(move || {
        if gate.load(Ordering::Acquire){Ok(())}else{Err("synthetic retryable CLI cleanup failure".into())}
    })));
    assert!(prepared.cleanup().is_err());
    // This is the lifetime edge reached by the compatibility CLI's cleanup()?.
    drop(prepared);
    let retained=oauth.upgrade().is_some();
    let pending=crate::provider_owner::ProviderOwner::reconcile_rollbacks().is_err();
    let reopened=agent_bridge_oauth_server::OAuthServer::open(agent_bridge_oauth_server::OAuthConfig {
        state_dir:fixture.root.join("oauth-workstation"),public_origin:ORIGIN.into(),
        audience:agent_bridge_oauth_server::Audience::Workstation,
    });
    let exclusive=reopened.is_err(); drop(reopened);
    release.store(true,Ordering::Release);
    crate::provider_owner::ProviderOwner::reconcile_rollbacks().unwrap();
    assert!(oauth.upgrade().is_none());
    assert!(pending && retained && exclusive,"CLI cleanup failure must retain providers and exclusive OAuth together");
}

fn backend_access(server:&mut agent_bridge_oauth_server::OAuthServer,state:&std::path::Path)->String {
    use agent_bridge_oauth_server::{Audience,OAuthConfig,LocalOwner,HttpAction,HttpRequest};
    use sha2::{Digest,Sha256};
    let owner=LocalOwner::open(OAuthConfig{state_dir:state.into(),public_origin:ORIGIN.into(),audience:Audience::Workstation}).unwrap();
    owner.enable_enrollment(||true).unwrap();
    let callback="https://oauth-redirect.googleusercontent.com/r/backend-stop-fixture";
    let invoke=|server:&mut agent_bridge_oauth_server::OAuthServer,method:&str,target:&str,body:&[u8],content_type:Option<&str>| {
        match server.handle_http(HttpRequest{method,target,body,content_type,origin:None,authorization:None}) {
            HttpAction::Reply(reply)=>reply,_=>panic!("synthetic OAuth request unexpectedly dispatched")
        }
    };
    let registration=serde_json::json!({"redirect_uris":[callback],"token_endpoint_auth_method":"client_secret_post"}).to_string();
    let client:Value=serde_json::from_slice(&invoke(server,"POST","/oauth/register",registration.as_bytes(),Some("application/json")).body).unwrap();
    let id=client["client_id"].as_str().unwrap();let secret=client["client_secret"].as_str().unwrap();
    let verifier="V".repeat(43);
    let alphabet=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut challenge=String::new();
    for chunk in Sha256::digest(verifier.as_bytes()).chunks(3) {
        let a=chunk[0] as usize;let b=chunk.get(1).copied().unwrap_or(0) as usize;let c=chunk.get(2).copied().unwrap_or(0) as usize;
        challenge.push(alphabet[a>>2] as char);challenge.push(alphabet[((a&3)<<4)|(b>>4)] as char);
        if chunk.len()>1{challenge.push(alphabet[((b&15)<<2)|(c>>6)] as char);}
        if chunk.len()>2{challenge.push(alphabet[c&63] as char);}
    }
    let target=format!("/oauth/authorize?response_type=code&client_id={id}&redirect_uri={callback}&code_challenge_method=S256&code_challenge={challenge}&state=late-body");
    assert_eq!(invoke(server,"GET",&target,b"",None).status,200);
    let pending=owner.pending_requests().unwrap().into_iter().find(|request|request.client_id==id).unwrap();
    owner.approve_request(&pending.id,|_|true).unwrap();
    let accepted=invoke(server,"GET",&target,b"",None);
    let location=&accepted.headers.iter().find(|(name,_)|name=="location").unwrap().1;
    let code=location.split_once('?').unwrap().1.split('&').find_map(|part|part.strip_prefix("code=")).unwrap();
    let form=format!("grant_type=authorization_code&client_id={id}&client_secret={secret}&redirect_uri={callback}&code={code}&code_verifier={verifier}");
    let tokens:Value=serde_json::from_slice(&invoke(server,"POST","/oauth/token",form.as_bytes(),Some("application/x-www-form-urlencoded")).body).unwrap();
    tokens["access_token"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn request_audit_public_listener_refuses_diagnostics_with_valid_mcp_bearer() {
    use std::io::Read;

    let _serial = BACKEND_TEST_OWNER.lock().unwrap_or_else(|p| p.into_inner());
    let fixture = Fixture::new();
    let mut running = start_backend(fixture.config()).await.unwrap();
    let token = backend_access(&mut running.owner.as_ref().unwrap()._oauth.lock().unwrap(),
        &fixture.root.join("oauth-workstation"));
    let operator = running.operator();
    let port = fixture.port;
    let host = ORIGIN.strip_prefix("https://").unwrap();
    let send = |method: &str, path: &str, body: &str| {
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\n\
            Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        tokio::task::spawn_blocking(move || {
            let timeout = Duration::from_secs(3);
            let mut stream = TcpStream::connect_timeout(&(Ipv4Addr::LOCALHOST, port).into(), timeout).unwrap();
            stream.set_read_timeout(Some(timeout)).unwrap();
            stream.set_write_timeout(Some(timeout)).unwrap();
            stream.write_all(request.as_bytes()).unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            response
        })
    };

    let ping = send("POST", "/mcp", r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#).await.unwrap();
    let before = operator.get(OperatorRead::Diagnostics).await.unwrap();
    let public = send("GET", "/api/diagnostics", "").await.unwrap();
    let after = operator.get(OperatorRead::Diagnostics).await.unwrap();
    assert!(running.shutdown().await.unwrap().clean);

    assert!(ping.starts_with("HTTP/1.1 200 "));
    let (_, ping_body) = ping.split_once("\r\n\r\n").unwrap();
    let ping_body: serde_json::Value = serde_json::from_str(ping_body).unwrap();
    assert_eq!(ping_body["result"], serde_json::json!({}));
    assert_eq!(before.status, 200);
    let audit = &before.body["mcp_request_audit"];
    assert_eq!(audit["records"].as_array().unwrap().len(), 1);
    assert_eq!(audit["records"][0]["method"], "ping");
    assert_eq!(audit["records"][0]["provider"], "gemini");

    assert!(public.starts_with("HTTP/1.1 404 "));
    let (_, body) = public.split_once("\r\n\r\n").unwrap();
    assert_eq!(serde_json::from_str::<serde_json::Value>(body).unwrap(),
        serde_json::json!({"error":"not_found"}));
    assert_eq!(after.status, 200);
    assert_eq!(after.body["mcp_request_audit"], *audit);
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn capability_fix_stop_refuses_post_body_completed_after_stop() {
    use std::io::Read;
    let _serial=BACKEND_TEST_OWNER.lock().unwrap_or_else(|p|p.into_inner());
    let fixture=Fixture::new();
    let mut running=start_backend(fixture.config()).await.unwrap();
    let database=running.owner.as_ref().unwrap().database.clone().unwrap();
    let requests=Arc::clone(&running.owner.as_ref().unwrap().requests);
    let token=backend_access(&mut running.owner.as_ref().unwrap()._oauth.lock().unwrap(),&fixture.root.join("oauth-workstation"));
    let frame=serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        "name":"desktop_task_manage","arguments":{"action":"context_create","context_label":"must not run after Stop"}}}).to_string();
    let mut stream=TcpStream::connect((Ipv4Addr::LOCALHOST,fixture.port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    write!(stream,"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        fixture.port,token,frame.len()).unwrap();
    stream.write_all(&frame.as_bytes()[..frame.len()-1]).unwrap();
    tokio::time::timeout(Duration::from_secs(2),async {
        while requests.available_permits()==32 {tokio::time::sleep(Duration::from_millis(5)).await;}
    }).await.unwrap();
    running.request_shutdown().unwrap();
    stream.write_all(&frame.as_bytes()[frame.len()-1..]).unwrap();
    let response=tokio::task::spawn_blocking(move || {
        let mut bytes=Vec::new();stream.read_to_end(&mut bytes).unwrap();String::from_utf8(bytes).unwrap()
    });
    tokio::time::timeout(Duration::from_secs(3),running.join()).await.unwrap().unwrap();
    let response=response.await.unwrap();
    let effects:i64=database.lock().unwrap().connection().query_row("SELECT COUNT(*) FROM task_room_contexts",[],|row|row.get(0)).unwrap();
    assert_eq!(effects,0,"request admission before Stop is not permission to begin an effect after Stop");
    assert!(response.starts_with("HTTP/1.1 503"),"{response}");
}
