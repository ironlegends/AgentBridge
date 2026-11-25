use super::*;
use crate::agent_desktop::{self, AgentDesktopConfig};
use agent_bridge_desktop::DesktopProfile;
use agent_bridge_gateway::{GatewayConfig, McpGateway};
use serde_json::{json, Value};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use crate::owned_children::{ChildSpec, OwnedChild};

static TEST_ID: AtomicU64 = AtomicU64::new(1);
#[link(name="user32")]
unsafe extern "system" {fn GetForegroundWindow()->isize;}
fn foreground_window()->isize {unsafe{GetForegroundWindow()}}

fn config() -> WindowsToolsConfig {
    let root = PathBuf::from(std::env::var_os("AGENT_BRIDGE_NATIVE_TEST_BUNDLE").expect("native bundle test selection"));
    let manifest = std::fs::read(root.join("manifest.json")).unwrap();
    use sha2::{Digest, Sha256};
    let seal=format!("{:x}",Sha256::digest(manifest));
    assert_eq!(seal,std::env::var("AGENT_BRIDGE_NATIVE_TEST_MANIFEST_SHA256").expect("externally pinned native manifest"));
    WindowsToolsConfig { bundle_root: root, manifest_sha256: seal,
        state_root: std::env::temp_dir().join(format!("ab-native-tests-{}-{}", std::process::id(), TEST_ID.fetch_add(1,Ordering::Relaxed))) }
}
fn native_config(config: &WindowsToolsConfig) -> AgentDesktopConfig {
    AgentDesktopConfig { bundle_root: config.bundle_root.clone(), manifest_sha256: config.manifest_sha256.clone(),
        state_root: config.state_root.join("desktops"), desktops: vec![] }
}
fn invoke(gateway: &McpGateway<ToolMapHandler>, tool: &str, arguments: Value) -> Value {
    serde_json::to_value(gateway.handle_value(json!({"jsonrpc":"2.0","id":10,
        "method":"tools/call","params":{"name":tool,"arguments":arguments}})).unwrap()).unwrap()
}
fn text_value(response: &Value) -> Value {
    assert!(response.get("error").is_none(), "{response}");
    assert_ne!(response["result"]["isError"], true, "{response}");
    serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

#[test]
#[ignore = "requires independently packaged Windows resources"]
fn packaged_native_preflight_is_read_only_and_rejects_wrong_seals() {
    let config = config();
    assert!(!config.state_root.exists());
    validate_bundle(&config).expect("actual pinned native package must pass preflight");
    agent_desktop::validate_bundle(&native_config(&config)).unwrap();
    assert!(!config.state_root.exists(), "preflight must never create runtime state");
    let mut changed = config.clone();
    changed.manifest_sha256 = "0".repeat(64);
    assert!(validate_bundle(&changed).is_err());
}

#[test]
#[ignore = "requires independently packaged Windows resources"]
fn four_native_handlers_cross_the_real_mcp_schema_boundary() {
    let config = config();
    let profile = ProfileControl::new(DesktopProfile::FullyUnlocked);
    let mut catalog = Vec::new();
    let mut handlers = ToolMapHandler::new();
    let (desktops, mut desktop_owner) = agent_desktop::attach(native_config(&config), profile.clone(),
        Arc::new(|_, _| Err("no task binding in this isolated test".into())), &mut catalog, &mut handlers)
        .expect("native desktop provider must attach real handlers");
    let mut ui_owner = attach(config.clone(), profile.clone(), desktops, &mut catalog, &mut handlers).unwrap();
    profile.register_revoker(DesktopProfile::FullControl, ui_owner.revoker()).unwrap();
    profile.register_revoker(DesktopProfile::FullControl, desktop_owner.revoker()).unwrap();
    let gateway = McpGateway::new(GatewayConfig::new("native-test", "1"), catalog, handlers);
    let listed = gateway.handle_value(json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}})).unwrap();
    assert_eq!(listed.result.unwrap()["tools"].as_array().unwrap().len(), 4);
    let status = text_value(&invoke(&gateway, "desktop_agent_desktop", json!({"action":"status"})));
    assert_eq!(status["configured"], false);
    assert_eq!(status["desktops"].as_array().unwrap().len(), 0);
    let list = text_value(&invoke(&gateway, "desktop_ui_windows", json!({"app":"agent-bridge-native-fixture-not-running"})));
    assert!(list.as_array().unwrap().is_empty());
    let wrong = invoke(&gateway, "desktop_ui_action", json!({"window_id":"not-a-uuid",
        "computer_observation_id":"not-a-uuid","action":"click"}));
    assert!(wrong.get("error").is_some(), "bad schemas must be rejected before dispatch: {wrong}");
    for arguments in [json!({"app":"fixture","unexpected":true}),json!({"include_untitled":"true"}),json!({"app":"x".repeat(257)})] {
        let invalid=invoke(&gateway,"desktop_ui_windows",arguments);assert!(invalid.get("error").is_some(),"{invalid}");
    }
    profile.set(DesktopProfile::ReadOnly).unwrap();
    let denied = invoke(&gateway, "desktop_ui_windows", json!({"app":"agent-bridge-native-fixture-not-running"}));
    assert_eq!(denied["result"]["isError"], true);
    ui_owner.shutdown().unwrap(); desktop_owner.shutdown().unwrap();
    drop(gateway); drop(ui_owner); drop(desktop_owner);
    if config.state_root.exists() { std::fs::remove_dir_all(config.state_root).unwrap(); }
}

struct Rig {
    gateway: McpGateway<ToolMapHandler>, desktops: crate::agent_desktop::AgentDesktopHandle,
    ui_owner: ProviderOwner, desktop_owner: ProviderOwner, profile: ProfileControl, config:WindowsToolsConfig,
}
impl Rig {
    fn new(bindings: Vec<crate::agent_desktop::DesktopBinding>) -> Self {
        let config=config(); eprintln!("native fixture state root={}",config.state_root.display()); let profile=ProfileControl::new(DesktopProfile::FullyUnlocked);
        let mut catalog=Vec::new(); let mut handlers=ToolMapHandler::new(); let mut native=native_config(&config); native.desktops=bindings;
        let (desktops,desktop_owner)=agent_desktop::attach(native,profile.clone(),Arc::new(|task,context| {
            if task == "fixture-task" && context == "fixture-context" {Ok(())} else {Err("TEST_TASK_BINDING_INVALID".into())}
        }),&mut catalog,&mut handlers).unwrap();
        let ui_owner=attach(config.clone(),profile.clone(),desktops.clone(),&mut catalog,&mut handlers).unwrap();
        profile.register_revoker(DesktopProfile::FullControl,ui_owner.revoker()).unwrap();
        profile.register_revoker(DesktopProfile::FullControl,desktop_owner.revoker()).unwrap();
        let gateway=McpGateway::new(GatewayConfig::new("native-fixture-test","1"),catalog,handlers);
        Self{gateway,desktops,ui_owner,desktop_owner,profile,config}
    }
    fn call(&self,name:&str,args:Value)->Value { invoke(&self.gateway,name,args) }
    fn snapshot(&self,id:&str,lease:Option<&str>,image:bool)->Value {
        let mut args=json!({"window_id":id,"include_tree":true,"include_screenshot":image,"interactive_only":false,"max_elements":200});
        if let Some(lease)=lease { args["agent_desktop_lease_id"]=json!(lease); }
        self.call("desktop_ui_snapshot",args)
    }
    fn act(&self,id:&str,lease:Option<&str>,mut args:Value)->Value {
        let snapshot=text_value(&self.snapshot(id,lease,false));
        args["window_id"]=json!(id); args["computer_observation_id"]=snapshot["computer_observation_id"].clone();
        args["observe_after"]=json!("none"); args["settle_ms"]=json!(50);
        if let Some(lease)=lease {args["agent_desktop_lease_id"]=json!(lease);}
        self.call("desktop_ui_action",args)
    }
    fn close(mut self) { self.ui_owner.shutdown().unwrap(); self.desktop_owner.shutdown().unwrap(); let root=self.config.state_root.clone(); drop(self); std::fs::remove_dir_all(root).unwrap(); }
}
impl Drop for Rig {fn drop(&mut self){let _=self.ui_owner.shutdown();let _=self.desktop_owner.shutdown();}}

struct Fixture {child:OwnedChild,state:PathBuf,root:PathBuf,_image_pin:std::fs::File}
impl Fixture {
    fn new()->Self { Self::launch(false) }
    fn passive()->Self { Self::launch(true) }
    fn launch(passive:bool)->Self {
        let root=std::env::temp_dir().join(format!("ab-native-fixture-{}-{}",std::process::id(),TEST_ID.fetch_add(1,Ordering::Relaxed)));
        std::fs::create_dir(&root).unwrap(); let state=root.join("state.json");
        let (executable,image_pin)=crate::test_process_fixture::native_gui_fixture();
        let mut arguments=vec![state.clone().into_os_string()];
        if passive {arguments.push("--passive".into());}
        let child=OwnedChild::spawn(&ChildSpec{cwd:executable.parent().unwrap().to_path_buf(),executable,
            arguments,env_overrides:Default::default()}).unwrap();
        let fixture=Self{child,state,root,_image_pin:image_pin}; fixture.wait(|state|state["hwnd"].as_u64().is_some_and(|h|h>0) && state["rendered"]==true);
        assert_eq!(fixture.read()["console"],false); fixture
    }
    fn read(&self)->Value {
        std::fs::read(&self.state).ok().and_then(|bytes|serde_json::from_slice(&bytes).ok()).unwrap_or(Value::Null)
    }
    fn wait(&self,condition:impl Fn(&Value)->bool)->Value {
        let until=Instant::now()+Duration::from_secs(5);
        loop { let value=self.read(); if condition(&value){return value;} assert!(Instant::now()<until,"fixture condition failed: {value}"); std::thread::sleep(Duration::from_millis(25)); }
    }
    fn stop(&mut self) { self.child.terminate().unwrap(); let until=Instant::now()+Duration::from_secs(3);
        while self.child.finish().unwrap().is_none(){assert!(Instant::now()<until);std::thread::sleep(Duration::from_millis(10));} }
}
impl Drop for Fixture {fn drop(&mut self){self.stop();let _=std::fs::remove_dir_all(&self.root);}}
fn select_fixture(rig:&Rig,fixture:&Fixture,lease:Option<&str>)->String {
    let mut args=json!({"app":"agent-bridge-native-fixture"});
    if let Some(lease)=lease {args["agent_desktop_lease_id"]=json!(lease);}
    let windows=text_value(&rig.call("desktop_ui_windows",args));
    let expected=format!("Agent Bridge Native Fixture {}",fixture.child.root_pid());
    windows.as_array().unwrap().iter().find(|window|window["title"]==expected).unwrap_or_else(||panic!("fixture window missing: {windows}")).get("window_id").unwrap().as_str().unwrap().to_owned()
}
fn selectors(snapshot:&Value)->std::collections::BTreeMap<String,String> {
    snapshot["elements"].as_array().unwrap().iter().filter_map(|element|Some((element["automationId"].as_str()?.to_owned(),element["selector"].as_str()?.to_owned()))).collect()
}

#[test]
#[ignore="requires real owned WPF fixture and explicit foreground synthetic input"]
fn all_eight_action_families_have_real_effects_and_one_use_observations() {
    let rig=Rig::new(vec![]); let mut fixture=Fixture::new(); let id=select_fixture(&rig,&fixture,None);
    let screenshot=rig.snapshot(&id,None,true); let data=text_value(&screenshot);
    assert_eq!(screenshot["result"]["content"][1]["mimeType"],"image/png");
    assert!(screenshot["result"]["content"][1]["data"].as_str().unwrap().starts_with("iVBORw0K"));
    assert!(data["screenshot"]["width"].as_u64().unwrap()>100);
    let selectors=selectors(&data);
    for expected in ["InvokeButton","ValueBox","KeysBox","HoverButton","ScrollHost","DragSource","DragTarget"] {assert!(selectors.contains_key(expected),"missing {expected}: {data}");}
    let initial=fixture.read()["invoked"].as_u64().unwrap();
    let actions=[
        json!({"action":"invoke","selector":selectors["InvokeButton"]}),
        json!({"action":"set_value","selector":selectors["ValueBox"],"value":"native-value-proof"}),
        json!({"action":"click","selector":selectors["InvokeButton"]}),
        json!({"action":"hover","selector":selectors["HoverButton"],"dwell_ms":150}),
        json!({"action":"scroll","selector":selectors["ScrollHost"],"to":"bottom"}),
        json!({"action":"send_keys","selector":selectors["KeysBox"],"keys":"native-key-proof","verbatim":true}),
        json!({"action":"drag","from":selectors["DragSource"],"drag_to":selectors["DragTarget"],"hold_ms":150,"dwell_ms":150}),
        json!({"action":"wait","wait_ms":120}),
    ];
    for (index,action) in actions.into_iter().enumerate(){
        let started=Instant::now(); let response=rig.act(&id,None,action.clone()); let result=text_value(&response);
        assert_eq!(result["succeeded"],true,"{action}: {response}");
        match index {
            0=>{fixture.wait(|value|value["invoked"].as_u64()==Some(initial+1));},
            1=>{fixture.wait(|value|value["value"]=="native-value-proof");},
            2=>{fixture.wait(|value|value["invoked"].as_u64()==Some(initial+2));},
            3=>{fixture.wait(|value|value["hovered"].as_u64().unwrap_or(0)>0);},
            4=>{fixture.wait(|value|value["scroll_offset"].as_f64().unwrap_or(0.0)>100.0);},
            5=>{fixture.wait(|value|value["keys"]=="native-key-proof");},
            6=>{fixture.wait(|value|value["dragged"].as_u64().unwrap_or(0)>0);},
            _=>assert!(started.elapsed()>=Duration::from_millis(120)),
        }
    }
    let first=text_value(&rig.snapshot(&id,None,false)); let second=text_value(&rig.snapshot(&id,None,false));
    let bad=rig.call("desktop_ui_action",json!({"window_id":id,"computer_observation_id":first["computer_observation_id"],
        "action":"invoke","selector":"#AControlThatDoesNotExist","observe_after":"none"}));
    assert_eq!(bad["result"]["isError"],true); let bad_meta:Value=serde_json::from_str(bad["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(bad_meta["attempted"],true,"{bad}");
    let stale=rig.call("desktop_ui_action",json!({"window_id":id,"computer_observation_id":second["computer_observation_id"],"action":"invoke","selector":selectors["InvokeButton"]}));
    assert_eq!(stale["result"]["isError"],true); assert_eq!(fixture.read()["invoked"],initial+2);
    let fresh=text_value(&rig.snapshot(&id,None,false)); fixture.stop();
    let gone=rig.call("desktop_ui_action",json!({"window_id":id,"computer_observation_id":fresh["computer_observation_id"],"action":"wait","wait_ms":0}));
    assert_eq!(gone["result"]["isError"],true);
    rig.profile.set(DesktopProfile::ReadOnly).unwrap(); rig.close();
}

struct DedicatedDesktop {handle:crate::agent_desktop::AgentDesktopHandle,binding:crate::agent_desktop::DesktopBinding,fixture:Option<Fixture>}
impl Drop for DedicatedDesktop {fn drop(&mut self){self.fixture.take();let _=self.handle.local_remove_desktop(&self.binding);}}

#[test]
#[ignore="requires real owned WPF fixture and native Windows command-line limits"]
fn literal_values_are_preserved_and_oversized_commands_have_no_effect() {
    let foreground=foreground_window();assert_ne!(foreground,0,"no independent foreground witness");
    let rig=Rig::new(vec![]);let mut fixture=Fixture::passive();
    assert_eq!(foreground_window(),foreground,"passive fixture changed foreground");
    let id=select_fixture(&rig,&fixture,None);
    let observed=rig.snapshot(&id,None,false);
    if observed["result"]["isError"]==true{
        #[link(name="user32")]
        extern "system" {fn IsWindow(hwnd:isize)->i32;fn GetWindowThreadProcessId(hwnd:isize,pid:*mut u32)->u32;}
        let state=fixture.read();
        let hwnd=state["hwnd"].as_u64().expect("exact fixture HWND");
        let mut pid=0;
        let exists=unsafe{IsWindow(hwnd as isize)}!=0;
        let tid=unsafe{GetWindowThreadProcessId(hwnd as isize,&mut pid)};
        let owner=fixture.child.owns_process(fixture.child.root_pid()).unwrap();
        let helper=rig.desktops.window(hwnd).map(|window|(window.pid,window.tid,window.birth)).map_err(|error|error.to_string());
        println!("UIA_PASSIVE_IDENTITY_DIAGNOSTIC hwnd_alive={exists} hwnd_pid={pid} hwnd_tid={tid} root_pid={} job_owned={owner} helper={helper:?} foreground_unchanged={}",
            fixture.child.root_pid(),foreground_window()==foreground);
        // Collect only the exact test-owned child's diagnostics before Drop
        // stops its Job. A natural exit must not be confused with cleanup.
        println!("UIA_FIXTURE_EXIT_BEFORE_CLEANUP={:?}; fixture_closed={:?}",fixture.child.try_exit().unwrap().map(|x|x.code),state["closed"]);
        for stderr in [false,true] {
            let mut bytes=Vec::new();let mut buf=[0u8;4096];
            while bytes.len()<65536 {
                let read=if stderr{fixture.child.read_stderr(&mut buf)}else{fixture.child.read_stdout(&mut buf)};
                match read {Ok(0)=>break,Ok(n)=>bytes.extend_from_slice(&buf[..n]),Err(error) if error.kind()==std::io::ErrorKind::WouldBlock=>break,
                    Err(error)=>{println!("UIA_FIXTURE_READ_FAILED stderr={stderr} {error}");break;}}
            }
            println!("UIA_FIXTURE_OUTPUT stderr={stderr} bytes={} text={:?}",bytes.len(),String::from_utf8_lossy(&bytes));
        }
        // Never retry the mutation or switch/activate a window on this path.
    }
    let snapshot=text_value(&observed);let selectors=selectors(&snapshot);
    for value in ["--json","--literal-proof","valeur littérale \" avec espace et antislash\\"] {
        let response=rig.act(&id,None,json!({"action":"set_value","selector":selectors["ValueBox"],"value":value}));
        assert_eq!(text_value(&response)["succeeded"],true,"{response}");
        fixture.wait(|state|state["value"]==value);
        assert_eq!(foreground_window(),foreground,"semantic value changed foreground");
    }
    let initial=fixture.read()["value"].clone();
    let response=rig.act(&id,None,json!({"action":"set_value","selector":selectors["ValueBox"],"value":"😀".repeat(17000)}));
    assert_eq!(response["result"]["isError"],true,"{response}");
    assert!(response["result"]["content"][0]["text"].as_str().unwrap().contains("UI_WINDOWS_COMMAND_LINE_LIMIT"),"{response}");
    assert_eq!(fixture.read()["value"],initial);
    assert_eq!(foreground_window(),foreground);
    drop(fixture);rig.close();
}

#[test]
#[ignore="requires explicitly created dedicated Virtual Desktop and owned fixture plus qualified passive capture bundle"]
fn real_agent_desktop_moves_only_owned_windows_and_refuses_background_physical_input() {
    verify_passive_desktop(true);
}

#[test]
#[ignore="requires exact pinned native bundle and passive fixture on dedicated Virtual Desktop; no capture or physical input"]
fn real_agent_desktop_passive_semantic_actions_without_capture() {
    verify_passive_desktop(false);
}

fn verify_passive_desktop(include_capture:bool) {
    // Qualification must be tied to externally supplied, independently
    // reviewed seals. Refuse before creating any desktop or fixture if the
    // new WinApp image is not yet admitted by the product's compiled pin.
    use sha2::{Digest,Sha256};
    use std::io::Read;
    let qualified=config();
    let expected=std::env::var("AGENT_BRIDGE_NATIVE_TEST_MANIFEST_SHA256").expect("externally pinned native manifest");
    assert_eq!(qualified.manifest_sha256,expected);
    let resources=super::bundle::Resources::verify(&qualified.bundle_root,&expected).unwrap();
    if include_capture {
        assert!(resources.exact_passive_capture_qualified(),"UI_EXACT_PASSIVE_UNQUALIFIED: no native desktop or fixture created");
    }
    let fixture_path=PathBuf::from(std::env::var_os("AGENT_BRIDGE_NATIVE_TEST_FIXTURE").expect("exact owned fixture"));
    let expected_fixture=std::env::var("AGENT_BRIDGE_NATIVE_TEST_FIXTURE_SHA256").expect("externally pinned fixture");
    let mut fixture_pin=super::bundle::pin(&fixture_path,false).unwrap();
    assert!(fixture_pin.metadata().unwrap().len()<=512*1024*1024);
    let mut digest=Sha256::new();let mut buf=[0u8;65536];let mut size=0u64;
    loop {let n=fixture_pin.read(&mut buf).unwrap();if n==0{break;}size+=n as u64;
        assert!(size<=512*1024*1024);digest.update(&buf[..n]);}
    assert_eq!(format!("{:x}",digest.finalize()),expected_fixture);
    let creator=Rig::new(vec![]); let before=creator.desktops.current_desktop().unwrap();
    let binding=creator.desktops.local_create_desktop().unwrap();
    let mut dedicated=DedicatedDesktop{handle:creator.desktops.clone(),binding:binding.clone(),fixture:None};
    let rig=Rig::new(vec![binding.clone()]);
    let invalid=rig.call("desktop_agent_desktop",json!({"action":"start","desktop_number":binding.desktop_number,"task_id":"fixture-task","context_handle":"wrong"}));
    assert_eq!(invalid["result"]["isError"],true);
    let started=text_value(&rig.call("desktop_agent_desktop",json!({"action":"start","desktop_number":binding.desktop_number,
        "task_label":"Agent Bridge isolated native qualification","task_id":"fixture-task","context_handle":"fixture-context"})));
    let lease=started["control"]["lease_id"].as_str().unwrap().to_owned(); assert_eq!(started["control"]["hud_ready"],true);
    let occupied=rig.call("desktop_agent_desktop",json!({"action":"start","desktop_number":binding.desktop_number}));assert_eq!(occupied["result"]["isError"],true);
    let prior_foreground=foreground_window();
    dedicated.fixture=Some(Fixture::passive()); let fixture=dedicated.fixture.as_ref().unwrap();
    assert_eq!(foreground_window(),prior_foreground,"passive fixture activation changed foreground before placement");
    assert_eq!(creator.desktops.current_desktop().unwrap(),before,"passive fixture startup switched desktop");
    let native_lease=rig.desktops.verify_lease(&lease).unwrap();
    rig.desktops.place_owned_tree(&native_lease,&fixture.child,Duration::from_secs(5)).unwrap();
    let actual=rig.desktops.window(fixture.read()["hwnd"].as_u64().unwrap()).unwrap();
    assert_eq!(actual.desktop_id,binding.desktop_id); assert_eq!(creator.desktops.current_desktop().unwrap(),before);
    let foreground_before=foreground_window();assert_ne!(foreground_before,0);assert_ne!(foreground_before as u64,actual.hwnd);
    let id=select_fixture(&rig,fixture,Some(&lease));
    let captured=rig.snapshot(&id,Some(&lease),include_capture);
    assert_eq!(creator.desktops.current_desktop().unwrap(),before,"passive background screenshot switched the desktop: {captured}");
    assert_eq!(foreground_window(),foreground_before,"passive background screenshot changed foreground");
    rig.desktops.verify_lease(&lease).unwrap_or_else(|error|panic!("HUD lost after passive background screenshot: {error}; {captured}"));
    // Capture failure invalidates the window capability. Do not reuse it,
    // rediscover a foreground target, or treat tree-only output as a PNG pass.
    assert_ne!(captured["result"]["isError"],true,"passive observation refused: {captured}");
    let snapshot=text_value(&captured);
    let content=captured["result"]["content"].as_array().unwrap();
    if include_capture {
        assert_eq!(content.len(),2,"exactly one text receipt and one image");
        assert_eq!(content[1]["mimeType"],"image/png");
        assert!(content[1]["data"].as_str().unwrap().starts_with("iVBORw0K"));
        assert!(snapshot["screenshot"]["width"].as_u64().unwrap()>100);
        assert!(snapshot["screenshot"]["height"].as_u64().unwrap()>100);
        println!("UIA_PASSIVE_CAPTURE_OK=true; exact image and window identity verified");
    }else{
        assert_eq!(content.len(),1,"semantic-only test must not capture");
        assert!(snapshot.get("screenshot").is_none());
        println!("UIA_PASSIVE_SEMANTIC_ONLY=true; no capture qualification claimed");
    }
    assert_eq!(snapshot["window"]["window_id"],id);
    assert!(actual.same_target(&rig.desktops.window(actual.hwnd).unwrap()));
    assert!(fixture.child.owns_process(actual.pid).unwrap());
    let selectors=selectors(&snapshot);
    let invoke_selector=selectors.get("InvokeButton").expect("real background UIA button").clone();
    let invoked=rig.act(&id,Some(&lease),json!({"action":"invoke","selector":invoke_selector}));
    assert_eq!(creator.desktops.current_desktop().unwrap(),before,"semantic invoke switched the desktop: {invoked}");
    assert_eq!(foreground_window(),foreground_before,"semantic invoke changed foreground");
    rig.desktops.verify_lease(&lease).unwrap_or_else(|error|panic!("HUD lost after semantic invoke: {error}; {invoked}"));
    assert_eq!(text_value(&invoked)["succeeded"],true);
    fixture.wait(|value|value["invoked"]==1);
    println!("UIA_BACKGROUND_INVOKE=VERIFIED");
    for action in [json!({"action":"set_value","selector":selectors["ValueBox"],"value":"background-value-proof"}),
        json!({"action":"scroll","selector":selectors["ScrollHost"],"to":"bottom"})] {
        let response=rig.act(&id,Some(&lease),action);
        assert_eq!(creator.desktops.current_desktop().unwrap(),before,"background UIA switched the desktop: {response}");
        assert_eq!(foreground_window(),foreground_before,"background UIA changed foreground");
        rig.desktops.verify_lease(&lease).unwrap_or_else(|error|panic!("HUD lost after background UIA: {error}; {response}"));
        assert_eq!(text_value(&response)["succeeded"],true);
    }
    fixture.wait(|value|value["value"]=="background-value-proof" && value["scroll_offset"].as_f64().unwrap_or(0.0)>100.0);
    println!("UIA_BACKGROUND_VALUE_SCROLL=VERIFIED");
    assert_ne!(fixture.read()["native_keys_hwnd"],fixture.read()["hwnd"]);
    assert!(fixture.read()["native_keys_hwnd"].as_u64().is_some_and(|hwnd|hwnd>0));
    let native_keys=selectors.get("NativeKeysBox").unwrap_or_else(||panic!("real observed child HWND editor absent: {snapshot}"));
    let messages=rig.act(&id,Some(&lease),json!({"action":"send_keys","selector":native_keys,"keys":"owned-post-message-proof","verbatim":true}));
    assert_eq!(text_value(&messages)["succeeded"],true,"{messages}");
    fixture.wait(|value|value["native_keys"]=="owned-post-message-proof");
    println!("UIA_BACKGROUND_NATIVE_EDITOR=VERIFIED");
    assert_eq!(creator.desktops.current_desktop().unwrap(),before,"post-message changed desktop");
    assert_eq!(foreground_window(),foreground_before,"post-message changed foreground");
    rig.desktops.verify_lease(&lease).unwrap();
    let windowless=rig.act(&id,Some(&lease),json!({"action":"send_keys","selector":selectors["KeysBox"],"keys":"must-not-land","verbatim":true}));
    assert_eq!(windowless["result"]["isError"],true,"{windowless}");
    assert!(windowless["result"]["content"][0]["text"].as_str().unwrap().contains("UI_BACKGROUND_TARGET_UNAVAILABLE"),"{windowless}");
    assert_eq!(fixture.read()["keys"],"");
    assert_eq!(creator.desktops.current_desktop().unwrap(),before);
    assert_eq!(foreground_window(),foreground_before,"windowless post-message changed foreground");
    rig.desktops.verify_lease(&lease).unwrap();
    for action in [json!({"action":"click","selector":invoke_selector}),json!({"action":"hover","selector":invoke_selector}),
        json!({"action":"scroll","wheel":1}),json!({"action":"drag","from":invoke_selector,"drag_to":invoke_selector}),
        json!({"action":"send_keys","keys":"x","transport":"send-input"}),json!({"action":"send_keys","keys":"x","allow_system_keys":true})] {
        let denied=rig.act(&id,Some(&lease),action);assert_eq!(denied["result"]["isError"],true,"{denied}");
        assert!(denied["result"]["content"][0]["text"].as_str().unwrap().contains("requires_foreground_input"));
    }
    assert_eq!(fixture.read()["invoked"],1); assert_eq!(creator.desktops.current_desktop().unwrap(),before);
    text_value(&rig.call("desktop_agent_desktop",json!({"action":"stop","lease_id":lease})));
    assert!(rig.desktops.verify_lease(&lease).is_err()); assert!(fixture.child.owns_process(fixture.child.root_pid()).unwrap(),"lease stop must not kill the independent app");
    rig.close(); drop(dedicated); assert!(!creator.desktops.local_pool_candidates().unwrap().contains(&binding)); creator.close();
    drop(fixture_pin);drop(resources);
    if include_capture {println!("UIA_PASSIVE_RECIPE_COMPLETE=true; no activation fallback");}
    else {println!("UIA_PASSIVE_SEMANTIC_RECIPE_COMPLETE=true; no capture or activation fallback");}
}
