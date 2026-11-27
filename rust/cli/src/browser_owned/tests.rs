use super::*;
use crate::owned_children::ChildSpec;
use agent_bridge_gateway::{GatewayConfig, McpGateway, ToolMapHandler};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

struct PrivateTestRoot(PathBuf);
impl PrivateTestRoot {
    fn new() -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../workers/browser-playwright/.test-state")
            .join(format!("rust-test-{}", profiles::opaque_id().unwrap()));
        fs::create_dir_all(&path).unwrap(); Self(path.canonicalize().unwrap())
    }
}
impl Drop for PrivateTestRoot {
    fn drop(&mut self) {
        if thread::panicking() { eprintln!("Browser test diagnostic root retained: {}",self.0.display()); }
        else { let _ = fs::remove_dir_all(&self.0); }
    }
}
fn configuration(root: &Path) -> BrowserConfig {
    BrowserConfig {
        bundle_root:PathBuf::from(std::env::var_os("AGENT_BRIDGE_BROWSER_BUNDLE").expect("qualification requires the dedicated offline browser bundle")),
        manifest_sha256:std::env::var("AGENT_BRIDGE_BROWSER_MANIFEST_SHA256").expect("qualification requires its frozen manifest digest"),
        state_root:root.join("private-browser"),
    }
}
type Gateway = McpGateway<ToolMapHandler>;
fn call(gateway: &Gateway, name: &str, args: Value) -> Value {
    let response = gateway.handle_value(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}})).unwrap();
    assert!(response.error.is_none(), "protocol dispatch failed: {:?}", response.error);
    response.result.unwrap()
}
fn ok(result: Value) -> Value {
    assert_ne!(result["isError"], true, "tool call failed: {result}");
    result["structuredContent"].clone()
}
fn snapshot(gateway: &Gateway, id: &str) -> Value {
    ok(call(gateway,"desktop_browser_snapshot",json!({"session_id":id,"screenshot":false})))
}
fn act(gateway: &Gateway, id: &str, action: Value) -> Value {
    let view = snapshot(gateway,id);
    ok(call(gateway,"desktop_browser_act",json!({"session_id":id,"browser_observation_id":view["browser_observation_id"],"actions":[action],"screenshot":false})))
}

struct Fixture { base:String, stop:Arc<AtomicBool>, thread:Option<thread::JoinHandle<()>> }
const PAGE: &str = r#"<!doctype html><title>MCP browser witness</title>
<label>Name<input id="name"></label><label>Secret<input type="password" value="hidden-password"></label>
<label>Consent<input id="check" type="checkbox"></label><label>Pick<select id="pick"><option value="a">Alpha</option><option value="b">Beta</option></select></label>
<button id="click" onclick="document.querySelector('#result').textContent='clicked'">Click witness</button><p id="result">ready</p>
<div id="hover" onmouseenter="this.textContent='hovered'" style="width:100px;height:40px">Hover target</div>
<div id="drag" draggable="true" ondragstart="event.dataTransfer.setData('text/plain','dragged')" style="width:100px;height:40px">Drag source</div>
<div id="drop" ondragover="event.preventDefault()" ondrop="event.preventDefault();this.textContent=event.dataTransfer.getData('text/plain')" style="width:100px;height:40px">Drop target</div>
<input type="file" id="files" onchange="document.querySelector('#result').textContent=this.files[0].name"><a id="download" href="/download">Download witness</a>
<button id="dialog" onclick="alert('synthetic dialog')">Open dialog</button><button id="popup" onclick="window.open('/next')">Open popup</button>
<iframe title="Frame witness" src="/frame"></iframe><p>École école</p><div style="height:1600px">Tall witness</div>"#;
impl Fixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}",listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false)); let done = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !done.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream,_)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
                        let mut buffer=[0u8;8192]; let count=stream.read(&mut buffer).unwrap_or(0);
                        let request=String::from_utf8_lossy(&buffer[..count]);
                        let route=request.split_whitespace().nth(1).unwrap_or("/");
                        if route == "/abort" { continue; }
                        let (body,extra)=match route {
                            "/frame" => ("<button onclick=\"this.textContent='Frame clicked'\">Frame button</button>",""),
                            "/download-observe-failure" => ("<a id=\"download\" href=\"/download\" onclick=\"document.body.style.height='100000px'\">Download and exceed image budget</a>",""),
                            "/next" => ("<title>Next witness</title><h1>Next destination</h1>",""),
                            "/download" => ("download witness\n","Content-Disposition: attachment; filename=\"witness.txt\"\r\n"),
                            "/set-cookie" => ("<p>Owned cookie set</p>","Set-Cookie: owned_session=retained; Max-Age=3600; Path=/\r\n"),
                            "/cookie" if request.contains("owned_session=retained") => ("<p>Owned cookie retained</p>",""),
                            "/cookie" => ("<p>Owned cookie absent</p>",""),
                            _ => (PAGE,""),
                        };
                        let response=format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",body.len());
                        let _ = stream.write_all(response.as_bytes());
                    }
                    Err(error) if error.kind()==std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(2)),
                    Err(_) => break,
                }
            }
        });
        Self { base,stop,thread:Some(thread) }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true,Ordering::Release);
        let _ = TcpStream::connect(self.base.trim_start_matches("http://"));
        if let Some(thread)=self.thread.take() { let _=thread.join(); }
    }
}

fn transfers(root: &Path) -> BrowserTransferCallbacks {
    let input = root.join("upload.txt"); fs::write(&input,"upload witness").unwrap();
    let published = root.join("published"); fs::create_dir(&published).unwrap();
    BrowserTransferCallbacks {
        stage_uploads:Arc::new(move |profile,paths,directory| {
            assert!(matches!(profile,DesktopProfile::FullControl|DesktopProfile::FullyUnlocked));
            let mut staged=Vec::new();
            for path in paths {
                if Path::new(path).canonicalize()? != input.canonicalize()? { return Err("TEST_UPLOAD_AUTHORITY_REFUSED".into()); }
                let target=directory.join("upload.txt"); fs::copy(&input,&target)?; staged.push(target);
            }
            Ok(staged)
        }),
        publish_download:Arc::new(move |profile,path,name| {
            assert!(matches!(profile,DesktopProfile::FullControl|DesktopProfile::FullyUnlocked));
            assert_eq!(name,"witness.txt");
            let destination=published.join("witness.txt"); fs::copy(path,&destination)?;
            let bytes=fs::read(destination)?; assert_eq!(bytes,b"download witness\n");
            Ok(json!({"artifact_id":"test-published-artifact","bytes":bytes.len(),"sha256":Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect::<String>()}))
        }),
    }
}
fn gateway(config: BrowserConfig, profile:Arc<ProfileControl>, callbacks:BrowserTransferCallbacks) -> (Gateway,ProviderOwner) {
    let mut catalog=Vec::new(); let mut handlers=ToolMapHandler::new();
    let owner=attach(config,profile,AgentDesktopHandle::disabled(),callbacks,&mut catalog,&mut handlers).unwrap();
    (McpGateway::new(GatewayConfig::new("browser-parity-test","1"),catalog,handlers),owner)
}

#[test]
fn real_mcp_all_browser_actions_sessions_images_transfers_and_profile_revoke() {
    let root=PrivateTestRoot::new(); let fixture=Fixture::start();
    let profile=Arc::new(ProfileControl::new(DesktopProfile::FullyUnlocked));
    let callbacks=transfers(&root.0);
    let (gateway,mut owner)=gateway(configuration(&root.0),Arc::clone(&profile),callbacks);
    let tools=gateway.handle_value(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})).unwrap().result.unwrap();
    assert_eq!(tools["tools"].as_array().unwrap().len(),3);
    let session_schema=tools["tools"].as_array().unwrap().iter().find(|t| t["name"]=="desktop_browser_session").unwrap();
    assert_eq!(session_schema["inputSchema"]["properties"]["action"]["enum"].as_array().unwrap().len(),9);
    let action_schema=tools["tools"].as_array().unwrap().iter().find(|t| t["name"]=="desktop_browser_act").unwrap();
    assert_eq!(action_schema["inputSchema"]["properties"]["actions"]["items"]["properties"]["type"]["enum"].as_array().unwrap().len(),17);
    profile.set(DesktopProfile::ReadOnly).unwrap();
    assert_eq!(call(&gateway,"desktop_browser_session",json!({"action":"start"}))["isError"],true);
    profile.set(DesktopProfile::FullControl).unwrap();
    let started=ok(call(&gateway,"desktop_browser_session",json!({"action":"start","url":fixture.base,"profile_id":"mcp-parity","viewport":{"width":800,"height":600}})));
    let id=started["session_id"].as_str().unwrap().to_owned();
    let profiles=ok(call(&gateway,"desktop_browser_session",json!({"action":"list_profiles"})));
    assert_eq!(profiles["profiles"][0]["in_use"],true);
    assert_eq!(call(&gateway,"desktop_browser_session",json!({"action":"delete_profile","profile_id":"mcp-parity"}))["isError"],true);
    assert_eq!(call(&gateway,"desktop_browser_session",json!({"action":"start","profile_id":"MCP-PARITY"}))["isError"],true);
    let first=snapshot(&gateway,&id);
    assert!(!first.to_string().contains("hidden-password"));
    let image=call(&gateway,"desktop_browser_snapshot",json!({"session_id":id,"full_page":true}));
    assert_ne!(image["isError"],true);
    assert!(image["content"].as_array().unwrap().iter().any(|item| item["type"]=="image" && item["mimeType"]=="image/png" && item["data"].as_str().unwrap().starts_with("iVBORw0KGgo")));
    assert!(image["structuredContent"].get("_screenshot_png_base64").is_none());
    let found=ok(call(&gateway,"desktop_browser_snapshot",json!({"session_id":id,"mode":"find","find_query":"École","find_case_sensitive":true,"max_find_results":50,"screenshot":false})));
    assert!(!found["matches"].as_array().unwrap().is_empty());
    let frame=first["interactive_elements"].as_array().unwrap().iter().find(|entry| entry["ref"].as_str().is_some_and(|r|r.starts_with('f'))).unwrap()["ref"].clone();
    assert!(act(&gateway,&id,json!({"type":"click","ref":frame})).to_string().contains("Frame clicked"));
    act(&gateway,&id,json!({"type":"fill","selector":"#name","value":"first"}));
    assert!(act(&gateway,&id,json!({"type":"type_text","selector":"#name","text":" second","delay_ms":1})).to_string().contains("first second"));
    act(&gateway,&id,json!({"type":"press","selector":"#name","key":"ControlOrMeta+A"}));
    assert!(act(&gateway,&id,json!({"type":"set_checked","selector":"#check","checked":true}))["interactive_elements"].as_array().unwrap().iter().any(|e| e["checked"]==true));
    act(&gateway,&id,json!({"type":"select","selector":"#pick","value":"b"}));
    assert!(act(&gateway,&id,json!({"type":"hover","selector":"#hover"}))["text"].as_str().unwrap().contains("hovered"));
    assert!(act(&gateway,&id,json!({"type":"drag","source_selector":"#drag","target_selector":"#drop"}))["text"].as_str().unwrap().contains("dragged"));
    act(&gateway,&id,json!({"type":"scroll","delta_x":0,"delta_y":500}));
    act(&gateway,&id,json!({"type":"wait","duration_ms":25}));
    act(&gateway,&id,json!({"type":"wait_selector","selector":"#click","state":"visible","timeout_ms":1000}));
    act(&gateway,&id,json!({"type":"wait_url","url":format!("{}/",fixture.base),"timeout_ms":1000}));
    act(&gateway,&id,json!({"type":"wait_text","text":"Click witness","exact":true,"state":"visible","timeout_ms":1000}));
    let before=snapshot(&gateway,&id);
    let failed=call(&gateway,"desktop_browser_act",json!({"session_id":id,"browser_observation_id":before["browser_observation_id"],"actions":[{"type":"wait","duration_ms":0},{"type":"wait_text","text":"not present","timeout_ms":1000}],"screenshot":false}));
    assert_eq!(failed["isError"],true); assert_eq!(failed["structuredContent"]["error"]["details"]["completed_actions"],1);
    assert_eq!(failed["structuredContent"]["error"]["details"]["session_usable"],true);
    assert_eq!(call(&gateway,"desktop_browser_act",json!({"session_id":id,"browser_observation_id":before["browser_observation_id"],"actions":[{"type":"click","selector":"#click"}],"screenshot":false}))["isError"],true);
    assert!(act(&gateway,&id,json!({"type":"set_files","selector":"#files","files":[root.0.join("upload.txt")]}))["text"].as_str().unwrap().contains("upload.txt"));
    let downloaded=act(&gateway,&id,json!({"type":"download","selector":"#download"}));
    assert_eq!(downloaded["download"]["artifact_id"],"test-published-artifact"); assert!(downloaded.get("_download").is_none());
    act(&gateway,&id,json!({"type":"goto","url":format!("{}/next",fixture.base),"wait_until":"load"}));
    act(&gateway,&id,json!({"type":"navigation","direction":"back","timeout_ms":1000}));
    let page=ok(call(&gateway,"desktop_browser_session",json!({"action":"new_page","session_id":id,"url":format!("{}/next",fixture.base)})));
    ok(call(&gateway,"desktop_browser_session",json!({"action":"select_page","session_id":id,"page_id":first["page_id"]})));
    ok(call(&gateway,"desktop_browser_session",json!({"action":"close_page","session_id":id,"page_id":page["page_id"]})));
    let before=snapshot(&gateway,&id);
    assert_eq!(call(&gateway,"desktop_browser_act",json!({"session_id":id,"browser_observation_id":before["browser_observation_id"],"actions":[{"type":"click","selector":"#dialog"}],"screenshot":false}))["isError"],true);
    let listed=ok(call(&gateway,"desktop_browser_session",json!({"action":"list","session_id":id})));
    assert_eq!(listed["sessions"][0]["pages"][0]["dialog_pending"],true);
    ok(call(&gateway,"desktop_browser_session",json!({"action":"handle_dialog","session_id":id,"page_id":first["page_id"],"accept":true})));
    let popup=act(&gateway,&id,json!({"type":"click","selector":"#popup"})); assert_eq!(popup["pages"].as_array().unwrap().len(),2);
    act(&gateway,&id,json!({"type":"goto","url":format!("{}/set-cookie",fixture.base)}));
    let active=ok(call(&gateway,"desktop_browser_session",json!({"action":"list"}))); assert_eq!(active["count"],1);
    ok(call(&gateway,"desktop_browser_session",json!({"action":"close","session_id":id})));
    let again=ok(call(&gateway,"desktop_browser_session",json!({"action":"start","profile_id":"mcp-parity","url":format!("{}/cookie",fixture.base)})));
    let second=again["session_id"].as_str().unwrap(); assert_ne!(second,id);
    assert!(snapshot(&gateway,second)["text"].as_str().unwrap().contains("Owned cookie retained"));
    profile.set(DesktopProfile::ReadOnly).unwrap();
    assert_eq!(call(&gateway,"desktop_browser_snapshot",json!({"session_id":second,"screenshot":false}))["isError"],true);
    profile.set(DesktopProfile::FullControl).unwrap();
    assert_eq!(ok(call(&gateway,"desktop_browser_session",json!({"action":"list"})))["count"],0);
    ok(call(&gateway,"desktop_browser_session",json!({"action":"delete_profile","profile_id":"mcp-parity"})));
    owner.shutdown().unwrap();
    assert_eq!(call(&gateway,"desktop_browser_session",json!({"action":"start"}))["isError"],true);
}

#[test]
fn worker_deadline_wrong_correlation_and_eof_revoke_and_drain_the_entire_job() {
    let root=PrivateTestRoot::new(); let config=configuration(&root.0);
    let resource=resources::Resources::verify(&config.bundle_root,&config.manifest_sha256).unwrap();
    for mode in ["deadline","wrong-id","eof","empty-result","incomplete-timeout"] {
        let directory=root.0.join(mode); fs::create_dir(&directory).unwrap();
        let script=directory.join("fault.mjs");
        fs::write(&script,format!(r#"import {{spawn}} from 'node:child_process'; import {{writeFileSync}} from 'node:fs';
const child=spawn(process.execPath,['-e','setInterval(()=>{{}},1000)'],{{windowsHide:true,stdio:'ignore'}}); writeFileSync('descendant.pid',String(child.pid));
process.stdin.once('data',()=>{{
 if('{mode}'==='eof') process.exit(71);
 const receipt={{operation:'init',session_id:'fault-owned',phase:'init',completed_actions:0,failed_action_index:null,effect_uncertain:false,session_usable:true,upload_effect_started:false}};
 let reply;
 if('{mode}'==='wrong-id')reply={{v:2,id:'r999',ok:true,result:{{}},receipt}};
 if('{mode}'==='empty-result')reply={{v:2,id:'r1',ok:true,result:{{}},receipt}};
 if('{mode}'==='incomplete-timeout')reply={{v:2,id:'r1',ok:false,error:{{code:'PLAYWRIGHT_TIMEOUT',message:'Timed out',details:{{}}}},receipt}};
 if(reply){{const body=Buffer.from(JSON.stringify(reply)),h=Buffer.alloc(4);h.writeUInt32LE(body.length);process.stdout.write(h);process.stdout.write(body);}}
}}); setInterval(()=>{{}},1000);"#)).unwrap();
        let spec=ChildSpec { executable:resource.node.clone(),arguments:vec![resources::node_path(&script).unwrap().into_os_string()],cwd:directory.clone(),env_overrides:BTreeMap::new() };
        let mut worker=worker::Worker::spawn(&spec,&directory,Arc::new(AtomicBool::new(false))).unwrap();
        let failed=worker.rpc("init",json!({"session_id":"fault-owned"}),Duration::from_millis(1000)).unwrap_err();
        assert!(failed.transport); assert!(worker.revoked());
        if mode=="empty-result" { assert_eq!(failed.error["code"],"WORKER_RESULT_INVALID"); }
        if mode=="incomplete-timeout" { assert_eq!(failed.error["code"],"WORKER_ERROR_INVALID"); }
        let descendant=fs::read_to_string(directory.join("descendant.pid")).unwrap().parse::<u32>().unwrap();
        if mode != "eof" { assert!(worker.child().owns_process(descendant).unwrap()); }
        worker.close(false).unwrap(); assert!(worker.exit.is_some());
        if mode == "eof" { assert_eq!(worker.exit.unwrap().code,Some(71)); }
        let diagnostic=fs::read_to_string(directory.join("diagnostic.jsonl")).unwrap(); assert!(diagnostic.contains("job_empty"));
        assert!(worker.rpc("snapshot",json!({}),Duration::from_millis(20)).unwrap_err().transport);
    }
}

#[test]
fn immutable_bundle_qualification_rejects_changed_pins_and_holds_resources_against_write() {
    let root=PrivateTestRoot::new(); let config=configuration(&root.0);
    let mut changed=config.clone(); changed.manifest_sha256="0".repeat(64);
    assert!(validate_bundle(&changed).is_err());
    let resources=resources::Resources::verify(&config.bundle_root,&config.manifest_sha256).unwrap();
    assert!(fs::OpenOptions::new().write(true).open(&resources.worker).is_err());
    assert!(fs::OpenOptions::new().write(true).open(&resources.node).is_err());
    assert!(fs::OpenOptions::new().write(true).open(&resources.chromium).is_err());
    assert!(!config.state_root.exists());
}

#[test]
fn failure_receipt_initial_navigation_reports_closed_session_and_verified_job_cleanup() {
    let root=PrivateTestRoot::new(); let fixture=Fixture::start();
    let profile=Arc::new(ProfileControl::new(DesktopProfile::FullControl));
    let (gateway,mut owner)=gateway(configuration(&root.0),profile,transfers(&root.0));
    let failed=call(&gateway,"desktop_browser_session",json!({"action":"start","profile_id":"startup-failed","url":format!("{}/abort",fixture.base),"timeout_ms":1000}));
    assert_eq!(failed["isError"],true);
    assert_eq!(ok(call(&gateway,"desktop_browser_session",json!({"action":"list"})))["count"],0);
    let retained=ok(call(&gateway,"desktop_browser_session",json!({"action":"list_profiles"})));
    assert_eq!(retained["profiles"][0]["profile_id"],"startup-failed");
    assert_eq!(retained["profiles"][0]["in_use"],false);
    owner.shutdown().unwrap();
    assert_eq!(failed["structuredContent"]["error"]["details"]["session_usable"],false,"start failure must describe the closed owner, not the worker's earlier usable context");
    assert_eq!(failed["structuredContent"]["error"]["cleanup_verified"],true);
    assert_eq!(failed["structuredContent"]["error"]["details"]["phase"],"start");
}

#[test]
fn failure_receipt_publication_preserves_completed_download_without_replaying_effects() {
    let root=PrivateTestRoot::new(); let fixture=Fixture::start();
    let profile=Arc::new(ProfileControl::new(DesktopProfile::FullControl));
    let mut callbacks=transfers(&root.0);
    let published=Arc::new(std::sync::atomic::AtomicUsize::new(0)); let count=Arc::clone(&published);
    callbacks.publish_download=Arc::new(move |_,path,_| {
        assert_eq!(fs::read(path)?,b"download witness\n");
        count.fetch_add(1,Ordering::SeqCst);
        Err("TEST_ARTIFACT_COMMIT_FAILURE".into())
    });
    let (gateway,mut owner)=gateway(configuration(&root.0),profile,callbacks);
    let started=ok(call(&gateway,"desktop_browser_session",json!({"action":"start","url":fixture.base})));
    let id=started["session_id"].as_str().unwrap(); let before=snapshot(&gateway,id);
    let failed=call(&gateway,"desktop_browser_act",json!({"session_id":id,"browser_observation_id":before["browser_observation_id"],"actions":[{"type":"download","selector":"#download"}],"screenshot":false}));
    assert_eq!(failed["isError"],true);
    assert_eq!(published.load(Ordering::SeqCst),1);
    assert!(snapshot(&gateway,id)["title"].as_str().unwrap().contains("MCP browser witness"));
    assert_eq!(call(&gateway,"desktop_browser_act",json!({"session_id":id,"browser_observation_id":before["browser_observation_id"],"actions":[{"type":"download","selector":"#download"}],"screenshot":false}))["isError"],true);
    assert_eq!(published.load(Ordering::SeqCst),1);
    owner.shutdown().unwrap();
    assert_eq!(call(&gateway,"desktop_browser_session",json!({"action":"list"}))["isError"],true);
    let log=fs::read_to_string(root.0.join("private-browser/sessions").join(id).join("diagnostic.jsonl")).unwrap();
    assert!(log.contains("job_empty"));
    let error=&failed["structuredContent"]["error"];
    assert_eq!(error["code"],"BROWSER_DOWNLOAD_PUBLICATION_FAILED");
    assert_eq!(error["details"]["completed_actions"],1);
    assert_eq!(error["details"]["failed_action_index"],Value::Null);
    assert_eq!(error["details"]["phase"],"publish_download");
    assert_eq!(error["details"]["effect_uncertain"],false);
    assert_eq!(error["details"]["session_usable"],true);
    assert_eq!(error["details"]["artifact_committed"],false);
}

#[test]
fn review_observation_is_reserved_before_any_staging_and_abandoned_staging_is_removed() {
    let root=PrivateTestRoot::new(); let fixture=Fixture::start();
    let mut callbacks=transfers(&root.0);
    let staged=Arc::new(std::sync::atomic::AtomicUsize::new(0)); let count=Arc::clone(&staged);
    callbacks.stage_uploads=Arc::new(move |_,_,directory| {
        count.fetch_add(1,Ordering::SeqCst); fs::write(directory.join("partial.txt"),"partial stage")?;
        Err("TEST_STAGING_FAILED_AFTER_COPY".into())
    });
    let (gateway,mut owner)=gateway(configuration(&root.0),Arc::new(ProfileControl::new(DesktopProfile::FullControl)),callbacks);
    let started=ok(call(&gateway,"desktop_browser_session",json!({"action":"start","url":fixture.base})));
    let id=started["session_id"].as_str().unwrap();
    let args=|observation:Value| json!({"session_id":id,"browser_observation_id":observation,"actions":[{"type":"set_files","selector":"#files","files":[root.0.join("upload.txt")]}],"screenshot":false});
    assert_eq!(call(&gateway,"desktop_browser_act",args(json!("24be9e1c-e15b-4776-b103-01b42a8f33ed")))["isError"],true);
    assert_eq!(staged.load(Ordering::SeqCst),0,"unknown observation must not read or copy any source file");
    let view=snapshot(&gateway,id);
    let failed=call(&gateway,"desktop_browser_act",args(view["browser_observation_id"].clone()));
    assert_eq!(failed["isError"],true); assert_eq!(staged.load(Ordering::SeqCst),1);
    let uploads=root.0.join("private-browser/sessions").join(id).join("uploads");
    assert_eq!(fs::read_dir(uploads).unwrap().count(),0,"abandoned partial staging must be removed immediately");
    assert_eq!(call(&gateway,"desktop_browser_act",args(view["browser_observation_id"].clone()))["isError"],true);
    assert_eq!(staged.load(Ordering::SeqCst),1,"failed admitted staging must consume its observation");
    assert_eq!(failed["structuredContent"]["error"]["details"]["completed_actions"],0);
    assert_eq!(failed["structuredContent"]["error"]["details"]["phase"],"stage_uploads");
    assert!(snapshot(&gateway,id)["text"].as_str().unwrap().contains("ready"));
    owner.shutdown().unwrap();
}

#[test]
fn review_completed_download_is_published_when_after_action_image_fails() {
    let root=PrivateTestRoot::new(); let fixture=Fixture::start();
    let (gateway,mut owner)=gateway(configuration(&root.0),Arc::new(ProfileControl::new(DesktopProfile::FullControl)),transfers(&root.0));
    let started=ok(call(&gateway,"desktop_browser_session",json!({"action":"start","url":format!("{}/download-observe-failure",fixture.base)})));
    let id=started["session_id"].as_str().unwrap(); let before=snapshot(&gateway,id);
    let failed=call(&gateway,"desktop_browser_act",json!({"session_id":id,"browser_observation_id":before["browser_observation_id"],"actions":[{"type":"download","selector":"#download"}],"screenshot":true,"full_page":true}));
    assert_eq!(failed["isError"],true);
    let details=&failed["structuredContent"]["error"]["details"];
    assert_eq!(details["completed_actions"],1); assert_eq!(details["phase"],"observe_after");
    assert_eq!(details["artifact_committed"],true); assert_eq!(details["artifact"]["artifact_id"],"test-published-artifact");
    assert_eq!(details["session_id"],id); assert_eq!(fs::read(root.0.join("published/witness.txt")).unwrap(),b"download witness\n");
    assert_eq!(fs::read_dir(root.0.join("private-browser/sessions").join(id).join("downloads")).unwrap().count(),0);
    assert!(!failed.to_string().contains("private-browser"));
    owner.shutdown().unwrap();
}

#[test]
fn review_new_page_failure_preserves_created_tab_and_list_always_returns_inventory() {
    let root=PrivateTestRoot::new(); let fixture=Fixture::start();
    let (gateway,mut owner)=gateway(configuration(&root.0),Arc::new(ProfileControl::new(DesktopProfile::FullControl)),transfers(&root.0));
    let started=ok(call(&gateway,"desktop_browser_session",json!({"action":"start","url":fixture.base})));
    let id=started["session_id"].as_str().unwrap();
    let failed=call(&gateway,"desktop_browser_session",json!({"action":"new_page","session_id":id,"url":format!("{}/abort",fixture.base),"timeout_ms":1000}));
    assert_eq!(failed["isError"],true);
    let details=&failed["structuredContent"]["error"]["details"];
    let created=details["created_page_id"].as_str().expect("created tab must retain its identity after failed navigation");
    assert_eq!(details["phase"],"navigate_new_page");
    let listed=ok(call(&gateway,"desktop_browser_session",json!({"action":"list","session_id":id})));
    assert_eq!(listed["count"],1); assert_eq!(listed["sessions"][0]["pages"].as_array().unwrap().len(),2);
    assert!(listed["sessions"][0]["pages"].as_array().unwrap().iter().any(|p|p["page_id"]==created));
    assert_eq!(ok(call(&gateway,"desktop_browser_session",json!({"action":"list","session_id":"24be9e1c-e15b-4776-b103-01b42a8f33ed"})))["count"],1);
    owner.shutdown().unwrap();
}


#[test]
fn review_mcp_budget_failure_preserves_the_already_committed_artifact_identity() {
    let root=PrivateTestRoot::new(); let fixture=Fixture::start();
    let mut callbacks=transfers(&root.0); let publish=Arc::clone(&callbacks.publish_download);
    callbacks.publish_download=Arc::new(move |profile,path,name| {
        let mut artifact=publish(profile,path,name)?; artifact["oversized_metadata"]=json!("x".repeat(25*1024*1024)); Ok(artifact)
    });
    let (gateway,mut owner)=gateway(configuration(&root.0),Arc::new(ProfileControl::new(DesktopProfile::FullControl)),callbacks);
    let started=ok(call(&gateway,"desktop_browser_session",json!({"action":"start","url":fixture.base})));
    let id=started["session_id"].as_str().unwrap(); let before=snapshot(&gateway,id);
    let failed=call(&gateway,"desktop_browser_act",json!({"session_id":id,"browser_observation_id":before["browser_observation_id"],"actions":[{"type":"download","selector":"#download"}],"screenshot":false}));
    assert_eq!(failed["isError"],true); let details=&failed["structuredContent"]["error"]["details"];
    assert_eq!(details["completed_actions"],1); assert_eq!(details["phase"],"encode_mcp");
    assert_eq!(details["artifact_committed"],true); assert_eq!(details["artifact"]["artifact_id"],"test-published-artifact");
    assert!(failed.to_string().len()<16*1024); assert_eq!(fs::read(root.0.join("published/witness.txt")).unwrap(),b"download witness\n");
    owner.shutdown().unwrap();
}
