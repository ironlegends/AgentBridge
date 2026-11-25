//! Opt-in composition test of the real unified providers. Never opens the
//! operator's settings, OAuth state, personal browser, or desktop lease.
use super::*;
use crate::capability_manifest::{catalogue_digest, ManifestContext, QualifiedManifest, COMPLETE_TOOL_NAMES};
use crate::provider_owner::ProviderOwner;
use std::collections::BTreeSet;
use std::io::{Read as _, Write as _};

struct Fixture { root: PathBuf }
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("isolated integration diagnostic fixture retained: {}", self.root.display());
        } else {
            std::fs::remove_dir_all(&self.root).expect("isolated fixture cleanup");
        }
    }
}

fn mcp(runtime: &WorkstationRuntime, method: &str, params: Value) -> Value {
    serde_json::to_value(runtime.router.handle_value(json!({
        "jsonrpc":"2.0", "id":1, "method":method, "params":params
    })).expect("MCP response")).unwrap()
}

fn call(runtime: &WorkstationRuntime, name: &str, arguments: Value) -> Value {
    mcp(runtime, "tools/call", json!({"name":name,"arguments":arguments}))
}
fn text_result(response: Value) -> Value {
    assert!(response.get("error").is_none(), "{response}");
    assert_ne!(response["result"]["isError"], true, "{response}");
    serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

/// Isolated settings, Core database and workspace bound to the real pinned
/// resource bundles. `prepare` may add private operator settings before the
/// extension authority and manifest are derived from them.
struct Bench {
    fixture: Fixture,
    settings: PathBuf,
    workspace: PathBuf,
    db: PathBuf,
    context: ManifestContext,
    extension_authority: Value,
    selected: Value,
}

fn bench(os_user: bool, allow_import: bool, prepare: impl FnOnce(&Path, &Path)) -> Bench {
    let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    let temp = temp.to_str().and_then(|s|s.strip_prefix(r"\\?\")).map(PathBuf::from).unwrap_or(temp);
    let fixture = Fixture {root:temp.join(format!("ab-catalogue46-{}-{}",std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()))};
    let root=fixture.root.clone();
    std::fs::create_dir(&root).unwrap();
    for name in ["settings","oauth","lifecycle","db","private"] {
        agent_bridge_lifecycle::initialize_operator_settings(&root.join(name)).unwrap();
    }
    for name in ["workspace","private/browser","private/windows","private/desktops"] {
        std::fs::create_dir_all(root.join(name)).unwrap();
    }
    let settings=root.join("settings");
    let workspace=root.join("workspace");
    let db=root.join("db/core.sqlite");
    drop(agent_bridge_core::CoreDatabase::initialize_new(&db).unwrap());
    prepare(&settings, &workspace);
    let browser=PathBuf::from(std::env::var_os("AGENT_BRIDGE_BROWSER_BUNDLE").expect("browser bundle"));
    let browser_sha=std::env::var("AGENT_BRIDGE_BROWSER_MANIFEST_SHA256").expect("browser seal");
    let native=PathBuf::from(std::env::var_os("AGENT_BRIDGE_NATIVE_TEST_BUNDLE").expect("native bundle"));
    let native_sha=std::env::var("AGENT_BRIDGE_NATIVE_TEST_MANIFEST_SHA256").expect("native seal");
    let extension_authority=workstation_extension_authority(&settings).unwrap();
    let context=ManifestContext {
        workspace:workspace.clone(),
        protected_roots:["settings","oauth","lifecycle","db"].map(|p|root.join(p)).to_vec(),
        legacy_authority:json!({"purpose":"isolated-qualification","resource":"https://synthetic.invalid/mcp",
            "database_boundary":crate::gemini::scope_file(&db).unwrap(),
            "effective_extension_authority":extension_authority}),
    };
    let selected=json!({"version":1,"policy_version":1,"catalogue_sha256":"0".repeat(64),
        "private_root":root.join("private"),"file_scope":{"kind":if os_user { "os-user" } else { "workspace" }},"allow_import":allow_import,
        "browser":{"bundle_root":browser,"manifest_sha256":browser_sha,"state_root":root.join("private/browser")},
        "windows":{"bundle_root":native,"manifest_sha256":native_sha,"state_root":root.join("private/windows")},
        "agent_desktop":{"bundle_root":native,"manifest_sha256":native_sha,"state_root":root.join("private/desktops"),"desktops":[]}});
    Bench {fixture,settings,workspace,db,context,extension_authority,selected}
}

struct Attached {
    runtime: WorkstationRuntime,
    supervisors: Vec<crate::terminal::SessionSupervisor>,
    providers: Vec<ProviderOwner>,
    profile: ProfileControl,
    manifest: QualifiedManifest,
}

fn attach(bench: &Bench) -> Attached {
    std::fs::write(bench.settings.join("unified-v1.json"),serde_json::to_vec(&bench.selected).unwrap()).unwrap();
    let manifest=QualifiedManifest::load(&bench.settings,bench.context.clone()).expect("physical fixture manifest");
    manifest.preflight_providers().expect("real pinned bundle preflight");
    let profile=ProfileControl::new(DesktopProfile::FullyUnlocked);
    let mut supervisors=Vec::new();
    let mut providers=Vec::new();
    let runtime=unified_router(&manifest,&bench.db,None,&bench.settings,&bench.extension_authority,
        profile.clone(),&mut supervisors,&mut providers).expect("all real providers must attach");
    Attached {runtime,supervisors,providers,profile,manifest}
}

/// Shuts every owner down and proves no provider retained the Core database.
fn shutdown(attached: Attached, db: &Path) {
    let Attached {runtime,mut supervisors,mut providers,profile,manifest}=attached;
    let database_owner=Arc::downgrade(runtime.database.as_ref().expect("real Core owner"));
    drop(runtime);
    for supervisor in supervisors.iter_mut().rev() {supervisor.shutdown().unwrap();}
    for owner in providers.iter_mut().rev() {owner.shutdown().unwrap();}
    drop(supervisors); drop(providers); drop(profile); drop(manifest);
    assert_eq!(ProviderOwner::rollback_status().unwrap().pending,0);
    assert!(database_owner.upgrade().is_none(), "shutdown retained the Core database through a provider ownership cycle");
    for suffix in ["-wal","-shm","-journal"] {
        assert!(!db.with_file_name(format!("core.sqlite{suffix}")).exists(), "clean shutdown left {suffix}");
    }
}

/// Lists the real catalogue, checks its 46 names, and returns its digest.
fn listed_digest(attached: &Attached) -> String {
    let listed=mcp(&attached.runtime,"tools/list",json!({}));
    let tools=listed["result"]["tools"].as_array().unwrap();
    let names: BTreeSet<_>=tools.iter().map(|t|t["name"].as_str().unwrap()).collect();
    let expected: BTreeSet<_>=COMPLETE_TOOL_NAMES.iter().copied().collect();
    eprintln!("catalogue count={} missing={:?} extra={:?}",tools.len(),
        expected.difference(&names).collect::<Vec<_>>(),names.difference(&expected).collect::<Vec<_>>());
    assert_eq!(tools.len(),46);
    assert_eq!(names,expected);
    let catalogue:Vec<_>=attached.runtime.router.published_tools().into_iter().cloned().collect();
    catalogue_digest(&catalogue).unwrap()
}

#[test]
#[ignore = "requires the explicitly pinned Windows native and headless browser resource bundles"]
fn integration_real_catalogue_46_providers_and_lifecycle() {
    qualify_catalogue(false);
}

#[test]
#[ignore = "requires the explicitly pinned Windows native and headless browser resource bundles"]
fn integration_real_catalogue_46_os_user_scope_and_downgrade() {
    qualify_catalogue(true);
}

fn qualify_catalogue(os_user: bool) {
    let mut bench=bench(os_user,false,|_,workspace| {
        std::fs::write(workspace.join("witness.txt"),"CATALOGUE46_ISOLATED_WITNESS").unwrap();
    });
    let external=bench.fixture.root.join("outside.txt");
    std::fs::write(&external,"EXTERNAL_SYNTHETIC_BEFORE").unwrap();
    let settings=bench.settings.clone();
    let mut digest=String::new();
    for pass in 0..2 {
        let attached=attach(&bench);
        let catalogue:Vec<_>=attached.runtime.router.published_tools().into_iter().cloned().collect();
        let observed=listed_digest(&attached);
        let (runtime,profile,manifest)=(&attached.runtime,&attached.profile,&attached.manifest);
        if pass==0 {
            digest=observed;
            assert!(manifest.verify_catalogue(&catalogue).is_err(),"wrong seal must fail");
            bench.selected["catalogue_sha256"]=json!(digest);
        } else {
            manifest.verify_catalogue(&catalogue).expect("exact observed schema digest");
            let status=text_result(call(runtime,"agent_bridge_status",json!({})));
            assert_eq!(status["total_tools"],46);
            assert_eq!(status["families"],json!({"desktop":27,"missions_including_status":16,"project_commands":1,"historical_utilities":2,"other":0}));
            let read=call(runtime,"desktop_read_file",json!({"path":"witness.txt"}));
            assert_ne!(read["result"]["isError"],true,"{read}");
            assert!(read.to_string().contains("CATALOGUE46_ISOLATED_WITNESS"));
            let policy=text_result(call(runtime,"desktop_policy_status",json!({})));
            assert_eq!(policy["filesystem_scope"],if os_user { "os-user" } else { "workspace" });
            if os_user {
                let observed=text_result(call(runtime,"desktop_read_file",json!({"path":external})));
                assert_eq!(observed["content"],"EXTERNAL_SYNTHETIC_BEFORE");
                let request=json!({"path":external,"mode":"rewrite","content":"EXTERNAL_SYNTHETIC_AFTER",
                    "observation_id":observed["observation_id"]});
                let _=text_result(call(runtime,"desktop_write_file",request.clone()));
                assert_eq!(std::fs::read_to_string(&external).unwrap(),"EXTERNAL_SYNTHETIC_AFTER");
                assert_eq!(call(runtime,"desktop_write_file",request)["result"]["isError"],true);
                let protected=call(runtime,"desktop_read_file",json!({"path":settings.join("unified-v1.json")}));
                assert_eq!(protected["result"]["isError"],true);
                profile.set(DesktopProfile::FullControl).expect("downgrade outside workspace authority");
                assert_eq!(call(runtime,"desktop_read_file",json!({"path":external}))["result"]["isError"],true);
                assert_eq!(text_result(call(runtime,"desktop_policy_status",json!({})))["filesystem_scope"],"workspace");
                profile.set(DesktopProfile::FullyUnlocked).expect("restore locally selected ceiling");
            } else {
                assert_eq!(call(runtime,"desktop_read_file",json!({"path":external}))["result"]["isError"],true);
            }
            let desktop=text_result(call(runtime,"desktop_agent_desktop",json!({"action":"status"})));
            assert_eq!(desktop["configured"],false,"no live desktop pool");
            let browser=call(runtime,"desktop_browser_session",json!({"action":"list"}));
            assert_ne!(browser["result"]["isError"],true,"{browser}");
            let ui=text_result(call(runtime,"desktop_ui_windows",json!({"app":"ab-catalogue46-fixture-not-running"})));
            assert!(ui.as_array().unwrap().is_empty());
            profile.set(DesktopProfile::ReadOnly).expect("real provider downgrade");
            let refused=call(runtime,"desktop_browser_session",json!({"action":"start","headless":true}));
            assert_eq!(refused["result"]["isError"],true,"no launch after downgrade");
            let status=text_result(call(runtime,"agent_bridge_status",json!({})));
            assert_eq!(status["desktop_profile"],"read-only");
            assert_eq!(status["process_tools_enabled"],false);
        }
        shutdown(attached,&bench.db);
    }
    eprintln!("catalogue_sha256={digest}; real provider attachment, MCP list, exact seal, isolated status/read and downgrade verified");
}

#[test]
#[ignore = "requires pinned native and browser bundles, the pinned WPF fixture, the reviewed Microsoft Learn descriptor and network access"]
fn integration_every_46_tool_has_an_observed_real_effect_workspace_scope() {
    exercise_every_tool(false);
}

#[test]
#[ignore = "requires pinned native and browser bundles, the pinned WPF fixture, the reviewed Microsoft Learn descriptor and network access"]
fn integration_every_46_tool_has_an_observed_real_effect_os_user_scope() {
    exercise_every_tool(true);
}

/// Serves one synthetic page on loopback for the owned headless browser.
struct Page { base: String, stop: Arc<std::sync::atomic::AtomicBool>, thread: Option<std::thread::JoinHandle<()>> }
impl Page {
    fn start() -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        let listener=std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base=format!("http://{}",listener.local_addr().unwrap());
        let stop=Arc::new(AtomicBool::new(false)); let done=Arc::clone(&stop);
        let thread=std::thread::spawn(move || while !done.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream,_)) => {
                    let _=stream.set_nonblocking(false);
                    let _=stream.set_read_timeout(Some(std::time::Duration::from_secs(1)));
                    let mut buffer=[0u8;8192]; let count=stream.read(&mut buffer).unwrap_or(0);
                    let request=String::from_utf8_lossy(&buffer[..count]);
                    let body=if request.split_whitespace().nth(1)==Some("/next") {
                        "<title>Next witness</title><h1>Next destination</h1>"
                    } else {
                        "<!doctype html><title>Catalogue46 browser witness</title><button id=\"click\" \
                         onclick=\"document.querySelector('#result').textContent='clicked46'\">Click</button><p id=\"result\">ready</p>"
                    };
                    let _=stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
                        Content-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes());
                }
                Err(error) if error.kind()==std::io::ErrorKind::WouldBlock => std::thread::sleep(std::time::Duration::from_millis(2)),
                Err(_) => break,
            }
        });
        Self {base,stop,thread:Some(thread)}
    }
}
impl Drop for Page {
    fn drop(&mut self) {
        self.stop.store(true,std::sync::atomic::Ordering::Release);
        if let Some(thread)=self.thread.take() { let _=thread.join(); }
    }
}

/// Records which tools returned a successful result through the real router.
struct Exercise<'a> { runtime: &'a WorkstationRuntime, observed: BTreeSet<String> }
impl Exercise<'_> {
    fn raw(&self, name: &str, arguments: Value) -> Value { call(self.runtime,name,arguments) }
    fn ok(&mut self, name: &str, arguments: Value) -> Value {
        let response=self.raw(name,arguments.clone());
        assert!(response.get("error").is_none(), "{name} {arguments}: {response}");
        assert_ne!(response["result"]["isError"], true, "{name} {arguments}: {response}");
        self.observed.insert(name.to_owned());
        let result=&response["result"];
        if result.get("structuredContent").is_some_and(|value|!value.is_null()) {
            return result["structuredContent"].clone();
        }
        let text=result["content"][0]["text"].as_str().unwrap_or_default();
        serde_json::from_str(text).unwrap_or_else(|_|json!({"text":text}))
    }
    fn refused(&self, name: &str, arguments: Value) {
        let response=self.raw(name,arguments.clone());
        assert!(response.get("error").is_some() || response["result"]["isError"]==true,
            "{name} {arguments} must be refused: {response}");
    }
}

fn revision(value: &Value, fallback: &Value) -> i64 {
    value.get("subtask").and_then(|s|s["revision"].as_i64())
        .or_else(||value["revision"].as_i64())
        .or_else(||fallback["revision"].as_i64()).expect("revision")
}

fn descriptor_hash(descriptor: &Value) -> String {
    use sha2::{Digest, Sha256};
    let mut canonical=descriptor.clone();
    canonical.sort_all_objects();
    Sha256::digest(canonical.to_string().as_bytes()).iter().map(|byte|format!("{byte:02x}")).collect()
}

fn exercise_every_tool(os_user: bool) {
    let descriptor_path=PathBuf::from(std::env::var_os("AGENT_BRIDGE_EXTENSION_TEST_DESCRIPTOR")
        .expect("reviewed public Microsoft Learn microsoft_docs_search descriptor"));
    let descriptor:Value=serde_json::from_slice(&std::fs::read(&descriptor_path).unwrap()).unwrap();
    assert_eq!(descriptor["name"],"microsoft_docs_search");
    let git=PathBuf::from("C:/Program Files/Git/cmd/git.exe");
    let git_pin=agent_bridge_commands::EnvironmentVerifier::verify_executable(
        &agent_bridge_commands::FsEnvironmentVerifier,&git).expect("pinned Git for Windows");
    let mut bench=bench(os_user,true,|settings,workspace| {
        std::fs::write(workspace.join("witness.txt"),"CATALOGUE46_EVERY_TOOL_WITNESS").unwrap();
        std::fs::create_dir(workspace.join("skill-src")).unwrap();
        std::fs::write(workspace.join("skill-src/SKILL.md"),
            "---\nname: catalogue-skill\ndescription: qualification\nversion: 0.1.0\n---\n# Catalogue skill body\n").unwrap();
        std::fs::write(settings.join("commands.json"),json!({"version":1,"programs":{
            "git-version":{"executable":git,"sha256":git_pin.sha256,"preapproved":true}}}).to_string()).unwrap();
        std::fs::write(settings.join("extensions.json"),json!({"version":1,"servers":{"microsoft_learn":{
            "endpoint":"https://learn.microsoft.com/api/mcp",
            "tools":{"microsoft_docs_search":{"descriptor_sha256":descriptor_hash(&descriptor),
                "descriptor":descriptor,"parameters":{"query":{"type":"search_terms"}}}}}}}).to_string()).unwrap();
    });
    let workspace=bench.workspace.clone();
    let path=|relative: &str| -> Value {
        if os_user { json!(workspace.join(relative)) } else { json!(relative) }
    };
    // The first attachment observes the real schema digest; the second runs
    // every tool under the exact sealed catalogue.
    let first=attach(&bench);
    bench.selected["catalogue_sha256"]=json!(listed_digest(&first));
    shutdown(first,&bench.db);
    let attached=attach(&bench);
    let catalogue:Vec<_>=attached.runtime.router.published_tools().into_iter().cloned().collect();
    attached.manifest.verify_catalogue(&catalogue).expect("exact observed schema digest");
    let mut run=Exercise {runtime:&attached.runtime,observed:BTreeSet::new()};

    let status=run.ok("agent_bridge_status",json!({}));
    assert_eq!(status["total_tools"],46);
    assert_eq!(run.ok("desktop_policy_status",json!({}))["filesystem_scope"],if os_user {"os-user"} else {"workspace"});

    // Files: metadata, listing, search, then create, write, edit and move
    // with one-use observations.
    assert!(run.ok("desktop_get_file_info",json!({"path":path("witness.txt")})).to_string().contains("witness.txt"));
    assert!(run.ok("desktop_list_directory",json!({"path":path("."),"depth":1})).to_string().contains("witness.txt"));
    assert!(run.ok("desktop_search",json!({"path":path("."),"pattern":"EVERY_TOOL","search_type":"content"})).to_string().contains("witness.txt"));
    run.ok("desktop_create_directory",json!({"path":path("made")}));
    assert!(workspace.join("made").is_dir());
    run.ok("desktop_write_file",json!({"path":path("made/new.txt"),"content":"alpha","mode":"rewrite"}));
    let observed=run.ok("desktop_read_file",json!({"path":path("made/new.txt")}));
    assert_eq!(observed["content"],"alpha");
    run.ok("desktop_edit_file",json!({"path":path("made/new.txt"),"old_string":"alpha","new_string":"beta",
        "observation_id":observed["observation_id"]}));
    assert_eq!(std::fs::read_to_string(workspace.join("made/new.txt")).unwrap(),"beta");
    let observed=run.ok("desktop_read_file",json!({"path":path("made/new.txt")}));
    run.ok("desktop_move_file",json!({"source":path("made/new.txt"),"destination":path("made/moved.txt"),
        "source_observation_id":observed["observation_id"]}));
    assert!(!workspace.join("made/new.txt").exists());
    assert_eq!(std::fs::read_to_string(workspace.join("made/moved.txt")).unwrap(),"beta");

    // Artifacts.
    let published=run.ok("desktop_artifact_manage",json!({"action":"publish","path":path("witness.txt")}));
    let artifact=published["artifact"]["artifact_id"].clone();
    assert!(artifact.is_string(),"{published}");
    assert!(run.ok("desktop_artifact_manage",json!({"action":"list"})).to_string().contains(artifact.as_str().unwrap()));
    run.ok("desktop_artifact_manage",json!({"action":"get","artifact_id":artifact}));
    assert!(run.ok("desktop_artifact_manage",json!({"action":"read","artifact_id":artifact,"encoding":"utf8"}))
        .to_string().contains("CATALOGUE46_EVERY_TOOL_WITNESS"));
    run.ok("desktop_artifact_manage",json!({"action":"delete","artifact_id":artifact}));
    run.refused("desktop_artifact_manage",json!({"action":"get","artifact_id":artifact}));

    // Documentary skills. Skill sources stay workspace-relative in both
    // file scopes.
    assert_eq!(run.ok("desktop_skill_manage",json!({"action":"validate","source_path":"skill-src","name":"catalogue-skill"}))["valid"],true);
    run.ok("desktop_skill_manage",json!({"action":"install","source_path":"skill-src","name":"catalogue-skill","activate":true}));
    assert!(run.ok("desktop_skill_manage",json!({"action":"list"})).to_string().contains("catalogue-skill"));
    run.ok("desktop_skill_manage",json!({"action":"get","name":"catalogue-skill"}));
    assert!(run.ok("desktop_skill_manage",json!({"action":"read","name":"catalogue-skill"}))["content"]
        .as_str().unwrap().contains("Catalogue skill body"));

    // Fixed project commands.
    assert_eq!(run.ok("desktop_list_allowed_commands",json!({}))["commands"],json!(["git-version"]));
    let version=run.ok("agent_bridge_project_command",json!({"command":"git-version"}));
    assert_eq!(version["exit_code"],0,"{version}");
    assert!(version["stdout"].as_str().unwrap().starts_with("git version"),"{version}");

    // Owned processes: interactive input, bounded reads and termination.
    let started=run.ok("desktop_start_process",json!({"command":"$line=[Console]::In.ReadLine(); \"got:$line\"",
        "shell":"powershell","timeout_ms":1000}));
    let session=started["session_id"].as_str().expect("process session").to_owned();
    let mut output=run.ok("desktop_interact_process",json!({"session_id":session,"input":"AB46\n","timeout_ms":5000}))
        .to_string();
    let deadline=std::time::Instant::now()+std::time::Duration::from_secs(15);
    while !output.contains("got:AB46") {
        assert!(std::time::Instant::now()<deadline,"missing interactive echo: {output}");
        output.push_str(&run.ok("desktop_read_process",json!({"session_id":session,"timeout_ms":1000})).to_string());
    }
    run.ok("desktop_read_process",json!({"session_id":session,"timeout_ms":250}));
    let sleeper=run.ok("desktop_start_process",json!({"command":"Start-Sleep -Seconds 60","shell":"powershell","timeout_ms":250}));
    run.ok("desktop_terminate_process",json!({"session_id":sleeper["session_id"]}));

    // Missions shared by two contexts, including subtasks and transfer.
    let first=run.ok("agent_bridge_context_create",json!({}));
    let second=run.ok("agent_bridge_context_create",json!({}));
    let (h1,h2)=(first["context_handle"].clone(),second["context_handle"].clone());
    let mission=run.ok("agent_bridge_mission_create",json!({"actor_context_handle":h1,
        "goal":"Catalogue46 mission","idempotency_key":"catalogue46"}));
    let mid=mission["mission_id"].clone();
    assert_eq!(run.ok("agent_bridge_mission_get",json!({"actor_context_handle":h1,"mission_id":mid}))["mission_id"],mid);
    assert!(run.ok("agent_bridge_mission_list",json!({"actor_context_handle":h1,"limit":10})).to_string().contains(mid.as_str().unwrap()));
    let observe=|run:&mut Exercise|run.ok("agent_bridge_mission_observe",json!({"actor_context_handle":h1,"mission_id":mid}));
    let rev=revision(&observe(&mut run),&mission);
    run.ok("agent_bridge_mission_grant",json!({"actor_context_handle":h1,"mission_id":mid,"if_revision":rev,
        "target_context_id":second["context_id"]}));
    let rev=revision(&observe(&mut run),&mission);
    run.ok("agent_bridge_mission_attach",json!({"actor_context_handle":h2,"mission_id":mid,"if_revision":rev}));
    let rev=revision(&observe(&mut run),&mission);
    run.ok("agent_bridge_mission_checkpoint",json!({"actor_context_handle":h1,"mission_id":mid,"if_revision":rev,
        "summary":"catalogue46 checkpoint"}));
    assert!(run.ok("agent_bridge_mission_checkpoints",json!({"actor_context_handle":h2,"mission_id":mid,"limit":10}))
        .to_string().contains("catalogue46 checkpoint"));
    let subtask=run.ok("agent_bridge_mission_subtask_create",json!({"actor_context_handle":h1,"mission_id":mid,
        "goal":"Catalogue46 subtask","idempotency_key":"catalogue46-sub"}));
    let sid=subtask.get("subtask").map(|s|s["subtask_id"].clone()).unwrap_or_else(||subtask["subtask_id"].clone());
    let assigned=run.ok("agent_bridge_mission_subtask_assign",json!({"actor_context_handle":h1,"mission_id":mid,
        "subtask_id":sid,"if_revision":revision(&subtask,&subtask),"idempotency_key":"catalogue46-assign",
        "assignee_context_id":second["context_id"]}));
    let progressed=run.ok("agent_bridge_mission_subtask_update",json!({"actor_context_handle":h2,"mission_id":mid,"subtask_id":sid,
        "if_revision":revision(&assigned,&assigned),"idempotency_key":"catalogue46-update","status":"in_progress"}));
    run.ok("agent_bridge_mission_subtask_update",json!({"actor_context_handle":h2,"mission_id":mid,"subtask_id":sid,
        "if_revision":revision(&progressed,&progressed),"idempotency_key":"catalogue46-done","status":"completed",
        "summary":"catalogue46 subtask done"}));
    assert!(run.ok("agent_bridge_mission_subtask_list",json!({"actor_context_handle":h1,"mission_id":mid,"limit":10}))
        .to_string().contains(sid.as_str().unwrap()));
    let rev=revision(&observe(&mut run),&mission);
    run.ok("agent_bridge_mission_transfer",json!({"actor_context_handle":h1,"mission_id":mid,"if_revision":rev,
        "target_context_id":second["context_id"]}));
    let rev=revision(&run.ok("agent_bridge_mission_observe",json!({"actor_context_handle":h2,"mission_id":mid})),&mission);
    assert_eq!(run.ok("agent_bridge_mission_complete",json!({"actor_context_handle":h2,"mission_id":mid,"if_revision":rev,
        "idempotency_key":"catalogue46-complete"}))["status"],"completed");

    // Task Room lifecycle, then an exact historical import into a mission.
    let room=run.ok("desktop_task_manage",json!({"action":"context_create","context_label":"Catalogue46 Room"}));
    let handle=room["context_handle"].clone();
    assert!(run.ok("desktop_task_manage",json!({"action":"context_discover","limit":10})).to_string()
        .contains(room["context_id"].as_str().unwrap()));
    let task=run.ok("desktop_task_manage",json!({"action":"create","context_handle":handle,"title":"Catalogue46 task",
        "goal":"Exercise every Task Room action","steps":[{"id":"s1","title":"Step","phase":"execute"}],
        "completion_conditions":["all pass"]}));
    let tid=task["task"]["task_id"].clone();
    let source=run.ok("desktop_task_manage",json!({"action":"create","context_handle":handle,"title":"Catalogue46 source",
        "goal":"Historical import source","steps":[{"id":"s1","title":"Historical only"}]}));
    let imported=run.ok("agent_bridge_task_import",json!({"actor_context_handle":h1,"context_id":room["context_id"],
        "context_handle":handle,"task_id":source["task"]["task_id"]}));
    assert!(imported["mission_id"].is_string(),"{imported}");
    run.ok("desktop_task_manage",json!({"action":"list","context_handle":handle,"limit":10}));
    run.ok("desktop_task_manage",json!({"action":"checkpoint","context_handle":handle,"task_id":tid,
        "completed_step_ids":["s1"],"summary":"verified","verified_facts":["catalogue46"]}));
    assert_eq!(run.ok("desktop_task_manage",json!({"action":"block","context_handle":handle,"task_id":tid,
        "summary":"waiting"}))["task"]["status"],"blocked");
    assert_eq!(run.ok("desktop_task_manage",json!({"action":"resume","context_handle":handle,"task_id":tid,
        "summary":"resumed"}))["task"]["status"],"active");
    run.ok("desktop_task_manage",json!({"action":"final_review","context_handle":handle,"task_id":tid,
        "review_status":"pass","summary":"approved"}));
    assert_eq!(run.ok("desktop_task_manage",json!({"action":"complete","context_handle":handle,"task_id":tid,
        "summary":"closed"}))["task"]["status"],"completed");
    run.ok("desktop_task_manage",json!({"action":"get","context_handle":handle,"task_id":tid}));
    let rotated=run.ok("desktop_task_manage",json!({"action":"context_reattach","context_handle":handle,
        "context_id":room["context_id"],"confirm_label":"Catalogue46 Room"}));
    assert_ne!(rotated["context_handle"],handle);
    run.refused("desktop_task_manage",json!({"action":"list","context_handle":handle}));

    // Extensions: cached inspection, a queued local proposal, and one real
    // public Microsoft Learn search through the pinned descriptor.
    assert!(run.ok("desktop_mcp_manage",json!({"action":"list"})).to_string().contains("microsoft_learn"));
    run.ok("desktop_mcp_manage",json!({"action":"inspect","name":"microsoft_learn"}));
    run.ok("desktop_mcp_manage",json!({"action":"refresh","name":"microsoft_learn"}));
    assert!(run.ok("desktop_mcp_tool_search",json!({"query":"docs"})).to_string().contains("microsoft_learn:microsoft_docs_search"));
    assert_eq!(run.ok("desktop_mcp_tool_inspect",json!({"name":"microsoft_learn:microsoft_docs_search"}))["name"],
        "microsoft_learn:microsoft_docs_search");
    let searched=run.ok("desktop_mcp_tool_call",json!({"name":"microsoft_learn:microsoft_docs_search",
        "arguments":{"query":"Windows virtual desktops"}}));
    assert!(searched.to_string().contains("learn.microsoft.com"),"{searched}");

    // Owned headless browser on a loopback page.
    let page=Page::start();
    let browser=run.ok("desktop_browser_session",json!({"action":"start","url":page.base,"headless":true,
        "viewport":{"width":800,"height":600}}));
    let bid=browser["session_id"].as_str().expect("browser session").to_owned();
    let view=run.ok("desktop_browser_snapshot",json!({"session_id":bid,"screenshot":false}));
    assert!(view.to_string().contains("Catalogue46 browser witness"),"{view}");
    let acted=run.ok("desktop_browser_act",json!({"session_id":bid,"browser_observation_id":view["browser_observation_id"],
        "actions":[{"type":"click","selector":"#click"}],"screenshot":false}));
    assert!(acted.to_string().contains("clicked46"),"{acted}");
    run.ok("desktop_browser_session",json!({"action":"new_page","session_id":bid,"url":format!("{}/next",page.base)}));
    assert_eq!(run.ok("desktop_browser_session",json!({"action":"list"}))["count"],1);
    run.ok("desktop_browser_session",json!({"action":"close","session_id":bid}));
    drop(page);

    // Native UI Automation on the pinned passive WPF fixture: discovery,
    // semantic tree and one background invoke with an observed effect.
    let fixture_root=bench.fixture.root.join("native-fixture");
    std::fs::create_dir(&fixture_root).unwrap();
    let state=fixture_root.join("state.json");
    let (executable,_image_pin)=crate::test_process_fixture::native_gui_fixture();
    let mut child=crate::owned_children::OwnedChild::spawn(&crate::owned_children::ChildSpec {
        cwd:executable.parent().unwrap().to_path_buf(),executable,
        arguments:vec![state.clone().into_os_string(),"--passive".into()],env_overrides:Default::default()}).unwrap();
    let read_state=||std::fs::read(&state).ok().and_then(|bytes|serde_json::from_slice::<Value>(&bytes).ok()).unwrap_or(Value::Null);
    let wait_state=|condition:&dyn Fn(&Value)->bool| {
        let until=std::time::Instant::now()+std::time::Duration::from_secs(10);
        loop {
            let value=read_state();
            if condition(&value) { return value; }
            assert!(std::time::Instant::now()<until,"fixture condition failed: {value}");
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    };
    wait_state(&|value|value["hwnd"].as_u64().is_some_and(|h|h>0) && value["rendered"]==true);
    let windows=run.ok("desktop_ui_windows",json!({"app":"agent-bridge-native-fixture"}));
    let title=format!("Agent Bridge Native Fixture {}",child.root_pid());
    let window=windows.as_array().unwrap().iter().find(|window|window["title"]==title)
        .unwrap_or_else(||panic!("fixture window missing: {windows}"))["window_id"].clone();
    let tree=run.ok("desktop_ui_snapshot",json!({"window_id":window,"include_tree":true,"include_screenshot":false,
        "interactive_only":false,"max_elements":200}));
    let invoke=tree["elements"].as_array().unwrap().iter().find(|element|element["automationId"]=="InvokeButton")
        .unwrap_or_else(||panic!("InvokeButton missing: {tree}"))["selector"].clone();
    let invoked=run.ok("desktop_ui_action",json!({"window_id":window,"computer_observation_id":tree["computer_observation_id"],
        "action":"invoke","selector":invoke,"observe_after":"none","settle_ms":50}));
    assert_eq!(invoked["succeeded"],true,"{invoked}");
    wait_state(&|value|value["invoked"]==1);
    child.terminate().unwrap();
    let until=std::time::Instant::now()+std::time::Duration::from_secs(5);
    while child.finish().unwrap().is_none() {
        assert!(std::time::Instant::now()<until,"fixture did not exit");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // No agent desktop pool is selected: status is real, start is refused.
    assert_eq!(run.ok("desktop_agent_desktop",json!({"action":"status"}))["configured"],false);
    run.refused("desktop_agent_desktop",json!({"action":"start","desktop_number":1}));

    let expected: BTreeSet<String>=COMPLETE_TOOL_NAMES.iter().map(|name|name.to_string()).collect();
    let missing: Vec<_>=expected.difference(&run.observed).collect();
    assert!(missing.is_empty(),"tools without an observed successful call: {missing:?}");
    assert_eq!(run.observed.len(),46);
    drop(run);
    shutdown(attached,&bench.db);
    eprintln!("every_tool os_user={os_user}: 46/46 tools returned an observed successful result");
}
