//! Opt-in composition test of the real unified providers. Never opens the
//! operator's settings, OAuth state, personal browser, or desktop lease.
use super::*;
use crate::capability_manifest::{catalogue_digest, ManifestContext, QualifiedManifest, COMPLETE_TOOL_NAMES};
use crate::provider_owner::ProviderOwner;
use std::collections::BTreeSet;

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
    let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    let temp = temp.to_str().and_then(|s|s.strip_prefix(r"\\?\")).map(PathBuf::from).unwrap_or(temp);
    let fixture = Fixture {root:temp.join(format!("ab-catalogue46-{}-{}",std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()))};
    let root=&fixture.root;
    std::fs::create_dir(root).unwrap();
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
    std::fs::write(workspace.join("witness.txt"),"CATALOGUE46_ISOLATED_WITNESS").unwrap();
    let external=root.join("outside.txt");
    std::fs::write(&external,"EXTERNAL_SYNTHETIC_BEFORE").unwrap();
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
    let mut selected=json!({"version":1,"policy_version":1,"catalogue_sha256":"0".repeat(64),
        "private_root":root.join("private"),"file_scope":{"kind":if os_user { "os-user" } else { "workspace" }},"allow_import":false,
        "browser":{"bundle_root":browser,"manifest_sha256":browser_sha,"state_root":root.join("private/browser")},
        "windows":{"bundle_root":native,"manifest_sha256":native_sha,"state_root":root.join("private/windows")},
        "agent_desktop":{"bundle_root":native,"manifest_sha256":native_sha,"state_root":root.join("private/desktops"),"desktops":[]}});
    let mut digest=String::new();
    for pass in 0..2 {
        std::fs::write(settings.join("unified-v1.json"),serde_json::to_vec(&selected).unwrap()).unwrap();
        let manifest=QualifiedManifest::load(&settings,context.clone()).expect("physical fixture manifest");
        manifest.preflight_providers().expect("real pinned bundle preflight");
        let profile=ProfileControl::new(DesktopProfile::FullyUnlocked);
        let mut supervisors=Vec::new();
        let mut providers=Vec::new();
        let runtime=unified_router(&manifest,&db,None,&settings,&extension_authority,
            profile.clone(),&mut supervisors,&mut providers).expect("all real providers must attach");
        let listed=mcp(&runtime,"tools/list",json!({}));
        let tools=listed["result"]["tools"].as_array().unwrap();
        let names: BTreeSet<_>=tools.iter().map(|t|t["name"].as_str().unwrap()).collect();
        let expected: BTreeSet<_>=COMPLETE_TOOL_NAMES.iter().copied().collect();
        eprintln!("catalogue pass={pass} count={} missing={:?} extra={:?}",tools.len(),
            expected.difference(&names).collect::<Vec<_>>(),names.difference(&expected).collect::<Vec<_>>());
        assert_eq!(tools.len(),46);
        assert_eq!(names,expected);
        let catalogue:Vec<_>=runtime.router.published_tools().into_iter().cloned().collect();
        if pass==0 {
            digest=catalogue_digest(&catalogue).unwrap();
            assert!(manifest.verify_catalogue(&catalogue).is_err(),"wrong seal must fail");
            selected["catalogue_sha256"]=json!(digest);
        } else {
            manifest.verify_catalogue(&catalogue).expect("exact observed schema digest");
            let status=text_result(call(&runtime,"agent_bridge_status",json!({})));
            assert_eq!(status["total_tools"],46);
            assert_eq!(status["families"],json!({"desktop":27,"missions_including_status":16,"project_commands":1,"historical_utilities":2,"other":0}));
            let read=call(&runtime,"desktop_read_file",json!({"path":"witness.txt"}));
            assert_ne!(read["result"]["isError"],true,"{read}");
            assert!(read.to_string().contains("CATALOGUE46_ISOLATED_WITNESS"));
            let policy=text_result(call(&runtime,"desktop_policy_status",json!({})));
            assert_eq!(policy["filesystem_scope"],if os_user { "os-user" } else { "workspace" });
            if os_user {
                let observed=text_result(call(&runtime,"desktop_read_file",json!({"path":external})));
                assert_eq!(observed["content"],"EXTERNAL_SYNTHETIC_BEFORE");
                let request=json!({"path":external,"mode":"rewrite","content":"EXTERNAL_SYNTHETIC_AFTER",
                    "observation_id":observed["observation_id"]});
                let _=text_result(call(&runtime,"desktop_write_file",request.clone()));
                assert_eq!(std::fs::read_to_string(&external).unwrap(),"EXTERNAL_SYNTHETIC_AFTER");
                assert_eq!(call(&runtime,"desktop_write_file",request)["result"]["isError"],true);
                let protected=call(&runtime,"desktop_read_file",json!({"path":settings.join("unified-v1.json")}));
                assert_eq!(protected["result"]["isError"],true);
                profile.set(DesktopProfile::FullControl).expect("downgrade outside workspace authority");
                assert_eq!(call(&runtime,"desktop_read_file",json!({"path":external}))["result"]["isError"],true);
                assert_eq!(text_result(call(&runtime,"desktop_policy_status",json!({})))["filesystem_scope"],"workspace");
                profile.set(DesktopProfile::FullyUnlocked).expect("restore locally selected ceiling");
            } else {
                assert_eq!(call(&runtime,"desktop_read_file",json!({"path":external}))["result"]["isError"],true);
            }
            let desktop=text_result(call(&runtime,"desktop_agent_desktop",json!({"action":"status"})));
            assert_eq!(desktop["configured"],false,"no live desktop pool");
            let browser=call(&runtime,"desktop_browser_session",json!({"action":"list"}));
            assert_ne!(browser["result"]["isError"],true,"{browser}");
            let ui=text_result(call(&runtime,"desktop_ui_windows",json!({"app":"ab-catalogue46-fixture-not-running"})));
            assert!(ui.as_array().unwrap().is_empty());
            profile.set(DesktopProfile::ReadOnly).expect("real provider downgrade");
            let refused=call(&runtime,"desktop_browser_session",json!({"action":"start","headless":true}));
            assert_eq!(refused["result"]["isError"],true,"no launch after downgrade");
            let status=text_result(call(&runtime,"agent_bridge_status",json!({})));
            assert_eq!(status["desktop_profile"],"read-only");
            assert_eq!(status["process_tools_enabled"],false);
        }
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
    eprintln!("catalogue_sha256={digest}; real provider attachment, MCP list, exact seal, isolated status/read and downgrade verified");
}
