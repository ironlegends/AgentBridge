//! Single bounded, operator-selected preparation walkthrough. Never deploy.
#![allow(dead_code, unused_imports)]
#![recursion_limit = "256"]

#[cfg(not(windows))]
fn main() {
    eprintln!("native_chrome_navigation example requires Windows");
}

#[cfg(windows)]
#[path = "../src/browser_docs.rs"]
mod browser_docs;

#[cfg(windows)]
mod win_demo {
    use crate::browser_docs::interactive::{
        approve_local_with_transfers, LocalInteractiveSelection,
        LocalTransferSelection, NativeProvider,
    };
    use serde_json::{json, Value};
    use std::path::PathBuf;

    fn send(p: &mut NativeProvider, name: &str, args: Value) -> Result<Value,String> {
        let map=args.as_object().ok_or("Invalid local demo args")?.clone();
        p.dispatch(name,map).map_err(|e|format!("{name}: {:?}",e.kind()))
    }
    fn wanted_ref(observation:&Value, name:&str) -> Result<String,String> {
        observation["interactive_elements"].as_array()
            .and_then(|elements|elements.iter().find(|element|
                element["name"].as_str().is_some_and(|s|s.eq_ignore_ascii_case(name))))
            .and_then(|element|element["ref"].as_str())
            .map(str::to_owned).ok_or_else(||format!("Missing live DOM ref: {name}"))
    }
    fn act(p:&mut NativeProvider, session:&str, obs:&Value, operation:Value)->Result<Value,String>{
        send(p,"desktop_browser_act",json!({
            "session_id":session,
            "browser_observation_id":obs["browser_observation_id"],
            "actions":[operation],
            "max_text_chars":12000,
            "screenshot":false
        }))
    }
    fn run(root: PathBuf) -> Result<Value,String> {
        let fixture="rust/cli/src/browser_docs/interaction_fixture.html";
        let approval=approve_local_with_transfers(LocalInteractiveSelection {
            workspace:root,
            pages:vec![fixture.to_owned()],
            allowed_origins:vec![],
        },LocalTransferSelection{
            upload_files:vec![
                "rust/cli/src/browser_docs/transfer_witness.txt".into()
            ],
            output_dir:"rust/cli/src/browser_docs/output".into(),
        }).map_err(|e|format!("Local transfer selection: {:?}",e.kind()))?;
        let mut browser=NativeProvider::new(approval);
        let session=send(&mut browser,"desktop_browser_session",json!({"action":"start"}))?;
        let id=session["session_id"].as_str().ok_or("Missing session id")?.to_owned();
        let mut snap=send(&mut browser,"desktop_browser_snapshot",
            json!({"session_id":id,"max_text_chars":12000,"screenshot":false}))?;
        let initial_title=snap["title"].as_str().unwrap_or("").to_owned();
        if !initial_title.contains("Interactive Project Fixture") {
            return Err("Chrome did not render the selected project page".into());
        }
        let first_observed=snap["interactive_elements"].as_array().map_or(0,Vec::len);
        let screenshot=send(&mut browser,"desktop_browser_snapshot",json!({
            "session_id":id,"screenshot":true,"max_text_chars":12000
        }))?;
        let screenshot_bytes=screenshot["_screenshot_png_base64"].as_str()
            .map_or(0,str::len);
        if screenshot_bytes<1000 {return Err("Chrome screenshot did not return image data".into());}
        let found=send(&mut browser,"desktop_browser_snapshot",json!({
            "session_id":id,"mode":"find","find_query":"Agent Bridge Project Browser",
            "screenshot":false
        }))?;
        if found["matches"].as_array().is_none_or(Vec::is_empty) {
            return Err("Live document find did not locate the heading".into());
        }
        let link=wanted_ref(&found,"details")?;
        snap=act(&mut browser,&id,&found,json!({"type":"hover","ref":link}))?;
        let alias=wanted_ref(&snap,"Alias")?;
        snap=act(&mut browser,&id,&snap,json!({"type":"fill","ref":alias,"value":"Bridge"}))?;
        let alias=wanted_ref(&snap,"Alias")?;
        snap=act(&mut browser,&id,&snap,json!({"type":"type_text","ref":alias,"value":" Demo"}))?;
        let check=wanted_ref(&snap,"confirmed")?;
        snap=act(&mut browser,&id,&snap,json!({"type":"set_checked","ref":check,"checked":true}))?;
        let topic=wanted_ref(&snap,"topic")?;
        snap=act(&mut browser,&id,&snap,json!({"type":"select","ref":topic,"value":"automation"}))?;
        let apply=wanted_ref(&snap,"apply")?;
        snap=act(&mut browser,&id,&snap,json!({"type":"click","ref":apply}))?;
        let result=snap["text"].as_str().unwrap_or("").to_owned();
        if !result.contains("Result: alias=Bridge Demo; topic=automation; confirmed=true") {
            return Err("Rendered live DOM lacks the actual local form result".into());
        }
        snap=act(&mut browser,&id,&snap,json!({
            "type":"wait_text","text":"Result: alias=Bridge Demo; topic=automation; confirmed=true"
        }))?;
        snap=act(&mut browser,&id,&snap,json!({
            "type":"wait_selector","selector":"#result"
        }))?;
        snap=act(&mut browser,&id,&snap,json!({"type":"press","key":"Tab"}))?;
        snap=act(&mut browser,&id,&snap,json!({"type":"scroll","direction":"down"}))?;
        snap=act(&mut browser,&id,&snap,json!({"type":"scroll","direction":"up"}))?;
        snap=act(&mut browser,&id,&snap,json!({"type":"wait","delay_ms":50}))?;
        let drag_source=wanted_ref(&snap,"Drag source")?;
        let drag_target=wanted_ref(&snap,"Drop target")?;
        let drag_attempt=act(&mut browser,&id,&snap,json!({
            "type":"drag","source_ref":drag_source,"target_ref":drag_target
        }));
        let drag_verified=drag_attempt.as_ref().ok()
            .and_then(|v|v["text"].as_str())
            .is_some_and(|text|text.contains("Drag: completed locally"));
        snap=match drag_attempt {
            Ok(observed)=>observed,
            Err(_)=>send(&mut browser,"desktop_browser_snapshot",json!({
                "session_id":id,"screenshot":false
            }))?
        };
        let witness=wanted_ref(&snap,"Witness upload")?;
        snap=act(&mut browser,&id,&snap,json!({
            "type":"set_files","ref":witness,
            "files":["rust/cli/src/browser_docs/transfer_witness.txt"]
        }))?;
        let selected=snap["transfer"].clone();
        let expected_upload=format!("Upload: transfer_witness.txt ({} bytes)",
            selected["size_bytes"].as_u64().ok_or("Witness upload size missing")?);
        if selected["action"]!="set_files"
            || selected["size_bytes"].as_u64()!=Some(71)
            || !snap["text"].as_str().is_some_and(|t|t.contains(&expected_upload)) {
            return Err("Witness selection not reflected in live Chrome DOM".into());
        }
        let download=wanted_ref(&snap,"Download witness")?;
        snap=act(&mut browser,&id,&snap,json!({
            "type":"download","ref":download
        }))?;
        let downloaded=snap["transfer"].clone();
        if downloaded["action"]!="download"
            || downloaded["size_bytes"].as_u64().is_none_or(|n|n<20||n>1024*1024)
            || !snap["text"].as_str().is_some_and(|text|
                text.contains("Download: generated locally")) {
            return Err("Chrome project download not observed and verified".into());
        }
        let link=wanted_ref(&snap,"details")?;
        snap=act(&mut browser,&id,&snap,json!({"type":"click","ref":link}))?;
        let after_link=snap["text"].as_str().unwrap_or("").to_owned();
        if !after_link.contains("Route: details") {
            return Err("Live link click did not update the document route".into());
        }
        snap=act(&mut browser,&id,&snap,json!({"type":"navigation","direction":"back"}))?;
        let back=snap["text"].as_str().unwrap_or("").to_owned();
        if !back.contains("Route: overview") {
            return Err("Browser history back not reflected in actual rendered page".into());
        }
        snap=act(&mut browser,&id,&snap,json!({"type":"navigation","direction":"forward"}))?;
        let forward=snap["text"].as_str().unwrap_or("").to_owned();
        if !forward.contains("Route: details") {
            return Err("Browser history forward not reflected in actual rendered page".into());
        }
        snap=act(&mut browser,&id,&snap,json!({"type":"navigation","direction":"reload"}))?;
        let reloaded=snap["title"].as_str().unwrap_or("").to_owned();
        if reloaded!=initial_title {
            return Err("Reload did not preserve actual document title".into());
        }
        snap=act(&mut browser,&id,&snap,json!({
            "type":"goto",
            "url":"bridge-project:///rust/cli/src/browser_docs/interaction_fixture.html"
        }))?;
        let _=act(&mut browser,&id,&snap,json!({
            "type":"wait_url",
            "url":"bridge-project:///rust/cli/src/browser_docs/interaction_fixture.html"
        }))?;
        let old_page=session["page_id"].as_str().ok_or("First page id missing")?.to_owned();
        let new_page=send(&mut browser,"desktop_browser_session",json!({
            "action":"new_page","session_id":id,
            "url":"bridge-project:///rust/cli/src/browser_docs/interaction_fixture.html"
        }))?;
        let second_page=new_page["page_id"].as_str().ok_or("Second page missing")?.to_owned();
        let second_snap=send(&mut browser,"desktop_browser_snapshot",json!({
            "session_id":id,"page_id":second_page,"screenshot":false
        }))?;
        if second_snap["title"].as_str()!=Some(initial_title.as_str()) {
            return Err("Second real Chrome tab did not render the project page".into());
        }
        send(&mut browser,"desktop_browser_session",json!({
            "action":"select_page","session_id":id,"page_id":old_page
        }))?;
        send(&mut browser,"desktop_browser_session",json!({
            "action":"close_page","session_id":id,"page_id":second_page
        }))?;
        let listed=send(&mut browser,"desktop_browser_session",
            json!({"action":"list"}))?;
        if listed["sessions"][0]["tabs"]!=1 {return Err("Tab closure was not observed".into());}
        let closed=send(&mut browser,"desktop_browser_session",
            json!({"action":"close","session_id":id}))?;
        if closed["temporary_profile_removed"] != true {
            return Err("Owned profile cleanup not verified".into());
        }
        Ok(json!({
            "kind":"rust_native_chrome_cdp_project_walkthrough_v1",
            "browser_engine":"installed_chrome",
            "control_transport":"private_cdp_pipe",
            "project_fixture":fixture,
            "session_started":true,
            "initial_title":initial_title,
            "live_elements":first_observed,
            "full_snapshot":"ok","find_snapshot":"ok",
            "screenshot":"ok","screenshot_base64_chars":screenshot_bytes,
            "hover":"ok","fill":"ok","type_text":"ok",
            "set_checked":"ok","select":"ok","click_form":"ok",
            "wait_text":"ok","wait_selector":"ok","press":"ok",
            "scroll_down":"ok","scroll_up":"ok","wait":"ok",
            "drag":if drag_verified {"ok"} else {"unqualified"},
            "set_files":"ok",
            "set_files_name":selected["name"],
            "set_files_size":selected["size_bytes"],
            "set_files_sha256":selected["sha256"],
            "set_files_dom_verified":true,
            "download":"ok",
            "download_output_path":downloaded["relative_output_path"],
            "download_size":downloaded["size_bytes"],
            "download_sha256":downloaded["sha256"],
            "download_readback_verified":true,
            "live_form_result":"Result: alias=Bridge Demo; topic=automation; confirmed=true",
            "click_link":"ok","history_back":"ok","history_forward":"ok","reload":"ok",
            "goto":"ok","wait_url":"ok",
            "new_page":"ok","select_page":"ok","close_page":"ok","list":"ok",
            "session_closed":closed["closed"],
            "temporary_profile_removed":closed["temporary_profile_removed"],
            "owned_chrome_exited":closed["owned_chrome_exited"],
            "personal_profile_used":false,
            "external_form_submission":false,
            "node_playwright_required":false
        }))
    }
    pub fn main()->std::process::ExitCode{
        let mut args=std::env::args_os().skip(1);
        let Some(workspace)=args.next()else{
            eprintln!("Exact project directory required");
            return std::process::ExitCode::FAILURE;
        };
        if args.next().is_some(){return std::process::ExitCode::FAILURE;}
        match run(PathBuf::from(workspace)){
            Ok(result)=>{println!("{result}");std::process::ExitCode::SUCCESS}
            Err(e)=>{eprintln!("PREPARATION_UNQUALIFIED: {e}");std::process::ExitCode::FAILURE}
        }
    }
}

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    win_demo::main()
}
