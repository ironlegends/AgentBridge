use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Fake {
    identity: Arc<Mutex<String>>,
    writes: Arc<AtomicUsize>,
    last_value: Arc<Mutex<String>>,
}
impl Backend for Fake {
    fn inspect(&mut self) -> io::Result<NativeWindow> {
        Ok(NativeWindow { identity:self.identity.lock().unwrap().clone(), x:1, y:2,
            width:300, height:200, enabled:true })
    }
    #[cfg(any(target_os="linux",target_os="macos"))]
    fn confirm(&mut self, _: &DedicatedWindow) -> io::Result<()> { Ok(()) }
    fn capabilities(&self) -> Capabilities {
        Capabilities { backend:"fixture", tree:"fixture_controls",
            actions:&["wait","invoke","set_value"], screenshot:false }
    }
    fn snapshot(&mut self, options: SnapshotOptions) -> io::Result<NativeSnapshot> {
        Ok(NativeSnapshot { elements:if options.tree {vec![json!({"ref":"control:1","role":"text"})]}else{vec![]},
            truncated:false, screenshot:None, screenshot_status:"unsupported" })
    }
    fn action(&mut self, action:&Action) -> io::Result<Value> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if let Action::SetValue { value, .. }=action { *self.last_value.lock().unwrap()=value.clone(); }
        Ok(json!({"completed":true}))
    }
}
fn fixture() -> (Session, Arc<Mutex<String>>, Arc<AtomicUsize>, Arc<Mutex<String>>) {
    let identity=Arc::new(Mutex::new("original-window".to_owned()));
    let writes=Arc::new(AtomicUsize::new(0));
    let value=Arc::new(Mutex::new(String::new()));
    let selection=DedicatedWindow { desktop_name:"fixture".into(),
        executable:std::env::current_exe().unwrap(), class_name:"ExactClass".into(), title:"Exact title".into() };
    let backend=Box::new(Fake { identity:identity.clone(),writes:writes.clone(),last_value:value.clone() });
    (Session {selection, backend, approved_identity:"original-window".into(),ticket:None,observation:None},
        identity,writes,value)
}
fn args(value:Value)->Map<String,Value>{value.as_object().unwrap().clone()}
fn observe(session:&mut Session)->(String,String) {
    let listed=session.windows(args(json!({}))).unwrap();
    let window=listed[0]["window_id"].as_str().unwrap().to_owned();
    let snapshot=session.snapshot(args(json!({"window_id":window}))).unwrap();
    (window,snapshot["computer_observation_id"].as_str().unwrap().to_owned())
}

#[test]
fn portable_tokens_are_single_use_and_malformed_requests_revoke_them() {
    let (mut session,_,writes,_)=fixture();
    let listed=session.windows(args(json!({}))).unwrap();
    let window=listed[0]["window_id"].as_str().unwrap();
    assert!(session.snapshot(args(json!({"window_id":window,"raw_window":1}))).is_err());
    assert!(session.snapshot(args(json!({"window_id":window}))).is_err());
    let (window,observation)=observe(&mut session);
    let action=args(json!({"action":"invoke","selector":"control:1","window_id":window,
        "computer_observation_id":observation,"observe_after":"none"}));
    assert!(session.action(action.clone()).is_ok());
    assert!(session.action(action).is_err());
    assert_eq!(writes.load(Ordering::SeqCst),1);
}

#[test]
fn portable_replacement_or_expiration_never_retargets_actions() {
    let (mut session,identity,writes,_)=fixture();
    let (window,observation)=observe(&mut session);
    *identity.lock().unwrap()="replacement-with-the-same-caption".into();
    assert!(session.action(args(json!({"action":"invoke","selector":"control:1","window_id":window,
        "computer_observation_id":observation}))).is_err());
    assert_eq!(writes.load(Ordering::SeqCst),0);
    *identity.lock().unwrap()="original-window".into();
    let (window,observation)=observe(&mut session);
    session.observation.as_mut().unwrap().issued=Instant::now()-Duration::from_secs(31);
    assert!(session.action(args(json!({"action":"invoke","selector":"control:1","window_id":window,
        "computer_observation_id":observation}))).is_err());
    assert_eq!(writes.load(Ordering::SeqCst),0);
}

#[test]
fn portable_requests_reject_external_targets_global_input_and_unadvertised_actions() {
    let (mut session,_,writes,_)=fixture();
    for extra in [
        json!({"pid":123}),json!({"agent_desktop_lease_id":"unowned"}),json!({"app":"another-app"}),
    ] {
        assert!(session.windows(args(extra)).is_err());
    }
    for extra in [
        json!({"action":"send_keys","keys":"Control+Q"}),
        json!({"action":"invoke","selector":"control:1","allow_system_keys":true}),
        json!({"action":"invoke","selector":"control:1","transport":"send-input"}),
        json!({"action":"set_value","selector":"control:1","value":"x","script":"do shell script"}),
    ] {
        let (window,observation)=observe(&mut session);
        let mut action=args(extra);
        action.insert("window_id".into(),json!(window));
        action.insert("computer_observation_id".into(),json!(observation));
        assert!(session.action(action).is_err());
    }
    assert_eq!(writes.load(Ordering::SeqCst),0);
}

#[test]
fn portable_values_remain_literal_and_success_issues_a_fresh_observation() {
    let (mut session,_,writes,last)=fixture();
    let (window,observation)=observe(&mut session);
    let text="quotes \" ; do shell script \"ignored\" \n $HOME €";
    let result=session.action(args(json!({"action":"set_value","selector":"control:1","value":text,
        "window_id":window,"computer_observation_id":observation,"observe_after":"tree"}))).unwrap();
    assert_eq!(*last.lock().unwrap(),text);
    assert_eq!(writes.load(Ordering::SeqCst),1);
    assert_ne!(result["snapshot"]["computer_observation_id"],observation);
    assert_eq!(result["snapshot"]["window"]["window_id"],window);
}

#[test]
fn portable_catalog_advertises_only_real_scoped_tools_and_actions() {
    let (session,_,_,_)=fixture();
    let mut catalog=Vec::new();
    let mut handlers=ToolMapHandler::new();
    attach(LocalApproval { session },&mut catalog,&mut handlers);
    assert_eq!(catalog.len(),3);
    assert!(catalog.iter().all(|tool|tool.name!="desktop_agent_desktop"));
    let action=catalog.iter().find(|tool|tool.name=="desktop_ui_action").unwrap();
    assert_eq!(action.input_schema["properties"]["action"]["enum"],json!(["wait","invoke","set_value"]));
}

#[test]
fn portable_selection_rejects_aliases_unbounded_labels_and_controls() {
    let (session,_,_,_)=fixture();
    let mut selection=session.selection;
    selection.desktop_name="macos".into();
    assert!(selection.validate().is_ok());
    selection.title="bad\ncaption".into();
    assert!(selection.validate().is_err());
    selection.title="a".repeat(257);
    assert!(selection.validate().is_err());
    selection.title="exact".into();
    selection.executable=PathBuf::from("relative/path");
    assert!(selection.validate().is_err());
}
