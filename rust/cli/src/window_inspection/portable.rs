//! Unix adapters keep one locally approved native window. MCP never accepts a
//! PID, XID, AppleScript source, display selector, or a request for consent.
use agent_bridge_gateway::{ToolCallResult, ToolDefinition, ToolMapHandler};
use serde_json::{json, Map, Value};
use std::io;
use std::path::{Component, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(target_os="linux")]
#[path="x11.rs"]
mod native;
#[cfg(target_os="macos")]
#[path="macos.rs"]
mod native;
#[cfg(any(target_os="linux", test))]
#[path="image.rs"]
mod image;

const TTL: Duration=Duration::from_secs(30);

fn error(code:&'static str)->io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied,code)
}
fn invalid()->io::Error { error("WINDOW_INVALID_REQUEST") }
fn unsupported()->io::Error {
    io::Error::new(io::ErrorKind::Unsupported,"WINDOW_ACTION_UNSUPPORTED")
}

#[derive(Clone)]
pub struct DedicatedWindow {
    pub desktop_name:String,
    pub executable:PathBuf,
    pub class_name:String,
    pub title:String,
}
impl DedicatedWindow {
    fn validate(&self)->io::Result<()> {
        if !self.executable.is_absolute() || self.executable.file_name().is_none()
            || self.executable.components().any(|part|matches!(part,Component::ParentDir|Component::CurDir))
            || self.executable.to_str().is_none_or(|text|text.len()>4096||text.contains('\0'))
        {return Err(invalid());}
        for text in [&self.desktop_name,&self.class_name,&self.title] {
            if text.is_empty()||text.len()>256||text.chars().any(char::is_control){return Err(invalid());}
        }
        Ok(())
    }
    fn accepts_app(&self,args:&Map<String,Value>)->io::Result<()> {
        match args.get("app") {
            None=>Ok(()),
            Some(Value::String(app)) if self.executable.to_str()==Some(app.as_str())
                || self.executable.file_name().and_then(|name|name.to_str())==Some(app.as_str())=>Ok(()),
            _=>Err(invalid()),
        }
    }
}

#[derive(Clone)]
struct NativeWindow {
    // Private incarnation witness. Never exposed as an MCP target or selector.
    identity:String,
    x:i64,y:i64,width:u64,height:u64,enabled:bool,
}
#[derive(Clone,Copy)]
struct Capabilities {
    backend:&'static str,
    tree:&'static str,
    actions:&'static [&'static str],
    screenshot:bool,
}
#[derive(Clone,Copy)]
struct SnapshotOptions {
    tree:bool,
    screenshot:bool,
    #[cfg(target_os="macos")]
    interactive:bool,
    maximum:usize,
}
struct NativeSnapshot {
    elements:Vec<Value>,
    truncated:bool,
    screenshot:Option<Value>,
    screenshot_status:&'static str,
}
#[derive(Clone,Debug)]
enum Action {
    Wait{millis:u64},
    Invoke {
        #[cfg(target_os="macos")]
        selector:String,
    },
    SetValue {
        #[cfg(target_os="macos")]
        selector:String,
        #[cfg(any(target_os="macos",test))]
        value:String,
    },
    Click {
        #[cfg(target_os="linux")]
        selector:String,
    },
    SendKeys {
        #[cfg(target_os="linux")]
        selector:String,
        #[cfg(target_os="linux")]
        keys:String,
    },
}
impl Action {
    fn name(&self)->&'static str { match self {
        Self::Wait{..}=>"wait",Self::Invoke{..}=>"invoke",Self::SetValue{..}=>"set_value",
        Self::Click{..}=>"click",Self::SendKeys{..}=>"send_keys",
    }}
}
trait Backend:Send {
    fn inspect(&mut self)->io::Result<NativeWindow>;
    #[cfg(any(target_os="linux",target_os="macos"))]
    fn confirm(&mut self,selection:&DedicatedWindow)->io::Result<()>;
    fn capabilities(&self)->Capabilities;
    fn snapshot(&mut self,options:SnapshotOptions)->io::Result<NativeSnapshot>;
    fn action(&mut self,action:&Action)->io::Result<Value>;
}

pub struct LocalApproval {session:Session}

#[cfg(not(windows))]
pub fn confirm_local_selection(selection:DedicatedWindow)->io::Result<LocalApproval> {
    selection.validate()?;
    #[cfg(any(target_os="linux",target_os="macos"))]
    {
        let mut backend:Box<dyn Backend>=Box::new(native::Native::connect(&selection)?);
        let approved=backend.inspect()?.identity;
        backend.confirm(&selection)?;
        if backend.inspect()?.identity!=approved{return Err(error("WINDOW_IDENTITY_CHANGED"));}
        Ok(LocalApproval {session:Session {
            selection,backend,approved_identity:approved,ticket:None,observation:None,
        }})
    }
    #[cfg(not(any(target_os="linux",target_os="macos")))]
    {let _=selection;Err(error("WINDOW_PLATFORM_UNAVAILABLE"))}
}

struct Ticket {id:String,issued:Instant}
struct Observation {id:String,window:String,issued:Instant}
struct Session {
    selection:DedicatedWindow,
    backend:Box<dyn Backend>,
    approved_identity:String,
    ticket:Option<Ticket>,
    observation:Option<Observation>,
}
impl Session {
    fn verify(&mut self)->io::Result<NativeWindow> {
        let current=self.backend.inspect()?;
        if current.identity!=self.approved_identity{return Err(error("WINDOW_IDENTITY_CHANGED"));}
        Ok(current)
    }
    fn summary(&self,window:&NativeWindow,id:&str)->Value {
        json!({"window_id":id,"title":self.selection.title,"class_name":self.selection.class_name,
            "process_name":self.selection.executable.file_name().and_then(|name|name.to_str()),
            "x":window.x,"y":window.y,"width":window.width,"height":window.height,
            "is_foreground":true,"is_visible":true,"is_enabled":window.enabled,
            "backend":self.backend.capabilities().backend,"scoped_native_actions_only":true})
    }
    fn windows(&mut self,args:Map<String,Value>)->io::Result<Value> {
        self.ticket=None;
        self.observation=None;
        keys(&args,&["app","include_untitled"])?;
        self.selection.accepts_app(&args)?;
        bool_arg(&args,"include_untitled",false)?;
        let current=self.verify()?;
        let id=new_id()?;
        let result=json!([self.summary(&current,&id)]);
        self.ticket=Some(Ticket{id,issued:Instant::now()});
        Ok(result)
    }
    fn render(&mut self,window_id:&str,options:SnapshotOptions)->io::Result<Value> {
        let current=self.verify()?;
        let captured=self.backend.snapshot(options)?;
        self.verify()?;
        let capabilities=self.backend.capabilities();
        let id=new_id()?;
        let mut result=json!({
            "captured_at_unix_ms":SystemTime::now().duration_since(UNIX_EPOCH)
                .map_err(|_|error("WINDOW_CLOCK_UNAVAILABLE"))?.as_millis() as u64,
            "window":self.summary(&current,window_id),"elements":captured.elements,
            "elements_truncated":captured.truncated,
            "semantic_tree_status":if options.tree{capabilities.tree}else{"not_requested"},
            "screenshot_status":if options.screenshot{captured.screenshot_status}else{"not_requested"},
            "computer_observation_id":id,"supported_actions":capabilities.actions,
            "action_capability":capabilities.actions.iter().any(|action|*action!="wait"),
            "scoped_native_actions_only":true,
        });
        if let Some(screenshot)=captured.screenshot {result["screenshot"]=screenshot;}
        self.observation=Some(Observation{id,window:window_id.to_owned(),issued:Instant::now()});
        Ok(result)
    }
    fn snapshot(&mut self,args:Map<String,Value>)->io::Result<Value> {
        let ticket=self.ticket.take().ok_or_else(||error("WINDOW_TICKET_REQUIRED"))?;
        self.observation=None;
        keys(&args,&["window_id","app","include_tree","include_screenshot","interactive_only","max_elements"])?;
        if string(&args,"window_id",36)?!=ticket.id||ticket.issued.elapsed()>TTL{return Err(error("WINDOW_TICKET_STALE"));}
        self.selection.accepts_app(&args)?;
        let tree=bool_arg(&args,"include_tree",true)?;
        let screenshot=bool_arg(&args,"include_screenshot",false)?;
        // Validate the same request on every platform with a portable adapter.
        let _interactive=bool_arg(&args,"interactive_only",true)?;
        let options=SnapshotOptions {
            tree,
            screenshot,
            #[cfg(target_os="macos")]
            interactive:_interactive,
            maximum:number(&args,"max_elements",80,200)? as usize,
        };
        if options.maximum==0{return Err(invalid());}
        self.render(&ticket.id,options)
    }
    fn action(&mut self,args:Map<String,Value>)->io::Result<Value> {
        let previous=self.observation.take().ok_or_else(||error("WINDOW_OBSERVATION_REQUIRED"))?;
        self.ticket=None;
        keys(&args,&["action","window_id","computer_observation_id","selector","value","keys",
            "wait_ms","settle_ms","observe_after"])?;
        if string(&args,"window_id",36)?!=previous.window
            || string(&args,"computer_observation_id",36)?!=previous.id
            || previous.issued.elapsed()>TTL
        {return Err(error("WINDOW_OBSERVATION_STALE"));}
        let kind=string(&args,"action",32)?;
        let action=match kind {
            "wait"=>{
                if args.contains_key("selector")||args.contains_key("value")||args.contains_key("keys"){return Err(invalid());}
                Action::Wait{millis:number(&args,"wait_ms",100,10_000)?}
            }
            "invoke"|"click"=>{
                if args.contains_key("value")||args.contains_key("keys")||args.contains_key("wait_ms"){return Err(invalid());}
                let _selector=string(&args,"selector",128)?;
                if kind=="invoke" {
                    Action::Invoke {
                        #[cfg(target_os="macos")]
                        selector:_selector.into(),
                    }
                } else {
                    Action::Click {
                        #[cfg(target_os="linux")]
                        selector:_selector.into(),
                    }
                }
            }
            "set_value"=>{
                if args.contains_key("keys")||args.contains_key("wait_ms"){return Err(invalid());}
                let _value=args.get("value").and_then(Value::as_str).filter(|v|v.len()<=65536&&!v.contains('\0')).ok_or_else(invalid)?;
                let _selector=string(&args,"selector",128)?;
                Action::SetValue {
                    #[cfg(target_os="macos")]
                    selector:_selector.into(),
                    #[cfg(any(target_os="macos",test))]
                    value:_value.into(),
                }
            }
            "send_keys"=>{
                if args.contains_key("value")||args.contains_key("wait_ms"){return Err(invalid());}
                let _selector=string(&args,"selector",128)?;
                let _keys=string(&args,"keys",32)?;
                Action::SendKeys {
                    #[cfg(target_os="linux")]
                    selector:_selector.into(),
                    #[cfg(target_os="linux")]
                    keys:_keys.into(),
                }
            }
            _=>return Err(unsupported()),
        };
        if !self.backend.capabilities().actions.contains(&action.name()){return Err(unsupported());}
        let after=match args.get("observe_after") {
            None=>"tree",
            Some(Value::String(value)) if ["none","tree","screenshot","both"].contains(&value.as_str())=>value,
            _=>return Err(invalid()),
        };
        let settle=number(&args,"settle_ms",0,1000)?;
        self.verify()?;
        let mut result=if let Action::Wait{millis}=&action {
            let deadline=Instant::now()+Duration::from_millis(*millis);
            while Instant::now()<deadline {
                std::thread::sleep(deadline.saturating_duration_since(Instant::now()).min(Duration::from_millis(50)));
                self.verify()?;
            }
            json!({"completed":true})
        }else{self.backend.action(&action)?};
        result["action"]=json!(action.name());
        result["new_observation_required"]=json!(true);
        if settle>0{std::thread::sleep(Duration::from_millis(settle));}
        if after!="none" {
            match self.render(&previous.window,SnapshotOptions {
                tree:matches!(after,"tree"|"both"),screenshot:matches!(after,"screenshot"|"both"),
                #[cfg(target_os="macos")]
                interactive:true,
                maximum:80,
            }) {
                Ok(snapshot)=>result["snapshot"]=snapshot,
                Err(_)=>result["snapshot_status"]=json!("target_unavailable_after_action"),
            }
        }
        Ok(result)
    }
}
fn keys(args:&Map<String,Value>,allowed:&[&str])->io::Result<()> {
    if args.keys().any(|key|!allowed.contains(&key.as_str())){Err(invalid())}else{Ok(())}
}
fn string<'a>(args:&'a Map<String,Value>,key:&str,maximum:usize)->io::Result<&'a str>{
    args.get(key).and_then(Value::as_str)
        .filter(|text|!text.is_empty()&&text.len()<=maximum&&!text.contains('\0')).ok_or_else(invalid)
}
fn bool_arg(args:&Map<String,Value>,key:&str,default:bool)->io::Result<bool>{
    match args.get(key){None=>Ok(default),Some(Value::Bool(value))=>Ok(*value),_=>Err(invalid())}
}
fn number(args:&Map<String,Value>,key:&str,default:u64,maximum:u64)->io::Result<u64>{
    match args.get(key){None=>Ok(default),Some(value)=>value.as_u64().filter(|v|*v<=maximum).ok_or_else(invalid)}
}
fn new_id()->io::Result<String>{
    let mut bytes=[0u8;16];
    getrandom::getrandom(&mut bytes).map_err(|_|error("WINDOW_RANDOMNESS_UNAVAILABLE"))?;
    bytes[6]=(bytes[6]&15)|64;bytes[8]=(bytes[8]&63)|128;
    let text:String=bytes.iter().map(|byte|format!("{byte:02x}")).collect();
    Ok(format!("{}-{}-{}-{}-{}",&text[..8],&text[8..12],&text[12..16],&text[16..20],&text[20..]))
}
fn tool_result(result:io::Result<Value>)->ToolCallResult {
    match result{Ok(value)=>ToolCallResult::text(value.to_string()),Err(error)=>ToolCallResult::tool_error(error.to_string())}
}

pub fn attach(approval:LocalApproval,catalog:&mut Vec<ToolDefinition>,handlers:&mut ToolMapHandler) {
    let capabilities=approval.session.backend.capabilities();
    let state=Arc::new(Mutex::new(approval.session));
    let windows=Arc::clone(&state);
    handlers.register("desktop_ui_windows",move|args|Ok(tool_result(
        windows.lock().map_err(|_|error("WINDOW_STATE_UNAVAILABLE")).and_then(|mut state|state.windows(args)))));
    let snapshots=Arc::clone(&state);
    handlers.register("desktop_ui_snapshot",move|args|Ok(tool_result(
        snapshots.lock().map_err(|_|error("WINDOW_STATE_UNAVAILABLE")).and_then(|mut state|state.snapshot(args)))));
    handlers.register("desktop_ui_action",move|args|Ok(tool_result(
        state.lock().map_err(|_|error("WINDOW_STATE_UNAVAILABLE")).and_then(|mut state|state.action(args)))));
    catalog.push(ToolDefinition::new("desktop_ui_windows",Some(
        format!("List only the exact foreground window already selected and confirmed locally using {}. No discovery, new target or desktop lease.",capabilities.backend)),
        json!({"type":"object","additionalProperties":false,"properties":{
            "app":{"type":"string","minLength":1,"maxLength":4096},"include_untitled":{"type":"boolean"}
        }})));
    catalog.push(ToolDefinition::new("desktop_ui_snapshot",Some(format!(
        "One-use window ticket: bounded {}. Native identity is revalidated before and after. Selected-window capture supported: {}. No desktop/root image.",
        capabilities.tree,capabilities.screenshot)),
        json!({"type":"object","additionalProperties":false,"required":["window_id"],"properties":{
            "window_id":{"type":"string","minLength":36,"maxLength":36},"app":{"type":"string","maxLength":4096},
            "include_tree":{"type":"boolean","default":true},"include_screenshot":{"type":"boolean","default":false},
            "interactive_only":{"type":"boolean","default":true},"max_elements":{"type":"integer","minimum":1,"maximum":200}
        }})));
    catalog.push(ToolDefinition::new("desktop_ui_action",Some(format!(
        "One scoped operation from a fresh one-use observation using {}. No global input, raw PID/window, script, system keys or target selection. X11 events report dispatch, not verified application effect.",
        capabilities.backend)),
        json!({"type":"object","additionalProperties":false,"required":["action","window_id","computer_observation_id"],"properties":{
            "action":{"type":"string","enum":capabilities.actions},
            "window_id":{"type":"string","minLength":36,"maxLength":36},
            "computer_observation_id":{"type":"string","minLength":36,"maxLength":36},
            "selector":{"type":"string","minLength":1,"maxLength":128},"value":{"type":"string","maxLength":65536},
            "keys":{"type":"string","enum":["Enter","Escape","Tab","ArrowUp","ArrowDown","ArrowLeft","ArrowRight"]},
            "wait_ms":{"type":"integer","minimum":0,"maximum":10000},
            "settle_ms":{"type":"integer","minimum":0,"maximum":1000},
            "observe_after":{"type":"string","enum":["none","tree","screenshot","both"],"default":"tree"}
        }})));
}

#[cfg(test)]
#[path="portable_tests.rs"]
mod tests;
