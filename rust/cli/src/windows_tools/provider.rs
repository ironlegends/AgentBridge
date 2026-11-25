use super::{bundle::{self, Resources}, runner::Runner, WindowsToolsConfig};
use super::process_pin::ProcessPin;
use crate::agent_desktop::{AgentDesktopHandle, DesktopLease, NativeWindow};
use crate::provider_owner::ProviderOwner;
use crate::runtime::RuntimeError;
use crate::session_profile::{rank, ProfileControl};
use agent_bridge_desktop::DesktopProfile;
use agent_bridge_gateway::{ToolDefinition, ToolMapHandler, ToolCallResult, ToolContent, ToolDispatchError};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const WINDOW_TTL: Duration = Duration::from_secs(300);
const OBSERVATION_TTL: Duration = Duration::from_secs(30);
const PNG_LIMIT: usize = 32 * 1024 * 1024;
static PHYSICAL_INPUT: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Clone)]
struct WindowRecord { native: NativeWindow, app: String, observed: Instant, process: Arc<ProcessPin> }
#[derive(Clone)]
struct Observation { window_id: String, window: NativeWindow, epoch: u64, created: Instant, lease: Option<(String, DesktopLease)> }
struct State { epoch: u64, windows: BTreeMap<String, WindowRecord>, observations: BTreeMap<String, Observation> }
struct Runtime { runner: Runner, desktops: AgentDesktopHandle, profile: ProfileControl, state: Mutex<State>, serial: Mutex<()> }
struct Capture { tree: bool, screenshot: bool, interactive: bool, maximum: usize }
struct Action { name: String, arguments: Option<Vec<String>>, physical: bool, wait: Duration }

fn string<'a>(args: &'a Map<String, Value>, key: &str) -> Result<&'a str, RuntimeError> {
    args.get(key).and_then(Value::as_str).filter(|value| !value.contains('\0')).ok_or_else(|| format!("UI_ARGUMENT_REQUIRED_{key}").into())
}
fn flag(args: &Map<String, Value>, key: &str, fallback: bool) -> bool { args.get(key).and_then(Value::as_bool).unwrap_or(fallback) }
fn number(args: &Map<String, Value>, key: &str, fallback: u64) -> u64 { args.get(key).and_then(Value::as_u64).unwrap_or(fallback) }
fn public_window(id: &str, record: &WindowRecord) -> Value {
    json!({"window_id":id,"app":record.app,"title":record.native.title,"class_name":record.native.class_name,
        "width":record.native.width,"height":record.native.height,"foreground":record.native.foreground})
}
fn code(error: &RuntimeError) -> String {
    let text = error.to_string();
    if text.len() <= 160 && text.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-')) { text }
    else { "UI_BACKEND_FAILED".to_owned() }
}
fn partial(action: &str, error: &RuntimeError, succeeded: bool) -> ToolCallResult {
    let attempted=error.to_string()!="UI_WINDOWS_COMMAND_LINE_LIMIT";
    let mut result = ToolCallResult::text(json!({"action":action,"succeeded":succeeded,"attempted":attempted,
        "error_code":code(error),"observation_required_before_next_action":true}).to_string());
    result.is_error = true; result
}
// The backend returned, but the target could not be re-attested. Do not
// turn a vanished/recycled window into a successful UI effect receipt.
fn uncertain_action(action:&str,error:&RuntimeError)->ToolCallResult{
    let mut result=ToolCallResult::text(json!({"action":action,"succeeded":false,"attempted":true,
        "effect_dispatched":action!="wait","outcome_uncertain":true,
        "error_code":code(error),"observation_required_before_next_action":true,
        "window_id_invalidated":true}).to_string());
    result.is_error=true;result
}
fn timestamp() -> Result<String, RuntimeError> {
    let time = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let seconds = time.as_secs(); let days = (seconds / 86400) as i64 + 719468;
    let era = days / 146097; let doe = days - era * 146097;
    let yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365;
    let mut year = yoe + era * 400; let doy = doe - (365*yoe + yoe/4 - yoe/100);
    let mp = (5*doy + 2)/153; let day = doy - (153*mp + 2)/5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 }; year += i64::from(month <= 2);
    Ok(format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z", seconds/3600%24, seconds/60%60, seconds%60, time.subsec_millis()))
}
fn inspected_elements<'a>(value:&'a Value,window:&NativeWindow)->Result<&'a [Value],RuntimeError>{
    let windows=value["windows"].as_array().filter(|items|items.len()<=2048).ok_or("UI_INSPECTION_TARGET_INVALID")?;
    let mut matching=windows.iter().filter(|item|item["hwnd"]==window.hwnd);
    let entry=matching.next().ok_or("UI_INSPECTION_TARGET_INVALID")?;
    if matching.next().is_some(){return Err("UI_INSPECTION_TARGET_AMBIGUOUS".into());}
    Ok(entry["elements"].as_array().ok_or("UI_INSPECTION_ELEMENTS_INVALID")?)
}
fn observed_action_target(observed:&NativeWindow,current:&NativeWindow,physical:bool)->bool{
    observed.same_target(current) && (!physical || (
        observed.visible && current.visible && observed.foreground && current.foreground
        && observed.left==current.left && observed.top==current.top
        && observed.width==current.width && observed.height==current.height
    ))
}
fn screenshot_dimensions(value:&Value, window:&NativeWindow)->Result<(u64,u64),RuntimeError>{
    if value["hwnd"] != window.hwnd || value["processId"] != window.pid
        || value.get("windows").is_some_and(|windows|!windows.is_null()) {
        return Err("UI_SCREENSHOT_TARGET_INVALID".into());
    }
    let width=value["width"].as_u64().filter(|v|*v>0&&*v<=100000).ok_or("UI_SCREENSHOT_METADATA_INVALID")?;
    let height=value["height"].as_u64().filter(|v|*v>0&&*v<=100000).ok_or("UI_SCREENSHOT_METADATA_INVALID")?;
    if width.saturating_mul(height)>100_000_000 {return Err("UI_SCREENSHOT_METADATA_INVALID".into());}
    Ok((width,height))
}
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8;64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3)*4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0] as usize; let b = *chunk.get(1).unwrap_or(&0) as usize; let c = *chunk.get(2).unwrap_or(&0) as usize;
        out.push(TABLE[a>>2] as char); out.push(TABLE[((a&3)<<4)|(b>>4)] as char);
        out.push(if chunk.len()>1 { TABLE[((b&15)<<2)|(c>>6)] as char } else { '=' });
        out.push(if chunk.len()>2 { TABLE[c&63] as char } else { '=' });
    }
    out
}
fn png(bytes: &[u8], width: u64, height: u64) -> Result<(), RuntimeError> {
    if bytes.len() < 33 || bytes.len() > PNG_LIMIT || bytes[..8] != [137,80,78,71,13,10,26,10]
        || bytes[8..12] != [0,0,0,13] || &bytes[12..16] != b"IHDR" || width == 0 || height == 0
        || width > 100000 || height > 100000 || width.saturating_mul(height) > 100_000_000
        || u32::from_be_bytes(bytes[16..20].try_into().unwrap()) as u64 != width
        || u32::from_be_bytes(bytes[20..24].try_into().unwrap()) as u64 != height { return Err("UI_SCREENSHOT_INVALID".into()); }
    const fn table() -> [u32;256] {
        let mut out=[0u32;256];let mut index=0;
        while index<256 {let mut crc=index as u32;let mut bit=0;while bit<8 {crc=if crc&1!=0 {(crc>>1)^0xedb88320}else{crc>>1};bit+=1;}out[index]=crc;index+=1;}out
    }
    const CRC:[u32;256]=table();
    let mut offset=8; let mut idat=false; let mut ended=false;
    while offset<bytes.len() {
        if bytes.len()-offset<12 {return Err("UI_SCREENSHOT_INVALID".into());}
        let length=u32::from_be_bytes(bytes[offset..offset+4].try_into().unwrap()) as usize;
        let end=offset.checked_add(length).and_then(|value|value.checked_add(12)).filter(|end|*end<=bytes.len()).ok_or("UI_SCREENSHOT_INVALID")?;
        let kind=&bytes[offset+4..offset+8];let payload=&bytes[offset+4..end-4];
        let mut crc=0xffffffffu32;for byte in payload {crc=CRC[((crc^*byte as u32)&255)as usize]^(crc>>8);}
        if !crc!=u32::from_be_bytes(bytes[end-4..end].try_into().unwrap()) {return Err("UI_SCREENSHOT_INVALID".into());}
        if kind==b"IDAT" {idat=true;}
        if kind==b"IEND" {if length!=0||end!=bytes.len(){return Err("UI_SCREENSHOT_INVALID".into());}ended=true;}
        offset=end;
    }
    if !idat||!ended {return Err("UI_SCREENSHOT_INVALID".into());}Ok(())
}
fn flatten(values: &[Value], maximum: usize) -> Vec<Value> {
    fn visit(value: &Value, ancestors: &[String], out: &mut Vec<Value>, maximum: usize, depth: usize) {
        if out.len() >= maximum || depth > 16 { return; }
        let Some(value) = value.as_object() else { return; };
        let mut projected = Map::new();
        for key in ["type","name","automationId","className","selector","value","expandState","toggleState"] {
            if let Some(text) = value.get(key).and_then(Value::as_str) { projected.insert(key.to_owned(), json!(text.chars().take(65536).collect::<String>())); }
        }
        for key in ["isEnabled","isOffscreen","isSelected","isInvokable"] {
            if let Some(flag) = value.get(key).and_then(Value::as_bool) { projected.insert(key.to_owned(), json!(flag)); }
        }
        for key in ["x","y","width","height"] {
            if let Some(number) = value.get(key).and_then(Value::as_f64).filter(|number| number.is_finite()) { projected.insert(key.to_owned(), json!(number)); }
        }
        if !ancestors.is_empty() { projected.insert("ancestorPath".to_owned(), json!(ancestors)); }
        let mut next = ancestors.to_vec(); if let Some(kind) = value.get("type").and_then(Value::as_str) { next.push(kind.chars().take(128).collect()); }
        out.push(Value::Object(projected));
        if let Some(children) = value.get("children").and_then(Value::as_array) {
            for child in children { visit(child, &next, out, maximum, depth + 1); if out.len() >= maximum { break; } }
        }
    }
    let mut out = Vec::new(); for value in values { visit(value, &[], &mut out, maximum, 0); if out.len() >= maximum { break; } } out
}

impl Runtime {
    fn state_epoch(&self) -> Result<u64, RuntimeError> {
        let epoch = self.runner.epoch(); self.runner.admitted(epoch)?;
        let mut state = self.state.lock().map_err(|_| "UI_STATE_UNAVAILABLE")?;
        if state.epoch != epoch { state.epoch = epoch; state.windows.clear(); state.observations.clear(); }
        state.windows.retain(|_, record| record.observed.elapsed() <= WINDOW_TTL);
        let valid: Vec<_> = state.windows.keys().cloned().collect();
        state.observations.retain(|_, observation| observation.created.elapsed() <= OBSERVATION_TTL && valid.contains(&observation.window_id));
        Ok(epoch)
    }
    fn issue_window(&self, record: WindowRecord) -> Result<String, RuntimeError> {
        let mut state = self.state.lock().map_err(|_| "UI_STATE_UNAVAILABLE")?;
        if let Some(id) = state.windows.iter().find(|(_, old)| old.native.same_target(&record.native)).map(|(id,_)| id.clone()) {
            state.windows.insert(id.clone(), record); return Ok(id);
        }
        if state.windows.len() >= 1024 {
            let oldest = state.windows.iter().min_by_key(|(_, record)| record.observed).map(|(id,_)| id.clone()).ok_or("UI_STATE_UNAVAILABLE")?;
            state.windows.remove(&oldest); state.observations.retain(|_, observation| observation.window_id != oldest);
        }
        let id = bundle::uuid()?; state.windows.insert(id.clone(), record); Ok(id)
    }
    fn lease(&self, args: &Map<String, Value>) -> Result<Option<(String, DesktopLease)>, RuntimeError> {
        args.get("agent_desktop_lease_id").and_then(Value::as_str).map(|id| self.desktops.verify_lease(id).map(|lease| (id.to_owned(), lease))).transpose()
    }
    fn target_safe(&self, window: &NativeWindow, lease: Option<&(String, DesktopLease)>) -> Result<(), RuntimeError> {
        if window.is_hud || window.title.starts_with("Agent Bridge Agent Desktop") || window.title.starts_with("DeskMCP Agent Desktop") { return Err("UI_SAFETY_HUD_REFUSED".into()); }
        if let Some((_, lease)) = lease { self.desktops.assert_window(window, lease)?; }
        Ok(())
    }
    fn list(&self, app: Option<&str>, untitled: bool, lease: Option<&(String, DesktopLease)>) -> Result<Vec<WindowRecord>, RuntimeError> {
        let mut args = vec!["ui".to_owned(), "list-windows".to_owned()];
        if let Some(app) = app { if app.contains('\0') { return Err("UI_ARGUMENT_INVALID".into()); } args.push(format!("--app={app}")); }
        let value = self.runner.run(args, Duration::from_secs(10))?;
        let windows = value.as_array().filter(|items| items.len() <= 2048).ok_or("UI_WINDOWS_RESPONSE_INVALID")?;
        let mut results = Vec::new();
        for raw in windows {
            let hwnd = raw["hwnd"].as_u64().filter(|value| *value > 0).ok_or("UI_WINDOWS_RESPONSE_INVALID")?;
            let pid = raw["processId"].as_u64().filter(|value| *value > 0 && *value <= u32::MAX as u64).ok_or("UI_WINDOWS_RESPONSE_INVALID")?;
            let app = raw["processName"].as_str().filter(|value| !value.is_empty() && value.len() <= 4096).ok_or("UI_WINDOWS_RESPONSE_INVALID")?;
            let window = match self.desktops.window(hwnd) { Ok(window) => window,
                Err(error) if error.to_string().starts_with("WINDOW_") => continue,
                Err(error) => return Err(error) };
            if window.pid as u64 != pid || !window.visible || window.width < 32 || window.height < 24 || self.target_safe(&window, lease).is_err()
                || (!untitled && window.title.trim().is_empty() && !window.foreground) { continue; }
            let process = match ProcessPin::open(&window) { Ok(pin) => Arc::new(pin), Err(_) => continue };
            results.push(WindowRecord { native: window, app: app.to_owned(), observed: Instant::now(), process });
        }
        results.sort_by_key(|record| (!record.native.foreground, -(record.native.width as i64 * record.native.height as i64)));
        results.truncate(100);
        if let Some((id,_)) = lease { self.desktops.verify_lease(id)?; }
        Ok(results)
    }
    fn resolve(&self, id: &str, lease: Option<&(String, DesktopLease)>) -> Result<WindowRecord, RuntimeError> {
        let record = self.state.lock().map_err(|_| "UI_STATE_UNAVAILABLE")?.windows.get(id).cloned().ok_or("UI_WINDOW_CAPABILITY_EXPIRED")?;
        if record.observed.elapsed() > WINDOW_TTL { return Err("UI_WINDOW_CAPABILITY_EXPIRED".into()); }
        let native=match self.desktops.window(record.native.hwnd){
            Ok(window)=>window,
            Err(error)=>{self.invalidate_window(id)?;return Err(error);}
        };
        if !record.native.same_target(&native) {
            self.invalidate_window(id)?;
            return Err("UI_WINDOW_IDENTITY_CHANGED".into());
        }
        if let Err(error)=record.process.verify(&native){self.invalidate_window(id)?;return Err(error);}
        self.target_safe(&native, lease)?;
        Ok(WindowRecord { native, app: record.app, observed: Instant::now(), process:record.process })
    }
    fn invalidate_window(&self,id:&str)->Result<(),RuntimeError>{
        let mut state=self.state.lock().map_err(|_|"UI_STATE_UNAVAILABLE")?;
        state.windows.remove(id);
        state.observations.retain(|_,observation|observation.window_id!=id);
        Ok(())
    }
    fn recheck_capture(&self,record:&WindowRecord,lease:Option<&(String,DesktopLease)>,epoch:u64,current_desktop:&str)
        ->Result<NativeWindow,RuntimeError>{
        self.runner.admitted(epoch)?;
        let window=self.desktops.window(record.native.hwnd)?;
        if !record.native.same_target(&window) {return Err("UI_WINDOW_IDENTITY_CHANGED".into());}
        record.process.verify(&window)?;
        self.target_safe(&window,lease)?;
        if self.desktops.current_desktop()?!=current_desktop {return Err("UI_DESKTOP_CHANGED_DURING_CAPTURE".into());}
        Ok(window)
    }
    fn capture(&self, id: &str, record: &WindowRecord, options: Capture, lease: Option<(String, DesktopLease)>, epoch: u64) -> Result<ToolCallResult, RuntimeError> {
        let result=self.capture_verified(id,record,options,lease,epoch);
        if result.is_err(){self.invalidate_window(id)?;}
        result
    }
    fn capture_verified(&self, id: &str, record: &WindowRecord, options: Capture, lease: Option<(String, DesktopLease)>, epoch: u64) -> Result<ToolCallResult, RuntimeError> {
        if options.screenshot {self.runner.require_exact_passive_capture()?;}
        let current_desktop=self.desktops.current_desktop()?;
        self.recheck_capture(record,lease.as_ref(),epoch,&current_desktop)?;
        let hwnd = record.native.hwnd.to_string();
        let tree = if options.tree {
            let mut args = vec!["ui".to_owned(),"inspect".to_owned(),"-w".to_owned(),hwnd.clone(),"--depth".to_owned(), if options.interactive {"8"} else {"5"}.to_owned()];
            if options.interactive { args.push("--interactive".to_owned()); }
            let value = self.runner.run(args, Duration::from_secs(12))?;
            Some(flatten(inspected_elements(&value,&record.native)?, options.maximum))
        } else { None };
        let screenshot = if options.screenshot {
            // The inspection may have outlived or moved its window. Do not
            // send a second native command until the identity is checked.
            self.recheck_capture(record,lease.as_ref(),epoch,&current_desktop)?;
            let path = self.runner.capture_path()?;
            let result = (|| -> Result<(Vec<u8>, u64, u64), RuntimeError> {
                let value = self.runner.run(vec!["ui".to_owned(),"screenshot".to_owned(),"-w".to_owned(),hwnd,
                    "--exact-passive".to_owned(),"--output".to_owned(),path.to_str().ok_or("UI_SCREENSHOT_PATH_ENCODING")?.to_owned()], Duration::from_secs(15))?;
                self.recheck_capture(record,lease.as_ref(),epoch,&current_desktop)?;
                let (width,height)=screenshot_dimensions(&value,&record.native)?;
                let reported=value["filePath"].as_str().ok_or("UI_SCREENSHOT_METADATA_INVALID")?;
                // Compare only the reported spelling, do not open an
                // attacker-selected path outside the capture directory.
                if !reported.eq_ignore_ascii_case(path.to_str().ok_or("UI_SCREENSHOT_PATH_ENCODING")?) {
                    return Err("UI_SCREENSHOT_PATH_MISMATCH".into());
                }
                let mut file = bundle::pin(&path, false)?;
                if file.metadata()?.len() > PNG_LIMIT as u64 { return Err("UI_SCREENSHOT_LIMIT".into()); }
                let mut bytes = Vec::new(); (&mut file).take((PNG_LIMIT + 1) as u64).read_to_end(&mut bytes)?;
                png(&bytes, width, height)?; Ok((bytes, width, height))
            })();
            self.runner.finish_capture(&path)?;
            Some(result?)
        } else { None };
        let refreshed = self.recheck_capture(record,lease.as_ref(),epoch,&current_desktop)?;
        let observation = bundle::uuid()?;
        let observed_record=WindowRecord{native:refreshed.clone(),app:record.app.clone(),observed:Instant::now(),process:record.process.clone()};
        let mut metadata = json!({"computer_observation_id":observation,"captured_at":timestamp()?,"window":public_window(id, &observed_record)});
        if let Some(elements) = tree {
            if lease.is_some() && record.native.class_name.starts_with("WindowsForms10.") && !elements.iter().any(|element|
                element["type"] != "Window" && element["className"].as_str().is_some_and(|class| class.starts_with("WindowsForms10."))) {
                metadata["semantic_tree_status"] = json!("limited");
                metadata["semantic_tree_warning"] = json!("Windows Forms child controls may not expose UI Automation on a non-current Agent Desktop; this tree is not complete.");
            }
            metadata["elements"] = json!(elements);
        }
        if let Some((_, width, height)) = &screenshot { metadata["screenshot"] = json!({"width":width,"height":height}); }
        {
            let mut state = self.state.lock().map_err(|_| "UI_STATE_UNAVAILABLE")?;
            if state.observations.len() >= 1024 {
                if let Some(oldest) = state.observations.iter().min_by_key(|(_, item)| item.created).map(|(id,_)| id.clone()) { state.observations.remove(&oldest); }
            }
            state.observations.insert(observation, Observation { window_id:id.to_owned(), window:refreshed, epoch, created:Instant::now(), lease });
            if let Some(window) = state.windows.get_mut(id) { window.observed = Instant::now(); }
        }
        let mut result = ToolCallResult::text(metadata.to_string());
        if let Some((bytes,_,_)) = screenshot { result.content.push(ToolContent::Image { data:base64(&bytes), mime_type:"image/png".to_owned() }); }
        Ok(result)
    }
    fn snapshot(&self, args: &Map<String,Value>, epoch: u64) -> Result<ToolCallResult,RuntimeError> {
        let lease = self.lease(args)?;
        let (id, record) = if let Some(id) = args.get("window_id").and_then(Value::as_str) {
            (id.to_owned(), self.resolve(id, lease.as_ref())?)
        } else {
            let candidates = self.list(args.get("app").and_then(Value::as_str), false, lease.as_ref())?;
            let target = if candidates.len() == 1 { candidates[0].clone() }
                else if flag(args,"include_screenshot",false) {return Err("UI_WINDOW_SELECTION_REQUIRED".into());}
                else { candidates.iter().find(|record| record.native.foreground).cloned().ok_or("UI_WINDOW_SELECTION_REQUIRED")? };
            (self.issue_window(target.clone())?, target)
        };
        self.capture(&id, &record, Capture { tree:flag(args,"include_tree",true), screenshot:flag(args,"include_screenshot",false),
            interactive:flag(args,"interactive_only",true), maximum:number(args,"max_elements",80) as usize }, lease, epoch)
    }
    fn action(&self, args: &Map<String,Value>, epoch: u64, profile: DesktopProfile) -> Result<ToolCallResult,RuntimeError> {
        let id = string(args,"window_id")?; let observation_id = string(args,"computer_observation_id")?;
        let observation = self.state.lock().map_err(|_| "UI_STATE_UNAVAILABLE")?.observations.remove(observation_id).ok_or("UI_OBSERVATION_EXPIRED_OR_CONSUMED")?;
        if observation.window_id != id || observation.epoch != epoch || observation.created.elapsed() > OBSERVATION_TTL {
            return Err("UI_OBSERVATION_EXPIRED_OR_CONSUMED".into());
        }
        if let Some(requested) = args.get("agent_desktop_lease_id").and_then(Value::as_str) {
            if observation.lease.as_ref().map(|(id,_)| id.as_str()) != Some(requested) { return Err("UI_OBSERVATION_LEASE_MISMATCH".into()); }
        }
        let lease = observation.lease;
        let record = self.resolve(id, lease.as_ref())?;
        // A nonforeground target is semantic-only, even without a lease.
        // Do not let an unleased background window use WinApp's autofocus.
        let action = parse_action(args, &record.native, lease.is_some()||!record.native.foreground, profile)?;
        if !observed_action_target(&observation.window,&record.native,action.physical) {
            self.invalidate_window(id)?;
            return Err("UI_OBSERVATION_TARGET_CHANGED".into());
        }
        {
            let mut state = self.state.lock().map_err(|_| "UI_STATE_UNAVAILABLE")?;
            state.observations.retain(|_, observation| !action.physical && observation.window_id != id);
        }
        let physical = if action.physical { Some(PHYSICAL_INPUT.get_or_init(||Mutex::new(())).lock().map_err(|_| "UI_INPUT_COORDINATOR_UNAVAILABLE")?) } else { None };
        let before=match self.desktops.window(record.native.hwnd){
            Ok(window)=>window,
            Err(error)=>{self.invalidate_window(id)?;return Err(error);}
        };
        if !observed_action_target(&observation.window,&before,action.physical)
            || record.native.foreground!=before.foreground {
            self.invalidate_window(id)?;
            return Err("UI_WINDOW_IDENTITY_CHANGED".into());
        }
        if let Err(error)=record.process.verify(&before){self.invalidate_window(id)?;return Err(error);}
        self.target_safe(&before, lease.as_ref())?;
        if action.physical && self.desktops.current_desktop()? != before.desktop_id { return Err("requires_foreground_input".into()); }
        self.runner.admitted(epoch)?;
        let effect = if let Some(arguments) = action.arguments { self.runner.run(arguments, Duration::from_secs(15)).map(|_| ()) }
            else { self.pause(action.wait, epoch) };
        drop(physical);
        if let Err(error) = effect { return Ok(partial(&action.name, &error, false)); }
        if action.name != "wait" { if let Err(error) = self.pause(Duration::from_millis(number(args,"settle_ms",150)), epoch) { return Ok(partial(&action.name,&error,true)); } }
        let verified=(||->Result<NativeWindow,RuntimeError>{
            let window=self.desktops.window(record.native.hwnd)?;
            if !record.native.same_target(&window){return Err("UI_WINDOW_IDENTITY_CHANGED".into());}
            record.process.verify(&window)?;
            self.target_safe(&window,lease.as_ref())?;
            self.runner.admitted(epoch)?;
            Ok(window)
        })();
        let refreshed=match verified{
            Ok(window)=>window,
            Err(error)=>{self.invalidate_window(id)?;return Ok(uncertain_action(&action.name,&error));}
        };
        let mode = args.get("observe_after").and_then(Value::as_str).unwrap_or("tree");
        if mode == "none" { return Ok(ToolCallResult::text(json!({"action":action.name,"succeeded":true,"observation_required_before_next_action":true}).to_string())); }
        let refreshed = WindowRecord { native:refreshed, app:record.app, observed:Instant::now(), process:record.process };
        let mut result = match self.capture(id,&refreshed,Capture {tree:matches!(mode,"tree"|"both"),screenshot:matches!(mode,"screenshot"|"both"),interactive:true,maximum:80},lease,epoch) {
            Ok(result) => result, Err(error) => return Ok(partial(&action.name,&error,true)),
        };
        if let Some(ToolContent::Text {text}) = result.content.first_mut() {
            let state: Value = serde_json::from_str(text)?; *text = json!({"action":action.name,"succeeded":true,"state":state}).to_string();
        }
        Ok(result)
    }
    fn pause(&self, duration: Duration, epoch: u64) -> Result<(),RuntimeError> {
        let deadline = Instant::now() + duration;
        loop { self.runner.admitted(epoch)?; let now = Instant::now(); if now >= deadline { return Ok(()); } std::thread::sleep((deadline-now).min(Duration::from_millis(20))); }
    }
    fn dispatch(&self, name: &str, args: Map<String,Value>) -> Result<ToolCallResult,RuntimeError> {
        let profile = self.profile.read()?;
        if rank(*profile) < rank(DesktopProfile::FullControl) { return Err("PROFILE_FULL_CONTROL_REQUIRED".into()); }
        let _operation = self.serial.lock().map_err(|_| "UI_STATE_UNAVAILABLE")?; let epoch = self.state_epoch()?;
        match name {
            "desktop_ui_windows" => {
                let lease = self.lease(&args)?; let records = self.list(args.get("app").and_then(Value::as_str),flag(&args,"include_untitled",false),lease.as_ref())?;
                let mut windows = Vec::new(); for record in records { let id = self.issue_window(record.clone())?; windows.push(public_window(&id,&record)); }
                self.runner.admitted(epoch)?; Ok(ToolCallResult::text(json!(windows).to_string()))
            }
            "desktop_ui_snapshot" => self.snapshot(&args,epoch),
            "desktop_ui_action" => self.action(&args,epoch,*profile),
            _ => Err("UI_TOOL_UNKNOWN".into()),
        }
    }
}

fn parse_action(args: &Map<String,Value>, window: &NativeWindow, background: bool, profile: DesktopProfile) -> Result<Action,RuntimeError> {
    let name = string(args,"action")?.to_owned();
    let physical = matches!(name.as_str(),"click"|"hover"|"drag") || (name == "scroll" && args.contains_key("wheel")) || (name == "send_keys" && !background);
    if background && (physical || flag(args,"allow_system_keys",false) || args.get("transport").and_then(Value::as_str) == Some("send-input")) { return Err("requires_foreground_input".into()); }
    if flag(args,"allow_system_keys",false) && profile != DesktopProfile::FullyUnlocked { return Err("UI_SYSTEM_KEYS_REQUIRE_UNLOCK".into()); }
    for key in ["selector","from","drag_to"] {
        if let Some(value) = args.get(key).and_then(Value::as_str) {
            if let Some((x,y)) = value.split_once(',').and_then(|(x,y)| Some((x.trim().parse::<i64>().ok()?,y.trim().parse::<i64>().ok()?))) {
                if background { return Err("requires_foreground_input".into()); }
                if x < window.left as i64 || y < window.top as i64 || x >= window.left as i64 + window.width as i64
                    || y >= window.top as i64 + window.height as i64 { return Err("UI_COORDINATES_OUTSIDE_OBSERVED_WINDOW".into()); }
            }
        }
    }
    if name == "wait" { return Ok(Action { name,arguments:None,physical:false,wait:Duration::from_millis(number(args,"wait_ms",800)) }); }
    let mut command = vec!["ui".to_owned(), if name == "set_value" {"set-value"} else if name == "send_keys" {"send-keys"} else {&name}.to_owned()];
    let mut positionals=Vec::new();
    match name.as_str() {
        "invoke"|"click"|"hover" => positionals.push(string(args,"selector")?.to_owned()),
        "set_value" => positionals.extend([string(args,"selector")?.to_owned(),string(args,"value")?.to_owned()]),
        "scroll" => {
            if !args.contains_key("direction") && !args.contains_key("to") && !args.contains_key("wheel") { return Err("UI_SCROLL_DIRECTION_REQUIRED".into()); }
            if let Some(selector) = args.get("selector").and_then(Value::as_str) { positionals.push(selector.to_owned()); }
        }
        "send_keys" => positionals.push(string(args,"keys")?.to_owned()),
        "drag" => positionals.extend([string(args,"from")?.to_owned(),string(args,"drag_to")?.to_owned()]),
        _ => return Err("UI_ACTION_INVALID".into()),
    }
    command.extend(["-w".to_owned(),window.hwnd.to_string()]);
    if background && matches!(name.as_str(),"invoke"|"set_value"|"scroll") {command.push("--no-focus".to_owned());}
    match name.as_str() {
        "click" => { if flag(args,"double",false) { command.push("--double".to_owned()); } },
        "hover" => { if let Some(value) = args.get("dwell_ms") { command.extend(["--dwell-time".to_owned(),value.to_string()]); } },
        "scroll" => {
            for (key,option) in [("direction","--direction"),("to","--to")] { if let Some(value) = args.get(key).and_then(Value::as_str) { command.extend([option.to_owned(),value.to_owned()]); } }
            if let Some(value) = args.get("wheel") { command.extend(["--wheel".to_owned(),value.to_string()]); }
        }
        "send_keys" => {
            command.extend(["--via".to_owned(),if background {"post-message"} else {"send-input"}.to_owned()]);
            if background { command.push("--no-focus".to_owned()); }
            if let Some(selector) = args.get("selector").and_then(Value::as_str) { command.push(format!("--target={selector}")); }
            if flag(args,"verbatim",false) { command.push("--verbatim".to_owned()); }
            if flag(args,"allow_system_keys",false) { command.push("--allow-system-keys".to_owned()); }
        }
        "drag" => {
            for (key,option) in [("hold_ms","--hold-ms"),("dwell_ms","--dwell-ms")] { if let Some(value) = args.get(key) { command.extend([option.to_owned(),value.to_string()]); } }
        }
        _ => {}
    }
    if matches!(name.as_str(),"click"|"drag") && args.get("button").and_then(Value::as_str) == Some("right") { command.push("--right".to_owned()); }
    if !positionals.is_empty() {command.push("--".to_owned());command.extend(positionals);}
    if command.iter().any(|argument| argument.contains('\0')) { return Err("UI_ARGUMENT_INVALID".into()); }
    Ok(Action { name,arguments:Some(command),physical,wait:Duration::ZERO })
}

pub(super) fn attach(config: WindowsToolsConfig, profile: ProfileControl, desktops: AgentDesktopHandle,
    catalog: &mut Vec<ToolDefinition>, handlers: &mut ToolMapHandler) -> Result<ProviderOwner,RuntimeError> {
    let resources = Arc::new(Resources::verify(&config.bundle_root,&config.manifest_sha256)?);
    let runner = Runner::new(resources,&config.state_root)?;
    let runtime = Arc::new(Runtime { runner,desktops,profile,state:Mutex::new(State {epoch:1,windows:BTreeMap::new(),observations:BTreeMap::new()}),serial:Mutex::new(()) });
    let revoke = runtime.clone(); let shutdown = runtime.clone();
    let owner = ProviderOwner::new(Arc::new(move||revoke.runner.close(false)),Arc::new(move||shutdown.runner.close(true)));
    for definition in super::definitions()?.into_iter().filter(|definition| definition.name.starts_with("desktop_ui_")) {
        let provider = runtime.clone(); let name = definition.name.clone(); let schema=definition.input_schema.clone();
        handlers.register(definition.name.clone(),move|args| {
            let args=super::validate_arguments(&schema,args)?;
            provider.dispatch(&name,args).map_err(|error|ToolDispatchError::tool_error(code(&error)))
        });
        catalog.push(definition);
    }
    Ok(owner)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn target()->NativeWindow {NativeWindow{hwnd:1,pid:2,tid:3,birth:4,image:"fixture.exe".to_owned(),class_name:"Fixture".to_owned(),title:"fixture".to_owned(),
        left:100,top:100,width:400,height:300,foreground:true,desktop_id:"11111111-1111-4111-8111-111111111111".to_owned(),desktop_number:2,visible:true,is_hud:false}}
    fn parse(value:Value,background:bool,profile:DesktopProfile)->Result<Action,RuntimeError>{parse_action(value.as_object().unwrap(),&target(),background,profile)}
    #[test]fn background_message_transport_explicitly_forbids_focus(){
        let value=json!({"action":"send_keys","keys":"owned-window-proof"});
        let background=parse(value.clone(),true,DesktopProfile::FullControl).unwrap().arguments.unwrap();
        assert!(background.iter().any(|argument|argument=="--no-focus"),"background command must explicitly prohibit activation");
        let foreground=parse(value,false,DesktopProfile::FullControl).unwrap().arguments.unwrap();
        assert!(!foreground.iter().any(|argument|argument=="--no-focus"),"normal foreground contract must remain available");
    }
    #[test]fn background_semantic_actions_disable_uia_autofocus(){
        for value in [json!({"action":"invoke","selector":"button"}),
            json!({"action":"set_value","selector":"editor","value":"value"}),
            json!({"action":"scroll","selector":"list","to":"bottom"})] {
            let background=parse(value.clone(),true,DesktopProfile::FullControl).unwrap().arguments.unwrap();
            assert!(background.iter().any(|argument|argument=="--no-focus"),"background UIA must explicitly disable AutoSetFocus");
            let foreground=parse(value,false,DesktopProfile::FullControl).unwrap().arguments.unwrap();
            assert!(!foreground.iter().any(|argument|argument=="--no-focus"),"normal foreground default remains available");
        }
    }
    #[test]fn action_values_remain_literal_cli_arguments(){
        let arguments=parse(json!({"action":"set_value","selector":"--selector","value":"--literal-proof"}),false,DesktopProfile::FullControl).unwrap().arguments.unwrap();
        let separator=arguments.iter().position(|value|value=="--").expect("positional user values require the CLI end-of-options marker");
        assert_eq!(&arguments[separator+1..],["--selector","--literal-proof"]);
        let keys=parse(json!({"action":"send_keys","selector":"--target","keys":"--literal-proof"}),true,DesktopProfile::FullControl).unwrap().arguments.unwrap();
        assert!(keys.iter().any(|value|value=="--target=--target"));
    }
    #[test]fn restrictions_are_effect_specific_and_preserve_semantic_actions(){
        for value in [json!({"action":"click","selector":"#button"}),json!({"action":"hover","selector":"#button"}),
            json!({"action":"drag","from":"#a","drag_to":"#b"}),json!({"action":"scroll","wheel":1}),
            json!({"action":"send_keys","keys":"x","transport":"send-input"})] {assert_eq!(parse(value,true,DesktopProfile::FullyUnlocked).err().unwrap().to_string(),"requires_foreground_input");}
        for value in [json!({"action":"invoke","selector":"#button"}),json!({"action":"set_value","selector":"#value","value":""}),
            json!({"action":"scroll","direction":"down"}),json!({"action":"send_keys","keys":"text"}),json!({"action":"wait"})] {assert!(!parse(value,true,DesktopProfile::FullControl).unwrap().physical);}
        assert!(parse(json!({"action":"send_keys","keys":"WIN","allow_system_keys":true}),false,DesktopProfile::FullControl).is_err());
        assert!(parse(json!({"action":"send_keys","keys":"WIN","allow_system_keys":true}),false,DesktopProfile::FullyUnlocked).is_ok());
        assert!(parse(json!({"action":"click","selector":"99,200"}),false,DesktopProfile::FullyUnlocked).is_err());
        assert!(parse(json!({"action":"click","selector":"120,200"}),false,DesktopProfile::FullyUnlocked).is_ok());
    }
    #[test]fn inspection_rejects_duplicate_exact_window_entries(){
        let native=target();
        let entry=json!({"hwnd":native.hwnd,"className":native.class_name,"elements":[{"name":"fixture"}]});
        assert_eq!(inspected_elements(&json!({"windows":[entry.clone()]}),&native).unwrap().len(),1);
        assert!(inspected_elements(&json!({"windows":[entry.clone(),entry]}),&native).is_err());
    }
    #[test]fn physical_action_cannot_reuse_observation_after_geometry_or_focus_changes(){
        let native=target();
        let mut moved=native.clone();moved.left+=1;
        assert!(!observed_action_target(&native,&moved,true));
        assert!(observed_action_target(&native,&moved,false),"semantic selector is not a screen coordinate");
        let mut blurred=native.clone();blurred.foreground=false;
        assert!(!observed_action_target(&native,&blurred,true));
        let mut reused=native.clone();reused.birth+=1;
        assert!(!observed_action_target(&native,&reused,false));
    }
    #[test]fn lost_post_effect_identity_is_not_a_success_or_window_close_receipt(){
        for error in ["WINDOW_GONE","WINDOW_PROCESS_UNAVAILABLE","UI_WINDOW_IDENTITY_CHANGED"] {
            let result=uncertain_action("invoke",&error.into());
            assert!(result.is_error);
            let value=serde_json::to_value(result).unwrap();
            let meta:Value=serde_json::from_str(value["content"][0]["text"].as_str().unwrap()).unwrap();
            assert_eq!(meta["succeeded"],false);
            assert_eq!(meta["effect_dispatched"],true);
            assert_eq!(meta["outcome_uncertain"],true);
            assert_eq!(meta["window_id_invalidated"],true);
            assert!(meta.get("window_closed").is_none());
        }
    }
    #[test]fn passive_screenshot_must_match_exact_process_and_exclude_composites(){
        let native=target();
        let good=json!({"hwnd":native.hwnd,"processId":native.pid,"width":400,"height":300,"windows":null});
        assert_eq!(screenshot_dimensions(&good,&native).unwrap(),(400,300));
        for field in ["processId","hwnd"]{
            let mut bad=good.clone();bad[field]=json!(999);
            assert!(screenshot_dimensions(&bad,&native).is_err(),"{field} mismatch");
            let mut bad=good.clone();bad.as_object_mut().unwrap().remove(field);
            assert!(screenshot_dimensions(&bad,&native).is_err(),"{field} missing");
        }
        let mut composite=good.clone();composite["windows"]=json!([{"hwnd":native.hwnd},{"hwnd":999}]);
        assert!(screenshot_dimensions(&composite,&native).is_err(),"composite may disclose an unrelated window");
    }
    #[test]fn malformed_images_and_transport_expansion_are_bounded(){
        assert!(png(&vec![0;PNG_LIMIT+1],1,1).is_err());
        assert!(png(b"\x89PNG\r\n\x1a\n",1,1).is_err());
        assert_eq!(base64(b"a"),"YQ==");assert_eq!(base64(b"ab"),"YWI=");assert_eq!(base64(b"abc"),"YWJj");
        assert!(PNG_LIMIT.div_ceil(3)*4+4*1024*1024<48*1024*1024);
    }
}
