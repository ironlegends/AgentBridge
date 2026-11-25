//! Native, private Chromium DevTools Protocol pipe. No TCP listener, driver,
//! Node, Playwright, shell, remote browser discovery or personal Chrome profile.
//! Chrome is owned by a Windows Job or a fresh Unix process group.
//! Unix ownership does not cover processes that deliberately leave the group.
//! Client-supplied JavaScript, CDP method names and raw target identifiers are
//! NEVER accepted. Only higher-level fixed Rust operations use this transport.
use super::*;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::fs::File;
use crate::browser_docs::transfer;

#[cfg(windows)]
#[path = "chrome_cdp_win32.rs"]
mod winpipe;
#[cfg(unix)]
#[path = "chrome_cdp_unix.rs"]
mod unixpipe;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

const MAX_CDP_FRAME: usize = 2 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(12);

fn fail() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "PRIVATE_CHROME_CDP_UNAVAILABLE")
}

enum CdpEvent {
    Frame(Value),
    End,
}

fn read_cdp(mut stdout: impl Read, tx: mpsc::SyncSender<CdpEvent>) {
    let mut pending = Vec::new();
    let mut scratch = [0u8; 8192];
    loop {
        let count = match stdout.read(&mut scratch) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        for &c in &scratch[..count] {
            if c == 0 {
                if let Ok(data) = serde_json::from_slice::<Value>(&pending) {
                    if tx.send(CdpEvent::Frame(data)).is_err() { return; }
                }
                pending.clear();
            } else {
                if pending.len() >= MAX_CDP_FRAME { return; }
                pending.push(c);
            }
        }
    }
    let _ = tx.send(CdpEvent::End);
}

#[cfg(any(windows, unix))]
struct ActiveDownload {
    expected_frame: String,
    guid: Option<String>,
    completed: bool,
    size: u64,
}

#[cfg(any(windows, unix))]
pub(in crate::browser_docs) struct NativeChrome {
    profile: PrivateProfile,
    documents: Vec<TemporaryHtml>,
    _binary_pins: native::BrowserPins,
    #[cfg(windows)]
    job: win::Job,
    #[cfg(windows)]
    child: winpipe::ChildProcess,
    #[cfg(unix)]
    child: unixpipe::ChildProcess,
    #[cfg(unix)]
    _persistent_pin: Option<native::DirectoryPin>,
    stdin: File,
    events: Receiver<CdpEvent>,
    pending: BTreeMap<u64, Value>,
    abandoned: BTreeSet<u64>,
    next_id: u64,
    page_sessions: BTreeMap<String, String>,
    dialogs: BTreeMap<String, Value>,
    allowed_files: Vec<String>,
    allowed_origins: Vec<String>,
    download: Option<ActiveDownload>,
}

#[cfg(any(windows, unix))]
impl NativeChrome {
    pub(in crate::browser_docs) fn start(
        selected_documents: &[(String, String)],
        origins: Vec<String>,
    ) -> io::Result<Self> {
        Self::start_with_profile(selected_documents, origins, None)
    }

    pub(in crate::browser_docs) fn start_with_profile(
        selected_documents: &[(String, String)],
        origins: Vec<String>,
        persistent_profile: Option<&std::path::Path>,
    ) -> io::Result<Self> {
        // All inherited OS handles are explicitly selected by Win32 STARTUPINFOEX.
        // No public debugger socket or stdio/CDP mixing.
        // The Win32 launcher suspends Chrome until the Job is attached.
        if selected_documents.is_empty() || selected_documents.len() > 8
            || origins.len() > 4 || !origins.iter().all(|o| o == "https://learn.microsoft.com")
        {
            return Err(fail());
        }
        let executable = installed_chrome()?;
        let _binary_pins = native::pin_browser(&executable)?;
        let profile = PrivateProfile::create()?;
        let mut documents = Vec::new();
        let mut urls = Vec::new();
        for (_, bytes) in selected_documents {
            if bytes.is_empty() || bytes.len() > 96 * 1024 {
                return Err(fail());
            }
            // This is the *exact* operator-selected project HTML, not a
            // transcript. Its DOM, scripts and form behavior remain real.
            let temp = profile.new_html(bytes)?;
            let url = file_url(&temp.path)?;
            urls.push(url);
            documents.push(temp);
        }
        let scratch_data = profile.chrome_data()?;
        let work_dir = scratch_data.parent().ok_or_else(fail)?;
        let data_dir = match persistent_profile {
            Some(dir) => dir.to_path_buf(),
            None => scratch_data.clone(),
        };
        #[cfg(windows)]
        let (child, stdin, stdout, job) = {
            let (child, stdin, stdout) = winpipe::launch(
            &executable, work_dir, &data_dir,
        )?;
        let job = match win::Job::attach_raw(child.process_handle()) {
            Ok(v) => v,
            Err(_) => {
                child.kill_root();
                return Err(fail());
            }
        };
        if child.resume().is_err() {
            drop(job); // Kill exactly this process and its descendants.
            child.kill_root();
            return Err(fail());
        }
            (child, stdin, stdout, job)
        };
        #[cfg(unix)]
        let _persistent_pin = persistent_profile.map(|path| {
            let pin = native::DirectoryPin::open(path)?;
            pin.require_private()?;
            Ok::<_, io::Error>(pin)
        }).transpose()?;
        #[cfg(unix)]
        let (child, stdin, stdout) = unixpipe::launch(&executable, work_dir, &data_dir)?;
        let (tx, events) = mpsc::sync_channel(48);
        thread::spawn(move || read_cdp(stdout, tx));
        let mut browser = Self {
            profile, documents, _binary_pins, child, stdin,
            #[cfg(windows)]
            job,
            #[cfg(unix)]
            _persistent_pin,
            events, pending: BTreeMap::new(), abandoned: BTreeSet::new(), next_id: 1,
            page_sessions: BTreeMap::new(), dialogs: BTreeMap::new(),
            allowed_files: urls, allowed_origins: origins,
            download: None,
        };
        browser.command(None, "Browser.getVersion", json!({}))?;
        Ok(browser)
    }

    fn accepts_url(&self, url: &str) -> bool {
        if url == "about:blank" { return true; }
        let no_fragment = url.split('#').next().unwrap_or("");
        if self.allowed_files.iter().any(|own| own == no_fragment) {
            return true;
        }
        // Only explicit locally selected *public Microsoft Learn* origins.
        // No IP, loopback, arbitrary websites, user-info, redirects or URL
        // punctuation interpreted by a second parser.
        self.allowed_origins.iter().any(|origin|
            origin == "https://learn.microsoft.com"
                && url.starts_with("https://learn.microsoft.com/en-us/")
                && url.len() <= 1024 && !url.contains('@')
                && !url.contains('\\') && !url.contains('%')
                && !url["https://".len()..].contains("//")
        )
    }

    fn send_raw(&mut self, session: Option<&str>, method: &str, params: Value) -> io::Result<u64> {
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).ok_or_else(fail)?;
        let mut cmd = json!({"id":id,"method":method,"params":params});
        if let Some(s) = session { cmd["sessionId"] = json!(s); }
        let bytes = serde_json::to_vec(&cmd).map_err(|_| fail())?;
        if bytes.len() > MAX_CDP_FRAME { return Err(fail()); }
        self.stdin.write_all(&bytes)?;
        self.stdin.write_all(&[0])?;
        self.stdin.flush()?;
        Ok(id)
    }

    fn on_event(&mut self, event: &Value) -> io::Result<()> {
        match event.get("method").and_then(Value::as_str) {
            Some("Browser.downloadWillBegin") => {
                let record=self.download.as_mut().ok_or_else(fail)?;
                let params=&event["params"];
                let guid=params["guid"].as_str().ok_or_else(fail)?;
                let filename=params["suggestedFilename"].as_str().ok_or_else(fail)?;
                let frame=params["frameId"].as_str().ok_or_else(fail)?;
                let url=params["url"].as_str().ok_or_else(fail)?;
                if record.guid.is_some()
                    || frame!=record.expected_frame
                    || filename!="agent-bridge-download.txt"
                    || !url.starts_with("blob:")
                    || guid.len()!=36
                    || !guid.bytes().enumerate().all(|(i,b)|
                        if matches!(i,8|13|18|23){b==b'-'}
                        else{b.is_ascii_hexdigit()})
                {return Err(fail());}
                record.guid=Some(guid.to_owned());
            }
            Some("Browser.downloadProgress") => {
                let record=self.download.as_mut().ok_or_else(fail)?;
                let params=&event["params"];
                if record.guid.as_deref()!=params["guid"].as_str(){return Err(fail());}
                let received=params["receivedBytes"].as_u64().ok_or_else(fail)?;
                let total=params["totalBytes"].as_u64().ok_or_else(fail)?;
                if received>transfer::MAX_DOWNLOAD_BYTES as u64
                    || total>transfer::MAX_DOWNLOAD_BYTES as u64
                {return Err(fail());}
                record.size=received;
                match params["state"].as_str(){
                    Some("completed")=>record.completed=true,
                    Some("inProgress")=>{},
                    _=>return Err(fail()),
                }
            }
            Some("Page.javascriptDialogOpening") => {
                if let Some(session) = event.get("sessionId").and_then(Value::as_str) {
                    let params = &event["params"];
                    let kind = params["type"].as_str().unwrap_or("alert");
                    let message: String = params["message"].as_str().unwrap_or("").chars().take(512).collect();
                    let default_prompt: String = params["defaultPrompt"].as_str().unwrap_or("").chars().take(256).collect();
                    let has_handler = params["hasBrowserHandler"].as_bool().unwrap_or(false);
                    self.dialogs.insert(session.to_owned(), json!({
                        "type": kind,
                        "message": message,
                        "default_prompt": default_prompt,
                        "has_browser_handler": has_handler,
                    }));
                }
            }
            Some("Page.javascriptDialogClosed") => {
                if let Some(session) = event.get("sessionId").and_then(Value::as_str) {
                    self.dialogs.remove(session);
                }
            }
            _=>{}
        }
        if event.get("method").and_then(Value::as_str) == Some("Fetch.requestPaused") {
            let request_id = event["params"]["requestId"].as_str().ok_or_else(fail)?;
            let address = event["params"]["request"]["url"].as_str().ok_or_else(fail)?;
            let session = event["sessionId"].as_str().ok_or_else(fail)?;
            // Fail closed: read-only public fetch and exact selected files.
            let allowed = self.accepts_url(address)
                && !matches!(event["params"]["request"]["method"].as_str(), Some(m) if m != "GET");
            if allowed {
                self.send_raw(Some(session), "Fetch.continueRequest",
                    json!({"requestId":request_id}))?;
            } else {
                self.send_raw(Some(session), "Fetch.failRequest",
                    json!({"requestId":request_id,"errorReason":"BlockedByClient"}))?;
            }
        }
        Ok(())
    }

    pub(in crate::browser_docs) fn command(
        &mut self, session: Option<&str>, method: &str, params: Value,
    ) -> io::Result<Value> {
        let id = self.send_raw(session, method, params)?;
        if let Some(ready) = self.pending.remove(&id) { return Self::check(ready); }
        let began = std::time::Instant::now();
        loop {
            let remaining = REQUEST_TIMEOUT.checked_sub(began.elapsed()).ok_or_else(fail)?;
            let message = match self.events.recv_timeout(remaining) {
                Ok(CdpEvent::Frame(v)) => v,
                _ => return Err(fail()),
            };
            if let Some(reply_id) = message.get("id").and_then(Value::as_u64) {
                if reply_id == id { return Self::check(message); }
                if self.abandoned.remove(&reply_id) { continue; }
                if self.pending.len() >= 64 { return Err(fail()); }
                self.pending.insert(reply_id, message);
            } else {
                self.on_event(&message)?;
            }
        }
    }

    fn drain_queued_events(&mut self) -> io::Result<()> {
        while let Ok(CdpEvent::Frame(v)) = self.events.try_recv() {
            if let Some(reply_id) = v.get("id").and_then(Value::as_u64) {
                if !self.abandoned.remove(&reply_id) && self.pending.len() < 64 {
                    self.pending.insert(reply_id, v);
                }
            } else {
                self.on_event(&v)?;
            }
        }
        Ok(())
    }

    fn command_or_dialog(
        &mut self, session: &str, method: &str, params: Value,
    ) -> io::Result<Option<Value>> {
        let id = self.send_raw(Some(session), method, params)?;
        if let Some(ready) = self.pending.remove(&id) { return Self::check(ready).map(Some); }
        let began = std::time::Instant::now();
        loop {
            let remaining = REQUEST_TIMEOUT.checked_sub(began.elapsed()).ok_or_else(fail)?;
            let message = match self.events.recv_timeout(remaining) {
                Ok(CdpEvent::Frame(v)) => v,
                _ => return Err(fail()),
            };
            if let Some(reply_id) = message.get("id").and_then(Value::as_u64) {
                if reply_id == id { return Self::check(message).map(Some); }
                if self.abandoned.remove(&reply_id) { continue; }
                if self.pending.len() >= 64 { return Err(fail()); }
                self.pending.insert(reply_id, message);
            } else {
                self.on_event(&message)?;
                if self.dialogs.contains_key(session) {
                    if self.abandoned.len() >= 64 { return Err(fail()); }
                    self.abandoned.insert(id);
                    return Ok(None);
                }
            }
        }
    }

    pub(in crate::browser_docs) fn active_dialog(&mut self, session: &str) -> io::Result<Option<Value>> {
        self.drain_queued_events()?;
        Ok(self.dialogs.get(session).cloned())
    }

    pub(in crate::browser_docs) fn handle_dialog(
        &mut self, session: &str, accept: bool, prompt_text: Option<&str>,
    ) -> io::Result<Value> {
        self.drain_queued_events()?;
        let previous = self.dialogs.get(session).cloned().ok_or_else(fail)?;
        let mut params = json!({"accept": accept});
        if let Some(text) = prompt_text {
            params["promptText"] = json!(text);
        }
        self.command(Some(session), "Page.handleJavaScriptDialog", params)?;
        self.dialogs.remove(session);
        self.drain_queued_events()?;
        Ok(previous)
    }

    fn check(reply: Value) -> io::Result<Value> {
        if reply.get("error").is_some() { return Err(fail()); }
        reply.get("result").cloned().ok_or_else(fail)
    }

    pub(in crate::browser_docs) fn file_url_at(&self, index: usize) -> Option<String> {
        self.allowed_files.get(index).cloned()
    }

    pub(in crate::browser_docs) fn create_page(&mut self) -> io::Result<(String,String)> {
        let created = self.command(None, "Target.createTarget",
            json!({"url":"about:blank"}))?;
        let target = created["targetId"].as_str().ok_or_else(fail)?.to_owned();
        let attached = self.command(None, "Target.attachToTarget",
            json!({"targetId":target,"flatten":true}))?;
        let session = attached["sessionId"].as_str().ok_or_else(fail)?.to_owned();
        self.command(Some(&session), "Page.enable", json!({}))?;
        self.command(Some(&session), "DOM.enable", json!({}))?;
        self.command(Some(&session), "Runtime.enable", json!({}))?;
        self.command(Some(&session), "Fetch.enable",
            json!({"patterns":[{"urlPattern":"*","requestStage":"Request"}]}))?;
        self.page_sessions.insert(target.clone(), session.clone());
        Ok((target,session))
    }

    pub(in crate::browser_docs) fn close_page(&mut self, target: &str) -> io::Result<()> {
        self.command(None, "Target.closeTarget", json!({"targetId":target}))?;
        if let Some(cdp_session) = self.page_sessions.remove(target) {
            self.dialogs.remove(&cdp_session);
        }
        Ok(())
    }

    pub(in crate::browser_docs) fn navigate(&mut self, session: &str, url: &str) -> io::Result<()> {
        if !self.accepts_url(url) { return Err(fail()); }
        let response = self.command(Some(session), "Page.navigate", json!({"url":url}))?;
        if response.get("errorText").is_some() { return Err(fail()); }
        Ok(())
    }

    pub(in crate::browser_docs) fn read(&mut self, session: &str) -> io::Result<Value> {
        // Constant provider-owned expression, NEVER a JS string from MCP.
        // A page's rendered text is obtained from the actual live DOM,
        // including effects of its own event handlers and form submission.
        const FIXED: &str =
            "({url:document.URL,title:document.title,text:document.body?document.body.innerText:''})";
        let result = self.command(Some(session), "Runtime.evaluate", json!({
            "expression":FIXED,"returnByValue":true,"awaitPromise":false
        }))?;
        if result.get("exceptionDetails").is_some() { return Err(fail()); }
        let value = result["result"]["value"].clone();
        let url = value["url"].as_str().ok_or_else(fail)?;
        if !self.accepts_url(url) { return Err(fail()); }
        Ok(value)
    }

    pub(in crate::browser_docs) fn dom_refs(&mut self, session: &str, maximum: usize) -> io::Result<Vec<Value>> {
        let doc = self.command(Some(session), "DOM.getDocument",
            json!({"depth":1,"pierce":false}))?;
        let root_id = doc["root"]["nodeId"].as_i64().ok_or_else(fail)?;
        let ids = self.command(Some(session), "DOM.querySelectorAll", json!({
            "nodeId":root_id,
            "selector":"a,button,input,textarea,select,[role=button],[role=link]"
        }))?;
        let mut result = Vec::new();
        for node in ids["nodeIds"].as_array().ok_or_else(fail)?.iter().take(maximum) {
            let Some(node_id) = node.as_i64() else { continue; };
            let desc = self.command(Some(session), "DOM.describeNode",
                json!({"nodeId":node_id,"depth":0}))?;
            let info = &desc["node"];
            let tag = info["nodeName"].as_str().unwrap_or("").to_ascii_lowercase();
            let fields = info["attributes"].as_array();
            let mut attrs = BTreeMap::<String,String>::new();
            if let Some(fields) = fields {
                for parts in fields.chunks_exact(2) {
                    if let (Some(key),Some(value))=(parts[0].as_str(),parts[1].as_str()){
                        if key.len()<=80 && value.len()<=512 {
                            attrs.insert(key.to_owned(),value.to_owned());
                        }
                    }
                }
            }
            let private = fields_sensitive(&attrs, &tag);
            let raw_label = attrs.get("aria-label")
                .or_else(||attrs.get("placeholder"))
                .or_else(||attrs.get("name"))
                .or_else(||attrs.get("id"))
                .map(String::as_str).unwrap_or(&tag);
            let label: String = raw_label.chars().take(100).collect();
            let entry = json!({
                "node_id":node_id,
                "backend_id":info["backendNodeId"],
                "tag":tag,"name":label,
                "type":attrs.get("type").map(String::as_str).unwrap_or(""),
                "url":attrs.get("href"),
                "sensitive":private
            });
            result.push(entry);
        }
        Ok(result)
    }

    fn element_center(&mut self, session: &str, node_id: i64) -> io::Result<(f64,f64)> {
        self.command(Some(session),"DOM.scrollIntoViewIfNeeded",json!({
            "nodeId":node_id
        }))?;
        let box_model=self.command(Some(session),"DOM.getBoxModel",
            json!({"nodeId":node_id}))?;
        let border=box_model["model"]["border"].as_array().ok_or_else(fail)?;
        if border.len()!=8 {return Err(fail());}
        let mut x=0.0;
        let mut y=0.0;
        for i in (0..8).step_by(2){
            x+=border[i].as_f64().ok_or_else(fail)?;
            y+=border[i+1].as_f64().ok_or_else(fail)?;
        }
        x/=4.0;
        y/=4.0;
        if !x.is_finite() || !y.is_finite() || x<0.0 || y<0.0
            || x>7680.0 || y>4320.0 {return Err(fail());}
        Ok((x,y))
    }

    pub(in crate::browser_docs) fn mouse_on(
        &mut self, session:&str, node_id:i64, click:bool,
    )->io::Result<()>{
        let (x,y)=self.element_center(session,node_id)?;
        self.command(Some(session),"Input.dispatchMouseEvent",json!({
            "type":"mouseMoved","x":x,"y":y
        }))?;
        if click {
            self.command(Some(session),"Input.dispatchMouseEvent",json!({
                "type":"mousePressed","x":x,"y":y,
                "button":"left","buttons":1,"clickCount":1
            }))?;
            self.command(Some(session),"Input.dispatchMouseEvent",json!({
                "type":"mouseReleased","x":x,"y":y,
                "button":"left","buttons":0,"clickCount":1
            }))?;
        }
        Ok(())
    }

    pub(in crate::browser_docs) fn drag_between(
        &mut self, session:&str, from:i64, to:i64,
    )->io::Result<()>{
        let (sx,sy)=self.element_center(session,from)?;
        let (tx,ty)=self.element_center(session,to)?;
        self.command(Some(session),"Input.dispatchMouseEvent",json!({
            "type":"mouseMoved","x":sx,"y":sy
        }))?;
        self.command(Some(session),"Input.dispatchMouseEvent",json!({
            "type":"mousePressed","x":sx,"y":sy,
            "button":"left","buttons":1,"clickCount":1
        }))?;
        for step in 1..=4 {
            let fraction=step as f64/4.0;
            self.command(Some(session),"Input.dispatchMouseEvent",json!({
                "type":"mouseMoved","x":sx+(tx-sx)*fraction,"y":sy+(ty-sy)*fraction,
                "button":"left","buttons":1
            }))?;
        }
        self.command(Some(session),"Input.dispatchMouseEvent",json!({
            "type":"mouseReleased","x":tx,"y":ty,
            "button":"left","buttons":0,"clickCount":1
        }))?;
        Ok(())
    }

    pub(in crate::browser_docs) fn selector_exists(
        &mut self,session:&str,selector:&str
    )->io::Result<bool>{
        if selector.is_empty()||selector.len()>128 || !selector.bytes().all(|b|
            b.is_ascii_alphanumeric() || matches!(b,b'#'|b'.'|b'_'|b'-')
        ){return Err(fail());}
        let doc=self.command(Some(session),"DOM.getDocument",
            json!({"depth":1,"pierce":false}))?;
        let root=doc["root"]["nodeId"].as_i64().ok_or_else(fail)?;
        let found=self.command(Some(session),"DOM.querySelector",
            json!({"nodeId":root,"selector":selector}))?;
        Ok(found["nodeId"].as_i64().is_some_and(|id|id>0))
    }

    pub(in crate::browser_docs) fn insert_text(
        &mut self,session:&str,node_id:i64,text:&str
    )->io::Result<()>{
        if text.is_empty()||text.len()>256{return Err(fail());}
        self.command(Some(session),"DOM.focus",json!({"nodeId":node_id}))?;
        self.command(Some(session),"Input.insertText",json!({"text":text}))?;
        Ok(())
    }

    pub(in crate::browser_docs) fn scroll_viewport(
        &mut self, session:&str, down:bool
    )->io::Result<()>{
        let metrics=self.command(Some(session),"Page.getLayoutMetrics",json!({}))?;
        let viewport=&metrics["cssLayoutViewport"];
        let width=viewport["clientWidth"].as_f64().ok_or_else(fail)?;
        let height=viewport["clientHeight"].as_f64().ok_or_else(fail)?;
        if !width.is_finite()||!height.is_finite()||width<10.0||height<10.0 {
            return Err(fail());
        }
        self.command(Some(session),"Input.dispatchMouseEvent",json!({
            "type":"mouseWheel",
            "x":width/2.0,"y":height/2.0,
            "deltaX":0,"deltaY":if down {440} else {-440}
        }))?;
        Ok(())
    }

    /// Select one exact locally admitted and physically pinned file through
    /// Chrome DOM.setFileInputFiles. Nothing is uploaded: the caller permits
    /// this ONLY on the owner-selected local page.
    pub(in crate::browser_docs) fn set_files(
        &mut self, session:&str, node:i64, path:&std::path::Path,
    )->io::Result<()>{
        let name=path.to_str().ok_or_else(fail)?;
        if name.is_empty()||name.len()>2048{return Err(fail());}
        self.command(Some(session),"DOM.setFileInputFiles",json!({
            "nodeId":node,"files":[name]
        }))?;
        Ok(())
    }

    /// Fixed provider-owned DOM observation, not an arbitrary JavaScript
    /// expression supplied by the Web agent. Return only name and byte size.
    pub(in crate::browser_docs) fn file_selection(
        &mut self,session:&str,node:i64,
    )->io::Result<(String,u64)>{
        let resolved=self.command(Some(session),"DOM.resolveNode",
            json!({"nodeId":node}))?;
        let object=resolved["object"]["objectId"].as_str().ok_or_else(fail)?;
        let response=self.command(Some(session),"Runtime.callFunctionOn",json!({
            "objectId":object,
            "functionDeclaration":"function(){const f=this.files&&this.files[0];return f?{name:f.name,size:f.size}:null;}",
            "returnByValue":true
        }))?;
        if response.get("exceptionDetails").is_some(){return Err(fail());}
        let value=&response["result"]["value"];
        let name=value["name"].as_str().ok_or_else(fail)?;
        let size=value["size"].as_u64().ok_or_else(fail)?;
        if name.is_empty()||name.len()>255
            || size>transfer::MAX_INPUT_BYTES as u64{return Err(fail());}
        Ok((name.to_owned(),size))
    }

    /// A *single* locally generated Blob download. Chrome first saves into
    /// its OWN pinned scratch tree, never into the project. The caller later
    /// copies verified bytes into a create-new project output file.
    pub(in crate::browser_docs) fn download_one(
        &mut self, session:&str, node:i64, frame:&str,
    )->io::Result<Vec<u8>>{
        if self.download.is_some()||frame.is_empty()||frame.len()>128 {
            return Err(fail());
        }
        let root=self.profile.download_root()?;
        let root_str=root.to_str().ok_or_else(fail)?;
        self.command(None,"Browser.setDownloadBehavior",json!({
            "behavior":"allowAndName","downloadPath":root_str,
            "eventsEnabled":true
        }))?;
        self.download=Some(ActiveDownload{
            expected_frame:frame.to_owned(),guid:None,
            completed:false,size:0,
        });
        let attempt=(||->io::Result<Vec<u8>>{
            self.call_element(session,node,"click",Value::Null)?;
            let started=std::time::Instant::now();
            while !self.download.as_ref().ok_or_else(fail)?.completed {
                let wait=Duration::from_secs(12).checked_sub(started.elapsed())
                    .ok_or_else(fail)?;
                let event=self.events.recv_timeout(wait).map_err(|_|fail())?;
                match event {
                    CdpEvent::Frame(value)=>{
                        if let Some(id)=value.get("id").and_then(Value::as_u64){
                            if self.pending.len()>=64{return Err(fail());}
                            self.pending.insert(id,value);
                        }else{self.on_event(&value)?;}
                    }
                    CdpEvent::End=>return Err(fail()),
                }
            }
            let record=self.download.as_ref().ok_or_else(fail)?;
            let guid=record.guid.as_deref().ok_or_else(fail)?;
            #[cfg(windows)]
            let bytes=transfer::read_private_download(
                &root,guid,transfer::MAX_DOWNLOAD_BYTES,
            )?;
            #[cfg(unix)]
            let bytes=self.profile.read_download(guid,transfer::MAX_DOWNLOAD_BYTES)?;
            if record.size!=bytes.len() as u64 {return Err(fail());}
            Ok(bytes)
        })();
        // Refuse a second download even if this one failed. Do not claim
        // success while the browser remains configured to save files.
        self.download=None;
        let disabled=self.command(None,"Browser.setDownloadBehavior",json!({
            "behavior":"deny","eventsEnabled":false
        }));
        disabled?;
        attempt
    }

    pub(in crate::browser_docs) fn screenshot(&mut self,session:&str)->io::Result<String>{
        let data=self.command(Some(session),"Page.captureScreenshot",json!({
            "format":"png","captureBeyondViewport":false,"fromSurface":true
        }))?;
        let encoded=data["data"].as_str().ok_or_else(fail)?;
        if encoded.is_empty() || encoded.len()>MAX_CDP_FRAME-1024
            || !encoded.bytes().all(|b| b.is_ascii_alphanumeric()
                || matches!(b,b'+'|b'/'|b'=')) {
            return Err(fail());
        }
        Ok(encoded.to_owned())
    }

    pub(in crate::browser_docs) fn call_element(
        &mut self, session: &str, node_id: i64, operation: &str, value: Value,
    ) -> io::Result<()> {
        let resolved = self.command(Some(session), "DOM.resolveNode",
            json!({"nodeId":node_id}))?;
        let object = resolved["object"]["objectId"].as_str().ok_or_else(fail)?;
        // All functionDeclarations are *fixed*, maintained Rust constants;
        // the agent can only supply typed scalar values through callArguments.
        let code = match operation {
            "click" => "function(){this.click();return true;}",
            "fill" => "function(v){this.focus();this.value=v;this.dispatchEvent(new Event('input',{bubbles:true}));this.dispatchEvent(new Event('change',{bubbles:true}));return true;}",
            "check" => "function(v){this.checked=v;this.dispatchEvent(new Event('input',{bubbles:true}));this.dispatchEvent(new Event('change',{bubbles:true}));return true;}",
            "select" => "function(v){this.value=v;this.dispatchEvent(new Event('input',{bubbles:true}));this.dispatchEvent(new Event('change',{bubbles:true}));return true;}",
            _ => return Err(fail()),
        };
        let args = if operation=="click" { vec![] } else { vec![json!({"value":value})] };
        let params = json!({
            "objectId":object,"functionDeclaration":code,
            "arguments":args,"returnByValue":true,"awaitPromise":false
        });
        let call = if operation == "click" {
            let Some(reply) = self.command_or_dialog(session, "Runtime.callFunctionOn", params)? else {
                return Ok(());
            };
            reply
        } else {
            self.command(Some(session), "Runtime.callFunctionOn", params)?
        };
        if call.get("exceptionDetails").is_some() || call["result"]["value"] != true {
            return Err(fail());
        }
        Ok(())
    }

    pub(in crate::browser_docs) fn history(&mut self, session: &str, dir: &str) -> io::Result<()> {
        match dir {
            "reload" => { self.command(Some(session),"Page.reload",json!({"ignoreCache":true}))?; }
            "back" | "forward" => {
                let h = self.command(Some(session),"Page.getNavigationHistory",json!({}))?;
                let current = h["currentIndex"].as_i64().ok_or_else(fail)?;
                let next = if dir=="back" { current-1 } else { current+1 };
                let entries = h["entries"].as_array().ok_or_else(fail)?;
                if next<0 || next as usize>=entries.len() {return Err(fail());}
                let entry = &entries[next as usize];
                let url = entry["url"].as_str().ok_or_else(fail)?;
                if !self.accepts_url(url){return Err(fail());}
                let target = entry["id"].as_i64().ok_or_else(fail)?;
                self.command(Some(session),"Page.navigateToHistoryEntry",json!({"entryId":target}))?;
            }
            _ => return Err(fail())
        }
        Ok(())
    }

    pub(in crate::browser_docs) fn key(&mut self, session: &str, key: &str) -> io::Result<()> {
        if !matches!(key,"Enter"|"Escape"|"Tab"|"ArrowDown"|"ArrowUp"){return Err(fail());}
        let code = match key {
            "Enter"=>"Enter","Escape"=>"Escape","Tab"=>"Tab",
            "ArrowDown"=>"ArrowDown","ArrowUp"=>"ArrowUp",_=>return Err(fail())
        };
        if self.command_or_dialog(session,"Input.dispatchKeyEvent",
            json!({"type":"keyDown","key":key,"code":code}))?.is_none() {
            return Ok(());
        }
        let _ = self.command_or_dialog(session,"Input.dispatchKeyEvent",
            json!({"type":"keyUp","key":key,"code":code}))?;
        Ok(())
    }

    fn stop_owned(&mut self) -> io::Result<()> {
        #[cfg(windows)]
        {
            self.job.finish(Duration::from_secs(3))?;
            let _ = self.child.wait();
            Ok(())
        }
        #[cfg(unix)]
        self.child.finish(Duration::from_secs(3))
    }

    pub(in crate::browser_docs) fn close(mut self) -> io::Result<()> {
        self.stop_owned()?;
        self.documents.clear();
        self.profile.cleanup()
    }
}

#[cfg(any(windows, unix))]
impl Drop for NativeChrome {
    fn drop(&mut self) {
        if self.stop_owned().is_err() {
            // A failed Job/group stop cannot authorize profile deletion.
            // Nested destructors only release pins in this state.
            self.profile.abandon_cleanup();
            return;
        }
        self.documents.clear();
        let _ = self.profile.cleanup();
    }
}

#[cfg(unix)]
pub(super) fn dump_dom(executable: &std::path::Path, profile: &std::path::Path, url: &str)
    -> io::Result<String>
{
    unixpipe::dump_dom(executable, profile, url)
}

fn fields_sensitive(attrs: &BTreeMap<String,String>, tag: &str) -> bool {
    if tag=="input" {
        let kind=attrs.get("type").map(String::as_str).unwrap_or("text").to_ascii_lowercase();
        if matches!(kind.as_str(),"password"|"hidden"|"file"|"email"|"tel"|"number"|"date"|"time") {return true;}
    }
    attrs.iter().any(|(k,v)| {
        if matches!(k.as_str(),"name"|"id"|"autocomplete"|"aria-label"|"placeholder") {
            let s=v.to_ascii_lowercase();
            ["password","secret","token","auth","credit","card","payment","private","email","ssn","phone"].iter().any(|w|s.contains(w))
        }else{false}
    })
}


#[cfg(all(test, unix))]
mod unix_chrome_tests {
    use super::*;

    /// Ubuntu/macOS CI sets this variable so a missing installed binary is a
    /// failing gate. Local transport-only suites may run without Chrome.
    fn chrome_available() -> bool {
        let issue = match installed_chrome() {
            Ok(_) => return true,
            Err(issue) => issue,
        };
        assert!(std::env::var_os("AGENT_BRIDGE_REQUIRE_NATIVE_CHROME").is_none(),
            "required system Chrome/Chromium installation is unavailable or refused: category={:?}, os_code={:?}",
            issue.kind(), issue.raw_os_error());
        eprintln!("native Chrome test skipped: no qualified system Chrome/Chromium installation; category={:?}, os_code={:?}",
            issue.kind(), issue.raw_os_error());
        false
    }

    #[test]
    fn unix_native_chrome_uses_private_pipes_and_cleans_its_profile() {
        let _installation = super::super::test_fixture::Guard::from_env()
            .expect("requested native Chrome fixture must qualify without fallback");
        if !chrome_available() { return; }
        let html = "<!doctype html><title>Owned Unix fixture</title><button id='go' onclick=\"document.getElementById('result').textContent='clicked-é'\">Go</button><p id='result'>ready</p>";
        let mut chrome = NativeChrome::start(&[("owned.html".into(), html.into())], vec![]).unwrap();
        let scratch = chrome.profile.chrome_data().unwrap().parent().unwrap().to_path_buf();
        let (target, session) = chrome.create_page().unwrap();
        let url = chrome.file_url_at(0).unwrap();
        chrome.navigate(&session, &url).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        loop {
            if chrome.read(&session).unwrap()["title"] == "Owned Unix fixture" { break; }
            assert!(std::time::Instant::now() < deadline, "selected page did not load");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(chrome.navigate(&session, "https://example.invalid/unapproved").is_err());
        let elements = chrome.dom_refs(&session, 10).unwrap();
        let button = elements.iter().find(|node| node["tag"] == "button").unwrap();
        chrome.call_element(&session, button["node_id"].as_i64().unwrap(), "click", Value::Null).unwrap();
        assert!(chrome.read(&session).unwrap()["text"].as_str().unwrap().contains("clicked-é"));
        assert!(chrome.screenshot(&session).unwrap().starts_with("iVBORw0KGgo"));
        chrome.close_page(&target).unwrap();
        chrome.close().unwrap();
        assert!(!scratch.exists(), "owned scratch/profile was not removed after group exit");
    }

    #[test]
    fn unix_inert_render_preserves_the_exact_selected_document() {
        let _installation = super::super::test_fixture::Guard::from_env()
            .expect("requested native Chrome fixture must qualify without fallback");
        if !chrome_available() { return; }
        let executable = installed_chrome().unwrap();
        let mut profile = PrivateProfile::create().unwrap();
        let scratch = profile.chrome_data().unwrap().parent().unwrap().to_path_buf();
        let body = "first line\n<& é>\nlast line\n";
        let rendered = render(&executable, &profile, body, &"a".repeat(64)).unwrap();
        assert_eq!(rendered.document, body);
        profile.cleanup().unwrap();
        assert!(!scratch.exists());
    }
}
