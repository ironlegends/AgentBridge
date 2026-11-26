//! Native Chrome interactive workstation mode. This is separate from the
//! existing README and public Learn readers, and must be attached as a mutually
//! exclusive browser provider by a LOCAL startup selection, never by Web MCP.
//! Only Rust + installed Chrome are runtime dependencies. CDP stays on Chrome's
//! anonymous private CDP pipes; no debugger TCP listener or agent CDP access.
use super::{chrome, read_payload, transfer};
use agent_bridge_desktop::{DesktopConfig, DesktopFiles};
use agent_bridge_gateway::{ToolCallResult, ToolContent, ToolDefinition, ToolMapHandler};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Component, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const TTL: Duration = Duration::from_secs(30);
const SESSION_AGE: Duration = Duration::from_secs(600);
const MAX_ELEMENTS: usize = 80;
const MAX_TEXT_CHARS: u64 = 50_000;
const PREFIX: &str = "bridge-project:///";
const MAX_LOCAL_DOCUMENTS: usize = 8;

fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "CHROME_NATIVE_SCOPE_REFUSED")
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "CHROME_NATIVE_INVALID_REQUEST")
}

/// Operator-selected LOCAL process arguments only. Never construct from MCP.
pub struct LocalInteractiveSelection {
    pub workspace: PathBuf,
    pub pages: Vec<String>,
    pub allowed_origins: Vec<String>,
}

pub struct LocalInteractiveApproval {
    #[cfg(windows)]
    project: PathBuf,
    pages: Vec<(String,String)>,
    origins: Vec<String>,
    approved_at: Instant,
    transfers: Option<ApprovedTransfers>,
    profile_root: Option<PathBuf>,
}

impl LocalInteractiveApproval {
    /// Opt-in operator-scoped directory for persistent MCP browser profiles
    /// (e.g. `<settings>/mcp-browser-profiles`). Never a personal Chrome dir.
    pub fn with_profile_root(mut self, root: PathBuf) -> io::Result<Self> {
        if !root.is_absolute() || root.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(denied());
        }
        if let Ok(meta) = std::fs::symlink_metadata(&root) {
            if !meta.is_dir() || meta.file_type().is_symlink() {
                return Err(denied());
            }
        }
        #[cfg(unix)]
        {
            if root.file_name() != Some(std::ffi::OsStr::new("mcp-browser-profiles")) {
                return Err(denied());
            }
            if root.exists() {
                chrome::native::DirectoryPin::open(&root)?.require_private()?;
            } else {
                chrome::native::DirectoryPin::open(root.parent().ok_or_else(denied)?)?;
            }
        }
        self.profile_root = Some(root);
        Ok(self)
    }
}

fn valid_profile_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

#[cfg(windows)]
fn remove_tree_no_symlinks(dir: &std::path::Path, depth: usize) -> io::Result<()> {
    if depth > 24 { return Err(chrome::operator_error("profile.delete.depth", denied())); }
    let meta = chrome::at_stage("profile.delete.metadata", std::fs::symlink_metadata(dir))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(chrome::operator_error("profile.delete.root_kind", denied()));
    }
    for entry in chrome::at_stage("profile.delete.enumerate", std::fs::read_dir(dir))? {
        let entry = chrome::at_stage("profile.delete.entry", entry)?;
        let path = entry.path();
        let md = chrome::at_stage("profile.delete.child_metadata", std::fs::symlink_metadata(&path))?;
        if md.file_type().is_symlink() {
            return Err(chrome::operator_error("profile.delete.symlink", denied()));
        }
        if md.is_dir() {
            remove_tree_no_symlinks(&path, depth + 1)?;
        } else {
            chrome::at_stage("profile.delete.file", std::fs::remove_file(&path))?;
        }
    }
    chrome::at_stage("profile.delete.directory", std::fs::remove_dir(dir))
}

#[cfg(unix)]
fn remove_tree_no_symlinks(dir: &std::path::Path, depth: usize) -> io::Result<()> {
    if depth != 0 { return Err(denied()); }
    chrome::native::remove_private_tree(dir)
}

#[cfg(windows)]
pub struct LocalTransferSelection {
    /// Exact project-relative, UTF-8 witness names selected by operator argv.
    /// Web can choose only among these names, never arbitrary host paths.
    pub upload_files: Vec<String>,
    /// Existing project-local output directory, chosen by operator argv.
    pub output_dir: String,
}

struct ApprovedTransfers {
    inputs: BTreeMap<String,transfer::ProjectInputPin>,
    output: transfer::ProjectOutputPin,
}

fn safe_path(s: &str) -> bool {
    if s.len()>512 || s.is_empty() || !s.is_ascii() || !s.ends_with(".html")
        || s.contains('\\') || s.contains(':') || s.contains('~')
        || s.starts_with('/') || s.ends_with('/')
    {return false;}
    s.split('/').all(|part| !part.is_empty() && !part.starts_with('.')
        && !part.ends_with('.') && !part.ends_with(' ')
        && part.bytes().all(|b|b.is_ascii_alphanumeric() || matches!(b,b'_'|b'-'|b'.')))
}

pub fn approve_local(selection: LocalInteractiveSelection) -> io::Result<LocalInteractiveApproval> {
    let LocalInteractiveSelection { workspace, pages, allowed_origins } = selection;
    if !workspace.is_absolute() || workspace.components().any(|c|matches!(c,Component::ParentDir))
        || pages.is_empty() || pages.len()>MAX_LOCAL_DOCUMENTS
        || pages.iter().any(|p| !safe_path(p))
        || pages.iter().collect::<BTreeSet<_>>().len()!=pages.len()
        || allowed_origins.len()>4
        || allowed_origins.iter().any(|o|o!="https://learn.microsoft.com")
    {return Err(denied());}
    let _ = chrome::installed_chrome()?;
    #[cfg(windows)]
    let _pin = agent_bridge_lifecycle::workspace_access::PinnedProjectDirectory::open(&workspace)
        .map_err(|_|denied())?;
    #[cfg(unix)]
    let _pin = chrome::native::DirectoryPin::open(&workspace).map_err(|_| denied())?;
    #[cfg(not(any(windows, unix)))]
    return Err(denied());
    let files = DesktopFiles::open(
        DesktopConfig::new(&workspace).with_web_project_read_policy()
    ).map_err(|_|denied())?;
    let mut owned = Vec::new();
    for path in pages {
        let meta = read_payload(&files,"desktop_get_file_info",&path)?;
        if meta["kind"].as_str()!=Some("file")
            || meta["bytes"].as_u64().is_none_or(|size|size>96*1024)
        {return Err(denied());}
        let view=read_payload(&files,"desktop_read_file",&path)?;
        if view["truncated"].as_bool()!=Some(false){return Err(denied());}
        let text=view["content"].as_str().ok_or_else(denied)?;
        if text.len()>96*1024||text.is_empty(){return Err(denied());}
        owned.push((path,text.to_owned()));
    }
    // No process is launched during local admission.
    Ok(LocalInteractiveApproval {
        #[cfg(windows)]
        project:workspace,
        pages:owned,origins:allowed_origins,
        approved_at:Instant::now(),transfers:None,profile_root:None,
    })
}

/// Additional local approval for the two file-transfer actions. Separate from
/// the read-only project page approval, so existing sessions retain NO file
/// rights. Use only after the operator has selected a writable project profile.
#[cfg(windows)]
pub fn approve_local_with_transfers(
    selection:LocalInteractiveSelection,
    files:LocalTransferSelection,
)->io::Result<LocalInteractiveApproval>{
    let mut approval=approve_local(selection)?;
    // A file input can expose selected bytes to the page's JavaScript.
    // Transfer grants are valid ONLY on the exact source-controlled, inert-
    // network demo fixture, never on arbitrary project or public pages.
    // DesktopFiles strips at most the optional final LF of returned text.
    // Admit only byte-identical fixed fixture content modulo that *one*
    // transport terminator; never accept other HTML/script changes.
    let local=approval.pages.first()
        .map(|p|p.1.replace("\r\n","\n")).ok_or_else(denied)?;
    let embedded=include_str!("interaction_fixture.html").replace("\r\n","\n");
    let same_fixture=local==embedded
        || embedded.strip_suffix('\n')==Some(local.as_str());
    if approval.pages.len()!=1
        || approval.pages[0].0!="rust/cli/src/browser_docs/interaction_fixture.html"
        || !same_fixture || !approval.origins.is_empty()
    {return Err(chrome::operator_error("transfer.fixture_identity",denied()));}
    if files.upload_files.is_empty() || files.upload_files.len()>4
        || files.upload_files.iter().collect::<BTreeSet<_>>().len()!=files.upload_files.len()
        || !transfer::safe_relative_dir(&files.output_dir)
    {return Err(chrome::operator_error("transfer.selection_limits",denied()));}
    let facade=DesktopFiles::open(
        DesktopConfig::new(&approval.project).with_web_project_read_policy()
    ).map_err(|_|chrome::operator_error("transfer.desktop_facade",denied()))?;
    let mut inputs=BTreeMap::new();
    for path in files.upload_files {
        if !transfer::safe_relative_file(&path) {return Err(chrome::operator_error("transfer.relative_file",denied()));}
        // Existing DesktopFiles checks policy BEFORE metadata/read. Its
        // private-setting exclusions and symlink rules still apply.
        let meta=read_payload(&facade,"desktop_get_file_info",&path)?;
        if meta["kind"].as_str()!=Some("file")
            || meta["bytes"].as_u64().is_none_or(|n|
                n==0||n>transfer::MAX_INPUT_BYTES as u64)
        {return Err(chrome::operator_error("transfer.metadata",denied()));}
        let body=read_payload(&facade,"desktop_read_file",&path)?;
        if body["truncated"]!=false {return Err(chrome::operator_error("transfer.bounded_read",denied()));}
        let expected=body["sha256"].as_str().ok_or_else(denied)?;
        let mut pin=transfer::ProjectInputPin::open(&approval.project,&path)
            .map_err(|e|chrome::operator_error("transfer.input_pin_open",e))?;
        pin.verify().map_err(|e|chrome::operator_error("transfer.input_pin_verify",e))?;
        if pin.sha256!=expected || pin.size!=meta["bytes"].as_u64().ok_or_else(denied)?{
            return Err(chrome::operator_error("transfer.input_digest",denied()));
        }
        inputs.insert(path,pin);
    }
    let output=transfer::ProjectOutputPin::open(&approval.project,&files.output_dir)
        .map_err(|e|chrome::operator_error("transfer.output_pin_open",e))?;
    approval.transfers=Some(ApprovedTransfers{inputs,output});
    Ok(approval)
}

#[derive(Clone)]
struct Element {
    name:String,
    node_id:i64,
    backend_id:i64,
    tag:String,
    kind:String,
    href:Option<String>,
    sensitive:bool,
}
struct Observation {
    id:String,
    at:Instant,
    url:String,
    loader:String,
    history_id:i64,
    refs:BTreeMap<String,Element>,
}
struct Tab {
    target:String,
    session:String,
    last_url:String,
    observation:Option<Observation>,
}
struct BrowserSession {
    downloads_attempted: u8,
    id: String,
    profile_id: Option<String>,
    started: Instant,
    current: String,
    tabs: BTreeMap<String, Tab>,
    #[cfg(any(windows, unix))]
    chrome: chrome::NativeChrome,
}
pub struct NativeProvider {
    approval:LocalInteractiveApproval,
    consumed:bool,
    session:Option<BrowserSession>,
}

fn object_keys(args:&Map<String,Value>,permitted:&[&str])->io::Result<()> {
    if args.keys().any(|key|!permitted.contains(&key.as_str())){return Err(invalid());}
    Ok(())
}
fn required<'a>(args:&'a Map<String,Value>,key:&str)->io::Result<&'a str> {
    args.get(key).and_then(Value::as_str).ok_or_else(invalid)
}
fn flag_false(args:&Map<String,Value>,key:&str)->io::Result<()> {
    if args.get(key).is_some_and(|v|v.as_bool()!=Some(false)){return Err(invalid());}
    Ok(())
}
fn wants_screenshot(args:&Map<String,Value>)->io::Result<bool>{
    match args.get("screenshot"){
        None=>Ok(false),
        Some(Value::Bool(want))=>Ok(*want),
        _=>Err(invalid())
    }
}
fn max_text(args:&Map<String,Value>)->io::Result<usize>{
    match args.get("max_text_chars") {
        None=>Ok(8000),
        Some(v)=>match v.as_u64(){Some(chars @ 1..=MAX_TEXT_CHARS)=>Ok(chars as usize),_=>Err(invalid())}
    }
}
fn public_origin(url:&str)->bool {
    url.starts_with("https://learn.microsoft.com/en-us/")
        && !url.contains('@') && !url.contains('\\') && url.len()<=1024
}

impl NativeProvider {
    pub fn new(approval:LocalInteractiveApproval)->Self {
        Self {approval,consumed:false,session:None}
    }

    fn logical_url(&self,url:&str)->Option<String> {
        let session=self.session.as_ref()?;
        for (i,(name,_)) in self.approval.pages.iter().enumerate() {
            let owned=session.chrome.file_url_at(i)?;
            if url==owned || url.starts_with(&(owned.clone()+"#")) {
                let hash=url.strip_prefix(&owned).unwrap_or("");
                return Some(format!("{PREFIX}{name}{hash}"));
            }
        }
        public_origin(url).then_some(url.to_owned())
    }

    fn resolve_url(&self, url:&str)->io::Result<String>{
        if let Some(relative)=url.strip_prefix(PREFIX){
            if let Some((i,_))=self.approval.pages.iter().enumerate().find(|(_,p)|p.0==relative){
                return self.session.as_ref().ok_or_else(denied)?
                    .chrome.file_url_at(i).ok_or_else(denied);
            }
        }
        if self.approval.origins.iter().any(|x|x=="https://learn.microsoft.com") && public_origin(url){
            return Ok(url.to_owned());
        }
        Err(denied())
    }

    fn start(&mut self,args:Map<String,Value>)->io::Result<Value> {
        object_keys(&args,&["action","profile_id"])?;
        if self.consumed || self.session.is_some()
            || self.approval.approved_at.elapsed()>SESSION_AGE {return Err(denied());}
        let requested_profile: Option<String> = match args.get("profile_id") {
            None => None,
            Some(v) => {
                let id = v.as_str().ok_or_else(invalid)?;
                if !valid_profile_id(id) { return Err(invalid()); }
                Some(id.to_owned())
            }
        };
        let persistent_dir = if let Some(pid) = &requested_profile {
            let root = self.approval.profile_root.as_ref().ok_or_else(denied)?;
            #[cfg(unix)]
            let dir = {
                let root = chrome::native::ensure_private_directory(root)?;
                let dir = root.path().join(pid);
                chrome::native::ensure_private_directory(&dir)?;
                dir
            };
            #[cfg(windows)]
            let dir = {
            if let Ok(meta) = std::fs::symlink_metadata(root) {
                if !meta.is_dir() || meta.file_type().is_symlink() { return Err(denied()); }
            } else {
                std::fs::create_dir(root)?;
            }
            let dir = root.join(pid);
            if let Ok(meta) = std::fs::symlink_metadata(&dir) {
                if !meta.is_dir() || meta.file_type().is_symlink() { return Err(denied()); }
            } else {
                std::fs::create_dir(&dir)?;
            }
                dir
            };
            Some(dir)
        } else {
            None
        };
        #[cfg(not(any(windows, unix)))]
        {
            let _ = persistent_dir;
            return Err(denied());
        }
        #[cfg(any(windows, unix))]
        {
            let mut chrome=chrome::NativeChrome::start_with_profile(
                &self.approval.pages,
                self.approval.origins.clone(),
                persistent_dir.as_deref(),
            )?;
            let (target,cdp_session)=chrome.create_page()?;
            let first=chrome.file_url_at(0).ok_or_else(denied)?;
            chrome.navigate(&cdp_session,&first)?;
            let id=chrome::random_id()?;
            let page_id=chrome::random_id()?;
            let mut tabs=BTreeMap::new();
            tabs.insert(page_id.clone(),Tab{
                target,session:cdp_session,last_url:first,observation:None
            });
            self.consumed=true;
            let profile_label = requested_profile.clone().unwrap_or_else(|| "bridge_private_ephemeral".to_owned());
            let persistent = requested_profile.is_some();
            self.session=Some(BrowserSession{
                downloads_attempted:0,
                id:id.clone(),profile_id:requested_profile,started:Instant::now(),current:page_id.clone(),tabs,chrome
            });
            Ok(json!({"action":"start","session_id":id,"page_id":page_id,
                "url":format!("{PREFIX}{}",&self.approval.pages[0].0),
                "browser_engine":"installed_chrome","transport":"private_cdp_pipe",
                "profile":profile_label,"profile_persistent":persistent,"tabs":1}))
        }
    }

    fn check_session(&mut self,args:&Map<String,Value>)->io::Result<String>{
        let session=self.session.as_ref().ok_or_else(denied)?;
        if session.started.elapsed()>SESSION_AGE || required(args,"session_id")?!=session.id {
            return Err(denied());
        }
        let id=args.get("page_id").and_then(Value::as_str)
            .unwrap_or(&session.current).to_owned();
        if !session.tabs.contains_key(&id){return Err(denied());}
        Ok(id)
    }

    fn info(&mut self, session:&str)->io::Result<(Value,String,i64)>{
        let read=self.session.as_mut().ok_or_else(denied)?
            .chrome.read(session)?;
        let frame=self.session.as_mut().ok_or_else(denied)?
            .chrome.command(Some(session),"Page.getFrameTree",json!({}))?;
        let loader=frame["frameTree"]["frame"]["loaderId"].as_str()
            .ok_or_else(denied)?.to_owned();
        let history=self.session.as_mut().ok_or_else(denied)?
            .chrome.command(Some(session),"Page.getNavigationHistory",json!({}))?;
        let index=history["currentIndex"].as_u64().ok_or_else(denied)? as usize;
        let id=history["entries"].as_array().and_then(|entries|entries.get(index))
            .and_then(|entry|entry["id"].as_i64()).ok_or_else(denied)?;
        Ok((read,loader,id))
    }

    /// Resolve only a reference from the consumed, matching observation.
    /// Prevent numeric DOM node IDs from silently referring to a replacement.
    fn check_live_element(&mut self,cdp:&str,element:&Element)->io::Result<()>{
        let desc=self.session.as_mut().ok_or_else(denied)?
            .chrome.command(Some(cdp),"DOM.describeNode",json!({
                "nodeId":element.node_id,"depth":0
            }))?;
        if desc["node"]["backendNodeId"].as_i64()!=Some(element.backend_id)
            || desc["node"]["nodeName"].as_str().map(str::to_ascii_lowercase)
                .as_deref()!=Some(element.tag.as_str()) {
            return Err(denied());
        }
        Ok(())
    }

    fn fresh_snapshot(&mut self, page_id:&str, max:usize, find:Option<&str>)->io::Result<Value>{
        let cdp_session=self.session.as_ref().ok_or_else(denied)?
            .tabs.get(page_id).ok_or_else(denied)?.session.clone();
        let expected=self.session.as_ref().ok_or_else(denied)?
            .tabs.get(page_id).ok_or_else(denied)?.last_url.clone();
        let began=Instant::now();
        let (read,loader,history_id)=loop {
            let (v,l,h)=self.info(&cdp_session)?;
            let url=v["url"].as_str().ok_or_else(denied)?;
            if (url==expected || (expected=="about:blank"&&url=="about:blank")
                || url.starts_with(&(expected.clone()+"#")))
                && (!v["title"].as_str().unwrap_or("").is_empty()||url=="about:blank")
            {
                break (v,l,h);
            }
            if began.elapsed()>Duration::from_secs(8){return Err(denied());}
            thread::sleep(Duration::from_millis(75));
        };
        let current=read["url"].as_str().ok_or_else(denied)?.to_owned();
        let logical=self.logical_url(&current).ok_or_else(denied)?;
        let title:String=read["title"].as_str().unwrap_or("").chars().take(512).collect();
        let full=read["text"].as_str().ok_or_else(denied)?;
        let text:String=full.chars().take(max).collect();
        let truncated=full.chars().nth(max).is_some();
        let elements=self.session.as_mut().ok_or_else(denied)?
            .chrome.dom_refs(&cdp_session,MAX_ELEMENTS)?;
        let mut refs=BTreeMap::new();
        let mut presented=Vec::new();
        let allow_transfer_input=self.approval.transfers.is_some()
            && self.approval.pages.iter().enumerate().any(|(i,_)|
                self.session.as_ref().and_then(|s|s.chrome.file_url_at(i))
                    .is_some_and(|u|current==u||current.starts_with(&(u+"#"))));
        for entry in elements {
            let is_selected_file_input=allow_transfer_input
                && entry["tag"].as_str()==Some("input")
                && entry["type"].as_str()==Some("file")
                && entry["name"].as_str()==Some("Witness upload");
            if entry["sensitive"].as_bool()!=Some(false)
                && !is_selected_file_input {continue;}
            let Some(node)=entry["node_id"].as_i64() else {continue;};
            let backend=entry["backend_id"].as_i64().unwrap_or(0);
            let tag=entry["tag"].as_str().unwrap_or("").to_owned();
            let kind=entry["type"].as_str().unwrap_or("").to_owned();
            let name=entry["name"].as_str().unwrap_or("").to_owned();
            let href=entry["url"].as_str().map(str::to_owned);
            let reference=format!("e{}",refs.len()+1);
            refs.insert(reference.clone(),Element{
                name:name.clone(),
                node_id:node,backend_id:backend,tag:tag.clone(),
                kind:kind.clone(),href:href.clone(),sensitive:false
            });
            presented.push(json!({"ref":reference,"role":tag,"name":name,
                "input_type":kind,"href":href}));
        }
        let obs_id=chrome::random_id()?;
        let obs=Observation{
            id:obs_id.clone(),at:Instant::now(),url:current.clone(),
            loader,history_id,refs
        };
        let session=self.session.as_mut().ok_or_else(denied)?;
        session.tabs.get_mut(page_id).ok_or_else(denied)?.observation=Some(obs);
        let mut result=json!({"session_id":session.id,"page_id":page_id,
            "url":logical,"title":title,"text":text,"text_truncated":truncated,
            "interactive_elements":presented,"element_count":session.tabs[page_id].observation.as_ref()
                .map_or(0,|o|o.refs.len()),"browser_observation_id":obs_id,
            "browser_engine":"installed_chrome","transport":"private_cdp_pipe",
            "render_verified":true,"screenshot":null,"console":null,"network":null,
            "read_only":false
        });
        if let Some(query)=find{
            if query.is_empty()||query.len()>256{return Err(invalid());}
            let matched:Vec<Value>=full.lines().enumerate()
                .filter(|(_,line)|line.to_ascii_lowercase().contains(&query.to_ascii_lowercase()))
                .take(20)
                .map(|(i,line)|json!({"line":i+1,"snippet":line.chars().take(180).collect::<String>()}))
                .collect();
            result["mode"]=json!("find");
            result["matches"]=json!(matched);
        } else {result["mode"]=json!("full");}
        Ok(result)
    }

    fn session_manage(&mut self,args:Map<String,Value>)->io::Result<Value>{
        match required(&args,"action")?{
            "start"=>self.start(args),
            "list"=>{
                object_keys(&args,&["action"])?;
                let sessions:Vec<Value>=self.session.iter().map(|s|json!({
                    "session_id":s.id,"page_id":s.current,"tabs":s.tabs.len()
                })).collect();
                Ok(json!({"action":"list","sessions":sessions,"count":sessions.len()}))
            }
            "close"=>{
                object_keys(&args,&["action","session_id"])?;
                self.check_session(&args)?;
                let session=self.session.take().ok_or_else(denied)?;
                session.chrome.close()?;
                Ok(json!({"action":"close","closed":true,
                    "owned_chrome_exited":true,"temporary_profile_removed":true}))
            }
            "new_page"=>{
                object_keys(&args,&["action","session_id","url"])?;
                self.check_session(&args)?;
                let url=args.get("url").and_then(Value::as_str).map(|v|self.resolve_url(v))
                    .transpose()?.unwrap_or_else(||"about:blank".to_owned());
                let session=self.session.as_mut().ok_or_else(denied)?;
                if session.tabs.len()>=3{return Err(denied());}
                let (target,cdp)=session.chrome.create_page()?;
                session.chrome.navigate(&cdp,&url)?;
                let page_id=chrome::random_id()?;
                session.tabs.insert(page_id.clone(),Tab{
                    target,session:cdp,last_url:url,observation:None
                });
                session.current=page_id.clone();
                Ok(json!({"action":"new_page","page_id":page_id,
                    "session_id":session.id,"tabs":session.tabs.len()}))
            }
            "select_page"=>{
                object_keys(&args,&["action","session_id","page_id"])?;
                let page=self.check_session(&args)?;
                let session=self.session.as_mut().ok_or_else(denied)?;
                session.current=page.clone();
                Ok(json!({"action":"select_page","page_id":page}))
            }
            "close_page"=>{
                object_keys(&args,&["action","session_id","page_id"])?;
                let page=self.check_session(&args)?;
                let session=self.session.as_mut().ok_or_else(denied)?;
                if session.tabs.len()<=1{return Err(denied());}
                let tab=session.tabs.remove(&page).ok_or_else(denied)?;
                session.chrome.close_page(&tab.target)?;
                if session.current==page {
                    session.current=session.tabs.keys().next().ok_or_else(denied)?.to_owned();
                }
                Ok(json!({"action":"close_page","page_id":page,"tabs":session.tabs.len()}))
            }
            "handle_dialog"=>{
                object_keys(&args,&["action","session_id","page_id","accept","prompt_text"])?;
                let page=self.check_session(&args)?;
                let accept=args.get("accept").and_then(Value::as_bool).ok_or_else(invalid)?;
                let prompt_text=match args.get("prompt_text") {
                    None => None,
                    Some(v) => {
                        let s=v.as_str().ok_or_else(invalid)?;
                        if s.len()>4096 || s.chars().any(char::is_control) { return Err(invalid()); }
                        Some(s)
                    }
                };
                let cdp=self.session.as_ref().ok_or_else(denied)?
                    .tabs.get(&page).ok_or_else(denied)?.session.clone();
                let dialog=self.session.as_mut().ok_or_else(denied)?
                    .chrome.handle_dialog(&cdp,accept,prompt_text)?;
                let sid=self.session.as_ref().ok_or_else(denied)?.id.clone();
                Ok(json!({"action":"handle_dialog","session_id":sid,"page_id":page,
                    "handled":true,"accept":accept,"dialog":dialog}))
            }
            "list_profiles"=>{
                object_keys(&args,&["action"])?;
                let root=self.approval.profile_root.as_ref().ok_or_else(denied)?;
                let active_id=self.session.as_ref().and_then(|s|s.profile_id.as_deref());
                let mut profiles=Vec::new();
                if let Ok(meta)=std::fs::symlink_metadata(root) {
                    if !meta.is_dir() || meta.file_type().is_symlink() { return Err(denied()); }
                    let mut names=Vec::new();
                    for entry in std::fs::read_dir(root)? {
                        let entry=entry?;
                        let md=std::fs::symlink_metadata(entry.path())?;
                        if !md.is_dir() || md.file_type().is_symlink() { continue; }
                        if let Some(name)=entry.file_name().to_str() {
                            if valid_profile_id(name) { names.push(name.to_owned()); }
                        }
                    }
                    names.sort();
                    for name in names.into_iter().take(64) {
                        profiles.push(json!({
                            "profile_id": name,
                            "active": active_id == Some(name.as_str()),
                        }));
                    }
                }
                Ok(json!({"action":"list_profiles","profiles":profiles,"count":profiles.len()}))
            }
            "delete_profile"=>{
                object_keys(&args,&["action","profile_id"])?;
                let root=self.approval.profile_root.as_ref().ok_or_else(denied)?;
                let pid=required(&args,"profile_id")?;
                if !valid_profile_id(pid) { return Err(invalid()); }
                if self.session.as_ref().and_then(|s|s.profile_id.as_deref()) == Some(pid) {
                    return Err(denied());
                }
                let root_meta=std::fs::symlink_metadata(root).map_err(|_|denied())?;
                if !root_meta.is_dir() || root_meta.file_type().is_symlink() { return Err(denied()); }
                let target=root.join(pid);
                let target_meta=std::fs::symlink_metadata(&target).map_err(|_|denied())?;
                if !target_meta.is_dir() || target_meta.file_type().is_symlink() { return Err(denied()); }
                remove_tree_no_symlinks(&target, 0)?;
                Ok(json!({"action":"delete_profile","profile_id":pid,"deleted":true}))
            }
            _=>Err(denied())
        }
    }

    fn with_screenshot(&mut self,page_id:&str,mut output:Value,want:bool)->io::Result<Value>{
        if want{
            let session=self.session.as_ref().ok_or_else(denied)?
                .tabs.get(page_id).ok_or_else(denied)?.session.clone();
            let png=self.session.as_mut().ok_or_else(denied)?
                .chrome.screenshot(&session)?;
            output["_screenshot_png_base64"]=json!(png);
            output["screenshot"]=json!({"mime_type":"image/png","capture":"live_chrome_viewport"});
        }
        Ok(output)
    }

    fn snapshot(&mut self,args:Map<String,Value>)->io::Result<Value>{
        object_keys(&args,&["session_id","page_id","mode","find_query",
            "max_text_chars","screenshot","full_page","include_console","include_network"])?;
        for flag in ["full_page","include_console","include_network"] {
            flag_false(&args,flag)?;
        }
        let screenshot=wants_screenshot(&args)?;
        let page=self.check_session(&args)?;
        let max=max_text(&args)?;
        let find=match args.get("mode").and_then(Value::as_str).unwrap_or("full"){
            "full"=>{
                if args.contains_key("find_query"){return Err(invalid());}None
            },
            "find"=>Some(required(&args,"find_query")?.to_owned()),
            _=>return Err(invalid())
        };
        self.session.as_mut().ok_or_else(denied)?
            .tabs.get_mut(&page).ok_or_else(denied)?.observation=None;
        let cdp_id=self.session.as_ref().ok_or_else(denied)?
            .tabs.get(&page).ok_or_else(denied)?.session.clone();
        if let Some(dialog)=self.session.as_mut().ok_or_else(denied)?.chrome.active_dialog(&cdp_id)? {
            let sid=self.session.as_ref().ok_or_else(denied)?.id.clone();
            let last=self.session.as_ref().ok_or_else(denied)?.tabs[&page].last_url.clone();
            let logical=self.logical_url(&last).unwrap_or_else(||"about:blank".to_owned());
            return Ok(json!({"session_id":sid,"page_id":page,"url":logical,
                "dialog_open":true,"blocking_dialog":dialog}));
        }
        let result=self.fresh_snapshot(&page,max,find.as_deref())?;
        self.with_screenshot(&page,result,screenshot)
    }

    fn act(&mut self,args:Map<String,Value>)->io::Result<Value>{
        object_keys(&args,&["session_id","page_id","browser_observation_id",
            "actions","max_text_chars","screenshot","full_page","include_console","include_network"])?;
        for flag in ["full_page","include_console","include_network"]{
            flag_false(&args,flag)?;
        }
        let screenshot=wants_screenshot(&args)?;
        let page=self.check_session(&args)?;
        let max=max_text(&args)?;
        let obs=self.session.as_mut().ok_or_else(denied)?
            .tabs.get_mut(&page).ok_or_else(denied)?.observation.take().ok_or_else(denied)?;
        if obs.id!=required(&args,"browser_observation_id")? || obs.at.elapsed()>TTL{
            return Err(denied());
        }
        let actions=args.get("actions").and_then(Value::as_array).ok_or_else(invalid)?;
        if actions.len()!=1{return Err(denied());}
        let action=actions[0].as_object().ok_or_else(invalid)?;
        let kind=required(action,"type")?;
        let cdp=self.session.as_ref().ok_or_else(denied)?
            .tabs.get(&page).ok_or_else(denied)?.session.clone();
        let (status,loader,history_id)=self.info(&cdp)?;
        if status["url"].as_str()!=Some(&obs.url)
            || loader!=obs.loader || history_id!=obs.history_id {
            return Err(denied());
        }
        if matches!(kind,"click"|"fill"|"type_text"|"set_checked"|"select"|"press"|"drag"|"set_files"|"download"){
            // Write to project HTML only. Remote documentation remains read-only
            // except for safe link navigation via browser click.
            let project_page=self.approval.pages.iter().enumerate().any(|(i,_)|
                self.session.as_ref().and_then(|s|s.chrome.file_url_at(i))
                    .is_some_and(|u|obs.url.starts_with(&u)));
            if !project_page && kind!="click" {return Err(denied());}
            if !project_page && kind=="click" {
                let reference=required(action,"ref")?;
                if obs.refs.get(reference).is_none_or(|e|e.tag!="a") {
                    return Err(denied()); // Never submit a third-party form.
                }
            }
        }
        let mut transfer_receipt:Option<Value>=None;
        match kind {
            "set_files"=>{
                object_keys(action,&["type","ref","files"])?;
                let refs=action.get("files").and_then(Value::as_array).ok_or_else(invalid)?;
                if refs.len()!=1{return Err(denied());}
                let selected=refs[0].as_str().ok_or_else(invalid)?;
                let reference=required(action,"ref")?;
                let element=obs.refs.get(reference).ok_or_else(denied)?;
                if element.tag!="input" || element.kind!="file"
                    || element.name!="Witness upload" || element.sensitive {
                    return Err(denied());
                }
                self.check_live_element(&cdp,element)?;
                let (path,basename,expected_size,digest)={
                    let input=self.approval.transfers.as_mut()
                        .and_then(|t|t.inputs.get_mut(selected)).ok_or_else(denied)?;
                    let path=input.verify()?;
                    (path,input.basename.clone(),input.size,input.sha256.clone())
                };
                self.session.as_mut().ok_or_else(denied)?.chrome.set_files(
                    &cdp,element.node_id,&path
                )?;
                let observed=self.session.as_mut().ok_or_else(denied)?.chrome.file_selection(
                    &cdp,element.node_id
                )?;
                self.approval.transfers.as_mut().and_then(|t|t.inputs.get_mut(selected))
                    .ok_or_else(denied)?.verify()?;
                if observed.0!=basename || observed.1!=expected_size {
                    return Err(denied());
                }
                transfer_receipt=Some(json!({
                    "action":"set_files",
                    "relative_path":selected,
                    "name":observed.0,
                    "size_bytes":observed.1,
                    "sha256":digest,
                    "physical_identity_verified":true,
                    "chrome_dom_file_verified":true,
                    "network_upload":false
                }));
            }
            "download"=>{
                object_keys(action,&["type","ref"])?;
                let reference=required(action,"ref")?;
                let element=obs.refs.get(reference).ok_or_else(denied)?;
                if element.tag!="button" || element.name!="Download witness"
                    || element.sensitive || self.approval.transfers.is_none() {
                    return Err(denied());
                }
                self.check_live_element(&cdp,element)?;
                {
                    let session=self.session.as_mut().ok_or_else(denied)?;
                    if session.downloads_attempted>=1{return Err(denied());}
                    session.downloads_attempted=1;
                }
                let frame=self.session.as_mut().ok_or_else(denied)?.chrome.command(
                    Some(&cdp),"Page.getFrameTree",json!({})
                )?;
                let frame_id=frame["frameTree"]["frame"]["id"]
                    .as_str().ok_or_else(denied)?.to_owned();
                let bytes=self.session.as_mut().ok_or_else(denied)?
                    .chrome.download_one(&cdp,element.node_id,&frame_id)?;
                let filename=format!("agent-bridge-download-{}.txt",chrome::random_id()?);
                let (relative,size,digest)=self.approval.transfers.as_ref()
                    .ok_or_else(denied)?.output.write_new(&filename,&bytes)?;
                transfer_receipt=Some(json!({
                    "action":"download",
                    "relative_output_path":relative,
                    "size_bytes":size,
                    "sha256":digest,
                    "source":"local_project_page_blob",
                    "new_file_only":true,
                    "readback_sha256_verified":true
                }));
            }
            "goto"=>{
                object_keys(action,&["type","url"])?;
                let url=self.resolve_url(required(action,"url")?)?;
                self.session.as_mut().ok_or_else(denied)?.chrome.navigate(&cdp,&url)?;
                self.session.as_mut().ok_or_else(denied)?
                    .tabs.get_mut(&page).ok_or_else(denied)?.last_url=url;
            }
            "navigation"=>{
                object_keys(action,&["type","direction"])?;
                let dir=required(action,"direction")?;
                self.session.as_mut().ok_or_else(denied)?.chrome.history(&cdp,dir)?;
                // After history navigation, derive the new URL from Chrome.
                let h=self.session.as_mut().ok_or_else(denied)?.chrome.command(
                    Some(&cdp),"Page.getNavigationHistory",json!({}))?;
                let i=h["currentIndex"].as_u64().ok_or_else(denied)? as usize;
                let next=h["entries"].as_array().and_then(|e|e.get(i))
                    .and_then(|v|v["url"].as_str()).ok_or_else(denied)?;
                if self.logical_url(next).is_none(){return Err(denied());}
                self.session.as_mut().ok_or_else(denied)?
                    .tabs.get_mut(&page).ok_or_else(denied)?.last_url=next.to_owned();
            }
            "wait"=>{
                object_keys(action,&["type","delay_ms"])?;
                let millis=action.get("delay_ms").and_then(Value::as_u64).unwrap_or(100);
                if millis>500{return Err(invalid());}
                thread::sleep(Duration::from_millis(millis));
            }
            "scroll"=>{
                object_keys(action,&["type","direction"])?;
                let down=match required(action,"direction")?{
                    "down"=>true,"up"=>false,_=>return Err(invalid())
                };
                self.session.as_mut().ok_or_else(denied)?
                    .chrome.scroll_viewport(&cdp,down)?;
            }
            "wait_text"=>{
                object_keys(action,&["type","text","delay_ms"])?;
                let expected=required(action,"text")?;
                if expected.is_empty()||expected.len()>256 {return Err(invalid());}
                let delay=action.get("delay_ms").and_then(Value::as_u64).unwrap_or(0);
                if delay>500 {return Err(invalid());}
                if delay>0{thread::sleep(Duration::from_millis(delay));}
                let rendered=self.session.as_mut().ok_or_else(denied)?
                    .chrome.read(&cdp)?;
                if !rendered["text"].as_str().is_some_and(|t|t.contains(expected)){
                    return Err(denied());
                }
            }
            "wait_url"=>{
                object_keys(action,&["type","url"])?;
                let expected=self.resolve_url(required(action,"url")?)?;
                let observed=self.session.as_mut().ok_or_else(denied)?
                    .chrome.read(&cdp)?;
                if observed["url"].as_str()!=Some(expected.as_str()){return Err(denied());}
            }
            "wait_selector"=>{
                object_keys(action,&["type","selector"])?;
                let selector=required(action,"selector")?;
                if !self.session.as_mut().ok_or_else(denied)?
                    .chrome.selector_exists(&cdp,selector)? {return Err(denied());}
            }
            "drag"=>{
                object_keys(action,&["type","source_ref","target_ref"])?;
                let source=obs.refs.get(required(action,"source_ref")?).ok_or_else(denied)?;
                let target=obs.refs.get(required(action,"target_ref")?).ok_or_else(denied)?;
                if source.sensitive||target.sensitive {return Err(denied());}
                for element in [source,target] {
                    let description=self.session.as_mut().ok_or_else(denied)?
                        .chrome.command(Some(&cdp),"DOM.describeNode",
                            json!({"nodeId":element.node_id,"depth":0}))?;
                    if description["node"]["backendNodeId"].as_i64()!=Some(element.backend_id){
                        return Err(denied());
                    }
                }
                self.session.as_mut().ok_or_else(denied)?
                    .chrome.drag_between(&cdp,source.node_id,target.node_id)?;
            }
            "click"|"fill"|"type_text"|"set_checked"|"select"|"hover"=>{
                let permitted=match kind {
                    "click"|"hover"=>&["type","ref"][..],
                    "fill"|"select"|"type_text"=>&["type","ref","value"][..],
                    "set_checked"=>&["type","ref","checked"][..],
                    _=>&["type"][..]
                };
                object_keys(action,permitted)?;
                let reference=required(action,"ref")?;
                let element=obs.refs.get(reference).ok_or_else(denied)?;
                if element.sensitive{return Err(denied());}
                // Recheck that the exact same live DOM node still owns this
                // reference, not a newly-reused numeric frontend nodeId.
                let description=self.session.as_mut().ok_or_else(denied)?
                    .chrome.command(Some(&cdp),"DOM.describeNode",
                        json!({"nodeId":element.node_id,"depth":0}))?;
                if description["node"]["backendNodeId"].as_i64()!=Some(element.backend_id)
                    || description["node"]["nodeName"].as_str().map(str::to_ascii_lowercase)
                        .as_deref()!=Some(element.tag.as_str()) {
                    return Err(denied());
                }
                if kind=="click" && element.tag=="a" {
                    if let Some(href)=&element.href {
                        // Clicking an unapproved destination is never allowed.
                        if href.starts_with('#') {
                            if href.len()>160 || href.chars().any(char::is_control){return Err(denied());}
                        } else if self.resolve_url(href).is_err() {
                            return Err(denied());
                        }
                    }else{return Err(denied());}
                }
                let value=match kind{
                    "fill"|"select"|"type_text"=>{
                        let text=required(action,"value")?;
                        if text.len()>256 || text.chars().any(char::is_control){return Err(invalid());}
                        if matches!(kind,"fill"|"type_text")
                            && !matches!(element.tag.as_str(),"input"|"textarea")
                            || kind=="select" && element.tag!="select" {
                            return Err(denied());
                        }
                        if matches!(kind,"fill"|"type_text") && element.tag=="input"
                            && !matches!(element.kind.as_str(),""|"text"|"search") {
                            return Err(denied());
                        }
                        json!(text)
                    }
                    "set_checked"=>{
                        if element.tag!="input" || element.kind!="checkbox" {return Err(denied());}
                        json!(action.get("checked").and_then(Value::as_bool).ok_or_else(invalid)?)
                    }
                    _=>Value::Null
                };
                let chrome=&mut self.session.as_mut().ok_or_else(denied)?.chrome;
                match kind{
                    "click"=>chrome.call_element(&cdp,element.node_id,"click",Value::Null)?,
                    "hover"=>chrome.mouse_on(&cdp,element.node_id,false)?,
                    "type_text"=>chrome.insert_text(&cdp,element.node_id,
                        value.as_str().ok_or_else(invalid)?)?,
                    "set_checked"=>chrome.call_element(&cdp,element.node_id,"check",value)?,
                    "fill"|"select"=>chrome.call_element(&cdp,element.node_id,kind,value)?,
                    _=>return Err(denied())
                }
                // For an actual element click on a local anchor, the browser
                // can update URL/history. Read it back; don't claim a fake goto.
                if kind=="click" {
                    if let Some(dialog)=self.session.as_mut().ok_or_else(denied)?.chrome.active_dialog(&cdp)? {
                        let sid=self.session.as_ref().ok_or_else(denied)?.id.clone();
                        let last=self.session.as_ref().ok_or_else(denied)?.tabs[&page].last_url.clone();
                        let logical=self.logical_url(&last).unwrap_or_else(||"about:blank".to_owned());
                        return Ok(json!({"session_id":sid,"page_id":page,"url":logical,
                            "dialog_open":true,"blocking_dialog":dialog,"observation_invalidated":true}));
                    }
                    let new=self.session.as_mut().ok_or_else(denied)?.chrome.read(&cdp)?;
                    let url=new["url"].as_str().ok_or_else(denied)?.to_owned();
                    if self.logical_url(&url).is_none(){return Err(denied());}
                    self.session.as_mut().ok_or_else(denied)?
                        .tabs.get_mut(&page).ok_or_else(denied)?.last_url=url;
                }
            }
            "press"=>{
                object_keys(action,&["type","key"])?;
                self.session.as_mut().ok_or_else(denied)?
                    .chrome.key(&cdp,required(action,"key")?)?;
                if let Some(dialog)=self.session.as_mut().ok_or_else(denied)?.chrome.active_dialog(&cdp)? {
                    let sid=self.session.as_ref().ok_or_else(denied)?.id.clone();
                    let last=self.session.as_ref().ok_or_else(denied)?.tabs[&page].last_url.clone();
                    let logical=self.logical_url(&last).unwrap_or_else(||"about:blank".to_owned());
                    return Ok(json!({"session_id":sid,"page_id":page,"url":logical,
                        "dialog_open":true,"blocking_dialog":dialog,"observation_invalidated":true}));
                }
            }
            _=>return Err(denied())
        }
        let mut result=self.fresh_snapshot(&page,max,None)?;
        if let Some(receipt)=transfer_receipt {
            result["transfer"]=receipt;
        }
        self.with_screenshot(&page,result,screenshot)
    }

    pub fn dispatch(&mut self,name:&str,args:Map<String,Value>)->io::Result<Value> {
        match name {
            "desktop_browser_session"=>self.session_manage(args),
            "desktop_browser_snapshot"=>self.snapshot(args),
            "desktop_browser_act"=>self.act(args),
            _=>Err(denied())
        }
    }
}

/// Attach INSTEAD OF either documentary reader, never next to them. The
/// transporter's runtime supplies the unforgeable locally approved selection.
pub fn attach_native(
    approval:LocalInteractiveApproval,
    catalog:&mut Vec<ToolDefinition>,
    handlers:&mut ToolMapHandler,
){
    let state=Arc::new(Mutex::new(NativeProvider::new(approval)));
    for name in ["desktop_browser_session","desktop_browser_snapshot","desktop_browser_act"]{
        let reader=Arc::clone(&state);
        handlers.register(name,move |args|{
            let result=reader.lock().map_err(|_|denied())
                .and_then(|mut owned|owned.dispatch(name,args));
            Ok(match result{
                Ok(mut value)=>{
                    let image=value.as_object_mut()
                        .and_then(|object|object.remove("_screenshot_png_base64"));
                    if let Some(Value::String(data))=image {
                        ToolCallResult {
                            content:vec![
                                ToolContent::Text{text:value.to_string()},
                                ToolContent::Image{data,mime_type:"image/png".into()}
                            ],
                            is_error:false,
                            structured_content:None
                        }
                    }else{ToolCallResult::text(value.to_string())}
                }
                Err(_)=>ToolCallResult::tool_error("CHROME_NATIVE_SCOPE_REFUSED")
            })
        });
    }
    catalog.push(ToolDefinition::new("desktop_browser_session",
        Some("Locally approved isolated Chrome, one to three project-owned tabs; private CDP pipe.".into()),
        json!({"type":"object","required":["action"],"additionalProperties":false,"properties":{
            "action":{"enum":["start","list","close","new_page","select_page","close_page","handle_dialog","list_profiles","delete_profile"]},
            "session_id":{"type":"string","format":"uuid"},
            "page_id":{"type":"string"},
            "profile_id":{"type":"string","minLength":1,"maxLength":64},
            "url":{"type":"string","maxLength":1024},
            "accept":{"type":"boolean"},
            "prompt_text":{"type":"string","maxLength":4096}
        }})));

    catalog.push(ToolDefinition::new("desktop_browser_snapshot",
        Some("Read title, actual live rendered text and ephemeral DOM refs; full/find. No raw CDP or script.".into()),
        json!({"type":"object","required":["session_id"],"additionalProperties":false,"properties":{
            "session_id":{"type":"string","format":"uuid"},
            "page_id":{"type":"string"},
            "mode":{"enum":["full","find"]},
            "find_query":{"type":"string","maxLength":256},
            "max_text_chars":{"type":"integer","minimum":1,"maximum":MAX_TEXT_CHARS},
            "screenshot":{"type":"boolean","default":false},
            "full_page":{"type":"boolean","const":false},
            "include_console":{"type":"boolean","const":false},
            "include_network":{"type":"boolean","const":false}
        }})));
    catalog.push(ToolDefinition::new("desktop_browser_act",
        Some("One private Chrome DOM action on a fresh one-time observation; typed and origin scoped.".into()),
        json!({"type":"object","required":["session_id","browser_observation_id","actions"],
            "additionalProperties":false,"properties":{
            "session_id":{"type":"string","format":"uuid"},
            "page_id":{"type":"string"},
            "browser_observation_id":{"type":"string","format":"uuid"},
            "actions":{"type":"array","minItems":1,"maxItems":1,"items":{
                "type":"object","required":["type"],"additionalProperties":false,
                "properties":{
                    "type":{"enum":["goto","click","hover","drag","fill","type_text",
                        "set_checked","press","wait","wait_selector","wait_url",
                        "wait_text","select","set_files","download","scroll","navigation"]},
                    "url":{"type":"string","maxLength":1024},
                    "ref":{"type":"string","pattern":"^e[1-9][0-9]?$"},
                    "source_ref":{"type":"string","pattern":"^e[1-9][0-9]?$"},
                    "target_ref":{"type":"string","pattern":"^e[1-9][0-9]?$"},
                    "files":{"type":"array","minItems":1,"maxItems":1,
                        "items":{"type":"string","minLength":1,"maxLength":300}},
                    "selector":{"type":"string","minLength":1,"maxLength":128},
                    "text":{"type":"string","minLength":1,"maxLength":256},
                    "value":{"type":"string","maxLength":256},
                    "checked":{"type":"boolean"},
                    "key":{"enum":["Enter","Escape","Tab","ArrowDown","ArrowUp"]},
                    "direction":{"enum":["back","forward","reload"]},
                    "delay_ms":{"type":"integer","minimum":0,"maximum":500}
                }
            }},
            "max_text_chars":{"type":"integer","minimum":1,"maximum":MAX_TEXT_CHARS},
            "screenshot":{"type":"boolean","default":false},
            "full_page":{"type":"boolean","const":false},
            "include_console":{"type":"boolean","const":false},
            "include_network":{"type":"boolean","const":false}
        }})));
}
