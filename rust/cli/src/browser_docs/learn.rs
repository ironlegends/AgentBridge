//! Narrow public-document workflow, independent of personal browser tabs.
//!
//! A LOCAL operator explicitly chooses a Microsoft Learn documentation URL.
//! Web can only read that page and follow hrefs genuinely observed in its
//! source, after a fresh, single-use browser observation. Only the fixed
//! microsoft.com documentation path is eligible. The HTTPS fetch is one
//! bounded, certificate-verified curl.exe GET, without cookies, config,
//! proxy, redirects or caller-supplied headers. Chrome is then launched
//! headless against a completely inert local transcription, with a fresh
//! Bridge-owned Windows temporary profile deleted after each render.
//! This deliberately is not general Web browsing or CDP automation.

use super::chrome;
use agent_bridge_gateway::{ToolCallResult, ToolDefinition, ToolMapHandler};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PREFIX: &str = "https://learn.microsoft.com/en-us/windows/win32/winauto/";
const CURL: &str = r"C:\Windows\System32\curl.exe";
const MAX_SOURCE_BYTES: usize = 512 * 1024;
const MAX_TEXT_BYTES: usize = 80 * 1024;
const MAX_LINKS: usize = 30;
const MAX_SNAPSHOT_CHARS: usize = 50_000;
const SNAPSHOT_TTL: Duration = Duration::from_secs(30);
const SESSION_TTL: Duration = Duration::from_secs(300);
const CURL_TIMEOUT: Duration = Duration::from_secs(24);

fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "BRIDGE_LEARN_BROWSER_DENIED")
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "BRIDGE_LEARN_DOCUMENT_INVALID")
}
fn unavailable() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "BRIDGE_LEARN_DOCUMENT_TRANSPORT_UNAVAILABLE")
}

/// Exactly one public documentation family. No queries, fragments, encoded
/// navigation, user info, redirects, IP literals or other origins.
fn approved_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix(PREFIX) else { return false; };
    !rest.is_empty() && rest.len() <= 160 && url.len() <= 512
        && !rest.contains("..") && !rest.contains("//")
        && rest.split('/').all(|segment| !segment.is_empty()
            && segment.len() <= 80
            && segment.bytes().all(|c| c.is_ascii_lowercase()
                || c.is_ascii_digit() || c == b'-'))
}

fn resolved_link(current: &str, href: &str) -> Option<String> {
    // Strip fragments and queries before resolving a passive document link.
    // Their contents cannot influence network navigation.
    let raw = href.trim().split(['#', '?']).next()?;
    let candidate = if raw.starts_with(PREFIX) {
        raw.to_owned()
    } else if let Some(path) = raw.strip_prefix("/en-us/windows/win32/winauto/") {
        format!("{PREFIX}{path}")
    } else if !raw.starts_with('/') && !raw.contains(':')
        && !raw.contains('%') && !raw.contains('\\') && !raw.contains("..")
    {
        let suffix = raw.strip_prefix("./").unwrap_or(raw);
        let directory = current.rsplit_once('/')?.0;
        format!("{directory}/{suffix}")
    } else {
        return None;
    };
    approved_url(&candidate).then_some(candidate)
}

fn decode_entities(raw: &str) -> String {
    // Transcription only; the result is ALWAYS re-escaped before Chrome.
    let mut s = raw.replace("&nbsp;", " ").replace("&#160;", " ");
    for (encoded, plain) in [
        ("&amp;", "&"), ("&quot;", "\""), ("&apos;", "'"),
        ("&#39;", "'"), ("&#x27;", "'"), ("&lt;", "<"),
        ("&gt;", ">"), ("&mdash;", "-"), ("&ndash;", "–"),
        ("&hellip;", "…"), ("&copy;", "©"), ("&reg;", "®"),
    ] {
        s = s.replace(encoded, plain);
    }
    s
}

fn strip_tags(raw: &str) -> io::Result<String> {
    let block = Regex::new(r"(?is)</?(?:p|div|h[1-6]|li|ul|ol|article|section|br|tr|table|main|pre)\b[^>]*>")
        .map_err(|_| invalid())?;
    let text = block.replace_all(raw, "\n");
    let tags = Regex::new(r"(?s)<[^>]*>").map_err(|_| invalid())?;
    let text = tags.replace_all(&text, " ");
    let decoded = decode_entities(&text);
    let mut out = String::new();
    for line in decoded.lines() {
        let collapsed = line.split_whitespace().collect::<Vec<_>>().join(" ");
        if collapsed.is_empty() { continue; }
        if !out.is_empty() { out.push('\n'); }
        out.push_str(&collapsed);
        if out.len() > MAX_TEXT_BYTES {
            out.truncate(out.floor_char_boundary(MAX_TEXT_BYTES));
            break;
        }
    }
    Ok(out)
}

#[derive(Clone)]
struct DocLink {
    reference: String,
    label: String,
    url: String,
}

struct Page {
    title: String,
    content: String,
    links: Vec<DocLink>,
}

fn parse_document(source: &str, current: &str) -> io::Result<Page> {
    // A successful HTTP response is not proof that the returned bytes are
    // documentation. Require a genuine HTML title and a content region.
    let prefix = source.get(..source.len().min(1024)).unwrap_or("");
    if !prefix.to_ascii_lowercase().contains("<!doctype html")
        && !prefix.to_ascii_lowercase().contains("<html")
    {
        return Err(invalid());
    }
    let title_re = Regex::new(r"(?is)<title\b[^>]*>(.*?)</title>").map_err(|_| invalid())?;
    let title_markup = title_re.captures(source)
        .and_then(|cap| cap.get(1)).ok_or_else(invalid)?.as_str();
    let title = strip_tags(title_markup)?;
    if title.is_empty() || title.len() > 512 {
        return Err(invalid());
    }

    // Prefer Microsoft Learn's server-rendered <main>. Never trust scripts,
    // styles, form controls, iframe URLs or page-origin active elements.
    let main_re = Regex::new(r"(?is)<main\b[^>]*>(.*?)</main>").map_err(|_| invalid())?;
    let article_re = Regex::new(r"(?is)<article\b[^>]*>(.*?)</article>").map_err(|_| invalid())?;
    let content_html = main_re.captures(source).and_then(|cap| cap.get(1))
        .or_else(|| article_re.captures(source).and_then(|cap| cap.get(1)))
        .ok_or_else(invalid)?.as_str();
    let unsafe_tags = Regex::new(r"(?is)<(?:script|style|svg|iframe|object|form|noscript)\b[^>]*>.*?</(?:script|style|svg|iframe|object|form|noscript)\s*>")
        .map_err(|_| invalid())?;
    let cleaned = unsafe_tags.replace_all(content_html, "");
    let content = strip_tags(&cleaned)?;
    if content.len() < 90 { return Err(invalid()); }

    // Only references from the real HTML source, restricted to the same
    // explicit public documentation family. No page-supplied code executes.
    let anchor_re = Regex::new(r"(?is)<a\b(?P<attrs>[^>]{0,2048})>(?P<label>.{0,4096}?)</a\s*>")
        .map_err(|_| invalid())?;
    let href_re = Regex::new(r#"(?i)\bhref\s*=\s*["']([^"']{1,1024})["']"#)
        .map_err(|_| invalid())?;
    let mut links = Vec::new();
    let mut seen = BTreeSet::new();
    for captures in anchor_re.captures_iter(content_html) {
        let Some(attrs) = captures.name("attrs") else { continue; };
        let Some(href) = href_re.captures(attrs.as_str())
            .and_then(|capture| capture.get(1)) else { continue; };
        let Some(destination) = resolved_link(current, &decode_entities(href.as_str())) else {
            continue;
        };
        if destination == current || !seen.insert(destination.clone()) { continue; }
        let Some(markup) = captures.name("label") else { continue; };
        let label = strip_tags(markup.as_str())?;
        if label.is_empty() { continue; }
        let label: String = label.chars().take(100).collect();
        links.push(DocLink {
            reference: format!("e{}", links.len() + 1),
            label,
            url: destination,
        });
        if links.len() >= MAX_LINKS { break; }
    }
    Ok(Page { title, content, links })
}

fn curl_exe() -> io::Result<PathBuf> {
    let path = PathBuf::from(CURL);
    let meta = std::fs::symlink_metadata(&path).map_err(|_| unavailable())?;
    if !meta.is_file() || meta.file_type().is_symlink() { return Err(unavailable()); }
    let physical = std::fs::canonicalize(&path).map_err(|_| unavailable())?;
    let name = physical.to_str().ok_or_else(unavailable)?;
    if !name.strip_prefix(r"\\?\").unwrap_or(name).eq_ignore_ascii_case(CURL) {
        return Err(unavailable());
    }
    Ok(path)
}

fn bounded_output(mut reader: impl Read) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = reader.read(&mut buffer).map_err(|_| unavailable())?;
        if count == 0 { break; }
        if output.len().checked_add(count).is_none_or(|len| len > MAX_SOURCE_BYTES) {
            return Err(invalid());
        }
        output.extend_from_slice(&buffer[..count]);
    }
    Ok(output)
}

fn fetch_document(url: &str) -> io::Result<Page> {
    if !approved_url(url) { return Err(denied()); }
    let curl = curl_exe()?;
    let mut cmd = Command::new(curl);
    cmd.arg("--disable")
        .arg("--proto").arg("=https")
        .arg("--noproxy").arg("*")
        .arg("--fail")
        .arg("--silent")
        .arg("--show-error")
        .arg("--http1.1")
        .arg("--connect-timeout").arg("5")
        .arg("--max-time").arg("18")
        .arg("--max-filesize").arg(MAX_SOURCE_BYTES.to_string())
        .arg("--request").arg("GET")
        .arg("--header").arg("Accept: text/html")
        .arg("--output").arg("-")
        .arg("--url").arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_remove("CURL_HOME")
        .env_remove("XDG_CONFIG_HOME");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // No visible console.
    }
    let mut child = cmd.spawn().map_err(|_| unavailable())?;
    let stdout = child.stdout.take().ok_or_else(unavailable)?;
    let (tx, rx) = mpsc::sync_channel(1);
    thread::spawn(move || { let _ = tx.send(bounded_output(stdout)); });
    let started = Instant::now();
    let status = loop {
        match child.try_wait().map_err(|_| unavailable())? {
            Some(status) => break status,
            None if started.elapsed() <= CURL_TIMEOUT => thread::sleep(Duration::from_millis(25)),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(unavailable());
            }
        }
    };
    let bytes = rx.recv_timeout(Duration::from_secs(2))
        .map_err(|_| unavailable())??;
    if !status.success() { return Err(unavailable()); }
    let source = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
    parse_document(source, url)
}

/// Selected by the operator outside MCP. This never accepts a browser URL
/// from Web input; the initial page is exact and immutable per admission.
pub struct LocalLearnSelection {
    pub home_url: String,
}

pub struct LocalLearnApproval {
    home_url: String,
    chrome: PathBuf,
    approved_at: Instant,
}

pub fn approve_local(selection: LocalLearnSelection) -> io::Result<LocalLearnApproval> {
    if !approved_url(&selection.home_url) { return Err(denied()); }
    let chrome = chrome::installed_chrome()?;
    let _ = curl_exe()?;
    Ok(LocalLearnApproval {
        home_url: selection.home_url,
        chrome,
        approved_at: Instant::now(),
    })
}

struct Observation {
    id: String,
    issued_at: Instant,
    links: Vec<DocLink>,
}
struct Session {
    id: String,
    url: String,
    observation: Option<Observation>,
    navigations: u8,
}
struct Reader {
    approval: LocalLearnApproval,
    consumed: bool,
    session: Option<Session>,
}

fn required<'a>(args: &'a Map<String, Value>, key: &str) -> io::Result<&'a str> {
    args.get(key).and_then(Value::as_str).ok_or_else(denied)
}
fn keys(args: &Map<String, Value>, permitted: &[&str]) -> io::Result<()> {
    if args.keys().all(|key| permitted.contains(&key.as_str())) {
        Ok(())
    } else { Err(denied()) }
}
fn char_budget(args: &Map<String, Value>) -> io::Result<usize> {
    match args.get("max_text_chars") {
        None => Ok(8000),
        Some(v) => match v.as_u64() {
            Some(1..=50000) => Ok(v.as_u64().unwrap_or(0) as usize),
            _ => Err(denied()),
        },
    }
}
fn false_only(args: &Map<String, Value>) -> io::Result<()> {
    for key in ["screenshot", "include_network", "include_console", "full_page"] {
        if args.get(key).is_some_and(|value| value.as_bool() != Some(false)) {
            return Err(denied());
        }
    }
    Ok(())
}

impl Reader {
    fn begin(&mut self, args: Map<String, Value>) -> io::Result<Value> {
        keys(&args, &["action"])?;
        if required(&args, "action")? != "start" || self.consumed
            || self.approval.approved_at.elapsed() > SESSION_TTL
        { return Err(denied()); }
        let id = chrome::random_id()?;
        let url = self.approval.home_url.clone();
        self.session = Some(Session { id: id.clone(), url: url.clone(),
            observation: None, navigations: 0 });
        self.consumed = true;
        Ok(json!({"action":"start","session_id":id,"page_id":"main",
            "url":url,"profile":"bridge_temporary_private",
            "browser_engine":"installed_chrome","read_only":true,
            "chrome_running":false,"tabs":1}))
    }

    fn manage(&mut self, args: Map<String, Value>) -> io::Result<Value> {
        let action = required(&args, "action")?;
        match action {
            "start" => self.begin(args),
            "list" => {
                keys(&args, &["action"])?;
                let values: Vec<Value> = self.session.iter().map(|s|
                    json!({"session_id":s.id,"url":s.url,"page_id":"main",
                        "read_only":true,"chrome_running":false})).collect();
                Ok(json!({"action":"list","count":values.len(),"sessions":values}))
            }
            "close" => {
                keys(&args, &["action", "session_id"])?;
                let id = required(&args, "session_id")?;
                if self.session.as_ref().map(|s| s.id.as_str()) != Some(id) {
                    return Err(denied());
                }
                self.session.take();
                // Chrome subprocess and its profile were closed and deleted
                // synchronously by the verified render before this point.
                Ok(json!({"action":"close","closed":true,
                    "browser_processes_remaining_in_session":0}))
            }
            _ => Err(denied()),
        }
    }

    fn session_id(&self, args: &Map<String, Value>) -> io::Result<()> {
        let s = self.session.as_ref().ok_or_else(denied)?;
        if self.approval.approved_at.elapsed() > SESSION_TTL
            || required(args, "session_id")? != s.id
            || args.get("page_id").is_some_and(|v| v.as_str() != Some("main"))
        {
            return Err(denied());
        }
        Ok(())
    }

    fn page(&self, url: &str, max_chars: usize) -> io::Result<(Value, Vec<DocLink>)> {
        if !approved_url(url) { return Err(denied()); }
        let source = fetch_document(url)?;
        let verified = chrome::render_public_inert(
            self.approval.chrome.as_path(), &source.title, &source.content,
        )?;
        let excerpt: String = verified.text.chars().take(max_chars).collect();
        let truncated = verified.text.chars().nth(max_chars).is_some();
        let links: Vec<Value> = source.links.iter().map(|link|
            json!({"ref":link.reference,"title":link.label,"url":link.url,
                "type":"documentation_link"})).collect();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_| denied())?.as_secs();
        Ok((json!({
            "url":url,
            "page_id":"main",
            "browser_engine":"installed_chrome",
            "render_transport":"inert_html_headless_dump_dom",
            "source_transport":"bounded_public_https_get",
            "captured_at_unix_s":timestamp,
            "title":verified.title,
            "text":excerpt,
            "text_truncated":truncated,
            "links":links,
            "link_count":source.links.len(),
            "render_verified":true,
            "profile_cleanup_verified":true,
            "read_only":true,
            "screenshot":null,
            "interactive_elements":[],
            "console":null,"network":null,"script_execution":false
        }), source.links))
    }

    fn observe(&mut self, url: &str, max: usize) -> io::Result<Value> {
        let (mut answer, links) = self.page(url, max)?;
        let observation_id = chrome::random_id()?;
        let session = self.session.as_mut().ok_or_else(denied)?;
        session.observation = Some(Observation {
            id: observation_id.clone(), issued_at: Instant::now(), links,
        });
        answer["session_id"] = json!(session.id);
        answer["browser_observation_id"] = json!(observation_id);
        Ok(answer)
    }

    fn snapshot(&mut self, args: Map<String, Value>) -> io::Result<Value> {
        keys(&args, &["session_id","page_id","max_text_chars","screenshot",
            "include_network","include_console","full_page","mode"])?;
        self.session_id(&args)?;
        false_only(&args)?;
        if args.get("mode").is_some_and(|v| v.as_str() != Some("full")) {
            return Err(denied());
        }
        let max = char_budget(&args)?;
        let url = self.session.as_ref().ok_or_else(denied)?.url.clone();
        // Invalidate the preceding observation before any I/O.
        self.session.as_mut().ok_or_else(denied)?.observation = None;
        self.observe(&url, max)
    }

    fn act(&mut self, args: Map<String, Value>) -> io::Result<Value> {
        keys(&args, &["session_id","page_id","browser_observation_id","actions",
            "max_text_chars","screenshot","include_network","include_console","full_page"])?;
        self.session_id(&args)?;
        false_only(&args)?;
        let max = char_budget(&args)?;
        let observation = self.session.as_mut().ok_or_else(denied)?
            .observation.take().ok_or_else(denied)?;
        if observation.issued_at.elapsed() > SNAPSHOT_TTL
            || required(&args, "browser_observation_id")? != observation.id
        { return Err(denied()); }
        let actions = args.get("actions").and_then(Value::as_array).ok_or_else(denied)?;
        if actions.len() != 1 { return Err(denied()); }
        let action = actions[0].as_object().ok_or_else(denied)?;
        keys(action, &["type", "ref"])?;
        if required(action, "type")? != "click" { return Err(denied()); }
        let reference = required(action, "ref")?;
        let target = observation.links.iter()
            .find(|link| link.reference == reference)
            .ok_or_else(denied)?;
        let next_url = target.url.clone();
        let session = self.session.as_mut().ok_or_else(denied)?;
        if session.navigations >= 2 || session.url == next_url { return Err(denied()); }
        // A new confirmed public HTTPS fetch AND a new real Chrome render.
        // No page change is recorded after any uncertainty or failure.
        let next = self.observe(&next_url, max)?;
        let session = self.session.as_mut().ok_or_else(denied)?;
        session.url = next_url;
        session.navigations += 1;
        Ok(next)
    }
}

/// A public-browser handler must be attached ALTERNATIVELY to the existing
/// local README reader; registering both would overwrite tool handlers.
/// Only locally selected, strict Microsoft Learn URLs are admitted.
pub fn attach_public(
    approval: LocalLearnApproval,
    catalog: &mut Vec<ToolDefinition>,
    handlers: &mut ToolMapHandler,
) {
    let reader = Arc::new(Mutex::new(Reader {
        approval, consumed: false, session: None,
    }));
    for tool in ["desktop_browser_session","desktop_browser_snapshot","desktop_browser_act"] {
        let local = Arc::clone(&reader);
        handlers.register(tool, move |args| {
            let result = local.lock().map_err(|_| denied())
                .and_then(|mut reader| match tool {
                    "desktop_browser_session" => reader.manage(args),
                    "desktop_browser_snapshot" => reader.snapshot(args),
                    "desktop_browser_act" => reader.act(args),
                    _ => Err(denied()),
                });
            Ok(match result {
                Ok(value) => ToolCallResult::text(value.to_string()),
                Err(_) => ToolCallResult::tool_error("BRIDGE_LEARN_BROWSER_REFUSED"),
            })
        });
    }
    catalog.push(ToolDefinition::new(
        "desktop_browser_session",
        Some("One operator-selected public Microsoft Learn documentation session; start/list/close only.".into()),
        json!({"type":"object","additionalProperties":false,"required":["action"],"properties":{
            "action":{"enum":["start","list","close"]},
            "session_id":{"type":"string","format":"uuid"}
        }})
    ));
    catalog.push(ToolDefinition::new(
        "desktop_browser_snapshot",
        Some("Verified installed Chrome headless render of a bounded inert Microsoft Learn document.".into()),
        json!({"type":"object","additionalProperties":false,"required":["session_id"],"properties":{
            "session_id":{"type":"string","format":"uuid"},
            "page_id":{"type":"string","const":"main"},
            "mode":{"type":"string","const":"full"},
            "max_text_chars":{"type":"integer","minimum":1,"maximum":MAX_SNAPSHOT_CHARS,"default":8000},
            "screenshot":{"type":"boolean","const":false},
            "full_page":{"type":"boolean","const":false},
            "include_console":{"type":"boolean","const":false},
            "include_network":{"type":"boolean","const":false}
        }})
    ));
    catalog.push(ToolDefinition::new(
        "desktop_browser_act",
        Some("Follow exactly one previously observed, allowed Microsoft Learn documentation href by reference.".into()),
        json!({"type":"object","additionalProperties":false,
            "required":["session_id","browser_observation_id","actions"],
            "properties":{
                "session_id":{"type":"string","format":"uuid"},
                "page_id":{"type":"string","const":"main"},
                "browser_observation_id":{"type":"string","format":"uuid"},
                "actions":{"type":"array","minItems":1,"maxItems":1,"items":{
                    "type":"object","additionalProperties":false,
                    "required":["type","ref"],"properties":{
                        "type":{"const":"click"},"ref":{"type":"string","pattern":"^e[1-9][0-9]?$"}
                    }
                }},
                "max_text_chars":{"type":"integer","minimum":1,"maximum":MAX_SNAPSHOT_CHARS,"default":8000},
                "screenshot":{"type":"boolean","const":false},
                "full_page":{"type":"boolean","const":false},
                "include_console":{"type":"boolean","const":false},
                "include_network":{"type":"boolean","const":false}
            }
        })
    ));
}

/// Owner-requested ONE actual preparation run, with two distinct real
/// public source GETs and two separate ephemeral Chrome renders.
pub fn preparation_once(initial_url: &str) -> io::Result<Value> {
    let approval = approve_local(LocalLearnSelection {
        home_url: initial_url.to_owned(),
    })?;
    let mut reader = Reader { approval, consumed: false, session: None };
    let started = reader.manage(json!({"action":"start"}).as_object().cloned().ok_or_else(invalid)?)?;
    let session_id = started["session_id"].as_str().ok_or_else(invalid)?.to_owned();
    let first = reader.snapshot(json!({"session_id":session_id,"max_text_chars":12000})
        .as_object().cloned().ok_or_else(invalid)?)?;
    let links = first["links"].as_array().ok_or_else(invalid)?;
    let candidate = links.iter()
        .find(|link| link["title"].as_str().is_some_and(|title|
            title.to_ascii_lowercase().contains("overview")))
        .or_else(|| links.first())
        .ok_or_else(invalid)?;
    let ref_id = candidate["ref"].as_str().ok_or_else(invalid)?.to_owned();
    let observed_id = first["browser_observation_id"].as_str().ok_or_else(invalid)?.to_owned();
    let second = reader.act(json!({
        "session_id":session_id,
        "browser_observation_id":observed_id,
        "actions":[{"type":"click","ref":ref_id}],
        "max_text_chars":12000
    }).as_object().cloned().ok_or_else(invalid)?)?;
    let closed = reader.manage(json!({"action":"close","session_id":session_id})
        .as_object().cloned().ok_or_else(invalid)?)?;
    Ok(json!({
        "kind":"agent_bridge_public_learn_chrome_navigation_v1",
        "session_started":started["action"] == "start",
        "first_url":first["url"],
        "first_title":first["title"],
        "first_text_excerpt":first["text"].as_str().unwrap_or("").chars().take(400).collect::<String>(),
        "first_render_verified":first["render_verified"],
        "selected_link":candidate,
        "second_url":second["url"],
        "second_title":second["title"],
        "second_text_excerpt":second["text"].as_str().unwrap_or("").chars().take(400).collect::<String>(),
        "second_render_verified":second["render_verified"],
        "session_closed":closed["closed"],
        "profile_cleanup_verified": first["profile_cleanup_verified"] == true
            && second["profile_cleanup_verified"] == true,
        "javascript_executed":false,
        "chrome_network_access":false,
        "personal_profile_used":false,
        "production_changed":false,
        "notes":"Public HTTPS bodies were fetched under a fixed Learn-only URL policy; installed Chrome rendered inert text and verified titles without active remote markup."
    }))
}
