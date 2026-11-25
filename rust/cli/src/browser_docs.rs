//! Opt-in, read-only project-document browsing with an installed Chrome.
//!
//! This is deliberately NOT a CDP/Playwright or general Computer Use bridge.
//! It supports one logical page per local approval. Each snapshot or navigation
//! performs a REAL, bounded, one-shot Chrome headless DOM render of inert HTML.
//! No personal Chrome profile, browser transport port, extensions, cookies,
//! scripts, remote URL, console/network inspection, screenshots or input events.
//!
//! Integration (LOCAL command-line options, not MCP fields):
//!   mod browser_docs;
//!   let request = browser_docs::LocalDocsRequest { workspace, pages };
//!   let approval = browser_docs::approve_from_local_cli(request)?;
//!   browser_docs::attach(approval, &mut catalog, &mut handlers);
//!
//! The explicitly repeated --local-doc-page arguments are the admission;
//! the first page is home. No consent prompt ever reads the MCP stdin.
//! Attach only on the physically qualified read-only stdio workspace router.

#[path = "browser_docs/chrome.rs"]
mod chrome;

#[path = "browser_docs/learn.rs"]
pub mod learn;

#[cfg(any(windows, unix))]
#[path = "browser_docs/interactive.rs"]
pub mod interactive;

#[cfg(windows)]
#[path = "browser_docs/transfer.rs"]
mod transfer;
#[cfg(unix)]
#[path = "browser_docs/transfer_unix.rs"]
mod transfer;

use agent_bridge_desktop::{DesktopConfig, DesktopFiles};
use agent_bridge_gateway::{ToolCallResult, ToolDefinition, ToolMapHandler};
use serde_json::{json, Map, Value};
use regex::{Regex, RegexBuilder};
use std::collections::BTreeSet;
use std::io;
use std::path::{Component, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) const MAX_APPROVED_PAGES: usize = 32;
const MAX_DOC_BYTES: u64 = 96 * 1024;
const MAX_TEXT_CHARS: usize = 50_000;
const DEFAULT_TEXT_CHARS: usize = 8_000;
const MAX_FIND_QUERY_CHARS: usize = 1_024;
const MAX_FIND_RESULTS: usize = 50;
const DEFAULT_FIND_RESULTS: usize = 20;
const MAX_LOCAL_ADMISSION_AGE: Duration = Duration::from_secs(300);
const MAX_OBSERVATION_AGE: Duration = Duration::from_secs(30);

fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "BRIDGE_DOC_BROWSER_REFUSED")
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "BRIDGE_DOC_BROWSER_INVALID_INPUT")
}
#[cfg(not(any(windows, unix)))]
fn unavailable() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "BRIDGE_CHROME_UNAVAILABLE")
}

/// Supplied solely by an operator-owned LOCAL startup path. Each exact page
/// must have been selected; Web callers never choose or extend this set.
pub struct LocalDocsRequest {
    pub workspace: PathBuf,
    /// Exact, workspace-relative documents from LOCAL process argv, in order.
    /// The first one becomes the home page.
    pub pages: Vec<String>,
}

pub struct LocalApproval {
    workspace: PathBuf,
    allowed: BTreeSet<String>,
    home: String,
    chrome: PathBuf,
    files: DesktopFiles,
    approved_at: Instant,
}

fn valid_page(raw: &str) -> bool {
    if raw.is_empty() || raw.len() > 512 || !raw.is_ascii()
        || raw.contains('\\') || raw.contains(':') || raw.contains('~')
        || raw.starts_with('/') || raw.ends_with('/')
        || raw.chars().any(char::is_control)
    {
        return false;
    }
    let lower = raw.to_ascii_lowercase();
    if ![".html", ".htm", ".md", ".markdown"]
        .iter().any(|extension| lower.ends_with(extension))
    {
        return false;
    }
    raw.split('/').all(|segment| {
        !segment.is_empty() && !segment.starts_with('.')
            && !segment.ends_with('.') && !segment.ends_with(' ')
            && !segment.starts_with(' ') && segment.len() <= 255
            && segment.bytes().all(|b| b.is_ascii_alphanumeric()
                || matches!(b, b'.' | b'_' | b'-'))
    })
}


/// Accept ONLY the operator's explicit local CLI document arguments after
/// runtime::qualified_workspace has pinned and qualified that project.
/// This never reads stdin, contacts a website, or starts Chrome.
pub fn approve_from_local_cli(request: LocalDocsRequest) -> io::Result<LocalApproval> {
    #[cfg(not(any(windows, unix)))]
    { let _ = request; return Err(unavailable()); }

    #[cfg(any(windows, unix))]
    {
        let LocalDocsRequest { workspace, pages } = request;
        if !workspace.is_absolute()
            || workspace.components().any(|part| matches!(part, Component::ParentDir))
            || pages.is_empty() || pages.len() > MAX_APPROVED_PAGES
            || !pages.iter().all(|page| valid_page(page))
        {
            return Err(invalid());
        }
        let home = pages[0].clone();
        let count = pages.len();
        let allowed: BTreeSet<String> = pages.into_iter().collect();
        let casefolded: BTreeSet<String> = allowed.iter()
            .map(|page| page.to_ascii_lowercase()).collect();
        if allowed.len() != count || casefolded.len() != count {
            return Err(invalid());
        }

        // No PATH discovery, browser process or personal Chrome profile.
        let chrome = chrome::installed_chrome()?;
        #[cfg(windows)]
        let _pin = agent_bridge_lifecycle::workspace_access::PinnedProjectDirectory::open(
            workspace.as_path(),
        ).map_err(|_| denied())?;
        #[cfg(unix)]
        let _pin = chrome::native::DirectoryPin::open(&workspace).map_err(|_| denied())?;
        let files = DesktopFiles::open(
            DesktopConfig::new(workspace.as_path()).with_web_project_read_policy(),
        ).map_err(|_| denied())?;

        // Gate every path BEFORE enabling the tools. The same capability
        // revalidates metadata, regular-file identity and bytes on each read.
        for page in &allowed {
            let meta = read_payload(&files, "desktop_get_file_info", page)?;
            if meta["kind"].as_str() != Some("file")
                || meta["bytes"].as_u64().is_none_or(|size| size > MAX_DOC_BYTES)
            {
                return Err(denied());
            }
        }
        eprintln!("agent-bridge: documentary reader selected {} local pages", allowed.len());
        Ok(LocalApproval {
            workspace,
            allowed,
            home,
            chrome,
            files,
            approved_at: Instant::now(),
        })
    }
}

struct Observation {
    id: String,
    issued: Instant,
}

struct SingleSession {
    id: String,
    page: String,
    observation: Option<Observation>,
}

struct Reader {
    approval: LocalApproval,
    consumed: bool,
    active: Option<SingleSession>,
}

fn exact_keys(args: &Map<String, Value>, allowed: &[&str]) -> io::Result<()> {
    if args.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid());
    }
    Ok(())
}
fn string<'a>(args: &'a Map<String, Value>, key: &str) -> io::Result<&'a str> {
    args.get(key).and_then(Value::as_str).ok_or_else(invalid)
}
fn bool_false(args: &Map<String, Value>, name: &str) -> io::Result<()> {
    if args.get(name).is_some_and(|value| value.as_bool() != Some(false)) {
        return Err(invalid());
    }
    Ok(())
}
fn only_main_page(args: &Map<String, Value>) -> io::Result<()> {
    if args.get("page_id").is_some_and(|page| page.as_str() != Some("main")) {
        return Err(denied());
    }
    Ok(())
}
fn text_limit(args: &Map<String, Value>) -> io::Result<usize> {
    match args.get("max_text_chars") {
        None => Ok(DEFAULT_TEXT_CHARS),
        Some(value) => match value.as_u64() {
            Some(1..=50000) => Ok(value.as_u64().unwrap_or(0) as usize),
            _ => Err(invalid()),
        },
    }
}
fn find_options(args: &Map<String, Value>) -> io::Result<(&str, bool, usize)> {
    let query = string(args, "find_query")?;
    // Find matches one source line at a time: refuse multiline/control input
    // rather than treating it as a regex or a new document selector.
    if query.trim().is_empty() || query.encode_utf16().count() > MAX_FIND_QUERY_CHARS
        || query.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    let case_sensitive = match args.get("find_case_sensitive") {
        None => false,
        Some(Value::Bool(value)) => *value,
        _ => return Err(invalid()),
    };
    let max_results = match args.get("max_find_results") {
        None => DEFAULT_FIND_RESULTS,
        Some(value) => match value.as_u64() {
            Some(count) if count >= 1 && count <= MAX_FIND_RESULTS as u64 => count as usize,
            _ => return Err(invalid()),
        },
    };
    Ok((query, case_sensitive, max_results))
}

/// The compiled Unicode matcher is built ONCE per find request from escaped
/// literal input. Its match offset indexes the ORIGINAL line, avoiding
/// context-sensitive lowercasing offsets (e.g. final sigma in Greek).
fn first_match_column(line: &str, matcher: &Regex) -> Option<usize> {
    matcher.find(line).map(|found| line[..found.start()].chars().count())
}

/// Search the complete Chrome-verified document, BEFORE applying the combined
/// excerpt character budget. One result represents one matching source line.
fn find_document(
    document: &str,
    page: &str,
    query: &str,
    case_sensitive: bool,
    max_results: usize,
    max_text_chars: usize,
) -> io::Result<Value> {
    const MAX_EXCERPT_CHARS: usize = 240;
    let mut results = Vec::new();
    let mut total_matching_lines = 0usize;
    let mut used_chars = 0usize;
    let mut text_truncated = false;
    // Escaping makes the user input a literal, never a regex program.
    // RegexBuilder performs Unicode case-insensitive matching even when
    // lowercase mapping depends on the characters around the match.
    let matcher = RegexBuilder::new(&regex::escape(query))
        .case_insensitive(!case_sensitive)
        .unicode(true)
        .build()
        .map_err(|_| invalid())?;
    let query_chars = query.chars().count();
    // A line locator in the approved document, not an interactive DOM node.
    let document_path = logical_url(page);

    for (line_index, line) in document.split('\n').enumerate() {
        let Some(column) = first_match_column(line, &matcher) else {
            continue;
        };
        total_matching_lines += 1;
        // Still count matches in the rest of the complete document after the
        // result limit or output budget has been exhausted.
        if results.len() >= max_results || used_chars >= max_text_chars {
            continue;
        }
        let length = line.chars().count();
        let shown = length.min(MAX_EXCERPT_CHARS).min(max_text_chars - used_chars);
        if shown == 0 { continue; }
        let start = if length > shown {
            // Prioritize the hit itself when the remaining total budget is
            // smaller than the query; otherwise include bounded left context.
            let left_context = shown.saturating_sub(query_chars).min(48);
            column.saturating_sub(left_context).min(length - shown)
        } else {
            0
        };
        let snippet: String = line.chars().skip(start).take(shown).collect();
        let clipped = start != 0 || start + shown < length;
        text_truncated |= clipped;
        used_chars += shown;
        results.push(json!({
            "path":format!("{document_path}#L{}", line_index + 1),
            "line":line_index + 1,
            "column":column + 1,
            "excerpt_start_column":start + 1,
            "snippet":snippet,
            "excerpt_truncated":clipped
        }));
    }

    let returned_count = results.len();
    Ok(json!({
        "mode":"find",
        "find_query":query,
        "find_case_sensitive":case_sensitive,
        "max_find_results":max_results,
        "matches":results,
        "match_count":returned_count,
        "total_matching_lines":total_matching_lines,
        "results_truncated":total_matching_lines > returned_count,
        "text_truncated":text_truncated,
        "no_results":total_matching_lines == 0,
        "text_budget_chars":max_text_chars,
        "text_returned_chars":used_chars
    }))
}

fn logical_url(page: &str) -> String {
    format!("bridge-doc:///{page}")
}
fn url_to_page(url: &str) -> io::Result<&str> {
    // No parsing of external URLs, relative URL resolution or %-decoding:
    // only the exact canonical operator-approved document names are eligible.
    let page = url.strip_prefix("bridge-doc:///").ok_or_else(denied)?;
    if !valid_page(page) || logical_url(page) != url {
        return Err(denied());
    }
    Ok(page)
}

fn read_payload(files: &DesktopFiles, tool: &str, path: &str) -> io::Result<Value> {
    let request = json!({"path":path,"length":5000});
    let args = if tool == "desktop_get_file_info" {
        json!({"path":path})
    } else { request };
    let response = files.dispatch(tool, &args);
    if response["isError"].as_bool() == Some(true) { return Err(denied()); }
    let json_text = response["content"].as_array()
        .and_then(|entries| entries.first())
        .and_then(|entry| entry["text"].as_str())
        .ok_or_else(denied)?;
    serde_json::from_str(json_text).map_err(|_| denied())
}

impl Reader {
    fn session_manage(&mut self, args: Map<String, Value>) -> io::Result<Value> {
        let action = string(&args, "action")?;
        match action {
            "start" => {
                exact_keys(&args, &["action"])?;
                if self.consumed || self.active.is_some()
                    || self.approval.approved_at.elapsed() > MAX_LOCAL_ADMISSION_AGE {
                    return Err(denied());
                }
                let id = chrome::random_id()?;
                let first = self.approval.home.clone();
                self.active = Some(SingleSession {
                    id: id.clone(), page: first.clone(), observation: None,
                });
                self.consumed = true;
                Ok(json!({
                    "action":"start","session_id":id,"page_id":"main",
                    "url":logical_url(&first),"logical_session":true,
                    "chrome_running":false,
                    "render_transport":"one_shot_headless_dump_dom",
                    "profile":"bridge_temporary_private","tabs":1
                }))
            }
            "list" => {
                exact_keys(&args, &["action"])?;
                let sessions: Vec<Value> = self.active.iter().filter(|_| self.approval.approved_at.elapsed() <= MAX_LOCAL_ADMISSION_AGE).map(|s| json!({
                    "session_id":s.id,"page_id":"main","url":logical_url(&s.page),
                    "profile":"bridge_temporary_private","chrome_running":false
                })).collect();
                Ok(json!({"action":"list","sessions":sessions,"count":sessions.len()}))
            }
            "close" => {
                exact_keys(&args, &["action", "session_id"])?;
                if self.active.as_ref().map(|s| s.id.as_str()) != Some(string(&args, "session_id")?) {
                    return Err(denied());
                }
                // The transient Chrome render has finished before close.
                self.active.take();
                Ok(json!({"action":"close","closed":true}))
            }
            _ => Err(denied()),
        }
    }

    fn session_id(&self, args: &Map<String, Value>) -> io::Result<()> {
        if self.approval.approved_at.elapsed() > MAX_LOCAL_ADMISSION_AGE { return Err(denied()); }
        let session = self.active.as_ref().ok_or_else(denied)?;
        if args.get("session_id").and_then(Value::as_str) != Some(session.id.as_str()) {
            return Err(denied());
        }
        only_main_page(args)
    }

    fn document(&self, path: &str) -> io::Result<(String, String)> {
        if !self.approval.allowed.contains(path) { return Err(denied()); }
        #[cfg(windows)]
        let _pin = agent_bridge_lifecycle::workspace_access::PinnedProjectDirectory::open(
            &self.approval.workspace,
        ).map_err(|_| chrome::operator_error("document.workspace_pin", denied()))?;
        #[cfg(unix)]
        let _pin = chrome::native::DirectoryPin::open(&self.approval.workspace)
            .map_err(|_| denied())?;
        #[cfg(not(any(windows, unix)))]
        return Err(unavailable());

        let meta = chrome::at_stage(
            "document.metadata",
            read_payload(&self.approval.files, "desktop_get_file_info", path),
        )?;
        if meta["kind"].as_str() != Some("file")
            || meta["bytes"].as_u64().is_none_or(|size| size > MAX_DOC_BYTES)
        {
            return Err(chrome::operator_error("document.metadata_policy", denied()));
        }
        let content = chrome::at_stage(
            "document.read",
            read_payload(&self.approval.files, "desktop_read_file", path),
        )?;
        if content["truncated"].as_bool() != Some(false) {
            return Err(chrome::operator_error("document.truncation_policy", denied()));
        }
        let body = content["content"].as_str().ok_or_else(|| chrome::operator_error("document.content_shape", denied()))?;
        let hash = content["sha256"].as_str().ok_or_else(|| chrome::operator_error("document.digest_shape", denied()))?;
        if body.len() as u64 > MAX_DOC_BYTES || hash.len() != 64
            || !hash.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(chrome::operator_error("document.read_policy", denied()));
        }
        Ok((body.to_owned(), hash.to_owned()))
    }

    fn rendered_page(
        &self,
        page: &str,
        max_text_chars: usize,
        find: Option<(&str, bool, usize)>,
    ) -> io::Result<Value> {
        let (body, digest) = self.document(page)?;
        let session = self.active.as_ref().ok_or_else(denied)?;
        // One complete verified Chrome render per request. In find mode search
        // that complete document, not the full-mode truncated display string.
        // No Chrome process or profile survives between requests.
        let mut profile = chrome::at_stage(
            "profile.create", chrome::PrivateProfile::create(),
        )?;
        // Cleanup is mandatory even if rendering fails; never print source,
        // private URL or raw errors to the operator's stderr.
        let rendered = chrome::at_stage(
            "chrome.render", chrome::render(&self.approval.chrome, &profile, &body, &digest),
        );
        chrome::at_stage("profile.cleanup", profile.cleanup())?;
        let render = rendered?;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_| denied())?.as_secs();
        let mut result = json!({
            "session_id":session.id,
            "page_id":"main","url":logical_url(page),
            "captured_at_unix_s":timestamp,
            "document_sha256":digest,
            "render_verified":true,
            "browser_engine":"installed_chrome",
            "render_transport":"one_shot_headless_dump_dom",
            "screenshot":null,
            "interactive_elements":[],
            "console":null,"network":null,
            "script_execution":false,
            "profile":"bridge_temporary_private"
        });
        if let Some((query, case_sensitive, max_results)) = find {
            let found = find_document(
                &render.document, page, query, case_sensitive, max_results, max_text_chars,
            )?;
            // Both values are internally constructed JSON objects; refuse
            // rather than return a misleading partial search response.
            let fields = found.as_object().ok_or_else(invalid)?;
            result.as_object_mut().ok_or_else(invalid)?.extend(fields.clone());
        } else {
            // Preserve the original full-mode response and truncation contract.
            let text: String = render.document.chars().take(max_text_chars).collect();
            let truncated = render.document.chars().nth(max_text_chars).is_some();
            result["text"] = json!(text);
            result["text_truncated"] = json!(truncated);
        }
        Ok(result)
    }

    fn issue_snapshot(
        &mut self,
        page: &str,
        max_text_chars: usize,
        find: Option<(&str, bool, usize)>,
    ) -> io::Result<Value> {
        let mut result = self.rendered_page(page, max_text_chars, find)?;
        let id = chrome::random_id()?;
        let session = self.active.as_mut().ok_or_else(denied)?;
        session.observation = Some(Observation { id: id.clone(), issued: Instant::now() });
        result["browser_observation_id"] = json!(id);
        Ok(result)
    }

    fn snapshot(&mut self, args: Map<String, Value>) -> io::Result<Value> {
        exact_keys(&args, &[
            "session_id","page_id","screenshot","full_page","max_text_chars",
            "include_network","include_console","mode",
            "find_query","find_case_sensitive","max_find_results",
        ])?;
        self.session_id(&args)?;
        for key in ["screenshot","full_page","include_network","include_console"] {
            bool_false(&args, key)?;
        }
        let mode = match args.get("mode") {
            None => "full",
            Some(Value::String(mode)) => mode.as_str(),
            _ => return Err(invalid()),
        };
        let find = match mode {
            "full" => {
                // Search-only fields must not silently change a full snapshot.
                if ["find_query","find_case_sensitive","max_find_results"]
                    .iter().any(|field| args.contains_key(*field))
                {
                    return Err(invalid());
                }
                None
            }
            "find" => Some(find_options(&args)?),
            _ => return Err(denied()),
        };
        let max = text_limit(&args)?;
        let page = self.active.as_ref().ok_or_else(denied)?.page.clone();
        // Any new snapshot invalidates the preceding observation.
        self.active.as_mut().ok_or_else(denied)?.observation = None;
        self.issue_snapshot(&page, max, find)
    }

    fn act(&mut self, args: Map<String, Value>) -> io::Result<Value> {
        exact_keys(&args, &[
            "session_id","page_id","browser_observation_id","actions",
            "screenshot","full_page","max_text_chars","include_network","include_console",
        ])?;
        self.session_id(&args)?;
        let obs = self.active.as_mut().ok_or_else(denied)?
            .observation.take().ok_or_else(denied)?;
        if string(&args, "browser_observation_id")? != obs.id
            || obs.issued.elapsed() > MAX_OBSERVATION_AGE {
            return Err(denied());
        }
        for key in ["screenshot","full_page","include_network","include_console"] {
            bool_false(&args, key)?;
        }
        let max = text_limit(&args)?;
        let actions = args.get("actions").and_then(Value::as_array).ok_or_else(invalid)?;
        if actions.len() != 1 { return Err(denied()); }
        let action = actions[0].as_object().ok_or_else(invalid)?;
        exact_keys(action, &["type","url"])?;
        if string(action, "type")? != "goto" { return Err(denied()); }
        let page = url_to_page(string(action, "url")?)?;
        if !self.approval.allowed.contains(page) { return Err(denied()); }
        let next = self.issue_snapshot(page, max, None)?;
        // Only a completed, verified Chrome render changes the logical page.
        self.active.as_mut().ok_or_else(denied)?.page = page.to_owned();
        Ok(next)
    }
}

/// Register the strictly narrower tool schemas only on an operator-approved
/// workstation gateway. No installation/Chrome execution occurs at attach.
pub fn attach(
    approval: LocalApproval,
    catalog: &mut Vec<ToolDefinition>,
    handlers: &mut ToolMapHandler,
) {
    let reader = Arc::new(Mutex::new(Reader {
        approval, consumed: false, active: None,
    }));
    for name in ["desktop_browser_session","desktop_browser_snapshot","desktop_browser_act"] {
        let r = Arc::clone(&reader);
        handlers.register(name, move |args| {
            let result = r.lock().map_err(|_| denied()).and_then(|mut state| match name {
                "desktop_browser_session" => state.session_manage(args),
                "desktop_browser_snapshot" => state.snapshot(args),
                "desktop_browser_act" => state.act(args),
                _ => Err(denied()),
            });
            Ok(match result {
                Ok(value) => ToolCallResult::text(value.to_string()),
                Err(_) => ToolCallResult::tool_error("BRIDGE_DOC_BROWSER_REFUSED"),
            })
        });
    }

    catalog.push(ToolDefinition::new(
        "desktop_browser_session",
        Some("One locally approved, temporary Chrome documentation session; no personal profiles or tabs.".into()),
        json!({"type":"object","additionalProperties":false,"required":["action"],"properties":{
            "action":{"type":"string","enum":["start","list","close"]},
            "session_id":{"type":"string","format":"uuid"}
        }}),
    ));
    catalog.push(ToolDefinition::new(
        "desktop_browser_snapshot",
        Some("Render a locally approved document through Chrome: full text or bounded find excerpts over the entire verified text. No screenshots, UI actions, console or network logs.".into()),
        json!({"type":"object","additionalProperties":false,"required":["session_id"],"properties":{
            "session_id":{"type":"string","format":"uuid"},
            "page_id":{"type":"string","const":"main"},
            "mode":{"type":"string","enum":["full","find"],"default":"full"},
            "find_query":{"type":"string","minLength":1,"maxLength":MAX_FIND_QUERY_CHARS},
            "find_case_sensitive":{"type":"boolean","default":false},
            "max_find_results":{"type":"integer","minimum":1,"maximum":MAX_FIND_RESULTS,"default":DEFAULT_FIND_RESULTS},
            "screenshot":{"type":"boolean","const":false,"default":false},
            "full_page":{"type":"boolean","const":false},
            "max_text_chars":{"type":"integer","minimum":1,"maximum":MAX_TEXT_CHARS,"default":DEFAULT_TEXT_CHARS},
            "include_network":{"type":"boolean","const":false},
            "include_console":{"type":"boolean","const":false}
        }}),
    ));
    catalog.push(ToolDefinition::new(
        "desktop_browser_act",
        Some("Navigate once to another exact operator-approved bridge-doc:/// URL, then return a real Chrome-verified read-only snapshot. No click, typing, scripting or external URLs.".into()),
        json!({"type":"object","additionalProperties":false,"required":["session_id","browser_observation_id","actions"],"properties":{
            "session_id":{"type":"string","format":"uuid"},
            "page_id":{"type":"string","const":"main"},
            "browser_observation_id":{"type":"string","format":"uuid"},
            "actions":{"type":"array","minItems":1,"maxItems":1,"items":{
                "type":"object","additionalProperties":false,"required":["type","url"],
                "properties":{"type":{"type":"string","const":"goto"},
                              "url":{"type":"string","pattern":"^bridge-doc:///"}}
            }},
            "screenshot":{"type":"boolean","const":false,"default":false},
            "full_page":{"type":"boolean","const":false},
            "max_text_chars":{"type":"integer","minimum":1,"maximum":MAX_TEXT_CHARS,"default":DEFAULT_TEXT_CHARS},
            "include_network":{"type":"boolean","const":false},
            "include_console":{"type":"boolean","const":false}
        }}),
    ));
}
