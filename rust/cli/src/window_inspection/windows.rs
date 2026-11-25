//! Local consent pins one named-desktop work window and its process/thread
//! incarnation. Observations expose bounded native child controls or a PNG of
//! only that selected HWND. Actions use bounded control messages, never global
//! mouse, keyboard, desktop pixels or general UI Automation.
//!
//! Only the explicit LOCAL stdio startup option may request the exact target;
//! confirmation is a native Windows Yes/No dialog, defaulting to No. MCP
//! traffic has no operation for selecting a target or requesting consent.

use agent_bridge_gateway::{ToolCallResult, ToolDefinition, ToolMapHandler};
use serde_json::{json, Map, Value};
use std::io;
use std::path::{Component, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const WINDOW_TOKEN_TTL: Duration = Duration::from_secs(30);
const STATUS_TOKEN_TTL: Duration = Duration::from_secs(30);
const MAX_WAIT_MS: u64 = 10_000;
// Win32 desktops have names, not ordinal identities. Public slot 2 is
// exclusively the preselected local desktop; other slots cannot be targeted.
const SELECTED_DESKTOP_SLOT: u64 = 2;

#[derive(Clone, Copy, PartialEq, Eq)]
enum DesktopAvailability {
    Free,
    Occupied,
    Unavailable,
}

impl DesktopAvailability {
    fn as_str(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Occupied => "occupied",
            Self::Unavailable => "unavailable",
        }
    }
}

fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "Window inspection denied")
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "Invalid window inspection request")
}

/// These are LOCAL operator selections, not parameters accepted from an MCP
/// client. No wildcard paths, application discovery or window-title searches.
#[derive(Clone)]
pub struct DedicatedWindow {
    pub desktop_name: String,
    pub executable: PathBuf,
    pub class_name: String,
    pub title: String,
}

impl DedicatedWindow {
    fn validate(&self) -> io::Result<()> {
        if !self.executable.is_absolute()
            || self.executable.components().any(|part| matches!(part, Component::ParentDir))
            || self.executable.to_str().map_or(true, |s| s.len() > 4096)
            || !self.executable.extension().and_then(|s| s.to_str())
                .is_some_and(|s| s.eq_ignore_ascii_case("exe"))
        {
            return Err(invalid());
        }
        let desktop = &self.desktop_name;
        if desktop.is_empty() || desktop.len() > 96
            || !desktop.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
            || ["Default", "Winlogon", "Disconnect", "Screen-saver"]
                .iter().any(|blocked| desktop.eq_ignore_ascii_case(blocked))
        {
            return Err(denied());
        }
        for field in [&self.class_name, &self.title] {
            if field.is_empty() || field.encode_utf16().count() > 255
                || field.chars().any(char::is_control)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    fn accepts_app(&self, app: Option<&str>) -> bool {
        let Some(app) = app else { return true };
        let expected = self.executable.file_name().and_then(|name| name.to_str());
        !app.is_empty() && app.encode_utf16().count() <= 256
            && (expected.is_some_and(|name| app.eq_ignore_ascii_case(name))
                || self.executable.to_str().is_some_and(|path| app.eq_ignore_ascii_case(path)))
    }
}

/// This type has no public constructor. An API/MCP caller cannot authorize a
/// desktop by merely setting an `enabled` field or supplying a raw HWND.
pub struct LocalApproval {
    selection: DedicatedWindow,
    // Captured BEFORE the local dialogue and revalidated after approval.
    // No later MCP call can substitute another HWND with matching title.
    approved_identity: Identity,
}

/// Approve the actual, currently selected window incarnation, not merely a
/// user-entered (executable, class, title) pattern. Dialog dismissal or
/// replacement of the selected HWND/process/thread fails closed.
pub fn confirm_local_selection(selection: DedicatedWindow) -> io::Result<LocalApproval> {
    selection.validate()?;
    let observed = native::foreground(&selection)?;
    let approved_identity = observed.identity;
    native::confirm_local_dialog(&selection, &approved_identity)?;
    // MessageBox may take foreground focus; revalidate the SAVED local HWND,
    // never enumerate/search another window after the modal dialog closes.
    native::verify_selected_identity(&selection, &approved_identity)?;
    Ok(LocalApproval { selection, approved_identity })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Identity {
    // This HWND is never used as a target after the initial observation.
    // Every subsequent read samples GetForegroundWindow anew, then compares.
    hwnd: isize,
    process_id: u32,
    thread_id: u32,
    process_created: u64,
    thread_created: u64,
    desktop: String,
    image: String,
    class_name: String,
    title: String,
}

struct WindowObservation {
    identity: Identity,
    x: i32,
    y: i32,
    width: i64,
    height: i64,
    enabled: bool,
}

impl WindowObservation {
    fn summary(&self, token: &str, selection: &DedicatedWindow) -> Value {
        json!({
            "window_id": token,
            "title": selection.title,
            "class_name": selection.class_name,
            "process_name": selection.executable.file_name().and_then(|n| n.to_str()),
            "x": self.x,
            "y": self.y,
            "width": self.width,
            "height": self.height,
            "is_foreground": true,
            "is_visible": true,
            "is_enabled": self.enabled,
            "targeted_win32_actions_only": true
        })
    }
}

struct Ticket {
    opaque_id: String,
    identity: Identity,
    issued: Instant,
    lease_id: Option<String>,
}

struct Observation {
    opaque_id: String,
    window_id: String,
    identity: Identity,
    issued: Instant,
    lease_id: Option<String>,
    controls: Vec<native::ControlRef>,
}

struct ActiveLease {
    id: String,
    desktop: native::DesktopLease,
}

struct Session {
    selection: DedicatedWindow,
    approved_identity: Identity,
    ticket: Option<Ticket>,
    observation: Option<Observation>,
    lease: Option<ActiveLease>,
    last_free_status: Option<Instant>,
}

impl Session {
    /// A worker releases expired leases even without traffic. This cleanup
    /// additionally revokes all tokens when a later request sees expiration.
    fn expire_lease(&mut self) {
        if self.lease.as_ref().is_some_and(|l| l.desktop.is_expired()) {
            self.lease.take();
            self.ticket = None;
            self.observation = None;
            self.last_free_status = None;
        }
    }

    fn verify_active_lease(&self) -> io::Result<()> {
        if let Some(lease) = &self.lease {
            lease.desktop.verify(&self.selection)?;
        }
        Ok(())
    }

    /// A real Windows desktop handle plus a process-shared exclusive mutex
    /// is required for each read. Legacy read requests get a short-lived
    /// guard; once a lease is active its exact ID must accompany every read.
    fn read_guard(&self, args: &Map<String, Value>) -> io::Result<Option<native::DesktopLease>> {
        let supplied = match args.get("agent_desktop_lease_id") {
            None => None,
            Some(Value::String(id)) if !id.is_empty() => Some(id.as_str()),
            _ => return Err(invalid()),
        };
        if let Some(lease) = &self.lease {
            if supplied != Some(lease.id.as_str()) {
                return Err(denied());
            }
            lease.desktop.verify(&self.selection)?;
            Ok(None)
        } else if supplied.is_some() {
            Err(denied())
        } else {
            Ok(Some(native::DesktopLease::acquire(&self.selection)?))
        }
    }

    fn desktop(&mut self, args: Map<String, Value>) -> io::Result<Value> {
        self.expire_lease();
        if args.keys().any(|key| !matches!(key.as_str(),
            "action" | "desktop_number" | "lease_id"))
            || args.get("desktop_number").is_some_and(|value|
                value.as_u64() != Some(SELECTED_DESKTOP_SLOT))
        {
            return Err(invalid());
        }
        match args.get("action").and_then(Value::as_str) {
            Some("status") if !args.contains_key("lease_id") => {
                let state = if let Some(lease) = &self.lease {
                    if lease.desktop.verify(&self.selection).is_ok() {
                        DesktopAvailability::Occupied
                    } else {
                        DesktopAvailability::Unavailable
                    }
                } else {
                    native::desktop_availability(&self.selection)
                };
                self.last_free_status = (state == DesktopAvailability::Free)
                    .then(Instant::now);
                Ok(json!({
                    "desktop_number": SELECTED_DESKTOP_SLOT,
                    "desktop_name": self.selection.desktop_name,
                    "status": state.as_str(),
                    "leased_by_this_session": self.lease.is_some(),
                    "hud_heartbeating": self.lease.as_ref().is_some_and(|lease|
                        lease.desktop.verify(&self.selection).is_ok()),
                    "mode": "existing-approved-work-desktop",
                    "creates_desktop": false,
                    "switches_desktop": false
                }))
            }
            Some("start") if args.get("desktop_number").and_then(Value::as_u64)
                == Some(SELECTED_DESKTOP_SLOT) && !args.contains_key("lease_id") =>
            {
                let observed_free = self.last_free_status.take()
                    .is_some_and(|at| at.elapsed() <= STATUS_TOKEN_TTL);
                if !observed_free || self.lease.is_some() {
                    return Err(denied());
                }
                // Recheck the exact named desktop under its own mutex.
                // The dedicated owner thread binds it and starts a blue HUD
                // BEFORE the lease can be granted; no SwitchDesktop or UAC.
                let desktop = native::DesktopLease::acquire(&self.selection)?;
                let id = native::new_id()?;
                self.ticket = None;
                self.observation = None;
                self.lease = Some(ActiveLease { id: id.clone(), desktop });
                Ok(json!({
                    "desktop_number": SELECTED_DESKTOP_SLOT,
                    "desktop_name": self.selection.desktop_name,
                    "lease_id": id,
                    "status": "occupied",
                    "hud_heartbeating": true,
                    "mode": "existing-approved-work-desktop",
                    "creates_desktop": false,
                    "switches_desktop": false
                }))
            }
            Some("stop") if !args.contains_key("desktop_number") => {
                let id = args.get("lease_id").and_then(Value::as_str)
                    .ok_or_else(invalid)?;
                if !self.lease.as_ref().is_some_and(|lease| lease.id == id) {
                    return Err(denied());
                }
                // Verify BEFORE taking ownership so a wrong-thread caller
                // cannot accidentally discard the sole native lock handle.
                self.lease.as_ref().ok_or_else(denied)?
                    .desktop.verify(&self.selection)?;
                let lease = self.lease.take().ok_or_else(denied)?;
                self.ticket = None;
                self.observation = None;
                self.last_free_status = None;
                lease.desktop.release()?;
                Ok(json!({
                    "desktop_number": SELECTED_DESKTOP_SLOT,
                    "desktop_name": self.selection.desktop_name,
                    "released": true,
                    "hud_heartbeating": false,
                    "mode": "existing-approved-work-desktop"
                }))
            }
            _ => Err(invalid()),
        }
    }

    fn windows(&mut self, args: Map<String, Value>) -> io::Result<Value> {
        self.expire_lease();
        // Invalidate all previous capabilities even on malformed requests.
        self.ticket = None;
        self.observation = None;
        if args.keys().any(|k| !matches!(k.as_str(),
            "app" | "include_untitled" | "agent_desktop_lease_id"))
            || !valid_app(&args, &self.selection)?
            || bool_arg(&args, "include_untitled", false).is_err()
        {
            return Err(invalid());
        }
        let _transient = self.read_guard(&args)?;
        // A missing, untitled or non-matching target is never substituted
        // by enumeration or a different window.
        let observed = native::foreground(&self.selection)?;
        if observed.identity != self.approved_identity {
            return Err(denied());
        }
        self.verify_active_lease()?;
        let opaque_id = native::new_id()?;
        let response = json!([observed.summary(&opaque_id, &self.selection)]);
        self.ticket = Some(Ticket {
            opaque_id,
            identity: observed.identity,
            issued: Instant::now(),
            lease_id: self.lease.as_ref().map(|lease| lease.id.clone()),
        });
        Ok(response)
    }

    fn snapshot(&mut self, args: Map<String, Value>) -> io::Result<Value> {
        self.expire_lease();
        // Revoke the window ticket and the previous computer observation before
        // looking at user-controlled fields or touching the selected HWND.
        let ticket = self.ticket.take().ok_or_else(denied)?;
        self.observation = None;
        if args.keys().any(|k| !matches!(k.as_str(),
            "window_id" | "app" | "include_tree" | "include_screenshot"
            | "interactive_only" | "max_elements" | "agent_desktop_lease_id"))
            || args.get("window_id").and_then(Value::as_str) != Some(ticket.opaque_id.as_str())
            || ticket.issued.elapsed() > WINDOW_TOKEN_TTL
            || !valid_app(&args, &self.selection)?
        { return Err(invalid()); }
        let with_tree = bool_arg(&args,"include_tree",true)?;
        let screenshot = bool_arg(&args,"include_screenshot",false)?;
        let interactive = bool_arg(&args,"interactive_only",true)?;
        let maximum = number_arg(&args,"max_elements",80,200)?;
        if maximum == 0 { return Err(invalid()); }
        let _transient = self.read_guard(&args)?;
        if ticket.lease_id != self.lease.as_ref().map(|l| l.id.clone()) {
            return Err(denied());
        }
        let observed = native::foreground(&self.selection)?;
        if observed.identity != ticket.identity || observed.identity != self.approved_identity {
            return Err(denied());
        }
        self.verify_active_lease()?;
        let id = native::new_id()?;
        let (result, controls) = snapshot_value(&observed, &ticket.opaque_id,
            &id, &self.selection, with_tree, screenshot, interactive, maximum as usize)?;
        // A modal dialog, reparented child or replacement window must never
        // inherit the ticket simply because the caption happens to match.
        if native::foreground(&self.selection)?.identity != self.approved_identity {
            return Err(denied());
        }
        self.observation = Some(Observation {
            opaque_id: id, window_id: ticket.opaque_id,
            identity: observed.identity, issued: Instant::now(),
            lease_id: ticket.lease_id, controls,
        });
        Ok(result)
    }

    /// One serialized, observation-scoped operation. Physical input remains
    /// unavailable; only native Button.invoke, Edit.set_value and wait work.
    fn action(&mut self, args: Map<String, Value>) -> io::Result<Value> {
        self.expire_lease();
        let previous = self.observation.take().ok_or_else(denied)?;
        self.ticket = None;
        if args.keys().any(|key| !matches!(key.as_str(),
            "action" | "window_id" | "computer_observation_id"
            | "selector" | "value" | "wait_ms" | "settle_ms" | "observe_after"
            | "agent_desktop_lease_id" | "transport"
            | "button" | "double" | "keys" | "verbatim" | "allow_system_keys"
            | "direction" | "to" | "from" | "drag_to" | "wheel"
            | "hold_ms" | "dwell_ms"))
            || args.get("window_id").and_then(Value::as_str)
                != Some(previous.window_id.as_str())
            || args.get("computer_observation_id").and_then(Value::as_str)
                != Some(previous.opaque_id.as_str())
            || previous.issued.elapsed() > WINDOW_TOKEN_TTL
            || args.get("transport").is_some_and(|v| v.as_str()!=Some("send-input"))
        { return Err(invalid()); }
        let action=args.get("action").and_then(Value::as_str).ok_or_else(invalid)?;
        if !matches!(action,"wait"|"invoke"|"set_value"|"click"
            |"hover"|"drag"|"send_keys"|"scroll") { return Err(invalid()); }
        if matches!(action,"wait"|"invoke"|"set_value")
            && args.keys().any(|k| matches!(k.as_str(),
                "button"|"double"|"keys"|"verbatim"|"allow_system_keys"
                |"direction"|"to"|"from"|"drag_to"|"wheel"|"hold_ms"|"dwell_ms"))
        {return Err(invalid());}
        let after=args.get("observe_after").map_or(Some("tree"),Value::as_str)
            .ok_or_else(invalid)?;
        if !matches!(after,"none"|"tree"|"screenshot"|"both") {return Err(invalid());}
        let settle=number_arg(&args,"settle_ms",150,5_000)?;
        let wait=number_arg(&args,"wait_ms",1_000,MAX_WAIT_MS)?;
        let _transient=self.read_guard(&args)?;
        if previous.lease_id != self.lease.as_ref().map(|l|l.id.clone()) {
            return Err(denied());
        }
        let current=native::foreground(&self.selection)?;
        if current.identity != previous.identity || current.identity != self.approved_identity {
            return Err(denied());
        }
        self.verify_active_lease()?;

        match parse_ui_action(action, &args)? {
            ParsedUiAction::Invoke { selector } => {
                native::act(&self.selection,&previous.identity,
                    &previous.controls,selector,"invoke",None)?;
                if settle > 0 {std::thread::sleep(Duration::from_millis(settle));}
            }
            ParsedUiAction::SetValue { selector, value } => {
                native::act(&self.selection,&previous.identity,
                    &previous.controls,selector,"set_value",Some(value))?;
                if settle > 0 {std::thread::sleep(Duration::from_millis(settle));}
            }
            ParsedUiAction::Wait => {
                let start=Instant::now();
                loop {
                    if let Ok(observed)=native::foreground(&self.selection) {
                        if observed.identity != previous.identity
                            || observed.identity != self.approved_identity {
                            return Err(denied());
                        }
                        break;
                    }
                    let remaining=Duration::from_millis(wait).saturating_sub(start.elapsed());
                    if remaining.is_zero() {return Err(denied());}
                    std::thread::sleep(remaining.min(Duration::from_millis(100)));
                }
            }
            ParsedUiAction::Scroll { selector, direction, to } => {
                native::scroll(&self.selection,&previous.identity,&previous.controls,
                    selector,direction,to)?;
                if settle > 0 {std::thread::sleep(Duration::from_millis(settle));}
            }
            ParsedUiAction::SendKeys { selector, keys, verbatim } => {
                native::send_keys(&self.selection,&previous.identity,&previous.controls,
                    selector,keys,verbatim)?;
                if settle > 0 {std::thread::sleep(Duration::from_millis(settle));}
            }
        }

        // An action can legitimately close/rename its own approved window.
        // Report performed, but do NOT mint a successor capability for any
        // different HWND/process/thread incarnation or non-foreground app.
        let mut result=json!({"action":action,"completed":true,
            "transport":"bounded_selected_window_message",
            "new_observation_required":true});
        if after=="none" {return Ok(result);}
        let Ok(observed)=native::foreground(&self.selection) else {
            result["snapshot_status"]=json!("target_unavailable_after_action");
            return Ok(result);
        };
        if observed.identity!=previous.identity||observed.identity!=self.approved_identity {
            result["snapshot_status"]=json!("identity_changed_after_action");
            return Ok(result);
        }
        self.verify_active_lease()?;
        let id=native::new_id()?;
        let include_tree=matches!(after,"tree"|"both");
        let screenshot=matches!(after,"screenshot"|"both");
        let (snapshot,controls)=snapshot_value(
            &observed,&previous.window_id,&id,&self.selection,
            include_tree,screenshot,true,80)?;
        if native::foreground(&self.selection)?.identity!=self.approved_identity {
            result["snapshot_status"]=json!("stale_after_action");
            return Ok(result);
        }
        self.observation=Some(Observation {
            opaque_id:id,window_id:previous.window_id,identity:observed.identity,
            issued:Instant::now(),lease_id:previous.lease_id,controls,
        });
        result["snapshot"]=snapshot;
        Ok(result)
    }
}

fn snapshot_value(
    observed: &WindowObservation, window_id: &str, observation_id: &str,
    selection: &DedicatedWindow, include_tree: bool, include_screenshot: bool,
    interactive_only: bool, maximum: usize,
) -> io::Result<(Value, Vec<native::ControlRef>)> {
    let captured_at_unix_ms = u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_| denied())?.as_millis()
    ).map_err(|_| denied())?;
    let (elements, refs, truncated) = if include_tree {
        let result = native::controls(selection, &observed.identity, maximum, interactive_only)?;
        (result.nodes, result.refs, result.truncated)
    } else { (Vec::new(), Vec::new(), false) };
    let mut snapshot=json!({
        "captured_at_unix_ms":captured_at_unix_ms,
        "window":observed.summary(window_id,selection),
        "elements":elements,
        "elements_truncated":truncated,
        "semantic_tree_status":if include_tree {"win32_native_controls"} else {"not_requested"},
        "screenshot_status":"not_requested",
        "computer_observation_id":observation_id,
        "action_capability":true,
        "supported_actions":["wait","invoke","set_value","scroll","send_keys"],
        "targeted_win32_actions_only":true
    });
    if include_screenshot {
        match native::screenshot(selection,&observed.identity) {
            Ok((png,width,height)) => {
                snapshot["screenshot_status"]=json!("captured_selected_window_only");
                snapshot["screenshot"]=json!({
                    "mime_type":"image/png","data_base64":png,
                    "width":width,"height":height,"source":"selected_window_wm_print"
                });
            }
            Err(_) => snapshot["screenshot_status"]=json!("unsupported_for_selected_window"),
        }
    }
    Ok((snapshot,refs))
}

fn number_arg(args: &Map<String,Value>, key: &str, default: u64, maximum: u64) -> io::Result<u64> {
    let result = match args.get(key) {
        None => default,
        Some(value) => value.as_u64().ok_or_else(invalid)?,
    };
    if result > maximum {return Err(invalid());}
    Ok(result)
}

fn valid_app(args: &Map<String, Value>, selection: &DedicatedWindow) -> io::Result<bool> {
    match args.get("app") {
        None => Ok(true),
        Some(Value::String(value)) => Ok(selection.accepts_app(Some(value))),
        _ => Err(invalid()),
    }
}

fn bool_arg(args: &Map<String, Value>, key: &str, default: bool) -> io::Result<bool> {
    match args.get(key) {
        None => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        _ => Err(invalid()),
    }
}

/// Register only locally approved, genuinely implemented read-only tools.
/// Even "start" only opens the existing selected desktop and takes a lock;
/// it cannot launch a desktop, create a window or switch user input.
pub fn attach(
    approval: LocalApproval,
    catalog: &mut Vec<ToolDefinition>,
    handlers: &mut ToolMapHandler,
) {
    let session = Arc::new(Mutex::new(Session {
        selection: approval.selection,
        approved_identity: approval.approved_identity,
        ticket: None,
        observation: None,
        lease: None,
        last_free_status: None,
    }));
    let list = Arc::clone(&session);
    handlers.register("desktop_ui_windows", move |args| {
        let result = list.lock().map_err(|_| denied())
            .and_then(|mut state| state.windows(args));
        Ok(match result {
            Ok(value) => ToolCallResult::text(value.to_string()),
            Err(_) => ToolCallResult::tool_error("WINDOW_READ_REFUSED"),
        })
    });
    let inspect = Arc::clone(&session);
    handlers.register("desktop_ui_snapshot", move |args| {
        let result = inspect.lock().map_err(|_| denied())
            .and_then(|mut state| state.snapshot(args));
        Ok(match result {
            Ok(value) => ToolCallResult::text(value.to_string()),
            Err(error) if error.kind() == io::ErrorKind::Unsupported =>
                ToolCallResult::tool_error("WINDOW_TREE_UNSUPPORTED"),
            Err(_) => ToolCallResult::tool_error("WINDOW_READ_REFUSED"),
        })
    });

    let desktop = Arc::clone(&session);
    handlers.register("desktop_agent_desktop", move |args| {
        let result = desktop.lock().map_err(|_| denied())
            .and_then(|mut state| state.desktop(args));
        Ok(match result {
            Ok(value) => ToolCallResult::text(value.to_string()),
            Err(_) => ToolCallResult::tool_error("WINDOW_READ_REFUSED"),
        })
    });
    let actions = Arc::clone(&session);
    handlers.register("desktop_ui_action", move |args| {
        let result = actions.lock().map_err(|_| denied())
            .and_then(|mut state| state.action(args));
        Ok(match result {
            Ok(value) => ToolCallResult::text(value.to_string()),
            Err(error) if error.kind() == io::ErrorKind::Unsupported
                && error.to_string() == "requires_foreground_input" =>
                ToolCallResult::tool_error("REQUIRES_FOREGROUND_INPUT"),
            Err(error) if error.kind() == io::ErrorKind::Unsupported =>
                ToolCallResult::tool_error("WINDOW_ACTION_UNSUPPORTED"),
            Err(error) if error.kind() == io::ErrorKind::TimedOut =>
                ToolCallResult::tool_error("WINDOW_ACTION_TIMEOUT"),
            Err(_) => ToolCallResult::tool_error("WINDOW_ACTION_REFUSED"),
        })
    });

    catalog.push(ToolDefinition::new(
        "desktop_ui_windows",
        Some("List ONLY the operator-approved foreground window on a dedicated Windows desktop; never enumerate other windows.".into()),
        json!({"type":"object","additionalProperties":false,"properties":{
            "app":{"type":"string","minLength":1,"maxLength":256},
            "include_untitled":{"type":"boolean"},
            "agent_desktop_lease_id":{"type":"string","minLength":36,"maxLength":36}
        }})
    ));
    catalog.push(ToolDefinition::new(
        "desktop_ui_snapshot",
        Some("Inspect only the exact locally approved work window: bounded Win32 native control tree and optional window-only WM_PRINT PNG. No unrelated HWND or desktop capture.".into()),
        json!({"type":"object","additionalProperties":false,"required":["window_id"],"properties":{
            "window_id":{"type":"string","minLength":36,"maxLength":36},
            "app":{"type":"string","minLength":1,"maxLength":256},
            "include_tree":{"type":"boolean","default":true},
            "include_screenshot":{"type":"boolean","default":false},
            "interactive_only":{"type":"boolean","default":true},
            "max_elements":{"type":"integer","minimum":1,"maximum":200},
            "agent_desktop_lease_id":{"type":"string","minLength":36,"maxLength":36}
        }})
    ));
    catalog.push(ToolDefinition::new(
        "desktop_agent_desktop",
        Some("Status/start/stop for one locally preselected dedicated desktop. Start atomically claims it and requires a visible blue safety HUD with a live heartbeat. No user desktop switching or elevation; slot 2 is a local alias, not an OS desktop index.".into()),
        json!({"type":"object","additionalProperties":false,"required":["action"],"properties":{
            "action":{"type":"string","enum":["status","start","stop"]},
            "desktop_number":{"type":"integer","const":SELECTED_DESKTOP_SLOT},
            "lease_id":{"type":"string","minLength":36,"maxLength":36}
        }})
    ));
    catalog.push(ToolDefinition::new(
        "desktop_ui_action",
        Some("Fresh one-time observation: native Button.invoke, non-password Edit.set_value, semantic WM_VSCROLL/WM_HSCROLL scroll, bounded post-message Edit.send_keys, or wait. Physical mouse/wheel/SendInput actions refuse REQUIRES_FOREGROUND_INPUT.".into()),
        json!({"type":"object","additionalProperties":false,
            "required":["action","window_id","computer_observation_id"],"properties":{
            "action":{"type":"string","enum":["invoke","set_value","click","hover","scroll","send_keys","drag","wait"]},
            "window_id":{"type":"string","minLength":36,"maxLength":36},
            "computer_observation_id":{"type":"string","minLength":36,"maxLength":36},
            "selector":{"type":"string","minLength":1,"maxLength":512},
            "value":{"type":"string","maxLength":65536},
            "button":{"type":"string","enum":["left","right"]},
            "double":{"type":"boolean"},
            "keys":{"type":"string","maxLength":4096},
            "verbatim":{"type":"boolean"},
            "allow_system_keys":{"type":"boolean"},
            "direction":{"type":"string","enum":["up","down","left","right"]},
            "to":{"type":"string","enum":["top","bottom"]},
            "from":{"type":"string","minLength":1,"maxLength":512},
            "drag_to":{"type":"string","minLength":1,"maxLength":512},
            "wheel":{"type":"integer","minimum":-100,"maximum":100},
            "hold_ms":{"type":"integer","minimum":0,"maximum":5000},
            "dwell_ms":{"type":"integer","minimum":0,"maximum":5000},
            "wait_ms":{"type":"integer","minimum":0,"maximum":MAX_WAIT_MS},
            "settle_ms":{"type":"integer","minimum":0,"maximum":5000},
            "observe_after":{"type":"string","enum":["none","tree","screenshot","both"],"default":"tree"},
            "transport":{"type":"string","const":"send-input"},
            "agent_desktop_lease_id":{"type":"string","minLength":36,"maxLength":36}
        }})
    ));
}

#[cfg(windows)]
#[path = "../window_inspection_win32.rs"]
mod native;

#[cfg(not(windows))]
mod native {
    use super::*;
    #[derive(Clone)]
    pub(super) struct ControlRef;
    pub(super) struct Tree {
        pub(super) nodes: Vec<Value>,
        pub(super) refs: Vec<ControlRef>,
        pub(super) truncated: bool,
    }
    pub(super) fn controls(_: &DedicatedWindow, _: &Identity, _: usize, _: bool)
        -> io::Result<Tree> { Err(denied()) }
    pub(super) fn screenshot(_: &DedicatedWindow, _: &Identity)
        -> io::Result<(String,usize,usize)> { Err(denied()) }
    pub(super) fn act(_: &DedicatedWindow, _: &Identity, _: &[ControlRef],
        _: &str, _: &str, _: Option<&str>) -> io::Result<()> { Err(denied()) }
    pub(super) fn scroll(_: &DedicatedWindow, _: &Identity, _: &[ControlRef],
        _: Option<&str>, _: Option<&str>, _: Option<&str>) -> io::Result<()> { Err(denied()) }
    pub(super) fn send_keys(_: &DedicatedWindow, _: &Identity, _: &[ControlRef],
        _: &str, _: &str, _: bool) -> io::Result<()> { Err(denied()) }
    pub(super) struct DesktopLease;
    impl DesktopLease {
        pub(super) fn acquire(_: &DedicatedWindow) -> io::Result<Self> { Err(denied()) }
        pub(super) fn is_expired(&self) -> bool { true }
        pub(super) fn verify(&self, _: &DedicatedWindow) -> io::Result<()> { Err(denied()) }
        pub(super) fn release(self) -> io::Result<()> { Err(denied()) }
    }
    pub(super) fn desktop_availability(_: &DedicatedWindow) -> DesktopAvailability {
        DesktopAvailability::Unavailable
    }
    pub(super) fn confirm_local_dialog(_: &DedicatedWindow, _: &Identity) -> io::Result<()> {
        Err(denied())
    }
    pub(super) fn verify_selected_identity(_: &DedicatedWindow, _: &Identity) -> io::Result<()> {
        Err(denied())
    }
    pub(super) fn foreground(_: &DedicatedWindow) -> io::Result<WindowObservation> {
        Err(denied())
    }
    pub(super) fn new_id() -> io::Result<String> {
        Err(denied())
    }
}
#[derive(Debug, PartialEq, Eq)]
enum ParsedUiAction<'a> {
    Invoke { selector: &'a str },
    SetValue { selector: &'a str, value: &'a str },
    Wait,
    Scroll { selector: Option<&'a str>, direction: Option<&'a str>, to: Option<&'a str> },
    SendKeys { selector: &'a str, keys: &'a str, verbatim: bool },
}

fn parse_ui_action<'a>(action: &str, args: &'a Map<String, Value>) -> io::Result<ParsedUiAction<'a>> {
    match action {
        "invoke" | "set_value" => {
            if args.contains_key("wait_ms") { return Err(invalid()); }
            let selector = args.get("selector").and_then(Value::as_str)
                .filter(|s| !s.is_empty() && s.len() <= 512).ok_or_else(invalid)?;
            if action == "set_value" {
                let value = args.get("value").and_then(Value::as_str).ok_or_else(invalid)?;
                Ok(ParsedUiAction::SetValue { selector, value })
            } else {
                if args.contains_key("value") { return Err(invalid()); }
                Ok(ParsedUiAction::Invoke { selector })
            }
        }
        "wait" => {
            if args.contains_key("selector") || args.contains_key("value") { return Err(invalid()); }
            Ok(ParsedUiAction::Wait)
        }
        "scroll" => {
            if args.contains_key("wheel") {
                return Err(io::Error::new(io::ErrorKind::Unsupported, "requires_foreground_input"));
            }
            if args.keys().any(|k| matches!(k.as_str(),
                "value"|"keys"|"verbatim"|"allow_system_keys"|"button"|"double"
                |"from"|"drag_to"|"hold_ms"|"dwell_ms"|"wait_ms"|"transport")) {
                return Err(invalid());
            }
            let selector = match args.get("selector") {
                None => None,
                Some(v) => Some(v.as_str().filter(|s| !s.is_empty() && s.len() <= 512).ok_or_else(invalid)?),
            };
            let direction = match args.get("direction") {
                None => None,
                Some(v) => {
                    let d = v.as_str().ok_or_else(invalid)?;
                    if !matches!(d, "up"|"down"|"left"|"right") { return Err(invalid()); }
                    Some(d)
                }
            };
            let to = match args.get("to") {
                None => None,
                Some(v) => {
                    let t = v.as_str().ok_or_else(invalid)?;
                    if !matches!(t, "top"|"bottom") { return Err(invalid()); }
                    Some(t)
                }
            };
            if direction.is_some() == to.is_some() { return Err(invalid()); }
            Ok(ParsedUiAction::Scroll { selector, direction, to })
        }
        "send_keys" => {
            if args.contains_key("transport") {
                return Err(io::Error::new(io::ErrorKind::Unsupported, "requires_foreground_input"));
            }
            if args.keys().any(|k| matches!(k.as_str(),
                "value"|"button"|"double"|"direction"|"to"|"from"|"drag_to"
                |"wheel"|"hold_ms"|"dwell_ms"|"wait_ms")) {
                return Err(invalid());
            }
            if bool_arg(args, "allow_system_keys", false)? {
                return Err(denied());
            }
            let selector = args.get("selector").and_then(Value::as_str)
                .filter(|s| !s.is_empty() && s.len() <= 512).ok_or_else(invalid)?;
            let keys = args.get("keys").and_then(Value::as_str)
                .filter(|s| !s.is_empty() && s.len() <= 4096).ok_or_else(invalid)?;
            let verbatim = bool_arg(args, "verbatim", false)?;
            Ok(ParsedUiAction::SendKeys { selector, keys, verbatim })
        }
        "click" | "hover" | "drag" => {
            Err(io::Error::new(io::ErrorKind::Unsupported, "requires_foreground_input"))
        }
        _ => Err(invalid()),
    }
}

#[cfg(test)]
mod action_guard_tests {
    use super::*;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn foreground_only_and_system_key_gaps_fail_closed() {
        for fg in ["click", "hover", "drag"] {
            let err = parse_ui_action(fg, &obj(json!({"selector": "control:1"}))).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);
            assert_eq!(err.to_string(), "requires_foreground_input");
        }
        let wheel_err = parse_ui_action("scroll", &obj(json!({"wheel": -3}))).unwrap_err();
        assert_eq!(wheel_err.kind(), io::ErrorKind::Unsupported);
        assert_eq!(wheel_err.to_string(), "requires_foreground_input");

        let si_err = parse_ui_action(
            "send_keys",
            &obj(json!({"selector": "control:1", "keys": "hi", "transport": "send-input"})),
        )
        .unwrap_err();
        assert_eq!(si_err.kind(), io::ErrorKind::Unsupported);
        assert_eq!(si_err.to_string(), "requires_foreground_input");

        let sys_err = parse_ui_action(
            "send_keys",
            &obj(json!({"selector": "control:1", "keys": "hi", "allow_system_keys": true})),
        )
        .unwrap_err();
        assert_eq!(sys_err.kind(), io::ErrorKind::PermissionDenied);

        assert!(parse_ui_action("scroll", &obj(json!({"direction": "down", "to": "bottom"}))).is_err());
        assert!(parse_ui_action("scroll", &obj(json!({}))).is_err());
        assert_eq!(
            parse_ui_action("scroll", &obj(json!({"selector": "control:2", "direction": "down"}))).unwrap(),
            ParsedUiAction::Scroll { selector: Some("control:2"), direction: Some("down"), to: None }
        );
        assert_eq!(
            parse_ui_action("send_keys", &obj(json!({"selector": "control:1", "keys": "abc", "verbatim": true}))).unwrap(),
            ParsedUiAction::SendKeys { selector: "control:1", keys: "abc", verbatim: true }
        );
    }
}