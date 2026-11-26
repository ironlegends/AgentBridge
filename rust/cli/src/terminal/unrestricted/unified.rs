//! Launch settings and lease authority for the unified direct terminal.
use super::{invalid, string, ProcessResult};
use crate::agent_desktop::AgentDesktopHandle;
#[cfg(windows)]
use crate::agent_desktop::DesktopLease;
#[cfg(windows)]
use crate::owned_children::OwnedChild;
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::time::Duration;

#[derive(Clone)]
pub(super) struct Configuration {
    pub(super) desktops: AgentDesktopHandle,
    pub(super) private_root: PathBuf,
}

pub(super) struct Launch {
    pub(super) presentation: Presentation,
    pub(super) lease: Option<LeaseBinding>,
}

#[derive(Default)]
pub(super) struct Presentation {
    pub(super) visible: bool,
    pub(super) temp: Option<TemporaryDirectory>,
    pub(super) cwd_warning: Option<String>,
}

pub(super) struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    #[cfg(windows)]
    pub(super) fn path(&self) -> &Path { &self.0 }

    pub(super) fn cleanup(&self) -> std::io::Result<()> {
        match std::fs::remove_dir_all(&self.0) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) { let _ = self.cleanup(); }
}

#[derive(Clone)]
pub(super) struct LeaseBinding {
    desktops: AgentDesktopHandle,
    #[cfg(windows)]
    lease: DesktopLease,
    pub(super) id: String,
}

impl LeaseBinding {
    #[cfg(windows)]
    pub(super) fn place(&self, child: &OwnedChild, timeout: Duration) -> ProcessResult<()> {
        self.desktops.place_owned_tree(&self.lease, child, timeout)
            .map_err(|error| error.to_string())
    }

    pub(super) fn verify(&self) -> ProcessResult<()> {
        self.desktops.verify_lease(&self.id).map(|_| ())
            .map_err(|error| error.to_string())
    }
}

pub(super) fn visible_requested(args: &Map<String, Value>) -> bool {
    args.get("window_mode").and_then(Value::as_str) == Some("visible")
}

fn option<'a>(args: &'a Map<String, Value>, name: &str,
    default: &'a str, allowed: &[&str]) -> ProcessResult<&'a str>
{
    match args.get(name) {
        None => Ok(default),
        Some(value) => value.as_str().filter(|text| allowed.contains(text))
            .ok_or_else(|| invalid(&format!("{name} must be {}", allowed.join(" or ")))),
    }
}

#[cfg(windows)]
fn path_budget(path: &Path) -> ProcessResult<Option<String>> {
    use std::os::windows::ffi::OsStrExt;
    // The verbatim prefix does not consume legacy DOS path headroom.
    let mut units = path.as_os_str().encode_wide().count();
    if path.to_string_lossy().starts_with(r"\\?\UNC\") { units = units.saturating_sub(6); }
    else if path.to_string_lossy().starts_with(r"\\?\") { units = units.saturating_sub(4); }
    let remaining = 258usize.saturating_sub(units);
    if remaining < 48 {
        return Err(format!("PROCESS_WINDOWS_PATH_BUDGET: length={units}, remaining_relative={remaining}"));
    }
    Ok((remaining < 96).then(|| format!("WINDOWS_PATH_BUDGET_WARNING cwd_length={units} remaining_relative={remaining}")))
}

#[cfg(windows)]
fn private_temp(root: &Path, id: &str) -> ProcessResult<TemporaryDirectory> {
    if !root.is_absolute() {
        return Err("PROCESS_TEMP_UNAVAILABLE: private runtime directory must be absolute".into());
    }
    let path = root.join(format!("t-{}{}", &id[..8], &id[9..13]));
    path_budget(&path).map_err(|error| format!("PROCESS_TEMP_UNAVAILABLE: {error}"))?;
    // The runtime provisions this root. A child gets its own fresh directory;
    // create_dir refuses existing names, including any preexisting reparse point.
    std::fs::create_dir(&path).map_err(|error| format!("PROCESS_TEMP_UNAVAILABLE: {error}"))?;
    Ok(TemporaryDirectory(path))
}

impl Configuration {
    pub(super) fn prepare(&self, args: &Map<String, Value>, cwd: &Path, id: &str) -> ProcessResult<Launch> {
        let visible = option(args, "window_mode", "hidden", &["hidden", "visible"])? == "visible";
        let elevation = option(args, "elevation", "standard", &["standard", "admin"])?;
        let cwd_requested = args.contains_key("cwd");
        let temp_default = if cfg!(windows) && cwd_requested { "short" } else { "inherit" };
        let short = option(args, "temp_mode", temp_default, &["short", "inherit"])? == "short";
        let lease_id = args.contains_key("agent_desktop_lease_id")
            .then(|| string(args, "agent_desktop_lease_id", 36)).transpose()?;
        if elevation == "admin" {
            if lease_id.is_some() { return Err("PROCESS_ADMIN_AGENT_DESKTOP_UNSUPPORTED".into()); }
            return Err("PROCESS_ADMIN_UNAVAILABLE: normal UAC launch is not qualified".into());
        }
        if !cfg!(windows) && (visible || short || lease_id.is_some()) {
            return Err("PROCESS_PRESENTATION_UNAVAILABLE: visible, short TEMP, and Agent Desktop require Windows".into());
        }
        if visible && lease_id.is_some() {
            return Err("PROCESS_VISIBLE_AGENT_DESKTOP_UNSUPPORTED: the system console host cannot be verified as a member of the owned Job".into());
        }
        let lease = lease_id.map(|id| {
            let _lease = self.desktops.verify_lease(id).map_err(|error| error.to_string())?;
            Ok::<_, String>(LeaseBinding {
                desktops: self.desktops.clone(),
                #[cfg(windows)]
                lease: _lease,
                id: id.to_owned(),
            })
        }).transpose()?;
        #[cfg(windows)]
        let cwd_warning = if cwd_requested {
            let verified = cwd.canonicalize().map_err(|error| format!("PROCESS_CWD_UNAVAILABLE: {error}"))?;
            path_budget(&verified)?
        } else { None };
        #[cfg(windows)]
        let temp = if short { Some(private_temp(&self.private_root, id)?) } else { None };
        #[cfg(not(windows))]
        let (cwd_warning, temp) = { let _ = (&self.private_root, cwd, id); (None, None) };
        Ok(Launch { presentation: Presentation { visible, temp, cwd_warning }, lease })
    }
}


pub(super) fn describe(tools: &mut [agent_bridge_gateway::ToolDefinition]) {
    use serde_json::json;
    for tool in tools {
        let properties = tool.input_schema["properties"].as_object_mut().expect("terminal schema");
        let description = match tool.name.as_str() {
            "desktop_start_process" => {
                properties.get_mut("command").expect("command schema")["maxLength"] = json!(32768);
                properties.get_mut("shell").expect("shell schema")["enum"] = json!(["pwsh", "powershell", "powershell.exe", "cmd", "cmd.exe", "sh", "bash"]);
                properties.insert("timeout_ms".into(), json!({"type":"integer","minimum":250,"maximum":30000,"default":3000}));
                properties.insert("window_mode".into(), json!({"type":"string","enum":["hidden","visible"],"default":"hidden",
                    "description":"Windows only. Visible creates an interactive physical console with console stdin/stdout/stderr. MCP does not capture those streams."}));
                properties.insert("temp_mode".into(), json!({"type":"string","enum":["inherit","short"],
                    "description":"Windows short mode creates private TEMP/TMP for the child and is the default with an explicit cwd."}));
                properties.insert("elevation".into(), json!({"type":"string","enum":["standard","admin"],"default":"standard"}));
                properties.insert("agent_desktop_lease_id".into(), json!({"type":"string","format":"uuid",
                    "description":"Validate an active lease and bind the owned GUI window tree to it. Admin and visible console modes are unavailable with a lease."}));
                "Start a current-user shell command or literal program with exact argv in Fully Unlocked mode. The start timeout bounds the receipt wait. The gateway owns the process tree through confirmed cleanup. A visible Windows console requires explicit opt-in."
            }
            "desktop_read_process" => {
                properties.insert("offset".into(), json!({"type":"integer","minimum":-100000,"maximum":100000,"default":0}));
                properties.insert("length".into(), json!({"type":"integer","minimum":1,"maximum":5000,"default":1000}));
                "Read bounded UTF-8 history from an owned session. Offset 0 advances the reader, a positive offset is an index in the retained history, and a negative offset is relative to the end. Visible console sessions report lifecycle diagnostics."
            }
            "desktop_interact_process" => {
                properties.get_mut("timeout_ms").expect("timeout schema")["default"] = json!(8000);
                properties.insert("wait_for_prompt".into(), json!({"type":"boolean","default":true}));
                "Queue literal UTF-8 stdin and optional EOF to an owned hidden session. With wait_for_prompt enabled, allow the new output to settle until the wait expires. Disabling the wait returns the queue receipt immediately."
            }
            _ => continue,
        };
        tool.description = Some(description.into());
    }
}
