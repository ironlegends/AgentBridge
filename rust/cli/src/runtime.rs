#[path = "workspace_qualification.rs"]
mod workspace_qualification;
#[path = "runtime_unified.rs"]
mod unified;
pub(crate) use unified::unified_router;
#[cfg(all(test, windows))]
#[path = "integration_qualification_tests.rs"]
mod integration_qualification_tests;

use agent_bridge_core::CoreDatabase;
use agent_bridge_desktop::{DesktopConfig, DesktopFiles, DesktopProfile};
use agent_bridge_gateway::{
    GatewayConfig, McpGateway, ToolCallResult, ToolContent, ToolDefinition, ToolDispatchError,
    ToolHandler, ToolMapHandler,
};
use crate::session_profile::{rank, ProfileControl};
use serde_json::{json, Value};
use std::error::Error;
pub type RuntimeError = Box<dyn Error + Send + Sync>;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub type Router = McpGateway<ToolMapHandler>;
pub(crate) type SharedCoreDatabase = Arc<Mutex<CoreDatabase>>;

/// The optional Core connection was qualified once before Task Room startup.
/// The local operator UI shares this owner instead of reopening a live WAL DB.
pub(crate) struct WorkstationRuntime {
    pub(crate) router: Router,
    pub(crate) database: Option<SharedCoreDatabase>,
}

// This value comes exclusively from the operator-qualified physical directory.
// Every Task Room request rechecks it; a directory replaced after startup loses
// access even when the SQLite database is shared between projects.
pub(crate) fn task_room_workspace_binding(root: &Path) -> Result<String, RuntimeError> {
    #[cfg(windows)]
    {
        let sid = agent_bridge_lifecycle::workspace_access::project_read_sid(root)?;
        Ok(format!("task-room.windows.project-read-sid.v1:{sid}"))
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let canonical = std::fs::canonicalize(root)?;
        if canonical != root {
            return Err("Task Room project path changed".into());
        }
        let link = std::fs::symlink_metadata(root)?;
        if !link.is_dir() || link.file_type().is_symlink() {
            return Err("Task Room project path is not a physical directory".into());
        }
        let pinned = std::fs::File::open(root)?;
        let identity = pinned.metadata()?;
        if !identity.is_dir() || identity.dev() != link.dev()
            || identity.ino() != link.ino()
        {
            return Err("Task Room project directory identity changed".into());
        }
        Ok(format!(
            "task-room.unix.dir.v1:{}:{}:{}",
            canonical.display(), identity.dev(), identity.ino()
        ))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = root;
        Err("Task Rooms require a physically identified project directory".into())
    }
}

struct Workspace {
    root: PathBuf,
    write_files: bool,
    profile: DesktopProfile,
}

/// Validate all requested workstation paths BEFORE opening a database or
/// registering any workstation tools. None means mission-only stdio/HTTP.
fn qualified_workspace(
    database_path: &Path,
    workspace: Option<(&Path, bool)>,
    settings: Option<&Path>,
) -> Result<Option<Workspace>, RuntimeError> {
    workspace
        .map(|(selected, writable)| {
            let root = workspace_qualification::qualify(selected, database_path, settings)?;
            let profile = match std::env::var("AGENT_BRIDGE_DESKTOP_PROFILE") {
                Ok(raw) => raw.parse::<DesktopProfile>()?,
                Err(std::env::VarError::NotPresent) if writable => DesktopProfile::WorkspaceWrite,
                Err(std::env::VarError::NotPresent) => DesktopProfile::ReadOnly,
                Err(error) => return Err(error.into()),
            };
            Ok::<_, RuntimeError>(Workspace {
                root,
                write_files: writable && !matches!(profile, DesktopProfile::ReadOnly),
                profile,
            })
        })
        .transpose()
}

pub fn inspect_revision(project: &Path, database: &Path, settings: &Path) -> Result<Value, RuntimeError> {
    #[cfg(windows)]
    {
        let _selection = agent_bridge_lifecycle::workspace_access::PinnedProjectDirectory::open(project)?;
        let project = workspace_qualification::qualify(project, database, Some(settings))?;
        let sid = agent_bridge_lifecycle::workspace_access::project_read_sid(&project)?;
        eprintln!("agent-bridge: project read SID for {}: {sid}", project.display());
        crate::terminal::inspect_revision(settings, &project, database)
    }
    #[cfg(not(windows))]
    {
        let _ = (project, database, settings);
        Err("Restricted Git process inspection requires Windows".into())
    }
}

pub fn missions(database_path: &Path) -> Result<Router, RuntimeError> {
    // Mission-only HTTP has no workstation sessions or watchdog to keep.
    let mut supervisors = Vec::new();
    open_qualified(database_path, None, None, None, None, None,
        #[cfg(any(windows, unix))] None, &mut supervisors)
}

/// Standalone Web MCP file-READ router. Unlike the mission/stdio gateway this
/// does not create a SQLite handle, inspect mission rows, attach a terminal,
/// extensions, any write-capable tool, or even a workspace status tool.
/// The database path is used *only* by the existing project qualification
/// guard to exclude the Core state directory. It is never opened here.
/// Both independent OAuth state roots are also excluded from the project.
pub fn project_read_router(
    project: &Path,
    database_boundary: &Path,
    workstation_oauth_state: &Path,
    missions_oauth_state: &Path,
    settings_dir: &Path,
    lifecycle_dir: &Path,
) -> Result<Router, RuntimeError> {
    let qualified = workspace_qualification::qualify(
        project, database_boundary, Some(workstation_oauth_state),
    )?;
    for excluded in [missions_oauth_state, settings_dir, lifecycle_dir] {
        let validated = workspace_qualification::qualify(
            project, database_boundary, Some(excluded),
        )?;
        if qualified != validated {
            return Err("Project selection changed during read-only qualification".into());
        }
    }
    // Do not use AGENT_BRIDGE_DESKTOP_PROFILE: an environment value must
    // never promote this Web reader to workspace-write/full-control.
    let files = Arc::new(DesktopFiles::open(
        DesktopConfig::new(qualified).with_web_project_read_policy(),
    ).map_err(|error| io::Error::other(error.message))?);
    const READ_TOOLS: &[&str] = &[
        "desktop_get_file_info", "desktop_list_directory",
        "desktop_read_file", "desktop_search",
    ];
    let mut catalog = Vec::with_capacity(READ_TOOLS.len());
    let mut handlers = ToolMapHandler::new();
    for spec in files.tool_catalog() {
        if !READ_TOOLS.contains(&spec.name) { continue; }
        let reader = Arc::clone(&files);
        let name = spec.name;
        handlers.register(name, move |args| {
            // DesktopFiles enforces private-path exclusions BEFORE opening
            // entries or consuming any quota; no post-read filtering.
            let result = reader.dispatch(name, &Value::Object(args));
            if result.get("isError").and_then(Value::as_bool) == Some(true) {
                return Ok(ToolCallResult::tool_error("PROJECT_READ_REFUSED"));
            }
            serde_json::from_value(result)
                .map_err(|_| ToolDispatchError::internal("PROJECT_READ_UNAVAILABLE"))
        });
        catalog.push(ToolDefinition::new(
            name, Some(spec.description.to_owned()), spec.input_schema,
        ));
    }
    if catalog.len() != READ_TOOLS.len() {
        return Err("Required read-only DesktopFiles tools are unavailable".into());
    }
    Ok(McpGateway::new(
        GatewayConfig::new("agent-bridge-project-read", env!("CARGO_PKG_VERSION")),
        catalog, handlers,
    ))
}

/// Snapshot the EXACT effective local extension authority, including the
/// journal overlay and per-tool parameter/descriptor pins, without reading
/// bearer credentials or contacting a remote MCP server. Only a hash of each
/// server's canonical configuration is retained with the approved tool names.
pub fn workstation_extension_authority(settings:&Path)->Result<Value,RuntimeError>{
    let registry=crate::extensions::read(settings)?;
    let overview=registry.servers(None)?;
    let mut hashes=std::collections::BTreeMap::<String,String>::new();
    let entries=overview.get("servers").and_then(Value::as_array)
        .ok_or("Effective extension server overview unavailable")?;
    for item in entries {
        let name=item.get("id").and_then(Value::as_str)
            .ok_or("Invalid effective extension server identifier")?;
        let sha=registry.server_sha256(name)?
            .ok_or("Effective extension server disappeared")?;
        hashes.insert(name.to_owned(),sha);
    }
    // No secrets, no endpoints or token values in the OAuth scope marker.
    Ok(json!({
        "schema":1,
        "approved_tools":registry.list(),
        "server_controls":overview,
        "server_configuration_sha256":hashes,
    }))
}

fn registry_matches_authority(
    registry:&agent_bridge_extensions::Registry,
    expected:&Value,
)->Result<bool,RuntimeError>{
    let overview=registry.servers(None)?;
    let entries=overview.get("servers").and_then(Value::as_array)
        .ok_or("Invalid effective extension overview")?;
    let mut hashes=std::collections::BTreeMap::<String,String>::new();
    for entry in entries {
        let id=entry.get("id").and_then(Value::as_str)
            .ok_or("Invalid extension server name")?;
        hashes.insert(id.to_owned(),registry.server_sha256(id)?
            .ok_or("Extension server changed")?);
    }
    Ok(&json!({
        "schema":1,
        "approved_tools":registry.list(),
        "server_controls":overview,
        "server_configuration_sha256":hashes,
    }) == expected)
}

#[derive(Clone, Copy)]
struct DesktopSurface {
    web_read_only: bool,
    task_rooms: bool,
    settings_tools: bool,
    terminal_tool: bool,
    processes: bool,
}

/// Reuse the *same* DesktopFiles, Task Room, skill, extension and terminal
/// implementations for stdio and separately authenticated Web workstation
/// gateways. Only caller-local choices select capability families. In Web
/// read-only mode, always enforce the pre-read private-path filter.
fn attach_desktop_surface(
    work: &Workspace,
    database: Option<&Arc<Mutex<CoreDatabase>>>,
    database_path: &Path,
    settings: Option<&Path>,
    selection: DesktopSurface,
    catalog: &mut Vec<ToolDefinition>,
    handlers: &mut ToolMapHandler,
    supervisors: &mut Vec<crate::terminal::SessionSupervisor>,
    extension_authority: Option<&Value>,
    live_profile: Option<&ProfileControl>,
) -> Result<(), RuntimeError> {
    if selection.processes && (!work.profile.permits_processes() || !selection.terminal_tool) {
        return Err("Process tools require an explicitly selected full-control workstation".into());
    }
    if selection.web_read_only
        && (work.write_files || selection.task_rooms || selection.settings_tools
            || selection.terminal_tool || selection.processes)
    {
        return Err("Web project-read permissions cannot be expanded".into());
    }
    if (selection.settings_tools || selection.terminal_tool) && settings.is_none() {
        return Err("Operator settings must be supplied explicitly for private tool families".into());
    }
    if selection.task_rooms && (!work.write_files || database.is_none()) {
        return Err("Task Rooms need locally authorized workspace write and the existing Core database".into());
    }

    let config = if selection.web_read_only {
        DesktopConfig::new(&work.root).with_web_project_read_policy()
    } else {
        let config = DesktopConfig::new(&work.root).with_session_profile(work.profile);
        if work.write_files { config.allow_workspace_write() } else { config }
    };
    let files = Arc::new(DesktopFiles::open(config)
        .map_err(|error| io::Error::other(error.message))?);

    if selection.task_rooms {
        let task_room_root = work.root.clone();
        let task_room_binding = task_room_workspace_binding(&task_room_root)?;
        let rooms = Arc::clone(database.ok_or("Task Room Core database unavailable")?);
        rooms.lock().map_err(|_| io::Error::other("Core unavailable"))
            .and_then(|mut db| agent_bridge_missions::task_room::init_schema(db.connection_mut())
                .map_err(|error| io::Error::other(error.message)))?;
        catalog.push(ToolDefinition::new("desktop_task_manage",
            Some("Manage locally authorized, project-bound persistent Task Rooms.".into()),
            serde_json::from_str(include_str!("../../../contracts/task-room-v1.json"))?));
        handlers.register("desktop_task_manage", move |args| {
            let current_binding = task_room_workspace_binding(&task_room_root)
                .map_err(|_| ToolDispatchError::internal("Task Room project identity unavailable"))?;
            if current_binding != task_room_binding {
                return Ok(ToolCallResult::tool_error(
                    "SECURITY_DENIED: Task Room project identity changed",
                ));
            }
            let mut db = rooms.lock()
                .map_err(|_| ToolDispatchError::internal("Core unavailable"))?;
            Ok(match agent_bridge_missions::task_room::dispatch_scoped(
                db.connection_mut(), &Value::Object(args), &current_binding,
            ) {
                Ok(value) => ToolCallResult::text(value.to_string()),
                Err(error) => ToolCallResult::tool_error(format!("{}: {}",error.code,error.message)),
            })
        });
    }

    if selection.settings_tools {
        struct CliRemoteSkillProvider;
        impl agent_bridge_desktop::skills::ApprovedRemoteProvider for CliRemoteSkillProvider {
            fn fetch_zip_bytes(
                &self,
                url: &str,
                max_bytes: usize,
            ) -> Result<Vec<u8>, agent_bridge_desktop::skills::SkillError> {
                agent_bridge_extensions::fetch_https_bytes(url, max_bytes).map_err(|e| {
                    agent_bridge_desktop::skills::SkillError::new(
                        agent_bridge_desktop::skills::SkillErrorCode::ActionUnavailable,
                        e.to_string(),
                    )
                })
            }
            fn extract_zip_entries(
                &self,
                zip_bytes: &[u8],
                limits: &agent_bridge_desktop::skills::PackageLimits,
            ) -> Result<
                Vec<agent_bridge_desktop::skills::RawPackageFile>,
                agent_bridge_desktop::skills::SkillError,
            > {
                agent_bridge_desktop::skills::decode_zip_bytes(zip_bytes, limits)
            }
        }

        let settings = settings.ok_or("Private settings directory not selected")?;
        let directory = agent_bridge_lifecycle::operator_skill_directory(settings)?;
        let mut skill_config = agent_bridge_desktop::skills::SkillManagerConfig::for_operator("local");
        if matches!(work.profile, DesktopProfile::FullControl | DesktopProfile::FullyUnlocked) {
            if let Ok(raw_origins) = std::env::var("AGENT_BRIDGE_SKILL_ALLOWED_HTTPS_ORIGINS") {
                let origins: Vec<String> = raw_origins
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
                if !origins.is_empty() {
                    skill_config.remote_policy.full_unlock_enabled = true;
                    skill_config.remote_policy.allowed_https_origins = origins;
                }
            }
        }
        let manager = files.documentary_skills_with_policy(
            &directory,
            skill_config.remote_policy,
            Some(Box::new(CliRemoteSkillProvider)),
        )?;
        let writable = work.write_files;
        catalog.push(ToolDefinition::new("desktop_skill_manage",
            Some("Manage locally selected versioned documentary skills.".into()),
            agent_bridge_desktop::skills::input_schema()));
        handlers.register("desktop_skill_manage", move |args| {
            if !writable && !matches!(
                args.get("action").and_then(Value::as_str),
                Some("list" | "get" | "read" | "validate")
            ) {
                return Ok(ToolCallResult::tool_error(
                    "WRITE_ACCESS_REQUIRED: this skill action changes the private store",
                ));
            }
            Ok(match manager.dispatch(&Value::Object(args)) {
                Ok(value) => {
                    let text = value.to_string();
                    if text.len() > 450 * 1024 {
                        ToolCallResult::tool_error(
                            "RESULT_TOO_LARGE: select one skill, revision or smaller resource",
                        )
                    } else { ToolCallResult::text(text) }
                }
                Err(error) => ToolCallResult::tool_error(error.to_string()),
            })
        });
    }

    // Never invent a tool from a published JSON contract. DesktopFiles is
    // the authority for the implemented and profile-permitted tool catalog.
    for tool in files.tool_catalog() {
        let owner = Arc::clone(&files);
        let name = tool.name;
        handlers.register(name, move |args| {
            let response = owner.dispatch(name, &Value::Object(args));
            if selection.web_read_only && response.get("isError").and_then(Value::as_bool)==Some(true) {
                return Ok(ToolCallResult::tool_error("PROJECT_READ_REFUSED"));
            }
            serde_json::from_value(response)
                .map_err(|_| ToolDispatchError::internal("Invalid workstation tool response"))
        });
        catalog.push(ToolDefinition::new(name,Some(tool.description.to_owned()),tool.input_schema));
    }
    if selection.web_read_only
        && catalog.iter().filter(|tool| tool.name.starts_with("desktop_")).count() != 4
    {
        return Err("Web read-only DesktopFiles catalogue must contain exactly four tools".into());
    }

    if selection.settings_tools {
        let directory=settings.ok_or("Private settings directory not selected")?;
        crate::extensions::attach(directory,catalog,handlers)?;
        if let Some(expected)=extension_authority {
            // This overrides the only effectful extension dispatch with a
            // grant-bound one. It reads ONE effective Registry, compares
            // its complete approved authority and executes through that SAME
            // instance, eliminating a read-then-reload authorization race.
            let bound=expected.clone();
            let local_settings=directory.to_owned();
            handlers.register("desktop_mcp_tool_call",move |args| {
                let Some(name)=args.get("name").and_then(Value::as_str) else {
                    return Ok(ToolCallResult::tool_error("An individually approved extension name is required"));
                };
                if name.len()>193 || args.keys().any(|key|key!="name"&&key!="arguments") {
                    return Ok(ToolCallResult::tool_error("Unsupported extension call arguments"));
                }
                let empty=serde_json::Map::new();
                let params=match args.get("arguments") {
                    None=>&empty,
                    Some(Value::Object(value))=>value,
                    _=>return Ok(ToolCallResult::tool_error("Extension arguments must be an object")),
                };
                let Ok(registry)=crate::extensions::read(&local_settings) else {
                    return Ok(ToolCallResult::tool_error("EXTENSION_AUTHORITY_UNAVAILABLE"));
                };
                if !registry_matches_authority(&registry,&bound).unwrap_or(false) {
                    return Ok(ToolCallResult::tool_error("EXTENSION_AUTHORITY_CHANGED: new local OAuth authorization required"));
                }
                Ok(match registry.call(name,params) {
                    Ok(value)=>{
                        let mut output=ToolCallResult::text(value.to_string());
                        output.is_error=value.get("isError").and_then(Value::as_bool).unwrap_or(false);
                        output
                    },
                    Err(_)=>ToolCallResult::tool_error("EXTENSION_CALL_REFUSED_OR_UNCERTAIN"),
                })
            });
        }
    }
    if selection.terminal_tool {
        let settings = settings.ok_or("Private settings directory not selected")?;
        let direct = selection.processes && work.profile == DesktopProfile::FullyUnlocked
            && live_profile.is_some();
        let supervisor = if direct {
            Some(crate::terminal::attach_unrestricted(
                settings, &work.root, database_path, catalog, handlers,
                live_profile.ok_or("Live workstation profile unavailable")?.shared(),
            )?)
        } else {
            crate::terminal::attach_with_workspace(
                settings,&work.root,database_path,catalog,handlers,selection.processes,Arc::clone(&files),
            )?
        };
        if let Some(supervisor) = supervisor {
            if let Some(profile) = live_profile {
                profile.register_revoker(
                    if direct { DesktopProfile::FullyUnlocked } else { DesktopProfile::FullControl },
                    supervisor.revoker(),
                )?;
            }
            supervisors.push(supervisor);
        }
    }
    Ok(())
}

/// Capabilities are approved by the LOCAL CLI, not accepted from MCP frames.
/// Read-only Web remains limited to four prefiltered file tools, plus the
/// separately approved exact window if the operator selected one locally.
#[derive(Clone, Copy)]
pub struct WebWorkstationCapabilities {
    pub profile: DesktopProfile,
    pub task_rooms: bool,
    pub settings_tools: bool,
    pub processes: bool,
}

/// Use this same root qualification before window consent and before opening
/// OAuth/SQLite state. The database is an exclusion boundary unless Task
/// Rooms were explicitly selected.
pub fn qualify_web_workstation_project(
    project: &Path,
    database_boundary: &Path,
    workstation_oauth_state: &Path,
    missions_oauth_state: &Path,
    settings_dir: &Path,
    lifecycle_dir: &Path,
) -> Result<PathBuf, RuntimeError> {
    let qualified = workspace_qualification::qualify(
        project,database_boundary,Some(workstation_oauth_state),
    )?;
    for excluded in [missions_oauth_state,settings_dir,lifecycle_dir] {
        let checked = workspace_qualification::qualify(
            project,database_boundary,Some(excluded),
        )?;
        if checked != qualified {
            return Err("Project selection changed during workstation qualification".into());
        }
    }
    Ok(qualified)
}

/// Authenticated workstation-only Web gateway: deliberately NO mission
/// handlers, no anonymous desktop paths, no inherited read-only OAuth grants.
pub(crate) fn workstation_router(
    project: &Path,
    database_boundary: &Path,
    workstation_oauth_state: &Path,
    missions_oauth_state: &Path,
    settings_dir: &Path,
    lifecycle_dir: &Path,
    permitted: WebWorkstationCapabilities,
    window_approval: Option<crate::window_inspection::LocalApproval>,
    docs_approval: Option<crate::browser_docs::LocalApproval>,
    learn_approval: Option<crate::browser_docs::learn::LocalLearnApproval>,
    #[cfg(any(windows, unix))] native_chrome_approval: Option<crate::browser_docs::interactive::LocalInteractiveApproval>,
    supervisors: &mut Vec<crate::terminal::SessionSupervisor>,
    extension_authority: Option<&Value>,
    active_profile: ProfileControl,
) -> Result<WorkstationRuntime, RuntimeError> {
    if active_profile.startup_profile() != permitted.profile {
        return Err("Workstation live profile does not match its startup ceiling".into());
    }
    let is_read_only = permitted.profile == DesktopProfile::ReadOnly;
    if is_read_only && (permitted.task_rooms || permitted.settings_tools || permitted.processes) {
        return Err("Read-only Web tokens cannot request write, settings or process tool families".into());
    }
    if permitted.processes && !permitted.profile.permits_processes() {
        return Err("Web process tools require local full-control or fully-unlocked".into());
    }
    // The three browser providers implement the same MCP tool names. Only
    // one can be selected locally for each gateway, but its project/origin
    // scope is independent of locally approved files, tasks, extensions,
    // processes and the exact-window consent. Never overwrite handlers.
    let mut browser_providers = usize::from(docs_approval.is_some())
        + usize::from(learn_approval.is_some());
    let read_only_browser = docs_approval.is_some() || learn_approval.is_some();
    #[cfg(any(windows, unix))]
    { browser_providers += usize::from(native_chrome_approval.is_some()); }
    if browser_providers > 1 {
        return Err("Select exactly one local browser provider per Web workstation".into());
    }
    // A locally selected HWND/process incarnation is independently verified
    // and sealed, including in full-control sessions. It must never be
    // invented or reauthorized by a remote MCP caller.
    let _ = window_approval.as_ref();
    let root = qualify_web_workstation_project(
        project,database_boundary,workstation_oauth_state,
        missions_oauth_state,settings_dir,lifecycle_dir,
    )?;
    let work = Workspace {
        root, write_files: !is_read_only, profile: permitted.profile,
    };
    let database = if permitted.task_rooms {
        Some(Arc::new(Mutex::new(CoreDatabase::open_existing(database_boundary)?)))
    } else { None };

    let mut catalog = Vec::new();
    let mut handlers = ToolMapHandler::new();
    attach_desktop_surface(
        &work,database.as_ref(),database_boundary,
        if permitted.settings_tools || permitted.processes {
            Some(settings_dir)
        } else { None },
        DesktopSurface {
            web_read_only:is_read_only,
            task_rooms:permitted.task_rooms,
            settings_tools:permitted.settings_tools,
            terminal_tool:permitted.processes,
            processes:permitted.processes,
        },
        &mut catalog,&mut handlers,supervisors,extension_authority,Some(&active_profile),
    )?;
    if let Some(approval)=window_approval {
        crate::window_inspection::attach(approval,&mut catalog,&mut handlers);
    }
    if let Some(approval)=docs_approval {
        crate::browser_docs::attach(approval,&mut catalog,&mut handlers);
    }
    if let Some(approval)=learn_approval {
        crate::browser_docs::learn::attach_public(approval,&mut catalog,&mut handlers);
    }
    #[cfg(any(windows, unix))]
    if let Some(approval)=native_chrome_approval {
        crate::browser_docs::interactive::attach_native(
            approval,&mut catalog,&mut handlers);
    }
    // Only tools with real attached handlers can be published. The client
    // cannot expand this catalog, and our OAuth scope marker seals the exact
    // published names + schemas before any bearer request is accepted.
    let count = catalog.len();
    let status_profile = active_profile.clone();
    handlers.register("agent_bridge_status", move |arguments| {
        if !arguments.is_empty() {
            return Err(ToolDispatchError::invalid_params("status takes no arguments"));
        }
        let profile = *status_profile.read()
            .map_err(|_| ToolDispatchError::internal("PROFILE_STATE_UNAVAILABLE"))?;
        Ok(ToolCallResult::text(json!({
            "ok":true,"version":env!("CARGO_PKG_VERSION"),
            "active_backend":"rust","audience":"workstation",
            "desktop_profile":profile,"vendor_tools":count,
            "startup_profile":permitted.profile,
            "process_tools_enabled":permitted.processes && if permitted.profile == DesktopProfile::FullyUnlocked {
                profile == DesktopProfile::FullyUnlocked
            } else { profile.permits_processes() },
            "project_commands_enabled":permitted.processes && profile.permits_processes(),
            "direct_processes_enabled":permitted.processes && profile == DesktopProfile::FullyUnlocked,
            "database_schema": if permitted.task_rooms {
                Some(agent_bridge_core::CURRENT_SCHEMA_VERSION)
            } else { None },
            "channel":"development","production":false
        }).to_string()))
    });
    catalog.push(ToolDefinition::new(
        "agent_bridge_status",Some("Report this locally approved Web workstation profile.".into()),
        json!({"type":"object","properties":{},"additionalProperties":false}),
    ));
    let handlers = guard_live_workstation(
        handlers, &catalog, &work.root, active_profile,
        permitted.profile == DesktopProfile::FullyUnlocked && permitted.processes,
        read_only_browser,
    )?;
    Ok(WorkstationRuntime {
        router: McpGateway::new(GatewayConfig::new("agent-bridge-workstation",
            env!("CARGO_PKG_VERSION")),catalog,handlers),
        database,
    })
}

const WORKSTATION_READ_TOOLS: &[&str] = &[
    "desktop_get_file_info", "desktop_list_directory", "desktop_read_file", "desktop_search",
];
const PROCESS_TOOLS: &[&str] = &[
    "desktop_start_process", "desktop_read_process", "desktop_interact_process", "desktop_terminate_process",
];

fn live_tool_allowed(profile: DesktopProfile, name: &str, arguments: &serde_json::Map<String, Value>, read_only_browser: bool) -> bool {
    if matches!(name, "agent_bridge_status" | "desktop_policy_status") {
        return true;
    }
    // These handlers exist only after the operator selected an exact window
    // or browser source. Preserve their bounded inspection and cleanup paths.
    if matches!(name, "desktop_ui_windows" | "desktop_ui_snapshot" | "desktop_browser_snapshot")
        || (name == "desktop_ui_action" && arguments.get("action").and_then(Value::as_str) == Some("wait"))
        || (name == "desktop_agent_desktop" && matches!(arguments.get("action").and_then(Value::as_str), Some("status" | "start" | "stop")))
        || (read_only_browser && matches!(name, "desktop_browser_session" | "desktop_browser_act"))
        || (name == "desktop_browser_session" && matches!(arguments.get("action").and_then(Value::as_str), Some("list" | "list_profiles" | "close")))
    {
        return true;
    }
    if profile == DesktopProfile::ReadOnly {
        return WORKSTATION_READ_TOOLS.contains(&name);
    }
    if PROCESS_TOOLS.contains(&name) || matches!(name,
        "agent_bridge_project_command" | "desktop_agent_desktop" | "desktop_ui_action")
    {
        return profile.permits_processes();
    }
    if name == "desktop_skill_manage" && arguments.contains_key("source_url") {
        return rank(profile) >= rank(DesktopProfile::FullControl);
    }
    true
}

fn guard_live_workstation(
    original: ToolMapHandler,
    catalog: &[ToolDefinition],
    root: &Path,
    profile: ProfileControl,
    direct_processes: bool,
    read_only_browser: bool,
) -> Result<ToolMapHandler, RuntimeError> {
    let original = Arc::new(original);
    let read_only = Arc::new(DesktopFiles::open(
        DesktopConfig::new(root).with_web_project_read_policy(),
    ).map_err(|error| io::Error::other(error.message))?);
    let mut guarded = ToolMapHandler::new();
    for tool in catalog {
        let name = tool.name.clone();
        let owner = Arc::clone(&original);
        let reader = Arc::clone(&read_only);
        let control = profile.clone();
        guarded.register(name.clone(), move |arguments| {
            // Direct process handlers synchronize admission with revocation themselves
            // and release the profile lock before waiting for asynchronous output.
            if name == "agent_bridge_status" || (direct_processes &&
                (PROCESS_TOOLS.contains(&name.as_str()) || name == "agent_bridge_project_command")) {
                return owner.call(&name, arguments);
            }
            let active = control.read()
                .map_err(|_| ToolDispatchError::internal("PROFILE_STATE_UNAVAILABLE"))?;
            if !live_tool_allowed(*active, &name, &arguments, read_only_browser) {
                return Ok(ToolCallResult::tool_error("PROFILE_DENIED: this tool is disabled by the active local mode"));
            }
            if *active == DesktopProfile::ReadOnly && WORKSTATION_READ_TOOLS.contains(&name.as_str()) {
                let response = reader.dispatch(&name, &Value::Object(arguments));
                if response.get("isError").and_then(Value::as_bool) == Some(true) {
                    return Ok(ToolCallResult::tool_error("PROJECT_READ_REFUSED"));
                }
                return serde_json::from_value(response)
                    .map_err(|_| ToolDispatchError::internal("PROJECT_READ_UNAVAILABLE"));
            }
            let mut result = owner.call(&name, arguments)?;
            if name == "desktop_policy_status" && !result.is_error {
                for content in &mut result.content {
                    if let ToolContent::Text { text } = content {
                        let mut policy: Value = serde_json::from_str(text)
                            .map_err(|_| ToolDispatchError::internal("Invalid policy response"))?;
                        policy["profile"] = json!(*active);
                        policy["startup_profile"] = json!(control.startup_profile());
                        if *active == DesktopProfile::ReadOnly {
                            policy["file_access"] = json!("read-only");
                            policy["tools"] = json!(WORKSTATION_READ_TOOLS);
                            policy["limits"]["listing_depth"] = json!(1);
                            policy["unsupported"] = json!(["file_mutation", "artifacts", "hidden_or_sensitive_paths", "content_search"]);
                        }
                        *text = policy.to_string();
                    }
                }
            }
            Ok(result)
        });
    }
    Ok(guarded)
}

fn open_qualified(
    database_path: &Path,
    workspace: Option<Workspace>,
    settings: Option<&Path>,
    window_approval: Option<crate::window_inspection::LocalApproval>,
    docs_approval: Option<crate::browser_docs::LocalApproval>,
    learn_approval: Option<crate::browser_docs::learn::LocalLearnApproval>,
    #[cfg(any(windows, unix))] native_chrome_approval: Option<crate::browser_docs::interactive::LocalInteractiveApproval>,
    // Owned by serve_stdio. Drop is a safe fallback on early failures.
    supervisors: &mut Vec<crate::terminal::SessionSupervisor>,
) -> Result<Router, RuntimeError> {
    // Every supplementary workstation family is opt-in on the LOCAL process
    // command line. Browser readers are distinct source-confined providers;
    // their three handler names cannot be registered simultaneously.
    if window_approval.is_some() && workspace.is_none() {
        return Err("An exact locally approved window requires a selected project".into());
    }
    let mut browsers=usize::from(docs_approval.is_some())+
        usize::from(learn_approval.is_some());
    #[cfg(any(windows, unix))]
    { browsers+=usize::from(native_chrome_approval.is_some()); }
    if browsers>1 {
        return Err("Exactly one local Chrome browser provider may be selected".into());
    }
    if browsers>0 && workspace.is_none() {
        return Err("Browser provider requires the qualified local workspace".into());
    }
    // A qualified operator workspace is required before any SQLite handle.
    let database = Arc::new(Mutex::new(CoreDatabase::open_existing(database_path)?));
    let mut catalog: Vec<ToolDefinition> =
        serde_json::from_str(include_str!("../../../contracts/mission-tools-v1.json"))?;
    let mut handlers = ToolMapHandler::new();
    for tool in &catalog {
        if tool.name == "agent_bridge_status" {
            continue;
        }
        let connection = Arc::clone(&database);
        let name = tool.name.clone();
        handlers.register(name.clone(), move |args| {
            let mut db = connection.lock().map_err(|_| ToolDispatchError::internal("Core unavailable"))?;
            let result = agent_bridge_missions::dispatch_tool(db.connection_mut(), &name, &Value::Object(args));
            match result {
                Ok(value) => Ok(ToolCallResult::text(value.to_string())),
                Err(error) => Ok(ToolCallResult::tool_error(format!("CORE_{}: {}", error.code, error.message))),
            }
        });
    }
    let mission_count = catalog.len();
    if let Some(work) = &workspace {
        attach_desktop_surface(
            work,Some(&database),database_path,settings,
            DesktopSurface {
                web_read_only:false,
                task_rooms:work.write_files,
                settings_tools:settings.is_some(),
                terminal_tool:settings.is_some(),
                processes:work.profile.permits_processes(),
            },
            &mut catalog,&mut handlers,supervisors,None,None,
        )?;
    } else if let Some(settings) = settings {
        // Preserve the existing mission-only stdio + explicitly selected
        // operator settings behavior; never enabled on the Web mission route.
        crate::extensions::attach(settings,&mut catalog,&mut handlers)?;
    }
    if let Some(approval) = window_approval {
        // No HTTP/Web route accepts this unforgeable, locally granted value.
        crate::window_inspection::attach(approval, &mut catalog, &mut handlers);
    }
    if let Some(approval) = docs_approval {
        // Only the exact LOCAL CLI-approved page list can be reached.
        crate::browser_docs::attach(approval, &mut catalog, &mut handlers);
    }
    if let Some(approval) = learn_approval {
        crate::browser_docs::learn::attach_public(approval, &mut catalog, &mut handlers);
    }
    #[cfg(any(windows, unix))]
    if let Some(approval) = native_chrome_approval {
        crate::browser_docs::interactive::attach_native(approval, &mut catalog, &mut handlers);
    }
    let desktop_count = catalog.len() - mission_count;
    let desktop_profile = workspace.as_ref().map(|work| work.profile);
    let version = env!("CARGO_PKG_VERSION");
    handlers.register("agent_bridge_status", move |arguments| {
        if !arguments.is_empty() {
            return Err(ToolDispatchError::invalid_params("status takes no arguments"));
        }
        Ok(ToolCallResult::text(json!({
            "ok": true, "version": version, "active_backend": "rust",
            "database_schema": agent_bridge_core::CURRENT_SCHEMA_VERSION,
            "vendor_contract": null, "vendor_tools": desktop_count, "desktop_profile": desktop_profile,
            "channel": "development", "production": false
        }).to_string()))
    });
    Ok(McpGateway::new(GatewayConfig::new("agent-bridge", version), catalog, handlers))
}

pub fn serve_stdio(
    database_path: &Path,
    workspace: Option<(&Path, bool)>,
    settings: Option<&Path>,
    local_window: Option<crate::window_inspection::DedicatedWindow>,
    local_doc_pages: Vec<String>,
    local_learn_url: Option<String>,
    native_chrome_pages: Vec<String>,
    native_chrome_origins: Vec<String>,
) -> Result<(), RuntimeError> {
    #[cfg(not(any(windows, unix)))]
    if !native_chrome_pages.is_empty() || !native_chrome_origins.is_empty() {
        return Err("Native Chrome interactive provider is unavailable on this platform".into());
    }
    if !native_chrome_origins.is_empty() && native_chrome_pages.is_empty() {
        return Err("An origin cannot authorize Chrome without a local project page".into());
    }
    let providers = usize::from(!local_doc_pages.is_empty())
        + usize::from(local_learn_url.is_some())
        + usize::from(!native_chrome_pages.is_empty());
    if providers > 1 || (providers > 0 && workspace.is_none()) {
        return Err("Select one local browser provider and a qualified project".into());
    }
    if local_window.is_some() && workspace.is_none() {
        return Err("Exact selected window requires a local project".into());
    }
    // Qualify and pin the exact operator-selected workspace BEFORE consent,
    // SQLite opening or any MCP registration. stdout stays reserved for MCP.
    #[cfg(windows)]
    let _session_directory = workspace
        .map(|(root, _)| agent_bridge_lifecycle::workspace_access::PinnedProjectDirectory::open(root))
        .transpose()?;
    let qualified = qualified_workspace(database_path, workspace, settings)?;
    if let Some(work) = &qualified {
        eprintln!(
            "agent-bridge: selected project workspace [{}] : {}",
            if work.write_files { "write enabled" } else { "read-only" },
            work.root.display()
        );
    }
    let window_approval = if let Some(selection) = local_window {
        // Native local Yes/No dialog; No is default. No MCP frame can invoke it.
        Some(crate::window_inspection::confirm_local_selection(selection)?)
    } else {
        None
    };
    let docs_approval = if local_doc_pages.is_empty() {
        None
    } else {
        let approved_workspace = qualified.as_ref()
            .ok_or("Local Chrome documents require a physically qualified workspace")?;
        // The operator chose these exact pages on the local command line.
        // No confirmation reads MCP stdin and no MCP request can extend them.
        Some(crate::browser_docs::approve_from_local_cli(
            crate::browser_docs::LocalDocsRequest {
                workspace: approved_workspace.root.clone(),
                pages: local_doc_pages,
            },
        )?)
    };
    let learn_approval = if let Some(home_url) = local_learn_url {
        let work = qualified.as_ref()
            .ok_or("Microsoft Learn requires a physically qualified workspace")?;
        // Requalify the already locally selected project as part of its
        // session admission. The URL itself is selected locally, not by MCP.
        let _ = &work.root;
        Some(crate::browser_docs::learn::approve_local(
            crate::browser_docs::learn::LocalLearnSelection { home_url },
        )?)
    } else { None };
    #[cfg(any(windows, unix))]
    let native_chrome_approval = if native_chrome_pages.is_empty() {
        None
    } else {
        let project = qualified.as_ref()
            .ok_or("Native Chrome requires the physically selected workspace")?;
        let mut approved = crate::browser_docs::interactive::approve_local(
            crate::browser_docs::interactive::LocalInteractiveSelection{
                workspace:project.root.clone(),
                pages:native_chrome_pages,
                allowed_origins:native_chrome_origins,
            },
        )?;
        if let Some(settings_dir) = settings {
            approved = approved.with_profile_root(settings_dir.join("mcp-browser-profiles"))?;
        }
        Some(approved)
    };
    let mut supervisors = Vec::new();
    let gateway = open_qualified(
        database_path, qualified, settings, window_approval, docs_approval,
        learn_approval,
        #[cfg(any(windows, unix))] native_chrome_approval,
        &mut supervisors,
    )?;
    let served = agent_bridge_gateway::stdio::serve(
        io::stdin().lock(), io::stdout().lock(), |frame| gateway.handle_str(frame)
    );
    // stdio EOF or an I/O error must not allow any owned child or watchdog to
    // survive the stream. Join even when the client was idle at disconnect.
    drop(gateway);
    let mut shutdown_failure = None;
    for supervisor in &mut supervisors {
        if let Err(error) = supervisor.shutdown() {
            shutdown_failure = Some(error);
        }
    }
    if let Some(error) = shutdown_failure { return Err(error.into()); }
    served?;
    Ok(())
}

pub fn check_port(port: u16) -> Result<(), RuntimeError> {
    if matches!(port, 0..=1024 | 8765 | 8766 | 18865) {
        return Err("Choose an unprivileged local gateway port outside reserved product endpoints".into());
    }
    Ok(())
}

pub fn serve_http(database: &Path, port: u16) -> Result<(), RuntimeError> {
    check_port(port)?;
    let router = missions(database)?;
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async move {
        let listener = agent_bridge_http::bind_loopback(port).await?;
        agent_bridge_http::serve(
            listener,
            agent_bridge_http::HttpServerConfig::default(),
            move |frame| router.handle_str(frame),
            agent_bridge_http::HealthStatus::ok,
            async { let _ = tokio::signal::ctrl_c().await; },
        ).await
    })?;
    Ok(())
}