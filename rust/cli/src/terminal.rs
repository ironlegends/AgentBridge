mod metadata_child;
mod operator_confirmation;
mod sessions;
mod unrestricted;

pub(crate) enum SessionSupervisor {
    Restricted(sessions::SessionSupervisor),
    Unrestricted(unrestricted::SessionSupervisor),
}

impl SessionSupervisor {
    pub(crate) fn minimum_profile(&self) -> agent_bridge_desktop::DesktopProfile {
        use agent_bridge_desktop::DesktopProfile;
        match self {
            Self::Restricted(_) => DesktopProfile::FullControl,
            Self::Unrestricted(_) => DesktopProfile::FullyUnlocked,
        }
    }

    pub(crate) fn shutdown(&mut self) -> std::io::Result<()> {
        match self {
            Self::Restricted(supervisor) => supervisor.shutdown(),
            Self::Unrestricted(supervisor) => supervisor.shutdown(),
        }
    }

    pub(crate) fn revoker(&self) -> std::sync::Arc<
        dyn Fn() -> Result<(), RuntimeError> + Send + Sync,
    > {
        match self {
            Self::Restricted(supervisor) => supervisor.revoker(),
            Self::Unrestricted(supervisor) => supervisor.revoker(),
        }
    }
}

use crate::runtime::RuntimeError;
use crate::command_catalogue::CommandCatalogueSnapshot;

// The private child is reachable only through a literal CLI subcommand. It
// exposes no MCP router and never accesses operator settings or a database.
pub(crate) fn serve_metadata_child(root: &Path, binding: &str) -> Result<(), RuntimeError> {
    metadata_child::serve(root, binding)
}

// Stable physical identity of the locally qualified project directory.
// Windows reuses the pinned-file-ID project SID. Unix transfers the actual
// DesktopFiles root over a private SCM_RIGHTS channel instead of reopening it.
#[cfg(not(unix))]
fn metadata_project_binding(root: &Path) -> Result<String, RuntimeError> {
    #[cfg(windows)]
    {
        let sid = agent_bridge_lifecycle::workspace_access::project_read_sid(root)?;
        Ok(format!("agent-bridge.metadata.windows.v1:{sid}"))
    }
    #[cfg(not(any(windows, unix)))]
    { let _ = root; Err("Metadata diagnostics are unsupported on this platform".into()) }
}
use agent_bridge_commands::{
    CommandDecisionEngine, CommandRequest, EngineLimits, EnvironmentVerifier, ExecutionOutcome,
    FsEnvironmentVerifier, OperatorPolicy, RequesterContext, SubmissionOutcome,
};
use agent_bridge_gateway::{ToolCallResult, ToolDefinition, ToolHandler, ToolMapHandler};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::io::Read;

fn capture(mut stream: impl Read) -> std::io::Result<(String, bool)> {
    const LIMIT: usize = 64 * 1024;
    let mut text = Vec::new();
    let mut block = [0u8; 4096];
    let mut truncated = false;
    loop {
        let count = stream.read(&mut block)?;
        if count == 0 { break; }
        let keep = count.min(LIMIT - text.len());
        text.extend_from_slice(&block[..keep]);
        truncated |= keep < count;
    }
    Ok((String::from_utf8_lossy(&text).into_owned(), truncated))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    version: u8,
    programs: BTreeMap<String, Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    executable: PathBuf,
    sha256: agent_bridge_commands::Sha256Digest,
    // An explicit legacy false disables the entry. A named, pinned entry
    // without this field follows the session's locally selected profile.
    #[serde(default = "enabled_by_profile")]
    preapproved: bool,
    // ONLY a project-program entry may pin argv, CWD and a narrow stdin
    // protocol. The fixed toolchain diagnostics ignore all these fields and
    // retain their existing exact-argument admission path.
    #[serde(default)]
    arguments: Option<Vec<String>>,
    #[serde(default)]
    cwd: Option<PathBuf>,
    #[serde(default)]
    stdin_protocol: Option<String>,
}

fn enabled_by_profile() -> bool { true }

#[cfg(windows)]
fn private_files(database: &Path, settings: &Path) -> std::io::Result<Vec<PathBuf>> {
    let db_parent = database.parent().ok_or_else(|| std::io::Error::other("database directory missing"))?;
    let mut files = vec![settings.to_owned(), settings.join("extensions.json")];
    if db_parent != settings { files.push(db_parent.to_owned()); }
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = database.as_os_str().to_os_string();
        name.push(suffix);
        let path = PathBuf::from(name);
        match path.symlink_metadata() {
            Ok(_) => files.push(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(files)
}

fn configured_command(
    settings: &Path,
    root: &Path,
    action: &str,
    image: &str,
    enforce_local_denial: bool,
) -> Result<Entry, RuntimeError> {
    configured_command_with_snapshot(settings,root,action,image,enforce_local_denial,None)
}

fn configured_command_with_snapshot(
    settings:&Path,root:&Path,action:&str,image:&str,enforce_local_denial:bool,
    commands:Option<&CommandCatalogueSnapshot>,
)->Result<Entry,RuntimeError> {
    let bytes=match commands {
        Some(commands)=>std::borrow::Cow::Borrowed(commands.bytes()?),
        None=>std::borrow::Cow::Owned(agent_bridge_lifecycle::read_operator_setting(settings,"commands.json")?),
    };
    let mut catalog: Catalog = serde_json::from_slice(&bytes)?;
    if catalog.version != 1 { return Err("unsupported local command catalog".into()); }
    let entry = catalog.programs.remove(action)
        .ok_or("command is not configured on this workstation")?;
    if entry.arguments.is_some() || entry.cwd.is_some() || entry.stdin_protocol.is_some() {
        return Err("Fixed diagnostic cannot accept project-program arguments or stdin rules".into());
    }
    if enforce_local_denial && !entry.preapproved {
        return Err("PROCESS_DENIED_BY_LOCAL_CATALOG: preapproved:false explicitly forbids this diagnostic".into());
    }
    let extension = std::env::consts::EXE_SUFFIX;
    let filename = entry.executable.file_name().and_then(|v|v.to_str()).ok_or("invalid executable name")?;
    if !filename.eq_ignore_ascii_case(&format!("{image}{extension}")) || !entry.executable.is_absolute() {
        return Err("unexpected executable for the configured diagnostic".into());
    }
    let verifier = FsEnvironmentVerifier;
    let pin = verifier.verify_executable(&entry.executable)?;
    let canonical_root = root.canonicalize()?;
    if pin.sha256 != entry.sha256 || pin.canonical_path.starts_with(&canonical_root) {
        return Err("toolchain executable must match the local pin and be outside the agent workspace".into());
    }
    Ok(entry)
}

#[cfg(windows)]
fn prepare_revision(entry: &Entry, settings: &Path, root: &Path, database: &Path)
    -> Result<agent_bridge_lifecycle::git_revision_windows::PreparedGitRevision, RuntimeError> {
    use agent_bridge_lifecycle::git_revision_windows::{prepare_git_revision, GitRevisionSpec};
    let extra = private_files(database, settings)?;
    let paths: Vec<&Path> = extra.iter().map(PathBuf::as_path).collect();
    Ok(prepare_git_revision(&GitRevisionSpec {
        git_executable: &entry.executable,
        expected_sha256: *entry.sha256.as_bytes(),
        workspace: root,
        database_file: database,
        operator_catalog_file: &settings.join("commands.json"),
        additional_private_paths: &paths,
        deadline: std::time::Duration::from_secs(10),
    })?)
}

#[cfg(windows)]
fn prepare_native_head(settings: &Path, root: &Path, database: &Path)
    -> Result<agent_bridge_lifecycle::git_revision_windows::PreparedNativeRevision, RuntimeError>
{
    use agent_bridge_lifecycle::git_revision_windows::{prepare_native_revision, NativeRevisionSpec};
    let additional = private_files(database, settings)?;
    let extra_paths: Vec<&Path> = additional.iter().map(PathBuf::as_path).collect();
    Ok(prepare_native_revision(&NativeRevisionSpec {
        workspace: root,
        database_file: database,
        operator_catalog_file: &settings.join("commands.json"),
        additional_private_paths: &extra_paths,
    })?)
}

#[cfg(windows)]
pub(super) fn inspect_revision(settings: &Path, root: &Path, database: &Path) -> Result<Value, RuntimeError> {
    let entry = configured_command(settings, root, "git-revision", "git", false)?;
    prepare_revision(&entry, settings, root, database)?;
    Ok(json!({"workspace":root, "image":entry.executable, "access_check":"passed", "process_started":false}))
}

/// These project commands have a fixed argument vector and bounded output.
/// A configurable command string can never be substituted for their argv.
fn run(settings: &Path, root: &Path, database: &Path, action: &str) -> Result<Value, RuntimeError> {
    run_with_snapshot(settings,root,database,action,None,false)
}

fn run_with_snapshot(settings:&Path,root:&Path,database:&Path,action:&str,
    commands:Option<&CommandCatalogueSnapshot>, fully_unlocked:bool)->Result<Value,RuntimeError> {
    let (image, args): (&str, &[&str]) = match action {
        "git-version" => ("git", &["--version"]),
        "rust-version" => ("rustc", &["--version"]),
        "git-branch" => ("git", &["--no-pager", "symbolic-ref", "--short", "HEAD"]),
        "git-revision" => ("git", &["--no-pager", "rev-parse", "--verify", "HEAD"]),
        "git-root" => ("git", &["--no-pager", "rev-parse", "--show-toplevel"]),
        _ => return Err("the general workspace execution host is not enabled in this build".into()),
    };
    let entry = configured_command_with_snapshot(settings, root, action, image, true,commands)?;
    #[cfg(windows)]
    let native_revision = if action == "git-revision" && !fully_unlocked {
        // Lower profiles retain the project-specific restricted reader.
        // A failed restricted launch must never fall back to the OS user.
        Some(prepare_native_head(settings, root, database)?)
    } else { None };
    #[cfg(not(windows))]
    let _ = (database, fully_unlocked);
    let verifier = FsEnvironmentVerifier;
    let canonical_root = root.canonicalize()?;
    let args: Vec<String> = args.iter().map(|v| v.to_string()).collect();
    let limits = EngineLimits::default();
    // Create only an exact one-shot predefined rule for this invocation:
    // executable SHA-256, canonical working directory and argv are pinned.
    let policy = OperatorPolicy::builder(root)
        .add_predefined(action, &entry.executable, entry.sha256, args.clone(), root);
    let (client, _owner, execution) = CommandDecisionEngine::with_fs_verifier(
        policy.build(&verifier, &limits)?, limits,
    ).split();
    let who = RequesterContext::new("local-stdio")?;
    let decision = client.submit(&who, CommandRequest::new(&entry.executable, args, root))?;
    let id = match decision {
        SubmissionOutcome::PredefinedApproved { request_id, .. } => request_id,
        SubmissionOutcome::PendingLocalConfirmation { .. } =>
            return Err("PROCESS_NOT_PREDEFINED: local policy did not grant this exact diagnostic; no interactive or automatic approval is permitted".into()),
    };
    let permit = execution.consume(&id)?;
    let verified = permit.command();
    // Keep the pinned Windows image open without write or delete sharing
    // until the owned child has exited. Confirm the image after taking that
    // handle; a replacement that raced the authorization must not start.
    #[cfg(windows)]
    let _image_guard = {
        use std::os::windows::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new().read(true).share_mode(1)
            .open(&verified.executable.canonical_path)?;
        if verifier.verify_executable(&verified.executable.canonical_path)? != verified.executable {
            return Err("toolchain image changed after authorization".into());
        }
        file
    };
    #[cfg(windows)]
    if let Some(operation) = native_revision {
        // A successful native resolution returns only a validated OID, not a
        // Git process receipt. It uses the one-use policy permit already
        // consumed above and retains this invocation's full-control gate.
        use agent_bridge_lifecycle::git_revision_windows::GitRevisionError;
        return match operation.resolve() {
            Ok(result) => {
                execution.finish(permit, ExecutionOutcome::Completed {
                    exit_code:0, summary:None,
                })?;
                Ok(json!({
                    "exit_code":0,
                    "stdout":format!("{}\n",result.oid),
                    "stderr":"",
                    "stdout_truncated":false,
                    "stderr_truncated":false,
                    "provenance":result.provenance,
                    "git_process_started":false
                }))
            }
            Err(error) => {
                let outcome = match &error {
                    GitRevisionError::Refused(_) | GitRevisionError::Os {..} =>
                        ExecutionOutcome::FailedBeforeStart {
                            reason_code:"native_revision_refused".into()
                        },
                    GitRevisionError::Uncertain(_) | GitRevisionError::Deadline =>
                        ExecutionOutcome::Uncertain {
                            reason_code:"native_revision_uncertain".into()
                        },
                };
                execution.finish(permit,outcome)?;
                Err(error.into())
            }
        };
    }
    #[cfg(windows)]
    if fully_unlocked && action == "git-revision" {
        // Local active Fully Unlocked already grants current-user execution.
        // Keep the exact command pin and one-use permit, hidden owned Job,
        // bounded output and cleanup; this is not a restricted-token fallback.
        let result = unrestricted::run_pinned_git_revision(
            &verified.executable.canonical_path, &verified.args, &canonical_root,
        );
        return match result {
            Ok(output) => {
                let exit_code = output["exit_code"].as_i64().ok_or("missing diagnostic exit code")? as i32;
                execution.finish(permit, ExecutionOutcome::Completed {exit_code,summary:None})?;
                Ok(output)
            }
            Err(error) => {
                execution.finish(permit, ExecutionOutcome::Uncertain {
                    reason_code:"owned_diagnostic_unavailable".into(),
                })?;
                Err(error)
            }
        };
    }
    let mut cmd = Command::new(&verified.executable.canonical_path);
    cmd.args(&verified.args).stdin(Stdio::null())
        .stdout(Stdio::piped()).stderr(Stdio::piped()).env_clear();
    if image == "git" {
        cmd.env("GIT_CONFIG_NOSYSTEM", "1").env("GIT_CONFIG_GLOBAL", if cfg!(windows) { "NUL" } else { "/dev/null" })
            .env("GIT_NO_LAZY_FETCH", "1").env("GIT_TERMINAL_PROMPT", "0").env("GIT_NO_OPTIONAL_LOCKS", "1")
            .env("GIT_CEILING_DIRECTORIES", canonical_root.parent().unwrap_or(&canonical_root));
    }
    #[cfg(windows)]
    {
        use agent_bridge_lifecycle::git_revision_windows::repository_directories;
        use std::os::windows::process::CommandExt;
        let image_dir = verified.executable.canonical_path.parent().ok_or("missing toolchain directory")?;
        cmd.current_dir(image_dir).creation_flags(0x08000000);
        if matches!(action, "git-branch" | "git-root") {
            let (git_dir, tree) = repository_directories(root)?;
            cmd.env("GIT_DIR", git_dir);
            if let Some(tree) = tree { cmd.env("GIT_WORK_TREE", tree); }
        }
    }
    #[cfg(not(windows))]
    cmd.current_dir(&verified.cwd);
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(_) => {
            execution.finish(permit, ExecutionOutcome::Uncertain {reason_code:"process_result_unavailable".into()})?;
            return Err("command outcome uncertain; do not resubmit automatically".into());
        }
    };
    let (status, stdout, stderr) = std::thread::scope(|scope| -> Result<_,RuntimeError> {
        let out = child.stdout.take().ok_or("command stdout missing")?;
        let err = child.stderr.take().ok_or("command stderr missing")?;
        let output = scope.spawn(move || capture(out));
        let errors = scope.spawn(move || capture(err));
        Ok((child.wait()?, output.join().map_err(|_|"command stdout unavailable")??,
            errors.join().map_err(|_|"command stderr unavailable")??))
    })?;
    let Some(exit_code) = status.code() else {
        execution.finish(permit, ExecutionOutcome::Uncertain {reason_code:"process_interrupted".into()})?;
        return Err("command interrupted without an exit code".into());
    };
    execution.finish(permit, ExecutionOutcome::Completed {exit_code,summary:None})?;
    Ok(json!({"exit_code":exit_code,"stdout":stdout.0,"stderr":stderr.0,
        "stdout_truncated":stdout.1,"stderr_truncated":stderr.1}))
}

/// The last argument is a LOCAL startup policy decision, fixed for this
/// handler's lifetime. A request cannot change it or prompt for permission.
pub fn attach(
    settings: &Path,
    root: &Path,
    database: &Path,
    catalog: &mut Vec<ToolDefinition>,
    handlers: &mut ToolMapHandler,
    process_enabled: bool,
) -> Result<Option<SessionSupervisor>, RuntimeError> {
    attach_inner(settings, root, database, catalog, handlers, process_enabled, None)
}

/// Attach restricted diagnostics to the same workspace capability used by the
/// file tools. Unix metadata children receive a clone of this exact root.
pub(crate) fn attach_with_workspace(
    settings: &Path,
    root: &Path,
    database: &Path,
    catalog: &mut Vec<ToolDefinition>,
    handlers: &mut ToolMapHandler,
    process_enabled: bool,
    workspace: std::sync::Arc<agent_bridge_desktop::DesktopFiles>,
) -> Result<Option<SessionSupervisor>, RuntimeError> {
    attach_inner(settings, root, database, catalog, handlers, process_enabled, Some(workspace))
}

fn attach_inner(
    settings: &Path, root: &Path, database: &Path,
    catalog: &mut Vec<ToolDefinition>, handlers: &mut ToolMapHandler,
    process_enabled: bool,
    workspace: Option<std::sync::Arc<agent_bridge_desktop::DesktopFiles>>,
) -> Result<Option<SessionSupervisor>, RuntimeError> {
    // The stdio caller receives ownership of the joinable session supervisor.
    // A failed watchdog creation fails the attachment before any child starts.
    let supervisor = sessions::attach(settings, root, database, catalog, handlers, process_enabled, workspace)?
        .map(SessionSupervisor::Restricted);
    attach_project_command(settings, root, database, catalog, handlers, process_enabled);
    Ok(supervisor)
}

/// Called only by the Workstation router selected locally at startup with
/// FullyUnlocked AND --enable-processes. Never replaces the restricted stdio
/// or FullControl provider, and never registers duplicate process tool names.
pub(crate) fn attach_unrestricted(
    settings: &Path,
    root: &Path,
    database: &Path,
    catalog: &mut Vec<ToolDefinition>,
    handlers: &mut ToolMapHandler,
    live_profile: std::sync::Arc<std::sync::RwLock<agent_bridge_desktop::DesktopProfile>>,
) -> Result<SessionSupervisor, RuntimeError> {
    let supervisor = unrestricted::attach(root, catalog, handlers, std::sync::Arc::clone(&live_profile))?;
    // All direct-profile diagnostics self-gate, including after a downgrade.
    attach_project_command_with_snapshot(settings,root,database,catalog,handlers,true,None,Some(live_profile));
    Ok(SessionSupervisor::Unrestricted(supervisor))
}

pub(crate) fn attach_unified(
    settings: &Path,
    root: &Path,
    database: &Path,
    catalog: &mut Vec<ToolDefinition>,
    handlers: &mut ToolMapHandler,
    process_enabled: bool,
    workspace: std::sync::Arc<agent_bridge_desktop::DesktopFiles>,
    live_profile: std::sync::Arc<std::sync::RwLock<agent_bridge_desktop::DesktopProfile>>,
    desktops: crate::agent_desktop::AgentDesktopHandle,
    private_root: &Path,
    commands: std::sync::Arc<CommandCatalogueSnapshot>,
) -> Result<Option<SessionSupervisor>, RuntimeError> {
    use agent_bridge_desktop::DesktopProfile;
    let startup = *live_profile.read().map_err(|_| "PROFILE_STATE_UNAVAILABLE")?;
    let mut restricted = ToolMapHandler::new();
    let direct = process_enabled && startup == DesktopProfile::FullyUnlocked;
    let supervisor = if direct {
        let supervisor = unrestricted::attach_unified(
            root, catalog, handlers, std::sync::Arc::clone(&live_profile), desktops, private_root,
        )?;
        attach_project_command_with_snapshot(settings, root, database, catalog, &mut restricted, true,
            Some(std::sync::Arc::clone(&commands)),Some(std::sync::Arc::clone(&live_profile)));
        Some(SessionSupervisor::Unrestricted(supervisor))
    } else {
        let enabled=process_enabled && startup.permits_processes();
        let supervisor=sessions::attach_with_snapshot(settings,root,database,catalog,&mut restricted,
            enabled,Some(workspace),Some(std::sync::Arc::clone(&commands)))?
            .map(SessionSupervisor::Restricted);
        attach_project_command_with_snapshot(settings,root,database,catalog,&mut restricted,enabled,
            Some(std::sync::Arc::clone(&commands)),Some(std::sync::Arc::clone(&live_profile)));
        supervisor
    };
    let names: &[&str] = if direct { &["agent_bridge_project_command"] } else {
        &["desktop_start_process", "desktop_read_process", "desktop_interact_process",
            "desktop_terminate_process", "agent_bridge_project_command"]
    };
    let restricted = std::sync::Arc::new(restricted);
    for &name in names {
        let profile = std::sync::Arc::clone(&live_profile);
        let restricted = std::sync::Arc::clone(&restricted);
        handlers.register(name, move |args| {
            // The fixed diagnostic takes the same live lock itself. Avoid
            // recursively reading it while a local downgrade may be waiting.
            if name == "agent_bridge_project_command" {
                return restricted.call(name, args);
            }
            let active = profile.read().map_err(|_| agent_bridge_gateway::ToolDispatchError::internal("PROFILE_STATE_UNAVAILABLE"))?;
            if process_enabled && startup.permits_processes() && !active.permits_processes() {
                return Ok(ToolCallResult::tool_error(
                    "PROFILE_RESTRICTED_BY_OPERATOR: full-control is required",
                ));
            }
            restricted.call(name, args)
        });
    }
    Ok(supervisor)
}

fn attach_project_command(
    settings: &Path, root: &Path, database: &Path,
    catalog: &mut Vec<ToolDefinition>, handlers: &mut ToolMapHandler,
    process_enabled: bool,
) {
    attach_project_command_with_snapshot(settings,root,database,catalog,handlers,process_enabled,None,None)
}

fn attach_project_command_with_snapshot(
    settings:&Path,root:&Path,database:&Path,catalog:&mut Vec<ToolDefinition>,handlers:&mut ToolMapHandler,
    process_enabled:bool,commands:Option<std::sync::Arc<CommandCatalogueSnapshot>>,
    live_profile:Option<std::sync::Arc<std::sync::RwLock<agent_bridge_desktop::DesktopProfile>>>,
) {
    let (settings, root, database) = (settings.to_owned(), root.to_owned(), database.to_owned());
    handlers.register("agent_bridge_project_command", move |arguments| {
        // Refuse before parsing arguments, reading operator settings, probing
        // the workspace or constructing any command permit.
        if !process_enabled {
            return Ok(ToolCallResult::tool_error(
                "PROCESS_DISABLED_BY_LOCAL_PROFILE: process execution is disabled at startup",
            ));
        }
        let active = live_profile.as_ref().map(|profile| profile.read()
            .map_err(|_| agent_bridge_gateway::ToolDispatchError::internal("PROFILE_STATE_UNAVAILABLE")))
            .transpose()?;
        if active.as_ref().is_some_and(|profile| !profile.permits_processes()) {
            return Ok(ToolCallResult::tool_error(
                "PROFILE_RESTRICTED_BY_OPERATOR: full-control is required",
            ));
        }
        let fully_unlocked = active.as_ref().is_some_and(|profile|
            **profile == agent_bridge_desktop::DesktopProfile::FullyUnlocked);
        let Some(action) = arguments.get("command").and_then(Value::as_str).filter(|_|arguments.len()==1) else {
            return Ok(ToolCallResult::tool_error("Choose a configured project command"));
        };
        Ok(match run_with_snapshot(&settings, &root, &database, action,commands.as_deref(),fully_unlocked) {
            Ok(output) => ToolCallResult::text(output.to_string()),
            Err(err) => ToolCallResult::tool_error(err.to_string()),
        })
    });
    catalog.push(ToolDefinition::new("agent_bridge_project_command",Some("Run one locally configured, pinned, fixed-argv project diagnostic only when the operator's startup process profile enables it; preapproved:false always denies, and no interactive approval is possible.".into()),
        json!({"type":"object","properties":{"command":{"type":"string","enum":["git-branch","git-revision","git-root","git-version","rust-version"]}},
            "additionalProperties":false,"required":["command"]})));
}

#[cfg(all(test,windows))]
mod capability_fix_tests {
    use super::*;
    use std::sync::Arc;
    use agent_bridge_desktop::{DesktopConfig,DesktopFiles,DesktopProfile};

    #[test]
    fn fully_unlocked_pinned_revision_uses_current_user_and_denies_after_downgrade() {
        use std::os::windows::process::CommandExt;
        let root=std::env::temp_dir().join(format!("unlocked-revision-{}",std::process::id()));
        let project=root.join("project");
        let settings=root.join("settings");
        std::fs::create_dir_all(&project).unwrap();
        agent_bridge_lifecycle::initialize_operator_settings(&settings).unwrap();
        let git=PathBuf::from("C:/Program Files/Git/cmd/git.exe");
        let pin=FsEnvironmentVerifier.verify_executable(&git).unwrap();
        let git_call=|args:&[&str]| {
            let result=Command::new(&git).args(args).current_dir(&project)
                .env("GIT_CONFIG_NOSYSTEM","1").env("GIT_CONFIG_GLOBAL","NUL")
                .creation_flags(0x08000000).output().unwrap();
            assert!(result.status.success(), "{}",String::from_utf8_lossy(&result.stderr));
            String::from_utf8(result.stdout).unwrap()
        };
        git_call(&["init","--quiet"]);
        git_call(&["-c","user.name=Agent Bridge Test","-c","user.email=fixture@example.invalid",
            "commit","--allow-empty","--no-gpg-sign","--no-verify","--quiet","-m","fixture"]);
        let expected=git_call(&["rev-parse","--verify","HEAD"]);
        std::fs::write(settings.join("commands.json"),json!({"version":1,"programs":{
            "git-revision":{"executable":git,"sha256":pin.sha256,"preapproved":true}
        }}).to_string()).unwrap();
        for unified in [false,true] {
            let profile=crate::session_profile::ProfileControl::new(DesktopProfile::FullyUnlocked);
            let mut catalogue=Vec::new();
            let mut handlers=ToolMapHandler::new();
            let database=root.join("core.sqlite");
            let mut owner=if unified {
                let files=Arc::new(DesktopFiles::open(DesktopConfig::new(&project)
                    .with_session_profile(DesktopProfile::FullyUnlocked).allow_workspace_write()).unwrap());
                attach_unified(&settings,&project,&database,&mut catalogue,&mut handlers,true,
                    files,profile.shared(),crate::agent_desktop::AgentDesktopHandle::disabled(),
                    &root.join("private"),Arc::new(CommandCatalogueSnapshot::load(&settings).unwrap()))
                    .unwrap().unwrap()
            } else {
                attach_unrestricted(&settings,&project,&database,&mut catalogue,&mut handlers,profile.shared()).unwrap()
            };
            let call=|| serde_json::to_value(handlers.call("agent_bridge_project_command",
                json!({"command":"git-revision"}).as_object().unwrap().clone()).unwrap()).unwrap();
            let response=call();
            assert_ne!(response["isError"],true,"{response}");
            let output:Value=serde_json::from_str(response["content"][0]["text"].as_str().unwrap()).unwrap();
            assert_eq!(output["exit_code"],0,"{output}");
            assert_eq!(output["stdout"].as_str().unwrap().trim(),expected.trim());
            assert_eq!(output["provenance"],"current-os-user-owned-git");
            assert_eq!(output["git_process_started"],true);
            assert_eq!(output["owned_job_drained"],true);
            profile.set(DesktopProfile::WorkspaceWrite).unwrap();
            let denied=call();
            assert_eq!(denied["isError"],true,"{denied}");
            assert!(denied["content"][0]["text"].as_str().unwrap().contains("PROFILE_RESTRICTED_BY_OPERATOR"));
            owner.shutdown().unwrap();
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn capability_fix_full_control_consumes_only_bound_diagnostic_and_project_policy() {
        let base=std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let base=base.to_str().and_then(|value|value.strip_prefix(r"\\?\"))
            .map(PathBuf::from).unwrap_or(base);
        let root=base.join(format!("bound-command-policy-{}",std::process::id()));
        let project=root.join("project");let settings=root.join("settings");
        std::fs::create_dir_all(&project).unwrap();
        agent_bridge_lifecycle::initialize_operator_settings(&settings).unwrap();
        let git=PathBuf::from("C:/Program Files/Git/cmd/git.exe");
        let pin=FsEnvironmentVerifier.verify_executable(&git).unwrap();
        let mut original=json!({"version":1,"programs":{
            "git-version":{"executable":git,"sha256":pin.sha256,"preapproved":false},
            "project-program":{"executable":git,"sha256":pin.sha256,"preapproved":false,
                "arguments":[],"cwd":project}
        }});
        std::fs::write(settings.join("commands.json"),original.to_string()).unwrap();
        let selected=Arc::new(CommandCatalogueSnapshot::load(&settings).unwrap());
        let profile=crate::session_profile::ProfileControl::new(DesktopProfile::FullControl);
        let files=Arc::new(DesktopFiles::open(DesktopConfig::new(&project)
            .with_session_profile(DesktopProfile::FullyUnlocked).allow_workspace_write()).unwrap());
        let mut catalogue=Vec::new();let mut handlers=ToolMapHandler::new();
        let mut owner=attach_unified(&settings,&project,&root.join("core.sqlite"),&mut catalogue,
            &mut handlers,true,files,profile.shared(),crate::agent_desktop::AgentDesktopHandle::disabled(),
            &root.join("private"),selected).unwrap().unwrap();
        // A locally valid replacement would enable the fixed Git diagnostic.
        // For project-program, the replacement instead fails before any UI
        // prompt or process, so the negative regression cannot show a dialog.
        original["programs"]["git-version"]["preapproved"]=json!(true);
        original["programs"]["project-program"]["preapproved"]=json!(true);
        original["programs"]["project-program"]["stdin_protocol"]=json!("invalid-synthetic-protocol");
        std::fs::write(settings.join("commands.json"),original.to_string()).unwrap();
        assert!(configured_command(&settings,&project,"git-version","git",true).is_ok(),
            "the legacy reader still consumes the current locally valid replacement");
        let fixed=serde_json::to_value(handlers.call("agent_bridge_project_command",
            json!({"command":"git-version"}).as_object().unwrap().clone()).unwrap()).unwrap();
        let session=serde_json::to_value(handlers.call("desktop_start_process",
            json!({"command":"git-version"}).as_object().unwrap().clone()).unwrap()).unwrap();
        let project_call=serde_json::to_value(handlers.call("desktop_start_process",
            json!({"command":"project-program","executable":git,"arguments":[],"cwd":project})
                .as_object().unwrap().clone()).unwrap()).unwrap();
        owner.shutdown().unwrap();
        let _=std::fs::remove_dir_all(&root);
        for (reply,code) in [
            (fixed,"PROCESS_DENIED_BY_LOCAL_CATALOG"),
            (session,"PROCESS_NOT_LOCALLY_APPROVED"),
            (project_call,"PROCESS_NOT_LOCALLY_APPROVED"),
        ] {
            assert_eq!(reply["isError"],true,"{reply}");
            assert!(reply["content"][0]["text"].as_str().unwrap().contains(code),"{reply}");
        }
    }
}
