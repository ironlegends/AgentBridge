#[cfg(test)]
mod elevation_entry_tests;
#[cfg(test)]
mod test_process_fixture;

/// Base directory for synthetic private test state. Unix private-state checks
/// refuse group or world writable ancestors such as /tmp, so Unix tests use an
/// owner-only directory under HOME; Windows keeps the temporary directory.
#[cfg(test)]
pub(crate) fn test_state_base() -> std::path::PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let base = std::path::PathBuf::from(std::env::var_os("HOME").expect("HOME")).join(".ab-embedded-tests");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        base
    }
    #[cfg(not(unix))]
    {
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        base.to_str().and_then(|s| s.strip_prefix(r"\\?\")).map(std::path::PathBuf::from).unwrap_or(base)
    }
}

/// Writes synthetic private state with the owner-only mode that the Unix
/// readers require; on Windows the file inherits the private directory ACL.
#[cfg(test)]
pub(crate) fn write_private(path: impl AsRef<std::path::Path>, bytes: impl AsRef<[u8]>) {
    let path = path.as_ref();
    std::fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}
// The native elevation broker is compiled but not admitted until relay qualification.
#[cfg(any(test, windows))]
#[allow(dead_code)]
mod elevation;
pub mod backend;
pub(crate) mod capability_manifest;
pub(crate) mod unified_core;
pub(crate) mod operation_admission;
pub(crate) mod database_binding;
pub(crate) mod command_catalogue;
pub(crate) mod agent_desktop;
pub(crate) mod windows_tools;
pub(crate) mod browser_owned;
mod browser_docs;
mod extensions;
mod gemini;
mod request_audit;
mod lifecycle;
pub(crate) mod owned_children;
pub(crate) mod provider_owner;
mod runtime;
mod session_profile;
mod terminal;
mod ui;
mod window_inspection;

/// Local entry points for the separately compiled browser walkthroughs.
#[doc(hidden)]
pub mod walkthroughs {
    #[cfg(windows)]
    pub use crate::browser_docs::interactive::{
        approve_local_with_transfers, LocalInteractiveSelection, LocalTransferSelection, NativeProvider,
    };
    pub use crate::browser_docs::learn::preparation_once;
}

use agent_bridge_web_launch::{ChromeLauncher, LocalCliProfiles, LaunchRequest, OperatorApproval, Provider};
use agent_bridge_core::{inspect_existing, CoreDatabase};
use runtime::RuntimeError;
use std::ffi::OsString;
use std::path::Path;
use std::io::{self, BufRead, IsTerminal, Read, Write};

/// The browser Learn reader options stay in 2.x for compatibility with
/// 2.0.0 and are removed in 3.0.0. The warning goes to stderr, never to
/// the MCP stdout stream.
pub(crate) fn warn_deprecated(option: &str) {
    eprintln!("agent-bridge: {option} is deprecated since 2.1.0 and will be removed in 3.0.0");
}

const USAGE: &str = "agent-bridge start [--state-dir <directory>] [--database <path>] [--port <number>]\nagent-bridge stop [--state-dir <directory>]\nagent-bridge web open <private-directory> <chatgpt|gemini> <mission-id> <subtask-id> <ChatGPT-project-URL|Gemini-notebook-URL>\nagent-bridge import <database-path> <task-room.json> [--historical-source-provider <provider>]\nagent-bridge settings init <private-directory>\nagent-bridge oauth enroll <private-oauth-state> <https-origin> <missions|workstation>\nagent-bridge oauth requests <private-oauth-state> <https-origin> <missions|workstation>\nagent-bridge oauth approve <private-oauth-state> <https-origin> <missions|workstation> <request-id> <exact-callback-from-client-interface>\nagent-bridge workspace inspect <absolute-project-directory> [--git-revision <database> <private-settings-directory>]\nagent-bridge gemini serve <database> <private-state> <https-origin> <loopback-port>\nagent-bridge gemini project-read <db-boundary> <workstation-oauth-state> <https-workstation-origin> <loopback-port> --read-project <absolute-project> --missions-state <missions-oauth-state> --missions-origin <https-missions-origin> --settings-dir <private-settings-directory> --lifecycle-dir <private-lifecycle-directory>\nagent-bridge gemini workstation <db-boundary> <NEW-private-workstation-oauth-state> <DISTINCT-https-workstation-origin> <loopback-port> --project <absolute-project> --profile <read-only|workspace-write|full-control|fully-unlocked> --missions-state <missions-oauth-state> --missions-origin <https-missions-origin> --settings-dir <private-settings-directory> --lifecycle-dir <private-lifecycle-directory> [--enable-task-rooms] [--enable-settings-tools] [--enable-processes] [--unified-v1] [--ui-port <port> [--ui-open]] [--local-window-read <dedicated-desktop|macos|x11:N> <absolute-executable> <class-or-bundle-id> <exact-title>] [--local-doc-page <relative-html-or-markdown> ... | --local-learn-url <exact-Microsoft-Learn-HTTPS-URL> | --local-chrome-page <project-relative-html> ... [--local-chrome-origin https://learn.microsoft.com]]\nagent-bridge extensions describe <private-directory> <server> <tool>\nagent-bridge extensions refresh-check <private-directory> <mcp_docs|microsoft_learn|stdio-server>\nagent-bridge extensions requests <private-directory>\nagent-bridge extensions request <private-directory> <request-id>\nagent-bridge extensions approve <private-directory> <request-id> [<request-id>...]\nagent-bridge extensions refuse <private-directory> <request-id>\nagent-bridge extensions compact <private-directory>\nagent-bridge extensions forget-absent <private-directory> <server-name>\nagent-bridge extensions import <private-directory> <mcp-json-path> [--inherit-path <stdio-server>]...\nagent-bridge db <inspect|init|migrate> <database-path>\nagent-bridge stdio <database-path> [--workspace <directory> | --write-workspace <directory>] [--settings <private-directory>]\nagent-bridge stdio <database-path> --workspace <project> --local-doc-page <relative-html-or-markdown> [--local-doc-page <relative-html-or-markdown>]...\nagent-bridge stdio <database-path> --workspace <project> --local-window-read <dedicated-desktop|macos|x11:N> <absolute-executable> <class-or-bundle-id> <exact-title>\nagent-bridge stdio <database-path> --workspace <project> --local-learn-url <exact-Microsoft-Learn-HTTPS-URL>\nagent-bridge stdio <database-path> --workspace <project> --local-chrome-page <project-relative-html> [--local-chrome-page <project-relative-html>...] [--local-chrome-origin https://learn.microsoft.com]\nagent-bridge serve <database-path> --port <number>\nagent-bridge ui [--port <number>] [--database <path>] [--settings-dir <dir>] [--oauth-state <dir> --oauth-origin <https-origin> --oauth-audience <missions|workstation>] [--project <dir>] [--open]";

// This workflow runs ONLY as an explicitly selected LOCAL CLI command.
// OAuth HTTP/MCP handlers cannot invoke this function. A visible interactive
// console is mandatory; neither flags nor a piped answer can auto-approve.
fn local_console_confirmation(prompt:&str)->bool{
    if !io::stdin().is_terminal() || !io::stderr().is_terminal(){
        eprintln!("LOCAL_OAUTH_CONSENT_REQUIRED: a visible, directly operated terminal is required");
        return false;
    }
    eprintln!("{prompt}");
    eprintln!("Type APPROVE exactly and press Enter. Any other input refuses.");
    let _=io::stderr().flush();
    let mut answer=String::new();
    let input=io::stdin();
    // One bounded line, never an unbounded secret-bearing input.
    let mut reader=input.lock().take(64);
    matches!(reader.read_line(&mut answer),Ok(n) if n>0 && n<64
        && answer.trim_end_matches(['\r','\n'])=="APPROVE")
}

/// Local owner controller: enrollment is 10 minutes, authorization requests
/// expire within the existing OAuth lifetime, and each exact client/callback
/// must receive an independent human confirmation. No login secret, bearer or
/// refresh token is ever printed by these local commands.
fn oauth_owner_cli(args:&[OsString])->Result<(),RuntimeError>{
    use agent_bridge_oauth_server::{Audience, LocalOwner, OAuthConfig};
    let (action,state,origin,audience,details)=match args {
        [action,state,origin,audience,rest@..]=>(
            action.to_str().ok_or(USAGE)?,Path::new(state),
            origin.to_str().ok_or(USAGE)?,
            audience.to_str().ok_or(USAGE)?,rest,
        ),
        _=>return Err(USAGE.into()),
    };
    let audience=match audience{
        "missions"=>Audience::Missions,
        "workstation"=>Audience::Workstation,
        _=>return Err("OAuth owner audience must be missions or workstation".into()),
    };
    let owner=LocalOwner::open(OAuthConfig{
        state_dir:state.to_owned(),public_origin:origin.to_owned(),audience,
    })?;
    match (action,details){
        ("enroll",[])=>{
            let expires=owner.enable_enrollment(||local_console_confirmation(
                &format!(
                    "Allow OAuth enrollment on {origin}, audience {:?}, \
                     for 10 minutes only? No client is approved yet.",
                    audience,
                ),
            ))?;
            println!("{}",serde_json::json!({
                "local_oauth_enrollment":"enabled","expires_epoch_ms":expires,
                "duration_max_seconds":600,"audience":format!("{audience:?}")
            }));
        },
        ("requests",[])=>{
            let pending=owner.pending_requests()?;
            // Client IDs are public registration identifiers, NOT secrets.
            // Their full value is deliberately visible in this local owner
            // console so the operator can compare the actual client interface.
            let list=pending.iter().map(|req|serde_json::json!({
                "id":req.id,"client_id":req.client_id,
                "provider":if req.client_id.starts_with("chatgpt_"){"chatgpt"}else{"gemini"},
                "redirect_uri":req.redirect_uri,"resource":req.resource,
                "scope":req.scope,"expires_epoch_ms":req.expires_epoch_ms,
                "audience":format!("{:?}",req.audience),"capability":req.capability
            })).collect::<Vec<_>>();
            println!("{}",serde_json::json!({"count":list.len(),"pending":list}));
        },
        ("approve",[request_id,callback])=>{
            let id=request_id.to_str().ok_or(USAGE)?;
            let expected_callback=callback.to_str().ok_or(USAGE)?;
            // The human must copy the exact callback from the actual
            // ChatGPT/Gemini connection UI. A value from the MCP request alone
            // cannot authorize itself. Official-host validation is repeated
            // independently by LocalOwner and OAuthServer.
            owner.approve_request(id,|req|{
                if req.redirect_uri!=expected_callback {
                    eprintln!("LOCAL_OAUTH_CALLBACK_MISMATCH: callback from client UI does not match requested callback");
                    return false;
                }
                local_console_confirmation(&format!(
                    "Individual OAuth Request\nClient: {}\nResource: {}\n\
                     EXACT Callback: {}\nScope: {}\nExpires: {} ms Unix\n\
                     Contract: {:?}\nApprove this single request?",
                    req.client_id,req.resource,req.redirect_uri,req.scope,req.expires_epoch_ms,req.capability,
                ))
            })?;
            println!("{}",serde_json::json!({
                "local_oauth_request":"approved","id":id,
                "permission":"one_exact_request_only"
            }));
        },
        _=>return Err("Usage: agent-bridge oauth <enroll|requests|approve> <private-oauth-state> <https-origin> <missions|workstation> [<request-id> <exact-callback-from-client-interface>]".into()),
    }
    Ok(())
}

fn database_command(action: &str, path: &Path) -> Result<(), RuntimeError> {
    let version = match action {
        "inspect" => {
            let status = inspect_existing(path)?;
            println!("{}", serde_json::json!({
                "schema_version": status.version,
                "pending_migrations": status.pending_migrations,
            }));
            return Ok(());
        }
        "init" => CoreDatabase::initialize_new(path)?.schema_version(),
        "migrate" => CoreDatabase::migrate_existing(path)?.schema_version(),
        _ => return Err(USAGE.into()),
    };
    println!("{}", serde_json::json!({"schema_version": version}));
    Ok(())
}

pub fn run_cli(args: &[OsString]) -> Result<(), RuntimeError> {
    if backend::dispatch_private_child(args)?.is_some() { return Ok(()); }
    match args {
        [cmd, options @ ..] if cmd == "oauth" => oauth_owner_cli(options),
        [cmd, options @ ..] if cmd == "ui" => ui::run_cli(options),
        [cmd, rest @ ..] if cmd == "start" || cmd == "stop" => lifecycle::control(cmd, rest),
        [arg] if arg == "--version" => {
            println!("agent-bridge {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        [arg] if arg == "--help" || arg == "-h" => {
            println!("{USAGE}");
            Ok(())
        }
        [cmd, action, dir, provider, mission, task, extra @ ..] if cmd == "web" && action == "open" => {
            let (provider, project) = match (provider.to_str(), extra) {
                (Some("chatgpt"), [project]) => (Provider::ChatGpt, Some(project.to_str().ok_or(USAGE)?)),
                (Some("gemini"), [notebook]) => (Provider::Gemini, Some(notebook.to_str().ok_or(USAGE)?)),
                _ => return Err(USAGE.into()),
            };
            let request = LaunchRequest::new(provider, mission.to_str().ok_or(USAGE)?, task.to_str().ok_or(USAGE)?)?;
            let (chatgpt, gemini) = agent_bridge_lifecycle::browser_profiles(Path::new(dir))?;
            let profiles = LocalCliProfiles::from_local_cli(chatgpt, gemini)?;
            let launcher = ChromeLauncher::discover(project, profiles)?;
            let result = launcher.launch(&request, OperatorApproval::ExplicitlyRequested)?;
            println!("{}", serde_json::json!({"launch_status":format!("{:?}",result.status),"pid":result.initial_process_id,
                "authenticated":null,"mission_started":null}));
            Ok(())
        }
        [cmd, db, snapshot, extra @ ..] if cmd == "import" => {
            // This explicit, local-only alias must refer to one existing
            // import row for the same source context/task and matching digest.
            let historical_source_provider = match extra {
                [] => None,
                [flag, value] if flag == "--historical-source-provider" =>
                    Some(value.to_str().ok_or(USAGE)?),
                _ => return Err(USAGE.into()),
            };
            let mut bytes = Vec::new();
            let file = std::fs::File::open(snapshot)?;
            if !file.metadata()?.is_file() { return Err("expected a regular Task Room snapshot".into()); }
            file.take(8 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 8 * 1024 * 1024 { return Err("snapshot exceeds import limit".into()); }
            let snapshot = serde_json::from_slice(&bytes)?;
            let mut core = CoreDatabase::open_existing(Path::new(db))?;
            let imported = agent_bridge_import::import_snapshot_with_alias(core.connection_mut(), &snapshot, historical_source_provider)?;
            println!("{}", serde_json::to_string(&imported)?);
            Ok(())
        }
        [cmd, action, db, state, origin, port] if cmd == "gemini" && action == "serve" => {
            gemini::serve(Path::new(db), Path::new(state), origin.to_str().ok_or(USAGE)?, port.to_str().ok_or(USAGE)?.parse()?)
        }
        [cmd, action, db, state, origin, port, project_flag, project, state_flag, missions_state, origin_flag, missions_origin, settings_flag, settings_dir, lifecycle_flag, lifecycle_dir]
            if cmd == "gemini" && action == "project-read"
                && project_flag == "--read-project"
                && state_flag == "--missions-state"
                && origin_flag == "--missions-origin"
                && settings_flag == "--settings-dir"
                && lifecycle_flag == "--lifecycle-dir" =>
        {
            gemini::serve_project_reads(
                Path::new(db), Path::new(state), origin.to_str().ok_or(USAGE)?,
                port.to_str().ok_or(USAGE)?.parse()?, Path::new(project),
                Path::new(missions_state), missions_origin.to_str().ok_or(USAGE)?,
                Path::new(settings_dir), Path::new(lifecycle_dir),
            )
        }
        [cmd, action, ..] if cmd == "gemini" && action == "workstation" => {
            let mut config = backend::parse_cli(args)?;
            gemini::serve_workstation(config.take_start())
        }
        [cmd, action, dir, flag, db, settings] if cmd == "workspace" && action == "inspect" && flag == "--git-revision" => {
            let project = Path::new(dir);
            let report = runtime::inspect_revision(project, Path::new(db), Path::new(settings))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        [cmd, action, dir] if cmd == "workspace" && action == "inspect" => {
            let project = Path::new(dir);
            let access = agent_bridge_lifecycle::workspace_access::inspect_project_access(project)?;
            println!("{}", serde_json::to_string_pretty(&access)?);
            Ok(())
        }
        [cmd, action, dir] if cmd == "settings" && action == "init" => {
            agent_bridge_lifecycle::initialize_operator_settings(Path::new(dir))?;
            Ok(())
        }
        // Exact local, read-only public MCP catalogue observation. Web
        // administration refresh remains a queued operator decision.
        [cmd, action, dir, server] if cmd == "extensions" && action == "refresh-check" => {
            extensions::refresh_check(Path::new(dir), server.to_str().ok_or(USAGE)?)
        }
        [cmd, action, dir, server, tool] if cmd == "extensions" && action == "describe" => {
            let registry = extensions::read(Path::new(dir))?;
            println!("{}", registry.describe_for_operator(server.to_str().ok_or(USAGE)?, tool.to_str().ok_or(USAGE)?)?);
            Ok(())
        }
        [cmd, action, dir] if cmd == "extensions" && matches!(action.to_str(), Some("requests" | "compact")) => {
            extensions::local(Path::new(dir), action.to_str().ok_or(USAGE)?, None)
        }
        [cmd, action, dir, path, options @ ..] if cmd == "extensions" && action == "import" && !options.is_empty() => {
            let mut inherit_path = std::collections::BTreeSet::new();
            let mut iter = options.iter();
            while let Some(flag) = iter.next() {
                match (flag.to_str(), iter.next().and_then(|name| name.to_str())) {
                    (Some("--inherit-path"), Some(name)) => { inherit_path.insert(name.to_owned()); }
                    _ => return Err(USAGE.into()),
                }
            }
            extensions::import(Path::new(dir), Path::new(path), &inherit_path)
        }
        [cmd, action, dir, ids @ ..] if cmd == "extensions" && action == "approve" && ids.len() > 1 => {
            let ids = ids.iter().map(|id| id.to_str().ok_or(USAGE)).collect::<Result<Vec<_>, _>>()?;
            extensions::approve_batch(Path::new(dir), &ids)
        }
        [cmd, action, dir, id] if cmd == "extensions"
            && matches!(action.to_str(), Some("request" | "approve" | "refuse" | "forget-absent" | "import")) =>
        {
            extensions::local(Path::new(dir), action.to_str().ok_or(USAGE)?, Some(id.to_str().ok_or(USAGE)?))
        }
        [cmd, path, options @ ..] if cmd == "stdio" => {
            let mut workspace = None;
            let mut settings = None;
            let mut local_window = None;
            let mut local_doc_pages: Vec<String> = Vec::new();
            let mut local_learn_url: Option<String> = None;
            let mut local_chrome_pages:Vec<String> = Vec::new();
            let mut local_chrome_origins:Vec<String> = Vec::new();
            let mut iter = options.iter();
            while let Some(flag) = iter.next() {
                match flag.to_str() {
                    Some("--workspace") if workspace.is_none() => {
                        workspace = Some((Path::new(iter.next().ok_or(USAGE)?), false));
                    }
                    Some("--write-workspace") if workspace.is_none() => {
                        workspace = Some((Path::new(iter.next().ok_or(USAGE)?), true));
                    }
                    Some("--settings") if settings.is_none() => {
                        settings = Some(Path::new(iter.next().ok_or(USAGE)?));
                    }
                    Some("--local-doc-page") if local_learn_url.is_none()
                        && local_chrome_pages.is_empty() => {
                        let page = iter.next().and_then(|value| value.to_str()).ok_or(USAGE)?;
                        if local_doc_pages.len() >= browser_docs::MAX_APPROVED_PAGES {
                            return Err(USAGE.into());
                        }
                        local_doc_pages.push(page.to_owned());
                    }
                    Some("--local-learn-url") if local_learn_url.is_none()
                        && local_doc_pages.is_empty() && local_chrome_pages.is_empty() => {
                        warn_deprecated("--local-learn-url");
                        local_learn_url = Some(iter.next().and_then(|v|v.to_str())
                            .ok_or(USAGE)?.to_owned());
                    }
                    Some("--local-chrome-page") if local_doc_pages.is_empty()
                        && local_learn_url.is_none() && local_chrome_pages.len()<8 => {
                        local_chrome_pages.push(iter.next().and_then(|v|v.to_str())
                            .ok_or(USAGE)?.to_owned());
                    }
                    Some("--local-chrome-origin") if local_chrome_origins.len()<4 => {
                        warn_deprecated("--local-chrome-origin");
                        local_chrome_origins.push(iter.next().and_then(|v|v.to_str())
                            .ok_or(USAGE)?.to_owned());
                    }
                    Some("--local-window-read") if local_window.is_none() => {
                        // Only the LOCAL process argv can select this exact window.
                        let desktop_name = iter.next().and_then(|s| s.to_str()).ok_or(USAGE)?;
                        let executable = iter.next().ok_or(USAGE)?;
                        let class_name = iter.next().and_then(|s| s.to_str()).ok_or(USAGE)?;
                        let title = iter.next().and_then(|s| s.to_str()).ok_or(USAGE)?;
                        local_window = Some(window_inspection::DedicatedWindow {
                            desktop_name: desktop_name.to_owned(),
                            executable: Path::new(executable).to_path_buf(),
                            class_name: class_name.to_owned(),
                            title: title.to_owned(),
                        });
                    }
                    _ => return Err(USAGE.into()),
                }
            }
            // The local caller chooses exactly one browser provider, because
            // all browser implementations publish the same three MCP names.
            // Other tool families remain independent and locally scoped.
            let count=usize::from(!local_doc_pages.is_empty())
                +usize::from(local_learn_url.is_some())
                +usize::from(!local_chrome_pages.is_empty());
            if count>1 || (!local_chrome_origins.is_empty()
                && local_chrome_pages.is_empty()) {
                return Err("Select one browser provider and one bound project".into());
            }
            if (count>0 || local_window.is_some()) && workspace.is_none() {
                return Err("Browser and window tools require a locally selected workspace".into());
            }
            runtime::serve_stdio(Path::new(path), workspace, settings,
                local_window, local_doc_pages, local_learn_url,
                local_chrome_pages, local_chrome_origins)
        }
        [cmd, path, flag, port] if cmd == "serve" && flag == "--port" => {
            runtime::serve_http(Path::new(path), port.to_str().ok_or(USAGE)?.parse()?)
        }
        [cmd, action, path] if cmd == "db" => {
            database_command(action.to_str().ok_or(USAGE)?, Path::new(path))
        }
        _ => Err(USAGE.into()),
    }
}
