//! The full view is assembled separately; legacy definitions and handlers are
//! never widened. Both views and native control share one qualified Core owner.
use super::*;
use crate::capability_manifest::QualifiedManifest;
use crate::provider_owner::ProviderOwner;
use agent_bridge_desktop::unified::UnifiedFiles;

pub(crate) fn unified_router(
    manifest:&QualifiedManifest, database_path:&Path, shared_database:Option<SharedCoreDatabase>,
    settings:&Path, extension_authority:&Value, profile:ProfileControl,
    supervisors:&mut Vec<crate::terminal::SessionSupervisor>,
    providers:&mut Vec<ProviderOwner>,
)->Result<WorkstationRuntime,RuntimeError> {
    let database=manifest.acquire_database(database_path,shared_database)?;
    let files=Arc::new(UnifiedFiles::open(manifest.file_config())
        .map_err(|error|io::Error::other(error.message))?);
    let file_cleanup=Arc::clone(&files);
    providers.push(ProviderOwner::new(Arc::new(||Ok(())),Arc::new(move ||
        file_cleanup.shutdown().map_err(|error|io::Error::other(error.message).into()))));

    let root=&manifest.context.workspace;
    let mut catalogue=Vec::new(); let mut handlers=ToolMapHandler::new();
    // Reuse the implemented Task Room and documentary skill adapters. Their
    // live policy is wrapped below. File handlers are replaced as a whole.
    attach_desktop_surface(&Workspace {root:root.clone(),write_files:true,profile:DesktopProfile::FullyUnlocked},
        Some(&database),database_path,Some(settings),
        DesktopSurface {web_read_only:false,task_rooms:true,settings_tools:true,terminal_tool:false,processes:false},
        &mut catalogue,&mut handlers,supervisors,Some(extension_authority),Some(&profile))?;
    replace_extension_view(settings,&mut catalogue,&mut handlers)?;
    handlers=guard_common(handlers,&catalogue,profile.clone());

    let specs=files.tool_catalog();
    let file_names:std::collections::BTreeSet<_>=specs.iter().map(|spec|spec.name).collect();
    catalogue.retain(|definition|!file_names.contains(definition.name.as_str()));
    for spec in specs {
        let owner=Arc::clone(&files); let live=profile.clone(); let name=spec.name;
        handlers.register(name,move |arguments| {
            let active=live.read().map_err(|_|ToolDispatchError::internal("PROFILE_STATE_UNAVAILABLE"))?;
            serde_json::from_value(owner.dispatch(*active,name,&Value::Object(arguments)))
                .map_err(|_|ToolDispatchError::internal("INVALID_FILE_PROVIDER_RESPONSE"))
        });
        catalogue.push(ToolDefinition::new(name,Some(spec.description.into()),spec.input_schema));
    }
    crate::unified_core::attach(Arc::clone(&database),root,manifest.commands(),profile.clone(),
        manifest.selection.allow_import,&mut catalogue,&mut handlers)?;

    let binding=task_room_workspace_binding(root)?;
    let room_root=root.clone(); let rooms=Arc::clone(&database);
    let validator:crate::agent_desktop::TaskBindingValidator=Arc::new(move |task_id,context_handle| {
        let current=task_room_workspace_binding(&room_root)?;
        if current!=binding {return Err("TASK_ROOM_PROJECT_CHANGED".into());}
        let mut core=rooms.lock().map_err(|_|"CORE_UNAVAILABLE")?;
        agent_bridge_missions::task_room::dispatch_scoped(core.connection_mut(),
            &json!({"action":"get","task_id":task_id,"context_handle":context_handle}),&current)
            .map_err(|_|"TASK_ROOM_CAPABILITY_REFUSED")?;
        Ok(())
    });
    let (desktops,desktop_owner)=crate::agent_desktop::attach(
        manifest.desktop_config(),profile.clone(),validator,&mut catalogue,&mut handlers)?;
    profile.register_revoker(DesktopProfile::FullControl,desktop_owner.revoker())?;
    providers.push(desktop_owner);

    let terminal_workspace=Arc::new(DesktopFiles::open(DesktopConfig::new(root)
        .with_session_profile(DesktopProfile::FullyUnlocked).allow_workspace_write())
        .map_err(|error|io::Error::other(error.message))?);
    if let Some(supervisor)=crate::terminal::attach_unified(
        settings,root,database_path,&mut catalogue,&mut handlers,true,terminal_workspace,
        profile.shared(),desktops.clone(),&manifest.selection.private_root,manifest.commands(),
    )? {
        let minimum=match &supervisor {
            crate::terminal::SessionSupervisor::Restricted(_)=>DesktopProfile::FullControl,
            crate::terminal::SessionSupervisor::Unrestricted(_)=>DesktopProfile::FullyUnlocked,
        };
        profile.register_revoker(minimum,supervisor.revoker())?;
        supervisors.push(supervisor);
    }
    let windows_owner=crate::windows_tools::attach(
        manifest.windows_config(),profile.clone(),desktops.clone(),&mut catalogue,&mut handlers)?;
    profile.register_revoker(DesktopProfile::FullControl,windows_owner.revoker())?;
    providers.push(windows_owner);

    let uploads=Arc::clone(&files); let downloads=Arc::clone(&files);
    let callbacks=crate::browser_owned::BrowserTransferCallbacks {
        stage_uploads:Arc::new(move |active,paths,session|uploads.stage_uploads(active,paths,session)
            .map_err(|error|io::Error::other(error.message).into())),
        publish_download:Arc::new(move |active,path,name|downloads.publish_download(active,path,name)
            .map_err(|error|io::Error::other(error.message).into())),
    };
    let browser_owner=crate::browser_owned::attach(
        manifest.browser_config(),Arc::new(profile.clone()),desktops,callbacks,&mut catalogue,&mut handlers)?;
    profile.register_revoker(DesktopProfile::FullControl,browser_owner.revoker())?;
    providers.push(browser_owner);

    let total=catalogue.len()+1;
    let mut families=json!({"desktop":0,"missions_including_status":1,"project_commands":0,"historical_utilities":0,"other":0});
    for tool in &catalogue {
        let family=if matches!(tool.name.as_str(),"agent_bridge_task_import"|"desktop_list_allowed_commands") {
            "historical_utilities"
        } else if tool.name=="agent_bridge_project_command" {"project_commands"}
        else if tool.name.starts_with("desktop_") {"desktop"}
        else if tool.name.starts_with("agent_bridge_mission_")||tool.name=="agent_bridge_context_create" {"missions_including_status"}
        else {"other"};
        families[family]=json!(families[family].as_u64().unwrap_or(0)+1);
    }
    let identity=manifest.identity()?; let summary=manifest.summary()?;
    let live=profile.clone();
    handlers.register("agent_bridge_status",move |arguments| {
        if !arguments.is_empty() {return Err(ToolDispatchError::invalid_params("status takes no arguments"));}
        let active=*live.read().map_err(|_|ToolDispatchError::internal("PROFILE_STATE_UNAVAILABLE"))?;
        let processes=process_status(live.startup_profile(),active);
        Ok(ToolCallResult::text(json!({
            "ok":true,"version":env!("CARGO_PKG_VERSION"),"active_backend":"rust","audience":"workstation",
            "capability":identity,"total_tools":total,"families":families,
            "vendor_tools":total.saturating_sub(16),
            "vendor_tools_definition":"Non-mission additions; historical compatibility field",
            "desktop_profile":active,"startup_profile":live.startup_profile(),
            "process_tools_enabled":processes["process_tools_enabled"],
            "project_commands_enabled":processes["project_commands_enabled"],
            "direct_processes_enabled":processes["direct_processes_enabled"],
            "database_schema":agent_bridge_core::CURRENT_SCHEMA_VERSION,
            "components":summary["components"],"channel":"development","production":false,
        }).to_string()))
    });
    catalogue.push(ToolDefinition::new("agent_bridge_status",
        Some("Report the exact selected tool capability, family counts, live profile and component qualification.".into()),
        json!({"type":"object","properties":{},"additionalProperties":false})));
    Ok(WorkstationRuntime {
        router:McpGateway::new(GatewayConfig::new("agent-bridge-workstation",env!("CARGO_PKG_VERSION")),
            catalogue,handlers),
        database:Some(database),
    })
}

fn replace_extension_view(
    settings:&Path,catalogue:&mut Vec<ToolDefinition>,handlers:&mut ToolMapHandler,
)->Result<(),RuntimeError> {
    let mut replacement=Vec::new(); let mut new_handlers=ToolMapHandler::new();
    crate::extensions::attach_unified(settings,&mut replacement,&mut new_handlers)?;
    // The effectful call retains the exact-authority/same-Registry handler
    // already attached above. Do not silently preserve it if its schema grows.
    let before=catalogue.iter().find(|tool|tool.name=="desktop_mcp_tool_call")
        .ok_or("Missing bound extension call")?;
    let after=replacement.iter().find(|tool|tool.name=="desktop_mcp_tool_call")
        .ok_or("Missing unified extension call")?;
    if before.input_schema!=after.input_schema {return Err("Unified extension call requires an explicit bound adapter".into());}
    let names:std::collections::BTreeSet<_>=replacement.iter().map(|tool|tool.name.clone()).collect();
    catalogue.retain(|tool|!names.contains(&tool.name));
    let replacement_handlers=Arc::new(new_handlers);
    for tool in replacement {
        if tool.name!="desktop_mcp_tool_call" {
            let selected=Arc::clone(&replacement_handlers); let name=tool.name.clone();
            handlers.register(name.clone(),move |arguments|selected.call(&name,arguments));
        }
        catalogue.push(tool);
    }
    Ok(())
}

fn guard_common(
    handlers:ToolMapHandler,catalogue:&[ToolDefinition],profile:ProfileControl,
)->ToolMapHandler {
    let original=Arc::new(handlers); let mut guarded=ToolMapHandler::new();
    for tool in catalogue {
        let name=tool.name.clone(); let inner=Arc::clone(&original); let live=profile.clone();
        guarded.register(name.clone(),move |arguments| {
            let active=live.read().map_err(|_|ToolDispatchError::internal("PROFILE_STATE_UNAVAILABLE"))?;
            let action=arguments.get("action").and_then(Value::as_str);
            let read=match name.as_str() {
                "desktop_task_manage"=>matches!(action,Some("get"|"list"|"context_discover")),
                "desktop_skill_manage"=>matches!(action,Some("list"|"get"|"read"|"validate")),
                "desktop_mcp_manage"=>matches!(action,Some("list"|"inspect")),
                "desktop_mcp_tool_inspect"|"desktop_mcp_tool_search"|"desktop_policy_status"=>true,
                _=>WORKSTATION_READ_TOOLS.contains(&name.as_str()),
            };
            let needs_full=name=="desktop_mcp_tool_call" || name=="desktop_skill_manage"
                && (arguments.contains_key("source_url") || matches!(action,Some("install"|"update"|"import"|"fetch")));
            if *active==DesktopProfile::ReadOnly&&!read || needs_full&&rank(*active)<rank(DesktopProfile::FullControl) {
                return Ok(ToolCallResult::tool_error("LIVE_PROFILE_REFUSED"));
            }
            inner.call(&name,arguments)
        });
    }
    guarded
}

// Kept separate so the reported policy is exercised alongside the actual
// direct-process handler without starting unrelated native providers.
fn process_status(startup:DesktopProfile,active:DesktopProfile)->Value {
    let direct=startup==DesktopProfile::FullyUnlocked;
    json!({"process_tools_enabled":if direct {active==DesktopProfile::FullyUnlocked}else{active.permits_processes()},
        "project_commands_enabled":active.permits_processes(),
        "direct_processes_enabled":direct && active==DesktopProfile::FullyUnlocked})
}

#[cfg(test)]
mod capability_fix_tests {
    use super::*;
    #[test]
    fn capability_fix_status_matches_direct_process_startup_minimum() {
        use agent_bridge_gateway::ToolHandler;
        let root=std::env::temp_dir().join(format!("status-direct-{}",std::process::id()));
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        std::fs::create_dir_all(root.join("private")).unwrap();
        agent_bridge_lifecycle::initialize_operator_settings(&root.join("settings")).unwrap();
        let project=std::fs::canonicalize(root.join("workspace")).unwrap();
        let project=project.to_str().and_then(|path|path.strip_prefix(r"\\?\"))
            .map(PathBuf::from).unwrap_or(project);
        let files=Arc::new(DesktopFiles::open(DesktopConfig::new(&project)
            .with_session_profile(DesktopProfile::FullyUnlocked).allow_workspace_write()).unwrap());
        let live=ProfileControl::new(DesktopProfile::FullyUnlocked);
        let mut catalogue=Vec::new();let mut handlers=ToolMapHandler::new();
        let mut owner=crate::terminal::attach_unified(&root.join("settings"),&project,
            &root.join("core.sqlite"),&mut catalogue,&mut handlers,true,files,live.shared(),
            crate::agent_desktop::AgentDesktopHandle::disabled(),&root.join("private"),
            Arc::new(crate::command_catalogue::CommandCatalogueSnapshot::load(&root.join("settings")).unwrap())).unwrap().unwrap();
        live.set(DesktopProfile::FullControl).unwrap();
        let response=handlers.call("desktop_start_process",serde_json::Map::new()).unwrap();
        let denied=serde_json::to_value(response).unwrap()["isError"]==true;
        let reported=process_status(live.startup_profile(),*live.read().unwrap());
        owner.shutdown().unwrap();
        let _=std::fs::remove_dir_all(&root);
        assert!(denied,"the real direct handler must retain its initial Unlock requirement");
        assert_eq!(reported["process_tools_enabled"],false,
            "status must not report process execution available after a direct startup is downgraded to Full");
        assert_eq!(reported["direct_processes_enabled"],false);
        assert_eq!(reported["project_commands_enabled"],true);
    }
}
