//! Mission and historical utility composition over the single qualified Core.
use crate::runtime::{RuntimeError, SharedCoreDatabase, task_room_workspace_binding};
use crate::session_profile::ProfileControl;
use agent_bridge_desktop::DesktopProfile;
use agent_bridge_gateway::{ToolCallResult, ToolDefinition, ToolDispatchError, ToolMapHandler};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;

const MISSION_READS: &[&str] = &[
    "agent_bridge_mission_get", "agent_bridge_mission_observe", "agent_bridge_mission_list",
    "agent_bridge_mission_checkpoints", "agent_bridge_mission_subtask_list",
];

pub(crate) fn attach(
    database: SharedCoreDatabase, project: &Path,
    commands: Arc<crate::command_catalogue::CommandCatalogueSnapshot>,
    profile: ProfileControl, allow_import: bool,
    catalogue: &mut Vec<ToolDefinition>, handlers: &mut ToolMapHandler,
) -> Result<(), RuntimeError> {
    let definitions: Vec<ToolDefinition> =
        serde_json::from_str(include_str!("../../../contracts/mission-tools-v1.json"))?;
    for definition in definitions.into_iter().filter(|tool|tool.name!="agent_bridge_status") {
        let name=definition.name.clone();
        let connection=Arc::clone(&database);
        let live=profile.clone();
        handlers.register(name.clone(),move |arguments| {
            let active=live.read().map_err(|_|ToolDispatchError::internal("PROFILE_STATE_UNAVAILABLE"))?;
            if *active==DesktopProfile::ReadOnly && !MISSION_READS.contains(&name.as_str()) {
                return Ok(ToolCallResult::tool_error("WRITE_ACCESS_REQUIRED: mission mutation refused"));
            }
            let mut db=connection.lock().map_err(|_|ToolDispatchError::internal("CORE_UNAVAILABLE"))?;
            Ok(match agent_bridge_missions::dispatch_tool(db.connection_mut(),&name,&Value::Object(arguments)) {
                Ok(value)=>ToolCallResult::text(value.to_string()),
                Err(error)=>ToolCallResult::tool_error(format!("CORE_{}: {}",error.code,error.message)),
            })
        });
        catalogue.push(definition);
    }
    let project=project.to_owned();
    let initial_binding=task_room_workspace_binding(&project)?;
    let connection=Arc::clone(&database);
    let live=profile.clone();
    catalogue.push(ToolDefinition::new("agent_bridge_task_import",
        Some("Import a historical snapshot by exact Task Room context/task capability into the same Core. The source remains unchanged; local import selection and workspace write are required.".into()),
        json!({"type":"object","additionalProperties":false,"properties":{
            "actor_context_handle":{"type":"string"},"context_id":{"type":"string"},
            "context_handle":{"type":"string"},"task_id":{"type":"string"}},
            "required":["actor_context_handle","context_id","context_handle","task_id"]})));
    handlers.register("agent_bridge_task_import",move |arguments| {
        let active=live.read().map_err(|_|ToolDispatchError::internal("PROFILE_STATE_UNAVAILABLE"))?;
        if !allow_import || *active==DesktopProfile::ReadOnly {
            return Ok(ToolCallResult::tool_error("IMPORT_NOT_AUTHORIZED: explicit local import selection and workspace write required"));
        }
        let current=task_room_workspace_binding(&project)
            .map_err(|_|ToolDispatchError::internal("TASK_ROOM_PROJECT_UNAVAILABLE"))?;
        if current!=initial_binding {
            return Ok(ToolCallResult::tool_error("TASK_ROOM_PROJECT_CHANGED"));
        }
        Ok(match import_task(&connection,&current,&Value::Object(arguments)) {
            Ok(value)=>ToolCallResult::text(value.to_string()),
            Err(error)=>ToolCallResult::tool_error(error.to_string()),
        })
    });
    catalogue.push(ToolDefinition::new("desktop_list_allowed_commands",
        Some("List only the sorted configured fixed-command names and whether a private catalogue exists. Executable paths, arguments and secret values are never returned.".into()),
        json!({"type":"object","properties":{},"required":[],"additionalProperties":false})));
    handlers.register("desktop_list_allowed_commands",move |arguments| {
        if !arguments.is_empty() {
            return Err(ToolDispatchError::invalid_params("No arguments are accepted"));
        }
        Ok(match commands.names() {
            Ok(value)=>ToolCallResult::text(value.to_string()),
            Err(_)=>ToolCallResult::tool_error("COMMAND_CATALOGUE_UNAVAILABLE"),
        })
    });
    Ok(())
}

fn import_task(database:&SharedCoreDatabase,binding:&str,args:&Value)->Result<Value,RuntimeError> {
    const FIELDS:[&str;4]=["actor_context_handle","context_id","context_handle","task_id"];
    let fields=args.as_object().ok_or("INVALID_IMPORT_ARGUMENTS")?;
    if fields.len()!=FIELDS.len() || FIELDS.iter().any(|name|
        !fields.get(*name).and_then(Value::as_str).is_some_and(|value|!value.is_empty()&&value.len()<=256))
    { return Err("INVALID_IMPORT_ARGUMENTS: exact source and actor capabilities required".into()); }
    let actor=fields["actor_context_handle"].as_str().ok_or("INVALID_ACTOR")?;
    let context=fields["context_id"].as_str().ok_or("INVALID_CONTEXT")?;
    let handle=fields["context_handle"].as_str().ok_or("INVALID_CONTEXT_CAPABILITY")?;
    let task_id=fields["task_id"].as_str().ok_or("INVALID_TASK")?;
    let mut db=database.lock().map_err(|_|"CORE_UNAVAILABLE")?;
    let conn=db.connection_mut();
    // This validates the registered actor without enrolling it into the
    // historical mission or changing any source Task Room membership.
    agent_bridge_missions::dispatch_tool(conn,"agent_bridge_mission_list",
        &json!({"actor_context_handle":actor,"limit":1}))
        .map_err(|error|format!("CORE_{}: {}",error.code,error.message))?;
    let source=agent_bridge_missions::task_room::read_import_snapshot_scoped(conn,
        handle,task_id,binding)
        .map_err(|error|format!("TASK_ROOM_{}: {}",error.code,error.message))?;
    let task=&source["task"];
    if source["context_id"]!=context || task["context_id"]!=context || task["task_id"]!=task_id {
        return Err("IMPORT_SOURCE_CAPABILITY_MISMATCH".into());
    }
    let events=source["events"].as_array().ok_or("INVALID_SOURCE_EVENTS")?;
    let steps=task["steps"].as_array().ok_or("INVALID_SOURCE_STEPS")?;
    if events.len()>50 || steps.len()>12 || source.to_string().len()>400_000 {
        return Err("IMPORT_SOURCE_EXCEEDS_BOUND".into());
    }
    let text=|value:&Value,key:&str|->Result<String,RuntimeError>{
        value.get(key).and_then(Value::as_str).map(str::to_owned).ok_or_else(||"INVALID_SOURCE_FIELD".into())
    };
    let goal=task["goal"].as_str().filter(|value|!value.trim().is_empty())
        .or_else(||task["title"].as_str()).ok_or("INVALID_SOURCE_GOAL")?.to_owned();
    let mut normalized_events=Vec::with_capacity(events.len());
    for event in events {
        normalized_events.push(agent_bridge_import::LegacyEventSnapshot {
            sequence:event["sequence"].as_i64().filter(|sequence|*sequence>0)
                .ok_or("INVALID_SOURCE_SEQUENCE")?,
            event_type:text(event,"event_type")?,summary:text(event,"summary")?,
        });
    }
    let mut normalized_steps=Vec::with_capacity(steps.len());
    for step in steps {
        normalized_steps.push(agent_bridge_import::LegacyStepSnapshot {
            step_id:text(step,"id")?,title:text(step,"title")?,state:text(step,"status")?,
        });
    }
    let snapshot=agent_bridge_import::LegacyTaskSnapshot {
        provider:"agent-bridge".into(),context_id:context.into(),task_id:task_id.into(),
        goal,status:text(task,"status")?,
        total_events_reported:i32::try_from(source["total_events_reported"].as_i64()
            .ok_or("INVALID_SOURCE_TOTAL")?).map_err(|_|"SOURCE_TOTAL_EXCEEDS_IMPORT_BOUND")?,
        events:normalized_events,steps:normalized_steps,
    };
    Ok(serde_json::to_value(agent_bridge_import::import_snapshot(conn,&snapshot)?)?)
}

#[cfg(test)]
fn list_allowed_commands(settings: &Path) -> Result<Value, RuntimeError> {
    crate::command_catalogue::CommandCatalogueSnapshot::load(settings)?.names()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_bridge_core::CoreDatabase;
    use agent_bridge_desktop::DesktopProfile;
    use agent_bridge_gateway::{GatewayConfig, McpGateway};
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct TestRoot(PathBuf);
    impl Drop for TestRoot { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
    struct Fixture {
        router: McpGateway<ToolMapHandler>,
        database: SharedCoreDatabase,
        profile: ProfileControl,
        binding: String,
        root: TestRoot,
    }
    impl Fixture {
        fn new(allow_import: bool) -> Self {
            let base = crate::test_state_base();
            let root = TestRoot(base.join(format!("unified-core-{}-{}",std::process::id(),
                NEXT.fetch_add(1,Ordering::Relaxed))));
            std::fs::create_dir_all(root.0.join("project")).unwrap();
            agent_bridge_lifecycle::initialize_operator_settings(&root.0.join("settings")).unwrap();
            let database = Arc::new(Mutex::new(CoreDatabase::initialize_new(&root.0.join("core.db")).unwrap()));
            agent_bridge_missions::task_room::init_schema(database.lock().unwrap().connection_mut()).unwrap();
            let binding = crate::runtime::task_room_workspace_binding(&std::fs::canonicalize(root.0.join("project")).unwrap()).unwrap();
            let profile = ProfileControl::new(DesktopProfile::FullyUnlocked);
            let mut catalogue = Vec::new(); let mut handlers = ToolMapHandler::new();
            attach(database.clone(),&std::fs::canonicalize(root.0.join("project")).unwrap(),
                Arc::new(crate::command_catalogue::CommandCatalogueSnapshot::load(&root.0.join("settings")).unwrap()),
                profile.clone(),allow_import,&mut catalogue,&mut handlers)
                .expect("real Core handlers must be composed over the shared owner");
            assert_eq!(catalogue.len(),17);
            Self {router:McpGateway::new(GatewayConfig::new("core-fixture","1"),catalogue,handlers),
                database,profile,binding,root}
        }
        fn call(&self,name:&str,args:Value)->Value {
            serde_json::from_str(&self.router.handle_str(&json!({"jsonrpc":"2.0","id":1,
                "method":"tools/call","params":{"name":name,"arguments":args}}).to_string())
                .unwrap()).unwrap()
        }
        fn success(&self,name:&str,args:Value)->Value {
            let reply=self.call(name,args);
            assert!(reply.get("error").is_none() && reply["result"]["isError"]!=true,"{reply}");
            serde_json::from_str(reply["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
        }
        fn source(&self)->(Value,Value) {
            let mut database=self.database.lock().unwrap();
            let conn=database.connection_mut();
            let context=agent_bridge_missions::task_room::dispatch_scoped(conn,
                &json!({"action":"context_create","context_label":"Synthetic import"}),&self.binding).unwrap();
            let task=agent_bridge_missions::task_room::dispatch_scoped(conn,
                &json!({"action":"create","context_handle":context["context_handle"],"title":"Safe historical task",
                    "goal":"Read-only source","steps":[{"id":"s1","title":"Historical only"}]}),&self.binding).unwrap();
            (context,task)
        }
    }
    fn denied(reply:&Value)->bool { reply.get("error").is_some() || reply["result"]["isError"]==true }

    #[test]
    fn capability_core_mcp_preserves_actor_membership_revision_and_live_profile() {
        let fixture=Fixture::new(true);
        let first=fixture.success("agent_bridge_context_create",json!({}));
        let other=fixture.success("agent_bridge_context_create",json!({}));
        let args=json!({"actor_context_handle":first["context_handle"],"goal":"Synthetic mission","idempotency_key":"once"});
        let created=fixture.success("agent_bridge_mission_create",args.clone());
        assert_eq!(fixture.success("agent_bridge_mission_create",args)["mission_id"],created["mission_id"]);
        let own=json!({"actor_context_handle":first["context_handle"],"mission_id":created["mission_id"]});
        assert_eq!(fixture.success("agent_bridge_mission_get",own.clone())["mission_id"],created["mission_id"]);
        assert!(denied(&fixture.call("agent_bridge_mission_get",json!({
            "actor_context_handle":other["context_handle"],"mission_id":created["mission_id"]}))));
        assert!(denied(&fixture.call("agent_bridge_mission_checkpoint",json!({
            "actor_context_handle":first["context_handle"],"mission_id":created["mission_id"],
            "if_revision":999,"summary":"stale"}))));
        fixture.profile.set(DesktopProfile::ReadOnly).unwrap();
        assert_eq!(fixture.success("agent_bridge_mission_get",own)["mission_id"],created["mission_id"]);
        assert!(denied(&fixture.call("agent_bridge_context_create",json!({}))));
        assert!(denied(&fixture.call("agent_bridge_mission_checkpoint",json!({
            "actor_context_handle":first["context_handle"],"mission_id":created["mission_id"],
            "if_revision":created["revision"],"summary":"must not mutate"}))));
    }

    #[test]
    fn capability_task_import_mcp_is_exact_bounded_idempotent_and_does_not_modify_source() {
        let fixture=Fixture::new(true);
        let actor=fixture.success("agent_bridge_context_create",json!({}));
        let (context,task)=fixture.source();
        let source_args=json!({"action":"get","context_handle":context["context_handle"],
            "task_id":task["task"]["task_id"]});
        let before=agent_bridge_missions::task_room::dispatch_scoped(
            fixture.database.lock().unwrap().connection_mut(),&source_args,&fixture.binding).unwrap();
        let args=json!({"actor_context_handle":actor["context_handle"],"context_id":context["context_id"],
            "context_handle":context["context_handle"],"task_id":task["task"]["task_id"]});
        let imported=fixture.success("agent_bridge_task_import",args.clone());
        assert_eq!(fixture.success("agent_bridge_task_import",args.clone()),imported);
        let history=agent_bridge_import::read_imported_events(
            fixture.database.lock().unwrap().connection(),imported["mission_id"].as_str().unwrap()).unwrap();
        assert_eq!(history.len(),1);
        let after=agent_bridge_missions::task_room::dispatch_scoped(
            fixture.database.lock().unwrap().connection_mut(),&source_args,&fixture.binding).unwrap();
        assert_eq!(before,after,"import is a read of the source Task Room");
        for (field,value) in [("context_id",json!("trctx_wrong")),("context_handle",actor["context_handle"].clone()),
            ("task_id",json!("task_wrong")),("actor_context_handle",json!("ctx_00000000000000000000000000000000")),
            ("path",json!("C:/private/snapshot.json"))] {
            let mut invalid=args.clone(); invalid[field]=value;
            assert!(denied(&fixture.call("agent_bridge_task_import",invalid)),"{field}");
        }
        let other_project=fixture.root.0.join("another-project");
        std::fs::create_dir(&other_project).unwrap();
        let mut other_catalogue=Vec::new(); let mut other_handlers=ToolMapHandler::new();
        attach(fixture.database.clone(),&std::fs::canonicalize(&other_project).unwrap(),
            Arc::new(crate::command_catalogue::CommandCatalogueSnapshot::load(&fixture.root.0.join("settings")).unwrap()),
            fixture.profile.clone(),true,
            &mut other_catalogue,&mut other_handlers).unwrap();
        let other_router=McpGateway::new(GatewayConfig::new("other-project","1"),other_catalogue,other_handlers);
        let wrong_project:Value=serde_json::from_str(&other_router.handle_str(&json!({
            "jsonrpc":"2.0","id":1,"method":"tools/call","params":{
                "name":"agent_bridge_task_import","arguments":args}}).to_string()).unwrap()).unwrap();
        assert!(denied(&wrong_project),"a valid Task Room handle must stay bound to its physical project");
        agent_bridge_missions::task_room::dispatch_scoped(
            fixture.database.lock().unwrap().connection_mut(),
            &json!({"action":"checkpoint","context_handle":context["context_handle"],
                "task_id":task["task"]["task_id"],"summary":"Source evolved explicitly in fixture"}),
            &fixture.binding).unwrap();
        assert!(denied(&fixture.call("agent_bridge_task_import",args.clone())),
            "a changed source snapshot must conflict rather than overwrite an existing import");
        fixture.profile.set(DesktopProfile::ReadOnly).unwrap();
        assert!(denied(&fixture.call("agent_bridge_task_import",args)));
        // Import cannot implicitly enroll the caller as owner of historical effects.
        assert!(denied(&fixture.call("agent_bridge_mission_get",json!({
            "actor_context_handle":actor["context_handle"],"mission_id":imported["mission_id"]}))));
    }

    #[test]
    fn capability_task_import_requires_explicit_local_selection() {
        let fixture=Fixture::new(false);
        let actor=fixture.success("agent_bridge_context_create",json!({}));
        let (context,task)=fixture.source();
        assert!(denied(&fixture.call("agent_bridge_task_import",json!({
            "actor_context_handle":actor["context_handle"],"context_id":context["context_id"],
            "context_handle":context["context_handle"],"task_id":task["task"]["task_id"]}))));
        let count:i64=fixture.database.lock().unwrap().connection().query_row(
            "SELECT COUNT(*) FROM imports",[],|row|row.get(0)).unwrap();
        assert_eq!(count,0);
    }

    #[test]
    fn capability_allowed_commands_exposes_sorted_names_without_execution_details() {
        let fixture=Fixture::new(true);
        let settings=fixture.root.0.join("settings");
        let path=settings.join("commands.json");
        let configuration=json!({"version":1,"programs":{
            "zeta":{"executable":"C:/private/tool.exe","arguments":["private-argument"]},
            "alpha":{"executable":"C:/another/private.exe","arguments":[]}}});
        std::fs::write(&path,configuration.to_string()).unwrap();
        let names=list_allowed_commands(&settings).unwrap();
        assert_eq!(names,json!({"commands":["alpha","zeta"],"catalog_present":true}));
        assert!(denied(&fixture.call("desktop_list_allowed_commands",json!({"path":"C:/"}))));
        std::fs::remove_file(&path).unwrap();
        assert_eq!(list_allowed_commands(&settings).unwrap(),
            json!({"commands":[],"catalog_present":false}));
        std::fs::write(&path,vec![b' ';65537]).unwrap();
        assert!(list_allowed_commands(&settings).is_err());
    }

    #[test]
    fn capability_fix_import_distinguishes_repeated_truncated_events() {
        let fixture=Fixture::new(true);
        let actor=fixture.success("agent_bridge_context_create",json!({}));
        let (context,task)=fixture.source();
        let checkpoint=json!({"action":"checkpoint","context_handle":context["context_handle"],
            "task_id":task["task"]["task_id"],"summary":"Repeated historical checkpoint"});
        for _ in 0..55 {
            agent_bridge_missions::task_room::dispatch_scoped(
                fixture.database.lock().unwrap().connection_mut(),&checkpoint,&fixture.binding).unwrap();
        }
        let args=json!({"actor_context_handle":actor["context_handle"],"context_id":context["context_id"],
            "context_handle":context["context_handle"],"task_id":task["task"]["task_id"]});
        let imported=fixture.success("agent_bridge_task_import",args.clone());
        assert_eq!(fixture.success("agent_bridge_task_import",args.clone()),imported);
        let (history,total)={
            let database=fixture.database.lock().unwrap();
            let history=agent_bridge_import::read_imported_events(database.connection(),
                imported["mission_id"].as_str().unwrap()).unwrap();
            let total:i64=database.connection().query_row(
                "SELECT COUNT(*) FROM task_room_events WHERE task_id=?1",
                [task["task"]["task_id"].as_str().unwrap()],|row|row.get(0)).unwrap();
            (history,total)
        };
        assert_eq!(history.len(),50);
        assert_eq!(history.first().unwrap().sequence,total-49);
        assert_eq!(history.last().unwrap().sequence,total);
        assert_eq!(imported["partial_history"],true);
        agent_bridge_missions::task_room::dispatch_scoped(
            fixture.database.lock().unwrap().connection_mut(),&checkpoint,&fixture.binding).unwrap();
        assert!(denied(&fixture.call("agent_bridge_task_import",args)),
            "a newer event with identical text beyond the visible fifty must not become an idempotent duplicate");
    }

    #[test]
    fn capability_fix_selected_command_bytes_are_not_reloaded_at_dispatch() {
        use agent_bridge_gateway::ToolHandler;
        let fixture=Fixture::new(true);
        let settings=fixture.root.0.join("settings");
        let original=json!({"version":1,"programs":{"sealed-command":{"executable":"C:/sealed/tool.exe"}}});
        let replacement=json!({"version":1,"programs":{"replacement-command":{"executable":"C:/replacement/tool.exe"}}});
        std::fs::write(settings.join("commands.json"),original.to_string()).unwrap();
        let mut catalogue=Vec::new();let mut handlers=ToolMapHandler::new();
        attach(fixture.database.clone(),&std::fs::canonicalize(fixture.root.0.join("project")).unwrap(),
            Arc::new(crate::command_catalogue::CommandCatalogueSnapshot::load(&settings).unwrap()),
            fixture.profile.clone(),true,&mut catalogue,&mut handlers).unwrap();
        // Selection is complete. Replace the file before the real handler
        // consumes the selected catalogue, rather than before validation.
        std::fs::write(settings.join("commands.json"),replacement.to_string()).unwrap();
        let response=handlers.call("desktop_list_allowed_commands",serde_json::Map::new()).unwrap();
        let response=serde_json::to_value(response).unwrap();
        let value:Value=serde_json::from_str(response["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(value["commands"],json!(["sealed-command"]),
            "the bound view must consume only the bytes used to select its command authority");
    }

}
