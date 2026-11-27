//! Opt-in member route for the single operator-selected maintenance mandate.
//! No web thread navigation, arbitrary targets, processes, or new worker.
use crate::{capability_manifest::AttemptSelection, command_catalogue::CommandCatalogueSnapshot,
    runtime::{RuntimeError, SharedCoreDatabase}, session_profile::ProfileControl};
use agent_bridge_gateway::{ToolDefinition, ToolMapHandler};
use std::{path::Path, sync::Arc};

pub(crate) const TOOL_NAME: &str = "agent_bridge_mission_attempt";

#[cfg(windows)]
mod platform {
    use super::*;
    use agent_bridge_desktop::DesktopProfile;
    use agent_bridge_gateway::{ToolCallResult, ToolDispatchError};
    use agent_bridge_missions::{attempts::{BlockReason, Coordinator, LocalMandate, ReviewDecision},
        AuthenticatedContext, BridgeError};
    use serde_json::{json, Map, Value};

    fn text<'a>(fields:&'a Map<String,Value>,key:&str)->Result<&'a str,BridgeError>{
        fields.get(key).and_then(Value::as_str).filter(|s|!s.is_empty()&&s.len()<=256)
            .ok_or_else(||BridgeError::new("INVALID_PAYLOAD","Missing or invalid attempt field."))
    }
    fn dispatch(
        conn:&mut agent_bridge_core::CoreDatabase, plan:&LocalMandate, fields:Map<String,Value>,
        read_head:impl FnOnce()->Result<String,BridgeError>,
    )->Result<Value,BridgeError>{
        let action=text(&fields,"action")?;
        let expected:&[&str]=match action {
            "get"=>&["action","actor_context_handle"],
            "prepare"=>&["action","actor_context_handle","if_revision","idempotency_key"],
            "claim"|"heartbeat"|"verify"|"recover"=>&["action","actor_context_handle","attempt_id","if_revision","idempotency_key"],
            "block"=>&["action","actor_context_handle","attempt_id","if_revision","idempotency_key","reason"],
            "review"=>&["action","actor_context_handle","attempt_id","if_revision","idempotency_key","receipt_id","decision"],
            _=>return Err(BridgeError::new("INVALID_PAYLOAD","Unsupported attempt action.")),
        };
        if fields.len()!=expected.len() || fields.keys().any(|key|!expected.contains(&key.as_str())){
            return Err(BridgeError::new("INVALID_PAYLOAD","Unexpected attempt argument."));
        }
        let actor=text(&fields,"actor_context_handle")?;
        let identity=AuthenticatedContext::authenticate(conn.connection(),actor)?;
        let coordinator=Coordinator::default();
        let answer=if action=="get" {
            json!({"mandate":"verify_local_git_head_v1","plan":plan,
                "observation":coordinator.get(conn.connection(),actor,plan)?})
        }else{
            let revision=fields.get("if_revision").and_then(Value::as_i64)
                .filter(|r|(1..=9_007_199_254_740_991).contains(r))
                .ok_or_else(||BridgeError::new("INVALID_PAYLOAD","Observed safe revision required."))?;
            let key=text(&fields,"idempotency_key")?;
            let conn=conn.connection_mut();
            let result=if action=="prepare"{coordinator.prepare(conn,actor,plan,revision,key)?}
            else {
                let id=text(&fields,"attempt_id")?;
                match action {
                    "claim"=>coordinator.claim(conn,actor,plan,id,revision,key)?,
                    "heartbeat"=>coordinator.heartbeat(conn,actor,plan,id,revision,key)?,
                    "verify"=>coordinator.verify_base(conn,actor,plan,id,revision,key,read_head)?,
                    "recover"=>coordinator.recover_unknown(conn,actor,plan,id,revision,key)?,
                    "block"=>{
                        let reason=match text(&fields,"reason")?{
                            "quota"=>BlockReason::Quota,"approval"=>BlockReason::Approval,
                            "unknown"=>BlockReason::Unknown,
                            _=>return Err(BridgeError::new("INVALID_PAYLOAD","Unknown blocker category.")),
                        };
                        coordinator.block(conn,actor,plan,id,revision,key,reason)?
                    }
                    "review"=>{
                        let decision=match text(&fields,"decision")?{
                            "pass"=>ReviewDecision::Pass,"failed"=>ReviewDecision::Failed,
                            _=>return Err(BridgeError::new("INVALID_PAYLOAD","Unknown review decision.")),
                        };
                        coordinator.review(conn,actor,plan,id,revision,key,text(&fields,"receipt_id")?,decision)?
                    }
                    _=>unreachable!(),
                }
            };
            serde_json::to_value(result).map_err(|_|BridgeError::new("INTERNAL_ERROR","Attempt receipt encoding failed."))?
        };
        // Existing context activity throttle and session link, not an
        // independent provider heartbeat or synthetic live session.
        identity.observe_attached_mission_success(conn.connection(), &plan.mission_id, crate::client_sessions::link_activity);
        Ok(answer)
    }

    pub(super) fn attach(
        selection:&AttemptSelection,root:&Path,settings:&Path,database_path:&Path,
        database:SharedCoreDatabase,commands:Arc<CommandCatalogueSnapshot>,profile:ProfileControl,
        catalogue:&mut Vec<ToolDefinition>,handlers:&mut ToolMapHandler,
    )->Result<(),RuntimeError>{
        if !profile.allows(DesktopProfile::FullControl) {
            return Err("ATTEMPT_PROFILE_CEILING_REFUSED".into());
        }
        // Fixed preapproved diagnostic is a prerequisite, not a fallback
        // grant to arbitrary Git invocations or another worktree.
        crate::terminal::qualify_attempt_revision(settings,root,&commands)?;
        let binding=crate::runtime::task_room_workspace_binding(root)?;
        let plan=LocalMandate::from_qualified_workspace(selection.mission_id.clone(),
            selection.subtask_id.clone(),&binding,selection.base_commit.clone())
            .map_err(|_|"ATTEMPT_MANDATE_INVALID")?;
        let root=root.to_owned(); let settings=settings.to_owned(); let database_path=database_path.to_owned();
        catalogue.push(ToolDefinition::new(TOOL_NAME,Some(
            "Coordinate the one operator-approved local HEAD verification attempt. Read, prepare, claim, heartbeat, block, verify, recover unknown or independently review. No commands, targets, or provider inputs.".into()),
            json!({"type":"object","additionalProperties":false,"properties":{
                "action":{"type":"string","enum":["get","prepare","claim","heartbeat","block","verify","recover","review"]},
                "actor_context_handle":{"type":"string","minLength":36,"maxLength":36},
                "attempt_id":{"type":"string","pattern":"^att_[0-9a-f]{32}$"},
                "if_revision":{"type":"integer","minimum":1,"maximum":9007199254740991_i64},
                "idempotency_key":{"type":"string","minLength":1,"maxLength":256},
                "reason":{"type":"string","enum":["quota","approval","unknown"]},
                "receipt_id":{"type":"string","pattern":"^rcpt_[0-9a-f]{32}$"},
                "decision":{"type":"string","enum":["pass","failed"]}
            },"required":["action","actor_context_handle"]})));
        handlers.register(TOOL_NAME,move |fields|{
            // Keep the live read guard over the single synchronous effect.
            let active=profile.read().map_err(|_|ToolDispatchError::internal("PROFILE_STATE_UNAVAILABLE"))?;
            if fields.get("action").and_then(Value::as_str)!=Some("get")
                && crate::session_profile::rank(*active)<crate::session_profile::rank(DesktopProfile::FullControl) {
                return Ok(ToolCallResult::tool_error("ATTEMPT_PROFILE_REFUSED"));
            }
            let current=crate::runtime::task_room_workspace_binding(&root)
                .map_err(|_|ToolDispatchError::internal("ATTEMPT_WORKTREE_UNAVAILABLE"))?;
            if current!=binding {
                return Ok(ToolCallResult::tool_error("ATTEMPT_WORKTREE_CHANGED"));
            }
            let _pin=match agent_bridge_lifecycle::workspace_access::PinnedProjectDirectory::open(&root){
                Ok(pin)=>pin,Err(_)=>return Ok(ToolCallResult::tool_error("ATTEMPT_WORKTREE_UNAVAILABLE")),
            };
            if crate::runtime::task_room_workspace_binding(&root).ok().as_deref()!=Some(binding.as_str()) {
                return Ok(ToolCallResult::tool_error("ATTEMPT_WORKTREE_CHANGED"));
            }
            let mut db=database.lock().map_err(|_|ToolDispatchError::internal("CORE_UNAVAILABLE"))?;
            let result=dispatch(&mut db,&plan,fields,||
                crate::terminal::verify_attempt_revision(&settings,&root,&database_path,&commands)
                    .map_err(|_|BridgeError::new("ATTEMPT_RECONCILIATION_REQUIRED","Local verification result uncertain.")));
            Ok(match result {
                Ok(answer)=>ToolCallResult::text(answer.to_string()),
                Err(error)=>ToolCallResult::tool_error(error.code),
            })
        });
        Ok(())
    }
}

pub(crate) fn attach(
    selection:&AttemptSelection,root:&Path,settings:&Path,database_path:&Path,
    database:SharedCoreDatabase,commands:Arc<CommandCatalogueSnapshot>,profile:ProfileControl,
    catalogue:&mut Vec<ToolDefinition>,handlers:&mut ToolMapHandler,
)->Result<(),RuntimeError>{
    #[cfg(windows)]
    { platform::attach(selection,root,settings,database_path,database,commands,profile,catalogue,handlers) }
    #[cfg(not(windows))]
    {
        let _=(selection,root,settings,database_path,database,commands,profile,catalogue,handlers);
        Err("ATTEMPT_PLATFORM_UNQUALIFIED".into())
    }
}
