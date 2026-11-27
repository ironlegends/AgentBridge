//! Agent Bridge durable mission engine for Windows and Unix.
//!
//! This is a pure business layer: the caller supplies an already-open, idle,
//! private SQLite v7 connection. This crate operates on that connection and does not start external programs.
//!
//! Public entry points:
//! - typed APIs in mission / subtask;
//! - dispatch_tool for the JSON arguments of gateway/src/bridge-extras.mjs;
//! - dispatch_rpc / dispatch_rpc_envelope for Core's JSON RPC v1 method names.
//!
//! The adapter must preserve the context handle as a SECRET capability. A
//! public ctx_* ID is not an authenticator. Neither transport retries writes
//! after uncertain delivery; callers must inspect/reconcile first.

pub mod mission;
pub mod operator;
pub mod subtask;
pub mod task_room;
mod store;

use chrono::{DateTime, FixedOffset, Utc};
use rusqlite::Connection;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};

pub use store::{
    create_context, valid_id, verify_schema, BridgeError, ContextCreated, MissionDto, Result,
    SCHEMA_VERSION,
};

use crate::mission::{
    attach_mission, checkpoint_mission, create_mission, get_mission, grant_mission,
    list_missions, observe_mission, recent_checkpoints, set_orchestrator,
    transfer_mission, transition_mission, CreateMissionRequest, HandoffRequest,
    MissionFilter, TransitionMissionRequest,
};
use crate::store::{invalid, new_id, require_text};
use crate::subtask::{
    assign_subtask, create_subtask, list_subtasks, update_subtask,
    AssignSubtaskRequest, CreateSubtaskRequest, ListSubtasksRequest, UpdateSubtaskRequest,
};

/// Same error/result shape as AgentBridge.Contracts.RpcResult<T>.
#[derive(Serialize)]
pub struct RpcReply {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<BridgeError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<i64>,
}
impl RpcReply {
    fn success(result: Value) -> Self {
        Self { ok: true, result: Some(result), error: None, revision: None }
    }
    fn failure(error: BridgeError) -> Self {
        Self { ok: false, result: None, error: Some(error), revision: None }
    }
}

fn decode<T: DeserializeOwned>(value: &Value) -> Result<T> {
    serde_json::from_value(value.clone())
        .map_err(|_| invalid("Malformed or missing structured RPC payload."))
}
fn to_value<T: Serialize>(value: T) -> Result<Value> {
    serde_json::to_value(value)
        .map_err(|_| BridgeError::new("INTERNAL_ERROR", "Cannot serialize mission result."))
}
fn required<'a>(value: &'a Value, key: &'static str) -> Result<&'a str> {
    value.get(key).and_then(Value::as_str)
        .ok_or_else(|| invalid("Missing or invalid string argument."))
}
fn maybe_int(value: &Value, key: &str, default: i64) -> Result<i64> {
    match value.get(key) {
        None => Ok(default),
        Some(number) => number.as_i64().ok_or_else(|| invalid("Expected integer argument.")),
    }
}
fn optional_bool(value: &Value, key: &str) -> Result<bool> {
    match value.get(key) {
        None => Ok(false),
        Some(flag) => flag.as_bool().ok_or_else(|| invalid("Expected boolean argument.")),
    }
}
fn check_rpc_request(request: &Value, method: &str) -> Result<()> {
    // Exact JSON transport body length, including method + request envelope.
    let payload_size = serde_json::to_vec(&json!({"method":method,"request":request}))?.len();
    if payload_size > 1024 * 1024 {
        return Err(invalid("Agent Bridge RPC request exceeds 1 MiB."));
    }
    if required(request, "api_version")? != "1" {
        return Err(BridgeError::new("UPGRADE_INCOMPATIBLE", "Unsupported Agent Bridge API version."));
    }
    require_text(required(request, "request_id")?, 128, "request_id must be 1-128 characters.")?;
    if request.get("payload").is_none() {
        return Err(invalid("RPC payload is required."));
    }
    if let Some(deadline) = request.get("deadline") {
        if !deadline.is_null() {
            let time = DateTime::<FixedOffset>::parse_from_rfc3339(
                deadline.as_str().ok_or_else(|| invalid("Invalid deadline."))?
            ).map_err(|_| invalid("Invalid deadline."))?;
            if time <= Utc::now() {
                return Err(BridgeError {
                    code: "DEADLINE_EXCEEDED",
                    message: "The request deadline has expired.".into(),
                    retryable: true,
                });
            }
        }
    }
    Ok(())
}

/// Dispatch an Agent Bridge Core v1 RPC method against the supplied connection.
/// Never catches, logs, or exposes the caller's private handle in errors.
pub fn dispatch_rpc(conn: &mut Connection, method: &str, request: &Value) -> RpcReply {
    let result = (|| {
        check_rpc_request(request, method)?;
        let payload = &request["payload"];
        let actor = request.get("actor_context_handle").and_then(Value::as_str);
        dispatch_core(conn, method, payload, actor, |_| {})
    })();
    match result {
        Ok(result) => RpcReply::success(result),
        Err(error) => RpcReply::failure(error),
    }
}

/// Dispatch the wire envelope {method,request} accepted by the Windows named
/// pipe and Unix stdio Core transports. Frame encoding is the host's concern.
pub fn dispatch_rpc_envelope(conn: &mut Connection, envelope: &Value) -> RpcReply {
    let method = match envelope.get("method").and_then(Value::as_str) {
        Some(method) => method,
        None => return RpcReply::failure(invalid("Missing RPC method.")),
    };
    match envelope.get("request") {
        Some(request) => dispatch_rpc(conn, method, request),
        None => RpcReply::failure(invalid("Missing RPC request.")),
    }
}

/// A registered mission actor authenticated without writing activity.
pub struct AuthenticatedContext(String);

impl AuthenticatedContext {
    pub fn authenticate(conn: &Connection, handle: &str) -> Result<Self> {
        verify_schema(conn)?;
        Ok(Self(store::require_context(conn, handle)?))
    }

    /// Record activity on the same Core connection after the caller's operation succeeds.
    pub fn observe_success(self, conn: &Connection, observe_context: impl FnOnce(&str)) {
        if let Some(context_id) = store::note_context_use(conn, &self.0) {
            observe_context(&context_id);
        }
    }
}

fn dispatch_core(
    conn: &mut Connection, method: &str, payload: &Value,
    actor_handle: Option<&str>, observe_context: impl FnOnce(&str),
) -> Result<Value> {
    // Always check the source-owned v7 schema BEFORE authorization or mutation.
    // No implicit migration, DB creation, or permission escalation.
    verify_schema(conn)?;
    if method == "System.Health" {
        return Ok(json!({"status":"healthy","schema_version":SCHEMA_VERSION}));
    }
    if method == "Context.Create" {
        if required(payload, "actor_kind")? != "chatgpt" {
            return Err(invalid("Only the Agent Bridge chatgpt actor kind is supported."));
        }
        let context = create_context(conn)?;
        let result = to_value(&context)?;
        observe_context(&context.context_id);
        return Ok(result);
    }
    let actor = actor_handle.ok_or_else(|| {
        BridgeError::new("SECURITY_DENIED", "A private actor_context_handle is required.")
    })?;
    // Even methods returning no mission data require a real registered context.
    let context = AuthenticatedContext(store::require_context(conn, actor)?);

    let result = match method {
        "Mission.Create" => to_value(create_mission(conn, actor, decode::<CreateMissionRequest>(payload)?)?),
        "Mission.Get" => to_value(get_mission(conn, actor, required(payload, "mission_id")?)?),
        "Mission.List" => {
            let filter = if payload.is_object() { decode::<MissionFilter>(payload)? }
                         else { MissionFilter::default() };
            to_value(list_missions(conn, actor, filter)?)
        }
        "Mission.Observe" => to_value(observe_mission(
            conn, actor, required(payload, "mission_id")?
        )?),
        "Mission.Grant" => to_value(grant_mission(conn, actor, decode::<HandoffRequest>(payload)?)?),
        "Mission.Attach" => to_value(attach_mission(
            conn, actor, required(payload, "mission_id")?,
            maybe_int(payload, "if_revision", 0)?
        )?),
        "Mission.Transfer" => to_value(transfer_mission(conn, actor, decode::<HandoffRequest>(payload)?)?),
        "Mission.Checkpoint" => to_value(checkpoint_mission(
            conn, actor, required(payload, "mission_id")?,
            required(payload, "summary")?, maybe_int(payload, "if_revision", 0)?
        )?),
        "Mission.Checkpoints" => to_value(recent_checkpoints(
            conn, actor, required(payload, "mission_id")?,
            maybe_int(payload, "limit", 20)?
        )?),
        "Mission.SetOrchestrator" => to_value(set_orchestrator(
            conn, actor, required(payload, "mission_id")?,
            optional_bool(payload, "enabled")?, maybe_int(payload, "if_revision", 0)?
        )?),
        "Mission.Transition" => to_value(transition_mission(
            conn, actor, decode::<TransitionMissionRequest>(payload)?
        )?),
        "Mission.Subtask.Create" => to_value(create_subtask(
            conn, actor, decode::<CreateSubtaskRequest>(payload)?
        )?),
        "Mission.Subtask.Assign" => to_value(assign_subtask(
            conn, actor, decode::<AssignSubtaskRequest>(payload)?
        )?),
        "Mission.Subtask.Update" => to_value(update_subtask(
            conn, actor, decode::<UpdateSubtaskRequest>(payload)?
        )?),
        "Mission.Subtask.List" => to_value(list_subtasks(
            conn, actor, decode::<ListSubtasksRequest>(payload)?
        )?),
        // These belong to other Agent Bridge porting lots and are denied, not faked.
        "System.Capabilities" | "TaskRoom.ImportSnapshot"
        | "Desktop.Acquire" | "Resource.Acquire" | "Resource.Renew"
        | "Resource.Release" | "Resource.IsCurrent" | "Step.Schedule"
        | "Step.RunReady" | "Step.EmergencyStop" | "Workspace.Create"
        | "Workspace.Inspect" | "Workspace.Release" | "Workspace.Integrate" =>
            Err(BridgeError::new("CAPABILITY_UNAVAILABLE",
                "This isolated missions crate does not provide the requested host capability.")),
        _ => Err(BridgeError::new("METHOD_NOT_FOUND", "Unsupported Agent Bridge RPC method.")),
    }?;
    context.observe_success(conn, observe_context);
    Ok(result)
}

fn tool_contract(name: &str) -> Result<(&'static str, &'static [&'static str])> {
    // Exact JSON argument keys from gateway/src/bridge-extras.mjs.
    // Unknown keys are rejected for the public MCP tool-names entry point.
    let contract: (&'static str, &'static [&'static str]) = match name {
        "agent_bridge_status" => ("System.Health", &[]),
        "agent_bridge_context_create" => ("Context.Create", &[]),
        "agent_bridge_mission_create" => ("Mission.Create",
            &["actor_context_handle","goal","idempotency_key"]),
        "agent_bridge_mission_get" => ("Mission.Get",
            &["actor_context_handle","mission_id"]),
        "agent_bridge_mission_list" => ("Mission.List",
            &["actor_context_handle","limit"]),
        "agent_bridge_mission_observe" => ("Mission.Observe",
            &["actor_context_handle","mission_id"]),
        "agent_bridge_mission_grant" => ("Mission.Grant",
            &["actor_context_handle","mission_id","if_revision","target_context_id"]),
        "agent_bridge_mission_attach" => ("Mission.Attach",
            &["actor_context_handle","mission_id","if_revision"]),
        "agent_bridge_mission_transfer" => ("Mission.Transfer",
            &["actor_context_handle","mission_id","if_revision","target_context_id"]),
        "agent_bridge_mission_checkpoints" => ("Mission.Checkpoints",
            &["actor_context_handle","mission_id","limit"]),
        "agent_bridge_mission_checkpoint" => ("Mission.Checkpoint",
            &["actor_context_handle","mission_id","summary","if_revision"]),
        "agent_bridge_mission_subtask_create" => ("Mission.Subtask.Create",
            &["actor_context_handle","mission_id","goal","idempotency_key","assignee_context_id"]),
        "agent_bridge_mission_subtask_assign" => ("Mission.Subtask.Assign",
            &["actor_context_handle","mission_id","subtask_id","assignee_context_id",
              "if_revision","idempotency_key"]),
        "agent_bridge_mission_subtask_update" => ("Mission.Subtask.Update",
            &["actor_context_handle","mission_id","subtask_id","if_revision",
              "status","summary","idempotency_key"]),
        "agent_bridge_mission_subtask_list" => ("Mission.Subtask.List",
            &["actor_context_handle","mission_id","subtask_id","limit","after_created_revision"]),
        "agent_bridge_mission_complete" => ("Mission.Transition",
            &["actor_context_handle","mission_id","if_revision","idempotency_key"]),
        _ => return Err(BridgeError::new("METHOD_NOT_FOUND", "Unknown Agent Bridge tool name.")),
    };
    Ok(contract)
}

/// Dispatch a named Gateway MCP mission tool with its plain JSON arguments.
/// Returns the *result object* (not the MCP content wrapper); errors are typed.
/// Network and transport adapters must not retry uncertain writes automatically.
pub fn dispatch_tool(conn: &mut Connection, tool_name: &str, args: &Value) -> Result<Value> {
    dispatch_tool_observed(conn, tool_name, args, |_| {})
}

/// Observe only the public ID of an authenticated context after a successful operation.
pub fn dispatch_tool_observed(
    conn: &mut Connection, tool_name: &str, args: &Value, observe_context: impl FnOnce(&str),
) -> Result<Value> {
    let (method, allowed) = tool_contract(tool_name)?;
    let object = args.as_object().ok_or_else(|| invalid("Tool arguments must be a JSON object."))?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid("Unknown argument for Agent Bridge tool."));
    }
    if serde_json::to_vec(args)?.len() > 1024 * 1024 {
        return Err(invalid("Tool arguments exceed 1 MiB."));
    }
    // The Gateway accepts only JavaScript-safe integers for these fields.
    // Preserve that boundary even when this Rust API is called directly.
    for (field, minimum) in [("if_revision", 1), ("after_created_revision", 0)] {
        if let Some(raw) = args.get(field) {
            let value = raw.as_i64().ok_or_else(|| invalid("Expected a safe integer."))?;
            if value < minimum || value > 9_007_199_254_740_991 {
                return Err(invalid("Tool revision is outside the safe integer range."));
            }
        }
    }
    let actor = args.get("actor_context_handle").and_then(Value::as_str);
    if !matches!(method, "System.Health" | "Context.Create") {
        let actor_handle = actor.ok_or_else(|| invalid("Missing private context handle."))?;
        if !valid_id("ctx", actor_handle) {
            return Err(BridgeError::new("SECURITY_DENIED", "Invalid private context handle."));
        }
    }

    let mut payload = args.clone();
    let data = payload.as_object_mut().ok_or_else(|| invalid("Tool requires an object."))?;
    match tool_name {
        "agent_bridge_context_create" => { data.insert("actor_kind".into(), json!("chatgpt")); }
        "agent_bridge_mission_create" => {
            data.insert("operation_id".into(), json!(new_id("op")));
        }
        "agent_bridge_mission_complete" => {
            data.insert("operation_id".into(), json!(new_id("op")));
            data.insert("to_status".into(), json!("completed"));
        }
        "agent_bridge_mission_list" | "agent_bridge_mission_checkpoints" => {
            let limit = maybe_int(args, "limit", 20)?;
            if !(1..=100).contains(&limit) {
                return Err(invalid("Tool list limit must be 1-100."));
            }
            data.insert("limit".into(), json!(limit));
        }
        "agent_bridge_mission_subtask_list" => {
            let limit = maybe_int(args, "limit", 20)?;
            if !(1..=20).contains(&limit) {
                return Err(invalid("Subtask list limit must be 1-20."));
            }
            data.insert("limit".into(), json!(limit));
        }
        _ => {}
    }
    // Public context IDs used as target/assignee are validated within the
    // business APIs. Only the caller's raw registered handle authenticates.
    dispatch_core(conn, method, &payload, actor, observe_context)
}

/// Convenience for JSON-only callers without allocating their own Value tree.
/// This function never opens, caches, or owns the SQLite database connection.
pub fn dispatch_tool_json(
    conn: &mut Connection, tool_name: &str, argument_json: &str
) -> Result<String> {
    if argument_json.len() > 1024 * 1024 {
        return Err(invalid("Tool arguments exceed 1 MiB."));
    }
    let args: Value = serde_json::from_str(argument_json)?;
    serde_json::to_string(&dispatch_tool(conn, tool_name, &args)?)
        .map_err(|_| BridgeError::new("INTERNAL_ERROR", "Cannot serialize tool result."))
}
