use std::collections::{HashMap, HashSet};

use chrono::{SecondsFormat, Utc};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::store;

const MAX_CONTEXT_HANDLE_LEN: usize = 256;
const MAX_CONTEXT_ID_LEN: usize = 64;
const MAX_LABEL_LEN: usize = 256;
const MAX_PROJECT_LEN: usize = 256;
const MAX_DEVICE_LEN: usize = 256;
const MAX_TITLE_LEN: usize = 512;
const MAX_GOAL_LEN: usize = 16_384;
const MAX_SUMMARY_LEN: usize = 8_192;
const MAX_TASK_ID_LEN: usize = 128;
const MAX_STEP_ID_LEN: usize = 128;
const MAX_STEP_TITLE_LEN: usize = 512;
const MAX_STEPS_COUNT: usize = 12;
const MAX_LIST_ITEMS: usize = 64;
const MAX_LIST_ITEM_LEN: usize = 4_096;
const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 200;
const MAX_EVENTS_RETURNED: usize = 50;
const MAX_IMPORT_EVENT_COUNT: i64 = 1_000_000;
// Leave margin for JSON-RPC/MCP envelopes in the 1 MiB stdio frame.
const MAX_TOOL_RESPONSE_BYTES: usize = 400_000;

pub const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS task_room_contexts (
    context_id TEXT PRIMARY KEY NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    project TEXT NOT NULL DEFAULT '',
    device TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_reattached_at TEXT
);

-- Separate, Task-Room-only capabilities. Legacy contexts lacking this row
-- are intentionally inaccessible; Mission handles are never accepted here.
CREATE TABLE IF NOT EXISTS task_room_context_access (
    context_id TEXT PRIMARY KEY NOT NULL REFERENCES task_room_contexts(context_id) ON DELETE CASCADE,
    handle_hash TEXT NOT NULL UNIQUE,
    workspace_binding TEXT NOT NULL,
    rotated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_task_room_access_workspace
    ON task_room_context_access(workspace_binding, context_id);

CREATE TABLE IF NOT EXISTS task_room_tasks (
    task_id TEXT PRIMARY KEY NOT NULL,
    context_id TEXT NOT NULL REFERENCES task_room_contexts(context_id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    goal TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('active', 'blocked', 'completed')),
    summary TEXT NOT NULL DEFAULT '',
    project TEXT NOT NULL DEFAULT '',
    device TEXT NOT NULL DEFAULT '',
    current_step_id TEXT,
    completion_conditions_json TEXT NOT NULL DEFAULT '[]',
    verified_facts_json TEXT NOT NULL DEFAULT '[]',
    open_risks_json TEXT NOT NULL DEFAULT '[]',
    missing_checks_json TEXT NOT NULL DEFAULT '[]',
    blocked_reason TEXT,
    review_status TEXT CHECK (review_status IS NULL OR review_status IN ('pass', 'failed')),
    review_summary TEXT,
    reviewed_at TEXT,
    completed_at TEXT,
    revision INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS task_room_steps (
    task_id TEXT NOT NULL REFERENCES task_room_tasks(task_id) ON DELETE CASCADE,
    step_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    title TEXT NOT NULL,
    phase TEXT CHECK (phase IS NULL OR phase IN ('check', 'execute', 'verify', 'closeout')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'in_progress', 'completed')),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (task_id, step_id)
);

CREATE TABLE IF NOT EXISTS task_room_events (
    event_id TEXT PRIMARY KEY NOT NULL,
    task_id TEXT NOT NULL REFERENCES task_room_tasks(task_id) ON DELETE CASCADE,
    context_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_task_room_contexts_scope
    ON task_room_contexts(project, device, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_task_room_tasks_context_status
    ON task_room_tasks(context_id, status, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_task_room_steps_task_pos
    ON task_room_steps(task_id, position ASC);

CREATE INDEX IF NOT EXISTS idx_task_room_events_task_time
    ON task_room_events(task_id, created_at ASC);
"#;

const REQUIRED_TABLES: [&str; 5] = [
    "task_room_contexts",
    "task_room_context_access",
    "task_room_tasks",
    "task_room_steps",
    "task_room_events",
];

#[derive(Debug, Clone)]
struct StepInput {
    id: String,
    title: String,
    phase: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ContextRecord {
    context_id: String,
    context_label: String,
    project: String,
    device: String,
    created_at: String,
    updated_at: String,
    last_reattached_at: Option<String>,
}

fn context_access(record: &ContextRecord, handle: &str) -> Value {
    let mut access = json!(record);
    access["label"] = json!(record.context_label);
    access["context_handle"] = json!(handle);
    access
}

#[derive(Debug, Clone, Serialize)]
struct StepRecord {
    id: String,
    title: String,
    phase: Option<String>,
    status: String,
    step_status: String,
    updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
struct TaskRecord {
    id: String,
    task_id: String,
    context_id: String,
    title: String,
    goal: String,
    status: String,
    task_status: String,
    summary: String,
    project: String,
    device: String,
    current_step_id: Option<String>,
    steps: Vec<StepRecord>,
    completion_conditions: Vec<String>,
    verified_facts: Vec<String>,
    open_risks: Vec<String>,
    missing_checks: Vec<String>,
    blocked_reason: Option<String>,
    review_status: Option<String>,
    review_summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    final_review: Option<Value>,
    reviewed_at: Option<String>,
    completed_at: Option<String>,
    revision: i64,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
struct EventRecord {
    event_id: String,
    event_type: String,
    #[serde(rename = "type")]
    client_type: String,
    summary: String,
    payload: Value,
    created_at: String,
}

#[derive(Debug, Clone, Serialize)]
struct DiscoveryCounts {
    active: i64,
    blocked: i64,
    completed: i64,
    total: i64,
}

#[derive(Debug, Clone, Serialize)]
struct DiscoveryContextEntry {
    context_id: String,
    created_at: String,
    updated_at: String,
    task_counts: DiscoveryCounts,
}

// Compact list rows do not repeat 64 long evidence strings per task.
#[derive(Debug, Clone, Serialize)]
struct TaskDigest {
    id: String,
    task_id: String,
    title: String,
    status: String,
    task_status: String,
    current_step_id: Option<String>,
    steps: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    final_review: Option<String>,
    revision: i64,
    updated_at: String,
    // Extra fields exist only in list; reattach retains the historic digest.
    #[serde(skip_serializing_if = "Option::is_none")]
    goal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocker: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocked_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_at: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    truncated_fields: Vec<&'static str>,
    #[serde(skip)]
    resume: Option<ListResumeFields>,
    #[serde(skip)]
    legacy_bytes: usize,
}

/// Explicitly initializes the isolated auxiliary Task Room schema inside an IMMEDIATE transaction.
/// Call this once during database bootstrap after initializing the core `store` schema.
pub fn init_schema(conn: &mut Connection) -> crate::Result<()> {
    store::verify_schema(conn)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| store::invalid("failed to open transaction for task room schema init"))?;
    tx.execute_batch(SCHEMA_SQL)
        .map_err(|_| store::invalid("failed to initialize task room schema"))?;
    tx.commit()
        .map_err(|_| store::invalid("failed to commit task room schema initialization"))?;
    Ok(())
}

/// Verifies that the auxiliary Task Room schema tables exist without mutating the database.
pub fn verify_schema(conn: &Connection) -> crate::Result<()> {
    for table in REQUIRED_TABLES {
        let found: Option<String> = conn
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![table],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| store::invalid("failed to inspect task room schema"))?;
        if found.is_none() {
            return Err(store::invalid(
                "task room schema not initialized; run task_room::init_schema first",
            ));
        }
    }
    Ok(())
}

// Retain the previous Rust entry point for source compatibility, but refuse
// unbound callers instead of silently granting a Mission context capability.
pub fn dispatch(_conn: &mut Connection, _args: &Value) -> crate::Result<Value> {
    Err(store::denied("Task Rooms require a physically qualified project scope"))
}

/// Only the trusted workstation runtime supplies this binding. It includes
/// the physical directory identity and canonical path, never caller labels.
pub fn dispatch_scoped(
    conn: &mut Connection, args: &Value, qualified_workspace_binding: &str,
) -> crate::Result<Value> {
    if qualified_workspace_binding.is_empty() {
        return Err(store::denied("Task Room project identity is unavailable"));
    }
    store::verify_schema(conn)?;
    verify_schema(conn)?;
    let workspace_binding = store::sha256_hex(
        format!("agent-bridge.task-room.workspace.v1\0{qualified_workspace_binding}").as_bytes()
    );
    let obj = args
        .as_object()
        .ok_or_else(|| store::invalid("arguments must be a JSON object"))?;
    let action = req_str(obj, "action", 64)?;
    let response = match action.as_str() {
        "context_create" => handle_context_create(conn, obj, &workspace_binding),
        "context_discover" => handle_context_discover(conn, obj, &workspace_binding),
        "context_reattach" => handle_context_reattach(conn, obj, &workspace_binding),
        "create" => handle_create(conn, obj, &workspace_binding),
        "list" => handle_list(conn, obj, &workspace_binding),
        "get" => handle_get(conn, obj, &workspace_binding),
        "checkpoint" => handle_checkpoint(conn, obj, &workspace_binding),
        "block" => handle_block(conn, obj, &workspace_binding),
        "resume" => handle_resume(conn, obj, &workspace_binding),
        "final_review" => handle_final_review(conn, obj, &workspace_binding),
        "complete" => handle_complete(conn, obj, &workspace_binding),
        _ => Err(store::invalid("unsupported desktop_task_manage action")),
    }?;
    checked_response(response)
}

fn checked_response(value: Value) -> crate::Result<Value> {
    let encoded = serde_json::to_vec(&value)
        .map_err(|_| store::invalid("failed to encode Task Room response"))?;
    if encoded.len() > MAX_TOOL_RESPONSE_BYTES {
        return Err(store::invalid(
            "Task Room response exceeds stdio size budget; reduce the requested data",
        ));
    }
    Ok(value)
}

// Check the response while rollback is still possible. A committed mutation
// must never be rendered unreturnable by the stdio frame limit.
fn commit_response(
    tx: Transaction<'_>, response: Value, error: &'static str,
) -> crate::Result<Value> {
    let response = checked_response(response)?;
    tx.commit().map_err(|_| store::invalid(error))?;
    Ok(response)
}

fn new_room_handle() -> String { store::new_id("trh") }

fn room_handle_hash(handle: &str) -> String {
    store::sha256_hex(format!("agent-bridge.task-room.handle.v1\0{handle}").as_bytes())
}

fn require_room_context(
    conn: &Connection, handle: &str, workspace_binding: &str,
) -> crate::Result<String> {
    if !store::valid_id("trh", handle) {
        return Err(store::denied("Unknown Task Room context capability"));
    }
    conn.query_row(
        "SELECT context_id FROM task_room_context_access
         WHERE handle_hash=?1 AND workspace_binding=?2",
        params![room_handle_hash(handle), workspace_binding],
        |row| row.get(0),
    )
    .optional()
    .map_err(|_| store::invalid("failed to validate Task Room context"))?
    .ok_or_else(|| store::denied("Unknown, rotated, or out-of-project Task Room capability"))
}

fn handle_context_create(
    conn: &mut Connection, obj: &Map<String, Value>, workspace_binding: &str,
) -> crate::Result<Value> {
    let label = opt_text(obj, "context_label", MAX_LABEL_LEN)?.unwrap_or_default();
    let project = opt_text(obj, "project", MAX_PROJECT_LEN)?.unwrap_or_default();
    let device = opt_text(obj, "device", MAX_DEVICE_LEN)?.unwrap_or_default();
    let now = now_rfc3339();
    // Task Rooms never write agent_contexts or reuse a Mission handle hash.
    let context_id = store::new_id("trctx");
    let context_handle = new_room_handle();
    let hash = room_handle_hash(&context_handle);
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| store::invalid("failed to start transaction for context_create"))?;
    tx.execute(
        "INSERT INTO task_room_contexts
         (context_id, label, project, device, created_at, updated_at, last_reattached_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5, NULL)",
        params![context_id, label, project, device, now],
    ).map_err(|_| store::invalid("failed to persist Task Room context"))?;
    tx.execute(
        "INSERT INTO task_room_context_access
         (context_id, handle_hash, workspace_binding, rotated_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![context_id, hash, workspace_binding, now],
    ).map_err(|_| store::invalid("failed to bind Task Room capability to project"))?;
    let record = load_context(&tx, &context_id)?
        .ok_or_else(|| store::invalid("failed to reload created Task Room context"))?;
    commit_response(tx, json!({
        "ok": true, "action": "context_create",
        "context_id": context_id, "context_handle": context_handle,
        "context": context_access(&record, &context_handle),
    }), "failed to commit context_create")
}

/// Discovery is bound to the authenticated operator workspace, not to any
/// Mission identity or a caller-supplied project/device/label. No task titles,
/// goals, summaries, event contents, or capability values are disclosed.
fn handle_context_discover(
    conn: &mut Connection,
    obj: &Map<String, Value>,
    workspace_binding: &str,
) -> crate::Result<Value> {
    let project = opt_text(obj, "project", MAX_PROJECT_LEN)?;
    let device = opt_text(obj, "device", MAX_DEVICE_LEN)?;
    let label = opt_text(obj, "context_label", MAX_LABEL_LEN)?;
    let context_filter = opt_strict_str(obj, "context_id", MAX_CONTEXT_ID_LEN)?;
    let task_status = opt_task_status(obj)?;
    let limit = opt_limit(obj)?;
    let handle_filter = opt_strict_str(obj, "context_handle", MAX_CONTEXT_HANDLE_LEN)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(|_| store::invalid("failed to start read transaction for context_discover"))?;
    let owned_context = handle_filter.as_deref()
        .map(|handle| require_room_context(&tx, handle, workspace_binding))
        .transpose()?;
    let rows = {
        let mut query = tx.prepare(
            "SELECT c.context_id, c.created_at, c.updated_at
             FROM task_room_contexts c
             JOIN task_room_context_access a ON a.context_id=c.context_id
             WHERE a.workspace_binding=?1
               AND (?2 IS NULL OR c.project=?2)
               AND (?3 IS NULL OR c.device=?3)
               AND (?4 IS NULL OR c.label=?4)
               AND (?5 IS NULL OR c.context_id=?5)
               AND (?6 IS NULL OR c.context_id=?6)
               AND (?7 IS NULL OR EXISTS(
                   SELECT 1 FROM task_room_tasks t
                   WHERE t.context_id=c.context_id AND t.status=?7))
             ORDER BY c.updated_at DESC, c.context_id DESC LIMIT ?8",
        ).map_err(|_| store::invalid("failed to prepare Task Room discovery"))?;
        let mapped = query.query_map(
            params![workspace_binding, project, device, label, context_filter,
                owned_context, task_status, limit as i64],
            |row| Ok((row.get::<_, String>(0)?,
                      row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
        ).map_err(|_| store::invalid("failed to query project Task Rooms"))?;
        let collected = mapped.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| store::invalid("failed to decode Task Room metadata"))?;
        collected
    };
    let mut contexts = Vec::with_capacity(rows.len());
    for (context_id, created_at, updated_at) in rows {
        let task_counts = load_context_counts(&tx, &context_id)?;
        contexts.push(DiscoveryContextEntry {
            context_id, created_at, updated_at, task_counts,
        });
    }
    tx.commit().map_err(|_| store::invalid("failed to close Task Room discovery"))?;
    Ok(json!({
        "ok": true, "action": "context_discover", "read_only": true,
        "scope": "selected_physical_workspace",
        "reattach_policy": "requires_context_handle",
        "count": contexts.len(), "contexts": contexts,
    }))
}

fn handle_context_reattach(
    conn: &mut Connection,
    obj: &Map<String, Value>,
    workspace_binding: &str,
) -> crate::Result<Value> {
    let handle = opt_strict_str(obj, "context_handle", MAX_CONTEXT_HANDLE_LEN)?
        .ok_or_else(|| store::denied(
            "context_reattach requires an existing Task Room capability",
        ))?;
    let target_task_id = opt_strict_str(obj, "task_id", MAX_TASK_ID_LEN)?;
    let target_context_id = opt_strict_str(obj, "context_id", MAX_CONTEXT_ID_LEN)?;
    let confirm_label = opt_strict_str(obj, "confirm_label", MAX_LABEL_LEN)?;
    let project = opt_text(obj, "project", MAX_PROJECT_LEN)?;
    let device = opt_text(obj, "device", MAX_DEVICE_LEN)?;
    let limit = opt_limit(obj)?;
    if target_task_id.is_none()
        && !(target_context_id.is_some() && confirm_label.is_some())
    {
        return Err(store::invalid(
            "context_reattach requires task_id or context_id and confirm_label, plus a capability",
        ));
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| store::invalid("failed to start transaction for context_reattach"))?;
    let context_id = require_room_context(&tx, &handle, workspace_binding)?;
    let ctx = load_context(&tx, &context_id)?
        .ok_or_else(|| store::denied("Task Room context not found"))?;
    if target_context_id.as_ref().is_some_and(|v| v != &context_id) {
        return Err(store::denied("context_id does not match capability"));
    }
    if confirm_label.as_ref().is_some_and(|v| v != &ctx.context_label) {
        return Err(store::denied("confirm_label does not match context"));
    }
    if project.as_ref().is_some_and(|v| v != &ctx.project)
        || device.as_ref().is_some_and(|v| v != &ctx.device)
    {
        return Err(store::denied("project or device does not match Task Room metadata"));
    }
    let attached_task = if let Some(ref tid) = target_task_id {
        Some(load_task_scoped(&tx, &context_id, tid)?
            .ok_or_else(|| store::denied("task not found in Task Room"))?)
    } else { None };
    let now = now_rfc3339();
    let rotated_handle = new_room_handle();
    let changed = tx.execute(
        "UPDATE task_room_context_access
         SET handle_hash=?1, rotated_at=?2
         WHERE context_id=?3 AND handle_hash=?4 AND workspace_binding=?5",
        params![room_handle_hash(&rotated_handle), now, context_id,
            room_handle_hash(&handle), workspace_binding],
    ).map_err(|_| store::invalid("failed to rotate Task Room capability"))?;
    if changed != 1 {
        return Err(store::denied("Task Room capability changed or was revoked"));
    }
    tx.execute(
        "UPDATE task_room_contexts
         SET last_reattached_at=?1, updated_at=?1 WHERE context_id=?2",
        params![now, context_id],
    ).map_err(|_| store::invalid("failed to update Task Room reattach timestamp"))?;
    let context = load_context(&tx, &context_id)?
        .ok_or_else(|| store::denied("Task Room context not found"))?;
    let (tasks, _) = load_compact_tasks_for_context(&tx, &context_id, None, None, None, limit, false)?;
    commit_response(tx, json!({
        "ok": true, "action": "context_reattach",
        "context_id": context_id,
        "context_handle": rotated_handle,
        "context": context_access(&context, &rotated_handle), "task": attached_task, "tasks": tasks,
    }), "failed to commit context_reattach")
}

fn handle_create(conn: &mut Connection, obj: &Map<String, Value>, workspace_binding: &str) -> crate::Result<Value> {
    let handle = req_str(obj, "context_handle", MAX_CONTEXT_HANDLE_LEN)?;
    let title = req_str(obj, "title", MAX_TITLE_LEN)?;
    let goal = opt_text(obj, "goal", MAX_GOAL_LEN)?.unwrap_or_default();
    let summary = opt_text(obj, "summary", MAX_SUMMARY_LEN)?.unwrap_or_default();
    let project_arg = opt_text(obj, "project", MAX_PROJECT_LEN)?;
    let device_arg = opt_text(obj, "device", MAX_DEVICE_LEN)?;
    let steps = opt_steps(obj)?.unwrap_or_default();
    let current_step_arg = opt_strict_str(obj, "current_step_id", MAX_STEP_ID_LEN)?;
    let completion_conditions =
        opt_string_list(obj, "completion_conditions", MAX_LIST_ITEMS, MAX_LIST_ITEM_LEN)?
            .unwrap_or_default();
    let verified_facts =
        opt_string_list(obj, "verified_facts", MAX_LIST_ITEMS, MAX_LIST_ITEM_LEN)?
            .unwrap_or_default();
    let open_risks =
        opt_string_list(obj, "open_risks", MAX_LIST_ITEMS, MAX_LIST_ITEM_LEN)?.unwrap_or_default();
    let missing_checks =
        opt_string_list(obj, "missing_checks", MAX_LIST_ITEMS, MAX_LIST_ITEM_LEN)?
            .unwrap_or_default();

    let resolved_current_step = if let Some(ref csid) = current_step_arg {
        if !steps.iter().any(|s| &s.id == csid) {
            return Err(store::invalid(
                "current_step_id must match one of the provided steps",
            ));
        }
        Some(csid.clone())
    } else {
        steps.first().map(|s| s.id.clone())
    };

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| store::invalid("failed to start transaction for create"))?;

    let context_id = require_room_context(&tx, &handle, workspace_binding)?;
    let now = now_rfc3339();
    // Legacy unbound contexts are not enrolled by creating a task.
    let ctx = load_context(&tx, &context_id)?
        .ok_or_else(|| store::invalid("failed to load task room context"))?;
    let project = project_arg.unwrap_or(ctx.project);
    let device = device_arg.unwrap_or(ctx.device);

    let task_id = store::new_id("task");
    let completion_conditions_json = to_json_string(&completion_conditions)?;
    let verified_facts_json = to_json_string(&verified_facts)?;
    let open_risks_json = to_json_string(&open_risks)?;
    let missing_checks_json = to_json_string(&missing_checks)?;

    tx.execute(
        "INSERT INTO task_room_tasks (
            task_id, context_id, title, goal, status, summary, project, device,
            current_step_id, completion_conditions_json, verified_facts_json,
            open_risks_json, missing_checks_json, blocked_reason, review_status,
            review_summary, reviewed_at, completed_at, revision, created_at, updated_at
         ) VALUES (
            ?1, ?2, ?3, ?4, 'active', ?5, ?6, ?7,
            ?8, ?9, ?10, ?11, ?12, NULL, NULL,
            NULL, NULL, NULL, 1, ?13, ?13
         )",
        params![
            task_id,
            context_id,
            title,
            goal,
            summary,
            project,
            device,
            resolved_current_step,
            completion_conditions_json,
            verified_facts_json,
            open_risks_json,
            missing_checks_json,
            now
        ],
    )
    .map_err(|_| store::invalid("failed to insert task room task"))?;

    for (idx, step) in steps.iter().enumerate() {
        let status = if resolved_current_step.as_deref() == Some(step.id.as_str()) {
            "in_progress"
        } else {
            "pending"
        };
        tx.execute(
            "INSERT INTO task_room_steps (
                task_id, step_id, position, title, phase, status, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![task_id, step.id, idx as i64, step.title, step.phase, status, now],
        )
        .map_err(|_| store::invalid("failed to insert task room step"))?;
    }

    append_event(
        &tx,
        &task_id,
        &context_id,
        "create",
        &summary,
        &json!({ "step_count": steps.len(), "current_step_id": resolved_current_step }),
        &now,
    )?;

    touch_context(&tx, &context_id, &now)?;

    let task = load_task_scoped(&tx, &context_id, &task_id)?
        .ok_or_else(|| store::invalid("failed to reload created task"))?;
    commit_response(tx, json!({
        "ok": true,
        "action": "create",
        "context_id": context_id,
        "task": task
    }), "failed to commit create")
}

fn handle_list(conn: &mut Connection, obj: &Map<String, Value>, workspace_binding: &str) -> crate::Result<Value> {
    let handle = req_str(obj, "context_handle", MAX_CONTEXT_HANDLE_LEN)?;
    let task_status = opt_task_status(obj)?;
    let project = opt_text(obj, "project", MAX_PROJECT_LEN)?;
    let device = opt_text(obj, "device", MAX_DEVICE_LEN)?;
    let limit = opt_limit(obj)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(|_| store::invalid("failed to start read transaction for list"))?;
    let context_id = require_room_context(&tx, &handle, workspace_binding)?;
    let (mut tasks, rows_bytes) = load_compact_tasks_for_context(
        &tx, &context_id, task_status.as_deref(),
        project.as_deref(), device.as_deref(), limit, true,
    )?;
    tx.commit().map_err(|_| store::invalid("failed to close read transaction for list"))?;

    // One serialized legacy row per task plus the exact JSON envelope/commas.
    // Reserve room for truncation flags; never remove or shorten old fields.
    let envelope = json!({"ok":true,"action":"list","context_id":context_id,
        "count":tasks.len(),"tasks":[]});
    let base = envelope.to_string().len().saturating_add(rows_bytes)
        .saturating_add(tasks.len().saturating_sub(1));
    let mut remaining = MAX_TOOL_RESPONSE_BYTES.saturating_sub(base.saturating_add(128));
    if remaining == 0 {
        return Ok(json!({"ok":true,"action":"list","context_id":context_id,
            "count":tasks.len(),"tasks":tasks}));
    }
    let mut truncated = false;
    let mut omitted = false;
    let total = tasks.len();
    for (index, task) in tasks.iter_mut().enumerate() {
        let Some(raw) = task.resume.take() else { continue; };
        let allowance = remaining / (total - index);
        let cap = (allowance.saturating_sub(192) / 6).min(256);
        let (goal, cut_goal) = list_preview(&raw.goal, cap * 2);
        let (summary, cut_summary) = list_preview(&raw.summary, cap * 2);
        let (blocker, cut_blocker) = match raw.blocked_reason.as_deref() {
            Some(reason) => {
                let (excerpt, cut) = list_preview(reason, cap);
                (Some(excerpt), cut)
            }
            None => (None, false),
        };
        task.goal = Some(goal);
        task.summary = Some(summary);
        task.blocker = blocker.clone();
        task.blocked_reason = blocker;
        task.created_at = Some(raw.created_at);
        task.completed_at = raw.completed_at;
        if cut_goal { task.truncated_fields.push("goal"); }
        if cut_summary { task.truncated_fields.push("summary"); }
        if cut_blocker { task.truncated_fields.extend(["blocker", "blocked_reason"]); }
        let serialized = serde_json::to_vec(&*task)
            .map_err(|_| store::invalid("failed to size Task Room list row"))?.len();
        let extra = serialized.saturating_sub(task.legacy_bytes);
        if extra <= allowance {
            remaining -= extra;
            truncated |= !task.truncated_fields.is_empty();
        } else {
            task.goal = None;
            task.summary = None;
            task.blocker = None;
            task.blocked_reason = None;
            task.created_at = None;
            task.completed_at = None;
            task.truncated_fields.clear();
            omitted = true;
        }
    }
    let mut response = json!({"ok":true,"action":"list","context_id":context_id,
        "count":tasks.len(),"tasks":tasks});
    if truncated || omitted {
        response["text_truncated"] = json!(true);
        response["full_details_action"] = json!("get");
    }
    if omitted { response["resume_fields_omitted"] = json!(true); }
    Ok(response)
}

fn handle_get(conn: &mut Connection, obj: &Map<String, Value>, workspace_binding: &str) -> crate::Result<Value> {
    let handle = req_str(obj, "context_handle", MAX_CONTEXT_HANDLE_LEN)?;
    let task_id = req_str(obj, "task_id", MAX_TASK_ID_LEN)?;

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(|_| store::invalid("failed to start read transaction for get"))?;

    let context_id = require_room_context(&tx, &handle, workspace_binding)?;
    let task = load_task_scoped(&tx, &context_id, &task_id)?
        .ok_or_else(|| store::denied("task not found in context"))?;
    let limit = if obj.contains_key("limit") { opt_limit(obj)?.min(MAX_EVENTS_RETURNED) } else { MAX_EVENTS_RETURNED };
    let events = load_recent_events(&tx, &task_id, limit + 1)?;
    tx.commit()
        .map_err(|_| store::invalid("failed to close read transaction for get"))?;
    let mut resp = json!({"ok":true,"action":"get","context_id":context_id,"task":task,
        "events":[],"events_truncated":false});
    resp["task"]["events"] = json!([]);
    let mut size = resp.to_string().len();
    let mut selected = Vec::new();
    let total = events.len();
    // The database returns chronological order. Budget the newest events
    // first, then restore that order for the client.
    for event in events.into_iter().rev().take(limit) {
        let value = json!(event);
        size += 2 * (value.to_string().len() + 1);
        if size > MAX_TOOL_RESPONSE_BYTES { break; }
        selected.push(value);
    }
    resp["events_truncated"] = json!(selected.len() < total);
    selected.reverse();
    resp["task"]["events"] = json!(selected);
    resp["events"] = Value::Array(selected);
    Ok(resp)
}

/// Internal, bounded import view. The public get response stays unchanged.
/// Exact count and chronological source positions come from one transaction;
/// only the newest fifty summaries are materialized, never the full history.
pub fn read_import_snapshot_scoped(
    conn:&mut Connection,context_handle:&str,task_id:&str,qualified_workspace_binding:&str,
)->crate::Result<Value> {
    if qualified_workspace_binding.is_empty() {
        return Err(store::denied("Task Room project identity is unavailable"));
    }
    store::verify_schema(conn)?;
    verify_schema(conn)?;
    let workspace_binding=store::sha256_hex(
        format!("agent-bridge.task-room.workspace.v1\0{qualified_workspace_binding}").as_bytes()
    );
    let arguments=json!({"context_handle":context_handle,"task_id":task_id});
    let obj=arguments.as_object().ok_or_else(||store::invalid("invalid import source"))?;
    let handle=req_str(obj,"context_handle",MAX_CONTEXT_HANDLE_LEN)?;
    let task_id=req_str(obj,"task_id",MAX_TASK_ID_LEN)?;
    let tx=conn.transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(|_|store::invalid("failed to start import snapshot"))?;
    let context_id=require_room_context(&tx,&handle,&workspace_binding)?;
    let task=load_task_scoped(&tx,&context_id,&task_id)?
        .ok_or_else(||store::denied("task not found in context"))?;
    // The covering task/time index provides an exact count up to this
    // explicit work bound. Larger histories are refused, never approximated.
    let total:i64=tx.query_row("SELECT COUNT(*) FROM
        (SELECT 1 FROM task_room_events WHERE task_id=?1 LIMIT ?2)",
        params![task_id,MAX_IMPORT_EVENT_COUNT+1],|row|row.get(0))
        .map_err(|_|store::invalid("failed to count import events"))?;
    if total<0 || total>MAX_IMPORT_EVENT_COUNT {
        return Err(store::invalid("source event total exceeds import bound"));
    }
    let mut response=json!({"context_id":context_id,
        "task":{"task_id":task.task_id,"context_id":task.context_id,"title":task.title,
            "goal":task.goal,"status":task.status,"steps":task.steps},
        "events":[],"total_events_reported":total,"events_truncated":false});
    let mut size=response.to_string().len();
    if size>MAX_TOOL_RESPONSE_BYTES {return Err(store::invalid("import task exceeds response bound"));}
    let rows={
        let mut query=tx.prepare("SELECT event_type,summary FROM task_room_events WHERE task_id=?1
            ORDER BY created_at DESC,rowid DESC LIMIT ?2")
            .map_err(|_|store::invalid("failed to prepare import events"))?;
        let mapped=query.query_map(params![task_id,MAX_EVENTS_RETURNED as i64],|row|
            Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?)))
            .map_err(|_|store::invalid("failed to query import events"))?;
        mapped.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_|store::invalid("failed to decode import events"))?
    };
    let mut selected=Vec::new();
    for (index,(event_type,summary)) in rows.into_iter().enumerate() {
        // DESC LIMIT returns the true last ordinal, then its predecessors.
        // The count and ordering are read under the same SQLite snapshot.
        let sequence=total-index as i64;
        if sequence<=0 {return Err(store::invalid("inconsistent source event count"));}
        let event=json!({"sequence":sequence,"event_type":event_type,"summary":summary});
        let bytes=event.to_string().len()+1;
        if bytes>MAX_TOOL_RESPONSE_BYTES.saturating_sub(size) {break;}
        size+=bytes;selected.push(event);
    }
    selected.reverse();
    response["events_truncated"]=json!((selected.len() as i64)<total);
    response["events"]=Value::Array(selected);
    tx.commit().map_err(|_|store::invalid("failed to close import snapshot"))?;
    Ok(response)
}

fn handle_checkpoint(conn: &mut Connection, obj: &Map<String, Value>, workspace_binding: &str) -> crate::Result<Value> {
    let handle = req_str(obj, "context_handle", MAX_CONTEXT_HANDLE_LEN)?;
    let task_id = req_str(obj, "task_id", MAX_TASK_ID_LEN)?;
    let title = opt_strict_str(obj, "title", MAX_TITLE_LEN)?;
    let goal = opt_text(obj, "goal", MAX_GOAL_LEN)?;
    let summary = opt_text(obj, "summary", MAX_SUMMARY_LEN)?;
    let project = opt_text(obj, "project", MAX_PROJECT_LEN)?;
    let device = opt_text(obj, "device", MAX_DEVICE_LEN)?;
    let steps = opt_steps(obj)?;
    let current_step_id = opt_strict_str(obj, "current_step_id", MAX_STEP_ID_LEN)?;
    let completed_step_ids =
        opt_string_list(obj, "completed_step_ids", MAX_STEPS_COUNT, MAX_STEP_ID_LEN)?;
    let step_update = opt_step_update(obj)?;
    let completion_conditions =
        opt_string_list(obj, "completion_conditions", MAX_LIST_ITEMS, MAX_LIST_ITEM_LEN)?;
    let verified_facts =
        opt_string_list(obj, "verified_facts", MAX_LIST_ITEMS, MAX_LIST_ITEM_LEN)?;
    let open_risks = opt_string_list(obj, "open_risks", MAX_LIST_ITEMS, MAX_LIST_ITEM_LEN)?;
    let missing_checks =
        opt_string_list(obj, "missing_checks", MAX_LIST_ITEMS, MAX_LIST_ITEM_LEN)?;

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| store::invalid("failed to start transaction for checkpoint"))?;

    let context_id = require_room_context(&tx, &handle, workspace_binding)?;
    let mut task = load_task_scoped(&tx, &context_id, &task_id)?
        .ok_or_else(|| store::denied("task not found in context"))?;

    if task.task_status == "completed" {
        return Err(store::invalid("cannot checkpoint a completed task"));
    }
    if task.task_status == "blocked" {
        return Err(store::invalid(
            "cannot checkpoint a blocked task; resume first",
        ));
    }

    let now = now_rfc3339();

    if let Some(new_steps) = steps {
        replace_steps(&tx, &task_id, &new_steps, &now)?;
    }

    let updated_current_step = apply_step_mutations(
        &tx,
        &task_id,
        task.current_step_id.as_deref(),
        completed_step_ids.as_deref(),
        step_update.as_ref(),
        current_step_id.as_deref(),
        &now,
    )?;

    if let Some(v) = title {
        task.title = v;
    }
    if let Some(v) = goal {
        task.goal = v;
    }
    if let Some(v) = summary {
        task.summary = v;
    }
    if let Some(v) = project {
        task.project = v;
    }
    if let Some(v) = device {
        task.device = v;
    }
    if let Some(v) = completion_conditions {
        task.completion_conditions = v;
    }
    if let Some(v) = verified_facts {
        task.verified_facts = v;
    }
    if let Some(v) = open_risks {
        task.open_risks = v;
    }
    if let Some(v) = missing_checks {
        task.missing_checks = v;
    }

    tx.execute(
        "UPDATE task_room_tasks
         SET title = ?1,
             goal = ?2,
             summary = ?3,
             project = ?4,
             device = ?5,
             current_step_id = ?6,
             completion_conditions_json = ?7,
             verified_facts_json = ?8,
             open_risks_json = ?9,
             missing_checks_json = ?10,
             review_status = NULL,
             review_summary = NULL,
             reviewed_at = NULL,
             revision = revision + 1,
             updated_at = ?11
         WHERE task_id = ?12 AND context_id = ?13",
        params![
            task.title,
            task.goal,
            task.summary,
            task.project,
            task.device,
            updated_current_step,
            to_json_string(&task.completion_conditions)?,
            to_json_string(&task.verified_facts)?,
            to_json_string(&task.open_risks)?,
            to_json_string(&task.missing_checks)?,
            now,
            task_id,
            context_id
        ],
    )
    .map_err(|_| store::invalid("failed to update task checkpoint"))?;

    append_event(
        &tx,
        &task_id,
        &context_id,
        "checkpoint",
        &task.summary,
        &json!({ "current_step_id": updated_current_step }),
        &now,
    )?;

    touch_context(&tx, &context_id, &now)?;

    let reloaded = load_task_scoped(&tx, &context_id, &task_id)?
        .ok_or_else(|| store::invalid("failed to reload checkpointed task"))?;
    commit_response(tx, json!({
        "ok": true,
        "action": "checkpoint",
        "context_id": context_id,
        "task": reloaded
    }), "failed to commit checkpoint")
}

fn handle_block(conn: &mut Connection, obj: &Map<String, Value>, workspace_binding: &str) -> crate::Result<Value> {
    let handle = req_str(obj, "context_handle", MAX_CONTEXT_HANDLE_LEN)?;
    let task_id = req_str(obj, "task_id", MAX_TASK_ID_LEN)?;
    let summary = opt_text(obj, "summary", MAX_SUMMARY_LEN)?;
    let current_step_id = opt_strict_str(obj, "current_step_id", MAX_STEP_ID_LEN)?;
    let step_update = opt_step_update(obj)?;
    let verified_facts =
        opt_string_list(obj, "verified_facts", MAX_LIST_ITEMS, MAX_LIST_ITEM_LEN)?;
    let open_risks = opt_string_list(obj, "open_risks", MAX_LIST_ITEMS, MAX_LIST_ITEM_LEN)?;
    let missing_checks =
        opt_string_list(obj, "missing_checks", MAX_LIST_ITEMS, MAX_LIST_ITEM_LEN)?;

    let has_blocker_detail = summary.is_some()
        || open_risks.as_ref().map(|v| !v.is_empty()).unwrap_or(false)
        || missing_checks
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or(false);
    if !has_blocker_detail {
        return Err(store::invalid(
            "block requires summary, open_risks, or missing_checks describing the blocker",
        ));
    }

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| store::invalid("failed to start transaction for block"))?;

    let context_id = require_room_context(&tx, &handle, workspace_binding)?;
    let mut task = load_task_scoped(&tx, &context_id, &task_id)?
        .ok_or_else(|| store::denied("task not found in context"))?;

    if task.task_status == "completed" {
        return Err(store::invalid("cannot block a completed task"));
    }

    let now = now_rfc3339();
    let updated_current_step = apply_step_mutations(
        &tx,
        &task_id,
        task.current_step_id.as_deref(),
        None,
        step_update.as_ref(),
        current_step_id.as_deref(),
        &now,
    )?;

    if let Some(v) = verified_facts {
        task.verified_facts = v;
    }
    if let Some(v) = open_risks {
        task.open_risks = v;
    }
    if let Some(v) = missing_checks {
        task.missing_checks = v;
    }

    let blocked_reason = summary
        .clone()
        .or_else(|| task.open_risks.first().cloned())
        .or_else(|| task.missing_checks.first().cloned())
        .unwrap_or_else(|| "blocked".to_string());

    if let Some(v) = summary {
        task.summary = v;
    }

    tx.execute(
        "UPDATE task_room_tasks
         SET status = 'blocked',
             summary = ?1,
             blocked_reason = ?2,
             current_step_id = ?3,
             verified_facts_json = ?4,
             open_risks_json = ?5,
             missing_checks_json = ?6,
             review_status = NULL,
             review_summary = NULL,
             reviewed_at = NULL,
             revision = revision + 1,
             updated_at = ?7
         WHERE task_id = ?8 AND context_id = ?9",
        params![
            task.summary,
            blocked_reason,
            updated_current_step,
            to_json_string(&task.verified_facts)?,
            to_json_string(&task.open_risks)?,
            to_json_string(&task.missing_checks)?,
            now,
            task_id,
            context_id
        ],
    )
    .map_err(|_| store::invalid("failed to mark task as blocked"))?;

    append_event(
        &tx,
        &task_id,
        &context_id,
        "block",
        &blocked_reason,
        &json!({ "current_step_id": updated_current_step }),
        &now,
    )?;

    touch_context(&tx, &context_id, &now)?;

    let reloaded = load_task_scoped(&tx, &context_id, &task_id)?
        .ok_or_else(|| store::invalid("failed to reload blocked task"))?;
    commit_response(tx, json!({
        "ok": true,
        "action": "block",
        "context_id": context_id,
        "task": reloaded
    }), "failed to commit block")
}

fn handle_resume(conn: &mut Connection, obj: &Map<String, Value>, workspace_binding: &str) -> crate::Result<Value> {
    let handle = req_str(obj, "context_handle", MAX_CONTEXT_HANDLE_LEN)?;
    let task_id = req_str(obj, "task_id", MAX_TASK_ID_LEN)?;
    let summary = opt_text(obj, "summary", MAX_SUMMARY_LEN)?;
    let current_step_id = opt_strict_str(obj, "current_step_id", MAX_STEP_ID_LEN)?;
    let completed_step_ids =
        opt_string_list(obj, "completed_step_ids", MAX_STEPS_COUNT, MAX_STEP_ID_LEN)?;
    let step_update = opt_step_update(obj)?;
    let verified_facts =
        opt_string_list(obj, "verified_facts", MAX_LIST_ITEMS, MAX_LIST_ITEM_LEN)?;
    let open_risks = opt_string_list(obj, "open_risks", MAX_LIST_ITEMS, MAX_LIST_ITEM_LEN)?;
    let missing_checks =
        opt_string_list(obj, "missing_checks", MAX_LIST_ITEMS, MAX_LIST_ITEM_LEN)?;

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| store::invalid("failed to start transaction for resume"))?;

    let context_id = require_room_context(&tx, &handle, workspace_binding)?;
    let mut task = load_task_scoped(&tx, &context_id, &task_id)?
        .ok_or_else(|| store::denied("task not found in context"))?;

    if task.task_status != "blocked" {
        return Err(store::invalid("resume is only allowed for blocked tasks"));
    }

    let now = now_rfc3339();
    let updated_current_step = apply_step_mutations(
        &tx,
        &task_id,
        task.current_step_id.as_deref(),
        completed_step_ids.as_deref(),
        step_update.as_ref(),
        current_step_id.as_deref(),
        &now,
    )?;

    if let Some(v) = summary {
        task.summary = v;
    }
    if let Some(v) = verified_facts {
        task.verified_facts = v;
    }
    if let Some(v) = open_risks {
        task.open_risks = v;
    }
    if let Some(v) = missing_checks {
        task.missing_checks = v;
    }

    tx.execute(
        "UPDATE task_room_tasks
         SET status = 'active',
             summary = ?1,
             blocked_reason = NULL,
             current_step_id = ?2,
             verified_facts_json = ?3,
             open_risks_json = ?4,
             missing_checks_json = ?5,
             revision = revision + 1,
             updated_at = ?6
         WHERE task_id = ?7 AND context_id = ?8",
        params![
            task.summary,
            updated_current_step,
            to_json_string(&task.verified_facts)?,
            to_json_string(&task.open_risks)?,
            to_json_string(&task.missing_checks)?,
            now,
            task_id,
            context_id
        ],
    )
    .map_err(|_| store::invalid("failed to resume task"))?;

    append_event(
        &tx,
        &task_id,
        &context_id,
        "resume",
        &task.summary,
        &json!({ "current_step_id": updated_current_step }),
        &now,
    )?;

    touch_context(&tx, &context_id, &now)?;

    let reloaded = load_task_scoped(&tx, &context_id, &task_id)?
        .ok_or_else(|| store::invalid("failed to reload resumed task"))?;
    commit_response(tx, json!({
        "ok": true,
        "action": "resume",
        "context_id": context_id,
        "task": reloaded
    }), "failed to commit resume")
}

fn handle_final_review(conn: &mut Connection, obj: &Map<String, Value>, workspace_binding: &str) -> crate::Result<Value> {
    let handle = req_str(obj, "context_handle", MAX_CONTEXT_HANDLE_LEN)?;
    let task_id = req_str(obj, "task_id", MAX_TASK_ID_LEN)?;
    let review_status = req_review_status(obj)?;
    let summary = opt_text(obj, "summary", MAX_SUMMARY_LEN)?;
    let current_step_id = opt_strict_str(obj, "current_step_id", MAX_STEP_ID_LEN)?;
    let completed_step_ids =
        opt_string_list(obj, "completed_step_ids", MAX_STEPS_COUNT, MAX_STEP_ID_LEN)?;
    let step_update = opt_step_update(obj)?;
    let completion_conditions =
        opt_string_list(obj, "completion_conditions", MAX_LIST_ITEMS, MAX_LIST_ITEM_LEN)?;
    let verified_facts =
        opt_string_list(obj, "verified_facts", MAX_LIST_ITEMS, MAX_LIST_ITEM_LEN)?;
    let open_risks = opt_string_list(obj, "open_risks", MAX_LIST_ITEMS, MAX_LIST_ITEM_LEN)?;
    let missing_checks =
        opt_string_list(obj, "missing_checks", MAX_LIST_ITEMS, MAX_LIST_ITEM_LEN)?;

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| store::invalid("failed to start transaction for final_review"))?;

    let context_id = require_room_context(&tx, &handle, workspace_binding)?;
    let mut task = load_task_scoped(&tx, &context_id, &task_id)?
        .ok_or_else(|| store::denied("task not found in context"))?;

    if task.task_status == "completed" {
        return Err(store::invalid("cannot run final_review on a completed task"));
    }
    if task.task_status == "blocked" {
        return Err(store::invalid(
            "cannot run final_review on a blocked task; resume first",
        ));
    }

    let now = now_rfc3339();
    let updated_current_step = apply_step_mutations(
        &tx,
        &task_id,
        task.current_step_id.as_deref(),
        completed_step_ids.as_deref(),
        step_update.as_ref(),
        current_step_id.as_deref(),
        &now,
    )?;

    if let Some(v) = completion_conditions {
        task.completion_conditions = v;
    }
    if let Some(v) = verified_facts {
        task.verified_facts = v;
    }
    if let Some(v) = open_risks {
        task.open_risks = v;
    }
    if let Some(v) = missing_checks {
        task.missing_checks = v;
    }

    if review_status == "pass" {
        let steps = load_steps(&tx, &task_id)?;
        if steps.iter().any(|s| s.step_status != "completed") {
            return Err(store::invalid(
                "passing final_review requires every defined step completed",
            ));
        }
        if task.verified_facts.is_empty() {
            return Err(store::invalid(
                "passing final_review requires verified_facts",
            ));
        }
        if !task.missing_checks.is_empty() || !task.open_risks.is_empty() {
            return Err(store::invalid(
                "passing final_review requires no open_risks or missing_checks",
            ));
        }
        if updated_current_step.is_some() {
            return Err(store::invalid(
                "passing final_review cannot have an active current step",
            ));
        }
    }

    let review_summary = summary.clone().unwrap_or_default();
    if let Some(v) = summary {
        task.summary = v;
    }

    tx.execute(
        "UPDATE task_room_tasks
         SET summary = ?1,
             current_step_id = ?2,
             completion_conditions_json = ?3,
             verified_facts_json = ?4,
             open_risks_json = ?5,
             missing_checks_json = ?6,
             review_status = ?7,
             review_summary = ?8,
             reviewed_at = ?9,
             revision = revision + 1,
             updated_at = ?9
         WHERE task_id = ?10 AND context_id = ?11",
        params![
            task.summary,
            updated_current_step,
            to_json_string(&task.completion_conditions)?,
            to_json_string(&task.verified_facts)?,
            to_json_string(&task.open_risks)?,
            to_json_string(&task.missing_checks)?,
            review_status,
            review_summary,
            now,
            task_id,
            context_id
        ],
    )
    .map_err(|_| store::invalid("failed to persist final_review"))?;

    append_event(
        &tx,
        &task_id,
        &context_id,
        "final_review",
        &review_summary,
        &json!({
            "review_status": review_status,
            "missing_checks_count": task.missing_checks.len(),
            "open_risks_count": task.open_risks.len()
        }),
        &now,
    )?;

    touch_context(&tx, &context_id, &now)?;

    let reloaded = load_task_scoped(&tx, &context_id, &task_id)?
        .ok_or_else(|| store::invalid("failed to reload reviewed task"))?;
    commit_response(tx, json!({
        "ok": true,
        "action": "final_review",
        "context_id": context_id,
        "task": reloaded
    }), "failed to commit final_review")
}

fn handle_complete(
    conn: &mut Connection, obj: &Map<String, Value>, workspace_binding: &str,
) -> crate::Result<Value> {
    let handle = req_str(obj, "context_handle", MAX_CONTEXT_HANDLE_LEN)?;
    let task_id = req_str(obj, "task_id", MAX_TASK_ID_LEN)?;
    let summary = opt_text(obj, "summary", MAX_SUMMARY_LEN)?;
    if ["completed_step_ids", "step_id", "step_status", "verified_facts",
        "open_risks", "missing_checks", "current_step_id",
        "completion_conditions", "steps"].iter().any(|key| obj.contains_key(*key))
    {
        return Err(store::invalid(
            "complete cannot supply steps or review evidence; pass final_review first",
        ));
    }
    if let Some(status) = opt_review_status(obj)? {
        if status != "pass" {
            return Err(store::invalid("cannot complete a task with a failed review"));
        }
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| store::invalid("failed to start transaction for complete"))?;
    let context_id = require_room_context(&tx, &handle, workspace_binding)?;
    let mut task = load_task_scoped(&tx, &context_id, &task_id)?
        .ok_or_else(|| store::denied("task not found in context"))?;
    if task.task_status != "active" {
        return Err(store::invalid("only active tasks may be completed"));
    }
    if task.review_status.as_deref() != Some("pass") {
        return Err(store::invalid(
            "task requires a passing final_review before completion",
        ));
    }
    let steps = load_steps(&tx, &task_id)?;
    if steps.iter().any(|s| s.step_status != "completed")
        || task.current_step_id.is_some()
    {
        return Err(store::invalid("every task step must already be completed"));
    }
    if task.verified_facts.is_empty() || !task.open_risks.is_empty()
        || !task.missing_checks.is_empty()
    {
        return Err(store::invalid(
            "passing review evidence must remain verified with no open risks/checks",
        ));
    }
    if let Some(value) = summary { task.summary = value; }
    let now = now_rfc3339();
    tx.execute(
        "UPDATE task_room_tasks
         SET status='completed', summary=?1, current_step_id=NULL,
             blocked_reason=NULL, completed_at=?2, revision=revision+1,
             updated_at=?2
         WHERE task_id=?3 AND context_id=?4",
        params![task.summary, now, task_id, context_id],
    ).map_err(|_| store::invalid("failed to complete task"))?;
    append_event(
        &tx, &task_id, &context_id, "complete", &task.summary,
        &json!({"verified_facts_count": task.verified_facts.len()}), &now,
    )?;
    touch_context(&tx, &context_id, &now)?;
    let reloaded = load_task_scoped(&tx, &context_id, &task_id)?
        .ok_or_else(|| store::invalid("failed to reload completed task"))?;
    commit_response(tx, json!({
        "ok":true, "action":"complete", "context_id":context_id, "task":reloaded,
    }), "failed to commit complete")
}

fn touch_context(tx: &Transaction<'_>, context_id: &str, now: &str) -> crate::Result<()> {
    tx.execute(
        "UPDATE task_room_contexts SET updated_at = ?1 WHERE context_id = ?2",
        params![now, context_id],
    )
    .map_err(|_| store::invalid("failed to update context timestamp"))?;
    Ok(())
}

fn replace_steps(
    tx: &Transaction<'_>,
    task_id: &str,
    new_steps: &[StepInput],
    now: &str,
) -> crate::Result<()> {
    let existing = load_steps(tx, task_id)?;
    // A checkpoint may add/reorder/rename steps but cannot erase progress.
    if existing.iter().any(|previous|
        !new_steps.iter().any(|step| step.id == previous.id)
    ) {
        return Err(store::invalid("checkpoint cannot remove existing task steps"));
    }
    let prev_statuses: HashMap<String, String> = existing
        .into_iter()
        .map(|s| (s.id, s.step_status))
        .collect();

    tx.execute(
        "DELETE FROM task_room_steps WHERE task_id = ?1",
        params![task_id],
    )
    .map_err(|_| store::invalid("failed to clear existing task steps"))?;

    for (idx, step) in new_steps.iter().enumerate() {
        let status = prev_statuses
            .get(&step.id)
            .map(String::as_str)
            .unwrap_or("pending");
        tx.execute(
            "INSERT INTO task_room_steps (
                task_id, step_id, position, title, phase, status, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![task_id, step.id, idx as i64, step.title, step.phase, status, now],
        )
        .map_err(|_| store::invalid("failed to insert replaced task step"))?;
    }

    Ok(())
}

fn apply_step_mutations(
    tx: &Transaction<'_>,
    task_id: &str,
    existing_current_step: Option<&str>,
    completed_step_ids: Option<&[String]>,
    step_update: Option<&(String, String)>,
    explicit_current_step: Option<&str>,
    now: &str,
) -> crate::Result<Option<String>> {
    let steps = load_steps(tx, task_id)?;
    if steps.iter().filter(|s| s.step_status == "in_progress").count() > 1 {
        return Err(store::invalid("task contains multiple in_progress steps"));
    }
    let mut next: HashMap<String, String> = steps.iter()
        .map(|s| (s.id.clone(), s.step_status.clone())).collect();

    if let Some(done_ids) = completed_step_ids {
        for sid in done_ids {
            let slot = next.get_mut(sid)
                .ok_or_else(|| store::invalid("completed_step_ids contains unknown step_id"))?;
            *slot = "completed".to_string();
        }
    }
    if let Some((sid, status)) = step_update {
        let slot = next.get_mut(sid)
            .ok_or_else(|| store::invalid("step_id does not exist on task"))?;
        let rank = |s: &str| match s {
            "pending" => 0, "in_progress" => 1, "completed" => 2, _ => -1,
        };
        if rank(status.as_str()) < rank(slot.as_str()) {
            return Err(store::invalid("step status cannot regress"));
        }
        *slot = status.clone();
    }
    let chosen = if let Some(csid) = explicit_current_step {
        let slot = next.get_mut(csid)
            .ok_or_else(|| store::invalid("current_step_id does not exist on task"))?;
        if slot.as_str() == "completed" {
            return Err(store::invalid("completed step cannot be current"));
        }
        if slot.as_str() == "pending" { *slot = "in_progress".to_string(); }
        Some(csid.to_string())
    } else {
        let active = steps.iter()
            .find(|s| next.get(&s.id).is_some_and(|status| status.as_str() == "in_progress"))
            .map(|s| s.id.clone());
        let current = existing_current_step
            .filter(|id| next.get(*id).is_some_and(|status| status.as_str() == "pending"))
            .map(str::to_string);
        let chosen = active.or(current).or_else(|| steps.iter()
            .find(|s| next.get(&s.id).is_some_and(|status| status.as_str() == "pending"))
            .map(|s| s.id.clone()));
        if let Some(ref id) = chosen {
            if let Some(status) = next.get_mut(id) {
                if status.as_str() == "pending" { *status = "in_progress".to_string(); }
            }
        }
        chosen
    };

    let progress = next.iter().filter(|(_, status)| status.as_str() == "in_progress")
        .map(|(id, _)| id.as_str()).collect::<Vec<_>>();
    if progress.len() > 1 || progress.first().copied() != chosen.as_deref() {
        return Err(store::invalid(
            "exactly the current step must be in_progress; complete it before advancing",
        ));
    }
    for old in &steps {
        let new_status = next.get(&old.id)
            .ok_or_else(|| store::invalid("task step disappeared"))?;
        if old.step_status.as_str() != new_status.as_str() {
            tx.execute(
                "UPDATE task_room_steps SET status=?1, updated_at=?2
                 WHERE task_id=?3 AND step_id=?4",
                params![new_status, now, task_id, old.id],
            ).map_err(|_| store::invalid("failed to update task step"))?;
        }
    }
    Ok(chosen)
}

fn append_event(
    tx: &Transaction<'_>,
    task_id: &str,
    context_id: &str,
    event_type: &str,
    summary: &str,
    payload: &Value,
    now: &str,
) -> crate::Result<()> {
    let event_id = store::new_id("tevt");
    let payload_json = serde_json::to_string(payload)
        .map_err(|_| store::invalid("failed to serialize task event payload"))?;
    tx.execute(
        "INSERT INTO task_room_events (
            event_id, task_id, context_id, event_type, summary, payload_json, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            event_id,
            task_id,
            context_id,
            event_type,
            summary,
            payload_json,
            now
        ],
    )
    .map_err(|_| store::invalid("failed to append task room event"))?;
    Ok(())
}

fn load_context(conn: &Connection, context_id: &str) -> crate::Result<Option<ContextRecord>> {
    conn.query_row(
        "SELECT context_id, label, project, device, created_at, updated_at, last_reattached_at
         FROM task_room_contexts
         WHERE context_id = ?1",
        params![context_id],
        |row| {
            Ok(ContextRecord {
                context_id: row.get(0)?,
                context_label: row.get(1)?,
                project: row.get(2)?,
                device: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
                last_reattached_at: row.get(6)?,
            })
        },
    )
    .optional()
    .map_err(|_| store::invalid("failed to query task room context"))
}

fn load_context_counts(conn: &Connection, context_id: &str) -> crate::Result<DiscoveryCounts> {
    conn.query_row(
        "SELECT
            COALESCE(SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0),
            COUNT(*)
         FROM task_room_tasks
         WHERE context_id = ?1",
        params![context_id],
        |row| {
            Ok(DiscoveryCounts {
                active: row.get(0)?,
                blocked: row.get(1)?,
                completed: row.get(2)?,
                total: row.get(3)?,
            })
        },
    )
    .map_err(|_| store::invalid("failed to aggregate context task counts"))
}



fn load_task_scoped(
    conn: &Connection,
    context_id: &str,
    task_id: &str,
) -> crate::Result<Option<TaskRecord>> {
    let row = conn
        .query_row(
            "SELECT
                task_id, context_id, title, goal, status, summary, project, device,
                current_step_id, completion_conditions_json, verified_facts_json,
                open_risks_json, missing_checks_json, blocked_reason, review_status,
                review_summary, reviewed_at, completed_at, revision, created_at, updated_at
             FROM task_room_tasks
             WHERE task_id = ?1 AND context_id = ?2",
            params![task_id, context_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, Option<String>>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, String>(10)?,
                    r.get::<_, String>(11)?,
                    r.get::<_, String>(12)?,
                    r.get::<_, Option<String>>(13)?,
                    r.get::<_, Option<String>>(14)?,
                    r.get::<_, Option<String>>(15)?,
                    r.get::<_, Option<String>>(16)?,
                    r.get::<_, Option<String>>(17)?,
                    r.get::<_, i64>(18)?,
                    r.get::<_, String>(19)?,
                    r.get::<_, String>(20)?,
                ))
            },
        )
        .optional()
        .map_err(|_| store::invalid("failed to query task room task"))?;

    let Some(r) = row else {
        return Ok(None);
    };

    let steps = load_steps(conn, &r.0)?;
    let verified_facts = from_json_string_vec(&r.10)?;
    let open_risks = from_json_string_vec(&r.11)?;
    let missing_checks = from_json_string_vec(&r.12)?;
    let final_review = if let (Some(status), Some(reviewed_at)) = (&r.14, &r.16) {
        let id: Option<String> = conn.query_row(
            "SELECT event_id FROM task_room_events WHERE task_id=?1 AND context_id=?2
             AND event_type='final_review' ORDER BY rowid DESC LIMIT 1",
            params![task_id, context_id], |row| row.get(0),
        ).optional().map_err(|_| store::invalid("failed to load final review"))?;
        Some(json!({"status":status,"summary":r.15,"review_revision":id,"reviewed_at":reviewed_at,
            "verified_facts":verified_facts,"open_risks":open_risks,"missing_checks":missing_checks}))
    } else { None };
    Ok(Some(TaskRecord {
        id: r.0.clone(),
        task_id: r.0,
        context_id: r.1,
        title: r.2,
        goal: r.3,
        status: r.4.clone(),
        task_status: r.4,
        summary: r.5,
        project: r.6,
        device: r.7,
        current_step_id: r.8,
        steps,
        completion_conditions: from_json_string_vec(&r.9)?,
        verified_facts,
        open_risks,
        missing_checks,
        blocked_reason: r.13,
        review_status: r.14,
        review_summary: r.15,
        final_review,
        reviewed_at: r.16,
        completed_at: r.17,
        revision: r.18,
        created_at: r.19,
        updated_at: r.20,
    }))
}

fn load_compact_tasks_for_context(
    conn: &Connection,
    context_id: &str,
    status_filter: Option<&str>,
    project_filter: Option<&str>,
    device_filter: Option<&str>,
    limit: usize,
    include_resume: bool,
) -> crate::Result<(Vec<TaskDigest>, usize)> {
    let mut stmt = conn.prepare(
        "SELECT task_id, title, status, current_step_id, revision, updated_at, review_status,
            (SELECT count(*) FROM task_room_steps s WHERE s.task_id=t.task_id),
            (SELECT count(*) FROM task_room_steps s WHERE s.task_id=t.task_id AND s.status='completed'),
            goal, summary, blocked_reason, created_at, completed_at
         FROM task_room_tasks t
         WHERE context_id=?1
           AND (?2 IS NULL OR status=?2)
           AND (?3 IS NULL OR project=?3)
           AND (?4 IS NULL OR device=?4)
         ORDER BY updated_at DESC, task_id DESC LIMIT ?5",
    ).map_err(|_| store::invalid("failed to prepare Task Room list"))?;
    let rows = stmt.query_map(
        params![context_id, status_filter, project_filter, device_filter, limit as i64],
        |row| {
            let id: String = row.get(0)?;
            let status: String = row.get(2)?;
            let current: Option<String> = row.get(3)?;
            let mut steps = json!({"total":row.get::<_,i64>(7)?,"completed":row.get::<_,i64>(8)?});
            if let Some(id) = &current { steps["current"] = json!(id); }
            Ok(TaskDigest {
                id: id.clone(), task_id: id,
                title: row.get(1)?, status: status.clone(),
                task_status: status, current_step_id: current, steps, final_review: row.get(6)?,
                revision: row.get(4)?, updated_at: row.get(5)?,
                goal: None, summary: None, blocker: None, blocked_reason: None,
                created_at: None, completed_at: None, truncated_fields: Vec::new(),
                resume: if include_resume { Some(ListResumeFields {
                    goal: row.get(9)?, summary: row.get(10)?,
                    blocked_reason: row.get(11)?, created_at: row.get(12)?,
                    completed_at: row.get(13)?,
                }) } else { None },
                legacy_bytes: 0,
            })
        },
    ).map_err(|_| store::invalid("failed to query Task Room list"))?;
    let mut tasks = Vec::new();
    let mut rows_bytes = 0usize;
    for row in rows {
        let mut task = row.map_err(|_| store::invalid("failed to decode Task Room list"))?;
        task.legacy_bytes = serde_json::to_vec(&task)
            .map_err(|_| store::invalid("failed to size Task Room digest"))?.len();
        rows_bytes = rows_bytes.saturating_add(task.legacy_bytes);
        tasks.push(task);
    }
    Ok((tasks, rows_bytes))
}

// Only preview new content; the legacy digest is never modified.
#[derive(Debug, Clone)]
struct ListResumeFields {
    goal: String,
    summary: String,
    blocked_reason: Option<String>,
    created_at: String,
    completed_at: Option<String>,
}

fn list_preview(text: &str, max_bytes: usize) -> (String, bool) {
    let mut end = text.len().min(max_bytes);
    while !text.is_char_boundary(end) { end -= 1; }
    (text[..end].to_owned(), end != text.len())
}

fn load_steps(conn: &Connection, task_id: &str) -> crate::Result<Vec<StepRecord>> {
    let mut stmt = conn
        .prepare(
            "SELECT step_id, title, phase, status, updated_at
             FROM task_room_steps
             WHERE task_id = ?1
             ORDER BY position ASC",
        )
        .map_err(|_| store::invalid("failed to prepare task steps query"))?;

    let rows = stmt
        .query_map(params![task_id], |row| {
            Ok(StepRecord {
                id: row.get(0)?,
                title: row.get(1)?,
                phase: row.get(2)?,
                status: row.get(3)?,
                step_status: row.get(3)?,
                updated_at: row.get(4)?,
            })
        })
        .map_err(|_| store::invalid("failed to query task steps"))?;

    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| store::invalid("failed to decode task steps"))
}

// The historical client consumes events[].type, while Rust clients retain
// events[].event_type. Translate on read, including rows written before this
// compatibility change; never rewrite stored events or event IDs.
fn historical_event_type(event_type: &str) -> &str {
    match event_type {
        "create" | "created" => "created",
        "checkpoint" => "checkpoint",
        "block" | "blocked" => "blocked",
        "resume" | "resumed" => "resumed",
        "final_review" => "final_review",
        "complete" | "completed" => "completed",
        other => other,
    }
}

fn load_recent_events(
    conn: &Connection,
    task_id: &str,
    limit: usize,
) -> crate::Result<Vec<EventRecord>> {
    let mut stmt = conn
        .prepare(
            "SELECT event_id, event_type, summary, payload_json, created_at
             FROM task_room_events
             WHERE task_id = ?1
             ORDER BY created_at DESC, rowid DESC
             LIMIT ?2",
        )
        .map_err(|_| store::invalid("failed to prepare task events query"))?;

    let raw = stmt
        .query_map(params![task_id, limit as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|_| store::invalid("failed to query task events"))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| store::invalid("failed to decode task events"))?;

    let mut events = Vec::with_capacity(raw.len());
    for (event_id, event_type, summary, payload_json, created_at) in raw.into_iter().rev() {
        let payload = serde_json::from_str(&payload_json).unwrap_or_else(|_| json!({}));
        events.push(EventRecord {
            event_id,
            client_type: historical_event_type(&event_type).to_owned(),
            event_type,
            summary,
            payload,
            created_at,
        });
    }
    Ok(events)
}

fn req_str(
    obj: &Map<String, Value>,
    key: &'static str,
    limit: usize,
) -> crate::Result<String> {
    let value = obj
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| store::invalid("missing or non-string required field"))?;
    store::require_text(value, limit, key)?;
    Ok(value.to_string())
}

fn opt_strict_str(
    obj: &Map<String, Value>,
    key: &'static str,
    limit: usize,
) -> crate::Result<Option<String>> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            store::require_text(s, limit, key)?;
            Ok(Some(s.clone()))
        }
        Some(_) => Err(store::invalid("expected string field")),
    }
}

fn opt_text(
    obj: &Map<String, Value>,
    key: &'static str,
    limit: usize,
) -> crate::Result<Option<String>> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            if s.is_empty() {
                return Ok(Some(String::new()));
            }
            store::require_text(s, limit, key)?;
            Ok(Some(s.clone()))
        }
        Some(_) => Err(store::invalid("expected string field")),
    }
}

fn opt_limit(obj: &Map<String, Value>) -> crate::Result<usize> {
    match obj.get("limit") {
        None | Some(Value::Null) => Ok(DEFAULT_LIMIT),
        Some(v) => {
            let n = v
                .as_u64()
                .ok_or_else(|| store::invalid("limit must be an integer between 1 and 200"))?;
            if n < 1 || n > MAX_LIMIT as u64 {
                return Err(store::invalid("limit must be an integer between 1 and 200"));
            }
            Ok(n as usize)
        }
    }
}

fn opt_task_status(obj: &Map<String, Value>) -> crate::Result<Option<String>> {
    let Some(status) = opt_strict_str(obj, "task_status", 32)? else {
        return Ok(None);
    };
    match status.as_str() {
        "active" | "blocked" | "completed" => Ok(Some(status)),
        _ => Err(store::invalid(
            "task_status must be one of: active, blocked, completed",
        )),
    }
}

fn req_review_status(obj: &Map<String, Value>) -> crate::Result<String> {
    let status = req_str(obj, "review_status", 32)?;
    match status.as_str() {
        "pass" | "failed" => Ok(status),
        _ => Err(store::invalid("review_status must be one of: pass, failed")),
    }
}

fn opt_review_status(obj: &Map<String, Value>) -> crate::Result<Option<String>> {
    let Some(status) = opt_strict_str(obj, "review_status", 32)? else {
        return Ok(None);
    };
    match status.as_str() {
        "pass" | "failed" => Ok(Some(status)),
        _ => Err(store::invalid("review_status must be one of: pass, failed")),
    }
}

fn opt_step_update(obj: &Map<String, Value>) -> crate::Result<Option<(String, String)>> {
    let step_id = opt_strict_str(obj, "step_id", MAX_STEP_ID_LEN)?;
    let step_status = opt_strict_str(obj, "step_status", 32)?;
    match (step_id, step_status) {
        (None, None) => Ok(None),
        (Some(sid), Some(status)) => match status.as_str() {
            "pending" | "in_progress" | "completed" => Ok(Some((sid, status))),
            _ => Err(store::invalid(
                "step_status must be one of: pending, in_progress, completed",
            )),
        },
        _ => Err(store::invalid(
            "step_id and step_status must be provided together",
        )),
    }
}

fn opt_string_list(
    obj: &Map<String, Value>,
    key: &'static str,
    max_items: usize,
    max_item_len: usize,
) -> crate::Result<Option<Vec<String>>> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => {
            if items.len() > max_items {
                return Err(store::invalid("array field exceeds schema maxItems"));
            }
            let mut out = Vec::with_capacity(items.len());
            let mut seen = HashSet::with_capacity(items.len());
            for item in items {
                let s = item
                    .as_str()
                    .ok_or_else(|| store::invalid("array items must be strings"))?;
                store::require_text(s, max_item_len, key)?;
                if seen.insert(s.to_string()) {
                    out.push(s.to_string());
                }
            }
            Ok(Some(out))
        }
        Some(_) => Err(store::invalid("expected array of strings")),
    }
}

fn opt_steps(obj: &Map<String, Value>) -> crate::Result<Option<Vec<StepInput>>> {
    match obj.get("steps") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => {
            if items.len() > MAX_STEPS_COUNT {
                return Err(store::invalid("steps exceeds maxItems (12)"));
            }
            let mut out = Vec::with_capacity(items.len());
            let mut seen_ids = HashSet::with_capacity(items.len());
            for item in items {
                let step_obj = item
                    .as_object()
                    .ok_or_else(|| store::invalid("each step must be an object"))?;
                let id = req_str(step_obj, "id", MAX_STEP_ID_LEN)?;
                let title = req_str(step_obj, "title", MAX_STEP_TITLE_LEN)?;
                let phase = match opt_strict_str(step_obj, "phase", 32)? {
                    None => None,
                    Some(p) => match p.as_str() {
                        "check" | "execute" | "verify" | "closeout" => Some(p),
                        _ => {
                            return Err(store::invalid(
                                "step phase must be one of: check, execute, verify, closeout",
                            ));
                        }
                    },
                };
                if !seen_ids.insert(id.clone()) {
                    return Err(store::invalid("duplicate step id in steps array"));
                }
                out.push(StepInput { id, title, phase });
            }
            Ok(Some(out))
        }
        Some(_) => Err(store::invalid("steps must be an array")),
    }
}

fn to_json_string(items: &[String]) -> crate::Result<String> {
    serde_json::to_string(items).map_err(|_| store::invalid("failed to serialize string list"))
}

fn from_json_string_vec(raw: &str) -> crate::Result<Vec<String>> {
    serde_json::from_str(raw)
        .map_err(|_| store::invalid("corrupt JSON list in task room database"))
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}
