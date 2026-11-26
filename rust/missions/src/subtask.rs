//! Web-agent subtasks on *existing* schema-7 operations/events.
//! No shadow subtask table: the latest event for each public locator points
//! to an operation whose result_json is the complete current subtask.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};

use crate::store::{
    append_event, attached_assignee, denied, digest_json, fetch_mission, insert_operation,
    invalid, membership, new_id, replay, require_context, require_id, require_key,
    require_text, touch, verify_schema, write, BridgeError, Result,
};

pub const SUBTASK_EVENT: &str = "mission.subtask";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionSubtask {
    pub subtask_id: String,
    pub mission_id: String,
    pub goal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee_context_id: Option<String>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_reason: Option<String>,
    pub revision: i64,
    pub created_revision: i64,
    pub mission_revision: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubtaskMutation {
    pub subtask: MissionSubtask,
    pub replayed: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct SubtaskPage {
    pub subtasks: Vec<MissionSubtask>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_after_created_revision: Option<i64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSubtaskRequest {
    pub mission_id: String,
    pub goal: String,
    pub idempotency_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee_context_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignSubtaskRequest {
    pub mission_id: String,
    pub subtask_id: String,
    pub assignee_context_id: String,
    pub if_revision: i64,
    pub idempotency_key: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSubtaskRequest {
    pub mission_id: String,
    pub subtask_id: String,
    pub if_revision: i64,
    pub status: String,
    pub idempotency_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct ListSubtasksRequest {
    pub mission_id: String,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub after_created_revision: i64,
    #[serde(default)]
    pub subtask_id: Option<String>,
}
fn default_limit() -> i64 { 20 }
#[derive(Serialize)]
struct OperationDigest<'a, T> {
    method: &'a str,
    actor: &'a str,
    request: &'a T,
}

fn mutation_parameters(mission: &str, key: &str) -> Result<()> {
    require_id("mis", mission)?;
    require_key(key)
}
fn update_parameters(mission: &str, key: &str, subtask: &str, revision: i64) -> Result<()> {
    mutation_parameters(mission, key)?;
    require_id("sub", subtask)?;
    if revision < 1 { return Err(invalid("A positive subtask revision is required.")); }
    Ok(())
}
fn open_mission(tx: &Connection, mission: &str) -> Result<crate::store::MissionDto> {
    let value = fetch_mission(tx, mission)?;
    if value.status == "completed" {
        return Err(BridgeError::new("INVALID_TRANSITION", "Completed missions cannot modify subtasks."));
    }
    Ok(value)
}
fn locator(id: &str) -> String {
    // This exact redacted JSON is the persisted C# v7 event locator.
    format!(r#"{{"subtask_id":"{id}"}}"#)
}
fn read_subtask(
    tx: &Connection, mission: &str, subtask_id: &str
) -> Result<Option<MissionSubtask>> {
    let result: Option<String> = tx.query_row(
        "SELECT o.result_json FROM events e \
         JOIN operations o ON o.operation_id=e.operation_id AND o.mission_id=e.mission_id \
         WHERE e.mission_id=?1 AND e.event_type=?2 AND e.payload_redacted=?3 \
         ORDER BY e.event_seq DESC LIMIT 1",
        params![mission, SUBTASK_EVENT, locator(subtask_id)],
        |row| row.get(0),
    ).optional()?;
    result.map(|value| serde_json::from_str::<MissionSubtask>(&value)
        .map_err(|_| BridgeError::new("INTERNAL_ERROR", "Stored subtask cannot be decoded.")))
        .transpose()
}
fn record(
    tx: &Transaction<'_>, method: &str, key: &str, digest: &str,
    subtask: MissionSubtask
) -> Result<SubtaskMutation> {
    let operation = new_id("op");
    insert_operation(tx, &operation, &subtask.mission_id, key, digest, &subtask, method)?;
    append_event(
        tx, &subtask.mission_id, Some(&operation),
        SUBTASK_EVENT, &locator(&subtask.subtask_id),
    )?;
    Ok(SubtaskMutation { subtask, replayed: false })
}

pub fn create_subtask(
    conn: &mut Connection, actor_handle: &str, request: CreateSubtaskRequest
) -> Result<SubtaskMutation> {
    mutation_parameters(&request.mission_id, &request.idempotency_key)?;
    require_text(&request.goal, 2048, "Subtask goal must be 1-2048 characters.")?;
    if let Some(ref assignee) = request.assignee_context_id { require_id("ctx", assignee)?; }
    let method = "Mission.Subtask.Create";
    write(conn, |tx| {
        let actor = require_context(tx, actor_handle)?;
        membership(tx, &request.mission_id, &actor, true)?;
        let digest = digest_json(&OperationDigest { method, actor: &actor, request: &request })?;
        if let Some(prior) = replay::<MissionSubtask>(tx, &request.idempotency_key, &digest)? {
            return Ok(SubtaskMutation { subtask: prior, replayed: true });
        }
        if let Some(ref assignee) = request.assignee_context_id {
            attached_assignee(tx, &request.mission_id, assignee)?;
        }
        let current = open_mission(tx, &request.mission_id)?;
        let next = touch(tx, &current, current.revision)?;
        let subtask = MissionSubtask {
            subtask_id: new_id("sub"), mission_id: request.mission_id.clone(),
            goal: request.goal.clone(), assignee_context_id: request.assignee_context_id.clone(),
            status: "pending".into(), summary: None, release_reason: None, revision: 1,
            created_revision: next.revision, mission_revision: next.revision,
            created_at: next.updated_at.clone(), updated_at: next.updated_at,
        };
        record(tx, method, &request.idempotency_key, &digest, subtask)
    })
}

pub fn assign_subtask(
    conn: &mut Connection, actor_handle: &str, request: AssignSubtaskRequest
) -> Result<SubtaskMutation> {
    update_parameters(
        &request.mission_id, &request.idempotency_key, &request.subtask_id, request.if_revision
    )?;
    require_id("ctx", &request.assignee_context_id)?;
    let method = "Mission.Subtask.Assign";
    write(conn, |tx| {
        let actor = require_context(tx, actor_handle)?;
        membership(tx, &request.mission_id, &actor, true)?;
        let digest = digest_json(&OperationDigest { method, actor: &actor, request: &request })?;
        if let Some(prior) = replay::<MissionSubtask>(tx, &request.idempotency_key, &digest)? {
            return Ok(SubtaskMutation { subtask: prior, replayed: true });
        }
        attached_assignee(tx, &request.mission_id, &request.assignee_context_id)?;
        let current = read_subtask(tx, &request.mission_id, &request.subtask_id)?
            .ok_or_else(|| BridgeError::new("NOT_FOUND", "Subtask not found."))?;
        if current.revision != request.if_revision {
            return Err(BridgeError::new("CONFLICT_REVISION", "Subtask changed since observation."));
        }
        if !matches!(current.status.as_str(), "pending" | "blocked")
            || current.assignee_context_id.as_deref() == Some(request.assignee_context_id.as_str())
        {
            return Err(BridgeError::new("INVALID_TRANSITION",
                "Only pending or blocked subtasks can be assigned to a different attached context."));
        }
        let mission = open_mission(tx, &request.mission_id)?;
        let next = touch(tx, &mission, mission.revision)?;
        let updated = MissionSubtask {
            assignee_context_id: Some(request.assignee_context_id.clone()),
            status: "pending".into(),
            revision: current.revision.checked_add(1)
                .ok_or_else(|| invalid("Subtask revision overflow."))?,
            mission_revision: next.revision, updated_at: next.updated_at,
            ..current
        };
        record(tx, method, &request.idempotency_key, &digest, updated)
    })
}

pub fn update_subtask(
    conn: &mut Connection, actor_handle: &str, request: UpdateSubtaskRequest
) -> Result<SubtaskMutation> {
    update_parameters(
        &request.mission_id, &request.idempotency_key, &request.subtask_id, request.if_revision
    )?;
    if !matches!(request.status.as_str(), "in_progress" | "blocked" | "completed")
        || (request.status != "in_progress" && request.summary.is_none())
    {
        return Err(invalid("Provide a valid status and a summary for blocked or completed work."));
    }
    if let Some(ref summary) = request.summary {
        require_text(summary, 4096, "Subtask summary must be 1-4096 characters.")?;
    }
    let method = "Mission.Subtask.Update";
    write(conn, |tx| {
        let actor = require_context(tx, actor_handle)?;
        membership(tx, &request.mission_id, &actor, false)?;
        let current = read_subtask(tx, &request.mission_id, &request.subtask_id)?
            .ok_or_else(|| BridgeError::new("NOT_FOUND", "Subtask not found."))?;
        let is_assignee: Option<i64> = tx.query_row(
            "SELECT 1 FROM agent_contexts WHERE context_id=?1 AND handle_hash=?2",
            params![current.assignee_context_id.as_deref(), actor], |r| r.get(0),
        ).optional()?;
        // On the existing blocked transition, an owner can release another
        // context's assignment. An assignee's own update retains its assignment.
        let owner_release = is_assignee.is_none();
        if owner_release {
            if request.status != "blocked" {
                return Err(denied("Only the assigned context can update this subtask."));
            }
            membership(tx, &request.mission_id, &actor, true)?;
        }
        let digest = digest_json(&OperationDigest { method, actor: &actor, request: &request })?;
        if let Some(prior) = replay::<MissionSubtask>(tx, &request.idempotency_key, &digest)? {
            // A release clears the assignment in its receipt; a regular update retains it.
            if prior.assignee_context_id.is_none() {
                membership(tx, &request.mission_id, &actor, true)?;
            } else if owner_release {
                return Err(denied("Only the assigned context can update this subtask."));
            }
            return Ok(SubtaskMutation { subtask: prior, replayed: true });
        }
        if current.revision != request.if_revision {
            return Err(BridgeError::new("CONFLICT_REVISION", "Subtask changed since observation."));
        }
        let allowed = matches!(
            (current.status.as_str(), request.status.as_str()),
            ("pending" | "blocked", "in_progress") |
            ("in_progress", "blocked" | "completed")
        );
        if !allowed {
            return Err(BridgeError::new("INVALID_TRANSITION", "Subtask status transition is not allowed."));
        }
        let mission = open_mission(tx, &request.mission_id)?;
        let next = touch(tx, &mission, mission.revision)?;
        let (summary, release_reason) = if owner_release {
            (current.summary, request.summary)
        } else {
            (request.summary.or(current.summary), current.release_reason)
        };
        let updated = MissionSubtask {
            assignee_context_id: if owner_release { None } else { current.assignee_context_id },
            status: request.status.clone(),
            summary,
            release_reason,
            revision: current.revision.checked_add(1)
                .ok_or_else(|| invalid("Subtask revision overflow."))?,
            mission_revision: next.revision,
            updated_at: next.updated_at,
            ..current
        };
        record(tx, method, &request.idempotency_key, &digest, updated)
    })
}

pub fn list_subtasks(
    conn: &Connection, actor_handle: &str, request: ListSubtasksRequest
) -> Result<SubtaskPage> {
    verify_schema(conn)?;
    require_id("mis", &request.mission_id)?;
    if !(1..=20).contains(&request.limit) || request.after_created_revision < 0
        || (request.subtask_id.is_some() && request.after_created_revision != 0)
    {
        return Err(invalid("Invalid subtask selection or page."));
    }
    if let Some(ref id) = request.subtask_id { require_id("sub", id)?; }
    let actor = require_context(conn, actor_handle)?;
    // Include the caller CTE in this same query even for an empty page.
    let mut statement = conn.prepare(
        "WITH caller AS ( \
           SELECT mission_id FROM mission_memberships \
           WHERE mission_id=?1 AND context_hash=?2 AND state='attached' \
         ), latest AS ( \
           SELECT MAX(e.event_seq) AS event_seq \
           FROM caller JOIN events e ON e.mission_id=caller.mission_id \
           WHERE e.event_type=?3 AND (?4 IS NULL OR e.payload_redacted=?4) \
           GROUP BY e.payload_redacted \
         ), page AS ( \
           SELECT o.result_json,json_extract(o.result_json,'$.created_revision') AS created_revision \
           FROM latest JOIN events e ON e.event_seq=latest.event_seq \
           JOIN operations o ON o.operation_id=e.operation_id AND o.mission_id=e.mission_id \
           WHERE created_revision > ?5 ORDER BY created_revision LIMIT ?6 \
         ) \
         SELECT page.result_json FROM caller LEFT JOIN page ON true \
         ORDER BY page.created_revision"
    )?;
    let selected = request.subtask_id.as_deref().map(locator);
    let mut rows = statement.query(params![
        request.mission_id, actor, SUBTASK_EVENT, selected, request.after_created_revision,
        request.limit + 1
    ])?;
    let mut found_caller = false;
    let mut subtasks: Vec<MissionSubtask> = Vec::new();
    while let Some(row) = rows.next()? {
        found_caller = true;
        let result: Option<String> = row.get(0)?;
        if let Some(result) = result {
            if subtasks.len() == request.limit as usize {
                return Ok(SubtaskPage {
                    next_after_created_revision: subtasks.last().map(|s| s.created_revision),
                    subtasks,
                });
            }
            let subtask: MissionSubtask = serde_json::from_str(&result).map_err(|_| {
                BridgeError::new("INTERNAL_ERROR", "Stored subtask page cannot be decoded.")
            })?;
            if subtask.mission_id != request.mission_id || subtask.created_revision < 1 {
                return Err(BridgeError::new("INTERNAL_ERROR", "Subtask history has invalid provenance."));
            }
            subtasks.push(subtask);
        }
    }
    if !found_caller { return Err(denied("Context is not attached to mission.")); }
    Ok(SubtaskPage { subtasks, next_after_created_revision: None })
}
