//! Read-only operator inspection helpers for the local Agent Bridge UI and
//! cryptographic token generation. Never returns raw handles or handle hashes.

use chrono::{DateTime, SecondsFormat, Utc};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::time::SystemTime;

use crate::store::{invalid, verify_schema, Result, SCHEMA_VERSION};

const MAX_SESSION_DISPLAY_TEXT: usize = 200;

/// Generate a cryptographically random lowercase hexadecimal token with
/// `byte_len` bytes of OS entropy (resulting in `2 * byte_len` hex chars).
pub fn random_token_hex(byte_len: usize) -> String {
    let len = byte_len.clamp(16, 64);
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn utc_timestamp(time: SystemTime) -> String {
    DateTime::<Utc>::from(time).to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Return linked contexts in input order and up to 20 eligible earlier contexts.
/// The byte budget shares the operator transport limit across all context rows.
/// For the local authenticated view, project only the bounded mission goal and
/// subtask title as free-form display text, alongside their status metadata.
pub fn inspect_session_contexts(
    conn: &Connection,
    linked: &[String],
    seen: Option<&BTreeSet<String>>,
    byte_budget: usize,
) -> Result<(Vec<Option<Value>>, Vec<Value>)> {
    verify_schema(conn)?;
    let tx = conn.unchecked_transaction()?;
    let mut earlier_ids = Vec::new();
    if let Some(seen) = seen {
        let mut stmt = tx.prepare(
            "SELECT a.context_id FROM agent_contexts a
             WHERE a.context_id NOT IN (SELECT value FROM json_each(?1))
               AND EXISTS (
                   SELECT 1 FROM mission_memberships mm JOIN missions m USING (mission_id)
                   WHERE mm.context_hash=a.handle_hash AND mm.state='attached'
                     AND m.status IN ('active','blocked')
               )
             ORDER BY julianday(a.last_seen) DESC, julianday(a.attached_at) DESC, a.context_id
             LIMIT 20",
        )?;
        let excluded = serde_json::to_string(seen)?;
        earlier_ids = stmt.query_map([excluded], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<_>>()?;
    }

    let per_context = byte_budget / (linked.len() + earlier_ids.len()).max(1);
    let mut context_stmt = tx.prepare(
        "SELECT actor_kind, attached_at, last_seen FROM agent_contexts WHERE context_id=?1",
    )?;
    let mut mission_stmt = tx.prepare(
        "SELECT m.mission_id, m.goal, m.status, m.current_revision, m.updated_at, mm.role
         FROM agent_contexts a JOIN mission_memberships mm ON mm.context_hash=a.handle_hash
         JOIN missions m ON m.mission_id=mm.mission_id
         WHERE a.context_id=?1 AND mm.state='attached'
         ORDER BY m.updated_at DESC, m.mission_id LIMIT 20",
    )?;
    let mut subtask_stmt = tx.prepare(
        "WITH latest AS (
             SELECT MAX(event_seq) AS event_seq FROM events
             WHERE mission_id=?1 AND event_type=?3 GROUP BY payload_redacted
             ORDER BY event_seq DESC LIMIT 20
         )
         SELECT json_extract(o.result_json,'$.subtask_id'),
                json_extract(o.result_json,'$.goal'),
                json_extract(o.result_json,'$.status'),
                json_extract(o.result_json,'$.assignee_context_id') IS ?2
         FROM latest JOIN events e USING (event_seq)
         JOIN operations o ON o.operation_id=e.operation_id AND o.mission_id=e.mission_id
         ORDER BY e.event_seq DESC",
    )?;
    let mut read_context = |id: &str| -> Result<Option<Value>> {
        let row = context_stmt.query_row([id], |row| {
            Ok(json!({
                "context_id": cap(id, 64),
                "actor_kind": cap(&row.get::<_, String>(0)?, 64),
                "attached_at": row.get::<_, Option<String>>(1)?.map(|s| cap(&s, 64)),
                "last_seen": row.get::<_, Option<String>>(2)?.map(|s| cap(&s, 64)),
                "missions": [],
            }))
        }).optional()?;
        let Some(mut context) = row else { return Ok(None); };
        let Some(mut remaining) = per_context.checked_sub(serde_json::to_vec(&context)?.len() + 1) else {
            return Ok(None);
        };
        let mut missions = Vec::new();
        let mission_rows = mission_stmt.query_map([id], |row| {
            let mission_id: String = row.get(0)?;
            let view = json!({
                "mission_id": cap(&mission_id, 64),
                "goal": cap(&row.get::<_, String>(1)?, MAX_SESSION_DISPLAY_TEXT),
                "status": cap(&row.get::<_, String>(2)?, 32),
                "revision": row.get::<_, i64>(3)?,
                "updated_at": cap(&row.get::<_, String>(4)?, 64),
                "role": cap(&row.get::<_, String>(5)?, 32),
                "subtasks": [],
            });
            Ok((mission_id, view))
        })?;
        for mission in mission_rows {
            let (mission_id, mut view) = mission?;
            let size = serde_json::to_vec(&view)?.len() + 1;
            if size > remaining { break; }
            remaining -= size;
            let tasks = subtask_stmt.query_map(params![mission_id, id, crate::subtask::SUBTASK_EVENT], |row| {
                Ok(json!({
                    "id": cap(&row.get::<_, String>(0)?, 64),
                    "title": cap(&row.get::<_, String>(1)?, MAX_SESSION_DISPLAY_TEXT),
                    "status": cap(&row.get::<_, String>(2)?, 32),
                    "assigned_to_context": row.get::<_, bool>(3)?,
                }))
            })?;
            let mut subtasks = Vec::new();
            for task in tasks {
                let task = task?;
                let size = serde_json::to_vec(&task)?.len() + 1;
                if size > remaining { break; }
                remaining -= size;
                subtasks.push(task);
            }
            view["subtasks"] = Value::Array(subtasks);
            missions.push(view);
        }
        context["missions"] = Value::Array(missions);
        Ok(Some(context))
    };
    let current = linked.iter().map(|id| read_context(id)).collect::<Result<_>>()?;
    let earlier = earlier_ids.iter().map(|id| read_context(id))
        .collect::<Result<Vec<_>>>()?.into_iter().flatten().collect();
    Ok((current, earlier))
}

fn cap(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

/// Produce a bounded, read-only operator snapshot of durable missions, their
/// latest checkpoints, and (when present) Task Room tasks and contexts.
/// Secret capability handles and hashes are strictly excluded.
pub fn inspect_operator_snapshot(conn: &Connection, limit: i64) -> Result<Value> {
    verify_schema(conn)?;
    if !(1..=200).contains(&limit) {
        return Err(invalid("Operator inspection limit must be 1-200."));
    }

    let mut mission_stmt = conn.prepare(
        "SELECT m.mission_id, m.goal, m.status, m.current_revision, m.project_id, \
                m.created_at, m.updated_at, \
                (SELECT COUNT(*) FROM mission_checkpoints cp WHERE cp.mission_id = m.mission_id) AS cp_count, \
                (SELECT COUNT(*) FROM mission_memberships mm WHERE mm.mission_id = m.mission_id AND mm.state = 'attached') AS attached_count \
         FROM missions m \
         ORDER BY m.updated_at DESC, m.mission_id DESC \
         LIMIT ?1",
    )?;

    let mut latest_cp_stmt = conn.prepare(
        "SELECT checkpoint_id, summary, revision, created_at \
         FROM mission_checkpoints \
         WHERE mission_id = ?1 \
         ORDER BY revision DESC \
         LIMIT 3",
    )?;

    let mut missions = Vec::new();
    let rows = mission_stmt.query_map(params![limit], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, i64>(7)?,
            row.get::<_, i64>(8)?,
        ))
    })?;

    for row in rows {
        let (mission_id, goal, status, revision, project_id, created_at, updated_at, cp_count, attached_count) = row?;
        let cp_rows = latest_cp_stmt.query_map(params![&mission_id], |cp| {
            Ok(json!({
                "checkpoint_id": cp.get::<_, String>(0)?,
                "summary": cp.get::<_, String>(1)?,
                "revision": cp.get::<_, i64>(2)?,
                "created_at": cp.get::<_, String>(3)?,
            }))
        })?;
        let mut recent_checkpoints = Vec::new();
        for cp in cp_rows {
            recent_checkpoints.push(cp?);
        }
        missions.push(json!({
            "mission_id": mission_id,
            "goal": goal,
            "status": status,
            "revision": revision,
            "project_id": project_id,
            "created_at": created_at,
            "updated_at": updated_at,
            "checkpoint_count": cp_count,
            "attached_members": attached_count,
            "recent_checkpoints": recent_checkpoints,
        }));
    }

    let total_missions: i64 = conn.query_row("SELECT COUNT(*) FROM missions", [], |r| r.get(0))?;
    let active_missions: i64 = conn.query_row(
        "SELECT COUNT(*) FROM missions WHERE status = 'active'",
        [],
        |r| r.get(0),
    )?;
    let completed_missions: i64 = conn.query_row(
        "SELECT COUNT(*) FROM missions WHERE status = 'completed'",
        [],
        |r| r.get(0),
    )?;

    let task_room_schema_present: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='task_room_tasks'",
            [],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);

    let mut task_rooms = Vec::new();
    let mut task_room_contexts = Vec::new();
    let mut total_task_rooms: i64 = 0;

    if task_room_schema_present {
        total_task_rooms =
            conn.query_row("SELECT COUNT(*) FROM task_room_tasks", [], |r| r.get(0))?;

        let mut tr_stmt = conn.prepare(
            "SELECT t.task_id, t.context_id, t.title, t.goal, t.status, t.summary, \
                    t.project, t.device, t.current_step_id, t.blocked_reason, \
                    t.review_status, t.revision, t.created_at, t.updated_at, \
                    (SELECT COUNT(*) FROM task_room_steps s WHERE s.task_id = t.task_id) AS steps_total, \
                    (SELECT COUNT(*) FROM task_room_steps s WHERE s.task_id = t.task_id AND s.status = 'completed') AS steps_done \
             FROM task_room_tasks t \
             ORDER BY t.updated_at DESC, t.task_id DESC \
             LIMIT ?1",
        )?;
        let tr_rows = tr_stmt.query_map(params![limit], |r| {
            Ok(json!({
                "task_id": r.get::<_, String>(0)?,
                "context_id": r.get::<_, String>(1)?,
                "title": r.get::<_, String>(2)?,
                "goal": r.get::<_, String>(3)?,
                "status": r.get::<_, String>(4)?,
                "summary": r.get::<_, String>(5)?,
                "project": r.get::<_, String>(6)?,
                "device": r.get::<_, String>(7)?,
                "current_step_id": r.get::<_, Option<String>>(8)?,
                "blocked_reason": r.get::<_, Option<String>>(9)?,
                "review_status": r.get::<_, Option<String>>(10)?,
                "revision": r.get::<_, i64>(11)?,
                "created_at": r.get::<_, String>(12)?,
                "updated_at": r.get::<_, String>(13)?,
                "steps_total": r.get::<_, i64>(14)?,
                "steps_completed": r.get::<_, i64>(15)?,
            }))
        })?;
        for row in tr_rows {
            task_rooms.push(row?);
        }

        let mut ctx_stmt = conn.prepare(
            "SELECT context_id, label, project, device, created_at, updated_at \
             FROM task_room_contexts \
             ORDER BY updated_at DESC, context_id DESC \
             LIMIT ?1",
        )?;
        let ctx_rows = ctx_stmt.query_map(params![limit], |r| {
            Ok(json!({
                "context_id": r.get::<_, String>(0)?,
                "label": r.get::<_, String>(1)?,
                "project": r.get::<_, String>(2)?,
                "device": r.get::<_, String>(3)?,
                "created_at": r.get::<_, String>(4)?,
                "updated_at": r.get::<_, String>(5)?,
            }))
        })?;
        for row in ctx_rows {
            task_room_contexts.push(row?);
        }
    }

    Ok(json!({
        "schema_version": SCHEMA_VERSION,
        "mission_counts": {
            "total": total_missions,
            "active": active_missions,
            "completed": completed_missions,
            "other": (total_missions - active_missions - completed_missions).max(0),
        },
        "missions": missions,
        "task_room_schema_present": task_room_schema_present,
        "total_task_rooms": total_task_rooms,
        "task_rooms": task_rooms,
        "task_room_contexts": task_room_contexts,
    }))
}
