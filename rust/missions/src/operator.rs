//! Read-only operator inspection helpers for the local Agent Bridge UI and
//! cryptographic token generation. Never returns raw handles or handle hashes.

use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

use crate::store::{invalid, verify_schema, Result, SCHEMA_VERSION};

/// Generate a cryptographically random lowercase hexadecimal token with
/// `byte_len` bytes of OS entropy (resulting in `2 * byte_len` hex chars).
pub fn random_token_hex(byte_len: usize) -> String {
    let len = byte_len.clamp(16, 64);
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
