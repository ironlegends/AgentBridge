//! Durable contexts, missions, ownership, revisions, checkpoints and transitions.
//! Raw context handles are capabilities. Public context IDs are NEVER accepted
//! in place of handles, even if a caller knows the mission ID.

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::store::{
    append_event, denied, digest_json, fetch_mission, invalid, json, membership, new_id, now,
    new_guid_n, open_subtasks_exist, replay, require_context, require_id, require_key, require_text,
    resolve_target, touch, verify_schema, write, BridgeError, ContextCreated, MissionDto, Result,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct CreateMissionRequest {
    pub goal: String,
    #[serde(default)]
    pub project_id: Option<String>,
    pub actor_context_handle: String,
    pub operation_id: String,
    pub idempotency_key: String,
}
#[derive(Serialize)]
struct CreateDigest<'a> {
    goal: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    project_id: Option<&'a str>,
    actor_context_handle: &'a str,
}
pub fn create_mission(
    conn: &mut Connection, actor_handle: &str, request: CreateMissionRequest
) -> Result<MissionDto> {
    require_text(&request.goal, 16384, "Mission goal must be 1-16384 characters.")?;
    require_id("op", &request.operation_id)?;
    require_key(&request.idempotency_key)?;
    if request.actor_context_handle != actor_handle {
        return Err(denied("Mission actor differs from the authenticated request."));
    }
    let digest = digest_json(&CreateDigest {
        goal: &request.goal, project_id: request.project_id.as_deref(),
        actor_context_handle: &request.actor_context_handle,
    })?;
    write(conn, |tx| {
        let actor_hash = require_context(tx, actor_handle)?;
        if let Some(previous) = replay(tx, &request.idempotency_key, &digest)? {
            return Ok(previous);
        }
        let timestamp = now();
        let mission = MissionDto {
            mission_id: new_id("mis"), goal: request.goal.clone(), status: "active".into(),
            revision: 1, project_id: request.project_id.clone(),
            actor_context_handle: actor_hash.clone(),
            created_at: timestamp.clone(), updated_at: timestamp.clone(),
        };
        tx.execute(
            "INSERT INTO missions(mission_id,project_id,goal,status,current_revision,\
             actor_context_handle,create_idempotency_key,created_at,updated_at) \
             VALUES(?1,?2,?3,'active',1,?4,?5,?6,?6)",
            params![&mission.mission_id, &mission.project_id, &mission.goal,
                    &actor_hash, &request.idempotency_key, &timestamp],
        )?;
        // Ownership is granted as part of creation, never via a later non-atomic step.
        tx.execute(
            "INSERT INTO mission_memberships(mission_id,context_hash,role,state,updated_at) \
             VALUES(?1,?2,'owner','attached',?3)",
            params![mission.mission_id, actor_hash, timestamp],
        )?;
        crate::store::insert_operation(
            tx, &request.operation_id, &mission.mission_id, &request.idempotency_key,
            &digest, &mission, "Mission.Create",
        )?;
        append_event(
            tx, &mission.mission_id, Some(&request.operation_id),
            "mission.created", &json(&serde_json::json!({"id":mission.mission_id}))?,
        )?;
        Ok(mission)
    })
}

/// Explicitly verify and repair *only* an already authenticated original creator.
/// Not used to adopt blocked legacy imports or to override an existing owner.
pub fn ensure_original_owner(conn: &mut Connection, mission_id: &str, handle: &str) -> Result<()> {
    require_id("mis", mission_id)?;
    write(conn, |tx| {
        let hash = require_context(tx, handle)?;
        let mission = fetch_mission(tx, mission_id)?;
        if mission.actor_context_handle != hash {
            return Err(denied("Only the original creator can initialize ownership."));
        }
        tx.execute(
            "INSERT INTO mission_memberships(mission_id,context_hash,role,state,updated_at) \
             VALUES(?1,?2,'owner','attached',?3) \
             ON CONFLICT(mission_id,context_hash) DO NOTHING",
            params![mission_id, hash, now()],
        )?;
        Ok(())
    })
}

pub fn get_mission(conn: &Connection, actor_handle: &str, mission_id: &str) -> Result<MissionDto> {
    verify_schema(conn)?;
    let hash = require_context(conn, actor_handle)?;
    get_mission_snapshot(conn, &hash, mission_id)
}

pub(crate) fn get_mission_snapshot(conn: &Connection, hash: &str, mission_id: &str) -> Result<MissionDto> {
    require_id("mis", mission_id)?;
    // Authorize in the same statement as the row: a public mission ID grants nothing.
    let value: Option<MissionDto> = conn.query_row(
        "SELECT m.mission_id,m.goal,m.status,m.current_revision,m.project_id,\
                m.actor_context_handle,m.created_at,m.updated_at \
         FROM missions m JOIN mission_memberships mm ON mm.mission_id=m.mission_id \
         WHERE m.mission_id=?1 AND mm.context_hash=?2 AND mm.state='attached'",
        params![mission_id, hash], |row| {
            Ok(MissionDto {
                mission_id: row.get(0)?, goal: row.get(1)?, status: row.get(2)?,
                revision: row.get(3)?, project_id: row.get(4)?, actor_context_handle: row.get(5)?,
                created_at: row.get(6)?, updated_at: row.get(7)?,
            })
        },
    ).optional()?;
    value.ok_or_else(|| denied("Context not attached to mission."))
}

#[derive(Debug, Clone, Deserialize)]
pub struct MissionFilter {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default = "default_mission_limit")]
    pub limit: i64,
}
fn default_mission_limit() -> i64 { 100 }
impl Default for MissionFilter {
    fn default() -> Self { Self { status: None, limit: default_mission_limit() } }
}
pub fn list_missions(
    conn: &Connection, actor_handle: &str, filter: MissionFilter
) -> Result<Vec<MissionDto>> {
    verify_schema(conn)?;
    if !(1..=500).contains(&filter.limit) { return Err(invalid("Mission list limit must be 1-500.")); }
    let hash = require_context(conn, actor_handle)?;
    // Filter authorized missions BEFORE ordering/limiting to avoid pagination leakage.
    let mut statement = conn.prepare(
        "SELECT m.mission_id,m.goal,m.status,m.current_revision,m.project_id,\
                m.actor_context_handle,m.created_at,m.updated_at \
         FROM missions m JOIN mission_memberships mm ON mm.mission_id=m.mission_id \
             AND mm.context_hash=?1 AND mm.state='attached' \
         WHERE (?2 IS NULL OR m.status=?2) \
         ORDER BY m.created_at DESC,m.mission_id DESC LIMIT ?3"
    )?;
    let rows = statement.query_map(params![hash, filter.status, filter.limit], |row| {
        Ok(MissionDto {
            mission_id: row.get(0)?, goal: row.get(1)?, status: row.get(2)?,
            revision: row.get(3)?, project_id: row.get(4)?,
            actor_context_handle: row.get(5)?, created_at: row.get(6)?, updated_at: row.get(7)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
}

#[derive(Debug, Clone, Serialize)]
pub struct MissionObservation {
    pub mission_id: String,
    pub revision: i64,
    pub owner_context_id: String,
    pub caller_role: String,
    pub caller_state: String,
}
pub fn observe_mission(
    conn: &Connection, actor_handle: &str, mission_id: &str
) -> Result<MissionObservation> {
    verify_schema(conn)?;
    let hash = require_context(conn, actor_handle)?;
    observe_mission_snapshot(conn, &hash, mission_id)
}

pub(crate) fn observe_mission_snapshot(
    conn: &Connection, hash: &str, mission_id: &str
) -> Result<MissionObservation> {
    require_id("mis", mission_id)?;
    // Exactly one snapshot, including an invitee who has not attached yet.
    conn.query_row(
        "SELECT m.current_revision,owner_context.context_id,caller.role,caller.state \
         FROM missions m \
         JOIN mission_memberships caller ON caller.mission_id=m.mission_id \
             AND caller.context_hash=?2 AND caller.state IN ('invited','attached') \
         JOIN mission_memberships owner ON owner.mission_id=m.mission_id \
             AND owner.role='owner' AND owner.state='attached' \
         JOIN agent_contexts owner_context ON owner_context.handle_hash=owner.context_hash \
         WHERE m.mission_id=?1",
        params![mission_id, hash],
        |row| Ok(MissionObservation {
            mission_id: mission_id.to_owned(), revision: row.get(0)?,
            owner_context_id: row.get(1)?, caller_role: row.get(2)?,
            caller_state: row.get(3)?,
        }),
    ).optional()?.ok_or_else(|| denied("Context is not authorized to observe this mission."))
}

#[derive(Clone, Deserialize)]
pub struct HandoffRequest {
    pub mission_id: String,
    pub if_revision: i64,
    #[serde(default)]
    pub target_context_id: Option<String>,
    #[serde(default)]
    pub target_context_handle: Option<String>,
}
pub fn grant_mission(
    conn: &mut Connection, actor_handle: &str, request: HandoffRequest
) -> Result<MissionDto> {
    require_id("mis", &request.mission_id)?;
    if request.if_revision < 1 { return Err(invalid("An observed mission revision is required.")); }
    write(conn, |tx| {
        let actor_hash = require_context(tx, actor_handle)?;
        let current = fetch_mission(tx, &request.mission_id)?;
        membership(tx, &request.mission_id, &actor_hash, true)?;
        let target = resolve_target(tx, &actor_hash,
            request.target_context_id.as_deref(), request.target_context_handle.as_deref())?;
        if current.revision != request.if_revision {
            return Err(BridgeError::new("CONFLICT_REVISION", "Mission changed before invitation."));
        }
        let inserted = tx.execute(
            "INSERT INTO mission_memberships(mission_id,context_hash,role,state,updated_at) \
             VALUES(?1,?2,'member','invited',?3) \
             ON CONFLICT(mission_id,context_hash) DO NOTHING",
            params![request.mission_id, target, now()],
        )?;
        if inserted == 0 { return Ok(current); }
        let next = touch(tx, &current, request.if_revision)?;
        append_event(tx, &request.mission_id, None, "mission.invite", r#"{"state":"invited"}"#)?;
        Ok(next)
    })
}

pub fn attach_mission(
    conn: &mut Connection, actor_handle: &str, mission_id: &str, revision: i64
) -> Result<MissionDto> {
    require_id("mis", mission_id)?;
    // As in the C# Core, an already attached member may reattach idempotently
    // even when its old observed revision is stale or absent.
    write(conn, |tx| {
        let hash = require_context(tx, actor_handle)?;
        let current = fetch_mission(tx, mission_id)?;
        let state: Option<String> = tx.query_row(
            "SELECT state FROM mission_memberships WHERE mission_id=?1 AND context_hash=?2",
            params![mission_id, hash], |r| r.get(0),
        ).optional()?;
        if state.as_deref() == Some("attached") { return Ok(current); }
        if state.as_deref() != Some("invited") {
            return Err(denied("Mission invitation missing."));
        }
        if current.revision != revision {
            return Err(BridgeError::new("CONFLICT_REVISION", "Stale mission observation."));
        }
        tx.execute(
            "UPDATE mission_memberships SET state='attached',updated_at=?3 \
             WHERE mission_id=?1 AND context_hash=?2",
            params![mission_id, hash, now()],
        )?;
        let next = touch(tx, &current, revision)?;
        append_event(tx, mission_id, None, "mission.attach", r#"{"state":"attached"}"#)?;
        Ok(next)
    })
}

pub fn transfer_mission(
    conn: &mut Connection, actor_handle: &str, request: HandoffRequest
) -> Result<MissionDto> {
    require_id("mis", &request.mission_id)?;
    if request.if_revision < 1 { return Err(invalid("An observed mission revision is required.")); }
    write(conn, |tx| {
        let actor_hash = require_context(tx, actor_handle)?;
        let current = fetch_mission(tx, &request.mission_id)?;
        membership(tx, &request.mission_id, &actor_hash, true)?;
        let target = resolve_target(tx, &actor_hash,
            request.target_context_id.as_deref(), request.target_context_handle.as_deref())?;
        membership(tx, &request.mission_id, &target, false)?;
        if current.revision != request.if_revision {
            return Err(BridgeError::new("CONFLICT_REVISION", "Mission changed before handoff."));
        }
        tx.execute(
            "UPDATE mission_memberships SET role='member',updated_at=?3 \
             WHERE mission_id=?1 AND context_hash=?2",
            params![request.mission_id, actor_hash, now()],
        )?;
        tx.execute(
            "UPDATE mission_memberships SET role='owner',updated_at=?3 \
             WHERE mission_id=?1 AND context_hash=?2",
            params![request.mission_id, target, now()],
        )?;
        let next = touch(tx, &current, request.if_revision)?;
        append_event(tx, &request.mission_id, None, "mission.handoff", r#"{"status":"transferred"}"#)?;
        Ok(next)
    })
}

pub fn checkpoint_mission(
    conn: &mut Connection, actor_handle: &str, mission_id: &str,
    summary: &str, revision: i64
) -> Result<MissionDto> {
    require_id("mis", mission_id)?;
    require_text(summary, 4096, "Checkpoint summary must be 1-4096 characters.")?;
    if revision < 1 { return Err(invalid("An observed mission revision is required.")); }
    write(conn, |tx| {
        let hash = require_context(tx, actor_handle)?;
        let current = fetch_mission(tx, mission_id)?;
        membership(tx, mission_id, &hash, false)?;
        let next = touch(tx, &current, revision)?;
        let checkpoint_id = new_guid_n();
        tx.execute(
            "INSERT INTO mission_checkpoints(checkpoint_id,mission_id,context_hash,summary,revision,created_at) \
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![checkpoint_id, mission_id, hash, summary, next.revision, now()],
        )?;
        append_event(
            tx, mission_id, None, "mission.checkpoint",
            &json(&serde_json::json!({"revision": next.revision}))?,
        )?;
        Ok(next)
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct MissionCheckpoint {
    pub checkpoint_id: String,
    pub mission_id: String,
    pub summary: String,
    pub revision: i64,
}
pub fn recent_checkpoints(
    conn: &Connection, actor_handle: &str, mission_id: &str, limit: i64
) -> Result<Vec<MissionCheckpoint>> {
    verify_schema(conn)?;
    let hash = require_context(conn, actor_handle)?;
    recent_checkpoints_snapshot(conn, &hash, mission_id, limit)
}

pub(crate) fn recent_checkpoints_snapshot(
    conn: &Connection, hash: &str, mission_id: &str, limit: i64
) -> Result<Vec<MissionCheckpoint>> {
    require_id("mis", mission_id)?;
    if !(1..=100).contains(&limit) { return Err(invalid("Checkpoint limit must be 1-100.")); }
    // Membership and bounded checkpoint selection share one read statement.
    let mut query = conn.prepare(
        "SELECT cp.checkpoint_id,cp.summary,cp.revision \
         FROM mission_checkpoints cp \
         WHERE cp.mission_id=?1 AND EXISTS(SELECT 1 FROM mission_memberships mm \
           WHERE mm.mission_id=cp.mission_id AND mm.context_hash=?2 AND mm.state='attached') \
         ORDER BY cp.revision DESC LIMIT ?3"
    )?;
    // A zero-row result could be an empty authorized page or unauthorized.
    // Confirm access *first*, never silently return an unauthorized empty page.
    membership(conn, mission_id, hash, false)?;
    let results = query.query_map(params![mission_id, hash, limit], |r| {
        Ok(MissionCheckpoint {
            checkpoint_id: r.get(0)?, mission_id: mission_id.to_owned(),
            summary: r.get(1)?, revision: r.get(2)?,
        })
    })?;
    results.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
}

pub fn set_orchestrator(
    conn: &mut Connection, actor_handle: &str, mission_id: &str,
    enabled: bool, revision: i64
) -> Result<MissionDto> {
    require_id("mis", mission_id)?;
    if revision < 1 { return Err(invalid("An observed mission revision is required.")); }
    write(conn, |tx| {
        let hash = require_context(tx, actor_handle)?;
        let current = fetch_mission(tx, mission_id)?;
        membership(tx, mission_id, &hash, true)?;
        if current.revision != revision {
            return Err(BridgeError::new("CONFLICT_REVISION", "Stale orchestrator revision."));
        }
        let updated = tx.execute(
            "UPDATE missions SET orchestrator_enabled=?1 WHERE mission_id=?2 AND current_revision=?3",
            params![enabled as i64, mission_id, revision]
        )?;
        if updated != 1 { return Err(BridgeError::new("CONFLICT_REVISION", "Stale orchestrator state.")); }
        let next = touch(tx, &current, revision)?;
        append_event(
            tx, mission_id, None, "mission.orchestrator",
            if enabled { r#"{"enabled":true}"# } else { r#"{"enabled":false}"# },
        )?;
        Ok(next)
    })
}

#[derive(Debug, Clone, Deserialize)]
pub struct TransitionMissionRequest {
    pub mission_id: String,
    pub to_status: String,
    pub if_revision: i64,
    pub operation_id: String,
    pub idempotency_key: String,
}
#[derive(Serialize)]
struct TransitionDigest<'a> {
    mission_id: &'a str,
    to_status: &'a str,
    if_revision: i64,
}
pub fn transition_mission(
    conn: &mut Connection, actor_handle: &str, request: TransitionMissionRequest
) -> Result<MissionDto> {
    require_id("mis", &request.mission_id)?;
    require_id("op", &request.operation_id)?;
    require_key(&request.idempotency_key)?;
    if request.if_revision < 1 || !matches!(request.to_status.as_str(), "active" | "blocked" | "completed") {
        return Err(invalid("Invalid mission revision or target status."));
    }
    let digest = digest_json(&TransitionDigest {
        mission_id: &request.mission_id, to_status: &request.to_status,
        if_revision: request.if_revision
    })?;
    write(conn, |tx| {
        let hash = require_context(tx, actor_handle)?;
        membership(tx, &request.mission_id, &hash, true)?;
        if let Some(previous) = replay(tx, &request.idempotency_key, &digest)? {
            return Ok(previous);
        }
        let previous = fetch_mission(tx, &request.mission_id)?;
        if previous.revision != request.if_revision {
            return Err(BridgeError::new("CONFLICT_REVISION", "Mission was updated by another agent."));
        }
        if previous.status == "completed" || previous.status == request.to_status {
            return Err(BridgeError::new("INVALID_TRANSITION", "Illegal mission state transition."));
        }
        if request.to_status == "completed" && open_subtasks_exist(tx, &request.mission_id)? {
            return Err(BridgeError::new("INVALID_TRANSITION", "Complete the mission's open subtasks first."));
        }
        let timestamp = now();
        let changed = tx.execute(
            "UPDATE missions SET status=?1,current_revision=current_revision+1,updated_at=?2 \
             WHERE mission_id=?3 AND current_revision=?4",
            params![&request.to_status, &timestamp, &request.mission_id, request.if_revision],
        )?;
        if changed != 1 { return Err(BridgeError::new("CONFLICT_REVISION", "Mission revision changed.")); }
        let mut next = previous;
        next.status = request.to_status.clone();
        next.revision += 1;
        next.updated_at = timestamp;
        crate::store::insert_operation(
            tx, &request.operation_id, &request.mission_id, &request.idempotency_key,
            &digest, &next, "Mission.Transition",
        )?;
        append_event(
            tx, &request.mission_id, Some(&request.operation_id), "mission.transition",
            &json(&serde_json::json!({"status":request.to_status}))?,
        )?;
        Ok(next)
    })
}

// Re-export the context creator at the business-layer boundary as well.
pub fn create_context(conn: &mut Connection) -> Result<ContextCreated> {
    crate::store::create_context(conn)
}
