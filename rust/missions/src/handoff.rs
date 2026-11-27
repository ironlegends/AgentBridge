//! Member-authorized mission handoff. A local copy uses a short-lived,
//! revision-bound checkpoint grant, never a public context ID as a credential.
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

use crate::mission::{get_mission_snapshot, observe_mission_snapshot, recent_checkpoints_snapshot};
use crate::store::{attached_assignee, denied, invalid, require_context, require_id, verify_schema, Result};
use crate::subtask::{list_subtasks_snapshot, ListSubtasksRequest};

pub const MAX_HANDOFF_BYTES: usize = 4096;
const SUBTASK_LIMIT: i64 = 20;
const NOTE_LIMIT: i64 = 3;
const COPY_MARKER: &str = "handoff: desktop-copy";
const OMITTED: &str = "[free-form text omitted; consult authorized mission records]";

// Render only canonical ticket references and fixed labels into a portable brief.
fn ticket_numbers(goal: &str) -> impl Iterator<Item=u32> + '_ {
    goal.match_indices('#').filter_map(|(start, _)| {
        let tail = &goal[start+1..];
        let end = tail.bytes().take_while(u8::is_ascii_digit).count();
        let before = goal[..start].chars().next_back();
        let after = tail[end..].chars().next();
        if end == 0 || end > 6 || tail.starts_with('0')
            || before.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '#')
            || after.is_some_and(|c| c.is_alphanumeric() || c == '_') {
            return None;
        }
        tail[..end].parse().ok()
    })
}

fn goal_references(goal: &str) -> Option<String> {
    let mut references = Vec::new();
    for number in ticket_numbers(goal) {
        if !references.contains(&number) {
            references.push(number);
            if references.len() == 4 { break; }
        }
    }
    if references.is_empty() { return None; }
    Some(format!("Work on {}.", references.iter().map(|n| format!("#{n}")).collect::<Vec<_>>().join(", ")))
}

fn safe_note(raw: &str, goal: &str) -> String {
    if raw == COPY_MARKER { return "Member authorized local handoff copy.".into(); }
    if raw == "handoff: revoke-copy" { return "Member revoked local handoff copy.".into(); }
    let Some(body) = raw.strip_prefix("handoff: ") else { return OMITTED.into(); };
    let mut words = body.strip_prefix("goal ").unwrap_or(body).split(' ').peekable();
    let (verb, generic) = match words.next() {
        Some("implement") => ("Implement", "Continue implementation."),
        Some("verify") => ("Verify", "Run the agreed verification."),
        Some("review") => ("Review", "Request independent review."),
        Some("blocked") => ("Blocked on", "Resolve the recorded blocker."),
        Some("complete") => ("Completed", "Review completion evidence."),
        Some("restore") => ("Restore", "Restore the agreed behavior."),
        _ => return OMITTED.into(),
    };
    let mut action = generic.to_owned();
    if words.peek().is_some_and(|word| !word.starts_with('#')) {
        let subject = match words.next() {
            Some("session-history") => "session history",
            Some("handoff") => "mission handoff",
            Some("storage") => "storage",
            Some("interface") => "the interface",
            Some("provider") => "the provider integration",
            Some("permissions") => "permissions",
            Some("build") => "the build",
            Some("tests") => "tests",
            Some("docs") => "documentation",
            Some("release") => "the release",
            _ => return OMITTED.into(),
        };
        action = format!("{verb} {subject}.");
        if words.next_if_eq(&"needs").is_some() {
            let reason = match words.next() {
                Some("approval") => "Needs operator approval.",
                Some("input") => "Needs operator input.",
                Some("dependency") => "Waiting for a dependency.",
                Some("access") => "Waiting for access.",
                Some("verification") => "Waiting for verification.",
                Some("environment") => "Waiting for the test environment.",
                _ => return OMITTED.into(),
            };
            action.push(' ');
            action.push_str(reason);
        }
    }
    let mut tickets = Vec::new();
    for word in words {
        let Some(digits) = word.strip_prefix('#') else { return OMITTED.into(); };
        if digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return OMITTED.into();
        }
        let Ok(n) = digits.parse::<u32>() else { return OMITTED.into(); };
        if n == 0 || digits != n.to_string() || tickets.len() == 4 || tickets.contains(&n)
            || !ticket_numbers(goal).any(|number| number == n) {
            return OMITTED.into();
        }
        tickets.push(n);
    }
    if tickets.is_empty() { return action; }
    format!("{action} Tickets: {}.", tickets.iter().map(|n| format!("#{n}")).collect::<Vec<_>>().join(", "))
}

fn status(raw: &str) -> Result<&'static str> {
    match raw {
        "active" => Ok("active"),
        "pending" => Ok("pending"),
        "in_progress" => Ok("in_progress"),
        "blocked" => Ok("blocked"),
        "completed" => Ok("completed"),
        _ => Err(invalid("Unknown handoff state.")),
    }
}

fn result(text: &str, truncated: bool) -> Value {
    json!({"handoff": text, "truncated": truncated, "max_bytes": MAX_HANDOFF_BYTES})
}

fn append(text: &mut String, line: &str) -> Result<bool> {
    let candidate = format!("{text}{line}\n");
    if serde_json::to_vec(&result(&candidate, false))?.len() > MAX_HANDOFF_BYTES {
        return Ok(false);
    }
    *text = candidate;
    Ok(true)
}

// A lease is counted only when the exact bound owner identity used by
// LeaseCoordinator::dispatch_rpc matches an existing operation of this
// mission. Never expose resource keys, operation identities or fence tokens.
// A mission count is not a claim that the caller owns any individual lease.
fn mission_lease_count(conn: &Connection, mission_id: &str) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM resource_leases l JOIN operations o
         ON l.owner_operation = ('mission:' || o.mission_id || ':op:' || o.operation_id)
         WHERE o.mission_id=?1 AND length(l.owner_operation)<=256
           AND l.generation>0 AND l.token=l.generation
           AND julianday(l.expires_at)>julianday('now')",
        [mission_id], |row| row.get(0),
    )?)
}

// A current checkpoint written by an attached member is the explicit
// authorization. A new revision, membership loss, or five minutes elapsing
// revokes it. The hash is used only inside this module, never in an IPC reply.
fn copy_grant(conn: &Connection, mission_id: &str, revision: i64, context_id: Option<&str>) -> Result<Option<String>> {
    require_id("mis", mission_id)?;
    if revision < 1 || revision > 9_007_199_254_740_991 { return Err(invalid("Invalid handoff revision.")); }
    let mut stmt = conn.prepare(
        "SELECT cp.context_hash FROM mission_checkpoints cp
         JOIN missions m ON m.mission_id=cp.mission_id AND m.current_revision=cp.revision
         JOIN mission_memberships mm ON mm.mission_id=cp.mission_id AND mm.context_hash=cp.context_hash AND mm.state='attached'
         JOIN agent_contexts c ON c.handle_hash=cp.context_hash
         WHERE cp.mission_id=?1 AND cp.revision=?2 AND cp.summary=?3
           AND (?4 IS NULL OR c.context_id=?4)
           AND julianday(cp.created_at)<=julianday(?5)
           AND julianday(cp.created_at)>julianday(?5, '-5 minutes')
           AND EXISTS (SELECT 1 FROM events e WHERE e.mission_id=cp.mission_id
               AND e.event_type='mission.checkpoint' AND json_extract(e.payload_redacted,'$.revision')=cp.revision)
         LIMIT 2"
    )?;
    // Use the checkpoint writer's clock for both ends of the approval window.
    let mut rows = stmt.query(params![mission_id, revision, COPY_MARKER, context_id, crate::store::now()])?;
    let grant = rows.next()?.map(|row| row.get::<_, String>(0)).transpose()?;
    if rows.next()?.is_some() { return Ok(None); }
    Ok(grant)
}

pub(crate) fn copy_available(conn: &Connection, mission_id: &str, revision: i64, context_id: Option<&str>) -> bool {
    copy_grant(conn, mission_id, revision, context_id).ok().flatten().is_some()
}

/// Only for an already authenticated local operator transport. This is not
/// a new member or an MCP operation, and a mission locator alone grants nothing.
pub fn desktop_copy_handoff(conn: &Connection, mission_id: &str, revision: i64) -> Result<Value> {
    verify_schema(conn)?;
    let tx = conn.unchecked_transaction()?;
    let hash = copy_grant(&tx, mission_id, revision, None)?
        .ok_or_else(|| denied("Current explicit member approval is required for desktop copy."))?;
    let value = build_handoff(&tx, &hash, mission_id)?;
    tx.commit()?;
    Ok(value)
}

pub fn mission_handoff(conn: &Connection, actor: &str, mission_id: &str) -> Result<Value> {
    verify_schema(conn)?;
    let tx = conn.unchecked_transaction()?;
    let hash = require_context(&tx, actor)?;
    let value = build_handoff(&tx, &hash, mission_id)?;
    tx.commit()?;
    Ok(value)
}

// All reads take place in the same snapshot, following member authentication
// through either the private handle or a verified explicit copy checkpoint.
fn build_handoff(conn: &Connection, actor_hash: &str, mission_id: &str) -> Result<Value> {
    let mission = get_mission_snapshot(conn, actor_hash, mission_id)?;
    let observation = observe_mission_snapshot(conn, actor_hash, mission_id)?;
    require_id("mis", &mission.mission_id)?;
    require_id("ctx", &observation.owner_context_id)?;
    let checkpoints = recent_checkpoints_snapshot(conn, actor_hash, mission_id, NOTE_LIMIT + 1)?;
    let page = list_subtasks_snapshot(conn, actor_hash, ListSubtasksRequest {
        mission_id: mission_id.to_owned(),
        limit: SUBTASK_LIMIT,
        after_created_revision: 0,
        subtask_id: None,
    })?;
    let published: Option<String> = conn.query_row(
        "SELECT summary FROM mission_checkpoints WHERE mission_id=?1 AND summary GLOB 'handoff: goal *'
         ORDER BY revision DESC LIMIT 1", [mission_id], |row| row.get(0),
    ).optional()?;
    let objective = published.iter().map(String::as_str).chain(std::iter::once(mission.goal.as_str()))
        .map(|note| safe_note(note, &mission.goal)).find(|brief| brief != OMITTED)
        .or_else(|| goal_references(&mission.goal))
        .unwrap_or_else(|| "Read the member-only goal with agent_bridge_mission_get.".to_owned());
    let mut next = if mission.status == "completed" {
        "Review the existing completion receipt; no new execution.".to_owned()
    } else if let Some(task) = page.subtasks.iter().find(|t| t.status=="in_progress")
        .or_else(|| page.subtasks.iter().find(|t| t.status=="blocked"))
        .or_else(|| page.subtasks.iter().find(|t| t.status=="pending")) {
        require_id("sub", &task.subtask_id)?;
        format!("Read subtask {} with agent_bridge_mission_subtask_list; reconcile its current assignment and revision with the owner before any effect.", task.subtask_id)
    } else {
        "Read the authorized mission goal and subtasks; coordinate the next assignment with the owner.".to_owned()
    };
    if mission.status != "completed" {
        if let Some(action) = checkpoints.iter().take(NOTE_LIMIT as usize)
            .filter(|cp| cp.summary != COPY_MARKER && cp.summary != "handoff: revoke-copy")
            .map(|cp| safe_note(&cp.summary, &mission.goal)).find(|note| note != OMITTED) {
            next = format!("{action} {next}");
        }
    }
    let mut text = String::new();
    let header = format!(
        "Mission {} | revision {} | {}\nOwner: {}\nGoal: {}\nNext: {}\nResume through an existing invitation or ownership transfer; observe the current revision before acting.\nMission-bound active lease rows: {}. Resource identities omitted; verify current authority before use.",
        mission.mission_id, mission.revision, status(&mission.status)?,
        observation.owner_context_id, objective, next, mission_lease_count(conn, mission_id)?,
    );
    if !append(&mut text, &header)? { return Err(invalid("Handoff metadata exceeds its byte budget.")); }
    let mut truncated = page.next_after_created_revision.is_some() || checkpoints.len() > NOTE_LIMIT as usize;
    if checkpoints.is_empty() { truncated |= !append(&mut text, "Latest checkpoint: none")?; }
    for (index, checkpoint) in checkpoints.iter().take(NOTE_LIMIT as usize).enumerate() {
        let label = if index == 0 { "Latest checkpoint" } else { "Recent checkpoint" };
        let line = format!("{label} at revision {}: {}", checkpoint.revision, safe_note(&checkpoint.summary, &mission.goal));
        if !append(&mut text, &line)? { truncated = true; break; }
    }
    for subtask in page.subtasks {
        require_id("sub", &subtask.subtask_id)?;
        let assignee = match subtask.assignee_context_id.as_deref() {
            Some(id) => {
                attached_assignee(conn, mission_id, id)?;
                id
            }
            None => "unassigned",
        };
        let mut line = format!("Subtask {} | revision {} | {} | assignee {} | goal: {}",
            subtask.subtask_id, subtask.revision, status(&subtask.status)?, assignee,
            match safe_note(&subtask.goal, &subtask.goal) {
                brief if brief == OMITTED => goal_references(&subtask.goal).unwrap_or(brief),
                brief => brief,
            });
        if let Some(summary) = subtask.summary.as_deref() {
            line.push_str(" | note: ");
            line.push_str(&safe_note(summary, &subtask.goal));
        }
        if !append(&mut text, &line)? { truncated = true; break; }
    }
    Ok(result(&text, truncated))
}
