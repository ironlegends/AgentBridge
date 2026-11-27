//! First-party C# v7 owner migration port. Runs only in the Core schema
//! transaction; imported read-only missions retain their original provenance.

use chrono::DateTime;
use rusqlite::{params, Transaction};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{CoreError, Result};

// Source provenance is already recorded in the imports table.
// Provider labels are not owner capabilities.

struct LegacyMission {
    id: String,
    stored_owner: String,
    updated_at: String,
    status: String,
    attached_owner: bool,
    has_membership: bool,
    is_imported_snapshot: bool,
}

/// C# MissionDto serialized with JsonDefaults.Options (snake_case lower,
/// omit null project_id). Using an owned record also drops any unexpected
/// properties when sanitizing, just as C# deserialization/serialization does.
#[derive(Serialize, Deserialize)]
struct MissionReplay {
    mission_id: String,
    goal: String,
    status: String,
    revision: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    project_id: Option<String>,
    actor_context_handle: String,
    created_at: String,
    updated_at: String,
}

pub(crate) fn apply(tx: &Transaction<'_>) -> Result<()> {
    let missions: Vec<LegacyMission> = {
        let mut statement = tx.prepare(
            "SELECT m.mission_id,m.actor_context_handle,m.updated_at,m.status, \
             EXISTS(SELECT 1 FROM mission_memberships mm \
                    WHERE mm.mission_id=m.mission_id AND mm.role='owner' \
                      AND mm.state='attached'), \
             EXISTS(SELECT 1 FROM mission_memberships mm \
                    WHERE mm.mission_id=m.mission_id), \
             EXISTS(SELECT 1 FROM imports i \
                    WHERE i.target_mission_id=m.mission_id) \
             FROM missions m ORDER BY m.mission_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(LegacyMission {
                id: row.get(0)?,
                stored_owner: row.get(1)?,
                updated_at: row.get(2)?,
                status: row.get(3)?,
                attached_owner: row.get::<_, i64>(4)? == 1,
                has_membership: row.get::<_, i64>(5)? == 1,
                is_imported_snapshot: row.get::<_, i64>(6)? == 1,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };

    for old in missions {
        if old.is_imported_snapshot {
            if old.stored_owner == "legacy-import" && old.status == "blocked" && !old.has_membership {
                continue;
            }
            return Err(CoreError::IncompatibleSchema(
                "imported mission ownership or status requires manual review",
            ));
        }
        if old.attached_owner {
            // Existing ownership and completed handoffs remain authoritative.
            continue;
        }
        if old.has_membership {
            return Err(CoreError::IncompatibleSchema(
                "legacy mission has conflicting membership",
            ));
        }

        let trusted = if registered_count(tx, &old.stored_owner)? == 1 {
            // Already a registered M4 hash: never hash this value twice.
            old.stored_owner.clone()
        } else {
            if !valid_opaque_context(&old.stored_owner) {
                return Err(CoreError::IncompatibleSchema(
                    "legacy mission creator could not be verified",
                ));
            }
            let candidate: String = Sha256::digest(old.stored_owner.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
            if registered_count(tx, &candidate)? != 1 {
                return Err(CoreError::IncompatibleSchema(
                    "legacy mission creator could not be verified",
                ));
            }
            candidate
        };

        redact_replays(tx, &old.id, &old.stored_owner, &trusted)?;
        let changed = tx.execute(
            "UPDATE missions SET actor_context_handle=?1 \
             WHERE mission_id=?2 AND actor_context_handle=?3",
            params![trusted, old.id, old.stored_owner],
        )?;
        if changed != 1 {
            return Err(CoreError::IncompatibleSchema(
                "legacy mission ownership changed during migration",
            ));
        }
        tx.execute(
            "INSERT INTO mission_memberships \
                 (mission_id,context_hash,role,state,updated_at) \
             VALUES(?1,?2,'owner','attached',?3)",
            params![old.id, trusted, old.updated_at],
        )?;
    }
    Ok(())
}

fn valid_opaque_context(value: &str) -> bool {
    value
        .strip_prefix("ctx_")
        .is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn registered_count(tx: &Transaction<'_>, hash: &str) -> Result<i64> {
    Ok(tx.query_row(
        "SELECT count(*) FROM agent_contexts WHERE handle_hash=?1",
        [hash],
        |row| row.get(0),
    )?)
}

fn redact_replays(
    tx: &Transaction<'_>,
    mission_id: &str,
    stored_owner: &str,
    trusted_hash: &str,
) -> Result<()> {
    let snapshots: Vec<(String, String)> = {
        let mut statement = tx.prepare(
            "SELECT operation_id,result_json FROM operations \
             WHERE mission_id=?1 \
               AND tool_name IN ('Mission.Create','Mission.Transition') \
               AND result_json IS NOT NULL",
        )?;
        let rows = statement.query_map([mission_id], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };

    for (operation_id, stored_json) in snapshots {
        let mut replay: MissionReplay = serde_json::from_str(&stored_json)
            .map_err(|_| CoreError::IncompatibleSchema("legacy replay is malformed"))?;
        if replay.mission_id != mission_id
            || (replay.actor_context_handle != stored_owner
                && replay.actor_context_handle != trusted_hash)
            || DateTime::parse_from_rfc3339(&replay.created_at).is_err()
            || DateTime::parse_from_rfc3339(&replay.updated_at).is_err()
        {
            return Err(CoreError::IncompatibleSchema(
                "legacy replay owner or timestamp mismatch",
            ));
        }
        if replay.actor_context_handle == trusted_hash {
            continue;
        }
        replay.actor_context_handle = trusted_hash.to_owned();
        let safe_json = serde_json::to_string(&replay)?;
        let changed = tx.execute(
            "UPDATE operations SET result_json=?1 WHERE operation_id=?2",
            params![safe_json, operation_id],
        )?;
        if changed != 1 {
            return Err(CoreError::IncompatibleSchema(
                "legacy replay changed during migration",
            ));
        }
    }
    Ok(())
}
