// Copyright 2026 agent-bridge contributors
// SPDX-License-Identifier: Apache-2.0

//! Explicit, operator-provided historical Task Room import into existing
//! Agent Bridge SQLite schema 7. No vendor client, database opening, files,
//! secrets, transport, migration, authorization or execution-effect replay.
//!
//! The operator alone supplies and vouches for the historical snapshot.
//! Never expose this API as a remotely callable import RPC or MCP tool.
//! Imports retain the provider identity supplied by the original producer.
//! Exact-source replays are idempotent. Cross-source aliases require explicit reconciliation.
//! Existing SQLite provenance, digests and targets are never relabeled.
//! Imported missions remain blocked, with actor_context_handle="legacy-import"
//! and no owner membership, approval, execution or scheduler action.
//!
//! Exact format caveats: unknown step state and event type strings survive;
//! the source task's top-level status is hashed but is not stored separately
//! by the existing C# schema. Unknown extra JSON keys are ignored by the
//! known C# DTO and cannot be persisted without a prohibited schema change.
//! Historic source steps/events are read-only; never replay their effects.
//! The caller's trusted Core must independently validate schema migration
//! checksums before opening this SQLite connection for import.

use chrono::Utc;
use getrandom::fill as getrandom_fill;
use rusqlite::{params, Connection, Error as SqlError, ErrorCode, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt::{self, Write as _};

pub type Result<T> = std::result::Result<T, ImportError>;
pub const SCHEMA_VERSION: i64 = 7;
pub const IMPORT_PROVIDER: &str = "agent-bridge";
// Public identity emitted by the current product. Source data may carry a
// distinct bounded provider identity; never overwrite its historical label.

pub const MAX_SNAPSHOT_JSON_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportError {
    pub code: &'static str,
    pub message: &'static str,
    pub retryable: bool,
}
impl ImportError {
    const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message, retryable: false }
    }
}
impl fmt::Display for ImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}
impl std::error::Error for ImportError {}
impl From<SqlError> for ImportError {
    fn from(error: SqlError) -> Self {
        match error {
            SqlError::SqliteFailure(detail, _)
                if matches!(detail.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) =>
                Self::new("DATABASE_BUSY", "SQLite locked; inspect before retrying an import."),
            _ => Self::new("INTERNAL_ERROR", "Agent Bridge import database operation failed."),
        }
    }
}
fn invalid() -> ImportError {
    ImportError::new("INVALID_PAYLOAD", "Invalid historical Task Room snapshot.")
}
fn import_conflict() -> ImportError {
    ImportError::new(
        "IMPORT_CONFLICT",
        "Existing source identity, mission or snapshot differs; explicit review required.",
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyEventSnapshot {
    pub sequence: i64,
    #[serde(rename = "type")]
    pub event_type: String,
    pub summary: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyStepSnapshot {
    pub step_id: String,
    pub title: String,
    pub state: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyTaskSnapshot {
    pub provider: String,
    pub context_id: String,
    pub task_id: String,
    pub goal: String,
    pub status: String,
    pub total_events_reported: i32,
    pub events: Vec<LegacyEventSnapshot>,
    pub steps: Vec<LegacyStepSnapshot>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportResult {
    pub mission_id: String,
    pub source_digest: String,
    pub partial_history: bool,
    pub import_state: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedLegacyStep {
    pub step_id: String,
    pub title: String,
    pub state: String,
    /// Historic only; this does NOT authorize execution.
    pub approved: bool,
}

fn utf16_len(text: &str) -> usize { text.encode_utf16().count() }
fn blank(text: &str) -> bool { text.trim().is_empty() }

// The identity is supplied by the original source, not inferred from a
// producer brand. Exclude the '|' delimiter used by the historical SQLite
// idempotency key. Reject unbounded or ambiguous identifiers.
fn bounded_provider(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
        })
}
fn bounded_source_id(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':')
        })
}

fn validate(input: &LegacyTaskSnapshot) -> Result<()> {
    if !bounded_provider(&input.provider)
        || !bounded_source_id(&input.context_id)
        || !bounded_source_id(&input.task_id) || blank(&input.goal)
        || utf16_len(&input.goal) > 16384
        || input.total_events_reported < 0
        || input.events.len() > 1000
    { return Err(invalid()); }
    let mut event_sequences = HashSet::with_capacity(input.events.len());
    for event in &input.events {
        if event.sequence <= 0 || utf16_len(&event.event_type) > 256
            || utf16_len(&event.summary) > 8192
            || !event_sequences.insert(event.sequence)
        { return Err(invalid()); }
    }
    let mut step_ids = HashSet::with_capacity(input.steps.len());
    for step in &input.steps {
        if blank(&step.step_id) || utf16_len(&step.step_id) > 128
            || !step_ids.insert(step.step_id.as_str())
        { return Err(invalid()); }
    }
    // Deliberately allow unknown task, step and event status strings.
    Ok(())
}

/// The caller owns this already-open connection. This function DOES NOT
/// migrate it, accept a database path, or open any file. Core must have
/// already verified the migration checksums as an independent trust gate.
pub fn verify_existing_v7(conn: &Connection) -> Result<()> {
    if !conn.is_autocommit() {
        return Err(ImportError::new(
            "INVALID_PAYLOAD", "An idle SQLite connection is required."
        ));
    }
    let mut query = conn.prepare(
        "SELECT version,checksum,compatibility_min FROM schema_migrations ORDER BY version"
    ).map_err(|_| ImportError::new(
        "UPGRADE_INCOMPATIBLE", "Agent Bridge schema migration history is missing."
    ))?;
    let mut rows = query.query([])?;
    for expected in 1..=SCHEMA_VERSION {
        let row = rows.next()?.ok_or_else(|| ImportError::new(
            "UPGRADE_INCOMPATIBLE", "Agent Bridge schema is incomplete."
        ))?;
        let version: i64 = row.get(0)?;
        let checksum: String = row.get(1)?;
        let min: i64 = row.get(2)?;
        if version != expected || min < 1 || min > expected
            || checksum.len() != 64
            || !checksum.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ImportError::new(
                "UPGRADE_INCOMPATIBLE", "Unexpected Agent Bridge schema history."
            ));
        }
    }
    if rows.next()?.is_some() {
        return Err(ImportError::new(
            "UPGRADE_INCOMPATIBLE", "Newer SQLite schema is not supported."
        ));
    }
    drop(rows);
    drop(query);

    // Check only static, first-party schema table/column names. No second
    // storage format, migrations or SQL from operator-controlled strings.
    const TABLES: &[(&str, &[&str])] = &[
        ("missions", &[
            "mission_id", "goal", "status", "current_revision", "priority",
            "orchestrator_enabled", "actor_context_handle",
            "create_idempotency_key", "created_at", "updated_at",
        ]),
        ("imports", &[
            "source_provider", "source_context_id", "source_task_id", "source_digest",
            "target_mission_id", "imported_at", "state",
        ]),
        ("legacy_import_steps", &[
            "mission_id", "source_step_id", "title", "source_state", "approved",
        ]),
        ("legacy_import_events", &[
            "mission_id", "source_seq", "source_type", "summary",
        ]),
        ("events", &[
            "mission_id", "operation_id", "event_type", "payload_redacted", "created_at",
        ]),
        ("mission_memberships", &["mission_id", "context_hash", "role", "state"]),
    ];
    for (table, required) in TABLES {
        let sql = format!("PRAGMA table_info({table})");
        let mut statement = conn.prepare(&sql)?;
        let columns: HashSet<String> = statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<std::result::Result<_, _>>()?;
        if required.iter().any(|name| !columns.contains(*name)) {
            return Err(ImportError::new(
                "UPGRADE_INCOMPATIBLE", "Agent Bridge schema 7 tables are incompatible."
            ));
        }
    }
    Ok(())
}


fn sha256_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// System.Text.Json's default JavaScriptEncoder for C# JsonDefaults.Options.
/// The original DTO is serialized in record-constructor property order,
/// snake_case; quote, HTML-sensitive ASCII and non-ASCII UTF-16 are escaped.
fn dotnet_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str(r"\u0022"),
            '\\' => out.push_str(r"\\"),
            '\u{0008}' => out.push_str(r"\b"),
            '\u{0009}' => out.push_str(r"\t"),
            '\u{000A}' => out.push_str(r"\n"),
            '\u{000C}' => out.push_str(r"\f"),
            '\u{000D}' => out.push_str(r"\r"),
            '\'' | '&' | '+' | '<' | '>' | '\u{0060}' => {
                let _ = write!(out, r"\u{:04X}", ch as u32);
            }
            c if (c as u32) < 0x20 || (c as u32) >= 0x7f => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units).iter() {
                    let _ = write!(out, r"\u{unit:04X}");
                }
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

/// Only the known first-party DTO properties participate in the C# digest.
/// The original array order matters, although database event rows are later
/// inserted in source sequence order. Unknown state/type strings are intact.
fn canonical_snapshot(snapshot: &LegacyTaskSnapshot, provider: &str) -> String {
    let mut out = String::with_capacity(
        snapshot.goal.len() + snapshot.events.len() * 80
            + snapshot.steps.len() * 80 + 256
    );
    out.push_str("{\"provider\":");
    dotnet_string(&mut out, provider);
    out.push_str(",\"context_id\":");
    dotnet_string(&mut out, &snapshot.context_id);
    out.push_str(",\"task_id\":");
    dotnet_string(&mut out, &snapshot.task_id);
    out.push_str(",\"goal\":");
    dotnet_string(&mut out, &snapshot.goal);
    out.push_str(",\"status\":");
    dotnet_string(&mut out, &snapshot.status);
    out.push_str(",\"total_events_reported\":");
    let _ = write!(out, "{}", snapshot.total_events_reported);
    out.push_str(",\"events\":[");
    for (index, event) in snapshot.events.iter().enumerate() {
        if index > 0 { out.push(','); }
        out.push_str("{\"sequence\":");
        let _ = write!(out, "{}", event.sequence);
        out.push_str(",\"type\":");
        dotnet_string(&mut out, &event.event_type);
        out.push_str(",\"summary\":");
        dotnet_string(&mut out, &event.summary);
        out.push('}');
    }
    out.push_str("],\"steps\":[");
    for (index, step) in snapshot.steps.iter().enumerate() {
        if index > 0 { out.push(','); }
        out.push_str("{\"step_id\":");
        dotnet_string(&mut out, &step.step_id);
        out.push_str(",\"title\":");
        dotnet_string(&mut out, &step.title);
        out.push_str(",\"state\":");
        dotnet_string(&mut out, &step.state);
        out.push('}');
    }
    out.push_str("]}");
    out
}

/// Compute the first-party DTO digest for a specific stored provider spelling.
/// The provider spelling is part of the persisted fingerprint.
fn digest_for_provider(snapshot: &LegacyTaskSnapshot, provider: &str) -> String {
    sha256_hex(canonical_snapshot(snapshot, provider).as_bytes())
}

/// Digest of the supplied snapshot, including the original provider spelling.
pub fn snapshot_digest(snapshot: &LegacyTaskSnapshot) -> Result<String> {
    validate(snapshot)?;
    Ok(digest_for_provider(snapshot, &snapshot.provider))
}

fn identity_key(provider: &str, context: &str, task: &str) -> String {
    sha256_hex(format!("{provider}|{context}|{task}").as_bytes())
}
fn mission_id() -> Result<String> {
    let mut raw = [0u8; 16];
    getrandom_fill(&mut raw).map_err(|_| ImportError::new(
        "INTERNAL_ERROR", "Secure random mission ID generation failed."
    ))?;
    let mut id = String::from("mis_");
    for byte in raw {
        let _ = write!(id, "{byte:02x}");
    }
    Ok(id)
}
fn timestamp() -> String {
    let now = Utc::now();
    // DateTimeOffset.UtcNow.ToString("O"): seven fractional digits, UTC.
    format!("{}.{:07}+00:00",
        now.format("%Y-%m-%dT%H:%M:%S"),
        now.timestamp_subsec_nanos() / 100
    )
}
fn title_prefix(title: &str) -> String {
    // C# truncates at UTF-16 offset 512. Avoid making an invalid unpaired
    // surrogate if a non-BMP scalar straddles that boundary.
    if utf16_len(title) <= 512 { return title.to_owned(); }
    let mut copied = String::new();
    let mut units = 0usize;
    for scalar in title.chars() {
        if units + scalar.len_utf16() > 512 { break; }
        copied.push(scalar);
        units += scalar.len_utf16();
    }
    copied
}
fn has_partial_history(snapshot: &LegacyTaskSnapshot) -> bool {
    if snapshot.events.len() < snapshot.total_events_reported as usize {
        return true;
    }
    let mut sequences: Vec<i64> = snapshot.events.iter().map(|e| e.sequence).collect();
    sequences.sort_unstable();
    sequences.iter().enumerate()
        .any(|(index, sequence)| *sequence != (index + 1) as i64)
}

/// Atomic v7-only write transaction. Foreign keys are checked, not assumed.
fn begin_import(conn: &mut Connection) -> Result<rusqlite::Transaction<'_>> {
    verify_existing_v7(conn)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    let enabled: i64 = conn.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    if enabled != 1 {
        return Err(ImportError::new(
            "UPGRADE_INCOMPATIBLE", "SQLite foreign keys must be enabled."
        ));
    }
    conn.transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(Into::into)
}


/// A previously imported mission must still have its original read-only
/// source history. A matching digest is not permission to adopt mutated rows.
fn stored_history_matches(
    tx: &rusqlite::Transaction<'_>,
    mission_id: &str,
    snapshot: &LegacyTaskSnapshot,
) -> Result<bool> {
    let mut steps_query = tx.prepare(
        "SELECT source_step_id,title,source_state,approved
           FROM legacy_import_steps
          WHERE mission_id=?1 ORDER BY source_step_id",
    )?;
    let stored_steps: Vec<(String, String, String, i64)> = steps_query
        .query_map([mission_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<std::result::Result<_, _>>()?;
    if stored_steps.len() != snapshot.steps.len() {
        return Ok(false);
    }
    let mut expected_steps = snapshot.steps.iter().collect::<Vec<_>>();
    expected_steps.sort_by(|left, right| left.step_id.cmp(&right.step_id));
    if !stored_steps.iter().zip(expected_steps).all(|(stored, original)| {
        stored.0 == original.step_id
            && stored.1 == title_prefix(&original.title)
            && stored.2 == original.state
            && stored.3 == 0
    }) {
        return Ok(false);
    }

    let mut events_query = tx.prepare(
        "SELECT source_seq,source_type,summary
           FROM legacy_import_events
          WHERE mission_id=?1 ORDER BY source_seq",
    )?;
    let stored_events: Vec<(i64, String, String)> = events_query
        .query_map([mission_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?
        .collect::<std::result::Result<_, _>>()?;
    if stored_events.len() != snapshot.events.len() {
        return Ok(false);
    }
    let mut expected_events = snapshot.events.iter().collect::<Vec<_>>();
    expected_events.sort_by_key(|event| event.sequence);
    Ok(stored_events.iter().zip(expected_events).all(|(stored, original)| {
        stored.0 == original.sequence
            && stored.1 == original.event_type
            && stored.2 == original.summary
    }))
}

/// Local import of a source-provided snapshot. The provider in the snapshot
/// is part of both its provenance and its original digest. No foreign provider
/// is inferred or renamed, and importing never executes source effects.
pub fn import_snapshot(
    conn: &mut Connection,
    snapshot: &LegacyTaskSnapshot,
) -> Result<ImportResult> {
    import_snapshot_with_alias(conn, snapshot, None)
}

/// Explicit reconciliation for a *pre-existing* historical provider spelling.
/// The alias is supplied by the local operator; it cannot create an import,
/// authorize a different source, or change any stored provenance. Its record
/// must match the same context/task, original fingerprint and blocked mission.
/// Never expose this option through a remotely callable MCP endpoint.
pub fn import_snapshot_with_alias(
    conn: &mut Connection,
    snapshot: &LegacyTaskSnapshot,
    historical_source_provider: Option<&str>,
) -> Result<ImportResult> {
    validate(snapshot)?;
    if let Some(alias) = historical_source_provider {
        if !bounded_provider(alias) || alias == snapshot.provider {
            return Err(invalid());
        }
    }
    let partial = has_partial_history(snapshot);
    let import_state = if partial { "imported_partial" } else { "imported" };
    let digest = snapshot_digest(snapshot)?;
    let key = identity_key(&snapshot.provider, &snapshot.context_id, &snapshot.task_id);
    let tx = begin_import(conn)?;

    // Primary key: (source_provider,source_context_id,source_task_id).
    // A matching pair from a different provider is NOT proof of common origin.
    // Read at most three contenders; two already mean ambiguous provenance.
    let mut lookup = tx.prepare(
        "SELECT source_provider,source_digest,target_mission_id,state
           FROM imports
          WHERE source_context_id=?1 AND source_task_id=?2
          ORDER BY source_provider LIMIT 3",
    )?;
    let records: Vec<(String, String, Option<String>, String)> = lookup.query_map(
        params![&snapshot.context_id, &snapshot.task_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?.collect::<std::result::Result<_, _>>()?;
    drop(lookup);
    if records.len() > 1 {
        return Err(import_conflict());
    }
    if let Some((stored_provider, previous_digest, prior_mission, prior_state)) =
        records.into_iter().next()
    {
        if stored_provider == snapshot.provider {
            // Exact source identity needs no alias. Do not silently adopt
            // an unrelated operator-supplied alias.
            if historical_source_provider.is_some() {
                return Err(import_conflict());
            }
        } else if historical_source_provider != Some(stored_provider.as_str()) {
            return Err(import_conflict());
        }
        if prior_state != import_state || previous_digest != digest_for_provider(snapshot, &stored_provider) {
            return Err(import_conflict());
        }
        let mission_id = prior_mission.ok_or_else(import_conflict)?;
        let existing: Option<(String, String, i64, i64, i64, String, String)> =
            tx.query_row(
                "SELECT goal,status,current_revision,orchestrator_enabled,
                        priority,actor_context_handle,create_idempotency_key
                   FROM missions WHERE mission_id=?1",
                [&mission_id],
                |row| Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?,
                    row.get(4)?, row.get(5)?, row.get(6)?,
                )),
            ).optional()?;
        let original_key = format!(
            "legacy:{}",
            identity_key(&stored_provider, &snapshot.context_id, &snapshot.task_id)
        );
        if !matches!(existing, Some((goal, status, 1, 0, 0, owner, idem))
            if goal == snapshot.goal && status == "blocked"
                && owner == "legacy-import" && idem == original_key)
        {
            return Err(import_conflict());
        }
        // A single stored import must own this blocked mission. A second
        // source with a shared target is never accepted as a historical alias.
        let import_count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM imports WHERE target_mission_id=?1",
            [&mission_id], |row| row.get(0),
        )?;
        let memberships: i64 = tx.query_row(
            "SELECT COUNT(*) FROM mission_memberships WHERE mission_id=?1",
            [&mission_id], |row| row.get(0),
        )?;
        if import_count != 1 || memberships != 0
            || !stored_history_matches(&tx, &mission_id, snapshot)?
        {
            return Err(import_conflict());
        }
        // Preserve the original digest, mission, source metadata and status.
        // Idempotent observation makes NO SQL changes or effect replay.
        return Ok(ImportResult {
            mission_id,
            source_digest: previous_digest,
            partial_history: prior_state == "imported_partial",
            import_state: prior_state,
        });
    }

    // A claimed alias without a matching prior row cannot authorize creation.
    // Another provider with the same pair likewise required explicit review.
    if historical_source_provider.is_some() {
        return Err(import_conflict());
    }
    let idem = format!("legacy:{key}");
    let orphan_count: i64 = tx.query_row(
        "SELECT COUNT(*) FROM missions WHERE create_idempotency_key=?1",
        [&idem], |row| row.get(0),
    )?;
    if orphan_count != 0 {
        return Err(import_conflict());
    }

    // A prior import can lose its imports row while retaining the blocked
    // mission. Its legacy: digest includes the ORIGINAL source provider, so
    // the incoming provider's exact key cannot rule out that orphan. Refuse
    // new creation until provenance is reconciled; never infer a source,
    // adopt the orphan or insert a second mission. Existing verified replays
    // already returned above and are unaffected by this creation-only gate.
    let missing_provenance: i64 = tx.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM missions AS m
              WHERE m.actor_context_handle='legacy-import'
                AND substr(m.create_idempotency_key,1,7)='legacy:'
                AND NOT EXISTS (
                    SELECT 1 FROM imports AS i
                     WHERE i.target_mission_id=m.mission_id
                )
         )",
        [],
        |row| row.get(0),
    )?;
    if missing_provenance != 0 {
        return Err(import_conflict());
    }

    let mission = mission_id()?;
    let when = timestamp();


    // "legacy-import" is an explicit non-capability sentinel, not a context
    // or an owner hash. The mission is BLOCKED, revision 1, orchestrator 0.
    tx.execute(
        "INSERT INTO missions( \
            mission_id,goal,status,current_revision,orchestrator_enabled,priority, \
            actor_context_handle,create_idempotency_key,created_at,updated_at \
         ) VALUES(?1,?2,'blocked',1,0,0,'legacy-import',?3,?4,?4)",
        params![&mission, &snapshot.goal, &idem, &when],
    )?;

    // All unknown step states are copied as-is, but never approved or
    // transformed into executable mission_steps.
    for step in &snapshot.steps {
        tx.execute(
            "INSERT INTO legacy_import_steps( \
                mission_id,source_step_id,title,source_state,approved \
             ) VALUES(?1,?2,?3,?4,0)",
            params![&mission, &step.step_id, title_prefix(&step.title), &step.state],
        )?;
    }

    // Preserve every provided source event, its unknown type and summary,
    // while storing by source sequence like the C# LegacyImportRepository.
    let mut ordered: Vec<&LegacyEventSnapshot> = snapshot.events.iter().collect();
    ordered.sort_by_key(|event| event.sequence);
    for event in ordered {
        tx.execute(
            "INSERT INTO legacy_import_events( \
                mission_id,source_seq,source_type,summary \
             ) VALUES(?1,?2,?3,?4)",
            params![&mission, event.sequence, &event.event_type, &event.summary],
        )?;
    }

    tx.execute(
        "INSERT INTO imports( \
            source_provider,source_context_id,source_task_id,source_digest, \
            target_mission_id,imported_at,state \
         ) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            &snapshot.provider, &snapshot.context_id, &snapshot.task_id,
            &digest, &mission, &when, import_state
        ],
    )?;

    // Exactly one minimal/redacted legacy.import journal marker, no operation
    // reference, no result to replay, and no Task Room authorization encoded.
    let redacted = if partial {
        r#"{"status":"imported_partial"}"#
    } else {
        r#"{"status":"imported"}"#
    };
    tx.execute(
        "INSERT INTO events( \
            mission_id,operation_id,event_type,payload_redacted,created_at \
         ) VALUES(?1,NULL,'legacy.import',?2,?3)",
        params![&mission, redacted, timestamp()],
    )?;
    tx.commit()?;

    Ok(ImportResult {
        mission_id: mission,
        source_digest: digest,
        partial_history: partial,
        import_state: import_state.to_owned(),
    })
}

/// Optional JSON helper for a snapshot already PROVIDED IN MEMORY by the
/// operator. No disk, network or provider access. Unrecognized extra JSON
/// properties are ignored exactly as in the first-party C# DTO parser.
pub fn import_snapshot_json(
    conn: &mut Connection,
    bytes: &[u8],
) -> Result<ImportResult> {
    if bytes.len() > MAX_SNAPSHOT_JSON_BYTES {
        return Err(ImportError::new("INVALID_PAYLOAD", "Snapshot JSON exceeds 1 MiB."));
    }
    let snapshot: LegacyTaskSnapshot =
        serde_json::from_slice(bytes).map_err(|_| invalid())?;
    import_snapshot(conn, &snapshot)
}

/// Read historical imported steps. Unknown source states are returned
/// unchanged; approved is a historical flag, never permission to execute.
pub fn read_imported_steps(
    conn: &Connection,
    mission_id: &str,
) -> Result<Vec<ImportedLegacyStep>> {
    verify_existing_v7(conn)?;
    if !valid_mission_id(mission_id) { return Err(invalid()); }
    let mut query = conn.prepare(
        "SELECT source_step_id,title,source_state,approved FROM legacy_import_steps \
         WHERE mission_id=?1 ORDER BY source_step_id",
    )?;
    let rows = query.query_map([mission_id], |row| {
        let approved: i64 = row.get(3)?;
        Ok(ImportedLegacyStep {
            step_id: row.get(0)?,
            title: row.get(1)?,
            state: row.get(2)?,
            approved: approved == 1,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
}

/// Read the source event history without interpreting event kinds, scheduling
/// prepared actions, or replaying the original effects of task execution.
pub fn read_imported_events(
    conn: &Connection,
    mission_id: &str,
) -> Result<Vec<LegacyEventSnapshot>> {
    verify_existing_v7(conn)?;
    if !valid_mission_id(mission_id) { return Err(invalid()); }
    let mut query = conn.prepare(
        "SELECT source_seq,source_type,summary FROM legacy_import_events \
         WHERE mission_id=?1 ORDER BY source_seq",
    )?;
    let rows = query.query_map([mission_id], |row| {
        Ok(LegacyEventSnapshot {
            sequence: row.get(0)?,
            event_type: row.get(1)?,
            summary: row.get(2)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
}

fn valid_mission_id(id: &str) -> bool {
    id.strip_prefix("mis_").is_some_and(|value| {
        value.len() == 32 && value.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}
