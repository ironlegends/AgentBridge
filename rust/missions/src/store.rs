//! Shared Agent Bridge schema-v7 storage primitives. The caller owns the connection.
//! No database path, SQLite migration, transport, or third-party Task Room state is created here.

use chrono::Utc;
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SCHEMA_VERSION: i64 = agent_bridge_core::CURRENT_SCHEMA_VERSION as i64;

#[derive(Debug, Clone, Serialize)]
pub struct BridgeError {
    pub code: &'static str,
    pub message: String,
    pub retryable: bool,
}
pub type Result<T> = std::result::Result<T, BridgeError>;

impl BridgeError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), retryable: false }
    }
}
impl From<rusqlite::Error> for BridgeError {
    fn from(error: rusqlite::Error) -> Self {
        match error {
            rusqlite::Error::SqliteFailure(failure, _)
                if matches!(failure.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) =>
            {
                Self {
                    code: "DATABASE_BUSY",
                    message: "SQLite is temporarily locked; inspect the result before retrying a write.".into(),
                    retryable: true,
                }
            }
            _ => Self::new("INTERNAL_ERROR", "SQLite mission operation failed."),
        }
    }
}
impl From<serde_json::Error> for BridgeError {
    fn from(_: serde_json::Error) -> Self {
        Self::new("INVALID_PAYLOAD", "Malformed Agent Bridge JSON.")
    }
}

pub fn invalid(message: &'static str) -> BridgeError {
    BridgeError::new("INVALID_PAYLOAD", message)
}
pub fn denied(message: &'static str) -> BridgeError {
    BridgeError::new("SECURITY_DENIED", message)
}

pub fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    Sha256::digest(bytes.as_ref()).iter().map(|byte| format!("{byte:02x}")).collect()
}
/// Matches System.Text.Json's default JavaScriptEncoder (the C# v7
/// JsonDefaults.Options encoder) for operation digests. Property order comes
/// from the dedicated Serialize structs at each call site. Crucial when a
/// cross-runtime replay includes French accents, quotes or HTML characters.
pub fn digest_json<T: Serialize>(value: &T) -> Result<String> {
    let serialized = serde_json::to_string(value)?;
    let mut result = String::with_capacity(serialized.len());
    let mut chars = serialized.chars();
    let mut in_string = false;
    while let Some(character) = chars.next() {
        if !in_string {
            result.push(character);
            if character == '"' { in_string = true; }
            continue;
        }
        match character {
            '"' => {
                result.push('"');
                in_string = false;
            }
            '\\' => {
                let escaped = chars.next().ok_or_else(|| invalid("Invalid JSON escape."))?;
                if escaped == '"' {
                    // System.Text.Json uses the six-character quote escape.
                    result.push_str("\\u0022");
                } else if escaped == 'u' {
                    result.push_str("\\u");
                    for _ in 0..4 {
                        result.push(chars.next()
                            .ok_or_else(|| invalid("Incomplete JSON escape."))?
                            .to_ascii_uppercase());
                    }
                } else {
                    result.push('\\');
                    result.push(escaped);
                }
            }
            '\'' | '&' | '+' | '<' | '>' | '\u{0060}' => {
                result.push_str(&format!("\\u{:04X}", character as u32));
            }
            value if !value.is_ascii() || value == '\u{7F}' => {
                let mut utf16 = [0u16; 2];
                for code_unit in value.encode_utf16(&mut utf16).iter() {
                    result.push_str(&format!("\\u{code_unit:04X}"));
                }
            }
            other => result.push(other),
        }
    }
    Ok(sha256_hex(result.as_bytes()))
}
pub fn json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(Into::into)
}
pub fn new_id(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("{}_{}", prefix, bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
}
pub fn new_guid_n() -> String {
    // The legacy checkpoint ID is Guid.NewGuid().ToString("N"), not an opaque cp_ ID.
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
pub fn valid_id(prefix: &str, id: &str) -> bool {
    id.strip_prefix(prefix)
        .and_then(|part| part.strip_prefix('_'))
        .is_some_and(|part| part.len() == 32 && part.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}
pub fn require_id(prefix: &str, id: &str) -> Result<()> {
    if valid_id(prefix, id) { Ok(()) } else { Err(invalid("Malformed Agent Bridge public ID.")) }
}
pub fn require_text(value: &str, limit: usize, name: &'static str) -> Result<()> {
    if !value.trim().is_empty() && value.encode_utf16().count() <= limit { Ok(()) }
    else { Err(invalid(name)) }
}
pub fn require_key(key: &str) -> Result<()> {
    require_text(key, 256, "An idempotency key of 1-256 characters is required.")
}
pub fn now() -> String {
    // .NET DateTimeOffset.ToString("O") has exactly 7 fractional digits.
    let time = Utc::now();
    format!("{}.{:07}+00:00",
        time.format("%Y-%m-%dT%H:%M:%S"),
        time.timestamp_subsec_nanos() / 100)
}

/// Strict, read-only verification against Agent Bridge's *own* embedded migration files.
/// Refuses absent, partial, reordered, tampered, and newer schemas; never initializes SQLite.
pub fn verify_schema(conn: &Connection) -> Result<()> {
    if !conn.is_autocommit() {
        return Err(BridgeError::new("INVALID_PAYLOAD", "An idle caller-owned SQLite connection is required."));
    }
    let exists: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'",
        [], |row| row.get(0)
    )?;
    if exists != 1 {
        return Err(BridgeError::new("UPGRADE_INCOMPATIBLE", "Agent Bridge schema migrations are not installed."));
    }
    let mut query = conn.prepare(
        "SELECT version,checksum,compatibility_min FROM schema_migrations ORDER BY version"
    )?;
    let mut rows = query.query([])?;
    let mut expected = 1i64;
    while let Some(row) = rows.next()? {
        let version: i64 = row.get(0)?;
        let checksum: String = row.get(1)?;
        let compatibility_min: i64 = row.get(2)?;
        if version != expected || expected > SCHEMA_VERSION
            || !agent_bridge_core::migration_checksum_matches(version, &checksum)
            || compatibility_min != 1
        {
            return Err(BridgeError::new("UPGRADE_INCOMPATIBLE", "Unrecognized Agent Bridge schema history."));
        }
        expected += 1;
    }
    if expected != SCHEMA_VERSION + 1 {
        return Err(BridgeError::new("UPGRADE_INCOMPATIBLE", "Agent Bridge database has not reached schema 7."));
    }
    Ok(())
}

/// BEGIN IMMEDIATE serializes all writers, protects CAS/ownership checks, and
/// atomically commits event + operation + mission mutations. On error it rolls back.
pub fn write<T>(conn: &mut Connection, body: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
    verify_schema(conn)?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;
    let enabled: i64 = conn.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    if enabled != 1 {
        return Err(BridgeError::new("SECURITY_DENIED", "SQLite foreign-key enforcement is required."));
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let output = body(&tx)?;
    tx.commit()?;
    Ok(output)
}

pub fn require_context(conn: &Connection, handle: &str) -> Result<String> {
    if !valid_id("ctx", handle) {
        return Err(denied("Unknown or forged context handle."));
    }
    let hash = sha256_hex(handle.as_bytes());
    let count: i64 = conn.query_row(
        "SELECT count(*) FROM agent_contexts WHERE handle_hash=?1",
        [hash.as_str()], |row| row.get(0)
    )?;
    if count != 1 {
        return Err(denied("Unknown or inactive context handle."));
    }
    Ok(hash)
}

/// Telemetry is best effort. Locks or read-only connections cannot change
/// the authorization decision or the result of the caller's operation.
pub(crate) fn note_context_use(conn: &Connection, hash: &str) -> Option<String> {
    let (id, touch): (String, bool) = conn.query_row(
        "SELECT context_id, last_seen IS NULL OR
            julianday(last_seen) < julianday(datetime('now', '-60 seconds'))
         FROM agent_contexts WHERE handle_hash=?1",
        [hash],
        |row| Ok((row.get(0)?, row.get::<_, Option<bool>>(1)?.unwrap_or(true))),
    ).ok()?;
    if touch {
        // Recheck under the SQLite write lock for concurrent connections.
        let _ = conn.execute(
            "UPDATE agent_contexts SET last_seen=?1 WHERE context_id=?2 AND handle_hash=?3
             AND (julianday(last_seen) IS NULL OR
                  julianday(last_seen) < julianday(datetime(?1, '-60 seconds')))",
            params![now(), id, hash],
        );
    }
    Some(id)
}

pub fn membership(tx: &Connection, mission: &str, actor_hash: &str, owner_only: bool) -> Result<()> {
    let membership: Option<(String, String)> = tx.query_row(
        "SELECT role,state FROM mission_memberships WHERE mission_id=?1 AND context_hash=?2",
        params![mission, actor_hash], |row| Ok((row.get(0)?, row.get(1)?))
    ).optional()?;
    if !matches!(membership, Some((ref role, ref state)) if state=="attached" && (!owner_only || role=="owner")) {
        return Err(denied("Context is not an attached member with the required role."));
    }
    Ok(())
}

pub fn attached_assignee(tx: &Connection, mission: &str, assignee: &str) -> Result<()> {
    require_id("ctx", assignee)?;
    let ok: Option<i64> = tx.query_row(
        "SELECT 1 FROM mission_memberships m JOIN agent_contexts c ON c.handle_hash=m.context_hash \
         WHERE m.mission_id=?1 AND m.state='attached' AND c.context_id=?2",
        params![mission, assignee], |r| r.get(0)
    ).optional()?;
    if ok.is_none() { Err(denied("Assignee must be attached to the mission.")) } else { Ok(()) }
}

/// An ID is a public locator; only its *registered secret-handle hash* is used
/// for membership. Also accepts the legacy RPC target_context_handle input.
pub fn resolve_target(
    tx: &Connection, actor_hash: &str,
    target_id: Option<&str>, target_handle: Option<&str>
) -> Result<String> {
    if target_id.is_some() == target_handle.is_some() {
        return Err(invalid("Specify exactly one target context."));
    }
    let (column, locator) = if let Some(id) = target_id {
        require_id("ctx", id)?;
        ("context_id", id.to_owned())
    } else {
        let handle = target_handle.expect("exclusive target selector");
        if !valid_id("ctx", handle) { return Err(denied("Unknown target context handle.")); }
        ("handle_hash", sha256_hex(handle.as_bytes()))
    };
    let sql = format!("SELECT handle_hash FROM agent_contexts WHERE {column}=?1");
    let mut statement = tx.prepare(&sql)?;
    let mut rows = statement.query([locator])?;
    let hash = match rows.next()? {
        Some(row) => row.get::<_, String>(0)?,
        None => return Err(denied("Unknown target context.")),
    };
    if rows.next()?.is_some() {
        return Err(denied("Ambiguous target context."));
    }
    if hash == actor_hash {
        return Err(invalid("Target context must differ from the caller."));
    }
    Ok(hash)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionDto {
    pub mission_id: String,
    pub goal: String,
    pub status: String,
    pub revision: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    pub actor_context_handle: String, // SHA-256 hash, never the private handle.
    pub created_at: String,
    pub updated_at: String,
}
fn mission_row(row: &Row<'_>) -> rusqlite::Result<MissionDto> {
    Ok(MissionDto {
        mission_id: row.get(0)?, goal: row.get(1)?, status: row.get(2)?,
        revision: row.get(3)?, project_id: row.get(4)?,
        actor_context_handle: row.get(5)?, created_at: row.get(6)?, updated_at: row.get(7)?,
    })
}
const MISSION_COLUMNS: &str =
    "mission_id,goal,status,current_revision,project_id,actor_context_handle,created_at,updated_at";

pub fn fetch_mission(conn: &Connection, id: &str) -> Result<MissionDto> {
    require_id("mis", id)?;
    let sql = format!("SELECT {MISSION_COLUMNS} FROM missions WHERE mission_id=?1");
    conn.query_row(&sql, [id], mission_row).optional()?
        .ok_or_else(|| BridgeError::new("NOT_FOUND", "Mission not found."))
}
pub fn touch(tx: &Transaction<'_>, mission: &MissionDto, revision: i64) -> Result<MissionDto> {
    if mission.revision != revision {
        return Err(BridgeError::new("CONFLICT_REVISION", "Mission changed since observation."));
    }
    let updated = tx.execute(
        "UPDATE missions SET current_revision=current_revision+1,updated_at=?1 \
         WHERE mission_id=?2 AND current_revision=?3",
        params![now(), mission.mission_id, revision],
    )?;
    if updated != 1 { return Err(BridgeError::new("CONFLICT_REVISION", "Stale mission revision.")); }
    fetch_mission(tx, &mission.mission_id)
}
pub fn append_event(tx: &Transaction<'_>, mission: &str, op: Option<&str>,
                    kind: &str, redacted_json: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO events(mission_id,operation_id,event_type,payload_redacted,created_at) \
         VALUES(?1,?2,?3,?4,?5)",
        params![mission, op, kind, redacted_json, now()],
    )?;
    Ok(())
}
pub fn replay<T: DeserializeOwned>(tx: &Transaction<'_>, key: &str, digest: &str) -> Result<Option<T>> {
    let stored: Option<(String, Option<String>)> = tx.query_row(
        "SELECT args_digest,result_json FROM operations WHERE idempotency_key=?1",
        [key], |r| Ok((r.get(0)?, r.get(1)?))
    ).optional()?;
    match stored {
        None => Ok(None),
        Some((prior, _)) if prior != digest => Err(BridgeError::new(
            "IDEMPOTENCY_CONFLICT", "Idempotency key was previously used with different arguments."
        )),
        Some((_, Some(json))) => serde_json::from_str(&json).map(Some).map_err(|_| BridgeError::new(
            "INTERNAL_ERROR", "Stored operation reply could not be decoded."
        )),
        Some((_, None)) => Err(BridgeError::new("INTERNAL_ERROR", "Stored operation has no reply.")),
    }
}
pub fn insert_operation<T: Serialize>(
    tx: &Transaction<'_>, op: &str, mission: &str, key: &str, digest: &str,
    response: &T, method: &str
) -> Result<()> {
    tx.execute(
        "INSERT INTO operations(operation_id,mission_id,tool_name,idempotency_key,args_digest,result_json,state,created_at) \
         VALUES(?1,?2,?3,?4,?5,?6,'succeeded',?7)",
        params![op, mission, method, key, digest, json(response)?, now()],
    )?;
    Ok(())
}

#[derive(Clone, Serialize)]
pub struct ContextCreated {
    pub context_id: String,
    pub context_handle: String, // A secret, returned *only* on creation.
}
pub fn create_context(conn: &mut Connection) -> Result<ContextCreated> {
    write(conn, |tx| {
        let value = ContextCreated { context_id: new_id("ctx"), context_handle: new_id("ctx") };
        let timestamp = now();
        tx.execute(
            "INSERT INTO agent_contexts(context_id,handle_hash,actor_kind,attached_at,last_seen) \
             VALUES(?1,?2,'chatgpt',?3,?3)",
            params![value.context_id, sha256_hex(value.context_handle.as_bytes()), timestamp]
        )?;
        Ok(value)
    })
}

pub fn open_subtasks_exist(tx: &Connection, mission: &str) -> Result<bool> {
    let count: Option<i64> = tx.query_row(
        "WITH latest AS (SELECT MAX(event_seq) AS event_seq FROM events \
          WHERE mission_id=?1 AND event_type='mission.subtask' GROUP BY payload_redacted) \
         SELECT 1 FROM latest JOIN events e ON e.event_seq=latest.event_seq \
         LEFT JOIN operations o ON o.operation_id=e.operation_id AND o.mission_id=e.mission_id \
         WHERE json_extract(o.result_json,'$.status') IS NOT 'completed' LIMIT 1",
        [mission], |r| r.get(0),
    ).optional()?;
    Ok(count.is_some())
}
