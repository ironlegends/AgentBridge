// SPDX-License-Identifier: Apache-2.0

//! Concise Rust port of Agent Bridge's `ResourceKey`, `LeaseCoordinator`, and
//! `Resource.{Acquire,Renew,Release,IsCurrent}` RPC routing on an existing
//! SQLite `resource_leases` table.

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use chrono::{DateTime, Datelike, Utc};

/// Minimum allowed lease TTL (`100ms`), matching `LeaseCoordinator.ValidateTtl`.
pub const MIN_TTL: Duration = Duration::from_millis(100);

/// Maximum allowed lease TTL (`15m`), matching `LeaseCoordinator.ValidateTtl`.
pub const MAX_TTL: Duration = Duration::from_secs(15 * 60);

/// Maximum length of a raw resource key (`4096`).
pub const MAX_RESOURCE_KEY_LEN: usize = 4096;

/// Maximum distinct resource keys per lease (`100`).
pub const MAX_LEASE_KEYS: usize = 100;

/// Maximum length of an `operation_id` (`256`).
pub const MAX_OPERATION_ID_LEN: usize = 256;

const ALLOWED_NAMESPACES: &[&str] = &[
    "git",
    "file",
    "service",
    "port",
    "desktop",
    "browser-profile",
    "deploy",
];

/// UTC timestamp rendered with the seven fractional digits used by .NET's
/// round-trip format. The historical SQLite column compares that text directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcTimestamp(DateTime<Utc>);

impl UtcTimestamp {
    pub fn now() -> Self { Self(Utc::now()) }

    pub fn checked_add(self, ttl: Duration) -> Result<Self, LeaseError> {
        let duration = chrono::TimeDelta::from_std(ttl)
            .map_err(|_| LeaseError::invalid_argument("Invalid lease duration."))?;
        self.0.checked_add_signed(duration).filter(|t| (1..=9999).contains(&t.year()))
            .map(Self).ok_or_else(|| LeaseError::invalid_argument("Timestamp overflow."))
    }

    pub fn to_iso8601_o(self) -> String {
        format!("{}.{:07}+00:00", self.0.format("%Y-%m-%dT%H:%M:%S"), self.0.timestamp_subsec_nanos()/100)
    }

    pub fn parse(raw: &str) -> Result<Self, LeaseError> {
        let stamp = DateTime::parse_from_rfc3339(raw.trim()).map(|t| t.with_timezone(&Utc))
            .map_err(|_| LeaseError::invalid_argument("Invalid UTC timestamp."))?;
        if !(1..=9999).contains(&stamp.year()) || stamp.timestamp_subsec_nanos() >= 1_000_000_000 {
            return Err(LeaseError::invalid_argument("Timestamp outside the historical format."));
        }
        Ok(Self(stamp))
    }
}

impl fmt::Display for UtcTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_iso8601_o())
    }
}

impl Serialize for UtcTimestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_iso8601_o())
    }
}

impl<'de> Deserialize<'de> for UtcTimestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(|_| serde::de::Error::custom("invalid ISO-8601 timestamp"))
    }
}

/// Time source equivalent to C# `TimeProvider`.
pub trait Clock: Send + Sync {
    fn utc_now(&self) -> UtcTimestamp;
}

/// Default wall-clock UTC time provider.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn utc_now(&self) -> UtcTimestamp {
        UtcTimestamp::now()
    }
}

/// Protocol, validation, or SQLite error returned by the lease coordinator and
/// RPC handlers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseError {
    Protocol {
        code: String,
        message: String,
        retryable: bool,
    },
    InvalidArgument(String),
    Sqlite(String),
}

impl LeaseError {
    pub fn protocol(
        code: impl Into<String>,
        message: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self::Protocol {
            code: code.into(),
            message: message.into(),
            retryable,
        }
    }

    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::InvalidArgument(message.into())
    }

    pub fn code(&self) -> &str {
        match self {
            Self::Protocol { code, .. } => code.as_str(),
            Self::InvalidArgument(_) => "INVALID_ARGUMENT",
            Self::Sqlite(_) => "STORAGE_ERROR",
        }
    }

    pub fn retryable(&self) -> bool {
        matches!(self, Self::Protocol { retryable: true, .. })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "code": self.code(),
            "message": self.to_string(),
            "retryable": self.retryable(),
        })
    }
}

impl fmt::Display for LeaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol { message, .. }
            | Self::InvalidArgument(message)
            | Self::Sqlite(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for LeaseError {}

impl From<rusqlite::Error> for LeaseError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Sqlite(err.to_string())
    }
}

/// Faithful port of `AgentBridge.CoreService.Resources.ResourceLeaseGrant`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceLeaseGrant {
    #[serde(alias = "OperationId")]
    pub operation_id: String,
    #[serde(alias = "Keys")]
    pub keys: Vec<String>,
    #[serde(alias = "Fences")]
    pub fences: BTreeMap<String, i64>,
    #[serde(alias = "ExpiresAt")]
    pub expires_at: UtcTimestamp,
}

/// Faithful port of `RpcRouter.ResourceAcquireDto`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceAcquireDto {
    #[serde(alias = "MissionId")]
    pub mission_id: String,
    #[serde(alias = "OperationId")]
    pub operation_id: String,
    #[serde(alias = "ResourceKeys")]
    pub resource_keys: Vec<String>,
    #[serde(alias = "TtlSeconds")]
    pub ttl_seconds: i32,
}

fn default_control_ttl_seconds() -> i32 {
    30
}

/// Faithful port of `RpcRouter.ResourceControlDto` (`TtlSeconds = 30` default).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceControlDto {
    #[serde(alias = "MissionId")]
    pub mission_id: String,
    #[serde(alias = "Grant")]
    pub grant: ResourceLeaseGrant,
    #[serde(default = "default_control_ttl_seconds", alias = "TtlSeconds")]
    pub ttl_seconds: i32,
}

/// Caller-supplied prerequisites that live outside `LeaseCoordinator` in C#
/// (`RequireMember` and `capabilities.InspectAsync().GuiAvailable`).
pub trait RpcContext {
    /// Enforces `RequireMember(missionId, actor, ct)` before any lease action.
    fn require_member(&self, mission_id: &str) -> Result<(), LeaseError>;

    /// Returns `GuiAvailable` for `desktop:` leases; fails closed (`Ok(false)`)
    /// by default.
    fn gui_available(&self) -> Result<bool, LeaseError> {
        Ok(false)
    }
}

/// Canonical resource key normalizer matching C# `ResourceKey.Normalize`.
pub fn normalize_resource_key(input: &str) -> Result<String, LeaseError> {
    if input.trim().is_empty() || input.len() > MAX_RESOURCE_KEY_LEN {
        return Err(LeaseError::invalid_argument("Invalid resource key."));
    }
    let Some(pos) = input.find(':') else {
        return Err(LeaseError::invalid_argument(
            "Missing key namespace or value.",
        ));
    };
    if pos < 1 || pos == input.len() - 1 {
        return Err(LeaseError::invalid_argument(
            "Missing key namespace or value.",
        ));
    }

    let prefix = input[..pos].to_ascii_lowercase();
    if !ALLOWED_NAMESPACES.contains(&prefix.as_str()) {
        return Err(LeaseError::invalid_argument(
            "Unsupported resource namespace.",
        ));
    }

    let raw_value = input[pos + 1..].trim();
    let value = if prefix == "file" {
        normalize_file_path(raw_value)?
    } else {
        raw_value.to_lowercase()
    };

    if value.is_empty() || value.contains('\n') || value.contains('\r') {
        return Err(LeaseError::invalid_argument("Invalid resource key."));
    }
    if prefix == "port" {
        let port = value
            .parse::<i32>()
            .map_err(|_| LeaseError::invalid_argument("Invalid port resource key."))?;
        if !(1..=65535).contains(&port) {
            return Err(LeaseError::invalid_argument("Invalid port resource key."));
        }
    }

    Ok(format!("{prefix}:{value}"))
}

/// Builds the bound mission/operation owner identifier used by `Resource.Acquire`:
/// `mission:<mission_id>:op:<operation_id>`.
pub fn bind_operation_id(mission_id: &str, operation_id: &str) -> Result<String, LeaseError> {
    if mission_id.trim().is_empty() || mission_id.contains(":op:") {
        return Err(LeaseError::invalid_argument(
            "Lease requires a valid mission identity.",
        ));
    }
    if operation_id.trim().is_empty() {
        return Err(LeaseError::invalid_argument(
            "Lease requires an operation identity.",
        ));
    }
    let bound = format!("mission:{mission_id}:op:{operation_id}");
    if bound.len() > MAX_OPERATION_ID_LEN {
        return Err(LeaseError::invalid_argument(
            "Lease operation identity exceeds 256 characters.",
        ));
    }
    Ok(bound)
}

/// Enforces that `grant` is bound to `mission_id` and carries a non-empty
/// operation identity and matching key/fence map.
pub fn require_bound_resource_grant(
    mission_id: &str,
    grant: &ResourceLeaseGrant,
) -> Result<(), LeaseError> {
    if mission_id.trim().is_empty() || mission_id.contains(":op:") {
        return Err(LeaseError::protocol(
            "GRANT_MISMATCH",
            "Resource lease grant is not bound to the target mission.",
            false,
        ));
    }
    let prefix = format!("mission:{mission_id}:op:");
    let Some(op_suffix) = grant.operation_id.strip_prefix(&prefix) else {
        return Err(LeaseError::protocol(
            "GRANT_MISMATCH",
            "Resource lease grant is not bound to the target mission.",
            false,
        ));
    };
    if op_suffix.trim().is_empty() || grant.operation_id.len() > MAX_OPERATION_ID_LEN {
        return Err(LeaseError::protocol(
            "GRANT_MISMATCH",
            "Resource lease grant is missing a bound operation identity.",
            false,
        ));
    }
    validate_grant_shape(grant)?;
    Ok(())
}

/// Faithful port of `AgentBridge.CoreService.Resources.LeaseCoordinator`.
pub struct LeaseCoordinator<C: Clock = SystemClock> {
    clock: C,
}

impl Default for LeaseCoordinator<SystemClock> {
    fn default() -> Self {
        Self::new()
    }
}

impl LeaseCoordinator<SystemClock> {
    pub fn new() -> Self {
        Self { clock: SystemClock }
    }
}

impl<C: Clock> LeaseCoordinator<C> {
    pub fn with_clock(clock: C) -> Self {
        Self { clock }
    }

    /// Atomically acquires all distinct normalized `resource_keys` on the
    /// existing `resource_leases` table using `BEGIN IMMEDIATE`.
    pub fn acquire(
        &self,
        conn: &mut Connection,
        resource_keys: &[String],
        operation_id: &str,
        ttl: Duration,
    ) -> Result<ResourceLeaseGrant, LeaseError> {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let grant = self.acquire_in_transaction(&tx, resource_keys, operation_id, ttl)?;
        tx.commit()?;
        Ok(grant)
    }

    /// Compose the same lease acquisition with a caller-owned IMMEDIATE
    /// transaction. The caller must roll back the entire transaction on error.
    pub fn acquire_in_transaction(
        &self,
        tx: &rusqlite::Transaction<'_>,
        resource_keys: &[String],
        operation_id: &str,
        ttl: Duration,
    ) -> Result<ResourceLeaseGrant, LeaseError> {
        validate_ttl(ttl)?;
        if operation_id.trim().is_empty() || operation_id.len() > MAX_OPERATION_ID_LEN {
            return Err(LeaseError::invalid_argument(
                "Lease requires an operation identity.",
            ));
        }

        let keys = canonical_keys(resource_keys)?;
        let now = self.clock.utc_now();
        let expires = now.checked_add(ttl)?;
        let now_str = now.to_iso8601_o();
        let exp_str = expires.to_iso8601_o();

        let mut fences = BTreeMap::new();

        for key in &keys {
            let existing: Option<(String, i64, Option<String>)> = tx
                .query_row(
                    "SELECT owner_operation, generation, expires_at FROM resource_leases WHERE resource_key = ?1",
                    params![key],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;

            let generation = match existing {
                Some((owner, generation, old_expiry_raw)) => {
                    let old_expiry = match old_expiry_raw {
                        Some(raw) => Some(UtcTimestamp::parse(&raw)?),
                        None => None,
                    };
                    if !owner.is_empty() && (old_expiry.is_none() || old_expiry > Some(now)) {
                        return Err(LeaseError::protocol(
                            "RESOURCE_BUSY",
                            "Protected resource already leased.",
                            true,
                        ));
                    }
                    generation
                }
                None => 0,
            };

            let fence = generation
                .checked_add(1)
                .ok_or_else(|| LeaseError::invalid_argument("Lease fencing token overflow."))?;

            tx.execute(
                "INSERT INTO resource_leases(resource_key, owner_operation, generation, token, expires_at, renew_at, conflict_scope) \
                 VALUES(?1, ?2, ?3, ?3, ?4, ?5, 'exact') \
                 ON CONFLICT(resource_key) DO UPDATE SET \
                   owner_operation = ?2, generation = ?3, token = ?3, expires_at = ?4, renew_at = ?5",
                params![key, operation_id, fence, &exp_str, &now_str],
            )?;
            fences.insert(key.clone(), fence);
        }

        Ok(ResourceLeaseGrant {
            operation_id: operation_id.to_string(),
            keys,
            fences,
            expires_at: expires,
        })
    }

    /// Atomically renews every key in `grant` if and only if owner, fencing
    /// token, and non-expiration still match in `resource_leases`.
    pub fn renew(
        &self,
        conn: &mut Connection,
        grant: &ResourceLeaseGrant,
        ttl: Duration,
    ) -> Result<ResourceLeaseGrant, LeaseError> {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let renewed = self.renew_in_transaction(&tx, grant, ttl)?;
        tx.commit()?;
        Ok(renewed)
    }

    /// Renew under the same transaction as an attempt revision update.
    pub fn renew_in_transaction(
        &self, tx: &rusqlite::Transaction<'_>, grant: &ResourceLeaseGrant, ttl: Duration,
    ) -> Result<ResourceLeaseGrant, LeaseError> {
        validate_ttl(ttl)?;
        validate_grant_shape(grant)?;

        let now = self.clock.utc_now();
        let expires = now.checked_add(ttl)?;
        let now_str = now.to_iso8601_o();
        let exp_str = expires.to_iso8601_o();

        for key in &grant.keys {
            let fence = grant.fences.get(key).copied().ok_or_else(|| {
                LeaseError::invalid_argument("Grant is missing fencing token for resource key.")
            })?;
            let updated = tx.execute(
                "UPDATE resource_leases SET expires_at = ?1, renew_at = ?2 \
                 WHERE resource_key = ?3 AND owner_operation = ?4 AND token = ?5 AND generation = ?5 AND expires_at > ?2",
                params![&exp_str, &now_str, key, &grant.operation_id, fence],
            )?;
            if updated != 1 {
                return Err(LeaseError::protocol(
                    "STALE_OBSERVATION",
                    "Resource lease has expired or been replaced.",
                    false,
                ));
            }
        }
        let mut renewed = grant.clone();
        renewed.expires_at = expires;
        Ok(renewed)
    }

    /// Atomically releases every key in `grant` still owned by `grant`'s
    /// operation and fencing token (idempotent when already released/replaced).
    pub fn release(
        &self,
        conn: &mut Connection,
        grant: &ResourceLeaseGrant,
    ) -> Result<(), LeaseError> {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.release_in_transaction(&tx, grant)?;
        tx.commit()?;
        Ok(())
    }

    /// Release only the original owner/fence inside the caller's transaction.
    pub fn release_in_transaction(
        &self, tx: &rusqlite::Transaction<'_>, grant: &ResourceLeaseGrant,
    ) -> Result<(), LeaseError> {
        validate_grant_shape(grant)?;

        for key in &grant.keys {
            let fence = grant.fences.get(key).copied().ok_or_else(|| {
                LeaseError::invalid_argument("Grant is missing fencing token for resource key.")
            })?;
            let now_str = self.clock.utc_now().to_iso8601_o();
            tx.execute(
                "UPDATE resource_leases SET owner_operation = '', expires_at = ?1 \
                 WHERE resource_key = ?2 AND owner_operation = ?3 AND token = ?4 AND generation = ?4",
                params![&now_str, key, &grant.operation_id, fence],
            )?;
        }
        Ok(())
    }

    /// Checks whether all keys in `grant` are still actively held with the
    /// exact owner and fencing token.
    pub fn is_current(
        &self,
        conn: &Connection,
        grant: &ResourceLeaseGrant,
    ) -> Result<bool, LeaseError> {
        validate_grant_shape(grant)?;

        for key in &grant.keys {
            let fence = grant.fences.get(key).copied().ok_or_else(|| {
                LeaseError::invalid_argument("Grant is missing fencing token for resource key.")
            })?;
            let now_str = self.clock.utc_now().to_iso8601_o();
            let count: i64 = conn.query_row(
                "SELECT count(*) FROM resource_leases \
                 WHERE resource_key = ?1 AND owner_operation = ?2 AND token = ?3 AND generation = ?3 AND expires_at > ?4",
                params![key, &grant.operation_id, fence, &now_str],
                |row| row.get(0),
            )?;
            if count != 1 {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Routes historical RPC methods `Resource.Acquire`, `Resource.Renew`,
    /// `Resource.Release`, and `Resource.IsCurrent`, returning the legacy
    /// `serde_json::Value` payload.
    pub fn dispatch_rpc(
        &self,
        conn: &mut Connection,
        ctx: &dyn RpcContext,
        method: &str,
        payload: Value,
    ) -> Result<Value, LeaseError> {
        match method {
            "Resource.Acquire" => {
                let dto: ResourceAcquireDto = decode_payload(payload)?;
                ctx.require_member(&dto.mission_id)?;
                if dto
                    .resource_keys
                    .iter()
                    .any(|k| k.len() >= 8 && k[..8].eq_ignore_ascii_case("desktop:"))
                    && !ctx.gui_available()?
                {
                    return Err(LeaseError::protocol(
                        "CAPABILITY_UNAVAILABLE",
                        "GUI session locked or companion unavailable.",
                        false,
                    ));
                }
                let ttl = ttl_from_seconds(dto.ttl_seconds)?;
                let bound_op = bind_operation_id(&dto.mission_id, &dto.operation_id)?;
                let grant = self.acquire(conn, &dto.resource_keys, &bound_op, ttl)?;
                serde_json::to_value(grant)
                    .map_err(|e| LeaseError::invalid_argument(e.to_string()))
            }
            "Resource.Renew" => {
                let dto: ResourceControlDto = decode_payload(payload)?;
                ctx.require_member(&dto.mission_id)?;
                require_bound_resource_grant(&dto.mission_id, &dto.grant)?;
                let ttl = ttl_from_seconds(dto.ttl_seconds)?;
                let grant = self.renew(conn, &dto.grant, ttl)?;
                serde_json::to_value(grant)
                    .map_err(|e| LeaseError::invalid_argument(e.to_string()))
            }
            "Resource.Release" => {
                let dto: ResourceControlDto = decode_payload(payload)?;
                ctx.require_member(&dto.mission_id)?;
                require_bound_resource_grant(&dto.mission_id, &dto.grant)?;
                self.release(conn, &dto.grant)?;
                Ok(json!({ "released": true }))
            }
            "Resource.IsCurrent" => {
                let dto: ResourceControlDto = decode_payload(payload)?;
                ctx.require_member(&dto.mission_id)?;
                require_bound_resource_grant(&dto.mission_id, &dto.grant)?;
                let current = self.is_current(conn, &dto.grant)?;
                Ok(json!({ "current": current }))
            }
            _ => Err(LeaseError::protocol(
                "METHOD_NOT_FOUND",
                format!("Unsupported lease RPC method: {method}"),
                false,
            )),
        }
    }
}

fn decode_payload<T: for<'de> Deserialize<'de>>(payload: Value) -> Result<T, LeaseError> {
    serde_json::from_value(payload)
        .map_err(|e| LeaseError::invalid_argument(format!("Invalid RPC payload: {e}")))
}

fn ttl_from_seconds(seconds: i32) -> Result<Duration, LeaseError> {
    if seconds <= 0 {
        return Err(LeaseError::invalid_argument(
            "Lease TTL must be between 100ms and 15 minutes.",
        ));
    }
    let ttl = Duration::from_secs(seconds as u64);
    validate_ttl(ttl)?;
    Ok(ttl)
}

fn validate_ttl(ttl: Duration) -> Result<(), LeaseError> {
    if ttl < MIN_TTL || ttl > MAX_TTL {
        return Err(LeaseError::invalid_argument(
            "Lease TTL must be between 100ms and 15 minutes.",
        ));
    }
    Ok(())
}

fn canonical_keys(values: &[String]) -> Result<Vec<String>, LeaseError> {
    let mut set = BTreeSet::new();
    for raw in values {
        set.insert(normalize_resource_key(raw)?);
    }
    if set.is_empty() || set.len() > MAX_LEASE_KEYS {
        return Err(LeaseError::invalid_argument(
            "Resource lease requires 1-100 distinct keys.",
        ));
    }
    Ok(set.into_iter().collect())
}

fn validate_grant_shape(grant: &ResourceLeaseGrant) -> Result<(), LeaseError> {
    if grant.operation_id.trim().is_empty() || grant.operation_id.len() > MAX_OPERATION_ID_LEN {
        return Err(LeaseError::invalid_argument(
            "Lease grant requires an operation identity.",
        ));
    }
    if grant.keys.is_empty() || grant.keys.len() > MAX_LEASE_KEYS {
        return Err(LeaseError::invalid_argument(
            "Resource lease grant requires 1-100 keys.",
        ));
    }
    let mut seen = BTreeSet::new();
    for key in &grant.keys {
        if !seen.insert(key.as_str()) {
            return Err(LeaseError::invalid_argument(
                "Resource lease grant contains duplicate keys.",
            ));
        }
        if !grant.fences.contains_key(key) {
            return Err(LeaseError::invalid_argument(
                "Resource lease grant is missing a fencing token.",
            ));
        }
    }
    if grant.fences.len() != grant.keys.len() {
        return Err(LeaseError::invalid_argument(
            "Resource lease grant fences do not match keys.",
        ));
    }
    Ok(())
}

fn normalize_file_path(raw: &str) -> Result<String, LeaseError> {
    if raw.is_empty() || raw.contains('\0') || raw.contains('\n') || raw.contains('\r') {
        return Err(LeaseError::invalid_argument("Invalid resource key."));
    }
    let path = Path::new(raw);
    if !path.is_absolute() {
        return Err(LeaseError::invalid_argument(
            "File lease requires absolute path.",
        ));
    }

    let mut out = PathBuf::new();
    let mut normal_depth = 0usize;
    for comp in path.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => out.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if normal_depth > 0 {
                    out.pop();
                    normal_depth -= 1;
                }
            }
            Component::Normal(seg) => {
                out.push(seg);
                normal_depth += 1;
            }
        }
    }

    let normalized = out
        .to_string_lossy()
        .trim_end_matches(std::path::MAIN_SEPARATOR)
        .to_lowercase();
    if normalized.is_empty() || normalized.contains('\n') || normalized.contains('\r') {
        return Err(LeaseError::invalid_argument("Invalid resource key."));
    }
    Ok(normalized)
}
