//! Validated atomic reload, live revocation, and bounded audit log.
//!
//! Keeps an `Arc<Registry>` active under an atomic swap boundary, tracks
//! in-flight tool calls per server with cooperative cancellation tokens, and
//! closes pooled idle sessions whenever servers are removed, disabled, or
//! reconfigured.

use crate::pool::SessionPool;
use crate::status::StatusTracker;
use crate::transport::CancellationToken;
use crate::{error, Registry, Result, ToolScope};
use crate::result_cache::{CacheCaller, CacheRequest, ResultCache};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_RELOAD_AUDIT: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReloadMode {
    /// Rejects new enabled servers, newly enabled disabled servers, new tools,
    /// transport/pin/credential changes, or widened parameter contracts.
    StrictNoWidening,
    /// Accepts any valid registry already filtered through local operator
    /// journal approvals and pin checks.
    OperatorApproved,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReloadAuditRecord {
    pub timestamp_unix_ms: u64,
    pub generation: u64,
    pub ok: bool,
    pub reason_code: &'static str,
    pub server_count: usize,
    pub removed_or_disabled: usize,
    pub changed: usize,
    pub closed_idle_sessions: usize,
    pub cancelled_in_flight: usize,
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

struct TrackedCall {
    server: String,
    cancel: CancellationToken,
    revoked: bool,
}

#[derive(Default)]
struct InFlightState {
    next_id: u64,
    calls: BTreeMap<u64, TrackedCall>,
}

/// Tracks active upstream extension calls so live revocation can cancel them.
#[derive(Default)]
pub struct InFlightTracker {
    state: Mutex<InFlightState>,
}

pub struct InFlightGuard {
    tracker: Arc<InFlightTracker>,
    id: Option<u64>,
}

impl InFlightGuard {
    fn unregister(&mut self) -> Option<TrackedCall> {
        let id = self.id.take()?;
        let mut state = self.tracker.state.lock().unwrap_or_else(|p| p.into_inner());
        state.calls.remove(&id)
    }

    // Revocation marks the same entry under the same lock. Once removed
    // here, the result has been committed to the local dispatcher.
    fn finish(mut self, result: Result<Value>) -> Result<Value> {
        if self.unregister().is_some_and(|call| !call.revoked && !call.cancel.is_cancelled()) {
            result
        } else {
            Err(error("Extension call cancelled due to revocation; outcome may be uncertain; do not replay"))
        }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.unregister();
    }
}

impl InFlightTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn register(self: &Arc<Self>, server: &str) -> (InFlightGuard, CancellationToken) {
        let token = CancellationToken::new();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.next_id = state.next_id.saturating_add(1);
        let id = state.next_id;
        state.calls.insert(id, TrackedCall {
            server: server.to_owned(), cancel: token.clone(), revoked: false,
        });
        (
            InFlightGuard {
                tracker: Arc::clone(self),
                id: Some(id),
            },
            token,
        )
    }

    pub fn cancel_servers(&self, servers: &BTreeSet<String>) -> usize {
        self.cancel_matching(|server| servers.contains(server))
    }

    pub fn cancel_all(&self) -> usize {
        self.cancel_matching(|_| true)
    }

    fn cancel_matching(&self, selected: impl Fn(&str) -> bool) -> usize {
        let tokens = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            let mut tokens = Vec::new();
            for call in state.calls.values_mut() {
                if !call.revoked && !call.cancel.is_cancelled() && selected(&call.server) {
                    call.revoked = true;
                    tokens.push(call.cancel.clone());
                }
            }
            tokens
        };
        // Wake transports after releasing the tracker mutex.
        let count = tokens.len();
        for token in tokens {
            token.cancel();
        }
        count
    }

    pub fn active_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .calls
            .len()
    }
}

/// A candidate qualified against one exact live generation.
pub struct PreparedReload {
    origin: Arc<InFlightTracker>,
    generation: u64,
    next: Registry,
}

/// Single-use admitted call with a server-specific revocation token.
pub struct AdmittedCall {
    registry: Arc<Registry>,
    qualified: String,
    scope: ToolScope,
    guard: InFlightGuard,
    cancel: CancellationToken,
    cache: Option<CacheRequest>,
}

impl AdmittedCall {
    pub fn execute(self, args: &Map<String, Value>) -> Result<Value> {
        let result = self.registry.call_managed(
            &self.qualified, args, self.scope, &self.cancel, self.cache.as_ref(),
        );
        self.guard.finish(result)
    }
}

/// Single-use admitted connection probe with a server-specific revocation token.
pub struct AdmittedProbe {
    registry: Arc<Registry>,
    server: String,
    generation: u64,
    guard: InFlightGuard,
    cancel: CancellationToken,
}

impl AdmittedProbe {
    pub fn execute(self) -> Result<Value> {
        let result = self.registry.test_connection_managed(&self.server, &self.cancel, self.generation);
        self.guard.finish(result)
    }
}

fn sync_registry_status(status: &StatusTracker, registry: &Registry) -> Result<()> {
    let mut configured = BTreeSet::new();
    let mut enabled_fingerprints = BTreeMap::new();
    for name in registry.server_names() {
        configured.insert(name.clone());
        if registry.is_server_enabled(&name) {
            if let Some(sha) = registry.server_sha256(&name)? {
                enabled_fingerprints.insert(name, sha);
            }
        }
    }
    status.sync_authority(&enabled_fingerprints, &configured);
    Ok(())
}

/// Process-local atomic container holding the active validated `Registry`.
pub struct LiveExtensionRegistry {
    active: RwLock<Arc<Registry>>,
    generation: AtomicU64,
    pool: Arc<SessionPool>,
    status: Arc<StatusTracker>,
    in_flight: Arc<InFlightTracker>,
    audit: Mutex<VecDeque<ReloadAuditRecord>>,
    cache: Arc<ResultCache>,
}

impl LiveExtensionRegistry {
    pub fn new(
        initial: Registry,
        pool: Arc<SessionPool>,
        status: Arc<StatusTracker>,
    ) -> Arc<Self> {
        let bound = initial
            .with_session_pool(pool.clone())
            .with_status_tracker(status.clone());
        let _ = sync_registry_status(&status, &bound);
        Arc::new(Self {
            active: RwLock::new(Arc::new(bound)),
            generation: AtomicU64::new(1),
            pool,
            status,
            in_flight: InFlightTracker::new(),
            audit: Mutex::default(),
            cache: Arc::default(),
        })
    }

    /// Trusted authenticated host only. This early observation is not a
    /// grant: it must be claimed under the ordinary admission gate.
    pub fn cache_request(&self,token_hash:[u8;32],profile:u8)->Option<CacheRequest>{
        self.cache.request(CacheCaller::authenticated(token_hash,profile)?)
    }
    pub fn invalidate_results(&self){self.cache.invalidate();}

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn current(&self) -> Arc<Registry> {
        Arc::clone(
            &self
                .active
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }

    pub fn pool(&self) -> &Arc<SessionPool> {
        &self.pool
    }

    pub fn status(&self) -> &Arc<StatusTracker> {
        &self.status
    }

    pub fn in_flight(&self) -> &Arc<InFlightTracker> {
        &self.in_flight
    }

    pub fn audit_snapshot(&self) -> Value {
        let guard = self
            .audit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let records: Vec<&ReloadAuditRecord> = guard.iter().collect();
        json!({
            "generation": self.generation(),
            "in_flight": self.in_flight.active_count(),
            "max_records": MAX_RELOAD_AUDIT,
            "records": records,
        })
    }

    fn record_audit(&self, record: ReloadAuditRecord) -> ReloadAuditRecord {
        let mut guard = self
            .audit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.len() == MAX_RELOAD_AUDIT {
            guard.pop_front();
        }
        guard.push_back(record.clone());
        record
    }

    /// Prepare slow pin/catalogue validation without excluding admissions
    /// or revocations. Publication is a separate generation CAS.
    pub fn prepare_reload(&self, candidate: Result<Registry>, mode: ReloadMode) -> Result<PreparedReload> {
        let (previous, generation) = {
            let active = self.active.read().unwrap_or_else(|p| p.into_inner());
            (Arc::clone(&active), self.generation())
        };
        let result = (|| {
            let next = candidate?;
            if mode == ReloadMode::StrictNoWidening && crate::authority_widens(&previous, &next)? {
                return Err(error("Extension reload refused: authority cannot widen without operator approval"));
            }
            next.validate_replacement(Some(&previous))?;
            Ok(PreparedReload { origin: Arc::clone(&self.in_flight), generation, next })
        })();
        if let Err(ref err) = result { self.record_failure(err); }
        result
    }

    /// Commit only the exact prepared generation. The caller may recheck
    /// its private approval journal between preparation and this CAS.
    pub fn commit_reload(&self, prepared: PreparedReload) -> Result<ReloadAuditRecord> {
        let mut active = self.active.write().unwrap_or_else(|p| p.into_inner());
        if !Arc::ptr_eq(&self.in_flight, &prepared.origin) || self.generation() != prepared.generation {
            let err = error("Extension registry changed during reload; retry explicitly");
            self.failure_locked(&active, &err);
            return Err(err);
        }
        self.replace_locked(&mut active, prepared.next)
    }

    pub fn reload(&self, candidate: Result<Registry>, mode: ReloadMode) -> Result<ReloadAuditRecord> {
        self.commit_reload(self.prepare_reload(candidate, mode)?)
    }

    /// Revocations are not a connection probe. Apply only restrictions of
    /// the current approved configuration; new grants need a validated swap.
    pub fn restrict_to(&self, effective: &Registry) -> Result<Option<ReloadAuditRecord>> {
        let mut active = self.active.write().unwrap_or_else(|p| p.into_inner());
        let next = active.restricted_to(effective)?;
        if active.matches_fingerprints(&next)? { return Ok(None); }
        self.replace_locked(&mut active, next).map(Some)
    }

    pub fn record_failure(&self, err: &std::io::Error) {
        let active = self.active.read().unwrap_or_else(|p| p.into_inner());
        self.failure_locked(&active, err);
    }

    fn failure_locked(&self, active: &Registry, err: &std::io::Error) {
        self.record_audit(ReloadAuditRecord {
            timestamp_unix_ms: now_unix_ms(),
            generation: self.generation(),
            ok: false,
            reason_code: classify_reload_error(err),
            server_count: active.server_names().len(),
            removed_or_disabled: 0,
            changed: 0,
            closed_idle_sessions: 0,
            cancelled_in_flight: 0,
        });
    }

    // The active write lock excludes admission until every affected old
    // token has been cancelled and every old idle entry removed. The pool
    // checks cancellation under its own lock on checkout and return.
    fn replace_locked(&self, active: &mut Arc<Registry>, next: Registry) -> Result<ReloadAuditRecord> {
        let next = next.with_session_pool(self.pool.clone()).with_status_tracker(self.status.clone());
        let next_keys = next.session_keys()?;
        let diff = diff_registries(active, &next)?;
        let new_gen = self.generation().checked_add(1)
            .ok_or_else(|| error("Extension generation exhausted"))?;
        // Fence even unchanged servers and previous in-flight cache admissions.
        self.cache.invalidate();
        let cancelled_in_flight = self.in_flight.cancel_servers(&diff.affected);
        let closed_idle_sessions = self.pool.retain(&next_keys)
            + self.pool.close_servers(&diff.affected);
        let server_count = next.server_names().len();
        sync_registry_status(&self.status, &next)?;
        *active = Arc::new(next);
        self.generation.store(new_gen, Ordering::Release);
        Ok(self.record_audit(ReloadAuditRecord {
            timestamp_unix_ms: now_unix_ms(),
            generation: new_gen,
            ok: true,
            reason_code: "reloaded",
            server_count,
            removed_or_disabled: diff.removed_or_disabled,
            changed: diff.changed,
            closed_idle_sessions,
            cancelled_in_flight,
        }))
    }

    /// Immediately revokes an active server without a stale read/modify/write.
    pub fn revoke_server(&self, server_name: &str) -> Result<ReloadAuditRecord> {
        let mut active = self.active.write().unwrap_or_else(|p| p.into_inner());
        if !active.has_server(server_name) { return Err(error("Unknown extension server")); }
        let next = active.with_server_disabled(server_name);
        self.replace_locked(&mut active, next)
    }

    /// Exclude admission while cancelling the entire current pool, e.g.
    /// when the profile is lowered or the private authority is unavailable.
    pub fn cancel_all(&self) {
        let _active = self.active.write().unwrap_or_else(|p| p.into_inner());
        self.cache.invalidate();
        self.in_flight.cancel_all();
        self.pool.close_all();
    }

    /// The returned receipt owns exactly one admission. Run it only after
    /// releasing the caller's profile/journal locks. It cannot select another
    /// tool or profile, and dropping it removes the in-flight registration.
    pub fn admit(
        &self,
        qualified: &str,
        scope: ToolScope,
        authorize: impl FnOnce(&Registry) -> Result<()>,
    ) -> Result<AdmittedCall> {
        self.admit_with_cache(qualified,scope,None,0,authorize)
    }

    pub fn admit_with_cache(
        &self, qualified:&str, scope:ToolScope, request:Option<&CacheRequest>, profile:u8,
        authorize:impl FnOnce(&Registry)->Result<()>,
    )->Result<AdmittedCall>{
        let (server_id, _) = qualified.split_once(':')
            .ok_or_else(|| error("An exact qualified tool name is required"))?;
        let active = self.active.read().unwrap_or_else(|p| p.into_inner());
        authorize(&active)?;
        if !active.is_server_enabled(server_id) {
            return Err(error("Extension unavailable or disabled by the operator"));
        }
        let (guard, cancel) = self.in_flight.register(server_id);
        let cache=request.and_then(|request|request.claim(&self.cache,profile));
        Ok(AdmittedCall {
            registry: Arc::clone(&active), qualified: qualified.to_owned(), scope, guard, cancel,cache,
        })
    }

    pub fn call(&self, qualified: &str, args: &Map<String, Value>, scope: ToolScope) -> Result<Value> {
        self.admit(qualified, scope, |_| Ok(()))?.execute(args)
    }

    /// Admits a single read-only connection probe bound to the live generation
    /// and protected by in-flight cancellation on revocation/reload.
    pub fn admit_probe(&self, server: &str) -> Result<AdmittedProbe> {
        let active = self.active.read().unwrap_or_else(|p| p.into_inner());
        if !active.has_server(server) {
            return Err(error("Extension server is not configured"));
        }
        if !active.is_server_enabled(server) {
            return Err(error("Extension disabled by the operator"));
        }
        let generation = self.generation();
        let (guard, cancel) = self.in_flight.register(server);
        Ok(AdmittedProbe {
            registry: Arc::clone(&active),
            server: server.to_owned(),
            generation,
            guard,
            cancel,
        })
    }

    pub fn test_connection(&self, server: &str) -> Result<Value> {
        self.admit_probe(server)?.execute()
    }
}

struct RegistryDiff {
    affected: BTreeSet<String>,
    removed_or_disabled: usize,
    changed: usize,
}

fn diff_registries(old: &Registry, new: &Registry) -> Result<RegistryDiff> {
    let mut affected = BTreeSet::new();
    let mut removed_or_disabled = 0usize;
    let mut changed = 0usize;
    for name in old.server_names() {
        let old_enabled = old.is_server_enabled(&name);
        let new_enabled = new.is_server_enabled(&name);
        if old_enabled && !new_enabled {
            affected.insert(name);
            removed_or_disabled += 1;
        } else if old.server_sha256(&name)? != new.server_sha256(&name)? {
            affected.insert(name);
            changed += 1;
        }
    }
    Ok(RegistryDiff {
        affected,
        removed_or_disabled,
        changed,
    })
}

fn classify_reload_error(err: &std::io::Error) -> &'static str {
    let msg = err.to_string();
    if msg.contains("widening") || msg.contains("widen") {
        "authority_widening_refused"
    } else if msg.contains("pin") || msg.contains("executable") || msg.contains("descriptor") {
        "pin_validation_failed"
    } else if msg.contains("exceeds limit") || msg.contains("Unsupported extension") {
        "schema_limit_refused"
    } else {
        "invalid_config_refused"
    }
}

#[cfg(test)]
mod result_release_tests {
    use super::*;

    #[test]
    fn revocation_and_result_commit_are_ordered_per_server() {
        let tracker = InFlightTracker::new();
        let (early, _) = tracker.register("clock");
        let (pending, _) = tracker.register("clock");
        let (other, _) = tracker.register("notes");
        assert_eq!(early.finish(Ok(Value::from(1))).unwrap(), Value::from(1));

        let affected = BTreeSet::from([String::from("clock")]);
        assert_eq!(tracker.cancel_servers(&affected), 1);
        assert_eq!(tracker.active_count(), 2);
        assert!(pending.finish(Ok(Value::from(2))).is_err());
        assert_eq!(other.finish(Ok(Value::from(3))).unwrap(), Value::from(3));
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn stopping_all_discards_pending_results_and_conserves_original_errors() {
        let tracker = InFlightTracker::new();
        let (ordinary, _) = tracker.register("clock");
        assert_eq!(ordinary.finish(Err(error("fixture error"))).unwrap_err().to_string(), "fixture error");
        let (pending, _) = tracker.register("clock");
        assert_eq!(tracker.cancel_all(), 1);
        assert_eq!(tracker.cancel_all(), 0);
        assert!(pending.finish(Ok(Value::Null)).unwrap_err().to_string().contains("cancelled due to revocation"));
        assert_eq!(tracker.active_count(), 0);
    }
}
