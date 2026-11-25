//! Explicit provider lifetime, independent of retained MCP handler clones.
//!
//! The shutdown closure MUST close its provider admission before cleanup, and
//! retain every uncertain child/worker in its captured owner on an error. It
//! must be retryable. Neither callback may acquire the live-profile lock:
//! ProfileControl already holds that lock during a downgrade.
//! Revoke allows future reactivation; final shutdown never reopens admission.
//! Before admitting a new generation, the root MUST reconcile_rollbacks().
//! An uncertain last Drop remains in that reachable registry until confirmed.
use crate::runtime::RuntimeError;
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

pub(crate) type Cleanup = Arc<dyn Fn() -> Result<(), RuntimeError> + Send + Sync>;

struct Hooks { revoke: Cleanup, shutdown: Cleanup }
struct State {
    closing: bool,
    hooks: Option<Hooks>,
}

#[derive(Clone, Debug)]
pub(crate) struct RollbackFailure {
    pub(crate) owner_id: u64,
    pub(crate) code: &'static str,
    pub(crate) attempts: u64,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RollbackStatus {
    pub(crate) pending: usize,
    pub(crate) failures: Vec<RollbackFailure>,
    pub(crate) omitted: usize,
}

struct PendingRollback {
    state: Arc<Mutex<State>>,
    failure: RollbackFailure,
}
#[derive(Default)]
struct RollbackRegistry {
    entries: Mutex<BTreeMap<u64, PendingRollback>>,
    next_id: AtomicU64,
}
impl RollbackRegistry {
    fn retain(&self, state: Arc<Mutex<State>>, code: &'static str, attempts: u64) {
        let mut entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut owner_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        // Keep ownership even in the theoretical counter wraparound case.
        while entries.contains_key(&owner_id) {
            owner_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        }
        entries.insert(owner_id, PendingRollback {
            state, failure: RollbackFailure { owner_id, code, attempts },
        });
    }

    fn status(&self) -> Result<RollbackStatus, RuntimeError> {
        let entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let failures: Vec<_> = entries.values().take(32)
            .map(|pending| pending.failure.clone()).collect();
        Ok(RollbackStatus {
            pending: entries.len(),
            omitted: entries.len().saturating_sub(failures.len()),
            failures,
        })
    }

    fn reconcile(&self) -> Result<RollbackStatus, RuntimeError> {
        // Entries remain visible throughout reconciliation. Do not execute a
        // provider callback under this index lock or release its last owner.
        let pending: Vec<_> = {
            let entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            entries.iter().map(|(id, pending)| (*id, Arc::clone(&pending.state))).collect()
        };
        for (id, state) in pending {
            // Reduce errors to stable codes before locking the index, so even
            // provider-owned error destructors run outside its mutex.
            let failure_code = shutdown_shared(&state).err().map(|failure| failure.code());
            let mut entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            match failure_code {
                None => { entries.remove(&id); }
                Some(code) => {
                    if let Some(pending) = entries.get_mut(&id) {
                        pending.failure.code = code;
                        pending.failure.attempts = pending.failure.attempts.saturating_add(1);
                    }
                }
            }
        }
        let status = self.status()?;
        if status.pending == 0 { Ok(status) }
        else { Err(format!("PROVIDER_ROLLBACK_PENDING: {}", status.pending).into()) }
    }
}
fn global_rollbacks() -> &'static Arc<RollbackRegistry> {
    static REGISTRY: OnceLock<Arc<RollbackRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Arc::new(RollbackRegistry::default()))
}

enum ShutdownFailure {
    Failed(RuntimeError),
    Panicked,
}
impl ShutdownFailure {
    fn code(&self) -> &'static str {
        match self { Self::Failed(_) => "cleanup_failed", Self::Panicked => "cleanup_panicked" }
    }
    fn into_error(self) -> RuntimeError {
        match self {
            Self::Failed(error) => error,
            Self::Panicked => "PROVIDER_CLEANUP_PANICKED".into(),
        }
    }
}

pub(crate) struct ProviderOwner {
    state: Arc<Mutex<State>>,
    rollbacks: Arc<RollbackRegistry>,
    final_requested: Arc<AtomicBool>,
    deferred: bool,
}

fn shutdown_state(state: &mut State) -> Result<(), ShutdownFailure> {
    state.closing = true;
    if let Some(hooks) = state.hooks.as_ref() {
        // Catch inside the state guard so a callback panic cannot poison the
        // owner or unwind past the last accessible resource captures.
        match catch_unwind(AssertUnwindSafe(|| (hooks.shutdown)())) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(ShutdownFailure::Failed(error)),
            Err(_) => return Err(ShutdownFailure::Panicked),
        }
    }
    state.hooks.take();
    Ok(())
}
fn shutdown_shared(shared: &Arc<Mutex<State>>) -> Result<(), ShutdownFailure> {
    // A panic in a revoke callback may have poisoned the state. Final cleanup
    // can recover it safely because this path only closes admission.
    let mut state = shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    shutdown_state(&mut state)
}

impl ProviderOwner {
    pub(crate) fn new(revoke: Cleanup, shutdown: Cleanup) -> Self {
        Self::with_registry(revoke, shutdown, Arc::clone(global_rollbacks()))
    }

    fn with_registry(revoke: Cleanup, shutdown: Cleanup, rollbacks: Arc<RollbackRegistry>) -> Self {
        Self { state: Arc::new(Mutex::new(State {
            closing: false, hooks: Some(Hooks { revoke, shutdown }),
        })), rollbacks, final_requested: Arc::new(AtomicBool::new(false)), deferred: false }
    }

    /// Transfer to the reachable rollback registry without invoking either hook.
    /// The caller closes its outer admission before scheduling this final drain.
    pub(crate) fn defer(mut self) {
        self.final_requested.store(true, Ordering::Release);
        self.rollbacks.retain(Arc::clone(&self.state), "cleanup_pending", 0);
        self.deferred = true;
    }

    pub(crate) fn rollback_status() -> Result<RollbackStatus, RuntimeError> {
        global_rollbacks().status()
    }

    pub(crate) fn reconcile_rollbacks() -> Result<RollbackStatus, RuntimeError> {
        global_rollbacks().reconcile()
    }

    pub(crate) fn revoker(&self) -> Cleanup {
        let shared = Arc::clone(&self.state);
        let final_requested = Arc::clone(&self.final_requested);
        Arc::new(move || {
            let mut state = shared.lock().map_err(|_| "PROVIDER_OWNER_POISONED")?;
            if state.closing || final_requested.load(Ordering::Acquire) {
                return shutdown_state(&mut state).map_err(ShutdownFailure::into_error);
            }
            if let Some(hooks) = &state.hooks { (hooks.revoke)()?; }
            Ok(())
        })
    }

    pub(crate) fn shutdown(&mut self) -> Result<(), RuntimeError> {
        self.final_requested.store(true, Ordering::Release);
        shutdown_shared(&self.state).map_err(ShutdownFailure::into_error)
    }
}

impl Drop for ProviderOwner {
    fn drop(&mut self) {
        if self.deferred { return; }
        self.final_requested.store(true, Ordering::Release);
        if let Err(failure) = shutdown_shared(&self.state) {
            // No eviction: a new generation is forbidden until reconciliation
            // confirms every rollback. Only diagnostics are capped, not owners.
            self.rollbacks.retain(Arc::clone(&self.state), failure.code(), 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[test]
    fn failed_final_cleanup_keeps_owner_and_retries_without_reopening_admission() {
        struct Resource(Arc<AtomicBool>);
        impl Drop for Resource {
            fn drop(&mut self) { self.0.store(true, Ordering::SeqCst); }
        }
        let released = Arc::new(AtomicBool::new(false));
        let resource = Resource(Arc::clone(&released));
        let accepting = Arc::new(AtomicBool::new(true));
        let attempts = Arc::new(AtomicUsize::new(0));
        let gate = Arc::clone(&accepting);
        let calls = Arc::clone(&attempts);
        let shutdown: Cleanup = Arc::new(move || {
            let _keep_owned = &resource;
            gate.store(false, Ordering::SeqCst);
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Err("fixture: owned cleanup unconfirmed".into())
            } else { Ok(()) }
        });
        let mut owner = ProviderOwner::new(Arc::new(|| Ok(())), shutdown);
        assert!(owner.shutdown().is_err(), "unconfirmed cleanup cannot be reported clean");
        assert!(!accepting.load(Ordering::SeqCst));
        assert!(!released.load(Ordering::SeqCst), "failed cleanup lost its resource owner");
        owner.shutdown().unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert!(released.load(Ordering::SeqCst), "successful final cleanup must release captured owners");
        owner.shutdown().unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn last_owner_drop_keeps_failed_cleanup_accessible_until_reconciled() {
        struct Resource(Arc<AtomicBool>);
        impl Drop for Resource {
            fn drop(&mut self) { self.0.store(true, Ordering::SeqCst); }
        }
        let registry = Arc::new(RollbackRegistry::default());
        let released = Arc::new(AtomicBool::new(false));
        let resource = Resource(Arc::clone(&released));
        let allow_cleanup = Arc::new(AtomicBool::new(false));
        let allow = Arc::clone(&allow_cleanup);
        let calls = Arc::new(AtomicUsize::new(0));
        let attempts = Arc::clone(&calls);
        let mutex_held = Arc::new(AtomicBool::new(false));
        let callback_mutex_held = Arc::clone(&mutex_held);
        let observed_registry = Arc::downgrade(&registry);
        let owner = ProviderOwner::with_registry(
            Arc::new(|| Ok(())),
            Arc::new(move || {
                let _keep_owned = &resource;
                let registry = observed_registry.upgrade().unwrap();
                if registry.entries.try_lock().is_err() {
                    callback_mutex_held.store(true, Ordering::SeqCst);
                }
                attempts.fetch_add(1, Ordering::SeqCst);
                if allow.load(Ordering::SeqCst) { Ok(()) }
                else { Err("fixture-private-diagnostic-never-publish".into()) }
            }),
            Arc::clone(&registry),
        );
        // No revoker or ProviderOwner survives this point.
        drop(owner);
        assert!(!released.load(Ordering::SeqCst), "uncertain resources must remain owned");
        let status = registry.status().unwrap();
        assert_eq!(status.pending, 1, "last Drop must publish a reachable cleanup owner");
        assert_eq!(status.failures.len(), 1);
        assert_eq!(status.failures[0].code, "cleanup_failed");
        assert_eq!(status.failures[0].attempts, 1);
        assert!(!format!("{status:?}").contains("fixture-private-diagnostic"));
        assert!(registry.reconcile().is_err(), "uncertain cleanup must block new admission");
        let retried = registry.status().unwrap();
        assert_eq!(retried.pending, 1, "a failed retry must never evict its resource owner");
        assert_eq!(retried.failures[0].owner_id, status.failures[0].owner_id);
        assert_eq!(retried.failures[0].attempts, 2);
        assert!(!released.load(Ordering::SeqCst));
        allow_cleanup.store(true, Ordering::SeqCst);
        assert_eq!(registry.reconcile().unwrap().pending, 0);
        assert!(released.load(Ordering::SeqCst));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert!(!mutex_held.load(Ordering::SeqCst), "cleanup ran while holding registry mutex");
        assert_eq!(registry.reconcile().unwrap().pending, 0);
        assert_eq!(calls.load(Ordering::SeqCst), 3, "successful cleanup is not repeated");
    }

    #[test]
    fn panicked_cleanup_stays_reachable_for_a_later_reconciliation() {
        let registry = Arc::new(RollbackRegistry::default());
        let permit = Arc::new(AtomicBool::new(false));
        let allowed = Arc::clone(&permit);
        let resource = Arc::new(());
        let reachable = Arc::downgrade(&resource);
        let owner = ProviderOwner::with_registry(
            Arc::new(|| Ok(())),
            Arc::new(move || {
                let _keep_owned = &resource;
                assert!(allowed.load(Ordering::SeqCst), "fixture cleanup panic");
                Ok(())
            }),
            Arc::clone(&registry),
        );
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(owner))).is_ok(),
            "Drop must retain uncertain cleanup even when its callback panics");
        assert!(reachable.upgrade().is_some());
        let status = registry.status().unwrap();
        assert_eq!(status.pending, 1);
        assert_eq!(status.failures[0].code, "cleanup_panicked");
        permit.store(true, Ordering::SeqCst);
        assert_eq!(registry.reconcile().unwrap().pending, 0);
        assert!(reachable.upgrade().is_none());
    }

    #[test]
    fn deferred_owner_transfers_without_cleanup_and_remains_final_and_reconcilable() {
        let registry = Arc::new(RollbackRegistry::default());
        let permit = Arc::new(AtomicBool::new(false));
        let allowed = Arc::clone(&permit);
        let calls = Arc::new(AtomicUsize::new(0));
        let attempts = Arc::clone(&calls);
        let revoked = Arc::new(AtomicUsize::new(0));
        let revoke_calls = Arc::clone(&revoked);
        let resource = Arc::new(());
        let reachable = Arc::downgrade(&resource);
        let owner = ProviderOwner::with_registry(
            Arc::new(move || { revoke_calls.fetch_add(1, Ordering::SeqCst); Ok(()) }),
            Arc::new(move || {
                let _keep_owned = &resource;
                attempts.fetch_add(1, Ordering::SeqCst);
                if allowed.load(Ordering::SeqCst) { Ok(()) } else { Err("cleanup not ready".into()) }
            }), Arc::clone(&registry),
        );
        let stale_revoker = owner.revoker();
        owner.defer();
        assert_eq!(calls.load(Ordering::SeqCst), 0, "defer must never call cleanup on the transferring thread");
        assert!(reachable.upgrade().is_some());
        let status = registry.status().unwrap();
        assert_eq!(status.pending, 1);
        assert_eq!(status.failures[0].code, "cleanup_pending");
        assert_eq!(status.failures[0].attempts, 0);
        assert!(stale_revoker().is_err());
        assert_eq!(revoked.load(Ordering::SeqCst), 0, "a deferred owner cannot return to revocable admission");
        drop(stale_revoker);
        assert!(registry.reconcile().is_err());
        assert_eq!(registry.status().unwrap().pending, 1);
        assert!(reachable.upgrade().is_some());
        permit.store(true, Ordering::SeqCst);
        assert_eq!(registry.reconcile().unwrap().pending, 0);
        assert!(reachable.upgrade().is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn bounded_diagnostics_do_not_evict_uncertain_cleanup_owners() {
        struct Resource(Arc<AtomicUsize>);
        impl Drop for Resource {
            fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
        }
        let registry = Arc::new(RollbackRegistry::default());
        let allow = Arc::new(AtomicBool::new(false));
        let released = Arc::new(AtomicUsize::new(0));
        for _ in 0..34 {
            let permit = Arc::clone(&allow);
            let resource = Resource(Arc::clone(&released));
            let owner = ProviderOwner::with_registry(
                Arc::new(|| Ok(())),
                Arc::new(move || {
                    let _keep_owned = &resource;
                    if permit.load(Ordering::SeqCst) { Ok(()) }
                    else { Err("cleanup-unconfirmed".into()) }
                }),
                Arc::clone(&registry),
            );
            drop(owner);
        }
        let status = registry.status().unwrap();
        assert_eq!(status.pending, 34);
        assert_eq!(status.failures.len(), 32);
        assert_eq!(status.omitted, 2);
        assert_eq!(released.load(Ordering::SeqCst), 0);
        assert!(registry.reconcile().is_err());
        assert_eq!(registry.status().unwrap().pending, 34);
        assert_eq!(released.load(Ordering::SeqCst), 0);
        allow.store(true, Ordering::SeqCst);
        let complete = registry.reconcile().unwrap();
        assert_eq!(complete.pending, 0);
        assert!(complete.failures.is_empty());
        assert_eq!(complete.omitted, 0);
        assert_eq!(released.load(Ordering::SeqCst), 34);
    }

    #[test]
    fn profile_revocation_preserves_reactivation_but_stale_revoker_cannot_revoke_after_shutdown() {
        let revoked = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicBool::new(false));
        let count = Arc::clone(&revoked);
        let gate = Arc::clone(&closed);
        let mut owner = ProviderOwner::new(
            Arc::new(move || { count.fetch_add(1, Ordering::SeqCst); Ok(()) }),
            Arc::new(move || { gate.store(true, Ordering::SeqCst); Ok(()) }),
        );
        let revoker = owner.revoker();
        revoker().unwrap();
        revoker().unwrap();
        assert_eq!(revoked.load(Ordering::SeqCst), 2);
        assert!(!closed.load(Ordering::SeqCst));
        owner.shutdown().unwrap();
        assert!(closed.load(Ordering::SeqCst));
        revoker().unwrap();
        assert_eq!(revoked.load(Ordering::SeqCst), 2);
    }
}
