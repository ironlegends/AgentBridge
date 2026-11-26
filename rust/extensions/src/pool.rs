//! Reuse of extension sessions between tool calls, with idle shutdown.
//!
//! A session is reused only for the same server name and the same server
//! fingerprint, so any registry edit, grant change or new pin opens a new
//! session. A session leaves the pool for the whole call and returns only
//! after a confirmed reply; any transport failure drops it. One reaper
//! thread runs only while the pool holds a session and closes each session
//! idle longer than the bound. Dropping the pool closes every session.

use crate::transport::Session;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

/// Every live pool of this process. The four stdio slots are shared, so a
/// new session of any caller may close an idle child of any pool.
static POOLS: Mutex<Vec<Weak<SessionPool>>> = Mutex::new(Vec::new());

/// Closes the longest idle stdio session of one live pool, if any. No pool
/// is held while the session closes, so its owner still drops it alone.
pub(crate) fn evict_idle_stdio() -> bool {
    let pools: Vec<Weak<SessionPool>> = {
        let mut pools = POOLS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        pools.retain(|pool| pool.strong_count() > 0);
        pools.clone()
    };
    for pool in pools {
        let evicted = pool.upgrade().and_then(|pool| pool.take_oldest_stdio());
        if let Some(evicted) = evicted {
            drop(evicted);
            return true;
        }
    }
    false
}

/// Closes sessions one by one; a failing close does not stop the others.
fn close_each(closed: &Mutex<Vec<Pooled>>) {
    let entries = std::mem::take(&mut *closed.lock().unwrap_or_else(|poisoned| poisoned.into_inner()));
    for entry in entries {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(entry)));
    }
}

/// Default idle bound before a pooled session and its child are closed.
pub const DEFAULT_IDLE: Duration = Duration::from_secs(120);

struct Pooled {
    key: String,
    stdio: bool,
    session: Session,
    since: Instant,
}

#[derive(Default)]
struct State {
    entries: Vec<Pooled>,
    reaper: bool,
}

/// Process-local reusable sessions. Attach one to a [`crate::Registry`] with
/// `with_session_pool`; a registry without a pool opens one session per call.
pub struct SessionPool {
    state: Mutex<State>,
    idle: Duration,
}

impl SessionPool {
    pub fn new() -> Arc<Self> { Self::with_idle(DEFAULT_IDLE) }

    /// A pool with another idle bound, at least one second.
    pub fn with_idle(idle: Duration) -> Arc<Self> {
        let pool = Arc::new(Self { state: Mutex::default(), idle: idle.max(Duration::from_secs(1)) });
        let mut pools = POOLS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        pools.retain(|pool| pool.strong_count() > 0);
        pools.push(Arc::downgrade(&pool));
        pool
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Number of idle sessions held now.
    pub fn idle_sessions(&self) -> usize { self.state().entries.len() }

    /// Closes every idle session now. Closing waits outside the lock.
    pub fn close_all(&self) {
        let closed = Mutex::new(std::mem::take(&mut self.state().entries));
        if closed.lock().map_or(true, |entries| entries.is_empty()) { return; }
        // A session closes by blocking on its own runtime, which cannot
        // start on an async worker thread. A plain scoped thread always can;
        // without one, the sessions close here.
        std::thread::scope(|scope| {
            let _ = std::thread::Builder::new().name("extension-session-close".into())
                .spawn_scoped(scope, || close_each(&closed));
        });
        close_each(&closed);
    }

    /// Takes the idle session for `key`, if it has not expired.
    pub(crate) fn take(&self, key: &str) -> Option<Session> {
        let (found, expired) = {
            let mut state = self.state();
            let expired = self.expire(&mut state);
            let found = state.entries.iter().position(|entry| entry.key == key)
                .map(|index| state.entries.swap_remove(index).session);
            (found, expired)
        };
        drop(expired);
        found
    }

    /// Returns a healthy session after a confirmed reply. A second idle
    /// session for the same key is closed instead of kept.
    pub(crate) fn put(self: &Arc<Self>, key: String, stdio: bool, session: Session) {
        let spare = {
            let mut state = self.state();
            if state.entries.iter().any(|entry| entry.key == key) {
                Some(session)
            } else {
                state.entries.push(Pooled { key, stdio, session, since: Instant::now() });
                if !state.reaper {
                    state.reaper = true;
                    let pool = Arc::downgrade(self);
                    let idle = self.idle;
                    if std::thread::Builder::new().name("extension-session-reaper".into())
                        .spawn(move || reap(pool, idle)).is_err() {
                        // Without a reaper nothing may stay idle.
                        state.reaper = false;
                        let closed = std::mem::take(&mut state.entries);
                        drop(state);
                        drop(closed);
                        return;
                    }
                }
                None
            }
        };
        drop(spare);
    }

    /// Closes idle sessions whose server was removed, disabled or changed.
    pub(crate) fn retain(&self, current: &BTreeSet<String>) {
        let closed: Vec<Pooled> = {
            let mut state = self.state();
            let (keep, closed) = std::mem::take(&mut state.entries).into_iter()
                .partition(|entry| current.contains(&entry.key));
            state.entries = keep;
            closed
        };
        drop(closed);
    }

    /// Removes the longest idle stdio session, which frees its slot once dropped.
    fn take_oldest_stdio(&self) -> Option<Pooled> {
        let mut state = self.state();
        let oldest = state.entries.iter().enumerate().filter(|(_, entry)| entry.stdio)
            .min_by_key(|(_, entry)| entry.since).map(|(index, _)| index);
        oldest.map(|index| state.entries.swap_remove(index))
    }

    fn expire(&self, state: &mut State) -> Vec<Pooled> {
        let now = Instant::now();
        let (keep, expired) = std::mem::take(&mut state.entries).into_iter()
            .partition(|entry| now.duration_since(entry.since) < self.idle);
        state.entries = keep;
        expired
    }
}

impl Drop for SessionPool {
    fn drop(&mut self) { self.close_all(); }
}

/// Wakes at the next expiry, closes expired sessions outside the lock and
/// exits once the pool is empty or gone.
fn reap(pool: Weak<SessionPool>, idle: Duration) {
    let mut wait = idle;
    loop {
        std::thread::sleep(wait);
        let Some(owner) = pool.upgrade() else { return };
        let (expired, next) = {
            let mut state = owner.state();
            let expired = owner.expire(&mut state);
            let next = state.entries.iter().map(|entry| entry.since).min();
            if next.is_none() { state.reaper = false; }
            (expired, next)
        };
        // Closing can take seconds: the pool must not outlive its owner
        // meanwhile, and a panic must not leave pooled sessions unreaped.
        drop(owner);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(expired)));
        let Some(oldest) = next else { return };
        wait = idle.saturating_sub(oldest.elapsed()).max(Duration::from_millis(50));
    }
}
