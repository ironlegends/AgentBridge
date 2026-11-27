//! Bounded, redacted upstream execution status tracking for MCP extensions.
//!
//! Tracks per-server lifecycle state (`idle`, `starting`, `ready`, `slow`,
//! `error`), static error class and timestamp, recent bounded latencies, and
//! session pool summary. Never stores arguments, outputs, tokens, or
//! environment values.

use crate::pool::{PoolSummary, SessionPool};
use crate::transport::CancellationToken;
use crate::Registry;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const MAX_TRACKED_SERVERS: usize = 64;
pub const MAX_LATENCY_SAMPLES: usize = 16;
pub const DEFAULT_SLOW_THRESHOLD_MS: u64 = 2_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamState {
    Idle,
    Starting,
    Ready,
    Slow,
    Error,
    Disabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Ready,
    Error,
}

#[derive(Debug, Default)]
struct ServerEntry {
    in_flight: usize,
    last_outcome: Option<Outcome>,
    last_error_class: Option<&'static str>,
    last_error_unix_ms: Option<u64>,
    last_ready_unix_ms: Option<u64>,
    last_latency_ms: Option<u64>,
    recent_latencies_ms: VecDeque<u64>,
    authority_key: Option<String>,
    authority_epoch: u64,
    touch_seq: u64,
}

impl ServerEntry {
    fn state(&self, slow_threshold_ms: u64) -> UpstreamState {
        if self.in_flight > 0 {
            return UpstreamState::Starting;
        }
        match self.last_outcome {
            None => UpstreamState::Idle,
            Some(Outcome::Error) => UpstreamState::Error,
            Some(Outcome::Ready) => {
                if self.last_latency_ms.is_some_and(|ms| ms >= slow_threshold_ms) {
                    UpstreamState::Slow
                } else {
                    UpstreamState::Ready
                }
            }
        }
    }

    fn record_latency(&mut self, latency_ms: u64) {
        self.last_latency_ms = Some(latency_ms);
        if self.recent_latencies_ms.len() == MAX_LATENCY_SAMPLES {
            self.recent_latencies_ms.pop_front();
        }
        self.recent_latencies_ms.push_back(latency_ms);
    }

    fn view(&self, server: &str, slow_threshold_ms: u64, pool_idle_sessions: usize) -> Value {
        let recent: Vec<u64> = self.recent_latencies_ms.iter().copied().collect();
        json!({
            "server": server,
            "state": self.state(slow_threshold_ms),
            "in_flight": self.in_flight,
            "last_latency_ms": self.last_latency_ms,
            "recent_latencies_ms": recent,
            "last_error_class": self.last_error_class,
            "last_error_unix_ms": self.last_error_unix_ms,
            "last_ready_unix_ms": self.last_ready_unix_ms,
            "pool_idle_sessions": pool_idle_sessions,
        })
    }
}

struct State {
    next_seq: u64,
    epoch: u64,
    entries: BTreeMap<String, ServerEntry>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            next_seq: 0,
            epoch: 1,
            entries: BTreeMap::new(),
        }
    }
}

impl State {
    fn touch<'a>(&'a mut self, server: &str) -> Option<&'a mut ServerEntry> {
        if !self.entries.contains_key(server) && self.entries.len() >= MAX_TRACKED_SERVERS {
            let victim = self
                .entries
                .iter()
                .filter(|(_, entry)| entry.in_flight == 0)
                .min_by_key(|(_, entry)| entry.touch_seq)
                .map(|(name, _)| name.clone())?;
            self.entries.remove(&victim);
        }
        self.next_seq = self.next_seq.saturating_add(1);
        let seq = self.next_seq;
        let epoch = self.epoch;
        let entry = self
            .entries
            .entry(server.to_owned())
            .or_insert_with(|| ServerEntry {
                authority_epoch: epoch,
                ..Default::default()
            });
        entry.touch_seq = seq;
        Some(entry)
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Process-local, bounded status tracker for extension upstream servers.
pub struct StatusTracker {
    slow_threshold_ms: u64,
    state: Mutex<State>,
}

impl StatusTracker {
    pub fn new() -> Arc<Self> {
        Self::with_slow_threshold(Duration::from_millis(DEFAULT_SLOW_THRESHOLD_MS))
    }

    pub fn with_slow_threshold(threshold: Duration) -> Arc<Self> {
        Arc::new(Self {
            slow_threshold_ms: threshold.as_millis().max(1) as u64,
            state: Mutex::default(),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Marks `server` as `starting` until the returned guard is finished or dropped.
    pub fn begin_starting(self: &Arc<Self>, server: &str) -> StartingGuard {
        self.begin_starting_for(server, None, None)
    }

    /// Marks `server` as `starting` bound to `authority_key` and current epoch.
    /// A later finish/drop is ignored if authority changed or `cancel` fired.
    pub fn begin_starting_for(
        self: &Arc<Self>,
        server: &str,
        authority_key: Option<&str>,
        cancel: Option<&CancellationToken>,
    ) -> StartingGuard {
        if cancel.is_some_and(CancellationToken::is_cancelled) {
            return StartingGuard {
                tracker: None,
                server: server.to_owned(),
                authority_key: authority_key.map(str::to_owned),
                authority_epoch: 0,
                cancel: cancel.cloned(),
                completed: true,
            };
        }
        let mut state = self.lock();
        if let Some(key) = authority_key {
            let changed = state
                .entries
                .get(server)
                .is_some_and(|entry| entry.authority_key.as_deref() != Some(key));
            if changed {
                state.entries.remove(server);
                state.epoch = state.epoch.saturating_add(1);
            }
        }
        let current_epoch = state.epoch;
        let (tracked, guard_key, guard_epoch) = if let Some(entry) = state.touch(server) {
            if let Some(key) = authority_key {
                if entry.authority_key.as_deref() != Some(key) {
                    entry.authority_key = Some(key.to_owned());
                    entry.authority_epoch = current_epoch;
                }
            }
            entry.in_flight = entry.in_flight.saturating_add(1);
            (true, entry.authority_key.clone(), entry.authority_epoch)
        } else {
            (false, authority_key.map(str::to_owned), current_epoch)
        };
        StartingGuard {
            tracker: tracked.then(|| Arc::clone(self)),
            server: server.to_owned(),
            authority_key: guard_key,
            authority_epoch: guard_epoch,
            cancel: cancel.cloned(),
            completed: false,
        }
    }

    pub fn mark_ready(&self, server: &str, latency_ms: u64) {
        let mut state = self.lock();
        if let Some(entry) = state.touch(server) {
            entry.last_outcome = Some(Outcome::Ready);
            entry.last_ready_unix_ms = Some(now_unix_ms());
            entry.record_latency(latency_ms);
        }
    }

    pub fn mark_error(&self, server: &str, error_class: &'static str, latency_ms: Option<u64>) {
        let mut state = self.lock();
        if let Some(entry) = state.touch(server) {
            entry.last_outcome = Some(Outcome::Error);
            entry.last_error_class = Some(error_class);
            entry.last_error_unix_ms = Some(now_unix_ms());
            if let Some(ms) = latency_ms {
                entry.record_latency(ms);
            }
        }
    }

    /// Synchronizes tracked state with the active authority mapping
    /// (`enabled server -> config_sha256`). Disabled, removed, or changed
    /// servers lose their cached status immediately, even if an old attempt
    /// is still unwinding.
    pub fn sync_authority(
        &self,
        enabled_fingerprints: &BTreeMap<String, String>,
        configured_servers: &BTreeSet<String>,
    ) {
        let mut state = self.lock();
        state.epoch = state.epoch.saturating_add(1);
        state.entries.retain(|name, entry| {
            configured_servers.contains(name)
                && enabled_fingerprints
                    .get(name)
                    .is_some_and(|sha| entry.authority_key.as_deref() == Some(sha.as_str()))
        });
    }

    pub fn retain_servers(&self, keep: &BTreeSet<String>) {
        let mut state = self.lock();
        state.epoch = state.epoch.saturating_add(1);
        state.entries.retain(|name, _| keep.contains(name));
    }

    pub fn snapshot(&self, configured_servers: &[String], pool: Option<&SessionPool>) -> Value {
        let pool_summary: PoolSummary = pool.map(SessionPool::summary).unwrap_or_default();
        let state = self.lock();
        let mut names = BTreeSet::<String>::new();
        for name in state.entries.keys() {
            names.insert(name.clone());
        }
        for name in configured_servers {
            if names.len() >= MAX_TRACKED_SERVERS {
                break;
            }
            names.insert(name.clone());
        }
        let servers: Vec<Value> = names
            .into_iter()
            .take(MAX_TRACKED_SERVERS)
            .map(|name| {
                let idle_sessions = pool_summary.per_server.get(&name).copied().unwrap_or(0);
                match state.entries.get(&name) {
                    Some(entry) => entry.view(&name, self.slow_threshold_ms, idle_sessions),
                    None => ServerEntry::default().view(&name, self.slow_threshold_ms, idle_sessions),
                }
            })
            .collect();
        json!({
            "tracked_servers": servers.len(),
            "max_tracked_servers": MAX_TRACKED_SERVERS,
            "max_latency_samples": MAX_LATENCY_SAMPLES,
            "slow_threshold_ms": self.slow_threshold_ms,
            "pool": {
                "idle_sessions": pool_summary.idle_sessions,
                "stdio_idle_sessions": pool_summary.stdio_idle_sessions,
                "http_idle_sessions": pool_summary.http_idle_sessions,
            },
            "servers": servers,
        })
    }

    /// Snapshot aligned to an exact `Registry`: disabled servers report
    /// `"disabled"` with cleared telemetry, and entries whose `config_sha256`
    /// no longer matches report `"idle"`.
    pub fn snapshot_for_registry(
        &self,
        registry: &Registry,
        pool: Option<&SessionPool>,
        generation: Option<u64>,
    ) -> Value {
        let pool_summary: PoolSummary = pool.map(SessionPool::summary).unwrap_or_default();
        let state = self.lock();
        let mut servers = Vec::new();
        for name in registry.server_names().into_iter().take(MAX_TRACKED_SERVERS) {
            let enabled = registry.is_server_enabled(&name);
            let sha = registry.server_sha256(&name).ok().flatten();
            if !enabled {
                servers.push(json!({
                    "server": name,
                    "enabled": false,
                    "config_sha256": sha,
                    "state": UpstreamState::Disabled,
                    "in_flight": 0,
                    "last_latency_ms": null,
                    "recent_latencies_ms": [],
                    "last_error_class": null,
                    "last_error_unix_ms": null,
                    "last_ready_unix_ms": null,
                    "pool_idle_sessions": 0,
                }));
                continue;
            }
            let idle_sessions = pool_summary.per_server.get(&name).copied().unwrap_or(0);
            let entry = state.entries.get(&name).filter(|entry| {
                entry.authority_key.is_none() || entry.authority_key == sha
            });
            let mut view = match entry {
                Some(entry) => entry.view(&name, self.slow_threshold_ms, idle_sessions),
                None => ServerEntry::default().view(&name, self.slow_threshold_ms, idle_sessions),
            };
            view["enabled"] = json!(true);
            view["config_sha256"] = json!(sha);
            servers.push(view);
        }
        let mut out = json!({
            "tracked_servers": servers.len(),
            "max_tracked_servers": MAX_TRACKED_SERVERS,
            "max_latency_samples": MAX_LATENCY_SAMPLES,
            "slow_threshold_ms": self.slow_threshold_ms,
            "pool": {
                "idle_sessions": pool_summary.idle_sessions,
                "stdio_idle_sessions": pool_summary.stdio_idle_sessions,
                "http_idle_sessions": pool_summary.http_idle_sessions,
            },
            "servers": servers,
        });
        if let Some(generation) = generation {
            out["generation"] = json!(generation);
        }
        out
    }
}

/// RAII guard for an active connection/call attempt.
pub struct StartingGuard {
    tracker: Option<Arc<StatusTracker>>,
    server: String,
    authority_key: Option<String>,
    authority_epoch: u64,
    cancel: Option<CancellationToken>,
    completed: bool,
}

impl StartingGuard {
    fn matching_entry<'a>(&self, state: &'a mut State) -> Option<&'a mut ServerEntry> {
        let entry = state.entries.get_mut(&self.server)?;
        if entry.authority_epoch != self.authority_epoch || entry.authority_key != self.authority_key {
            return None;
        }
        Some(entry)
    }

    pub fn finish_ready(mut self, latency_ms: u64) {
        self.completed = true;
        let cancelled = self.cancel.as_ref().is_some_and(CancellationToken::is_cancelled);
        if let Some(tracker) = self.tracker.take() {
            let mut state = tracker.lock();
            if let Some(entry) = self.matching_entry(&mut state) {
                entry.in_flight = entry.in_flight.saturating_sub(1);
                if !cancelled {
                    entry.last_outcome = Some(Outcome::Ready);
                    entry.last_ready_unix_ms = Some(now_unix_ms());
                    entry.record_latency(latency_ms);
                }
            }
        }
    }

    pub fn finish_error(mut self, error_class: &'static str, latency_ms: Option<u64>) {
        self.completed = true;
        let cancelled = self.cancel.as_ref().is_some_and(CancellationToken::is_cancelled);
        if let Some(tracker) = self.tracker.take() {
            let mut state = tracker.lock();
            if let Some(entry) = self.matching_entry(&mut state) {
                entry.in_flight = entry.in_flight.saturating_sub(1);
                if !cancelled {
                    entry.last_outcome = Some(Outcome::Error);
                    entry.last_error_class = Some(error_class);
                    entry.last_error_unix_ms = Some(now_unix_ms());
                    if let Some(ms) = latency_ms {
                        entry.record_latency(ms);
                    }
                }
            }
        }
    }
}

impl Drop for StartingGuard {
    fn drop(&mut self) {
        if !self.completed {
            if let Some(tracker) = self.tracker.take() {
                let mut state = tracker.lock();
                if let Some(entry) = self.matching_entry(&mut state) {
                    entry.in_flight = entry.in_flight.saturating_sub(1);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_tracker_transitions_and_bounds() {
        let tracker = StatusTracker::with_slow_threshold(Duration::from_millis(50));
        let configured = vec!["alpha".to_owned()];

        let snap_idle = tracker.snapshot(&configured, None);
        assert_eq!(snap_idle["servers"][0]["state"], "idle");

        let guard = tracker.begin_starting("alpha");
        let snap_starting = tracker.snapshot(&configured, None);
        assert_eq!(snap_starting["servers"][0]["state"], "starting");
        assert_eq!(snap_starting["servers"][0]["in_flight"], 1);

        guard.finish_ready(10);
        let snap_ready = tracker.snapshot(&configured, None);
        assert_eq!(snap_ready["servers"][0]["state"], "ready");
        assert_eq!(snap_ready["servers"][0]["last_latency_ms"], 10);

        tracker.mark_ready("alpha", 75);
        let snap_slow = tracker.snapshot(&configured, None);
        assert_eq!(snap_slow["servers"][0]["state"], "slow");

        tracker.mark_error("alpha", "timeout", Some(120));
        let snap_err = tracker.snapshot(&configured, None);
        assert_eq!(snap_err["servers"][0]["state"], "error");
        assert_eq!(snap_err["servers"][0]["last_error_class"], "timeout");
        assert!(snap_err["servers"][0]["last_error_unix_ms"].as_u64().is_some());

        tracker.mark_ready("alpha", 5);
        let snap_recovered = tracker.snapshot(&configured, None);
        assert_eq!(snap_recovered["servers"][0]["state"], "ready");

        for idx in 0..30u64 {
            tracker.mark_ready("alpha", idx);
        }
        let snap_samples = tracker.snapshot(&configured, None);
        let recent = snap_samples["servers"][0]["recent_latencies_ms"].as_array().unwrap();
        assert_eq!(recent.len(), MAX_LATENCY_SAMPLES);
        assert_eq!(recent.first().unwrap(), 14);
        assert_eq!(recent.last().unwrap(), 29);

        for idx in 0..80 {
            tracker.mark_ready(&format!("srv_{idx:03}"), idx as u64);
        }
        let snap_capped = tracker.snapshot(&[], None);
        assert_eq!(snap_capped["tracked_servers"], MAX_TRACKED_SERVERS);
        assert_eq!(snap_capped["servers"].as_array().unwrap().len(), MAX_TRACKED_SERVERS);
    }

    #[test]
    fn status_tracker_clears_on_authority_sync_and_ignores_stale_guards() {
        let tracker = StatusTracker::new();
        let cancel = CancellationToken::new();

        // 1. Complete a probe under sha-1.
        let g1 = tracker.begin_starting_for("alpha", Some("sha-1"), Some(&cancel));
        g1.finish_ready(12);

        // 2. Start an in-flight probe under sha-1, then disable server via sync_authority.
        let stale_guard = tracker.begin_starting_for("alpha", Some("sha-1"), None);
        let mut enabled = BTreeMap::new();
        let mut configured = BTreeSet::from(["alpha".to_owned()]);
        tracker.sync_authority(&enabled, &configured);

        // Old guard finishing later must NOT resurrect ready status.
        stale_guard.finish_ready(9);

        // Re-enable with same sha-1 -> still idle (not stale ready).
        enabled.insert("alpha".to_owned(), "sha-1".to_owned());
        tracker.sync_authority(&enabled, &configured);
        let snap = tracker.snapshot(&["alpha".to_owned()], None);
        assert_eq!(snap["servers"][0]["state"], "idle");
        assert!(snap["servers"][0]["last_latency_ms"].is_null());

        // 3. Complete under sha-1, then replace authority key with sha-2 -> stale ready cleared.
        tracker
            .begin_starting_for("alpha", Some("sha-1"), None)
            .finish_ready(15);
        enabled.insert("alpha".to_owned(), "sha-2".to_owned());
        tracker.sync_authority(&enabled, &configured);
        let snap_replaced = tracker.snapshot(&["alpha".to_owned()], None);
        assert_eq!(snap_replaced["servers"][0]["state"], "idle");
        assert!(snap_replaced["servers"][0]["last_latency_ms"].is_null());

        // 4. Cancelled token guard never records ready even without sync_authority.
        let tok = CancellationToken::new();
        let cancelled_guard = tracker.begin_starting_for("beta", Some("sha-b"), Some(&tok));
        tok.cancel();
        cancelled_guard.finish_ready(5);
        configured.insert("beta".to_owned());
        enabled.insert("beta".to_owned(), "sha-b".to_owned());
        let snap_beta = tracker.snapshot(&["beta".to_owned()], None);
        let beta = snap_beta["servers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["server"] == "beta")
            .unwrap();
        assert_eq!(beta["state"], "idle");
    }
}
