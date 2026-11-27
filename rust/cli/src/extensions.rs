mod admin;
mod revocation_ipc;
pub(crate) mod stdio_child;
pub(crate) use admin::UiOAuthOwner;
use revocation_ipc::RevocationAckReceipt;

use agent_bridge_desktop::DesktopProfile;
use agent_bridge_extensions::{
    LiveExtensionRegistry, Registry, ReloadAuditRecord, ReloadMode, SessionPool, StatusTracker,
    ToolScope, CacheRequest,
};
use agent_bridge_gateway::{ToolCallResult, ToolDefinition, ToolMapHandler};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::sync::atomic::{AtomicU8, Ordering};
use std::io;
use crate::runtime::RuntimeError;
use crate::session_profile::{rank, ProfileControl};

thread_local! {
    static AUTHENTICATED_CACHE: std::cell::RefCell<Option<CacheRequest>> = const { std::cell::RefCell::new(None) };
}

/// Synchronous, reentrant request scope. The nested call sees only its own
/// authority (including None); unwind restores the prior one. No caller
/// metadata or argument can populate this slot.
pub(crate) fn with_authenticated_cache<T>(request:Option<CacheRequest>,f:impl FnOnce()->T)->T{
    struct Restore(Option<CacheRequest>);
    impl Drop for Restore {
        fn drop(&mut self){AUTHENTICATED_CACHE.with(|slot|{slot.replace(self.0.take());});}
    }
    let _restore=Restore(AUTHENTICATED_CACHE.with(|slot|slot.replace(request)));
    f()
}

fn authenticated_cache()->Option<CacheRequest>{
    AUTHENTICATED_CACHE.with(|slot|slot.borrow().clone())
}

#[cfg(test)]
pub(crate) fn test_cache_scope_present()->bool{
    authenticated_cache().is_some()
}

struct ValidatedBase {
    bytes: Vec<u8>,
    stamp: (u64, String),
}

struct Attached {
    identity: PathBuf,
    live: Arc<LiveExtensionRegistry>,
    base: Mutex<ValidatedBase>,
    _peer: Arc<revocation_ipc::PeerLease>,
}

// Each route retains its own pool/profile. Weak references exist only to
// deliver a committed local restriction to every attached view of this root.
static ATTACHED: Mutex<Vec<Weak<Attached>>> = Mutex::new(Vec::new());

fn attached_at(identity: &Path) -> Vec<Arc<Attached>> {
    let mut all = ATTACHED.lock().unwrap_or_else(|p| p.into_inner());
    all.retain(|entry| entry.strong_count() > 0);
    all.iter().filter_map(Weak::upgrade).filter(|entry| entry.identity == identity).collect()
}

fn journal_registry(bytes: &[u8], journal: &admin::Journal) -> io::Result<Registry> {
    Ok(admin::apply_journal(bytes, journal)?.with_stdio_launcher(Arc::new(stdio_child::ContainedLauncher)))
}

impl Attached {
    fn reconcile_detailed(&self, base: &mut ValidatedBase, journal: &admin::Journal) -> io::Result<(usize, usize)> {
        let result = (|| {
            let stamp = admin::journal_stamp(journal)?;
            if stamp.0 < base.stamp.0 || (stamp.0 == base.stamp.0 && stamp != base.stamp) {
                return Err(io::Error::other("Extension approval journal changed or regressed"));
            }
            let effective = journal_registry(&base.bytes, journal)?;
            // Even a revoke/re-enable that returns to the identical effective
            // fingerprint has crossed a durable approval generation.
            if stamp!=base.stamp { self.live.invalidate_results(); }
            let record = self.live.restrict_to(&effective)?;
            base.stamp = stamp;
            Ok(record.map_or((0, 0), |r| (r.cancelled_in_flight, r.closed_idle_sessions)))
        })();
        if result.is_err() { self.live.cancel_all(); }
        result
    }

    fn reconcile(&self, base: &mut ValidatedBase, journal: &admin::Journal) -> io::Result<()> {
        self.reconcile_detailed(base, journal).map(|_| ())
    }
}

// Called under the existing private journal writer lock AFTER durable commit,
// before the native operator decision is acknowledged. No network probe.
fn journal_committed(settings: &Path, journal: &admin::Journal) -> io::Result<RevocationAckReceipt> {
    let identity = std::fs::canonicalize(settings)?;
    let (journal_revision, state_hash) = admin::journal_stamp(journal)?;
    let mut receipt = RevocationAckReceipt {
        journal_revision,
        ..RevocationAckReceipt::default()
    };
    for entry in attached_at(&identity) {
        let mut base = entry.base.lock().unwrap_or_else(|p| p.into_inner());
        let (cancelled, closed) = entry.reconcile_detailed(&mut base, journal)?;
        receipt.local_views_acknowledged += 1;
        receipt.cancelled_in_flight += cancelled;
        receipt.closed_idle_sessions += closed;
    }
    let (remote_ack, remote_cancelled, remote_closed) = revocation_ipc::notify_and_wait_peers(
        settings,
        &identity,
        journal_revision,
        &state_hash,
        revocation_ipc::DEFAULT_ACK_TIMEOUT,
    )?;
    receipt.remote_backends_acknowledged = remote_ack;
    receipt.cancelled_in_flight += remote_cancelled;
    receipt.closed_idle_sessions += remote_closed;
    Ok(receipt)
}

pub(super) fn reconcile_from_disk_for_peer(
    settings: &Path,
    identity: &Path,
    expected_revision: u64,
    expected_state_hash: &str,
) -> io::Result<(usize, usize, usize)> {
    let journal = match admin::read_committed_for_reconcile(settings) {
        Ok(journal) => journal,
        Err(err) => {
            journal_unavailable(settings);
            return Err(err);
        }
    };
    let stamp = match admin::journal_stamp(&journal) {
        Ok(stamp) => stamp,
        Err(err) => {
            journal_unavailable(settings);
            return Err(err);
        }
    };
    if stamp != (expected_revision, expected_state_hash.to_owned()) {
        return Err(io::Error::other(
            "Committed extension journal does not match revocation request",
        ));
    }
    let mut views_reconciled = 0usize;
    let mut cancelled_in_flight = 0usize;
    let mut closed_idle_sessions = 0usize;
    for entry in attached_at(identity) {
        let mut base = entry.base.lock().unwrap_or_else(|p| p.into_inner());
        let (cancelled, closed) = entry.reconcile_detailed(&mut base, &journal)?;
        views_reconciled += 1;
        cancelled_in_flight += cancelled;
        closed_idle_sessions += closed;
    }
    Ok((views_reconciled, cancelled_in_flight, closed_idle_sessions))
}

fn journal_unavailable(settings: &Path) {
    if let Ok(identity) = std::fs::canonicalize(settings) {
        for entry in attached_at(&identity) { entry.live.cancel_all(); }
    }
}

/// The profile that decides which granted extension tools a route may call.
/// It is read at each call, so a profile change applies to the next one.
/// The route's tool calls share its pool of idle sessions, status tracker,
/// and live atomic registry.
#[derive(Clone)]
pub(crate) struct ExtensionScope {
    profile: Option<Arc<RwLock<DesktopProfile>>>,
    pool: Arc<SessionPool>,
    status: Arc<StatusTracker>,
    live: Arc<Mutex<Option<Arc<Attached>>>>,
    minimum_profile: Arc<AtomicU8>,
    reload_audit: Arc<Mutex<VecDeque<ReloadAuditRecord>>>,
}

impl std::fmt::Debug for ExtensionScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtensionScope").finish_non_exhaustive()
    }
}

impl ExtensionScope {
    /// A route without a profile: named data operations only.
    pub(crate) fn data_only() -> Self {
        Self {
            profile: None,
            minimum_profile: Arc::new(AtomicU8::new(0)),
            pool: SessionPool::new(),
            status: StatusTracker::new(),
            live: Arc::default(),
            reload_audit: Arc::default(),
        }
    }
    pub(crate) fn fixed(profile: DesktopProfile) -> Self {
        Self {
            profile: Some(Arc::new(RwLock::new(profile))),
            minimum_profile: Arc::new(AtomicU8::new(0)),
            pool: SessionPool::new(),
            status: StatusTracker::new(),
            live: Arc::default(),
            reload_audit: Arc::default(),
        }
    }
    /// A live profile. Any lowering closes the idle sessions, like the
    /// other processes the bridge owns; routes gate calls at different ranks.
    pub(crate) fn live(profile: &ProfileControl) -> Result<Self, RuntimeError> {
        let scope = Self {
            profile: Some(profile.shared()),
            minimum_profile: Arc::new(AtomicU8::new(rank(DesktopProfile::WorkspaceWrite))),
            pool: SessionPool::new(),
            status: StatusTracker::new(),
            live: Arc::default(),
            reload_audit: Arc::default(),
        };
        let binding=Arc::downgrade(&scope.live);
        profile.register_change_observer(Arc::new(move || {
            if let Some(binding)=binding.upgrade(){
                if let Some(entry)=binding.lock().unwrap_or_else(|p|p.into_inner()).as_ref(){
                    entry.live.invalidate_results();
                }
            }
        }))?;
        for minimum in [DesktopProfile::WorkspaceWrite, DesktopProfile::FullControl, DesktopProfile::FullyUnlocked] {
            let live = Arc::downgrade(&scope.live);
            profile.register_revoker(minimum, Arc::new(move || {
                if let Some(binding) = live.upgrade() {
                    if let Some(entry) = binding.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
                        entry.live.cancel_all();
                    }
                }
                Ok(())
            }))?;
        }
        Ok(scope)
    }
    pub(crate) fn require_full_control(&self) {
        self.minimum_profile.store(rank(DesktopProfile::FullControl), Ordering::Release);
    }

    pub(crate) fn bind_live(&self, settings: &Path) -> Result<Arc<LiveExtensionRegistry>, RuntimeError> {
        let identity = std::fs::canonicalize(settings)?;
        admin::with_current(settings, |bytes, journal| {
            let mut slot = self.live.lock().map_err(|_| io::Error::other("Extension owner unavailable"))?;
            if let Some(entry) = slot.as_ref() {
                if entry.identity != identity { return Err(io::Error::other("Extension owner path changed")); }
                return Ok(Arc::clone(&entry.live));
            }
            let initial = journal_registry(bytes, journal)?;
            let live = LiveExtensionRegistry::new(initial, self.pool.clone(), self.status.clone());
            let peer = revocation_ipc::acquire_peer_lease(settings, &identity)?;
            let entry = Arc::new(Attached { identity, live: Arc::clone(&live),
                base: Mutex::new(ValidatedBase { bytes: bytes.to_vec(), stamp: admin::journal_stamp(journal)? }),
                _peer: peer });
            let mut all = ATTACHED.lock().unwrap_or_else(|p| p.into_inner());
            all.retain(|entry| entry.strong_count() > 0);
            all.push(Arc::downgrade(&entry));
            *slot = Some(entry);
            Ok(live)
        }).map_err(Into::into)
    }

    /// Snapshot only the exact profile and epoch under its read gate. Called
    /// while the HTTP transport still holds the validated OAuth owner lock.
    /// The ordinary journal/profile admission will recheck this observation.
    pub(crate) fn cache_request(&self,token_hash:[u8;32])->Option<CacheRequest>{
        let active=self.profile.as_ref()?.read().ok()?;
        let binding=self.live.lock().ok()?;
        binding.as_ref()?.live.cache_request(token_hash,rank(*active))
    }
    pub(crate) fn invalidate_results(&self){
        if let Some(binding)=self.live.lock().unwrap_or_else(|p|p.into_inner()).as_ref(){
            binding.live.invalidate_results();
        }
    }

    fn get_binding(&self, settings: &Path) -> Option<Arc<Attached>> {
        let identity = std::fs::canonicalize(settings).ok()?;
        self.live.lock().ok()?.as_ref().filter(|entry| entry.identity == identity).cloned()
    }

    fn get_live(&self, settings: &Path) -> Option<Arc<LiveExtensionRegistry>> {
        self.get_binding(settings).map(|entry| Arc::clone(&entry.live))
    }

    /// Reconcile journal restrictions and capture the same validated
    /// registry that admission will use. An untrusted/missing journal is
    /// never a reason to fall back to an earlier approval.
    fn with_live<T>(&self, settings: &Path, f: impl FnOnce(&Attached) -> io::Result<T>) -> io::Result<T> {
        let entry = self.get_binding(settings).ok_or_else(|| io::Error::other("Extension owner unavailable"))?;
        let result = admin::with_current(settings, |_, journal| {
            let mut base = entry.base.lock().map_err(|_| io::Error::other("Extension owner unavailable"))?;
            entry.reconcile(&mut base, journal)?;
            f(&entry)
        });
        result
    }

    pub(crate) fn current_registry(&self, settings: &Path) -> Result<Arc<Registry>, RuntimeError> {
        Ok(self.with_live(settings, |entry| Ok(entry.live.current()))?)
    }

    /// The existing exact OAuth seal is still checked on the very snapshot
    /// admitted, under the journal lock. Invalid candidate bytes do not
    /// replace that snapshot or implicitly broaden it.
    pub(crate) fn call(
        &self, settings: &Path, name: &str, params: &serde_json::Map<String, Value>, bound: Option<&Value>,
    ) -> Result<Value, RuntimeError> {
        // Historical local-only/fixed routes have no mandatory operator UI:
        // keep their valid disk-refresh behavior, with the same validation
        // and generation CAS. A rejected candidate leaves the last valid
        // base in use, subject to fresh journal restrictions below.
        if self.minimum_profile.load(Ordering::Acquire) == 0 {
            if let (Ok(candidate), Some(live)) = (read(settings), self.get_live(settings)) {
                if !live.current().matches_fingerprints(&candidate)? {
                    let _ = self.reload_from_disk(settings);
                }
            }
        }
        let active = self.profile.as_ref().map(|profile| profile.read()
            .map_err(|_| io::Error::other("PROFILE_STATE_UNAVAILABLE"))).transpose()?;
        let minimum = self.minimum_profile.load(Ordering::Acquire);
        let profile = active.as_deref().copied().unwrap_or(DesktopProfile::ReadOnly);
        if rank(profile) < minimum { return Err("LIVE_PROFILE_REFUSED".into()); }
        let tool_scope = if profile == DesktopProfile::ReadOnly { ToolScope::DataOperations } else { ToolScope::AnyGranted };
        // Only the exact OAuth-bound handler can use the transport scope.
        // A local/fixed/unbound call remains uncached even inside a nested
        // synchronous dispatch with an authenticated outer frame.
        let cache=if bound.is_some(){authenticated_cache()}else{None};
        let admitted = self.with_live(settings, |entry| entry.live.admit_with_cache(
            name, tool_scope,cache.as_ref(),rank(profile), |registry| {
            if let Some(expected) = bound {
                if !crate::runtime::registry_matches_authority(registry, expected).unwrap_or(false) {
                    return Err(io::Error::other("EXTENSION_AUTHORITY_CHANGED: new local OAuth authorization required"));
                }
            }
            Ok(())
        }))?;
        // Registration is inside both the live profile and journal gates.
        // No slow upstream effect holds either lock.
        drop(active);
        Ok(admitted.execute(params)?)
    }

    /// Attaches the status tracker for one-shot operator probes without pooling.
    pub(crate) fn with_status(&self, registry: Registry) -> Registry {
        registry.with_status_tracker(self.status.clone())
    }
    pub(crate) fn status_snapshot(&self, settings: &Path) -> Value {
        if let Some(live) = self.get_live(settings) {
            let registry = self.current_registry(settings).ok().unwrap_or_else(|| live.current());
            return self
                .status
                .snapshot_for_registry(&registry, Some(&self.pool), Some(live.generation()));
        }
        if let Ok(registry) = read(settings) {
            return self.status.snapshot_for_registry(&registry, Some(&self.pool), None);
        }
        self.status.snapshot(&[], Some(&self.pool))
    }

    pub(crate) fn live_generation(&self, settings: &Path) -> Option<u64> {
        self.get_live(settings).map(|live| live.generation())
    }

    /// Admits and runs one read-only connection probe under the active
    /// generation lock so concurrent revocation cancels it immediately.
    pub(crate) fn test_connection(&self, settings: &Path, server: &str) -> Result<Value, RuntimeError> {
        if self.get_binding(settings).is_some() {
            let admitted = self.with_live(settings, |entry| entry.live.admit_probe(server))?;
            return Ok(admitted.execute()?);
        }
        Ok(self.with_status(read(settings)?).test_connection(server)?)
    }

    /// Capture and qualify outside the writer gate, then recheck the exact
    /// private base/journal and live generation before publishing.
    pub(crate) fn reload_from_disk(&self, settings: &Path) -> Result<Value, RuntimeError> {
        let Some(entry) = self.get_binding(settings) else {
            // A detached operator has no live registry to swap.
            let candidate = read(settings).and_then(|registry| {
                registry.validate_replacement(None)?;
                Ok(registry)
            });
            let record = ReloadAuditRecord {
                timestamp_unix_ms: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64).unwrap_or(0),
                generation: 0, ok: candidate.is_ok(),
                reason_code: if candidate.is_ok() {"validated_not_attached"} else {"invalid_config_refused"},
                server_count: candidate.as_ref().map(|reg|reg.server_names().len()).unwrap_or(0),
                removed_or_disabled:0, changed:0, closed_idle_sessions:0, cancelled_in_flight:0,
            };
            self.push_fallback_audit(record.clone());
            candidate?;
            let mut value = serde_json::to_value(record)?;
            value["applied"] = json!(false);
            return Ok(value);
        };
        let snapshot = admin::with_current(settings, |bytes, journal| {
            let mut base = entry.base.lock().map_err(|_| io::Error::other("Extension owner unavailable"))?;
            entry.reconcile(&mut base, journal)?;
            Ok((bytes.to_vec(), admin::journal_stamp(journal)?, journal_registry(bytes, journal)?))
        });
        let (bytes, stamp, candidate) = match snapshot {
            Ok(snapshot) => snapshot,
            Err(error) => { entry.live.record_failure(&error); return Err(error.into()); }
        };
        let prepared = entry.live.prepare_reload(Ok(candidate.clone()), ReloadMode::OperatorApproved)?;
        let committed = admin::with_current(settings, |current, journal| {
            let mut base = entry.base.lock().map_err(|_| io::Error::other("Extension owner unavailable"))?;
            entry.reconcile(&mut base, journal)?;
            if current != bytes.as_slice() || admin::journal_stamp(journal)? != stamp {
                let error = io::Error::other("Extension settings or approval changed during reload");
                entry.live.record_failure(&error);
                return Err(error);
            }
            let record = entry.live.commit_reload(prepared)?;
            *base = ValidatedBase { bytes, stamp };
            // Other live views keep their own sealed configuration, but no
            // removed/reconfigured entry may survive a successful reload.
            for other in attached_at(&entry.identity) {
                if !Arc::ptr_eq(&entry, &other) { other.live.restrict_to(&candidate)?; }
            }
            Ok(record)
        })?;
        Ok(serde_json::to_value(committed)?)
    }

    fn push_fallback_audit(&self, record: ReloadAuditRecord) {
        let mut guard = self.reload_audit.lock().unwrap_or_else(|p| p.into_inner());
        if guard.len() == agent_bridge_extensions::reload::MAX_RELOAD_AUDIT {
            guard.pop_front();
        }
        guard.push_back(record);
    }
    /// Bounded reload/revocation audit snapshot for operator diagnostics.
    pub(crate) fn reload_audit_snapshot(&self) -> Value {
        if let Some(entry) = self.live.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            return entry.live.audit_snapshot();
        }
        let guard = self.reload_audit.lock().unwrap_or_else(|p| p.into_inner());
        let records: Vec<&ReloadAuditRecord> = guard.iter().collect();
        json!({
            "generation": 0,
            "in_flight": 0,
            "max_records": agent_bridge_extensions::reload::MAX_RELOAD_AUDIT,
            "records": records,
        })
    }
}

pub fn read(settings: &Path) -> Result<Registry, RuntimeError> {
    let bytes = agent_bridge_lifecycle::read_operator_setting(settings, "extensions.json")?;
    // The private journal supplies server tombstones and generation-bound
    // additions. A matching local tool grant marker is stripped by admin
    // before the strict Registry parser verifies each individual approval.
    // Stdio servers start only through the contained launcher, and only after
    // the extensions crate re-verifies the executable pin for each session.
    Ok(admin::apply_local(settings, &bytes)?.with_stdio_launcher(Arc::new(stdio_child::ContainedLauncher)))
}

/// Explicitly selected, *read-only* local CLI connection & catalog probe.
/// Uses the exact configured pins, approvals, and launcher without granting
/// tools or modifying the private journal.
pub fn refresh_check(settings: &Path, server: &str) -> Result<(), RuntimeError> {
    if !agent_bridge_extensions::valid_server_name(server) {
        return Err("Invalid extension server name".into());
    }
    let report = read(settings)?.test_connection(server)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if report.get("ok").and_then(Value::as_bool) != Some(true) {
        let class = report
            .get("error_class")
            .and_then(Value::as_str)
            .unwrap_or("connection_check_failed");
        return Err(format!("Extension connection check failed: {class}").into());
    }
    Ok(())
}

/// Operator-only local UI connection check (never exposed to Web MCP).
pub(crate) fn test_connection_from_operator_ui(
    settings: &Path,
    server: &str,
    scope: Option<&ExtensionScope>,
) -> Result<Value, RuntimeError> {
    if !agent_bridge_extensions::valid_server_name(server) {
        return Err("Invalid extension server name".into());
    }
    match scope {
        Some(scope) => scope.test_connection(settings, server),
        None => Ok(read(settings)?.test_connection(server)?),
    }
}

/// Explicitly selected local CLI validation/reload check for `extensions.json`.
/// Validates configuration and controls fail-closed without mutating state.
pub fn reload_cli(settings: &Path) -> Result<(), RuntimeError> {
    let registry = read(settings)?;
    registry.validate_replacement(None)?;
    let overview = registry.servers(None)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": true,
            "reason_code": "validated_not_attached",
            "applied": false,
            "server_count": registry.server_names().len(),
            "servers": overview["servers"],
        }))?
    );
    Ok(())
}

/// Operator-only local UI atomic reload path (never exposed to Web MCP).
pub(crate) fn reload_from_operator_ui(
    settings: &Path,
    scope: Option<&ExtensionScope>,
) -> Result<Value, RuntimeError> {
    if let Some(scope) = scope {
        return scope.reload_from_disk(settings);
    }
    let registry = read(settings)?;
    registry.validate_replacement(None)?;
    Ok(json!({
        "ok": true,
        "reason_code": "validated_not_attached",
        "applied": false,
        "server_count": registry.server_names().len(),
    }))
}

/// Operator-only terminal path. No Web handler can invoke this function.
pub fn local(settings: &Path, action: &str, id: Option<&str>) -> Result<(), RuntimeError> {
    let answer = admin::local(settings, action, id)?;
    println!("{}", serde_json::to_string_pretty(&answer)?);
    if answer.get("decision").and_then(Value::as_str) == Some("unsupported") {
        return Err("Extension operation explicitly refused: not implemented by the local adapter".into());
    }
    Ok(())
}

/// `extensions approve` with several request ids of one import.
pub fn approve_batch(settings: &Path, ids: &[&str]) -> Result<(), RuntimeError> {
    let answer = admin::approve_batch(settings, ids)?;
    println!("{}", serde_json::to_string_pretty(&answer)?);
    Ok(())
}

/// `extensions import` with `--inherit-path <server>` options.
pub fn import(settings: &Path, mcp_json: &Path, inherit_path: &std::collections::BTreeSet<String>)
    -> Result<(), RuntimeError>
{
    let answer = admin::import(settings, mcp_json, inherit_path)?;
    println!("{}", serde_json::to_string_pretty(&answer)?);
    Ok(())
}

/// Operator-only local loopback UI read view (never exposed to Web MCP).
pub(crate) fn ui_overview(owner: &UiOAuthOwner, settings: &Path) -> Result<Value, RuntimeError> {
    Ok(admin::ui_overview(owner, settings)?)
}

/// Operator-only local loopback UI decision path (never exposed to Web MCP).
pub(crate) fn decide_from_operator_ui(
    owner: &UiOAuthOwner,
    settings: &Path,
    id: &str,
    approve: bool,
) -> Result<Value, RuntimeError> {
    Ok(admin::decide_from_operator_ui(owner, settings, id, approve)?)
}

pub(crate) fn attach(settings: &Path, catalog: &mut Vec<ToolDefinition>, handlers: &mut ToolMapHandler,
    scope: ExtensionScope) -> Result<(), RuntimeError>
{
    attach_inner(settings, catalog, handlers, false, scope)
}

pub(crate) fn attach_unified(settings: &Path, catalog: &mut Vec<ToolDefinition>, handlers: &mut ToolMapHandler,
    scope: ExtensionScope) -> Result<(), RuntimeError>
{
    attach_inner(settings, catalog, handlers, true, scope)
}

fn attach_inner(settings: &Path, catalog: &mut Vec<ToolDefinition>, handlers: &mut ToolMapHandler, unified: bool,
    scope: ExtensionScope) -> Result<(), RuntimeError>
{
    // Retain the last valid base; every call still checks the private journal.
    scope.bind_live(settings)?;
    let settings = settings.to_owned();
    for name in ["desktop_mcp_manage", "desktop_mcp_tool_inspect"] {
        let directory = settings.clone();
        let inspection_scope = scope.clone();
        handlers.register(name, move |args| {
            if name == "desktop_mcp_manage" && matches!(
                args.get("action").and_then(Value::as_str),
                Some("add" | "remove" | "enable" | "disable" | "set_oauth"
                    | "auth_start" | "auth_status" | "auth_disconnect" | "refresh")
            ) {
                let proposed = if unified { admin::submit_unified(&directory, &args) }
                    else { admin::submit(&directory, &args) };
                return Ok(match proposed {
                    Ok(receipt) => ToolCallResult::text(receipt.to_string()),
                    Err(_) => ToolCallResult::tool_error("Extension proposal refused or local journal unavailable"),
                });
            }
            let Ok(registry) = inspection_scope.current_registry(&directory) else {
                return Ok(ToolCallResult::tool_error("Local extension configuration unavailable"));
            };
            let result = match (name, args.get("action").and_then(Value::as_str)) {
                ("desktop_mcp_manage", Some("list")) if args.len() == 1 => registry.servers(None),
                ("desktop_mcp_manage", Some("inspect")) if args.len() == 2 => match args.get("name").and_then(Value::as_str) {
                    Some(server) => registry.servers(Some(server)),
                    None => return Ok(ToolCallResult::tool_error("Expected a server identifier")),
                },
                ("desktop_mcp_tool_inspect", None) if args.len() == 1 => match args.get("name").and_then(Value::as_str) {
                    Some(tool) => registry.inspect_cached(tool),
                    None => return Ok(ToolCallResult::tool_error("Expected a qualified tool name")),
                },
                _ => return Ok(ToolCallResult::tool_error("Unsupported extension inspection request")),
            };
            Ok(match result {
                Ok(value) => ToolCallResult::text(value.to_string()),
                Err(error) => ToolCallResult::tool_error(error.to_string()),
            })
        });
    }
    let mut manage_schema = json!({"type":"object","required":["action"],"additionalProperties":false,"properties":{
            "action":{"enum":["list","inspect","add","remove","enable","disable",
                "set_oauth","auth_start","auth_status","auth_disconnect","refresh"]},
            "name":{"type":"string","minLength":1,"maxLength":96},
            "description":{"type":"string","maxLength":1024},
            "url":{"type":"string","maxLength":4096},
            "enabled":{"type":"boolean"},
            "oauth":{"type":"boolean"},
            "oauth_scope":{"type":"string","maxLength":8192},
            "oauth_client_id":{"type":"string","maxLength":1024},
            "oauth_client_auth_method":{"enum":["client_secret_basic","client_secret_post","none"]},
            "oauth_client_secret_env":{"type":"string","maxLength":128},
            "force":{"type":"boolean"},
            "timeout_ms":{"type":"integer","minimum":250,"maximum":300000}}});
    if unified {
        manage_schema["properties"]["header_env"] = json!({"type":"object","maxProperties":16,
            "propertyNames":{"type":"string","minLength":1,"maxLength":128},
            "additionalProperties":{"type":"string","minLength":1,"maxLength":128,
                "pattern":"^AGENT_BRIDGE_EXTENSION_[A-Z0-9_]+$"},
            "description":"Add only: HTTP header names mapped to local secret environment variable names. Values are never accepted. Requires local approval; transport headers cannot be overridden."});
    }
    catalog.push(ToolDefinition::new("desktop_mcp_manage", Some("Inspect local extensions or submit a typed administration proposal. Web never executes the proposal; only an interactive operator can decide locally.".into()), manage_schema));
    catalog.push(ToolDefinition::new("desktop_mcp_tool_inspect", Some("Read the cached descriptor for an approved extension tool.".into()),
        json!({"type":"object","required":["name"],"additionalProperties":false,"properties":{"name":{"type":"string","maxLength":193}}})));
    let list = settings.clone();
    let search_scope=scope.clone();
    handlers.register("desktop_mcp_tool_search", move |args| {
        if args.keys().any(|key| !matches!(key.as_str(), "query" | "server" | "limit")) {
            return Ok(ToolCallResult::tool_error("Invalid extension search"));
        }
        let Some(query) = args.get("query").and_then(Value::as_str) else {
            return Ok(ToolCallResult::tool_error("Invalid extension search"));
        };
        let server = match args.get("server") {
            None => None,
            Some(Value::String(value)) => Some(value.as_str()),
            _ => return Ok(ToolCallResult::tool_error("Invalid extension search")),
        };
        let limit = match args.get("limit") {
            None => 10,
            Some(value) => match value.as_u64() {
                Some(value @ 1..=100) => value as usize,
                _ => return Ok(ToolCallResult::tool_error("Invalid extension search")),
            },
        };
        Ok(match search_scope.current_registry(&list) {
            Ok(registry) => match registry.search_cached(query, server, limit) {
                Ok(value) => ToolCallResult::text(value.to_string()),
                Err(error) => ToolCallResult::tool_error(error.to_string()),
            },
            Err(_) => ToolCallResult::tool_error("Local extension configuration unavailable"),
        })
    });
    // Tool calls reuse an idle session of the same exact server. The pool
    // lives with the route scope; dropping it closes every idle child.
    handlers.register("desktop_mcp_tool_call", move |args| {
        let Some(name) = args.get("name").and_then(Value::as_str) else {
            return Ok(ToolCallResult::tool_error("An approved tool name is required"));
        };
        let empty = serde_json::Map::new();
        let arguments = match args.get("arguments") {
            None => &empty,
            Some(Value::Object(map)) => map,
            _ => return Ok(ToolCallResult::tool_error("Expected an arguments object")),
        };
        if args.keys().any(|k| !matches!(k.as_str(), "name" | "arguments")) || name.len() > 193 {
            return Ok(ToolCallResult::tool_error("Unexpected extension input"));
        }
        Ok(match scope.call(&settings, name, arguments, None) {
            Ok(value) => {
                // Third-party content is data. It cannot register tools or
                // trigger another action, and resources are never auto-read.
                let mut answer = ToolCallResult::text(value.to_string());
                answer.is_error = value.get("isError").and_then(Value::as_bool).unwrap_or(false);
                answer
            }
            Err(error) => ToolCallResult::tool_error(error.to_string()),
        })
    });
    catalog.push(ToolDefinition::new("desktop_mcp_tool_search", Some("Search cached metadata for locally approved extension tools without contacting upstream servers.".into()),
        json!({"type":"object","required":["query"],"additionalProperties":false,"properties":{
            "query":{"type":"string","minLength":1,"maxLength":1024},
            "server":{"type":"string","maxLength":64},
            "limit":{"type":"integer","minimum":1,"maximum":100}}})));
    catalog.push(ToolDefinition::new("desktop_mcp_tool_call", Some("Call one locally approved extension operation.".into()),
        json!({"type":"object","additionalProperties":false,"required":["name"],"properties":{
            "name":{"type":"string","maxLength":193},"arguments":{"type":"object"}}})));
    Ok(())
}

#[cfg(test)]
mod connection_tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{Ipv4Addr, TcpListener};

    #[test]
    fn result_cache_request_scope_is_reentrant_thread_local_and_unwind_safe(){
        let live=LiveExtensionRegistry::new(
            Registry::parse(br#"{"version":1,"servers":{}}"#).unwrap(),
            SessionPool::new(),StatusTracker::new());
        let outer=live.cache_request([1;32],2).unwrap();
        let inner=live.cache_request([2;32],3).unwrap();
        assert!(authenticated_cache().is_none());
        with_authenticated_cache(Some(outer),||{
            assert!(authenticated_cache().is_some());
            with_authenticated_cache(None,||assert!(authenticated_cache().is_none()));
            let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
                with_authenticated_cache(Some(inner),||{
                    assert!(authenticated_cache().is_some());
                    with_authenticated_cache(None,||panic!("fixture unwind"));
                });
            }));
            assert!(result.is_err());
            assert!(authenticated_cache().is_some());
            assert!(std::thread::spawn(||authenticated_cache().is_none()).join().unwrap());
        });
        assert!(authenticated_cache().is_none());
    }

    #[test]
    fn cli_refresh_check_tests_approved_server_and_refuses_unapproved_or_disabled() {
        let dir = crate::test_state_base().join(format!(
            "ext-cli-check-{}",
            agent_bridge_missions::operator::random_token_hex(8)
        ));
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let settings = dir.join("settings");
        agent_bridge_lifecycle::initialize_operator_settings(&settings).unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let srv = std::thread::spawn(move || {
            for _ in 0..2 {
                let Ok((mut stream, _)) = listener.accept() else { break };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut len = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some((k, v)) = line.split_once(':') {
                        if k.eq_ignore_ascii_case("content-length") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                    }
                }
                let mut body = vec![0u8; len];
                reader.read_exact(&mut body).unwrap();
                let req: Value = serde_json::from_slice(&body).unwrap();
                let id = req["id"].clone();
                let resp = match req["method"].as_str().unwrap_or("") {
                    "server/discover" => json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": {
                            "resultType": "complete",
                            "supportedVersions": ["2026-07-28"],
                            "capabilities": {"tools": {}},
                            "ttlMs": 0, "cacheScope": "private"
                        }
                    }),
                    "tools/list" => json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": {
                            "resultType": "complete", "ttlMs": 0, "cacheScope": "private",
                            "tools": [{"name": "get_item", "inputSchema": {"type": "object"}}]
                        }
                    }),
                    _ => json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "unexpected"}}),
                };
                let text = resp.to_string();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                    text.len()
                )
                .unwrap();
            }
        });

        crate::write_private(
            settings.join("extensions.json"),
            serde_json::to_vec(&json!({
                "version": 1,
                "servers": {
                    "approved_local": {
                        "endpoint": format!("http://127.0.0.1:{port}/mcp"),
                        "tools": {}
                    }
                }
            }))
            .unwrap(),
        );

        assert!(refresh_check(&settings, "unapproved").is_err());
        refresh_check(&settings, "approved_local").expect("approved server connection test");
        srv.join().unwrap();
    }

    #[test]
    fn extension_scope_status_snapshot_tracks_tests_without_leaking_secrets() {
        let dir = crate::test_state_base().join(format!(
            "ext-scope-status-{}",
            agent_bridge_missions::operator::random_token_hex(8)
        ));
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let settings = dir.join("settings");
        agent_bridge_lifecycle::initialize_operator_settings(&settings).unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let srv = std::thread::spawn(move || {
            for _ in 0..2 {
                let Ok((mut stream, _)) = listener.accept() else { break };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut len = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some((k, v)) = line.split_once(':') {
                        if k.eq_ignore_ascii_case("content-length") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                    }
                }
                let mut body = vec![0u8; len];
                reader.read_exact(&mut body).unwrap();
                let req: Value = serde_json::from_slice(&body).unwrap();
                let id = req["id"].clone();
                let resp = match req["method"].as_str().unwrap_or("") {
                    "server/discover" => json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": {
                            "resultType": "complete",
                            "supportedVersions": ["2026-07-28"],
                            "capabilities": {"tools": {}},
                            "ttlMs": 0, "cacheScope": "private"
                        }
                    }),
                    "tools/list" => json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": {
                            "resultType": "complete", "ttlMs": 0, "cacheScope": "private",
                            "tools": [{"name": "get_item", "inputSchema": {"type": "object"}}]
                        }
                    }),
                    _ => json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "unexpected"}}),
                };
                let text = resp.to_string();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                    text.len()
                )
                .unwrap();
            }
        });

        crate::write_private(
            settings.join("extensions.json"),
            serde_json::to_vec(&json!({
                "version": 1,
                "servers": {
                    "approved_local": {
                        "endpoint": format!("http://127.0.0.1:{port}/mcp"),
                        "tools": {}
                    }
                }
            }))
            .unwrap(),
        );

        let scope = ExtensionScope::data_only();
        let before = scope.status_snapshot(&settings);
        assert_eq!(before["servers"][0]["server"], "approved_local");
        assert_eq!(before["servers"][0]["state"], "idle");

        let report = test_connection_from_operator_ui(&settings, "approved_local", Some(&scope)).unwrap();
        srv.join().unwrap();
        assert_eq!(report["ok"], true);

        let after = scope.status_snapshot(&settings);
        assert!(matches!(after["servers"][0]["state"].as_str(), Some("ready" | "slow")));
        let serialized = after.to_string();
        assert!(!serialized.contains("127.0.0.1"));
        assert!(!serialized.contains(&format!("{port}")));
    }

    #[test]
    fn cli_reload_validates_config_and_refuses_invalid_extensions_json() {
        let dir = crate::test_state_base().join(format!(
            "ext-cli-reload-{}",
            agent_bridge_missions::operator::random_token_hex(8)
        ));
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let settings = dir.join("settings");
        agent_bridge_lifecycle::initialize_operator_settings(&settings).unwrap();

        crate::write_private(
            settings.join("extensions.json"),
            serde_json::to_vec(&json!({
                "version": 1,
                "servers": {
                    "valid_srv": {
                        "endpoint": "https://mcp.example.invalid/mcp",
                        "tools": {}
                    }
                }
            }))
            .unwrap(),
        );
        reload_cli(&settings).expect("valid extensions.json must validate");

        crate::write_private(settings.join("extensions.json"), b"{invalid json");
        assert!(reload_cli(&settings).is_err());
    }

    #[test]
    fn operator_ui_probe_uses_admitted_live_generation_and_cancels_on_revocation() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};

        let dir = crate::test_state_base().join(format!(
            "ext-ui-live-probe-{}",
            agent_bridge_missions::operator::random_token_hex(8)
        ));
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let settings = dir.join("settings");
        agent_bridge_lifecycle::initialize_operator_settings(&settings).unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stalled_in_list = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let stalled_srv = Arc::clone(&stalled_in_list);
        let stop_srv = Arc::clone(&stop);

        let srv = std::thread::spawn(move || {
            let mut held = Vec::new();
            let mut list_count = 0usize;
            for _ in 0..8 {
                if stop_srv.load(Ordering::Acquire) {
                    break;
                }
                let Ok((mut stream, _)) = listener.accept() else { break };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut len = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some((k, v)) = line.split_once(':') {
                        if k.eq_ignore_ascii_case("content-length") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                    }
                }
                if len == 0 {
                    continue;
                }
                let mut body = vec![0u8; len];
                if reader.read_exact(&mut body).is_err() {
                    continue;
                }
                let req: Value = serde_json::from_slice(&body).unwrap();
                let id = req["id"].clone();
                let method = req["method"].as_str().unwrap_or("");
                assert_ne!(method, "tools/call", "probe must never invoke tools/call");
                if method == "tools/list" {
                    list_count += 1;
                    if list_count >= 2 {
                        stalled_srv.store(true, Ordering::Release);
                        held.push((stream, reader));
                        while !stop_srv.load(Ordering::Acquire) {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        break;
                    }
                }
                let resp = match method {
                    "server/discover" => json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": {
                            "resultType": "complete",
                            "supportedVersions": ["2026-07-28"],
                            "capabilities": {"tools": {}},
                            "ttlMs": 0, "cacheScope": "private"
                        }
                    }),
                    "tools/list" => json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": {
                            "resultType": "complete", "ttlMs": 0, "cacheScope": "private",
                            "tools": [{"name": "get_item", "inputSchema": {"type": "object"}}]
                        }
                    }),
                    _ => json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "unexpected"}}),
                };
                let text = resp.to_string();
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                    text.len()
                );
            }
            drop(held);
        });

        crate::write_private(
            settings.join("extensions.json"),
            serde_json::to_vec(&json!({
                "version": 1,
                "servers": {
                    "approved_local": {
                        "endpoint": format!("http://127.0.0.1:{port}/mcp"),
                        "tools": {}
                    }
                }
            }))
            .unwrap(),
        );

        let scope = ExtensionScope::data_only();
        let _live = scope.bind_live(&settings).unwrap();

        // First probe succeeds cleanly on generation 1.
        let ok = test_connection_from_operator_ui(&settings, "approved_local", Some(&scope)).unwrap();
        assert_eq!(ok["ok"], true);
        assert_eq!(ok["generation"], 1);
        assert!(ok["config_sha256"].as_str().is_some());
        assert_eq!(scope.status_snapshot(&settings)["servers"][0]["state"], "ready");

        // Second probe stalls on tools/list; concurrent operator disable cancels it immediately.
        let sub = admin::submit(
            &settings,
            json!({"action": "disable", "name": "approved_local"})
                .as_object()
                .unwrap(),
        )
        .unwrap();
        let disable_id = sub["request_id"].as_str().unwrap().to_owned();

        let started = Instant::now();
        let probe_err = std::thread::scope(|s| {
            let h = s.spawn(|| test_connection_from_operator_ui(&settings, "approved_local", Some(&scope)));
            let deadline = Instant::now() + Duration::from_secs(5);
            while !stalled_in_list.load(Ordering::Acquire) {
                assert!(Instant::now() < deadline, "operator probe did not stall on tools/list");
                std::thread::sleep(Duration::from_millis(10));
            }
            let decision = decide_from_operator_ui(&UiOAuthOwner::default(), &settings, &disable_id, true).unwrap();
            assert_eq!(decision["decision"], "approved");
            h.join().unwrap().unwrap_err()
        });
        assert!(started.elapsed() < Duration::from_secs(3), "operator probe cancellation took {:?}", started.elapsed());
        assert!(probe_err.to_string().contains("cancelled due to revocation"), "{probe_err}");

        let snap = scope.status_snapshot(&settings);
        assert_eq!(snap["servers"][0]["enabled"], false);
        assert_eq!(snap["servers"][0]["state"], "disabled");
        assert!(snap["servers"][0]["last_latency_ms"].is_null());
        assert!(test_connection_from_operator_ui(&settings, "approved_local", Some(&scope)).is_err());

        stop.store(true, Ordering::Release);
        srv.join().unwrap();
    }
}