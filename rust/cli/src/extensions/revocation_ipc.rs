//! Cross-process owner-private revocation channel for backends sharing one settings root.
//! Uses OS-locked peer liveness markers and MAC-authenticated atomic JSON files
//! inside `<settings>/.extensions-peers/`, with zero network listeners.

use agent_bridge_extensions::config_sha256;
use agent_bridge_lifecycle::private_store::{ensure_private_dir, verify_private_dir};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const PEERS_DIR: &str = ".extensions-peers";
const REQUEST_FILE: &str = "request.json";
const MAX_PEER_FILE_BYTES: usize = 4096;
const MAX_LIVE_PEERS: usize = 32;
pub(super) const DEFAULT_ACK_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Clone, Debug, Default, Serialize)]
pub(super) struct RevocationAckReceipt {
    pub journal_revision: u64,
    pub local_views_acknowledged: usize,
    pub remote_backends_acknowledged: usize,
    pub cancelled_in_flight: usize,
    pub closed_idle_sessions: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerRegistration {
    version: u8,
    peer_id: String,
    settings_sha256: String,
    pid: u32,
    ack_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationRequest {
    version: u8,
    action: String,
    settings_sha256: String,
    request_nonce: String,
    journal_revision: u64,
    state_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerAck {
    version: u8,
    peer_id: String,
    settings_sha256: String,
    request_nonce: String,
    journal_revision: u64,
    state_hash: String,
    ok: bool,
    views_reconciled: usize,
    cancelled_in_flight: usize,
    closed_idle_sessions: usize,
    mac: String,
}

fn refused(msg: &'static str) -> io::Error {
    io::Error::other(msg)
}

fn settings_digest(identity: &Path) -> String {
    config_sha256(identity.to_string_lossy().as_bytes())
}

fn random_hex(byte_len: usize) -> io::Result<String> {
    let mut bytes = vec![0u8; byte_len];
    getrandom::fill(&mut bytes).map_err(|_| refused("System randomness unavailable"))?;
    let mut out = String::with_capacity(byte_len * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    Ok(out)
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[allow(clippy::too_many_arguments)]
fn ack_mac(
    ack_key: &str,
    peer_id: &str,
    settings_sha256: &str,
    request_nonce: &str,
    journal_revision: u64,
    state_hash: &str,
    ok: bool,
    views_reconciled: usize,
    cancelled_in_flight: usize,
    closed_idle_sessions: usize,
) -> String {
    let payload = format!(
        "agent-bridge/revocation-ack/v1\0{peer_id}\0{settings_sha256}\0{request_nonce}\0{journal_revision}\0{state_hash}\0{ok}\0{views_reconciled}\0{cancelled_in_flight}\0{closed_idle_sessions}\0{ack_key}"
    );
    config_sha256(payload.as_bytes())
}

fn peer_json_name(peer_id: &str) -> String {
    format!("peer-{peer_id}.json")
}

fn peer_lock_name(peer_id: &str) -> String {
    format!("peer-{peer_id}.lock")
}

fn peer_ack_name(peer_id: &str) -> String {
    format!("peer-{peer_id}.ack.json")
}

fn parse_peer_stem(name: &str, suffix: &str) -> Option<String> {
    let stem = name.strip_prefix("peer-")?.strip_suffix(suffix)?;
    is_hex(stem, 32).then(|| stem.to_owned())
}

fn is_valid_staging_name(name: &str) -> bool {
    let Some((base, rest)) = name.split_once(".tmp-") else {
        return false;
    };
    let valid_base = base == REQUEST_FILE
        || parse_peer_stem(base, ".json").is_some()
        || parse_peer_stem(base, ".ack.json").is_some();
    if !valid_base {
        return false;
    }
    let Some((nonce, pid)) = rest.split_once('-') else {
        return false;
    };
    is_hex(nonce, 16) && !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit())
}

fn open_peer_lock_exclusive(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    super::admin::apply_private_open_options(&mut options);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Disallow FILE_SHARE_DELETE so a live peer lock cannot be unlinked.
        options.share_mode(0x1 | 0x2);
    }
    let file = options.open(path)?;
    if let Err(err) = super::admin::check_private_handle(&file) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(err);
    }
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => {
            drop(file);
            Err(refused("Peer lock already contended"))
        }
        Err(TryLockError::Error(err)) => {
            drop(file);
            let _ = fs::remove_file(path);
            Err(err)
        }
    }
}

fn probe_peer_lock(path: &Path) -> io::Result<Option<File>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(refused("Unsafe peer lock file"));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    super::admin::apply_private_open_options(&mut options);
    let file = options.open(path)?;
    super::admin::check_private_handle(&file)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(err)) => Err(err),
    }
}

fn verify_existing_private(path: &Path) -> io::Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_PEER_FILE_BYTES as u64 {
        return Err(refused("Unsafe peer IPC file"));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    super::admin::apply_private_open_options(&mut options);
    let file = options.open(path)?;
    super::admin::check_private_handle(&file)
}

fn write_private_atomic(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > MAX_PEER_FILE_BYTES {
        return Err(refused("Peer IPC payload too large"));
    }
    let target = dir.join(name);
    verify_existing_private(&target)?;
    let nonce = random_hex(8)?;
    let stage = dir.join(format!("{name}.tmp-{nonce}-{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    super::admin::apply_private_open_options(&mut options);
    let mut file = options.open(&stage)?;
    if let Err(err) = super::admin::check_private_handle(&file) {
        drop(file);
        let _ = fs::remove_file(&stage);
        return Err(err);
    }
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&stage, &target)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&stage);
    }
    result
}

fn read_private_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_PEER_FILE_BYTES as u64 {
        return Err(refused("Unsafe peer IPC file"));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    super::admin::apply_private_open_options(&mut options);
    let file = options.open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() > MAX_PEER_FILE_BYTES as u64 {
        return Err(refused("Unsafe peer IPC file"));
    }
    super::admin::check_private_handle(&file)?;
    let mut bytes = Vec::new();
    file.take(MAX_PEER_FILE_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PEER_FILE_BYTES {
        return Err(refused("Peer IPC file exceeds limit"));
    }
    Ok(bytes)
}

static PEERS: Mutex<BTreeMap<PathBuf, Weak<PeerLease>>> = Mutex::new(BTreeMap::new());

pub(super) struct PeerLease {
    identity: PathBuf,
    peers_dir: PathBuf,
    peer_id: String,
    stop: Arc<(Mutex<bool>, Condvar)>,
    lock_file: Mutex<Option<File>>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for PeerLease {
    fn drop(&mut self) {
        {
            let (lock, cvar) = &*self.stop;
            let mut stopped = lock.lock().unwrap_or_else(|p| p.into_inner());
            *stopped = true;
            cvar.notify_all();
        }
        if let Some(handle) = self.thread.lock().unwrap_or_else(|p| p.into_inner()).take() {
            if handle.thread().id() != std::thread::current().id() {
                let _ = handle.join();
            }
        }
        let _ = fs::remove_file(self.peers_dir.join(peer_ack_name(&self.peer_id)));
        let _ = fs::remove_file(self.peers_dir.join(peer_json_name(&self.peer_id)));
        let lock_file = self.lock_file.lock().unwrap_or_else(|p| p.into_inner()).take();
        drop(lock_file);
        let _ = fs::remove_file(self.peers_dir.join(peer_lock_name(&self.peer_id)));
        let mut peers = PEERS.lock().unwrap_or_else(|p| p.into_inner());
        if peers.get(&self.identity).is_some_and(|w| w.strong_count() == 0) {
            peers.remove(&self.identity);
        }
    }
}

pub(super) fn acquire_peer_lease(settings: &Path, identity: &Path) -> io::Result<Arc<PeerLease>> {
    let mut peers = PEERS.lock().unwrap_or_else(|p| p.into_inner());
    peers.retain(|_, w| w.strong_count() > 0);
    if let Some(existing) = peers.get(identity).and_then(Weak::upgrade) {
        return Ok(existing);
    }

    let peers_dir = ensure_private_dir(&settings.join(PEERS_DIR))
        .map_err(|_| refused("Private peer directory unavailable"))?;
    let peer_id = random_hex(16)?;
    let ack_key = random_hex(32)?;
    let expected_settings_sha256 = settings_digest(identity);
    let lock_path = peers_dir.join(peer_lock_name(&peer_id));
    let lock_file = open_peer_lock_exclusive(&lock_path)?;

    let registration = PeerRegistration {
        version: 1,
        peer_id: peer_id.clone(),
        settings_sha256: expected_settings_sha256.clone(),
        pid: std::process::id(),
        ack_key: ack_key.clone(),
    };
    let reg_bytes = serde_json::to_vec(&registration)
        .map_err(|_| refused("Cannot encode peer registration"))?;
    if let Err(err) = write_private_atomic(&peers_dir, &peer_json_name(&peer_id), &reg_bytes) {
        drop(lock_file);
        let _ = fs::remove_file(&lock_path);
        return Err(err);
    }

    let stop = Arc::new((Mutex::new(false), Condvar::new()));
    let w_settings = settings.to_path_buf();
    let w_identity = identity.to_path_buf();
    let w_peers_dir = peers_dir.clone();
    let w_peer_id = peer_id.clone();
    let w_stop = Arc::clone(&stop);

    let handle = match std::thread::Builder::new()
        .name("ext-revocation-watch".to_owned())
        .spawn(move || {
            watcher_loop(
                &w_settings,
                &w_identity,
                &w_peers_dir,
                &w_peer_id,
                &expected_settings_sha256,
                &ack_key,
                &w_stop,
            );
        }) {
        Ok(handle) => handle,
        Err(err) => {
            let _ = fs::remove_file(peers_dir.join(peer_json_name(&peer_id)));
            drop(lock_file);
            let _ = fs::remove_file(&lock_path);
            return Err(err);
        }
    };

    let lease = Arc::new(PeerLease {
        identity: identity.to_path_buf(),
        peers_dir,
        peer_id,
        stop,
        lock_file: Mutex::new(Some(lock_file)),
        thread: Mutex::new(Some(handle)),
    });
    peers.insert(identity.to_path_buf(), Arc::downgrade(&lease));
    Ok(lease)
}

fn watcher_loop(
    settings: &Path,
    identity: &Path,
    peers_dir: &Path,
    peer_id: &str,
    expected_settings_sha256: &str,
    ack_key: &str,
    stop: &Arc<(Mutex<bool>, Condvar)>,
) {
    let mut last_handled_nonce: Option<String> = None;
    let request_path = peers_dir.join(REQUEST_FILE);
    let ack_name = peer_ack_name(peer_id);

    loop {
        {
            let (lock, cvar) = &**stop;
            let guard = lock.lock().unwrap_or_else(|p| p.into_inner());
            if *guard {
                break;
            }
            let (guard, _) = cvar
                .wait_timeout(guard, POLL_INTERVAL)
                .unwrap_or_else(|p| p.into_inner());
            if *guard {
                break;
            }
        }

        let bytes = match read_private_bounded(&request_path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => continue,
        };
        let Ok(req) = serde_json::from_slice::<RevocationRequest>(&bytes) else {
            continue;
        };
        if req.version != 1
            || req.action != "restrict"
            || req.settings_sha256 != expected_settings_sha256
            || !is_hex(&req.request_nonce, 64)
            || !is_hex(&req.state_hash, 64)
        {
            continue;
        }
        if last_handled_nonce.as_deref() == Some(req.request_nonce.as_str()) {
            continue;
        }

        let result = super::reconcile_from_disk_for_peer(
            settings,
            identity,
            req.journal_revision,
            &req.state_hash,
        );
        let (ok, views_reconciled, cancelled_in_flight, closed_idle_sessions) = match result {
            Ok((views, cancelled, closed)) => (true, views, cancelled, closed),
            Err(_) => (false, 0, 0, 0),
        };
        let mac = ack_mac(
            ack_key,
            peer_id,
            expected_settings_sha256,
            &req.request_nonce,
            req.journal_revision,
            &req.state_hash,
            ok,
            views_reconciled,
            cancelled_in_flight,
            closed_idle_sessions,
        );
        let ack = PeerAck {
            version: 1,
            peer_id: peer_id.to_owned(),
            settings_sha256: expected_settings_sha256.to_owned(),
            request_nonce: req.request_nonce.clone(),
            journal_revision: req.journal_revision,
            state_hash: req.state_hash,
            ok,
            views_reconciled,
            cancelled_in_flight,
            closed_idle_sessions,
            mac,
        };
        if let Ok(ack_bytes) = serde_json::to_vec(&ack) {
            let _ = write_private_atomic(peers_dir, &ack_name, &ack_bytes);
        }
        last_handled_nonce = Some(req.request_nonce);
    }
}

fn own_peer_id(identity: &Path) -> Option<String> {
    let peers = PEERS.lock().unwrap_or_else(|p| p.into_inner());
    peers
        .get(identity)
        .and_then(Weak::upgrade)
        .map(|lease| lease.peer_id.clone())
}

fn cleanup_dead_peer(peers_dir: &Path, peer_id: &str, lock_file: File) {
    let _ = fs::remove_file(peers_dir.join(peer_ack_name(peer_id)));
    let _ = fs::remove_file(peers_dir.join(peer_json_name(peer_id)));
    drop(lock_file);
    let _ = fs::remove_file(peers_dir.join(peer_lock_name(peer_id)));
}

pub(super) fn notify_and_wait_peers(
    settings: &Path,
    identity: &Path,
    journal_revision: u64,
    state_hash: &str,
    timeout: Duration,
) -> io::Result<(usize, usize, usize)> {
    let peers_dir = settings.join(PEERS_DIR);
    match fs::symlink_metadata(&peers_dir) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok((0, 0, 0)),
        Err(err) => return Err(err),
        Ok(_) => {}
    }
    let peers_dir = verify_private_dir(&peers_dir)
        .map_err(|_| refused("Unsafe private peer directory"))?;

    let expected_settings_sha256 = settings_digest(identity);
    let self_id = own_peer_id(identity);
    let mut lock_ids = BTreeSet::new();
    let mut json_ids = BTreeSet::new();

    for entry in fs::read_dir(&peers_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            return Err(refused("Unexpected non-UTF8 entry in private peer directory"));
        };
        let path = entry.path();
        if is_valid_staging_name(name) {
            match verify_existing_private(&path) {
                Ok(()) => continue,
                Err(err) => return Err(err),
            }
        }
        let meta = fs::symlink_metadata(&path)?;
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err(refused("Unexpected non-file entry in private peer directory"));
        }
        if name == REQUEST_FILE {
            verify_existing_private(&path)?;
            continue;
        }
        if let Some(id) = parse_peer_stem(name, ".lock") {
            lock_ids.insert(id);
        } else if let Some(id) = parse_peer_stem(name, ".json") {
            json_ids.insert(id);
        } else if parse_peer_stem(name, ".ack.json").is_some() {
            verify_existing_private(&path)?;
        } else {
            return Err(refused("Unknown file in private peer directory"));
        }
    }

    if let Some(orphan) = json_ids.difference(&lock_ids).next() {
        let _ = orphan;
        return Err(refused("Orphaned peer registration without OS lock"));
    }

    let mut live_peers: Vec<PeerRegistration> = Vec::new();
    for peer_id in lock_ids {
        if self_id.as_deref() == Some(peer_id.as_str()) {
            continue;
        }
        let lock_path = peers_dir.join(peer_lock_name(&peer_id));
        match probe_peer_lock(&lock_path)? {
            Some(dead_lock) => {
                cleanup_dead_peer(&peers_dir, &peer_id, dead_lock);
            }
            None => {
                let reg_bytes = read_private_bounded(&peers_dir.join(peer_json_name(&peer_id)))?;
                let reg: PeerRegistration = serde_json::from_slice(&reg_bytes)
                    .map_err(|_| refused("Invalid peer registration"))?;
                if reg.version != 1
                    || reg.peer_id != peer_id
                    || reg.settings_sha256 != expected_settings_sha256
                    || reg.pid == 0
                    || !is_hex(&reg.ack_key, 64)
                {
                    return Err(refused("Mismatched or invalid peer registration"));
                }
                live_peers.push(reg);
            }
        }
    }

    if live_peers.len() > MAX_LIVE_PEERS {
        return Err(refused("Too many attached backend peers"));
    }
    if live_peers.is_empty() {
        let _ = fs::remove_file(peers_dir.join(REQUEST_FILE));
        return Ok((0, 0, 0));
    }

    let request_nonce = random_hex(32)?;
    let request = RevocationRequest {
        version: 1,
        action: "restrict".to_owned(),
        settings_sha256: expected_settings_sha256.clone(),
        request_nonce: request_nonce.clone(),
        journal_revision,
        state_hash: state_hash.to_owned(),
    };
    let req_bytes = serde_json::to_vec(&request)
        .map_err(|_| refused("Cannot encode revocation request"))?;
    write_private_atomic(&peers_dir, REQUEST_FILE, &req_bytes)?;

    let deadline = Instant::now() + timeout;
    let mut pending = live_peers;
    let mut remote_ack = 0usize;
    let mut cancelled_in_flight = 0usize;
    let mut closed_idle_sessions = 0usize;

    loop {
        let mut still_pending = Vec::with_capacity(pending.len());
        for peer in pending {
            let ack_path = peers_dir.join(peer_ack_name(&peer.peer_id));
            let matched = match read_private_bounded(&ack_path) {
                Ok(bytes) => match serde_json::from_slice::<PeerAck>(&bytes) {
                    Ok(ack)
                        if ack.version == 1
                            && ack.peer_id == peer.peer_id
                            && ack.settings_sha256 == expected_settings_sha256
                            && ack.request_nonce == request_nonce
                            && ack.journal_revision == journal_revision
                            && ack.state_hash == state_hash =>
                    {
                        let expected_mac = ack_mac(
                            &peer.ack_key,
                            &peer.peer_id,
                            &expected_settings_sha256,
                            &request_nonce,
                            journal_revision,
                            state_hash,
                            ack.ok,
                            ack.views_reconciled,
                            ack.cancelled_in_flight,
                            ack.closed_idle_sessions,
                        );
                        if !constant_time_eq(ack.mac.as_bytes(), expected_mac.as_bytes()) {
                            return Err(refused("Peer acknowledgement MAC verification failed"));
                        }
                        if !ack.ok {
                            return Err(refused(
                                "Attached backend failed to reconcile extension revocation",
                            ));
                        }
                        remote_ack += 1;
                        cancelled_in_flight += ack.cancelled_in_flight;
                        closed_idle_sessions += ack.closed_idle_sessions;
                        true
                    }
                    _ => false,
                },
                Err(err) if err.kind() == io::ErrorKind::NotFound => false,
                Err(_) => false,
            };
            if matched {
                continue;
            }
            let lock_path = peers_dir.join(peer_lock_name(&peer.peer_id));
            match probe_peer_lock(&lock_path) {
                Ok(Some(dead_lock)) => {
                    cleanup_dead_peer(&peers_dir, &peer.peer_id, dead_lock);
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    let _ = fs::remove_file(peers_dir.join(peer_ack_name(&peer.peer_id)));
                    let _ = fs::remove_file(peers_dir.join(peer_json_name(&peer.peer_id)));
                }
                Ok(None) => still_pending.push(peer),
                Err(err) => return Err(err),
            }
        }
        pending = still_pending;
        if pending.is_empty() {
            let _ = fs::remove_file(peers_dir.join(REQUEST_FILE));
            return Ok((remote_ack, cancelled_in_flight, closed_idle_sessions));
        }
        if Instant::now() >= deadline {
            return Err(refused(
                "Attached backend did not acknowledge local extension revocation",
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}
