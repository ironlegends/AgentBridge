use super::*;
use std::sync::atomic::AtomicUsize;

static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let n = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = crate::test_state_base().join(format!(
            "ab-audit-history-{label}-{}-{n}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn boot_hex(seed: u8) -> String {
    format!("{seed:02x}").repeat(16)
}

fn session_hex(seed: u8) -> String {
    format!("{seed:02x}").repeat(16)
}

fn hash_hex(seed: u8) -> String {
    format!("{seed:02x}").repeat(32)
}

fn sample_mcp_record(ts_ms: u64, seq: u64, boot: u8, session: u8, tool: Option<&str>) -> PersistedAuditRecord {
    PersistedAuditRecord::from_fields(
        ts_ms,
        seq,
        &boot_hex(boot),
        Some(&session_hex(session)),
        Some("gemini"),
        Some(&hash_hex(0xab)),
        Some(&hash_hex(0xcd)),
        if tool.is_some() { "tools/call" } else { "ping" },
        tool,
        "success",
        Some(200),
        None,
        12,
    )
}

#[test]
fn audit_history_persists_and_survives_restart() {
    let temp = TempDir::new("restart");
    let dir = temp.path().join("history");
    let clock_ms = Arc::new(AtomicU64::new(1_700_000_000_000));
    let clock_reader = Arc::clone(&clock_ms);
    let config = AuditHistoryConfig {
        clock: Some(Arc::new(move || clock_reader.load(Ordering::Relaxed))),
        ..AuditHistoryConfig::default()
    };

    {
        let sink = AuditHistorySink::open(&dir, config.clone()).unwrap();
        sink.enqueue(sample_mcp_record(1_700_000_000_001, 1, 1, 0x11, None));
        sink.enqueue(sample_mcp_record(
            1_700_000_000_002,
            2,
            1,
            0x11,
            Some("agent_bridge_status"),
        ));
        assert!(sink.flush(Duration::from_secs(2)));
        assert!(sink.available());
        assert_eq!(sink.lost(), 0);
    }

    // Simulate restart with a new boot_id against the same private directory.
    let sink2 = AuditHistorySink::open(&dir, config).unwrap();
    sink2.enqueue(sample_mcp_record(1_700_000_000_003, 1, 2, 0x22, None));
    assert!(sink2.flush(Duration::from_secs(2)));

    let diag = sink2.query(&AuditHistoryFilter::default());
    assert!(diag.available);
    assert_eq!(diag.lost, 0);
    assert_eq!(diag.records.len(), 3);
    assert_eq!(diag.records[0].boot_id, boot_hex(2));
    assert_eq!(diag.records[0].session_id, Some(session_hex(0x22)));
    assert_eq!(diag.records[1].tool_name.as_deref(), Some("agent_bridge_status"));
    assert_eq!(diag.records[2].method, "ping");
}

#[test]
fn audit_history_rotates_and_enforces_max_segment_and_total_bytes() {
    let temp = TempDir::new("rotate");
    let dir = temp.path().join("history");
    let clock_ms = Arc::new(AtomicU64::new(1_700_000_000_000));
    let clock_reader = Arc::clone(&clock_ms);
    let config = AuditHistoryConfig {
        queue_capacity: 64,
        max_segment_bytes: 550,
        max_total_bytes: 1600,
        max_segments: 3,
        max_age: Duration::from_secs(3600),
        clock: Some(Arc::new(move || clock_reader.load(Ordering::Relaxed))),
    };

    let sink = AuditHistorySink::open(&dir, config.clone()).unwrap();
    for seq in 1..=12 {
        sink.enqueue(sample_mcp_record(
            1_700_000_000_000 + seq,
            seq,
            1,
            0x33,
            Some("agent_bridge_status"),
        ));
        assert!(sink.flush(Duration::from_secs(2)));
    }

    let segments = list_segments(&dir).unwrap();
    assert!(segments.len() <= 3, "segment count {} exceeded cap", segments.len());
    let total_bytes: u64 = segments.iter().map(|s| s.size).sum();
    assert!(total_bytes <= 1600, "total bytes {total_bytes} exceeded cap");

    let diag = sink.query(&AuditHistoryFilter::default());
    assert!(diag.available);
    assert!(!diag.records.is_empty());
    assert!(diag.records.len() < 12);
    assert_eq!(diag.records[0].sequence, 12);
}

#[test]
fn audit_history_prunes_expired_segments_and_filters_by_max_age() {
    let temp = TempDir::new("age");
    let dir = temp.path().join("history");
    let clock_ms = Arc::new(AtomicU64::new(1_700_000_000_000));
    let clock_reader = Arc::clone(&clock_ms);
    let config = AuditHistoryConfig {
        queue_capacity: 32,
        max_segment_bytes: 600,
        max_total_bytes: 100_000,
        max_segments: 32,
        max_age: Duration::from_secs(60),
        clock: Some(Arc::new(move || clock_reader.load(Ordering::Relaxed))),
    };

    let sink = AuditHistorySink::open(&dir, config.clone()).unwrap();
    sink.enqueue(sample_mcp_record(1_700_000_000_000, 1, 1, 0x44, None));
    assert!(sink.flush(Duration::from_secs(2)));
    // Advance 30s and write a newer record in a rotated segment.
    clock_ms.store(1_700_000_030_000, Ordering::Relaxed);
    sink.enqueue(sample_mcp_record(1_700_000_030_000, 2, 1, 0x44, None));
    assert!(sink.flush(Duration::from_secs(2)));
    assert_eq!(list_segments(&dir).unwrap().len(), 2);

    // Advance to +65s: first segment (ts=0s) is expired (>60s), second (ts=30s) remains.
    clock_ms.store(1_700_000_065_000, Ordering::Relaxed);
    sink.enqueue(sample_mcp_record(1_700_000_065_000, 3, 1, 0x44, None));
    assert!(sink.flush(Duration::from_secs(2)));

    let segments = list_segments(&dir).unwrap();
    assert_eq!(segments.len(), 2);
    let diag = sink.query(&AuditHistoryFilter::default());
    assert_eq!(diag.records.iter().map(|r| r.sequence).collect::<Vec<_>>(), vec![3, 2]);
}

#[test]
fn temporary_writer_contention_preserves_a_pending_batch() {
    let temp = TempDir::new("held-writer");
    let dir = private_store::ensure_private_dir(&temp.path().join("history")).unwrap();
    let held = private_store::lock_exclusive(&dir.join(LOCK_FILE_NAME), true).unwrap().unwrap();
    let (started, ready) = mpsc::sync_channel(0);
    thread::scope(|scope| {
        let directory = &dir;
        let worker = scope.spawn(move || {
            let losses = AtomicU64::new(0);
            let row = sample_mcp_record(system_unix_ms(), 1, 1, 1, Some("agent_bridge_status"));
            started.send(()).unwrap();
            let result = persist_batch(directory, &AuditHistoryConfig::default(), &[row],
                &AtomicU64::new(0), &losses, &mut 0, &mut HashMap::new());
            (result, losses.load(Ordering::Relaxed))
        });
        ready.recv().unwrap();
        thread::sleep(Duration::from_millis(400));
        drop(held);
        let (result, lost) = worker.join().unwrap();
        result.unwrap();
        assert_eq!(lost, 0);
    });
    let saved = read_history(&dir, &AuditHistoryFilter::default(), &AuditHistoryConfig::default()).unwrap();
    assert_eq!(saved.records.len(), 1);
    assert_eq!(saved.lost, 0);
}

#[test]
fn shutdown_releases_the_writer_even_if_another_process_keeps_the_file_lock() {
    let temp = TempDir::new("shutdown-lock");
    let dir = temp.path().join("history");
    let sink = AuditHistorySink::open(&dir, AuditHistoryConfig::default()).unwrap();
    let held = private_store::lock_exclusive(&dir.join(LOCK_FILE_NAME), true).unwrap().unwrap();
    sink.enqueue(sample_mcp_record(system_unix_ms(), 1, 1, 1, None));
    let (tx, rx) = mpsc::channel();
    let watcher = thread::spawn(move || { drop(sink); let _ = tx.send(()); });
    let closed_while_locked = rx.recv_timeout(Duration::from_secs(2)).is_ok();
    drop(held);
    watcher.join().unwrap();
    assert!(closed_while_locked);
}

#[test]
fn one_writer_batch_observes_both_byte_limits() {
    let temp = TempDir::new("batch-limits");
    let dir = private_store::ensure_private_dir(&temp.path().join("history")).unwrap();
    let now = system_unix_ms();
    let rows: Vec<_> = (1..=24).map(|seq| sample_mcp_record(now, seq, 1, 8, Some("agent_bridge_status"))).collect();
    let config = AuditHistoryConfig { max_segment_bytes: 1050, max_total_bytes: 2500, ..Default::default() };
    let losses = AtomicU64::new(0);
    persist_batch(&dir, &config, &rows, &AtomicU64::new(0), &losses, &mut 0, &mut HashMap::new()).unwrap();
    let segments = list_segments(&dir).unwrap();
    assert!(!segments.is_empty());
    assert!(segments.iter().all(|s| s.size <= config.max_segment_bytes));
    assert!(segments.iter().map(|s| s.size).sum::<u64>() <= config.max_total_bytes);
    assert_eq!(losses.load(Ordering::Acquire), 0);
    let retained = read_history(&dir, &AuditHistoryFilter::default(), &config).unwrap();
    assert_eq!(retained.records[0].sequence, 24);
}

#[test]
fn concurrent_writer_losses_are_added_once_across_flushes_and_restart() {
    let temp = TempDir::new("shared-losses");
    let dir = temp.path().join("history");
    let first = AuditHistorySink::open(&dir, AuditHistoryConfig::default()).unwrap();
    let second = AuditHistorySink::open(&dir, AuditHistoryConfig::default()).unwrap();
    let invalid = || {
        let mut row = sample_mcp_record(system_unix_ms(), 1, 1, 1, None);
        row.schema_version = 99;
        row
    };
    for _ in 0..3 { first.enqueue(invalid()); }
    assert!(first.flush(Duration::from_secs(2)));
    for _ in 0..5 { second.enqueue(invalid()); }
    assert!(second.flush(Duration::from_secs(2)));
    assert_eq!(second.lost(), 8);
    assert!(first.flush(Duration::from_secs(2)));
    assert_eq!(first.lost(), 8);
    drop((first, second));
    assert_eq!(read_meta(&dir).unwrap().unwrap().lost, 8);
}

#[test]
fn audit_history_nonblocking_queue_overflow_accounts_losses_and_persists_meta() {
    let temp = TempDir::new("overflow");
    let dir = temp.path().join("history");
    let validated = private_store::ensure_private_dir(&dir).unwrap();
    let lock_guard = private_store::lock_exclusive(&validated.join(LOCK_FILE_NAME), true)
        .unwrap()
        .unwrap();

    let sink = AuditHistorySink::open(
        &dir,
        AuditHistoryConfig {
            queue_capacity: 2,
            ..AuditHistoryConfig::default()
        },
    )
    .unwrap();

    // While exclusive lock is held on another handle, worker pauses on lock_exclusive.
    // Enqueue 64 records: enqueue must never block; overflow increments lost count.
    let started = Instant::now();
    for seq in 1..=64 {
        sink.enqueue(sample_mcp_record(1_700_000_000_000 + seq, seq, 1, 0x55, None));
    }
    assert!(started.elapsed() < Duration::from_millis(250));
    assert!(sink.lost() > 0, "bounded queue overflow must account losses");

    drop(lock_guard);
    assert!(sink.flush(Duration::from_secs(2)));

    let expected_lost = sink.lost();
    assert!(expected_lost > 0);
    drop(sink);

    // After restart, persisted audit-meta.json keeps the exact loss total.
    let result = read_history(&dir, &AuditHistoryFilter::default(), &AuditHistoryConfig::default()).unwrap();
    assert_eq!(result.lost, expected_lost);
}

#[test]
fn audit_history_handles_disk_outage_and_recovers_without_blocking() {
    let temp = TempDir::new("outage");
    let dir = temp.path().join("history");
    let config = AuditHistoryConfig {
        clock: Some(Arc::new(|| 1_700_000_000_500)),
        ..AuditHistoryConfig::default()
    };
    let sink = AuditHistorySink::open(&dir, config.clone()).unwrap();

    // Induce outage by replacing audit.lock with a directory after closing/removing it.
    let lock_path = dir.join(LOCK_FILE_NAME);
    fs::remove_file(&lock_path).unwrap();
    fs::create_dir(&lock_path).unwrap();

    sink.enqueue(sample_mcp_record(1_700_000_000_100, 1, 1, 0x66, None));
    sink.enqueue(sample_mcp_record(1_700_000_000_101, 2, 1, 0x66, None));
    assert!(sink.flush(Duration::from_secs(2)));
    assert!(!sink.available());
    assert!(sink.lost() >= 2);
    let lost_during_outage = sink.lost();

    // Restore directory state and verify sink recovers automatically.
    fs::remove_dir(&lock_path).unwrap();
    sink.enqueue(sample_mcp_record(1_700_000_000_200, 3, 1, 0x66, None));
    assert!(sink.flush(Duration::from_secs(2)));
    assert!(sink.available());
    assert_eq!(sink.lost(), lost_during_outage);

    let diag = sink.query(&AuditHistoryFilter::default());
    assert!(diag.available);
    assert_eq!(diag.lost, lost_during_outage);
    assert_eq!(diag.records.len(), 1);
    assert_eq!(diag.records[0].sequence, 3);
}

#[test]
fn audit_history_safe_reader_skips_corrupt_oversized_and_tampered_lines() {
    let temp = TempDir::new("corrupt");
    let dir = temp.path().join("history");
    let config = AuditHistoryConfig {
        clock: Some(Arc::new(|| 1_700_000_000_500)),
        ..AuditHistoryConfig::default()
    };
    let sink = AuditHistorySink::open(&dir, config.clone()).unwrap();
    sink.enqueue(sample_mcp_record(1_700_000_000_100, 1, 1, 0x77, None));
    assert!(sink.flush(Duration::from_secs(2)));
    drop(sink);

    // Append: (1) malformed JSON, (2) oversized line (>4096), (3) non-allowlisted raw session/method,
    // (4) unknown JSON field (deny_unknown_fields).
    let seg_path = list_segments(&dir).unwrap().into_iter().next().unwrap().path;
    let mut file = private_store::open_private_file(&seg_path, private_store::OpenMode::Append).unwrap();
    writeln!(file, "{{not-valid-json").unwrap();
    writeln!(file, "{{\"oversized\":\"{}\"}}", "x".repeat(MAX_LINE_BYTES + 64)).unwrap();
    let tampered_session = serde_json::json!({
        "schema_version": 1,
        "event_kind": "mcp_request",
        "timestamp_unix_ms": 1_700_000_000_200u64,
        "sequence": 2,
        "boot_id": boot_hex(1),
        "session_id": "raw-client-id-not-hex",
        "provider": "gemini",
        "client_id_sha256": null,
        "catalogue_sha256": null,
        "method": "ping",
        "tool_name": null,
        "outcome": "success",
        "http_status": 200,
        "error_code": null,
        "duration_ms": 1
    });
    writeln!(file, "{tampered_session}").unwrap();
    let unknown_field = serde_json::json!({
        "schema_version": 1,
        "event_kind": "mcp_request",
        "timestamp_unix_ms": 1_700_000_000_300u64,
        "sequence": 3,
        "boot_id": boot_hex(1),
        "session_id": null,
        "provider": "gemini",
        "client_id_sha256": null,
        "catalogue_sha256": null,
        "method": "ping",
        "tool_name": null,
        "outcome": "success",
        "http_status": 200,
        "error_code": null,
        "duration_ms": 1,
        "secret_payload": "must-not-parse"
    });
    writeln!(file, "{unknown_field}").unwrap();
    file.sync_all().unwrap();

    let result = read_history(&dir, &AuditHistoryFilter::default(), &config).unwrap();
    assert_eq!(result.records.len(), 1);
    assert_eq!(result.records[0].sequence, 1);
    assert_eq!(result.corrupt_lines, 4);

    let diag = read_history_diagnostics(&dir, &AuditHistoryFilter::default());
    assert_eq!(diag.lost, 4);
}

#[test]
fn audit_history_redacts_and_validates_restricted_non_mcp_events() {
    let mcp = PersistedAuditRecord::from_fields(
        1_700_000_000_000,
        1,
        &boot_hex(1),
        Some("raw-secret-client-id"),
        Some("untrusted-provider"),
        Some("not-sha256"),
        Some("also-not-sha256"),
        "private-method-name",
        Some("private-tool-name"),
        "unknown-outcome",
        Some(403),
        Some(PersistedErrorCode::Named("Bearer token=secret".to_owned())),
        5,
    );
    assert!(mcp.validate_persisted_record());
    assert_eq!(mcp.session_id, None);
    assert_eq!(mcp.provider, None);
    assert_eq!(mcp.client_id_sha256, None);
    assert_eq!(mcp.catalogue_sha256, None);
    assert_eq!(mcp.method, "other");
    assert_eq!(mcp.tool_name, None);
    assert_eq!(mcp.outcome, "http_refusal");
    assert_eq!(mcp.error_code, Some(PersistedErrorCode::Named("other".to_owned())));

    let oauth = PersistedAuditRecord::from_fields(
        1_700_000_000_010, 7, &boot_hex(2), Some("raw-oauth-client-secret"), Some("chatgpt"),
        Some(&hash_hex(0x99)), None, "oauth/token", None, "success", Some(200), None, 4,
    );
    assert!(oauth.validate_persisted_record());
    assert_eq!(oauth.event_kind, AuditEventKind::OAuth);
    assert_eq!(oauth.method, "oauth/token");
    assert_eq!(oauth.session_id, None);
    assert_eq!(oauth.outcome, "success");
    let mut forged = oauth.clone();
    forged.error_code = Some(PersistedErrorCode::Named("unlisted_demo_value".into()));
    assert!(!forged.validate_persisted_record());

    let lifecycle = PersistedAuditRecord::from_fields(
        1_700_000_000_020, 8, &boot_hex(2), None, None,
        None, None, "service/start", None, "success", None, None, 1,
    );
    assert!(lifecycle.validate_persisted_record());
    assert_eq!(lifecycle.event_kind, AuditEventKind::Lifecycle);
    assert_eq!(lifecycle.session_id, None);
}

#[test]
fn audit_history_refuses_unsafe_paths_symlinks_and_bad_permissions() {
    let temp = TempDir::new("unsafe");
    fs::create_dir_all(temp.path()).unwrap();

    assert!(AuditHistorySink::open(Path::new("relative/audit"), AuditHistoryConfig::default()).is_err());
    let traversal = temp.path().join("..").join("escape");
    assert!(AuditHistorySink::open(&traversal, AuditHistoryConfig::default()).is_err());

    // A plain pre-existing directory without owner-private ACL (Windows) or 0700 (Unix) is refused.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let open_dir = temp.path().join("world-readable");
        fs::create_dir(&open_dir).unwrap();
        fs::set_permissions(&open_dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(AuditHistorySink::open(&open_dir, AuditHistoryConfig::default()).is_err());

        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let link = temp.path().join("symlink-dir");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(AuditHistorySink::open(&link, AuditHistoryConfig::default()).is_err());
    }

    #[cfg(windows)]
    {
        // Verify private creation succeeds via CreateDirectoryW + SDDL, while an unprotected directory
        // with Everyone read access is refused.
        let private = temp.path().join("private");
        let sink = AuditHistorySink::open(&private, AuditHistoryConfig::default()).unwrap();
        drop(sink);

        let target_dir = temp.path().join("bad-acl");
        fs::create_dir(&target_dir).unwrap();
        // Grant Users read access explicitly with icacls to verify strict SDDL refusal.
        let status = std::process::Command::new("icacls")
            .arg(&target_dir)
            .args(["/grant", "*S-1-1-0:(OI)(CI)R"])
            .output()
            .unwrap();
        assert!(status.status.success());
        assert!(AuditHistorySink::open(&target_dir, AuditHistoryConfig::default()).is_err());
    }
}

#[test]
fn audit_history_concurrent_writers_serialize_cleanly() {
    let temp = TempDir::new("concurrent");
    let dir = temp.path().join("history");
    let config = AuditHistoryConfig {
        queue_capacity: 512,
        max_segment_bytes: 4096,
        max_total_bytes: 1024 * 1024,
        max_segments: 32,
        max_age: Duration::from_secs(3600),
        clock: Some(Arc::new(|| 1_700_000_000_999)),
    };

    let writers: Vec<_> = (0..4)
        .map(|_w| AuditHistorySink::open(&dir, config.clone()).unwrap())
        .collect();
    let counter = Arc::new(AtomicUsize::new(0));
    let mut threads = Vec::new();
    for (idx, sink) in writers.into_iter().enumerate() {
        let counter = Arc::clone(&counter);
        threads.push(thread::spawn(move || {
            for seq in 1..=25u64 {
                sink.enqueue(sample_mcp_record(
                    1_700_000_000_000 + (idx as u64) * 100 + seq,
                    seq,
                    (idx + 1) as u8,
                    (idx + 1) as u8,
                    Some("agent_bridge_status"),
                ));
                counter.fetch_add(1, Ordering::Relaxed);
            }
            assert!(sink.flush(Duration::from_secs(5)));
            assert_eq!(sink.lost(), 0);
        }));
    }
    for handle in threads {
        handle.join().unwrap();
    }
    assert_eq!(counter.load(Ordering::Relaxed), 100);

    let result = read_history(&dir, &AuditHistoryFilter::default(), &config).unwrap();
    assert_eq!(result.corrupt_lines, 0);
    assert_eq!(result.lost, 0);
    assert_eq!(result.records.len(), 100);
}

#[test]
fn audit_history_filter_query_supports_all_predicates_and_ordering() {
    let temp = TempDir::new("filter");
    let dir = temp.path().join("history");
    let config = AuditHistoryConfig {
        clock: Some(Arc::new(|| 1_700_000_001_000)),
        ..AuditHistoryConfig::default()
    };
    let sink = AuditHistorySink::open(&dir, config.clone()).unwrap();

    sink.enqueue(sample_mcp_record(1_700_000_000_100, 1, 1, 0x10, None));
    sink.enqueue(sample_mcp_record(
        1_700_000_000_200,
        2,
        1,
        0x20,
        Some("agent_bridge_status"),
    ));
    sink.enqueue(PersistedAuditRecord::from_fields(
        1_700_000_000_300, 3, &boot_hex(1), Some(&session_hex(0x20)), Some("chatgpt"),
        Some(&hash_hex(0xee)), None, "oauth/token", None, "http_refusal", Some(401),
        Some(PersistedErrorCode::Named("invalid_token".to_owned())), 3,
    ));
    assert!(sink.flush(Duration::from_secs(2)));

    let by_session = sink.query(&AuditHistoryFilter {
        session_id: Some(session_hex(0x20)),
        newest_first: Some(false),
        ..AuditHistoryFilter::default()
    });
    assert_eq!(by_session.records.len(), 2);
    assert_eq!(by_session.records[0].sequence, 2);
    assert_eq!(by_session.records[1].sequence, 3);

    let by_kind_error = sink.query(&AuditHistoryFilter {
        event_kind: Some(AuditEventKind::OAuth),
        error_code: Some("invalid_token".to_owned()),
        http_status: Some(401),
        outcome: Some("http_refusal".to_owned()),
        ..AuditHistoryFilter::default()
    });
    assert_eq!(by_kind_error.records.len(), 1);
    assert_eq!(by_kind_error.records[0].method, "oauth/token");

    let bounded = sink.query(&AuditHistoryFilter {
        since_unix_ms: Some(1_700_000_000_150),
        until_unix_ms: Some(1_700_000_000_250),
        tool_name: Some("agent_bridge_status".to_owned()),
        limit: Some(1),
        ..AuditHistoryFilter::default()
    });
    assert_eq!(bounded.records.len(), 1);
    assert_eq!(bounded.records[0].sequence, 2);
}

#[test]
fn audit_history_reader_bounds_memory_to_limit_across_multiple_segments() {
    let mut collector = BoundedRecordCollector::new(5, true);
    for seq in 1..=200u64 {
        let ts = 1_700_000_000_000 + ((seq * 37) % 200);
        collector.push(sample_mcp_record(ts, seq, 1, 0x12, None));
        assert!(
            collector.max_retained <= 5,
            "collector retained {} > limit 5",
            collector.max_retained
        );
    }
    let (top5, truncated) = collector.finish();
    assert!(truncated);
    assert_eq!(top5.len(), 5);
    assert!(top5.windows(2).all(|w| {
        (w[0].timestamp_unix_ms, &w[0].boot_id, w[0].sequence)
            >= (w[1].timestamp_unix_ms, &w[1].boot_id, w[1].sequence)
    }));

    let temp = TempDir::new("bounded-read");
    let dir = temp.path().join("history");
    let config = AuditHistoryConfig {
        queue_capacity: 512,
        max_segment_bytes: 4096,
        max_total_bytes: 1024 * 1024,
        max_segments: 64,
        max_age: Duration::from_secs(3600),
        clock: Some(Arc::new(|| 1_700_000_001_000)),
    };
    let sink = AuditHistorySink::open(&dir, config.clone()).unwrap();
    for i in 1..=240u64 {
        // Interleaved timestamps across multiple rotated segments.
        let ts = 1_700_000_000_000 + ((i * 53) % 240);
        sink.enqueue(sample_mcp_record(ts, i, 1, 0x13, Some("agent_bridge_status")));
    }
    assert!(sink.flush(Duration::from_secs(5)));
    assert!(list_segments(&dir).unwrap().len() >= 2);

    let newest = read_history(
        &dir,
        &AuditHistoryFilter {
            limit: Some(7),
            newest_first: Some(true),
            ..AuditHistoryFilter::default()
        },
        &config,
    )
    .unwrap();
    assert!(newest.truncated);
    assert_eq!(newest.records.len(), 7);
    assert_eq!(
        newest.records.iter().map(|r| r.timestamp_unix_ms).collect::<Vec<_>>(),
        (233..=239).rev().map(|o| 1_700_000_000_000 + o).collect::<Vec<_>>()
    );

    let oldest = read_history(
        &dir,
        &AuditHistoryFilter {
            limit: Some(7),
            newest_first: Some(false),
            ..AuditHistoryFilter::default()
        },
        &config,
    )
    .unwrap();
    assert!(oldest.truncated);
    assert_eq!(oldest.records.len(), 7);
    assert_eq!(
        oldest.records.iter().map(|r| r.timestamp_unix_ms).collect::<Vec<_>>(),
        (0..7).map(|o| 1_700_000_000_000 + o).collect::<Vec<_>>()
    );
}

#[test]
fn audit_history_reader_refuses_corrupt_schema_oversized_and_hardlinked_meta() {
    let temp = TempDir::new("meta-errors");
    let dir = temp.path().join("history");
    let config = AuditHistoryConfig {
        clock: Some(Arc::new(|| 1_700_000_000_500)),
        ..AuditHistoryConfig::default()
    };
    {
        let sink = AuditHistorySink::open(&dir, config.clone()).unwrap();
        sink.enqueue(sample_mcp_record(1_700_000_000_100, 1, 1, 0x21, None));
        assert!(sink.flush(Duration::from_secs(2)));
    }

    let meta_path = dir.join(META_FILE_NAME);
    let write_meta_raw = |bytes: &[u8]| {
        let _ = fs::remove_file(&meta_path);
        let mut f = private_store::open_private_file(&meta_path, private_store::OpenMode::CreateNew).unwrap();
        f.write_all(bytes).unwrap();
        f.sync_all().unwrap();
    };

    // 1. Corrupt JSON must return Err, never 0 lost.
    write_meta_raw(b"{corrupt-meta");
    assert!(read_history(&dir, &AuditHistoryFilter::default(), &config).is_err());
    assert!(!read_history_diagnostics(&dir, &AuditHistoryFilter::default()).available);
    assert!(AuditHistorySink::open(&dir, config.clone()).is_err());

    // 2. Unsupported schema_version must return Err.
    write_meta_raw(br#"{"schema_version":99,"lost":5}"#);
    assert!(read_history(&dir, &AuditHistoryFilter::default(), &config).is_err());
    assert!(!read_history_diagnostics(&dir, &AuditHistoryFilter::default()).available);

    // 3. Oversized metadata (> MAX_META_BYTES) must return Err.
    let oversized = vec![b' '; (MAX_META_BYTES as usize) + 64];
    write_meta_raw(&oversized);
    assert!(read_history(&dir, &AuditHistoryFilter::default(), &config).is_err());

    // 4. Hardlinked metadata (nlink == 2) must return Err.
    write_meta_raw(br#"{"schema_version":1,"lost":7}"#);
    let alias = dir.join("meta-alias.json");
    fs::hard_link(&meta_path, &alias).unwrap();
    assert!(read_history(&dir, &AuditHistoryFilter::default(), &config).is_err());
    fs::remove_file(&alias).unwrap();

    let valid = read_history(&dir, &AuditHistoryFilter::default(), &config).unwrap();
    assert_eq!(valid.lost, 7);
}

#[test]
fn audit_history_measures_enqueue_read_and_concurrent_writer_reader_contention() {
    let temp = TempDir::new("perf");
    let dir = temp.path().join("history");
    let config = AuditHistoryConfig {
        queue_capacity: 1024,
        max_segment_bytes: 16 * 1024,
        max_total_bytes: 4 * 1024 * 1024,
        max_segments: 32,
        max_age: Duration::from_secs(3600),
        clock: Some(Arc::new(|| 1_700_000_001_000)),
    };

    // Measure 200 non-blocking enqueues + flush.
    let sink = AuditHistorySink::open(&dir, config.clone()).unwrap();
    let enqueue_start = Instant::now();
    for seq in 1..=200u64 {
        sink.enqueue(sample_mcp_record(
            1_700_000_000_000 + seq,
            seq,
            1,
            0x31,
            Some("agent_bridge_status"),
        ));
    }
    let enqueue_elapsed = enqueue_start.elapsed();
    assert!(sink.flush(Duration::from_secs(5)));
    let flush_elapsed = enqueue_start.elapsed();
    assert_eq!(sink.lost(), 0);
    drop(sink);

    // Measure 4 concurrent writers + 2 concurrent readers contending on audit.lock.
    let contention_start = Instant::now();
    let mut handles = Vec::new();
    for w in 0..4u8 {
        let dir_w = dir.clone();
        let cfg_w = config.clone();
        handles.push(thread::spawn(move || {
            let writer = AuditHistorySink::open(&dir_w, cfg_w).unwrap();
            for seq in 1..=50u64 {
                writer.enqueue(sample_mcp_record(
                    1_700_000_000_500 + u64::from(w) * 100 + seq,
                    seq,
                    w + 2,
                    w + 2,
                    Some("agent_bridge_status"),
                ));
            }
            assert!(writer.flush(Duration::from_secs(10)));
            assert_eq!(writer.lost(), 0);
        }));
    }
    for _ in 0..2 {
        let dir_r = dir.clone();
        let cfg_r = config.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..10 {
                let res = read_history(
                    &dir_r,
                    &AuditHistoryFilter {
                        limit: Some(20),
                        ..AuditHistoryFilter::default()
                    },
                    &cfg_r,
                )
                .unwrap();
                assert_eq!(res.corrupt_lines, 0);
                assert!(res.records.len() <= 20);
            }
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
    let contention_elapsed = contention_start.elapsed();

    let read_start = Instant::now();
    let final_read = read_history(
        &dir,
        &AuditHistoryFilter {
            limit: Some(20),
            ..AuditHistoryFilter::default()
        },
        &config,
    )
    .unwrap();
    let read_elapsed = read_start.elapsed();
    assert_eq!(final_read.records.len(), 20);
    assert!(final_read.truncated);
    assert_eq!(final_read.corrupt_lines, 0);
    assert_eq!(final_read.lost, 0);

    eprintln!(
        "audit_history_perf: enqueue_200={:?} flush_200={:?} contention_4w_2r={:?} bounded_read_400_limit20={:?}",
        enqueue_elapsed, flush_elapsed, contention_elapsed, read_elapsed
    );
    assert!(enqueue_elapsed < Duration::from_millis(200));
    assert!(contention_elapsed < Duration::from_secs(10));
    assert!(read_elapsed < Duration::from_secs(2));
}
#[test]
fn recovery_blank_line_keeps_the_following_event() {
    let root = TempDir::new("blank");
    let dir = private_store::ensure_private_dir(&root.path().join("history")).unwrap();
    let now = system_unix_ms();
    let path = dir.join(format_segment_name(now, 0));
    let mut file = private_store::open_private_file(&path, private_store::OpenMode::CreateNew).unwrap();
    for seq in [1, 2] {
        writeln!(file, "{}", serde_json::to_string(&sample_mcp_record(now, seq, 1, 1, None)).unwrap()).unwrap();
        writeln!(file).unwrap();
    }
    drop(file);
    let result = read_history(&dir, &Default::default(), &Default::default()).unwrap();
    assert_eq!(result.records.len(), 2);
    assert_eq!(result.corrupt_lines, 0);
}

#[test]
fn recovery_torn_last_line_cannot_absorb_a_new_event() {
    let root = TempDir::new("torn");
    let dir = private_store::ensure_private_dir(&root.path().join("history")).unwrap();
    let now = system_unix_ms();
    let path = dir.join(format_segment_name(now, 0));
    let mut file = private_store::open_private_file(&path, private_store::OpenMode::CreateNew).unwrap();
    writeln!(file, "{}", serde_json::to_string(&sample_mcp_record(now, 1, 1, 1, None)).unwrap()).unwrap();
    file.write_all(b"{\"schema_").unwrap();
    drop(file);
    let sink = AuditHistorySink::open(&dir, Default::default()).unwrap();
    sink.enqueue(sample_mcp_record(now, 2, 2, 2, None));
    assert!(sink.flush(Duration::from_secs(3)));
    let result = sink.query(&Default::default());
    assert!(result.available);
    assert_eq!(result.records.len(), 2);
    assert_eq!(result.lost, 1);
    drop(sink);
    let recovered = read_history(&dir, &Default::default(), &Default::default()).unwrap();
    assert_eq!(recovered.corrupt_lines, 1);
    assert_eq!(recovered.records.len(), 2);
}

#[test]
fn recovery_expires_old_rows_on_disk_but_keeps_recent_rows_in_the_same_segment() {
    let root = TempDir::new("mixed-age");
    let dir = root.path().join("history");
    let base = system_unix_ms();
    let time = Arc::new(AtomicU64::new(base));
    let clock = Arc::clone(&time);
    let config = AuditHistoryConfig { max_age: Duration::from_secs(60),
        clock: Some(Arc::new(move || clock.load(Ordering::Acquire))), ..Default::default() };
    let sink = AuditHistorySink::open(&dir, config.clone()).unwrap();
    sink.enqueue(sample_mcp_record(base, 1, 0xee, 1, None));
    time.store(base + 30_000, Ordering::Release);
    sink.enqueue(sample_mcp_record(base + 30_000, 2, 0xcc, 1, None));
    assert!(sink.flush(Duration::from_secs(3)));
    assert_eq!(list_segments(&dir).unwrap().len(), 1);
    drop(sink);
    time.store(base + 65_000, Ordering::Release);
    let sink = AuditHistorySink::open(&dir, config).unwrap();
    assert!(sink.flush(Duration::from_secs(3)));
    let diagnostic = sink.query(&Default::default());
    assert!(diagnostic.available);
    assert_eq!(diagnostic.records.len(), 1);
    let mut physical = Vec::new();
    for part in list_segments(&dir).unwrap() { physical.extend(fs::read(part.path).unwrap()); }
    let content = String::from_utf8(physical).unwrap();
    assert!(content.contains(&boot_hex(0xcc)));
    assert!(!content.contains(&boot_hex(0xee)));
}
#[test]
fn recovery_independent_processes_keep_each_others_events_and_loss_counters() {
    const TEST: &str = "audit_history::tests::recovery_independent_processes_keep_each_others_events_and_loss_counters";
    const RUN_DIR: &str = "AB_AUDIT_PROCESS_TEST_DIR";
    const ID: &str = "AB_AUDIT_PROCESS_TEST_ID";
    if let (Some(dir), Ok(id)) = (std::env::var_os(RUN_DIR), std::env::var(ID)) {
        assert!(std::env::args().any(|arg| arg == TEST));
        let id: u8 = id.parse().unwrap();
        assert!((1..=2).contains(&id));
        let root = PathBuf::from(dir);
        let sink = AuditHistorySink::open(&root.join("history"), Default::default()).unwrap();
        fs::write(root.join(format!("ready-{id}")), []).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !root.join(format!("ready-{}", 3 - id)).is_file() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        for seq in 1..=12 {
            sink.enqueue(sample_mcp_record(system_unix_ms(), seq, id, id, None));
        }
        let mut invalid = sample_mcp_record(system_unix_ms(), 13, id, id, None);
        invalid.schema_version = u32::MAX;
        sink.enqueue(invalid);
        assert!(sink.flush(Duration::from_secs(5)));
        assert!(sink.available());
        return;
    }
    let root = TempDir::new("independent-processes");
    let mut children = Vec::new();
    for id in [1, 2] {
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", TEST, "--test-threads=1"])
            .env(RUN_DIR, root.path()).env(ID, id.to_string())
            .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000);
        }
        children.push(cmd.spawn().unwrap());
    }
    let outcomes: Vec<_> = children.into_iter().map(|child| child.wait_with_output().unwrap()).collect();
    let failures: Vec<_> = outcomes.iter().filter(|outcome| !outcome.status.success())
        .map(|outcome| format!("{}{}", String::from_utf8_lossy(&outcome.stdout), String::from_utf8_lossy(&outcome.stderr)))
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    let result = read_history(&root.path().join("history"), &Default::default(), &Default::default()).unwrap();
    assert_eq!(result.lost, 2);
    assert_eq!(result.corrupt_lines, 0);
    for id in [1, 2] {
        let mut sequences: Vec<_> = result.records.iter().filter(|row| row.boot_id == boot_hex(id))
            .map(|row| row.sequence).collect();
        sequences.sort_unstable();
        assert_eq!(sequences, (1..=12).collect::<Vec<_>>());
    }
}

#[test]
fn recovery_idle_writer_expires_an_event_without_another_request() {
    let root = TempDir::new("idle-expiry");
    let dir = root.path().join("history");
    let config = AuditHistoryConfig { max_age: Duration::from_millis(700), ..Default::default() };
    let sink = AuditHistorySink::open(&dir, config).unwrap();
    sink.enqueue(sample_mcp_record(system_unix_ms(), 1, 1, 1, None));
    assert!(sink.flush(Duration::from_secs(2)));
    assert_eq!(list_segments(&dir).unwrap().len(), 1);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !list_segments(&dir).unwrap().is_empty() {
        assert!(Instant::now() < deadline, "idle writer did not expire the file");
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn opted_in_attempt_retains_its_name_without_publishing_it_to_a_stable_client() {
    let tool = crate::attempt_maintenance::TOOL_NAME;
    let row = sample_mcp_record(system_unix_ms(), 1, 1, 1, Some(tool));
    assert_eq!(row.tool_name.as_deref(), Some(tool));
    assert!(row.validate_persisted_record());
    assert!(is_activity_tool(tool));
    assert!(!crate::capability_manifest::selected_tool_names(false).any(|name| name == tool));
}
