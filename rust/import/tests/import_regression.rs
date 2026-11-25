use agent_bridge_import::{
    import_snapshot_json, LegacyEventSnapshot, LegacyStepSnapshot, LegacyTaskSnapshot,
    MAX_SNAPSHOT_JSON_BYTES,
};
use rusqlite::Connection;

fn init_v7_schema() -> Connection {
    let conn = Connection::open_in_memory().expect("in-memory sqlite");
    let migrations = [
        include_str!("../../../contracts/sqlite/001_initial.sql"),
        include_str!("../../../contracts/sqlite/002_execution.sql"),
        include_str!("../../../contracts/sqlite/003_collaboration.sql"),
        include_str!("../../../contracts/sqlite/004_scheduler.sql"),
        include_str!("../../../contracts/sqlite/005_legacy_import.sql"),
        include_str!("../../../contracts/sqlite/006_legacy_events.sql"),
        include_str!("../../../contracts/sqlite/007_legacy_mission_owners.sql"),
    ];
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations(
            version INTEGER PRIMARY KEY,
            checksum TEXT NOT NULL,
            applied_at TEXT NOT NULL,
            compatibility_min INTEGER NOT NULL
        );",
    )
    .unwrap();
    for (idx, sql) in migrations.iter().enumerate() {
        conn.execute_batch(sql).expect("apply migration");
        conn.execute(
            "INSERT INTO schema_migrations(version, checksum, applied_at, compatibility_min) VALUES (?1, '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', '2026-01-01T00:00:00Z', 1)",
            [(idx + 1) as i64],
        )
        .unwrap();
    }
    conn
}

#[test]
fn import_snapshot_idempotency_conflict_blocked_mission_and_size_regressions() {
    let mut conn = init_v7_schema();

    let snap = LegacyTaskSnapshot {
        provider: "legacy-provider".into(),
        context_id: "ctx_hist_1".into(),
        task_id: "tsk_hist_1".into(),
        goal: "Preserve read-only historical task".into(),
        status: "active".into(),
        total_events_reported: 2,
        events: vec![
            LegacyEventSnapshot {
                sequence: 2,
                event_type: "custom.unknown_event".into(),
                summary: "second".into(),
            },
            LegacyEventSnapshot {
                sequence: 1,
                event_type: "created".into(),
                summary: "first".into(),
            },
        ],
        steps: vec![LegacyStepSnapshot {
            step_id: "step_1".into(),
            title: "Historic step".into(),
            state: "unknown_custom_state".into(),
        }],
    };
    let bytes = serde_json::to_vec(&snap).unwrap();

    // 1. First import succeeds, mission is blocked & actor_context_handle='legacy-import'
    let r1 = import_snapshot_json(&mut conn, &bytes).expect("first import");
    assert!(!r1.partial_history);
    assert_eq!(r1.import_state, "imported");

    let (status, actor): (String, String) = conn
        .query_row(
            "SELECT status, actor_context_handle FROM missions WHERE mission_id = ?1",
            [&r1.mission_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "blocked");
    assert_eq!(actor, "legacy-import");

    // 2. Exact replay is idempotent and returns same mission_id & digest
    let r2 = import_snapshot_json(&mut conn, &bytes).expect("idempotent replay");
    assert_eq!(r1, r2);

    // 3. Mutated snapshot for same source identity fails closed with IMPORT_CONFLICT
    let mut modified = snap.clone();
    modified.goal = "Tampered goal".into();
    let conflict = import_snapshot_json(&mut conn, &serde_json::to_vec(&modified).unwrap())
        .expect_err("modified snapshot must conflict");
    assert_eq!(conflict.code, "IMPORT_CONFLICT");

    // 4. Partial history detection when total_events_reported > events.len()
    let mut partial = snap;
    partial.task_id = "tsk_hist_2".into();
    partial.total_events_reported = 10;
    let rp = import_snapshot_json(&mut conn, &serde_json::to_vec(&partial).unwrap())
        .expect("partial import");
    assert!(rp.partial_history);

    // 5. Payload > 1 MiB fails closed
    let oversized = vec![b' '; MAX_SNAPSHOT_JSON_BYTES + 1];
    let err = import_snapshot_json(&mut conn, &oversized).expect_err("oversized must fail");
    assert_eq!(err.code, "INVALID_PAYLOAD");
}
