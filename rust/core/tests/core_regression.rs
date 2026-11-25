use agent_bridge_core::{
    inspect_existing, migration_checksum_matches, CoreDatabase, CoreError, CURRENT_SCHEMA_VERSION,
};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new(label: &str) -> Self {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = { let t = std::env::temp_dir(); if cfg!(unix) { std::fs::canonicalize(&t).unwrap_or(t) } else { t } }.join(format!("ab-core-test-{label}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn core_initialize_inspect_open_and_sidecar_safety_regressions() {
    let tmp = TempDir::new("init");
    let db_path = tmp.0.join("missions.sqlite");

    // Relative path must fail closed
    assert!(matches!(
        CoreDatabase::initialize_new("relative/missions.sqlite"),
        Err(CoreError::InvalidPath(_))
    ));

    // Initialize fresh DB -> schema v7, no pending migrations
    let db = CoreDatabase::initialize_new(&db_path).expect("initialize_new");
    assert_eq!(db.schema_version(), CURRENT_SCHEMA_VERSION);
    assert_eq!(db.schema_version(), 7);

    // While open in WAL mode with sidecar files, inspect_existing MUST fail closed
    let live_inspect = inspect_existing(&db_path);
    assert!(
        matches!(live_inspect, Err(CoreError::UnsafeHistory(_))),
        "live WAL sidecar must be rejected: {live_inspect:?}"
    );
    drop(db);

    // Offline DB after clean close passes inspect_existing and open_existing
    let status = inspect_existing(&db_path).expect("inspect offline db");
    assert_eq!(status.version, CURRENT_SCHEMA_VERSION);
    assert_eq!(status.pending_migrations, 0);

    let reopened = CoreDatabase::open_existing(&db_path).expect("open_existing");
    assert_eq!(reopened.schema_version(), CURRENT_SCHEMA_VERSION);

    // Verify all 7 recorded checksums match embedded C# SQL migrations
    let mut stmt = reopened
        .connection()
        .prepare("SELECT version, checksum FROM schema_migrations ORDER BY version")
        .unwrap();
    let rows: Vec<(i64, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(rows.len(), 7);
    for (version, checksum) in rows {
        assert!(
            migration_checksum_matches(version, &checksum),
            "checksum mismatch for migration {version}"
        );
    }
    assert!(!migration_checksum_matches(1, "0000000000000000000000000000000000000000000000000000000000000000"));
    assert!(!migration_checksum_matches(99, "abcd"));
}
