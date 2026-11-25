use agent_bridge_leases::{
    bind_operation_id, normalize_resource_key, require_bound_resource_grant, LeaseCoordinator,
};
use rusqlite::Connection;
use std::time::Duration;

fn init_leases_db() -> Connection {
    let conn = Connection::open_in_memory().expect("in-memory sqlite");
    conn.execute_batch(include_str!("../../../contracts/sqlite/001_initial.sql")).unwrap();
    conn.execute_batch(include_str!("../../../contracts/sqlite/002_execution.sql"))
    .expect("create resource_leases table");
    conn
}

#[test]
fn lease_normalization_mutual_exclusion_renew_release_and_rpc_regressions() {
    // Normalization & invalid key rejection
    assert!(normalize_resource_key("file:docs/a.txt").is_err(), "relative file lease must be rejected");
    let abs_key = if cfg!(windows) { "file:C:/workspace/docs/a.txt" } else { "file:/workspace/docs/a.txt" };
    assert!(normalize_resource_key(abs_key).is_ok());
    assert!(normalize_resource_key("").is_err());
    assert!(normalize_resource_key("bad\0key").is_err());

    let bound = bind_operation_id("msn_1", "op_1").expect("bind op");
    assert!(!bound.is_empty());

    let mut conn = init_leases_db();
    let coord = LeaseCoordinator::new();
    let keys = vec![if cfg!(windows) { "file:C:/workspace/docs/readme.md".to_owned() } else { "file:/workspace/docs/readme.md".to_owned() }];

    // Acquire succeeds for op1
    let g1 = coord
        .acquire(&mut conn, &keys, &bound, Duration::from_secs(30))
        .expect("acquire g1");
    assert!(coord.is_current(&conn, &g1).unwrap());
    require_bound_resource_grant("msn_1", &g1).expect("bound grant matches");
    assert!(require_bound_resource_grant("msn_2", &g1).is_err());

    // Contending operation fails closed while lease is active
    let bound2 = bind_operation_id("msn_1", "op_2").unwrap();
    let contended = coord.acquire(&mut conn, &keys, &bound2, Duration::from_secs(30));
    assert!(contended.is_err(), "concurrent acquire on held key must fail");

    // Renew succeeds for valid grant, fails with forged fencing token
    let g1_renewed = coord
        .renew(&mut conn, &g1, Duration::from_secs(45))
        .expect("renew g1");
    let mut forged = g1_renewed.clone();
    for v in forged.fences.values_mut() {
        *v += 99;
    }
    assert!(coord.renew(&mut conn, &forged, Duration::from_secs(45)).is_err());

    // Release frees key for op2
    coord.release(&mut conn, &g1_renewed).expect("release g1");
    assert!(!coord.is_current(&conn, &g1_renewed).unwrap());

    let g2 = coord
        .acquire(&mut conn, &keys, &bound2, Duration::from_secs(30))
        .expect("acquire g2 after release");
    assert!(coord.is_current(&conn, &g2).unwrap());

}
