use agent_bridge_core::{inspect_existing, CoreDatabase};
use agent_bridge_missions::{dispatch_tool, task_room};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

struct TempDb {
    dir: PathBuf,
    db: CoreDatabase,
}

impl TempDb {
    fn new(prefix: &str) -> Self {
        let dir = { let t = std::env::temp_dir(); if cfg!(unix) { std::fs::canonicalize(&t).unwrap_or(t) } else { t } }.join(format!(
            "ab-missions-test-{prefix}-{:016x}",
            rand::random::<u64>()
        ));
        fs::create_dir_all(&dir).expect("create temp db dir");
        let path = dir.join("missions.sqlite");
        let mut db = CoreDatabase::initialize_new(&path).expect("init core db");
        task_room::init_schema(db.connection_mut()).expect("init task room schema");
        Self { dir, db }
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn missions_full_16_tool_lifecycle_idempotency_and_revision_conflict() {
    let mut env = TempDb::new("missions16");
    assert!(inspect_existing(env.db.path()).is_err(), "live WAL sidecar must be rejected by inspect_existing");
    assert_eq!(env.db.schema_version(), 7);

    let conn = env.db.connection_mut();

    let c1 = dispatch_tool(conn, "agent_bridge_context_create", &json!({})).expect("context 1");
    let c2 = dispatch_tool(conn, "agent_bridge_context_create", &json!({})).expect("context 2");
    let h1 = c1["context_handle"].as_str().unwrap().to_owned();
    let id1 = c1["context_id"].as_str().unwrap().to_owned();
    let h2 = c2["context_handle"].as_str().unwrap().to_owned();
    let id2 = c2["context_id"].as_str().unwrap().to_owned();

    let m = dispatch_tool(
        conn,
        "agent_bridge_mission_create",
        &json!({
            "actor_context_handle": h1,
            "goal": "Verify all mission transitions",
            "idempotency_key": "m-key-1"
        }),
    )
    .expect("mission create");
    let mid = m["mission_id"].as_str().unwrap().to_owned();
    let mut rev = m["revision"].as_i64().unwrap_or(1);

    // Idempotency replay returns the exact same mission
    let m_replay = dispatch_tool(
        conn,
        "agent_bridge_mission_create",
        &json!({
            "actor_context_handle": h1,
            "goal": "Verify all mission transitions",
            "idempotency_key": "m-key-1"
        }),
    )
    .expect("idempotent replay");
    assert_eq!(m_replay["mission_id"], mid);

    let got = dispatch_tool(
        conn,
        "agent_bridge_mission_get",
        &json!({ "actor_context_handle": h1, "mission_id": mid }),
    )
    .expect("mission get");
    assert_eq!(got["mission_id"], mid);

    let listed = dispatch_tool(
        conn,
        "agent_bridge_mission_list",
        &json!({ "actor_context_handle": h1, "limit": 10 }),
    )
    .expect("mission list");
    let items = listed
        .as_array()
        .or_else(|| listed.get("missions").and_then(Value::as_array))
        .expect("missions list array");
    assert!(items.iter().any(|x| x["mission_id"] == mid));

    let obs = dispatch_tool(
        conn,
        "agent_bridge_mission_observe",
        &json!({ "actor_context_handle": h1, "mission_id": mid }),
    )
    .expect("observe");
    assert_eq!(obs["owner_context_id"], id1);
    rev = obs["revision"].as_i64().unwrap_or(rev);

    // Grant & attach second actor
    let granted = dispatch_tool(
        conn,
        "agent_bridge_mission_grant",
        &json!({
            "actor_context_handle": h1,
            "mission_id": mid,
            "if_revision": rev,
            "target_context_id": id2
        }),
    )
    .expect("grant");
    rev = granted["revision"].as_i64().unwrap_or(rev + 1);

    let attached = dispatch_tool(
        conn,
        "agent_bridge_mission_attach",
        &json!({ "actor_context_handle": h2, "mission_id": mid, "if_revision": rev }),
    )
    .expect("attach");
    rev = attached["revision"].as_i64().unwrap_or(rev + 1);

    // Stale revision conflict regression
    let stale_err = dispatch_tool(
        conn,
        "agent_bridge_mission_checkpoint",
        &json!({
            "actor_context_handle": h1,
            "mission_id": mid,
            "if_revision": 1,
            "summary": "should conflict"
        }),
    );
    assert!(stale_err.is_err(), "stale if_revision must fail");

    let cp = dispatch_tool(
        conn,
        "agent_bridge_mission_checkpoint",
        &json!({
            "actor_context_handle": h1,
            "mission_id": mid,
            "if_revision": rev,
            "summary": "checkpoint 1"
        }),
    )
    .expect("checkpoint");
    let _ = cp["revision"].as_i64().unwrap_or(rev + 1);

    let cps = dispatch_tool(
        conn,
        "agent_bridge_mission_checkpoints",
        &json!({ "actor_context_handle": h2, "mission_id": mid, "limit": 10 }),
    )
    .expect("checkpoints");
    let cp_arr = cps
        .as_array()
        .or_else(|| cps.get("checkpoints").and_then(Value::as_array))
        .expect("checkpoints array");
    assert!(!cp_arr.is_empty());

    // Subtasks lifecycle
    let sub = dispatch_tool(
        conn,
        "agent_bridge_mission_subtask_create",
        &json!({
            "actor_context_handle": h1,
            "mission_id": mid,
            "goal": "Subtask 1",
            "idempotency_key": "sub-1"
        }),
    )
    .expect("subtask create");
    let sub_id = sub
        .get("subtask")
        .and_then(|s| s["subtask_id"].as_str())
        .or_else(|| sub["subtask_id"].as_str())
        .unwrap()
        .to_owned();
    let mut sub_rev = sub
        .get("subtask")
        .and_then(|s| s["revision"].as_i64())
        .or_else(|| sub["revision"].as_i64())
        .unwrap_or(1);

    let assigned = dispatch_tool(
        conn,
        "agent_bridge_mission_subtask_assign",
        &json!({
            "actor_context_handle": h1,
            "mission_id": mid,
            "subtask_id": sub_id,
            "if_revision": sub_rev,
            "idempotency_key": "sub-assign-1",
            "assignee_context_id": id2
        }),
    )
    .expect("subtask assign");
    sub_rev = assigned
        .get("subtask")
        .and_then(|s| s["revision"].as_i64())
        .or_else(|| assigned["revision"].as_i64())
        .unwrap_or(sub_rev + 1);

    let upd1 = dispatch_tool(
        conn,
        "agent_bridge_mission_subtask_update",
        &json!({
            "actor_context_handle": h2,
            "mission_id": mid,
            "subtask_id": sub_id,
            "if_revision": sub_rev,
            "idempotency_key": "sub-upd-1",
            "status": "in_progress"
        }),
    )
    .expect("subtask in_progress");
    sub_rev = upd1
        .get("subtask")
        .and_then(|s| s["revision"].as_i64())
        .or_else(|| upd1["revision"].as_i64())
        .unwrap_or(sub_rev + 1);

    dispatch_tool(
        conn,
        "agent_bridge_mission_subtask_update",
        &json!({
            "actor_context_handle": h2,
            "mission_id": mid,
            "subtask_id": sub_id,
            "if_revision": sub_rev,
            "idempotency_key": "sub-upd-2",
            "status": "completed",
            "summary": "subtask done"
        }),
    )
    .expect("subtask completed");

    let sub_list = dispatch_tool(
        conn,
        "agent_bridge_mission_subtask_list",
        &json!({ "actor_context_handle": h1, "mission_id": mid, "limit": 10 }),
    )
    .expect("subtask list");
    let st_arr = sub_list
        .as_array()
        .or_else(|| sub_list.get("subtasks").and_then(Value::as_array))
        .expect("subtasks array");
    assert_eq!(st_arr.len(), 1);

    // Transfer ownership to actor 2 & complete
    let obs2 = dispatch_tool(
        conn,
        "agent_bridge_mission_observe",
        &json!({ "actor_context_handle": h1, "mission_id": mid }),
    )
    .expect("observe before transfer");
    rev = obs2["revision"].as_i64().unwrap();

    let tr = dispatch_tool(
        conn,
        "agent_bridge_mission_transfer",
        &json!({
            "actor_context_handle": h1,
            "mission_id": mid,
            "if_revision": rev,
            "target_context_id": id2
        }),
    )
    .expect("transfer");
    rev = tr["revision"].as_i64().unwrap_or(rev + 1);

    let done = dispatch_tool(
        conn,
        "agent_bridge_mission_complete",
        &json!({
            "actor_context_handle": h2,
            "mission_id": mid,
            "if_revision": rev,
            "idempotency_key": "m-complete-1"
        }),
    )
    .expect("complete");
    assert_eq!(done["status"], "completed");
}

#[test]
fn task_room_all_11_actions_handle_rotation_and_workspace_isolation() {
    let mut env = TempDb::new("taskroom11");
    let conn = env.db.connection_mut();
    let ws_a = "phys-workspace-a";
    let ws_b = "phys-workspace-b";

    // Unbound dispatch must fail closed
    assert!(task_room::dispatch(conn, &json!({ "action": "context_discover" })).is_err());
    assert!(task_room::dispatch_scoped(conn, &json!({ "action": "context_discover" }), "").is_err());

    // 1. context_create
    let cc = task_room::dispatch_scoped(
        conn,
        &json!({ "action": "context_create", "context_label": "Unit Room", "project": "parity", "device": "dev-workstation" }),
        ws_a,
    )
    .expect("context_create");
    let h1 = cc["context_handle"].as_str().unwrap().to_owned();
    let cid = cc["context_id"].as_str().unwrap().to_owned();

    // 2. context_discover (visible in ws_a, isolated from ws_b)
    let disc_a = task_room::dispatch_scoped(conn, &json!({ "action": "context_discover", "limit": 10 }), ws_a)
        .expect("discover a");
    assert!(disc_a["contexts"].as_array().unwrap().iter().any(|c| c["context_id"] == cid));
    let disc_b = task_room::dispatch_scoped(conn, &json!({ "action": "context_discover", "limit": 10 }), ws_b)
        .expect("discover b");
    assert!(disc_b["contexts"].as_array().unwrap().is_empty(), "workspace isolation breached");

    // 3. create
    let created = task_room::dispatch_scoped(
        conn,
        &json!({
            "action": "create",
            "context_handle": h1,
            "title": "Parity Qualification",
            "goal": "Verify all 11 task room actions",
            "steps": [{ "id": "s1", "title": "Step 1", "phase": "execute" }],
            "completion_conditions": ["all pass"]
        }),
        ws_a,
    )
    .expect("create");
    let tid = created["task"]["task_id"].as_str().unwrap().to_owned();

    // 4. list (includes goal & summary)
    let listed = task_room::dispatch_scoped(
        conn,
        &json!({ "action": "list", "context_handle": h1, "limit": 10 }),
        ws_a,
    )
    .expect("list");
    let t0 = &listed["tasks"].as_array().unwrap()[0];
    assert_eq!(t0["task_id"], tid);
    assert!(t0["goal"].as_str().unwrap().contains("11 task room"));

    // 5. checkpoint -> 6. block -> 7. resume -> 8. final_review -> 9. complete
    task_room::dispatch_scoped(
        conn,
        &json!({
            "action": "checkpoint",
            "context_handle": h1,
            "task_id": tid,
            "completed_step_ids": ["s1"],
            "summary": "step 1 verified",
            "verified_facts": ["fact-a"]
        }),
        ws_a,
    )
    .expect("checkpoint");

    let blk = task_room::dispatch_scoped(
        conn,
        &json!({ "action": "block", "context_handle": h1, "task_id": tid, "summary": "waiting check" }),
        ws_a,
    )
    .expect("block");
    assert_eq!(blk["task"]["status"], "blocked");

    let res = task_room::dispatch_scoped(
        conn,
        &json!({ "action": "resume", "context_handle": h1, "task_id": tid, "summary": "resumed" }),
        ws_a,
    )
    .expect("resume");
    assert_eq!(res["task"]["status"], "active");

    task_room::dispatch_scoped(
        conn,
        &json!({ "action": "final_review", "context_handle": h1, "task_id": tid, "review_status": "pass", "summary": "approved" }),
        ws_a,
    )
    .expect("final_review");

    let comp = task_room::dispatch_scoped(
        conn,
        &json!({ "action": "complete", "context_handle": h1, "task_id": tid, "summary": "closed" }),
        ws_a,
    )
    .expect("complete");
    assert_eq!(comp["task"]["status"], "completed");

    // 10. get (verifies history event types & stable order)
    let got = task_room::dispatch_scoped(
        conn,
        &json!({ "action": "get", "context_handle": h1, "task_id": tid }),
        ws_a,
    )
    .expect("get");
    let events = got["recent_events"]
        .as_array()
        .or_else(|| got["events"].as_array())
        .expect("events array");
    assert!(events.len() >= 5);
    assert!(events.iter().all(|e| e.get("event_type").or_else(|| e.get("type")).is_some()));

    // 11. context_reattach rotates handle and invalidates old handle
    let re = task_room::dispatch_scoped(
        conn,
        &json!({
            "action": "context_reattach",
            "context_handle": h1,
            "context_id": cid,
            "confirm_label": "Unit Room"
        }),
        ws_a,
    )
    .expect("context_reattach");
    let h2 = re["context_handle"].as_str().unwrap().to_owned();
    assert_ne!(h1, h2);
    assert!(task_room::dispatch_scoped(conn, &json!({ "action": "list", "context_handle": h1 }), ws_a).is_err());
    assert!(task_room::dispatch_scoped(conn, &json!({ "action": "list", "context_handle": h2 }), ws_a).is_ok());
}
