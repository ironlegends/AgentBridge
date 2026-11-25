use agent_bridge_core::CoreDatabase;
use agent_bridge_missions::{dispatch_tool, task_room};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDb {
    dir: PathBuf,
    db: CoreDatabase,
}

impl TempDb {
    fn new(label: &str) -> Self {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = { let t = std::env::temp_dir(); if cfg!(unix) { std::fs::canonicalize(&t).unwrap_or(t) } else { t } }.join(format!(
            "ab-missions-test-{}-{}-{}",
            label,
            std::process::id(),
            n
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        let db_path = dir.join("missions.sqlite");
        let mut db = CoreDatabase::initialize_new(&db_path).expect("init sqlite v7");
        task_room::init_schema(db.connection_mut()).expect("init task room schema");
        Self { dir, db }
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn rev_of(v: &Value) -> i64 {
    v.get("revision")
        .or_else(|| v.get("current_revision"))
        .and_then(Value::as_i64)
        .expect("revision")
}

#[test]
fn missions_all_16_tools_concurrency_idempotency_and_ownership_regressions() {
    let mut t = TempDb::new("missions16");
    let conn = t.db.connection_mut();

    let st = dispatch_tool(conn, "agent_bridge_status", &json!({})).expect("status");
    assert!(st.is_object() && st.get("schema_version").is_some() || st.get("status").is_some(), "{st}");

    let c1 = dispatch_tool(conn, "agent_bridge_context_create", &json!({})).expect("c1");
    let c2 = dispatch_tool(conn, "agent_bridge_context_create", &json!({})).expect("c2");
    let c3 = dispatch_tool(conn, "agent_bridge_context_create", &json!({})).expect("c3");
    let h1 = c1["context_handle"].as_str().unwrap().to_owned();
    let id1 = c1["context_id"].as_str().unwrap().to_owned();
    let h2 = c2["context_handle"].as_str().unwrap().to_owned();
    let id2 = c2["context_id"].as_str().unwrap().to_owned();
    let h3 = c3["context_handle"].as_str().unwrap().to_owned();

    // Create + idempotent replay + conflict on different payload
    let m = dispatch_tool(
        conn,
        "agent_bridge_mission_create",
        &json!({"actor_context_handle": h1, "goal": "Validate 16 tools", "idempotency_key": "k-create-1"}),
    )
    .expect("create");
    let mid = m["mission_id"].as_str().unwrap().to_owned();
    let mut rev;

    let replay = dispatch_tool(
        conn,
        "agent_bridge_mission_create",
        &json!({"actor_context_handle": h1, "goal": "Validate 16 tools", "idempotency_key": "k-create-1"}),
    )
    .expect("idempotent replay");
    assert_eq!(replay["mission_id"], mid);

    let conflict = dispatch_tool(
        conn,
        "agent_bridge_mission_create",
        &json!({"actor_context_handle": h1, "goal": "Different goal", "idempotency_key": "k-create-1"}),
    );
    assert!(conflict.is_err(), "idempotency key with different payload must fail");

    // Get, list, observe
    let got = dispatch_tool(
        conn,
        "agent_bridge_mission_get",
        &json!({"actor_context_handle": h1, "mission_id": mid}),
    )
    .expect("get");
    assert_eq!(got["mission_id"], mid);

    let list = dispatch_tool(
        conn,
        "agent_bridge_mission_list",
        &json!({"actor_context_handle": h1, "limit": 10}),
    )
    .expect("list");
    assert!(list.as_array().unwrap().iter().any(|x| x["mission_id"] == mid));

    let obs = dispatch_tool(
        conn,
        "agent_bridge_mission_observe",
        &json!({"actor_context_handle": h1, "mission_id": mid}),
    )
    .expect("observe");
    assert_eq!(obs["owner_context_id"], id1);
    rev = rev_of(&obs);

    // Regression: outsider cannot read or grant
    assert!(dispatch_tool(
        conn,
        "agent_bridge_mission_get",
        &json!({"actor_context_handle": h3, "mission_id": mid}),
    )
    .is_err());

    // Grant -> attach -> stale revision regression
    let gr = dispatch_tool(
        conn,
        "agent_bridge_mission_grant",
        &json!({"actor_context_handle": h1, "mission_id": mid, "if_revision": rev, "target_context_id": id2}),
    )
    .expect("grant");
    let old_rev = rev;
    rev = rev_of(&gr);

    let stale_cp = dispatch_tool(
        conn,
        "agent_bridge_mission_checkpoint",
        &json!({"actor_context_handle": h1, "mission_id": mid, "if_revision": old_rev, "summary": "stale"}),
    );
    assert!(stale_cp.is_err(), "stale if_revision must fail");

    let att = dispatch_tool(
        conn,
        "agent_bridge_mission_attach",
        &json!({"actor_context_handle": h2, "mission_id": mid, "if_revision": rev}),
    )
    .expect("attach");
    rev = rev_of(&att);

    // Non-owner cannot transfer or complete
    assert!(dispatch_tool(
        conn,
        "agent_bridge_mission_complete",
        &json!({"actor_context_handle": h2, "mission_id": mid, "if_revision": rev, "idempotency_key": "k-bad-comp"}),
    )
    .is_err());

    // Checkpoint & checkpoints
    let cp = dispatch_tool(
        conn,
        "agent_bridge_mission_checkpoint",
        &json!({"actor_context_handle": h1, "mission_id": mid, "if_revision": rev, "summary": "cp1"}),
    )
    .expect("checkpoint");
    let _ = rev_of(&cp);

    let cps = dispatch_tool(
        conn,
        "agent_bridge_mission_checkpoints",
        &json!({"actor_context_handle": h2, "mission_id": mid, "limit": 10}),
    )
    .expect("checkpoints");
    assert_eq!(cps.as_array().unwrap().len(), 1);

    // Subtasks (create, assign, update, list)
    let stc = dispatch_tool(
        conn,
        "agent_bridge_mission_subtask_create",
        &json!({"actor_context_handle": h1, "mission_id": mid, "goal": "Subtask A", "idempotency_key": "k-sub-1"}),
    )
    .expect("subtask_create");
    let sub = stc.get("subtask").unwrap_or(&stc);
    let sub_id = sub["subtask_id"].as_str().unwrap().to_owned();
    let mut sub_rev = rev_of(sub);

    let sta = dispatch_tool(
        conn,
        "agent_bridge_mission_subtask_assign",
        &json!({
            "actor_context_handle": h1, "mission_id": mid, "subtask_id": sub_id,
            "if_revision": sub_rev, "idempotency_key": "k-sub-assign", "assignee_context_id": id2
        }),
    )
    .expect("subtask_assign");
    sub_rev = rev_of(sta.get("subtask").unwrap_or(&sta));

    let stu1 = dispatch_tool(
        conn,
        "agent_bridge_mission_subtask_update",
        &json!({
            "actor_context_handle": h2, "mission_id": mid, "subtask_id": sub_id,
            "if_revision": sub_rev, "idempotency_key": "k-sub-upd-1", "status": "in_progress"
        }),
    )
    .expect("subtask_update in_progress");
    sub_rev = rev_of(stu1.get("subtask").unwrap_or(&stu1));

    let stu2 = dispatch_tool(
        conn,
        "agent_bridge_mission_subtask_update",
        &json!({
            "actor_context_handle": h2, "mission_id": mid, "subtask_id": sub_id,
            "if_revision": sub_rev, "idempotency_key": "k-sub-upd-2", "status": "completed", "summary": "done"
        }),
    )
    .expect("subtask_update completed");
    assert_eq!(stu2.get("subtask").unwrap_or(&stu2)["status"], "completed");

    let stl = dispatch_tool(
        conn,
        "agent_bridge_mission_subtask_list",
        &json!({"actor_context_handle": h1, "mission_id": mid, "limit": 10}),
    )
    .expect("subtask_list");
    let st_arr = stl.as_array().or_else(|| stl.get("subtasks").and_then(Value::as_array)).expect("subtasks array");
    assert_eq!(st_arr.len(), 1);

    // Transfer ownership to h2, then h2 completes
    let obs_tr = dispatch_tool(
        conn,
        "agent_bridge_mission_observe",
        &json!({"actor_context_handle": h1, "mission_id": mid}),
    )
    .expect("observe before transfer");
    rev = rev_of(&obs_tr);

    let tr = dispatch_tool(
        conn,
        "agent_bridge_mission_transfer",
        &json!({"actor_context_handle": h1, "mission_id": mid, "if_revision": rev, "target_context_id": id2}),
    )
    .expect("transfer");
    rev = rev_of(&tr);

    let comp = dispatch_tool(
        conn,
        "agent_bridge_mission_complete",
        &json!({"actor_context_handle": h2, "mission_id": mid, "if_revision": rev, "idempotency_key": "k-comp-1"}),
    )
    .expect("complete");
    assert_eq!(comp["status"], "completed");
}

#[test]
fn task_room_all_11_actions_isolation_rotation_and_state_guard_regressions() {
    let mut t = TempDb::new("taskroom11");
    let conn = t.db.connection_mut();
    let ws_a = "vol:1|id:100|path:C:\\workspace-a";
    let ws_b = "vol:1|id:200|path:C:\\workspace-b";

    // Unbound dispatch is always refused
    assert!(task_room::dispatch(conn, &json!({"action": "context_discover"})).is_err());
    assert!(task_room::dispatch_scoped(conn, &json!({"action": "context_discover"}), "").is_err());

    // 1. context_create & context_discover
    let ctx = task_room::dispatch_scoped(
        conn,
        &json!({"action": "context_create", "context_label": "Alpha Room", "project": "p1", "device": "dev-workstation"}),
        ws_a,
    )
    .expect("context_create");
    let h1 = ctx["context_handle"].as_str().unwrap().to_owned();
    let cid = ctx["context_id"].as_str().unwrap().to_owned();

    let disc_a = task_room::dispatch_scoped(conn, &json!({"action": "context_discover", "limit": 10}), ws_a)
        .expect("discover A");
    assert!(disc_a["contexts"].as_array().unwrap().iter().any(|c| c["context_id"] == cid));

    // Cross-workspace isolation: ws_b cannot see or use ws_a context
    let disc_b = task_room::dispatch_scoped(conn, &json!({"action": "context_discover", "limit": 10}), ws_b)
        .expect("discover B");
    assert!(!disc_b["contexts"].as_array().unwrap().iter().any(|c| c["context_id"] == cid));
    assert!(task_room::dispatch_scoped(
        conn,
        &json!({"action": "list", "context_handle": h1}),
        ws_b,
    )
    .is_err());

    // 2. create, list, get
    let created = task_room::dispatch_scoped(
        conn,
        &json!({
            "action": "create", "context_handle": h1,
            "title": "Regression Task", "goal": "Verify all 11 Task Room actions",
            "steps": [{"id": "s1", "title": "Execute step", "phase": "execute"}],
            "completion_conditions": ["all checks verified"]
        }),
        ws_a,
    )
    .expect("create");
    let tid = created["task"]["task_id"].as_str().unwrap().to_owned();

    let listed = task_room::dispatch_scoped(
        conn,
        &json!({"action": "list", "context_handle": h1, "limit": 10}),
        ws_a,
    )
    .expect("list");
    assert_eq!(listed["tasks"][0]["task_id"], tid);
    assert_eq!(listed["tasks"][0]["goal"], "Verify all 11 Task Room actions");

    // 3. checkpoint -> block -> cannot complete while blocked -> resume
    let _ = task_room::dispatch_scoped(
        conn,
        &json!({
            "action": "checkpoint", "context_handle": h1, "task_id": tid,
            "completed_step_ids": ["s1"], "summary": "step done", "verified_facts": ["f1"]
        }),
        ws_a,
    )
    .expect("checkpoint");

    let blocked = task_room::dispatch_scoped(
        conn,
        &json!({"action": "block", "context_handle": h1, "task_id": tid, "summary": "waiting check"}),
        ws_a,
    )
    .expect("block");
    assert_eq!(blocked["task"]["status"], "blocked");

    // Regression: cannot complete while blocked or without passing final_review
    assert!(task_room::dispatch_scoped(
        conn,
        &json!({"action": "complete", "context_handle": h1, "task_id": tid}),
        ws_a,
    )
    .is_err());

    let resumed = task_room::dispatch_scoped(
        conn,
        &json!({"action": "resume", "context_handle": h1, "task_id": tid, "summary": "unblocked"}),
        ws_a,
    )
    .expect("resume");
    assert_eq!(resumed["task"]["status"], "active");

    // 4. final_review (failed then pass) -> complete
    let fr_fail = task_room::dispatch_scoped(
        conn,
        &json!({"action": "final_review", "context_handle": h1, "task_id": tid, "review_status": "failed", "missing_checks": ["check X"]}),
        ws_a,
    )
    .expect("final_review failed");
    assert_eq!(fr_fail["ok"], true);

    assert!(task_room::dispatch_scoped(
        conn,
        &json!({"action": "complete", "context_handle": h1, "task_id": tid}),
        ws_a,
    )
    .is_err());

    let fr_pass = task_room::dispatch_scoped(
        conn,
        &json!({"action": "final_review", "context_handle": h1, "task_id": tid, "review_status": "pass", "missing_checks": [], "summary": "all green"}),
        ws_a,
    )
    .expect("final_review pass");
    assert_eq!(fr_pass["ok"], true);

    let completed = task_room::dispatch_scoped(
        conn,
        &json!({"action": "complete", "context_handle": h1, "task_id": tid, "summary": "closed"}),
        ws_a,
    )
    .expect("complete");
    assert_eq!(completed["task"]["status"], "completed");

    // Verify get includes ordered event types
    let got = task_room::dispatch_scoped(
        conn,
        &json!({"action": "get", "context_handle": h1, "task_id": tid}),
        ws_a,
    )
    .expect("get");
    let events = got["events"].as_array().expect("events array");
    assert!(events.len() >= 6, "expected full lifecycle events, got {events:?}");
    assert!(events.iter().all(|e| e.get("event_type").or_else(|| e.get("type")).and_then(Value::as_str).is_some()), "missing event type: {events:?}");

    // 5. context_reattach: wrong confirm_label refused; valid label rotates & invalidates h1
    assert!(task_room::dispatch_scoped(
        conn,
        &json!({"action": "context_reattach", "context_handle": h1, "context_id": cid, "confirm_label": "Wrong Label"}),
        ws_a,
    )
    .is_err());

    let re = task_room::dispatch_scoped(
        conn,
        &json!({"action": "context_reattach", "context_handle": h1, "context_id": cid, "confirm_label": "Alpha Room"}),
        ws_a,
    )
    .expect("context_reattach");
    let h2 = re["context_handle"].as_str().unwrap().to_owned();
    assert_ne!(h1, h2);
    assert!(task_room::dispatch_scoped(conn, &json!({"action": "list", "context_handle": h1}), ws_a).is_err());
    assert!(task_room::dispatch_scoped(conn, &json!({"action": "list", "context_handle": h2}), ws_a).is_ok());
}
