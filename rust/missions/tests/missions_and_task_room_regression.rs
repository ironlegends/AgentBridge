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

#[test]
fn observed_mission_context_use_touches_stale_last_seen_and_throttles_writes() {
    let mut fixture = TempDb::new("context-last-seen");
    let conn = fixture.db.connection_mut();
    let context = agent_bridge_missions::create_context(conn).unwrap();
    let old = "2000-01-01T00:00:00Z";
    conn.execute("UPDATE agent_contexts SET last_seen=?1 WHERE context_id=?2",
        [old, &context.context_id]).unwrap();
    let read_seen = |conn: &rusqlite::Connection| -> String {
        conn.query_row("SELECT last_seen FROM agent_contexts WHERE context_id=?1",
            [&context.context_id], |row| row.get(0)).unwrap()
    };
    let args = json!({"actor_context_handle":context.context_handle});
    let mut observed = None;
    agent_bridge_missions::dispatch_tool_observed(conn, "agent_bridge_mission_list", &args, |id| {
        observed = Some(id.to_owned());
    }).unwrap();
    assert_eq!(observed.as_deref(), Some(context.context_id.as_str()));
    let recent = read_seen(conn);
    assert_ne!(recent, old);
    let before = conn.total_changes();
    dispatch_tool(conn, "agent_bridge_mission_list", &args).unwrap();
    assert_eq!(conn.total_changes(), before);
    assert_eq!(read_seen(conn), recent);
}

#[test]
fn refused_mission_operations_leave_context_unobserved_and_timestamp_unchanged() {
    let mut fixture = TempDb::new("refused-context-last-seen");
    let conn = fixture.db.connection_mut();
    let owner = agent_bridge_missions::create_context(conn).unwrap();
    let other = agent_bridge_missions::create_context(conn).unwrap();
    let mission = dispatch_tool(conn, "agent_bridge_mission_create", &json!({
        "actor_context_handle":owner.context_handle,"goal":"Example mission","idempotency_key":"create"
    })).unwrap();
    let old = "2000-01-01T00:00:00Z";
    for (tool, context, args, code) in [
        ("agent_bridge_mission_get", &other, json!({
            "actor_context_handle":other.context_handle,"mission_id":mission["mission_id"]
        }), "SECURITY_DENIED"),
        ("agent_bridge_mission_checkpoint", &owner, json!({
            "actor_context_handle":owner.context_handle,"mission_id":mission["mission_id"],
            "summary":"Example checkpoint","if_revision":999
        }), "CONFLICT_REVISION"),
    ] {
        conn.execute("UPDATE agent_contexts SET last_seen=?1 WHERE context_id=?2",
            [old, &context.context_id]).unwrap();
        let mut observed = false;
        let error = agent_bridge_missions::dispatch_tool_observed(conn, tool, &args, |_| {
            observed = true;
        }).unwrap_err();
        assert_eq!(error.code, code);
        let seen: String = conn.query_row("SELECT last_seen FROM agent_contexts WHERE context_id=?1",
            [&context.context_id], |row| row.get(0)).unwrap();
        assert_eq!(seen, old);
        assert!(!observed);
    }
}

#[test]
fn session_mission_display_keeps_only_bounded_goal_and_subtask_title() {
    let mut fixture = TempDb::new("session-mission-display");
    let conn = fixture.db.connection_mut();
    let context = agent_bridge_missions::create_context(conn).unwrap();
    let mission = dispatch_tool(conn, "agent_bridge_mission_create", &json!({
        "actor_context_handle":context.context_handle,
        "goal":"a".repeat(250),"idempotency_key":"create"
    })).unwrap();
    let subtask = dispatch_tool(conn, "agent_bridge_mission_subtask_create", &json!({
        "actor_context_handle":context.context_handle, "mission_id":mission["mission_id"],
        "assignee_context_id":context.context_id, "goal":"b".repeat(250),"idempotency_key":"subtask"
    })).unwrap();
    let subtask_id = &subtask["subtask"]["subtask_id"];
    dispatch_tool(conn, "agent_bridge_mission_subtask_update", &json!({
        "actor_context_handle":context.context_handle, "mission_id":mission["mission_id"],
        "subtask_id":subtask_id, "if_revision":subtask["subtask"]["revision"],
        "status":"in_progress","summary":"Example summary","idempotency_key":"start"
    })).unwrap();
    let tasks = agent_bridge_missions::operator::inspect_operator_snapshot(conn, 20).unwrap();
    let (views, _) = agent_bridge_missions::operator::inspect_session_contexts(
        conn, &[context.context_id], None, 4_096,
    ).unwrap();
    let mission = &views[0].as_ref().unwrap()["missions"][0];
    let task_page_goal = tasks["missions"][0]["goal"].as_str().unwrap();
    assert_eq!(mission["goal"], &task_page_goal[..200]);
    assert_eq!(mission["subtasks"], json!([{
        "id":subtask_id, "title":"b".repeat(200), "status":"in_progress", "assigned_to_context":true
    }]));
}

fn rev_of(v: &Value) -> i64 {
    v.get("revision")
        .or_else(|| v.get("current_revision"))
        .and_then(Value::as_i64)
        .expect("revision")
}

#[test]
fn ordinary_subtask_update_replay_requires_the_current_assignee() {
    let mut t = TempDb::new("subtask-update-replay");
    let conn = t.db.connection_mut();
    let owner = dispatch_tool(conn, "agent_bridge_context_create", &json!({})).unwrap();
    let next = dispatch_tool(conn, "agent_bridge_context_create", &json!({})).unwrap();
    let owner_handle = &owner["context_handle"];
    let next_id = &next["context_id"];
    let mission = dispatch_tool(conn, "agent_bridge_mission_create", &json!({
        "actor_context_handle": owner_handle, "goal": "Check update replay",
        "idempotency_key": "k-owner-mission-create"
    })).unwrap();
    let mid = &mission["mission_id"];
    let granted = dispatch_tool(conn, "agent_bridge_mission_grant", &json!({
        "actor_context_handle": owner_handle, "mission_id": mid, "target_context_id": next_id,
        "if_revision": rev_of(&mission)
    })).unwrap();
    dispatch_tool(conn, "agent_bridge_mission_attach", &json!({
        "actor_context_handle": next["context_handle"], "mission_id": mid,
        "if_revision": rev_of(&granted)
    })).unwrap();

    let owned = dispatch_tool(conn, "agent_bridge_mission_subtask_create", &json!({
        "actor_context_handle": owner_handle, "mission_id": mid, "goal": "Owner's assigned work",
        "assignee_context_id": owner["context_id"], "idempotency_key": "k-owner-work-create"
    })).unwrap();
    let owned_id = &owned["subtask"]["subtask_id"];
    let started = dispatch_tool(conn, "agent_bridge_mission_subtask_update", &json!({
        "actor_context_handle": owner_handle, "mission_id": mid, "subtask_id": owned_id,
        "if_revision": rev_of(&owned["subtask"]), "status": "in_progress",
        "idempotency_key": "k-owner-work-start"
    })).unwrap();
    let owner_update = json!({
        "actor_context_handle": owner_handle, "mission_id": mid, "subtask_id": owned_id,
        "if_revision": rev_of(&started["subtask"]), "status": "blocked",
        "summary": "Waiting for input", "idempotency_key": "k-owner-work-block"
    });
    let blocked = dispatch_tool(conn, "agent_bridge_mission_subtask_update", &owner_update).unwrap();
    assert_eq!(blocked["subtask"]["assignee_context_id"], owner["context_id"]);
    let prior = dispatch_tool(conn, "agent_bridge_mission_subtask_update", &owner_update).unwrap();
    assert_eq!(prior["replayed"], true);
    assert_eq!(prior["subtask"], blocked["subtask"]);
    let reassigned = dispatch_tool(conn, "agent_bridge_mission_subtask_assign", &json!({
        "actor_context_handle": owner_handle, "mission_id": mid, "subtask_id": owned_id,
        "if_revision": rev_of(&blocked["subtask"]), "assignee_context_id": next_id,
        "idempotency_key": "k-owner-work-reassign"
    })).unwrap();
    assert_eq!(reassigned["subtask"]["assignee_context_id"], *next_id);
    assert_eq!(dispatch_tool(conn, "agent_bridge_mission_subtask_update", &owner_update)
        .unwrap_err().code, "SECURITY_DENIED");
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

    let stuck = dispatch_tool(
        conn,
        "agent_bridge_mission_subtask_create",
        &json!({"actor_context_handle": h1, "mission_id": mid, "goal": "Recover stuck work",
            "assignee_context_id": id2, "idempotency_key": "k-recover-create"}),
    ).unwrap();
    let stuck_id = &stuck["subtask"]["subtask_id"];
    let update_as_assignee = |revision, status, key| json!({
        "actor_context_handle": h2, "mission_id": mid, "subtask_id": stuck_id,
        "if_revision": revision, "status": status, "summary": "Assignee update",
        "idempotency_key": key
    });
    let progress = dispatch_tool(conn, "agent_bridge_mission_subtask_update",
        &update_as_assignee(rev_of(&stuck["subtask"]), "in_progress", "k-recover-first-start")).unwrap();
    let blocked = dispatch_tool(conn, "agent_bridge_mission_subtask_update",
        &update_as_assignee(rev_of(&progress["subtask"]), "blocked", "k-recover-assignee-block")).unwrap();
    assert_eq!(blocked["subtask"]["assignee_context_id"], id2);
    let progress = dispatch_tool(conn, "agent_bridge_mission_subtask_update",
        &update_as_assignee(rev_of(&blocked["subtask"]), "in_progress", "k-recover-second-start")).unwrap();
    let stuck_rev = rev_of(&progress["subtask"]);
    let assign = |revision| json!({"actor_context_handle": h1, "mission_id": mid,
        "subtask_id": stuck_id, "if_revision": revision, "assignee_context_id": id1,
        "idempotency_key": "k-recover-assign"});
    assert_eq!(dispatch_tool(conn, "agent_bridge_mission_subtask_assign", &assign(stuck_rev))
        .unwrap_err().code, "INVALID_TRANSITION");

    let mut release = json!({"actor_context_handle": h3, "mission_id": mid, "subtask_id": stuck_id,
        "if_revision": stuck_rev, "status": "blocked", "summary": "Provider quota exhausted",
        "idempotency_key": "k-recover-release"});
    assert_eq!(dispatch_tool(conn, "agent_bridge_mission_subtask_update", &release)
        .unwrap_err().code, "SECURITY_DENIED");
    let observed = dispatch_tool(conn, "agent_bridge_mission_observe",
        &json!({"actor_context_handle": h1, "mission_id": mid})).unwrap();
    let invited = dispatch_tool(conn, "agent_bridge_mission_grant",
        &json!({"actor_context_handle": h1, "mission_id": mid, "if_revision": rev_of(&observed),
            "target_context_id": c3["context_id"]})).unwrap();
    dispatch_tool(conn, "agent_bridge_mission_attach",
        &json!({"actor_context_handle": h3, "mission_id": mid, "if_revision": rev_of(&invited)})).unwrap();
    assert_eq!(dispatch_tool(conn, "agent_bridge_mission_subtask_update", &release)
        .unwrap_err().code, "SECURITY_DENIED");
    release["actor_context_handle"] = json!(h1);
    release["if_revision"] = json!(stuck_rev - 1);
    assert_eq!(dispatch_tool(conn, "agent_bridge_mission_subtask_update", &release)
        .unwrap_err().code, "CONFLICT_REVISION");
    release["if_revision"] = json!(stuck_rev);
    let mut no_reason = release.clone();
    no_reason.as_object_mut().unwrap().remove("summary");
    assert_eq!(dispatch_tool(conn, "agent_bridge_mission_subtask_update", &no_reason)
        .unwrap_err().code, "INVALID_PAYLOAD");
    no_reason["summary"] = json!("  ");
    assert_eq!(dispatch_tool(conn, "agent_bridge_mission_subtask_update", &no_reason)
        .unwrap_err().code, "INVALID_PAYLOAD");
    let mut too_long = release.clone();
    let reason = format!("Provider quota exhausted{}", "\u{1f9ea}".repeat(2036));
    assert_eq!(reason.encode_utf16().count(), 4096);
    too_long["summary"] = json!(format!("{reason}!"));
    assert_eq!(dispatch_tool(conn, "agent_bridge_mission_subtask_update", &too_long)
        .unwrap_err().code, "INVALID_PAYLOAD");
    release["summary"] = json!(reason);
    let released = dispatch_tool(conn, "agent_bridge_mission_subtask_update", &release).unwrap();
    assert_eq!(released["subtask"]["status"], "blocked");
    assert_eq!(released["subtask"]["summary"], progress["subtask"]["summary"]);
    assert_eq!(released["subtask"]["summary"], "Assignee update");
    assert_eq!(released["subtask"]["release_reason"], release["summary"]);
    assert!(released["subtask"].get("assignee_context_id").is_none());
    assert_eq!(rev_of(&released["subtask"]), stuck_rev + 1);
    assert_eq!(dispatch_tool(conn, "agent_bridge_mission_subtask_update",
        &update_as_assignee(stuck_rev + 1, "in_progress", "k-recover-former-assignee"))
        .unwrap_err().code, "SECURITY_DENIED");
    let reassigned = dispatch_tool(conn, "agent_bridge_mission_subtask_assign", &assign(stuck_rev + 1)).unwrap();
    assert_eq!(reassigned["subtask"]["assignee_context_id"], id1);
    assert_eq!(reassigned["subtask"]["status"], "pending");
    assert_eq!(reassigned["subtask"]["summary"], "Assignee update");
    assert_eq!(reassigned["subtask"]["release_reason"], release["summary"]);
    let prior = dispatch_tool(conn, "agent_bridge_mission_subtask_update", &release).unwrap();
    assert_eq!(prior["replayed"], true);
    assert_eq!(prior["subtask"], released["subtask"]);
    let current = dispatch_tool(conn, "agent_bridge_mission_subtask_list",
        &json!({"actor_context_handle": h1, "mission_id": mid, "subtask_id": stuck_id})).unwrap();
    assert_eq!(current["subtasks"][0], reassigned["subtask"]);
    let resumed = dispatch_tool(conn, "agent_bridge_mission_subtask_update", &json!({
        "actor_context_handle": h1, "mission_id": mid, "subtask_id": stuck_id,
        "if_revision": rev_of(&reassigned["subtask"]), "status": "in_progress",
        "idempotency_key": "k-recover-resume"
    })).unwrap();
    let completed = dispatch_tool(conn, "agent_bridge_mission_subtask_update", &json!({
        "actor_context_handle": h1, "mission_id": mid, "subtask_id": stuck_id,
        "if_revision": rev_of(&resumed["subtask"]), "status": "completed",
        "summary": "Completed after handoff", "idempotency_key": "k-recover-complete"
    })).unwrap();
    assert_eq!(completed["subtask"]["summary"], "Completed after handoff");
    assert_eq!(completed["subtask"]["release_reason"], release["summary"]);

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

    // The former owner is now only the assignee and cannot replay the release.
    assert_eq!(dispatch_tool(conn, "agent_bridge_mission_subtask_update", &release)
        .unwrap_err().code, "SECURITY_DENIED");

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
