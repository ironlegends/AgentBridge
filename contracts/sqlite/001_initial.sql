CREATE TABLE devices(
  device_id TEXT PRIMARY KEY, hostname TEXT NOT NULL, boot_id TEXT, last_seen TEXT, capabilities TEXT
);
CREATE TABLE projects(
  project_id TEXT PRIMARY KEY, repo_url TEXT, reference_worktree TEXT, resource_policies TEXT
);
CREATE TABLE agent_contexts(
  context_id TEXT PRIMARY KEY, handle_hash TEXT NOT NULL, actor_kind TEXT NOT NULL, attached_at TEXT, last_seen TEXT
);
CREATE TABLE missions(
  mission_id TEXT PRIMARY KEY,
  project_id TEXT REFERENCES projects(project_id),
  goal TEXT NOT NULL CHECK(length(goal)>0),
  status TEXT NOT NULL CHECK(status IN ('active','blocked','completed')),
  current_revision INTEGER NOT NULL CHECK(current_revision>=1),
  orchestrator_enabled INTEGER NOT NULL DEFAULT 0,
  priority INTEGER NOT NULL DEFAULT 0,
  actor_context_handle TEXT NOT NULL,
  create_idempotency_key TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE mission_steps(
  step_id TEXT PRIMARY KEY, mission_id TEXT NOT NULL REFERENCES missions(mission_id),
  type TEXT NOT NULL, dependencies TEXT, preconditions TEXT, expected_postconditions TEXT,
  state TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE operations(
  operation_id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(mission_id),
  step_id TEXT REFERENCES mission_steps(step_id),
  tool_name TEXT NOT NULL, idempotency_key TEXT NOT NULL UNIQUE,
  args_digest TEXT NOT NULL, result_json TEXT, state TEXT NOT NULL,
  executor_id TEXT, created_at TEXT NOT NULL
);
CREATE TABLE executions(
  execution_id TEXT PRIMARY KEY, attempt INTEGER NOT NULL,
  operation_id TEXT NOT NULL REFERENCES operations(operation_id), pid INTEGER, pid_started_at TEXT,
  boot_id TEXT, owner_instance TEXT, exit_code INTEGER, state TEXT NOT NULL, checkpoint_ref TEXT
);
CREATE TABLE resource_leases(
  resource_key TEXT PRIMARY KEY, owner_operation TEXT NOT NULL,
  generation INTEGER NOT NULL, token INTEGER NOT NULL, expires_at TEXT, renew_at TEXT, conflict_scope TEXT
);
CREATE TABLE workspaces(
  workspace_id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(project_id),
  path TEXT NOT NULL, worktree_branch TEXT, base_commit TEXT, state TEXT NOT NULL
);
CREATE TABLE artifacts(
  artifact_id TEXT PRIMARY KEY, digest TEXT NOT NULL, size INTEGER NOT NULL,
  path TEXT NOT NULL, retention_class TEXT NOT NULL, mission_id TEXT REFERENCES missions(mission_id),
  created_at TEXT NOT NULL
);
CREATE TABLE events(
  event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
  mission_id TEXT REFERENCES missions(mission_id),
  operation_id TEXT, event_type TEXT NOT NULL, payload_redacted TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_events_mission_seq ON events(mission_id,event_seq);
CREATE TABLE imports(
  source_provider TEXT NOT NULL, source_context_id TEXT NOT NULL, source_task_id TEXT NOT NULL,
  source_digest TEXT NOT NULL, target_mission_id TEXT REFERENCES missions(mission_id),
  imported_at TEXT NOT NULL, state TEXT NOT NULL,
  PRIMARY KEY(source_provider,source_context_id,source_task_id)
);
CREATE TABLE releases(
  product TEXT NOT NULL, version TEXT NOT NULL, channel TEXT NOT NULL,
  build_digest TEXT NOT NULL, upstream_base_sha TEXT, schema_min INTEGER NOT NULL,
  schema_max INTEGER NOT NULL, signature_status TEXT NOT NULL,
  PRIMARY KEY(product,version,channel)
);
CREATE TABLE deployments(
  deployment_id TEXT PRIMARY KEY, from_release TEXT, to_release TEXT,
  channel TEXT NOT NULL, stage TEXT NOT NULL, health TEXT, rollback_reason TEXT
);
CREATE TABLE integration_outbox(
  event_seq INTEGER NOT NULL REFERENCES events(event_seq),
  adapter TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
  next_retry TEXT, delivered_at TEXT,
  PRIMARY KEY(event_seq,adapter)
);
