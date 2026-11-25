ALTER TABLE mission_steps ADD COLUMN approved INTEGER NOT NULL DEFAULT 0;
ALTER TABLE mission_steps ADD COLUMN idempotency_key TEXT;
ALTER TABLE mission_steps ADD COLUMN action_args TEXT NOT NULL DEFAULT '{}';
ALTER TABLE mission_steps ADD COLUMN attempted INTEGER NOT NULL DEFAULT 0;
ALTER TABLE mission_steps ADD COLUMN updated_at TEXT;
ALTER TABLE mission_steps ADD COLUMN last_error TEXT;
CREATE UNIQUE INDEX ux_prepared_steps_idempotency ON mission_steps(mission_id,idempotency_key);
CREATE INDEX ix_prepared_steps_state ON mission_steps(mission_id,state);
CREATE TABLE scheduler_control(
  scope TEXT PRIMARY KEY,
  emergency_stop INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);
