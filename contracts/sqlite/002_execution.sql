ALTER TABLE executions ADD COLUMN heartbeat_utc TEXT;
ALTER TABLE executions ADD COLUMN created_utc TEXT;
ALTER TABLE executions ADD COLUMN updated_utc TEXT;
ALTER TABLE executions ADD COLUMN revision INTEGER NOT NULL DEFAULT 1;
ALTER TABLE executions ADD COLUMN idempotency_key TEXT;
ALTER TABLE executions ADD COLUMN command_digest TEXT;
CREATE UNIQUE INDEX ux_execution_operation ON executions(operation_id);
CREATE UNIQUE INDEX ux_execution_idempotency ON executions(idempotency_key);
CREATE INDEX ix_execution_owner ON executions(owner_instance,state);
