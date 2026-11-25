CREATE TABLE legacy_import_steps(
  mission_id TEXT NOT NULL REFERENCES missions(mission_id),
  source_step_id TEXT NOT NULL,
  title TEXT NOT NULL,
  source_state TEXT NOT NULL,
  approved INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(mission_id,source_step_id)
);
CREATE INDEX ix_legacy_import_mission ON legacy_import_steps(mission_id);
