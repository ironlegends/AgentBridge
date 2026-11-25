CREATE TABLE legacy_import_events(
    mission_id TEXT NOT NULL REFERENCES missions(mission_id),
    source_seq INTEGER NOT NULL CHECK(source_seq > 0),
    source_type TEXT NOT NULL,
    summary TEXT NOT NULL,
    PRIMARY KEY(mission_id,source_seq)
);
CREATE INDEX ix_legacy_import_events ON legacy_import_events(mission_id,source_seq);
