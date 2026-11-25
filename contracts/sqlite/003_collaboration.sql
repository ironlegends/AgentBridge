CREATE TABLE mission_memberships(
    mission_id TEXT NOT NULL REFERENCES missions(mission_id),
    context_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('owner','member')),
    state TEXT NOT NULL CHECK(state IN ('invited','attached')),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(mission_id,context_hash)
);
CREATE UNIQUE INDEX ux_mission_owner ON mission_memberships(mission_id) WHERE role='owner' AND state='attached';
CREATE TABLE mission_checkpoints(
    checkpoint_id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL REFERENCES missions(mission_id),
    context_hash TEXT NOT NULL,
    summary TEXT NOT NULL CHECK(length(summary)>0 AND length(summary)<=4096),
    revision INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(mission_id,revision)
);
