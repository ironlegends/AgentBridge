-- Stable extension: prior migrations 001-006 must retain their exact SHA.
-- Runtime LegacyMissionOwnerBackfill applies the verified owner transfer
-- atomically in the same transaction as this schema migration.
CREATE INDEX idx_attached_memberships_by_context
 ON mission_memberships(context_hash,state,mission_id);
