BEGIN;
DROP TRIGGER IF EXISTS users_invalidate_agent_creation_receipts_update;
DROP TRIGGER IF EXISTS users_invalidate_agent_creation_receipts_delete;
DROP TABLE IF EXISTS agent_creation_receipts;
COMMIT;
