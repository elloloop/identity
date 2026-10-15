DROP TRIGGER IF EXISTS users_invalidate_agent_creation_receipts ON users;
DROP FUNCTION IF EXISTS invalidate_agent_creation_receipts();
DROP TABLE IF EXISTS agent_creation_receipts;
