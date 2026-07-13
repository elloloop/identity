-- Audit trail, mirroring the postgres driver's audit_events table. Rows
-- record security-relevant actions (login, password change, passkey add,
-- session revoke, ...) for accountability and for the self-service data
-- export (GDPR Art 15).
--
-- actor and target are user ids OR system principals (e.g. "system:admin"),
-- so they are plain TEXT with NO users() foreign key: an event must survive
-- the deletion of the user it references (the trail is retained on DeleteUser
-- for accountability). details holds event-specific JSON as text.
CREATE TABLE audit_events (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    event_type      TEXT NOT NULL,
    actor           TEXT NOT NULL DEFAULT '',
    target          TEXT NOT NULL DEFAULT '',
    ip_address      TEXT NOT NULL DEFAULT '',
    user_agent      TEXT NOT NULL DEFAULT '',
    success         INTEGER NOT NULL DEFAULT 0,
    details         TEXT NOT NULL DEFAULT '{}',
    occurred_at_ms  INTEGER NOT NULL
);
CREATE INDEX audit_events_project_actor_idx
    ON audit_events (project_id, actor, occurred_at_ms DESC);
CREATE INDEX audit_events_project_target_idx
    ON audit_events (project_id, target, occurred_at_ms DESC);
