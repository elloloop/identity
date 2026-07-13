-- Backing index for the audit-log retention sweep (DeleteAuditEventsBefore,
-- GDPR Art 5(1)(e) storage limitation), mirroring the postgres driver. The
-- existing (project_id, actor, occurred_at_ms) / (project_id, target,
-- occurred_at_ms) indexes need an actor / target prefix, so a project-wide
-- time range scan falls back to a full table scan without this index.
CREATE INDEX audit_events_project_time_idx
    ON audit_events (project_id, occurred_at_ms);
