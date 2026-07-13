-- Backing index for the audit-log retention sweep (DeleteAuditEventsBefore,
-- GDPR Art 5(1)(e) storage limitation). The sweep filters and orders by
-- occurred_at_ms within a project; the existing audit indexes
-- (project_id, actor, occurred_at_ms) and (project_id, event_type,
-- occurred_at_ms) require an actor / event_type prefix and so cannot serve a
-- project-wide time range scan. A dedicated (project_id, occurred_at_ms) index
-- keeps the periodic batched delete off a full audit_events scan.
CREATE INDEX IF NOT EXISTS audit_project_time_idx
    ON audit_events (project_id, occurred_at_ms);
