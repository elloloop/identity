ALTER TABLE login_policies
    DROP COLUMN IF EXISTS password_min_length,
    DROP COLUMN IF EXISTS password_require_classes,
    DROP COLUMN IF EXISTS session_idle_timeout_seconds,
    DROP COLUMN IF EXISTS session_absolute_timeout_seconds;
