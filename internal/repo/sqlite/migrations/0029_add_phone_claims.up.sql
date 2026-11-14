-- 0029_add_phone_claims.up.sql
--
-- phone_number_claims is which account holds a verified phone number in a
-- project that keeps numbers unique (phone.unique): one account per
-- (project, number), by its primary key. It starts empty.
CREATE TABLE phone_number_claims (
    project_id    TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    phone_number  TEXT NOT NULL CHECK (phone_number <> ''),
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    claimed_at_ms INTEGER NOT NULL,
    PRIMARY KEY (project_id, phone_number)
);
CREATE INDEX phone_number_claims_project_user_idx ON phone_number_claims (project_id, user_id);
