export const meta = {
  name: 'identity-redesign-build',
  description: 'Finalize the identity redesign: complete schema (+ project auth-domains), ADRs that supersede old decisions, an exhaustive PR-by-PR implementation plan, and the build-verified additive Postgres migration for the new tables',
  phases: [
    { title: 'Schema', detail: 'finalized entity model + Postgres DDL, all fixes folded in' },
    { title: 'ADR', detail: 'lock decisions; supersede the old tenant=shard / mode=multi / OrganizationSignup entries' },
    { title: 'Plan', detail: 'exhaustive sequenced PR-by-PR implementation plan to done' },
    { title: 'Build', detail: 'additive migration 0013 creating the new tables, build-verified' },
    { title: 'Verify', detail: 'adversarial check: SQL validity, schema match, plan completeness, build green' },
  ],
}

const REPO = '/Users/arun/projects/identity'

const SPEC = `
IDENTITY REDESIGN — CONVERGED TARGET MODEL (single source of truth). Postgres is the datastore.

TWO SERVICES: identity owns AuthN + User + Projects + Tenants + Domains + Login policies + tenant-level
membership/admin. Workspaces + workspace membership + fine-grained/ReBAC authz are a SEPARATE service (NOT here).
They meet only at token issuance. Identity never models "workspace".

THREE TENANT-LIKE CONCEPTS kept distinct: storage scope (physical tenant-shard, = DefaultTenantID in single mode);
Project (logical control-plane isolation entity, ONE per storage scope, = Firebase project); Tenant (logical
data-plane company entity, auto-formed per verified non-public email domain, many per project).

CONTROL PLANE (platform-global; the registry of projects):
- Project: id, storage_scope_id (UNIQUE; the shard it maps onto; the default project maps onto DefaultTenantID but
  is NOT equal to it), name, status (active|suspended), config_json (enabled login methods, OAuth providers, email
  templates, TTLs), created_at, updated_at.
- ProjectCredential: id, project_id, kind (publishable|secret|mtls), public_id (UNIQUE; the lookup handle), secret_hash
  (sha256; empty for publishable/mtls), status (active|revoked), created_at, last_used_at, revoked_at.
- ProjectAuthDomain (NEW — per-project serving hostname so one deployment serves product-branded domains):
  id, project_id, hostname (UNIQUE across the whole deployment — one host -> one project), is_primary (bool; the
  hostname used to build email/oauth links), verified_at (0 until DNS/ownership verified), created_at. The request
  resolves its Project by publishable/secret key OR by the Host header -> ProjectAuthDomain.hostname. NOTE: this
  "auth domain" (a HOSTNAME identity is served on, e.g. auth.easyloops.app) is a DIFFERENT concept from the Tenant
  email Domain (e.g. acme.com); never conflate them.
- PlatformAdmin: id, email (UNIQUE global), password_hash, totp_required, status, created_at, last_login_at.

PER-PROJECT DATA PLANE (every row carries project_id; one storage scope per project):
- User: existing auth/profile fields PLUS project_id. Uniqueness becomes (project_id, email) where email already
  holds the canonical form (KEEP canonical in 'email' — do NOT add a separate canonical_email field; matches today's
  canonicalizeEmail). One identity per person per project. Drop any organization linkage.
- Tenant: id, project_id, name, primary_domain (plain indexed convenience, NOT unique), status (latent|claimed|
  suspended). Auto-forms (latent) from the first user of a non-public email domain; no admin until a domain is
  verified (-> claimed).
- Domain (Tenant email domain): id, project_id, tenant_id, domain (UNIQUE (project_id, domain) — one tenant per
  domain), verification_method (dns_txt|email), status (pending|verified|failed), verified_at. PUBLIC providers
  (gmail.com, outlook.com, yahoo.com, ...) are BLOCKLISTED at THREE gates (signup tenant-formation, domain verify,
  derived-membership) on the canonical punycode domain.
- LoginPolicy: id, project_id, tenant_id (UNIQUE per project; 1:1 Tenant), allowed_methods (csv; fail-safe to
  email_otp if empty), sso_required, sso_connection_json, require_2fa. Controls HOW domain users authenticate, never
  WHETHER.
- TenantMembership: id, project_id, tenant_id, user_id, source (domain|invited|added), role (member|admin|owner),
  status (active|pending|inactive). UNIQUE (project_id, tenant_id, user_id). Materialized for explicit members + ALL
  role grants; pure domain membership is derivable. Precedence: a materialized row's status is authoritative when a
  row exists; derived domain-membership applies only when no row exists and only against a VERIFIED domain of a
  CLAIMED tenant. Tenant-admin manages domains/login-policy/billing; distinct from workspace roles.
- TenantInvitation: id, project_id, tenant_id, token_hash (UNIQUE per project), email, invited_by, role, status
  (pending|accepted|revoked|expired), expires_at, accepted_at, created_at. One open invite per (project,tenant,email)
  enforced via an atomic revoke-then-insert (entdb/memory can't do partial-unique).
- KEPT auth tables (each gains project_id, uniqueness -> (project_id, ...)): RefreshToken, Session, PasswordResetToken,
  EmailVerificationToken, EmailChangeToken, EmailLoginCode, MagicLinkToken, LoginChallenge, PasskeyCredential,
  PasskeyChallenge, TotpCredential, RecoveryCode, QrLoginSession, OAuthIdentity (unique (project_id, provider,
  provider_user_id)), OAuthOneTimeCode, PhoneVerificationCode, IdentityVerificationRecord, AuditEvent. Platform-admin
  sessions reuse RefreshToken/Session in a reserved platform scope.
- DROP (relocate to workspace service): Organization, OrganizationMembership, WorkingGroup + MEMBER_OF.

VERIFIED FIXES (apply): B1 storage cardinality inverts — PROJECT=shard (not tenant=shard); RepositoryForTenant ->
RepositoryForProject; per-request resolution resolves PROJECT (shard) first (by key or Host), then TENANT (logical)
from email domain/membership; mode=multi removed; existing mode=multi org-shards each become their own Project;
greenfield uses the default project. H2 keep canonical email in 'email'. H3 blocklist at three gates on punycode
domain. H6 derived-membership = verified-domain+claimed-tenant only; materialized overrides derived. M8 retire
UserInvitation; tenant invites use TenantInvitation. Drop Tenant.primary_domain uniqueness. Remove dead MEMBER_OF code.

ISOLATION (Postgres): project_id is the leading column of every unique + secondary index; every query carries a
mandatory WHERE project_id = predicate injected once at the repo boundary; Postgres RLS as defense-in-depth;
schema/db-per-project only for physical-isolation customers. The default project is seeded on boot mapped to
DefaultTenantID (logical Project entity, NOT equal to the storage id).

CURRENT MIGRATIONS: internal/repo/postgres/migrations/0001..0012 (golang-migrate, embedded, up/down). The next is 0013.
`

phase('Schema')
const schema = await agent(
  `Finalize the identity redesign DATABASE SCHEMA. Read the current proto schema at
${REPO}/proto/identity/schema/schema.proto and the existing migrations at ${REPO}/internal/repo/postgres/migrations/
(0001..0012) to ground field shapes and conventions.

Target model:
${SPEC}

Write ${REPO}/docs/redesign/schema.md containing: (1) a control-plane vs data-plane overview; (2) for EVERY entity
(control plane incl. ProjectAuthDomain, and per-project incl. the kept auth tables) a full field list with type,
nullability, primary key, uniqueness (scoped to project where applicable), indexes, and FKs; (3) a keep/modify/add/drop
table vs today's schema; (4) the per-project isolation rules. THEN write the complete, ready-to-apply Postgres DDL for
ALL the NEW tables only (projects, project_credentials, project_auth_domains, platform_admins, tenants, domains,
login_policies, tenant_memberships, tenant_invitations) — additive, creating new tables that reference the existing
users table where needed, NOT altering existing tables (the project_id backfill on existing tables is a later slice).
Output the DDL inline in the doc AND return it verbatim as the final part of your message so the Build phase can use it.
Be exact and complete.`,
  { label: 'schema', phase: 'Schema' },
)

phase('ADR')
const adrs = await agent(
  `Author Architecture Decision Records for the redesign. Read the decision log in ${REPO}/docs/IDENTITY.md.
Create ${REPO}/docs/adr/ (NNNN-title.md, standard Context/Decision/Status/Consequences). Write NEW ADRs for:
two-service split; Project = the isolation shard (replacing tenant=shard / mode=multi); global user pool per project +
login-always-by-email; auto-tenant-by-verified-domain + public-domain blocklist; login policy controls HOW not WHETHER;
tenant membership in identity, workspace membership OUT; Postgres as the datastore; admin APIs via mTLS/short-lived
secret + optional internal port; per-project serving auth-domains + Host-based project resolution. For each conflicting
existing decision-log entry (tenant<->shard 1:1, OrganizationSignup as the multi-tenant entry point, mode=multi), add a
"Superseded by ADR-NNNN" note. Ground in:
${SPEC}
Return the list of ADRs written and what each supersedes.`,
  { label: 'adrs', phase: 'ADR' },
)

phase('Plan')
const plan = await agent(
  `Write the EXHAUSTIVE PR-by-PR implementation plan to ${REPO}/docs/redesign/implementation-plan.md to take the
redesign to done. Each step = one feature-bounded, shippable PR with: goal, files touched, the proto/migration/driver
work (memory + postgres + conformance), tests (unit + e2e), and the AGENTS.md review-gate as the merge gate. Order so
each PR is shippable and the storage-model inversion (B1: RepositoryForTenant -> RepositoryForProject, project-then-
tenant resolution, remove mode=multi) is staged with expand-backfill-contract migrations and a data-migration for
existing single-mode data -> default project. Note what is already shipped (PR #195 the migrate subcommand) and what
this workflow lands (the additive new-tables migration). Cover EVERY remaining slice: project resolution by key+Host,
project auth-domains + per-project cookie/email/oauth/CORS/issuer, tenants/domains/login-policy/membership/invitations,
the blocklist, dropping Organization/WorkingGroup, the project_id backfill on existing tables, conformance, and the
control-plane admin APIs (mTLS + optional port). Ground in:
${SPEC}
Return the ordered list of PRs (title + one-line goal each).`,
  { label: 'plan', phase: 'Plan' },
)

phase('Build')
const build = await agent(
  `Implement the FIRST foundation slice: the additive Postgres migration that creates the new redesign tables.
Use the DDL produced by the schema phase (below) — adjust only to be valid, idempotent-safe golang-migrate SQL.

SCHEMA-PHASE OUTPUT (use its DDL):
${schema}

Tasks:
1. Write ${REPO}/internal/repo/postgres/migrations/0013_redesign_core_tables.up.sql creating: projects,
   project_credentials, project_auth_domains, platform_admins, tenants, domains, login_policies, tenant_memberships,
   tenant_invitations — with PKs, the uniqueness constraints and indexes from the schema (hostname globally unique;
   (project_id, domain) unique; (project_id, tenant_id, user_id) unique; project_credentials.public_id unique;
   projects.storage_scope_id unique; etc.), and FKs (FK to the existing users table where the schema specifies).
   Additive only — do NOT ALTER existing tables.
2. Write the matching ${REPO}/internal/repo/postgres/migrations/0013_redesign_core_tables.down.sql dropping them in
   reverse dependency order.
3. Verify the binary still builds: run \`cd ${REPO} && go build ./...\` and \`go vet ./internal/repo/postgres/...\`.
   The embedded migration FS must still load — run \`go test ./internal/repo/postgres/ -run TestMigrate_EmptyDSN -count=1\`
   to confirm the migration source compiles into the binary.
4. Report: the files written, and the exact build/vet/test results (paste the output). If build fails, FIX the SQL/
   embedding and re-verify until green.
Ground in:
${SPEC}`,
  { label: 'build-migration', phase: 'Build' },
)

phase('Verify')
const verdict = await agent(
  `Adversarially verify the redesign foundation just produced. Check:
(1) the migration SQL at ${REPO}/internal/repo/postgres/migrations/0013_redesign_core_tables.up.sql is valid Postgres,
    matches docs/redesign/schema.md (every table/constraint/index/FK present, names consistent), and the .down.sql
    drops everything in correct reverse order;
(2) isolation: project_id is present + leading on indexes; uniqueness scoped to project where the schema requires;
    hostname globally unique; no cross-project leak;
(3) the public-email-domain blocklist and the auth-domain-vs-email-domain distinction are correctly reflected in the
    schema doc;
(4) the build is actually green (run \`cd ${REPO} && go build ./...\` and the migrate test) — report real output;
(5) the implementation plan covers every remaining slice with the storage inversion safely staged.
List concrete defects (severity + fix). Give an overall verdict: is the foundation sound, and what are the top 3
things the next PR must do. Be specific.`,
  { label: 'verify', phase: 'Verify' },
)

return {
  artifacts: {
    schema: `${REPO}/docs/redesign/schema.md`,
    adrs: `${REPO}/docs/adr/`,
    plan: `${REPO}/docs/redesign/implementation-plan.md`,
    migration: `${REPO}/internal/repo/postgres/migrations/0013_redesign_core_tables.{up,down}.sql`,
  },
  adr_summary: adrs,
  plan_summary: plan,
  build_result: build,
  verdict,
}
