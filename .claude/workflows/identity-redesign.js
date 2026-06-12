export const meta = {
  name: 'identity-redesign',
  description: 'Identity redesign pipeline: write feature docs + diagrams → agent-panel approval gate (loops) → ADRs (supersede conflicts) → finalized DB schema → sequenced implementation plan',
  whenToUse: 'Run to produce/refresh the identity-service redesign docs, ADRs, schema, and implementation plan for the Project/Tenant/Domain model.',
  phases: [
    { title: 'Document', detail: 'fan-out: one author per feature area, mermaid + ascii diagrams, written to docs/identity/' },
    { title: 'Approve', detail: 'panel of reviewers gate the docs; revise + re-review until zero blockers (max 3 rounds)' },
    { title: 'ADR', detail: 'write new ADRs; supersede conflicting decision-log entries' },
    { title: 'Schema', detail: 'finalized DB schema spec (proto sketch + migration), fixes folded in' },
    { title: 'Plan', detail: 'sequenced, PR-by-PR implementation plan (code lands later as gated slices)' },
  ],
}

const REPO = '/Users/arun/projects/identity'
const DOCS = `${REPO}/docs/identity`
const ADRS = `${REPO}/docs/adr`

// ── Converged model (ground truth for every agent) ──────────────────────────
const SPEC = `
IDENTITY SERVICE — CONVERGED TARGET MODEL (the single source of truth for all docs/ADRs/schema).

WHAT IT IS: identity is a self-hostable (container) and embeddable (Go library) authentication service,
Firebase-Authentication-style. It provides: AuthN (sign-up / login + tokens), Projects (isolated instances),
Tenants + Domains + Login policies (per-company auth governance), and tenant-level membership/admin. Workspaces
and workspace/org membership are NOT part of identity — they are a SEPARATE service built LATER, out of scope for
these docs beyond a one-line boundary note. Do NOT position identity as "WorkOS" and do NOT describe workspaces as
an identity feature. Reference Firebase/WorkOS only as terse factual "equivalent to X" pointers, never as positioning
or marketing.

TWO SERVICES (hard boundary):
- IDENTITY (this) owns: AuthN + the user record + Projects + Tenants + Domains + Login policies + tenant-level
  membership/admin. It answers "who you are, how you may authenticate, and who governs you."
- WORKSPACE/AUTHZ SERVICE (separate, NOT built here) owns: Workspaces, workspace memberships/roles, enrollment/
  visibility policy, and fine-grained/ReBAC authorization. It answers "what you can do with the stuff inside."
  The two connect only at TOKEN ISSUANCE: identity mints a token (who you are + tenant context); the workspace
  service adds workspace context in its own scoped token/session. Identity never says the word "workspace".

THREE "TENANT-LIKE" CONCEPTS, kept strictly separate (conflating them is the main hazard):
- Storage scope  (physical) = the tenant-shard-db scope a call routes to; in single mode this is DefaultTenantID.
- Project        (logical control-plane entity) = Firebase-project-level isolation; ONE project = ONE storage scope.
                  Holds login/OAuth config + credentials. A default project is auto-seeded and MAPS ONTO (does not
                  equal) DefaultTenantID via Project.storage_scope_id.
- Tenant         (logical data-plane entity) = a company governance entity, AUTO-formed per verified non-public
                  email domain; owns domains + login policy + tenant-admins; many tenants live inside one project.

AUTHENTICATION (always open; login is ALWAYS by email/identifier, never by tenant/workspace):
- Global user pool PER PROJECT, keyed by canonical email (unique within project). One person = one User per project.
- Methods: password, OAuth (social), passwordless email OTP + magic link, phone SMS OTP, passkeys/WebAuthn, QR
  cross-device, TOTP 2FA. Email-OTP enforced by default (the trust root for join-requests etc.).
- Tokens: short-lived access JWT carrying { product/project_id, sub (user), email, tenant_id?, auth-facts } +
  refresh; mode=ttl (TTL-bounded) or mode=session (cached SID lookup → instant revocation). Fired-employee =
  remove membership + (instant) session revoke / (TTL) next-refresh drops it.

TENANTS & DOMAINS:
- First user of an unclaimed NON-PUBLIC email domain auto-forms a LATENT tenant (status=latent, NO admin yet).
- Verifying the domain (DNS TXT or email challenge) flips it to CLAIMED; the verifier becomes owner.
- PUBLIC/free providers (gmail.com, outlook.com, yahoo.com, …) are BLOCKLISTED: never form a tenant, can't be
  verified. The blocklist is config (env-seeded + built-in default), consulted on the CANONICAL punycode domain at
  THREE gates: (1) signup tenant-formation, (2) domain verify, (3) derived-membership resolution.

LOGIN POLICY (per tenant; controls HOW, never WHETHER):
- allowed methods, SSO required + connection config, 2FA required. Applies to users whose email domain ∈ the tenant.
- "Restricted in how you log in" (SSO/2FA/method), not "whether" — signup/login always allowed.

TENANT MEMBERSHIP (tenant-level, distinct from workspace membership which is the other service):
- Domain membership is DERIVABLE from email-domain match — counts ONLY against a VERIFIED domain of a CLAIMED tenant.
- Explicit members (external collaborators / admins, any email) + ALL role grants are MATERIALIZED rows.
- Precedence: a materialized TenantMembership.status is AUTHORITATIVE when a row exists; derived membership applies
  only when no row exists. Roles: member | admin | owner. Tenant-admin manages domains/login-policy/billing.
- Invitations (TenantInvitation) add explicit/external members+admins. Join-requests for WORKSPACES live in the
  other service; same-domain users are already tenant members by derivation.

ADMIN / PROVISIONING / SECURITY:
- Platform admin APIs (create projects, mint project credentials, create tenants/tenant-admins, e.g. on payment)
  are crown-jewels: authenticate callers with mTLS client certs or short-lived secrets (NOT static bearer keys),
  least-privileged per caller, and run on an OPTIONAL separate internal-only port deployers can bind private/disable.
  Mirrors Firebase's service-account model, plus the network isolation Firebase gets for free from owning the network.
- InstanceSignup remains the unauthenticated, self-disabling FIRST-ADMIN bootstrap for a fresh single-project/single
  deployment (auth-exempt + rate-limited; self-disables once an admin exists).

DATA MODEL & DB CHOICE:
- DB = POSTGRES for identity (the graph-shaped data left with workspaces; what remains is relational with hard
  uniqueness + transactions). Memory driver for dev/embedded. tenant-shard-db/entdb migrates to the workspace/authz
  service. Isolation: project_id is the leading column of every index + a mandatory WHERE project_id= predicate
  injected once at the repo boundary + Postgres RLS; shard/DB-per-project only for physical-isolation customers.
- CONTROL PLANE entities: Project (id, storage_scope_id unique, name, status, config_json), ProjectCredential
  (public_id unique, kind publishable|secret|mtls, secret_hash, status), PlatformAdmin (email unique global).
- PER-PROJECT entities: User (unique (project_id, canonical_email)), Tenant (latent|claimed), Domain (unique
  (project_id, domain) → one tenant), LoginPolicy (1:1 tenant), TenantMembership (source domain|invited|added; role),
  TenantInvitation; PLUS all kept AuthN tables (RefreshToken, Session, Passkey*, Totp*, RecoveryCode, OAuthIdentity,
  all token/code/challenge tables, IdentityVerificationRecord, AuditEvent) each gaining project_id and (project_id,…)
  uniqueness. DROP → workspace service: Organization, OrganizationMembership, WorkingGroup + MEMBER_OF.

VERIFIED FIXES (apply these; they were caught by adversarial review):
- B1: storage cardinality INVERTS — today tenant=shard; now PROJECT=shard with many tenants inside. RepositoryForTenant
  → RepositoryForProject(projectID); per-request resolution resolves PROJECT (shard) first, then TENANT (logical, from
  email domain / membership). Migration: existing mode=multi org-shards each become their own Project; greenfield uses
  the default project. mode=multi (tenant-as-shard) is removed.
- H2: KEEP canonical email in the existing 'email' field (smallest diff, matches current canonicalizeEmail); unique key
  (project_id, email). Do NOT split into a separate canonical_email field.
- H3: public-domain blocklist consulted at all three gates above, on canonical punycode domain.
- H6: derived membership = verified-domain + claimed-tenant only; materialized row overrides derived.
- M8: RETIRE UserInvitation; tenant invites use TenantInvitation; platform/project invites are separate.
- Misc: platform-admin sessions reuse RefreshToken/Session in a reserved platform scope; "one open invite per
  (tenant,email)" enforced via an atomic revoke-then-insert (no partial-unique, since entdb/memory can't); drop
  uniqueness from Tenant.primary_domain (Domain owns one-tenant-per-domain); fail-safe LoginPolicy.allowed_methods to
  email_otp if empty; remove now-dead MEMBER_OF drain code.
`

// ── Diagram + writing conventions every author must follow ──────────────────
const CONVENTIONS = `
WRITING + DIAGRAM CONVENTIONS (mandatory):
- These are REFERENCE + SETUP docs. Each doc covers exactly two things: (1) WHAT the feature does (factual, precise),
  and (2) HOW to set it up / configure / call it (env vars, config, the RPCs, the request flow). Nothing else.
- ABSOLUTELY NO sales pitch. Forbidden: vision/mission framing, value propositions, "for anyone", "imagine",
  "unlock", "empower", "powerful/elegant/seamless/robust/world-class/cutting-edge", benefit-selling, or any
  comparison used as marketing. State facts, not why they are good.
- Tone: terse, technical, imperative — like Firebase or Postgres reference docs. Short sentences. Prefer tables,
  config snippets, and field lists over prose. Assume a competent engineer who wants to USE it, not be sold on it.
- Reference other products (Firebase, WorkOS) only as a one-line factual "equivalent to X" pointer, never positioning.
- Use **Mermaid** (\`\`\`mermaid) for sequence/flow/ER diagrams that show HOW a flow works; small ASCII where clearer.
  Every diagram MUST be valid Mermaid and match the text.
- Structure per doc: one-line what-it-does → how-it-works (model + diagram) → SETUP (config/env/RPCs) → edge cases/notes.
- Ground terminology in SPEC exactly (Project / Tenant / Domain / User / storage-scope). No invented terms.
`

// ── Feature areas (one author each; distinct file → no write conflicts) ─────
const AREAS = [
  { key: '00-overview', title: 'Overview & setup',
    detail: 'one-paragraph factual statement of what identity is and what it provides; how to run it (container + Go library) with the minimal required config (env vars); the core concepts defined plainly as a glossary (Project, Tenant, Domain, User, storage-scope); a top-level architecture diagram of the control/data planes. State what it is and how to start it — no vision, no marketing.' },
  { key: '01-projects', title: 'Projects (control plane)',
    detail: 'Project as Firebase-project isolation, ProjectCredential (publishable/secret/mtls), PlatformAdmin, the default project + its mapping to DefaultTenantID (non-conflation), project resolution from a key. Sequences: provision a project, mint/rotate keys, resolve project on a request.' },
  { key: '02-authentication', title: 'Authentication',
    detail: 'login-always-by-email principle; every method (password, OAuth, email-OTP, magic-link, phone, passkey, QR, TOTP); token model (access+refresh, ttl vs session), refresh + revocation. Sequence diagrams for password login, OAuth, email-OTP, passkey, and token-refresh/revocation (incl. the fired-employee cutoff).' },
  { key: '03-tenants-domains', title: 'Tenants & domains',
    detail: 'auto-tenant-by-domain (latent→claimed), domain verification (DNS TXT / email), the public-provider blocklist (3 gates, punycode). Sequences: signup forms a latent tenant, domain verification → claim → owner.' },
  { key: '04-login-policies', title: 'Login policies',
    detail: 'per-tenant policy (allowed methods / SSO-required + connection / 2FA), how the login path consults it, controls HOW not WHETHER, fail-safe to email_otp. Sequence: a domain-governed (SSO-enforced) login.' },
  { key: '05-tenant-membership', title: 'Tenant membership',
    detail: 'domain-derived vs materialized membership + the precedence rule (verified+claimed only; row overrides derived), roles (member/admin/owner), TenantInvitation, offboarding/deactivation. Sequences: invite an external admin, a fired employee losing access.' },
  { key: '06-admin-and-security', title: 'Admin APIs & security',
    detail: 'platform-admin provisioning APIs (create projects/tenants/admins, on payment), mTLS/short-lived-secret auth + optional internal-only port, the InstanceSignup first-admin bootstrap, public-vs-internal exposure. Sequences: bootstrap the first admin, provision a tenant on payment.' },
  { key: '07-data-model', title: 'Data model & database',
    detail: 'the full entity model as a Mermaid ER diagram, the Postgres choice + rationale, project isolation (project_id leading column + mandatory predicate + RLS; shard/db-per-project option), per-driver enforcement, the keep/add/drop disposition.' },
  { key: '08-workspace-boundary', title: 'Workspace boundary (what is OUT)',
    detail: 'the identity↔workspace-service split, the token seam, AuthN vs AuthZ (coarse-claims-in-token vs fine-grained PDP), why workspaces/memberships/ReBAC are NOT in identity. Diagram of the two-service interaction.' },
]

const REVIEW_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['dimension', 'approve', 'blocking_findings', 'notes'],
  properties: {
    dimension: { type: 'string' },
    approve: { type: 'boolean', description: 'true only if zero blocking issues on your dimension' },
    blocking_findings: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        required: ['doc', 'issue', 'fix'],
        properties: {
          doc: { type: 'string', description: 'which docs/identity/*.md file' },
          issue: { type: 'string' },
          fix: { type: 'string', description: 'concrete change to make' },
        },
      },
    },
    notes: { type: 'string' },
  },
}

const REVIEWERS = [
  { key: 'completeness', lens: 'Is every feature in SPEC documented, with the key flows covered? Find missing features, missing sequences, missing edge cases (latent tenants, blocklist, revocation, default project, the workspace boundary).' },
  { key: 'correctness', lens: 'Does every doc match SPEC AND the VERIFIED FIXES (B1 project=shard, H2 keep canonical-in-email, H3 three blocklist gates, H6 derived-membership precedence, M8 retire UserInvitation)? Flag any technical error or contradiction with the model.' },
  { key: 'consistency', lens: 'Do the docs agree with each other and use SPEC terminology exactly (Project/Tenant/Domain/storage-scope/workspace)? Find cross-doc contradictions, duplicated-but-divergent explanations, term drift.' },
  { key: 'diagrams', lens: 'Is every Mermaid block syntactically valid and does each diagram match the prose beside it? Flag invalid syntax, diagrams that contradict the text, or key flows that lack a sequence diagram.' },
  { key: 'readability', lens: 'Could a new engineer understand each feature from its doc? Flag unclear structure, missing intros, verbosity, or jargon used without definition.' },
]

// ────────────────────────────────────────────────────────────────────────────
phase('Document')
log(`Writing ${AREAS.length} feature docs with diagrams to docs/identity/`)
const written = await parallel(AREAS.map((a) => () =>
  agent(
    `Write the identity-service documentation file ${DOCS}/${a.key}.md for the feature area "${a.title}".
Scope: ${a.detail}

${CONVENTIONS}

GROUND TRUTH (do not deviate):
${SPEC}

Also read the CURRENT docs at ${REPO}/docs/IDENTITY.md and ${REPO}/docs/embedding.md to ground against today's
state and reuse accurate detail — but the TARGET MODEL in SPEC supersedes anything there that conflicts.
Write a complete, self-contained Markdown file with mermaid sequence/architecture diagrams. Create the docs/identity
directory if needed. Return a one-paragraph summary of what you wrote and which diagrams it contains.`,
    { label: `doc:${a.key}`, phase: 'Document' },
  ),
))
log(`Drafted ${written.filter(Boolean).length}/${AREAS.length} docs`)

// docs-only mode: stop after regenerating the docs so the tone/positioning can be
// reviewed on the live site before spending the panel/ADR/schema/plan budget.
if (args === 'docs-only') {
  return {
    mode: 'docs-only',
    docs_written: written.filter(Boolean).length,
    docs_total: AREAS.length,
    note: 'Review tone + positioning on the live site, then run the full pipeline (no args) for review-gate + ADRs + schema + plan.',
  }
}

// ────────────────────────────────────────────────────────────────────────────
phase('Approve')
let approved = false
let round = 0
const maxRounds = 3
while (!approved && round < maxRounds) {
  round++
  log(`Approval round ${round}: panel reviewing docs/identity/`)
  const reviews = (await parallel(REVIEWERS.map((r) => () =>
    agent(
      `You are the "${r.key}" reviewer in the approval gate for the identity docs in ${DOCS}/ (read every *.md there).
Your lens: ${r.lens}

GROUND TRUTH the docs must satisfy:
${SPEC}

Return your dimension verdict. approve=true ONLY if you found zero blocking issues on your lens. For each blocking
issue give the exact file, the problem, and the concrete fix.`,
      { label: `review:${r.key}#${round}`, phase: 'Approve', schema: REVIEW_SCHEMA },
    ),
  ))).filter(Boolean)

  const blockers = reviews.flatMap((r) => (r.approve ? [] : r.blocking_findings))
  if (blockers.length === 0) {
    approved = true
    log(`Docs APPROVED by the panel in round ${round}`)
    break
  }
  log(`Round ${round}: ${blockers.length} blocking findings → revising`)
  // Group fixes by file so the reviser edits each doc once.
  await agent(
    `Revise the identity docs in ${DOCS}/ to resolve these blocking findings from the approval panel. Edit the named
files in place; keep them consistent with each other and with the GROUND TRUTH. Fix mermaid syntax where flagged.

BLOCKING FINDINGS (JSON):
${JSON.stringify(blockers, null, 2)}

GROUND TRUTH:
${SPEC}

${CONVENTIONS}
Return a summary of the edits you made per file.`,
    { label: `revise#${round}`, phase: 'Approve' },
  )
}
if (!approved) {
  log(`Docs NOT fully approved after ${maxRounds} rounds — proceeding to capture remaining gaps in the plan; review docs/identity/ before implementing.`)
}

// ────────────────────────────────────────────────────────────────────────────
phase('ADR')
const adrSummary = await agent(
  `Now that the identity feature docs in ${DOCS}/ are approved, author Architecture Decision Records.
1. Read the existing decision log in ${REPO}/docs/IDENTITY.md (the numbered "decision log" §-entries) and any ADRs.
2. Create ${ADRS}/ (numbered NNNN-title.md, standard ADR format: Context / Decision / Status / Consequences).
3. Write NEW ADRs for the load-bearing decisions in SPEC: (a) two-service split (identity vs workspace/authz);
   (b) Project = the isolation shard (replacing tenant-as-shard / mode=multi); (c) global user pool per project,
   login-always-by-email; (d) auto-tenant-by-verified-domain + public-domain blocklist; (e) login policy controls
   HOW not WHETHER; (f) tenant membership in identity, workspace membership OUT; (g) Postgres as the identity datastore
   (entdb→workspace service); (h) admin APIs via mTLS/short-lived secret + optional internal port.
4. For each NEW ADR that conflicts with an existing decision-log entry (notably the old "identity tenant ↔ shard 1:1",
   "OrganizationSignup is the multi-tenant entry point", "mode=multi"), mark the OLD decision **Superseded by ADR-NNNN**
   — add a short "Superseded" note in docs/IDENTITY.md pointing to the new ADR (do not silently delete the history).
Return the list of ADRs created and which prior decisions each supersedes.`,
  { label: 'adrs', phase: 'ADR' },
)

// ────────────────────────────────────────────────────────────────────────────
phase('Schema')
const schemaSummary = await agent(
  `Write the finalized database schema spec to ${DOCS}/09-schema.md, consistent with the approved docs + ADRs.
Include: (1) control-plane entities (Project, ProjectCredential, PlatformAdmin) and per-project entities (User, Tenant,
Domain, LoginPolicy, TenantMembership, TenantInvitation) + every KEPT auth table — each with full field list, primary
key, uniqueness (scoped (project_id,…)), indexes, FKs; (2) a Mermaid ER diagram; (3) the keep/modify/add/drop table vs
the current proto schema (read ${REPO}/proto/identity/schema/schema.proto); (4) the Postgres DDL sketch for the new
tables + the project_id isolation (leading-column indexes, mandatory predicate, RLS); (5) all the VERIFIED FIXES folded
in (B1 project=shard + RepositoryForProject; H2 keep canonical in 'email'; H3 blocklist 3 gates; H6 derived-membership
precedence; M8 retire UserInvitation; platform-admin sessions; atomic one-open-invite; drop Tenant.primary_domain
uniqueness). Ground in SPEC:
${SPEC}
Return a summary + the path written.`,
  { label: 'schema', phase: 'Schema' },
)

// ────────────────────────────────────────────────────────────────────────────
phase('Plan')
const planSummary = await agent(
  `Write a sequenced, PR-by-PR implementation plan to ${DOCS}/10-implementation-plan.md for building the model in the
approved docs + schema. Each step = one feature-bounded PR with: goal, files touched, the proto/migration/driver work
(memory+postgres+conformance), tests, and the AGENTS.md review-gate as the merge gate. Order it so each PR is shippable
and the risky storage-model inversion (B1: RepositoryForTenant→RepositoryForProject, project-then-tenant resolution,
remove mode=multi) is staged safely with a migration step. Start from the current state (InstanceSignup + single-mode
global pool already landed). Explicitly note that CODE is implemented later as these gated slices, not in this docs run.
Ground in SPEC:
${SPEC}
Return the ordered list of PRs (title + one-line goal each) and the path written.`,
  { label: 'plan', phase: 'Plan' },
)

return {
  docs_written: written.filter(Boolean).length,
  docs_total: AREAS.length,
  docs_approved: approved,
  approval_rounds: round,
  adr_summary: adrSummary,
  schema_summary: schemaSummary,
  plan_summary: planSummary,
  artifacts: {
    docs: `${DOCS}/`,
    adrs: `${ADRS}/`,
    schema: `${DOCS}/09-schema.md`,
    plan: `${DOCS}/10-implementation-plan.md`,
  },
}
