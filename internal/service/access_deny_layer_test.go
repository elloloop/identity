package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/config"
)

// testCfg is a bare deployment config: the built-in public-provider set with
// no GATEWAY_PUBLIC_EMAIL_DOMAINS additions.
var testCfg = &config.Config{}

// The deny layer ("work email only") subtracts from whatever the access mode
// admitted. These tests pin the three things that make it trustworthy: it
// refuses on BOTH signup and login, it cannot admit anyone the mode refused,
// and it is enforced at every door an address can enter or move through.

// workEmailOnlyJSON is the config an operator sets for "open to everyone at a
// company, closed to consumer mailboxes".
const workEmailOnlyJSON = `{"access":{"mode":"open","block_public_email_domains":true}}`

// ── the deny decision itself ─────────────────────────────────────────────

func TestAccessDenies_PersonalDomains(t *testing.T) {
	t.Parallel()
	cfg, err := ParseProjectConfig(workEmailOnlyJSON)
	require.NoError(t, err)
	a := cfg.Access

	for _, addr := range []string{
		"someone@gmail.com",
		"someone@outlook.com",
		"someone@yahoo.co.uk",
		"someone@icloud.com",
		"someone@proton.me",
		"someone@qq.com",
	} {
		require.True(t, a.denies(testCfg, canonicalize(addr)), "expected %s to be denied", addr)
	}
	for _, addr := range []string{"someone@corp.example", "someone@acme.co"} {
		require.False(t, a.denies(testCfg, canonicalize(addr)), "expected %s to be allowed", addr)
	}
}

// googlemail.com canonicalizes to gmail.com, so the block catches it without
// the table carrying a second entry — the case that would silently slip
// through if matching ran on the raw domain.
func TestAccessDenies_CanonicalizesBeforeMatching(t *testing.T) {
	t.Parallel()
	cfg, err := ParseProjectConfig(workEmailOnlyJSON)
	require.NoError(t, err)

	require.True(t, cfg.Access.denies(testCfg, canonicalize("Someone@GoogleMail.COM")))
	require.True(t, cfg.Access.denies(testCfg, canonicalize("Some.One+tag@GMAIL.com")))
}

func TestAccessDenies_BlockedDomainsAndExemptions(t *testing.T) {
	t.Parallel()
	cfg, err := ParseProjectConfig(
		`{"access":{"mode":"open","blocked_domains":["Rival.example"],` +
			`"block_public_email_domains":true,` +
			`"exempt_emails":["Contractor+work@GMail.com"]}}`,
	)
	require.NoError(t, err)
	a := cfg.Access

	require.True(t, a.denies(testCfg, canonicalize("someone@rival.example")), "blocked_domains entry")
	require.True(t, a.denies(testCfg, canonicalize("other@gmail.com")), "personal domain, not exempt")
	// The exemption is matched canonically, so the dotted/untagged spelling of
	// the listed address is the same person.
	require.False(t, a.denies(testCfg, canonicalize("contractor@gmail.com")), "exempt address")
	require.False(t, a.denies(testCfg, canonicalize("Contractor+other@gmail.com")), "exempt address, other tag")
}

// A malformed address is the format validator's to refuse. Folding it into
// "blocked" here would report the wrong reason for the refusal.
func TestAccessDenies_NoDomain_IsNotDenied(t *testing.T) {
	t.Parallel()
	cfg, err := ParseProjectConfig(workEmailOnlyJSON)
	require.NoError(t, err)
	require.False(t, cfg.Access.denies(testCfg, canonicalize("no-at-sign")))
}

// ── composition with the mode ────────────────────────────────────────────

// The layer only ever SUBTRACTS: it can never admit someone the mode refused.
func TestAccessDenyLayer_CannotAdmitWhatTheModeRefused(t *testing.T) {
	t.Parallel()
	// An exemption on an invite-only project does not create a signup path.
	cfg, err := ParseProjectConfig(
		`{"access":{"mode":"invite","block_public_email_domains":true,` +
			`"exempt_emails":["contractor@gmail.com"]}}`,
	)
	require.NoError(t, err)

	require.False(t, accessPermits(testCfg, cfg.Access, canonicalize("contractor@gmail.com"), true),
		"exempt address must still not self-signup on an invite-only project")
	require.True(t, accessPermits(testCfg, cfg.Access, canonicalize("contractor@gmail.com"), false),
		"exempt address may log in, which invite mode allows")
}

// The deny layer composes with allowlist mode: a listed domain still loses to
// a block, because the block is applied after the mode admits.
func TestAccessDenyLayer_ComposesWithAllowlist(t *testing.T) {
	t.Parallel()
	cfg, err := ParseProjectConfig(
		`{"access":{"mode":"allowlist","allowed_domains":["corp.example","gmail.com"],` +
			`"block_public_email_domains":true}}`,
	)
	require.NoError(t, err)

	require.True(t, accessPermits(testCfg, cfg.Access, canonicalize("dev@corp.example"), true))
	require.False(t, accessPermits(testCfg, cfg.Access, canonicalize("dev@gmail.com"), true),
		"an allowlisted consumer domain is still refused by the deny layer")
	require.False(t, accessPermits(testCfg, cfg.Access, canonicalize("dev@other.example"), true),
		"still not on the allowlist")
}

// The decisive property from the design: the block gates LOGIN too, not just
// signup. Gating only signup would leave a project that switches to
// work-email-only authenticating every consumer address forever.
func TestAccessDenyLayer_GatesLoginNotOnlySignup(t *testing.T) {
	t.Parallel()
	svc, _, _ := newAuthSvcWithMailer(t)
	ctx := accessScope(t, workEmailOnlyJSON)

	require.ErrorIs(t, svc.enforceProjectAccessSignup(ctx, canonicalize("new@gmail.com")), ErrAccessNotAllowed)
	require.ErrorIs(t, svc.enforceProjectAccessLogin(ctx, canonicalize("existing@gmail.com")), ErrAccessNotAllowed)

	require.NoError(t, svc.enforceProjectAccessSignup(ctx, canonicalize("new@corp.example")))
	require.NoError(t, svc.enforceProjectAccessLogin(ctx, canonicalize("existing@corp.example")))
}

// A denied address must not receive credential mail either — otherwise a
// blocked domain still costs SMTP reputation and confirms the address to its
// recipient.
func TestAccessDenyLayer_SuppressesCredentialMail(t *testing.T) {
	t.Parallel()
	svc, _, _ := newAuthSvcWithMailer(t)
	ctx := accessScope(t, workEmailOnlyJSON)

	require.False(t, svc.accessAllowsCodeSend(ctx, canonicalize("someone@gmail.com")))
	require.True(t, svc.accessAllowsCodeSend(ctx, canonicalize("someone@corp.example")))
}

// ── validation: an inert field is a misconfiguration, not a no-op ────────

func TestAccessDenyLayer_ValidationRejectsInertConfig(t *testing.T) {
	t.Parallel()
	for name, cfgJSON := range map[string]string{
		"exemption with no deny layer":   `{"access":{"mode":"open","exempt_emails":["a@b.com"]}}`,
		"deny layer on a closed project": `{"access":{"mode":"closed","block_public_email_domains":true}}`,
		// An unset mode denies everyone under default-DENY exactly as "closed"
		// does, so a deny layer there is equally inert and must fail the same way.
		"deny layer with no mode":          `{"access":{"block_public_email_domains":true}}`,
		"blocked_domains given an address": `{"access":{"mode":"open","blocked_domains":["a@b.com"]}}`,
		"blocked_domains without a dot":    `{"access":{"mode":"open","blocked_domains":["localhost"]}}`,
		"blank blocked_domains entry":      `{"access":{"mode":"open","blocked_domains":["  "]}}`,
		"blank exemption entry": `{"access":{"mode":"open","block_public_email_domains":true,` +
			`"exempt_emails":["  "]}}`,
		"malformed exemption": `{"access":{"mode":"open","block_public_email_domains":true,` +
			`"exempt_emails":["not-an-email"]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseProjectConfig(cfgJSON)
			require.Error(t, err, "expected %s to be rejected", name)
		})
	}
}

func TestAccessDenyLayer_ValidConfigsParse(t *testing.T) {
	t.Parallel()
	for name, cfgJSON := range map[string]string{
		"open + block":            workEmailOnlyJSON,
		"invite + block":          `{"access":{"mode":"invite","block_public_email_domains":true}}`,
		"blocked_domains only":    `{"access":{"mode":"open","blocked_domains":["rival.example"]}}`,
		"block + valid exemption": `{"access":{"mode":"open","block_public_email_domains":true,"exempt_emails":["c@gmail.com"]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseProjectConfig(cfgJSON)
			require.NoError(t, err)
		})
	}
}

// The env-configured default project goes through the SAME validation as the
// config_json path, so a deployment cannot express a policy a project cannot.
func TestAccessSpec_AppliesTheSameValidation(t *testing.T) {
	t.Parallel()
	_, err := NewProjectAccessConfig(ProjectAccessConfig{
		Mode:         AccessModeOpen,
		ExemptEmails: []string{"a@b.com"},
	})
	require.Error(t, err, "exemption with no deny layer must fail from env too")

	a, err := NewProjectAccessConfig(ProjectAccessConfig{
		Mode:                    AccessModeOpen,
		BlockPublicEmailDomains: true,
		BlockedDomains:          []string{"Rival.EXAMPLE"},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"rival.example"}, a.BlockedDomains, "entries canonicalized once at build time")
	require.True(t, a.denies(testCfg, canonicalize("x@gmail.com")))
	require.True(t, a.denies(testCfg, canonicalize("x@rival.example")))
}

// blocked_domains is a property of the project alone, so it works against a
// deployment that has added no GATEWAY_PUBLIC_EMAIL_DOMAINS of its own. cfg is
// a required argument rather than a nil-tolerant one: a deny decision that
// silently degrades when its provider set is unavailable is the one direction
// this function must never fail in.
func TestAccessDenies_BareConfig_KeepsBlockedDomains(t *testing.T) {
	t.Parallel()
	cfg, err := ParseProjectConfig(
		`{"access":{"mode":"open","block_public_email_domains":true,"blocked_domains":["rival.example"]}}`,
	)
	require.NoError(t, err)

	require.True(t, cfg.Access.denies(testCfg, canonicalize("x@rival.example")))
	require.True(t, cfg.Access.denies(testCfg, canonicalize("x@gmail.com")))
	require.False(t, cfg.Access.denies(testCfg, canonicalize("x@corp.example")))
}

// An entry that canonicalization cannot normalize into an address's domain form
// can never match, so it is inert — and for a DENY rule inert means fail-OPEN:
// the operator sees the rule in their config and believes it is holding.
// Wildcards are the realistic case, since matching is exact-domain only.
func TestAccessDenyLayer_RejectsDomainEntriesThatCouldNeverMatch(t *testing.T) {
	t.Parallel()
	for _, entry := range []string{
		"*.rival.example",
		".rival.example",
		"rival..example",
		"rival.example..",
		"http://rival.example",
		"rival.example/path",
	} {
		t.Run(entry, func(t *testing.T) {
			_, err := ParseProjectConfig(
				`{"access":{"mode":"open","blocked_domains":["` + entry + `"]}}`,
			)
			require.Error(t, err, "entry %q matches nothing and must be refused, not stored", entry)
		})
	}
	// The same rule guards the allowlist, where an inert entry fails closed.
	_, err := ParseProjectConfig(`{"access":{"mode":"allowlist","allowed_domains":["*.corp.example"]}}`)
	require.Error(t, err)
}

// NewDefaultProjectAccess exists to keep the env-to-policy mapping in one
// place, so the thing worth pinning is that it maps EVERY field — a helper that
// silently drops one is exactly the drift it was introduced to prevent, and
// nothing else in the suite would notice.
func TestNewDefaultProjectAccess_MapsEveryField(t *testing.T) {
	t.Parallel()
	access, err := NewDefaultProjectAccess(&config.Config{
		DefaultProjectAccessMode:              AccessModeAllowlist,
		DefaultProjectAllowedEmails:           "Op@Example.COM",
		DefaultProjectAllowedDomains:          "Corp.Example.",
		DefaultProjectBlockPublicEmailDomains: true,
		DefaultProjectBlockedEmailDomains:     "Rival.EXAMPLE",
		DefaultProjectExemptEmails:            "Contractor+work@GMail.com",
	})
	require.NoError(t, err)

	// Each assertion also proves the value was canonicalized on the way through,
	// so the env path compares like-against-like exactly as config_json does.
	require.Equal(t, AccessModeAllowlist, access.Mode)
	require.Equal(t, []string{"op@example.com"}, access.AllowedEmails)
	require.Equal(t, []string{"corp.example"}, access.AllowedDomains)
	require.True(t, access.BlockPublicEmailDomains)
	require.Equal(t, []string{"rival.example"}, access.BlockedDomains)
	require.Equal(t, []string{"contractor@gmail.com"}, access.ExemptEmails)

	// And the policy it produces actually enforces all three deny rules.
	require.True(t, access.denies(testCfg, canonicalize("someone@gmail.com")))
	require.True(t, access.denies(testCfg, canonicalize("someone@rival.example")))
	require.False(t, access.denies(testCfg, canonicalize("contractor@gmail.com")))
}

// A malformed env policy is returned as an error, never silently downgraded —
// both callers depend on that to fail the boot or fall back to deny-all.
func TestNewDefaultProjectAccess_PropagatesValidationErrors(t *testing.T) {
	t.Parallel()
	// The default access mode is "closed", on which a deny layer is inert.
	_, err := NewDefaultProjectAccess(&config.Config{
		DefaultProjectAccessMode:              AccessModeClosed,
		DefaultProjectBlockPublicEmailDomains: true,
	})
	require.Error(t, err, "a deny layer on a mode that admits nobody must not boot")

	_, err = NewDefaultProjectAccess(&config.Config{
		DefaultProjectAccessMode:   AccessModeOpen,
		DefaultProjectExemptEmails: "someone@corp.example",
	})
	require.Error(t, err, "an exemption with no deny layer must not boot")
}

// ── the email-change door ────────────────────────────────────────────────

// Email change was an unguarded door: it moved an account's address without
// consulting the project's access policy at all, which let a member of any
// restricted project walk their account to an address the project refuses.
func TestRequestEmailChange_EnforcesProjectAccess(t *testing.T) {
	t.Parallel()
	svc, repo, _ := newAuthSvcWithMailer(t)
	user := seedUserWithPassword(t, repo, "dev@corp.example", "Str0ng!Pass1")
	ctx := accessScope(t, workEmailOnlyJSON)

	err := svc.RequestEmailChange(ctx, user.ID, "dev@gmail.com", "Str0ng!Pass1")
	require.ErrorIs(t, err, ErrAccessNotAllowed, "must not move an account to a blocked domain")

	require.NoError(t, svc.RequestEmailChange(ctx, user.ID, "dev@other-corp.example", "Str0ng!Pass1"))
}

// An invite-only project must still let an existing member change address:
// the account is not being created, so the check runs as a LOGIN.
func TestRequestEmailChange_InviteProject_AllowsExistingMember(t *testing.T) {
	t.Parallel()
	svc, repo, _ := newAuthSvcWithMailer(t)
	user := seedUserWithPassword(t, repo, "dev@corp.example", "Str0ng!Pass1")
	ctx := accessScope(t, `{"access":{"mode":"invite"}}`)

	require.NoError(t, svc.RequestEmailChange(ctx, user.ID, "dev2@corp.example", "Str0ng!Pass1"))
}

// The token outlives the request, so redemption is the authoritative check: a
// project that tightens its policy after a token was issued must not have
// every outstanding token as a hole in the new policy.
func TestConfirmEmailChange_RechecksAccessAtRedemption(t *testing.T) {
	t.Parallel()
	svc, repo, rec := newAuthSvcWithMailer(t)
	user := seedUserWithPassword(t, repo, "dev@corp.example", "Str0ng!Pass1")

	// Requested with no project scope — permitted, token issued.
	tok := requestAndExtractChangeToken(t, svc, repo, rec, user.ID, "dev@gmail.com", "Str0ng!Pass1")

	// The project turns on work-email-only before the token is redeemed.
	ctx := accessScope(t, workEmailOnlyJSON)
	_, err := svc.ConfirmEmailChange(ctx, tok)
	require.ErrorIs(t, err, ErrAccessNotAllowed)

	// The account keeps its original address.
	got, err := repo.GetUser(context.Background(), user.ID)
	require.NoError(t, err)
	require.Equal(t, "dev@corp.example", got.Email)
}

// A trailing FQDN dot names the same domain, but an address's domain never
// carries one — so an entry that kept it could never match, silently weakening
// the deny rule. Canonicalization strips it for allowlist and deny alike.
func TestAccessConfig_TrailingDotDomainsStillMatch(t *testing.T) {
	t.Parallel()
	cfg, err := ParseProjectConfig(`{"access":{"mode":"open","blocked_domains":["Rival.example."]}}`)
	require.NoError(t, err)
	require.Equal(t, []string{"rival.example"}, cfg.Access.BlockedDomains)
	require.True(t, cfg.Access.denies(testCfg, canonicalize("x@rival.example")))

	allow, err := ParseProjectConfig(`{"access":{"mode":"allowlist","allowed_domains":["Corp.example."]}}`)
	require.NoError(t, err)
	require.Equal(t, []string{"corp.example"}, allow.Access.AllowedDomains)
	require.True(t, accessPermits(testCfg, allow.Access, canonicalize("x@corp.example"), true))
}

// InviteUser is the one deny-layer call site that is not the shared chokepoint
// — it calls accessPermits directly — so it needs its own coverage. Mirrors
// TestAdminService_InviteUser_{Denied,Allowed}ByAccessMode for the deny layer.
func TestAdminService_InviteUser_DeniedByDenyLayer(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	svc := newTestAdminService(db)

	cfg, err := ParseProjectConfig(workEmailOnlyJSON)
	require.NoError(t, err)
	ctx := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "test-tenant",
		Access:    cfg.Access,
	})

	// The mode is open, so only the deny layer can refuse this.
	_, err = svc.InviteUser(ctx, "admin-1", "contractor@gmail.com", "Contractor", "member", "", 1024, false)
	require.ErrorIs(t, err, ErrAccessNotAllowed,
		"an invite to a blocked domain dead-ends at acceptance, so it must be refused up front")

	_, err = svc.InviteUser(ctx, "admin-1", "dev@corp.example", "Dev", "member", "", 1024, false)
	require.NoError(t, err, "the same open project still admits a work address")
}

// Password-reset mail is credential mail: sending it to a refused address costs
// the project SMTP reputation and confirms the address to its recipient, for an
// account that cannot log in anyway. Silent, to preserve the RPC's
// anti-enumeration contract.
func TestAccessDenyLayer_SuppressesPasswordResetMail(t *testing.T) {
	t.Parallel()
	svc, repo, rec := newAuthSvcWithMailer(t)
	seedUserWithPassword(t, repo, "legacy@gmail.com", "Str0ng!Pass1")
	seedUserWithPassword(t, repo, "dev@corp.example", "Str0ng!Pass1")
	ctx := accessScope(t, workEmailOnlyJSON)

	rec.Reset()
	require.NoError(t, svc.RequestPasswordReset(ctx, "legacy@gmail.com"),
		"refusal stays silent — a fail-fast here would leak account existence")
	require.Empty(t, rec.Sent(), "no reset mail to a refused address")

	rec.Reset()
	require.NoError(t, svc.RequestPasswordReset(ctx, "dev@corp.example"))
	require.NotEmpty(t, rec.Sent(), "a permitted address still gets its reset mail")
}

// Turning the deny layer on for an existing population is the documented way
// to use it, so the refusal must not destroy the credential on its way out. If
// the access check ran after the token was consumed, the retry an SDK makes on
// a failed rotation would land on replay detection — deleting every refresh
// token the user has and signing them out everywhere, while stamping a routine
// config change into the audit log as refresh_token_replay_detected.
func TestAccessDenyLayer_RefreshDenialDoesNotBurnTheToken(t *testing.T) {
	t.Parallel()
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)

	// Signed up before the project switched to work-email-only.
	result, err := svc.PasswordSignup(context.Background(), "legacy@gmail.com", strongPW, "", "", 0, "")
	require.NoError(t, err)

	ctx := accessScope(t, workEmailOnlyJSON)
	_, _, _, err = svc.RefreshToken(ctx, result.RefreshToken, "", "")
	require.ErrorIs(t, err, ErrAccessNotAllowed)

	// The retry returns the SAME refusal rather than tripping replay detection,
	// which is only possible if the first attempt left the token unconsumed.
	_, _, _, err = svc.RefreshToken(ctx, result.RefreshToken, "", "")
	require.ErrorIs(t, err, ErrAccessNotAllowed,
		"a denied refresh must be retryable, not escalate to replay detection")

	// And the token still works once the project admits the address again.
	_, _, newRefresh, err := svc.RefreshToken(context.Background(), result.RefreshToken, "", "")
	require.NoError(t, err, "the credential survived the refusal intact")
	require.NotEqual(t, result.RefreshToken, newRefresh)
}

// ── one provider list, not two ───────────────────────────────────────────

// The block consults the SAME provider set that decides tenant auto-formation,
// including the operator's GATEWAY_PUBLIC_EMAIL_DOMAINS additions. A second
// copy of that list would drift: an operator who declared a domain
// consumer-grade for tenant formation would be astonished to find a
// work-email-only project still admitting it.
func TestAccessDenyLayer_UsesTheSharedProviderList(t *testing.T) {
	t.Parallel()
	cfg, err := ParseProjectConfig(workEmailOnlyJSON)
	require.NoError(t, err)

	extended := &config.Config{PublicEmailDomains: "startup.example"}
	require.True(t, extended.IsPublicEmailDomain("startup.example"),
		"precondition: the env var extends the provider set")
	require.True(t, cfg.Access.denies(extended, canonicalize("someone@startup.example")),
		"an operator-declared public domain must be refused by the block too")

	// Without the env addition the same address is ordinary.
	require.False(t, cfg.Access.denies(testCfg, canonicalize("someone@startup.example")))
}
