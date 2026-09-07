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
		"exemption with no deny layer":     `{"access":{"mode":"open","exempt_emails":["a@b.com"]}}`,
		"deny layer on a closed project":   `{"access":{"mode":"closed","block_public_email_domains":true}}`,
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

// A nil deployment config disables only the public-provider half of the layer.
// blocked_domains is a property of the project alone and must keep working, so
// a caller without a config still gets the project's explicit denials.
func TestAccessDenies_NilConfig_KeepsBlockedDomains(t *testing.T) {
	t.Parallel()
	cfg, err := ParseProjectConfig(
		`{"access":{"mode":"open","block_public_email_domains":true,"blocked_domains":["rival.example"]}}`,
	)
	require.NoError(t, err)

	require.True(t, cfg.Access.denies(nil, canonicalize("x@rival.example")))
	require.False(t, cfg.Access.denies(nil, canonicalize("x@gmail.com")))
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
