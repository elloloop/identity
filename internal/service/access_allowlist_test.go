package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/email"
)

// blockingTransport blocks in Send until release is closed, then signals sent.
// It lets a test prove the RPC does not wait on the (slow) SMTP send.
type blockingTransport struct {
	release chan struct{}
	sent    chan struct{}
}

func (b *blockingTransport) Send(context.Context, email.Message) error {
	<-b.release
	close(b.sent)
	return nil
}

// allowlistAccessJSON is the config_json an operator sets to restrict a
// project to an explicit two-email membership.
const allowlistAccessJSON = `{"access":{"mode":"allowlist","allowed_emails":["alice@example.com","bob@example.com"]}}`

// gmailAllowlistJSON lists a +tagged gmail address to prove canonicalization at
// match time (a login as the dotted/untagged form is admitted).
const gmailAllowlistJSON = `{"access":{"mode":"allowlist","allowed_emails":["alice.smith+work@gmail.com"],"allowed_domains":["example.com"]}}`

const accessTestPassword = "S3cure!Passw0rd"

// accessScope parses configJSON exactly as the control-plane resolver does and
// returns a context carrying the resulting per-project scope, so tests exercise
// the real parse + canonicalization rather than a hand-built policy.
func accessScope(t *testing.T, configJSON string) context.Context {
	t.Helper()
	cfg, err := ParseProjectConfig(configJSON)
	require.NoError(t, err)
	return WithProjectScope(context.Background(), &ProjectScope{ProjectID: "project-a", Access: cfg.Access})
}

// unconfiguredScope is a resolved project with NO access block — mode "". Under
// default-DENY this must deny every auth path (the core inversion).
func unconfiguredScope() context.Context {
	return WithProjectScope(context.Background(), &ProjectScope{ProjectID: "unconfigured"})
}

// seedInvitedUser seeds an invited (status "invited") user plus a matching
// invitation and returns the raw invitation token.
func seedInvitedUser(t *testing.T, repo *fakeRepo, email string) string {
	t.Helper()
	u := seedUser(repo, email, "", "invited")
	rawToken := "invite-token-" + email
	seedInvitation(repo, &InvitationRecord{
		TokenHash: hashInvitationToken(rawToken),
		Email:     email,
		UserID:    u.ID,
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
		CreatedAt: time.Now().UnixMilli(),
	})
	return rawToken
}

// seedEmailLoginCode writes a valid, unconsumed OTP directly into the repo,
// bypassing the request-phase send gate so a test can drive redemption for an
// address the send gate would otherwise suppress.
func seedEmailLoginCode(t *testing.T, repo *fakeRepo, email, code string) {
	t.Helper()
	now := time.Now().UnixMilli()
	_, err := repo.UpsertEmailLoginCode(context.Background(), &EmailLoginCodeRecord{
		Email:       email,
		CodeHash:    sha256Hex(code),
		ExpiresAt:   now + int64(5*time.Minute/time.Millisecond),
		CreatedAt:   now,
		MaxAttempts: 5,
	})
	require.NoError(t, err)
}

// ── Pure units: mode(), permits(), accessPermits() matrix ────────────────

func TestProjectAccessConfig_ModeNormalizes(t *testing.T) {
	t.Parallel()
	assert.Equal(t, AccessModeAllowlist, ProjectAccessConfig{Mode: "  Allowlist "}.mode())
	assert.Equal(t, "", ProjectAccessConfig{}.mode())
}

func TestProjectAccessConfig_Permits(t *testing.T) {
	t.Parallel()
	a := ProjectAccessConfig{
		Mode:           AccessModeAllowlist,
		AllowedEmails:  []string{"alicesmith@gmail.com"},
		AllowedDomains: []string{"example.com"},
	}
	for _, tc := range []struct {
		name  string
		email string // already-canonical, as the guard passes it
		want  bool
	}{
		{"email_match", "alicesmith@gmail.com", true},
		{"domain_match", "alice@example.com", true},
		{"no_match_gmail", "bob@gmail.com", false},
		{"no_match_domain", "x@other.com", false},
		{"no_at", "garbage", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, a.permits(canonicalize(tc.email)))
		})
	}
}

// accessPermits is the whole mode matrix (mode × signup/login) in one table.
func TestAccessPermits_Matrix(t *testing.T) {
	t.Parallel()
	const listed = "alice@example.com"
	const unlisted = "outsider@other.com"
	allow := ProjectAccessConfig{Mode: AccessModeAllowlist, AllowedDomains: []string{"example.com"}}

	for _, tc := range []struct {
		name       string
		access     ProjectAccessConfig
		email      string
		signup     bool
		wantPermit bool
	}{
		{"open_signup", ProjectAccessConfig{Mode: AccessModeOpen}, unlisted, true, true},
		{"open_login", ProjectAccessConfig{Mode: AccessModeOpen}, unlisted, false, true},
		{"closed_signup", ProjectAccessConfig{Mode: AccessModeClosed}, listed, true, false},
		{"closed_login", ProjectAccessConfig{Mode: AccessModeClosed}, listed, false, false},
		{"invite_signup_denied", ProjectAccessConfig{Mode: AccessModeInvite}, listed, true, false},
		{"invite_login_permitted", ProjectAccessConfig{Mode: AccessModeInvite}, listed, false, true},
		{"allowlist_listed_signup", allow, listed, true, true},
		{"allowlist_listed_login", allow, listed, false, true},
		{"allowlist_unlisted_signup", allow, unlisted, true, false},
		{"allowlist_unlisted_login", allow, unlisted, false, false},
		{"unset_signup_denied", ProjectAccessConfig{}, listed, true, false},
		{"unset_login_denied", ProjectAccessConfig{}, listed, false, false},
		{"unrecognized_denied", ProjectAccessConfig{Mode: "bogus"}, listed, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.wantPermit, accessPermits(tc.access, canonicalize(tc.email), tc.signup))
		})
	}
}

// ── Parsing + validation ─────────────────────────────────────────────────

func TestParseProjectConfig_Access_Modes(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{AccessModeOpen, AccessModeInvite, AccessModeClosed} {
		cfg, err := ParseProjectConfig(`{"access":{"mode":"` + mode + `"}}`)
		require.NoError(t, err)
		assert.Equal(t, mode, cfg.Access.Mode)
	}

	// allowlist canonicalizes emails (gmail dot/+tag) and domains (case + fold).
	cfg, err := ParseProjectConfig(`{"access":{"mode":"allowlist",` +
		`"allowed_emails":["Alice.Smith+work@GMAIL.com"],"allowed_domains":["Example.COM","Googlemail.com"]}}`)
	require.NoError(t, err)
	assert.Equal(t, []string{"alicesmith@gmail.com"}, cfg.Access.AllowedEmails)
	assert.Equal(t, []string{"example.com", "gmail.com"}, cfg.Access.AllowedDomains)
}

func TestParseProjectConfig_Access_OmittedIsUnsetMode(t *testing.T) {
	t.Parallel()
	// A config with no access block leaves mode "" — which denies at runtime.
	cfg, err := ParseProjectConfig(`{"cors":{"allowed_origins":["https://a.example.com"]}}`)
	require.NoError(t, err)
	assert.Equal(t, "", cfg.Access.Mode)
}

func TestParseProjectConfig_Access_Validation(t *testing.T) {
	t.Parallel()
	for name, blob := range map[string]string{
		"allowlist_empty":      `{"access":{"mode":"allowlist"}}`,
		"open_with_emails":     `{"access":{"mode":"open","allowed_emails":["a@b.com"]}}`,
		"invite_with_domains":  `{"access":{"mode":"invite","allowed_domains":["b.com"]}}`,
		"closed_with_emails":   `{"access":{"mode":"closed","allowed_emails":["a@b.com"]}}`,
		"unrecognized_mode":    `{"access":{"mode":"opne"}}`,
		"allowlist_bad_email":  `{"access":{"mode":"allowlist","allowed_emails":["not-an-email"]}}`,
		"allowlist_bad_domain": `{"access":{"mode":"allowlist","allowed_domains":["localhost"]}}`,
		"unset_with_entries":   `{"access":{"allowed_emails":["a@b.com"]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseProjectConfig(blob)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "parse project config")
		})
	}
}

func TestNewProjectAccessConfig(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{AccessModeOpen, AccessModeInvite, AccessModeClosed, ""} {
		a, err := NewProjectAccessConfig(mode, nil, nil)
		require.NoError(t, err, "mode %q", mode)
		assert.Equal(t, mode, a.Mode)
	}
	a, err := NewProjectAccessConfig(AccessModeAllowlist, []string{"OP@Example.COM"}, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"op@example.com"}, a.AllowedEmails)

	_, err = NewProjectAccessConfig(AccessModeAllowlist, nil, nil)
	require.Error(t, err, "allowlist without entries must fail")
	_, err = NewProjectAccessConfig("bogus", nil, nil)
	require.Error(t, err, "unrecognized mode must fail")
	_, err = NewProjectAccessConfig(AccessModeOpen, []string{"a@b.com"}, nil)
	require.Error(t, err, "entries with a non-allowlist mode must fail")
}

// ── enforceProjectAccess{Signup,Login} ───────────────────────────────────

func TestEnforceProjectAccess_NilScope_Permits(t *testing.T) {
	t.Parallel()
	svc, _, _ := newAuthSvcWithMailer(t)
	// No scope in context (direct call / non-project deployment) → no gate.
	require.NoError(t, svc.enforceProjectAccessSignup(context.Background(), canonicalize("anyone@anywhere.com")))
	require.NoError(t, svc.enforceProjectAccessLogin(context.Background(), canonicalize("anyone@anywhere.com")))
}

func TestEnforceProjectAccess_SignupVsLogin(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)

	invite := accessScope(t, `{"access":{"mode":"invite"}}`)
	require.ErrorIs(t, svc.enforceProjectAccessSignup(invite, canonicalize("x@y.com")), ErrSignupByInvitationOnly)
	require.NoError(t, svc.enforceProjectAccessLogin(invite, canonicalize("x@y.com")))

	closed := accessScope(t, `{"access":{"mode":"closed"}}`)
	require.ErrorIs(t, svc.enforceProjectAccessSignup(closed, canonicalize("x@y.com")), ErrAccessNotAllowed)
	require.ErrorIs(t, svc.enforceProjectAccessLogin(closed, canonicalize("x@y.com")), ErrAccessNotAllowed)

	open := accessScope(t, `{"access":{"mode":"open"}}`)
	require.NoError(t, svc.enforceProjectAccessSignup(open, canonicalize("x@y.com")))
	require.NoError(t, svc.enforceProjectAccessLogin(open, canonicalize("x@y.com")))

	// The caller canonicalizes (via canonicalize) before the gate, so a
	// dotted/cased variant of the listed gmail address is admitted by the allowlist.
	allow := accessScope(t, gmailAllowlistJSON)
	require.NoError(t, svc.enforceProjectAccessLogin(allow, canonicalize("Alice.Smith@gmail.com")))
	require.ErrorIs(t, svc.enforceProjectAccessSignup(allow, canonicalize("nope@nowhere.com")), ErrAccessNotAllowed)
}

// ── Default-DENY regression: unconfigured project denies everything ──────

func TestProjectAccess_Unconfigured_DeniesSignupAndLogin(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	ctx := unconfiguredScope()

	_, err := svc.PasswordSignup(ctx, "someone@random-domain.com", accessTestPassword, "S", "", 0, "")
	require.ErrorIs(t, err, ErrAccessNotAllowed, "unconfigured project must deny signup (default-DENY)")

	// A pre-existing user (seeded with no scope) also cannot log in.
	seedUser(repo, "legacy@random-domain.com", hashPW(t, accessTestPassword), "active")
	_, err = svc.PasswordLogin(ctx, "legacy@random-domain.com", accessTestPassword, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrAccessNotAllowed, "unconfigured project must deny login (default-DENY)")
}

// ── mode:open reproduces pre-change behavior ─────────────────────────────

func TestProjectAccess_Open_PermitsSignupAndLogin(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	ctx := accessScope(t, `{"access":{"mode":"open"}}`)

	res, err := svc.PasswordSignup(ctx, "anyone@random-domain.com", accessTestPassword, "Any", "", 0, "")
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)

	login, err := svc.PasswordLogin(ctx, "anyone@random-domain.com", accessTestPassword, "1.2.3.4", "agent")
	require.NoError(t, err)
	require.NotEmpty(t, login.AccessToken)
}

// ── mode:allowlist across every method ───────────────────────────────────

func TestProjectAccess_Allowlist_Password(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	ctx := accessScope(t, gmailAllowlistJSON)

	// Allowed by domain: signup + login succeed.
	res, err := svc.PasswordSignup(ctx, "alice@example.com", accessTestPassword, "Alice", "", 0, "")
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)
	login, err := svc.PasswordLogin(ctx, "alice@example.com", accessTestPassword, "1.2.3.4", "agent")
	require.NoError(t, err)
	require.NotEmpty(t, login.AccessToken)

	// gmail canonicalization: the dotted variant of the listed address is allowed.
	_, err = svc.PasswordSignup(ctx, "Alice.Smith@GMAIL.com", accessTestPassword, "Alice", "", 0, "")
	require.NoError(t, err)

	// Off-list: signup denied, no account created.
	_, err = svc.PasswordSignup(ctx, "outsider@other.com", accessTestPassword, "Out", "", 0, "")
	require.ErrorIs(t, err, ErrAccessNotAllowed)
	got, _ := repo.FindUserByEmail(context.Background(), "outsider@other.com")
	assert.Nil(t, got)

	// Off-list pre-existing user (seeded under no scope) denied login.
	seedUser(repo, "legacy@other.com", hashPW(t, accessTestPassword), "active")
	_, err = svc.PasswordLogin(ctx, "legacy@other.com", accessTestPassword, "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrAccessNotAllowed)
}

func TestProjectAccess_Allowlist_OAuth_JITAndFastPath(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := accessScope(t, gmailAllowlistJSON)

	// Off-list JIT denied, no user created.
	_, err := svc.OAuthLogin(ctx, OAuthLoginParams{
		Code: fakeOAuthCode("outsider@other.com", "Out", "", "google"), Provider: "google", RedirectURI: "https://app/cb",
	})
	require.ErrorIs(t, err, ErrAccessNotAllowed)
	got, _ := repo.FindUserByEmail(context.Background(), "outsider@other.com")
	assert.Nil(t, got)

	// Listed JIT succeeds.
	_, err = svc.OAuthLogin(ctx, OAuthLoginParams{
		Code: fakeOAuthCode("alice@example.com", "Alice", "", "google"), Provider: "google", RedirectURI: "https://app/cb",
	})
	require.NoError(t, err)

	// A returning (provider,sub) user provisioned open then tightened off-list is
	// denied on the fast path (which bypasses the resolver).
	code := fakeOAuthCode("returning@other.com", "Ret", "", "google")
	_, err = svc.OAuthLogin(context.Background(), OAuthLoginParams{Code: code, Provider: "google", RedirectURI: "https://app/cb"})
	require.NoError(t, err) // no scope → permitted, creates + links
	_, err = svc.OAuthLogin(ctx, OAuthLoginParams{Code: code, Provider: "google", RedirectURI: "https://app/cb"})
	require.ErrorIs(t, err, ErrAccessNotAllowed)
}

func TestProjectAccess_Allowlist_Passwordless(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	ctx := accessScope(t, gmailAllowlistJSON)

	// On-list: the OTP is sent and redemption logs in.
	require.NoError(t, svc.RequestEmailLoginCode(ctx, "alice@example.com"))
	require.Len(t, rec.Sent(), 1)
	res, err := svc.VerifyEmailLoginCode(ctx, "alice@example.com", extractCodeFromEmail(t, rec.Sent()[0].Text), "1.2.3.4", "a")
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)

	// Off-list: the send is suppressed (Blocker 1)...
	rec.Reset()
	require.NoError(t, svc.RequestEmailLoginCode(ctx, "outsider@other.com"))
	require.Empty(t, rec.Sent(), "off-list address must not receive an OTP")

	// ...and even a valid OTP (seeded past the send gate) is refused at
	// redemption (defense in depth).
	seedEmailLoginCode(t, repo, "outsider@other.com", "123456")
	_, err = svc.VerifyEmailLoginCode(ctx, "outsider@other.com", "123456", "1.2.3.4", "a")
	require.ErrorIs(t, err, ErrAccessNotAllowed)
}

func TestProjectAccess_Allowlist_Passkey(t *testing.T) {
	t.Run("listed_signup_ok", func(t *testing.T) {
		svc, repo, rec := newPasskeyVectorSvc(t)
		ctx := accessScope(t, `{"access":{"mode":"allowlist","allowed_domains":["example.org"]}}`)
		_, challengeID, err := svc.BeginPasskeySignup(ctx, pkVectorEmail, "Key")
		require.NoError(t, err)
		otp := passkeySignupOTP(t, rec, pkVectorEmail)
		setFakeChallengeValue(repo, challengeID, pkB64URL(t, pkRegChallengeHex))
		res, err := svc.CompletePasskeySignup(ctx, challengeID, pkRegCredentialJSON(t), pkVectorEmail, otp, "Key", "1.2.3.4", "a")
		require.NoError(t, err)
		require.NotEmpty(t, res.AccessToken)
	})

	t.Run("offlist_login_denied", func(t *testing.T) {
		svc, repo, rec := newPasskeyVectorSvc(t)
		// Provision (passkey) with NO scope, then log in under an off-list allowlist.
		_, challengeID, err := svc.BeginPasskeySignup(context.Background(), pkVectorEmail, "Key")
		require.NoError(t, err)
		otp := passkeySignupOTP(t, rec, pkVectorEmail)
		setFakeChallengeValue(repo, challengeID, pkB64URL(t, pkRegChallengeHex))
		_, err = svc.CompletePasskeySignup(context.Background(), challengeID, pkRegCredentialJSON(t), pkVectorEmail, otp, "Key", "1.2.3.4", "a")
		require.NoError(t, err)

		ctx := accessScope(t, `{"access":{"mode":"allowlist","allowed_domains":["example.com"]}}`)
		_, loginChallengeID, err := svc.BeginPasskeyLogin(ctx, pkVectorEmail)
		require.NoError(t, err)
		setFakeChallengeValue(repo, loginChallengeID, pkB64URL(t, pkLoginChallengeHex))
		_, err = svc.CompletePasskeyLogin(ctx, loginChallengeID, pkAssertionCredentialJSON(t), "1.2.3.4", "a")
		require.ErrorIs(t, err, ErrAccessNotAllowed)
	})
}

// ── mode:closed denies everything, including AcceptInvitation ────────────

func TestProjectAccess_Closed_DeniesAll(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	ctx := accessScope(t, `{"access":{"mode":"closed"}}`)

	_, err := svc.PasswordSignup(ctx, "a@b.com", accessTestPassword, "A", "", 0, "")
	require.ErrorIs(t, err, ErrAccessNotAllowed)

	seedUser(repo, "existing@b.com", hashPW(t, accessTestPassword), "active")
	_, err = svc.PasswordLogin(ctx, "existing@b.com", accessTestPassword, "1.2.3.4", "a")
	require.ErrorIs(t, err, ErrAccessNotAllowed)

	token := seedInvitedUser(t, repo, "invitee@b.com")
	_, err = svc.AcceptInvitation(ctx, token, accessTestPassword, "Name", "", "")
	require.ErrorIs(t, err, ErrAccessNotAllowed, "closed must deny invitation acceptance too")
}

// ── mode:invite: self-signup denied every method; invited/existing get in ──

func TestProjectAccess_Invite_SelfSignupDeniedAllMethods(t *testing.T) {
	const ctxJSON = `{"access":{"mode":"invite"}}`

	t.Run("password", func(t *testing.T) {
		svc, _, _ := newAuthSvcWithMailer(t)
		_, err := svc.PasswordSignup(accessScope(t, ctxJSON), "new@x.com", accessTestPassword, "N", "", 0, "")
		require.ErrorIs(t, err, ErrSignupByInvitationOnly)
	})

	t.Run("oauth_jit", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newTestAuthService(t, repo)
		_, err := svc.OAuthLogin(accessScope(t, ctxJSON), OAuthLoginParams{
			Code: fakeOAuthCode("new@x.com", "N", "", "google"), Provider: "google", RedirectURI: "https://app/cb",
		})
		require.ErrorIs(t, err, ErrSignupByInvitationOnly)
		got, _ := repo.FindUserByEmail(context.Background(), "new@x.com")
		assert.Nil(t, got)
	})

	t.Run("passwordless", func(t *testing.T) {
		svc, repo, rec := newAuthSvcWithMailer(t)
		ctx := accessScope(t, ctxJSON)
		// invite mode suppresses the OTP for a new (non-existent) address, so seed
		// a valid code past the send gate to prove redemption itself denies signup.
		require.NoError(t, svc.RequestEmailLoginCode(ctx, "new@x.com"))
		require.Empty(t, rec.Sent(), "invite mode must not email an OTP to a new address")
		seedEmailLoginCode(t, repo, "new@x.com", "123456")
		_, err := svc.VerifyEmailLoginCode(ctx, "new@x.com", "123456", "1.2.3.4", "a")
		require.ErrorIs(t, err, ErrSignupByInvitationOnly)
	})

	t.Run("passkey", func(t *testing.T) {
		svc, _, rec := newPasskeyVectorSvc(t)
		ctx := accessScope(t, ctxJSON)
		// invite mode fails the ceremony fast: no challenge, no OTP.
		_, challengeID, err := svc.BeginPasskeySignup(ctx, pkVectorEmail, "Key")
		require.ErrorIs(t, err, ErrSignupByInvitationOnly)
		assert.Empty(t, challengeID)
		assert.Empty(t, rec.Sent())
	})
}

func TestProjectAccess_Invite_ExistingUserLoginPermitted(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	ctx := accessScope(t, `{"access":{"mode":"invite"}}`)
	seedUser(repo, "member@x.com", hashPW(t, accessTestPassword), "active")

	login, err := svc.PasswordLogin(ctx, "member@x.com", accessTestPassword, "1.2.3.4", "a")
	require.NoError(t, err, "invite mode must permit an existing user to log in")
	require.NotEmpty(t, login.AccessToken)
}

func TestProjectAccess_Invite_AcceptInvitationThenLogin(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	ctx := accessScope(t, `{"access":{"mode":"invite"}}`)
	token := seedInvitedUser(t, repo, "invitee@x.com")

	res, err := svc.AcceptInvitation(ctx, token, accessTestPassword, "Invitee", "", "")
	require.NoError(t, err, "invite mode must permit admin-issued invitation acceptance")
	require.NotEmpty(t, res.AccessToken)

	// The now-provisioned user can log in under the same invite-only project.
	login, err := svc.PasswordLogin(ctx, "invitee@x.com", accessTestPassword, "1.2.3.4", "a")
	require.NoError(t, err)
	require.NotEmpty(t, login.AccessToken)
}

// ── AcceptInvitation under allowlist honors the list ─────────────────────

func TestProjectAccess_AcceptInvitation_AllowlistGatesInvitee(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	ctx := accessScope(t, gmailAllowlistJSON) // allows the example.com domain

	onList := seedInvitedUser(t, repo, "member@example.com")
	res, err := svc.AcceptInvitation(ctx, onList, accessTestPassword, "Member", "", "")
	require.NoError(t, err, "an on-list invitee may accept")
	require.NotEmpty(t, res.AccessToken)

	offList := seedInvitedUser(t, repo, "stranger@other.com")
	_, err = svc.AcceptInvitation(ctx, offList, accessTestPassword, "Stranger", "", "")
	require.ErrorIs(t, err, ErrAccessNotAllowed, "an admin cannot invite someone the allowlist excludes")
}

// ── Env-configured default project: mode governs deny/permit ────────────

func TestProjectAccess_EnvDefaultProject_ModeGovernsDenyOrPermit(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	build := func(mode string) context.Context {
		access, err := NewProjectAccessConfig(mode, nil, nil)
		require.NoError(t, err)
		return WithProjectScope(context.Background(), &ProjectScope{ProjectID: "default", Access: access})
	}

	// GATEWAY_DEFAULT_PROJECT_ACCESS_MODE=open → permit.
	require.NoError(t, svc.enforceProjectAccessSignup(build(AccessModeOpen), canonicalize("x@y.com")))

	// unset ("") and closed → deny (what a deployment gets if it sets nothing).
	require.ErrorIs(t, svc.enforceProjectAccessSignup(build(""), canonicalize("x@y.com")), ErrAccessNotAllowed)
	require.ErrorIs(t, svc.enforceProjectAccessLogin(build(""), canonicalize("x@y.com")), ErrAccessNotAllowed)
	require.ErrorIs(t, svc.enforceProjectAccessLogin(build(AccessModeClosed), canonicalize("x@y.com")), ErrAccessNotAllowed)
}

// ── The documented allowlist config parses to the intended membership ────

func TestProjectAccess_AllowlistDocumentedConfig(t *testing.T) {
	t.Parallel()
	cfg, err := ParseProjectConfig(allowlistAccessJSON)
	require.NoError(t, err)
	assert.Equal(t, AccessModeAllowlist, cfg.Access.Mode)
	assert.Equal(t, []string{"alice@example.com", "bob@example.com"}, cfg.Access.AllowedEmails)
}

// ── Blocker 1: request-phase email dispatch is gated by access mode ──────
//
// The RPC response must stay byte-identical (always nil / same shape) whether
// or not the email is sent, so gating adds no enumeration signal; only the
// side-effecting send is suppressed.

func TestProjectAccess_RequestEmailLoginCode_SendGatedByMode(t *testing.T) {
	for _, tc := range []struct {
		name         string
		cfgJSON      string
		email        string
		seedExisting bool
		wantSent     bool
	}{
		{"open_sends", `{"access":{"mode":"open"}}`, "x@any.com", false, true},
		{"closed_never_sends", `{"access":{"mode":"closed"}}`, "x@any.com", false, false},
		{"allowlist_onlist_sends", gmailAllowlistJSON, "alice@example.com", false, true},
		{"allowlist_offlist_dropped", gmailAllowlistJSON, "outsider@other.com", false, false},
		{"invite_no_user_dropped", `{"access":{"mode":"invite"}}`, "newbie@x.com", false, false},
		{"invite_existing_user_sends", `{"access":{"mode":"invite"}}`, "member@x.com", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo, rec := newAuthSvcWithMailer(t)
			if tc.seedExisting {
				seedUser(repo, tc.email, "", "active")
			}
			ctx := accessScope(t, tc.cfgJSON)

			// Response is identical (nil) regardless of the send decision.
			require.NoError(t, svc.RequestEmailLoginCode(ctx, tc.email))

			got := len(rec.Sent())
			if tc.wantSent {
				assert.Equal(t, 1, got, "expected an OTP email to be sent")
			} else {
				assert.Equal(t, 0, got, "expected NO OTP email (spam/abuse gate)")
			}
		})
	}
}

func TestProjectAccess_RequestMagicLink_SendGatedByMode(t *testing.T) {
	send := func(t *testing.T, cfgJSON string) int {
		t.Helper()
		svc, _, rec := newAuthSvcWithMailer(t)
		svc.returnAllow = ParseReturnAllowlist("https://app.test/")
		ctx := accessScope(t, cfgJSON)
		require.NoError(t, svc.RequestMagicLink(ctx, "x@any.com", "https://app.test/cb"))
		return len(rec.Sent())
	}
	assert.Equal(t, 1, send(t, `{"access":{"mode":"open"}}`), "open must send the magic link")
	assert.Equal(t, 0, send(t, `{"access":{"mode":"closed"}}`), "closed must not send the magic link")
}

// BeginPasskeySignup FAILS FAST on a project that forbids self-signup — the
// access check is DB-free, so it can deny before building the WebAuthn challenge
// or emailing an OTP (no biometric-ceremony-then-silent-drop UX). A denied
// begin returns no options, no challenge, and sends no OTP.
func TestProjectAccess_BeginPasskeySignup_FailFastByMode(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cfgJSON string
		wantErr error // nil = permitted
	}{
		{"open_permits", `{"access":{"mode":"open"}}`, nil},
		{"allowlist_onlist_permits", `{"access":{"mode":"allowlist","allowed_domains":["example.org"]}}`, nil},
		{"closed_denies", `{"access":{"mode":"closed"}}`, ErrAccessNotAllowed},
		{"invite_denies", `{"access":{"mode":"invite"}}`, ErrSignupByInvitationOnly},
		{"allowlist_offlist_denies", `{"access":{"mode":"allowlist","allowed_domains":["example.com"]}}`, ErrAccessNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, rec := newPasskeyVectorSvc(t)
			ctx := accessScope(t, tc.cfgJSON)

			optionsJSON, challengeID, err := svc.BeginPasskeySignup(ctx, pkVectorEmail, "Key")
			if tc.wantErr == nil {
				require.NoError(t, err)
				require.NotEmpty(t, optionsJSON)
				require.NotEmpty(t, challengeID)
				require.Len(t, rec.Sent(), 1, "a permitted signup emails the in-flow OTP")
				return
			}
			require.ErrorIs(t, err, tc.wantErr)
			assert.Empty(t, optionsJSON, "denied begin must not return options")
			assert.Empty(t, challengeID, "denied begin must not create a challenge")
			assert.Empty(t, rec.Sent(), "denied begin must not email an OTP")
		})
	}
}

// A project flipped to a signup-denying mode BETWEEN begin and complete is
// still refused at CompletePasskeySignup (defense in depth), and no account is
// created.
func TestProjectAccess_PasskeySignup_FlippedDenyBetweenBeginAndComplete(t *testing.T) {
	svc, repo, rec := newPasskeyVectorSvc(t)

	open := accessScope(t, `{"access":{"mode":"open"}}`)
	_, challengeID, err := svc.BeginPasskeySignup(open, pkVectorEmail, "Key")
	require.NoError(t, err)
	otp := passkeySignupOTP(t, rec, pkVectorEmail)
	setFakeChallengeValue(repo, challengeID, pkB64URL(t, pkRegChallengeHex))

	closed := accessScope(t, `{"access":{"mode":"closed"}}`)
	_, err = svc.CompletePasskeySignup(closed, challengeID, pkRegCredentialJSON(t), pkVectorEmail, otp, "Key", "1.2.3.4", "a")
	require.ErrorIs(t, err, ErrAccessNotAllowed)
	got, _ := repo.FindUserByEmail(context.Background(), pkVectorEmail)
	assert.Nil(t, got, "a denied completion must not create an account")
}

// ── Blocker 2: RefreshToken re-validates the project access mode ─────────

func TestProjectAccess_RefreshToken_RevalidatesMode(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	open := accessScope(t, `{"access":{"mode":"open"}}`)

	reg, err := svc.PasswordSignup(open, "user@ex.com", accessTestPassword, "U", "", 0, "")
	require.NoError(t, err)
	require.NotEmpty(t, reg.RefreshToken)

	// Under an open project the refresh rotates normally.
	_, at, rt, err := svc.RefreshToken(open, reg.RefreshToken, "1.2.3.4", "a")
	require.NoError(t, err)
	require.NotEmpty(t, at)
	require.NotEmpty(t, rt)

	// Flip the project to closed: the still-valid refresh token can no longer
	// mint fresh access tokens.
	closed := accessScope(t, `{"access":{"mode":"closed"}}`)
	_, _, _, err = svc.RefreshToken(closed, rt, "1.2.3.4", "a")
	require.ErrorIs(t, err, ErrAccessNotAllowed)
}

// ── Blocker 3: request-phase send is async (no timing oracle) ────────────

// With async dispatch enabled (as app.New does in production), the RPC returns
// without waiting on the SMTP send, so its response time cannot leak the gated
// send/no-send decision. The send still runs (on a detached context).
func TestProjectAccess_RequestEmailLoginCode_AsyncDoesNotBlock(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	svc.WithAsyncEmailDispatch()
	mailer := &blockingTransport{release: make(chan struct{}), sent: make(chan struct{})}
	svc.mailer = mailer
	ctx := accessScope(t, `{"access":{"mode":"open"}}`)

	start := time.Now()
	require.NoError(t, svc.RequestEmailLoginCode(ctx, "async@ex.com"))
	require.Less(t, time.Since(start), 500*time.Millisecond,
		"RPC must not block on the SMTP send")

	// The send is in flight on a detached context; release it and confirm it ran
	// (proving the detached ctx was NOT cancelled when the RPC returned).
	close(mailer.release)
	select {
	case <-mailer.sent:
	case <-time.After(2 * time.Second):
		t.Fatal("async send did not run after release")
	}
}

// ── Blocker 4: PasswordLogin access check precedes lookup + bcrypt ───────

// An off-list PasswordLogin is denied BEFORE FindUserByEmail (hence before
// bcrypt): forcing the repo lookup to error proves it is never reached, and the
// denial is ErrAccessNotAllowed regardless of the password (no bcrypt CPU-DoS,
// no password-guessing oracle for disallowed addresses).
func TestProjectAccess_PasswordLogin_OffListDeniedBeforeLookup(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	ctx := accessScope(t, gmailAllowlistJSON) // permits example.com only
	repo.findUserByEmailErr = errors.New("FindUserByEmail must not be reached for an off-list login")

	_, err := svc.PasswordLogin(ctx, "outsider@other.com", "any-Passw0rd!", "1.2.3.4", "a")
	require.ErrorIs(t, err, ErrAccessNotAllowed)
}

// ── One-shot canonicalization: NON-CANONICAL input at every gated entry point ─
//
// The access gate now takes a canonicalEmail — the caller canonicalizes ONCE and
// the gate never re-canonicalizes. These tests drive every gated entry point
// with a NON-CANONICAL variant (dots + mixed case + '+tag') that canonicalizes
// ONTO the allowlist, and assert the access decision AND provisioning are
// correct: an on-list variant is admitted and the account is resolved under the
// single canonical key, while an off-list variant is denied. They are the
// regression guard that the type-driven "canonicalize once" refactor did not
// weaken the gate.

const (
	// All three canonicalize to nonCanonCanonical, which gmailAllowlistJSON lists
	// (allowed_emails ["alice.smith+work@gmail.com"] → "alicesmith@gmail.com").
	nonCanonSignup      = "Alice.Smith+promo@GMAIL.com"
	nonCanonSignupLower = "alice.smith+promo@gmail.com" // the non-canonical key, lower-cased
	nonCanonLogin       = "aLiCe.SMITH+news@gmail.com"
	nonCanonCanonical   = "alicesmith@gmail.com"
	// Canonicalizes to bobjones@gmail.com — NOT on the list (gmail.com is not an
	// allowed domain; only example.com is), so every variant is denied.
	nonCanonOffList          = "Bob.Jones+x@GMAIL.com"
	nonCanonOffListCanonical = "bobjones@gmail.com"
)

func TestProjectAccess_NonCanonical_PasswordSignupAndLogin(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	ctx := accessScope(t, gmailAllowlistJSON)

	// A dotted/+tagged/mixed-case signup is admitted and stored ONCE under the
	// canonical key — never under the non-canonical form the client typed.
	res, err := svc.PasswordSignup(ctx, nonCanonSignup, accessTestPassword, "Alice", "", 0, "")
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)

	u, _ := repo.FindUserByEmail(context.Background(), nonCanonCanonical)
	require.NotNil(t, u, "account must be provisioned under the canonical key")
	dup, _ := repo.FindUserByEmail(context.Background(), nonCanonSignupLower)
	assert.Nil(t, dup, "no account may be stored under the non-canonical key")

	// A DIFFERENT non-canonical variant logs into the SAME account.
	login, err := svc.PasswordLogin(ctx, nonCanonLogin, accessTestPassword, "1.2.3.4", "a")
	require.NoError(t, err)
	require.NotEmpty(t, login.AccessToken)
	require.Equal(t, u.ID, login.User.ID)

	// An off-list variant is denied at signup, nothing created.
	_, err = svc.PasswordSignup(ctx, nonCanonOffList, accessTestPassword, "Bob", "", 0, "")
	require.ErrorIs(t, err, ErrAccessNotAllowed)
	got, _ := repo.FindUserByEmail(context.Background(), nonCanonOffListCanonical)
	assert.Nil(t, got)
}

func TestProjectAccess_NonCanonical_OAuthJIT(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := accessScope(t, gmailAllowlistJSON)

	// On-list (after canonicalization) → JIT provisioned under the canonical key.
	_, err := svc.OAuthLogin(ctx, OAuthLoginParams{
		Code: fakeOAuthCode(nonCanonSignup, "Alice", "", "google"), Provider: "google", RedirectURI: "https://app/cb",
	})
	require.NoError(t, err)
	require.NotNil(t, mustFindUser(t, repo, nonCanonCanonical))
	dup, _ := repo.FindUserByEmail(context.Background(), nonCanonSignupLower)
	assert.Nil(t, dup, "no duplicate under the non-canonical key")

	// Off-list variant → denied, nothing created.
	_, err = svc.OAuthLogin(ctx, OAuthLoginParams{
		Code: fakeOAuthCode(nonCanonOffList, "Bob", "", "google"), Provider: "google", RedirectURI: "https://app/cb",
	})
	require.ErrorIs(t, err, ErrAccessNotAllowed)
	got, _ := repo.FindUserByEmail(context.Background(), nonCanonOffListCanonical)
	assert.Nil(t, got)
}

// The strongest proof of the passwordless canonicalization fix: an OTP minted
// for one non-canonical variant is redeemable by a DIFFERENT non-canonical
// variant, because both key the SAME canonical OTP record (previously the send
// keyed on the non-canonical address while the gate canonicalized internally).
func TestProjectAccess_NonCanonical_PasswordlessOTP_CrossVariant(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	ctx := accessScope(t, gmailAllowlistJSON)

	require.NoError(t, svc.RequestEmailLoginCode(ctx, nonCanonSignup))
	require.Len(t, rec.Sent(), 1)
	assert.Equal(t, nonCanonCanonical, rec.Sent()[0].To, "OTP addressed to the canonical form")
	code := extractCodeFromEmail(t, rec.Sent()[0].Text)

	res, err := svc.VerifyEmailLoginCode(ctx, nonCanonLogin, code, "1.2.3.4", "a")
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)
	require.NotNil(t, mustFindUser(t, repo, nonCanonCanonical))

	// Off-list variant: the send is suppressed (spam/abuse gate) with an
	// unchanged response.
	rec.Reset()
	require.NoError(t, svc.RequestEmailLoginCode(ctx, nonCanonOffList))
	assert.Empty(t, rec.Sent())
}

func TestProjectAccess_NonCanonical_MagicLink(t *testing.T) {
	svc, repo, rec := newAuthSvcWithMailer(t)
	svc.returnAllow = ParseReturnAllowlist("https://app.test/")
	ctx := accessScope(t, gmailAllowlistJSON)

	require.NoError(t, svc.RequestMagicLink(ctx, nonCanonSignup, "https://app.test/cb"))
	require.Len(t, rec.Sent(), 1)
	assert.Equal(t, nonCanonCanonical, rec.Sent()[0].To, "link addressed to the canonical form")
	token := extractTokenFromLink(t, rec.Sent()[0].Text)

	res, err := svc.RedeemMagicLink(ctx, token, "1.2.3.4", "a")
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)
	require.NotNil(t, mustFindUser(t, repo, nonCanonCanonical))

	// Off-list variant: no link sent.
	rec.Reset()
	require.NoError(t, svc.RequestMagicLink(ctx, nonCanonOffList, "https://app.test/cb"))
	assert.Empty(t, rec.Sent())
}

func TestProjectAccess_NonCanonical_PasskeySignupAndLogin(t *testing.T) {
	svc, repo, rec := newPasskeyVectorSvc(t)
	ctx := accessScope(t, gmailAllowlistJSON)

	// Begin with variant A: the gate permits and the OTP is addressed to canonical.
	_, challengeID, err := svc.BeginPasskeySignup(ctx, nonCanonSignup, "Key")
	require.NoError(t, err)
	otp := passkeySignupOTP(t, rec, nonCanonCanonical)
	setFakeChallengeValue(repo, challengeID, pkB64URL(t, pkRegChallengeHex))

	// Complete presenting variant B as the request email: it canonicalizes to the
	// same bound address (so the match guard passes) and provisions under canonical.
	res, err := svc.CompletePasskeySignup(ctx, challengeID, pkRegCredentialJSON(t), nonCanonLogin, otp, "Key", "1.2.3.4", "a")
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)
	require.NotNil(t, mustFindUser(t, repo, nonCanonCanonical))

	// Login (login-context gate on the canonical account email) succeeds.
	_, loginChallengeID, err := svc.BeginPasskeyLogin(ctx, nonCanonLogin)
	require.NoError(t, err)
	setFakeChallengeValue(repo, loginChallengeID, pkB64URL(t, pkLoginChallengeHex))
	login, err := svc.CompletePasskeyLogin(ctx, loginChallengeID, pkAssertionCredentialJSON(t), "1.2.3.4", "a")
	require.NoError(t, err)
	require.NotEmpty(t, login.AccessToken)
}

func TestProjectAccess_NonCanonical_AcceptInvitation(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	ctx := accessScope(t, gmailAllowlistJSON)

	// A LEGACY invited user seeded under a NON-canonical email: the login-context
	// gate wraps user.Email via canonicalize (self-healing the row for the
	// decision) and admits the on-list invitee.
	token := seedInvitedUser(t, repo, nonCanonSignupLower)
	res, err := svc.AcceptInvitation(ctx, token, accessTestPassword, "Alice", "", "")
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)

	// An off-list invitee is refused (an admin cannot invite past the allowlist).
	off := seedInvitedUser(t, repo, nonCanonOffListCanonical)
	_, err = svc.AcceptInvitation(ctx, off, accessTestPassword, "Bob", "", "")
	require.ErrorIs(t, err, ErrAccessNotAllowed)
}

func TestProjectAccess_NonCanonical_RefreshTokenRevalidates(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	ctx := accessScope(t, gmailAllowlistJSON)

	// Sign up (non-canonical → canonical account), then refresh: the login-context
	// gate wraps the canonical user.Email and still admits under the allowlist.
	reg, err := svc.PasswordSignup(ctx, nonCanonSignup, accessTestPassword, "Alice", "", 0, "")
	require.NoError(t, err)
	_, at, rt, err := svc.RefreshToken(ctx, reg.RefreshToken, "1.2.3.4", "a")
	require.NoError(t, err)
	require.NotEmpty(t, at)
	require.NotEmpty(t, rt)

	// Flip the project to closed: the still-valid refresh token can no longer mint.
	closed := accessScope(t, `{"access":{"mode":"closed"}}`)
	_, _, _, err = svc.RefreshToken(closed, rt, "1.2.3.4", "a")
	require.ErrorIs(t, err, ErrAccessNotAllowed)
}

// mustFindUser returns the user stored under email, failing the test when absent.
func mustFindUser(t *testing.T, repo *fakeRepo, email string) *User {
	t.Helper()
	u, err := repo.FindUserByEmail(context.Background(), email)
	require.NoError(t, err)
	require.NotNil(t, u)
	return u
}
