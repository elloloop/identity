package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// glossAccessJSON is the config_json an operator sets to restrict a project
// (e.g. the future admin-gloss project) to an explicit two-email membership. It
// is the exact shape the PR body documents.
const glossAccessJSON = `{"access":{"mode":"allowlist","allowed_emails":["arun88m@gmail.com","sowjanya@tinykite.co"]}}`

// gmailAllowlistJSON lists a +tagged gmail address to prove canonicalization at
// match time (a login as the dotted/untagged form is admitted).
const gmailAllowlistJSON = `{"access":{"mode":"allowlist","allowed_emails":["alice.smith+work@gmail.com"],"allowed_domains":["cursive.ai"]}}`

const accessTestPassword = "S3cure!Passw0rd"

// accessScope parses configJSON exactly as the control-plane resolver does and
// returns a context carrying the resulting per-project scope, so tests exercise
// the real parse + canonicalization rather than a hand-built policy.
func accessScope(t *testing.T, configJSON string) context.Context {
	t.Helper()
	cfg, err := ParseProjectConfig(configJSON)
	require.NoError(t, err)
	return WithProjectScope(context.Background(), &ProjectScope{ProjectID: "admin-gloss", Access: cfg.Access})
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
		AllowedDomains: []string{"cursive.ai"},
	}
	for _, tc := range []struct {
		name  string
		email string // already-canonical, as the guard passes it
		want  bool
	}{
		{"email_match", "alicesmith@gmail.com", true},
		{"domain_match", "arun@cursive.ai", true},
		{"no_match_gmail", "bob@gmail.com", false},
		{"no_match_domain", "x@other.com", false},
		{"no_at", "garbage", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, a.permits(tc.email))
		})
	}
}

// accessPermits is the whole mode matrix (mode × signup/login) in one table.
func TestAccessPermits_Matrix(t *testing.T) {
	t.Parallel()
	const listed = "arun@cursive.ai"
	const unlisted = "outsider@other.com"
	allow := ProjectAccessConfig{Mode: AccessModeAllowlist, AllowedDomains: []string{"cursive.ai"}}

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
			assert.Equal(t, tc.wantPermit, accessPermits(tc.access, tc.email, tc.signup))
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
		`"allowed_emails":["Alice.Smith+work@GMAIL.com"],"allowed_domains":["Cursive.AI","Googlemail.com"]}}`)
	require.NoError(t, err)
	assert.Equal(t, []string{"alicesmith@gmail.com"}, cfg.Access.AllowedEmails)
	assert.Equal(t, []string{"cursive.ai", "gmail.com"}, cfg.Access.AllowedDomains)
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
	a, err := NewProjectAccessConfig(AccessModeAllowlist, []string{"OP@Cursive.AI"}, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"op@cursive.ai"}, a.AllowedEmails)

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
	require.NoError(t, svc.enforceProjectAccessSignup(context.Background(), "anyone@anywhere.com"))
	require.NoError(t, svc.enforceProjectAccessLogin(context.Background(), "anyone@anywhere.com"))
}

func TestEnforceProjectAccess_SignupVsLogin(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)

	invite := accessScope(t, `{"access":{"mode":"invite"}}`)
	require.ErrorIs(t, svc.enforceProjectAccessSignup(invite, "x@y.com"), ErrSignupByInvitationOnly)
	require.NoError(t, svc.enforceProjectAccessLogin(invite, "x@y.com"))

	closed := accessScope(t, `{"access":{"mode":"closed"}}`)
	require.ErrorIs(t, svc.enforceProjectAccessSignup(closed, "x@y.com"), ErrAccessNotAllowed)
	require.ErrorIs(t, svc.enforceProjectAccessLogin(closed, "x@y.com"), ErrAccessNotAllowed)

	open := accessScope(t, `{"access":{"mode":"open"}}`)
	require.NoError(t, svc.enforceProjectAccessSignup(open, "x@y.com"))
	require.NoError(t, svc.enforceProjectAccessLogin(open, "x@y.com"))

	// The guard canonicalizes, so a dotted/cased variant of the listed gmail
	// address is admitted by the allowlist.
	allow := accessScope(t, gmailAllowlistJSON)
	require.NoError(t, svc.enforceProjectAccessLogin(allow, "Alice.Smith@gmail.com"))
	require.ErrorIs(t, svc.enforceProjectAccessSignup(allow, "nope@nowhere.com"), ErrAccessNotAllowed)
}

// ── Default-DENY regression: unconfigured project denies everything ──────

func TestProjectAccess_Unconfigured_DeniesSignupAndLogin(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	ctx := unconfiguredScope()

	_, err := svc.PasswordSignup(ctx, "someone@random-domain.com", accessTestPassword, "S", "", 0)
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

	res, err := svc.PasswordSignup(ctx, "anyone@random-domain.com", accessTestPassword, "Any", "", 0)
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
	res, err := svc.PasswordSignup(ctx, "arun@cursive.ai", accessTestPassword, "Arun", "", 0)
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)
	login, err := svc.PasswordLogin(ctx, "arun@cursive.ai", accessTestPassword, "1.2.3.4", "agent")
	require.NoError(t, err)
	require.NotEmpty(t, login.AccessToken)

	// gmail canonicalization: the dotted variant of the listed address is allowed.
	_, err = svc.PasswordSignup(ctx, "Alice.Smith@GMAIL.com", accessTestPassword, "Alice", "", 0)
	require.NoError(t, err)

	// Off-list: signup denied, no account created.
	_, err = svc.PasswordSignup(ctx, "outsider@other.com", accessTestPassword, "Out", "", 0)
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
		Code: fakeOAuthCode("arun@cursive.ai", "Arun", "", "google"), Provider: "google", RedirectURI: "https://app/cb",
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
	require.NoError(t, svc.RequestEmailLoginCode(ctx, "arun@cursive.ai"))
	require.Len(t, rec.Sent(), 1)
	res, err := svc.VerifyEmailLoginCode(ctx, "arun@cursive.ai", extractCodeFromEmail(t, rec.Sent()[0].Text), "1.2.3.4", "a")
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

		ctx := accessScope(t, `{"access":{"mode":"allowlist","allowed_domains":["cursive.ai"]}}`)
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

	_, err := svc.PasswordSignup(ctx, "a@b.com", accessTestPassword, "A", "", 0)
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
		_, err := svc.PasswordSignup(accessScope(t, ctxJSON), "new@x.com", accessTestPassword, "N", "", 0)
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
	ctx := accessScope(t, gmailAllowlistJSON) // allows the cursive.ai domain

	onList := seedInvitedUser(t, repo, "member@cursive.ai")
	res, err := svc.AcceptInvitation(ctx, onList, accessTestPassword, "Member", "", "")
	require.NoError(t, err, "an on-list invitee may accept")
	require.NotEmpty(t, res.AccessToken)

	offList := seedInvitedUser(t, repo, "stranger@other.com")
	_, err = svc.AcceptInvitation(ctx, offList, accessTestPassword, "Stranger", "", "")
	require.ErrorIs(t, err, ErrAccessNotAllowed, "an admin cannot invite someone the allowlist excludes")
}

// ── Env-configured default project (Nesta): mode governs deny/permit ─────

func TestProjectAccess_EnvDefaultProject_ModeGovernsDenyOrPermit(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	build := func(mode string) context.Context {
		access, err := NewProjectAccessConfig(mode, nil, nil)
		require.NoError(t, err)
		return WithProjectScope(context.Background(), &ProjectScope{ProjectID: "default", Access: access})
	}

	// GATEWAY_DEFAULT_PROJECT_ACCESS_MODE=open → permit.
	require.NoError(t, svc.enforceProjectAccessSignup(build(AccessModeOpen), "x@y.com"))

	// unset ("") and closed → deny (what a deployment gets if it sets nothing).
	require.ErrorIs(t, svc.enforceProjectAccessSignup(build(""), "x@y.com"), ErrAccessNotAllowed)
	require.ErrorIs(t, svc.enforceProjectAccessLogin(build(""), "x@y.com"), ErrAccessNotAllowed)
	require.ErrorIs(t, svc.enforceProjectAccessLogin(build(AccessModeClosed), "x@y.com"), ErrAccessNotAllowed)
}

// ── The documented admin-gloss config parses to the intended allowlist ───

func TestProjectAccess_AdminGlossDocumentedConfig(t *testing.T) {
	t.Parallel()
	cfg, err := ParseProjectConfig(glossAccessJSON)
	require.NoError(t, err)
	assert.Equal(t, AccessModeAllowlist, cfg.Access.Mode)
	assert.Equal(t, []string{"arun88m@gmail.com", "sowjanya@tinykite.co"}, cfg.Access.AllowedEmails)
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
		{"allowlist_onlist_sends", gmailAllowlistJSON, "arun@cursive.ai", false, true},
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
		{"allowlist_offlist_denies", `{"access":{"mode":"allowlist","allowed_domains":["cursive.ai"]}}`, ErrAccessNotAllowed},
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

	reg, err := svc.PasswordSignup(open, "user@ex.com", accessTestPassword, "U", "", 0)
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
