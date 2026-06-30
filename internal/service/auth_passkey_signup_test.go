package service

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passkeys"
)

// WebAuthn spec test vectors (FIDO U2F), RP = example.org. The same vectors the
// integration suite uses; here they let a service-level unit test drive a full
// passkey-first-signup-then-login ceremony without a hardware authenticator.
const (
	pkRegAttestationObjectHex = "a363666d74686669646f2d7532666761747453746d74a26373696758473045022100f41887a20063bb26867cb9751978accea5b81791a68f4f4dd6ea1fb6a5c086c302204e5e00aa3895777e6608f1f375f95450045da3da57a0e4fd451df35a31d2d98a637835638159022530820221308201c7a003020102021004f66dc6542ea7719dea416d325a2401300a06082a8648ce3d0403023062311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331253023060355040b0c1c41757468656e74696361746f72204174746573746174696f6e204341310b30090603550406130241413020170d3234303130313030303030305a180f33303234303130313030303030305a305f311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130241413059301306072a8648ce3d020106082a8648ce3d0301070342000456fffa7093dede46aefeefb6e520c7ccc78967636e2f92582ba71455f64e93932dff3be4e0d4ef68e3e3b73aa087e26a0a0a30b02dc2aa2309db4c3a2fc936dea360305e300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301d0603551d0e04160414420822eb1908b5cd3911017fbcad4641c05e05a3301f0603551d2304183016801445aff715b0dd786741fee996ebc16547a3931b1e300a06082a8648ce3d040302034800304502200d0b777f0a0b181ad2830275acc3150fd6092430bcd034fd77beb7bdf8c2d546022100d4864edd95daa3927080855df199f1717299b24a5eecefbd017455a9b934d8f668617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b54100000000afb3c2efc054df425013d5c88e79c3c10020a4ba6e2d2cfec43648d7d25c5ed5659bc18f2b781538527ebd492de03256bdf4a5010203262001215820b0d62de6b30f86f0bac7a9016951391c2e31849e2e64661cbd2b13cd7d5508ad225820503b0bda2a357a9a4b34475a28e65b660b4898a9e3e9bbf0820d43494297edd0"
	pkRegClientDataJSONHex    = "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22344851334b5a4335797155486f696666786e73414e344445557955344452715177672d4237583049444159222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"
	pkCredentialIDHex         = "a4ba6e2d2cfec43648d7d25c5ed5659bc18f2b781538527ebd492de03256bdf4" //nolint:gosec // G101: WebAuthn spec test vector (credential id), not a secret
	pkRegChallengeHex         = "e074372990b9caa507a227dfc67b003780c45325380d1a90c20f81ed7d080c06"
	pkAuthenticatorDataHex    = "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50100000000"
	pkLoginClientDataJSONHex  = "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a222d5178684b59485954316d554f4e3461554139326b6d36537a49532d2d4f417362694e5650774249564455222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"
	pkLoginSignatureHex       = "304402206172459958fea907b7292b92f555034bfd884895f287a76200c1ba287239137002204727b166147e26a21bbc2921d192ebfed569b79438538e5c128b5e28e6926dd7"
	pkLoginChallengeHex       = "f90c612981d84f599438de1a500f76926e92cc84bef8e02c6e23553f00485435"

	pkVectorEmail = "u2f-signup@example.org"
)

func mustUnhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func pkB64URL(t *testing.T, hexStr string) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(mustUnhex(t, hexStr))
}

// newPasskeyVectorSvc builds an AuthService whose WebAuthn RP matches the spec
// vectors (example.org), backed by a fakeRepo + recording mailer.
func newPasskeyVectorSvc(t *testing.T) (*AuthService, *fakeRepo, *recordingTransport) {
	t.Helper()
	repo := newFakeRepo()
	cfg := testConfig()
	cfg.AppBaseURL = "https://app.test"
	cfg.SMTPFrom = "no-reply@test.local"
	cfg.EmailTokenExpirySeconds = 3600
	cfg.PasskeyRPID = "example.org"
	cfg.PasskeyRPName = "Example"
	cfg.PasskeyOrigin = "https://example.org"
	kr := testKeyRing(t)
	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID: cfg.PasskeyRPID, RPName: cfg.PasskeyRPName, Origin: cfg.PasskeyOrigin,
	})
	require.NoError(t, err)
	rec := &recordingTransport{}
	svc := NewAuthService(repo, cfg, kr, pkSvc,
		audit.NewLogger(nil, "test", zap.NewNop()),
		testTotpKey(), testTotpRecoveryPepper(), rec, nil, zap.NewNop())
	return svc, repo, rec
}

// setFakeChallengeValue overwrites a stored challenge's value so a spec
// attestation/assertion (whose challenge is fixed) verifies against it.
func setFakeChallengeValue(repo *fakeRepo, challengeID, value string) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	repo.passkeyChallenges[challengeID].Challenge = value
}

// handleFromOptions decodes the WebAuthn user handle (user.id) from the
// creation-options JSON returned by BeginPasskeySignup.
func handleFromOptions(t *testing.T, optionsJSON string) string {
	t.Helper()
	var opts struct {
		PublicKey struct {
			User struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	require.NoError(t, json.Unmarshal([]byte(optionsJSON), &opts))
	require.NotEmpty(t, opts.PublicKey.User.ID, "options must carry a user handle")
	raw, err := base64.RawURLEncoding.DecodeString(opts.PublicKey.User.ID)
	require.NoError(t, err)
	return string(raw)
}

func pkRegCredentialJSON(t *testing.T) string {
	t.Helper()
	id := pkB64URL(t, pkCredentialIDHex)
	body := map[string]any{
		"id": id, "rawId": id, "type": "public-key",
		"response": map[string]any{
			"attestationObject": pkB64URL(t, pkRegAttestationObjectHex),
			"clientDataJSON":    pkB64URL(t, pkRegClientDataJSONHex),
			"transports":        []string{"usb"},
		},
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	return string(b)
}

func pkAssertionCredentialJSON(t *testing.T) string {
	t.Helper()
	id := pkB64URL(t, pkCredentialIDHex)
	body := map[string]any{
		"id": id, "rawId": id, "type": "public-key",
		"response": map[string]any{
			"authenticatorData": pkB64URL(t, pkAuthenticatorDataHex),
			"clientDataJSON":    pkB64URL(t, pkLoginClientDataJSONHex),
			"signature":         pkB64URL(t, pkLoginSignatureHex),
		},
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	return string(b)
}

// passkeySignupOTP pulls the 6-digit OTP that BeginPasskeySignup emails (the
// in-flow proof of email control) out of the recording transport.
func passkeySignupOTP(t *testing.T, rec *recordingTransport, addr string) string {
	t.Helper()
	for _, msg := range rec.Sent() {
		if msg.To == addr && msg.Subject == "Your login code" {
			return extractCodeFromEmail(t, msg.Text)
		}
	}
	t.Fatalf("no passkey-signup OTP email for %q", addr)
	return ""
}

// TestPasskeySignup_NewEmail_BindsHandleAndLoginSucceeds is the core proof of
// the #283-class binding: the created user's id equals the WebAuthn user handle
// minted at Begin, and a subsequent CompletePasskeyLogin for that account
// succeeds with the credential registered during signup. It also proves the
// in-flow OTP path: a valid OTP creates an already-verified account.
func TestPasskeySignup_NewEmail_BindsHandleAndLoginSucceeds(t *testing.T) {
	svc, repo, rec := newPasskeyVectorSvc(t)
	ctx := context.Background()

	optionsJSON, challengeID, err := svc.BeginPasskeySignup(ctx, pkVectorEmail, "My Key")
	require.NoError(t, err)
	require.NotEmpty(t, challengeID)
	handle := handleFromOptions(t, optionsJSON)
	otp := passkeySignupOTP(t, rec, pkVectorEmail)

	// Drive the spec attestation against the minted challenge.
	setFakeChallengeValue(repo, challengeID, pkB64URL(t, pkRegChallengeHex))

	res, err := svc.CompletePasskeySignup(ctx, challengeID, pkRegCredentialJSON(t), pkVectorEmail, otp, "My Key", "1.2.3.4", "agent")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotNil(t, res.User)

	// The created user's id IS the WebAuthn handle (the binding invariant).
	assert.Equal(t, handle, res.User.ID, "created user id must equal the WebAuthn user handle")
	got, err := repo.FindUserByEmail(ctx, pkVectorEmail)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, handle, got.ID)
	// The consumed OTP proved inbox control, so the account is created VERIFIED.
	// There is no unverified account carrying a passkey — the pre-hijacking
	// surface is closed at the source.
	assert.True(t, got.EmailVerified, "passkey-first signup with a valid OTP creates a verified account")
	assert.NotZero(t, got.EmailVerifiedAt)
	assert.True(t, res.User.EmailVerified)

	// The credential is stored under that same id.
	creds, err := repo.ListPasskeyCredentials(ctx, got.ID)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, got.ID, creds[0].UserID)
	assert.Equal(t, pkB64URL(t, pkCredentialIDHex), creds[0].CredentialID)

	// A session was issued (the account is verified).
	assert.NotEmpty(t, res.AccessToken)
	assert.NotEmpty(t, res.RefreshToken)

	// PROOF: a subsequent passkey login for this account succeeds. This only
	// works if the stored credential's user id matches the handle the
	// authenticator returns — i.e. the binding is correct.
	_, loginChallengeID, err := svc.BeginPasskeyLogin(ctx, pkVectorEmail)
	require.NoError(t, err)
	setFakeChallengeValue(repo, loginChallengeID, pkB64URL(t, pkLoginChallengeHex))

	login, err := svc.CompletePasskeyLogin(ctx, loginChallengeID, pkAssertionCredentialJSON(t), "1.2.3.4", "agent")
	require.NoError(t, err)
	require.NotNil(t, login)
	assert.Equal(t, got.ID, login.User.ID)
	assert.NotEmpty(t, login.AccessToken)
	assert.NotEmpty(t, login.RefreshToken)
}

// TestPasskeySignup_ExistingEmail_Decoy: when the email already exists, no
// passkey is attached (anti-takeover), existence is not revealed (the result is
// the same success-shaped decoy as a duplicate PasswordSignup) and the
// existing-account notice is sent.
func TestPasskeySignup_ExistingEmail_Decoy(t *testing.T) {
	svc, repo, rec := newPasskeyVectorSvc(t)
	ctx := context.Background()

	existing := seedUser(repo, pkVectorEmail, hashPW(t, "Existing0wner!"), "active")

	_, challengeID, err := svc.BeginPasskeySignup(ctx, pkVectorEmail, "Attacker Key")
	require.NoError(t, err)
	// An OTP is still emailed for an existing address (enumeration-safe). Only an
	// inbox-controller has it; supplying a VALID one still yields the decoy.
	otp := passkeySignupOTP(t, rec, pkVectorEmail)
	setFakeChallengeValue(repo, challengeID, pkB64URL(t, pkRegChallengeHex))

	res, err := svc.CompletePasskeySignup(ctx, challengeID, pkRegCredentialJSON(t), pkVectorEmail, otp, "Attacker Key", "9.9.9.9", "agent")
	require.NoError(t, err)
	require.NotNil(t, res)

	// No passkey was attached to the real account (anti-takeover).
	creds, err := repo.ListPasskeyCredentials(ctx, existing.ID)
	require.NoError(t, err)
	assert.Empty(t, creds, "an existing account must not receive an unauthenticated passkey")

	// The decoy does not reveal the real account id.
	assert.NotEqual(t, existing.ID, res.User.ID)
	assert.True(t, strings.HasPrefix(res.User.ID, "signup-pending-"), "expected an enumeration-safe decoy id")

	// The existing-account notice was sent (after the OTP email).
	require.NotEmpty(t, rec.Sent())
}

// TestPasskeySignup_Disabled: both RPCs fail closed when the feature flag is off.
func TestPasskeySignup_Disabled(t *testing.T) {
	svc, _, _ := newPasskeyVectorSvc(t)
	svc.cfg.PasskeySignupEnabled = false
	ctx := context.Background()

	_, _, err := svc.BeginPasskeySignup(ctx, pkVectorEmail, "Key")
	require.ErrorIs(t, err, ErrPasskeySignupDisabled)

	_, err = svc.CompletePasskeySignup(ctx, "cid", "{}", pkVectorEmail, "000000", "Key", "", "")
	require.ErrorIs(t, err, ErrPasskeySignupDisabled)
}

// TestPasskeySignup_WrongOTP_NoAccountCreated: a passkey whose attestation
// verifies but whose OTP is wrong creates NO account and returns a generic
// error — there is never a planted passkey on an unverified account.
func TestPasskeySignup_WrongOTP_NoAccountCreated(t *testing.T) {
	svc, repo, rec := newPasskeyVectorSvc(t)
	ctx := context.Background()

	_, challengeID, err := svc.BeginPasskeySignup(ctx, pkVectorEmail, "My Key")
	require.NoError(t, err)
	// Confirm a real OTP was minted, then deliberately submit a different one.
	real := passkeySignupOTP(t, rec, pkVectorEmail)
	wrong := "000000"
	if real == wrong {
		wrong = "111111"
	}
	setFakeChallengeValue(repo, challengeID, pkB64URL(t, pkRegChallengeHex))

	res, err := svc.CompletePasskeySignup(ctx, challengeID, pkRegCredentialJSON(t), pkVectorEmail, wrong, "My Key", "1.2.3.4", "agent")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrEmailLoginCodeInvalid)
	assert.Nil(t, res)

	// No account, no passkey: the wrong OTP left nothing behind.
	got, err := repo.FindUserByEmail(ctx, pkVectorEmail)
	require.NoError(t, err)
	assert.Nil(t, got, "a wrong OTP must not create an account")
}

// TestPasskeySignup_WrongThenRightOTP_RetryableWithoutNewCeremony proves the
// OTP-before-challenge-consume ordering: a mistyped code returns the generic
// error but LEAVES THE SINGLE-USE CHALLENGE INTACT, so the client re-submits the
// SAME credentialJSON with the corrected code and it succeeds — no fresh
// BeginPasskeySignup and no second navigator.credentials.create ceremony.
func TestPasskeySignup_WrongThenRightOTP_RetryableWithoutNewCeremony(t *testing.T) {
	svc, repo, rec := newPasskeyVectorSvc(t)
	ctx := context.Background()

	optionsJSON, challengeID, err := svc.BeginPasskeySignup(ctx, pkVectorEmail, "My Key")
	require.NoError(t, err)
	handle := handleFromOptions(t, optionsJSON)
	otp := passkeySignupOTP(t, rec, pkVectorEmail)
	wrong := "000000"
	if otp == wrong {
		wrong = "111111"
	}
	setFakeChallengeValue(repo, challengeID, pkB64URL(t, pkRegChallengeHex))

	// The exact same credential is submitted on both attempts — the client does
	// NOT run a second ceremony.
	credJSON := pkRegCredentialJSON(t)

	// Attempt 1: correct attestation, WRONG code → generic error, no account.
	res, err := svc.CompletePasskeySignup(ctx, challengeID, credJSON, pkVectorEmail, wrong, "My Key", "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrEmailLoginCodeInvalid)
	assert.Nil(t, res)
	got, err := repo.FindUserByEmail(ctx, pkVectorEmail)
	require.NoError(t, err)
	assert.Nil(t, got, "a wrong OTP must not create an account")

	// The single-use challenge SURVIVED the wrong code — it was not burned.
	ch, err := repo.GetPasskeyChallenge(ctx, challengeID)
	require.NoError(t, err)
	require.NotNil(t, ch, "challenge must survive a wrong OTP so the code is retryable without a new ceremony")

	// Attempt 2: SAME credentialJSON + CORRECT code → SUCCEEDS.
	res, err = svc.CompletePasskeySignup(ctx, challengeID, credJSON, pkVectorEmail, otp, "My Key", "1.2.3.4", "agent")
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, handle, res.User.ID, "the retried completion binds the same WebAuthn handle")
	assert.NotEmpty(t, res.AccessToken)
	assert.NotEmpty(t, res.RefreshToken)

	got, err = repo.FindUserByEmail(ctx, pkVectorEmail)
	require.NoError(t, err)
	require.NotNil(t, got, "the corrected code must create the (verified) account")
	assert.True(t, got.EmailVerified)

	// Proof the binding is intact: a subsequent passkey login succeeds with the
	// credential registered during the retried signup.
	_, loginChallengeID, err := svc.BeginPasskeyLogin(ctx, pkVectorEmail)
	require.NoError(t, err)
	setFakeChallengeValue(repo, loginChallengeID, pkB64URL(t, pkLoginChallengeHex))
	login, err := svc.CompletePasskeyLogin(ctx, loginChallengeID, pkAssertionCredentialJSON(t), "1.2.3.4", "agent")
	require.NoError(t, err)
	require.NotNil(t, login)
	assert.Equal(t, got.ID, login.User.ID)
	assert.NotEmpty(t, login.AccessToken)
}

// TestPasskeySignup_DecoyTokenShapeParity proves new-vs-existing passkey-signup
// responses are indistinguishable by token presence with
// GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL both off and on. The new-account path
// always issues a session (the OTP proved email control), so the existing-email
// decoy must ALSO always carry a fabricated token — otherwise the gated decoy
// would be session-less and disclose that the address already exists.
func TestPasskeySignup_DecoyTokenShapeParity(t *testing.T) {
	for _, requireVerified := range []bool{false, true} {
		t.Run(fmt.Sprintf("require_verified_email=%v", requireVerified), func(t *testing.T) {
			ctx := context.Background()

			// New-account path.
			newSvc, newRepo, newRec := newPasskeyVectorSvc(t)
			newSvc.cfg.AuthRequireVerifiedEmail = requireVerified
			_, newChID, err := newSvc.BeginPasskeySignup(ctx, pkVectorEmail, "My Key")
			require.NoError(t, err)
			newOTP := passkeySignupOTP(t, newRec, pkVectorEmail)
			setFakeChallengeValue(newRepo, newChID, pkB64URL(t, pkRegChallengeHex))
			newRes, err := newSvc.CompletePasskeySignup(ctx, newChID, pkRegCredentialJSON(t), pkVectorEmail, newOTP, "My Key", "1.2.3.4", "agent")
			require.NoError(t, err)
			require.NotNil(t, newRes)

			// Existing-account path (decoy).
			exSvc, exRepo, exRec := newPasskeyVectorSvc(t)
			exSvc.cfg.AuthRequireVerifiedEmail = requireVerified
			seedUser(exRepo, pkVectorEmail, hashPW(t, "Existing0wner!"), "active")
			_, exChID, err := exSvc.BeginPasskeySignup(ctx, pkVectorEmail, "Attacker Key")
			require.NoError(t, err)
			exOTP := passkeySignupOTP(t, exRec, pkVectorEmail)
			setFakeChallengeValue(exRepo, exChID, pkB64URL(t, pkRegChallengeHex))
			exRes, err := exSvc.CompletePasskeySignup(ctx, exChID, pkRegCredentialJSON(t), pkVectorEmail, exOTP, "Attacker Key", "9.9.9.9", "agent")
			require.NoError(t, err)
			require.NotNil(t, exRes)

			// Token PRESENCE must be identical new-vs-existing, both flags.
			assert.Equal(t, newRes.AccessToken != "", exRes.AccessToken != "",
				"access-token presence must match new-vs-existing")
			assert.Equal(t, newRes.RefreshToken != "", exRes.RefreshToken != "",
				"refresh-token presence must match new-vs-existing")
			// Both paths actually issue tokens (the new path always does).
			assert.NotEmpty(t, newRes.AccessToken)
			assert.NotEmpty(t, newRes.RefreshToken)
			assert.NotEmpty(t, exRes.AccessToken)
			assert.NotEmpty(t, exRes.RefreshToken)
		})
	}
}

// TestPasskeySignup_ExpiredOTP_NoAccountCreated: an expired OTP behaves exactly
// like a wrong one — generic error, no account.
func TestPasskeySignup_ExpiredOTP_NoAccountCreated(t *testing.T) {
	svc, repo, rec := newPasskeyVectorSvc(t)
	ctx := context.Background()

	_, challengeID, err := svc.BeginPasskeySignup(ctx, pkVectorEmail, "My Key")
	require.NoError(t, err)
	otp := passkeySignupOTP(t, rec, pkVectorEmail)

	// Expire the minted OTP in place.
	repo.mu.Lock()
	for _, c := range repo.emailLoginCodes {
		if c.Email == pkVectorEmail {
			c.ExpiresAt = svc.nowMs() - 1
		}
	}
	repo.mu.Unlock()

	setFakeChallengeValue(repo, challengeID, pkB64URL(t, pkRegChallengeHex))

	res, err := svc.CompletePasskeySignup(ctx, challengeID, pkRegCredentialJSON(t), pkVectorEmail, otp, "My Key", "1.2.3.4", "agent")
	require.ErrorIs(t, err, ErrEmailLoginCodeInvalid)
	assert.Nil(t, res)

	got, err := repo.FindUserByEmail(ctx, pkVectorEmail)
	require.NoError(t, err)
	assert.Nil(t, got, "an expired OTP must not create an account")
}

// TestPasskeySignup_PreHijacking_ExternalProofClearsPasskeys exercises the
// DEFENSE-IN-DEPTH eviction: a passkey sitting on an unverified account is
// voided when an external proof (here an emailed OTP — the same
// markEmailVerifiedViaExternalProof path OAuth/passwordless use) proves the real
// owner controls the inbox.
//
// The PRIMARY fix for the pre-hijacking blocker is upstream: passkey-first
// signup now requires an in-flow OTP and creates the account already verified
// (see TestPasskeySignup_NewEmail_BindsHandleAndLoginSucceeds), so this
// unverified-account-with-a-passkey state can no longer arise via signup. This
// test keeps the external-proof eviction honest as belt-and-suspenders.
func TestPasskeySignup_PreHijacking_ExternalProofClearsPasskeys(t *testing.T) {
	svc, repo, rec := passwordlessSvc(t)
	ctx := context.Background()

	// Unverified account with an attacker-planted passkey (no password).
	victim := seedUser(repo, "victim@test.com", "", "active")
	victim.EmailVerified = false
	plantedCredID, err := repo.CreatePasskeyCredential(ctx, &PasskeyCredRecord{
		CredentialID: "planted-cred", UserID: victim.ID, PublicKey: "pk", CreatedAt: 1,
	})
	require.NoError(t, err)
	require.NotEmpty(t, plantedCredID)

	// The real owner proves inbox control via an emailed OTP.
	require.NoError(t, svc.RequestEmailLoginCode(ctx, "victim@test.com"))
	code := extractCodeFromEmail(t, rec.Sent()[0].Text)
	res, err := svc.VerifyEmailLoginCode(ctx, "victim@test.com", code, "1.1.1.1", "agent")
	require.NoError(t, err)
	require.Equal(t, victim.ID, res.User.ID)

	// The planted passkey is gone.
	creds, err := repo.ListPasskeyCredentials(ctx, victim.ID)
	require.NoError(t, err)
	assert.Empty(t, creds, "passkey planted while unverified must be cleared on external email proof")
	gone, err := repo.GetPasskeyCredentialByCredID(ctx, "planted-cred")
	require.NoError(t, err)
	assert.Nil(t, gone, "the old credential must no longer resolve, so a passkey login with it fails")
}
