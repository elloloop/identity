package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/internal/origin"
)

func TestPasskeysFor_NoScope_ReturnsGlobal(t *testing.T) {
	t.Parallel()
	svc, _ := newAuthSvcWithMailerForRepo(t, newFakeRepo())

	got, err := svc.passkeysFor(context.Background())
	require.NoError(t, err)
	assert.Same(t, svc.passkeys, got)
}

func TestPasskeysFor_NoPasskeyOverride_ReturnsGlobal(t *testing.T) {
	t.Parallel()
	svc, _ := newAuthSvcWithMailerForRepo(t, newFakeRepo())

	ctx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "p1"})
	got, err := svc.passkeysFor(ctx)
	require.NoError(t, err)
	assert.Same(t, svc.passkeys, got)
}

func TestPasskeysFor_ProjectOverride_ReturnsDistinctCachedInstance(t *testing.T) {
	t.Parallel()
	svc, _ := newAuthSvcWithMailerForRepo(t, newFakeRepo())

	kidsCtx := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "kids",
		Passkey: ProjectPasskeyConfig{
			RPID:   "kids.example.com",
			RPName: "Acme Kids",
			Origin: "https://kids.example.com",
		},
	})
	prosCtx := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "pros",
		Passkey: ProjectPasskeyConfig{
			RPID:   "pros.example.com",
			RPName: "Acme Pros",
			Origin: "https://pros.example.com",
		},
	})

	kids, err := svc.passkeysFor(kidsCtx)
	require.NoError(t, err)
	pros, err := svc.passkeysFor(prosCtx)
	require.NoError(t, err)

	require.NotNil(t, kids)
	require.NotNil(t, pros)
	// Each product gets its own RP-bound instance, distinct from the global
	// and from each other.
	assert.NotSame(t, svc.passkeys, kids)
	assert.NotSame(t, svc.passkeys, pros)
	assert.NotSame(t, kids, pros)

	// A second resolution of the same project reuses the cached instance.
	again, err := svc.passkeysFor(kidsCtx)
	require.NoError(t, err)
	assert.Same(t, kids, again)
}

func TestPasskeysFor_InvalidOverride_FallsBackToGlobal(t *testing.T) {
	t.Parallel()
	svc, _ := newAuthSvcWithMailerForRepo(t, newFakeRepo())

	// With no global origin to inherit, this block cannot build.
	ctx := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "broken",
		Passkey:   ProjectPasskeyConfig{RPID: "kids.example.com", Origin: ""},
	})
	svc.cfg.PasskeyOrigin = ""
	got, err := svc.passkeysFor(ctx)
	require.NoError(t, err)
	assert.Same(t, svc.passkeys, got)
}

const acmeRelyingParties = `[
	{"host": "auth.acme.example", "rp_id": "acme.example", "rp_name": "Acme", "origins": ["https://acme.example", "https://app.acme.example"]},
	{"host": "auth.widgets.example", "rp_id": "widgets.example", "origins": ["https://widgets.example"]}
]`

// rpIDOffered runs BeginPasskeyLogin and returns the relying party its options
// name: what a browser or a platform authenticator would be told.
func rpIDOffered(ctx context.Context, t *testing.T, svc *AuthService) string {
	t.Helper()
	optionsJSON, _, err := svc.BeginPasskeyLogin(ctx, "")
	require.NoError(t, err)
	var options struct {
		PublicKey struct {
			RPID string `json:"rpId"`
		} `json:"publicKey"`
	}
	require.NoError(t, json.Unmarshal([]byte(optionsJSON), &options))
	return options.PublicKey.RPID
}

func svcWithRelyingParties(t *testing.T) *AuthService {
	t.Helper()
	svc, _ := newAuthSvcWithMailerForRepo(t, newFakeRepo())
	svc.cfg.PasskeyRelyingPartiesJSON = acmeRelyingParties
	require.NoError(t, svc.cfg.ValidatePasskeyRelyingParties())
	return svc
}

func TestPasskeysFor_HostEntry_ChoosesItsRelyingParty(t *testing.T) {
	t.Parallel()
	svc := svcWithRelyingParties(t)

	acme := WithRequestHost(context.Background(), "auth.acme.example")
	widgets := WithRequestHost(context.Background(), "auth.widgets.example")

	assert.Equal(t, "acme.example", rpIDOffered(acme, t, svc))
	assert.Equal(t, "widgets.example", rpIDOffered(widgets, t, svc))

	first, err := svc.passkeysFor(acme)
	require.NoError(t, err)
	second, err := svc.passkeysFor(acme)
	require.NoError(t, err)
	assert.Same(t, first, second)
}

func TestPasskeysFor_HostEntry_WinsOverTheProjectsBlock(t *testing.T) {
	t.Parallel()
	svc := svcWithRelyingParties(t)

	ctx := WithProjectScope(
		WithRequestHost(context.Background(), "auth.acme.example"),
		&ProjectScope{ProjectID: "p", Passkey: ProjectPasskeyConfig{RPID: "other.example", Origin: "https://other.example"}},
	)
	assert.Equal(t, "acme.example", rpIDOffered(ctx, t, svc))
}

func TestPasskeysFor_UnlistedHost_NeverGetsAnotherRelyingParty(t *testing.T) {
	t.Parallel()
	svc := svcWithRelyingParties(t)

	for _, host := range []string{"auth.other.example", "", "acme.example", "evil.auth.acme.example"} {
		ctx := WithRequestHost(context.Background(), host)
		_, err := svc.passkeysFor(ctx)
		require.ErrorIs(t, err, ErrPasskeysUnavailable, "host %q", host)
		_, _, err = svc.BeginPasskeyLogin(ctx, "")
		require.ErrorIs(t, err, ErrPasskeysUnavailable, "host %q", host)
		_, _, err = svc.BeginPasskeySignup(ctx, "new@example.com", "")
		require.ErrorIs(t, err, ErrPasskeysUnavailable, "host %q", host)
	}
	// A call with no host at all, such as native gRPC, is refused too.
	_, err := svc.passkeysFor(context.Background())
	require.ErrorIs(t, err, ErrPasskeysUnavailable)
}

func TestPasskeysFor_UnlistedHost_KeepsItsProjectsOwnRelyingParty(t *testing.T) {
	t.Parallel()
	svc := svcWithRelyingParties(t)

	ctx := WithProjectScope(
		WithRequestHost(context.Background(), "auth.other.example"),
		&ProjectScope{ProjectID: "p", Passkey: ProjectPasskeyConfig{RPID: "other.example", Origin: "https://other.example"}},
	)
	assert.Equal(t, "other.example", rpIDOffered(ctx, t, svc))
}

// A block that leaves out rp_id or origin would inherit the global relying
// party, which on an unlisted host is another product's.
func TestPasskeysFor_UnlistedHost_PartialProjectBlockIsRefused(t *testing.T) {
	t.Parallel()
	svc := svcWithRelyingParties(t)

	for name, block := range map[string]ProjectPasskeyConfig{
		"name only": {RPName: "Other"},
		"no origin": {RPID: "other.example"},
		"no rp id":  {Origin: "https://other.example"},
	} {
		ctx := WithProjectScope(
			WithRequestHost(context.Background(), "auth.other.example"),
			&ProjectScope{ProjectID: "p", Passkey: block},
		)
		_, err := svc.passkeysFor(ctx)
		require.ErrorIs(t, err, ErrPasskeysUnavailable, name)
	}
}

func TestPasskeysFor_UnvalidatedConfig_FailsClosed(t *testing.T) {
	t.Parallel()
	svc, _ := newAuthSvcWithMailerForRepo(t, newFakeRepo())
	svc.cfg.PasskeyRelyingPartiesJSON = acmeRelyingParties

	_, err := svc.passkeysFor(WithRequestHost(context.Background(), "auth.acme.example"))
	require.ErrorIs(t, err, ErrPasskeysUnavailable)
}

func TestPasskeysFor_Unset_EveryHostKeepsTheGlobal(t *testing.T) {
	t.Parallel()
	svc, _ := newAuthSvcWithMailerForRepo(t, newFakeRepo())

	got, err := svc.passkeysFor(WithRequestHost(context.Background(), "auth.anything.example"))
	require.NoError(t, err)
	assert.Same(t, svc.passkeys, got)
}

// The begin-login and complete-login refusals answer before any lookup, so a
// refused host learns nothing about an email or a credential.
func TestPasskeyLogin_UnlistedHost_Refused(t *testing.T) {
	t.Parallel()
	svc := svcWithRelyingParties(t)
	ctx := WithRequestHost(context.Background(), "auth.other.example")

	_, _, err := svc.BeginPasskeyLogin(ctx, "")
	require.ErrorIs(t, err, ErrPasskeysUnavailable)
	_, err = svc.CompletePasskeyLogin(ctx, "challenge", "{}", "", "")
	require.ErrorIs(t, err, ErrPasskeysUnavailable)
}

// vectorRelyingParties lists the spec vectors' relying party on one host, and
// another relying party on a second.
const vectorRelyingParties = `[
	{"host":"auth.example.org","rp_id":"example.org","origins":["https://example.org"]},
	{"host":"auth.acme.example","rp_id":"acme.example","origins":["https://acme.example"]}
]`

// vectorHostSvc is a service with vectorRelyingParties, and the account the spec
// vectors' credential was made for, signed up on the vectors' host.
func vectorHostSvc(t *testing.T) (*AuthService, *fakeRepo, string) {
	t.Helper()
	svc, repo, rec := newPasskeyVectorSvc(t)
	svc.cfg.PasskeyRelyingPartiesJSON = vectorRelyingParties
	require.NoError(t, svc.cfg.ValidatePasskeyRelyingParties())
	ctx := WithRequestHost(context.Background(), "auth.example.org")

	_, challengeID, err := svc.BeginPasskeySignup(ctx, pkVectorEmail, "My Key")
	require.NoError(t, err)
	otp := passkeySignupOTP(t, rec, pkVectorEmail)
	setFakeChallengeValue(repo, challengeID, pkB64URL(t, pkRegChallengeHex))
	res, err := svc.CompletePasskeySignup(ctx, challengeID, pkRegCredentialJSON(t), pkVectorEmail, otp, "My Key", "1.2.3.4", "ua")
	require.NoError(t, err)
	return svc, repo, res.User.ID
}

// A ceremony that begins on a listed host cannot complete on an unlisted one, and
// neither registration step runs on an unlisted host for a real account.
func TestPasskeyRegistration_UnlistedHost_Refused(t *testing.T) {
	t.Parallel()
	svc, _, userID := vectorHostSvc(t)
	listed := WithRequestHost(context.Background(), "auth.example.org")
	unlisted := WithRequestHost(context.Background(), "auth.other.example")

	_, _, err := svc.BeginPasskeyRegistration(unlisted, userID, SessionSignIn{}, "Second")
	require.ErrorIs(t, err, ErrPasskeysUnavailable)

	_, challengeID, err := svc.BeginPasskeyRegistration(listed, userID, SessionSignIn{}, "Second")
	require.NoError(t, err)
	_, _, err = svc.CompletePasskeyRegistration(unlisted, userID, SessionSignIn{}, challengeID, pkRegCredentialJSON(t), "Second", false, "1.2.3.4", "ua")
	require.ErrorIs(t, err, ErrPasskeysUnavailable)
}

func TestPasskeySignup_UnlistedHost_Refused(t *testing.T) {
	t.Parallel()
	svc, _, rec := newPasskeyVectorSvc(t)
	svc.cfg.PasskeyRelyingPartiesJSON = vectorRelyingParties
	require.NoError(t, svc.cfg.ValidatePasskeyRelyingParties())
	listed := WithRequestHost(context.Background(), "auth.example.org")
	unlisted := WithRequestHost(context.Background(), "auth.other.example")

	_, _, err := svc.BeginPasskeySignup(unlisted, pkVectorEmail, "My Key")
	require.ErrorIs(t, err, ErrPasskeysUnavailable)

	_, challengeID, err := svc.BeginPasskeySignup(listed, pkVectorEmail, "My Key")
	require.NoError(t, err)
	otp := passkeySignupOTP(t, rec, pkVectorEmail)
	_, err = svc.CompletePasskeySignup(unlisted, challengeID, pkRegCredentialJSON(t), pkVectorEmail, otp, "My Key", "1.2.3.4", "ua")
	require.ErrorIs(t, err, ErrPasskeysUnavailable)
}

// An assertion made for one relying party verifies on its own host and on no other
// listed host, so naming another host gains nothing.
func TestPasskeyLogin_AssertionVerifiesOnlyOnItsOwnHost(t *testing.T) {
	t.Parallel()
	svc, repo, _ := vectorHostSvc(t)
	own := WithRequestHost(context.Background(), "auth.example.org")
	other := WithRequestHost(context.Background(), "auth.acme.example")

	_, challengeID, err := svc.BeginPasskeyLogin(own, pkVectorEmail)
	require.NoError(t, err)
	setFakeChallengeValue(repo, challengeID, pkB64URL(t, pkLoginChallengeHex))
	_, err = svc.CompletePasskeyLogin(other, challengeID, pkAssertionCredentialJSON(t), "1.2.3.4", "ua")
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrPasskeysUnavailable)

	_, challengeID, err = svc.BeginPasskeyLogin(own, pkVectorEmail)
	require.NoError(t, err)
	setFakeChallengeValue(repo, challengeID, pkB64URL(t, pkLoginChallengeHex))
	res, err := svc.CompletePasskeyLogin(own, challengeID, pkAssertionCredentialJSON(t), "1.2.3.4", "ua")
	require.NoError(t, err)
	assert.NotEmpty(t, res.AccessToken)
}

// The refusal is the operator's only signal, so its event and fields are held
// here, and a Host longer than a DNS name is cut to that length.
func TestPasskeysFor_Refusal_LogsTheHostBounded(t *testing.T) {
	t.Parallel()
	svc := svcWithRelyingParties(t)
	core, logs := observer.New(zap.WarnLevel)
	svc.logger = zap.New(core)
	long := strings.Repeat("a", origin.MaxDNSNameLen+50)
	ctx := WithProjectScope(WithRequestHost(context.Background(), long), &ProjectScope{ProjectID: "p1"})

	_, err := svc.passkeysFor(ctx)
	require.ErrorIs(t, err, ErrPasskeysUnavailable)

	entries := logs.FilterMessage("passkey_relying_party_unavailable").All()
	require.Len(t, entries, 1)
	fields := entries[0].ContextMap()
	assert.Equal(t, long[:origin.MaxDNSNameLen], fields["host"])
	assert.Equal(t, "p1", fields["project_id"])
	assert.NotEmpty(t, fields["hint"])
}

// The spec vectors' clientData names https://example.org. A ceremony verifies when
// that is any of the entry's origins, not only the first.
func TestPasskeySignup_HostEntry_VerifiesAgainstALaterOrigin(t *testing.T) {
	t.Parallel()
	svc, repo, rec := newPasskeyVectorSvc(t)
	svc.cfg.PasskeyRelyingPartiesJSON = `[{"host":"auth.example.org","rp_id":"example.org","origins":["https://accounts.example.org","https://example.org"]}]`
	require.NoError(t, svc.cfg.ValidatePasskeyRelyingParties())
	ctx := WithRequestHost(context.Background(), "auth.example.org")

	_, challengeID, err := svc.BeginPasskeySignup(ctx, pkVectorEmail, "My Key")
	require.NoError(t, err)
	otp := passkeySignupOTP(t, rec, pkVectorEmail)
	setFakeChallengeValue(repo, challengeID, pkB64URL(t, pkRegChallengeHex))

	res, err := svc.CompletePasskeySignup(ctx, challengeID, pkRegCredentialJSON(t), pkVectorEmail, otp, "My Key", "1.2.3.4", "ua")
	require.NoError(t, err)
	require.NotNil(t, res.User)
}

// A signature made for one relying party does not verify under another, so a
// spoofed Host gains nothing.
func TestPasskeySignup_HostEntry_RefusesAnotherOrigin(t *testing.T) {
	t.Parallel()
	svc, repo, rec := newPasskeyVectorSvc(t)
	svc.cfg.PasskeyRelyingPartiesJSON = `[{"host":"auth.acme.example","rp_id":"acme.example","origins":["https://acme.example"]}]`
	require.NoError(t, svc.cfg.ValidatePasskeyRelyingParties())
	ctx := WithRequestHost(context.Background(), "auth.acme.example")

	_, challengeID, err := svc.BeginPasskeySignup(ctx, pkVectorEmail, "My Key")
	require.NoError(t, err)
	otp := passkeySignupOTP(t, rec, pkVectorEmail)
	setFakeChallengeValue(repo, challengeID, pkB64URL(t, pkRegChallengeHex))

	_, err = svc.CompletePasskeySignup(ctx, challengeID, pkRegCredentialJSON(t), pkVectorEmail, otp, "My Key", "1.2.3.4", "ua")
	require.Error(t, err)
}

// Once hosts have relying parties a project block must name its own rp_id and
// origin, but rp_name is a display name and still comes from the global setting.
func TestPasskeysFor_PerHost_ProjectBlockInheritsName(t *testing.T) {
	t.Parallel()
	svc, _, _ := newPasskeyVectorSvc(t)
	svc.cfg.PasskeyRPName = "Global Name"
	svc.cfg.PasskeyRelyingPartiesJSON = `[{"host":"auth.acme.example","rp_id":"acme.example","origins":["https://acme.example"]}]`
	require.NoError(t, svc.cfg.ValidatePasskeyRelyingParties())
	ctx := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "widgets",
		Access:    ProjectAccessConfig{Mode: AccessModeOpen},
		Passkey:   ProjectPasskeyConfig{RPID: "widgets.example", Origin: "https://widgets.example"},
	})

	optionsJSON, _, err := svc.BeginPasskeySignup(ctx, pkVectorEmail, "My Key")
	require.NoError(t, err)
	var options struct {
		PublicKey struct {
			RP struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"rp"`
		} `json:"publicKey"`
	}
	require.NoError(t, json.Unmarshal([]byte(optionsJSON), &options))
	assert.Equal(t, "widgets.example", options.PublicKey.RP.ID)
	assert.Equal(t, "Global Name", options.PublicKey.RP.Name)
}
