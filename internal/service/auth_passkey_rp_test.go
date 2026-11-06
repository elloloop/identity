package service

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// Every ceremony refuses an unlisted host, including one that began on a listed
// host and completes on another.
func TestPasskeyCeremonies_UnlistedHost_AllRefused(t *testing.T) {
	t.Parallel()
	svc := svcWithRelyingParties(t)
	ctx := WithRequestHost(context.Background(), "auth.other.example")

	_, _, err := svc.BeginPasskeyRegistration(ctx, "user-1", "")
	require.Error(t, err)
	_, _, err = svc.BeginPasskeyLogin(ctx, "")
	require.ErrorIs(t, err, ErrPasskeysUnavailable)
	_, err = svc.CompletePasskeyLogin(ctx, "challenge", "{}", "", "")
	require.ErrorIs(t, err, ErrPasskeysUnavailable)
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
