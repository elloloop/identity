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

	// An empty origin makes NewWebAuthnService fail; we fall back to the
	// global instance rather than break the ceremony. (The write path
	// rejects such configs, so this is a defensive fallback.)
	ctx := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "broken",
		Passkey:   ProjectPasskeyConfig{RPID: "kids.example.com", Origin: ""},
	})
	// RPID set but origin falls back to the global origin, which is valid, so
	// this actually builds. Use a config that cannot build: blank RP-ID after
	// fallback is impossible, so instead clear the global to force failure.
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
