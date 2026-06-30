package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasskeysFor_NoScope_ReturnsGlobal(t *testing.T) {
	t.Parallel()
	svc, _ := newAuthSvcWithMailerForRepo(t, newFakeRepo())

	got := svc.passkeysFor(context.Background())
	assert.Same(t, svc.passkeys, got)
}

func TestPasskeysFor_NoPasskeyOverride_ReturnsGlobal(t *testing.T) {
	t.Parallel()
	svc, _ := newAuthSvcWithMailerForRepo(t, newFakeRepo())

	ctx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "p1"})
	got := svc.passkeysFor(ctx)
	assert.Same(t, svc.passkeys, got)
}

func TestPasskeysFor_ProjectOverride_ReturnsDistinctCachedInstance(t *testing.T) {
	t.Parallel()
	svc, _ := newAuthSvcWithMailerForRepo(t, newFakeRepo())

	kidsCtx := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "kids",
		Passkey: ProjectPasskeyConfig{
			RPID:   "kids.example.com",
			RPName: "Glassa Kids",
			Origin: "https://kids.example.com",
		},
	})
	prosCtx := WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "pros",
		Passkey: ProjectPasskeyConfig{
			RPID:   "pros.example.com",
			RPName: "Glassa Pros",
			Origin: "https://pros.example.com",
		},
	})

	kids := svc.passkeysFor(kidsCtx)
	pros := svc.passkeysFor(prosCtx)

	require.NotNil(t, kids)
	require.NotNil(t, pros)
	// Each product gets its own RP-bound instance, distinct from the global
	// and from each other.
	assert.NotSame(t, svc.passkeys, kids)
	assert.NotSame(t, svc.passkeys, pros)
	assert.NotSame(t, kids, pros)

	// A second resolution of the same project reuses the cached instance.
	assert.Same(t, kids, svc.passkeysFor(kidsCtx))
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
	got := svc.passkeysFor(ctx)
	assert.Same(t, svc.passkeys, got)
}
