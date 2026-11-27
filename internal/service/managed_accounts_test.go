package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/graph"
)

// Managed accounts are a per-project opt-in: both keys default off, the
// self-service extension needs the first, and either is valid with every
// access mode.
func TestParseProjectConfig_AdmitManagedAccounts(t *testing.T) {
	off, err := ParseProjectConfig(`{"access":{"mode":"invite"}}`)
	require.NoError(t, err)
	assert.False(t, off.Access.AdmitManagedAccounts, "off by default")
	assert.False(t, off.Access.AdmitManagedAccountsSelfService, "off by default")

	_, err = ParseProjectConfig(`{"access":{"mode":"invite","admit_managed_accounts_self_service":true}}`)
	require.ErrorContains(t, err, "admit_managed_accounts_self_service is only valid with admit_managed_accounts")

	for _, mode := range []string{AccessModeOpen, AccessModeClosed, AccessModeInvite, ""} {
		cfg, err := ParseProjectConfig(`{"access":{"mode":"` + mode + `","admit_managed_accounts":true,"admit_managed_accounts_self_service":true}}`)
		require.NoError(t, err, mode)
		assert.True(t, cfg.Access.AdmitManagedAccounts, mode)
		assert.True(t, cfg.Access.AdmitManagedAccountsSelfService, mode)
	}
}

// The graph read path carries a managed account's columns, and reads a
// node without them as a personal account.
func TestUserFromNode_ManagedAccount(t *testing.T) {
	setUp := time.Now().UnixMilli()
	u := userFromNode(&graph.Node{NodeID: "u", Payload: map[string]any{
		ufEmail: "ann@acme.example.com", ufManagedByTenantID: "tenant-acme", ufSetUpAt: setUp, ufSetupEpoch: int64(2),
	}})
	assert.Equal(t, "tenant-acme", u.ManagedByTenantID)
	assert.Equal(t, setUp, u.SetUpAtMs)
	assert.Equal(t, int64(2), u.SetupEpoch)

	personal := userFromNode(&graph.Node{NodeID: "p", Payload: map[string]any{ufEmail: "p@example.com"}})
	assert.Empty(t, personal.ManagedByTenantID)
	assert.Zero(t, personal.SetUpAtMs)
	assert.Zero(t, personal.SetupEpoch)
}

func TestTenantInvitation_IsManagedSetup(t *testing.T) {
	assert.False(t, (&TenantInvitation{Email: "a@example.com"}).IsManagedSetup())
	assert.True(t, (&TenantInvitation{Email: "a@example.com", UserID: "u"}).IsManagedSetup())
}
