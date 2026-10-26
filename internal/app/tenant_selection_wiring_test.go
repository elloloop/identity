package app

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
)

// countingTenantStore answers every tenant as claimed and counts the reads.
type countingTenantStore struct {
	service.TenantStore
	reads int
}

func (s *countingTenantStore) GetTenantStatus(context.Context, string, string) (string, error) {
	s.reads++
	return service.TenantStatusClaimed, nil
}

// Selection is off unless GATEWAY_TENANT_SELECTION_ENABLED is on and the
// driver has the governance stores; off, RefreshToken gets a nil interface
// (never a typed nil) and the token check accepts only the default tenant.
func TestTenantSelectionWiring_OffByDefault(t *testing.T) {
	for name, deps := range map[string]Deps{
		"switch off": {
			Config:          &config.Config{DefaultTenantID: "default"},
			MembershipStore: &stubMembershipStore{},
			TenantStore:     &countingTenantStore{},
		},
		"no stores": {Config: &config.Config{DefaultTenantID: "default", TenantSelectionEnabled: true}},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Nil(t, tenantSelectionReader(deps))
			tenants, err := tokenTenants(deps, zap.NewNop())
			require.NoError(t, err)
			assert.Equal(t, "default", tenants.Default)
			assert.Nil(t, tenants.Selectable)
		})
	}
}

// On, RefreshToken reads the membership store and the token check reads the
// tenant store through the cache: once per TTL, or on every request at TTL 0.
func TestTenantSelectionWiring_On(t *testing.T) {
	members := &stubMembershipStore{}
	for ttl, wantReads := range map[int]int{30: 1, 0: 3} {
		store := &countingTenantStore{}
		reg := prometheus.NewRegistry()
		deps := Deps{
			Config: &config.Config{
				DefaultTenantID: "default", TenantSelectionEnabled: true, TenantStatusCacheTTLSeconds: ttl,
			},
			MembershipStore: members, TenantStore: store, MetricsRegistry: reg,
		}
		assert.Same(t, members, tenantSelectionReader(deps))

		tenants, err := tokenTenants(deps, zap.NewNop())
		require.NoError(t, err)
		require.NotNil(t, tenants.Selectable)
		for range 3 {
			status, err := tenants.Selectable.GetTenantStatus(context.Background(), "proj", "t-acme")
			require.NoError(t, err)
			assert.Equal(t, service.TenantStatusClaimed, status)
		}
		assert.Equal(t, wantReads, store.reads, "TTL %ds", ttl)

		families, err := reg.Gather()
		require.NoError(t, err)
		var names []string
		for _, f := range families {
			names = append(names, f.GetName())
		}
		assert.Contains(t, names, "identity_token_tenant_lookup_duration_seconds")

		_, err = tokenTenants(deps, zap.NewNop())
		require.Error(t, err, "a second registration on one registry is refused, not ignored")
	}
}
