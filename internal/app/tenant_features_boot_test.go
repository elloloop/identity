package app

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
)

// governanceDeps is a build with every tenant store, as the postgres driver
// wires it.
func governanceDeps(cfg *config.Config) Deps {
	return Deps{
		Config:          cfg,
		InvitationStore: &stubInvitationStore{},
		MembershipStore: &stubMembershipStore{},
		TenantStore:     &stubTenantStore{},
	}
}

// A host that injects its own repository passes Config.Validate with no
// driver named, so New itself refuses a tenant switch it has no store for,
// rather than booting a feature that answers UNIMPLEMENTED or accepts no
// selected tenant. The same build boots with the switch off.
func TestNew_RefusesTenantSwitchesWithoutTheirStores(t *testing.T) {
	injectedRepo := func(t *testing.T, cfg *config.Config) Deps {
		t.Helper()
		pk, err := passkeys.NewWebAuthnService(passkeys.Config{RPID: "localhost", RPName: "Identity test", Origin: "http://localhost:9002"})
		require.NoError(t, err)
		repo := memory.New()
		return Deps{
			Config: cfg, Logger: zap.NewNop(), Signer: jwttest.NewSigner(t, "tenant-features-test"),
			Repo: repo, DB: repo, Passkeys: pk,
			TOTPKey:            []byte("01234567890123456789012345678901"),
			TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		}
	}
	built, err := New(injectedRepo(t, newTestConfig()))
	require.NoError(t, err, "the injected build boots with both switches off")
	built.Stop()

	for name, on := range map[string]func(*config.Config){
		"GATEWAY_TENANT_SELECTION_ENABLED":     func(c *config.Config) { c.TenantSelectionEnabled = true },
		"GATEWAY_SELF_SERVICE_TENANTS_ENABLED": func(c *config.Config) { c.SelfServiceTenantsEnabled = true },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := newTestConfig()
			on(cfg)
			_, err := New(injectedRepo(t, cfg))
			require.Error(t, err)
			assert.Contains(t, err.Error(), name)
		})
	}
}

func TestCheckTenantFeatures_EachStoreIsRequired(t *testing.T) {
	cfg := &config.Config{TenantSelectionEnabled: true, SelfServiceTenantsEnabled: true}
	require.NoError(t, checkTenantFeatures(governanceDeps(cfg), zap.NewNop()))
	for name, drop := range map[string]func(*Deps){
		"no invitation store": func(d *Deps) { d.InvitationStore = nil },
		"no membership store": func(d *Deps) { d.MembershipStore = nil },
		"no tenant store":     func(d *Deps) { d.TenantStore = nil },
	} {
		d := governanceDeps(cfg)
		drop(&d)
		assert.Error(t, checkTenantFeatures(d, zap.NewNop()), name)
	}
}

// The boot log says whether each tenant feature is served and, when it is,
// under which TTL and limits, so an operator can confirm the effective values
// without reading the environment.
func TestCheckTenantFeatures_LogsBootState(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		cfg := &config.Config{
			TenantSelectionEnabled: true, TenantStatusCacheTTLSeconds: 45,
			SelfServiceTenantsEnabled: true, SelfServiceTenantsMaxPerUser: 4, SelfServiceTenantsWindowSeconds: 600,
		}
		require.NoError(t, checkTenantFeatures(governanceDeps(cfg), zap.New(core)))

		selection := logs.FilterMessage("tenant_selection_enabled").All()
		require.Len(t, selection, 1)
		assert.Equal(t, 45*time.Second, selection[0].ContextMap()["status_cache_ttl"])
		selfService := logs.FilterMessage("self_service_tenants_enabled").All()
		require.Len(t, selfService, 1)
		assert.Equal(t, int64(4), selfService[0].ContextMap()["max_per_user"])
		assert.Equal(t, 10*time.Minute, selfService[0].ContextMap()["window"])
		assert.Zero(t, logs.FilterMessage("tenant_selection_disabled").Len())
		assert.Zero(t, logs.FilterMessage("self_service_tenants_disabled").Len())
	})

	t.Run("disabled", func(t *testing.T) {
		for name, deps := range map[string]Deps{
			"postgres": governanceDeps(&config.Config{}),
			"memory":   {Config: &config.Config{}},
		} {
			core, logs := observer.New(zapcore.InfoLevel)
			require.NoError(t, checkTenantFeatures(deps, zap.New(core)))
			assert.Equal(t, 1, logs.FilterMessage("tenant_selection_disabled").Len(), name)
			selfService := logs.FilterMessage("self_service_tenants_disabled").All()
			require.Len(t, selfService, 1, name)
			assert.Equal(t, name == "postgres", selfService[0].ContextMap()["other_projects_may_enable"],
				"%s: another project can turn self-service on only where CreateTenant is served", name)
			assert.Zero(t, logs.FilterMessage("tenant_selection_enabled").Len(), name)
			assert.Zero(t, logs.FilterMessage("self_service_tenants_enabled").Len(), name)
		}
	})
}
