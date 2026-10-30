package app

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
)

func TestTeammateKeysStayUnbuiltWhileDisabled(t *testing.T) {
	sweep := &sweeper{}
	configureTeammateKeySweep(sweep, Deps{}, nil)
	require.Nil(t, sweep.teammateKeySweep)
	configureTeammateKeySweep(nil, Deps{}, &service.TeammateKeyService{})
}

func TestTeammateKeysRefuseADriverWithoutAControlPlane(t *testing.T) {
	cfg := &config.Config{TeammateKeysEnabled: true, JWTIssuer: "https://auth.example.test", JWTAudience: "https://api.example.test", DefaultProjectID: "project"}
	_, err := buildTeammateKeys(Deps{Config: cfg, Repo: memory.New(), Signer: jwttest.NewSigner(t, "kid")}, nil, zap.NewNop())
	require.ErrorContains(t, err, "teammate keys")
}

func TestTeammateKeySweepNeedsTheirRepository(t *testing.T) {
	err := sweepTeammateKeys(context.Background(), memory.New(), nil, "project", 1, 10)
	require.ErrorIs(t, err, service.ErrServiceUnavailable)
	sweep := &sweeper{repo: memory.New()}
	configureTeammateKeySweep(sweep, Deps{Config: &config.Config{DefaultProjectID: "project"}, Repo: memory.New()}, &service.TeammateKeyService{})
	require.ErrorIs(t, sweep.teammateKeySweep(context.Background(), 1, 10), service.ErrServiceUnavailable)
	require.Equal(t, "teammate_keys", sweep.targets()[len(sweep.targets())-1].name)
}

func TestBuildRateLimits_TeammateKeysLimited(t *testing.T) {
	cfg := &config.Config{RateLimitWindowSeconds: 60, RateLimitDirectoryPerIP: 2, AgentOAuthProtocolPerIP: 3, AgentMachineChallengePerIP: 4, TeammateKeysEnabled: true}
	limits := buildRateLimits(cfg)
	for path, tag := range map[string]string{
		identityconnectgen.TeammateKeyServiceRegisterTeammateKeyProcedure:         "teammate_key_manager",
		identityconnectgen.TeammateKeyServiceRevokeTeammateKeyProcedure:           "teammate_key_manager",
		identityconnectgen.HireGrantServiceCreateHireGrantProcedure:               "hire_grant",
		identityconnectgen.IdentityServiceCreateAgentMachineChallengeProcedure:    "agent_machine_challenge",
		identityconnectgen.IdentityServiceExchangeAgentMachineCredentialProcedure: "agent_oauth_protocol",
	} {
		limit, ok := middleware.MatchPathLimit(limits, path)
		require.True(t, ok, path)
		require.Equal(t, tag, limit.Tag, path)
	}
	handler := middleware.RateLimitMiddleware(limits, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	assertQuotaExhausts(t, handler, identityconnectgen.TeammateKeyServiceRegisterTeammateKeyProcedure, "9.9.9.8", 2)
	assertQuotaExhausts(t, handler, identityconnectgen.HireGrantServiceCreateHireGrantProcedure, "9.9.9.8", 2)
	assertQuotaExhausts(t, handler, identityconnectgen.IdentityServiceCreateAgentMachineChallengeProcedure, "9.9.9.7", 4)
	assertQuotaExhausts(t, handler, identityconnectgen.IdentityServiceExchangeAgentMachineCredentialProcedure, "9.9.9.7", 3)

	cfg.TeammateKeysEnabled = false
	_, ok := middleware.MatchPathLimit(buildRateLimits(cfg), identityconnectgen.TeammateKeyServiceRegisterTeammateKeyProcedure)
	require.False(t, ok)
}
