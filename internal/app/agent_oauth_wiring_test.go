package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/elloloop/identity/internal/config"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestAgentOAuthRequestBoundsRemainFeatureScoped(t *testing.T) {
	for _, c := range []struct {
		name    string
		enabled bool
		path    string
		want    int
	}{
		{"enabled protocol refuses malformed transport", true, agentOAuthTokenPath, http.StatusBadRequest},
		{"disabled protocol does not change surrounding handler", false, agentOAuthTokenPath, http.StatusNoContent},
		{"enabled unrelated handler remains unchanged", true, "/existing", http.StatusNoContent},
	} {
		t.Run(c.name, func(t *testing.T) {
			reached := false
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached = true; w.WriteHeader(http.StatusNoContent) })
			h := agentOAuthRequestBounds(&config.Config{AgentOAuthEnabled: c.enabled}, next)
			r := httptest.NewRequest(http.MethodPost, c.path, strings.NewReader("{}"))
			r.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			h.ServeHTTP(response, r)
			require.Equal(t, c.want, response.Code)
			require.Equal(t, c.want == http.StatusNoContent, reached)
		})
	}
}

func TestAgentOAuthDisabledWiringDoesNotMountProtocol(t *testing.T) {
	f := newAgentOAuthHTTPFixture(t)
	cfg := *f.cfg
	cfg.AgentOAuthEnabled = false
	built, err := New(Deps{
		Config: &cfg, Logger: zap.NewNop(), Repo: f.repo, Signer: f.signer,
		TOTPKey: []byte("01234567890123456789012345678901"), TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
	})
	require.NoError(t, err)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, agentOAuthMetadataPath},
		{http.MethodPost, agentOAuthTokenPath},
	} {
		r := httptest.NewRequest(c.method, c.path, strings.NewReader("{}"))
		r.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		built.Handler.ServeHTTP(response, r)
		require.Equal(t, http.StatusNotFound, response.Code)
	}
}
