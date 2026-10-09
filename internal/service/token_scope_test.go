package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/jwt"
)

// Every project signs with the deployment's keys, so under
// GATEWAY_JWT_PROJECT_AUDIENCE a session token names its project as an
// audience beside the configured one, and a verifier that serves one project
// can refuse another project's token with a plain aud check.
func TestIssueTokens_ProjectAudienceAndIssuer(t *testing.T) {
	cases := []struct {
		name         string
		audience     string
		wantAudience []string
		perProject   bool
	}{
		{"default: no aud, no iss change", "", nil, false},
		{"configured audience only", "https://api.example.org", []string{"https://api.example.org"}, false},
		{"project audience beside the configured one", "https://api.example.org", []string{"https://api.example.org", "proj-a"}, true},
		{"project audience alone", "", []string{"proj-a"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := newFakeRepo()
			svc := newTestAuthService(t, repo)
			svc.cfg.JWTAudience = tc.audience
			svc.cfg.JWTProjectAudience = tc.perProject
			svc.cfg.JWTIssuer = "https://auth.example.org"
			user := seedUser(repo, "alice@acme.com", "", "active")

			access, _, err := svc.issueTokens(withProject("proj-a"), user, "", "")
			require.NoError(t, err)
			claims, err := jwt.VerifyAccessToken(access, svc.signer, "", "", false)
			require.NoError(t, err)
			assert.Equal(t, tc.wantAudience, claims.Audience)
			assert.Equal(t, "https://auth.example.org", claims.Issuer)
		})
	}
}

// A verifier pinned to one project's audience refuses another project's
// token: the cross-project reuse the per-project audience exists to stop.
func TestIssueTokens_ProjectAudienceRefusedByAnotherProject(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.JWTProjectAudience = true
	user := seedUser(repo, "alice@acme.com", "", "active")

	access, _, err := svc.issueTokens(withProject("proj-a"), user, "", "")
	require.NoError(t, err)
	_, err = jwt.VerifyAccessToken(access, svc.signer, "", "proj-b", true)
	require.Error(t, err)
	_, err = jwt.VerifyAccessToken(access, svc.signer, "", "proj-a", true)
	require.NoError(t, err)
}
