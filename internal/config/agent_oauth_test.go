package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func oauthConfig() *Config {
	sum := sha256.Sum256([]byte("test-only-resource-secret"))
	return &Config{AgentOAuthEnabled: true, AgentsEnabled: true, RevocationMode: RevocationModeSession, JWTIssuer: "https://auth.example.test", AgentOAuthAccessSeconds: DefaultAgentOAuthAccessSeconds, AgentOAuthConsentSeconds: DefaultAgentOAuthConsentSeconds, AgentOAuthRefreshIdleSeconds: DefaultAgentOAuthRefreshIdleSeconds, AgentOAuthResourceCredentialsJSON: fmt.Sprintf(`[{"id":"files","project_id":"project","resource":"https://files.example.test","secret_sha256":"%s"}]`, hex.EncodeToString(sum[:]))}
}

func TestAgentOAuthConfigFailClosed(t *testing.T) {
	require.NoError(t, (&Config{}).ValidateAgentOAuth())
	require.NoError(t, oauthConfig().ValidateAgentOAuth())
	cases := map[string]func(*Config){"agents off": func(c *Config) { c.AgentsEnabled = false }, "ttl revocation": func(c *Config) { c.RevocationMode = RevocationModeTTL }, "missing issuer": func(c *Config) { c.JWTIssuer = "" }, "oversized issuer": func(c *Config) {
		c.JWTIssuer = "https://auth.example.test/" + strings.Repeat("x", maxAgentOAuthIssuerBytes)
	}, "http issuer": func(c *Config) { c.JWTIssuer = "http://auth.example.test" }, "issuer fragment": func(c *Config) { c.JWTIssuer += "#x" }, "issuer query": func(c *Config) { c.JWTIssuer += "?x=1" }, "trailing slash": func(c *Config) { c.JWTIssuer += "/" }, "missing credential": func(c *Config) { c.AgentOAuthResourceCredentialsJSON = "[]" }, "unknown credential field": func(c *Config) { c.AgentOAuthResourceCredentialsJSON = `[{"id":"files","unexpected":true}]` }, "zero access": func(c *Config) { c.AgentOAuthAccessSeconds = 0 }, "long access": func(c *Config) { c.AgentOAuthAccessSeconds = 901 }, "short grant": func(c *Config) { c.AgentOAuthConsentSeconds = 1 }, "long grant": func(c *Config) { c.AgentOAuthConsentSeconds = 31 * 24 * 60 * 60 }, "short idle": func(c *Config) { c.AgentOAuthRefreshIdleSeconds = 1 }, "wide idle": func(c *Config) { c.AgentOAuthRefreshIdleSeconds = c.AgentOAuthConsentSeconds + 1 }, "oversized config": func(c *Config) {
		c.AgentOAuthResourceCredentialsJSON = strings.Repeat("x", maxAgentOAuthCredentialJSONBytes+1)
	}}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) { c := oauthConfig(); mutate(c); require.Error(t, c.ValidateAgentOAuth()) })
	}
}

func TestAgentOAuthCredentialValidation(t *testing.T) {
	c := oauthConfig()
	credentials, err := c.AgentOAuthCredentials()
	require.NoError(t, err)
	require.Len(t, credentials, 1)
	original := c.AgentOAuthResourceCredentialsJSON
	for _, bad := range []string{strings.ReplaceAll(original, "https://files.example.test", "http://files.example.test"), strings.ReplaceAll(original, "https://files.example.test", "https://files.example.test/#bad"), strings.ReplaceAll(original, "project_id", "unknown"), strings.ReplaceAll(original, credentials[0].SecretSHA256, "plaintext"), original[:len(original)-1] + "," + original[1:]} {
		c.AgentOAuthResourceCredentialsJSON = bad
		_, err = c.AgentOAuthCredentials()
		require.Error(t, err)
	}
}

func TestAgentOAuthIssuerIsOriginOnly(t *testing.T) {
	for name, suffix := range map[string]string{
		"path prefix":    "/identity",
		"encoded path":   "/%69dentity",
		"encoded slash":  "/%2Fidentity",
		"empty query":    "?",
		"empty fragment": "#",
	} {
		t.Run(name, func(t *testing.T) {
			c := oauthConfig()
			c.JWTIssuer += suffix
			require.ErrorContains(t, c.ValidateAgentOAuth(), "HTTPS origin")
		})
	}
	t.Run("origin", func(t *testing.T) {
		require.NoError(t, oauthConfig().ValidateAgentOAuth())
	})
	t.Run("ordinary human issuer unchanged", func(t *testing.T) {
		c := oauthConfig()
		c.AgentOAuthEnabled = false
		c.JWTIssuer += "/identity"
		require.NoError(t, c.ValidateAgentOAuth())
	})
}
