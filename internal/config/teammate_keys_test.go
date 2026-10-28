package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTeammateKeysValidation(t *testing.T) {
	require.NoError(t, (&Config{}).ValidateTeammateKeys())
	require.Error(t, (&Config{TeammateKeysEnabled: true, JWTIssuer: "https://auth.example.test"}).ValidateTeammateKeys())
	require.Error(t, (&Config{TeammateKeysEnabled: true, JWTAudience: "https://api.example.test"}).ValidateTeammateKeys())
	c := &Config{TeammateKeysEnabled: true, JWTIssuer: "https://auth.example.test", JWTAudience: "https://api.example.test"}
	require.NoError(t, c.ValidateTeammateKeys())
	require.Equal(t, DefaultAgentOAuthProtocolPerIP, c.AgentOAuthProtocolPerIP)
	c.AgentOAuthProtocolPerIP = -1
	require.Error(t, c.ValidateTeammateKeys())
	require.Error(t, c.Validate())
}
