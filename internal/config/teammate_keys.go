package config

import "errors"

// TeammateAccessSeconds is the lifetime of a teammate access token.
const TeammateAccessSeconds = 300

func (c *Config) ValidateTeammateKeys() error {
	if !c.TeammateKeysEnabled {
		return nil
	}
	if c.JWTIssuer == "" || c.JWTAudience == "" {
		return errors.New("config: GATEWAY_TEAMMATE_KEYS_ENABLED needs GATEWAY_JWT_ISSUER and GATEWAY_JWT_AUDIENCE, the issuer and audience of every teammate token")
	}
	if c.AgentOAuthProtocolPerIP == 0 {
		c.AgentOAuthProtocolPerIP = DefaultAgentOAuthProtocolPerIP
	}
	if c.AgentOAuthProtocolPerIP < 0 {
		return errors.New("config: GATEWAY_TEAMMATE_KEYS_ENABLED cannot disable GATEWAY_AGENT_OAUTH_PROTOCOL_PER_IP")
	}
	return nil
}
