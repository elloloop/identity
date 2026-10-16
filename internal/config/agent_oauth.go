package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"
	"unicode"
)

const (
	DefaultAgentOAuthProtocolPerIP      = 30
	DefaultAgentOAuthIntrospectionPerIP = 1200
	DefaultAgentOAuthAccessSeconds      = 300
	DefaultAgentOAuthConsentSeconds     = 86400
	DefaultAgentOAuthRefreshIdleSeconds = 3600
	AgentOAuthRequestLifetime           = 5 * time.Minute
	AgentOAuthCodeLifetime              = time.Minute
	AgentOAuthRecentSignIn              = 5 * time.Minute
	maxAgentOAuthCredentialIDBytes      = 128
	maxAgentOAuthIssuerBytes            = 2048
	maxAgentOAuthAccessSeconds          = 900
	maxAgentOAuthConsentDuration        = 30 * 24 * time.Hour
	maxAgentOAuthResources              = 64
	maxAgentOAuthCredentialJSONBytes    = 65536
)

type AgentOAuthResourceCredential struct {
	ID           string `json:"id"`
	ProjectID    string `json:"project_id"`
	Resource     string `json:"resource"`
	SecretSHA256 string `json:"secret_sha256"`
}

func (c *Config) AgentOAuthCredentials() ([]AgentOAuthResourceCredential, error) {
	if len(c.AgentOAuthResourceCredentialsJSON) > maxAgentOAuthCredentialJSONBytes {
		return nil, errors.New("config: delegated resource credentials exceed size limit")
	}
	decoder := json.NewDecoder(strings.NewReader(c.AgentOAuthResourceCredentialsJSON))
	decoder.DisallowUnknownFields()
	var credentials []AgentOAuthResourceCredential
	if err := decoder.Decode(&credentials); err != nil {
		return nil, errors.New("config: invalid delegated resource credential JSON")
	}
	if len(credentials) == 0 || len(credentials) > maxAgentOAuthResources {
		return nil, errors.New("config: configure between 1 and 64 delegated resource credentials")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("config: trailing delegated resource credential data")
	}
	seen := map[string]bool{}
	for _, credential := range credentials {
		key := credential.ProjectID + "\x00" + credential.ID
		secret, err := hex.DecodeString(credential.SecretSHA256)
		resource, uriErr := url.Parse(credential.Resource)
		if credential.ID == "" || len(credential.ID) > maxAgentOAuthCredentialIDBytes || strings.ContainsAny(credential.ID, " :\t\n\r") || strings.ContainsFunc(credential.ID, unicode.IsControl) || credential.ProjectID == "" || len(credential.ProjectID) > maxAgentOAuthCredentialIDBytes || seen[key] || err != nil || len(secret) != sha256.Size || credential.SecretSHA256 != strings.ToLower(credential.SecretSHA256) || uriErr != nil || resource.Fragment != "" || (resource.Scheme != "https" && resource.Scheme != "urn") || resource.User != nil || (resource.Scheme == "https" && resource.Hostname() == "") || (resource.Scheme == "urn" && resource.Opaque == "") {
			return nil, errors.New("config: invalid or duplicate delegated resource credential")
		}
		seen[key] = true
	}
	return credentials, nil
}

func (c *Config) ValidateAgentOAuth() error {
	if !c.AgentOAuthEnabled {
		return nil
	}
	if c.AgentOAuthProtocolPerIP == 0 {
		c.AgentOAuthProtocolPerIP = DefaultAgentOAuthProtocolPerIP
	}
	if c.AgentOAuthIntrospectionPerIP == 0 {
		c.AgentOAuthIntrospectionPerIP = DefaultAgentOAuthIntrospectionPerIP
	}
	if c.AgentOAuthProtocolPerIP < 0 || c.AgentOAuthIntrospectionPerIP < 0 {
		return errors.New("config: delegated OAuth rate limits cannot be disabled")
	}
	if !c.AgentsEnabled || c.RevocationMode != RevocationModeSession {
		return errors.New("config: GATEWAY_AGENT_OAUTH_ENABLED requires agents and session revocation")
	}
	issuer, err := url.Parse(c.JWTIssuer)
	if err != nil || len(c.JWTIssuer) > maxAgentOAuthIssuerBytes || issuer.Scheme != "https" || issuer.Hostname() == "" || issuer.User != nil || issuer.Path != "" || issuer.RawPath != "" || issuer.Opaque != "" || issuer.RawQuery != "" || issuer.ForceQuery || strings.Contains(c.JWTIssuer, "#") {
		return errors.New("config: delegated OAuth requires GATEWAY_JWT_ISSUER to be an HTTPS origin without path, query, fragment or trailing slash")
	}
	if c.AgentOAuthAccessSeconds < 1 || c.AgentOAuthAccessSeconds > maxAgentOAuthAccessSeconds || c.AgentOAuthConsentSeconds < c.AgentOAuthAccessSeconds || c.AgentOAuthConsentSeconds > int(maxAgentOAuthConsentDuration.Seconds()) || c.AgentOAuthRefreshIdleSeconds < c.AgentOAuthAccessSeconds || c.AgentOAuthRefreshIdleSeconds > c.AgentOAuthConsentSeconds {
		return errors.New("config: invalid delegated access, consent or refresh lifetime")
	}
	_, err = c.AgentOAuthCredentials()
	return err
}
