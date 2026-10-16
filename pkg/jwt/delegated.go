package jwt

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jws"
)

const (
	DelegatedAccessTokenType     = "at+jwt"
	maxDelegatedAccessTokenBytes = 32768
)

type (
	DelegatedActor struct {
		Sub string `json:"sub"`
	}
	DelegatedAccessClaims struct {
		Sub       string         `json:"sub"`
		Kind      string         `json:"kind"`
		Actor     DelegatedActor `json:"act"`
		Issuer    string         `json:"iss"`
		Project   string         `json:"project"`
		Audience  []string       `json:"aud"`
		ClientID  string         `json:"client_id"`
		Scope     string         `json:"scope"`
		GrantID   string         `json:"grant_id"`
		SID       string         `json:"sid"`
		IssuedAt  int64          `json:"iat"`
		ExpiresAt int64          `json:"exp"`
		JWTID     string         `json:"jti"`
		IsMinor   bool           `json:"is_minor,omitempty"`
	}
)

func (c DelegatedAccessClaims) Validate() error {
	if c.Sub == "" || c.Kind != "agent" || c.Actor.Sub == "" || c.Actor.Sub == c.Sub || c.Issuer == "" || c.Project == "" || len(c.Audience) != 1 || c.Audience[0] == "" || c.ClientID == "" || c.Scope == "" || c.GrantID == "" || c.SID == "" || c.JWTID == "" || c.IssuedAt <= 0 || c.ExpiresAt <= c.IssuedAt {
		return errors.New("invalid delegated access-token claims")
	}
	return nil
}

func (c DelegatedAccessClaims) ClaimsMap() (map[string]any, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return map[string]any{"sub": c.Sub, "kind": c.Kind, "act": c.Actor, "iss": c.Issuer, "project": c.Project, "aud": c.Audience, "client_id": c.ClientID, "scope": c.Scope, "grant_id": c.GrantID, "sid": c.SID, "iat": c.IssuedAt, "exp": c.ExpiresAt, "jti": c.JWTID, "is_minor": c.IsMinor}, nil
}

func tokenType(token []byte) (string, error) {
	msg, err := jws.Parse(token)
	if err != nil {
		return "", err
	}
	if len(msg.Signatures()) != 1 {
		return "", errors.New("exactly one signature required")
	}
	return msg.Signatures()[0].ProtectedHeaders().Type(), nil
}

// VerifyDelegatedAccessToken verifies only the OAuth access-token profile. A
// resource must additionally authenticate to current introspection on every
// request; signature validation alone cannot establish current delegation.
func VerifyDelegatedAccessToken(token string, kp KeyProvider, issuer, project, resource string) (*DelegatedAccessClaims, error) {
	if len(token) > maxDelegatedAccessTokenBytes || strings.Count(token, ".") != 2 || strings.ContainsAny(token, " \t\r\n") {
		return nil, errors.New("delegated access requires a bounded compact JWT")
	}
	if issuer == "" || project == "" || resource == "" {
		return nil, errors.New("delegated verification requires issuer, project and resource")
	}
	profile, err := verifyTokenProfile(token, kp, "", resource, true, DelegatedAccessTokenType)
	if err != nil {
		return nil, err
	}
	if profile.Purpose != "" {
		return nil, errors.New("purpose token is not delegated access")
	}
	msg, err := jws.Parse([]byte(token))
	if err != nil {
		return nil, err
	}
	var age struct {
		IsMinor *bool `json:"is_minor"`
	}
	if err = json.Unmarshal(msg.Payload(), &age); err != nil || age.IsMinor == nil {
		return nil, errors.New("delegated access requires explicit owner age standing")
	}
	var claims DelegatedAccessClaims
	if err = json.Unmarshal(msg.Payload(), &claims); err != nil {
		return nil, err
	}
	if err = claims.Validate(); err != nil {
		return nil, err
	}
	if claims.Issuer != issuer || claims.Project != project || claims.Audience[0] != resource || claims.IssuedAt > time.Now().Unix() {
		return nil, errors.New("delegated token binding mismatch")
	}
	return &claims, nil
}
