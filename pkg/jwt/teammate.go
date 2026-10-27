package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jws"
)

// TeammateAccessClaims is the at+jwt access token an agent account receives
// for one claim on one workstation. Its identity fields come from the
// registered teammate key, so a verifier can trust them as it trusts sub.
type TeammateAccessClaims struct {
	Sub           string   `json:"sub"`
	Kind          string   `json:"kind"`
	Issuer        string   `json:"iss"`
	Project       string   `json:"project"`
	Audience      []string `json:"aud"`
	ClaimID       string   `json:"claim_id"`
	WorkstationID string   `json:"workstation_id"`
	CompanyID     string   `json:"company_id"`
	IssuedAt      int64    `json:"iat"`
	ExpiresAt     int64    `json:"exp"`
	JWTID         string   `json:"jti"`
}

// TeammateSigner signs teammate access tokens under the at+jwt profile.
type TeammateSigner interface {
	Signer
	SignTeammateAccessToken(context.Context, TeammateAccessClaims) (string, error)
}

func (c TeammateAccessClaims) Validate() error {
	if c.Sub == "" || c.Kind != "agent" || c.Issuer == "" || c.Project == "" || len(c.Audience) != 1 || c.Audience[0] == "" || c.ClaimID == "" || c.WorkstationID == "" || c.CompanyID == "" || c.JWTID == "" || c.IssuedAt <= 0 || c.ExpiresAt <= c.IssuedAt {
		return errors.New("invalid teammate access-token claims")
	}
	return nil
}

func (c TeammateAccessClaims) ClaimsMap() (map[string]any, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return map[string]any{"sub": c.Sub, "kind": c.Kind, "iss": c.Issuer, "project": c.Project, "aud": c.Audience, "claim_id": c.ClaimID, "workstation_id": c.WorkstationID, "company_id": c.CompanyID, "iat": c.IssuedAt, "exp": c.ExpiresAt, "jti": c.JWTID}, nil
}

// VerifyTeammateAccessToken verifies a teammate access token's signature,
// profile and bindings. It does not tell whether the key was revoked since
// the token was issued; the token's short lifetime bounds that.
func VerifyTeammateAccessToken(token string, kp KeyProvider, issuer, project, audience string) (*TeammateAccessClaims, error) {
	if len(token) > maxDelegatedAccessTokenBytes || strings.Count(token, ".") != 2 || strings.ContainsAny(token, " \t\r\n") {
		return nil, errors.New("teammate access requires a bounded compact JWT")
	}
	if issuer == "" || project == "" || audience == "" {
		return nil, errors.New("teammate verification requires issuer, project and audience")
	}
	profile, err := verifyTokenProfile(token, kp, "", audience, true, DelegatedAccessTokenType)
	if err != nil {
		return nil, err
	}
	if profile.Purpose != "" {
		return nil, errors.New("purpose token is not teammate access")
	}
	msg, err := jws.Parse([]byte(token))
	if err != nil {
		return nil, err
	}
	var claims TeammateAccessClaims
	if err = json.Unmarshal(msg.Payload(), &claims); err != nil {
		return nil, err
	}
	if err = claims.Validate(); err != nil {
		return nil, err
	}
	if claims.Issuer != issuer || claims.Project != project || claims.Audience[0] != audience || claims.IssuedAt > time.Now().Unix() {
		return nil, errors.New("teammate token binding mismatch")
	}
	return &claims, nil
}
