package jwttest

import (
	"context"
	"testing"
	"time"

	"github.com/elloloop/identity/pkg/jwt"
)

// AssertTeammateProfile applies the teammate token-profile contract to each
// signer backend.
func AssertTeammateProfile(t *testing.T, signer jwt.TeammateSigner) {
	t.Helper()
	now := time.Now().Unix()
	claims := jwt.TeammateAccessClaims{Sub: "agent", Kind: "agent", Issuer: "https://auth.example.test", Project: "project", Audience: []string{"https://api.example.test"}, ClaimID: "claim", WorkstationID: "workstation", CompanyID: "company", IssuedAt: now, ExpiresAt: now + 300, JWTID: "token-id"}
	token, err := signer.SignTeammateAccessToken(context.Background(), claims)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := jwt.VerifyTeammateAccessToken(token, signer, claims.Issuer, claims.Project, claims.Audience[0])
	if err != nil || actual == nil || actual.Sub != claims.Sub || actual.ClaimID != claims.ClaimID || actual.WorkstationID != claims.WorkstationID || actual.CompanyID != claims.CompanyID {
		t.Fatalf("teammate profile roundtrip: claims=%+v err=%v", actual, err)
	}
	if _, err = jwt.VerifyAccessToken(token, signer, "", "", false); err == nil {
		t.Fatal("teammate token accepted as human access")
	}
	if _, err = jwt.VerifyDelegatedAccessToken(token, signer, claims.Issuer, claims.Project, claims.Audience[0]); err == nil {
		t.Fatal("teammate token accepted as delegated access")
	}
	claims.CompanyID = ""
	if _, err = signer.SignTeammateAccessToken(context.Background(), claims); err == nil {
		t.Fatal("incomplete profile signed")
	}
}
