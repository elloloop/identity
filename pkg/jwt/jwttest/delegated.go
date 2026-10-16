package jwttest

import (
	"context"
	"testing"
	"time"

	"github.com/elloloop/identity/pkg/jwt"
)

// AssertDelegatedProfile applies the same token-profile contract to each signer
// backend without requiring a cloud account or credentials.
func AssertDelegatedProfile(t *testing.T, signer jwt.DelegatedSigner) {
	t.Helper()
	now := time.Now().Unix()
	claims := jwt.DelegatedAccessClaims{Sub: "agent", Kind: "agent", Actor: jwt.DelegatedActor{Sub: "owner"}, Issuer: "https://auth.example.test", Project: "project", Audience: []string{"https://files.example.test"}, ClientID: "native", Scope: "files:read", GrantID: "grant", SID: "session", IssuedAt: now, ExpiresAt: now + 60, JWTID: "token-id"}
	token, err := signer.SignDelegatedAccessToken(context.Background(), claims)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := jwt.VerifyDelegatedAccessToken(token, signer, claims.Issuer, claims.Project, claims.Audience[0])
	if err != nil || actual == nil || actual.Sub != claims.Sub || actual.Actor != claims.Actor {
		t.Fatalf("delegated profile roundtrip: claims=%+v err=%v", actual, err)
	}
	if _, err = jwt.VerifyAccessToken(token, signer, "", "", false); err == nil {
		t.Fatal("delegated token accepted as human access")
	}
	if _, err = jwt.VerifyPurposeToken(token, signer, "", "", false, "login"); err == nil {
		t.Fatal("delegated token accepted as purpose token")
	}
	claims.ExpiresAt = now - 1
	claims.IssuedAt = now - 60
	token, err = signer.SignDelegatedAccessToken(context.Background(), claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = jwt.VerifyDelegatedAccessToken(token, signer, claims.Issuer, claims.Project, claims.Audience[0]); err == nil {
		t.Fatal("expired delegated token accepted")
	}
	claims.Sub = ""
	if _, err = signer.SignDelegatedAccessToken(context.Background(), claims); err == nil {
		t.Fatal("incomplete profile signed")
	}
}
