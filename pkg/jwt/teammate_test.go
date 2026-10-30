package jwt

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func teammateClaims() TeammateAccessClaims {
	now := time.Now().Unix()
	return TeammateAccessClaims{Sub: "agent", Kind: "agent", Actor: DelegatedActor{Sub: "lead"}, Issuer: "https://auth.example.test", Project: "project", Audience: []string{"https://api.example.test"}, ClaimID: "claim", WorkstationID: "workstation", CompanyID: "company", IssuedAt: now, ExpiresAt: now + 300, JWTID: "jti"}
}

func TestTeammateTokenProfileAndBindings(t *testing.T) {
	signer := newMemSigner(t, "teammate-key")
	c := teammateClaims()
	raw, err := signer.SignTeammateAccessToken(context.Background(), c)
	require.NoError(t, err)
	typ, err := tokenType([]byte(raw))
	require.NoError(t, err)
	require.Equal(t, DelegatedAccessTokenType, typ)
	actual, err := VerifyTeammateAccessToken(raw, signer, c.Issuer, c.Project, c.Audience[0])
	require.NoError(t, err)
	require.Equal(t, c, *actual)
	_, err = VerifyAccessToken(raw, signer, "", "", false)
	require.Error(t, err)
	_, err = VerifyDelegatedAccessToken(raw, signer, c.Issuer, c.Project, c.Audience[0])
	require.Error(t, err)
	for _, bound := range [][3]string{{"", c.Project, c.Audience[0]}, {"https://other.example.test", c.Project, c.Audience[0]}, {c.Issuer, "other", c.Audience[0]}, {c.Issuer, c.Project, "https://other.example.test"}} {
		_, err = VerifyTeammateAccessToken(raw, signer, bound[0], bound[1], bound[2])
		require.Error(t, err)
	}
	delegated, err := signer.SignDelegatedAccessToken(context.Background(), DelegatedAccessClaims{Sub: "agent", Kind: "agent", Actor: DelegatedActor{Sub: "human"}, Issuer: c.Issuer, Project: c.Project, Audience: c.Audience, ClientID: "desktop", Scope: "files:read", GrantID: "grant", SID: "sid", IssuedAt: c.IssuedAt, ExpiresAt: c.ExpiresAt, JWTID: "jti"})
	require.NoError(t, err)
	_, err = VerifyTeammateAccessToken(delegated, signer, c.Issuer, c.Project, c.Audience[0])
	require.Error(t, err)
	human, err := signer.SignAccessToken(context.Background(), Claims{Sub: "human", Audience: c.Audience}, time.Minute)
	require.NoError(t, err)
	_, err = VerifyTeammateAccessToken(human, signer, c.Issuer, c.Project, c.Audience[0])
	require.Error(t, err)
	split := strings.Split(raw, ".")
	split[2] = "AAAA"
	_, err = VerifyTeammateAccessToken(strings.Join(split, "."), signer, c.Issuer, c.Project, c.Audience[0])
	require.Error(t, err)
}

func TestTeammateClaimsRejectIncompletePrincipals(t *testing.T) {
	c := teammateClaims()
	m, err := c.ClaimsMap()
	require.NoError(t, err)
	require.Equal(t, DelegatedActor{Sub: "lead"}, m["act"])
	require.NotContains(t, m, "scope")
	for _, mutate := range []func(*TeammateAccessClaims){func(c *TeammateAccessClaims) { c.Sub = "" }, func(c *TeammateAccessClaims) { c.Actor.Sub = "" }, func(c *TeammateAccessClaims) { c.Actor.Sub = c.Sub }, func(c *TeammateAccessClaims) { c.Kind = "person" }, func(c *TeammateAccessClaims) { c.Issuer = "" }, func(c *TeammateAccessClaims) { c.Project = "" }, func(c *TeammateAccessClaims) { c.Audience = nil }, func(c *TeammateAccessClaims) { c.Audience = append(c.Audience, "urn:other") }, func(c *TeammateAccessClaims) { c.Audience = []string{""} }, func(c *TeammateAccessClaims) { c.ClaimID = "" }, func(c *TeammateAccessClaims) { c.WorkstationID = "" }, func(c *TeammateAccessClaims) { c.CompanyID = "" }, func(c *TeammateAccessClaims) { c.JWTID = "" }, func(c *TeammateAccessClaims) { c.IssuedAt = 0 }, func(c *TeammateAccessClaims) { c.ExpiresAt = c.IssuedAt }} {
		next := c
		mutate(&next)
		_, err := next.ClaimsMap()
		require.Error(t, err)
	}
}

func TestTeammateTokenRefusesPurposeExpiryAndMalformedInput(t *testing.T) {
	signer := newMemSigner(t, "teammate-profile-key")
	c := teammateClaims()
	values, err := c.ClaimsMap()
	require.NoError(t, err)
	values["purpose"] = "dob_completion"
	raw, err := signer.signClaims(context.Background(), values, DelegatedAccessTokenType)
	require.NoError(t, err)
	_, err = VerifyTeammateAccessToken(raw, signer, c.Issuer, c.Project, c.Audience[0])
	require.Error(t, err)
	expired := c
	expired.IssuedAt, expired.ExpiresAt = c.IssuedAt-600, c.IssuedAt-300
	raw, err = signer.SignTeammateAccessToken(context.Background(), expired)
	require.NoError(t, err)
	_, err = VerifyTeammateAccessToken(raw, signer, c.Issuer, c.Project, c.Audience[0])
	require.Error(t, err)
	future := c
	future.IssuedAt, future.ExpiresAt = c.IssuedAt+120, c.IssuedAt+420
	raw, err = signer.SignTeammateAccessToken(context.Background(), future)
	require.NoError(t, err)
	_, err = VerifyTeammateAccessToken(raw, signer, c.Issuer, c.Project, c.Audience[0])
	require.Error(t, err)
	for _, raw := range []string{strings.Repeat("a", maxDelegatedAccessTokenBytes+1), "a.b.c.d", "a. b.c"} {
		_, err := VerifyTeammateAccessToken(raw, signer, c.Issuer, c.Project, c.Audience[0])
		require.Error(t, err)
	}
	_, err = signer.SignTeammateAccessToken(context.Background(), TeammateAccessClaims{})
	require.Error(t, err)
}
