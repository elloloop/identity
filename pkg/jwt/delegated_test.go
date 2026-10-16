package jwt

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func delegatedClaims() DelegatedAccessClaims {
	now := time.Now().Unix()
	return DelegatedAccessClaims{Sub: "agent", Kind: "agent", Actor: DelegatedActor{Sub: "human"}, Issuer: "https://auth.example.test", Project: "project", Audience: []string{"https://files.example.test"}, ClientID: "desktop", Scope: "files:read", GrantID: "grant", SID: "sid", IssuedAt: now, ExpiresAt: now + 60, JWTID: "jti"}
}

func TestDelegatedTokenProfileAndBindings(t *testing.T) {
	signer := newMemSigner(t, "delegated-key")
	c := delegatedClaims()
	raw, err := signer.SignDelegatedAccessToken(context.Background(), c)
	require.NoError(t, err)
	typ, err := tokenType([]byte(raw))
	require.NoError(t, err)
	require.Equal(t, DelegatedAccessTokenType, typ)
	actual, err := VerifyDelegatedAccessToken(raw, signer, c.Issuer, c.Project, c.Audience[0])
	require.NoError(t, err)
	require.Equal(t, c, *actual)
	_, err = VerifyAccessToken(raw, signer, "", "", false)
	require.Error(t, err)
	_, err = VerifyPurposeToken(raw, signer, "", "", false, "dob_completion")
	require.Error(t, err)
	for _, bound := range [][3]string{{"", c.Project, c.Audience[0]}, {"https://other.example.test", c.Project, c.Audience[0]}, {c.Issuer, "other", c.Audience[0]}, {c.Issuer, c.Project, "urn:other"}} {
		_, err = VerifyDelegatedAccessToken(raw, signer, bound[0], bound[1], bound[2])
		require.Error(t, err)
	}
	human, err := signer.SignAccessToken(context.Background(), Claims{Sub: "human"}, time.Minute)
	require.NoError(t, err)
	_, err = VerifyDelegatedAccessToken(human, signer, c.Issuer, c.Project, c.Audience[0])
	require.Error(t, err)
	split := strings.Split(raw, ".")
	split[2] = "AAAA"
	_, err = VerifyDelegatedAccessToken(strings.Join(split, "."), signer, c.Issuer, c.Project, c.Audience[0])
	require.Error(t, err)
}

func TestDelegatedClaimsRejectIncompleteOrConfusedPrincipals(t *testing.T) {
	c := delegatedClaims()
	m, err := c.ClaimsMap()
	require.NoError(t, err)
	require.NotContains(t, m, "email")
	require.NotContains(t, m, "role")
	require.NotContains(t, m, "auth_time")
	for _, mutate := range []func(*DelegatedAccessClaims){func(c *DelegatedAccessClaims) { c.Sub = "" }, func(c *DelegatedAccessClaims) { c.Kind = "person" }, func(c *DelegatedAccessClaims) { c.Actor.Sub = c.Sub }, func(c *DelegatedAccessClaims) { c.Audience = append(c.Audience, "urn:other") }, func(c *DelegatedAccessClaims) { c.ExpiresAt = c.IssuedAt }, func(c *DelegatedAccessClaims) { c.SID = "" }, func(c *DelegatedAccessClaims) { c.Scope = "" }, func(c *DelegatedAccessClaims) { c.GrantID = "" }, func(c *DelegatedAccessClaims) { c.ClientID = "" }, func(c *DelegatedAccessClaims) { c.JWTID = "" }, func(c *DelegatedAccessClaims) { c.Project = "" }, func(c *DelegatedAccessClaims) { c.Issuer = "" }} {
		next := c
		mutate(&next)
		_, err := next.ClaimsMap()
		require.Error(t, err)
	}
	_, err = tokenType([]byte("invalid"))
	require.Error(t, err)
}

func TestDelegatedTokenRequiresExplicitAgeStandingAndCompactProfile(t *testing.T) {
	signer := newMemSigner(t, "profile-key")
	claims := delegatedClaims()
	for _, change := range []func(map[string]any){func(m map[string]any) { delete(m, "is_minor") }, func(m map[string]any) { m["purpose"] = "dob_completion" }} {
		values, err := claims.ClaimsMap()
		require.NoError(t, err)
		change(values)
		raw, err := signer.signClaims(context.Background(), values, DelegatedAccessTokenType)
		require.NoError(t, err)
		_, err = VerifyDelegatedAccessToken(raw, signer, claims.Issuer, claims.Project, claims.Audience[0])
		require.Error(t, err)
	}
	for _, raw := range []string{strings.Repeat("a", maxDelegatedAccessTokenBytes+1), "a.b.c.d", "a. b.c"} {
		_, err := VerifyDelegatedAccessToken(raw, signer, claims.Issuer, claims.Project, claims.Audience[0])
		require.Error(t, err)
	}
}

func TestDelegatedProfileSupportsRegisteredMaximumBounds(t *testing.T) {
	signer := newMemSigner(t, "wide-bounds")
	claims := delegatedClaims()
	claims.Issuer = "https://auth.example.test/" + strings.Repeat("i", 2000)
	claims.Audience = []string{"https://files.example.test/" + strings.Repeat("r", 2000)}
	scopes := make([]string, 64)
	for i := range scopes {
		scopes[i] = fmt.Sprintf("%03d", i) + strings.Repeat("s", 125)
	}
	claims.Scope = strings.Join(scopes, " ")
	raw, err := signer.SignDelegatedAccessToken(context.Background(), claims)
	require.NoError(t, err)
	require.Greater(t, len(raw), 16384, "valid registered URI/scope bounds exceed a sixteen-KiB JWT limit")
	_, err = VerifyDelegatedAccessToken(raw, signer, claims.Issuer, claims.Project, claims.Audience[0])
	require.NoError(t, err)
}
