package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tokenPayload decodes an access token's payload as published, so a test can
// tell an absent claim from one that is present and false.
func tokenPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}

// email_verified states whether the address in the email claim was proven,
// on every token that carries an address, and is absent with the address.
func TestAccessToken_EmailVerifiedClaim(t *testing.T) {
	cases := []struct {
		name     string
		email    string
		verified bool
		want     any
	}{
		{"proven address", "proven@example.com", true, true},
		{"unproven address", "unproven@example.com", false, false},
		{"no address", "", false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := newFakeRepo()
			svc := newTestAuthService(t, repo)
			user := seedUser(repo, tc.email, "", StatusActive)
			user.EmailVerified = tc.verified

			access, _, err := svc.issueTokens(context.Background(), user, "", "")
			require.NoError(t, err)
			got, present := tokenPayload(t, access)["email_verified"]
			if tc.want == nil {
				assert.False(t, present, "a token without an address carries no email_verified")
				return
			}
			require.True(t, present, "a token with an address always says whether it was proven")
			assert.Equal(t, tc.want, got)
		})
	}
}

// Verifying the address turns the claim on from the next token: a password
// account signs up unproven and signs in proven once the emailed link is
// redeemed.
func TestAccessToken_EmailVerifiedAfterVerification(t *testing.T) {
	svc, _, rec := newAuthSvcWithMailer(t)
	ctx := context.Background()

	signup, err := svc.PasswordSignup(ctx, "late@example.com", strongPW, "Late", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)
	require.NotEmpty(t, signup.AccessToken)
	assert.Equal(t, false, tokenPayload(t, signup.AccessToken)["email_verified"])

	sent := rec.Sent()
	require.NotEmpty(t, sent)
	_, err = svc.VerifyEmail(ctx, extractTokenFromLink(t, sent[len(sent)-1].Text))
	require.NoError(t, err)

	login, err := svc.PasswordLogin(ctx, "late@example.com", strongPW, "", "")
	require.NoError(t, err)
	assert.Equal(t, true, tokenPayload(t, login.AccessToken)["email_verified"])

	// A refresh token minted before the proof also picks it up: refresh
	// reads the claim from the account, not from the session it rotates.
	_, access, _, err := svc.RefreshToken(ctx, signup.RefreshToken, "", "")
	require.NoError(t, err)
	assert.Equal(t, true, tokenPayload(t, access)["email_verified"])
}

// A refresh after the address moves to another mailbox carries the new
// address unproven, even though the session began on a proven one.
func TestAccessToken_EmailVerifiedFollowsAnEmailChangeOnRefresh(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	ctx := context.Background()

	user := seedUser(repo, "before@example.com", "", StatusActive)
	require.NoError(t, repo.UpdateUser(ctx, user.ID, map[string]any{"email_verified": true}))
	user, err := repo.GetUser(ctx, user.ID)
	require.NoError(t, err)
	_, refresh, err := svc.issueTokens(ctx, user, "", "")
	require.NoError(t, err)

	// The write a directory sync makes when it moves the address elsewhere.
	require.NoError(t, repo.UpdateUser(ctx, user.ID, map[string]any{
		"email": "after@example.com", "email_verified": false, "email_verified_at": int64(0),
	}))

	_, access, _, err := svc.RefreshToken(ctx, refresh, "", "")
	require.NoError(t, err)
	claims := tokenPayload(t, access)
	assert.Equal(t, "after@example.com", claims["email"])
	assert.Equal(t, false, claims["email_verified"])
}

// The duplicate-signup decoy carries the email_verified a genuine sign-up's
// token would, or the claim would tell an existing address from a new one.
func TestAccessToken_DuplicateSignupDecoyEmailVerifiedParity(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	ctx := context.Background()

	fresh, err := svc.PasswordSignup(ctx, "twice@example.com", strongPW, "Twice", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)
	dup, err := svc.PasswordSignup(ctx, "twice@example.com", strongPW, "Twice", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)

	freshClaims, dupClaims := tokenPayload(t, fresh.AccessToken), tokenPayload(t, dup.AccessToken)
	assert.Equal(t, false, freshClaims["email_verified"])
	assert.Equal(t, freshClaims["email_verified"], dupClaims["email_verified"])
	assert.Equal(t, slices.Sorted(maps.Keys(freshClaims)), slices.Sorted(maps.Keys(dupClaims)),
		"the decoy carries the same claims as a genuine sign-up")
}
