package service

import (
	"context"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/jwt"
)

// signupShape is what a caller who is not signed in sees of a PasswordSignup
// answer, apart from values that differ on every call.
type signupShape struct {
	err                   error
	email, name           string
	access, refresh, totp bool
	expiresIn             int32
	claims                []string
}

func shapeOfSignup(t *testing.T, svc *AuthService, res *LoginResult, err error) signupShape {
	t.Helper()
	if err != nil {
		return signupShape{err: err}
	}
	shape := signupShape{
		email: res.User.Email, name: res.User.Name,
		access: res.AccessToken != "", refresh: res.RefreshToken != "", totp: res.TotpRequired,
		expiresIn: res.ExpiresIn,
	}
	if res.AccessToken != "" {
		claims, err := jwt.VerifyAccessToken(res.AccessToken, svc.signer, "", "", false)
		require.NoError(t, err)
		shape.claims = slices.Sorted(maps.Keys(claims.ClaimsMap(svc.nowFunc(), 0)))
	}
	return shape
}

// An address an account keeps as a recovery email is answered like one that
// is an account's primary email, and both like a free one: a caller who is
// not signed in learns nothing about which it named.
func TestPasswordSignup_RecoveryEmailAnswersLikeAFreeOrTakenAddress(t *testing.T) {
	for _, requireVerified := range []bool{false, true} {
		svc, repo, rec := newAuthSvcWithMailer(t)
		svc.cfg.AuthRequireVerifiedEmail = requireVerified
		ctx := context.Background()
		holder := seedUser(repo, "holder@example.com", hashPW(t, strongPW), StatusActive)
		holder.Name = "Holder"
		require.NoError(t, repo.AddRecoveryEmail(ctx, &RecoveryEmail{UserID: holder.ID, Email: "spare@example.com", VerifiedAt: 1}, 5))

		shapes := map[string]signupShape{}
		for _, addr := range []string{"free@example.com", "holder@example.com", "spare@example.com"} {
			res, err := svc.PasswordSignup(ctx, addr, strongPW, "Same Name", "", 0, "", EmailLinkParams{})
			shape := shapeOfSignup(t, svc, res, err)
			require.NoError(t, shape.err, addr)
			shape.email = strings.Replace(shape.email, strings.SplitN(addr, "@", 2)[0], "x", 1)
			shapes[addr] = shape
		}
		assert.Equal(t, shapes["free@example.com"], shapes["holder@example.com"], "require_verified=%t", requireVerified)
		assert.Equal(t, shapes["free@example.com"], shapes["spare@example.com"], "require_verified=%t", requireVerified)

		got, err := repo.FindUserByEmail(ctx, "spare@example.com")
		require.NoError(t, err)
		assert.Nil(t, got, "no account was made on the recovery email")
		var notices int
		for _, m := range rec.Sent() {
			if m.To == "spare@example.com" && m.Subject == "Someone tried to sign up with your email" {
				notices++
			}
		}
		assert.Equal(t, 1, notices, "the recovery address is told of the attempt")
	}
}

// A provider asserting an address an account keeps as a recovery email does
// not sign in to that account, and makes no account on it: it is told to
// sign in and link the provider, as for an account the provider cannot prove.
func TestOAuthLogin_RecoveryEmailIsRefusedLikeAnAccountTheProviderCannotProve(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	holder := seedUser(repo, "holder@example.com", "", StatusActive)
	require.NoError(t, repo.AddRecoveryEmail(ctx, &RecoveryEmail{UserID: holder.ID, Email: "spare@example.com", VerifiedAt: 1}, 5))
	users := len(repo.users)

	_, err := svc.OAuthLogin(ctx, OAuthLoginParams{
		Code: fakeOAuthCode("spare@example.com", "Spare", "", "google"), Provider: "google", RedirectURI: "https://app/cb",
	})
	require.ErrorIs(t, err, ErrUnauthenticated)
	require.ErrorContains(t, err, "sign in and link this provider")
	assert.Len(t, repo.users, users)
	linked, err := repo.FindUserByProviderID(ctx, "google", "sub-spare@example.com")
	require.NoError(t, err)
	assert.Nil(t, linked, "no provider was linked to the holding account")
}

// A passkey sign-up on an address an account keeps as a recovery email gets
// the decoy a sign-up on a taken primary email gets: no account, no passkey
// on the holder, and a notice to the address.
func TestPasskeySignup_RecoveryEmailDecoys(t *testing.T) {
	svc, repo, rec := newPasskeyVectorSvc(t)
	ctx := context.Background()
	holder := seedUser(repo, "holder@example.com", hashPW(t, "Existing0wner!"), StatusActive)
	require.NoError(t, repo.AddRecoveryEmail(ctx, &RecoveryEmail{UserID: holder.ID, Email: pkVectorEmail, VerifiedAt: 1}, 5))
	users := len(repo.users)

	_, challengeID, err := svc.BeginPasskeySignup(ctx, pkVectorEmail, "Key")
	require.NoError(t, err)
	otp := passkeySignupOTP(t, rec, pkVectorEmail)
	setFakeChallengeValue(repo, challengeID, pkB64URL(t, pkRegChallengeHex))
	rec.Reset()

	res, err := svc.CompletePasskeySignup(ctx, challengeID, pkRegCredentialJSON(t), pkVectorEmail, otp, "Key", "9.9.9.9", "agent")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(res.User.ID, "signup-pending-"), "expected the decoy, got %q", res.User.ID)
	assert.NotEmpty(t, res.AccessToken)
	assert.Len(t, repo.users, users, "no account was made on the recovery email")
	creds, err := repo.ListPasskeyCredentials(ctx, holder.ID)
	require.NoError(t, err)
	assert.Empty(t, creds)
	sent := rec.Sent()
	require.Len(t, sent, 1)
	assert.Equal(t, pkVectorEmail, sent[0].To)
}
