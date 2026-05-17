//go:build integration

package integration

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"

	pb "github.com/elloloop/identity/gen/go/identity"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/jwt"
)

// TestModeTTL_DefaultBehaviour confirms the existing mode=ttl
// contract:
//   - access tokens carry NO sid claim (no Session row written)
//   - in-flight access tokens stay valid until natural expiry even
//     after refresh tokens are revoked
//
// This is the regression test for the "deployer who never touches the
// config knob sees zero behaviour change" guarantee.
func TestModeTTL_DefaultBehaviour(t *testing.T) {
	h := StartServer(t) // default config: RevocationMode unset → ttl

	signupAndLogin := func(emailAddr string) (accessToken, refreshToken string) {
		t.Helper()
		ctx := context.Background()
		_, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&pb.PasswordSignupRequest{
			Email: emailAddr, Password: strongPassword,
		}))
		require.NoError(t, err)
		resp, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&pb.PasswordLoginRequest{
			Email: emailAddr, Password: strongPassword,
		}))
		require.NoError(t, err)
		return resp.Msg.AccessToken, resp.Msg.RefreshToken
	}

	access, refresh := signupAndLogin("ttl-default@example.com")
	require.NotEmpty(t, access)
	require.NotEmpty(t, refresh)

	claims, err := jwt.VerifyAccessToken(access, h.Signer, "", "", false)
	require.NoError(t, err)
	require.Empty(t, claims.SID, "mode=ttl must not put a sid on the access token")

	// Authenticated call works.
	authed := h.AuthedClient(access)
	_, err = authed.GetCurrentUser(context.Background(), connect.NewRequest(&pb.GetCurrentUserRequest{}))
	require.NoError(t, err)

	// Revoke refresh tokens directly via the repository — mode=ttl
	// contract says the access token is still valid afterwards.
	userID := h.FindUserIDByEmail(t, "ttl-default@example.com")
	require.NoError(t, h.Repo.DeleteRefreshTokensForUser(context.Background(), userID))

	_, err = authed.GetCurrentUser(context.Background(), connect.NewRequest(&pb.GetCurrentUserRequest{}))
	require.NoError(t, err, "mode=ttl: access token must keep working until natural expiry")
}

// TestModeSession_RevokeKillsAccessToken confirms the mode=session
// contract:
//   - access tokens carry a sid claim
//   - revoking the session causes the very next request to fail
//     (within the cache TTL window)
func TestModeSession_RevokeKillsAccessToken(t *testing.T) {
	h := StartServer(t, WithConfig(func(cfg *config.Config) {
		cfg.RevocationMode = config.RevocationModeSession
		cfg.SessionCacheTTLSeconds = 0 // strict: every request reads the repo
	}))

	ctx := context.Background()
	_, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&pb.PasswordSignupRequest{
		Email: "sess-revoke@example.com", Password: strongPassword,
	}))
	require.NoError(t, err)
	resp, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&pb.PasswordLoginRequest{
		Email: "sess-revoke@example.com", Password: strongPassword,
	}))
	require.NoError(t, err)
	access := resp.Msg.AccessToken

	claims, err := jwt.VerifyAccessToken(access, h.Signer, "", "", false)
	require.NoError(t, err)
	require.NotEmpty(t, claims.SID, "mode=session must put a sid on the access token")

	authed := h.AuthedClient(access)
	_, err = authed.GetCurrentUser(ctx, connect.NewRequest(&pb.GetCurrentUserRequest{}))
	require.NoError(t, err, "fresh session must be accepted")

	// Revoke the session through the repository the harness handed to
	// app.New; the wired Repository invalidates the in-process cache
	// on the same call, so the very next request must fail.
	require.NoError(t, h.Repo.RevokeSession(ctx, claims.SID, 1))

	_, err = authed.GetCurrentUser(ctx, connect.NewRequest(&pb.GetCurrentUserRequest{}))
	require.Error(t, err, "revoked session must reject subsequent requests")
	require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

// TestModeSession_StrictModeReadsRepoEachRequest covers
// GATEWAY_SESSION_CACHE_TTL_SECONDS=0: every authenticated request
// pays the repo round-trip, but a single revoke is observed
// immediately on every replica.
func TestModeSession_StrictModeReadsRepoEachRequest(t *testing.T) {
	h := StartServer(t, WithConfig(func(cfg *config.Config) {
		cfg.RevocationMode = config.RevocationModeSession
		cfg.SessionCacheTTLSeconds = 0
	}))

	ctx := context.Background()
	_, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&pb.PasswordSignupRequest{
		Email: "strict@example.com", Password: strongPassword,
	}))
	require.NoError(t, err)
	resp, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&pb.PasswordLoginRequest{
		Email: "strict@example.com", Password: strongPassword,
	}))
	require.NoError(t, err)
	access := resp.Msg.AccessToken
	authed := h.AuthedClient(access)

	for i := 0; i < 3; i++ {
		_, err := authed.GetCurrentUser(ctx, connect.NewRequest(&pb.GetCurrentUserRequest{}))
		require.NoError(t, err)
	}

	claims, err := jwt.VerifyAccessToken(access, h.Signer, "", "", false)
	require.NoError(t, err)
	require.NoError(t, h.Repo.RevokeSession(ctx, claims.SID, 1))

	_, err = authed.GetCurrentUser(ctx, connect.NewRequest(&pb.GetCurrentUserRequest{}))
	require.Error(t, err)
}

// TestModeSession_RefreshTokenReplayRevokesAccessToken is the
// regression test for the H2 motivation: a stolen refresh-token replay
// must also kill the attacker's in-flight access tokens.
func TestModeSession_RefreshTokenReplayRevokesAccessToken(t *testing.T) {
	h := StartServer(t, WithConfig(func(cfg *config.Config) {
		cfg.RevocationMode = config.RevocationModeSession
		cfg.SessionCacheTTLSeconds = 0
	}))

	ctx := context.Background()
	_, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&pb.PasswordSignupRequest{
		Email: "replay@example.com", Password: strongPassword,
	}))
	require.NoError(t, err)
	resp, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&pb.PasswordLoginRequest{
		Email: "replay@example.com", Password: strongPassword,
	}))
	require.NoError(t, err)
	originalAccess := resp.Msg.AccessToken
	originalRefresh := resp.Msg.RefreshToken

	// Legitimate refresh: rotates the refresh token, mints a new
	// access token + sid.
	refreshResp, err := h.Client.RefreshToken(ctx, connect.NewRequest(&pb.RefreshTokenRequest{
		RefreshToken: originalRefresh,
	}))
	require.NoError(t, err)
	require.NotEqual(t, originalAccess, refreshResp.Msg.AccessToken)

	// Attacker plays the stolen original refresh token — replay detected.
	_, err = h.Client.RefreshToken(ctx, connect.NewRequest(&pb.RefreshTokenRequest{
		RefreshToken: originalRefresh,
	}))
	require.Error(t, err)

	// The legitimate user's NEW access token must now also be rejected,
	// because the replay-detection path triggered RevokeSessionsForUser.
	authed := h.AuthedClient(refreshResp.Msg.AccessToken)
	_, err = authed.GetCurrentUser(ctx, connect.NewRequest(&pb.GetCurrentUserRequest{}))
	require.Error(t, err, "replay detection must invalidate the legitimate access token too")
}

const strongPassword = "Tr0ub4dor&3-MixedC4se!"
