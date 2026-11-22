//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"connectrpc.com/connect"
	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/service"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestPasskeyEligibilityHTTPRequiresIndependentSignIn(t *testing.T) {
	h := StartServer(t)
	ctx := context.Background()
	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{Email: "legacy-owner@example.com", Password: goodPassword}))
	require.NoError(t, err)
	userID := signup.Msg.User.Id
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	public, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: private.X.FillBytes(make([]byte, 32)), -3: private.Y.FillBytes(make([]byte, 32))})
	require.NoError(t, err)
	b64 := base64.RawURLEncoding.EncodeToString
	credentialID := b64([]byte("legacy-fixture"))
	_, err = h.Repo.CreatePasskeyCredential(ctx, &service.PasskeyCredRecord{UserID: userID, CredentialID: credentialID, PublicKey: base64.StdEncoding.EncodeToString(public)})
	require.NoError(t, err)
	assertion := func(challengeID string) string {
		t.Helper()
		challenge, err := h.Repo.GetPasskeyChallenge(ctx, challengeID)
		require.NoError(t, err)
		client, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge.Challenge, "origin": "http://localhost:9002"})
		require.NoError(t, err)
		rpHash := sha256.Sum256([]byte("localhost"))
		authData := append(append([]byte{}, rpHash[:]...), 0x05, 0, 0, 0, 0)
		clientHash := sha256.Sum256(client)
		digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
		signature, err := ecdsa.SignASN1(rand.Reader, private, digest[:])
		require.NoError(t, err)
		body, err := json.Marshal(map[string]any{"id": credentialID, "rawId": credentialID, "type": "public-key", "response": map[string]any{
			"authenticatorData": b64(authData), "clientDataJSON": b64(client), "signature": b64(signature), "userHandle": b64([]byte(userID)),
		}})
		require.NoError(t, err)
		return string(body)
	}
	beginLogin, err := h.Client.BeginPasskeyLogin(ctx, connect.NewRequest(&identitypb.BeginPasskeyLoginRequest{Email: "legacy-owner@example.com"}))
	require.NoError(t, err)
	legacy, err := h.Client.CompletePasskeyLogin(ctx, connect.NewRequest(&identitypb.CompletePasskeyLoginRequest{ChallengeId: beginLogin.Msg.ChallengeId, CredentialJson: assertion(beginLogin.Msg.ChallengeId)}))
	require.NoError(t, err, "legacy sign-in remains usable")
	legacyClient := h.AuthedClient(legacy.Msg.AccessToken)
	spoof := connect.NewRequest(&identitypb.BeginPasskeyEligibilityVerificationRequest{CredentialId: credentialID})
	spoof.Header().Set(middleware.AuthenticatedAMRHeader, service.AMRCredentialEnrollment)
	spoof.Header().Set(middleware.AuthenticatedAuthTimeHeader, strconv.FormatInt(time.Now().Unix(), 10))
	_, err = legacyClient.BeginPasskeyEligibilityVerification(ctx, spoof)
	require.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err), "request headers cannot upgrade signed session provenance")
	primary, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{Email: "legacy-owner@example.com", Password: goodPassword}))
	require.NoError(t, err)
	owner := h.AuthedClient(primary.Msg.AccessToken)
	begin, err := owner.BeginPasskeyEligibilityVerification(ctx, connect.NewRequest(&identitypb.BeginPasskeyEligibilityVerificationRequest{CredentialId: credentialID}))
	require.NoError(t, err)
	before, err := owner.ListPasskeys(ctx, connect.NewRequest(&identitypb.ListPasskeysRequest{}))
	require.NoError(t, err)
	require.Len(t, before.Msg.Credentials, 1)
	require.False(t, before.Msg.Credentials[0].ReauthenticationEligible)
	request := &identitypb.CompletePasskeyEligibilityVerificationRequest{CredentialId: credentialID, ChallengeId: begin.Msg.ChallengeId, CredentialJson: assertion(begin.Msg.ChallengeId)}
	completed, err := owner.CompletePasskeyEligibilityVerification(ctx, connect.NewRequest(request))
	require.NoError(t, err)
	require.Equal(t, credentialID, completed.Msg.Credential.CredentialId)
	require.True(t, completed.Msg.Credential.ReauthenticationEligible)
	after, err := owner.ListPasskeys(ctx, connect.NewRequest(&identitypb.ListPasskeysRequest{}))
	require.NoError(t, err)
	require.Len(t, after.Msg.Credentials, 1)
	require.True(t, after.Msg.Credentials[0].ReauthenticationEligible)
	_, err = owner.CompletePasskeyEligibilityVerification(ctx, connect.NewRequest(request))
	require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = legacyClient.GetCurrentUser(ctx, connect.NewRequest(&identitypb.GetCurrentUserRequest{}))
	require.NoError(t, err, "explicit verification preserves existing sign-in access")
	refreshed, err := h.Client.RefreshToken(ctx, connect.NewRequest(&identitypb.RefreshTokenRequest{RefreshToken: legacy.Msg.RefreshToken}))
	require.NoError(t, err)
	_, err = h.AuthedClient(refreshed.Msg.AccessToken).BeginPasskeyEligibilityVerification(ctx, connect.NewRequest(&identitypb.BeginPasskeyEligibilityVerificationRequest{CredentialId: credentialID}))
	require.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err), "a historical legacy session stays untrusted after another session verifies its key")
}
