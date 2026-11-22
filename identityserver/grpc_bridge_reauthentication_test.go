package identityserver

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

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestReauthenticationNativeGRPCBoundProof(t *testing.T) {
	client, repo, family := nativeChildFixture(t)
	ctx := context.Background()
	user := family.GuardianUserId
	require.NoError(t, repo.UpdateUser(ctx, user, map[string]any{"email_verified": true}))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	public, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: key.X.FillBytes(make([]byte, 32)), -3: key.Y.FillBytes(make([]byte, 32))})
	require.NoError(t, err)
	b64 := base64.RawURLEncoding.EncodeToString
	credentialID := b64([]byte("native-passkey-fixture"))
	_, err = repo.CreatePasskeyCredential(ctx, &service.PasskeyCredRecord{UserID: user, CredentialID: credentialID, PublicKey: base64.StdEncoding.EncodeToString(public), ReauthenticationEligible: true})
	require.NoError(t, err)
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("x-project-key", "pk_native", "x-authenticated-user-id", user))
	begin, err := client.BeginReauthentication(ctx, &identitypb.BeginReauthenticationRequest{Action: "account.pin.set", ResourceId: user})
	require.NoError(t, err)
	require.Contains(t, begin.OptionsJson, `"userVerification":"required"`)
	challenge, err := repo.GetPasskeyChallenge(context.Background(), begin.ChallengeId)
	require.NoError(t, err)
	clientData, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge.Challenge, "origin": "http://localhost:9002"})
	require.NoError(t, err)
	rpHash := sha256.Sum256([]byte("localhost"))
	authData := append(append([]byte{}, rpHash[:]...), 0x05, 0, 0, 0, 0)
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	require.NoError(t, err)
	assertion, err := json.Marshal(map[string]any{"id": credentialID, "rawId": credentialID, "type": "public-key", "response": map[string]any{
		"authenticatorData": b64(authData), "clientDataJSON": b64(clientData), "signature": b64(signature), "userHandle": b64([]byte(user)),
	}})
	require.NoError(t, err)
	request := &identitypb.VerifyReauthenticationRequest{Action: "account.pin.set", ResourceId: user, ChallengeId: begin.ChallengeId, CredentialJson: string(assertion)}
	otherProject := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-project-key", "pk_other", "x-authenticated-user-id", user))
	_, err = client.VerifyReauthentication(otherProject, request)
	require.Error(t, err)
	verified, err := client.VerifyReauthentication(ctx, request)
	require.NoError(t, err)
	require.Equal(t, user, verified.UserId)
	_, err = client.VerifyReauthentication(ctx, request)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestReauthenticationNativeGRPCRequiresProject(t *testing.T) {
	client, _, family := nativeChildFixture(t)
	for _, key := range []string{"", "pk_missing", "pk_empty"} {
		ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-project-key", key, "x-authenticated-user-id", family.GuardianUserId))
		_, err := client.BeginReauthentication(ctx, &identitypb.BeginReauthenticationRequest{Action: "account.pin.set", ResourceId: family.GuardianUserId})
		require.Equal(t, codes.Unauthenticated, status.Code(err))
	}
}

func TestPasskeyEligibilityNativeGRPCDoesNotTrustUnvouchedClaims(t *testing.T) {
	client, _, family := nativeChildFixture(t)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		"x-project-key", "pk_native", "x-authenticated-user-id", family.GuardianUserId,
		"x-authenticated-auth-time", strconv.FormatInt(time.Now().Unix(), 10),
		"x-authenticated-amr", service.AMRCredentialEnrollment,
	))
	_, err := client.BeginPasskeyEligibilityVerification(ctx, &identitypb.BeginPasskeyEligibilityVerificationRequest{CredentialId: "target"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, err = client.CompletePasskeyEligibilityVerification(ctx, &identitypb.CompletePasskeyEligibilityVerificationRequest{CredentialId: "target", ChallengeId: "id", CredentialJson: "{}"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}
