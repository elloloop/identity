package identityserver

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnect "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
	"github.com/elloloop/identity/pkg/passwords"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestProjectDOBPolicy_HTTPAndNativeCompletion(t *testing.T) {
	cfg := config.Load()
	cfg.RepoDriver = "memory"
	cfg.DefaultProjectID = "profile-default"
	cfg.DefaultProjectAccessMode = "open"
	cfg.AgeGateEnabled = true
	cfg.AgeGateChildMaxAge = 12
	cfg.AgeGateAdultAge = 18
	cfg.AgeGateRequireDOB = false
	cfg.AuthAllowLocal = true
	repo := memory.New()
	signer := jwttest.NewSigner(t, "profile-policy")
	pk, err := passkeys.NewWebAuthnService(passkeys.Config{RPID: "localhost", RPName: "Example", Origin: "http://localhost:9002"})
	require.NoError(t, err)
	project := &service.AdminProject{ID: cfg.DefaultProjectID, Access: service.ProjectAccessConfig{Mode: service.AccessModeOpen}, AgeGate: service.ProjectAgeGateConfig{RequireDOB: true}}
	built, err := app.New(app.Deps{Config: cfg, Logger: zap.NewNop(), Signer: signer, Repo: repo, DB: repo, Passkeys: pk, TOTPKey: []byte("01234567890123456789012345678901"), TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"), ActiveProjects: guardianPolicyProject{project: project}})
	require.NoError(t, err)
	const password = "Strong-parent-password-42!"
	hash, err := passwords.Hash(password)
	require.NoError(t, err)
	scoped := repo.WithProject(cfg.DefaultProjectID)
	ctx := context.Background()
	for _, address := range []string{"http-parent@example.com", "native-parent@example.com"} {
		_, err = scoped.CreateUser(ctx, &service.User{Email: address, PasswordHash: hash, Status: service.StatusActive, Kind: service.UserKindPerson, EmailVerified: true})
		require.NoError(t, err)
	}
	server := httptest.NewServer(built.Handler)
	t.Cleanup(server.Close)
	client := identityconnect.NewIdentityServiceClient(server.Client(), server.URL)
	_, err = client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{Email: "http-parent@example.com", Password: password}))
	require.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
	var connectErr *connect.Error
	require.True(t, errors.As(err, &connectErr))
	ticket := ""
	for _, detail := range connectErr.Details() {
		value, decodeErr := detail.Value()
		require.NoError(t, decodeErr)
		if dob, ok := value.(*identitypb.DOBRequiredDetails); ok {
			ticket = dob.CompletionToken
		}
	}
	require.NotEmpty(t, ticket)
	response, err := client.SubmitDateOfBirth(ctx, connect.NewRequest(&identitypb.SubmitDateOfBirthRequest{CompletionToken: ticket, DateOfBirthUnixMs: new(int64(0))}))
	require.NoError(t, err)
	require.NotEmpty(t, response.Msg.AccessToken)
	require.Equal(t, new(int64(0)), response.Msg.User.DateOfBirthUnixMs)
	bridge := newGRPCBridge(built, zap.NewNop(), grpcTrust{})
	_, err = bridge.PasswordLogin(ctx, &identitypb.PasswordLoginRequest{Email: "native-parent@example.com", Password: password})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	ticket = ""
	for _, detail := range status.Convert(err).Details() {
		if dob, ok := detail.(*identitypb.DOBRequiredDetails); ok {
			ticket = dob.CompletionToken
		}
	}
	require.NotEmpty(t, ticket)
	native, err := bridge.SubmitDateOfBirth(ctx, &identitypb.SubmitDateOfBirthRequest{CompletionToken: ticket, DateOfBirthUnixMs: new(int64(-1000))})
	require.NoError(t, err)
	require.NotEmpty(t, native.AccessToken)
	require.Equal(t, new(int64(-1000)), native.User.DateOfBirthUnixMs)
}
