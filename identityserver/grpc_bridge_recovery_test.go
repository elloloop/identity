package identityserver

import (
	"context"
	"net/http/httptest"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnect "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
)

// recoverySignInProject resolves every request to one project whose recovery
// emails sign in.
type recoverySignInProject struct{}

func (recoverySignInProject) ResolveByCredential(context.Context, string) (*service.ResolvedProject, error) {
	return nil, nil
}

func (recoverySignInProject) ResolveByHostname(context.Context, string) (*service.ResolvedProject, error) {
	return &service.ResolvedProject{
		ID:             "project-recovery",
		StorageScopeID: "tenant",
		Access:         service.ProjectAccessConfig{Mode: service.AccessModeOpen},
		RecoveryEmails: service.ProjectRecoveryEmailsConfig{Enabled: true, SignIn: true},
	}, nil
}

// codeInbox keeps the codes mailed to each address, in order.
type codeInbox struct {
	mu    sync.Mutex
	codes map[string][]string
}

var sixDigitCode = regexp.MustCompile(`\b\d{6}\b`)

func (m *codeInbox) Send(_ context.Context, msg email.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if code := sixDigitCode.FindString(msg.Text); code != "" {
		m.codes[msg.To] = append(m.codes[msg.To], code)
	}
	return nil
}

// code waits for the n-th code (from 0) mailed to addr.
func (m *codeInbox) code(t *testing.T, addr string, n int) string {
	t.Helper()
	var code string
	require.Eventually(t, func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		if len(m.codes[addr]) > n {
			code = m.codes[addr][n]
			return true
		}
		return false
	}, 5*time.Second, 10*time.Millisecond, "no code %d was mailed to %s", n, addr)
	return code
}

func bearerRequest[T any](msg *T, token string) *connect.Request[T] {
	req := connect.NewRequest(msg)
	req.Header().Set("Authorization", "Bearer "+token)
	return req
}

// Over native gRPC a recovery session is told apart by the token keys the
// host's interceptor forwards. With GRPCTrustAMR the bridge passes the amr
// and the recovery email the token names, so once the owner removes the
// address the session's account security changes are refused, in ttl mode,
// where nothing else ends its token. Without it the bridge cannot tell, and
// in a project whose recovery emails sign in every session is taken for a
// recovery session that cannot name its address.
func TestGRPCBridge_ARemovedRecoveryEmailsSessionMakesNoSecurityChange(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{ // #nosec G101 -- passkey relying-party settings are public WebAuthn metadata.
		DefaultTenantID: "tenant", DefaultProjectID: config.DefaultProjectIDFallback,
		DefaultProjectAccessMode: service.AccessModeOpen, AuthAllowLocal: true, PasswordlessSignupEnabled: true,
		AllowedOrigins: "http://localhost:9002", JWTExpirySeconds: 900, RefreshExpirySeconds: 604800,
		LoginMaxFailedAttempts: 5, LoginLockoutSeconds: 900, LoginChallengeExpirySeconds: 300,
		PasskeyRPID: "localhost", PasskeyRPName: "Bridge test", PasskeyOrigin: "http://localhost:9002",
		PasskeyChallengeExpirySeconds: 300, RevocationMode: config.RevocationModeTTL,
	}
	repo := memory.New()
	inbox := &codeInbox{codes: map[string][]string{}}
	signer := jwttest.NewSigner(t, "bridge-recovery-test-key")
	pk, err := passkeys.NewWebAuthnService(passkeys.Config{RPID: "localhost", RPName: "Bridge test", Origin: "http://localhost:9002"})
	require.NoError(t, err)
	built, err := app.New(app.Deps{
		Config: cfg, Logger: zap.NewNop(), Signer: signer, Repo: repo, DB: repo, Passkeys: pk,
		TOTPKey: []byte("01234567890123456789012345678901"), TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		EmailTransport: inbox, ProjectResolver: recoverySignInProject{},
	})
	require.NoError(t, err)
	server := httptest.NewServer(built.Handler)
	t.Cleanup(server.Close)
	client := identityconnect.NewIdentityServiceClient(server.Client(), server.URL)

	// An emailed code signs the owner up and proves the address, which an
	// account needs before it keeps a recovery email.
	_, err = client.RequestEmailLoginCode(ctx, connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{Email: "owner@example.com"}))
	require.NoError(t, err)
	owner, err := client.VerifyEmailLoginCode(ctx, connect.NewRequest(&identitypb.VerifyEmailLoginCodeRequest{
		Email: "owner@example.com", Code: inbox.code(t, "owner@example.com", 0),
	}))
	require.NoError(t, err)
	_, err = client.RequestRecoveryEmail(ctx, bearerRequest(&identitypb.RequestRecoveryEmailRequest{Email: "spare@example.net"}, owner.Msg.AccessToken))
	require.NoError(t, err)
	_, err = client.VerifyRecoveryEmail(ctx, bearerRequest(&identitypb.VerifyRecoveryEmailRequest{
		Email: "spare@example.net", Code: inbox.code(t, "spare@example.net", 0),
	}, owner.Msg.AccessToken))
	require.NoError(t, err)
	_, err = client.RequestEmailLoginCode(ctx, connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{Email: "spare@example.net"}))
	require.NoError(t, err)
	recovery, err := client.VerifyEmailLoginCode(ctx, connect.NewRequest(&identitypb.VerifyEmailLoginCodeRequest{Email: "spare@example.net", Code: inbox.code(t, "spare@example.net", 1)}))
	require.NoError(t, err)
	claims, err := jwt.VerifyAccessToken(recovery.Msg.AccessToken, signer, "", "", false)
	require.NoError(t, err)
	require.NotEmpty(t, claims.RecoveryEmailID)

	// What a host interceptor that owns every sign-in key forwards from the
	// recovery session's verified token, in the project the session is in.
	forwarded := service.WithProjectScope(peerContext("198.51.100.4", metadata.Pairs(
		"x-authenticated-user-id", claims.Sub,
		"x-authenticated-auth-time", strconv.FormatInt(claims.AuthTime, 10),
		"x-authenticated-amr", "recovery_email",
		"x-authenticated-recovery-email-id", claims.RecoveryEmailID,
	)), &service.ProjectScope{
		ProjectID: "project-recovery", StorageScopeID: "tenant",
		Access:         service.ProjectAccessConfig{Mode: service.AccessModeOpen},
		RecoveryEmails: service.ProjectRecoveryEmailsConfig{Enabled: true, SignIn: true},
	})
	trusted := newGRPCBridge(built, zap.NewNop(), grpcTrust{authTime: true, amr: true})
	unvouched := newGRPCBridge(built, zap.NewNop(), grpcTrust{authTime: true})
	register := func(b *grpcBridge) error {
		_, err := b.BeginPasskeyRegistration(forwarded, &identitypb.BeginPasskeyRegistrationRequest{DeviceName: "Key"})
		return err
	}
	link := func(b *grpcBridge) error {
		_, err := b.LinkIdentity(forwarded, &identitypb.LinkIdentityRequest{Provider: "google", Code: "code", RedirectUri: "http://localhost:9002/cb"})
		return err
	}

	for name, change := range map[string]func(*grpcBridge) error{"BeginPasskeyRegistration": register, "LinkIdentity": link} {
		err := change(trusted)
		require.Equal(t, codes.FailedPrecondition, status.Code(err), "%s during the hold: %v", name, err)
		require.ErrorContains(t, err, "recovery_hold")
		err = change(unvouched)
		require.Equal(t, codes.FailedPrecondition, status.Code(err), "%s by an unvouched session: %v", name, err)
		require.ErrorContains(t, err, "recovery_session")
	}

	_, err = client.RemoveRecoveryEmail(ctx, bearerRequest(&identitypb.RemoveRecoveryEmailRequest{Email: "spare@example.net"}, owner.Msg.AccessToken))
	require.NoError(t, err)

	for name, change := range map[string]func(*grpcBridge) error{"BeginPasskeyRegistration": register, "LinkIdentity": link} {
		err := change(trusted)
		require.Equal(t, codes.Unauthenticated, status.Code(err), "%s after the address was removed: %v", name, err)
		err = change(unvouched)
		require.Equal(t, codes.FailedPrecondition, status.Code(err), "%s by an unvouched session after the removal: %v", name, err)
		require.ErrorContains(t, err, "recovery_session")
	}
}
