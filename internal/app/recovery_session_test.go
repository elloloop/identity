package app

import (
	"context"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnect "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// recoveryProject resolves every request to one project whose recovery
// emails sign in.
type recoveryProject struct{}

func (recoveryProject) ResolveByCredential(context.Context, string) (*service.ResolvedProject, error) {
	return nil, nil
}

func (recoveryProject) ResolveByHostname(context.Context, string) (*service.ResolvedProject, error) {
	return &service.ResolvedProject{
		ID:             "project-recovery",
		StorageScopeID: "tenant",
		Access:         service.ProjectAccessConfig{Mode: service.AccessModeOpen},
		RecoveryEmails: service.ProjectRecoveryEmailsConfig{Enabled: true, SignIn: true},
	}, nil
}

// codeMailbox keeps every message sent, for a test to read the codes in.
type codeMailbox struct {
	mu   sync.Mutex
	sent []email.Message
}

func (m *codeMailbox) Send(_ context.Context, msg email.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	return nil
}

var mailedCode = regexp.MustCompile(`\b\d{6}\b`)

// codeFor waits for the next code mailed to addr after the first skip
// messages to it.
func (m *codeMailbox) codeFor(t *testing.T, addr string, skip int) string {
	t.Helper()
	var code string
	require.Eventually(t, func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		seen := 0
		for _, msg := range m.sent {
			if msg.To != addr {
				continue
			}
			if seen++; seen > skip {
				if code = mailedCode.FindString(msg.Text); code != "" {
					return true
				}
			}
		}
		return false
	}, 5*time.Second, 10*time.Millisecond, "no code was mailed to %s", addr)
	return code
}

func authed[T any](msg *T, token string) *connect.Request[T] {
	req := connect.NewRequest(msg)
	req.Header().Set("Authorization", "Bearer "+token)
	return req
}

// Under GATEWAY_REVOCATION_MODE=session, removing a recovery email ends the
// session it opened at once on the replica that removed it, its session
// cache warm and all. Another replica's cache passes the token until its
// TTL, but the session can make no account security change there: the store
// says it has ended, and no hold stands in the way any more.
func TestRecoveryEmailRemoval_EndsItsSessionAtOnceOnThisReplicaAndHoldsItOnOthers(t *testing.T) {
	ctx := context.Background()
	cfg := newTestConfig()
	cfg.DefaultProjectID = config.DefaultProjectIDFallback
	cfg.RevocationMode = config.RevocationModeSession
	cfg.SessionCacheTTLSeconds = 60
	repo := memory.New()
	mail := &codeMailbox{}
	signer := jwttest.NewSigner(t, "recovery-session-test-key")
	pk, err := passkeys.NewWebAuthnService(passkeys.Config{RPID: "localhost", RPName: "Identity test", Origin: "http://localhost:9002"})
	require.NoError(t, err)
	replica := func() identityconnect.IdentityServiceClient {
		built, err := New(Deps{
			Config: cfg, Logger: zap.NewNop(), Signer: signer, Repo: repo, DB: repo, Passkeys: pk,
			TOTPKey: []byte("01234567890123456789012345678901"), TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
			EmailTransport: mail, ProjectResolver: recoveryProject{},
		})
		require.NoError(t, err)
		server := httptest.NewServer(built.Handler)
		t.Cleanup(server.Close)
		return identityconnect.NewIdentityServiceClient(server.Client(), server.URL)
	}
	here, there := replica(), replica()

	owner, err := here.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{Email: "owner@example.com", Password: "Offline-test-Password123!"}))
	require.NoError(t, err)
	ownerToken := owner.Msg.AccessToken
	_, err = here.RequestRecoveryEmail(ctx, authed(&identitypb.RequestRecoveryEmailRequest{Email: "spare@example.net"}, ownerToken))
	require.NoError(t, err)
	_, err = here.VerifyRecoveryEmail(ctx, authed(&identitypb.VerifyRecoveryEmailRequest{Email: "spare@example.net", Code: mail.codeFor(t, "spare@example.net", 0)}, ownerToken))
	require.NoError(t, err)

	_, err = here.RequestEmailLoginCode(ctx, connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{Email: "spare@example.net"}))
	require.NoError(t, err)
	recovery, err := here.VerifyEmailLoginCode(ctx, connect.NewRequest(&identitypb.VerifyEmailLoginCodeRequest{Email: "spare@example.net", Code: mail.codeFor(t, "spare@example.net", 1)}))
	require.NoError(t, err)
	recoveryToken := recovery.Msg.AccessToken
	for _, client := range []identityconnect.IdentityServiceClient{here, there} {
		_, err = client.ListRecoveryEmails(ctx, authed(&identitypb.ListRecoveryEmailsRequest{}, recoveryToken))
		require.NoError(t, err, "the recovery session is live, and each replica's cache now holds it active")
	}

	_, err = here.RemoveRecoveryEmail(ctx, authed(&identitypb.RemoveRecoveryEmailRequest{Email: "spare@example.net"}, ownerToken))
	require.NoError(t, err)

	_, err = here.ListRecoveryEmails(ctx, authed(&identitypb.ListRecoveryEmailsRequest{}, recoveryToken))
	require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "the replica that removed the address refuses its session at once: %v", err)

	_, err = there.ListRecoveryEmails(ctx, authed(&identitypb.ListRecoveryEmailsRequest{}, recoveryToken))
	require.NoError(t, err, "another replica's cache passes the token until its TTL")
	_, err = there.BeginPasskeyRegistration(ctx, authed(&identitypb.BeginPasskeyRegistrationRequest{DeviceName: "Key"}, recoveryToken))
	require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "but makes no account security change there: %v", err)
	_, err = there.BeginPasskeyRegistration(ctx, authed(&identitypb.BeginPasskeyRegistrationRequest{DeviceName: "Key"}, ownerToken))
	require.NoError(t, err, "the owner's session is untouched")
}
