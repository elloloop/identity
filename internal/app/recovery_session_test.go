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

// recoveryDeployment is replicas of one deployment on one store, whose
// project lets recovery emails sign in: an owner signed in with a password,
// and a session the owner's recovery email opened.
type recoveryDeployment struct {
	repo                      *memory.Repo
	replicas                  []identityconnect.IdentityServiceClient
	ownerID                   string
	ownerToken, recoveryToken string
}

func newRecoveryDeployment(t *testing.T, cfg *config.Config, replicas int) *recoveryDeployment {
	t.Helper()
	ctx := context.Background()
	d := &recoveryDeployment{repo: memory.New()}
	mail := &codeMailbox{}
	signer := jwttest.NewSigner(t, "recovery-session-test-key")
	pk, err := passkeys.NewWebAuthnService(passkeys.Config{RPID: "localhost", RPName: "Identity test", Origin: "http://localhost:9002"})
	require.NoError(t, err)
	for range replicas {
		built, err := New(Deps{
			Config: cfg, Logger: zap.NewNop(), Signer: signer, Repo: d.repo, DB: d.repo, Passkeys: pk,
			TOTPKey: []byte("01234567890123456789012345678901"), TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
			EmailTransport: mail, ProjectResolver: recoveryProject{},
		})
		require.NoError(t, err)
		server := httptest.NewServer(built.Handler)
		t.Cleanup(server.Close)
		d.replicas = append(d.replicas, identityconnect.NewIdentityServiceClient(server.Client(), server.URL))
	}
	here := d.replicas[0]

	owner, err := here.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{Email: "owner@example.com", Password: "Offline-test-Password123!"}))
	require.NoError(t, err)
	d.ownerID, d.ownerToken = owner.Msg.User.Id, owner.Msg.AccessToken
	_, err = here.RequestRecoveryEmail(ctx, authed(&identitypb.RequestRecoveryEmailRequest{Email: "spare@example.net"}, d.ownerToken))
	require.NoError(t, err)
	_, err = here.VerifyRecoveryEmail(ctx, authed(&identitypb.VerifyRecoveryEmailRequest{Email: "spare@example.net", Code: mail.codeFor(t, "spare@example.net", 0)}, d.ownerToken))
	require.NoError(t, err)

	_, err = here.RequestEmailLoginCode(ctx, connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{Email: "spare@example.net"}))
	require.NoError(t, err)
	recovery, err := here.VerifyEmailLoginCode(ctx, connect.NewRequest(&identitypb.VerifyEmailLoginCodeRequest{Email: "spare@example.net", Code: mail.codeFor(t, "spare@example.net", 1)}))
	require.NoError(t, err)
	d.recoveryToken = recovery.Msg.AccessToken
	return d
}

// securityChangesRefused asserts that the recovery session makes none of
// the account security changes that would leave a way in behind, through
// client, and that the owner's session is not refused them.
func (d *recoveryDeployment) securityChangesRefused(t *testing.T, client identityconnect.IdentityServiceClient) {
	t.Helper()
	ctx := context.Background()
	_, err := client.BeginPasskeyRegistration(ctx, authed(&identitypb.BeginPasskeyRegistrationRequest{DeviceName: "Key"}, d.recoveryToken))
	require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "the removed address's session registers no passkey: %v", err)
	link := &identitypb.LinkIdentityRequest{Provider: "google", Code: "code", RedirectUri: "http://localhost:9002/cb"}
	_, err = client.LinkIdentity(ctx, authed(link, d.recoveryToken))
	require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "the removed address's session links no provider: %v", err)

	_, err = client.BeginPasskeyRegistration(ctx, authed(&identitypb.BeginPasskeyRegistrationRequest{DeviceName: "Key"}, d.ownerToken))
	require.NoError(t, err, "the owner's session is untouched")
	_, err = client.LinkIdentity(ctx, authed(link, d.ownerToken))
	require.NotEqual(t, connect.CodeUnauthenticated, connect.CodeOf(err), "the owner's session is not refused a link: %v", err)
}

// Under GATEWAY_REVOCATION_MODE=ttl, the default, nothing ends an access
// token before it expires, so the recovery session's token still
// authenticates once the owner removes the address. It makes no account
// security change, though: it names the address that opened it, which the
// account no longer holds.
func TestRecoveryEmailRemoval_InTTLModeTheTokenMakesNoSecurityChange(t *testing.T) {
	ctx := context.Background()
	cfg := newTestConfig()
	cfg.DefaultProjectID = config.DefaultProjectIDFallback
	cfg.RevocationMode = config.RevocationModeTTL
	d := newRecoveryDeployment(t, cfg, 1)
	client := d.replicas[0]

	_, err := client.RemoveRecoveryEmail(ctx, authed(&identitypb.RemoveRecoveryEmailRequest{Email: "spare@example.net"}, d.ownerToken))
	require.NoError(t, err)
	listed, err := client.ListRecoveryEmails(ctx, authed(&identitypb.ListRecoveryEmailsRequest{}, d.recoveryToken))
	require.NoError(t, err, "in ttl mode the token authenticates until it expires")
	require.Zero(t, listed.Msg.HoldUntil, "and no hold is left to stop it")
	d.securityChangesRefused(t, client)
}

// Under GATEWAY_REVOCATION_MODE=session, removing a recovery email ends the
// session it opened at once on the replica that removed it, its session
// cache warm and all. Another replica's cache passes the token until its
// TTL, but the session makes no account security change there: it names an
// address the account no longer holds, and the store says it has ended.
func TestRecoveryEmailRemoval_EndsItsSessionAtOnceOnThisReplicaAndHoldsItOnOthers(t *testing.T) {
	ctx := context.Background()
	cfg := newTestConfig()
	cfg.DefaultProjectID = config.DefaultProjectIDFallback
	cfg.RevocationMode = config.RevocationModeSession
	cfg.SessionCacheTTLSeconds = 60
	d := newRecoveryDeployment(t, cfg, 2)
	here, there := d.replicas[0], d.replicas[1]
	for _, client := range d.replicas {
		_, err := client.ListRecoveryEmails(ctx, authed(&identitypb.ListRecoveryEmailsRequest{}, d.recoveryToken))
		require.NoError(t, err, "the recovery session is live, and each replica's cache now holds it active")
	}

	_, err := here.RemoveRecoveryEmail(ctx, authed(&identitypb.RemoveRecoveryEmailRequest{Email: "spare@example.net"}, d.ownerToken))
	require.NoError(t, err)

	_, err = here.ListRecoveryEmails(ctx, authed(&identitypb.ListRecoveryEmailsRequest{}, d.recoveryToken))
	require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "the replica that removed the address refuses its session at once: %v", err)

	_, err = there.ListRecoveryEmails(ctx, authed(&identitypb.ListRecoveryEmailsRequest{}, d.recoveryToken))
	require.NoError(t, err, "another replica's cache passes the token until its TTL")
	d.securityChangesRefused(t, there)
}
