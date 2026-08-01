package connect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"go.uber.org/zap"

	identityconnect "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/assurance"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passkeys"
)

// anonHarness serves the handler behind a middleware that stamps a project
// scope on every request, the way the real project-resolution middleware
// does. The stock harness injects no scope, and anonymous sign-in reads its
// switch off the scope — so without this every call would simply be denied
// and the tests would prove nothing.
type anonHarness struct {
	repo   *fakeRepo
	auth   *service.AuthService
	cfg    *config.Config
	client identityconnect.IdentityServiceClient
}

func newAnonHarness(t *testing.T, enabled bool, mode string, mutate func(*config.Config)) *anonHarness {
	t.Helper()

	repo := newFakeRepo()
	db := newFakeDB()
	cfg := testConfig()
	if mutate != nil {
		mutate(cfg)
	}
	kr := testKeyRing(t)

	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID: cfg.PasskeyRPID, RPName: cfg.PasskeyRPName, Origin: cfg.PasskeyOrigin,
	})
	if err != nil {
		t.Fatalf("passkey svc: %v", err)
	}
	auditLog := audit.NewLogger(nil, "test", zap.NewNop())
	authSvc := service.NewAuthServiceWithOAuth(repo, cfg, kr, pkSvc, auditLog,
		[]byte("01234567890123456789012345678901"),
		[]byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		nil, nil, zap.NewNop(), nil)
	if cfg.AssuranceEnabled {
		// A web arm that always fails, so "assurance required" is provably
		// enforced rather than trivially satisfied.
		authSvc.WithAssurance(
			service.NewAssuranceResolver(cfg.DefaultProjectID, service.AssuranceProviders{}, nil, nil),
			&fakeVerifier{err: assurance.ErrVerificationFailed},
		)
	}
	adminSvc := service.NewAdminService(repo, db, cfg.DefaultTenantID, auditLog, cfg, nil, zap.NewNop())
	groupSvc := service.NewGroupService(db, cfg.DefaultTenantID, auditLog, zap.NewNop())
	helpSvc := service.NewHelpService(db, cfg.DefaultTenantID, auditLog, zap.NewNop())
	profSvc := service.NewProfileService(repo, db, cfg.DefaultTenantID, auditLog, zap.NewNop())

	h := NewIdentityHandler(authSvc, adminSvc, groupSvc, helpSvc, profSvc, nil, nil, nil, nil, cfg)

	path, handler := identityconnect.NewIdentityServiceHandler(h)
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := service.WithProjectScope(r.Context(), &service.ProjectScope{
			ProjectID: cfg.DefaultProjectID,
			Access:    service.ProjectAccessConfig{Mode: mode},
			Anonymous: service.ProjectAnonymousConfig{Enabled: enabled},
		})
		handler.ServeHTTP(w, r.WithContext(ctx))
	}))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &anonHarness{
		repo:   repo,
		auth:   authSvc,
		cfg:    cfg,
		client: identityconnect.NewIdentityServiceClient(srv.Client(), srv.URL),
	}
}

func TestSignInAnonymously_Wire(t *testing.T) {
	// mode=closed on purpose: over the wire, exactly as at the service
	// layer, the access mode must not gate an anonymous session.
	h := newAnonHarness(t, true, service.AccessModeClosed, nil)

	res, err := h.client.SignInAnonymously(context.Background(),
		connect.NewRequest(&identitypb.SignInAnonymouslyRequest{}))
	if err != nil {
		t.Fatalf("SignInAnonymously: %v", err)
	}
	msg := res.Msg
	if msg.GetUser() == nil || !msg.GetUser().GetIsAnonymous() {
		t.Fatalf("user = %#v, want is_anonymous on the wire", msg.GetUser())
	}
	if msg.GetUser().GetEmail() != "" {
		t.Errorf("email = %q, want empty", msg.GetUser().GetEmail())
	}
	if msg.GetAccessToken() == "" || msg.GetRefreshToken() == "" {
		t.Error("response is missing a token pair")
	}
	if msg.GetExpiresIn() <= 0 {
		t.Errorf("expires_in = %d, want the access-token lifetime", msg.GetExpiresIn())
	}
}

func TestSignInAnonymously_WireDisabledIsUnimplemented(t *testing.T) {
	h := newAnonHarness(t, false, service.AccessModeOpen, nil)

	_, err := h.client.SignInAnonymously(context.Background(),
		connect.NewRequest(&identitypb.SignInAnonymouslyRequest{}))
	if got := connect.CodeOf(err); got != connect.CodeUnimplemented {
		t.Fatalf("code = %v, want Unimplemented (the capability is absent, not refused for this caller)", got)
	}
}

// With GATEWAY_ANONYMOUS_REQUIRE_ASSURANCE on, the endpoint must refuse a
// caller carrying no assurance token. This is the anti-abuse control for
// what is otherwise an unauthenticated account-creation primitive.
func TestSignInAnonymously_WireRequiresAssurance(t *testing.T) {
	h := newAnonHarness(t, true, service.AccessModeOpen, func(c *config.Config) {
		c.AssuranceEnabled = true
		c.AnonymousRequireAssurance = true
		c.AssuranceWebProvider = config.AssuranceWebProviderTurnstile
	})

	_, err := h.client.SignInAnonymously(context.Background(),
		connect.NewRequest(&identitypb.SignInAnonymouslyRequest{}))
	if got := connect.CodeOf(err); got != connect.CodePermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied for a missing assurance token", got)
	}

	// And no account may have been created by the refused call.
	if u, _ := h.repo.FindUserByEmail(context.Background(), ""); u != nil {
		t.Error("an account was created despite the assurance denial")
	}
}

// The toggle must be honoured in both directions: with it off, the same
// deployment (assurance enabled globally) still admits an unassured caller.
func TestSignInAnonymously_WireAssuranceOffAdmits(t *testing.T) {
	h := newAnonHarness(t, true, service.AccessModeOpen, func(c *config.Config) {
		c.AssuranceEnabled = true
		c.AnonymousRequireAssurance = false
		c.AssuranceWebProvider = config.AssuranceWebProviderTurnstile
	})

	if _, err := h.client.SignInAnonymously(context.Background(),
		connect.NewRequest(&identitypb.SignInAnonymouslyRequest{})); err != nil {
		t.Fatalf("assurance not required, yet the call was refused: %v", err)
	}
}

func TestUpgradeAnonymousAccount_WireRequiresAuthentication(t *testing.T) {
	h := newAnonHarness(t, true, service.AccessModeOpen, nil)

	req := connect.NewRequest(&identitypb.UpgradeAnonymousAccountRequest{
		Credential: &identitypb.UpgradeAnonymousAccountRequest_Password{
			Password: &identitypb.PasswordCredential{
				Email: "someone@example.com", Password: strongPW,
			},
		},
	})
	// No X-Authenticated-User-Id header: the account is taken from the
	// access token, never from the body, so an unauthenticated call has
	// nothing to upgrade.
	_, err := h.client.UpgradeAnonymousAccount(context.Background(), req)
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", got)
	}
}

func TestUpgradeAnonymousAccount_Wire(t *testing.T) {
	h := newAnonHarness(t, true, service.AccessModeOpen, nil)

	signIn, err := h.client.SignInAnonymously(context.Background(),
		connect.NewRequest(&identitypb.SignInAnonymouslyRequest{}))
	if err != nil {
		t.Fatalf("SignInAnonymously: %v", err)
	}
	anonID := signIn.Msg.GetUser().GetId()

	req := connect.NewRequest(&identitypb.UpgradeAnonymousAccountRequest{
		Credential: &identitypb.UpgradeAnonymousAccountRequest_Password{
			Password: &identitypb.PasswordCredential{
				Email: "upgraded@example.com", Password: strongPW, Name: "Up Graded",
			},
		},
	})
	req.Header().Set(authUserHeader, anonID)

	res, err := h.client.UpgradeAnonymousAccount(context.Background(), req)
	if err != nil {
		t.Fatalf("UpgradeAnonymousAccount: %v", err)
	}
	got := res.Msg.GetUser()
	if got.GetId() != anonID {
		t.Fatalf("upgrade changed the id on the wire: %q -> %q", anonID, got.GetId())
	}
	if got.GetIsAnonymous() {
		t.Error("is_anonymous is still true on the wire after the upgrade")
	}
	if got.GetEmail() != "upgraded@example.com" {
		t.Errorf("email = %q", got.GetEmail())
	}
	if res.Msg.GetAccessToken() == "" || res.Msg.GetRefreshToken() == "" {
		t.Error("upgrade must reissue a token pair — the old one still claims anonymity")
	}
}

func TestUpgradeAnonymousAccount_WireRejectsAnEmptyCredential(t *testing.T) {
	h := newAnonHarness(t, true, service.AccessModeOpen, nil)

	signIn, err := h.client.SignInAnonymously(context.Background(),
		connect.NewRequest(&identitypb.SignInAnonymouslyRequest{}))
	if err != nil {
		t.Fatalf("SignInAnonymously: %v", err)
	}
	anonID := signIn.Msg.GetUser().GetId()

	// A oneof with nothing set. Treating it as a no-op upgrade would clear
	// is_anonymous and leave an account with NO credential — unreachable and
	// out of the retention sweep's reach, i.e. a permanent orphan row.
	req := connect.NewRequest(&identitypb.UpgradeAnonymousAccountRequest{})
	req.Header().Set(authUserHeader, anonID)

	if _, err := h.client.UpgradeAnonymousAccount(context.Background(), req); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", connect.CodeOf(err))
	}

	after, err := h.repo.GetUser(context.Background(), anonID)
	if err != nil || after == nil {
		t.Fatalf("GetUser = (%#v, %v)", after, err)
	}
	if !after.IsAnonymous {
		t.Fatal("an empty-credential upgrade cleared is_anonymous, orphaning the account")
	}
}

func TestUpgradeAnonymousAccount_WireNonAnonymousIsFailedPrecondition(t *testing.T) {
	h := newAnonHarness(t, true, service.AccessModeOpen, nil)

	permanent := h.repo.seedUser(&service.User{
		Email: "permanent@example.com", Status: "active", Role: "member",
	})
	req := connect.NewRequest(&identitypb.UpgradeAnonymousAccountRequest{
		Credential: &identitypb.UpgradeAnonymousAccountRequest_Password{
			Password: &identitypb.PasswordCredential{Email: "new@example.com", Password: strongPW},
		},
	})
	req.Header().Set(authUserHeader, permanent.ID)

	// The request is well-formed; the account is simply in the wrong state.
	if _, err := h.client.UpgradeAnonymousAccount(context.Background(), req); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", connect.CodeOf(err))
	}
}
