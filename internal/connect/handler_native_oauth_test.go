package connect

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnect "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/oauth"
	"github.com/elloloop/identity/pkg/passkeys"
)

const nativeHandlerGoogleAud = "web-client.apps.googleusercontent.com"

// nativeHandlerSigner is an RSA key + stub JWKS endpoint to mint Google ID
// tokens accepted by the verifier the handler harness wires.
type nativeHandlerSigner struct {
	priv *rsa.PrivateKey
	kid  string
	url  string
	now  time.Time
}

func newNativeHandlerSigner(t *testing.T) *nativeHandlerSigner {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub, err := jwk.FromRaw(priv.Public())
	require.NoError(t, err)
	const kid = "native-handler-kid"
	require.NoError(t, pub.Set(jwk.KeyIDKey, kid))
	require.NoError(t, pub.Set(jwk.AlgorithmKey, jwa.RS256))
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pub))
	body, err := json.Marshal(set)
	require.NoError(t, err)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return &nativeHandlerSigner{priv: priv, kid: kid, url: srv.URL, now: time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)}
}

func (s *nativeHandlerSigner) googleToken(t *testing.T, sub, email string) string {
	t.Helper()
	tok := jwt.New()
	_ = tok.Set(jwt.IssuerKey, "https://accounts.google.com")
	_ = tok.Set(jwt.SubjectKey, sub)
	_ = tok.Set(jwt.AudienceKey, nativeHandlerGoogleAud)
	_ = tok.Set(jwt.ExpirationKey, s.now.Add(time.Hour))
	_ = tok.Set(jwt.IssuedAtKey, s.now)
	_ = tok.Set("email", email)
	_ = tok.Set("email_verified", true)
	_ = tok.Set("name", "Handler User")
	signKey, err := jwk.FromRaw(s.priv)
	require.NoError(t, err)
	require.NoError(t, signKey.Set(jwk.KeyIDKey, s.kid))
	require.NoError(t, signKey.Set(jwk.AlgorithmKey, jwa.RS256))
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, signKey))
	require.NoError(t, err)
	return string(signed)
}

// newNativeHarness builds a Connect handler stack with native OAuth wired,
// using the given signer's stub JWKS. enabled toggles GATEWAY_NATIVE_OAUTH.
func newNativeHarness(t *testing.T, signer *nativeHandlerSigner, enabled bool) *testHarness {
	t.Helper()
	repo := newFakeRepo()
	db := newFakeDB()
	cfg := testConfig()
	cfg.DefaultProjectID = "proj-default"
	// Open the default project so this native-OAuth handler test exercises the
	// RPC wiring, not the access gate (which has its own tests). Under
	// default-DENY the mode must be set explicitly.
	cfg.DefaultProjectAccessMode = service.AccessModeOpen
	cfg.NativeOAuthEnabled = enabled
	cfg.NativeOAuthGoogleAudiences = nativeHandlerGoogleAud
	cfg.NativeOAuthProductProjects = "easyloops=proj-default"
	kr := testKeyRing(t)

	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{RPID: cfg.PasskeyRPID, RPName: cfg.PasskeyRPName, Origin: cfg.PasskeyOrigin})
	require.NoError(t, err)
	auditLog := audit.NewLogger(nil, "test", zap.NewNop())
	totpKey := []byte("01234567890123456789012345678901")
	totpRecoveryPepper := []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH")

	var verifier *oauth.NativeVerifier
	if enabled {
		verifier = oauth.NewNativeVerifier(oauth.NativeVerifierConfig{
			GoogleJWKSURL: signer.url,
			Now:           func() time.Time { return signer.now },
		})
	}

	authSvc := service.NewAuthServiceWithOAuth(repo, cfg, kr, pkSvc, auditLog, totpKey, totpRecoveryPepper, nil, nil, zap.NewNop(), nil).
		WithNativeOAuth(verifier, nil) // nil project store: default-project only
	adminSvc := service.NewAdminService(repo, db, cfg.DefaultTenantID, auditLog, cfg, nil, zap.NewNop())
	groupSvc := service.NewGroupService(db, cfg.DefaultTenantID, auditLog, zap.NewNop())
	helpSvc := service.NewHelpService(db, cfg.DefaultTenantID, auditLog, zap.NewNop())
	profSvc := service.NewProfileService(repo, db, cfg.DefaultTenantID, auditLog, zap.NewNop())

	h := NewIdentityHandler(authSvc, adminSvc, groupSvc, helpSvc, profSvc, nil, nil, nil, nil, cfg)
	mux := http.NewServeMux()
	path, handler := identityconnect.NewIdentityServiceHandler(h)
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &testHarness{
		repo: repo, db: db, auth: authSvc, admin: adminSvc, groups: groupSvc,
		help: helpSvc, prof: profSvc, cfg: cfg, server: srv,
		client: identityconnect.NewIdentityServiceClient(srv.Client(), srv.URL),
	}
}

func TestHandler_NativeOAuthLogin_Google_Success(t *testing.T) {
	signer := newNativeHandlerSigner(t)
	h := newNativeHarness(t, signer, true)

	tok := signer.googleToken(t, "handler-sub-1", "handler@example.com")
	// No Bearer/auth header is attached: the handler does not require one.
	resp, err := h.client.NativeOAuthLogin(context.Background(), connect.NewRequest(&identitypb.NativeOAuthLoginRequest{
		Provider: "google",
		IdToken:  tok,
		Product:  "easyloops",
	}))
	require.NoError(t, err)
	require.NotNil(t, resp.Msg)
	assert.NotEmpty(t, resp.Msg.AccessToken)
	assert.NotEmpty(t, resp.Msg.RefreshToken)
	require.NotNil(t, resp.Msg.User)
	assert.Equal(t, "handler@example.com", resp.Msg.User.Email)
	assert.Greater(t, resp.Msg.ExpiresIn, int32(0))
}

func TestHandler_NativeOAuthLogin_Disabled_FailedPrecondition(t *testing.T) {
	signer := newNativeHandlerSigner(t)
	h := newNativeHarness(t, signer, false)

	tok := signer.googleToken(t, "s", "u@example.com")
	_, err := h.client.NativeOAuthLogin(context.Background(), connect.NewRequest(&identitypb.NativeOAuthLoginRequest{
		Provider: "google", IdToken: tok, Product: "easyloops",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeFailedPrecondition, connectCodeOf(err))
}

func TestHandler_NativeOAuthLogin_BadToken_Unauthenticated(t *testing.T) {
	signer := newNativeHandlerSigner(t)
	h := newNativeHarness(t, signer, true)

	_, err := h.client.NativeOAuthLogin(context.Background(), connect.NewRequest(&identitypb.NativeOAuthLoginRequest{
		Provider: "google", IdToken: "not-a-jwt", Product: "easyloops",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connectCodeOf(err))
}

func TestHandler_NativeOAuthLogin_UnknownProduct_InvalidArgument(t *testing.T) {
	signer := newNativeHandlerSigner(t)
	h := newNativeHarness(t, signer, true)

	tok := signer.googleToken(t, "s", "u@example.com")
	_, err := h.client.NativeOAuthLogin(context.Background(), connect.NewRequest(&identitypb.NativeOAuthLoginRequest{
		Provider: "google", IdToken: tok, Product: "no-such-product",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connectCodeOf(err))
}
