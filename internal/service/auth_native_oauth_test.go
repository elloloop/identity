package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/oauth"
	"github.com/elloloop/identity/pkg/passkeys"
)

// nativeTokenSigner is an RSA key + stub JWKS endpoint a native test uses to
// mint provider ID tokens the NativeVerifier will accept.
type nativeTokenSigner struct {
	priv *rsa.PrivateKey
	kid  string
	url  string
	now  time.Time
}

func newNativeTokenSigner(t *testing.T) *nativeTokenSigner {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub, err := jwk.FromRaw(priv.Public())
	require.NoError(t, err)
	const kid = "native-svc-kid"
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
	return &nativeTokenSigner{priv: priv, kid: kid, url: srv.URL, now: time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)}
}

func (s *nativeTokenSigner) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	tok := jwt.New()
	for k, v := range claims {
		switch k {
		case "iss":
			_ = tok.Set(jwt.IssuerKey, v)
		case "sub":
			_ = tok.Set(jwt.SubjectKey, v)
		case "aud":
			_ = tok.Set(jwt.AudienceKey, v)
		case "exp":
			_ = tok.Set(jwt.ExpirationKey, v)
		case "iat":
			_ = tok.Set(jwt.IssuedAtKey, v)
		default:
			_ = tok.Set(k, v)
		}
	}
	signKey, err := jwk.FromRaw(s.priv)
	require.NoError(t, err)
	require.NoError(t, signKey.Set(jwk.KeyIDKey, s.kid))
	require.NoError(t, signKey.Set(jwk.AlgorithmKey, jwa.RS256))
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, signKey))
	require.NoError(t, err)
	return string(signed)
}

func (s *nativeTokenSigner) googleToken(t *testing.T, sub, email, aud string) string {
	t.Helper()
	return s.sign(t, map[string]any{
		"iss": "https://accounts.google.com", "sub": sub, "aud": aud,
		"exp": s.now.Add(time.Hour), "iat": s.now,
		"email": email, "email_verified": true, "name": "Native User",
	})
}

func nativeNonceHex(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// fakeNativeProjects is a stub NativeOAuthProjectStore mapping known ids to
// active projects. When err is set, ActiveProjectByID returns it (simulating
// an infrastructure failure).
type fakeNativeProjects struct {
	active map[string]string // id -> storage scope
	err    error
}

func (f *fakeNativeProjects) ActiveProjectByID(_ context.Context, id string) (*AdminProject, error) {
	if f.err != nil {
		return nil, f.err
	}
	scope, ok := f.active[id]
	if !ok {
		return nil, nil
	}
	return &AdminProject{ID: id, StorageScopeID: scope, Name: id}, nil
}

const (
	nativeGoogleAud = "web-client.apps.googleusercontent.com"
	nativeAppleAud  = "dev.easyloops.app"
)

func newNativeTestAuthService(t *testing.T, repo *fakeRepo, signer *nativeTokenSigner, projects NativeOAuthProjectStore, mutate func(*config.Config)) *AuthService {
	t.Helper()
	cfg := testConfig()
	cfg.DefaultProjectID = "proj-default"
	cfg.NativeOAuthEnabled = true
	cfg.NativeOAuthGoogleAudiences = nativeGoogleAud
	cfg.NativeOAuthAppleAudiences = nativeAppleAud
	cfg.NativeOAuthProductProjects = "easyloops=proj-easyloops,tortoise=proj-tortoise"
	if mutate != nil {
		mutate(cfg)
	}
	kr := testKeyRing(t)
	pkSvc, _ := passkeys.NewWebAuthnService(passkeys.Config{RPID: cfg.PasskeyRPID, RPName: cfg.PasskeyRPName, Origin: cfg.PasskeyOrigin})

	verifier := oauth.NewNativeVerifier(oauth.NativeVerifierConfig{
		GoogleAudiences: cfg.NativeOAuthGoogleAudienceList(),
		AppleAudiences:  cfg.NativeOAuthAppleAudienceList(),
		GoogleJWKSURL:   signer.url,
		AppleJWKSURL:    signer.url,
		Now:             func() time.Time { return signer.now },
	})

	svc := NewAuthServiceWithOAuth(
		repo, cfg, kr, pkSvc,
		audit.NewLogger(nil, "test", nil),
		testTotpKey(), testTotpRecoveryPepper(), email.NewLogOnly(zap.NewNop()), nil, zap.NewNop(),
		nil,
	).WithNativeOAuth(verifier, projects)
	return svc
}

func defaultNativeProjects() *fakeNativeProjects {
	return &fakeNativeProjects{active: map[string]string{
		"proj-default":   "scope-default",
		"proj-easyloops": "scope-easyloops",
		"proj-tortoise":  "scope-tortoise",
	}}
}

func TestNativeOAuthLogin_Google_NewUser(t *testing.T) {
	repo := newFakeRepo()
	signer := newNativeTokenSigner(t)
	svc := newNativeTestAuthService(t, repo, signer, defaultNativeProjects(), nil)

	tok := signer.googleToken(t, "g-sub-1", "newuser@example.com", nativeGoogleAud)
	res, err := svc.NativeOAuthLogin(context.Background(), NativeOAuthLoginParams{
		Provider: "google", IDToken: tok, Product: "easyloops",
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.NotEmpty(t, res.AccessToken)
	assert.NotEmpty(t, res.RefreshToken)
	require.NotNil(t, res.User)
	assert.Equal(t, "newuser@example.com", res.User.Email)
	assert.True(t, res.User.EmailVerified)
}

func TestNativeOAuthLogin_Google_LinksExistingEmail(t *testing.T) {
	repo := newFakeRepo()
	// Pre-existing user with the same email but no oauth identity.
	_, err := repo.CreateUser(context.Background(), &User{Email: "existing@example.com", Name: "Existing"})
	require.NoError(t, err)

	signer := newNativeTokenSigner(t)
	svc := newNativeTestAuthService(t, repo, signer, defaultNativeProjects(), nil)

	tok := signer.googleToken(t, "g-sub-existing", "existing@example.com", nativeGoogleAud)
	res, err := svc.NativeOAuthLogin(context.Background(), NativeOAuthLoginParams{
		Provider: "google", IDToken: tok, Product: "tortoise",
	})
	require.NoError(t, err)
	require.NotNil(t, res.User)
	assert.Equal(t, "existing@example.com", res.User.Email)

	// The provider identity is now linked to the existing user.
	linked, err := repo.FindUserByProviderID(context.Background(), "google", "g-sub-existing")
	require.NoError(t, err)
	require.NotNil(t, linked)
	assert.Equal(t, res.User.ID, linked.ID)
}

func TestNativeOAuthLogin_Apple_WithNonce(t *testing.T) {
	repo := newFakeRepo()
	signer := newNativeTokenSigner(t)
	svc := newNativeTestAuthService(t, repo, signer, defaultNativeProjects(), nil)

	const rawNonce = "client-raw-nonce"
	tok := signer.sign(t, map[string]any{
		"iss": "https://appleid.apple.com", "sub": "a-sub-1", "aud": nativeAppleAud,
		"exp": signer.now.Add(time.Hour), "iat": signer.now,
		"email": "apple@icloud.com", "email_verified": "true",
		"nonce": nativeNonceHex(rawNonce),
	})
	res, err := svc.NativeOAuthLogin(context.Background(), NativeOAuthLoginParams{
		Provider: "apple", IDToken: tok, Product: "easyloops", Nonce: rawNonce,
	})
	require.NoError(t, err)
	assert.Equal(t, "apple@icloud.com", res.User.Email)
}

func TestNativeOAuthLogin_Apple_NonceMismatch_Unauthenticated(t *testing.T) {
	repo := newFakeRepo()
	signer := newNativeTokenSigner(t)
	svc := newNativeTestAuthService(t, repo, signer, defaultNativeProjects(), nil)

	tok := signer.sign(t, map[string]any{
		"iss": "https://appleid.apple.com", "sub": "a-sub-2", "aud": nativeAppleAud,
		"exp": signer.now.Add(time.Hour), "iat": signer.now,
		"email": "apple@icloud.com", "email_verified": true,
		"nonce": nativeNonceHex("a-different-nonce"),
	})
	_, err := svc.NativeOAuthLogin(context.Background(), NativeOAuthLoginParams{
		Provider: "apple", IDToken: tok, Product: "easyloops", Nonce: "expected-nonce",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated), "got %v", err)
}

func TestNativeOAuthLogin_WrongAud_Unauthenticated(t *testing.T) {
	repo := newFakeRepo()
	signer := newNativeTokenSigner(t)
	svc := newNativeTestAuthService(t, repo, signer, defaultNativeProjects(), nil)

	tok := signer.googleToken(t, "g-sub-x", "u@example.com", "some-other-client")
	_, err := svc.NativeOAuthLogin(context.Background(), NativeOAuthLoginParams{
		Provider: "google", IDToken: tok, Product: "easyloops",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthenticated), "got %v", err)
}

func TestNativeOAuthLogin_Disabled_FailedPrecondition(t *testing.T) {
	repo := newFakeRepo()
	signer := newNativeTokenSigner(t)
	svc := newNativeTestAuthService(t, repo, signer, defaultNativeProjects(), func(c *config.Config) {
		c.NativeOAuthEnabled = false
	})

	tok := signer.googleToken(t, "g", "u@example.com", nativeGoogleAud)
	_, err := svc.NativeOAuthLogin(context.Background(), NativeOAuthLoginParams{
		Provider: "google", IDToken: tok, Product: "easyloops",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNativeOAuthDisabled), "got %v", err)
}

func TestNativeOAuthLogin_UnsupportedProvider_InvalidArgument(t *testing.T) {
	repo := newFakeRepo()
	signer := newNativeTokenSigner(t)
	svc := newNativeTestAuthService(t, repo, signer, defaultNativeProjects(), nil)

	_, err := svc.NativeOAuthLogin(context.Background(), NativeOAuthLoginParams{
		Provider: "microsoft", IDToken: "x", Product: "easyloops",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument), "got %v", err)
}

func TestNativeOAuthLogin_MissingIDToken_InvalidArgument(t *testing.T) {
	repo := newFakeRepo()
	signer := newNativeTokenSigner(t)
	svc := newNativeTestAuthService(t, repo, signer, defaultNativeProjects(), nil)

	_, err := svc.NativeOAuthLogin(context.Background(), NativeOAuthLoginParams{
		Provider: "google", IDToken: "  ", Product: "easyloops",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument), "got %v", err)
}

func TestNativeOAuthLogin_UnknownProduct_InvalidArgument(t *testing.T) {
	repo := newFakeRepo()
	signer := newNativeTokenSigner(t)
	svc := newNativeTestAuthService(t, repo, signer, defaultNativeProjects(), nil)

	tok := signer.googleToken(t, "g", "u@example.com", nativeGoogleAud)
	_, err := svc.NativeOAuthLogin(context.Background(), NativeOAuthLoginParams{
		Provider: "google", IDToken: tok, Product: "does-not-exist",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument), "got %v", err)
}

func TestNativeOAuthLogin_ProductFallsBackToProjectID(t *testing.T) {
	repo := newFakeRepo()
	signer := newNativeTokenSigner(t)
	// "proj-tortoise" is not a mapped product key, but it is a real project id;
	// the resolver should fall back to treating the product string as the id.
	svc := newNativeTestAuthService(t, repo, signer, defaultNativeProjects(), nil)

	tok := signer.googleToken(t, "g-fb", "fb@example.com", nativeGoogleAud)
	res, err := svc.NativeOAuthLogin(context.Background(), NativeOAuthLoginParams{
		Provider: "google", IDToken: tok, Product: "proj-tortoise",
	})
	require.NoError(t, err)
	assert.Equal(t, "fb@example.com", res.User.Email)
}

func TestNativeOAuthLogin_TotpRequired_ReturnsSecondFactorChallenge(t *testing.T) {
	repo := newFakeRepo()
	// Pre-existing TOTP-enrolled user with the provider email.
	_, err := repo.CreateUser(context.Background(), &User{
		Email: "totp@example.com", Name: "Totp", TotpRequired: true,
	})
	require.NoError(t, err)

	signer := newNativeTokenSigner(t)
	svc := newNativeTestAuthService(t, repo, signer, defaultNativeProjects(), nil)

	tok := signer.googleToken(t, "g-totp", "totp@example.com", nativeGoogleAud)
	res, err := svc.NativeOAuthLogin(context.Background(), NativeOAuthLoginParams{
		Provider: "google", IDToken: tok, Product: "easyloops",
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.True(t, res.TotpRequired, "second factor should be required")
	assert.NotEmpty(t, res.LoginChallengeID)
	assert.Empty(t, res.AccessToken, "no access token until 2FA completes")
}

func TestNativeOAuthLogin_EmptyProduct_InvalidArgument(t *testing.T) {
	repo := newFakeRepo()
	signer := newNativeTokenSigner(t)
	svc := newNativeTestAuthService(t, repo, signer, defaultNativeProjects(), nil)

	tok := signer.googleToken(t, "g", "u@example.com", nativeGoogleAud)
	_, err := svc.NativeOAuthLogin(context.Background(), NativeOAuthLoginParams{
		Provider: "google", IDToken: tok, Product: "   ",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument), "got %v", err)
}

func TestNativeOAuthLogin_ProjectStoreError_NotInvalidArgument(t *testing.T) {
	repo := newFakeRepo()
	signer := newNativeTokenSigner(t)
	failing := &fakeNativeProjects{err: errors.New("db down")}
	svc := newNativeTestAuthService(t, repo, signer, failing, nil)

	tok := signer.googleToken(t, "g", "u@example.com", nativeGoogleAud)
	_, err := svc.NativeOAuthLogin(context.Background(), NativeOAuthLoginParams{
		Provider: "google", IDToken: tok, Product: "easyloops",
	})
	require.Error(t, err)
	// An infra failure must NOT be reported as a client InvalidArgument.
	assert.False(t, errors.Is(err, ErrInvalidArgument), "infra error leaked as InvalidArgument: %v", err)
}

func TestNativeOAuthLogin_UppercaseProjectIDFallback(t *testing.T) {
	repo := newFakeRepo()
	signer := newNativeTokenSigner(t)
	// A mixed-case project id reached via the implicit fallback (NOT in the
	// product map). It must be looked up verbatim, not lower-cased.
	projects := &fakeNativeProjects{active: map[string]string{
		"Proj-MixedCase": "scope-mixed",
	}}
	svc := newNativeTestAuthService(t, repo, signer, projects, func(c *config.Config) {
		c.NativeOAuthProductProjects = "" // force the direct project-id fallback
	})

	tok := signer.googleToken(t, "g-mixed", "mixed@example.com", nativeGoogleAud)
	res, err := svc.NativeOAuthLogin(context.Background(), NativeOAuthLoginParams{
		Provider: "google", IDToken: tok, Product: "Proj-MixedCase",
	})
	require.NoError(t, err, "verbatim mixed-case project id must resolve")
	assert.Equal(t, "mixed@example.com", res.User.Email)
}

func TestNativeOAuthLogin_NoControlPlane_OnlyDefaultProject(t *testing.T) {
	repo := newFakeRepo()
	signer := newNativeTokenSigner(t)
	// nil project store => no control plane. Map the product to the default
	// project id so it resolves; any other product is rejected.
	svc := newNativeTestAuthService(t, repo, signer, nil, func(c *config.Config) {
		c.NativeOAuthProductProjects = "easyloops=proj-default"
	})

	tok := signer.googleToken(t, "g-cp", "cp@example.com", nativeGoogleAud)
	res, err := svc.NativeOAuthLogin(context.Background(), NativeOAuthLoginParams{
		Provider: "google", IDToken: tok, Product: "easyloops",
	})
	require.NoError(t, err)
	assert.Equal(t, "cp@example.com", res.User.Email)

	// A product that resolves to a NON-default id is rejected without a control plane.
	tok2 := signer.googleToken(t, "g-cp2", "cp2@example.com", nativeGoogleAud)
	_, err = svc.NativeOAuthLogin(context.Background(), NativeOAuthLoginParams{
		Provider: "google", IDToken: tok2, Product: "tortoise",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidArgument), "got %v", err)
}
