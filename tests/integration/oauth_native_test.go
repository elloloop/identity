//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/oauth"
)

const (
	nativeITGoogleAud = "web-client.apps.googleusercontent.com"
	nativeITAppleAud  = "dev.easyloops.app"
	nativeITProject   = "test-project"
	nativeITAppleIss  = "https://appleid.apple.com"
)

// nativeITSigner is an RSA key + stub JWKS endpoint that mints provider ID
// tokens the injected NativeVerifier accepts.
type nativeITSigner struct {
	priv *rsa.PrivateKey
	kid  string
	url  string
	now  time.Time
}

func newNativeITSigner(t *testing.T) *nativeITSigner {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa generate: %v", err)
	}
	pub, err := jwk.FromRaw(priv.Public())
	if err != nil {
		t.Fatalf("jwk from raw: %v", err)
	}
	const kid = "native-it-kid"
	_ = pub.Set(jwk.KeyIDKey, kid)
	_ = pub.Set(jwk.AlgorithmKey, jwa.RS256)
	set := jwk.NewSet()
	_ = set.AddKey(pub)
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return &nativeITSigner{priv: priv, kid: kid, url: srv.URL, now: time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)}
}

func (s *nativeITSigner) sign(t *testing.T, claims map[string]any) string {
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
	// Stamp a unique jti unless the caller pinned one, so every minted token is a
	// DISTINCT issued token like the real world. Without it, two runs in the same
	// second produce byte-identical (provider|iss|sub|iat|aud|nonce) replay keys
	// and the replay cache (correctly) rejects the second run as a replay.
	if tok.JwtID() == "" {
		_ = tok.Set(jwt.JwtIDKey, newNativeITJTI(t))
	}
	signKey, err := jwk.FromRaw(s.priv)
	if err != nil {
		t.Fatalf("priv jwk: %v", err)
	}
	_ = signKey.Set(jwk.KeyIDKey, s.kid)
	_ = signKey.Set(jwk.AlgorithmKey, jwa.RS256)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, signKey))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return string(signed)
}

func (s *nativeITSigner) googleToken(t *testing.T, sub, email, aud string, exp time.Time) string {
	return s.sign(t, map[string]any{
		"iss": "https://accounts.google.com", "sub": sub, "aud": aud,
		"exp": exp, "iat": s.now, "email": email, "email_verified": true, "name": "IT User",
	})
}

func nativeITHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// newNativeITJTI returns a random JWT ID so each minted token is unique across
// runs, keeping the native happy-path tests idempotent against a persistent DB.
func newNativeITJTI(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand jti: %v", err)
	}
	return hex.EncodeToString(b[:])
}

// nativeITHarness boots the full server with native OAuth wired to the
// signer's mock JWKS. enabled toggles GATEWAY_NATIVE_OAUTH_ENABLED.
func nativeITHarness(t *testing.T, signer *nativeITSigner, enabled bool) *Harness {
	t.Helper()
	cfgFn := WithConfig(func(c *config.Config) {
		c.DefaultProjectID = nativeITProject
		c.NativeOAuthEnabled = enabled
		c.NativeOAuthGoogleAudiences = nativeITGoogleAud
		c.NativeOAuthAppleAudiences = nativeITAppleAud
		c.NativeOAuthMicrosoftAudiences = nativeITMicrosoftAud
		// Pin the default project's accepted Microsoft tenant via the env
		// allow-list so a multi-tenant token's email is trusted (nOAuth guard).
		c.MicrosoftAllowedTenants = nativeITMSTenant
		c.NativeOAuthProductProjects = "easyloops=" + nativeITProject
	})
	if !enabled {
		return StartServer(t, cfgFn)
	}
	verifier := oauth.NewNativeVerifier(oauth.NativeVerifierConfig{
		GoogleJWKSURL:    signer.url,
		AppleJWKSURL:     signer.url,
		MicrosoftJWKSURL: signer.url,
		Now:              func() time.Time { return signer.now },
	})
	// Memory driver: no control plane, so nativeProjects is nil and the product
	// must resolve to the default project, whose native audiences come from env.
	return StartServer(t, cfgFn, WithNativeOAuth(verifier, nil))
}

const (
	nativeITMicrosoftAud  = "ms-native-client"
	nativeITMSTenant      = "aaaabbbb-cccc-dddd-eeee-ffff00001111"
	nativeITPerProjAud    = "perproject-ios.apps.googleusercontent.com"
	nativeITMSIssuerFmt   = "https://login.microsoftonline.com/%s/v2.0"
	nativeITPerProjProdID = "perproject"
)

func (s *nativeITSigner) microsoftToken(t *testing.T, sub, email, aud, tid string) string {
	return s.sign(t, map[string]any{
		"iss": fmt.Sprintf(nativeITMSIssuerFmt, tid), "tid": tid, "aud": aud,
		"oid": sub, "exp": s.now.Add(time.Hour), "iat": s.now, "email": email, "name": "IT MS User",
	})
}

// fakeITProjects is a control-plane stub for the integration harness: it maps a
// product→project id to an active project carrying its own per-project OAuth
// config (native audiences / Microsoft issuer pinning), exercising the
// non-default-project isolation path end-to-end.
type fakeITProjects struct {
	active map[string]*service.AdminProject
}

func (f *fakeITProjects) ActiveProjectByID(_ context.Context, id string) (*service.AdminProject, error) {
	p, ok := f.active[id]
	if !ok {
		return nil, nil
	}
	cp := *p
	return &cp, nil
}

// nativeITPerProjectHarness boots the server with a control-plane stub that
// returns per-project config_json native audiences (and Microsoft issuer
// pinning), proving config_json drives verification and OVERRIDES the env seed.
// The stub resolves to the boot-seeded project id (the only projects(id) row the
// sqlite/memory data plane has), since the data-plane writes FK onto it — the
// non-default-project isolation itself is unit-covered in internal/service.
func nativeITPerProjectHarness(t *testing.T, signer *nativeITSigner) *Harness {
	t.Helper()
	cfgFn := WithConfig(func(c *config.Config) {
		c.DefaultProjectID = nativeITProject
		c.NativeOAuthEnabled = true
		// The env seed differs from the per-project audiences so the test proves
		// config_json wins and the env seed does NOT leak in when config is present.
		c.NativeOAuthGoogleAudiences = nativeITGoogleAud
		c.NativeOAuthProductProjects = nativeITPerProjProdID + "=" + nativeITProject
	})
	verifier := oauth.NewNativeVerifier(oauth.NativeVerifierConfig{
		GoogleJWKSURL:    signer.url,
		AppleJWKSURL:     signer.url,
		MicrosoftJWKSURL: signer.url,
		Now:              func() time.Time { return signer.now },
	})
	projects := &fakeITProjects{active: map[string]*service.AdminProject{
		nativeITProject: {
			ID: nativeITProject, StorageScopeID: newTestConfig().DefaultTenantID, Name: nativeITProject,
			OAuth: service.ProjectOAuthConfig{
				Google: &service.ProjectOAuthGoogle{NativeAudiences: []string{nativeITPerProjAud}},
				Microsoft: &service.ProjectOAuthMicrosoft{
					NativeAudiences: []string{nativeITMicrosoftAud},
					TenantID:        nativeITMSTenant,
					IssuerFormat:    nativeITMSIssuerFmt,
				},
			},
		},
	}}
	return StartServer(t, cfgFn, WithNativeOAuth(verifier, projects))
}

func TestNativeOAuth_Google_HappyPath(t *testing.T) {
	signer := newNativeITSigner(t)
	h := nativeITHarness(t, signer, true)

	tok := signer.googleToken(t, "it-google-sub", "it-google@example.com", nativeITGoogleAud, signer.now.Add(time.Hour))
	resp, err := h.Client.NativeOAuthLogin(context.Background(), connect.NewRequest(&identitypb.NativeOAuthLoginRequest{
		Provider: "google", IdToken: tok, Product: "easyloops",
	}))
	if err != nil {
		t.Fatalf("NativeOAuthLogin: %v", err)
	}
	if resp.Msg.AccessToken == "" || resp.Msg.RefreshToken == "" {
		t.Fatal("expected a token pair")
	}
	if resp.Msg.User == nil || resp.Msg.User.Email != "it-google@example.com" {
		t.Fatalf("unexpected user: %+v", resp.Msg.User)
	}
	if resp.Msg.ExpiresIn <= 0 {
		t.Fatalf("expires_in = %d", resp.Msg.ExpiresIn)
	}
	// The user is persisted under the resolved (default) project.
	if u, _ := h.Repo.FindUserByEmail(context.Background(), "it-google@example.com"); u == nil {
		t.Fatal("user not created in the resolved project")
	}
}

func TestNativeOAuth_Apple_HappyPathWithNonce(t *testing.T) {
	signer := newNativeITSigner(t)
	h := nativeITHarness(t, signer, true)

	const rawNonce = "it-raw-nonce"
	tok := signer.sign(t, map[string]any{
		"iss": nativeITAppleIss, "sub": "it-apple-sub", "aud": nativeITAppleAud,
		"exp": signer.now.Add(time.Hour), "iat": signer.now,
		"email": "it-apple@icloud.com", "email_verified": "true", "nonce": nativeITHash(rawNonce),
	})
	resp, err := h.Client.NativeOAuthLogin(context.Background(), connect.NewRequest(&identitypb.NativeOAuthLoginRequest{
		Provider: "apple", IdToken: tok, Product: "easyloops", Nonce: rawNonce,
	}))
	if err != nil {
		t.Fatalf("NativeOAuthLogin apple: %v", err)
	}
	if resp.Msg.AccessToken == "" || resp.Msg.User == nil || resp.Msg.User.Email != "it-apple@icloud.com" {
		t.Fatalf("unexpected apple result: %+v", resp.Msg)
	}
}

func TestNativeOAuth_WrongAudience_Unauthenticated(t *testing.T) {
	signer := newNativeITSigner(t)
	h := nativeITHarness(t, signer, true)

	tok := signer.googleToken(t, "it-aud", "it-aud@example.com", "some-other-client", signer.now.Add(time.Hour))
	_, err := h.Client.NativeOAuthLogin(context.Background(), connect.NewRequest(&identitypb.NativeOAuthLoginRequest{
		Provider: "google", IdToken: tok, Product: "easyloops",
	}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("wrong aud: code = %v, want Unauthenticated (err=%v)", connect.CodeOf(err), err)
	}
}

func TestNativeOAuth_Expired_Unauthenticated(t *testing.T) {
	signer := newNativeITSigner(t)
	h := nativeITHarness(t, signer, true)

	tok := signer.googleToken(t, "it-exp", "it-exp@example.com", nativeITGoogleAud, signer.now.Add(-time.Hour))
	_, err := h.Client.NativeOAuthLogin(context.Background(), connect.NewRequest(&identitypb.NativeOAuthLoginRequest{
		Provider: "google", IdToken: tok, Product: "easyloops",
	}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("expired: code = %v, want Unauthenticated (err=%v)", connect.CodeOf(err), err)
	}
}

func TestNativeOAuth_UnknownProduct_InvalidArgument(t *testing.T) {
	signer := newNativeITSigner(t)
	h := nativeITHarness(t, signer, true)

	tok := signer.googleToken(t, "it-prod", "it-prod@example.com", nativeITGoogleAud, signer.now.Add(time.Hour))
	_, err := h.Client.NativeOAuthLogin(context.Background(), connect.NewRequest(&identitypb.NativeOAuthLoginRequest{
		Provider: "google", IdToken: tok, Product: "no-such-product",
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("unknown product: code = %v, want InvalidArgument (err=%v)", connect.CodeOf(err), err)
	}
}

func TestNativeOAuth_Disabled_FailedPrecondition(t *testing.T) {
	signer := newNativeITSigner(t)
	h := nativeITHarness(t, signer, false)

	tok := signer.googleToken(t, "it-off", "it-off@example.com", nativeITGoogleAud, signer.now.Add(time.Hour))
	_, err := h.Client.NativeOAuthLogin(context.Background(), connect.NewRequest(&identitypb.NativeOAuthLoginRequest{
		Provider: "google", IdToken: tok, Product: "easyloops",
	}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("disabled: code = %v, want FailedPrecondition (err=%v)", connect.CodeOf(err), err)
	}
}

// TestNativeOAuth_Microsoft_DefaultProject_HappyPath verifies a Microsoft native
// login for the DEFAULT project, whose accepted audiences come from the env seed
// (GATEWAY_NATIVE_OAUTH_MICROSOFT_AUDIENCES).
func TestNativeOAuth_Microsoft_DefaultProject_HappyPath(t *testing.T) {
	signer := newNativeITSigner(t)
	h := nativeITHarness(t, signer, true)

	tok := signer.microsoftToken(t, "it-ms-oid", "it-ms@contoso.com", nativeITMicrosoftAud, nativeITMSTenant)
	resp, err := h.Client.NativeOAuthLogin(context.Background(), connect.NewRequest(&identitypb.NativeOAuthLoginRequest{
		Provider: "microsoft", IdToken: tok, Product: "easyloops",
	}))
	if err != nil {
		t.Fatalf("NativeOAuthLogin microsoft: %v", err)
	}
	if resp.Msg.AccessToken == "" || resp.Msg.User == nil || resp.Msg.User.Email != "it-ms@contoso.com" {
		t.Fatalf("unexpected microsoft result: %+v", resp.Msg)
	}
}

// TestNativeOAuth_PerProjectAudiences drives a project whose config_json carries
// its own Google native audience. A token for that audience is accepted, while a
// token for the env-seed audience is rejected — config_json wins and the env seed
// does not merge in when the project configures its own audiences.
func TestNativeOAuth_PerProjectAudiences(t *testing.T) {
	signer := newNativeITSigner(t)
	h := nativeITPerProjectHarness(t, signer)

	// (a) the project's own (config_json) audience is accepted.
	ok := signer.googleToken(t, "it-pp-1", "it-pp@example.com", nativeITPerProjAud, signer.now.Add(time.Hour))
	resp, err := h.Client.NativeOAuthLogin(context.Background(), connect.NewRequest(&identitypb.NativeOAuthLoginRequest{
		Provider: "google", IdToken: ok, Product: nativeITPerProjProdID,
	}))
	if err != nil {
		t.Fatalf("per-project google login: %v", err)
	}
	if resp.Msg.User == nil || resp.Msg.User.Email != "it-pp@example.com" {
		t.Fatalf("unexpected per-project result: %+v", resp.Msg)
	}

	// (b) the env-seed audience must NOT be accepted once config_json sets its own.
	leak := signer.googleToken(t, "it-pp-2", "it-pp2@example.com", nativeITGoogleAud, signer.now.Add(time.Hour))
	_, err = h.Client.NativeOAuthLogin(context.Background(), connect.NewRequest(&identitypb.NativeOAuthLoginRequest{
		Provider: "google", IdToken: leak, Product: nativeITPerProjProdID,
	}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("env aud leak: code = %v, want Unauthenticated (err=%v)", connect.CodeOf(err), err)
	}
}

// TestNativeOAuth_PerProjectMicrosoft drives a non-default project's Microsoft
// native audience + tenant pinning end-to-end.
func TestNativeOAuth_PerProjectMicrosoft(t *testing.T) {
	signer := newNativeITSigner(t)
	h := nativeITPerProjectHarness(t, signer)

	tok := signer.microsoftToken(t, "it-pp-ms", "it-pp-ms@contoso.com", nativeITMicrosoftAud, nativeITMSTenant)
	resp, err := h.Client.NativeOAuthLogin(context.Background(), connect.NewRequest(&identitypb.NativeOAuthLoginRequest{
		Provider: "microsoft", IdToken: tok, Product: nativeITPerProjProdID,
	}))
	if err != nil {
		t.Fatalf("per-project microsoft login: %v", err)
	}
	if resp.Msg.User == nil || resp.Msg.User.Email != "it-pp-ms@contoso.com" {
		t.Fatalf("unexpected per-project microsoft result: %+v", resp.Msg)
	}

	// A token from a DIFFERENT tenant is rejected by the project's tenant pin.
	wrong := signer.microsoftToken(t, "it-pp-ms2", "x@contoso.com", nativeITMicrosoftAud, "other-tenant")
	_, err = h.Client.NativeOAuthLogin(context.Background(), connect.NewRequest(&identitypb.NativeOAuthLoginRequest{
		Provider: "microsoft", IdToken: wrong, Product: nativeITPerProjProdID,
	}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("wrong tenant: code = %v, want Unauthenticated (err=%v)", connect.CodeOf(err), err)
	}
}
