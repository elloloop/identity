//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

// nativeITHarness boots the full server with native OAuth wired to the
// signer's mock JWKS. enabled toggles GATEWAY_NATIVE_OAUTH_ENABLED.
func nativeITHarness(t *testing.T, signer *nativeITSigner, enabled bool) *Harness {
	t.Helper()
	cfgFn := WithConfig(func(c *config.Config) {
		c.DefaultProjectID = nativeITProject
		c.NativeOAuthEnabled = enabled
		c.NativeOAuthGoogleAudiences = nativeITGoogleAud
		c.NativeOAuthAppleAudiences = nativeITAppleAud
		c.NativeOAuthProductProjects = "easyloops=" + nativeITProject
	})
	if !enabled {
		return StartServer(t, cfgFn)
	}
	verifier := oauth.NewNativeVerifier(oauth.NativeVerifierConfig{
		GoogleAudiences: []string{nativeITGoogleAud},
		AppleAudiences:  []string{nativeITAppleAud},
		GoogleJWKSURL:   signer.url,
		AppleJWKSURL:    signer.url,
		Now:             func() time.Time { return signer.now },
	})
	// Memory driver: no control plane, so nativeProjects is nil and the product
	// must resolve to the default project.
	return StartServer(t, cfgFn, WithNativeOAuth(verifier, nil))
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
