//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
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

// Sign-In with Apple integration coverage. Apple is the newest OAuth
// provider and differs from the OIDC providers in three ways the unit
// tests in pkg/oauth/apple_test.go exercise but the integration suite
// did not: a JWT client-secret signed with an EC private key, a
// form_post callback (so there is no provider authorize endpoint to
// redirect through — BeginOAuthLogin's state is replayed straight back
// into OAuthLogin), and a one-time apple_user_payload carrying the
// user's name on first authorization. These tests drive the REAL Apple
// Exchanger against a mock Apple token+JWKS endpoint, signing the
// id_token in-test with a generated key — the same mechanism
// apple_test.go uses.

const (
	appleTestClientID    = "apple-client-id"
	appleTestIssuer      = "https://appleid.apple.com"
	appleTestRedirectURI = "https://app.example.com/oauth/callback"
)

// appleTestKey is an RSA key plus its matching single-key JWK Set, used
// to sign Apple id_tokens and serve the mock JWKS. Apple signs with
// ES256 in production, but the Exchanger verifies the id_token against
// whatever keys the configured JWKS endpoint advertises, so an RSA key
// is sufficient to exercise the full verification path (this mirrors
// pkg/oauth/oauth_testutil_test.go's testKey).
type appleTestKey struct {
	priv    *rsa.PrivateKey
	kid     string
	jwksRaw []byte
}

func appleNewTestKey(t *testing.T, kid string) *appleTestKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa generate: %v", err)
	}
	pub, err := jwk.FromRaw(priv.Public())
	if err != nil {
		t.Fatalf("jwk from raw: %v", err)
	}
	if err := pub.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := pub.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("set alg: %v", err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		t.Fatalf("add key: %v", err)
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return &appleTestKey{priv: priv, kid: kid, jwksRaw: raw}
}

// signIDToken signs the given claims as an RS256 compact JWS, the same
// shape Apple's token endpoint returns.
func (k *appleTestKey) signIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	tok := jwt.New()
	for key, val := range claims {
		switch key {
		case "iss":
			_ = tok.Set(jwt.IssuerKey, val)
		case "sub":
			_ = tok.Set(jwt.SubjectKey, val)
		case "aud":
			_ = tok.Set(jwt.AudienceKey, val)
		case "exp":
			_ = tok.Set(jwt.ExpirationKey, val)
		case "iat":
			_ = tok.Set(jwt.IssuedAtKey, val)
		default:
			_ = tok.Set(key, val)
		}
	}
	signKey, err := jwk.FromRaw(k.priv)
	if err != nil {
		t.Fatalf("priv jwk: %v", err)
	}
	if err := signKey.Set(jwk.KeyIDKey, k.kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := signKey.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("set alg: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, signKey))
	if err != nil {
		t.Fatalf("sign id_token: %v", err)
	}
	return string(signed)
}

// appleGenerateECKey returns a PEM-encoded PKCS#8 EC P-256 private key,
// matching the credential Apple requires for the client-secret JWT. The
// Exchanger parses and signs the client secret with it on every code
// exchange, so it must be a valid EC key even though the mock token
// endpoint ignores the secret's contents.
func appleGenerateECKey(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa generate: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal ec key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// appleMockProvider stands up Apple's token + JWKS endpoints. The token
// endpoint always returns the supplied id_token (the authorization code
// is opaque to the mock); the JWKS endpoint serves the public key the
// id_token was signed with.
func appleMockProvider(t *testing.T, idToken string, jwksRaw []byte) (tokenURL, jwksURL string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id_token":     idToken,
			"access_token": "discardable",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksRaw)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL + "/token", srv.URL + "/jwks"
}

// appleRegistry builds an OAuth registry whose single Apple provider is
// wired to the mock token/JWKS endpoints. Issuer defaults to Apple's,
// matching the id_token's `iss`.
func appleRegistry(tokenURL, jwksURL, privateKeyPEM string) *oauth.Registry {
	reg := oauth.NewRegistry()
	reg.Register("apple", oauth.NewApple(oauth.AppleConfig{
		ClientID:   appleTestClientID,
		TeamID:     "team-123",
		KeyID:      "key-123",
		PrivateKey: privateKeyPEM,
		TokenURL:   tokenURL,
		JWKSURL:    jwksURL,
		Issuer:     appleTestIssuer,
	}))
	return reg
}

// appleStandardClaims returns the id_token claims Apple emits for a
// verified user, with iat/exp anchored to real wall-clock time so the
// server-minted state token (validated against the live clock) and the
// id_token validity window agree.
func appleStandardClaims(sub, email string, emailVerified any) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":            appleTestIssuer,
		"sub":            sub,
		"aud":            appleTestClientID,
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"email":          email,
		"email_verified": emailVerified,
	}
}

// appleLogin drives the full server-owned flow: BeginOAuthLogin to mint
// the state artifacts, then OAuthLogin replaying that state alongside an
// opaque code and the optional one-time user payload. Apple's form_post
// callback means there is no provider authorize redirect to walk, so the
// state from Begin is fed straight back into OAuthLogin.
func appleLogin(
	t *testing.T,
	h *Harness,
	userPayload string,
) (*connect.Response[identitypb.OAuthLoginResponse], error) {
	t.Helper()
	ctx := context.Background()
	begin, err := h.Client.BeginOAuthLogin(ctx, connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
		Provider:    "apple",
		RedirectUri: appleTestRedirectURI,
	}))
	if err != nil {
		t.Fatalf("BeginOAuthLogin: %v", err)
	}
	if !strings.Contains(begin.Msg.AuthorizationUrl, "appleid.apple.com") {
		t.Fatalf("authorization_url = %q, want Apple authorize endpoint", begin.Msg.AuthorizationUrl)
	}
	return h.Client.OAuthLogin(ctx, connect.NewRequest(&identitypb.OAuthLoginRequest{
		Code:             "apple-auth-code",
		Provider:         "apple",
		RedirectUri:      appleTestRedirectURI,
		State:            begin.Msg.State,
		StateToken:       begin.Msg.StateToken,
		AppleUserPayload: userPayload,
	}))
}

func TestApple_HappyPath_AutoProvisionsUserWithName(t *testing.T) {
	t.Parallel()

	key := appleNewTestKey(t, "apple-kid-1")
	idToken := key.signIDToken(t, appleStandardClaims("apple-sub-happy", "ada@example.com", true))
	tokenURL, jwksURL := appleMockProvider(t, idToken, key.jwksRaw)
	h := StartServer(t, WithOAuthRegistry(appleRegistry(tokenURL, jwksURL, appleGenerateECKey(t))))

	// Apple only sends the user's name on the FIRST authorization, as a
	// JSON payload alongside the form_post callback.
	resp, err := appleLogin(t, h, `{"name":{"firstName":"Ada","lastName":"Lovelace"}}`)
	if err != nil {
		t.Fatalf("OAuthLogin: %v", err)
	}
	if resp.Msg.AccessToken == "" {
		t.Fatal("empty access_token")
	}
	if resp.Msg.RefreshToken == "" {
		t.Fatal("empty refresh_token")
	}
	if got := resp.Msg.GetUser().GetEmail(); got != "ada@example.com" {
		t.Fatalf("user email = %q, want ada@example.com", got)
	}
	if got := resp.Msg.GetUser().GetName(); got != "Ada Lovelace" {
		t.Fatalf("user name = %q, want Ada Lovelace (from apple_user_payload)", got)
	}
	if !resp.Msg.GetUser().GetEmailVerified() {
		t.Fatal("email_verified should be true")
	}

	// The user was actually persisted (auto-provisioned), not just echoed.
	h.WaitForUserCount(t, "ada@example.com", 1)

	cur, err := h.AuthedClient(resp.Msg.AccessToken).GetCurrentUser(
		context.Background(),
		connect.NewRequest(&identitypb.GetCurrentUserRequest{}),
	)
	if err != nil {
		t.Fatalf("GetCurrentUser: %v", err)
	}
	if got := cur.Msg.GetUser().GetEmail(); got != "ada@example.com" {
		t.Fatalf("GetCurrentUser email = %q, want ada@example.com", got)
	}
	if got := cur.Msg.GetUser().GetName(); got != "Ada Lovelace" {
		t.Fatalf("GetCurrentUser name = %q, want Ada Lovelace", got)
	}
}

// TestApple_EmailVerifiedAccepted covers Apple's two on-the-wire shapes
// for email_verified: a real JSON bool and the string "true" Apple also
// emits. Both must auto-provision a verified user (mirrors
// apple_test.go's TestApple_EmailVerifiedString).
func TestApple_EmailVerifiedAccepted(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		emailVerified any
		email         string
	}{
		{name: "bool_true", emailVerified: true, email: "bool-true@example.com"},
		{name: "string_true", emailVerified: "true", email: "string-true@example.com"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			key := appleNewTestKey(t, "apple-kid-"+tc.name)
			idToken := key.signIDToken(t, appleStandardClaims("apple-sub-"+tc.name, tc.email, tc.emailVerified))
			tokenURL, jwksURL := appleMockProvider(t, idToken, key.jwksRaw)
			h := StartServer(t, WithOAuthRegistry(appleRegistry(tokenURL, jwksURL, appleGenerateECKey(t))))

			resp, err := appleLogin(t, h, "")
			if err != nil {
				t.Fatalf("OAuthLogin: %v", err)
			}
			if got := resp.Msg.GetUser().GetEmail(); got != tc.email {
				t.Fatalf("user email = %q, want %q", got, tc.email)
			}
			if !resp.Msg.GetUser().GetEmailVerified() {
				t.Fatalf("email_verified should be true for %v", tc.emailVerified)
			}
		})
	}
}

// TestApple_RejectedIdentities covers the cases where Apple asserts an
// identity we must refuse: email_verified false (bool and string) and a
// missing email. Each surfaces as CodeUnauthenticated and no user is
// provisioned.
func TestApple_RejectedIdentities(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		claims map[string]any
		email  string
	}{
		{
			name:   "email_verified_bool_false",
			claims: appleStandardClaims("apple-sub-r1", "unverified-bool@example.com", false),
			email:  "unverified-bool@example.com",
		},
		{
			name:   "email_verified_string_false",
			claims: appleStandardClaims("apple-sub-r2", "unverified-string@example.com", "false"),
			email:  "unverified-string@example.com",
		},
		{
			name: "missing_email",
			claims: map[string]any{
				"iss": appleTestIssuer,
				"sub": "apple-sub-r3",
				"aud": appleTestClientID,
				"iat": time.Now().Unix(),
				"exp": time.Now().Add(5 * time.Minute).Unix(),
				// no email / email_verified
			},
			email: "",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			key := appleNewTestKey(t, "apple-kid-"+tc.name)
			idToken := key.signIDToken(t, tc.claims)
			tokenURL, jwksURL := appleMockProvider(t, idToken, key.jwksRaw)
			h := StartServer(t, WithOAuthRegistry(appleRegistry(tokenURL, jwksURL, appleGenerateECKey(t))))

			_, err := appleLogin(t, h, "")
			if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
				t.Fatalf("OAuthLogin code = %v, want Unauthenticated (err=%v)", got, err)
			}
			if tc.email != "" {
				if n := h.CountUsersByEmail(t, tc.email); n != 0 {
					t.Fatalf("rejected login provisioned %d users for %q, want 0", n, tc.email)
				}
			}
		})
	}
}

// TestApple_RegistrationRequiresAllFourCredentials asserts the
// config-driven registry build (internal/app.buildOAuthRegistry, reached
// here through app.New when no explicit registry is supplied) only
// enables Apple when all four credentials — client ID, team ID, key ID,
// and private key — are present. With any one missing, Apple is not
// registered: BeginOAuthLogin("apple") then reports the provider as
// unknown (CodeInvalidArgument) rather than starting a flow. A
// co-registered Google keeps the registry non-empty so the failure is
// specifically "apple not enabled", not "oauth disabled entirely".
func TestApple_RegistrationRequiresAllFourCredentials(t *testing.T) {
	t.Parallel()

	ecKey := appleGenerateECKey(t)

	type appleCreds struct {
		clientID, teamID, keyID, privateKey string
	}
	full := appleCreds{
		clientID:   appleTestClientID,
		teamID:     "team-123",
		keyID:      "key-123",
		privateKey: ecKey,
	}

	cases := []struct {
		name        string
		creds       appleCreds
		wantEnabled bool
	}{
		{name: "all_four_present", creds: full, wantEnabled: true},
		{name: "missing_client_id", creds: appleCreds{teamID: full.teamID, keyID: full.keyID, privateKey: full.privateKey}},
		{name: "missing_team_id", creds: appleCreds{clientID: full.clientID, keyID: full.keyID, privateKey: full.privateKey}},
		{name: "missing_key_id", creds: appleCreds{clientID: full.clientID, teamID: full.teamID, privateKey: full.privateKey}},
		{name: "missing_private_key", creds: appleCreds{clientID: full.clientID, teamID: full.teamID, keyID: full.keyID}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := StartServer(t, WithConfig(func(c *config.Config) {
				c.AppleClientID = tc.creds.clientID
				c.AppleTeamID = tc.creds.teamID
				c.AppleKeyID = tc.creds.keyID
				c.ApplePrivateKey = tc.creds.privateKey
				// Keep the registry non-empty regardless of Apple so a
				// disabled Apple reads as "unknown provider", not "oauth
				// disabled". Google registers from ID+secret alone (no
				// network until an exchange, which we never trigger here).
				c.GoogleClientID = "google-client-id"
				c.GoogleClientSecret = "google-client-secret"
			}))

			_, err := h.Client.BeginOAuthLogin(context.Background(), connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
				Provider:    "apple",
				RedirectUri: appleTestRedirectURI,
			}))
			if tc.wantEnabled {
				if err != nil {
					t.Fatalf("BeginOAuthLogin(apple) with all creds: %v", err)
				}
				return
			}
			if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
				t.Fatalf("BeginOAuthLogin(apple) code = %v, want InvalidArgument (err=%v)", got, err)
			}
		})
	}
}
