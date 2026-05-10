//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/mockoidc"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	"github.com/elloloop/identity/pkg/oauth"
)

func TestOIDC_HappyPath(t *testing.T) {
	t.Parallel()

	mock := newMockOIDCServer(t, nil)
	h := StartServer(t, WithOAuthRegistry(mockOIDCRegistry(mock)))

	redirectURI := "https://app.example.com/oauth/callback"
	begin, err := h.Client.BeginOAuthLogin(context.Background(), connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
		Provider:    "google",
		RedirectUri: redirectURI,
	}))
	if err != nil {
		t.Fatalf("BeginOAuthLogin: %v", err)
	}

	code, gotState := authorizeOIDC(t, mock, &mockoidc.MockUser{
		Subject:           "google-sub-1",
		Email:             "alice@example.com",
		EmailVerified:     true,
		PreferredUsername: "Alice OAuth",
	}, begin.Msg.AuthorizationUrl)
	if gotState != begin.Msg.State {
		t.Fatalf("authorize state = %q, want %q", gotState, begin.Msg.State)
	}

	resp, err := h.Client.OAuthLogin(context.Background(), connect.NewRequest(&identitypb.OAuthLoginRequest{
		Code:        code,
		Provider:    "google",
		RedirectUri: redirectURI,
		State:       gotState,
		StateToken:  begin.Msg.StateToken,
	}))
	if err != nil {
		t.Fatalf("OAuthLogin: %v", err)
	}
	if resp.Msg.AccessToken == "" {
		t.Fatal("OAuthLogin returned empty access_token")
	}
	if resp.Msg.RefreshToken == "" {
		t.Fatal("OAuthLogin returned empty refresh_token")
	}
	if got := resp.Msg.GetUser().GetEmail(); got != "alice@example.com" {
		t.Fatalf("user email = %q, want alice@example.com", got)
	}
	if got := resp.Msg.GetUser().GetName(); got != "Alice OAuth" {
		t.Fatalf("user name = %q, want Alice OAuth", got)
	}
	if !resp.Msg.GetUser().GetEmailVerified() {
		t.Fatal("user email_verified should be true")
	}

	cur, err := h.AuthedClient(resp.Msg.AccessToken).GetCurrentUser(
		context.Background(),
		connect.NewRequest(&identitypb.GetCurrentUserRequest{}),
	)
	if err != nil {
		t.Fatalf("GetCurrentUser: %v", err)
	}
	if got := cur.Msg.GetUser().GetEmail(); got != "alice@example.com" {
		t.Fatalf("GetCurrentUser email = %q, want alice@example.com", got)
	}
}

func TestOIDC_InvalidSignature(t *testing.T) {
	t.Parallel()

	mock := newMockOIDCServer(t, func(m *mockoidc.MockOIDC) {
		attacker, err := mockoidc.RandomKeypair(2048)
		if err != nil {
			t.Fatalf("RandomKeypair: %v", err)
		}
		if err := m.AddMiddleware(tokenResponseMiddleware(func() tokenResponse {
			raw, err := signRS256Token(attacker, m.Issuer(), m.ClientID, "google-sub-2", "mallory@example.com", true, time.Now().Add(5*time.Minute))
			if err != nil {
				t.Fatalf("signRS256Token: %v", err)
			}
			return tokenResponse{
				AccessToken: "unused-access-token",
				TokenType:   "bearer",
				ExpiresIn:   int((5 * time.Minute).Seconds()),
				IDToken:     raw,
			}
		})); err != nil {
			t.Fatalf("AddMiddleware: %v", err)
		}
	})
	h := StartServer(t, WithOAuthRegistry(mockOIDCRegistry(mock)))

	begin, err := h.Client.BeginOAuthLogin(context.Background(), connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
		Provider:    "google",
		RedirectUri: "https://app.example.com/oauth/callback",
	}))
	if err != nil {
		t.Fatalf("BeginOAuthLogin: %v", err)
	}

	code, state := authorizeOIDC(t, mock, &mockoidc.MockUser{
		Subject:           "google-sub-2",
		Email:             "mallory@example.com",
		EmailVerified:     true,
		PreferredUsername: "Mallory",
	}, begin.Msg.AuthorizationUrl)

	_, err = h.Client.OAuthLogin(context.Background(), connect.NewRequest(&identitypb.OAuthLoginRequest{
		Code:        code,
		Provider:    "google",
		RedirectUri: "https://app.example.com/oauth/callback",
		State:       state,
		StateToken:  begin.Msg.StateToken,
	}))
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("OAuthLogin code = %v, want Unauthenticated (err=%v)", got, err)
	}
}

func TestOIDC_ExpiredIDToken(t *testing.T) {
	t.Parallel()

	mock := newMockOIDCServer(t, func(m *mockoidc.MockOIDC) {
		m.AccessTTL = -1 * time.Minute
	})
	h := StartServer(t, WithOAuthRegistry(mockOIDCRegistry(mock)))

	begin, err := h.Client.BeginOAuthLogin(context.Background(), connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
		Provider:    "google",
		RedirectUri: "https://app.example.com/oauth/callback",
	}))
	if err != nil {
		t.Fatalf("BeginOAuthLogin: %v", err)
	}

	code, state := authorizeOIDC(t, mock, &mockoidc.MockUser{
		Subject:           "google-sub-3",
		Email:             "expired@example.com",
		EmailVerified:     true,
		PreferredUsername: "Expired User",
	}, begin.Msg.AuthorizationUrl)

	_, err = h.Client.OAuthLogin(context.Background(), connect.NewRequest(&identitypb.OAuthLoginRequest{
		Code:        code,
		Provider:    "google",
		RedirectUri: "https://app.example.com/oauth/callback",
		State:       state,
		StateToken:  begin.Msg.StateToken,
	}))
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("OAuthLogin code = %v, want Unauthenticated (err=%v)", got, err)
	}
}

func TestOIDC_KeyRotation(t *testing.T) {
	t.Parallel()

	mock := newMockOIDCServer(t, nil)
	h := StartServer(t, WithOAuthRegistry(mockOIDCRegistry(mock)))

	redirectURI := "https://app.example.com/oauth/callback"
	begin1, err := h.Client.BeginOAuthLogin(context.Background(), connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
		Provider:    "google",
		RedirectUri: redirectURI,
	}))
	if err != nil {
		t.Fatalf("BeginOAuthLogin: %v", err)
	}

	firstCode, firstState := authorizeOIDC(t, mock, &mockoidc.MockUser{
		Subject:           "google-sub-4",
		Email:             "rotate@example.com",
		EmailVerified:     true,
		PreferredUsername: "Rotate One",
	}, begin1.Msg.AuthorizationUrl)

	if _, err := h.Client.OAuthLogin(context.Background(), connect.NewRequest(&identitypb.OAuthLoginRequest{
		Code:        firstCode,
		Provider:    "google",
		RedirectUri: redirectURI,
		State:       firstState,
		StateToken:  begin1.Msg.StateToken,
	})); err != nil {
		t.Fatalf("first OAuthLogin: %v", err)
	}

	oldKid, err := mock.Keypair.KeyID()
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}
	nextKeypair, err := mockoidc.RandomKeypair(2048)
	if err != nil {
		t.Fatalf("RandomKeypair: %v", err)
	}
	nextKid, err := nextKeypair.KeyID()
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}
	if nextKid == oldKid {
		t.Fatal("rotated keypair reused the old kid")
	}
	mock.Keypair = nextKeypair

	begin2, err := h.Client.BeginOAuthLogin(context.Background(), connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
		Provider:    "google",
		RedirectUri: redirectURI,
	}))
	if err != nil {
		t.Fatalf("BeginOAuthLogin: %v", err)
	}

	secondCode, secondState := authorizeOIDC(t, mock, &mockoidc.MockUser{
		Subject:           "google-sub-4",
		Email:             "rotate@example.com",
		EmailVerified:     true,
		PreferredUsername: "Rotate Two",
	}, begin2.Msg.AuthorizationUrl)

	resp, err := h.Client.OAuthLogin(context.Background(), connect.NewRequest(&identitypb.OAuthLoginRequest{
		Code:        secondCode,
		Provider:    "google",
		RedirectUri: redirectURI,
		State:       secondState,
		StateToken:  begin2.Msg.StateToken,
	}))
	if err != nil {
		t.Fatalf("second OAuthLogin after JWKS rotation: %v", err)
	}
	if got := resp.Msg.GetUser().GetEmail(); got != "rotate@example.com" {
		t.Fatalf("rotated user email = %q, want rotate@example.com", got)
	}
}

func TestOIDC_AlgNoneRejected(t *testing.T) {
	t.Parallel()

	mock := newMockOIDCServer(t, func(m *mockoidc.MockOIDC) {
		if err := m.AddMiddleware(tokenResponseMiddleware(func() tokenResponse {
			raw, err := signAlgNoneToken(m.Issuer(), m.ClientID, "google-sub-5", "none@example.com", true, time.Now().Add(5*time.Minute))
			if err != nil {
				t.Fatalf("signAlgNoneToken: %v", err)
			}
			return tokenResponse{
				AccessToken: "unused-access-token",
				TokenType:   "bearer",
				ExpiresIn:   int((5 * time.Minute).Seconds()),
				IDToken:     raw,
			}
		})); err != nil {
			t.Fatalf("AddMiddleware: %v", err)
		}
	})
	h := StartServer(t, WithOAuthRegistry(mockOIDCRegistry(mock)))

	begin, err := h.Client.BeginOAuthLogin(context.Background(), connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
		Provider:    "google",
		RedirectUri: "https://app.example.com/oauth/callback",
	}))
	if err != nil {
		t.Fatalf("BeginOAuthLogin: %v", err)
	}

	code, state := authorizeOIDC(t, mock, &mockoidc.MockUser{
		Subject:           "google-sub-5",
		Email:             "none@example.com",
		EmailVerified:     true,
		PreferredUsername: "None User",
	}, begin.Msg.AuthorizationUrl)

	_, err = h.Client.OAuthLogin(context.Background(), connect.NewRequest(&identitypb.OAuthLoginRequest{
		Code:        code,
		Provider:    "google",
		RedirectUri: "https://app.example.com/oauth/callback",
		State:       state,
		StateToken:  begin.Msg.StateToken,
	}))
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("OAuthLogin code = %v, want Unauthenticated (err=%v)", got, err)
	}
}

func TestOIDC_StateMismatchRejected(t *testing.T) {
	t.Parallel()

	mock := newMockOIDCServer(t, nil)
	h := StartServer(t, WithOAuthRegistry(mockOIDCRegistry(mock)))

	begin, err := h.Client.BeginOAuthLogin(context.Background(), connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
		Provider:    "google",
		RedirectUri: "https://app.example.com/oauth/callback",
	}))
	if err != nil {
		t.Fatalf("BeginOAuthLogin: %v", err)
	}

	code, state := authorizeOIDC(t, mock, &mockoidc.MockUser{
		Subject:           "google-sub-6",
		Email:             "state@example.com",
		EmailVerified:     true,
		PreferredUsername: "State User",
	}, begin.Msg.AuthorizationUrl)
	if state != begin.Msg.State {
		t.Fatalf("authorize state = %q, want %q", state, begin.Msg.State)
	}

	_, err = h.Client.OAuthLogin(context.Background(), connect.NewRequest(&identitypb.OAuthLoginRequest{
		Code:        code,
		Provider:    "google",
		RedirectUri: "https://app.example.com/oauth/callback",
		State:       state + "-wrong",
		StateToken:  begin.Msg.StateToken,
	}))
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("OAuthLogin code = %v, want Unauthenticated (err=%v)", got, err)
	}
}

type tokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

func newMockOIDCServer(t *testing.T, configure func(*mockoidc.MockOIDC)) *mockoidc.MockOIDC {
	t.Helper()

	mock, err := mockoidc.NewServer(nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if configure != nil {
		configure(mock)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := mock.Start(ln, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		_ = mock.Shutdown()
		_ = ln.Close()
	})
	return mock
}

func mockOIDCRegistry(mock *mockoidc.MockOIDC) *oauth.Registry {
	reg := oauth.NewRegistry()
	reg.Register("google", oauth.NewGoogle(oauth.GoogleConfig{
		ClientID:     mock.ClientID,
		ClientSecret: mock.ClientSecret,
		Issuer:       mock.Issuer(),
		DiscoveryURL: mock.DiscoveryEndpoint(),
	}))
	return reg
}

func authorizeOIDC(t *testing.T, mock *mockoidc.MockOIDC, user *mockoidc.MockUser, authorizationURL string) (string, string) {
	t.Helper()

	mock.QueueUser(user)
	parsedAuth, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	authState := parsedAuth.Query().Get("state")
	mock.QueueCode("code-" + authState)

	req, err := http.NewRequest(http.MethodGet, authorizationURL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("authorize request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	redirected, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	return redirected.Query().Get("code"), redirected.Query().Get("state")
}

func tokenResponseMiddleware(build func() tokenResponse) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != mockoidc.TokenEndpoint {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(build()); err != nil {
				panic(err)
			}
		})
	}
}

func signRS256Token(keypair *mockoidc.Keypair, issuer, clientID, subject, email string, emailVerified bool, expiresAt time.Time) (string, error) {
	return keypair.SignJWT(jwt.MapClaims{
		"iss":            issuer,
		"sub":            subject,
		"aud":            clientID,
		"iat":            time.Now().Unix(),
		"exp":            expiresAt.Unix(),
		"email":          email,
		"email_verified": emailVerified,
	})
}

func signAlgNoneToken(issuer, clientID, subject, email string, emailVerified bool, expiresAt time.Time) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"iss":            issuer,
		"sub":            subject,
		"aud":            clientID,
		"iat":            time.Now().Unix(),
		"exp":            expiresAt.Unix(),
		"email":          email,
		"email_verified": emailVerified,
	})
	return token.SignedString(jwt.UnsafeAllowNoneSignatureType)
}
