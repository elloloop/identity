package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// TestNewExchangers_DefaultsApplied exercises the default-URL paths
// in NewGoogle / NewMicrosoft / NewGitHub.
func TestNewExchangers_DefaultsApplied(t *testing.T) {
	t.Parallel()
	g := NewGoogle(GoogleConfig{ClientID: "x", ClientSecret: "y"}).(*googleExchanger)
	if g.cfg.TokenURL != googleTokenURL || g.cfg.JWKSURL != googleJWKSURL || g.cfg.Issuer != googleIssuer {
		t.Fatalf("defaults not applied: %+v", g.cfg)
	}
	m := NewMicrosoft(MicrosoftConfig{ClientID: "x", ClientSecret: "y"}).(*microsoftExchanger)
	if m.cfg.TokenURL != microsoftExchangeEndpoint || m.cfg.JWKSURL != microsoftJWKSURL || m.cfg.IssuerFormat != microsoftIssuerFormat {
		t.Fatalf("ms defaults: %+v", m.cfg)
	}
	gh := NewGitHub(GitHubConfig{ClientID: "x", ClientSecret: "y"}).(*githubExchanger)
	if gh.cfg.TokenURL != githubTokenURL || gh.cfg.UserURL != githubUserURL || gh.cfg.UserMailURL != githubUserMailURL {
		t.Fatalf("gh defaults: %+v", gh.cfg)
	}
}

func TestExchanger_MissingCodeOrCreds(t *testing.T) {
	t.Parallel()
	g := NewGoogle(GoogleConfig{ClientID: "x", ClientSecret: "y"})
	if _, err := g.Exchange(context.Background(), "", "https://x"); !errors.Is(err, ErrCodeExchangeFailed) {
		t.Errorf("google empty code: %v", err)
	}
	g2 := NewGoogle(GoogleConfig{})
	if _, err := g2.Exchange(context.Background(), "code", "https://x"); !errors.Is(err, ErrCodeExchangeFailed) {
		t.Errorf("google empty creds: %v", err)
	}

	m := NewMicrosoft(MicrosoftConfig{})
	if _, err := m.Exchange(context.Background(), "code", "https://x"); !errors.Is(err, ErrCodeExchangeFailed) {
		t.Errorf("ms empty creds: %v", err)
	}
	m2 := NewMicrosoft(MicrosoftConfig{ClientID: "x", ClientSecret: "y"})
	if _, err := m2.Exchange(context.Background(), "", "https://x"); !errors.Is(err, ErrCodeExchangeFailed) {
		t.Errorf("ms empty code: %v", err)
	}

	gh := NewGitHub(GitHubConfig{})
	if _, err := gh.Exchange(context.Background(), "code", "https://x"); !errors.Is(err, ErrCodeExchangeFailed) {
		t.Errorf("gh empty creds: %v", err)
	}
	gh2 := NewGitHub(GitHubConfig{ClientID: "x", ClientSecret: "y"})
	if _, err := gh2.Exchange(context.Background(), "", "https://x"); !errors.Is(err, ErrCodeExchangeFailed) {
		t.Errorf("gh empty code: %v", err)
	}
}

// TestJWKSCache_StaleOnFetchFailure verifies that a transient JWKS
// fetch error returns the stale cached set rather than failing.
func TestJWKSCache_StaleOnFetchFailure(t *testing.T) {
	t.Parallel()
	key := newTestKey(t, "kid-A")
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(key.JWKJSON)
	}))
	t.Cleanup(srv.Close)

	cache := newJWKSCache(srv.URL, 0, srv.Client()) // ttl=0 → always refetch
	if _, err := cache.Get(context.Background()); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	fail.Store(true)
	got, err := cache.Get(context.Background())
	if err != nil {
		t.Fatalf("expected stale return on failure, got %v", err)
	}
	if got == nil {
		t.Fatal("expected cached set returned")
	}
}

func TestJWKSCache_FetchFailureNoCache(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := newJWKSCache(srv.URL, time.Hour, srv.Client())
	if _, err := c.Get(context.Background()); err == nil {
		t.Fatal("expected error with empty cache + failure")
	}
}

func TestJWKSCache_BadJSON(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	t.Cleanup(srv.Close)
	c := newJWKSCache(srv.URL, time.Hour, srv.Client())
	if _, err := c.Get(context.Background()); err == nil {
		t.Fatal("expected parse error")
	}
}

// TestVerifyJWS_BadAlg ensures alg-substitution attacks are rejected
// (signature with HS256 but JWKS contains an RSA key — wrong alg).
func TestVerifyJWS_BadAlg(t *testing.T) {
	t.Parallel()
	// Construct an HS256-signed JWS using a symmetric key so verifyJWS
	// must reject the alg before even attempting verification.
	hsKey, err := jwk.FromRaw([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("jwk.FromRaw: %v", err)
	}
	signed, err := jws.Sign([]byte(`{"sub":"x"}`), jws.WithKey(jwa.HS256, hsKey))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rsa := newTestKey(t, "kid-x")
	if _, err := verifyJWS(string(signed), rsa.JWKSet); err == nil {
		t.Fatal("expected verification to fail on HS256 alg")
	}
}

// TestVerifyJWS_NoKidMatch covers the "no jwk for kid" path.
func TestVerifyJWS_NoKidMatch(t *testing.T) {
	t.Parallel()
	signing := newTestKey(t, "kid-A")
	other := newTestKey(t, "kid-B") // serving set has different kid
	idToken := signing.signRawJWS(t, []byte(`{"sub":"x"}`))
	if _, err := verifyJWS(idToken, other.JWKSet); err == nil {
		t.Fatal("expected error when JWKS is missing the signing kid")
	}
}

// TestGoogle_JWKSRotationRetrySucceeds verifies that a JWKS rotation
// (cached set has stale keys; new fetch carries the matching kid) is
// recovered transparently via Invalidate + retry.
func TestGoogle_JWKSRotationRetrySucceeds(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)

	old := newTestKey(t, "kid-old")
	current := newTestKey(t, "kid-current")
	const clientID = "client-id"

	idToken := current.signIDToken(t, map[string]any{
		"iss":            "https://accounts.test",
		"sub":            "u",
		"aud":            clientID,
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"email":          "u@example.com",
		"email_verified": true,
	})

	var jwksHits atomic.Int32
	var jwksBody atomic.Value
	jwksBody.Store(old.JWKJSON) // first fetch sees the old key only

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			jwksHits.Add(1)
			body := jwksBody.Load().([]byte)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
			// After first fetch, swap to current key for the retry.
			jwksBody.Store(current.JWKJSON)
			return
		}
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id_token":"` + idToken + `"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	exch := NewGoogle(GoogleConfig{
		ClientID:     clientID,
		ClientSecret: "x",
		TokenURL:     srv.URL + "/token",
		JWKSURL:      srv.URL + "/jwks",
		Issuer:       "https://accounts.test",
		Now:          nowFunc(now),
		HTTPClient:   srv.Client(),
	})
	if _, err := exch.Exchange(context.Background(), "code", "https://x"); err != nil {
		t.Fatalf("Exchange after rotation: %v", err)
	}
	if got := jwksHits.Load(); got != 2 {
		t.Errorf("jwks hits = %d, want 2 (cache invalidate + retry)", got)
	}
}

// TestMicrosoft_MissingTID exercises the "missing tid" verification
// failure.
func TestMicrosoft_MissingTID(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-MS")
	fp := newFakeProvider(t)
	idToken := key.signIDToken(t, map[string]any{
		"sub":                "s",
		"aud":                "client-id",
		"iat":                now.Unix(),
		"exp":                now.Add(5 * time.Minute).Unix(),
		"preferred_username": "u@x.com",
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	exch := NewMicrosoft(MicrosoftConfig{
		ClientID:     "client-id",
		ClientSecret: "x",
		TokenURL:     fp.URL("/token"),
		JWKSURL:      fp.URL("/jwks"),
		IssuerFormat: "https://login.test/%s/v2.0",
		Now:          nowFunc(now),
	})
	_, err := exch.Exchange(context.Background(), "code", "https://x")
	if err == nil || !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
}

// TestMicrosoft_NoEmailFails covers the "missing email" path.
func TestMicrosoft_NoEmailFails(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, "kid-MS")
	fp := newFakeProvider(t)
	idToken := key.signIDToken(t, map[string]any{
		"iss": msIssuer(),
		"sub": "s",
		"oid": "o",
		"tid": msTenantID,
		"aud": "client-id",
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	})
	fp.tokenHandler = jsonHandler(map[string]any{"id_token": idToken})
	fp.jwksHandler = rawHandler(http.StatusOK, "application/json", key.JWKJSON)

	exch := NewMicrosoft(MicrosoftConfig{
		ClientID:     "client-id",
		ClientSecret: "x",
		TokenURL:     fp.URL("/token"),
		JWKSURL:      fp.URL("/jwks"),
		IssuerFormat: "https://login.test/%s/v2.0",
		Now:          nowFunc(now),
	})
	_, err := exch.Exchange(context.Background(), "code", "https://x")
	if err == nil || !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
}

// TestGoogle_NoIDToken covers the "provider returned no id_token" path.
func TestGoogle_NoIDToken(t *testing.T) {
	t.Parallel()
	fp := newFakeProvider(t)
	fp.tokenHandler = jsonHandler(map[string]any{"access_token": "tok"})
	exch := NewGoogle(GoogleConfig{
		ClientID:     "x",
		ClientSecret: "y",
		TokenURL:     fp.URL("/token"),
		JWKSURL:      fp.URL("/jwks"),
	})
	_, err := exch.Exchange(context.Background(), "code", "https://x")
	if err == nil || !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("want ErrCodeExchangeFailed, got %v", err)
	}
}

// TestGitHub_EmailEndpointBadJSON covers the parse error path on /user/emails.
func TestGitHub_EmailEndpointBadJSON(t *testing.T) {
	t.Parallel()
	fp := newFakeProvider(t)
	fp.tokenHandler = jsonHandler(map[string]any{"access_token": "tok"})
	fp.userHandler = jsonHandler(map[string]any{"id": 1, "login": "u"})
	fp.emailHandler = func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}
	exch := NewGitHub(GitHubConfig{
		ClientID:     "id",
		ClientSecret: "sec",
		TokenURL:     fp.URL("/token"),
		UserURL:      fp.URL("/user"),
		UserMailURL:  fp.URL("/user/emails"),
	})
	if _, err := exch.Exchange(context.Background(), "code", "https://x"); err == nil {
		t.Fatal("expected parse error")
	}
}

// TestVerifyJWS_BadJWS covers the parse-failure branch.
func TestVerifyJWS_BadJWS(t *testing.T) {
	t.Parallel()
	rsa := newTestKey(t, "kid-x")
	if _, err := verifyJWS("not-a-jws", rsa.JWKSet); err == nil {
		t.Fatal("expected parse error")
	}
}

// TestRegistry_Reregistration covers the replace-existing-entry branch.
func TestRegistry_Reregistration(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	r.Register("x", stubExchanger{name: "first"})
	r.Register("x", stubExchanger{name: "second"})
	got, _ := r.Get("x")
	if got.(stubExchanger).name != "second" {
		t.Fatalf("expected second, got %q", got.(stubExchanger).name)
	}
}

// TestGoogle_Exchange_BadResponseJSON covers the JSON-parse-failure
// branch on the token endpoint.
func TestGoogle_Exchange_BadResponseJSON(t *testing.T) {
	t.Parallel()
	fp := newFakeProvider(t)
	fp.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}
	exch := NewGoogle(GoogleConfig{
		ClientID:     "x",
		ClientSecret: "y",
		TokenURL:     fp.URL("/token"),
		JWKSURL:      fp.URL("/jwks"),
	})
	if _, err := exch.Exchange(context.Background(), "code", "https://x"); !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("want ErrCodeExchangeFailed, got %v", err)
	}
}

// TestMicrosoft_Exchange_NoIDToken covers the missing-id-token branch.
func TestMicrosoft_Exchange_NoIDToken(t *testing.T) {
	t.Parallel()
	fp := newFakeProvider(t)
	fp.tokenHandler = jsonHandler(map[string]any{"access_token": "x"})
	exch := NewMicrosoft(MicrosoftConfig{
		ClientID:     "id",
		ClientSecret: "sec",
		TokenURL:     fp.URL("/token"),
		JWKSURL:      fp.URL("/jwks"),
		IssuerFormat: "https://x/%s/v2.0",
	})
	if _, err := exch.Exchange(context.Background(), "code", "https://x"); !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("want ErrCodeExchangeFailed, got %v", err)
	}
}

// TestGitHub_NoAccessToken covers the missing-access-token branch.
func TestGitHub_NoAccessToken(t *testing.T) {
	t.Parallel()
	fp := newFakeProvider(t)
	fp.tokenHandler = jsonHandler(map[string]any{})
	exch := NewGitHub(GitHubConfig{
		ClientID:     "id",
		ClientSecret: "sec",
		TokenURL:     fp.URL("/token"),
		UserURL:      fp.URL("/user"),
		UserMailURL:  fp.URL("/user/emails"),
	})
	if _, err := exch.Exchange(context.Background(), "code", "https://x"); !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("want ErrCodeExchangeFailed, got %v", err)
	}
}

// TestGitHub_UserMissingID covers the missing-id branch.
func TestGitHub_UserMissingID(t *testing.T) {
	t.Parallel()
	fp := newFakeProvider(t)
	fp.tokenHandler = jsonHandler(map[string]any{"access_token": "tok"})
	fp.userHandler = jsonHandler(map[string]any{"login": "u"})
	exch := NewGitHub(GitHubConfig{
		ClientID:     "id",
		ClientSecret: "sec",
		TokenURL:     fp.URL("/token"),
		UserURL:      fp.URL("/user"),
		UserMailURL:  fp.URL("/user/emails"),
	})
	if _, err := exch.Exchange(context.Background(), "code", "https://x"); !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
}

// TestGitHub_UserBadJSON covers /user parse error.
func TestGitHub_UserBadJSON(t *testing.T) {
	t.Parallel()
	fp := newFakeProvider(t)
	fp.tokenHandler = jsonHandler(map[string]any{"access_token": "tok"})
	fp.userHandler = func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("nope"))
	}
	exch := NewGitHub(GitHubConfig{
		ClientID:     "id",
		ClientSecret: "sec",
		TokenURL:     fp.URL("/token"),
		UserURL:      fp.URL("/user"),
		UserMailURL:  fp.URL("/user/emails"),
	})
	if _, err := exch.Exchange(context.Background(), "code", "https://x"); err == nil {
		t.Fatal("expected parse error")
	}
}
