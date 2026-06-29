package oauth

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestGitHub_ExchangeSuccess(t *testing.T) {
	t.Parallel()
	fp := newFakeProvider(t)
	fp.tokenHandler = jsonHandler(map[string]any{
		"access_token": "gho_xxx",
		"token_type":   "bearer",
		"scope":        "user:email",
	})
	fp.userHandler = jsonHandler(map[string]any{
		"id":         98765,
		"login":      "octocat",
		"name":       "The Octocat",
		"avatar_url": "https://gh/avatar.png",
		"email":      "public@github.com", // public profile email; should be ignored when /emails has primary
	})
	fp.emailHandler = jsonHandler([]map[string]any{
		{"email": "secondary@example.com", "primary": false, "verified": true},
		{"email": "primary@example.com", "primary": true, "verified": true},
		{"email": "junk@example.com", "primary": false, "verified": false},
	})

	exch := NewGitHub(GitHubConfig{
		ClientID:     "id",
		ClientSecret: "sec",
		TokenURL:     fp.URL("/token"),
		UserURL:      fp.URL("/user"),
		UserMailURL:  fp.URL("/user/emails"),
	})
	id, err := exch.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Email != "primary@example.com" {
		t.Errorf("email = %q, want primary@example.com", id.Email)
	}
	if id.ProviderUserID != "98765" {
		t.Errorf("provider id = %q", id.ProviderUserID)
	}
	if id.Provider != "github" {
		t.Errorf("provider = %q", id.Provider)
	}
	if id.Name != "The Octocat" {
		t.Errorf("name = %q", id.Name)
	}
}

func TestGitHub_FallsBackToProfileEmail(t *testing.T) {
	t.Parallel()
	fp := newFakeProvider(t)
	fp.tokenHandler = jsonHandler(map[string]any{
		"access_token": "gho_xxx",
	})
	fp.userHandler = jsonHandler(map[string]any{
		"id":    1,
		"login": "u",
		"email": "fallback@example.com",
	})
	fp.emailHandler = func(w http.ResponseWriter, r *http.Request) {
		// Simulate user:email scope missing.
		w.WriteHeader(http.StatusForbidden)
	}

	exch := NewGitHub(GitHubConfig{
		ClientID:     "id",
		ClientSecret: "sec",
		TokenURL:     fp.URL("/token"),
		UserURL:      fp.URL("/user"),
		UserMailURL:  fp.URL("/user/emails"),
	})
	id, err := exch.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Email != "fallback@example.com" {
		t.Errorf("email = %q", id.Email)
	}
}

func TestGitHub_NoVerifiedEmailRejected(t *testing.T) {
	t.Parallel()
	fp := newFakeProvider(t)
	fp.tokenHandler = jsonHandler(map[string]any{"access_token": "tok"})
	fp.userHandler = jsonHandler(map[string]any{
		"id":    7,
		"login": "ghost",
	})
	fp.emailHandler = jsonHandler([]map[string]any{
		{"email": "u@example.com", "primary": true, "verified": false},
	})
	exch := NewGitHub(GitHubConfig{
		ClientID:     "id",
		ClientSecret: "sec",
		TokenURL:     fp.URL("/token"),
		UserURL:      fp.URL("/user"),
		UserMailURL:  fp.URL("/user/emails"),
	})
	_, err := exch.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
	if err == nil || !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("want ErrEmailNotVerified, got %v", err)
	}
}

func TestGitHub_TokenError(t *testing.T) {
	t.Parallel()
	fp := newFakeProvider(t)
	fp.tokenHandler = jsonHandler(map[string]any{
		"error":             "bad_verification_code",
		"error_description": "the code is bad",
	})
	exch := NewGitHub(GitHubConfig{
		ClientID:     "id",
		ClientSecret: "sec",
		TokenURL:     fp.URL("/token"),
		UserURL:      fp.URL("/user"),
		UserMailURL:  fp.URL("/user/emails"),
	})
	_, err := exch.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
	if err == nil || !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("want ErrCodeExchangeFailed, got %v", err)
	}
}

func TestGitHub_TokenEndpoint500(t *testing.T) {
	t.Parallel()
	fp := newFakeProvider(t)
	fp.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}
	exch := NewGitHub(GitHubConfig{
		ClientID:     "id",
		ClientSecret: "sec",
		TokenURL:     fp.URL("/token"),
		UserURL:      fp.URL("/user"),
		UserMailURL:  fp.URL("/user/emails"),
	})
	_, err := exch.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
	if err == nil || !errors.Is(err, ErrCodeExchangeFailed) {
		t.Fatalf("want ErrCodeExchangeFailed, got %v", err)
	}
}

func TestGitHub_UserEndpointFailure(t *testing.T) {
	t.Parallel()
	fp := newFakeProvider(t)
	fp.tokenHandler = jsonHandler(map[string]any{"access_token": "tok"})
	fp.userHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}
	exch := NewGitHub(GitHubConfig{
		ClientID:     "id",
		ClientSecret: "sec",
		TokenURL:     fp.URL("/token"),
		UserURL:      fp.URL("/user"),
		UserMailURL:  fp.URL("/user/emails"),
	})
	_, err := exch.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
	if err == nil || !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
}
