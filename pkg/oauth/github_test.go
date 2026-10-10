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

	exch := newGitHubForTest(fp)
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

func newGitHubForTest(fp *fakeProvider) Exchanger {
	return NewGitHub(GitHubConfig{
		ClientID:     "id",
		ClientSecret: "sec",
		TokenURL:     fp.URL("/token"),
		UserURL:      fp.URL("/user"),
		UserMailURL:  fp.URL("/user/emails"),
	})
}

func TestGitHub_UsesFirstVerifiedWhenPrimaryUnverified(t *testing.T) {
	t.Parallel()
	fp := newFakeProvider(t)
	fp.tokenHandler = jsonHandler(map[string]any{"access_token": "tok"})
	fp.userHandler = jsonHandler(map[string]any{
		"id":    3,
		"login": "u",
		"email": "public@example.com",
	})
	fp.emailHandler = jsonHandler([]map[string]any{
		{"email": "primary@example.com", "primary": true, "verified": false},
		{"email": "Second@Example.com", "primary": false, "verified": true},
		{"email": "third@example.com", "primary": false, "verified": true},
	})
	id, err := newGitHubForTest(fp).Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Email != "second@example.com" {
		t.Errorf("email = %q, want second@example.com", id.Email)
	}
}

func TestGitHub_ProfileEmailNeverUsedWithoutVerifiedAddress(t *testing.T) {
	t.Parallel()
	fp := newFakeProvider(t)
	fp.tokenHandler = jsonHandler(map[string]any{"access_token": "tok"})
	fp.userHandler = jsonHandler(map[string]any{
		"id":    1,
		"login": "u",
		"email": "victim@example.com",
	})
	fp.emailHandler = jsonHandler([]map[string]any{
		{"email": "victim@example.com", "primary": true, "verified": false},
	})
	id, err := newGitHubForTest(fp).Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
	if !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("want ErrEmailNotVerified, got id=%+v err=%v", id, err)
	}
}

func TestGitHub_EmailsUnavailableRejected(t *testing.T) {
	t.Parallel()
	fp := newFakeProvider(t)
	fp.tokenHandler = jsonHandler(map[string]any{"access_token": "tok"})
	fp.userHandler = jsonHandler(map[string]any{
		"id":    1,
		"login": "u",
		"email": "victim@example.com",
	})
	fp.emailHandler = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}
	id, err := newGitHubForTest(fp).Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
	if !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got id=%+v err=%v", id, err)
	}
}

func TestGitHub_NoEmailsRejected(t *testing.T) {
	t.Parallel()
	fp := newFakeProvider(t)
	fp.tokenHandler = jsonHandler(map[string]any{"access_token": "tok"})
	fp.userHandler = jsonHandler(map[string]any{
		"id":    1,
		"login": "u",
		"email": "victim@example.com",
	})
	fp.emailHandler = jsonHandler([]map[string]any{})
	id, err := newGitHubForTest(fp).Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
	if !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("want ErrEmailNotVerified, got id=%+v err=%v", id, err)
	}
}

func TestGitHub_TokenError(t *testing.T) {
	t.Parallel()
	fp := newFakeProvider(t)
	fp.tokenHandler = jsonHandler(map[string]any{
		"error":             "bad_verification_code",
		"error_description": "the code is bad",
	})
	exch := newGitHubForTest(fp)
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
	exch := newGitHubForTest(fp)
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
	exch := newGitHubForTest(fp)
	_, err := exch.Exchange(context.Background(), ExchangeParams{Code: "code", RedirectURI: "https://x"})
	if err == nil || !errors.Is(err, ErrIdentityVerification) {
		t.Fatalf("want ErrIdentityVerification, got %v", err)
	}
}
