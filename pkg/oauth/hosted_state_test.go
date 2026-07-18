package oauth

import (
	"context"
	"testing"
	"time"
)

func TestProjectKeyState_JoinSplit(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, key, token string
	}{
		{"no key", "", "eyJhbGciOi.eyJmbG93Ijo.c2ln"},
		{"simple key", "pk_live_abc", "eyJhbGciOi.eyJmbG93Ijo.c2ln"},
		{"key containing separators", "proj:with:colon", "eyJhbGciOi.eyJmbG93Ijo.c2ln"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			composite := JoinProjectKeyState(tc.key, tc.token)
			key, token := SplitProjectKeyState(composite)
			if key != tc.key {
				t.Errorf("key = %q, want %q", key, tc.key)
			}
			if token != tc.token {
				t.Errorf("token = %q, want %q", token, tc.token)
			}
		})
	}
}

// A bare token with no prefix splits to an empty key — the default-project
// flow round-trips unchanged.
func TestProjectKeyState_SplitBareToken(t *testing.T) {
	t.Parallel()

	key, token := SplitProjectKeyState("eyJhbGciOi.eyJmbG93Ijo.c2ln")
	if key != "" {
		t.Errorf("key = %q, want empty", key)
	}
	if token != "eyJhbGciOi.eyJmbG93Ijo.c2ln" {
		t.Errorf("token = %q", token)
	}
}

func TestHostedStateToken_RoundTrip(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	ring := newOAuthStateSigner(t)
	ctx := context.Background()

	token, err := IssueHostedStateToken(
		ctx, ring,
		"google",
		"https://identity.example.com/oauth/callback/google",
		"https://app.example.com/finish",
		"state-abc",
		"verifier-abc",
		"csrf-123",
		"proj-123",
		5*time.Minute,
		now,
	)
	if err != nil {
		t.Fatalf("IssueHostedStateToken: %v", err)
	}

	claims, err := VerifyHostedStateToken(token, ring, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("VerifyHostedStateToken: %v", err)
	}
	if claims.Provider != "google" {
		t.Errorf("provider = %q, want google", claims.Provider)
	}
	if claims.ReturnTo != "https://app.example.com/finish" {
		t.Errorf("return_to = %q", claims.ReturnTo)
	}
	if claims.CodeVerifier != "verifier-abc" {
		t.Errorf("code_verifier = %q", claims.CodeVerifier)
	}
	if claims.RedirectURI != "https://identity.example.com/oauth/callback/google" {
		t.Errorf("redirect_uri = %q", claims.RedirectURI)
	}
	if claims.CSRFToken != "csrf-123" {
		t.Errorf("csrf_token = %q", claims.CSRFToken)
	}
	if claims.ProjectID != "proj-123" {
		t.Errorf("project_id = %q", claims.ProjectID)
	}
}

func TestHostedStateToken_RejectsExpired(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	ring := newOAuthStateSigner(t)

	token, err := IssueHostedStateToken(
		context.Background(), ring,
		"google", "https://identity.example.com/cb", "https://app.example.com/", "s", "v", "c", "proj-123",
		5*time.Minute, now,
	)
	if err != nil {
		t.Fatalf("IssueHostedStateToken: %v", err)
	}
	if _, err := VerifyHostedStateToken(token, ring, now.Add(10*time.Minute)); err == nil {
		t.Fatal("VerifyHostedStateToken should reject an expired token")
	}
}

func TestHostedStateToken_RejectsTampered(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	ring := newOAuthStateSigner(t)

	token, err := IssueHostedStateToken(
		context.Background(), ring,
		"google", "https://identity.example.com/cb", "https://app.example.com/", "s", "v", "c", "proj-123",
		5*time.Minute, now,
	)
	if err != nil {
		t.Fatalf("IssueHostedStateToken: %v", err)
	}
	// Flip the second-to-last signature char to a guaranteed-different base64url
	// value. Overwriting the final char with a fixed literal (as this test used
	// to) is a no-op when the token already ends in that literal, and the final
	// char also carries base64 padding bits a flip may not change on decode — so
	// mutate the always-meaningful second-to-last char instead, making the
	// corruption deterministic.
	b := []byte(token)
	i := len(b) - 2
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	tampered := string(b)
	if _, err := VerifyHostedStateToken(tampered, ring, now.Add(time.Minute)); err == nil {
		t.Fatal("VerifyHostedStateToken should reject a tampered token")
	}
}

func TestHostedStateToken_RejectsHeadlessToken(t *testing.T) {
	t.Parallel()

	// A headless state token (no flow=hosted claim) must not validate as
	// a hosted token — they are deliberately separate artifacts.
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	ring := newOAuthStateSigner(t)

	headless, err := IssueStateToken(
		context.Background(), ring,
		"google", "https://identity.example.com/cb", "state-x", "verifier-x",
		5*time.Minute, now,
	)
	if err != nil {
		t.Fatalf("IssueStateToken: %v", err)
	}
	if _, err := VerifyHostedStateToken(headless, ring, now.Add(time.Minute)); err == nil {
		t.Fatal("VerifyHostedStateToken should reject a headless token")
	}
}

func TestHostedStateToken_MissingClaims(t *testing.T) {
	t.Parallel()

	ring := newOAuthStateSigner(t)
	now := time.Now().UTC()
	if _, err := IssueHostedStateToken(
		context.Background(), ring, "google", "https://cb", "", "s", "v", "c", "proj-123", time.Minute, now,
	); err == nil {
		t.Fatal("IssueHostedStateToken should reject an empty return_to")
	}
}
