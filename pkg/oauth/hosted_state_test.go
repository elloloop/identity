package oauth

import (
	"context"
	"testing"
	"time"
)

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
}

func TestHostedStateToken_RejectsExpired(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	ring := newOAuthStateSigner(t)

	token, err := IssueHostedStateToken(
		context.Background(), ring,
		"google", "https://identity.example.com/cb", "https://app.example.com/", "s", "v", "c",
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
		"google", "https://identity.example.com/cb", "https://app.example.com/", "s", "v", "c",
		5*time.Minute, now,
	)
	if err != nil {
		t.Fatalf("IssueHostedStateToken: %v", err)
	}
	tampered := token[:len(token)-2] + "AA"
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
		context.Background(), ring, "google", "https://cb", "", "s", "v", "c", time.Minute, now,
	); err == nil {
		t.Fatal("IssueHostedStateToken should reject an empty return_to")
	}
}
