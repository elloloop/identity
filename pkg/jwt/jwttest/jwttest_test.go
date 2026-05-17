package jwttest

import (
	"context"
	"testing"
	"time"

	"github.com/elloloop/identity/pkg/jwt"
)

func TestSigner_SignAndVerify(t *testing.T) {
	s := NewSigner(t, "test-kid")
	if got := s.ActiveKID(); got != "test-kid" {
		t.Fatalf("ActiveKID = %q, want test-kid", got)
	}

	tok, err := s.SignAccessToken(context.Background(), jwt.Claims{Sub: "u", Tenant: "t"}, time.Minute)
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	claims, err := jwt.VerifyAccessToken(tok, s, "t", "", false)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.Sub != "u" {
		t.Fatalf("sub = %q", claims.Sub)
	}
}

func TestSigner_AddAndPromoteAndDrop(t *testing.T) {
	s := NewSigner(t, "k1")
	s.AddKey(t, "k2")
	if len(s.Keys()) != 2 {
		t.Fatalf("Keys after AddKey = %d", len(s.Keys()))
	}
	if got := s.ActiveKID(); got != "k1" {
		t.Fatalf("ActiveKID after AddKey = %q", got)
	}

	s.SetActive("k2")
	if got := s.ActiveKID(); got != "k2" {
		t.Fatalf("ActiveKID after SetActive = %q", got)
	}

	// Tokens signed with k1 still verify (k1 is in the provider).
	tok2, err := s.SignAccessToken(context.Background(), jwt.Claims{Sub: "u"}, time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := jwt.VerifyAccessToken(tok2, s, "", "", false); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	s.DropKey("k1")
	if len(s.Keys()) != 1 {
		t.Fatalf("Keys after DropKey = %d", len(s.Keys()))
	}
	if _, ok := s.Get("k1"); ok {
		t.Fatalf("Get(k1) after DropKey = true")
	}
}

func TestSigner_SetActiveUnknownPanics(t *testing.T) {
	s := NewSigner(t, "k1")
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic")
		}
	}()
	s.SetActive("nope")
}

func TestSigner_Keys(t *testing.T) {
	s := NewSigner(t, "kid")
	pubs := s.Keys()
	if len(pubs) != 1 {
		t.Fatalf("Keys = %d", len(pubs))
	}
	if pubs[0].KID != "kid" {
		t.Fatalf("kid = %q", pubs[0].KID)
	}

	pub, ok := s.Get("kid")
	if !ok || pub == nil {
		t.Fatalf("Get(kid) = %v %v", pub, ok)
	}

	if _, ok := s.Get("unknown"); ok {
		t.Fatalf("Get(unknown) = true")
	}
}

func TestSigner_SignClaimsPropagates(t *testing.T) {
	s := NewSigner(t, "kid")
	tok, err := s.SignClaims(context.Background(), map[string]any{
		"sub": "u",
		"exp": time.Now().Add(time.Minute).Unix(),
		"iat": time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("SignClaims: %v", err)
	}
	if _, err := jwt.VerifyAccessToken(tok, s, "", "", false); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}
