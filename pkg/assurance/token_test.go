package assurance_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/elloloop/identity/pkg/assurance"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
)

var tokenNow = time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)

func TestMintAndVerifyToken(t *testing.T) {
	s := jwttest.NewSigner(t, "kid-1")
	tok, err := assurance.MintToken(context.Background(), s, assurance.TokenClaims{
		Project:   "proj-1",
		Providers: []string{assurance.ProviderAppAttest},
		DeviceID:  "dev-42",
	}, 0, tokenNow)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}

	claims, err := assurance.VerifyToken(tok, s, "proj-1", tokenNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims.Project != "proj-1" || claims.DeviceID != "dev-42" {
		t.Errorf("claims = %+v", claims)
	}
	if len(claims.Providers) != 1 || claims.Providers[0] != assurance.ProviderAppAttest {
		t.Errorf("Providers = %v", claims.Providers)
	}
	if claims.ExpiresAt != tokenNow.Add(assurance.DefaultTokenTTL).Unix() {
		t.Errorf("ExpiresAt = %d (default TTL not applied)", claims.ExpiresAt)
	}
}

func TestVerifyTokenRejections(t *testing.T) {
	s := jwttest.NewSigner(t, "kid-1")
	mint := func(claims assurance.TokenClaims, ttl time.Duration) string {
		t.Helper()
		tok, err := assurance.MintToken(context.Background(), s, claims, ttl, tokenNow)
		if err != nil {
			t.Fatalf("MintToken: %v", err)
		}
		return tok
	}
	base := assurance.TokenClaims{Project: "proj-1", Providers: []string{assurance.ProviderTurnstile}}

	t.Run("expired", func(t *testing.T) {
		tok := mint(base, time.Minute)
		if _, err := assurance.VerifyToken(tok, s, "proj-1", tokenNow.Add(2*time.Minute)); !errors.Is(err, assurance.ErrTokenInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("project mismatch", func(t *testing.T) {
		tok := mint(base, time.Minute)
		if _, err := assurance.VerifyToken(tok, s, "proj-2", tokenNow); !errors.Is(err, assurance.ErrTokenInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("scoped deployment rejects unscoped token", func(t *testing.T) {
		tok := mint(assurance.TokenClaims{Providers: []string{assurance.ProviderTurnstile}}, time.Minute)
		if _, err := assurance.VerifyToken(tok, s, "proj-1", tokenNow); !errors.Is(err, assurance.ErrTokenInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("unscoped verify accepts scoped token", func(t *testing.T) {
		tok := mint(base, time.Minute)
		if _, err := assurance.VerifyToken(tok, s, "", tokenNow); err != nil {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("unknown kid", func(t *testing.T) {
		tok := mint(base, time.Minute)
		other := jwttest.NewSigner(t, "kid-other")
		if _, err := assurance.VerifyToken(tok, other, "proj-1", tokenNow); !errors.Is(err, assurance.ErrTokenInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("garbage token", func(t *testing.T) {
		if _, err := assurance.VerifyToken("not.a.jwt", s, "", tokenNow); !errors.Is(err, assurance.ErrTokenInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("empty token", func(t *testing.T) {
		if _, err := assurance.VerifyToken("", s, "", tokenNow); !errors.Is(err, assurance.ErrTokenInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestAccessTokenIsNotAnAssuranceToken(t *testing.T) {
	s := jwttest.NewSigner(t, "kid-1")
	access, err := s.SignAccessToken(context.Background(), jwt.Claims{Sub: "user-1", Tenant: "t"}, time.Minute)
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	if _, err := assurance.VerifyToken(access, s, "", time.Now()); !errors.Is(err, assurance.ErrTokenInvalid) {
		t.Fatalf("access token verified as assurance token: err = %v", err)
	}
}

func TestAssuranceTokenIsNotAnAccessToken(t *testing.T) {
	// The inverse crossover: an assurance token (no sub) must never pass
	// access-token verification, even with audience checking off.
	s := jwttest.NewSigner(t, "kid-1")
	tok, err := assurance.MintToken(context.Background(), s, assurance.TokenClaims{
		Providers: []string{assurance.ProviderPlayIntegrity},
	}, time.Minute, time.Now())
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	if _, err := jwt.VerifyAccessToken(tok, s, "", "", false); err == nil {
		t.Fatal("assurance token verified as access token")
	}
}

func TestMintTokenRequiresProvider(t *testing.T) {
	s := jwttest.NewSigner(t, "kid-1")
	if _, err := assurance.MintToken(context.Background(), s, assurance.TokenClaims{}, time.Minute, tokenNow); err == nil {
		t.Fatal("MintToken succeeded with no providers")
	}
}
