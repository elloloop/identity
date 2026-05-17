package config

import (
	"testing"
	"time"
)

// TestRevocationModeEnv_DefaultIsTTL — unset env falls back to ttl,
// matching the documented default in docs/IDENTITY.md decision log §6.
func TestRevocationModeEnv_DefaultIsTTL(t *testing.T) {
	t.Setenv("GATEWAY_REVOCATION_MODE", "")
	cfg := Load()
	if cfg.RevocationMode != RevocationModeTTL {
		t.Fatalf("default = %q, want %q", cfg.RevocationMode, RevocationModeTTL)
	}
}

func TestRevocationModeEnv_SetSession(t *testing.T) {
	t.Setenv("GATEWAY_REVOCATION_MODE", "session")
	t.Setenv("GATEWAY_SESSION_CACHE_TTL_SECONDS", "120")
	cfg := Load()
	if cfg.RevocationMode != RevocationModeSession {
		t.Fatalf("mode = %q, want %q", cfg.RevocationMode, RevocationModeSession)
	}
	if cfg.SessionCacheTTLSeconds != 120 {
		t.Fatalf("ttl seconds = %d, want 120", cfg.SessionCacheTTLSeconds)
	}
}

func TestRevocationModeEnv_RejectsUnknownMode(t *testing.T) {
	cfg := Load()
	cfg.RevocationMode = "garbage"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate must reject garbage mode")
	}
}

// TestRevocationModeEnv_TTLCap is the regression test for the
// startup assertion: a deployer cannot raise GATEWAY_JWT_EXPIRY_SECONDS
// without explicitly switching to mode=session.
func TestRevocationModeEnv_TTLCap(t *testing.T) {
	t.Setenv("GATEWAY_REVOCATION_MODE", "ttl")
	t.Setenv("GATEWAY_JWT_EXPIRY_SECONDS", "1800")
	cfg := Load()
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate must reject 1800s access TTL in mode=ttl")
	}
}

func TestRevocationModeEnv_SessionAllowsLongerTTL(t *testing.T) {
	t.Setenv("GATEWAY_REVOCATION_MODE", "session")
	t.Setenv("GATEWAY_JWT_EXPIRY_SECONDS", "3600")
	cfg := Load()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("session mode must allow 3600s TTL: %v", err)
	}
}

func TestRevocationModeEnv_NegativeCacheTTL(t *testing.T) {
	cfg := Load()
	cfg.RevocationMode = RevocationModeSession
	cfg.SessionCacheTTLSeconds = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate must reject negative SessionCacheTTLSeconds")
	}
}

// TestRevocationModeEnv_UnrecognisedFallsBack is the regression for
// revocationModeFromEnv's default branch: garbage in env yields the
// safe default rather than crashing. Validate() then catches the
// configured-but-invalid case from a directly constructed Config.
func TestRevocationModeEnv_UnrecognisedFallsBack(t *testing.T) {
	t.Setenv("GATEWAY_REVOCATION_MODE", "garbage")
	cfg := Load()
	if cfg.RevocationMode != RevocationModeTTL {
		t.Fatalf("garbage env → mode = %q, want default %q", cfg.RevocationMode, RevocationModeTTL)
	}
}

// TestValidate_EmptyModeDefaultsToTTL exercises the empty-mode arm
// inside Validate so a directly-constructed Config (test, scaffold)
// still resolves to the documented default rather than failing
// validation on an unset enum.
func TestValidate_EmptyModeDefaultsToTTL(t *testing.T) {
	cfg := &Config{
		JWTExpirySeconds: 900,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate empty mode: %v", err)
	}
	if cfg.RevocationMode != RevocationModeTTL {
		t.Fatalf("Validate did not default empty mode to ttl: %q", cfg.RevocationMode)
	}
}

// TestSessionCacheTTL_RoundTrip covers the Duration accessor used
// by the middleware wiring.
func TestSessionCacheTTL_RoundTrip(t *testing.T) {
	cases := []struct {
		secs int
		want time.Duration
	}{
		{0, 0},
		{60, 60 * time.Second},
		{300, 5 * time.Minute},
	}
	for _, tc := range cases {
		cfg := &Config{SessionCacheTTLSeconds: tc.secs}
		if got := cfg.SessionCacheTTL(); got != tc.want {
			t.Errorf("SessionCacheTTL(%d) = %v, want %v", tc.secs, got, tc.want)
		}
	}
}
