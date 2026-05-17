package config

import (
	"testing"
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
