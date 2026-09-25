package config

import (
	"strings"
	"testing"
)

const (
	directoryRateLimitEnv = "GATEWAY_RATE_LIMIT_DIRECTORY_PER_IP"
	scimRateLimitEnv      = "GATEWAY_RATE_LIMIT_SCIM_PER_IP"
)

// The directory cap is parsed like every other GATEWAY_* integer: a positive
// value is taken as-is, and unset, zero or malformed input leaves the
// default in force — never an unthrottled lookup.
func TestRateLimitDirectoryPerIP_FromEnv(t *testing.T) {
	for raw, want := range map[string]int{
		"":    DefaultRateLimitDirectoryPerIP,
		"0":   DefaultRateLimitDirectoryPerIP,
		"abc": DefaultRateLimitDirectoryPerIP,
		"1e3": DefaultRateLimitDirectoryPerIP,
		"300": 300,
		"1":   1,
	} {
		t.Run("env="+raw, func(t *testing.T) {
			t.Setenv(directoryRateLimitEnv, raw)
			cfg := Load()
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if cfg.RateLimitDirectoryPerIP != want {
				t.Fatalf("RateLimitDirectoryPerIP = %d, want %d", cfg.RateLimitDirectoryPerIP, want)
			}
		})
	}
}

// A negative cap is refused at boot rather than read as "disabled", the
// meaning a non-positive value has on the other per-IP caps.
func TestRateLimitDirectoryPerIP_RejectsNegative(t *testing.T) {
	t.Setenv(directoryRateLimitEnv, "-5")
	err := Load().Validate()
	if err == nil || !strings.Contains(err.Error(), directoryRateLimitEnv+"=-5") {
		t.Fatalf("Validate = %v, want an error naming %s=-5", err, directoryRateLimitEnv)
	}
}

// A Config built in code (an embedder, a test) that leaves the field zero
// gets the default cap; a negative one is refused like the env value.
func TestRateLimitDirectoryPerIP_BuiltInCode(t *testing.T) {
	cfg := Load()
	cfg.RateLimitDirectoryPerIP = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.RateLimitDirectoryPerIP != DefaultRateLimitDirectoryPerIP {
		t.Fatalf("zero field = %d after Validate, want the default %d", cfg.RateLimitDirectoryPerIP, DefaultRateLimitDirectoryPerIP)
	}

	cfg.RateLimitDirectoryPerIP = -3
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), directoryRateLimitEnv+"=-3") {
		t.Fatalf("Validate = %v, want the negative cap refused", err)
	}
}

func TestRateLimitSCIMPerIP_FromEnv(t *testing.T) {
	for raw, want := range map[string]int{
		"":    300,
		"abc": 300,
		"0":   0,
		"50":  50,
	} {
		t.Run("env="+raw, func(t *testing.T) {
			t.Setenv(scimRateLimitEnv, raw)
			cfg := Load()
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if cfg.RateLimitSCIMPerIP != want {
				t.Fatalf("RateLimitSCIMPerIP = %d, want %d", cfg.RateLimitSCIMPerIP, want)
			}
		})
	}
}

func TestRateLimitSCIMPerIP_RejectsNegative(t *testing.T) {
	t.Setenv(scimRateLimitEnv, "-1")
	err := Load().Validate()
	if err == nil || !strings.Contains(err.Error(), scimRateLimitEnv+"=-1") {
		t.Fatalf("Validate = %v, want an error naming %s=-1", err, scimRateLimitEnv)
	}
}
