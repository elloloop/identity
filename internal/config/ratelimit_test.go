package config

import (
	"strings"
	"testing"
)

const (
	directoryRateLimitEnv = "GATEWAY_RATE_LIMIT_DIRECTORY_PER_IP"
	scimRateLimitEnv      = "GATEWAY_RATE_LIMIT_SCIM_PER_IP"
	qrPollRateLimitEnv    = "GATEWAY_RATE_LIMIT_QR_POLL_PER_IP"
	phoneMatchLimitEnv    = "GATEWAY_RATE_LIMIT_PHONE_MATCH_PER_TENANT"
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

// The phone-match cap is held like the directory cap: unset, zero or
// malformed input keeps the default, a negative value is refused at boot,
// and a Config built in code that leaves it zero gets the default.
func TestRateLimitPhoneMatchPerTenant(t *testing.T) {
	for raw, want := range map[string]int{
		"":    DefaultRateLimitPhoneMatchPerTenant,
		"0":   DefaultRateLimitPhoneMatchPerTenant,
		"abc": DefaultRateLimitPhoneMatchPerTenant,
		"5":   5,
	} {
		t.Run("env="+raw, func(t *testing.T) {
			t.Setenv(phoneMatchLimitEnv, raw)
			cfg := Load()
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if cfg.RateLimitPhoneMatchPerTenant != want {
				t.Fatalf("RateLimitPhoneMatchPerTenant = %d, want %d", cfg.RateLimitPhoneMatchPerTenant, want)
			}
		})
	}

	t.Run("negative", func(t *testing.T) {
		t.Setenv(phoneMatchLimitEnv, "-2")
		if err := Load().Validate(); err == nil || !strings.Contains(err.Error(), phoneMatchLimitEnv+"=-2") {
			t.Fatalf("Validate = %v, want an error naming %s=-2", err, phoneMatchLimitEnv)
		}
	})

	t.Run("built in code", func(t *testing.T) {
		cfg := Load()
		cfg.RateLimitPhoneMatchPerTenant = 0
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		if cfg.RateLimitPhoneMatchPerTenant != DefaultRateLimitPhoneMatchPerTenant {
			t.Fatalf("zero field = %d after Validate, want the default %d", cfg.RateLimitPhoneMatchPerTenant, DefaultRateLimitPhoneMatchPerTenant)
		}
	})
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

func TestRateLimitQrPollPerIP_FromEnv(t *testing.T) {
	for raw, want := range map[string]int{
		"":    DefaultRateLimitQrPollPerIP,
		"abc": DefaultRateLimitQrPollPerIP,
		"0":   0,
		"50":  50,
	} {
		t.Run("env="+raw, func(t *testing.T) {
			t.Setenv(qrPollRateLimitEnv, raw)
			cfg := Load()
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if cfg.RateLimitQrPollPerIP != want {
				t.Fatalf("RateLimitQrPollPerIP = %d, want %d", cfg.RateLimitQrPollPerIP, want)
			}
		})
	}
}

func TestRateLimitQrPollPerIP_RejectsNegative(t *testing.T) {
	t.Setenv(qrPollRateLimitEnv, "-1")
	err := Load().Validate()
	if err == nil || !strings.Contains(err.Error(), qrPollRateLimitEnv+"=-1") {
		t.Fatalf("Validate = %v, want an error naming %s=-1", err, qrPollRateLimitEnv)
	}
}

func TestRateLimitManagedChildAuthPerIP(t *testing.T) {
	const key = "GATEWAY_RATE_LIMIT_MANAGED_CHILD_AUTH_PER_IP"
	for raw, want := range map[string]int{"": 1200, "0": 1200, "invalid": 1200, "3000": 3000} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv(key, raw)
			cfg := Load()
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			if cfg.RateLimitManagedChildAuthPerIP != want {
				t.Fatalf("got %d want %d", cfg.RateLimitManagedChildAuthPerIP, want)
			}
		})
	}
	t.Setenv(key, "-1")
	if err := Load().Validate(); err == nil || !strings.Contains(err.Error(), key) {
		t.Fatalf("negative budget accepted: %v", err)
	}
	cfg := Load()
	cfg.RateLimitManagedChildAuthPerIP = 0
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.RateLimitManagedChildAuthPerIP != DefaultRateLimitManagedChildAuthPerIP {
		t.Fatal("zero disabled limit")
	}
}
