package config

import (
	"strconv"
	"strings"
	"testing"
)

const directoryRateLimitEnv = "GATEWAY_RATE_LIMIT_DIRECTORY_PER_IP"

func TestRateLimitDirectoryPerIP_FromEnv(t *testing.T) {
	for raw, want := range map[string]int{
		"":    DefaultRateLimitDirectoryPerIP,
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

// A value that would disable or silently replace the throttle is refused at
// boot rather than run unthrottled or on a default the operator did not pick.
func TestRateLimitDirectoryPerIP_RejectsNonPositiveOrMalformed(t *testing.T) {
	for _, raw := range []string{"0", "-5", "abc", "12.5", "1e3"} {
		t.Run("env="+raw, func(t *testing.T) {
			t.Setenv(directoryRateLimitEnv, raw)
			err := Load().Validate()
			if err == nil || !strings.Contains(err.Error(), directoryRateLimitEnv+"="+strconv.Quote(raw)) {
				t.Fatalf("Validate = %v, want an error naming %s and quoting %q", err, directoryRateLimitEnv, raw)
			}
		})
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
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), `="-3"`) {
		t.Fatalf("Validate = %v, want the negative cap refused and quoted", err)
	}
}
