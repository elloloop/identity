package postgres

import (
	"strings"
	"testing"
	"time"
)

func TestConfigApplyDefaultsAndValidate(t *testing.T) {
	cfg := Config{DSN: "postgres://example.com:5432/identity", ProjectID: "project"}
	cfg.applyDefaults()
	if cfg.MaxConns != DefaultMaxConns {
		t.Fatalf("MaxConns = %d", cfg.MaxConns)
	}
	if cfg.ConnTimeout != DefaultConnTimeout {
		t.Fatalf("ConnTimeout = %v", cfg.ConnTimeout)
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	var nilCfg *Config
	if err := nilCfg.validate(); err == nil || !strings.Contains(err.Error(), "nil config") {
		t.Fatalf("nil validate error = %v", err)
	}
	if err := (&Config{ProjectID: "project"}).validate(); err == nil || !strings.Contains(err.Error(), "DSN") {
		t.Fatalf("missing DSN error = %v", err)
	}
	if err := (&Config{DSN: "postgres://example.com:5432/identity"}).validate(); err == nil || !strings.Contains(err.Error(), "ProjectID") {
		t.Fatalf("missing project error = %v", err)
	}

	// A non-zero ConnTimeout (as injected from config.PostgresConnTimeoutMs via
	// repo.Build) is preserved, not overwritten by the default.
	injected := Config{DSN: "postgres://example.com:5432/identity", ProjectID: "p", ConnTimeout: 2500 * time.Millisecond}
	injected.applyDefaults()
	if injected.ConnTimeout != 2500*time.Millisecond {
		t.Fatalf("injected ConnTimeout overwritten = %v", injected.ConnTimeout)
	}
}
