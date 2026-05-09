package postgres

import (
	"strings"
	"testing"
	"time"
)

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("GATEWAY_POSTGRES_DSN", "postgres://example.com:5432/identity")
	t.Setenv("GATEWAY_POSTGRES_MAX_CONNS", "17")
	t.Setenv("GATEWAY_POSTGRES_CONN_TIMEOUT_MS", "2500")
	t.Setenv("GATEWAY_POSTGRES_AUTO_MIGRATE", "no")

	cfg := ConfigFromEnv("tenant-1")
	if cfg.DSN != "postgres://example.com:5432/identity" {
		t.Fatalf("DSN = %q", cfg.DSN)
	}
	if cfg.MaxConns != 17 {
		t.Fatalf("MaxConns = %d", cfg.MaxConns)
	}
	if cfg.ConnTimeout != 2500*time.Millisecond {
		t.Fatalf("ConnTimeout = %v", cfg.ConnTimeout)
	}
	if cfg.AutoMigrate {
		t.Fatal("AutoMigrate = true")
	}
	if cfg.TenantID != "tenant-1" {
		t.Fatalf("TenantID = %q", cfg.TenantID)
	}
}

func TestConfigFromEnvDefaultsInvalidValues(t *testing.T) {
	t.Setenv("GATEWAY_POSTGRES_MAX_CONNS", "not-an-int")
	t.Setenv("GATEWAY_POSTGRES_CONN_TIMEOUT_MS", "bad-timeout")
	t.Setenv("GATEWAY_POSTGRES_AUTO_MIGRATE", "maybe")

	cfg := ConfigFromEnv("tenant-defaults")
	if cfg.MaxConns != DefaultMaxConns {
		t.Fatalf("MaxConns = %d", cfg.MaxConns)
	}
	if cfg.ConnTimeout != DefaultConnTimeout {
		t.Fatalf("ConnTimeout = %v", cfg.ConnTimeout)
	}
	if !cfg.AutoMigrate {
		t.Fatal("AutoMigrate = false")
	}
}

func TestConfigApplyDefaultsAndValidate(t *testing.T) {
	cfg := Config{DSN: "postgres://example.com:5432/identity", TenantID: "tenant"}
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
	if err := (&Config{TenantID: "tenant"}).validate(); err == nil || !strings.Contains(err.Error(), "DSN") {
		t.Fatalf("missing DSN error = %v", err)
	}
	if err := (&Config{DSN: "postgres://example.com:5432/identity"}).validate(); err == nil || !strings.Contains(err.Error(), "TenantID") {
		t.Fatalf("missing tenant error = %v", err)
	}
}
