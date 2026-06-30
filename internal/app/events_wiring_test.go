package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/pkg/events"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
)

// eventsTestConfig returns a minimal-but-valid Config for exercising
// app.New, mirroring TestNewBuildsHealthHandler. Callers flip the
// webhook fields on top of this.
func eventsTestConfig() *config.Config {
	return &config.Config{ // #nosec G101 -- passkey relying-party settings are public WebAuthn metadata.
		DefaultTenantID:               "tenant",
		AuthAllowLocal:                true,
		PasswordSignupEnabled:         true,
		PasswordResetEnabled:          true,
		AllowedOrigins:                "http://localhost:9002",
		JWTExpirySeconds:              900,
		RefreshExpirySeconds:          604800,
		LoginMaxFailedAttempts:        5,
		LoginLockoutSeconds:           900,
		LoginChallengeExpirySeconds:   300,
		PasskeyRPID:                   "localhost",
		PasskeyRPName:                 "Identity Test",
		PasskeyOrigin:                 "http://localhost:9002",
		PasskeyChallengeExpirySeconds: 300,
		QRLoginBaseURL:                "http://localhost:9002",
		QRLoginExpirySeconds:          300,
		TOTPIssuer:                    "Identity Test",
		PasswordResetExpirySeconds:    3600,
	}
}

// enableWebhooks turns on outbound eventing with the per-field minimums
// Config.Validate requires.
func enableWebhooks(cfg *config.Config) {
	cfg.WebhooksEnabled = true
	cfg.WebhooksMaxAttempts = 3
	cfg.WebhooksBackoffBaseSeconds = 1
	cfg.WebhooksBackoffMaxSeconds = 30
	cfg.WebhooksWorkerIntervalSeconds = 1
	cfg.WebhooksBatchSize = 10
}

func newEventsTestApp(t *testing.T, cfg *config.Config, logger *zap.Logger, metrics prometheus.Registerer) *Built {
	t.Helper()
	signer := jwttest.NewSigner(t, "app-test")
	passkeyService, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   "localhost",
		RPName: "Identity Test",
		Origin: "http://localhost:9002",
	})
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}
	repo := memory.New()
	built, err := New(Deps{
		Config:             cfg,
		Logger:             logger,
		Signer:             signer,
		Repo:               repo,
		DB:                 repo,
		Passkeys:           passkeyService,
		TOTPKey:            []byte("01234567890123456789012345678901"),
		TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		MetricsRegistry:    metrics,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return built
}

// TestNewWiresWebhookWorker proves that enabling GATEWAY_WEBHOOKS_ENABLED
// constructs the outbox-backed event publisher and its delivery worker,
// and that the worker goroutine starts and drains cleanly across
// Start/Stop. With webhooks disabled the same path must build and run
// without spinning up any event worker.
func TestNewWiresWebhookWorker(t *testing.T) {
	t.Run("enabled starts and stops cleanly", func(t *testing.T) {
		cfg := eventsTestConfig()
		enableWebhooks(cfg)

		built := newEventsTestApp(t, cfg, zap.NewNop(), nil)
		built.Start()
		// Idempotent Start/Stop: the second Start is a no-op, and Stop must
		// cancel the worker context and return without blocking.
		built.Start()
		built.Stop()
		built.Stop()

		// The handler still serves after the event worker has drained.
		rr := httptest.NewRecorder()
		built.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("health status = %d", rr.Code)
		}
	})

	t.Run("disabled runs without an event worker", func(t *testing.T) {
		cfg := eventsTestConfig()
		built := newEventsTestApp(t, cfg, zap.NewNop(), nil)
		// Stop without Start, then Start/Stop: all must be no-op-safe when no
		// event worker was wired.
		built.Stop()
		built.Start()
		built.Stop()
	})

	t.Run("session revocation mode with a nil logger and webhooks", func(t *testing.T) {
		cfg := eventsTestConfig()
		enableWebhooks(cfg)
		// Exercise the session-cache wiring branch alongside the event worker,
		// and the nil-logger default (New falls back to zap.NewNop()).
		cfg.RevocationMode = config.RevocationModeSession
		cfg.SessionCacheTTLSeconds = 30
		// Isolated registry so the session metrics don't collide with the
		// default registry across test runs.
		built := newEventsTestApp(t, cfg, nil, prometheus.NewRegistry())
		built.Start()
		t.Cleanup(built.Stop)

		rr := httptest.NewRecorder()
		built.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("health status = %d", rr.Code)
		}
	})
}

// TestWebhookFailureHook proves the abandonment hook surfaces a failed
// delivery as a structured error log rather than swallowing it.
func TestWebhookFailureHook(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)
	hook := newWebhookFailureHook(zap.New(core))

	hook(&events.Delivery{
		EventID:        "evt_abc",
		SubscriptionID: "sub_123",
		Attempts:       5,
		LastError:      "connection refused",
	})

	entries := logs.FilterMessage("webhook_delivery_abandoned").All()
	if len(entries) != 1 {
		t.Fatalf("expected 1 abandonment log, got %d", len(entries))
	}
	fields := entries[0].ContextMap()
	if fields["event_id"] != "evt_abc" {
		t.Errorf("event_id = %v", fields["event_id"])
	}
	if fields["subscription_id"] != "sub_123" {
		t.Errorf("subscription_id = %v", fields["subscription_id"])
	}
	if fields["attempts"] != int64(5) {
		t.Errorf("attempts = %v", fields["attempts"])
	}
	if fields["last_error"] != "connection refused" {
		t.Errorf("last_error = %v", fields["last_error"])
	}
	if entries[0].Level != zapcore.ErrorLevel {
		t.Errorf("level = %v, want error", entries[0].Level)
	}
}

// TestRandomEventID proves the outbox id generator produces correctly
// prefixed, non-empty, unique ids (the idempotency key for at-least-once
// delivery).
func TestRandomEventID(t *testing.T) {
	const n = 1000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id := randomEventID()
		if !strings.HasPrefix(id, "evt_") {
			t.Fatalf("id %q missing evt_ prefix", id)
		}
		// "evt_" + 32 hex chars (16 random bytes).
		if len(id) != len("evt_")+32 {
			t.Fatalf("id %q has unexpected length %d", id, len(id))
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate id generated: %q", id)
		}
		seen[id] = struct{}{}
	}
}
