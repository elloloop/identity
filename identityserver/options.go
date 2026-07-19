package identityserver

import (
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/captcha"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/idv"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/oauth"
	"github.com/elloloop/identity/pkg/sms"
)

// Config is the full identity configuration, re-exported so embedding
// programs can build it field-by-field without importing internal
// packages. It is the same struct cmd/identity loads from the
// environment; OptionsFromEnv populates it the same way the container
// binary does.
type Config = config.Config

// Options is the programmatic form of the configuration plus the
// adapters identity needs to run. The zero value is not usable; supply
// at least a Config (via OptionsFromEnv, or a hand-built one) and either
// let New build the persistence/signer adapters from Config (the
// container path) or inject your own.
//
// Two construction modes:
//
//   - Env/container parity: take OptionsFromEnv() and tweak fields. New
//     builds the Postgres repository, the JWT signer, the WebAuthn
//     service, the IDV provider, and OpenTelemetry from Config exactly as
//     cmd/identity does.
//
//   - Injected adapters: set Repo+DB (and optionally Signer, Passkeys,
//     EmailTransport, OAuthRegistry, IDVProvider). New uses whatever is
//     supplied and only builds the adapters left nil. This is how a host
//     that already owns a database, or a test, mounts identity without a
//     a real Postgres database.
type Options struct {
	// Config holds every env-driven setting (ports, tenant, JWT,
	// revocation mode, OAuth credentials, OTel, sweeper, etc.). Required.
	Config Config

	// Logger receives identity's structured logs. nil installs a no-op
	// logger; the container passes a zap production logger.
	Logger *zap.Logger

	// MetricsRegistry is where identity records its Prometheus RED
	// metrics. nil uses prometheus.DefaultRegisterer (what the container
	// wants). Tests pass an isolated registry to avoid collisions.
	MetricsRegistry prometheus.Registerer

	// ── Injected adapters (optional) ─────────────────────────────────
	// Any field left nil is built from Config by New. Supplying one
	// overrides the Config-driven construction for that adapter.

	// Signer mints and verifies access tokens. nil builds the
	// Config.JWTSigner backend (file or kms_aws), including the dev
	// fallback key when no keys file is configured.
	Signer jwt.Signer

	// Repo and DB are the persistence adapters. They must be supplied
	// together: either both nil (New builds them from Config.RepoDriver)
	// or both set (New uses them and skips driver construction).
	Repo service.Repository
	DB   service.DB

	// EmailTransport delivers outbound mail. nil builds a transport from
	// the SMTP settings in Config (falling back to log-only).
	EmailTransport email.Transport

	// SMSSender delivers outbound SMS for phone verification. nil builds a
	// sender from the GATEWAY_SMS_* settings in Config (log-only when SMS
	// is disabled).
	SMSSender sms.Sender

	// OAuthRegistry holds the per-provider exchangers. nil builds one
	// from the OAuth client credentials in Config.
	OAuthRegistry *oauth.Registry

	// IDVProvider drives document/selfie identity verification. nil
	// builds the Config.IDVProvider backend (which may itself be
	// disabled, leaving the IDV RPCs Unimplemented).
	IDVProvider idv.Provider

	// CaptchaVerifier gates the unauthenticated auth endpoints. nil builds
	// the Config.CaptchaProvider backend (the no-op verifier when CAPTCHA
	// is disabled).
	CaptchaVerifier captcha.Verifier

	// DNSResolver is the TXT-lookup boundary VerifyDomain uses to confirm a
	// custom domain's ownership challenge. nil defaults to net.DefaultResolver
	// — the production behaviour. A host (or a full-stack test) supplies its
	// own resolver to verify domains without touching real DNS. Has effect
	// only on the postgres control-plane driver, where the DomainService is
	// wired; other drivers leave the domain RPCs Unimplemented.
	DNSResolver service.DNSResolver

	// SynchronousEmailSend forces request-phase credential emails to send
	// inline rather than on a detached goroutine. Production leaves it false
	// (async, so SMTP latency cannot time the gated send decision); full-stack
	// tests that read the recording mailer immediately after a request set it
	// true for deterministic observation.
	SynchronousEmailSend bool
}

// OptionsFromEnv loads Options from the environment exactly as the
// container binary does: it reads every GATEWAY_* variable into Config
// and leaves all adapter fields nil so New builds them from that Config.
// This keeps cmd/identity a thin shim and gives env-driven deployers an
// identical entry point.
func OptionsFromEnv() Options {
	return Options{
		Config:          *config.Load(),
		MetricsRegistry: prometheus.DefaultRegisterer,
	}
}
