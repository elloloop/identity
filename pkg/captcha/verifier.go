// Package captcha defines the pluggable CAPTCHA-verification provider
// interface and its in-tree implementations (Cloudflare Turnstile and
// Google reCAPTCHA v3) plus a no-op verifier for deployments that leave
// CAPTCHA disabled.
//
// The interface is intentionally narrow: a deployment swaps providers via
// config without the handler layer knowing which backend is in use. The
// handler passes the client-submitted token and the resolved client IP;
// the verifier decides pass/fail (reCAPTCHA additionally applies a score
// threshold internally).
package captcha

import (
	"context"
	"errors"
)

// Provider names select the implementation built from config. They are
// the accepted values of GATEWAY_CAPTCHA_PROVIDER.
const (
	ProviderTurnstile   = "turnstile"
	ProviderRecaptchaV3 = "recaptcha_v3"
)

// ErrVerificationFailed indicates the token was rejected by the provider
// (siteverify returned success=false, the reCAPTCHA score fell below the
// configured threshold, or the response was otherwise not a pass). The
// handler maps this to a permission-denied error so a client cannot
// distinguish a forged token from a genuine challenge failure.
var ErrVerificationFailed = errors.New("captcha: verification failed")

// ErrProviderUnavailable indicates the verifier could not reach the
// upstream siteverify endpoint or got an unusable response (network
// failure, non-200 status, malformed body). Distinct from
// ErrVerificationFailed so the handler can choose to surface a retryable
// error rather than a hard rejection.
var ErrProviderUnavailable = errors.New("captcha: provider unavailable")

// Verifier validates a client-submitted CAPTCHA token. The service holds
// exactly one Verifier for the lifetime of the process.
type Verifier interface {
	// Name returns the provider identifier (e.g. "turnstile",
	// "recaptcha_v3", "noop").
	Name() string

	// Verify checks token, optionally binding it to remoteip (the
	// resolved client IP; empty omits the binding). It returns nil when
	// the token is valid, ErrVerificationFailed when the provider rejects
	// it, and ErrProviderUnavailable when the check could not be
	// completed.
	Verify(ctx context.Context, token, remoteip string) error
}
