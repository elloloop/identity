// Package assurance implements client-assurance verification: proving a
// request comes from a legitimate client before (and independently of)
// proving who the user is. It is the identity server's equivalent of
// Firebase App Check.
//
// Four providers cover the three client surfaces:
//
//   - Web: Cloudflare Turnstile and Google reCAPTCHA v3 — "a human
//     interacted with this page". These implement the narrow [Verifier]
//     interface below (a client-submitted token checked against the
//     provider's siteverify endpoint).
//   - iOS: Apple App Attest (subpackage appattest) — "a genuine build of
//     the app on genuine Apple hardware". Challenge-bound, stateful
//     (registers a hardware key, verifies assertions against it), so it
//     has its own API rather than forcing the token-in/pass-fail shape.
//   - Android: Google Play Integrity (subpackage playintegrity) — same
//     guarantee for Android, verdict-based.
//
// What every provider yields is an assurance *fact* about the request
// ("this client passed <provider>"), never an identity. The service layer
// exchanges a verified fact for a short-lived assurance token that clients
// attach to subsequent requests; the identity token is untouched.
//
// The [Verifier] interface is intentionally narrow: a deployment swaps
// web providers via config without the handler layer knowing which
// backend is in use. The handler passes the client-submitted token and
// the resolved client IP; the verifier decides pass/fail (reCAPTCHA
// additionally applies a score threshold internally).
package assurance

import (
	"context"
	"errors"
)

// Provider names select the implementation built from config and are the
// values recorded in an assurance token's `amr` claim. Turnstile and
// reCAPTCHA are the accepted web-provider values; AppAttest and
// PlayIntegrity name the attestation subpackages' providers.
const (
	ProviderTurnstile     = "turnstile"
	ProviderRecaptchaV3   = "recaptcha_v3"
	ProviderAppAttest     = "app_attest"
	ProviderPlayIntegrity = "play_integrity"
)

// ErrVerificationFailed indicates the evidence was rejected by the
// provider (siteverify returned success=false, the reCAPTCHA score fell
// below the configured threshold, an attestation failed a check, or the
// response was otherwise not a pass). The handler maps this to a
// permission-denied error so a client cannot distinguish a forged token
// from a genuine challenge failure.
var ErrVerificationFailed = errors.New("assurance: verification failed")

// ErrProviderUnavailable indicates the verifier could not reach the
// upstream verification endpoint or got an unusable response (network
// failure, non-200 status, malformed body). Distinct from
// ErrVerificationFailed so the handler can choose to surface a retryable
// error rather than a hard rejection.
var ErrProviderUnavailable = errors.New("assurance: provider unavailable")

// Verifier validates client-submitted web-assurance evidence (a CAPTCHA
// token). The service holds exactly one web Verifier for the lifetime of
// the process.
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
