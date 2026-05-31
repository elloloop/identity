package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// turnstileVerifyURL is the Cloudflare Turnstile siteverify endpoint.
const turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// defaultVerifyTimeout bounds an outbound siteverify call. Shared by both
// HTTP providers.
const defaultVerifyTimeout = 5 * time.Second

// maxVerifyResponseBytes caps how much of a siteverify response body is
// read, so a hostile or buggy upstream cannot exhaust memory.
const maxVerifyResponseBytes = 1 << 16

// TurnstileConfig configures a TurnstileVerifier. Secret is the Cloudflare
// Turnstile secret key; everything else is optional.
type TurnstileConfig struct {
	Secret     string
	HTTPClient *http.Client // optional override for tests
	VerifyURL  string       // optional override for tests; defaults to turnstileVerifyURL
}

// TurnstileVerifier implements Verifier against Cloudflare Turnstile.
//
// API reference:
//
//	POST https://challenges.cloudflare.com/turnstile/v0/siteverify
//	form: secret, response, [remoteip]
type TurnstileVerifier struct {
	secret    string
	client    *http.Client
	verifyURL string
}

// NewTurnstileVerifier returns a TurnstileVerifier. Secret is required;
// the HTTP client and verify URL fall back to sensible defaults.
func NewTurnstileVerifier(cfg TurnstileConfig) (*TurnstileVerifier, error) {
	if cfg.Secret == "" {
		return nil, errors.New("captcha/turnstile: secret required")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultVerifyTimeout}
	}
	verifyURL := cfg.VerifyURL
	if verifyURL == "" {
		verifyURL = turnstileVerifyURL
	}
	return &TurnstileVerifier{
		secret:    cfg.Secret,
		client:    client,
		verifyURL: verifyURL,
	}, nil
}

// Name implements Verifier.
func (v *TurnstileVerifier) Name() string { return ProviderTurnstile }

// Verify implements Verifier.
func (v *TurnstileVerifier) Verify(ctx context.Context, token, remoteip string) error {
	if token == "" {
		return ErrVerificationFailed
	}

	form := url.Values{}
	form.Set("secret", v.secret)
	form.Set("response", token)
	if remoteip != "" {
		form.Set("remoteip", remoteip)
	}

	var out struct {
		Success    bool     `json:"success"`
		ErrorCodes []string `json:"error-codes"`
	}
	if err := postSiteVerify(ctx, v.client, v.verifyURL, form, &out); err != nil {
		return err
	}

	if !out.Success {
		return fmt.Errorf("%w: turnstile error-codes %v", ErrVerificationFailed, out.ErrorCodes)
	}
	return nil
}

// postSiteVerify POSTs an x-www-form-urlencoded siteverify request and
// decodes the JSON response into out. It is shared by both HTTP providers:
// non-200 status, transport failure, and malformed JSON all map to
// ErrProviderUnavailable.
func postSiteVerify(ctx context.Context, client *http.Client, verifyURL string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("captcha: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProviderUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		return fmt.Errorf("%w: HTTP %d: %s", ErrProviderUnavailable, resp.StatusCode, snippet)
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, maxVerifyResponseBytes)).Decode(out); err != nil {
		return fmt.Errorf("%w: decode response: %w", ErrProviderUnavailable, err)
	}
	return nil
}
