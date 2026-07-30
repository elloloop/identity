// Package playintegrity verifies Google Play Integrity verdicts
// server-side: the integrity token a client obtains from the Play
// Integrity API is decoded via Google's decodeIntegrityToken endpoint
// (never locally), and the resulting verdict is checked against the
// deployment's app identity. It proves a request originates from an
// unmodified, Play-recognized build of the app on a device that passes
// Android device integrity.
//
// Google steers integrations toward server-side decoding with a
// Google-authenticated call rather than local decryption with app-managed
// keys; this package implements only the server-side form. The OAuth
// service-account handshake is hand-rolled on the jwx dependency already
// in the tree (see tokenSource) instead of importing the
// google.golang.org/api client stack.
package playintegrity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/elloloop/identity/pkg/assurance"
)

// defaultBaseURL is the Play Integrity API endpoint.
const defaultBaseURL = "https://playintegrity.googleapis.com"

// scope is the OAuth scope decodeIntegrityToken requires.
const scope = "https://www.googleapis.com/auth/playintegrity"

// DefaultMaxTokenAge bounds how old a verdict's requestDetails timestamp
// may be. Play integrity tokens are minted per-request; a stale one is a
// replay.
const DefaultMaxTokenAge = 10 * time.Minute

// maxResponseBytes caps a decodeIntegrityToken response read.
const maxResponseBytes = 1 << 20

// Verdict values this package requires.
const (
	verdictPlayRecognized       = "PLAY_RECOGNIZED"
	verdictMeetsDeviceIntegrity = "MEETS_DEVICE_INTEGRITY"
)

// Config configures a Verifier for one Android app.
type Config struct {
	// PackageName is the app's Android package name; every verdict must
	// carry it in both requestDetails and appIntegrity.
	PackageName string

	// CertSHA256Digests are the allowed app-signing certificate digests
	// (unpadded base64url of the SHA-256, as Play reports them). At least
	// one must appear in the verdict's appIntegrity.
	CertSHA256Digests []string

	// ServiceAccountJSON is the Google service-account key file content
	// used to authenticate decodeIntegrityToken calls.
	ServiceAccountJSON []byte

	// MaxTokenAge bounds verdict freshness; zero uses DefaultMaxTokenAge.
	MaxTokenAge time.Duration

	// BaseURL and HTTPClient override the API endpoint and transport
	// (tests point these at a fake server). Zero values use the Google
	// endpoint and a 10s-timeout client. TokenURL overrides the OAuth
	// token endpoint from the service-account file.
	BaseURL    string
	HTTPClient *http.Client
	TokenURL   string

	// Now overrides the clock. nil uses time.Now.
	Now func() time.Time
}

// Verifier decodes and checks Play Integrity tokens. Safe for concurrent
// use.
type Verifier struct {
	packageName string
	certDigests map[string]struct{}
	maxAge      time.Duration
	baseURL     string
	client      *http.Client
	tokens      *tokenSource
	now         func() time.Time
}

// New returns a Verifier for cfg.
func New(cfg Config) (*Verifier, error) {
	if cfg.PackageName == "" {
		return nil, errors.New("playintegrity: PackageName is required")
	}
	if len(cfg.CertSHA256Digests) == 0 {
		return nil, errors.New("playintegrity: at least one certificate digest is required")
	}
	digests := make(map[string]struct{}, len(cfg.CertSHA256Digests))
	for _, d := range cfg.CertSHA256Digests {
		if d == "" {
			return nil, errors.New("playintegrity: empty certificate digest")
		}
		digests[normalizeB64(d)] = struct{}{}
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	tokens, err := newTokenSource(cfg.ServiceAccountJSON, cfg.TokenURL, client, now)
	if err != nil {
		return nil, err
	}
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	maxAge := cfg.MaxTokenAge
	if maxAge <= 0 {
		maxAge = DefaultMaxTokenAge
	}
	return &Verifier{
		packageName: cfg.PackageName,
		certDigests: digests,
		maxAge:      maxAge,
		baseURL:     strings.TrimRight(baseURL, "/"),
		client:      client,
		tokens:      tokens,
		now:         now,
	}, nil
}

// Verdict is the verified outcome: the facts a caller may want to audit.
type Verdict struct {
	PackageName string
	VersionCode string
	// DeviceVerdicts echoes deviceRecognitionVerdict (e.g. it may
	// additionally contain MEETS_STRONG_INTEGRITY).
	DeviceVerdicts []string
}

// tokenPayload mirrors the decodeIntegrityToken response body (v1,
// standard API requests).
type tokenPayload struct {
	TokenPayloadExternal struct {
		RequestDetails struct {
			RequestPackageName string `json:"requestPackageName"`
			Nonce              string `json:"nonce"`
			TimestampMillis    string `json:"timestampMillis"`
		} `json:"requestDetails"`
		AppIntegrity struct {
			AppRecognitionVerdict string   `json:"appRecognitionVerdict"`
			PackageName           string   `json:"packageName"`
			CertificateSha256     []string `json:"certificateSha256Digest"`
			VersionCode           string   `json:"versionCode"`
		} `json:"appIntegrity"`
		DeviceIntegrity struct {
			DeviceRecognitionVerdict []string `json:"deviceRecognitionVerdict"`
		} `json:"deviceIntegrity"`
	} `json:"tokenPayloadExternal"`
}

// failf wraps assurance.ErrVerificationFailed with step detail.
func failf(format string, args ...any) error {
	return fmt.Errorf("%w: playintegrity: %s", assurance.ErrVerificationFailed, fmt.Sprintf(format, args...))
}

// Verify decodes integrityToken via Google and checks the verdict:
// package name, nonce binding to expectedNonce, timestamp freshness,
// PLAY_RECOGNIZED app integrity with an allowed signing-cert digest, and
// MEETS_DEVICE_INTEGRITY.
//
// expectedNonce is the challenge STRING the server issued and the client
// passed verbatim to the Play Integrity API. Play echoes that string back
// in requestDetails.nonce, so the comparison is string-to-string (padding
// normalized, since the challenge is itself base64url and producers differ
// on padding). Single-use enforcement is the caller's job.
func (v *Verifier) Verify(ctx context.Context, integrityToken, expectedNonce string) (*Verdict, error) {
	if integrityToken == "" {
		return nil, failf("empty integrity token")
	}
	payload, err := v.decode(ctx, integrityToken)
	if err != nil {
		return nil, err
	}
	ext := payload.TokenPayloadExternal

	if ext.RequestDetails.RequestPackageName != v.packageName {
		return nil, failf("request package %q, want %q", ext.RequestDetails.RequestPackageName, v.packageName)
	}
	if expectedNonce == "" || normalizeB64(ext.RequestDetails.Nonce) != normalizeB64(expectedNonce) {
		return nil, failf("nonce mismatch")
	}
	tsMillis, err := strconv.ParseInt(ext.RequestDetails.TimestampMillis, 10, 64)
	if err != nil {
		return nil, failf("malformed verdict timestamp %q", ext.RequestDetails.TimestampMillis)
	}
	age := v.now().Sub(time.UnixMilli(tsMillis))
	if age < 0 || age > v.maxAge {
		return nil, failf("verdict timestamp outside freshness window (age %s)", age)
	}

	if ext.AppIntegrity.AppRecognitionVerdict != verdictPlayRecognized {
		return nil, failf("app recognition verdict %q", ext.AppIntegrity.AppRecognitionVerdict)
	}
	if ext.AppIntegrity.PackageName != v.packageName {
		return nil, failf("app integrity package %q, want %q", ext.AppIntegrity.PackageName, v.packageName)
	}
	digestOK := false
	for _, d := range ext.AppIntegrity.CertificateSha256 {
		if _, ok := v.certDigests[normalizeB64(d)]; ok {
			digestOK = true
			break
		}
	}
	if !digestOK {
		return nil, failf("no allowed signing-certificate digest in verdict")
	}

	deviceOK := false
	for _, verdict := range ext.DeviceIntegrity.DeviceRecognitionVerdict {
		if verdict == verdictMeetsDeviceIntegrity {
			deviceOK = true
			break
		}
	}
	if !deviceOK {
		return nil, failf("device integrity verdicts %v lack %s", ext.DeviceIntegrity.DeviceRecognitionVerdict, verdictMeetsDeviceIntegrity)
	}

	return &Verdict{
		PackageName:    ext.AppIntegrity.PackageName,
		VersionCode:    ext.AppIntegrity.VersionCode,
		DeviceVerdicts: ext.DeviceIntegrity.DeviceRecognitionVerdict,
	}, nil
}

// decode calls decodeIntegrityToken and parses the verdict payload.
// Transport, auth, and non-200 failures map to ErrProviderUnavailable —
// the evidence wasn't judged, so the caller may surface a retryable
// error; only Google-rejected tokens (400) map to ErrVerificationFailed.
func (v *Verifier) decode(ctx context.Context, integrityToken string) (*tokenPayload, error) {
	accessToken, err := v.tokens.get(ctx)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(map[string]string{"integrityToken": integrityToken})
	if err != nil {
		return nil, fmt.Errorf("playintegrity: encoding request: %w", err)
	}
	url := fmt.Sprintf("%s/v1/%s:decodeIntegrityToken", v.baseURL, v.packageName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("playintegrity: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: playintegrity: %w", assurance.ErrProviderUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: playintegrity: reading response: %w", assurance.ErrProviderUnavailable, err)
	}
	switch {
	case resp.StatusCode == http.StatusBadRequest:
		// Google judged the token and rejected it (malformed, expired,
		// or not for this app).
		return nil, failf("decodeIntegrityToken rejected token: %s", truncateForLog(raw))
	case resp.StatusCode/100 != 2:
		return nil, fmt.Errorf("%w: playintegrity: HTTP %d: %s", assurance.ErrProviderUnavailable, resp.StatusCode, truncateForLog(raw))
	}

	var payload tokenPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("%w: playintegrity: decoding response: %w", assurance.ErrProviderUnavailable, err)
	}
	return &payload, nil
}

// normalizeB64 strips base64 padding so digests and nonces compare
// equal regardless of whether the producer padded them.
func normalizeB64(s string) string { return strings.TrimRight(s, "=") }

// truncateForLog bounds an upstream error body embedded in an error.
func truncateForLog(b []byte) string {
	const max = 512
	if len(b) > max {
		return string(b[:max]) + "…"
	}
	return string(b)
}
