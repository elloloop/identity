package playintegrity_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/elloloop/identity/pkg/assurance"
	"github.com/elloloop/identity/pkg/assurance/playintegrity"
)

const (
	testPackage = "com.example.dictionary"
	testDigest  = "dGVzdC1jZXJ0LWRpZ2VzdA" // unpadded base64url, as Play reports
)

var testNow = time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)

// testSAKey generates a service-account key file with a fresh RSA key.
func testSAKey(t *testing.T, tokenURI string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	sa, err := json.Marshal(map[string]string{
		"client_email": "svc@test-project.iam.gserviceaccount.com",
		"private_key":  string(pemKey),
		"token_uri":    tokenURI,
	})
	if err != nil {
		t.Fatalf("marshal sa: %v", err)
	}
	return sa
}

// verdictPayload is a mutable decodeIntegrityToken response the fake
// Google server returns.
type verdictPayload struct {
	requestPackage string
	nonce          string
	timestampMs    int64
	timestampRaw   string // overrides timestampMs verbatim when non-empty
	appVerdict     string
	appPackage     string
	certDigests    []string
	deviceVerdicts []string
}

func validPayload(nonce []byte) *verdictPayload {
	return &verdictPayload{
		requestPackage: testPackage,
		nonce:          base64.RawURLEncoding.EncodeToString(nonce),
		timestampMs:    testNow.Add(-time.Minute).UnixMilli(),
		appVerdict:     "PLAY_RECOGNIZED",
		appPackage:     testPackage,
		certDigests:    []string{testDigest},
		deviceVerdicts: []string{"MEETS_DEVICE_INTEGRITY", "MEETS_BASIC_INTEGRITY"},
	}
}

func (p *verdictPayload) body() map[string]any {
	ts := strconv.FormatInt(p.timestampMs, 10)
	if p.timestampRaw != "" {
		ts = p.timestampRaw
	}
	return map[string]any{
		"tokenPayloadExternal": map[string]any{
			"requestDetails": map[string]any{
				"requestPackageName": p.requestPackage,
				"nonce":              p.nonce,
				"timestampMillis":    ts,
			},
			"appIntegrity": map[string]any{
				"appRecognitionVerdict":   p.appVerdict,
				"packageName":             p.appPackage,
				"certificateSha256Digest": p.certDigests,
				"versionCode":             "42",
			},
			"deviceIntegrity": map[string]any{
				"deviceRecognitionVerdict": p.deviceVerdicts,
			},
		},
	}
}

// fakeGoogle serves both the OAuth token endpoint and
// decodeIntegrityToken. It asserts the auth handshake shape and returns
// the configured payload.
type fakeGoogle struct {
	t          *testing.T
	payload    *verdictPayload
	decodeCode int
	tokenCalls int
	srv        *httptest.Server
}

func newFakeGoogle(t *testing.T, payload *verdictPayload) *fakeGoogle {
	t.Helper()
	f := &fakeGoogle{t: t, payload: payload, decodeCode: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		f.tokenCalls++
		if err := r.ParseForm(); err != nil {
			t.Errorf("token form: %v", err)
		}
		if got := r.Form.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Errorf("grant_type = %q", got)
		}
		if r.Form.Get("assertion") == "" {
			t.Error("empty assertion")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fake-access-token", "expires_in": 3600})
	})
	mux.HandleFunc(fmt.Sprintf("/v1/%s:decodeIntegrityToken", testPackage), func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer fake-access-token" {
			t.Errorf("Authorization = %q", got)
		}
		var req struct {
			IntegrityToken string `json:"integrityToken"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IntegrityToken == "" {
			t.Errorf("bad decode request: %v", err)
		}
		if f.decodeCode != http.StatusOK {
			w.WriteHeader(f.decodeCode)
			_, _ = w.Write([]byte(`{"error":{"message":"bad token"}}`))
			return
		}
		_ = json.NewEncoder(w).Encode(f.payload.body())
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGoogle) verifier(t *testing.T) *playintegrity.Verifier {
	t.Helper()
	v, err := playintegrity.New(playintegrity.Config{
		PackageName:        testPackage,
		CertSHA256Digests:  []string{testDigest},
		ServiceAccountJSON: testSAKey(t, f.srv.URL+"/token"),
		BaseURL:            f.srv.URL,
		HTTPClient:         f.srv.Client(),
		Now:                func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

func TestVerifyHappyPath(t *testing.T) {
	nonce := []byte("one-time-nonce")
	f := newFakeGoogle(t, validPayload(nonce))
	v := f.verifier(t)

	verdict, err := v.Verify(context.Background(), "integrity-token", nonce)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verdict.PackageName != testPackage || verdict.VersionCode != "42" {
		t.Errorf("verdict = %+v", verdict)
	}

	// Second call reuses the cached access token.
	if _, err := v.Verify(context.Background(), "integrity-token", nonce); err != nil {
		t.Fatalf("second Verify: %v", err)
	}
	if f.tokenCalls != 1 {
		t.Errorf("token endpoint called %d times, want 1 (cache)", f.tokenCalls)
	}
}

func TestVerifyPaddedDigestAndNonceNormalize(t *testing.T) {
	nonce := []byte("nonce-bytes")
	p := validPayload(nonce)
	p.nonce = base64.URLEncoding.EncodeToString(nonce) // padded variant
	p.certDigests = []string{testDigest + "=="}
	f := newFakeGoogle(t, p)
	if _, err := f.verifier(t).Verify(context.Background(), "tok", nonce); err != nil {
		t.Fatalf("Verify with padded encodings: %v", err)
	}
}

func TestVerifyRejections(t *testing.T) {
	nonce := []byte("nonce")
	cases := []struct {
		name   string
		mutate func(p *verdictPayload)
	}{
		{"wrong request package", func(p *verdictPayload) { p.requestPackage = "com.other" }},
		{"nonce mismatch", func(p *verdictPayload) { p.nonce = base64.RawURLEncoding.EncodeToString([]byte("other")) }},
		{"stale timestamp", func(p *verdictPayload) { p.timestampMs = testNow.Add(-time.Hour).UnixMilli() }},
		{"future timestamp", func(p *verdictPayload) { p.timestampMs = testNow.Add(time.Minute).UnixMilli() }},
		{"malformed timestamp", func(p *verdictPayload) { p.timestampRaw = "not-a-number" }},
		{"unrecognized app", func(p *verdictPayload) { p.appVerdict = "UNRECOGNIZED_VERSION" }},
		{"wrong app package", func(p *verdictPayload) { p.appPackage = "com.other" }},
		{"unknown cert digest", func(p *verdictPayload) { p.certDigests = []string{"c29tZS1vdGhlcg"} }},
		{"no cert digest", func(p *verdictPayload) { p.certDigests = nil }},
		{"device integrity missing", func(p *verdictPayload) { p.deviceVerdicts = []string{"MEETS_BASIC_INTEGRITY"} }},
		{"empty device verdicts", func(p *verdictPayload) { p.deviceVerdicts = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validPayload(nonce)
			tc.mutate(p)
			f := newFakeGoogle(t, p)
			_, err := f.verifier(t).Verify(context.Background(), "tok", nonce)
			if !errors.Is(err, assurance.ErrVerificationFailed) {
				t.Fatalf("err = %v, want ErrVerificationFailed", err)
			}
		})
	}
}

func TestVerifyGoogleRejectsToken(t *testing.T) {
	nonce := []byte("nonce")
	f := newFakeGoogle(t, validPayload(nonce))
	f.decodeCode = http.StatusBadRequest
	_, err := f.verifier(t).Verify(context.Background(), "tok", nonce)
	if !errors.Is(err, assurance.ErrVerificationFailed) {
		t.Fatalf("err = %v, want ErrVerificationFailed", err)
	}
}

func TestVerifyUpstreamUnavailable(t *testing.T) {
	nonce := []byte("nonce")
	f := newFakeGoogle(t, validPayload(nonce))
	f.decodeCode = http.StatusInternalServerError
	_, err := f.verifier(t).Verify(context.Background(), "tok", nonce)
	if !errors.Is(err, assurance.ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
}

func TestVerifyEmptyToken(t *testing.T) {
	f := newFakeGoogle(t, validPayload([]byte("n")))
	if _, err := f.verifier(t).Verify(context.Background(), "", []byte("n")); !errors.Is(err, assurance.ErrVerificationFailed) {
		t.Fatalf("err = %v, want ErrVerificationFailed", err)
	}
}

func TestNewConfigValidation(t *testing.T) {
	sa := testSAKey(t, "https://oauth2.googleapis.com/token")
	for _, tc := range []struct {
		name string
		cfg  playintegrity.Config
	}{
		{"missing package", playintegrity.Config{CertSHA256Digests: []string{testDigest}, ServiceAccountJSON: sa}},
		{"missing digests", playintegrity.Config{PackageName: testPackage, ServiceAccountJSON: sa}},
		{"empty digest", playintegrity.Config{PackageName: testPackage, CertSHA256Digests: []string{""}, ServiceAccountJSON: sa}},
		{"missing sa key", playintegrity.Config{PackageName: testPackage, CertSHA256Digests: []string{testDigest}}},
		{"garbage sa key", playintegrity.Config{PackageName: testPackage, CertSHA256Digests: []string{testDigest}, ServiceAccountJSON: []byte("{")}},
		{"sa key missing fields", playintegrity.Config{PackageName: testPackage, CertSHA256Digests: []string{testDigest}, ServiceAccountJSON: []byte(`{"client_email":"x"}`)}},
		{"sa key not pem", playintegrity.Config{PackageName: testPackage, CertSHA256Digests: []string{testDigest}, ServiceAccountJSON: []byte(`{"client_email":"x","private_key":"not-pem","token_uri":"https://t"}`)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := playintegrity.New(tc.cfg); err == nil {
				t.Fatal("New succeeded, want error")
			}
		})
	}
}
