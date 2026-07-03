package oauth

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// FuzzVerifyIDToken is a Go fuzz target that feeds arbitrary bytes to the
// provider verify functions to prove they don't panic on garbage input.
func FuzzVerifyIDToken(f *testing.F) {
	// Seed the corpus with some interesting strings.
	f.Add("")
	f.Add("garbage")
	f.Add("eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZC1BIn0.garbage.sig")
	f.Add("eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZC1BIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.sig")

	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	key := newTestKey(f, "kid-A")

	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) *http.Response {
			if strings.HasSuffix(req.URL.Path, "/jwks") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(key.JWKJSON)),
					Header:     make(http.Header),
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"id_token":"ignore"}`)),
				Header:     make(http.Header),
			}
		}),
	}

	//nolint:gosec // test fake credentials
	apple := NewApple(AppleConfig{
		ClientID:   "client",
		TeamID:     "team",
		KeyID:      "key",
		PrivateKey: generateTestECDSAKey(f),
		TokenURL:   "https://apple/token",
		JWKSURL:    "https://apple/jwks",
		Issuer:     "https://appleid.apple.com",
		Now:        nowFunc(now),
		HTTPClient: client,
	})

	//nolint:gosec // test fake credentials
	google := NewGoogle(GoogleConfig{
		ClientID:   "client",
		TokenURL:   "https://google/token",
		JWKSURL:    "https://google/jwks",
		Issuer:     "https://accounts.test",
		Now:        nowFunc(now),
		HTTPClient: client,
	})

	//nolint:gosec // test fake credentials
	microsoft := NewMicrosoft(MicrosoftConfig{
		ClientID:   "client",
		TokenURL:   "https://microsoft/token",
		JWKSURL:    "https://microsoft/jwks",
		Now:        nowFunc(now),
		HTTPClient: client,
	})

	f.Fuzz(func(t *testing.T, token string) {
		ctx := context.Background()
		_, _ = apple.(*appleExchanger).verifyIDToken(ctx, token)
		_, _ = google.(*googleExchanger).verifyIDToken(ctx, token)
		_, _, _ = microsoft.(*microsoftExchanger).verifyIDToken(ctx, token)
	})
}

type roundTripFunc func(req *http.Request) *http.Response

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}
