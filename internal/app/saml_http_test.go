package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/pkg/samlidp"
)

func TestSAMLHandler_DisabledMountsNothing(t *testing.T) {
	mux := http.NewServeMux()
	(&samlHandler{issuer: samlidp.NewNoopIssuer(), logger: zap.NewNop()}).register(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, middleware.SAMLMetadataPath, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled IdP must 404, got %d", rec.Code)
	}
}

func TestSAMLHandler_EnabledServesMetadata(t *testing.T) {
	key, cert := samlTestKeyCert(t)
	iss, err := samlidp.NewRSAIssuer(samlidp.Options{
		EntityID: "https://idp/meta",
		SSOURL:   "https://idp/sso",
		KeyPEM:   []byte(key),
		CertPEM:  []byte(cert),
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	(&samlHandler{issuer: iss, logger: zap.NewNop()}).register(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, middleware.SAMLMetadataPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/samlmetadata+xml" {
		t.Fatalf("content-type = %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "EntityDescriptor") {
		t.Fatal("body missing EntityDescriptor")
	}
}

func TestSAMLHandler_MetadataRejectsNonGET(t *testing.T) {
	key, cert := samlTestKeyCert(t)
	iss, _ := samlidp.NewRSAIssuer(samlidp.Options{
		EntityID: "e", SSOURL: "s", KeyPEM: []byte(key), CertPEM: []byte(cert),
	})
	mux := http.NewServeMux()
	(&samlHandler{issuer: iss, logger: zap.NewNop()}).register(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, middleware.SAMLMetadataPath, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

// TestSAMLMetadata_ServedThroughFullChain asserts the public metadata document
// is reachable through the served middleware chain without a JWT: an SP that
// imports the IdP's certificate holds no identity session.
func TestSAMLMetadata_ServedThroughFullChain(t *testing.T) {
	key, cert := samlTestKeyCert(t)
	cfg := newTestConfig()
	cfg.SAMLIDPEnabled = true
	cfg.SAMLEntityID = "https://idp.example/saml/metadata"
	cfg.SAMLSSOURL = "https://idp.example/saml/sso"
	cfg.SAMLSigningKey = key
	cfg.SAMLSigningCert = cert
	handler, _, stop := buildTestApp(t, cfg)
	defer stop()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, middleware.SAMLMetadataPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("metadata: status = %d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "EntityDescriptor") {
		t.Fatalf("metadata body is not an EntityDescriptor: %s", rec.Body.String())
	}
}
