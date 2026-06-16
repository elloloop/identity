package app

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/samlidp"
)

func samlTestKeyCert(t *testing.T) (key, cert string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	key = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
	cert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return key, cert
}

func TestBuildSAMLIssuer_DisabledReturnsNoop(t *testing.T) {
	iss, err := buildSAMLIssuer(&config.Config{SAMLIDPEnabled: false}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if iss.Enabled() || iss.Name() != samlidp.ProviderNoop {
		t.Fatalf("expected no-op issuer, got %s enabled=%v", iss.Name(), iss.Enabled())
	}
}

func TestBuildSAMLIssuer_EnabledReturnsRSA(t *testing.T) {
	key, cert := samlTestKeyCert(t)
	iss, err := buildSAMLIssuer(&config.Config{
		SAMLIDPEnabled:  true,
		SAMLEntityID:    "https://idp/meta",
		SAMLSSOURL:      "https://idp/sso",
		SAMLSigningKey:  key,
		SAMLSigningCert: cert,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !iss.Enabled() || iss.Name() != samlidp.ProviderRSA {
		t.Fatalf("expected RSA issuer, got %s enabled=%v", iss.Name(), iss.Enabled())
	}
}

func TestBuildSAMLIssuer_BadMaterialFailsClosed(t *testing.T) {
	_, err := buildSAMLIssuer(&config.Config{
		SAMLIDPEnabled:  true,
		SAMLEntityID:    "e",
		SAMLSSOURL:      "s",
		SAMLSigningKey:  "not pem",
		SAMLSigningCert: "not pem",
	}, nil)
	if err == nil {
		t.Fatal("expected error for invalid signing material")
	}
}
