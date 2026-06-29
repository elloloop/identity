package samlidp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// genKeyPair produces a throwaway RSA key + self-signed cert in PEM for tests.
func genKeyPair(t *testing.T) (keyPEM, certPEM []byte, key *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "identity-saml-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return keyPEM, certPEM, key
}

func newTestIssuer(t *testing.T) (*RSAIssuer, *rsa.PrivateKey) {
	t.Helper()
	keyPEM, certPEM, key := genKeyPair(t)
	iss, err := NewRSAIssuer(Options{
		EntityID: "https://idp.example.com/saml/metadata",
		SSOURL:   "https://idp.example.com/saml/sso",
		SLOURL:   "https://idp.example.com/saml/slo",
		KeyPEM:   keyPEM,
		CertPEM:  certPEM,
	})
	if err != nil {
		t.Fatalf("NewRSAIssuer: %v", err)
	}
	return iss, key
}

func TestNoopIssuer_Disabled(t *testing.T) {
	var n NoopIssuer
	if n.Enabled() {
		t.Fatal("noop must not be enabled")
	}
	if n.Name() != ProviderNoop {
		t.Fatalf("name = %q", n.Name())
	}
	if _, err := n.Metadata(); !errors.Is(err, ErrDisabled) {
		t.Fatalf("Metadata err = %v", err)
	}
	if _, err := n.ParseAuthnRequest(nil, ""); !errors.Is(err, ErrDisabled) {
		t.Fatalf("ParseAuthnRequest err = %v", err)
	}
	if _, err := n.Issue(context.Background(), ServiceProvider{}, Subject{}, AuthnRequestInfo{}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("Issue err = %v", err)
	}
}

func TestNewRSAIssuer_Validation(t *testing.T) {
	keyPEM, certPEM, _ := genKeyPair(t)
	otherKeyPEM, _, _ := genKeyPair(t)

	tests := []struct {
		name string
		opts Options
	}{
		{"missing entityID", Options{SSOURL: "x", KeyPEM: keyPEM, CertPEM: certPEM}},
		{"missing ssoURL", Options{EntityID: "x", KeyPEM: keyPEM, CertPEM: certPEM}},
		{"bad key pem", Options{EntityID: "x", SSOURL: "y", KeyPEM: []byte("nope"), CertPEM: certPEM}},
		{"bad cert pem", Options{EntityID: "x", SSOURL: "y", KeyPEM: keyPEM, CertPEM: []byte("nope")}},
		{"key/cert mismatch", Options{EntityID: "x", SSOURL: "y", KeyPEM: otherKeyPEM, CertPEM: certPEM}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewRSAIssuer(tc.opts); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestMetadata_ContainsEndpointsAndCert(t *testing.T) {
	iss, _ := newTestIssuer(t)
	md, err := iss.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	// Must be well-formed XML.
	if err := xml.Unmarshal(md, new(struct{ XMLName xml.Name })); err != nil {
		t.Fatalf("metadata not well-formed: %v", err)
	}
	s := string(md)
	for _, want := range []string{
		`entityID="https://idp.example.com/saml/metadata"`,
		"https://idp.example.com/saml/sso",
		"https://idp.example.com/saml/slo",
		"<md:SingleSignOnService",
		"<md:SingleLogoutService",
		"<ds:X509Certificate>" + iss.certBase64(),
	} {
		if !strings.Contains(s, want) {
			t.Errorf("metadata missing %q", want)
		}
	}
}

func TestMetadata_NoSLOWhenUnset(t *testing.T) {
	keyPEM, certPEM, _ := genKeyPair(t)
	iss, err := NewRSAIssuer(Options{EntityID: "e", SSOURL: "s", KeyPEM: keyPEM, CertPEM: certPEM})
	if err != nil {
		t.Fatal(err)
	}
	md, _ := iss.Metadata()
	if strings.Contains(string(md), "SingleLogoutService") {
		t.Fatal("SLO must be omitted when no SLOURL configured")
	}
}

func TestParseAuthnRequest(t *testing.T) {
	iss, _ := newTestIssuer(t)
	raw := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req123" AssertionConsumerServiceURL="https://sp.example.com/acs"><saml:Issuer>https://sp.example.com/saml</saml:Issuer></samlp:AuthnRequest>`
	info, err := iss.ParseAuthnRequest([]byte(raw), "relay-abc")
	if err != nil {
		t.Fatal(err)
	}
	if info.ID != "_req123" || info.Issuer != "https://sp.example.com/saml" ||
		info.ACSURL != "https://sp.example.com/acs" || info.RelayState != "relay-abc" {
		t.Fatalf("unexpected parse: %+v", info)
	}
}

func TestParseAuthnRequest_Invalid(t *testing.T) {
	iss, _ := newTestIssuer(t)
	cases := []string{
		`not xml`,
		`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">sp</saml:Issuer></samlp:AuthnRequest>`, // missing ID
		`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_x"></samlp:AuthnRequest>`,                                                                         // missing Issuer
	}
	for _, c := range cases {
		if _, err := iss.ParseAuthnRequest([]byte(c), ""); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestIssue_SignedAssertionVerifies(t *testing.T) {
	iss, key := newTestIssuer(t)
	sp := ServiceProvider{
		EntityID: "https://sp.example.com/saml",
		ACSURL:   "https://sp.example.com/acs",
	}
	req := AuthnRequestInfo{ID: "_req123", Issuer: sp.EntityID, RelayState: "rs"}
	subj := Subject{NameID: "alice@acme.com", Attributes: map[string]string{"email": "alice@acme.com", "role": "admin"}}

	resp, err := iss.Issue(context.Background(), sp, subj, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ACSURL != sp.ACSURL || resp.RelayState != "rs" {
		t.Fatalf("response routing wrong: %+v", resp)
	}
	x := string(resp.XML)
	// Well-formed and carries the expected subject + InResponseTo.
	if err := xml.Unmarshal(resp.XML, new(struct{ XMLName xml.Name })); err != nil {
		t.Fatalf("response not well-formed: %v", err)
	}
	for _, want := range []string{
		"alice@acme.com",
		`InResponseTo="_req123"`,
		"urn:oasis:names:tc:SAML:2.0:status:Success",
		`Name="email"`,
		`Name="role"`,
		"<ds:Signature",
	} {
		if !strings.Contains(x, want) {
			t.Errorf("response missing %q", want)
		}
	}

	verifyAssertionSignature(t, x, &key.PublicKey)
}

// verifyAssertionSignature extracts the assertion, recomputes the digest
// over the assertion-with-signature-removed, and verifies SignatureValue
// over SignedInfo — proving the produced XML-DSig is cryptographically
// valid (the SP-side check, in miniature).
func verifyAssertionSignature(t *testing.T, responseXML string, pub *rsa.PublicKey) {
	t.Helper()

	assertion := between(t, responseXML, "<saml:Assertion ", "</saml:Assertion>")
	assertion = "<saml:Assertion " + assertion + "</saml:Assertion>"

	signature := "<ds:Signature " + between(t, assertion, "<ds:Signature ", "</ds:Signature>") + "</ds:Signature>"
	signedInfo := "<ds:SignedInfo " + between(t, signature, "<ds:SignedInfo ", "</ds:SignedInfo>") + "</ds:SignedInfo>"

	// 1. Verify the digest: remove the whole Signature element from the
	// assertion (enveloped-signature transform) and SHA-256 it.
	stripped := strings.Replace(assertion, signature, "", 1)
	gotDigest := sha256.Sum256([]byte(stripped))
	wantDigestB64 := between(t, signedInfo, "<ds:DigestValue>", "</ds:DigestValue>")
	if base64.StdEncoding.EncodeToString(gotDigest[:]) != wantDigestB64 {
		t.Fatal("digest mismatch: assertion was altered or canonicalization differs")
	}

	// 2. Verify the signature over SignedInfo.
	sigB64 := between(t, signature, "<ds:SignatureValue>", "</ds:SignatureValue>")
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	siDigest := sha256.Sum256([]byte(signedInfo))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, siDigest[:], sigBytes); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

func between(t *testing.T, s, start, end string) string {
	t.Helper()
	i := strings.Index(s, start)
	if i < 0 {
		t.Fatalf("start %q not found", start)
	}
	rest := s[i+len(start):]
	j := strings.Index(rest, end)
	if j < 0 {
		t.Fatalf("end %q not found", end)
	}
	return rest[:j]
}

func TestIssue_RejectsUnknownSP(t *testing.T) {
	iss, _ := newTestIssuer(t)
	sp := ServiceProvider{EntityID: "https://sp.example.com/saml", ACSURL: "https://sp.example.com/acs"}
	req := AuthnRequestInfo{ID: "_r", Issuer: "https://attacker.example.com"}
	if _, err := iss.Issue(context.Background(), sp, Subject{NameID: "a@b.c"}, req); err == nil {
		t.Fatal("expected ErrUnknownServiceProvider")
	}
}

func TestIssue_RequiresSubjectAndSP(t *testing.T) {
	iss, _ := newTestIssuer(t)
	good := ServiceProvider{EntityID: "e", ACSURL: "a"}
	if _, err := iss.Issue(context.Background(), good, Subject{}, AuthnRequestInfo{}); err == nil {
		t.Fatal("expected error for empty NameID")
	}
	if _, err := iss.Issue(context.Background(), ServiceProvider{}, Subject{NameID: "x"}, AuthnRequestInfo{}); err == nil {
		t.Fatal("expected error for empty SP")
	}
}

func TestIssue_ACSFallbackOnMismatch(t *testing.T) {
	iss, _ := newTestIssuer(t)
	sp := ServiceProvider{EntityID: "e", ACSURL: "https://trusted/acs"}
	req := AuthnRequestInfo{ID: "_r", Issuer: "e", ACSURL: "https://evil/acs"}
	resp, err := iss.Issue(context.Background(), sp, Subject{NameID: "x@y.z"}, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ACSURL != "https://trusted/acs" {
		t.Fatalf("must fall back to registered ACS, got %q", resp.ACSURL)
	}
}

func TestIssue_DeterministicTime(t *testing.T) {
	fixed := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	old := now
	now = func() time.Time { return fixed }
	defer func() { now = old }()

	iss, _ := newTestIssuer(t)
	resp, err := iss.Issue(context.Background(), ServiceProvider{EntityID: "e", ACSURL: "a"}, Subject{NameID: "x@y.z"}, AuthnRequestInfo{ID: "_r"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resp.XML), "2026-06-16T12:00:00Z") {
		t.Fatal("expected fixed IssueInstant")
	}
	if !strings.Contains(string(resp.XML), "2026-06-16T12:05:00Z") {
		t.Fatal("expected NotOnOrAfter = issue + 5m")
	}
}

func TestEscape(t *testing.T) {
	if got := escape(`a<b>&"'`); got != "a&lt;b&gt;&amp;&quot;&apos;" {
		t.Fatalf("escape = %q", got)
	}
}
