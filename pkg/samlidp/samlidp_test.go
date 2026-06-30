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

func TestMetadata_ContainsIdentityAndCert(t *testing.T) {
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
		"<md:KeyDescriptor use=\"signing\"",
		"<ds:X509Certificate>" + iss.certBase64(),
	} {
		if !strings.Contains(s, want) {
			t.Errorf("metadata missing %q", want)
		}
	}
}

// TestMetadata_OmitsUnservedEndpoints asserts the descope: this slice mounts
// only /saml/metadata, so the metadata must NOT advertise SSO/SLO endpoints
// (an SP importing them would be redirected to a 404). It must also not leak
// the configured SSO/SLO URLs anywhere in the document.
func TestMetadata_OmitsUnservedEndpoints(t *testing.T) {
	iss, _ := newTestIssuer(t) // configured with SSOURL + SLOURL
	md, err := iss.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	s := string(md)
	for _, forbidden := range []string{
		"SingleSignOnService",
		"SingleLogoutService",
		"https://idp.example.com/saml/sso",
		"https://idp.example.com/saml/slo",
	} {
		if strings.Contains(s, forbidden) {
			t.Errorf("metadata must not advertise %q (no handler serves it this slice)", forbidden)
		}
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
		// @ID is not a valid XML NCName (contains a quote that, unescaped,
		// would break out of the InResponseTo attribute) — must be rejected
		// at the parse boundary before it can be echoed into a signed Response.
		`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="a&quot; x=&quot;y"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">sp</saml:Issuer></samlp:AuthnRequest>`,
		// @ID with a space is not an NCName.
		`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="has space"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">sp</saml:Issuer></samlp:AuthnRequest>`,
		// @ID starting with a digit is not an NCName.
		`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="1bad"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">sp</saml:Issuer></samlp:AuthnRequest>`,
	}
	for _, c := range cases {
		if _, err := iss.ParseAuthnRequest([]byte(c), ""); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

// TestIssue_MaliciousIDNoForgery is the core regression for the
// XML-attribute-injection → signed-assertion-forgery blocker. A hostile
// AuthnRequest @ID (which flows verbatim into InResponseTo on both the
// signed Assertion and the Response) is fed directly to Issue (bypassing the
// NCName parse guard) to prove the escaping layer alone neutralizes it: the
// crafted markup must appear only as escaped text, never as a real element
// or attribute, the document must round-trip through xml.Unmarshal, and the
// signature must still verify.
func TestIssue_MaliciousIDNoForgery(t *testing.T) {
	iss, key := newTestIssuer(t)
	sp := ServiceProvider{EntityID: "https://sp.example.com/saml", ACSURL: "https://sp.example.com/acs"}

	// A classic breakout payload: close the InResponseTo attribute, close
	// the element, then inject a forged signed-looking Attribute.
	malicious := `_x" foo="bar"><saml:Attribute Name="injected"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute><x y="`
	req := AuthnRequestInfo{ID: malicious, Issuer: sp.EntityID}
	subj := Subject{NameID: "alice@acme.com"}

	resp, err := iss.Issue(context.Background(), sp, subj, req)
	if err != nil {
		t.Fatal(err)
	}
	x := string(resp.XML)

	// 1. The output must remain well-formed XML.
	if err := xml.Unmarshal(resp.XML, new(struct{ XMLName xml.Name })); err != nil {
		t.Fatalf("malicious @ID produced non-well-formed XML: %v", err)
	}
	// 2. No forged element/attribute may appear unescaped.
	for _, forbidden := range []string{
		`Name="injected"`,
		`foo="bar"`,
		`<saml:Attribute Name="injected"`,
		`<x y=`,
	} {
		if strings.Contains(x, forbidden) {
			t.Fatalf("forged markup leaked into signed document: %q\n%s", forbidden, x)
		}
	}
	// 3. The payload must be present only in fully-escaped form.
	if !strings.Contains(x, "&lt;saml:Attribute") || !strings.Contains(x, "&quot;") {
		t.Fatalf("expected the payload to appear escaped; got:\n%s", x)
	}
	// 4. The signature must still verify over the (escaped) assertion.
	verifyAssertionSignature(t, x, &key.PublicKey)
}

// TestIssue_MaliciousAttributesNoForgery proves the same for
// attacker-controlled SAML attribute keys and values: special characters
// must be escaped, no injected markup may materialize, the document must
// round-trip, and the signature must verify.
func TestIssue_MaliciousAttributesNoForgery(t *testing.T) {
	iss, key := newTestIssuer(t)
	sp := ServiceProvider{EntityID: "https://sp.example.com/saml", ACSURL: "https://sp.example.com/acs"}
	req := AuthnRequestInfo{ID: "_req123", Issuer: sp.EntityID}
	subj := Subject{
		NameID: "alice@acme.com",
		Attributes: map[string]string{
			`evil"><saml:Attribute Name="role`: `admin"/><x a="`,
			"amp&lt<gt>":                       "v&v<v>\"v'v",
		},
	}

	resp, err := iss.Issue(context.Background(), sp, subj, req)
	if err != nil {
		t.Fatal(err)
	}
	x := string(resp.XML)

	if err := xml.Unmarshal(resp.XML, new(struct{ XMLName xml.Name })); err != nil {
		t.Fatalf("malicious attributes produced non-well-formed XML: %v", err)
	}
	for _, forbidden := range []string{
		`Name="role"`,
		`<x a=`,
		`<saml:Attribute Name="role`,
	} {
		if strings.Contains(x, forbidden) {
			t.Fatalf("forged markup leaked into signed document: %q\n%s", forbidden, x)
		}
	}
	// Raw special characters must not survive in element content/attributes.
	if strings.Contains(x, `"v'v`) {
		t.Fatalf("unescaped attribute value characters leaked:\n%s", x)
	}
	verifyAssertionSignature(t, x, &key.PublicKey)
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

func TestIsValidNCName(t *testing.T) {
	valid := []string{"_req123", "a", "Abc.def-ghi", "_", "x9"}
	for _, s := range valid {
		if !isValidNCName(s) {
			t.Errorf("isValidNCName(%q) = false, want true", s)
		}
	}
	invalid := []string{"", "1abc", ".abc", "-abc", "9", "has space", `a"b`, "ns:local", "a&b", "a<b"}
	for _, s := range invalid {
		if isValidNCName(s) {
			t.Errorf("isValidNCName(%q) = true, want false", s)
		}
	}
}

func TestEscape(t *testing.T) {
	if got := escape(`a<b>&"'`); got != "a&lt;b&gt;&amp;&quot;&apos;" {
		t.Fatalf("escape = %q", got)
	}
}
