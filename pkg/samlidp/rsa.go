package samlidp

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
)

// Standard SAML 2.0 URNs used in metadata, assertions, and responses.
const (
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"
	nsDSig      = "http://www.w3.org/2000/09/xmldsig#"

	// The HTTP-POST/HTTP-Redirect SSO/SLO binding URN constants live with
	// the SSO binding slice that mounts those handlers and re-adds the
	// corresponding <md:SingleSignOnService>/<md:SingleLogoutService>
	// metadata; this slice serves only /saml/metadata.

	nameIDFormatEmail = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

	statusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"

	// #nosec G101 -- SAML AuthnContext class URN, not a credential.
	authnContextPassword = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

	// algRSASHA256 / algSHA256 / algEnvC14N / algExcC14N are the
	// xmldsig-core algorithm identifiers modern SPs require.
	algRSASHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	algSHA256      = "http://www.w3.org/2001/04/xmlenc#sha256"
	algEnvelopeSig = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	algExcC14N     = "http://www.w3.org/2001/10/xml-exc-c14n#"

	// assertionValiditySeconds bounds the assertion's NotOnOrAfter window.
	// Five minutes is the conventional SAML clock-skew-tolerant default.
	assertionValiditySeconds = 300
)

// RSAIssuer is the real SAML 2.0 IdP: it signs assertions with an RSA key
// and advertises the matching certificate in its metadata. It is
// constructed once at boot from the configured key/cert and entityID and is
// safe for concurrent use (it holds only immutable signing material).
type RSAIssuer struct {
	entityID string // IdP entityID (also its metadata URL by convention)
	ssoURL   string // IdP SSO endpoint (HTTP-POST + HTTP-Redirect)
	sloURL   string // IdP SLO endpoint (optional; empty omits SLO metadata)

	key     *rsa.PrivateKey
	certDER []byte // raw signing certificate (DER)
}

var _ Issuer = (*RSAIssuer)(nil)

// Options configures an RSAIssuer. EntityID and SSOURL are required;
// SLOURL is optional. KeyPEM/CertPEM are the PEM-encoded RSA private key
// and X.509 certificate.
type Options struct {
	EntityID string
	SSOURL   string
	SLOURL   string
	KeyPEM   []byte
	CertPEM  []byte
}

// NewRSAIssuer builds an RSAIssuer from PEM key/cert material. It validates
// that the certificate's public key matches the private key so a
// misconfigured deployment fails closed at boot rather than minting
// assertions an SP cannot verify.
func NewRSAIssuer(opts Options) (*RSAIssuer, error) {
	if strings.TrimSpace(opts.EntityID) == "" {
		return nil, errors.New("samlidp: EntityID is required")
	}
	if strings.TrimSpace(opts.SSOURL) == "" {
		return nil, errors.New("samlidp: SSOURL is required")
	}
	key, err := parseRSAPrivateKey(opts.KeyPEM)
	if err != nil {
		return nil, err
	}
	cert, err := parseCertificate(opts.CertPEM)
	if err != nil {
		return nil, err
	}
	certPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("samlidp: certificate public key is not RSA")
	}
	if certPub.N.Cmp(key.N) != 0 || certPub.E != key.E {
		return nil, errors.New("samlidp: certificate does not match private key")
	}
	return &RSAIssuer{
		entityID: opts.EntityID,
		ssoURL:   opts.SSOURL,
		sloURL:   opts.SLOURL,
		key:      key,
		certDER:  cert.Raw,
	}, nil
}

func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("samlidp: signing key is not valid PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("samlidp: parse signing key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("samlidp: signing key is not an RSA key")
	}
	return key, nil
}

func parseCertificate(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("samlidp: signing certificate is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("samlidp: parse signing certificate: %w", err)
	}
	return cert, nil
}

// Name implements Issuer.
func (i *RSAIssuer) Name() string { return ProviderRSA }

// Enabled implements Issuer.
func (i *RSAIssuer) Enabled() bool { return true }

// EntityID implements MetadataProvider.
func (i *RSAIssuer) EntityID() string { return i.entityID }

// certBase64 returns the bare base64 DER certificate (no PEM armor), the
// form embedded in <ds:X509Certificate> and <md:KeyDescriptor>.
func (i *RSAIssuer) certBase64() string {
	return base64.StdEncoding.EncodeToString(i.certDER)
}

// ParseAuthnRequest implements AssertionIssuer.
func (i *RSAIssuer) ParseAuthnRequest(raw []byte, relayState string) (AuthnRequestInfo, error) {
	var ar struct {
		XMLName xml.Name `xml:"AuthnRequest"`
		ID      string   `xml:"ID,attr"`
		ACSURL  string   `xml:"AssertionConsumerServiceURL,attr"`
		Issuer  string   `xml:"Issuer"`
	}
	if err := xml.Unmarshal(raw, &ar); err != nil {
		return AuthnRequestInfo{}, fmt.Errorf("%w: %w", ErrInvalidAuthnRequest, err)
	}
	id := strings.TrimSpace(ar.ID)
	if id == "" {
		return AuthnRequestInfo{}, fmt.Errorf("%w: missing request ID", ErrInvalidAuthnRequest)
	}
	// The @ID is echoed verbatim into the signed Response/Assertion as
	// InResponseTo; reject anything that is not a syntactically valid XML
	// NCName so a hostile @ID can never be carried into the signed document.
	if !isValidNCName(id) {
		return AuthnRequestInfo{}, fmt.Errorf("%w: request ID is not a valid XML id", ErrInvalidAuthnRequest)
	}
	if strings.TrimSpace(ar.Issuer) == "" {
		return AuthnRequestInfo{}, fmt.Errorf("%w: missing Issuer", ErrInvalidAuthnRequest)
	}
	return AuthnRequestInfo{
		ID:         id,
		Issuer:     strings.TrimSpace(ar.Issuer),
		ACSURL:     strings.TrimSpace(ar.ACSURL),
		RelayState: relayState,
	}, nil
}
