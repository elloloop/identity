// Package appattest verifies Apple App Attest attestations and
// assertions server-side, per Apple's "Validating apps that connect to
// your server" (DCAppAttestService). It proves a request originates from
// a genuine build of a specific app on genuine Apple hardware, keyed by a
// hardware-backed P-256 key the Secure Enclave never releases.
//
// The package is pure verification: it holds no state. The caller stores
// the public key and sign counter returned by VerifyAttestation and
// supplies them back to VerifyAssertion, enforcing counter monotonicity
// across requests itself.
package appattest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/elloloop/identity/pkg/assurance"
)

// Environments an App Attest key can be generated in. The environment is
// bound into the attestation's AAGUID, so a development-environment
// attestation cannot be replayed against a production-configured
// verifier or vice versa.
const (
	EnvProduction  = "production"
	EnvDevelopment = "development"
)

// aaguid values Apple stamps into the attested credential data, one per
// environment ("appattest" zero-padded to 16 bytes, and
// "appattestdevelop").
var (
	aaguidProduction  = []byte("appattest\x00\x00\x00\x00\x00\x00\x00")
	aaguidDevelopment = []byte("appattestdevelop")
)

// attestationFormat is the required `fmt` of an App Attest attestation
// object (the WebAuthn attestation envelope with Apple's format).
const attestationFormat = "apple-appattest"

// nonceExtensionOID identifies the credCert X.509 extension Apple embeds
// the expected nonce in (OID 1.2.840.113635.100.8.2). The CA signing the
// nonce into the certificate is what binds the attestation to our
// challenge — App Attest has no separate attestation signature.
var nonceExtensionOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

// authenticatorData layout constants (WebAuthn §6.1): the fixed 37-byte
// prefix is rpIdHash(32) || flags(1) || signCount(4); an attestation then
// carries attested credential data: aaguid(16) || credIdLen(2) || credId.
const (
	authDataMinLen       = 37
	flagsIndex           = 32
	signCountOffset      = 33
	aaguidOffset         = 37
	credIDLenOffset      = 53
	credIDOffset         = 55
	flagAttestedCredData = 0x40
)

// Config configures a Verifier for one app.
type Config struct {
	// TeamID is the Apple Developer team identifier and BundleID the app's
	// bundle identifier; together they form the App ID ("TEAMID.bundle.id")
	// whose SHA-256 every attestation and assertion must carry as its RP ID
	// hash.
	TeamID   string
	BundleID string

	// Env selects which AAGUID is accepted: EnvProduction (default) or
	// EnvDevelopment (keys generated while the app runs from Xcode).
	Env string

	// Roots overrides the trust anchors for the credCert chain. nil uses
	// the embedded Apple App Attestation Root CA. Tests inject a synthetic
	// authority here; production deployments leave it nil.
	Roots *x509.CertPool

	// Now overrides the clock used for certificate-validity checks.
	// nil uses time.Now.
	Now func() time.Time
}

// Verifier verifies App Attest attestations and assertions for a single
// app. Safe for concurrent use.
type Verifier struct {
	appIDHash [sha256.Size]byte
	aaguid    []byte
	env       string
	roots     *x509.CertPool
	now       func() time.Time
}

// New returns a Verifier for cfg.
func New(cfg Config) (*Verifier, error) {
	if cfg.TeamID == "" {
		return nil, errors.New("appattest: TeamID is required")
	}
	if cfg.BundleID == "" {
		return nil, errors.New("appattest: BundleID is required")
	}
	env := cfg.Env
	if env == "" {
		env = EnvProduction
	}
	var aaguid []byte
	switch env {
	case EnvProduction:
		aaguid = aaguidProduction
	case EnvDevelopment:
		aaguid = aaguidDevelopment
	default:
		return nil, fmt.Errorf("appattest: unknown environment %q", cfg.Env)
	}
	roots := cfg.Roots
	if roots == nil {
		var err error
		if roots, err = appleRoots(); err != nil {
			return nil, err
		}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Verifier{
		appIDHash: sha256.Sum256([]byte(cfg.TeamID + "." + cfg.BundleID)),
		aaguid:    aaguid,
		env:       env,
		roots:     roots,
		now:       now,
	}, nil
}

// AttestationResult is the verified outcome of an attestation: the
// hardware key's identity and public key, which the caller persists and
// replays into VerifyAssertion on every refresh.
type AttestationResult struct {
	// KeyID is the standard-base64 SHA-256 of the attested public key —
	// the identifier the client presents on later assertions.
	KeyID string
	// PublicKeySPKI is the attested P-256 public key in DER (PKIX/SPKI)
	// encoding, ready for storage.
	PublicKeySPKI []byte
	// Receipt is Apple's attestation receipt, usable for server-to-Apple
	// fraud-metric requests. Stored opaquely; this package does not
	// consume it.
	Receipt []byte
	// Environment echoes the verifier's environment for audit trails.
	Environment string
}

// attestationObject is the CBOR envelope of DCAppAttestService.attestKey.
type attestationObject struct {
	Fmt      string               `cbor:"fmt"`
	AttStmt  attestationStatement `cbor:"attStmt"`
	AuthData []byte               `cbor:"authData"`
}

// attestationStatement carries the credCert chain and Apple's receipt.
type attestationStatement struct {
	X5C     [][]byte `cbor:"x5c"`
	Receipt []byte   `cbor:"receipt"`
}

// failf wraps assurance.ErrVerificationFailed with step detail so a
// caller can log which check rejected the evidence while clients see one
// uniform failure.
func failf(format string, args ...any) error {
	return fmt.Errorf("%w: appattest: %s", assurance.ErrVerificationFailed, fmt.Sprintf(format, args...))
}

// VerifyAttestation verifies an attestation object against the given
// challenge, following Apple's nine documented steps: certificate chain
// to the App Attest root, nonce binding via the credCert extension,
// key-identifier match, RP ID (App ID) match, zero initial counter,
// environment AAGUID, and credential-ID match. keyID is the
// standard-base64 key identifier the client obtained from attestKey;
// challenge is the one-time server nonce the client hashed into the
// attestation (single-use enforcement is the caller's job).
func (v *Verifier) VerifyAttestation(attestationCBOR []byte, keyID string, challenge []byte) (*AttestationResult, error) {
	keyIDBytes, err := base64.StdEncoding.DecodeString(keyID)
	if err != nil || len(keyIDBytes) != sha256.Size {
		return nil, failf("malformed key id")
	}

	var obj attestationObject
	if err := cbor.Unmarshal(attestationCBOR, &obj); err != nil {
		return nil, failf("attestation object is not valid CBOR: %v", err)
	}
	if obj.Fmt != attestationFormat {
		return nil, failf("attestation format %q, want %q", obj.Fmt, attestationFormat)
	}
	if len(obj.AttStmt.X5C) < 2 {
		return nil, failf("certificate chain has %d certificates, want at least 2", len(obj.AttStmt.X5C))
	}

	// Step 1: credCert must chain to the App Attest root through the
	// provided intermediate(s).
	credCert, err := x509.ParseCertificate(obj.AttStmt.X5C[0])
	if err != nil {
		return nil, failf("parsing credential certificate: %v", err)
	}
	intermediates := x509.NewCertPool()
	for _, der := range obj.AttStmt.X5C[1:] {
		ic, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, failf("parsing intermediate certificate: %v", err)
		}
		intermediates.AddCert(ic)
	}
	if _, err := credCert.Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		CurrentTime:   v.now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, failf("certificate chain: %v", err)
	}

	// Steps 2–4: recompute the nonce (SHA256(authData || SHA256(challenge)))
	// and require it in the credCert's Apple extension. This is the
	// challenge binding: the App Attest CA signed this nonce into the
	// certificate, so a replayed or forged attestation cannot carry it.
	clientDataHash := sha256.Sum256(challenge)
	expectedNonce := sha256.Sum256(append(append([]byte{}, obj.AuthData...), clientDataHash[:]...))
	certNonce, err := nonceFromCert(credCert)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(certNonce, expectedNonce[:]) {
		return nil, failf("nonce mismatch")
	}

	// Step 5: the client-claimed key identifier must be the SHA-256 of the
	// attested public key.
	pub, ok := credCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, failf("credential certificate key is %T, want *ecdsa.PublicKey", credCert.PublicKey)
	}
	point, err := uncompressedPoint(pub)
	if err != nil {
		return nil, failf("credential certificate key does not encode: %v", err)
	}
	pubHash := sha256.Sum256(point)
	if !bytes.Equal(pubHash[:], keyIDBytes) {
		return nil, failf("key id does not match attested public key")
	}

	// Steps 6–9: authenticator data checks — App ID, fresh key counter,
	// environment AAGUID, credential id == key id.
	if len(obj.AuthData) < credIDOffset {
		return nil, failf("authenticator data truncated (%d bytes)", len(obj.AuthData))
	}
	if !bytes.Equal(obj.AuthData[:sha256.Size], v.appIDHash[:]) {
		return nil, failf("RP ID hash does not match app id")
	}
	if obj.AuthData[flagsIndex]&flagAttestedCredData == 0 {
		return nil, failf("attested credential data flag not set")
	}
	if count := binary.BigEndian.Uint32(obj.AuthData[signCountOffset : signCountOffset+4]); count != 0 {
		return nil, failf("attestation sign count %d, want 0", count)
	}
	if !bytes.Equal(obj.AuthData[aaguidOffset:aaguidOffset+16], v.aaguid) {
		return nil, failf("AAGUID does not match %s environment", v.env)
	}
	credIDLen := int(binary.BigEndian.Uint16(obj.AuthData[credIDLenOffset:credIDOffset]))
	if credIDLen != sha256.Size || len(obj.AuthData) < credIDOffset+credIDLen {
		return nil, failf("credential id length %d, want %d", credIDLen, sha256.Size)
	}
	if !bytes.Equal(obj.AuthData[credIDOffset:credIDOffset+credIDLen], keyIDBytes) {
		return nil, failf("credential id does not match key id")
	}

	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("appattest: encoding attested public key: %w", err)
	}
	return &AttestationResult{
		KeyID:         keyID,
		PublicKeySPKI: spki,
		Receipt:       obj.AttStmt.Receipt,
		Environment:   v.env,
	}, nil
}

// nonceCertContainer mirrors the DER structure of Apple's nonce
// extension: SEQUENCE { [1] EXPLICIT OCTET STRING }.
type nonceCertContainer struct {
	Nonce []byte `asn1:"tag:1,explicit"`
}

// nonceFromCert extracts the expected-nonce octet string from the
// credCert's Apple extension.
func nonceFromCert(cert *x509.Certificate) ([]byte, error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(nonceExtensionOID) {
			continue
		}
		var container nonceCertContainer
		if rest, err := asn1.Unmarshal(ext.Value, &container); err != nil || len(rest) != 0 {
			return nil, failf("malformed nonce extension")
		}
		return container.Nonce, nil
	}
	return nil, failf("credential certificate has no nonce extension")
}

// uncompressedPoint returns the SEC1 uncompressed encoding (0x04||X||Y)
// of a P-256 public key — the bytes Apple hashes to form the key
// identifier.
func uncompressedPoint(pub *ecdsa.PublicKey) ([]byte, error) {
	return pub.Bytes()
}
