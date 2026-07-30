// Package appattesttest mints spec-shaped App Attest attestation and
// assertion objects signed by a synthetic certificate authority, so the
// verifier can be exercised in CI where genuine Apple attestations cannot
// be produced. The DER structures (nonce extension, authenticator data,
// CBOR envelopes) are built by hand rather than shared with the verifier,
// so a parser bug cannot be masked by a generator using the same code.
package appattesttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// nonceExtensionOID is Apple's credCert nonce extension
// (1.2.840.113635.100.8.2), duplicated here on purpose (see package doc).
var nonceExtensionOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

// Authority is a synthetic App Attest CA: a root and an intermediate that
// stand in for Apple's. Configure the verifier under test with
// RootPool().
type Authority struct {
	rootCert  *x509.Certificate
	rootKey   *ecdsa.PrivateKey
	interCert *x509.Certificate
	interKey  *ecdsa.PrivateKey
}

// NewAuthority generates a fresh root + intermediate pair valid for ±1h
// around now.
func NewAuthority(now time.Time) (*Authority, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test App Attestation Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, err
	}

	interKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test App Attestation CA 1"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	interCert, err := x509.ParseCertificate(interDER)
	if err != nil {
		return nil, err
	}
	return &Authority{rootCert: rootCert, rootKey: rootKey, interCert: interCert, interKey: interKey}, nil
}

// RootPool returns a pool trusting only this authority's root.
func (a *Authority) RootPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(a.rootCert)
	return pool
}

// MintOpts controls attestation minting. Zero values produce a valid
// attestation; the corruption knobs each break exactly one verification
// step so table tests can prove every check fires.
type MintOpts struct {
	AppID     string // "TEAMID.bundle.id"
	Challenge []byte
	AAGUID    []byte // 16 bytes; defaults to production "appattest"

	SignCount        uint32 // attestation counter; valid attestations carry 0
	WrongNonce       bool   // corrupt the nonce signed into the credCert
	OmitNonceExt     bool   // leaf without the Apple nonce extension
	RPIDHashOverride []byte // replace SHA256(AppID) in authData
	CredIDOverride   []byte // replace the credential id in authData
	KeyIDOverride    string // replace the client-claimed key id
	OmitIntermediate bool   // present a chain that cannot reach the root
	LeafExpired      bool   // leaf validity entirely in the past
	Format           string // attestation `fmt`; defaults to "apple-appattest"
	TruncateAuthData bool   // cut authData below the credential-data minimum
}

// Attestation is a minted attestation object plus the client-side facts
// that accompany it.
type Attestation struct {
	CBOR  []byte
	KeyID string
	Key   *ecdsa.PrivateKey
}

// aaguidProduction mirrors Apple's production AAGUID.
var aaguidProduction = []byte("appattest\x00\x00\x00\x00\x00\x00\x00")

// Mint produces an attestation object per opts.
func (a *Authority) Mint(now time.Time, opts MintOpts) (*Attestation, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pubPoint := uncompressedPoint(&key.PublicKey)
	keyIDBytes := sha256.Sum256(pubPoint)
	keyID := base64.StdEncoding.EncodeToString(keyIDBytes[:])
	if opts.KeyIDOverride != "" {
		keyID = opts.KeyIDOverride
	}

	authData, err := buildAuthData(opts, keyIDBytes[:])
	if err != nil {
		return nil, err
	}

	// The nonce the CA signs into the leaf: SHA256(authData || SHA256(challenge)).
	clientDataHash := sha256.Sum256(opts.Challenge)
	nonce := sha256.Sum256(append(append([]byte{}, authData...), clientDataHash[:]...))
	if opts.WrongNonce {
		nonce[0] ^= 0xFF
	}

	leafDER, err := a.mintLeaf(now, &key.PublicKey, nonce[:], opts)
	if err != nil {
		return nil, err
	}

	chain := [][]byte{leafDER, a.interCert.Raw}
	if opts.OmitIntermediate {
		chain = [][]byte{leafDER}
	}
	format := opts.Format
	if format == "" {
		format = "apple-appattest"
	}
	obj := map[string]any{
		"fmt": format,
		"attStmt": map[string]any{
			"x5c":     chain,
			"receipt": []byte("test-receipt"),
		},
		"authData": authData,
	}
	raw, err := cbor.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return &Attestation{CBOR: raw, KeyID: keyID, Key: key}, nil
}

// mintLeaf issues the credential certificate, embedding nonce in Apple's
// extension with hand-built DER: SEQUENCE { [1] { OCTET STRING nonce } }.
func (a *Authority) mintLeaf(now time.Time, pub *ecdsa.PublicKey, nonce []byte, opts MintOpts) ([]byte, error) {
	if len(nonce) != sha256.Size {
		return nil, fmt.Errorf("nonce must be %d bytes", sha256.Size)
	}
	// 04 20 <nonce> wrapped in A1 22, wrapped in 30 24.
	ext := append([]byte{0x30, 0x24, 0xA1, 0x22, 0x04, 0x20}, nonce...)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "Test App Attest Leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if opts.LeafExpired {
		tmpl.NotBefore = now.Add(-3 * time.Hour)
		tmpl.NotAfter = now.Add(-2 * time.Hour)
	}
	if !opts.OmitNonceExt {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: nonceExtensionOID, Value: ext}}
	}
	return x509.CreateCertificate(rand.Reader, tmpl, a.interCert, pub, a.interKey)
}

// buildAuthData assembles WebAuthn authenticator data with attested
// credential data, honoring the corruption overrides.
func buildAuthData(opts MintOpts, credID []byte) ([]byte, error) {
	rpIDHash := sha256.Sum256([]byte(opts.AppID))
	rpid := rpIDHash[:]
	if opts.RPIDHashOverride != nil {
		rpid = opts.RPIDHashOverride
	}
	aaguid := opts.AAGUID
	if aaguid == nil {
		aaguid = aaguidProduction
	}
	if len(aaguid) != 16 {
		return nil, fmt.Errorf("aaguid must be 16 bytes")
	}
	if opts.CredIDOverride != nil {
		credID = opts.CredIDOverride
	}

	out := make([]byte, 0, 55+len(credID))
	out = append(out, rpid...)
	out = append(out, 0x40) // attested credential data present
	out = binary.BigEndian.AppendUint32(out, opts.SignCount)
	out = append(out, aaguid...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(credID)))
	out = append(out, credID...)
	if opts.TruncateAuthData {
		out = out[:40]
	}
	return out, nil
}

// MintAssertion produces an assertion over clientData by key, exactly as
// the Secure Enclave would: signature = ECDSA(SHA256(authData ||
// SHA256(clientData))) — the digest signed is the nonce itself.
func MintAssertion(key *ecdsa.PrivateKey, appID string, counter uint32, clientData []byte, rpIDHashOverride []byte) ([]byte, error) {
	rpIDHash := sha256.Sum256([]byte(appID))
	rpid := rpIDHash[:]
	if rpIDHashOverride != nil {
		rpid = rpIDHashOverride
	}
	authData := make([]byte, 0, 37)
	authData = append(authData, rpid...)
	authData = append(authData, 0x00)
	authData = binary.BigEndian.AppendUint32(authData, counter)

	clientDataHash := sha256.Sum256(clientData)
	nonce := sha256.Sum256(append(append([]byte{}, authData...), clientDataHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, key, nonce[:])
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(map[string]any{
		"signature":         sig,
		"authenticatorData": authData,
	})
}

// uncompressedPoint returns 0x04||X||Y for a P-256 key.
func uncompressedPoint(pub *ecdsa.PublicKey) []byte {
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 1+2*byteLen)
	out[0] = 0x04
	pub.X.FillBytes(out[1 : 1+byteLen])
	pub.Y.FillBytes(out[1+byteLen:])
	return out
}
