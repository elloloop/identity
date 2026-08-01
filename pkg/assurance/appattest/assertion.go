package appattest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"

	"github.com/fxamacker/cbor/v2"
)

// assertionObject is the CBOR envelope of
// DCAppAttestService.generateAssertion.
type assertionObject struct {
	Signature         []byte `cbor:"signature"`
	AuthenticatorData []byte `cbor:"authenticatorData"`
}

// VerifyAssertion verifies an assertion produced by the previously
// attested key: the signature over SHA256(authenticatorData ||
// SHA256(clientData)) must verify against publicKeySPKI (stored from
// VerifyAttestation), the RP ID hash must match the app id, and the sign
// counter must exceed lastCounter (hardware-enforced replay protection).
// It returns the new counter for the caller to persist.
//
// clientData is the exact byte string the client signed over — for this
// service, the one-time challenge it was issued; challenge freshness and
// single-use are the caller's job. Note the signature digest is the nonce
// itself (the Secure Enclave signs the SHA-256 digest directly — there is
// no second hash), per Apple's assertion-validation steps 1–3.
func (v *Verifier) VerifyAssertion(assertionCBOR, clientData, publicKeySPKI []byte, lastCounter uint32) (uint32, error) {
	var obj assertionObject
	if err := cbor.Unmarshal(assertionCBOR, &obj); err != nil {
		return 0, failf("assertion is not valid CBOR: %v", err)
	}
	if len(obj.AuthenticatorData) < authDataMinLen {
		return 0, failf("assertion authenticator data truncated (%d bytes)", len(obj.AuthenticatorData))
	}

	pubAny, err := x509.ParsePKIXPublicKey(publicKeySPKI)
	if err != nil {
		return 0, failf("stored public key does not parse: %v", err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return 0, failf("stored public key is %T, want *ecdsa.PublicKey", pubAny)
	}

	clientDataHash := sha256.Sum256(clientData)
	nonce := sha256.Sum256(append(append([]byte{}, obj.AuthenticatorData...), clientDataHash[:]...))
	if !ecdsa.VerifyASN1(pub, nonce[:], obj.Signature) {
		return 0, failf("assertion signature invalid")
	}

	if !bytes.Equal(obj.AuthenticatorData[:sha256.Size], v.appIDHash[:]) {
		return 0, failf("assertion RP ID hash does not match app id")
	}

	counter := binary.BigEndian.Uint32(obj.AuthenticatorData[signCountOffset : signCountOffset+4])
	if counter <= lastCounter {
		return 0, failf("assertion counter %d not greater than last seen %d", counter, lastCounter)
	}
	return counter, nil
}
