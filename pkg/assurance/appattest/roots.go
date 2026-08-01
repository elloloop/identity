package appattest

import (
	"crypto/x509"
	"errors"
)

// appleAppAttestRootPEM is the Apple App Attestation Root CA, the trust
// anchor every genuine App Attest certificate chain terminates at.
// Retrieved from
// https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
// (subject CN=Apple App Attestation Root CA, O=Apple Inc., ST=California;
// valid 2020-03-18 through 2045-03-15; SHA-256 fingerprint
// 1CB9823BA28BA6AD2D33A006941DE2AE4F513EF1D4E831B9F7E0FA7B6242C932).
const appleAppAttestRootPEM = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`

// appleRoots returns a pool holding the Apple App Attestation Root CA.
// The embedded PEM is compiled in, so a parse failure is a build defect,
// not a runtime condition; it is still surfaced as an error so New can
// fail loudly instead of trusting an empty pool.
func appleRoots() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(appleAppAttestRootPEM)) {
		return nil, errors.New("appattest: embedded Apple root CA failed to parse")
	}
	return pool, nil
}
