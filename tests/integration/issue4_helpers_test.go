//go:build integration

package integration

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/pquerna/otp"
	otptotp "github.com/pquerna/otp/totp"

	"github.com/elloloop/identity/internal/config"
)

const (
	specRegAttestationObjectHex        = "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"
	specRegClientDataJSONHex           = "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d"
	specRegCredentialIDHex             = "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4"
	specRegChallengeHex                = "00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130"
	specFidoU2FRegAttestationObjectHex = "a363666d74686669646f2d7532666761747453746d74a26373696758473045022100f41887a20063bb26867cb9751978accea5b81791a68f4f4dd6ea1fb6a5c086c302204e5e00aa3895777e6608f1f375f95450045da3da57a0e4fd451df35a31d2d98a637835638159022530820221308201c7a003020102021004f66dc6542ea7719dea416d325a2401300a06082a8648ce3d0403023062311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331253023060355040b0c1c41757468656e74696361746f72204174746573746174696f6e204341310b30090603550406130241413020170d3234303130313030303030305a180f33303234303130313030303030305a305f311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130241413059301306072a8648ce3d020106082a8648ce3d0301070342000456fffa7093dede46aefeefb6e520c7ccc78967636e2f92582ba71455f64e93932dff3be4e0d4ef68e3e3b73aa087e26a0a0a30b02dc2aa2309db4c3a2fc936dea360305e300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301d0603551d0e04160414420822eb1908b5cd3911017fbcad4641c05e05a3301f0603551d2304183016801445aff715b0dd786741fee996ebc16547a3931b1e300a06082a8648ce3d040302034800304502200d0b777f0a0b181ad2830275acc3150fd6092430bcd034fd77beb7bdf8c2d546022100d4864edd95daa3927080855df199f1717299b24a5eecefbd017455a9b934d8f668617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b54100000000afb3c2efc054df425013d5c88e79c3c10020a4ba6e2d2cfec43648d7d25c5ed5659bc18f2b781538527ebd492de03256bdf4a5010203262001215820b0d62de6b30f86f0bac7a9016951391c2e31849e2e64661cbd2b13cd7d5508ad225820503b0bda2a357a9a4b34475a28e65b660b4898a9e3e9bbf0820d43494297edd0"
	specFidoU2FRegClientDataJSONHex    = "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22344851334b5a4335797155486f696666786e73414e344445557955344452715177672d4237583049444159222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"
	specFidoU2FCredentialIDHex         = "a4ba6e2d2cfec43648d7d25c5ed5659bc18f2b781538527ebd492de03256bdf4"
	specFidoU2FRegChallengeHex         = "e074372990b9caa507a227dfc67b003780c45325380d1a90c20f81ed7d080c06"
	specFidoU2FAuthenticatorDataHex    = "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50100000000"
	specFidoU2FLoginClientDataJSONHex  = "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a222d5178684b59485954316d554f4e3461554139326b6d36537a49532d2d4f417362694e5650774249564455222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"
	specFidoU2FLoginSignatureHex       = "304402206172459958fea907b7292b92f555034bfd884895f287a76200c1ba287239137002204727b166147e26a21bbc2921d192ebfed569b79438538e5c128b5e28e6926dd7"
	specFidoU2FLoginChallengeHex       = "f90c612981d84f599438de1a500f76926e92cc84bef8e02c6e23553f00485435"
)

func startPasskeyVectorServer(t *testing.T) *Harness {
	t.Helper()
	return StartServer(t, WithConfig(func(cfg *config.Config) {
		cfg.PasskeyRPID = "example.org"
		cfg.PasskeyRPName = "Example"
		cfg.PasskeyOrigin = "https://example.org"
		cfg.PasskeySignupEnabled = true
	}))
}

func specPasskeyRegistrationChallenge(t *testing.T) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(mustHex(t, specRegChallengeHex))
}

func specPasskeyLoginChallenge(t *testing.T) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(mustHex(t, specFidoU2FLoginChallengeHex))
}

func specPasskeyCredentialID(t *testing.T) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(mustHex(t, specRegCredentialIDHex))
}

func specPasskeyLoginCredentialID(t *testing.T) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(mustHex(t, specFidoU2FCredentialIDHex))
}

func specPasskeyLoginRegistrationChallenge(t *testing.T) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(mustHex(t, specFidoU2FRegChallengeHex))
}

func buildPasskeyRegistrationCredentialJSON(t *testing.T) string {
	t.Helper()

	credentialID := mustHex(t, specRegCredentialIDHex)
	id := base64.RawURLEncoding.EncodeToString(credentialID)
	body := map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"attestationObject": base64.RawURLEncoding.EncodeToString(mustHex(t, specRegAttestationObjectHex)),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(mustHex(t, specRegClientDataJSONHex)),
			"transports":        []string{"usb", "nfc"},
		},
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal registration credential: %v", err)
	}
	return string(encoded)
}

func buildPasskeyAssertionCredentialJSON(t *testing.T) string {
	t.Helper()

	credentialID := mustHex(t, specFidoU2FCredentialIDHex)
	id := base64.RawURLEncoding.EncodeToString(credentialID)
	body := map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"authenticatorData": base64.RawURLEncoding.EncodeToString(mustHex(t, specFidoU2FAuthenticatorDataHex)),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(mustHex(t, specFidoU2FLoginClientDataJSONHex)),
			"signature":         base64.RawURLEncoding.EncodeToString(mustHex(t, specFidoU2FLoginSignatureHex)),
		},
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal assertion credential: %v", err)
	}
	return string(encoded)
}

func buildPasskeyLoginRegistrationCredentialJSON(t *testing.T) string {
	t.Helper()

	credentialID := mustHex(t, specFidoU2FCredentialIDHex)
	id := base64.RawURLEncoding.EncodeToString(credentialID)
	body := map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"attestationObject": base64.RawURLEncoding.EncodeToString(mustHex(t, specFidoU2FRegAttestationObjectHex)),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(mustHex(t, specFidoU2FRegClientDataJSONHex)),
		},
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal login registration credential: %v", err)
	}
	return string(encoded)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return decoded
}

func generateTotpCodeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()

	code, err := otptotp.GenerateCodeCustom(secret, at, otptotp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	return code
}
