package identityserver

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
)

// The development TOTP key and recovery pepper are frozen: changing either
// makes every two-step secret and recovery code stored under them unusable on
// a deployment that never set the real keys. Their hashes pin them.
func TestDevTOTPKeyMaterialIsFrozen(t *testing.T) {
	for _, tc := range []struct {
		name, wantSHA256 string
		got              []byte
	}{
		{"encryption key", "9dc529d8fd09747351388b53b34af233342746ef0f7300a1d9e46f800afa3345", devTOTPEncryptionKey},
		{"recovery pepper", "dc413344511860ce3ee0c6869bb1fa6f9cdd881ea192aac284f6e37402ebb2d7", devTOTPRecoveryPepper},
	} {
		sum := sha256.Sum256(tc.got)
		if got := hex.EncodeToString(sum[:]); got != tc.wantSHA256 {
			t.Errorf("%s changed: sha256 %s, want %s", tc.name, got, tc.wantSHA256)
		}
	}

	cfg := &config.Config{}
	key, err := decodeTOTPKey(cfg, zap.NewNop())
	if err != nil || string(key) != string(devTOTPEncryptionKey) || len(key) != 32 {
		t.Errorf("decodeTOTPKey with no key = %d bytes, %v; want the 32-byte development key", len(key), err)
	}
	pepper, err := decodeTOTPRecoveryPepper(cfg, zap.NewNop())
	if err != nil || string(pepper) != string(devTOTPRecoveryPepper) {
		t.Errorf("decodeTOTPRecoveryPepper with no pepper = %v; want the development pepper", err)
	}
}
