package appattest_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/elloloop/identity/pkg/assurance"
	"github.com/elloloop/identity/pkg/assurance/appattest"
	"github.com/elloloop/identity/pkg/assurance/appattest/appattesttest"
)

const (
	testTeamID   = "TESTTEAM01"
	testBundleID = "com.example.dictionary"
	testAppID    = testTeamID + "." + testBundleID
)

var testNow = time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)

// newVerifier builds a Verifier trusting the synthetic authority.
func newVerifier(t *testing.T, auth *appattesttest.Authority, env string) *appattest.Verifier {
	t.Helper()
	v, err := appattest.New(appattest.Config{
		TeamID:   testTeamID,
		BundleID: testBundleID,
		Env:      env,
		Roots:    auth.RootPool(),
		Now:      func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

func newAuthority(t *testing.T) *appattesttest.Authority {
	t.Helper()
	auth, err := appattesttest.NewAuthority(testNow)
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	return auth
}

func TestVerifyAttestationHappyPath(t *testing.T) {
	auth := newAuthority(t)
	v := newVerifier(t, auth, appattest.EnvProduction)
	challenge := []byte("one-time-challenge")

	att, err := auth.Mint(testNow, appattesttest.MintOpts{AppID: testAppID, Challenge: challenge})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	res, err := v.VerifyAttestation(att.CBOR, att.KeyID, challenge)
	if err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}
	if res.KeyID != att.KeyID {
		t.Errorf("KeyID = %q, want %q", res.KeyID, att.KeyID)
	}
	if res.Environment != appattest.EnvProduction {
		t.Errorf("Environment = %q", res.Environment)
	}
	if string(res.Receipt) != "test-receipt" {
		t.Errorf("Receipt = %q", res.Receipt)
	}
	if _, err := x509.ParsePKIXPublicKey(res.PublicKeySPKI); err != nil {
		t.Errorf("PublicKeySPKI does not parse: %v", err)
	}
}

func TestVerifyAttestationDevelopmentEnvironment(t *testing.T) {
	auth := newAuthority(t)
	v := newVerifier(t, auth, appattest.EnvDevelopment)
	challenge := []byte("dev-challenge")

	att, err := auth.Mint(testNow, appattesttest.MintOpts{
		AppID:     testAppID,
		Challenge: challenge,
		AAGUID:    []byte("appattestdevelop"),
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := v.VerifyAttestation(att.CBOR, att.KeyID, challenge); err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}
}

func TestVerifyAttestationRejections(t *testing.T) {
	auth := newAuthority(t)
	challenge := []byte("challenge")
	wrongHash := sha256.Sum256([]byte("wrong"))
	fakeCredID := make([]byte, 32)

	cases := []struct {
		name string
		opts appattesttest.MintOpts
		// challengeAtVerify defaults to the minted challenge; override to
		// simulate a replayed/stale challenge.
		challengeAtVerify []byte
		env               string
	}{
		{name: "wrong challenge", opts: appattesttest.MintOpts{AppID: testAppID, Challenge: challenge}, challengeAtVerify: []byte("other")},
		{name: "corrupted nonce", opts: appattesttest.MintOpts{AppID: testAppID, Challenge: challenge, WrongNonce: true}},
		{name: "missing nonce extension", opts: appattesttest.MintOpts{AppID: testAppID, Challenge: challenge, OmitNonceExt: true}},
		{name: "wrong app id", opts: appattesttest.MintOpts{AppID: "OTHERTEAM0.com.other", Challenge: challenge}},
		{name: "rp id hash corrupted", opts: appattesttest.MintOpts{AppID: testAppID, Challenge: challenge, RPIDHashOverride: wrongHash[:]}},
		{name: "nonzero sign count", opts: appattesttest.MintOpts{AppID: testAppID, Challenge: challenge, SignCount: 7}},
		{name: "development aaguid against production verifier", opts: appattesttest.MintOpts{AppID: testAppID, Challenge: challenge, AAGUID: []byte("appattestdevelop")}},
		{name: "credential id mismatch", opts: appattesttest.MintOpts{AppID: testAppID, Challenge: challenge, CredIDOverride: fakeCredID}},
		{name: "chain missing intermediate", opts: appattesttest.MintOpts{AppID: testAppID, Challenge: challenge, OmitIntermediate: true}},
		{name: "expired leaf", opts: appattesttest.MintOpts{AppID: testAppID, Challenge: challenge, LeafExpired: true}},
		{name: "wrong format", opts: appattesttest.MintOpts{AppID: testAppID, Challenge: challenge, Format: "packed"}},
		{name: "truncated auth data", opts: appattesttest.MintOpts{AppID: testAppID, Challenge: challenge, TruncateAuthData: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := tc.env
			if env == "" {
				env = appattest.EnvProduction
			}
			v := newVerifier(t, auth, env)
			att, err := auth.Mint(testNow, tc.opts)
			if err != nil {
				t.Fatalf("Mint: %v", err)
			}
			verifyChallenge := tc.challengeAtVerify
			if verifyChallenge == nil {
				verifyChallenge = tc.opts.Challenge
			}
			_, err = v.VerifyAttestation(att.CBOR, att.KeyID, verifyChallenge)
			if !errors.Is(err, assurance.ErrVerificationFailed) {
				t.Fatalf("err = %v, want ErrVerificationFailed", err)
			}
		})
	}
}

func TestVerifyAttestationForeignRoot(t *testing.T) {
	// Attestation minted by one authority must not verify against a
	// verifier trusting a different root.
	minter := newAuthority(t)
	truster := newAuthority(t)
	v := newVerifier(t, truster, appattest.EnvProduction)
	challenge := []byte("challenge")

	att, err := minter.Mint(testNow, appattesttest.MintOpts{AppID: testAppID, Challenge: challenge})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := v.VerifyAttestation(att.CBOR, att.KeyID, challenge); !errors.Is(err, assurance.ErrVerificationFailed) {
		t.Fatalf("err = %v, want ErrVerificationFailed", err)
	}
}

func TestVerifyAttestationKeyIDMismatch(t *testing.T) {
	auth := newAuthority(t)
	v := newVerifier(t, auth, appattest.EnvProduction)
	challenge := []byte("challenge")
	att, err := auth.Mint(testNow, appattesttest.MintOpts{AppID: testAppID, Challenge: challenge})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	other := sha256.Sum256([]byte("not the key"))
	otherID := base64.StdEncoding.EncodeToString(other[:])
	if _, err := v.VerifyAttestation(att.CBOR, otherID, challenge); !errors.Is(err, assurance.ErrVerificationFailed) {
		t.Fatalf("err = %v, want ErrVerificationFailed", err)
	}
}

func TestVerifyAttestationMalformedInputs(t *testing.T) {
	auth := newAuthority(t)
	v := newVerifier(t, auth, appattest.EnvProduction)
	valid, err := auth.Mint(testNow, appattesttest.MintOpts{AppID: testAppID, Challenge: []byte("c")})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	for _, tc := range []struct {
		name  string
		cbor  []byte
		keyID string
	}{
		{"garbage cbor", []byte{0xFF, 0x00, 0x01}, valid.KeyID},
		{"empty cbor", nil, valid.KeyID},
		{"key id not base64", valid.CBOR, "!!not-base64!!"},
		{"key id wrong length", valid.CBOR, base64.StdEncoding.EncodeToString([]byte("short"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v.VerifyAttestation(tc.cbor, tc.keyID, []byte("c")); !errors.Is(err, assurance.ErrVerificationFailed) {
				t.Fatalf("err = %v, want ErrVerificationFailed", err)
			}
		})
	}
}

func TestNewConfigValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  appattest.Config
	}{
		{"missing team id", appattest.Config{BundleID: testBundleID}},
		{"missing bundle id", appattest.Config{TeamID: testTeamID}},
		{"unknown environment", appattest.Config{TeamID: testTeamID, BundleID: testBundleID, Env: "staging"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := appattest.New(tc.cfg); err == nil {
				t.Fatal("New succeeded, want error")
			}
		})
	}

	// Default environment is production; default roots are Apple's
	// embedded pool (constructing it must succeed).
	v, err := appattest.New(appattest.Config{TeamID: testTeamID, BundleID: testBundleID})
	if err != nil {
		t.Fatalf("New with defaults: %v", err)
	}
	if v == nil {
		t.Fatal("nil verifier")
	}
}

func TestVerifyAssertion(t *testing.T) {
	auth := newAuthority(t)
	v := newVerifier(t, auth, appattest.EnvProduction)
	challenge := []byte("attest-challenge")
	att, err := auth.Mint(testNow, appattesttest.MintOpts{AppID: testAppID, Challenge: challenge})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	res, err := v.VerifyAttestation(att.CBOR, att.KeyID, challenge)
	if err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}

	clientData := []byte("assertion-challenge-1")
	assertion, err := appattesttest.MintAssertion(att.Key, testAppID, 1, clientData, nil)
	if err != nil {
		t.Fatalf("MintAssertion: %v", err)
	}

	newCounter, err := v.VerifyAssertion(assertion, clientData, res.PublicKeySPKI, 0)
	if err != nil {
		t.Fatalf("VerifyAssertion: %v", err)
	}
	if newCounter != 1 {
		t.Errorf("counter = %d, want 1", newCounter)
	}

	t.Run("counter replay rejected", func(t *testing.T) {
		if _, err := v.VerifyAssertion(assertion, clientData, res.PublicKeySPKI, 1); !errors.Is(err, assurance.ErrVerificationFailed) {
			t.Fatalf("err = %v, want ErrVerificationFailed", err)
		}
	})
	t.Run("wrong client data rejected", func(t *testing.T) {
		if _, err := v.VerifyAssertion(assertion, []byte("different"), res.PublicKeySPKI, 0); !errors.Is(err, assurance.ErrVerificationFailed) {
			t.Fatalf("err = %v, want ErrVerificationFailed", err)
		}
	})
	t.Run("foreign key rejected", func(t *testing.T) {
		other, err := auth.Mint(testNow, appattesttest.MintOpts{AppID: testAppID, Challenge: challenge})
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		foreign, err := appattesttest.MintAssertion(other.Key, testAppID, 2, clientData, nil)
		if err != nil {
			t.Fatalf("MintAssertion: %v", err)
		}
		if _, err := v.VerifyAssertion(foreign, clientData, res.PublicKeySPKI, 0); !errors.Is(err, assurance.ErrVerificationFailed) {
			t.Fatalf("err = %v, want ErrVerificationFailed", err)
		}
	})
	t.Run("wrong rp id rejected", func(t *testing.T) {
		wrong := sha256.Sum256([]byte("elsewhere"))
		bad, err := appattesttest.MintAssertion(att.Key, testAppID, 3, clientData, wrong[:])
		if err != nil {
			t.Fatalf("MintAssertion: %v", err)
		}
		if _, err := v.VerifyAssertion(bad, clientData, res.PublicKeySPKI, 0); !errors.Is(err, assurance.ErrVerificationFailed) {
			t.Fatalf("err = %v, want ErrVerificationFailed", err)
		}
	})
	t.Run("malformed cbor rejected", func(t *testing.T) {
		if _, err := v.VerifyAssertion([]byte{0xFF}, clientData, res.PublicKeySPKI, 0); !errors.Is(err, assurance.ErrVerificationFailed) {
			t.Fatalf("err = %v, want ErrVerificationFailed", err)
		}
	})
	t.Run("bad stored key rejected", func(t *testing.T) {
		if _, err := v.VerifyAssertion(assertion, clientData, []byte("not spki"), 0); !errors.Is(err, assurance.ErrVerificationFailed) {
			t.Fatalf("err = %v, want ErrVerificationFailed", err)
		}
	})
}
