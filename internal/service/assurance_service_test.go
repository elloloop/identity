package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/elloloop/identity/pkg/assurance"
	"github.com/elloloop/identity/pkg/assurance/appattest"
	"github.com/elloloop/identity/pkg/assurance/appattest/appattesttest"
	"github.com/elloloop/identity/pkg/assurance/playintegrity"
)

const (
	assurTeamID   = "TESTTEAM01"
	assurBundleID = "com.example.dictionary"
	assurAppID    = assurTeamID + "." + assurBundleID
)

// fakeWebVerifier is a controllable web-assurance verifier.
type fakeWebVerifier struct {
	err error
}

func (fakeWebVerifier) Name() string { return "fake-web" }
func (f fakeWebVerifier) Verify(context.Context, string, string) error {
	return f.err
}

// fakePlayServer stands up a Google stand-in serving both the OAuth
// token endpoint and decodeIntegrityToken, and returns a Verifier wired
// to it. verdictNonce is echoed back as requestDetails.nonce — tests set
// it to the challenge string a real client would have passed. decodeCode
// != 200 makes the decode endpoint fail with that status.
func fakePlayServer(t *testing.T, verdictNonce *string, decodeCode *int) *playintegrity.Verifier {
	t.Helper()
	const pkg = "com.example.dictionary"
	const digest = "ZGlnZXN0"

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	saKey, err := json.Marshal(map[string]string{
		"client_email": "svc@test.iam.gserviceaccount.com",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
	})
	if err != nil {
		t.Fatalf("marshal sa key: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fake", "expires_in": 3600})
	})
	mux.HandleFunc("/v1/"+pkg+":decodeIntegrityToken", func(w http.ResponseWriter, _ *http.Request) {
		if *decodeCode != http.StatusOK {
			w.WriteHeader(*decodeCode)
			_, _ = w.Write([]byte(`{"error":"upstream"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tokenPayloadExternal": map[string]any{
				"requestDetails": map[string]any{
					"requestPackageName": pkg,
					"nonce":              *verdictNonce,
					"timestampMillis":    strconv.FormatInt(time.Now().UnixMilli(), 10),
				},
				"appIntegrity": map[string]any{
					"appRecognitionVerdict":   "PLAY_RECOGNIZED",
					"packageName":             pkg,
					"certificateSha256Digest": []string{digest},
					"versionCode":             "7",
				},
				"deviceIntegrity": map[string]any{
					"deviceRecognitionVerdict": []string{"MEETS_DEVICE_INTEGRITY"},
				},
			},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	v, err := playintegrity.New(playintegrity.Config{
		PackageName:        pkg,
		CertSHA256Digests:  []string{digest},
		ServiceAccountJSON: saKey,
		BaseURL:            srv.URL,
		TokenURL:           srv.URL + "/token",
		HTTPClient:         srv.Client(),
	})
	if err != nil {
		t.Fatalf("playintegrity.New: %v", err)
	}
	return v
}

// newAssuranceService builds an AuthService with assurance enabled, an
// App Attest verifier trusting the synthetic authority, and the given
// web verifier.
func newAssuranceService(t *testing.T, repo *fakeRepo, auth *appattesttest.Authority, web assurance.Verifier) *AuthService {
	t.Helper()
	svc := newTestAuthService(t, repo)
	svc.cfg.AssuranceEnabled = true
	svc.cfg.AssuranceChallengeTTLSeconds = 300
	svc.cfg.AssuranceTokenTTLSeconds = 3600

	var defaults AssuranceProviders
	if auth != nil {
		v, err := appattest.New(appattest.Config{
			TeamID:   assurTeamID,
			BundleID: assurBundleID,
			Roots:    auth.RootPool(),
			Now:      svc.nowFunc,
		})
		if err != nil {
			t.Fatalf("appattest.New: %v", err)
		}
		defaults.AppAttest = v
	}
	resolver := NewAssuranceResolver("", defaults, nil, nil)
	svc.WithAssurance(resolver, web)
	return svc
}

func TestCreateAssuranceChallenge(t *testing.T) {
	svc := newAssuranceService(t, newFakeRepo(), nil, nil)
	ctx := context.Background()

	ch, err := svc.CreateAssuranceChallenge(ctx, AssurancePlatformIOS)
	if err != nil {
		t.Fatalf("CreateAssuranceChallenge: %v", err)
	}
	if ch.ID == "" || ch.Challenge == "" {
		t.Fatalf("challenge = %+v", ch)
	}
	if ch.ExpiresAt <= svc.nowMs() {
		t.Fatalf("challenge already expired: %d", ch.ExpiresAt)
	}

	if _, err := svc.CreateAssuranceChallenge(ctx, "windows"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("bad platform err = %v", err)
	}
}

// mintAttestation issues a challenge through the service and mints a
// matching synthetic attestation bound to it.
func mintAttestation(ctx context.Context, t *testing.T, svc *AuthService, auth *appattesttest.Authority) (challengeID string, att *appattesttest.Attestation) {
	t.Helper()
	ch, err := svc.CreateAssuranceChallenge(ctx, AssurancePlatformIOS)
	if err != nil {
		t.Fatalf("CreateAssuranceChallenge: %v", err)
	}
	att, err = auth.Mint(time.Now(), appattesttest.MintOpts{
		AppID:     assurAppID,
		Challenge: []byte(ch.Challenge),
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return ch.ID, att
}

func TestIssueAssuranceTokenAppAttest(t *testing.T) {
	authy, err := appattesttest.NewAuthority(time.Now())
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	repo := newFakeRepo()
	svc := newAssuranceService(t, repo, authy, nil)
	ctx := context.Background()

	chID, att := mintAttestation(ctx, t, svc, authy)
	tok, err := svc.IssueAssuranceToken(ctx, AssuranceEvidence{
		Platform:          AssurancePlatformIOS,
		ChallengeID:       chID,
		KeyID:             att.KeyID,
		AttestationObject: att.CBOR,
	})
	if err != nil {
		t.Fatalf("IssueAssuranceToken: %v", err)
	}

	// The minted token verifies and carries the device + provider.
	claims, err := svc.VerifyAssuranceToken(ctx, tok.Token)
	if err != nil {
		t.Fatalf("VerifyAssuranceToken: %v", err)
	}
	if len(claims.Providers) != 1 || claims.Providers[0] != assurance.ProviderAppAttest {
		t.Errorf("Providers = %v", claims.Providers)
	}
	if claims.DeviceID == "" {
		t.Error("DeviceID empty")
	}
	dev, err := repo.GetAttestedDeviceByKeyID(ctx, att.KeyID)
	if err != nil || dev == nil {
		t.Fatalf("device not stored: (%#v, %v)", dev, err)
	}

	t.Run("challenge is single use", func(t *testing.T) {
		_, err := svc.IssueAssuranceToken(ctx, AssuranceEvidence{
			Platform:          AssurancePlatformIOS,
			ChallengeID:       chID,
			KeyID:             att.KeyID,
			AttestationObject: att.CBOR,
		})
		if !errors.Is(err, ErrAssuranceFailed) {
			t.Fatalf("replayed challenge err = %v", err)
		}
	})

	t.Run("replayed attestation rejected", func(t *testing.T) {
		// Fresh challenge, but an attestation whose key id is already
		// registered: the duplicate-device path must reject.
		ch2, err := svc.CreateAssuranceChallenge(ctx, AssurancePlatformIOS)
		if err != nil {
			t.Fatalf("challenge: %v", err)
		}
		att2, err := authy.Mint(time.Now(), appattesttest.MintOpts{
			AppID: assurAppID, Challenge: []byte(ch2.Challenge),
		})
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		// Pre-register the same key id.
		if _, err := repo.CreateAttestedDevice(ctx, &AttestedDeviceRecord{
			Platform: "ios", KeyID: att2.KeyID, PublicKeySPKI: "x", CreatedAt: 1, LastUsedAt: 1,
		}); err != nil {
			t.Fatalf("seed device: %v", err)
		}
		_, err = svc.IssueAssuranceToken(ctx, AssuranceEvidence{
			Platform:          AssurancePlatformIOS,
			ChallengeID:       ch2.ID,
			KeyID:             att2.KeyID,
			AttestationObject: att2.CBOR,
		})
		if !errors.Is(err, ErrAssuranceFailed) {
			t.Fatalf("duplicate device err = %v", err)
		}
	})

	t.Run("bad attestation rejected", func(t *testing.T) {
		ch3, err := svc.CreateAssuranceChallenge(ctx, AssurancePlatformIOS)
		if err != nil {
			t.Fatalf("challenge: %v", err)
		}
		_, err = svc.IssueAssuranceToken(ctx, AssuranceEvidence{
			Platform:          AssurancePlatformIOS,
			ChallengeID:       ch3.ID,
			KeyID:             att.KeyID,
			AttestationObject: []byte("garbage"),
		})
		if !errors.Is(err, ErrAssuranceFailed) {
			t.Fatalf("garbage attestation err = %v", err)
		}
	})
}

func TestRefreshAssuranceToken(t *testing.T) {
	authy, err := appattesttest.NewAuthority(time.Now())
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	repo := newFakeRepo()
	svc := newAssuranceService(t, repo, authy, nil)
	ctx := context.Background()

	chID, att := mintAttestation(ctx, t, svc, authy)
	if _, err := svc.IssueAssuranceToken(ctx, AssuranceEvidence{
		Platform: AssurancePlatformIOS, ChallengeID: chID,
		KeyID: att.KeyID, AttestationObject: att.CBOR,
	}); err != nil {
		t.Fatalf("attest: %v", err)
	}

	refresh := func(counter uint32) (*AssuranceToken, error) {
		ch, err := svc.CreateAssuranceChallenge(ctx, AssurancePlatformIOS)
		if err != nil {
			t.Fatalf("challenge: %v", err)
		}
		assertion, err := appattesttest.MintAssertion(att.Key, assurAppID, counter, []byte(ch.Challenge), nil)
		if err != nil {
			t.Fatalf("MintAssertion: %v", err)
		}
		return svc.RefreshAssuranceToken(ctx, ch.ID, att.KeyID, assertion)
	}

	tok, err := refresh(1)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	claims, err := svc.VerifyAssuranceToken(ctx, tok.Token)
	if err != nil || claims.DeviceID == "" {
		t.Fatalf("refresh token claims: (%+v, %v)", claims, err)
	}

	t.Run("counter must advance", func(t *testing.T) {
		if _, err := refresh(1); !errors.Is(err, ErrAssuranceFailed) {
			t.Fatalf("stale counter err = %v", err)
		}
	})
	t.Run("counter advances again", func(t *testing.T) {
		if _, err := refresh(2); err != nil {
			t.Fatalf("second refresh: %v", err)
		}
	})
	t.Run("unknown key rejected", func(t *testing.T) {
		ch, err := svc.CreateAssuranceChallenge(ctx, AssurancePlatformIOS)
		if err != nil {
			t.Fatalf("challenge: %v", err)
		}
		assertion, err := appattesttest.MintAssertion(att.Key, assurAppID, 9, []byte(ch.Challenge), nil)
		if err != nil {
			t.Fatalf("MintAssertion: %v", err)
		}
		if _, err := svc.RefreshAssuranceToken(ctx, ch.ID, "bm8ta2V5", assertion); !errors.Is(err, ErrAssuranceFailed) {
			t.Fatalf("unknown key err = %v", err)
		}
	})
}

func TestIssueAssuranceTokenWeb(t *testing.T) {
	repo := newFakeRepo()
	svc := newAssuranceService(t, repo, nil, fakeWebVerifier{})
	ctx := context.Background()

	tok, err := svc.IssueAssuranceToken(ctx, AssuranceEvidence{
		Platform: AssurancePlatformWeb, WebToken: "captcha-solution", ClientIP: "1.2.3.4",
	})
	if err != nil {
		t.Fatalf("web issue: %v", err)
	}
	claims, err := svc.VerifyAssuranceToken(ctx, tok.Token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(claims.Providers) != 1 || claims.Providers[0] != "fake-web" {
		t.Errorf("Providers = %v", claims.Providers)
	}
	if claims.DeviceID != "" {
		t.Errorf("web token carries a device id: %q", claims.DeviceID)
	}

	t.Run("failed captcha rejected", func(t *testing.T) {
		bad := newAssuranceService(t, newFakeRepo(), nil, fakeWebVerifier{err: assurance.ErrVerificationFailed})
		if _, err := bad.IssueAssuranceToken(ctx, AssuranceEvidence{
			Platform: AssurancePlatformWeb, WebToken: "wrong",
		}); !errors.Is(err, ErrAssuranceFailed) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("provider outage is not a rejection", func(t *testing.T) {
		out := newAssuranceService(t, newFakeRepo(), nil, fakeWebVerifier{err: assurance.ErrProviderUnavailable})
		_, err := out.IssueAssuranceToken(ctx, AssuranceEvidence{
			Platform: AssurancePlatformWeb, WebToken: "t",
		})
		if err == nil || errors.Is(err, ErrAssuranceFailed) {
			t.Fatalf("outage err = %v, want retryable non-rejection", err)
		}
	})
}

func TestAssuranceDisabledPaths(t *testing.T) {
	ctx := context.Background()

	t.Run("deployment toggle off", func(t *testing.T) {
		svc := newTestAuthService(t, newFakeRepo()) // AssuranceEnabled false
		if _, err := svc.IssueAssuranceToken(ctx, AssuranceEvidence{Platform: AssurancePlatformWeb}); !errors.Is(err, ErrAssuranceDisabled) {
			t.Fatalf("err = %v", err)
		}
		if _, err := svc.RefreshAssuranceToken(ctx, "c", "k", nil); !errors.Is(err, ErrAssuranceDisabled) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("platform not configured", func(t *testing.T) {
		svc := newAssuranceService(t, newFakeRepo(), nil, nil) // no ios, no web
		if _, err := svc.IssueAssuranceToken(ctx, AssuranceEvidence{Platform: AssurancePlatformIOS, ChallengeID: "x"}); !errors.Is(err, ErrAssuranceDisabled) {
			t.Fatalf("ios err = %v", err)
		}
		if _, err := svc.IssueAssuranceToken(ctx, AssuranceEvidence{Platform: AssurancePlatformAndroid, ChallengeID: "x"}); !errors.Is(err, ErrAssuranceDisabled) {
			t.Fatalf("android err = %v", err)
		}
		if _, err := svc.IssueAssuranceToken(ctx, AssuranceEvidence{Platform: AssurancePlatformWeb}); !errors.Is(err, ErrAssuranceDisabled) {
			t.Fatalf("web err = %v", err)
		}
	})
}

func TestVerifyAssuranceTokenRejectsGarbage(t *testing.T) {
	svc := newAssuranceService(t, newFakeRepo(), nil, fakeWebVerifier{})
	if _, err := svc.VerifyAssuranceToken(context.Background(), ""); !errors.Is(err, ErrAssuranceRequired) {
		t.Fatalf("empty token err = %v", err)
	}
	if _, err := svc.VerifyAssuranceToken(context.Background(), "junk"); !errors.Is(err, ErrAssuranceRequired) {
		t.Fatalf("junk token err = %v", err)
	}
}

func TestProjectAssuranceConfigValidate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cfg     ProjectAssuranceConfig
		wantErr bool
	}{
		{"zero", ProjectAssuranceConfig{}, false},
		{"ios ok", ProjectAssuranceConfig{IOS: &ProjectAssuranceIOS{TeamID: "T", BundleID: "b"}}, false},
		{"ios dev env ok", ProjectAssuranceConfig{IOS: &ProjectAssuranceIOS{TeamID: "T", BundleID: "b", Env: "development"}}, false},
		{"ios missing bundle", ProjectAssuranceConfig{IOS: &ProjectAssuranceIOS{TeamID: "T"}}, true},
		{"ios bad env", ProjectAssuranceConfig{IOS: &ProjectAssuranceIOS{TeamID: "T", BundleID: "b", Env: "staging"}}, true},
		{"android ok", ProjectAssuranceConfig{Android: &ProjectAssuranceAndroid{PackageName: "p", CertSHA256Digests: []string{"d"}, ServiceAccountKeyEnc: "e"}}, false},
		{"android missing digest", ProjectAssuranceConfig{Android: &ProjectAssuranceAndroid{PackageName: "p", ServiceAccountKeyEnc: "e"}}, true},
		{"android empty digest", ProjectAssuranceConfig{Android: &ProjectAssuranceAndroid{PackageName: "p", CertSHA256Digests: []string{""}, ServiceAccountKeyEnc: "e"}}, true},
		{"android missing key", ProjectAssuranceConfig{Android: &ProjectAssuranceAndroid{PackageName: "p", CertSHA256Digests: []string{"d"}}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.validate()
			if tc.wantErr && err == nil {
				t.Fatal("want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestIssueAssuranceTokenPlayIntegrity covers the Android service glue
// end-to-end against a fake Google: the challenge is consumed, the
// challenge STRING (not its base64 re-encoding) is what Play must echo
// back, a success mints a play_integrity token with no device id, and an
// upstream outage maps to ErrAssuranceUnavailable rather than a rejection.
func TestIssueAssuranceTokenPlayIntegrity(t *testing.T) {
	repo := newFakeRepo()
	svc := newAssuranceService(t, repo, nil, nil)
	ctx := context.Background()

	nonce := ""
	decodeCode := http.StatusOK
	verifier := fakePlayServer(t, &nonce, &decodeCode)
	svc.WithAssurance(
		NewAssuranceResolver("", AssuranceProviders{PlayIntegrity: verifier}, nil, nil),
		nil,
	)

	// Happy path: the client passes the challenge string verbatim as the
	// Play nonce, so that is what the verdict echoes.
	ch, err := svc.CreateAssuranceChallenge(ctx, AssurancePlatformAndroid)
	if err != nil {
		t.Fatalf("CreateAssuranceChallenge: %v", err)
	}
	nonce = ch.Challenge

	tok, err := svc.IssueAssuranceToken(ctx, AssuranceEvidence{
		Platform:       AssurancePlatformAndroid,
		ChallengeID:    ch.ID,
		IntegrityToken: "integrity-token",
	})
	if err != nil {
		t.Fatalf("IssueAssuranceToken(android): %v", err)
	}
	claims, err := svc.VerifyAssuranceToken(ctx, tok.Token)
	if err != nil {
		t.Fatalf("VerifyAssuranceToken: %v", err)
	}
	if len(claims.Providers) != 1 || claims.Providers[0] != assurance.ProviderPlayIntegrity {
		t.Errorf("Providers = %v, want [%s]", claims.Providers, assurance.ProviderPlayIntegrity)
	}
	if claims.DeviceID != "" {
		t.Errorf("android token carries a device id %q; Play Integrity registers no device", claims.DeviceID)
	}

	t.Run("challenge is single use", func(t *testing.T) {
		if _, err := svc.IssueAssuranceToken(ctx, AssuranceEvidence{
			Platform: AssurancePlatformAndroid, ChallengeID: ch.ID, IntegrityToken: "integrity-token",
		}); !errors.Is(err, ErrAssuranceFailed) {
			t.Fatalf("replayed challenge err = %v, want ErrAssuranceFailed", err)
		}
	})

	t.Run("nonce mismatch rejected", func(t *testing.T) {
		fresh, err := svc.CreateAssuranceChallenge(ctx, AssurancePlatformAndroid)
		if err != nil {
			t.Fatalf("challenge: %v", err)
		}
		nonce = "a-different-nonce" // Play echoes something else back
		if _, err := svc.IssueAssuranceToken(ctx, AssuranceEvidence{
			Platform: AssurancePlatformAndroid, ChallengeID: fresh.ID, IntegrityToken: "t",
		}); !errors.Is(err, ErrAssuranceFailed) {
			t.Fatalf("nonce mismatch err = %v, want ErrAssuranceFailed", err)
		}
	})

	t.Run("ios challenge cannot be redeemed as android", func(t *testing.T) {
		iosCh, err := svc.CreateAssuranceChallenge(ctx, AssurancePlatformIOS)
		if err != nil {
			t.Fatalf("challenge: %v", err)
		}
		nonce = iosCh.Challenge
		if _, err := svc.IssueAssuranceToken(ctx, AssuranceEvidence{
			Platform: AssurancePlatformAndroid, ChallengeID: iosCh.ID, IntegrityToken: "t",
		}); !errors.Is(err, ErrAssuranceFailed) {
			t.Fatalf("cross-platform challenge err = %v, want ErrAssuranceFailed", err)
		}
	})

	t.Run("upstream outage is unavailable, not a rejection", func(t *testing.T) {
		fresh, err := svc.CreateAssuranceChallenge(ctx, AssurancePlatformAndroid)
		if err != nil {
			t.Fatalf("challenge: %v", err)
		}
		nonce = fresh.Challenge
		decodeCode = http.StatusInternalServerError
		defer func() { decodeCode = http.StatusOK }()

		_, err = svc.IssueAssuranceToken(ctx, AssuranceEvidence{
			Platform: AssurancePlatformAndroid, ChallengeID: fresh.ID, IntegrityToken: "t",
		})
		if !errors.Is(err, ErrAssuranceUnavailable) {
			t.Fatalf("outage err = %v, want ErrAssuranceUnavailable", err)
		}
		if errors.Is(err, ErrAssuranceFailed) {
			t.Fatal("an outage must not be reported as a verification failure")
		}
	})
}

// TestAssuranceChallengeExpiry pins the expiry half of
// consumeAssuranceChallenge: a challenge redeemed after its TTL must be
// rejected even though the row is still present (the sweeper is periodic,
// so an expired-but-unswept row is the normal case, not an edge one).
func TestAssuranceChallengeExpiry(t *testing.T) {
	repo := newFakeRepo()
	svc := newAssuranceService(t, repo, nil, fakeWebVerifier{})
	svc.cfg.AssuranceChallengeTTLSeconds = 1
	ctx := context.Background()

	ch, err := svc.CreateAssuranceChallenge(ctx, AssurancePlatformIOS)
	if err != nil {
		t.Fatalf("CreateAssuranceChallenge: %v", err)
	}

	// Move the clock past the TTL; the row is still in the repo.
	base := svc.nowFunc()
	svc.nowFunc = func() time.Time { return base.Add(time.Minute) }

	if _, err := svc.RefreshAssuranceToken(ctx, ch.ID, "a2V5", nil); !errors.Is(err, ErrAssuranceDisabled) &&
		!errors.Is(err, ErrAssuranceFailed) {
		t.Fatalf("expired challenge err = %v, want a coarse assurance failure", err)
	}

	// With an App Attest verifier wired, the expiry is what rejects — not a
	// missing platform.
	authy, err := appattesttest.NewAuthority(time.Now())
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	svc2 := newAssuranceService(t, newFakeRepo(), authy, nil)
	svc2.cfg.AssuranceChallengeTTLSeconds = 1
	ch2, err := svc2.CreateAssuranceChallenge(ctx, AssurancePlatformIOS)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	att, err := authy.Mint(time.Now(), appattesttest.MintOpts{
		AppID: assurAppID, Challenge: []byte(ch2.Challenge),
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	base2 := svc2.nowFunc()
	svc2.nowFunc = func() time.Time { return base2.Add(time.Minute) }

	if _, err := svc2.IssueAssuranceToken(ctx, AssuranceEvidence{
		Platform: AssurancePlatformIOS, ChallengeID: ch2.ID,
		KeyID: att.KeyID, AttestationObject: att.CBOR,
	}); !errors.Is(err, ErrAssuranceFailed) {
		t.Fatalf("expired challenge with valid attestation err = %v, want ErrAssuranceFailed", err)
	}
}

// TestRefreshAssuranceCounterCASFailures pins the SERVICE-level replay
// defence: a lost compare-and-swap on the hardware counter (a concurrent
// assertion won) and a vanished device must both collapse to the coarse
// ErrAssuranceFailed, never surface a wrapped repository error. The
// repository CAS itself is pinned by conformance; this is the mapping.
func TestRefreshAssuranceCounterCASFailures(t *testing.T) {
	authy, err := appattesttest.NewAuthority(time.Now())
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	ctx := context.Background()

	for _, tc := range []struct {
		name    string
		repoErr error
	}{
		{"lost CAS (concurrent assertion won)", ErrCounterStale},
		{"device vanished", ErrNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newFakeRepo()
			svc := newAssuranceService(t, repo, authy, nil)

			chID, att := mintAttestation(ctx, t, svc, authy)
			if _, err := svc.IssueAssuranceToken(ctx, AssuranceEvidence{
				Platform: AssurancePlatformIOS, ChallengeID: chID,
				KeyID: att.KeyID, AttestationObject: att.CBOR,
			}); err != nil {
				t.Fatalf("attest: %v", err)
			}

			// The assertion itself is valid; only the CAS fails.
			repo.updateCounterErr = tc.repoErr

			ch, err := svc.CreateAssuranceChallenge(ctx, AssurancePlatformIOS)
			if err != nil {
				t.Fatalf("challenge: %v", err)
			}
			assertion, err := appattesttest.MintAssertion(att.Key, assurAppID, 1, []byte(ch.Challenge), nil)
			if err != nil {
				t.Fatalf("MintAssertion: %v", err)
			}

			_, err = svc.RefreshAssuranceToken(ctx, ch.ID, att.KeyID, assertion)
			if !errors.Is(err, ErrAssuranceFailed) {
				t.Fatalf("err = %v, want ErrAssuranceFailed (replay)", err)
			}
			if errors.Is(err, ErrCounterStale) || errors.Is(err, ErrNotFound) {
				t.Fatal("the repository error must not leak to the client")
			}
		})
	}
}

// TestConsumeAssuranceChallengeGuards covers the two remaining branches of
// the redemption guard: a missing challenge id is rejected before any
// repository call, and a repository failure propagates as an error rather
// than being mistaken for a rejected challenge (an outage must not read as
// "your evidence is bad").
func TestConsumeAssuranceChallengeGuards(t *testing.T) {
	authy, err := appattesttest.NewAuthority(time.Now())
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	ctx := context.Background()

	t.Run("empty challenge id rejected without touching the repo", func(t *testing.T) {
		repo := newFakeRepo()
		repo.consumeChallengeErr = errors.New("must not be called")
		svc := newAssuranceService(t, repo, authy, nil)

		if _, err := svc.IssueAssuranceToken(ctx, AssuranceEvidence{
			Platform: AssurancePlatformIOS, ChallengeID: "",
		}); !errors.Is(err, ErrAssuranceFailed) {
			t.Fatalf("err = %v, want ErrAssuranceFailed", err)
		}
	})

	t.Run("repository failure is not a verification failure", func(t *testing.T) {
		repo := newFakeRepo()
		svc := newAssuranceService(t, repo, authy, nil)
		ch, err := svc.CreateAssuranceChallenge(ctx, AssurancePlatformIOS)
		if err != nil {
			t.Fatalf("challenge: %v", err)
		}
		repo.consumeChallengeErr = errors.New("datastore down")

		_, err = svc.IssueAssuranceToken(ctx, AssuranceEvidence{
			Platform: AssurancePlatformIOS, ChallengeID: ch.ID, KeyID: "a2V5",
		})
		if err == nil {
			t.Fatal("expected an error")
		}
		if errors.Is(err, ErrAssuranceFailed) {
			t.Fatalf("a datastore outage must not read as rejected evidence: %v", err)
		}
	})
}

// TestAssuranceTokenIsProjectScoped threads TWO different project scopes
// through mint and verify. Both sides call the same s.projectID(ctx)
// helper, so a regression that dropped the claim at mint or passed "" at
// verify would leave every other test green while making a project-A
// token valid on project-B requests.
func TestAssuranceTokenIsProjectScoped(t *testing.T) {
	svc := newAssuranceService(t, newFakeRepo(), nil, fakeWebVerifier{})
	projA := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "proj-a"})
	projB := WithProjectScope(context.Background(), &ProjectScope{ProjectID: "proj-b"})

	tok, err := svc.IssueAssuranceToken(projA, AssuranceEvidence{
		Platform: AssurancePlatformWeb, WebToken: "solution",
	})
	if err != nil {
		t.Fatalf("mint under project A: %v", err)
	}

	if _, err := svc.VerifyAssuranceToken(projA, tok.Token); err != nil {
		t.Fatalf("project A token must verify on a project A request: %v", err)
	}
	if _, err := svc.VerifyAssuranceToken(projB, tok.Token); !errors.Is(err, ErrAssuranceRequired) {
		t.Fatalf("project A token verified on a project B request: err = %v", err)
	}
}

// TestAssuranceWebTokenUsesShorterTTL pins that the web arm gets its own
// lifetime. ADR-0012 offers "set a short web TTL" as the mitigation for
// the web token being reusable and transferable; before this the knob did
// not exist and shortening web would have shortened the hardware arms too.
func TestAssuranceWebTokenUsesShorterTTL(t *testing.T) {
	repo := newFakeRepo()
	svc := newAssuranceService(t, repo, nil, fakeWebVerifier{})
	svc.cfg.AssuranceTokenTTLSeconds = 3600
	svc.cfg.AssuranceWebTokenTTLSeconds = 300
	ctx := context.Background()

	tok, err := svc.IssueAssuranceToken(ctx, AssuranceEvidence{
		Platform: AssurancePlatformWeb, WebToken: "solution",
	})
	if err != nil {
		t.Fatalf("web issue: %v", err)
	}
	gotTTL := tok.ExpiresAt - svc.nowFunc().UnixMilli()
	if gotTTL > 300*1000 {
		t.Fatalf("web token TTL = %dms, want <= 300s — the web arm must not inherit the mobile TTL", gotTTL)
	}

	t.Run("unset falls back to the global TTL", func(t *testing.T) {
		svc.cfg.AssuranceWebTokenTTLSeconds = 0
		tok, err := svc.IssueAssuranceToken(ctx, AssuranceEvidence{
			Platform: AssurancePlatformWeb, WebToken: "solution",
		})
		if err != nil {
			t.Fatalf("web issue: %v", err)
		}
		if ttl := tok.ExpiresAt - svc.nowFunc().UnixMilli(); ttl <= 300*1000 {
			t.Fatalf("TTL = %dms, want the global 3600s fallback", ttl)
		}
	})
}

// TestAttestKeyIDIsCanonicalized pins that a non-canonical re-encoding of
// the same key cannot slip past the duplicate-key_id replay guard by
// landing in a second row.
func TestAttestKeyIDIsCanonicalized(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	canonical := base64.StdEncoding.EncodeToString(raw)

	got, err := canonicalAttestKeyID(canonical)
	if err != nil || got != canonical {
		t.Fatalf("canonical input round-trip = (%q, %v)", got, err)
	}
	if _, err := canonicalAttestKeyID("not-base64!!"); err == nil {
		t.Error("malformed key id must be rejected")
	}
	if _, err := canonicalAttestKeyID(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Error("a key id that is not a SHA-256 must be rejected")
	}
}
