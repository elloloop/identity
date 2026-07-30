package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/elloloop/identity/pkg/assurance"
	"github.com/elloloop/identity/pkg/assurance/appattest"
	"github.com/elloloop/identity/pkg/assurance/appattest/appattesttest"
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
func mintAttestation(t *testing.T, svc *AuthService, auth *appattesttest.Authority) (challengeID string, att *appattesttest.Attestation) {
	t.Helper()
	ch, err := svc.CreateAssuranceChallenge(context.Background(), AssurancePlatformIOS)
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

	chID, att := mintAttestation(t, svc, authy)
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

	chID, att := mintAttestation(t, svc, authy)
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
