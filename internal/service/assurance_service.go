package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/assurance"
	"github.com/elloloop/identity/pkg/audit"
)

// Assurance error sentinels. Failures are deliberately coarse: a client
// must not be able to distinguish a forged attestation from a replayed
// challenge or a stale counter.
var (
	// ErrAssuranceDisabled: the requested platform has no verifier for
	// this project (not configured, or assurance is off deployment-wide).
	ErrAssuranceDisabled = errors.New("assurance is not enabled for this platform")
	// ErrAssuranceFailed: the evidence did not verify.
	ErrAssuranceFailed = errors.New("assurance verification failed")
	// ErrAssuranceRequired: the RPC requires a valid assurance token and
	// none (or an invalid one) was presented.
	ErrAssuranceRequired = errors.New("assurance token required")
)

// Assurance platform identifiers accepted by the challenge and issue
// RPCs.
const (
	AssurancePlatformIOS     = "ios"
	AssurancePlatformAndroid = "android"
	AssurancePlatformWeb     = "web"
)

// assuranceChallengeBytes is the nonce entropy. 32 bytes matches the
// challenge size of the passkey flow.
const assuranceChallengeBytes = 32

// AssuranceChallenge is an issued one-time challenge. The client binds
// its attestation to Challenge (the base64url string's UTF-8 bytes are
// the clientData / Play nonce input).
type AssuranceChallenge struct {
	ID        string
	Challenge string // base64url
	ExpiresAt int64  // epoch ms
}

// AssuranceEvidence is one platform's proof for IssueAssuranceToken.
// Exactly the fields for Platform are consulted.
type AssuranceEvidence struct {
	Platform    string
	ChallengeID string // ios + android

	// iOS (App Attest attestation)
	KeyID             string
	AttestationObject []byte // raw CBOR

	// Android (Play Integrity)
	IntegrityToken string

	// Web (Turnstile / reCAPTCHA)
	WebToken string
	ClientIP string
}

// AssuranceToken is a minted assurance token plus its expiry for the
// client's scheduling.
type AssuranceToken struct {
	Token     string
	ExpiresAt int64 // epoch ms
}

// CreateAssuranceChallenge issues a one-time nonce for an attestation or
// assertion. Web evidence needs no challenge (the captcha provider runs
// its own).
func (s *AuthService) CreateAssuranceChallenge(ctx context.Context, platform string) (*AssuranceChallenge, error) {
	switch platform {
	case AssurancePlatformIOS, AssurancePlatformAndroid:
	default:
		return nil, fmt.Errorf("%w: platform must be ios or android", ErrInvalidArgument)
	}
	buf := make([]byte, assuranceChallengeBytes)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	now := s.nowMs()
	rec := &AssuranceChallengeRecord{
		Challenge: base64.RawURLEncoding.EncodeToString(buf),
		Platform:  platform,
		ExpiresAt: now + int64(s.cfg.AssuranceChallengeTTLSeconds)*1000,
		CreatedAt: now,
	}
	id, err := s.repo(ctx).CreateAssuranceChallenge(ctx, rec)
	if err != nil {
		return nil, fmt.Errorf("storing assurance challenge: %w", err)
	}
	return &AssuranceChallenge{ID: id, Challenge: rec.Challenge, ExpiresAt: rec.ExpiresAt}, nil
}

// consumeAssuranceChallenge redeems a challenge exactly once and checks
// expiry. Every failure collapses to ErrAssuranceFailed.
func (s *AuthService) consumeAssuranceChallenge(ctx context.Context, challengeID, platform string) (*AssuranceChallengeRecord, error) {
	if challengeID == "" {
		return nil, ErrAssuranceFailed
	}
	ch, err := s.repo(ctx).ConsumeAssuranceChallenge(ctx, challengeID)
	if err != nil {
		return nil, fmt.Errorf("consuming assurance challenge: %w", err)
	}
	if ch == nil || ch.Platform != platform || ch.ExpiresAt <= s.nowMs() {
		return nil, ErrAssuranceFailed
	}
	return ch, nil
}

// IssueAssuranceToken verifies platform evidence and exchanges it for an
// assurance token. iOS registers the attested device; Android and web
// are stateless.
func (s *AuthService) IssueAssuranceToken(ctx context.Context, ev AssuranceEvidence) (*AssuranceToken, error) {
	if !s.cfg.AssuranceEnabled {
		return nil, ErrAssuranceDisabled
	}
	switch ev.Platform {
	case AssurancePlatformIOS:
		return s.issueForAppAttest(ctx, ev)
	case AssurancePlatformAndroid:
		return s.issueForPlayIntegrity(ctx, ev)
	case AssurancePlatformWeb:
		return s.issueForWeb(ctx, ev)
	default:
		return nil, fmt.Errorf("%w: unknown assurance platform %q", ErrInvalidArgument, ev.Platform)
	}
}

// resolvedAssurance returns the request's attestation providers, or the
// zero value when the resolver is not wired.
func (s *AuthService) resolvedAssurance(ctx context.Context) AssuranceProviders {
	if s.assuranceResolver == nil {
		return AssuranceProviders{}
	}
	return s.assuranceResolver.For(ctx)
}

func (s *AuthService) issueForAppAttest(ctx context.Context, ev AssuranceEvidence) (*AssuranceToken, error) {
	verifier := s.resolvedAssurance(ctx).AppAttest
	if verifier == nil {
		return nil, ErrAssuranceDisabled
	}
	ch, err := s.consumeAssuranceChallenge(ctx, ev.ChallengeID, AssurancePlatformIOS)
	if err != nil {
		return nil, err
	}
	res, err := verifier.VerifyAttestation(ev.AttestationObject, ev.KeyID, []byte(ch.Challenge))
	if err != nil {
		s.logger.Info("assurance_attestation_rejected",
			zap.String("platform", AssurancePlatformIOS), zap.Error(err))
		s.auditAssurance(ctx, false, AssurancePlatformIOS)
		return nil, ErrAssuranceFailed
	}
	now := s.nowMs()
	dev := &AttestedDeviceRecord{
		Platform:      AssurancePlatformIOS,
		KeyID:         res.KeyID,
		PublicKeySPKI: base64.StdEncoding.EncodeToString(res.PublicKeySPKI),
		SignCount:     0,
		Environment:   res.Environment,
		CreatedAt:     now,
		LastUsedAt:    now,
	}
	deviceID, err := s.repo(ctx).CreateAttestedDevice(ctx, dev)
	if errors.Is(err, ErrAlreadyExists) {
		// A genuine attestKey call yields a fresh key; a duplicate key id
		// is a replayed attestation.
		s.auditAssurance(ctx, false, AssurancePlatformIOS)
		return nil, ErrAssuranceFailed
	}
	if err != nil {
		return nil, fmt.Errorf("storing attested device: %w", err)
	}
	s.auditAssurance(ctx, true, AssurancePlatformIOS)
	return s.mintAssuranceToken(ctx, assurance.ProviderAppAttest, deviceID)
}

func (s *AuthService) issueForPlayIntegrity(ctx context.Context, ev AssuranceEvidence) (*AssuranceToken, error) {
	verifier := s.resolvedAssurance(ctx).PlayIntegrity
	if verifier == nil {
		return nil, ErrAssuranceDisabled
	}
	ch, err := s.consumeAssuranceChallenge(ctx, ev.ChallengeID, AssurancePlatformAndroid)
	if err != nil {
		return nil, err
	}
	// The client passed the challenge string to the Play Integrity API as
	// its nonce; Play reports it base64url-encoded, so the expected raw
	// nonce is the challenge string's bytes.
	if _, err := verifier.Verify(ctx, ev.IntegrityToken, []byte(ch.Challenge)); err != nil {
		if errors.Is(err, assurance.ErrProviderUnavailable) {
			return nil, fmt.Errorf("play integrity decode: %w", err)
		}
		s.logger.Info("assurance_attestation_rejected",
			zap.String("platform", AssurancePlatformAndroid), zap.Error(err))
		s.auditAssurance(ctx, false, AssurancePlatformAndroid)
		return nil, ErrAssuranceFailed
	}
	s.auditAssurance(ctx, true, AssurancePlatformAndroid)
	return s.mintAssuranceToken(ctx, assurance.ProviderPlayIntegrity, "")
}

func (s *AuthService) issueForWeb(ctx context.Context, ev AssuranceEvidence) (*AssuranceToken, error) {
	verifier := s.webAssurance
	if verifier == nil {
		return nil, ErrAssuranceDisabled
	}
	if err := verifier.Verify(ctx, ev.WebToken, ev.ClientIP); err != nil {
		if errors.Is(err, assurance.ErrProviderUnavailable) {
			return nil, fmt.Errorf("web assurance verify: %w", err)
		}
		s.auditAssurance(ctx, false, AssurancePlatformWeb)
		return nil, ErrAssuranceFailed
	}
	s.auditAssurance(ctx, true, AssurancePlatformWeb)
	return s.mintAssuranceToken(ctx, verifier.Name(), "")
}

// RefreshAssuranceToken renews an assurance token without a full
// re-attestation: the client signs a fresh challenge with its Secure
// Enclave key (App Attest assertion) and the counter CAS provides the
// replay protection. iOS-only — Android re-verifies via
// IssueAssuranceToken each time (Play Integrity has no persistent key).
func (s *AuthService) RefreshAssuranceToken(ctx context.Context, challengeID, keyID string, assertion []byte) (*AssuranceToken, error) {
	if !s.cfg.AssuranceEnabled {
		return nil, ErrAssuranceDisabled
	}
	verifier := s.resolvedAssurance(ctx).AppAttest
	if verifier == nil {
		return nil, ErrAssuranceDisabled
	}
	ch, err := s.consumeAssuranceChallenge(ctx, challengeID, AssurancePlatformIOS)
	if err != nil {
		return nil, err
	}
	dev, err := s.repo(ctx).GetAttestedDeviceByKeyID(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("loading attested device: %w", err)
	}
	if dev == nil {
		return nil, ErrAssuranceFailed
	}
	spki, err := base64.StdEncoding.DecodeString(dev.PublicKeySPKI)
	if err != nil {
		return nil, fmt.Errorf("stored device key corrupt: %w", err)
	}
	newCount, err := verifier.VerifyAssertion(assertion, []byte(ch.Challenge), spki, uint32(dev.SignCount))
	if err != nil {
		s.logger.Info("assurance_assertion_rejected", zap.Error(err))
		s.auditAssurance(ctx, false, AssurancePlatformIOS)
		return nil, ErrAssuranceFailed
	}
	err = s.repo(ctx).UpdateAttestedDeviceCounter(ctx, dev.NodeID, dev.SignCount, int64(newCount), s.nowMs())
	if errors.Is(err, ErrCounterStale) || errors.Is(err, ErrNotFound) {
		// A racing assertion advanced the counter first (or the device
		// vanished): treat as replay.
		s.auditAssurance(ctx, false, AssurancePlatformIOS)
		return nil, ErrAssuranceFailed
	}
	if err != nil {
		return nil, fmt.Errorf("advancing device counter: %w", err)
	}
	s.auditAssurance(ctx, true, AssurancePlatformIOS)
	return s.mintAssuranceToken(ctx, assurance.ProviderAppAttest, dev.NodeID)
}

// mintAssuranceToken signs the token for the resolved project.
func (s *AuthService) mintAssuranceToken(ctx context.Context, provider, deviceID string) (*AssuranceToken, error) {
	now := s.nowFunc()
	ttl := s.cfg.AssuranceTokenTTL()
	tok, err := assurance.MintToken(ctx, s.signer, assurance.TokenClaims{
		Project:   s.projectID(ctx),
		Providers: []string{provider},
		DeviceID:  deviceID,
	}, ttl, now)
	if err != nil {
		return nil, fmt.Errorf("minting assurance token: %w", err)
	}
	return &AssuranceToken{Token: tok, ExpiresAt: now.Add(ttl).UnixMilli()}, nil
}

// auditAssurance records an attestation attempt. There is no actor: the
// whole point of the flow is that nobody is signed in yet.
func (s *AuthService) auditAssurance(ctx context.Context, success bool, platform string) {
	s.audit.Log(
		ctx, audit.EventAssuranceAttested,
		audit.WithSuccess(success),
		audit.WithDetails(map[string]any{"platform": platform}),
	)
}

// VerifyAssuranceToken checks a client-presented assurance token against
// the deployment's keys and the request's resolved project. Handlers
// call this to enforce assurance on protected RPCs.
func (s *AuthService) VerifyAssuranceToken(ctx context.Context, token string) (*assurance.TokenClaims, error) {
	if token == "" {
		return nil, ErrAssuranceRequired
	}
	claims, err := assurance.VerifyToken(token, s.signer, s.projectID(ctx), s.nowFunc())
	if err != nil {
		return nil, ErrAssuranceRequired
	}
	return claims, nil
}
