package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
	jwtpkg "github.com/elloloop/identity/pkg/jwt"
)

const (
	teammateKeyChallengeDomain   = "identity.agent-machine.v1"
	teammateKeyExchangeOperation = "exchange_teammate"
	maxTeammatePublicKeyBytes    = 256
)

var (
	ErrTeammateKeysDisabled = errors.New("teammate keys are disabled")
	ErrTeammateKeyConflict  = errors.New("teammate key conflicts with an existing registration")
	errTeammateKeyManager   = fmt.Errorf("%w: invalid teammate key manager credential", ErrPermissionDenied)
)

// TeammateKeyRegistration is one RegisterTeammateKey request. Algorithm is
// TeammateKeyEd25519 or TeammateKeyECDSAP256; PublicKey is a DER
// SubjectPublicKeyInfo of that key type.
type TeammateKeyRegistration struct {
	ClaimID       string
	TeammateID    string
	CompanyID     string
	WorkstationID string
	PublicKey     []byte
	Algorithm     string
}

// TeammateKeyService lets a service holding a teammate_key_manager
// credential register and revoke teammate keys, and lets a workstation
// exchange a challenge signed with one for a teammate access token. The
// token's identity fields always come from the stored key.
type TeammateKeyService struct {
	credentials    DirectoryCredentialStore
	base           Repository
	signer         jwtpkg.TeammateSigner
	issuer         string
	audience       string
	defaultProject string
	audit          *audit.Logger
	now            func() time.Time
	metrics        teammateKeyMetrics
}

type teammateKeyMetrics struct {
	registered *prometheus.CounterVec
	revoked    prometheus.Counter
}

func newTeammateKeyMetrics(reg prometheus.Registerer) (teammateKeyMetrics, error) {
	if reg == nil {
		reg = prometheus.NewRegistry()
	}
	metrics := teammateKeyMetrics{
		registered: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "identity_teammate_keys_registered_total",
			Help: "RegisterTeammateKey calls, labelled by result.",
		}, []string{"result"}),
		revoked: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "identity_teammate_keys_revoked_total",
			Help: "Teammate keys revoked by RevokeTeammateKey.",
		}),
	}
	for _, c := range []prometheus.Collector{metrics.registered, metrics.revoked} {
		if err := reg.Register(c); err != nil {
			return teammateKeyMetrics{}, fmt.Errorf("teammate key metrics: %w", err)
		}
	}
	return metrics, nil
}

func NewTeammateKeyService(cfg *config.Config, credentials DirectoryCredentialStore, base Repository, signer jwtpkg.Signer, auditLog *audit.Logger, reg prometheus.Registerer) (*TeammateKeyService, error) {
	if err := cfg.ValidateTeammateKeys(); err != nil {
		return nil, err
	}
	if credentials == nil {
		return nil, errors.New("teammate keys require the postgres control plane for teammate_key_manager credentials")
	}
	if _, ok := base.WithProject(cfg.DefaultProjectID).(TeammateKeyRepository); !ok {
		return nil, errors.New("teammate keys require the postgres repository")
	}
	teammateSigner, ok := signer.(jwtpkg.TeammateSigner)
	if !ok {
		return nil, errors.New("teammate keys require a signer with the teammate at+jwt profile")
	}
	metrics, err := newTeammateKeyMetrics(reg)
	if err != nil {
		return nil, err
	}
	if auditLog == nil {
		auditLog = audit.NewLogger(nil, "", zap.NewNop())
	}
	return &TeammateKeyService{credentials: credentials, base: base, signer: teammateSigner, issuer: cfg.JWTIssuer, audience: cfg.JWTAudience, defaultProject: cfg.DefaultProjectID, audit: auditLog, now: time.Now, metrics: metrics}, nil
}

func (s *TeammateKeyService) repo(project string) TeammateKeyRepository {
	return s.base.WithProject(project).(TeammateKeyRepository)
}

func (s *TeammateKeyService) requestProject(ctx context.Context) string {
	if scope := ProjectScopeFromContext(ctx); scope != nil && scope.ProjectID != "" {
		return scope.ProjectID
	}
	return s.defaultProject
}

func (s *TeammateKeyService) manager(ctx context.Context, presentedKey string) (*AdminProjectCredential, error) {
	publicID, secret, ok := strings.Cut(presentedKey, rawKeySeparator)
	if !ok || publicID == "" || secret == "" {
		return nil, errTeammateKeyManager
	}
	cred, reason, err := checkProjectCredential(ctx, s.credentials, CredentialKindTeammateKeyManager, publicID, secret)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, errTeammateKeyManager
	}
	if reason != "" {
		s.audit.Log(WithProjectScope(ctx, &ProjectScope{ProjectID: cred.ProjectID}), audit.EventTeammateKeyManagerRefused, audit.WithActor(credentialActor(cred)), audit.WithSuccess(false), audit.WithDetails(map[string]any{"reason": reason}))
		return nil, errTeammateKeyManager
	}
	return cred, nil
}

// RegisterTeammateKey stores the claim's key, or returns the key id the claim
// already has when the registration is the same.
func (s *TeammateKeyService) RegisterTeammateKey(ctx context.Context, presentedKey string, input TeammateKeyRegistration) (string, error) {
	id, result, err := s.register(ctx, presentedKey, input)
	s.metrics.registered.WithLabelValues(result).Inc()
	return id, err
}

func (s *TeammateKeyService) register(ctx context.Context, presentedKey string, input TeammateKeyRegistration) (string, string, error) {
	cred, err := s.manager(ctx, presentedKey)
	if err != nil {
		return "", registrationResult(err), err
	}
	if !validOAuthClientID(input.ClaimID) || !validOAuthClientID(input.TeammateID) || !validOAuthClientID(input.CompanyID) || !validOAuthClientID(input.WorkstationID) || !validTeammatePublicKey(input.Algorithm, input.PublicKey) {
		return "", "invalid", ErrInvalidArgument
	}
	ctx = WithProjectScope(ctx, &ProjectScope{ProjectID: cred.ProjectID})
	if err = s.activeTeammate(ctx, cred.ProjectID, input.TeammateID, ErrInvalidArgument); err != nil {
		return "", registrationResult(err), err
	}
	proposal := &TeammateKey{ID: rand.Text(), ClaimID: input.ClaimID, TeammateID: input.TeammateID, CompanyID: input.CompanyID, WorkstationID: input.WorkstationID, PublicKey: input.PublicKey, Algorithm: input.Algorithm, CreatedAtMs: s.now().UnixMilli()}
	stored, err := s.repo(cred.ProjectID).RegisterTeammateKey(ctx, proposal)
	if errors.Is(err, ErrAlreadyExists) {
		return "", "conflict", ErrTeammateKeyConflict
	}
	if err != nil {
		return "", "error", err
	}
	if stored.ID != proposal.ID {
		if stored.RevokedAtMs != 0 || stored.TeammateID != input.TeammateID || stored.CompanyID != input.CompanyID || stored.WorkstationID != input.WorkstationID || stored.Algorithm != input.Algorithm || !bytes.Equal(stored.PublicKey, input.PublicKey) {
			return "", "conflict", ErrTeammateKeyConflict
		}
		return stored.ID, "existing", nil
	}
	fingerprint := sha256.Sum256(stored.PublicKey)
	s.audit.Log(ctx, audit.EventTeammateKeyRegistered, audit.WithActor(credentialActor(cred)), audit.WithTarget(stored.TeammateID), audit.WithSuccess(true), audit.WithDetails(map[string]any{"key_id": stored.ID, "claim_id": stored.ClaimID, "workstation_id": stored.WorkstationID, "company_id": stored.CompanyID, "algorithm": stored.Algorithm, "key_fingerprint": hex.EncodeToString(fingerprint[:])}))
	return stored.ID, "created", nil
}

func registrationResult(err error) string {
	switch {
	case errors.Is(err, ErrPermissionDenied):
		return "denied"
	case errors.Is(err, ErrInvalidArgument):
		return "invalid"
	default:
		return "error"
	}
}

// RevokeTeammateKey revokes the claim's key; an unknown or already revoked
// claim is a success.
func (s *TeammateKeyService) RevokeTeammateKey(ctx context.Context, presentedKey, claimID, reason string) error {
	cred, err := s.manager(ctx, presentedKey)
	if err != nil {
		return err
	}
	if !validOAuthClientID(claimID) || !validTeammateKeyRevocationReason(reason) {
		return ErrInvalidArgument
	}
	ctx = WithProjectScope(ctx, &ProjectScope{ProjectID: cred.ProjectID})
	revoked, err := s.repo(cred.ProjectID).RevokeTeammateKey(ctx, claimID, reason, s.now().UnixMilli())
	if err != nil || !revoked {
		return err
	}
	s.metrics.revoked.Inc()
	s.audit.Log(ctx, audit.EventTeammateKeyRevoked, audit.WithActor(credentialActor(cred)), audit.WithSuccess(true), audit.WithDetails(map[string]any{"claim_id": claimID, "reason": reason}))
	return nil
}

// CreateChallenge issues a single-use challenge for an unrevoked key of the
// request's project.
func (s *TeammateKeyService) CreateChallenge(ctx context.Context, keyID string) (*TeammateKeyChallenge, error) {
	key, err := s.activeKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	project := s.requestProject(ctx)
	now := s.now().UnixMilli()
	challenge := &TeammateKeyChallenge{ID: rand.Text(), KeyID: key.ID, CreatedAtMs: now, ExpiresAtMs: now + AgentMachineChallengeLifetimeMs}
	message, err := json.Marshal(struct {
		Domain      string `json:"domain"`
		Issuer      string `json:"issuer"`
		Project     string `json:"project"`
		TeammateKey string `json:"teammate_key"`
		Operation   string `json:"operation"`
		Nonce       string `json:"nonce"`
		ExpiresAtMs int64  `json:"expires_at_ms"`
	}{teammateKeyChallengeDomain, s.issuer, project, key.ID, teammateKeyExchangeOperation, challenge.ID, challenge.ExpiresAtMs})
	if err != nil {
		return nil, err
	}
	challenge.Message = string(message)
	if err = s.repo(project).CreateTeammateKeyChallenge(ctx, challenge); err != nil {
		return nil, err
	}
	return challenge, nil
}

// Exchange verifies proof against the key's single-use challenge and issues a
// teammate access token naming the key's teammate, claim, workstation and
// company.
func (s *TeammateKeyService) Exchange(ctx context.Context, keyID string, proof AgentMachineProof) (*AgentOAuthTokens, error) {
	key, err := s.activeKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	project := s.requestProject(ctx)
	repo := s.repo(project)
	if !validOAuthClientID(proof.ChallengeID) {
		return nil, ErrUnauthenticated
	}
	challenge, err := repo.GetTeammateKeyChallenge(ctx, proof.ChallengeID)
	if err != nil {
		return nil, err
	}
	now := s.now()
	if challenge == nil || challenge.KeyID != key.ID || challenge.CreatedAtMs > now.UnixMilli() || challenge.ExpiresAtMs <= now.UnixMilli() || !verifyTeammateSignature(key, []byte(challenge.Message), proof.Signature) {
		return nil, ErrUnauthenticated
	}
	consumed, err := repo.ConsumeTeammateKeyChallenge(ctx, challenge.ID, key.ID, now.UnixMilli())
	if err != nil {
		return nil, err
	}
	if !consumed {
		return nil, ErrUnauthenticated
	}
	if err = s.activeTeammate(ctx, project, key.TeammateID, ErrUnauthenticated); err != nil {
		return nil, err
	}
	issuedAt := now.Unix()
	claims := jwtpkg.TeammateAccessClaims{Sub: key.TeammateID, Kind: UserKindAgent, Issuer: s.issuer, Project: project, Audience: []string{s.audience}, ClaimID: key.ClaimID, WorkstationID: key.WorkstationID, CompanyID: key.CompanyID, IssuedAt: issuedAt, ExpiresAt: issuedAt + config.TeammateAccessSeconds, JWTID: rand.Text()}
	token, err := s.signer.SignTeammateAccessToken(ctx, claims)
	if err != nil {
		return nil, err
	}
	s.audit.Log(ctx, audit.EventTeammateAccessIssued, audit.WithActor(key.TeammateID), audit.WithTarget(key.ID), audit.WithSuccess(true), audit.WithDetails(map[string]any{"claim_id": key.ClaimID, "workstation_id": key.WorkstationID, "company_id": key.CompanyID}))
	return &AgentOAuthTokens{AccessToken: token, ExpiresIn: config.TeammateAccessSeconds}, nil
}

func (s *TeammateKeyService) activeKey(ctx context.Context, keyID string) (*TeammateKey, error) {
	if !validOAuthClientID(keyID) {
		return nil, ErrUnauthenticated
	}
	key, err := s.repo(s.requestProject(ctx)).GetTeammateKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	if key == nil || key.RevokedAtMs != 0 {
		return nil, ErrUnauthenticated
	}
	return key, nil
}

func (s *TeammateKeyService) activeTeammate(ctx context.Context, project, teammateID string, refusal error) error {
	user, err := s.base.WithProject(project).GetUser(ctx, teammateID)
	if errors.Is(err, ErrNotFound) {
		return refusal
	}
	if err != nil {
		return err
	}
	if user == nil || !user.IsAgent() || !isActiveStatus(user.Status) {
		return refusal
	}
	return nil
}

func validTeammateKeyRevocationReason(reason string) bool {
	switch reason {
	case TeammateKeyReleased, TeammateKeyReclaimed, TeammateKeyRemoved, TeammateKeyDrifted:
		return true
	}
	return false
}

// validTeammatePublicKey accepts only the canonical DER SubjectPublicKeyInfo
// of the algorithm's key type, so one key has one stored form.
func validTeammatePublicKey(algorithm string, der []byte) bool {
	if len(der) == 0 || len(der) > maxTeammatePublicKeyBytes {
		return false
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return false
	}
	switch key := parsed.(type) {
	case ed25519.PublicKey:
		if algorithm != TeammateKeyEd25519 {
			return false
		}
	case *ecdsa.PublicKey:
		if algorithm != TeammateKeyECDSAP256 || key.Curve != elliptic.P256() {
			return false
		}
	default:
		return false
	}
	canonical, err := x509.MarshalPKIXPublicKey(parsed)
	return err == nil && bytes.Equal(canonical, der)
}

func verifyTeammateSignature(key *TeammateKey, message, signature []byte) bool {
	parsed, err := x509.ParsePKIXPublicKey(key.PublicKey)
	if err != nil {
		return false
	}
	switch public := parsed.(type) {
	case ed25519.PublicKey:
		return key.Algorithm == TeammateKeyEd25519 && len(signature) == ed25519.SignatureSize && ed25519.Verify(public, message, signature)
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(message)
		return key.Algorithm == TeammateKeyECDSAP256 && public.Curve == elliptic.P256() && ecdsa.VerifyASN1(public, digest[:], signature)
	}
	return false
}
