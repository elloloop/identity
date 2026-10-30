package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
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
	errHireGrant            = fmt.Errorf("%w: the hire grant is missing, expired, used by another claim or for another hire", ErrPermissionDenied)
)

// TeammateKeyRegistration is one RegisterTeammateKey request. Algorithm is
// TeammateKeyECDSAP256 and PublicKey a DER SubjectPublicKeyInfo of a P-256
// key; GrantID is a hire grant for TeammateID, PlacementID and CompanyID.
type TeammateKeyRegistration struct {
	ClaimID       string
	TeammateID    string
	CompanyID     string
	WorkstationID string
	PublicKey     []byte
	Algorithm     string
	GrantID       string
	PlacementID   string
}

// TeammateKeyService lets a signed-in person grant a hire, a service holding
// a teammate_key_manager credential register a teammate key with that grant
// and revoke it, and a workstation exchange a challenge signed with the key
// for a teammate access token. The token's identity fields always come from
// the stored key, and its owner from the grant.
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
	revoked    *prometheus.CounterVec
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
		revoked: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "identity_teammate_keys_revoked_total",
			Help: "RevokeTeammateKey calls that set or brought forward when a key stops working, labelled by schedule: immediate, or a later deadline.",
		}, []string{"schedule"}),
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
	if !validOAuthClientID(input.ClaimID) || !validOAuthClientID(input.TeammateID) || !validOAuthClientID(input.CompanyID) || !validOAuthClientID(input.WorkstationID) || !validOAuthClientID(input.PlacementID) || !validTeammatePublicKey(input.Algorithm, input.PublicKey) {
		return "", "invalid", ErrInvalidArgument
	}
	ctx = WithProjectScope(ctx, &ProjectScope{ProjectID: cred.ProjectID})
	if !validOAuthClientID(input.GrantID) {
		return "", "grant_refused", s.refuseHireGrant(ctx, cred, input)
	}
	if err = s.activeTeammate(ctx, cred.ProjectID, input.TeammateID, ErrInvalidArgument); err != nil {
		return "", registrationResult(err), err
	}
	proposal := &TeammateKey{ID: rand.Text(), ClaimID: input.ClaimID, TeammateID: input.TeammateID, CompanyID: input.CompanyID, WorkstationID: input.WorkstationID, PublicKey: input.PublicKey, Algorithm: input.Algorithm, GrantID: input.GrantID, CreatedAtMs: s.now().UnixMilli()}
	stored, err := s.repo(cred.ProjectID).RegisterTeammateKey(ctx, proposal, input.PlacementID)
	switch {
	case errors.Is(err, ErrAlreadyExists):
		return "", "conflict", ErrTeammateKeyConflict
	case errors.Is(err, ErrHireGrantRefused):
		return "", "grant_refused", s.refuseHireGrant(ctx, cred, input)
	case err != nil:
		return "", "error", err
	}
	if stored.ID != proposal.ID {
		if stored.RevokedAtMs != 0 || stored.TeammateID != input.TeammateID || stored.CompanyID != input.CompanyID || stored.WorkstationID != input.WorkstationID || stored.Algorithm != input.Algorithm || stored.GrantID != input.GrantID || !bytes.Equal(stored.PublicKey, input.PublicKey) {
			return "", "conflict", ErrTeammateKeyConflict
		}
		return stored.ID, "existing", nil
	}
	fingerprint := sha256.Sum256(stored.PublicKey)
	s.audit.Log(ctx, audit.EventTeammateKeyRegistered, audit.WithActor(credentialActor(cred)), audit.WithTarget(stored.TeammateID), audit.WithSuccess(true), audit.WithDetails(map[string]any{"key_id": stored.ID, "claim_id": stored.ClaimID, "workstation_id": stored.WorkstationID, "company_id": stored.CompanyID, "algorithm": stored.Algorithm, "key_fingerprint": hex.EncodeToString(fingerprint[:]), "grant_id": stored.GrantID, "owner_user_id": stored.OwnerUserID}))
	return stored.ID, "created", nil
}

func (s *TeammateKeyService) refuseHireGrant(ctx context.Context, cred *AdminProjectCredential, input TeammateKeyRegistration) error {
	s.audit.Log(ctx, audit.EventHireGrantRefused, audit.WithActor(credentialActor(cred)), audit.WithTarget(input.TeammateID), audit.WithSuccess(false), audit.WithDetails(map[string]any{"claim_id": input.ClaimID, "placement_id": input.PlacementID, "company_id": input.CompanyID, "has_grant_id": input.GrantID != ""}))
	return errHireGrant
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

// RevokeTeammateKey makes the claim's key stop working at deadline, or now
// when deadline is zero or past, and returns when it stops working: zero for
// a claim with no key. A key that already stops sooner keeps its time.
func (s *TeammateKeyService) RevokeTeammateKey(ctx context.Context, presentedKey, claimID, reason string, deadline time.Time) (time.Time, error) {
	cred, err := s.manager(ctx, presentedKey)
	if err != nil {
		return time.Time{}, err
	}
	now := s.now()
	if !validOAuthClientID(claimID) || !validTeammateKeyRevocationReason(reason) || deadline.After(now.Add(MaxTeammateKeyDrain)) {
		return time.Time{}, ErrInvalidArgument
	}
	at, schedule := now, "immediate"
	if deadline.After(now) {
		at, schedule = deadline, "deadline"
	}
	ctx = WithProjectScope(ctx, &ProjectScope{ProjectID: cred.ProjectID})
	stopsAtMs, changed, err := s.repo(cred.ProjectID).RevokeTeammateKey(ctx, claimID, reason, at.UnixMilli(), now.UnixMilli())
	if err != nil {
		return time.Time{}, err
	}
	if stopsAtMs == 0 {
		return time.Time{}, nil
	}
	if changed {
		s.metrics.revoked.WithLabelValues(schedule).Inc()
		s.audit.Log(ctx, audit.EventTeammateKeyRevoked, audit.WithActor(credentialActor(cred)), audit.WithSuccess(true), audit.WithDetails(map[string]any{"claim_id": claimID, "reason": reason, "revoked_at_ms": stopsAtMs}))
	}
	return time.UnixMilli(stopsAtMs), nil
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
	if err = s.activeTeammate(ctx, project, key.TeammateID, ErrUnauthenticated); err != nil {
		return nil, err
	}
	if err = s.activeOwner(ctx, project, key.OwnerUserID); err != nil {
		return nil, err
	}
	consumed, stopsAtMs, err := repo.ConsumeTeammateKeyChallenge(ctx, challenge.ID, key.ID, now.UnixMilli())
	if err != nil {
		return nil, err
	}
	if !consumed {
		return nil, ErrUnauthenticated
	}
	issuedAt := now.Unix()
	expiresAt := issuedAt + config.TeammateAccessSeconds
	if stopsAtMs != 0 {
		expiresAt = min(expiresAt, stopsAtMs/1000)
	}
	lifetime := expiresAt - issuedAt
	if lifetime <= 0 {
		return nil, ErrUnauthenticated
	}
	claims := jwtpkg.TeammateAccessClaims{Sub: key.TeammateID, Kind: UserKindAgent, Actor: jwtpkg.DelegatedActor{Sub: key.OwnerUserID}, Issuer: s.issuer, Project: project, Audience: []string{s.audience}, ClaimID: key.ClaimID, WorkstationID: key.WorkstationID, CompanyID: key.CompanyID, IssuedAt: issuedAt, ExpiresAt: expiresAt, JWTID: rand.Text()}
	token, err := s.signer.SignTeammateAccessToken(ctx, claims)
	if err != nil {
		return nil, err
	}
	s.audit.Log(ctx, audit.EventTeammateAccessIssued, audit.WithActor(key.TeammateID), audit.WithTarget(key.ID), audit.WithSuccess(true), audit.WithDetails(map[string]any{"claim_id": key.ClaimID, "workstation_id": key.WorkstationID, "company_id": key.CompanyID, "owner_user_id": key.OwnerUserID}))
	return &AgentOAuthTokens{AccessToken: token, ExpiresIn: uint64(lifetime)}, nil
}

func (s *TeammateKeyService) activeKey(ctx context.Context, keyID string) (*TeammateKey, error) {
	if !validOAuthClientID(keyID) {
		return nil, ErrUnauthenticated
	}
	key, err := s.repo(s.requestProject(ctx)).GetTeammateKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	if key == nil || key.revokedBy(s.now().UnixMilli()) {
		return nil, ErrUnauthenticated
	}
	return key, nil
}

// activeOwner refuses a token whose owner may no longer stand behind one: an
// agent can never do more than the person who granted it.
func (s *TeammateKeyService) activeOwner(ctx context.Context, project, ownerID string) error {
	owner, err := s.base.WithProject(project).GetUser(ctx, ownerID)
	if errors.Is(err, ErrNotFound) {
		return ErrUnauthenticated
	}
	if err != nil {
		return err
	}
	if !isActivePerson(owner) {
		return ErrUnauthenticated
	}
	return nil
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
// of an ECDSA P-256 key, so one key has one stored form.
func validTeammatePublicKey(algorithm string, der []byte) bool {
	if algorithm != TeammateKeyECDSAP256 || len(der) == 0 || len(der) > maxTeammatePublicKeyBytes {
		return false
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return false
	}
	if key, ok := parsed.(*ecdsa.PublicKey); !ok || key.Curve != elliptic.P256() {
		return false
	}
	canonical, err := x509.MarshalPKIXPublicKey(parsed)
	return err == nil && bytes.Equal(canonical, der)
}

// verifyTeammateSignature accepts an ASN.1 DER ECDSA signature over the
// message's SHA-256 digest, by a key stored as ECDSA P-256.
func verifyTeammateSignature(key *TeammateKey, message, signature []byte) bool {
	if key.Algorithm != TeammateKeyECDSAP256 {
		return false
	}
	parsed, err := x509.ParsePKIXPublicKey(key.PublicKey)
	if err != nil {
		return false
	}
	public, ok := parsed.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		return false
	}
	digest := sha256.Sum256(message)
	return ecdsa.VerifyASN1(public, digest[:], signature)
}
