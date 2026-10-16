package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
	jwtpkg "github.com/elloloop/identity/pkg/jwt"
)

const (
	maxAgentOAuthStateBytes    = 1024
	MaxAgentOAuthListLimit     = 100
	defaultAgentOAuthListLimit = 50
	agentOAuthChoicePage       = 50
	minPKCEVerifierBytes       = 43
	maxPKCEVerifierBytes       = 128
)

var (
	ErrAgentOAuthReauthenticationRequired = errors.New("reauthentication_required: sign in again to manage delegated access")
	ErrAgentOAuthDisabled                 = errors.New("delegated OAuth is disabled")
)

type (
	AgentOAuthHuman struct {
		UserID   string
		SID      string
		AuthTime int64
	}
	AgentOAuthStart struct {
		ClientID    string
		RedirectURI string
		Resource    string
		Scopes      []string
		Challenge   string
		State       string
	}
	AgentOAuthConsent struct {
		Request          *AgentAuthorization
		ClientName       string
		Agents           []*User
		NextAgentOffset  int32
		GrantExpiresAtMs int64
	}
	AgentOAuthTokens struct {
		AccessToken  string
		RefreshToken string
		ExpiresIn    uint64
		Scope        string
	}
	AgentOAuthIntrospection struct {
		Active    bool                   `json:"active"`
		Subject   string                 `json:"sub,omitempty"`
		Kind      string                 `json:"kind,omitempty"`
		Actor     *jwtpkg.DelegatedActor `json:"act,omitempty"`
		Issuer    string                 `json:"iss,omitempty"`
		Project   string                 `json:"project,omitempty"`
		Audience  []string               `json:"aud,omitempty"`
		ClientID  string                 `json:"client_id,omitempty"`
		Scope     string                 `json:"scope,omitempty"`
		GrantID   string                 `json:"grant_id,omitempty"`
		SID       string                 `json:"sid,omitempty"`
		IssuedAt  int64                  `json:"iat,omitempty"`
		ExpiresAt int64                  `json:"exp,omitempty"`
		IsMinor   bool                   `json:"is_minor,omitempty"`
	}
)

type AgentOAuthService struct {
	auth      *AuthService
	base      Repository
	resources []config.AgentOAuthResourceCredential
	signer    jwtpkg.DelegatedSigner
}

func NewAgentOAuthService(auth *AuthService, repo Repository) (*AgentOAuthService, error) {
	if auth == nil || auth.cfg == nil || !auth.cfg.AgentOAuthEnabled {
		return nil, ErrAgentOAuthDisabled
	}
	if err := auth.cfg.ValidateAgentOAuth(); err != nil {
		return nil, err
	}
	if _, ok := repo.(AgentOAuthRepository); !ok {
		return nil, errors.New("delegated OAuth requires a supported durable repository")
	}
	signer, ok := auth.signer.(jwtpkg.DelegatedSigner)
	if !ok {
		return nil, errors.New("delegated OAuth requires a signer with the at+jwt profile")
	}
	resources, err := auth.cfg.AgentOAuthCredentials()
	if err != nil {
		return nil, err
	}
	return &AgentOAuthService{auth: auth, base: repo, resources: resources, signer: signer}, nil
}

func (s *AgentOAuthService) repo(ctx context.Context) AgentOAuthRepository {
	return s.base.WithProject(s.auth.projectID(ctx)).(AgentOAuthRepository)
}

func agentOAuthHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (s *AgentOAuthService) resourceConfigured(ctx context.Context, resource string) bool {
	for _, r := range s.resources {
		if r.ProjectID == s.auth.projectID(ctx) && r.Resource == resource {
			return true
		}
	}
	return false
}

func (s *AgentOAuthService) AuthenticateResource(ctx context.Context, id, secret string) (string, error) {
	digest := sha256.Sum256([]byte(secret))
	var expected [sha256.Size]byte
	resource := ""
	for _, r := range s.resources {
		if r.ID == id && r.ProjectID == s.auth.projectID(ctx) {
			encoded, _ := hex.DecodeString(r.SecretSHA256)
			copy(expected[:], encoded)
			resource = r.Resource
			break
		}
	}
	if subtle.ConstantTimeCompare(digest[:], expected[:]) != 1 || resource == "" {
		return "", ErrUnauthenticated
	}
	return resource, nil
}

func (s *AgentOAuthService) Start(ctx context.Context, input AgentOAuthStart) (*AgentAuthorization, error) {
	if slices.Contains(input.Scopes, "openid") || input.State == "" || len(input.State) > maxAgentOAuthStateBytes || !ValidS256Challenge(input.Challenge) || !s.resourceConfigured(ctx, input.Resource) {
		return nil, ErrInvalidArgument
	}
	client, err := s.auth.repo(ctx).GetOAuthClient(ctx, input.ClientID)
	if err != nil {
		return nil, err
	}
	if err = client.ValidateOAuthRequest(input.RedirectURI, input.Resource, input.Scopes, OAuthGrantAuthorizationCode); err != nil {
		return nil, err
	}
	product := ""
	for _, bound := range client.Registration.Resources {
		if bound.Resource == input.Resource {
			product = bound.Product
			break
		}
	}
	if product == "" {
		return nil, ErrPermissionDenied
	}
	now := s.auth.nowMs()
	request := &AgentAuthorization{ID: rand.Text(), ClientID: client.ID, ClientRevision: client.Revision, RedirectURI: input.RedirectURI, State: input.State, Resource: input.Resource, Product: product, Scopes: slices.Clone(input.Scopes), Challenge: input.Challenge, CreatedAtMs: now, ExpiresAtMs: now + config.AgentOAuthRequestLifetime.Milliseconds(), Decision: AgentAuthorizationPending, Revision: 1}
	if err = s.repo(ctx).CreateAgentAuthorization(ctx, request); err != nil {
		return nil, err
	}
	return request, nil
}

func (s *AgentOAuthService) human(ctx context.Context, human AgentOAuthHuman, recent bool) (*User, error) {
	if human.UserID == "" || human.SID == "" {
		return nil, ErrAgentOAuthReauthenticationRequired
	}
	if recent {
		age := s.auth.nowMs()/1000 - human.AuthTime
		if human.AuthTime <= 0 || age < -int64(authTimeClockSkew.Seconds()) || age > int64(config.AgentOAuthRecentSignIn.Seconds()) {
			return nil, ErrAgentOAuthReauthenticationRequired
		}
	}
	user, err := s.base.WithProject(s.auth.projectID(ctx)).GetUser(ctx, human.UserID)
	if err != nil {
		return nil, err
	}
	if !isEligibleAgentOwner(user) {
		return nil, ErrPermissionDenied
	}
	session, err := s.base.WithProject(s.auth.projectID(ctx)).GetSessionBySid(ctx, human.SID)
	if err != nil {
		return nil, err
	}
	if session == nil || session.UserID != human.UserID || session.RevokedAtMs != 0 {
		return nil, ErrAgentOAuthReauthenticationRequired
	}
	return user, nil
}

func (s *AgentOAuthService) admitOwner(ctx context.Context, user *User, product string) error {
	if !isEligibleAgentOwner(user) {
		return ErrPermissionDenied
	}
	if s.auth.needsEmailVerification(user) {
		return ErrEmailVerificationRequired
	}
	if s.auth.cfg.IDVRequired && !user.IDVVerified {
		return ErrIDVRequired
	}
	if s.auth.cfg.AgeGateRequireDOB && user.DateOfBirthMs == 0 {
		return ErrDOBRequired
	}
	ctx = WithProduct(ctx, product)
	if err := s.auth.enforceAccountAccessLogin(ctx, user); err != nil {
		return err
	}
	copy := *user
	s.auth.stampAgeBand(ctx, &copy)
	return s.auth.enforceProductAgeGate(ctx, &copy)
}

func (s *AgentOAuthService) grantExpiry(ctx context.Context, user *User, session *SessionRecord) (int64, error) {
	expiry := min(s.auth.nowMs()+int64(s.auth.cfg.AgentOAuthConsentSeconds)*time.Second.Milliseconds(), session.CreatedAtMs+int64(s.auth.cfg.RefreshExpirySeconds)*time.Second.Milliseconds())
	_, policy, err := s.auth.governance.resolvePolicy(ctx, s.auth.projectID(ctx), s.auth.logger, user.Email)
	if err != nil {
		return 0, err
	}
	if policy != nil {
		if policy.SessionAbsoluteTimeoutSeconds > 0 {
			expiry = min(expiry, session.CreatedAtMs+policy.SessionAbsoluteTimeoutSeconds*time.Second.Milliseconds())
		}
		// A delegated grant cannot keep its source human session active. Its
		// idle-policy bound remains anchored to the original session start.
		if policy.SessionIdleTimeoutSeconds > 0 {
			expiry = min(expiry, session.CreatedAtMs+policy.SessionIdleTimeoutSeconds*time.Second.Milliseconds())
		}
	}
	return expiry, nil
}

func (s *AgentOAuthService) GetConsent(ctx context.Context, human AgentOAuthHuman, id string, agentOffset int) (*AgentOAuthConsent, error) {
	owner, err := s.human(ctx, human, true)
	if err != nil {
		return nil, err
	}
	if !validOAuthClientID(id) || agentOffset < 0 || agentOffset > math.MaxInt32-agentOAuthChoicePage {
		return nil, ErrInvalidArgument
	}
	request, err := s.repo(ctx).GetAgentAuthorization(ctx, id)
	if err != nil {
		return nil, err
	}
	if request == nil || request.Decision != AgentAuthorizationPending || request.ExpiresAtMs <= s.auth.nowMs() || request.RevokedAtMs != 0 {
		return nil, ErrAgentOAuthGrant
	}
	if err = s.admitOwner(ctx, owner, request.Product); err != nil {
		return nil, err
	}
	client, err := s.auth.repo(ctx).GetOAuthClient(ctx, request.ClientID)
	if err != nil {
		return nil, err
	}
	if client == nil || client.Revision != request.ClientRevision || client.ValidateOAuthRequest(request.RedirectURI, request.Resource, request.Scopes, OAuthGrantAuthorizationCode) != nil {
		return nil, ErrAgentOAuthGrant
	}
	choices, err := s.auth.repo(ctx).ListUsers(ctx, UserListFilter{IncludeAgents: true, OwnerUserID: owner.ID, Offset: agentOffset, Limit: agentOAuthChoicePage})
	if err != nil {
		return nil, err
	}
	out := &AgentOAuthConsent{Request: request, ClientName: client.Registration.Name, NextAgentOffset: -1}
	for _, agent := range choices {
		if agent.IsAgent() && isActiveStatus(agent.Status) {
			out.Agents = append(out.Agents, agent)
		}
	}
	if len(choices) == agentOAuthChoicePage {
		nextOffset := int64(agentOffset) + int64(len(choices))
		if nextOffset > math.MaxInt32 || nextOffset < 0 {
			return nil, ErrInvalidArgument
		}
		out.NextAgentOffset = int32(nextOffset)
	}
	session, err := s.base.WithProject(s.auth.projectID(ctx)).GetSessionBySid(ctx, human.SID)
	if err != nil {
		return nil, err
	}
	if session == nil || session.RevokedAtMs != 0 {
		return nil, ErrAgentOAuthReauthenticationRequired
	}
	out.GrantExpiresAtMs, err = s.grantExpiry(ctx, owner, session)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *AgentOAuthService) Decide(ctx context.Context, human AgentOAuthHuman, id string, revision int64, approve bool, agentID string) (string, error) {
	if !validOAuthClientID(id) || revision < 1 || (approve && !validOAuthClientID(agentID)) {
		return "", ErrInvalidArgument
	}
	if _, err := s.human(ctx, human, true); err != nil {
		return "", err
	}
	request, err := s.repo(ctx).GetAgentAuthorization(ctx, id)
	if err != nil {
		return "", err
	}
	if request == nil {
		return "", ErrAgentOAuthGrant
	}
	if !approve {
		agentID = ""
	}
	authority, err := s.repo(ctx).AgentOAuthAuthority(ctx, human.UserID, agentID, human.SID, request.ClientID)
	if err != nil {
		return "", err
	}
	op := AgentOAuthDeny
	code := ""
	now := s.auth.nowMs()
	m := AgentOAuthMutation{Operation: op, AtMs: now, ExpectedRevision: revision, OwnerID: human.UserID, AgentID: agentID, HumanSID: human.SID, AuthorityFingerprint: authority.Fingerprint()}
	if approve {
		candidate := request.Clone()
		candidate.OwnerID = human.UserID
		candidate.AgentID = agentID
		candidate.HumanSID = human.SID
		if !authority.Valid(candidate) {
			return "", ErrPermissionDenied
		}
		if err = s.admitOwner(ctx, authority.Owner, request.Product); err != nil {
			return "", err
		}
		code = rand.Text()
		m.Operation = AgentOAuthApprove
		m.CodeHash = agentOAuthHash(code)
		m.CodeExpiresAtMs = min(request.ExpiresAtMs, now+config.AgentOAuthCodeLifetime.Milliseconds())
		m.GrantExpiresAtMs, err = s.grantExpiry(ctx, authority.Owner, authority.HumanSession)
		if err != nil {
			return "", err
		}
	}
	decided, err := s.repo(ctx).MutateAgentAuthorization(ctx, id, m)
	if err != nil {
		return "", err
	}
	s.auth.audit.Log(ctx, audit.EventAgentOAuthConsent, audit.WithActor(human.UserID), audit.WithTarget(decided.ID), audit.WithSuccess(true), audit.WithDetails(map[string]any{"approved": approve, "agent_id": decided.AgentID, "client_id": decided.ClientID}))
	redirect, err := url.Parse(decided.RedirectURI)
	if err != nil {
		return "", err
	}
	params := redirect.Query()
	params.Set("state", decided.State)
	params.Set("iss", s.auth.cfg.JWTIssuer)
	if approve {
		params.Set("code", code)
	} else {
		params.Set("error", "access_denied")
	}
	redirect.RawQuery = params.Encode()
	return redirect.String(), nil
}

func ValidPKCEVerifier(verifier string) bool {
	if len(verifier) < minPKCEVerifierBytes || len(verifier) > maxPKCEVerifierBytes {
		return false
	}
	for _, r := range verifier {
		if r < 'a' || r > 'z' {
			if r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-._~", r) {
				continue
			}
			return false
		}
	}
	return true
}

func VerifyAgentPKCE(verifier, challenge string) bool {
	if !ValidPKCEVerifier(verifier) || !ValidS256Challenge(challenge) {
		return false
	}
	digest := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(digest[:])
	return subtle.ConstantTimeCompare([]byte(challenge), []byte(expected)) == 1
}

func (s *AgentOAuthService) admittedAuthority(ctx context.Context, request *AgentAuthorization) (AgentOAuthAuthority, int64, error) {
	if request == nil {
		return AgentOAuthAuthority{}, 0, ErrAgentOAuthGrant
	}
	a, err := s.repo(ctx).AgentOAuthAuthority(ctx, request.OwnerID, request.AgentID, request.HumanSID, request.ClientID)
	if err != nil {
		return a, 0, err
	}
	if request.RevokedAtMs != 0 {
		return a, 0, ErrAgentOAuthGrant
	}
	if !a.Valid(request) || request.GrantExpiresAtMs <= s.auth.nowMs() {
		return a, 0, s.invalidate(ctx, request)
	}
	if err = s.admitOwner(ctx, a.Owner, request.Product); err != nil {
		if isAgentOAuthAdmissionRefusal(err) {
			return a, 0, s.invalidate(ctx, request)
		}
		return a, 0, err
	}
	currentExpiry, err := s.grantExpiry(ctx, a.Owner, a.HumanSession)
	if err != nil {
		return a, 0, err
	}
	if !s.resourceConfigured(ctx, request.Resource) || currentExpiry <= s.auth.nowMs() {
		return a, 0, s.invalidate(ctx, request)
	}
	return a, currentExpiry, nil
}

func isAgentOAuthAdmissionRefusal(err error) bool {
	return errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrAccountNotActive) || errors.Is(err, ErrEmailVerificationRequired) || errors.Is(err, ErrIDVRequired) || errors.Is(err, ErrDOBRequired) || errors.Is(err, ErrAccessNotAllowed) || errors.Is(err, ErrProductAgeRestricted)
}

func (s *AgentOAuthService) invalidate(ctx context.Context, request *AgentAuthorization) error {
	if _, err := s.repo(ctx).MutateAgentAuthorization(ctx, request.ID, AgentOAuthMutation{Operation: AgentOAuthRevoke, OwnerID: request.OwnerID, AtMs: s.auth.nowMs()}); err != nil {
		return err
	}
	s.auditRevocation(ctx, request.OwnerID, request.ID)
	return ErrAgentOAuthGrant
}

func (s *AgentOAuthService) auditRevocation(ctx context.Context, owner, id string) {
	s.auth.audit.Log(ctx, audit.EventAgentOAuthRevoked, audit.WithActor(owner), audit.WithTarget(id), audit.WithSuccess(true))
}

func (s *AgentOAuthService) issue(ctx context.Context, request *AgentAuthorization, operation, presentedHash string) (*AgentOAuthTokens, error) {
	authority, currentExpiry, err := s.admittedAuthority(ctx, request)
	if err != nil {
		return nil, err
	}
	now := s.auth.nowMs()
	expires := min(request.GrantExpiresAtMs, currentExpiry, now+int64(s.auth.cfg.AgentOAuthAccessSeconds)*time.Second.Milliseconds())
	if expires/time.Second.Milliseconds() <= now/time.Second.Milliseconds() {
		return nil, ErrAgentOAuthGrant
	}
	sid := request.SessionID
	if operation == AgentOAuthRedeem {
		sid = rand.Text()
	}
	owner := *authority.Owner
	s.auth.stampAgeBand(WithProduct(ctx, request.Product), &owner)
	claims := jwtpkg.DelegatedAccessClaims{Sub: request.AgentID, Kind: UserKindAgent, Actor: jwtpkg.DelegatedActor{Sub: request.OwnerID}, Issuer: s.auth.cfg.JWTIssuer, Project: s.auth.projectID(ctx), Audience: []string{request.Resource}, ClientID: request.ClientID, Scope: strings.Join(request.Scopes, " "), GrantID: request.ID, SID: sid, IssuedAt: now / time.Second.Milliseconds(), ExpiresAt: expires / time.Second.Milliseconds(), JWTID: rand.Text(), IsMinor: owner.IsMinor}
	token, err := s.signer.SignDelegatedAccessToken(ctx, claims)
	if err != nil {
		return nil, err
	}
	m := AgentOAuthMutation{Operation: operation, AtMs: now, AuthorityFingerprint: authority.Fingerprint(), SessionID: sid}
	refresh := ""
	if slices.Contains(authority.Client.Registration.GrantTypes, OAuthGrantRefreshToken) {
		refresh = rand.Text()
		m.NextRefreshHash = agentOAuthHash(refresh)
		m.RefreshExpiresAtMs = min(request.GrantExpiresAtMs, currentExpiry, now+int64(s.auth.cfg.AgentOAuthRefreshIdleSeconds)*time.Second.Milliseconds())
	}
	if operation == AgentOAuthRedeem {
		m.CodeHash = presentedHash
	} else {
		m.RefreshHash = presentedHash
	}
	if _, err = s.repo(ctx).MutateAgentAuthorization(ctx, request.ID, m); err != nil {
		return nil, err
	}
	s.auth.audit.Log(ctx, audit.EventAgentOAuthIssued, audit.WithActor(request.OwnerID), audit.WithTarget(request.ID), audit.WithSuccess(true), audit.WithDetails(map[string]any{"agent_id": request.AgentID, "client_id": request.ClientID, "operation": operation}))
	lifetime := claims.ExpiresAt - claims.IssuedAt
	if lifetime <= 0 {
		return nil, ErrAgentOAuthGrant
	}
	return &AgentOAuthTokens{AccessToken: token, RefreshToken: refresh, ExpiresIn: uint64(lifetime), Scope: claims.Scope}, nil
}

func (s *AgentOAuthService) Redeem(ctx context.Context, client, redirect, resource, code, verifier string) (*AgentOAuthTokens, error) {
	request, err := s.repo(ctx).FindAgentAuthorizationByCode(ctx, agentOAuthHash(code))
	if err != nil {
		return nil, err
	}
	if request == nil || request.CodeUsedAtMs != 0 || request.CodeExpiresAtMs <= s.auth.nowMs() || request.ClientID != client || request.RedirectURI != redirect || request.Resource != resource || !VerifyAgentPKCE(verifier, request.Challenge) {
		return nil, ErrAgentOAuthGrant
	}
	return s.issue(ctx, request, AgentOAuthRedeem, agentOAuthHash(code))
}

func (s *AgentOAuthService) Refresh(ctx context.Context, client, resource, raw, scope string) (*AgentOAuthTokens, error) {
	request, err := s.repo(ctx).FindAgentAuthorizationByRefresh(ctx, agentOAuthHash(raw))
	if err != nil {
		return nil, err
	}
	if request == nil || request.ClientID != client || request.Resource != resource || (scope != "" && scope != strings.Join(request.Scopes, " ")) {
		return nil, ErrAgentOAuthGrant
	}
	return s.issue(ctx, request, AgentOAuthRotate, agentOAuthHash(raw))
}

func (s *AgentOAuthService) Introspect(ctx context.Context, resource, raw string) (*AgentOAuthIntrospection, error) {
	inactive := &AgentOAuthIntrospection{}
	claims, valid := s.verifiedDelegatedClaims(ctx, resource, raw)
	if !valid {
		return inactive, nil
	}
	request, err := s.repo(ctx).GetAgentAuthorization(ctx, claims.GrantID)
	if err != nil {
		return nil, err
	}
	if request == nil || request.AgentID != claims.Sub || request.OwnerID != claims.Actor.Sub || request.ClientID != claims.ClientID || request.Resource != resource || request.SessionID != claims.SID || strings.Join(request.Scopes, " ") != claims.Scope || request.GrantExpiresAtMs/time.Second.Milliseconds() < claims.ExpiresAt {
		return inactive, nil
	}
	authority, _, err := s.admittedAuthority(ctx, request)
	if err != nil {
		if errors.Is(err, ErrAgentOAuthGrant) || errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrAccountNotActive) || errors.Is(err, ErrEmailVerificationRequired) || errors.Is(err, ErrIDVRequired) || errors.Is(err, ErrDOBRequired) || errors.Is(err, ErrAccessNotAllowed) || errors.Is(err, ErrProductAgeRestricted) {
			return inactive, nil
		}
		return nil, err
	}
	if _, err = s.repo(ctx).MutateAgentAuthorization(ctx, request.ID, AgentOAuthMutation{Operation: AgentOAuthValidate, AtMs: s.auth.nowMs(), AuthorityFingerprint: authority.Fingerprint()}); err != nil {
		if errors.Is(err, ErrAgentOAuthGrant) {
			return inactive, nil
		}
		return nil, err
	}
	owner := *authority.Owner
	s.auth.stampAgeBand(WithProduct(ctx, request.Product), &owner)
	actor := claims.Actor
	return &AgentOAuthIntrospection{Active: true, Subject: claims.Sub, Kind: claims.Kind, Actor: &actor, Issuer: claims.Issuer, Project: claims.Project, Audience: claims.Audience, ClientID: claims.ClientID, Scope: claims.Scope, GrantID: claims.GrantID, SID: claims.SID, IssuedAt: claims.IssuedAt, ExpiresAt: claims.ExpiresAt, IsMinor: owner.IsMinor}, nil
}

func (s *AgentOAuthService) List(ctx context.Context, human AgentOAuthHuman, after string, limit int) ([]*AgentAuthorization, error) {
	if _, err := s.human(ctx, human, false); err != nil {
		return nil, err
	}
	if limit == 0 {
		limit = defaultAgentOAuthListLimit
	}
	if limit < 1 || limit > MaxAgentOAuthListLimit || (after != "" && !validOAuthClientID(after)) {
		return nil, ErrInvalidArgument
	}
	return s.repo(ctx).ListAgentAuthorizations(ctx, human.UserID, after, limit)
}

func (s *AgentOAuthService) Revoke(ctx context.Context, human AgentOAuthHuman, id string) error {
	if !validOAuthClientID(id) {
		return ErrInvalidArgument
	}
	if _, err := s.human(ctx, human, false); err != nil {
		return err
	}
	_, err := s.repo(ctx).MutateAgentAuthorization(ctx, id, AgentOAuthMutation{Operation: AgentOAuthRevoke, OwnerID: human.UserID, AtMs: s.auth.nowMs()})
	if err == nil {
		s.auditRevocation(ctx, human.UserID, id)
	}
	return err
}

func (s *AgentOAuthService) RevokeToken(ctx context.Context, client, raw string) error {
	request, err := s.repo(ctx).FindAgentAuthorizationByRefresh(ctx, agentOAuthHash(raw))
	if err != nil {
		return err
	}
	if request == nil {
		return nil
	}
	if request.ClientID != client {
		return nil
	}
	_, err = s.repo(ctx).MutateAgentAuthorization(ctx, request.ID, AgentOAuthMutation{Operation: AgentOAuthRevoke, OwnerID: request.OwnerID, AtMs: s.auth.nowMs()})
	if err == nil {
		s.auditRevocation(ctx, request.OwnerID, request.ID)
	}
	return err
}

func (s *AuthService) OAuthProtocolClient(ctx context.Context, id string) (*OAuthClient, error) {
	if !s.cfg.AgentOAuthEnabled {
		return nil, ErrAgentOAuthDisabled
	}
	client, err := s.repo(ctx).GetOAuthClient(ctx, id)
	if err != nil {
		return nil, err
	}
	if client == nil || client.Kind != OAuthClientNativePublic || client.Registration.Disabled {
		return nil, ErrPermissionDenied
	}
	return client, nil
}

func (s *AgentOAuthService) verifiedDelegatedClaims(ctx context.Context, resource, raw string) (*jwtpkg.DelegatedAccessClaims, bool) {
	claims, err := jwtpkg.VerifyDelegatedAccessToken(raw, s.auth.signer, s.auth.cfg.JWTIssuer, s.auth.projectID(ctx), resource)
	return claims, err == nil
}
