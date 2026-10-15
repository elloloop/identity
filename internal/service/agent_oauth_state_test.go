package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func oauthHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func agentOAuthFixture() (*AgentAuthorization, AgentOAuthAuthority, AgentOAuthMutation) {
	r := &AgentAuthorization{ID: "request", ClientID: "client", ClientRevision: 1, RedirectURI: "http://127.0.0.1:3123/callback", Resource: "https://files.example.test", Scopes: []string{"files:read"}, Challenge: strings.Repeat("a", 43), CreatedAtMs: 1000, ExpiresAtMs: 20000, Revision: 1, Decision: AgentAuthorizationPending}
	a := AgentOAuthAuthority{Owner: &User{ID: "human", Kind: UserKindPerson, Status: StatusActive}, Agent: &User{ID: "agent", Kind: UserKindAgent, Status: StatusActive, OwnerUserID: "human"}, HumanSession: &SessionRecord{SID: "human-sid", UserID: "human"}, Client: &OAuthClient{ID: "client", Kind: OAuthClientNativePublic, Revision: 1, Registration: OAuthClientRegistration{Name: "Example client", RedirectURIs: []string{r.RedirectURI}, Resources: []OAuthResourceBounds{{Resource: r.Resource, Scopes: r.Scopes}}, GrantTypes: []string{OAuthGrantAuthorizationCode, OAuthGrantRefreshToken}}}}
	m := AgentOAuthMutation{Operation: AgentOAuthApprove, AtMs: 2000, ExpectedRevision: 1, OwnerID: "human", AgentID: "agent", HumanSID: "human-sid", GrantExpiresAtMs: 50000, CodeHash: oauthHash("code"), CodeExpiresAtMs: 10000, AuthorityFingerprint: a.Fingerprint()}
	return r, a, m
}

func TestAgentOAuthConsentTerminalAndSnapshotBound(t *testing.T) {
	r, a, m := agentOAuthFixture()
	require.NoError(t, ValidateAgentAuthorization(r))
	approved, err := ApplyAgentOAuthMutation(r, a, nil, m)
	require.NoError(t, err)
	require.Equal(t, AgentAuthorizationApproved, approved.Decision)
	require.Equal(t, int64(2), approved.Revision)
	require.Equal(t, AgentAuthorizationPending, r.Decision)
	_, err = ApplyAgentOAuthMutation(approved, a, nil, m)
	require.ErrorIs(t, err, ErrAgentOAuthRevision)
	a.Owner.Email = "changed@example.test"
	_, err = ApplyAgentOAuthMutation(r, a, nil, m)
	require.ErrorIs(t, err, ErrPermissionDenied)
	m.Operation = AgentOAuthDeny
	m.AuthorityFingerprint = a.Fingerprint()
	denied, err := ApplyAgentOAuthMutation(r, a, nil, m)
	require.NoError(t, err)
	m.Operation = AgentOAuthApprove
	_, err = ApplyAgentOAuthMutation(denied, a, nil, m)
	require.ErrorIs(t, err, ErrAgentOAuthRevision)
}

func TestAgentOAuthCodeWrongProofDoesNotConsumeAndReplayRevokes(t *testing.T) {
	r, a, m := agentOAuthFixture()
	grant, err := ApplyAgentOAuthMutation(r, a, nil, m)
	require.NoError(t, err)
	redeem := AgentOAuthMutation{Operation: AgentOAuthRedeem, AtMs: 3000, AuthorityFingerprint: a.Fingerprint(), CodeHash: oauthHash("wrong"), SessionID: "delegated-sid", NextRefreshHash: oauthHash("refresh-one"), RefreshExpiresAtMs: 40000}
	_, err = ApplyAgentOAuthMutation(grant, a, nil, redeem)
	require.ErrorIs(t, err, ErrAgentOAuthGrant)
	require.Zero(t, grant.CodeUsedAtMs)
	redeem.CodeHash = m.CodeHash
	issued, err := ApplyAgentOAuthMutation(grant, a, nil, redeem)
	require.NoError(t, err)
	_, err = ApplyAgentOAuthMutation(issued, a, nil, redeem)
	require.ErrorIs(t, err, ErrAgentOAuthGrant)
	refresh := &AgentOAuthRefresh{Hash: redeem.NextRefreshHash, AuthorizationID: grant.ID, ExpiresAtMs: 40000}
	rotate := AgentOAuthMutation{Operation: AgentOAuthRotate, AtMs: 4000, AuthorityFingerprint: a.Fingerprint(), RefreshHash: refresh.Hash, NextRefreshHash: oauthHash("refresh-two"), RefreshExpiresAtMs: 45000}
	rotated, err := ApplyAgentOAuthMutation(issued, a, refresh, rotate)
	require.NoError(t, err)
	refresh.ConsumedAtMs = rotate.AtMs
	revoked, err := ApplyAgentOAuthMutation(rotated, a, refresh, rotate)
	require.ErrorIs(t, err, ErrAgentOAuthGrant)
	require.NotZero(t, revoked.RevokedAtMs)
	_, err = ApplyAgentOAuthMutation(revoked, a, nil, AgentOAuthMutation{Operation: AgentOAuthValidate, AtMs: 5000, AuthorityFingerprint: a.Fingerprint()})
	require.ErrorIs(t, err, ErrAgentOAuthGrant)
}

func TestAgentOAuthAuthorityAndLifetimeRefusals(t *testing.T) {
	cases := []struct {
		name  string
		apply func(*AgentAuthorization, *AgentOAuthAuthority)
	}{
		{"owner inactive", func(_ *AgentAuthorization, a *AgentOAuthAuthority) { a.Owner.Status = StatusDeactivated }},
		{"owner anonymous", func(_ *AgentAuthorization, a *AgentOAuthAuthority) { a.Owner.IsAnonymous = true }},
		{"owner merged", func(_ *AgentAuthorization, a *AgentOAuthAuthority) { a.Owner.MergedIntoUserID = "other" }},
		{"wrong owner", func(_ *AgentAuthorization, a *AgentOAuthAuthority) { a.Agent.OwnerUserID = "other" }},
		{"agent inactive", func(_ *AgentAuthorization, a *AgentOAuthAuthority) { a.Agent.Status = StatusDeactivated }},
		{"sid revoked", func(_ *AgentAuthorization, a *AgentOAuthAuthority) { a.HumanSession.RevokedAtMs = 2500 }},
		{"client revision", func(_ *AgentAuthorization, a *AgentOAuthAuthority) { a.Client.Revision++ }},
		{"client disabled", func(_ *AgentAuthorization, a *AgentOAuthAuthority) { a.Client.Registration.Disabled = true }},
		{"expiry", func(r *AgentAuthorization, _ *AgentOAuthAuthority) { r.GrantExpiresAtMs = 3000 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, a, m := agentOAuthFixture()
			r, err := ApplyAgentOAuthMutation(r, a, nil, m)
			require.NoError(t, err)
			tc.apply(r, &a)
			_, err = ApplyAgentOAuthMutation(r, a, nil, AgentOAuthMutation{Operation: AgentOAuthValidate, AtMs: 3000, AuthorityFingerprint: a.Fingerprint()})
			require.ErrorIs(t, err, ErrAgentOAuthGrant)
		})
	}
}

func TestAgentOAuthAuthorityLost(t *testing.T) {
	before := &User{ID: "person", Kind: UserKindPerson, Status: StatusActive}
	require.False(t, AgentOAuthAuthorityLost(nil, before))
	require.True(t, AgentOAuthAuthorityLost(before, nil))
	next := *before
	next.Name = "New display"
	next.PendingOwnerUserID = "pending"
	require.False(t, AgentOAuthAuthorityLost(before, &next))
	changes := []func(*User){func(u *User) { u.Status = StatusDeactivated }, func(u *User) { u.OwnerUserID = "other" }, func(u *User) { u.Kind = UserKindAgent }, func(u *User) { u.IsAnonymous = true }, func(u *User) { u.MergedIntoUserID = "other" }, func(u *User) { u.Email = "x@example.test" }, func(u *User) { u.EmailVerified = true }, func(u *User) { u.IDVVerified = true }, func(u *User) { u.DateOfBirthMs = 1 }, func(u *User) { u.Market = "IN" }, func(u *User) { u.Role = RoleAdmin }}
	for _, change := range changes {
		next := *before
		change(&next)
		require.True(t, AgentOAuthAuthorityLost(before, &next))
	}
}

func TestAgentOAuthCloneAndChallengeValidation(t *testing.T) {
	var empty *AgentAuthorization
	require.Nil(t, empty.Clone())
	r, _, _ := agentOAuthFixture()
	clone := r.Clone()
	clone.Scopes[0] = "changed"
	require.Equal(t, "files:read", r.Scopes[0])
	require.True(t, ValidS256Challenge(strings.Repeat("a", 43)))
	require.False(t, ValidS256Challenge(strings.Repeat("a", 42)))
	require.False(t, ValidS256Challenge(strings.Repeat("a", 42)+"+"))
	clone = r.Clone()
	clone.OwnerID = "prebound"
	require.ErrorIs(t, ValidateAgentAuthorization(clone), ErrInvalidArgument)
}

func TestAgentOAuthGrantExpiryHonorsOriginalHumanPolicy(t *testing.T) {
	auth, _, _ := newAuthSvcWithMailer(t)
	auth.cfg.AgentOAuthConsentSeconds = 86400
	auth.cfg.RefreshExpirySeconds = 86400
	auth.WithLoginGovernance(withSessionTimeouts(60, 3600))
	ctx := withProject("proj-1")
	now := auth.nowMs()
	oauth := &AgentOAuthService{auth: auth}
	owner := &User{ID: "owner", Email: "alice@acme.com"}
	session := &SessionRecord{SID: "human-sid", UserID: owner.ID, CreatedAtMs: now - 10000}
	expiry, err := oauth.grantExpiry(ctx, owner, session)
	require.NoError(t, err)
	require.Equal(t, session.CreatedAtMs+60000, expiry)
	auth.WithLoginGovernance(withSessionTimeouts(0, 30))
	expiry, err = oauth.grantExpiry(ctx, owner, session)
	require.NoError(t, err)
	require.Equal(t, session.CreatedAtMs+30000, expiry)
}

func TestAgentOAuthPolicyLookupFailureIsNotAbsentPolicy(t *testing.T) {
	for _, stage := range []string{"domain", "tenant", "policy"} {
		t.Run(stage, func(t *testing.T) {
			auth, _, _ := newAuthSvcWithMailer(t)
			governance := withSessionTimeouts(60, 3600)
			unavailable := errors.New("offline test governance unavailable")
			switch stage {
			case "domain":
				governance.Domains.(*lpDomainStore).err = unavailable
			case "tenant":
				governance.Tenants.(*lpTenantStore).err = unavailable
			case "policy":
				governance.Policies.(*fakePolicyStore).err = unavailable
			}
			auth.WithLoginGovernance(governance)
			oauth := &AgentOAuthService{auth: auth}
			_, err := oauth.grantExpiry(withProject("proj-1"), &User{Email: "alice@acme.com"}, &SessionRecord{CreatedAtMs: auth.nowMs()})
			require.ErrorIs(t, err, unavailable)
			_, policy := auth.resolveLoginPolicy(withProject("proj-1"), "alice@acme.com")
			require.Nil(t, policy, "ordinary human login retains its documented project default")
		})
	}
}
