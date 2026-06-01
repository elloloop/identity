package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/oauth"
	"github.com/elloloop/identity/pkg/passkeys"
)

// newTestAuthServiceMulti builds an AuthService configured for
// mode=multi so the invitation-redemption path adds the redeemed user
// to the resolved tenant's organisation. The boot-time default repo is
// supplied; per-request tenant scope is injected via WithTenantScope in
// the test body.
func newTestAuthServiceMulti(t *testing.T, repo Repository) *AuthService {
	t.Helper()
	cfg := testConfig()
	cfg.IdentityMode = config.IdentityModeMulti
	kr := testKeyRing(t)
	passkeysSvc, _ := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   cfg.PasskeyRPID,
		RPName: cfg.PasskeyRPName,
		Origin: cfg.PasskeyOrigin,
	})
	return NewAuthServiceWithOAuth(
		repo, cfg, kr, passkeysSvc,
		audit.NewLogger(nil, "test", nil),
		testTotpKey(), testTotpRecoveryPepper(), email.NewLogOnly(zap.NewNop()), nil, zap.NewNop(),
		oauth.NewRegistry(),
	)
}

// seedOrg writes an Organization (slug == tenant id, decision log §2)
// directly into a fake repo so a redemption can locate it.
func seedOrg(repo *fakeRepo, slug string) *Organization {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	id := nextNodeID()
	o := &Organization{ID: id, Slug: slug, DisplayName: slug, CreatedAtMs: time.Now().UnixMilli()}
	repo.orgs[id] = o
	return o
}

func (r *fakeRepo) membershipFor(orgID, userID string) *OrganizationMembership {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.orgMembers {
		if m.OrganizationID == orgID && m.UserID == userID {
			cp := *m
			return &cp
		}
	}
	return nil
}

// TestAcceptInvitation_Multi_AddsMembershipToInviteTenant covers the
// slice-4 redemption: in mode=multi the redeemed user becomes an
// OrganizationMembership member of the tenant the invitation was issued
// for, with the role recorded on the invitation.
func TestAcceptInvitation_Multi_AddsMembershipToInviteTenant(t *testing.T) {
	const tenantA = "acmecorp"
	repoA := newFakeRepo()
	svc := newTestAuthServiceMulti(t, repoA)

	org := seedOrg(repoA, tenantA)
	u := seedUser(repoA, "bob@x.com", "", "invited")

	rawToken := "tok-multi-membership"
	seedInvitation(repoA, &InvitationRecord{
		TokenHash: hashInvitationToken(rawToken),
		Email:     "bob@x.com",
		UserID:    u.ID,
		Role:      "admin",
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
		CreatedAt: time.Now().UnixMilli(),
	})

	ctx := WithTenantScope(context.Background(), &TenantScope{TenantID: tenantA, Repo: repoA})
	result, err := svc.AcceptInvitation(ctx, rawToken, strongPW, "Bob", "", "")
	require.NoError(t, err)
	require.NotNil(t, result)

	m := repoA.membershipFor(org.ID, u.ID)
	require.NotNil(t, m, "redeemed user must be a member of the invite's tenant org")
	assert.Equal(t, "admin", m.Role, "membership role comes from the invitation")

	// The user is visible as a member under tenant A's scope.
	orgs, err := repoA.ListOrganizationsForUser(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, orgs, 1)
	assert.Equal(t, tenantA, orgs[0].Slug)
}

// TestAcceptInvitation_Multi_RoleDefaultsToMember confirms an
// invitation with no explicit role lands the user as a "member".
func TestAcceptInvitation_Multi_RoleDefaultsToMember(t *testing.T) {
	const tenantA = "acmecorp"
	repoA := newFakeRepo()
	svc := newTestAuthServiceMulti(t, repoA)

	org := seedOrg(repoA, tenantA)
	u := seedUser(repoA, "carol@x.com", "", "invited")

	rawToken := "tok-default-role"
	seedInvitation(repoA, &InvitationRecord{
		TokenHash: hashInvitationToken(rawToken),
		Email:     "carol@x.com",
		UserID:    u.ID,
		Role:      "",
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
		CreatedAt: time.Now().UnixMilli(),
	})

	ctx := WithTenantScope(context.Background(), &TenantScope{TenantID: tenantA, Repo: repoA})
	_, err := svc.AcceptInvitation(ctx, rawToken, strongPW, "", "", "")
	require.NoError(t, err)

	m := repoA.membershipFor(org.ID, u.ID)
	require.NotNil(t, m)
	assert.Equal(t, "member", m.Role)
}

// TestAcceptInvitation_Multi_CrossTenantRejected covers slice-4
// cross-tenant safety: an invitation minted for tenant A cannot be
// redeemed under tenant B's host. The token lives only in A's data
// plane, so B's scoped repo never finds it.
func TestAcceptInvitation_Multi_CrossTenantRejected(t *testing.T) {
	const (
		tenantA = "acmecorp"
		tenantB = "globex"
	)
	repoA := newFakeRepo()
	repoB := newFakeRepo()
	// Single service instance; the boot-time default is irrelevant
	// because every call rides a per-request scope.
	svc := newTestAuthServiceMulti(t, repoA)

	seedOrg(repoA, tenantA)
	seedOrg(repoB, tenantB)
	bobA := seedUser(repoA, "bob@x.com", "", "invited")

	rawToken := "tok-cross-tenant"
	seedInvitation(repoA, &InvitationRecord{
		TokenHash: hashInvitationToken(rawToken),
		Email:     "bob@x.com",
		UserID:    bobA.ID,
		Role:      "member",
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
		CreatedAt: time.Now().UnixMilli(),
	})

	// Replay the A-issued token under tenant B's scope.
	ctxB := WithTenantScope(context.Background(), &TenantScope{TenantID: tenantB, Repo: repoB})
	_, err := svc.AcceptInvitation(ctxB, rawToken, strongPW, "Bob", "", "")
	require.Error(t, err, "A-issued invite must not redeem under B's host")
	assert.ErrorIs(t, err, ErrUnauthenticated)

	// Bob never became a member of B.
	orgsB, err := repoB.ListOrganizationsForUser(ctxB, bobA.ID)
	require.NoError(t, err)
	assert.Empty(t, orgsB)
}

// TestAcceptInvitation_Multi_NoOrgForTenantFails defends the branch
// where mode=multi resolves a tenant that has no Organization row. This
// is an inconsistent-state guard: redemption fails closed rather than
// issuing a session without a membership.
func TestAcceptInvitation_Multi_NoOrgForTenantFails(t *testing.T) {
	const tenantA = "acmecorp"
	repoA := newFakeRepo()
	svc := newTestAuthServiceMulti(t, repoA)

	// No seedOrg — tenant has an invitation but no organisation.
	u := seedUser(repoA, "dan@x.com", "", "invited")
	rawToken := "tok-no-org"
	seedInvitation(repoA, &InvitationRecord{
		TokenHash: hashInvitationToken(rawToken),
		Email:     "dan@x.com",
		UserID:    u.ID,
		Role:      "member",
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
		CreatedAt: time.Now().UnixMilli(),
	})

	ctx := WithTenantScope(context.Background(), &TenantScope{TenantID: tenantA, Repo: repoA})
	_, err := svc.AcceptInvitation(ctx, rawToken, strongPW, "", "", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

// TestAcceptInvitation_Single_NoMembershipNoOrgLookup confirms the
// mode=single redemption path is unchanged: no organisation is looked
// up and no membership is created, so a single-tenant deployment (which
// never provisions an Organization) still redeems invitations cleanly.
func TestAcceptInvitation_Single_NoMembershipNoOrgLookup(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo) // testConfig() → mode=single

	u := seedUser(repo, "single@x.com", "", "invited")
	rawToken := "tok-single"
	seedInvitation(repo, &InvitationRecord{
		TokenHash: hashInvitationToken(rawToken),
		Email:     "single@x.com",
		UserID:    u.ID,
		Role:      "member",
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
		CreatedAt: time.Now().UnixMilli(),
	})

	result, err := svc.AcceptInvitation(context.Background(), rawToken, strongPW, "Single", "", "")
	require.NoError(t, err)
	require.NotNil(t, result)

	// No membership rows were written.
	repo.mu.Lock()
	n := len(repo.orgMembers)
	repo.mu.Unlock()
	assert.Zero(t, n, "mode=single must not create org memberships")
}

// TestAcceptInvitation_Multi_AlreadyMemberTolerated covers the
// idempotency branch: a redemption whose membership row already exists
// (a re-run after a partial earlier accept) does not fail.
func TestAcceptInvitation_Multi_AlreadyMemberTolerated(t *testing.T) {
	const tenantA = "acmecorp"
	repoA := newFakeRepo()
	svc := newTestAuthServiceMulti(t, repoA)

	org := seedOrg(repoA, tenantA)
	u := seedUser(repoA, "eve@x.com", "", "invited")
	// Pre-existing membership for the same (org, user) pair.
	_, err := repoA.AddOrganizationMember(context.Background(), &OrganizationMembership{
		OrganizationID: org.ID, UserID: u.ID, Role: "member",
	})
	require.NoError(t, err)

	rawToken := "tok-already-member"
	seedInvitation(repoA, &InvitationRecord{
		TokenHash: hashInvitationToken(rawToken),
		Email:     "eve@x.com",
		UserID:    u.ID,
		Role:      "member",
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
		CreatedAt: time.Now().UnixMilli(),
	})

	ctx := WithTenantScope(context.Background(), &TenantScope{TenantID: tenantA, Repo: repoA})
	_, err = svc.AcceptInvitation(ctx, rawToken, strongPW, "", "", "")
	require.NoError(t, err, "an already-present membership must be tolerated")
}

// TestAcceptInvitation_Multi_OrgLookupErrorFailsClosed covers the
// GetOrganizationBySlug error branch: redemption fails rather than
// issuing a session without a membership.
func TestAcceptInvitation_Multi_OrgLookupErrorFailsClosed(t *testing.T) {
	const tenantA = "acmecorp"
	repo := newErrorRepo()
	svc := newTestAuthServiceMulti(t, repo)

	seedOrg(repo.fakeRepo, tenantA)
	u := seedUser(repo.fakeRepo, "frank@x.com", "", "invited")
	rawToken := "tok-orglookup-fc" // #nosec G101 -- test invitation token, not a credential.
	seedInvitation(repo.fakeRepo, &InvitationRecord{
		TokenHash: hashInvitationToken(rawToken),
		Email:     "frank@x.com",
		UserID:    u.ID,
		Role:      "member",
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
		CreatedAt: time.Now().UnixMilli(),
	})

	repo.failGetOrganizationBySlug = true
	ctx := WithTenantScope(context.Background(), &TenantScope{TenantID: tenantA, Repo: repo})
	_, err := svc.AcceptInvitation(ctx, rawToken, strongPW, "", "", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, errInjected)
}

// TestAcceptInvitation_Multi_AddMemberErrorFailsClosed covers the
// AddOrganizationMember non-AlreadyExists error branch.
func TestAcceptInvitation_Multi_AddMemberErrorFailsClosed(t *testing.T) {
	const tenantA = "acmecorp"
	repo := newErrorRepo()
	svc := newTestAuthServiceMulti(t, repo)

	seedOrg(repo.fakeRepo, tenantA)
	u := seedUser(repo.fakeRepo, "grace@x.com", "", "invited")
	rawToken := "tok-addmember-fc" // #nosec G101 -- test invitation token, not a credential.
	seedInvitation(repo.fakeRepo, &InvitationRecord{
		TokenHash: hashInvitationToken(rawToken),
		Email:     "grace@x.com",
		UserID:    u.ID,
		Role:      "member",
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
		CreatedAt: time.Now().UnixMilli(),
	})

	repo.failAddOrganizationMember = true
	ctx := WithTenantScope(context.Background(), &TenantScope{TenantID: tenantA, Repo: repo})
	_, err := svc.AcceptInvitation(ctx, rawToken, strongPW, "", "", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, errInjected)
}
