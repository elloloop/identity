package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/audit"
)

const (
	phoneMatchTenant      = "t-acme"
	phoneMatchOtherTenant = "t-other"
	phoneMatchDomain      = "acme.example.test"
)

func sha256Of(number string) []byte {
	h := sha256.Sum256([]byte(number))
	return h[:]
}

// phoneMatchFixture is a directory whose project A holds the claimed tenant
// phoneMatchTenant, which verified phoneMatchDomain, and whose project B
// holds phoneMatchOtherTenant. key is a directory_reader key of project A.
type phoneMatchFixture struct {
	*directoryFixture
	tenants  *fakeTenantStore
	members  *fakeMembershipStore
	accounts *fakeUserDirectory
	key      string
}

func newPhoneMatchFixture(t *testing.T, perTenant int) *phoneMatchFixture {
	t.Helper()
	f := &phoneMatchFixture{
		directoryFixture: newDirectoryFixture(t),
		tenants:          newFakeTenantStore(),
		members:          newFakeMembershipStore(),
		accounts:         newFakeUserDirectory(),
	}
	linkFakeTenantStores(f.tenants, f.members)
	f.members.accounts = f.accounts
	f.svc.WithTenantMemberPhones(f.members, perTenant, 60_000)
	f.tenants.put(&Tenant{ID: phoneMatchTenant, ProjectID: dirTestProjectA, Status: TenantStatusClaimed})
	f.tenants.put(&Tenant{ID: phoneMatchOtherTenant, ProjectID: dirTestProjectB, Status: TenantStatusClaimed})
	f.members.verifyDomain(dirTestProjectA, phoneMatchTenant, phoneMatchDomain)
	f.key = f.mint(t, dirTestProjectA, CredentialKindDirectoryReader).RawKey
	return f
}

// account stores u in projectID and, when source is set, gives it a
// membership of tenantID with that source and status.
func (f *phoneMatchFixture) account(t *testing.T, projectID, tenantID string, u *User, source, status string) {
	t.Helper()
	f.accounts.set(projectID, u)
	if source == "" {
		return
	}
	_, err := f.members.UpsertMembership(context.Background(), &TenantMembership{
		ProjectID: projectID, TenantID: tenantID, UserID: u.ID, Source: source, Role: RoleMember, Status: status,
	})
	require.NoError(t, err)
}

// Only a member who may act in the tenant, of an active person's account,
// whose number is verified and was asked for, is returned.
func TestMatchTenantMemberPhones_ReturnsOnlyMembersWithAVerifiedNumber(t *testing.T) {
	f := newPhoneMatchFixture(t, 10)
	cases := []struct {
		name     string
		user     User
		source   string
		status   string
		noNumber bool
		asked    bool
		match    bool
	}{
		{name: "member, no number", user: User{Email: "nonumber@corp.test", PhoneVerified: true}, source: MembershipSourceAdded, status: MembershipStatusActive, noNumber: true, asked: true},
		{name: "member, verified number", user: User{Email: "a@corp.test", PhoneVerified: true}, source: MembershipSourceAdded, status: MembershipStatusActive, asked: true, match: true},
		{name: "member, unverified number", user: User{Email: "b@corp.test"}, source: MembershipSourceAdded, status: MembershipStatusActive, asked: true},
		{name: "non-member, verified number", user: User{Email: "c@corp.test", PhoneVerified: true}, asked: true},
		{name: "suspended membership", user: User{Email: "d@corp.test", PhoneVerified: true}, source: MembershipSourceAdded, status: MembershipStatusSuspended, asked: true},
		{name: "ended membership", user: User{Email: "e@corp.test", PhoneVerified: true}, source: MembershipSourceInvited, status: MembershipStatusInactive, asked: true},
		{name: "deactivated account", user: User{Email: "f@corp.test", PhoneVerified: true, Status: StatusDeactivated}, source: MembershipSourceAdded, status: MembershipStatusActive, asked: true},
		{name: "anonymous account", user: User{PhoneVerified: true, IsAnonymous: true}, source: MembershipSourceAdded, status: MembershipStatusActive, asked: true},
		{name: "agent account", user: User{Kind: UserKindAgent, OwnerUserID: "someone", PhoneVerified: true}, source: MembershipSourceAdded, status: MembershipStatusActive, asked: true},
		{name: "domain member, verified email on the domain", user: User{Email: "g@" + phoneMatchDomain, EmailVerified: true, PhoneVerified: true}, source: MembershipSourceDomain, status: MembershipStatusActive, asked: true, match: true},
		{name: "domain member, unverified email", user: User{Email: "h@" + phoneMatchDomain, PhoneVerified: true}, source: MembershipSourceDomain, status: MembershipStatusActive, asked: true},
		{name: "domain member, email off the domain", user: User{Email: "i@elsewhere.test", EmailVerified: true, PhoneVerified: true}, source: MembershipSourceDomain, status: MembershipStatusActive, asked: true},
		{name: "member, number not asked for", user: User{Email: "j@corp.test", PhoneVerified: true}, source: MembershipSourceAdded, status: MembershipStatusActive},
	}
	var asked [][]byte
	var want []string
	for i, tc := range cases {
		u := tc.user
		u.ID = fmt.Sprintf("user-%02d", i)
		if !tc.noNumber {
			u.PhoneNumber = fmt.Sprintf("+14155550%03d", i)
		}
		f.account(t, dirTestProjectA, phoneMatchTenant, &u, tc.source, tc.status)
		if tc.asked {
			asked = append(asked, sha256Of(u.PhoneNumber))
		}
		if tc.match {
			want = append(want, u.ID)
		}
	}
	asked = append(asked, sha256Of("+19995550100"))

	got, err := f.svc.MatchTenantMemberPhones(context.Background(), f.key, phoneMatchTenant, asked)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

// The request is judged before the credential is read, so a malformed one
// costs no control-plane query: the tenant id must be one a tenant could
// have, and the batch 1 to MaxPhoneMatchHashes digests of 32 bytes.
func TestMatchTenantMemberPhones_RefusesABadRequestBeforeReadingTheCredential(t *testing.T) {
	f := newPhoneMatchFixture(t, 10)
	one := [][]byte{sha256Of("+14155550100")}
	overCap := make([][]byte, MaxPhoneMatchHashes+1)
	for i := range overCap {
		overCap[i] = sha256Of(fmt.Sprintf("+1415%07d", i))
	}
	cases := []struct {
		name   string
		tenant string
		hashes [][]byte
	}{
		{name: "blank tenant", tenant: "  ", hashes: one},
		{name: "tenant with a space", tenant: "t acme", hashes: one},
		{name: "tenant too long", tenant: strings.Repeat("t", maxTenantIDLen+1), hashes: one},
		{name: "no hashes", tenant: phoneMatchTenant},
		{name: "over the cap", tenant: phoneMatchTenant, hashes: overCap},
		{name: "a short hash", tenant: phoneMatchTenant, hashes: [][]byte{sha256Of("+1")[:31]}},
		{name: "a long hash", tenant: phoneMatchTenant, hashes: [][]byte{append(sha256Of("+1"), 0)}},
		{name: "a number, not its hash", tenant: phoneMatchTenant, hashes: [][]byte{[]byte("+14155550100")}},
	}
	f.store.lookupErr = errors.New("the credential store must not be read")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.svc.MatchTenantMemberPhones(context.Background(), f.key, tc.tenant, tc.hashes)
			require.ErrorIs(t, err, ErrInvalidArgument)
		})
	}
	f.store.lookupErr = nil

	atCap := overCap[:MaxPhoneMatchHashes]
	_, err := f.svc.MatchTenantMemberPhones(context.Background(), f.key, phoneMatchTenant, atCap)
	require.NoError(t, err, "a batch of exactly the cap is accepted")
}

// A credential reads its own project's tenants only: a tenant of another
// project is refused exactly as one that does not exist, and the refusal is
// recorded in the credential's project.
func TestMatchTenantMemberPhones_RefusesATenantOfAnotherProject(t *testing.T) {
	f := newPhoneMatchFixture(t, 10)
	other := &User{ID: "other-member", Email: "o@corp.test", PhoneNumber: "+14155550111", PhoneVerified: true}
	f.account(t, dirTestProjectB, phoneMatchOtherTenant, other, MembershipSourceAdded, MembershipStatusActive)
	asked := [][]byte{sha256Of(other.PhoneNumber)}

	for _, tenant := range []string{phoneMatchOtherTenant, "t-unknown"} {
		got, err := f.svc.MatchTenantMemberPhones(context.Background(), f.key, tenant, asked)
		require.ErrorIs(t, err, ErrPermissionDenied, tenant)
		assert.Nil(t, got)
	}
	refusals := f.audit.byEvent(string(audit.EventDirectoryPhoneMatch))
	require.Len(t, refusals, 2)
	for _, e := range refusals {
		assert.Equal(t, dirTestProjectA, e.project)
		assert.Equal(t, phoneMatchRefusedTenant, e.details["reason"])
		assert.True(t, strings.HasPrefix(e.actor, "credential:"))
	}

	ownKey := f.mint(t, dirTestProjectB, CredentialKindDirectoryReader).RawKey
	got, err := f.svc.MatchTenantMemberPhones(context.Background(), ownKey, phoneMatchOtherTenant, asked)
	require.NoError(t, err)
	assert.Equal(t, []string{other.ID}, got, "the tenant's own project's credential reads it")
}

// Nothing but an active directory_reader credential is accepted: another
// kind's key, a revoked one, a wrong secret or a user's token is
// unauthenticated, and only a refusal of a real directory_reader credential
// is recorded.
func TestMatchTenantMemberPhones_RefusesEveryOtherPresentation(t *testing.T) {
	f := newPhoneMatchFixture(t, 10)
	publicID, _, _ := strings.Cut(f.key, rawKeySeparator)
	revoked := f.mint(t, dirTestProjectA, CredentialKindDirectoryReader)
	require.NoError(t, f.admin.AdminRevokeProjectCredential(context.Background(), dirTestSecret, dirTestProjectA, revoked.ID))
	cases := []struct {
		name   string
		key    string
		reason string
	}{
		{name: "missing", key: ""},
		{name: "a user's token", key: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1In0.sig"},
		{name: "tenant operator credential", key: f.mint(t, dirTestProjectA, CredentialKindTenantOperator).RawKey},
		{name: "secret-kind credential", key: f.mint(t, dirTestProjectA, CredentialKindSecret).RawKey},
		{name: "wrong secret", key: publicID + rawKeySeparator + "not-the-secret", reason: credentialRefusedSecretMismatch},
		{name: "revoked credential", key: revoked.RawKey, reason: credentialRefusedRevoked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(f.audit.byEvent(string(audit.EventDirectoryPhoneMatch)))
			got, err := f.svc.MatchTenantMemberPhones(context.Background(), tc.key, phoneMatchTenant, [][]byte{sha256Of("+14155550100")})
			require.ErrorIs(t, err, ErrUnauthenticated)
			assert.Nil(t, got)
			after := f.audit.byEvent(string(audit.EventDirectoryPhoneMatch))
			if tc.reason == "" {
				assert.Len(t, after, before, "a refusal of no directory_reader credential records nothing")
				return
			}
			require.Len(t, after, before+1)
			assert.Equal(t, tc.reason, after[len(after)-1].details["reason"])
		})
	}
}

// Each credential has its own budget per tenant: spending it on one tenant
// leaves the credential's other tenants, and the tenant's other credentials,
// their own.
func TestMatchTenantMemberPhones_BudgetsEachCredentialPerTenant(t *testing.T) {
	f := newPhoneMatchFixture(t, 2)
	f.tenants.put(&Tenant{ID: "t-second", ProjectID: dirTestProjectA, Status: TenantStatusClaimed})
	asked := [][]byte{sha256Of("+14155550100")}
	match := func(key, tenant string) error {
		_, err := f.svc.MatchTenantMemberPhones(context.Background(), key, tenant, asked)
		return err
	}
	require.NoError(t, match(f.key, phoneMatchTenant))
	require.NoError(t, match(f.key, phoneMatchTenant))
	require.ErrorIs(t, match(f.key, phoneMatchTenant), ErrPhoneMatchLimited)

	require.NoError(t, match(f.key, "t-second"), "another tenant has its own budget")
	second := f.mint(t, dirTestProjectA, CredentialKindDirectoryReader).RawKey
	require.NoError(t, match(second, phoneMatchTenant), "another credential has its own budget")

	require.ErrorIs(t, match("", phoneMatchTenant), ErrUnauthenticated, "a refused key spends nothing and is refused as such")
}

// The audit trail records who matched against which tenant and how much,
// never a hash or a matched account.
func TestMatchTenantMemberPhones_AuditsCountsNeverHashes(t *testing.T) {
	f := newPhoneMatchFixture(t, 10)
	member := &User{ID: "member", Email: "m@corp.test", PhoneNumber: "+14155550123", PhoneVerified: true}
	f.account(t, dirTestProjectA, phoneMatchTenant, member, MembershipSourceAdded, MembershipStatusActive)
	hash := sha256Of(member.PhoneNumber)
	asked := [][]byte{hash, hash, sha256Of("+14155550124")}

	got, err := f.svc.MatchTenantMemberPhones(context.Background(), f.key, phoneMatchTenant, asked)
	require.NoError(t, err)
	require.Equal(t, []string{member.ID}, got)

	entries := f.audit.byEvent(string(audit.EventDirectoryPhoneMatch))
	require.Len(t, entries, 1)
	e := entries[0]
	assert.Equal(t, dirTestProjectA, e.project)
	assert.True(t, strings.HasPrefix(e.actor, "credential:"))
	assert.Equal(t, map[string]any{"tenant_id": phoneMatchTenant, "requested": float64(2), "matched": float64(1)}, e.details,
		"repeats count once")
	raw, err := json.Marshal(e.details)
	require.NoError(t, err)
	recorded := string(raw) + e.actor + e.project + e.client[0] + e.client[1]
	for _, leak := range []string{hex.EncodeToString(hash), base64.StdEncoding.EncodeToString(hash), string(hash), member.PhoneNumber, member.ID} {
		assert.NotContains(t, recorded, leak)
	}
}

// A store failure is the caller's error, unrecorded, and a directory built
// without the members it matches against does not serve the call.
func TestMatchTenantMemberPhones_StoreFailureAndUnwired(t *testing.T) {
	f := newPhoneMatchFixture(t, 10)
	down := errors.New("store down")
	f.members.listErr = down
	_, err := f.svc.MatchTenantMemberPhones(context.Background(), f.key, phoneMatchTenant, [][]byte{sha256Of("+1")})
	require.ErrorIs(t, err, down)
	assert.Empty(t, f.audit.byEvent(string(audit.EventDirectoryPhoneMatch)))

	unwired := newDirectoryFixture(t)
	_, err = unwired.svc.MatchTenantMemberPhones(context.Background(), f.key, phoneMatchTenant, [][]byte{sha256Of("+1")})
	require.ErrorIs(t, err, ErrUnimplemented)
}
