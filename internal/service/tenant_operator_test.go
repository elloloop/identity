package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

// asAdmin presents secret as the admin secret on an operator call.
func asAdmin(secret string) OperatorCredentials {
	return OperatorCredentials{AdminSecret: secret}
}

// asTenantOperator presents rawKey as a tenant_operator key.
func asTenantOperator(rawKey string) OperatorCredentials {
	return OperatorCredentials{TenantOperatorKey: rawKey}
}

// tenantOperatorFixture is an operator service configured with an admin
// secret (possibly none) whose audit records keep the project they were
// written under, holding a tenant_operator key of "proj", the recovery
// fixture's tenant t-1 there, which a person created, t-2, a claimed tenant
// nobody governs yet, as an operator's new tenant is, and "aide", an account
// of "proj" that belongs to no tenant.
type tenantOperatorFixture struct {
	*adminFixture
	records *projectAuditWriter
	key     *MintedCredential
}

func newTenantOperatorFixture(t *testing.T, adminSecret string) *tenantOperatorFixture {
	t.Helper()
	f := newRecoveryFixture()
	f.tenants.put(&Tenant{ID: "t-1", ProjectID: "proj", Name: "Acme", Status: TenantStatusClaimed, CreatedBy: "gone", UpdatedAtMs: 7})
	f.tenants.put(&Tenant{ID: "t-2", ProjectID: "proj", Name: "Acme West", Status: TenantStatusClaimed})
	f.users.set("proj", &User{ID: "aide", Email: "a@example.test", Status: StatusActive, EmailVerified: true})
	key, err := f.svc.AdminCreateProjectCredential(context.Background(), testAdminSecret, "proj", CredentialKindTenantOperator)
	require.NoError(t, err)
	auditLog, records := newProjectScopedAuditLog()
	f.svc = NewControlPlaneAdminService(adminSecret, false, testAdminSecretsKey(), f.projects, f.tenants, f.members, f.users,
		f.policies, f.admins, f.dns, auditLog, zap.NewNop())
	return &tenantOperatorFixture{adminFixture: f, records: records, key: key}
}

func (f *tenantOperatorFixture) actor() string {
	return "credential:" + f.key.ID
}

// tenantOperations are the operator calls a tenant_operator key authorizes,
// each made on tenant t-1 of project, but for the grant of t-2's first
// admin and the creation of a tenant. AdminAddTenantMember adds aide to t-1.
var tenantOperations = []struct {
	name string
	call func(svc *ControlPlaneAdminService, caller OperatorCredentials, project string) error
}{
	{"AdminGetTenant", func(svc *ControlPlaneAdminService, caller OperatorCredentials, project string) error {
		_, err := svc.AdminGetTenant(context.Background(), caller, project, "t-1")
		return err
	}},
	{"AdminListTenants", func(svc *ControlPlaneAdminService, caller OperatorCredentials, project string) error {
		_, err := svc.AdminListTenants(context.Background(), caller, project, 0, "")
		return err
	}},
	{"GetLoginPolicy", func(svc *ControlPlaneAdminService, caller OperatorCredentials, project string) error {
		_, err := svc.GetLoginPolicy(context.Background(), caller, project, "t-1")
		return err
	}},
	{"AdminSuspendTenant", func(svc *ControlPlaneAdminService, caller OperatorCredentials, project string) error {
		_, err := svc.AdminSuspendTenant(context.Background(), caller, project, "t-1", "why", testOperatorIP, testOperatorUA)
		return err
	}},
	{"AdminRestoreTenant", func(svc *ControlPlaneAdminService, caller OperatorCredentials, project string) error {
		_, err := svc.AdminRestoreTenant(context.Background(), caller, project, "t-1", "why", testOperatorIP, testOperatorUA)
		return err
	}},
	{"AdminRecoverTenantOwnership", func(svc *ControlPlaneAdminService, caller OperatorCredentials, project string) error {
		_, err := svc.AdminRecoverTenantOwnership(context.Background(), caller, project, "t-1", "heir", "why", testOperatorIP, testOperatorUA)
		return err
	}},
	{"AdminCreateTenant", func(svc *ControlPlaneAdminService, caller OperatorCredentials, project string) error {
		_, err := svc.AdminCreateTenant(context.Background(), caller, project, "Acme East", "east.example", testOperatorIP, testOperatorUA)
		return err
	}},
	{"AdminAddTenantAdmin", func(svc *ControlPlaneAdminService, caller OperatorCredentials, project string) error {
		_, err := svc.AdminAddTenantAdmin(context.Background(), caller, project, "t-2", "aide", RoleAdmin, testOperatorIP, testOperatorUA)
		return err
	}},
	{"AdminAddTenantMember", func(svc *ControlPlaneAdminService, caller OperatorCredentials, project string) error {
		_, err := svc.AdminAddTenantMember(context.Background(), caller, project, "t-1", "aide", testOperatorIP, testOperatorUA)
		return err
	}},
}

// requireNothingCreated fails unless the fixture still holds only the
// tenants it was given, n of them, and "aide" holds no membership.
func (f *tenantOperatorFixture) requireNothingCreated(t *testing.T, n int, msgAndArgs ...any) {
	t.Helper()
	assert.Len(t, f.tenants.byID, n, msgAndArgs...)
	for _, tenant := range []string{"t-1", "t-2"} {
		m, _ := f.members.GetMembership(context.Background(), "proj", tenant, "aide")
		assert.Nil(t, m, msgAndArgs...)
	}
}

// A tenant_operator key of the project does each tenant operation, and the
// changes it makes are recorded as its own.
func TestTenantOperator_AuthorizesTheTenantOperations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantOperatorFixture(t, testAdminSecret)
	f.seedMembership("heir", MembershipSourceInvited, RoleMember, MembershipStatusSuspended)
	for _, op := range tenantOperations {
		require.NoError(t, op.call(f.svc, asTenantOperator(f.key.RawKey), "proj"), op.name)
	}

	stored, _ := f.tenants.GetTenant(ctx, "proj", "t-1")
	assert.Equal(t, TenantStatusClaimed, stored.Status, "suspended, then restored")
	heir, _ := f.members.GetMembership(ctx, "proj", "t-1", "heir")
	assert.Equal(t, RoleOwner, heir.Role)
	assert.Equal(t, MembershipStatusActive, heir.Status)
	aide, _ := f.members.GetMembership(ctx, "proj", "t-2", "aide")
	require.NotNil(t, aide)
	assert.Equal(t, RoleAdmin, aide.Role)
	assert.Equal(t, MembershipSourceAdded, aide.Source)
	member, _ := f.members.GetMembership(ctx, "proj", "t-1", "aide")
	require.NotNil(t, member)
	assert.Equal(t, RoleMember, member.Role)
	assert.Equal(t, MembershipStatusActive, member.Status)
	page, err := f.svc.AdminListTenants(ctx, asTenantOperator(f.key.RawKey), "proj", 0, "")
	require.NoError(t, err)
	require.Len(t, page.Tenants, 3)
	for _, event := range []audit.EventType{
		audit.EventTenantSuspended, audit.EventTenantRestored, audit.EventTenantOwnershipRecovered, audit.EventTenantMemberRestored,
		audit.EventTenantCreated, audit.EventTenantAdminAdded, audit.EventTenantMemberAdded,
	} {
		records := f.records.byEvent(string(event))
		require.Len(t, records, 1, event)
		assert.Equal(t, "proj", records[0].project, event)
		assert.Equal(t, f.actor(), records[0].actor, event)
	}
	assert.Empty(t, f.records.byEvent(string(audit.EventTenantOperatorRefused)))
	created := f.records.byEvent(string(audit.EventTenantCreated))[0]
	var createdID string
	for _, tn := range page.Tenants {
		if tn.ID != "t-1" && tn.ID != "t-2" {
			createdID = tn.ID
		}
	}
	assert.Equal(t, map[string]any{"project_id": "proj", "tenant_id": createdID, "primary_domain": "east.example"}, created.details)
	assert.Equal(t, [2]string{testOperatorIP, testOperatorUA}, created.client)
	added := f.records.byEvent(string(audit.EventTenantAdminAdded))[0]
	assert.Equal(t, map[string]any{"project_id": "proj", "tenant_id": "t-2", "role": RoleAdmin}, added.details)
	assert.Equal(t, [2]string{testOperatorIP, testOperatorUA}, added.client)
	joined := f.records.byEvent(string(audit.EventTenantMemberAdded))[0]
	assert.Equal(t, map[string]any{"project_id": "proj", "tenant_id": "t-1", "role": RoleMember}, joined.details)
	assert.Equal(t, [2]string{testOperatorIP, testOperatorUA}, joined.client)
	stored, _ = f.tenants.GetTenant(ctx, "proj", createdID)
	assert.Equal(t, CredentialKindTenantOperator, stored.CreatorOperatorKind, "the tenant records the credential made it")
}

// The admin secret's changes name no actor, as before.
func TestTenantOperator_TheAdminSecretNamesNoActor(t *testing.T) {
	t.Parallel()
	f := newTenantOperatorFixture(t, testAdminSecret)
	_, err := f.svc.AdminSuspendTenant(context.Background(), asAdmin(testAdminSecret), "proj", "t-1", "why", "", "")
	require.NoError(t, err)
	records := f.records.byEvent(string(audit.EventTenantSuspended))
	require.Len(t, records, 1)
	assert.Empty(t, records[0].actor)
}

// A key used on another project is refused, whatever the operation, and the
// refusal is recorded in the key's own project.
func TestTenantOperator_ConfinedToItsProject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantOperatorFixture(t, testAdminSecret)
	f.tenants.put(&Tenant{ID: "t-1", ProjectID: "other", Name: "Other", Status: TenantStatusClaimed, CreatedBy: "u-other"})
	for _, op := range tenantOperations {
		err := op.call(f.svc, asTenantOperator(f.key.RawKey), "other")
		require.ErrorIs(t, err, ErrPermissionDenied, op.name)
		require.ErrorIs(t, err, errTenantOperatorRefused, op.name)
	}

	other, _ := f.tenants.GetTenant(ctx, "other", "t-1")
	assert.Equal(t, TenantStatusClaimed, other.Status)
	assert.Zero(t, f.tenants.writes)
	f.requireNothingCreated(t, 3)
	assert.Empty(t, f.records.byEvent(string(audit.EventTenantCreated)))
	assert.Empty(t, f.records.byEvent(string(audit.EventTenantAdminAdded)))
	refusals := f.records.byEvent(string(audit.EventTenantOperatorRefused))
	require.Len(t, refusals, len(tenantOperations))
	for _, r := range refusals {
		assert.Equal(t, projectAuditEntry{
			project: "proj", event: string(audit.EventTenantOperatorRefused), actor: f.actor(),
			details: map[string]any{"reason": credentialRefusedOtherProject},
		}, r)
	}
}

// Every way a presented key fails is the same refusal. A refusal of a
// tenant_operator credential that exists is recorded under its project with
// the reason; anything else records nothing.
func TestTenantOperator_RefusesABadKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for name, tc := range map[string]struct {
		key    func(f *tenantOperatorFixture) string
		reason string
	}{
		"wrong secret": {key: func(f *tenantOperatorFixture) string { return f.key.PublicID + ".wrong" }, reason: credentialRefusedSecretMismatch},
		"revoked": {key: func(f *tenantOperatorFixture) string {
			require.NoError(t, f.svc.AdminRevokeProjectCredential(ctx, testAdminSecret, "proj", f.key.ID))
			return f.key.RawKey
		}, reason: credentialRefusedRevoked},
		"no secret half":    {key: func(f *tenantOperatorFixture) string { return f.key.PublicID }},
		"empty secret half": {key: func(f *tenantOperatorFixture) string { return f.key.PublicID + "." }},
		"empty public id":   {key: func(*tenantOperatorFixture) string { return ".secret" }},
		"unknown public id": {key: func(*tenantOperatorFixture) string { return tenantOperatorKeyPrefix + "unknown.secret" }},
		"another kind's credential": {key: func(f *tenantOperatorFixture) string {
			reader, err := f.svc.AdminCreateProjectCredential(ctx, testAdminSecret, "proj", CredentialKindDirectoryReader)
			require.NoError(t, err)
			return reader.RawKey
		}},
		"a suspended project's key": {key: func(f *tenantOperatorFixture) string {
			f.projects.suspended["proj"] = true
			return f.key.RawKey
		}},
	} {
		f := newTenantOperatorFixture(t, testAdminSecret)
		key := tc.key(f)
		for _, op := range tenantOperations {
			err := op.call(f.svc, asTenantOperator(key), "proj")
			require.ErrorIs(t, err, errTenantOperatorRefused, "%s: %s", name, op.name)
		}
		assert.Zero(t, f.tenants.writes, name)
		f.requireNothingCreated(t, 2, name)
		refusals := f.records.byEvent(string(audit.EventTenantOperatorRefused))
		if tc.reason == "" {
			assert.Empty(t, refusals, name)
			continue
		}
		require.Len(t, refusals, len(tenantOperations), name)
		assert.Equal(t, "proj", refusals[0].project, name)
		assert.Equal(t, f.actor(), refusals[0].actor, name)
		assert.Equal(t, map[string]any{"reason": tc.reason}, refusals[0].details, name)
	}
}

// A revocation holds from the next call: the key is read uncached.
func TestTenantOperator_RevocationHoldsFromTheNextCall(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantOperatorFixture(t, testAdminSecret)
	_, err := f.svc.AdminGetTenant(ctx, asTenantOperator(f.key.RawKey), "proj", "t-1")
	require.NoError(t, err)
	_, err = f.svc.AdminCreateTenant(ctx, asTenantOperator(f.key.RawKey), "proj", "Before", "before.example", "", "")
	require.NoError(t, err)
	require.NoError(t, f.svc.AdminRevokeProjectCredential(ctx, testAdminSecret, "proj", f.key.ID))
	_, err = f.svc.AdminGetTenant(ctx, asTenantOperator(f.key.RawKey), "proj", "t-1")
	require.ErrorIs(t, err, errTenantOperatorRefused)
	_, err = f.svc.AdminCreateTenant(ctx, asTenantOperator(f.key.RawKey), "proj", "After", "after.example", "", "")
	require.ErrorIs(t, err, errTenantOperatorRefused)
	_, err = f.svc.AdminAddTenantAdmin(ctx, asTenantOperator(f.key.RawKey), "proj", "t-2", "aide", RoleOwner, "", "")
	require.ErrorIs(t, err, errTenantOperatorRefused)
	f.requireNothingCreated(t, 3, "only the tenant made before the revocation")
	assert.Len(t, f.records.byEvent(string(audit.EventTenantCreated)), 1)
	assert.Empty(t, f.records.byEvent(string(audit.EventTenantAdminAdded)))
}

// A key's AdminAddTenantAdmin must name a tenant and an account of its own
// project, so it writes no membership that reaches another project.
func TestTenantOperator_AddTenantAdminStaysInItsProject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantOperatorFixture(t, testAdminSecret)
	f.tenants.put(&Tenant{ID: "t-other", ProjectID: "other", Status: TenantStatusClaimed})
	f.users.set("other", &User{ID: "outsider", Email: "o@example.test", Status: StatusActive, EmailVerified: true})
	for name, ref := range map[string]struct{ tenant, user string }{
		"another project's tenant":  {"t-other", "aide"},
		"another project's account": {"t-2", "outsider"},
		"no such account":           {"t-2", "nobody"},
		"no such tenant":            {"t-none", "aide"},
	} {
		_, err := f.svc.AdminAddTenantAdmin(ctx, asTenantOperator(f.key.RawKey), "proj", ref.tenant, ref.user, RoleOwner, "", "")
		require.ErrorIs(t, err, ErrNotFound, name)
		m, _ := f.members.GetMembership(ctx, "proj", ref.tenant, ref.user)
		assert.Nil(t, m, name)
	}
	assert.Empty(t, f.records.byEvent(string(audit.EventTenantAdminAdded)))
}

// A key appoints only a tenant's first governor, under recovery's rules: it
// never overrides or lowers an owner or admin who can act, never appoints an
// account that may not own a tenant, and never touches a latent tenant. The
// admin secret is held to none of this.
func TestTenantOperator_AddTenantAdminAppointsOnlyAFirstGovernor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantOperatorFixture(t, testAdminSecret)
	key := asTenantOperator(f.key.RawKey)
	f.users.set("proj", &User{ID: "boss", Email: "b@example.test", Status: StatusActive, EmailVerified: true})
	f.seedMembership("boss", MembershipSourceCreated, RoleOwner, MembershipStatusActive)
	f.users.set("proj", &User{ID: "unverified", Email: "u@example.test", Status: StatusActive})
	f.users.set("proj", &User{ID: "anon", IsAnonymous: true, Status: StatusActive, EmailVerified: true})
	f.users.set("proj", &User{ID: "bot", Kind: UserKindAgent, OwnerUserID: "boss", Status: StatusActive, EmailVerified: true})
	f.tenants.put(&Tenant{ID: "t-latent", ProjectID: "proj", Status: TenantStatusLatent})

	for name, tc := range map[string]struct {
		tenant, user, role string
		want               error
	}{
		"a governed tenant":          {"t-1", "aide", RoleOwner, ErrTenantStillGoverned},
		"an admin on a governed one": {"t-1", "aide", RoleAdmin, ErrTenantStillGoverned},
		"lowering the owner":         {"t-1", "boss", RoleAdmin, ErrTenantStillGoverned},
		"an unverified email":        {"t-2", "unverified", RoleOwner, ErrIneligibleTenantOwner},
		"an anonymous account":       {"t-2", "anon", RoleOwner, ErrIneligibleTenantOwner},
		"an agent":                   {"t-2", "bot", RoleAdmin, ErrIneligibleTenantOwner},
		"a deactivated account":      {"t-2", "gone", RoleOwner, ErrIneligibleTenantOwner},
		"a latent tenant":            {"t-latent", "aide", RoleOwner, ErrTenantStatusConflict},
	} {
		_, err := f.svc.AdminAddTenantAdmin(ctx, key, "proj", tc.tenant, tc.user, tc.role, "", "")
		require.ErrorIs(t, err, tc.want, name)
	}
	boss, _ := f.members.GetMembership(ctx, "proj", "t-1", "boss")
	assert.Equal(t, RoleOwner, boss.Role, "the owner is not lowered")
	f.requireNothingCreated(t, 3)
	assert.Empty(t, f.records.byEvent(string(audit.EventTenantAdminAdded)))

	m, err := f.svc.AdminAddTenantAdmin(ctx, asAdmin(testAdminSecret), "proj", "t-1", "boss", RoleAdmin, "", "")
	require.NoError(t, err, "the admin secret sets the role it is given")
	assert.Equal(t, RoleAdmin, m.Role)
	grants := f.records.byEvent(string(audit.EventTenantAdminAdded))
	require.Len(t, grants, 1)
	assert.Empty(t, grants[0].actor)
	assert.Equal(t, map[string]any{
		"project_id": "proj", "tenant_id": "t-1", "role": RoleAdmin,
		"previous_role": RoleOwner, "previous_status": MembershipStatusActive,
	}, grants[0].details)
}

// A key's retry of a grant that landed returns the membership unchanged and
// records nothing; asking the appointed governor for another role is
// refused, since it would lower or change someone who can act.
func TestTenantOperator_AddTenantAdminRetryIsSafe(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantOperatorFixture(t, testAdminSecret)
	key := asTenantOperator(f.key.RawKey)
	first, err := f.svc.AdminAddTenantAdmin(ctx, key, "proj", "t-2", "aide", RoleOwner, "", "")
	require.NoError(t, err)
	again, err := f.svc.AdminAddTenantAdmin(ctx, key, "proj", "t-2", "aide", RoleOwner, "", "")
	require.NoError(t, err)
	assert.Equal(t, first.ID, again.ID)
	assert.Equal(t, RoleOwner, again.Role)
	assert.Len(t, f.records.byEvent(string(audit.EventTenantAdminAdded)), 1)

	_, err = f.svc.AdminAddTenantAdmin(ctx, key, "proj", "t-2", "aide", RoleAdmin, "", "")
	require.ErrorIs(t, err, ErrTenantStillGoverned)
	stored, _ := f.members.GetMembership(ctx, "proj", "t-2", "aide")
	assert.Equal(t, RoleOwner, stored.Role)
}

// A key's grant lifts a suspension as the secret's does, and both the lift and
// the grant are recorded as the key's, with the operator's client.
func TestTenantOperator_AGrantsLiftIsRecordedAsTheKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantOperatorFixture(t, testAdminSecret)
	_, err := f.members.UpsertMembership(ctx, &TenantMembership{
		ProjectID: "proj", TenantID: "t-2", UserID: "aide",
		Source: MembershipSourceInvited, Role: RoleMember, Status: MembershipStatusSuspended,
	})
	require.NoError(t, err)

	m, err := f.svc.AdminAddTenantAdmin(ctx, asTenantOperator(f.key.RawKey), "proj", "t-2", "aide", RoleAdmin, testOperatorIP, testOperatorUA)
	require.NoError(t, err)
	assert.Equal(t, MembershipStatusActive, m.Status)
	lifts := f.records.byEvent(string(audit.EventTenantMemberRestored))
	require.Len(t, lifts, 1)
	assert.Equal(t, f.actor(), lifts[0].actor)
	assert.Equal(t, [2]string{testOperatorIP, testOperatorUA}, lifts[0].client)
	grants := f.records.byEvent(string(audit.EventTenantAdminAdded))
	require.Len(t, grants, 1)
	assert.Equal(t, f.actor(), grants[0].actor)
	assert.Equal(t, [2]string{testOperatorIP, testOperatorUA}, grants[0].client)
	assert.Equal(t, map[string]any{
		"project_id": "proj", "tenant_id": "t-2", "role": RoleAdmin,
		"previous_role": RoleMember, "previous_status": MembershipStatusSuspended,
	}, grants[0].details)
}

// A failed read of the tenant, the account or the membership is the
// store's error, and nothing is written.
func TestTenantOperator_AddTenantAdminReadErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	boom := errors.New("read failed")
	for name, fail := range map[string]func(f *tenantOperatorFixture){
		"tenant":     func(f *tenantOperatorFixture) { f.tenants.getErr = boom },
		"account":    func(f *tenantOperatorFixture) { f.users.getErr = boom },
		"membership": func(f *tenantOperatorFixture) { f.members.getErr = boom },
	} {
		f := newTenantOperatorFixture(t, testAdminSecret)
		fail(f)
		_, err := f.svc.AdminAddTenantAdmin(ctx, asTenantOperator(f.key.RawKey), "proj", "t-2", "aide", RoleOwner, "", "")
		require.ErrorIs(t, err, boom, name)
		f.members.getErr = nil
		f.requireNothingCreated(t, 2, name)
	}
}

// When an admin secret is presented it alone is checked: a wrong one is
// refused even beside a valid key, and a right one admits the call beside a
// bad key.
func TestTenantOperator_APresentedAdminSecretAloneIsChecked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantOperatorFixture(t, testAdminSecret)
	_, err := f.svc.AdminGetTenant(ctx, OperatorCredentials{AdminSecret: "wrong", TenantOperatorKey: f.key.RawKey}, "proj", "t-1")
	require.ErrorIs(t, err, ErrPermissionDenied)
	require.NotErrorIs(t, err, errTenantOperatorRefused)

	_, err = f.svc.AdminSuspendTenant(ctx, OperatorCredentials{AdminSecret: testAdminSecret, TenantOperatorKey: "garbage"}, "proj", "t-1", "why", "", "")
	require.NoError(t, err)
	records := f.records.byEvent(string(audit.EventTenantSuspended))
	require.Len(t, records, 1)
	assert.Empty(t, records[0].actor, "the admin secret made the change")
	assert.Empty(t, f.records.byEvent(string(audit.EventTenantOperatorRefused)))
}

// A deployment that configures no admin secret still serves tenant_operator
// keys, while the admin secret stays switched off.
func TestTenantOperator_WorksWithoutAnAdminSecret(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantOperatorFixture(t, "")
	for _, op := range tenantOperations {
		require.NoError(t, op.call(f.svc, asTenantOperator(f.key.RawKey), "proj"), op.name)
	}
	for _, caller := range []OperatorCredentials{{}, asAdmin("anything")} {
		_, err := f.svc.AdminGetTenant(ctx, caller, "proj", "t-1")
		require.ErrorIs(t, err, ErrUnimplemented, "%+v", caller)
	}
	_, err := f.svc.AdminCreateProjectCredential(ctx, f.key.RawKey, "proj", CredentialKindTenantOperator)
	require.ErrorIs(t, err, ErrUnimplemented, "a key is not the admin secret of any other operator call")
}

// A key is never taken to name its project: the call must.
func TestTenantOperator_RequiresTheProject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantOperatorFixture(t, testAdminSecret)
	for _, project := range []string{"", "  "} {
		_, err := f.svc.AdminGetTenant(ctx, asTenantOperator(f.key.RawKey), project, "t-1")
		require.ErrorIs(t, err, ErrInvalidArgument, "%q", project)
		_, err = f.svc.AdminGetTenant(ctx, asTenantOperator(f.key.PublicID+".wrong"), project, "t-1")
		require.ErrorIs(t, err, errTenantOperatorRefused, "a bad key is refused before the project is read")
	}
	_, err := f.svc.AdminGetTenant(ctx, asTenantOperator(f.key.RawKey), " proj ", "t-1")
	require.NoError(t, err, "the project is trimmed as every operator call trims it")
}

// A failed credential read is the store's error, not a refusal.
func TestTenantOperator_StoreErrorIsNotARefusal(t *testing.T) {
	t.Parallel()
	f := newTenantOperatorFixture(t, testAdminSecret)
	boom := errors.New("read failed")
	f.projects.lookupErr = boom
	_, err := f.svc.AdminGetTenant(context.Background(), asTenantOperator(f.key.RawKey), "proj", "t-1")
	require.ErrorIs(t, err, boom)
	require.NotErrorIs(t, err, ErrPermissionDenied)
}

// A tenant records what authorized its creation, and a key restores a
// suspended tenant a key created though nobody governs it. The admin secret,
// and a key on a tenant the secret or no operator created, keep the old
// refusal.
func TestAdminRestoreTenant_AKeyRestoresTheTenantsKeysCreated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantOperatorFixture(t, testAdminSecret)
	key := asTenantOperator(f.key.RawKey)
	byKey, err := f.svc.AdminCreateTenant(ctx, key, "proj", "Made by a key", "", "", "")
	require.NoError(t, err)
	bySecret, err := f.svc.AdminCreateTenant(ctx, asAdmin(testAdminSecret), "proj", "Made by the secret", "", "", "")
	require.NoError(t, err)
	stored, _ := f.tenants.GetTenant(ctx, "proj", byKey)
	assert.Equal(t, CredentialKindTenantOperator, stored.CreatorOperatorKind)
	stored, _ = f.tenants.GetTenant(ctx, "proj", bySecret)
	assert.Equal(t, OperatorKindAdminSecret, stored.CreatorOperatorKind)
	f.tenants.put(&Tenant{ID: "t-unmarked", ProjectID: "proj", Status: TenantStatusSuspended})
	for _, id := range []string{byKey, bySecret} {
		_, err := f.svc.AdminSuspendTenant(ctx, key, "proj", id, "hold", "", "")
		require.NoError(t, err)
	}

	_, err = f.svc.AdminRestoreTenant(ctx, asAdmin(testAdminSecret), "proj", byKey, "lifted", "", "")
	require.ErrorIs(t, err, ErrTenantStatusConflict, "the admin secret's rule is unchanged")
	for _, id := range []string{bySecret, "t-unmarked"} {
		_, err := f.svc.AdminRestoreTenant(ctx, key, "proj", id, "lifted", "", "")
		require.ErrorIs(t, err, ErrTenantStatusConflict, id)
	}

	restored, err := f.svc.AdminRestoreTenant(ctx, key, "proj", byKey, "lifted", testOperatorIP, testOperatorUA)
	require.NoError(t, err)
	assert.Equal(t, TenantStatusClaimed, restored.Status)
	records := f.records.byEvent(string(audit.EventTenantRestored))
	require.Len(t, records, 1)
	assert.Equal(t, f.actor(), records[0].actor)
	assert.Equal(t, map[string]any{"project_id": "proj", "tenant_id": byKey, "reason": "lifted"}, records[0].details)
}
