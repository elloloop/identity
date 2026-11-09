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
// fixture's tenant t-1 there, which a person created, and "aide", an account
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
// each made on tenant t-1 of project.
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
		_, err := svc.AdminAddTenantAdmin(context.Background(), caller, project, "t-1", "aide", RoleAdmin, testOperatorIP, testOperatorUA)
		return err
	}},
}

// requireNothingCreated fails unless the fixture still holds only the
// tenants it was given, n of them, and "aide" holds no membership.
func (f *tenantOperatorFixture) requireNothingCreated(t *testing.T, n int, msgAndArgs ...any) {
	t.Helper()
	assert.Len(t, f.tenants.byID, n, msgAndArgs...)
	m, _ := f.members.GetMembership(context.Background(), "proj", "t-1", "aide")
	assert.Nil(t, m, msgAndArgs...)
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
	aide, _ := f.members.GetMembership(ctx, "proj", "t-1", "aide")
	require.NotNil(t, aide)
	assert.Equal(t, RoleAdmin, aide.Role)
	assert.Equal(t, MembershipSourceAdded, aide.Source)
	page, err := f.svc.AdminListTenants(ctx, asTenantOperator(f.key.RawKey), "proj", 0, "")
	require.NoError(t, err)
	require.Len(t, page.Tenants, 2)
	for _, event := range []audit.EventType{
		audit.EventTenantSuspended, audit.EventTenantRestored, audit.EventTenantOwnershipRecovered, audit.EventTenantMemberRestored,
		audit.EventTenantCreated, audit.EventTenantAdminAdded,
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
		if tn.ID != "t-1" {
			createdID = tn.ID
		}
	}
	assert.Equal(t, map[string]any{"project_id": "proj", "tenant_id": createdID}, created.details)
	assert.Equal(t, map[string]any{"project_id": "proj", "tenant_id": "t-1", "role": RoleAdmin},
		f.records.byEvent(string(audit.EventTenantAdminAdded))[0].details)
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
	f.requireNothingCreated(t, 2)
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
		f.requireNothingCreated(t, 1, name)
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
	_, err = f.svc.AdminAddTenantAdmin(ctx, asTenantOperator(f.key.RawKey), "proj", "t-1", "aide", RoleOwner, "", "")
	require.ErrorIs(t, err, errTenantOperatorRefused)
	f.requireNothingCreated(t, 2, "only the tenant made before the revocation")
	assert.Len(t, f.records.byEvent(string(audit.EventTenantCreated)), 1)
	assert.Empty(t, f.records.byEvent(string(audit.EventTenantAdminAdded)))
}

// A key's AdminAddTenantAdmin must name a tenant and an account of its own
// project, so it writes no membership that reaches another project. The
// admin secret is not held to it.
func TestTenantOperator_AddTenantAdminStaysInItsProject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantOperatorFixture(t, testAdminSecret)
	f.tenants.put(&Tenant{ID: "t-other", ProjectID: "other", Status: TenantStatusClaimed})
	f.users.set("other", &User{ID: "outsider", Email: "o@example.test", Status: StatusActive, EmailVerified: true})
	for name, ref := range map[string]struct{ tenant, user string }{
		"another project's tenant":  {"t-other", "aide"},
		"another project's account": {"t-1", "outsider"},
		"no such account":           {"t-1", "nobody"},
		"no such tenant":            {"t-none", "aide"},
	} {
		_, err := f.svc.AdminAddTenantAdmin(ctx, asTenantOperator(f.key.RawKey), "proj", ref.tenant, ref.user, RoleOwner, "", "")
		require.ErrorIs(t, err, ErrNotFound, name)
		m, _ := f.members.GetMembership(ctx, "proj", ref.tenant, ref.user)
		assert.Nil(t, m, name)
	}
	assert.Empty(t, f.records.byEvent(string(audit.EventTenantAdminAdded)))

	_, err := f.svc.AdminAddTenantAdmin(ctx, asAdmin(testAdminSecret), "proj", "t-1", "outsider", RoleOwner, "", "")
	require.NoError(t, err)
	m, _ := f.members.GetMembership(ctx, "proj", "t-1", "outsider")
	require.NotNil(t, m)
	assert.Equal(t, RoleOwner, m.Role)
}

// A failed read of the tenant or the account is the store's error.
func TestTenantOperator_AddTenantAdminReadErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	boom := errors.New("read failed")
	f := newTenantOperatorFixture(t, testAdminSecret)
	f.tenants.getErr = boom
	_, err := f.svc.AdminAddTenantAdmin(ctx, asTenantOperator(f.key.RawKey), "proj", "t-1", "aide", RoleOwner, "", "")
	require.ErrorIs(t, err, boom)

	f = newTenantOperatorFixture(t, testAdminSecret)
	f.users.getErr = boom
	_, err = f.svc.AdminAddTenantAdmin(ctx, asTenantOperator(f.key.RawKey), "proj", "t-1", "aide", RoleOwner, "", "")
	require.ErrorIs(t, err, boom)
	f.requireNothingCreated(t, 1)
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
