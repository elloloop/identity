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
// written under, holding a tenant_operator key of "proj" and the recovery
// fixture's tenant t-1 there, which a person created.
type tenantOperatorFixture struct {
	*adminFixture
	records *projectAuditWriter
	key     *MintedCredential
}

func newTenantOperatorFixture(t *testing.T, adminSecret string) *tenantOperatorFixture {
	t.Helper()
	f := newRecoveryFixture()
	f.tenants.put(&Tenant{ID: "t-1", ProjectID: "proj", Name: "Acme", Status: TenantStatusClaimed, CreatedBy: "gone", UpdatedAtMs: 7})
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
	for _, event := range []audit.EventType{
		audit.EventTenantSuspended, audit.EventTenantRestored, audit.EventTenantOwnershipRecovered, audit.EventTenantMemberRestored,
	} {
		records := f.records.byEvent(string(event))
		require.Len(t, records, 1, event)
		assert.Equal(t, "proj", records[0].project, event)
		assert.Equal(t, f.actor(), records[0].actor, event)
	}
	assert.Empty(t, f.records.byEvent(string(audit.EventTenantOperatorRefused)))
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
	require.NoError(t, f.svc.AdminRevokeProjectCredential(ctx, testAdminSecret, "proj", f.key.ID))
	_, err = f.svc.AdminGetTenant(ctx, asTenantOperator(f.key.RawKey), "proj", "t-1")
	require.ErrorIs(t, err, errTenantOperatorRefused)
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
	_, err := f.svc.AdminCreateTenant(ctx, f.key.RawKey, "proj", "New", "new.example")
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
