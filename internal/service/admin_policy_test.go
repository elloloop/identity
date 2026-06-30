package service

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"
)

const policyAdminSecret = "policy-operator-secret"

func TestUpsertLoginPolicy_AuthorsAndAudits(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(policyAdminSecret)
	ctx := context.Background()

	got, err := f.svc.UpsertLoginPolicy(ctx, policyAdminSecret, &LoginPolicy{
		ProjectID:      "proj-1",
		TenantID:       "tenant-1",
		AllowedMethods: LoginMethodPassword + "," + LoginMethodEmailOTP,
		Require2FA:     true,
	})
	if err != nil {
		t.Fatalf("UpsertLoginPolicy: %v", err)
	}
	if got.AllowedMethods != LoginMethodPassword+","+LoginMethodEmailOTP {
		t.Fatalf("allowed methods = %q", got.AllowedMethods)
	}
	if !got.Require2FA {
		t.Fatal("require_2fa not persisted")
	}

	// Round-trips via Get and is observable by the enforcement read path.
	read, err := f.svc.GetLoginPolicy(ctx, policyAdminSecret, "proj-1", "tenant-1")
	if err != nil {
		t.Fatalf("GetLoginPolicy: %v", err)
	}
	if read == nil || !read.Require2FA {
		t.Fatalf("read-back policy = %+v", read)
	}

	if n := f.audit.countByEventType(string(audit.EventLoginPolicyUpserted)); n != 1 {
		t.Fatalf("login_policy_upserted events = %d, want 1", n)
	}
}

// The admin upsert must read the per-tenant password/session governance
// fields from the request and persist them — the regression for the bug where
// UpsertLoginPolicy silently zeroed PasswordMinLength and the two session
// timeouts on every upsert, making them un-authorable through the RPC.
func TestUpsertLoginPolicy_PreservesGovernanceFields(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(policyAdminSecret)
	ctx := context.Background()

	got, err := f.svc.UpsertLoginPolicy(ctx, policyAdminSecret, &LoginPolicy{
		ProjectID:                     "proj-1",
		TenantID:                      "tenant-1",
		AllowedMethods:                LoginMethodPassword,
		PasswordMinLength:             16,
		SessionIdleTimeoutSeconds:     900,
		SessionAbsoluteTimeoutSeconds: 86400,
	})
	if err != nil {
		t.Fatalf("UpsertLoginPolicy: %v", err)
	}
	if got.PasswordMinLength != 16 || got.SessionIdleTimeoutSeconds != 900 || got.SessionAbsoluteTimeoutSeconds != 86400 {
		t.Fatalf("returned policy dropped governance fields: %+v", got)
	}

	// They round-trip through the read path (the enforcement plane sees them).
	read, err := f.svc.GetLoginPolicy(ctx, policyAdminSecret, "proj-1", "tenant-1")
	if err != nil {
		t.Fatalf("GetLoginPolicy: %v", err)
	}
	if read.PasswordMinLength != 16 || read.SessionIdleTimeoutSeconds != 900 || read.SessionAbsoluteTimeoutSeconds != 86400 {
		t.Fatalf("read-back policy dropped governance fields: %+v", read)
	}

	// A replacing upsert with new values overwrites them (upsert is replace,
	// not merge) — proving the path actually carries the request values
	// rather than ignoring them.
	got2, err := f.svc.UpsertLoginPolicy(ctx, policyAdminSecret, &LoginPolicy{
		ProjectID: "proj-1", TenantID: "tenant-1", AllowedMethods: LoginMethodPassword,
		PasswordMinLength: 24,
	})
	if err != nil {
		t.Fatalf("second UpsertLoginPolicy: %v", err)
	}
	if got2.PasswordMinLength != 24 || got2.SessionIdleTimeoutSeconds != 0 || got2.SessionAbsoluteTimeoutSeconds != 0 {
		t.Fatalf("replacing upsert = %+v, want min=24 and zeroed timeouts", got2)
	}
}

// Negative governance values are rejected before any write.
func TestUpsertLoginPolicy_RejectsNegativeGovernance(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(policyAdminSecret)
	if _, err := f.svc.UpsertLoginPolicy(context.Background(), policyAdminSecret, &LoginPolicy{
		ProjectID: "p", TenantID: "t", PasswordMinLength: -1,
	}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

// A password_min_length above bcrypt's max byte length would make every
// password simultaneously too short and too long, locking the tenant out of
// all password signups/resets; the upsert must reject it.
func TestUpsertLoginPolicy_RejectsPasswordMinLengthAboveBcryptMax(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(policyAdminSecret)
	if _, err := f.svc.UpsertLoginPolicy(context.Background(), policyAdminSecret, &LoginPolicy{
		ProjectID: "p", TenantID: "t", PasswordMinLength: passwords.MaxPasswordLength + 1,
	}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
	// The bcrypt max itself stays valid (boundary check).
	if _, err := f.svc.UpsertLoginPolicy(context.Background(), policyAdminSecret, &LoginPolicy{
		ProjectID: "p", TenantID: "t", PasswordMinLength: passwords.MaxPasswordLength,
	}); err != nil {
		t.Fatalf("MaxPasswordLength must be accepted: %v", err)
	}
}

// An absurd session timeout would overflow the seconds→ms (*1000) conversion
// in the enforcement path and wrap negative, silently disabling the timeout;
// the upsert must reject values above maxSessionTimeoutSeconds.
func TestUpsertLoginPolicy_RejectsOverlargeSessionTimeout(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(policyAdminSecret)
	if _, err := f.svc.UpsertLoginPolicy(context.Background(), policyAdminSecret, &LoginPolicy{
		ProjectID: "p", TenantID: "t", SessionIdleTimeoutSeconds: maxSessionTimeoutSeconds + 1,
	}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("idle timeout: err = %v, want ErrInvalidArgument", err)
	}
	if _, err := f.svc.UpsertLoginPolicy(context.Background(), policyAdminSecret, &LoginPolicy{
		ProjectID: "p", TenantID: "t", SessionAbsoluteTimeoutSeconds: maxSessionTimeoutSeconds + 1,
	}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("absolute timeout: err = %v, want ErrInvalidArgument", err)
	}
	// The bound itself stays valid (boundary check).
	if _, err := f.svc.UpsertLoginPolicy(context.Background(), policyAdminSecret, &LoginPolicy{
		ProjectID: "p", TenantID: "t",
		SessionIdleTimeoutSeconds:     maxSessionTimeoutSeconds,
		SessionAbsoluteTimeoutSeconds: maxSessionTimeoutSeconds,
	}); err != nil {
		t.Fatalf("maxSessionTimeoutSeconds must be accepted: %v", err)
	}
}

func TestUpsertLoginPolicy_RejectsUnknownMethod(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(policyAdminSecret)
	_, err := f.svc.UpsertLoginPolicy(context.Background(), policyAdminSecret, &LoginPolicy{
		ProjectID:      "p",
		TenantID:       "t",
		AllowedMethods: "carrier-pigeon",
	})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestUpsertLoginPolicy_RequiresIDs(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(policyAdminSecret)
	if _, err := f.svc.UpsertLoginPolicy(context.Background(), policyAdminSecret, &LoginPolicy{TenantID: "t"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("missing project_id: err = %v", err)
	}
	if _, err := f.svc.UpsertLoginPolicy(context.Background(), policyAdminSecret, &LoginPolicy{ProjectID: "p"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("missing tenant_id: err = %v", err)
	}
}

func TestLoginPolicy_BadSecretDenied(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(policyAdminSecret)
	if _, err := f.svc.UpsertLoginPolicy(context.Background(), "wrong", &LoginPolicy{ProjectID: "p", TenantID: "t"}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("err = %v, want ErrPermissionDenied", err)
	}
	if _, err := f.svc.GetLoginPolicy(context.Background(), "wrong", "p", "t"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("get err = %v", err)
	}
	if err := f.svc.DeleteLoginPolicy(context.Background(), "wrong", "p", "t"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("delete err = %v", err)
	}
}

func TestLoginPolicy_DisabledWhenNoSecret(t *testing.T) {
	t.Parallel()
	f := newAdminFixture("")
	if _, err := f.svc.UpsertLoginPolicy(context.Background(), "x", &LoginPolicy{ProjectID: "p", TenantID: "t"}); !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("err = %v, want ErrUnimplemented", err)
	}
}

func TestLoginPolicy_UnimplementedWithoutStore(t *testing.T) {
	t.Parallel()
	// Wired with a nil policies store (the memory shape).
	svc := NewControlPlaneAdminService(policyAdminSecret, newFakeControlPlaneStore(), newFakeTenantStore(), newFakeMembershipStore(), nil, nil, nil, nil, nil)
	if _, err := svc.UpsertLoginPolicy(context.Background(), policyAdminSecret, &LoginPolicy{ProjectID: "p", TenantID: "t"}); !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("upsert err = %v, want ErrUnimplemented", err)
	}
	if _, err := svc.GetLoginPolicy(context.Background(), policyAdminSecret, "p", "t"); !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("get err = %v, want ErrUnimplemented", err)
	}
	if err := svc.DeleteLoginPolicy(context.Background(), policyAdminSecret, "p", "t"); !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("delete err = %v, want ErrUnimplemented", err)
	}
}

func TestDeleteLoginPolicy_ClearsAndAudits(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(policyAdminSecret)
	ctx := context.Background()

	if _, err := f.svc.UpsertLoginPolicy(ctx, policyAdminSecret, &LoginPolicy{ProjectID: "p", TenantID: "t", Require2FA: true}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := f.svc.DeleteLoginPolicy(ctx, policyAdminSecret, "p", "t"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got, err := f.svc.GetLoginPolicy(ctx, policyAdminSecret, "p", "t")
	if err != nil {
		t.Fatalf("get after delete: %v", err)
	}
	if got != nil {
		t.Fatalf("policy still present after delete: %+v", got)
	}
	// Idempotent re-delete is a no-op.
	if err := f.svc.DeleteLoginPolicy(ctx, policyAdminSecret, "p", "t"); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
	if n := f.audit.countByEventType(string(audit.EventLoginPolicyDeleted)); n != 2 {
		t.Fatalf("login_policy_deleted events = %d, want 2", n)
	}
}

func TestUpsertProjectConfig_RoundTripsAndAudits(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(policyAdminSecret)
	ctx := context.Background()
	// Seed a project so the config write targets an existing row.
	projectID, err := f.svc.AdminCreateProject(ctx, policyAdminSecret, "Kids", "scope-kids")
	if err != nil {
		t.Fatalf("AdminCreateProject: %v", err)
	}

	const cfg = `{"cors":{"allowed_origins":["https://kids.example.com"]}}`
	stored, err := f.svc.UpsertProjectConfig(ctx, policyAdminSecret, projectID, cfg)
	if err != nil {
		t.Fatalf("UpsertProjectConfig: %v", err)
	}
	if stored != cfg {
		t.Fatalf("stored = %q, want %q", stored, cfg)
	}

	read, err := f.svc.GetProjectConfig(ctx, policyAdminSecret, projectID)
	if err != nil {
		t.Fatalf("GetProjectConfig: %v", err)
	}
	if read != cfg {
		t.Fatalf("read = %q, want %q", read, cfg)
	}
	// The stored blob decodes to the typed config the resolver consumes.
	parsed, err := ParseProjectConfig(read)
	if err != nil {
		t.Fatalf("ParseProjectConfig: %v", err)
	}
	if len(parsed.CORS.AllowedOrigins) != 1 || parsed.CORS.AllowedOrigins[0] != "https://kids.example.com" {
		t.Fatalf("parsed config = %+v", parsed)
	}

	if n := f.audit.countByEventType(string(audit.EventProjectConfigUpdated)); n != 1 {
		t.Fatalf("project_config_updated events = %d, want 1", n)
	}
}

func TestUpsertProjectConfig_RejectsMalformed(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(policyAdminSecret)
	ctx := context.Background()
	projectID, err := f.svc.AdminCreateProject(ctx, policyAdminSecret, "P", "scope-p")
	if err != nil {
		t.Fatalf("AdminCreateProject: %v", err)
	}
	if _, err := f.svc.UpsertProjectConfig(ctx, policyAdminSecret, projectID, "{not json"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestUpsertProjectConfig_UnknownProject(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(policyAdminSecret)
	if _, err := f.svc.UpsertProjectConfig(context.Background(), policyAdminSecret, "no-such-project", "{}"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestProjectConfig_BadSecretDenied(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(policyAdminSecret)
	if _, err := f.svc.UpsertProjectConfig(context.Background(), "wrong", "p", "{}"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("upsert err = %v", err)
	}
	if _, err := f.svc.GetProjectConfig(context.Background(), "wrong", "p"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("get err = %v", err)
	}
}

func TestNormalizeAllowedMethods_DedupesAndCanonicalizes(t *testing.T) {
	t.Parallel()
	got, err := normalizeAllowedMethods(" Password , password ,EMAIL_OTP")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != LoginMethodPassword+","+LoginMethodEmailOTP {
		t.Fatalf("normalized = %q", got)
	}
	if empty, err := normalizeAllowedMethods("  "); err != nil || empty != "" {
		t.Fatalf("empty: got %q err %v", empty, err)
	}
}
