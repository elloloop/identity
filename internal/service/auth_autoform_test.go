package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeAutoFormer records EnsureTenantForDomain calls and can force an error.
type fakeAutoFormer struct {
	calls []autoFormCall
	err   error
}

type autoFormCall struct{ project, domain, user string }

func (f *fakeAutoFormer) EnsureTenantForDomain(_ context.Context, projectID, domain, userID string) (string, error) {
	f.calls = append(f.calls, autoFormCall{projectID, domain, userID})
	if f.err != nil {
		return "", f.err
	}
	return "tenant-" + domain, nil
}

var _ TenantAutoFormStore = (*fakeAutoFormer)(nil)

// withProject returns a context carrying a resolved project scope, so
// signup auto-formation has a project to attribute the tenant to. The project
// is open-access (these tests exercise tenant auto-formation, not the access
// gate), which under default-DENY must be set explicitly.
func withProject(projectID string) context.Context {
	return WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: projectID,
		Access:    ProjectAccessConfig{Mode: AccessModeOpen},
	})
}

// A signup with a company email domain auto-forms its tenant.
func TestPasswordSignup_AutoFormsTenant_ForCompanyDomain(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	af := &fakeAutoFormer{}
	svc.WithTenantAutoFormer(af)

	res, err := svc.PasswordSignup(withProject("proj-1"), "alice@acme.com", "Str0ng!Pass1", "Alice", "", 0)
	require.NoError(t, err)
	require.NotNil(t, res)

	require.Len(t, af.calls, 1)
	require.Equal(t, "proj-1", af.calls[0].project)
	require.Equal(t, "acme.com", af.calls[0].domain)
	require.Equal(t, res.User.ID, af.calls[0].user)
}

// A signup with a public/consumer email domain does NOT auto-form a tenant.
func TestPasswordSignup_SkipsAutoForm_ForPublicDomain(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	af := &fakeAutoFormer{}
	svc.WithTenantAutoFormer(af)

	_, err := svc.PasswordSignup(withProject("proj-1"), "bob@gmail.com", "Str0ng!Pass1", "Bob", "", 0)
	require.NoError(t, err)
	require.Empty(t, af.calls, "a public email domain must not auto-form a tenant")
}

// With no project resolved, there is nothing to attribute a tenant to.
func TestPasswordSignup_SkipsAutoForm_WhenNoProject(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	af := &fakeAutoFormer{}
	svc.WithTenantAutoFormer(af)
	// cfg.DefaultProjectID is empty in the test config and no scope is set.

	_, err := svc.PasswordSignup(context.Background(), "dana@acme.com", "Str0ng!Pass1", "Dana", "", 0)
	require.NoError(t, err)
	require.Empty(t, af.calls, "no resolved project → no auto-formation")
}

// Auto-formation is best-effort: a failure is swallowed and never fails the
// signup itself (the account already exists).
func TestPasswordSignup_AutoFormError_DoesNotFailSignup(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	af := &fakeAutoFormer{err: errors.New("boom")}
	svc.WithTenantAutoFormer(af)

	res, err := svc.PasswordSignup(withProject("proj-1"), "carol@acme.com", "Str0ng!Pass1", "Carol", "", 0)
	require.NoError(t, err, "auto-form failure must not fail signup")
	require.NotNil(t, res)
	require.Len(t, af.calls, 1)
}

// With no auto-former wired (memory), signup proceeds untouched.
func TestPasswordSignup_NoAutoFormer_NoOp(t *testing.T) {
	svc, _, _ := newAuthSvcWithMailer(t)
	// autoFormer left nil.

	res, err := svc.PasswordSignup(withProject("proj-1"), "erin@acme.com", "Str0ng!Pass1", "Erin", "", 0)
	require.NoError(t, err)
	require.NotNil(t, res)
}
