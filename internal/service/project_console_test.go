package service

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

const (
	testConsoleProject = "console-project"
	testOtherProject   = "acme-project"
	testConsoleOwner   = "user-owner"
	testConsoleMaxOwn  = 3
)

// fakeProjectMembers is an in-memory ProjectMemberStore.
type fakeProjectMembers struct {
	// byProject maps project id → user id → the project as that member sees it.
	byProject map[string]map[string]*MemberProject
	created   []OwnedProjectRequest
	createErr error
}

func newFakeProjectMembers() *fakeProjectMembers {
	return &fakeProjectMembers{byProject: map[string]map[string]*MemberProject{}}
}

func (f *fakeProjectMembers) add(projectID, userID, role string) {
	if f.byProject[projectID] == nil {
		f.byProject[projectID] = map[string]*MemberProject{}
	}
	f.byProject[projectID][userID] = &MemberProject{ID: projectID, Name: projectID, Role: role, PublishableKey: "pk_" + projectID}
}

func (f *fakeProjectMembers) CreateOwnedProject(_ context.Context, req OwnedProjectRequest) (*MemberProject, error) {
	f.created = append(f.created, req)
	if f.createErr != nil {
		return nil, f.createErr
	}
	p := &MemberProject{ID: "project-new", Name: req.Name, Role: ProjectRoleOwner, PublishableKey: req.PublishableKey, CreatedAtMs: req.NowMs}
	f.byProject[p.ID] = map[string]*MemberProject{req.OwnerID: p}
	return p, nil
}

func (f *fakeProjectMembers) ListMemberProjects(_ context.Context, userID string) ([]*MemberProject, error) {
	var out []*MemberProject
	for _, members := range f.byProject {
		if p, ok := members[userID]; ok {
			out = append(out, p)
		}
	}
	return out, nil
}

func (f *fakeProjectMembers) GetMemberProject(_ context.Context, projectID, userID string) (*MemberProject, error) {
	return f.byProject[projectID][userID], nil
}

// fakeProjectSettings is an in-memory ProjectSettingsStore with the store's
// compare-and-swap on the version.
type fakeProjectSettings struct {
	config  map[string]string
	version map[string]int64
	writes  int
}

func newFakeProjectSettings() *fakeProjectSettings {
	return &fakeProjectSettings{config: map[string]string{}, version: map[string]int64{}}
}

func (f *fakeProjectSettings) GetProjectConfig(_ context.Context, projectID string) (string, int64, error) {
	cfg, ok := f.config[projectID]
	if !ok {
		return "", 0, ErrNotFound
	}
	return cfg, f.version[projectID], nil
}

func (f *fakeProjectSettings) UpdateProjectConfig(_ context.Context, projectID string, expectedVersion int64, configJSON string) (string, int64, error) {
	if _, ok := f.config[projectID]; !ok {
		return "", 0, ErrNotFound
	}
	if f.version[projectID] != expectedVersion {
		return "", 0, ErrProjectConfigConflict
	}
	f.writes++
	f.config[projectID] = configJSON
	f.version[projectID]++
	return configJSON, f.version[projectID], nil
}

type consoleFixture struct {
	svc      *ProjectConsoleService
	members  *fakeProjectMembers
	settings *fakeProjectSettings
	users    *fakeUserDirectory
	audit    *recordingAuditWriter
}

// auditDetails decodes the details of the i-th recorded audit event.
func (f *consoleFixture) auditDetails(t *testing.T, i int) map[string]any {
	t.Helper()
	return decodeForTest(t, f.audit.details[i])
}

func newConsoleFixture(t *testing.T, selfService bool) *consoleFixture {
	t.Helper()
	f := &consoleFixture{
		members:  newFakeProjectMembers(),
		settings: newFakeProjectSettings(),
		users:    newFakeUserDirectory(),
		audit:    newRecordingAuditWriter(),
	}
	f.users.put(testConsoleProject, testConsoleOwner, "owner@example.com")
	f.svc = NewProjectConsoleService(
		ProjectConsoleConfig{
			ConsoleProjectID:      testConsoleProject,
			SelfServiceProjects:   selfService,
			MaxProjectsPerAccount: testConsoleMaxOwn,
		},
		f.members, f.settings, f.users, nil,
		audit.NewLogger(f.audit, testConsoleProject, zap.NewNop()), zap.NewNop(),
	)
	f.svc.nowFunc = func() time.Time { return time.UnixMilli(1_700_000_000_000) }
	return f
}

// consoleCtx is a request that resolved to the console project.
func consoleCtx() context.Context {
	return WithProjectScope(context.Background(), &ProjectScope{ProjectID: testConsoleProject})
}

// passwordSignIn is a session a password opened: one no recovery hold binds.
func passwordSignIn() SessionSignIn {
	return SessionSignIn{AMR: []string{"pwd"}, SessionID: "session-1"}
}

func TestProjectConsole_CreateProject(t *testing.T) {
	f := newConsoleFixture(t, true)

	project, err := f.svc.CreateProject(consoleCtx(), testConsoleOwner, passwordSignIn(), "  Acme Storefront  ", "203.0.113.7", "test-agent")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if project.Name != "Acme Storefront" || project.Role != ProjectRoleOwner {
		t.Errorf("project = %+v, want trimmed name and the owner role", project)
	}
	if len(f.members.created) != 1 {
		t.Fatalf("store creates = %d, want 1", len(f.members.created))
	}
	req := f.members.created[0]
	if req.OwnerID != testConsoleOwner || req.MaxOwned != testConsoleMaxOwn {
		t.Errorf("request = %+v, want the caller as owner under the configured limit", req)
	}
	if !strings.HasPrefix(req.PublishableKey, publishableKeyPrefix) || len(req.PublishableKey) <= len(publishableKeyPrefix) {
		t.Errorf("publishable key = %q, want a %s key", req.PublishableKey, publishableKeyPrefix)
	}
	if !reflect.DeepEqual(f.audit.events, []string{string(audit.EventProjectCreated)}) {
		t.Fatalf("audit events = %v, want [project_created]", f.audit.events)
	}
	if !f.audit.successes[0] || f.audit.actors[0] != testConsoleOwner || f.auditDetails(t, 0)["project_id"] != project.ID {
		t.Errorf("audit = success %v actor %q details %s, want a successful project_created by the caller naming the project",
			f.audit.successes[0], f.audit.actors[0], f.audit.details[0])
	}
	if got := f.audit.clientsOf(string(audit.EventProjectCreated)); !reflect.DeepEqual(got, [][2]string{{"203.0.113.7", "test-agent"}}) {
		t.Errorf("audit client = %v, want the caller's address and user agent", got)
	}
}

func TestProjectConsole_CreateProject_Refusals(t *testing.T) {
	t.Run("self-service off", func(t *testing.T) {
		f := newConsoleFixture(t, false)
		_, err := f.svc.CreateProject(consoleCtx(), testConsoleOwner, passwordSignIn(), "Acme", "", "")
		if !errors.Is(err, ErrSelfServiceProjectsDisabled) {
			t.Fatalf("err = %v, want ErrSelfServiceProjectsDisabled", err)
		}
		if len(f.members.created) != 0 {
			t.Error("a project was created with self-service off")
		}
	})
	t.Run("blank name", func(t *testing.T) {
		f := newConsoleFixture(t, true)
		if _, err := f.svc.CreateProject(consoleCtx(), testConsoleOwner, passwordSignIn(), "   ", "", ""); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("err = %v, want ErrInvalidArgument", err)
		}
	})
	t.Run("name too long", func(t *testing.T) {
		f := newConsoleFixture(t, true)
		name := strings.Repeat("a", projectNameMaxRunes+1)
		if _, err := f.svc.CreateProject(consoleCtx(), testConsoleOwner, passwordSignIn(), name, "", ""); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("err = %v, want ErrInvalidArgument", err)
		}
	})
	t.Run("limit reached is audited as a failure", func(t *testing.T) {
		f := newConsoleFixture(t, true)
		f.members.createErr = ErrProjectCreationLimited
		if _, err := f.svc.CreateProject(consoleCtx(), testConsoleOwner, passwordSignIn(), "Acme", "", ""); !errors.Is(err, ErrProjectCreationLimited) {
			t.Fatalf("err = %v, want ErrProjectCreationLimited", err)
		}
		if len(f.audit.events) != 1 || f.audit.successes[0] || f.auditDetails(t, 0)["reason"] != auditReasonProjectLimit {
			t.Errorf("audit = %v success %v details %v, want one failed project_created with the limit reason",
				f.audit.events, f.audit.successes, f.audit.details)
		}
	})
}

// Every console RPC admits only a signed-in, active person of the console
// project whose email is verified.
func TestProjectConsole_AdmitsOnlyConsoleAccounts(t *testing.T) {
	cases := []struct {
		name    string
		ctx     context.Context
		caller  string
		prepare func(f *consoleFixture)
		want    error
	}{
		{name: "no session", ctx: consoleCtx(), caller: "", want: ErrUnauthenticated},
		{name: "no project scope", ctx: context.Background(), caller: testConsoleOwner, want: ErrPermissionDenied},
		{
			name: "token of another project", caller: testConsoleOwner, want: ErrPermissionDenied,
			ctx: WithProjectScope(context.Background(), &ProjectScope{ProjectID: testOtherProject}),
			prepare: func(f *consoleFixture) {
				// The same id exists in the other project: it must not be read
				// as the console account of that id.
				f.users.put(testOtherProject, testConsoleOwner, "someone@example.com")
			},
		},
		{name: "unknown account", ctx: consoleCtx(), caller: "user-missing", want: ErrPermissionDenied},
		{
			name: "unverified email", ctx: consoleCtx(), caller: "user-unverified", want: ErrEmailVerificationRequired,
			prepare: func(f *consoleFixture) {
				f.users.set(testConsoleProject, &User{ID: "user-unverified", Email: "new@example.com"})
			},
		},
		{
			name: "deactivated account", ctx: consoleCtx(), caller: "user-off", want: ErrPermissionDenied,
			prepare: func(f *consoleFixture) {
				f.users.set(testConsoleProject, &User{ID: "user-off", Email: "off@example.com", EmailVerified: true, Status: StatusDeactivated})
			},
		},
		{
			name: "anonymous account", ctx: consoleCtx(), caller: "user-anon", want: ErrPermissionDenied,
			prepare: func(f *consoleFixture) {
				f.users.set(testConsoleProject, &User{ID: "user-anon", IsAnonymous: true})
			},
		},
		{
			name: "tenant-managed account", ctx: consoleCtx(), caller: "user-managed", want: ErrManagedAccount,
			prepare: func(f *consoleFixture) {
				f.users.set(testConsoleProject, &User{ID: "user-managed", Email: "m@acme.example", EmailVerified: true, ManagedByTenantID: "tenant-1"})
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newConsoleFixture(t, true)
			f.members.add(testOtherProject, tc.caller, ProjectRoleOwner)
			f.settings.config[testOtherProject] = `{}`
			if tc.prepare != nil {
				tc.prepare(f)
			}
			calls := map[string]func() error{
				"CreateProject": func() error {
					_, err := f.svc.CreateProject(tc.ctx, tc.caller, passwordSignIn(), "Acme", "", "")
					return err
				},
				"ListMyProjects": func() error {
					_, err := f.svc.ListMyProjects(tc.ctx, tc.caller)
					return err
				},
				"GetProjectSettings": func() error {
					_, _, err := f.svc.GetProjectSettings(tc.ctx, tc.caller, testOtherProject)
					return err
				},
				"UpdateProjectSettings": func() error {
					_, _, err := f.svc.UpdateProjectSettings(tc.ctx, tc.caller, passwordSignIn(), testOtherProject, `{"access":{"mode":"open"}}`, 0, "", "")
					return err
				},
			}
			for name, call := range calls {
				if err := call(); !errors.Is(err, tc.want) {
					t.Errorf("%s: err = %v, want %v", name, err, tc.want)
				}
			}
			if len(f.members.created) != 0 || f.settings.writes != 0 {
				t.Errorf("a refused caller changed state: creates=%d writes=%d", len(f.members.created), f.settings.writes)
			}
		})
	}
}

// A change outlasts the session that made it, so a session that may have
// been opened by a recovery email is checked against its hold: with no way
// to read the hold the change fails closed, while reads are not held.
func TestProjectConsole_ChangesAreFencedToUnheldSessions(t *testing.T) {
	f := newConsoleFixture(t, true)
	f.members.add(testOtherProject, testConsoleOwner, ProjectRoleOwner)
	f.settings.config[testOtherProject] = `{}`
	recovery := SessionSignIn{AMR: []string{AMRRecoveryEmail}, RecoveryEmailID: "recovery-1", SessionID: "session-2"}

	if _, err := f.svc.CreateProject(consoleCtx(), testConsoleOwner, recovery, "Acme", "", ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("CreateProject: err = %v, want ErrServiceUnavailable", err)
	}
	if _, _, err := f.svc.UpdateProjectSettings(consoleCtx(), testConsoleOwner, recovery, testOtherProject, `{"access":{"mode":"open"}}`, 0, "", ""); !errors.Is(err, ErrServiceUnavailable) {
		t.Errorf("UpdateProjectSettings: err = %v, want ErrServiceUnavailable", err)
	}
	if len(f.members.created) != 0 || f.settings.writes != 0 {
		t.Errorf("a held session changed state: creates=%d writes=%d", len(f.members.created), f.settings.writes)
	}
	if _, err := f.svc.ListMyProjects(consoleCtx(), testConsoleOwner); err != nil {
		t.Errorf("ListMyProjects: %v", err)
	}
}

func TestProjectConsole_ListMyProjects(t *testing.T) {
	f := newConsoleFixture(t, true)
	f.members.add("project-a", testConsoleOwner, ProjectRoleOwner)
	f.members.add("project-b", "user-someone-else", ProjectRoleOwner)

	projects, err := f.svc.ListMyProjects(consoleCtx(), testConsoleOwner)
	if err != nil {
		t.Fatalf("ListMyProjects: %v", err)
	}
	if len(projects) != 1 || projects[0].ID != "project-a" {
		t.Fatalf("projects = %+v, want only project-a", projects)
	}
}

// A project the caller does not belong to is refused exactly as one that
// does not exist.
func TestProjectConsole_SettingsRefuseNonMembers(t *testing.T) {
	f := newConsoleFixture(t, true)
	f.members.add("project-theirs", "user-someone-else", ProjectRoleOwner)
	f.settings.config["project-theirs"] = `{"access":{"mode":"closed"}}`

	var refusals []string
	for _, projectID := range []string{"project-theirs", "project-missing"} {
		_, _, err := f.svc.GetProjectSettings(consoleCtx(), testConsoleOwner, projectID)
		if !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("GetProjectSettings(%s): err = %v, want ErrPermissionDenied", projectID, err)
		}
		refusals = append(refusals, err.Error())
		_, _, err = f.svc.UpdateProjectSettings(consoleCtx(), testConsoleOwner, passwordSignIn(), projectID, `{"access":{"mode":"open"}}`, 0, "", "")
		if !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("UpdateProjectSettings(%s): err = %v, want ErrPermissionDenied", projectID, err)
		}
	}
	if refusals[0] != refusals[1] {
		t.Errorf("refusals differ: %q vs %q", refusals[0], refusals[1])
	}
	if f.settings.config["project-theirs"] != `{"access":{"mode":"closed"}}` {
		t.Error("a non-member changed the project's config")
	}
	if _, _, err := f.svc.GetProjectSettings(consoleCtx(), testConsoleOwner, "  "); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("blank project_id: err = %v, want ErrInvalidArgument", err)
	}
}

func TestProjectConsole_GetAndUpdateSettings(t *testing.T) {
	f := newConsoleFixture(t, true)
	const projectID = "project-a"
	f.members.add(projectID, testConsoleOwner, ProjectRoleAdmin)
	f.settings.config[projectID] = `{"oauth":{"hub":true},"accounts":{"domain":"accounts.example.com"},"tenants":{"self_service":false}}`
	f.settings.version[projectID] = 4

	settings, version, err := f.svc.GetProjectSettings(consoleCtx(), testConsoleOwner, projectID)
	if err != nil {
		t.Fatalf("GetProjectSettings: %v", err)
	}
	if version != 4 {
		t.Errorf("version = %d, want 4", version)
	}
	if want := map[string]any{"tenants": map[string]any{"self_service": false}}; !reflect.DeepEqual(decodeForTest(t, settings), want) {
		t.Fatalf("settings = %s, want %v: the operator's sections are not a member's to read", settings, want)
	}

	stored, version, err := f.svc.UpdateProjectSettings(
		consoleCtx(), testConsoleOwner, passwordSignIn(), projectID,
		`{"access":{"mode":"open"},"tenants":{"self_service":true}}`, 4, "203.0.113.7", "test-agent",
	)
	if err != nil {
		t.Fatalf("UpdateProjectSettings: %v", err)
	}
	if version != 5 {
		t.Errorf("version = %d, want 5", version)
	}
	wantSettings := map[string]any{
		"access":  map[string]any{"mode": "open"},
		"tenants": map[string]any{"self_service": true},
	}
	if !reflect.DeepEqual(decodeForTest(t, stored), wantSettings) {
		t.Fatalf("returned settings = %s, want %v", stored, wantSettings)
	}
	wantConfig := map[string]any{
		"oauth":    map[string]any{"hub": true},
		"accounts": map[string]any{"domain": "accounts.example.com"},
		"access":   map[string]any{"mode": "open"},
		"tenants":  map[string]any{"self_service": true},
	}
	if !reflect.DeepEqual(decodeForTest(t, f.settings.config[projectID]), wantConfig) {
		t.Fatalf("stored config = %s, want %v", f.settings.config[projectID], wantConfig)
	}
	if !reflect.DeepEqual(f.audit.events, []string{string(audit.EventProjectSettingsUpdated)}) {
		t.Fatalf("audit events = %v, want [project_settings_updated]", f.audit.events)
	}
	details := f.auditDetails(t, 0)
	if details["project_id"] != projectID || !reflect.DeepEqual(details["sections"], []any{"access", "tenants"}) {
		t.Errorf("audit details = %v, want the project and the sections changed", details)
	}
	if strings.Contains(f.audit.details[0], "open") {
		t.Errorf("audit details carry a setting's value: %s", f.audit.details[0])
	}
}

func TestProjectConsole_UpdateSettings_Refusals(t *testing.T) {
	const projectID = "project-a"
	const stored = `{"access":{"mode":"closed"}}`
	cases := []struct {
		name     string
		settings string
		version  int64
		want     error
	}{
		{name: "stale version", settings: `{"access":{"mode":"open"}}`, version: 1, want: ErrProjectConfigConflict},
		{name: "operator section", settings: `{"oauth":{"hub":true}}`, version: 2, want: ErrInvalidArgument},
		{name: "config rules refuse the result", settings: `{"access":{"mode":"no-such-mode"}}`, version: 2, want: ErrInvalidArgument},
		{name: "invalid cors origin", settings: `{"cors":{"allowed_origins":["not a url"]}}`, version: 2, want: ErrInvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newConsoleFixture(t, true)
			f.members.add(projectID, testConsoleOwner, ProjectRoleOwner)
			f.settings.config[projectID] = stored
			f.settings.version[projectID] = 2

			_, _, err := f.svc.UpdateProjectSettings(consoleCtx(), testConsoleOwner, passwordSignIn(), projectID, tc.settings, tc.version, "", "")
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if f.settings.config[projectID] != stored || f.settings.writes != 0 {
				t.Errorf("a refused update changed the config: %s", f.settings.config[projectID])
			}
			if len(f.audit.events) != 0 {
				t.Errorf("a refused update was audited as a change: %v", f.audit.events)
			}
		})
	}
}
