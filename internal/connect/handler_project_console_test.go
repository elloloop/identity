package connect

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/service"
)

const (
	consoleTestProject = "console-project"
	consoleTestOwner   = "user-owner"
	consoleTestLimit   = 2
	// consoleTestPasswordAMR marks a session a password opened, which no
	// recovery hold binds.
	consoleTestPasswordAMR = "pwd"
)

// consoleStore is an in-memory ProjectMemberStore and ProjectSettingsStore
// for the console handler tests: one owner per project, a per-owner limit,
// and the config store's compare-and-swap.
type consoleStore struct {
	projects []*service.MemberProject
	owners   map[string]string
	config   map[string]string
	version  map[string]int64
}

func newConsoleStore() *consoleStore {
	return &consoleStore{owners: map[string]string{}, config: map[string]string{}, version: map[string]int64{}}
}

func (s *consoleStore) CreateOwnedProject(_ context.Context, req service.OwnedProjectRequest) (*service.MemberProject, error) {
	owned := 0
	for _, owner := range s.owners {
		if owner == req.OwnerID {
			owned++
		}
	}
	if owned >= req.MaxOwned {
		return nil, service.ErrProjectCreationLimited
	}
	p := &service.MemberProject{
		ID: "project-" + req.PublishableKey, Name: req.Name, Role: service.ProjectRoleOwner,
		PublishableKey: req.PublishableKey, CreatedAtMs: req.NowMs,
	}
	s.projects = append(s.projects, p)
	s.owners[p.ID] = req.OwnerID
	s.config[p.ID] = "{}"
	return p, nil
}

func (s *consoleStore) ListMemberProjects(_ context.Context, userID string) ([]*service.MemberProject, error) {
	var out []*service.MemberProject
	for _, p := range s.projects {
		if s.owners[p.ID] == userID {
			out = append(out, p)
		}
	}
	return out, nil
}

func (s *consoleStore) GetMemberProject(_ context.Context, projectID, userID string) (*service.MemberProject, error) {
	for _, p := range s.projects {
		if p.ID == projectID && s.owners[p.ID] == userID {
			return p, nil
		}
	}
	return nil, nil
}

func (s *consoleStore) GetProjectConfig(_ context.Context, projectID string) (string, int64, error) {
	return s.config[projectID], s.version[projectID], nil
}

func (s *consoleStore) UpdateProjectConfig(_ context.Context, projectID string, expectedVersion int64, configJSON string) (string, int64, error) {
	if s.version[projectID] != expectedVersion {
		return "", 0, service.ErrProjectConfigConflict
	}
	s.config[projectID] = configJSON
	s.version[projectID]++
	return configJSON, s.version[projectID], nil
}

// consoleUsers is a UserDirectory of console accounts.
type consoleUsers map[string]*service.User

func (u consoleUsers) GetUserInProject(_ context.Context, projectID, userID string) (*service.User, error) {
	if projectID != consoleTestProject {
		return nil, nil
	}
	return u[userID], nil
}

func newConsoleHandler(selfService bool) (*IdentityHandler, *consoleStore) {
	store := newConsoleStore()
	users := consoleUsers{
		consoleTestOwner:  {ID: consoleTestOwner, Email: "owner@example.com", EmailVerified: true},
		"user-unverified": {ID: "user-unverified", Email: "new@example.com"},
		"user-other":      {ID: "user-other", Email: "other@example.com", EmailVerified: true},
	}
	svc := service.NewProjectConsoleService(
		service.ProjectConsoleConfig{
			ConsoleProjectID: consoleTestProject, SelfServiceProjects: selfService, MaxProjectsPerAccount: consoleTestLimit,
		},
		store, store, users, nil, nil, nil,
	)
	h := NewIdentityHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, testConfig()).WithProjectConsole(svc)
	return h, store
}

// consoleRequest is an authenticated request from a session a password
// opened, as the auth middleware would have marked it.
func consoleRequest[T any](msg *T, userID string) *connect.Request[T] {
	req := withAuth(msg, userID)
	req.Header().Set(middleware.AuthenticatedAMRHeader, consoleTestPasswordAMR)
	return req
}

func consoleContext() context.Context {
	return service.WithProjectScope(context.Background(), &service.ProjectScope{ProjectID: consoleTestProject})
}

func TestProjectConsoleRPCs_NoConsole_ReturnUnimplemented(t *testing.T) {
	t.Parallel()
	h := NewIdentityHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, testConfig())
	ctx := consoleContext()

	_, err := h.CreateProject(ctx, consoleRequest(&identitypb.CreateProjectRequest{Name: "Acme"}, consoleTestOwner))
	requireCode(t, err, connect.CodeUnimplemented)
	_, err = h.ListMyProjects(ctx, consoleRequest(&identitypb.ListMyProjectsRequest{}, consoleTestOwner))
	requireCode(t, err, connect.CodeUnimplemented)
	_, err = h.GetProjectSettings(ctx, consoleRequest(&identitypb.GetProjectSettingsRequest{ProjectId: "p"}, consoleTestOwner))
	requireCode(t, err, connect.CodeUnimplemented)
	_, err = h.UpdateProjectSettings(ctx, consoleRequest(&identitypb.UpdateProjectSettingsRequest{ProjectId: "p"}, consoleTestOwner))
	requireCode(t, err, connect.CodeUnimplemented)
}

func TestProjectConsoleRPCs_NoSession_ReturnUnauthenticated(t *testing.T) {
	t.Parallel()
	h, _ := newConsoleHandler(true)
	ctx := consoleContext()

	_, err := h.CreateProject(ctx, connect.NewRequest(&identitypb.CreateProjectRequest{Name: "Acme"}))
	requireCode(t, err, connect.CodeUnauthenticated)
	_, err = h.ListMyProjects(ctx, connect.NewRequest(&identitypb.ListMyProjectsRequest{}))
	requireCode(t, err, connect.CodeUnauthenticated)
	_, err = h.GetProjectSettings(ctx, connect.NewRequest(&identitypb.GetProjectSettingsRequest{ProjectId: "p"}))
	requireCode(t, err, connect.CodeUnauthenticated)
	_, err = h.UpdateProjectSettings(ctx, connect.NewRequest(&identitypb.UpdateProjectSettingsRequest{ProjectId: "p"}))
	requireCode(t, err, connect.CodeUnauthenticated)
}

// TestProjectConsoleRPCs_OwnerManagesAProject walks the console's whole
// path: create a project, see it listed, read its settings and change them.
func TestProjectConsoleRPCs_OwnerManagesAProject(t *testing.T) {
	t.Parallel()
	h, store := newConsoleHandler(true)
	ctx := consoleContext()

	created, err := h.CreateProject(ctx, consoleRequest(&identitypb.CreateProjectRequest{Name: " Acme Storefront "}, consoleTestOwner))
	require.NoError(t, err)
	project := created.Msg.GetProject()
	assert.Equal(t, "Acme Storefront", project.GetName())
	assert.Equal(t, service.ProjectRoleOwner, project.GetRole())
	assert.NotEmpty(t, project.GetPublishableKey())
	assert.NotNil(t, project.GetCreatedAt())

	listed, err := h.ListMyProjects(ctx, consoleRequest(&identitypb.ListMyProjectsRequest{}, consoleTestOwner))
	require.NoError(t, err)
	assert.True(t, listed.Msg.GetCanCreateProject())
	require.Len(t, listed.Msg.GetProjects(), 1)
	assert.Equal(t, project.GetProjectId(), listed.Msg.GetProjects()[0].GetProjectId())
	assert.Equal(t, project.GetPublishableKey(), listed.Msg.GetProjects()[0].GetPublishableKey())

	read, err := h.GetProjectSettings(ctx, consoleRequest(&identitypb.GetProjectSettingsRequest{ProjectId: project.GetProjectId()}, consoleTestOwner))
	require.NoError(t, err)
	assert.JSONEq(t, "{}", read.Msg.GetSettingsJson(), "a new project has no settings: no access mode, so it admits nobody")

	updated, err := h.UpdateProjectSettings(ctx, consoleRequest(&identitypb.UpdateProjectSettingsRequest{
		ProjectId:       project.GetProjectId(),
		SettingsJson:    `{"access":{"mode":"open"},"tenants":{"self_service":true}}`,
		ExpectedVersion: read.Msg.GetVersion(),
	}, consoleTestOwner))
	require.NoError(t, err)
	assert.JSONEq(t, `{"access":{"mode":"open"},"tenants":{"self_service":true}}`, updated.Msg.GetSettingsJson())
	assert.Equal(t, read.Msg.GetVersion()+1, updated.Msg.GetVersion())
	assert.JSONEq(t, `{"access":{"mode":"open"},"tenants":{"self_service":true}}`, store.config[project.GetProjectId()])
}

func TestProjectConsoleRPCs_RefusalCodes(t *testing.T) {
	t.Parallel()
	ctx := consoleContext()

	t.Run("creation off is FailedPrecondition and the list says so", func(t *testing.T) {
		t.Parallel()
		h, _ := newConsoleHandler(false)
		_, err := h.CreateProject(ctx, consoleRequest(&identitypb.CreateProjectRequest{Name: "Acme"}, consoleTestOwner))
		requireCode(t, err, connect.CodeFailedPrecondition)
		listed, err := h.ListMyProjects(ctx, consoleRequest(&identitypb.ListMyProjectsRequest{}, consoleTestOwner))
		require.NoError(t, err)
		assert.False(t, listed.Msg.GetCanCreateProject())
	})

	t.Run("past the project limit is ResourceExhausted", func(t *testing.T) {
		t.Parallel()
		h, _ := newConsoleHandler(true)
		for range consoleTestLimit {
			_, err := h.CreateProject(ctx, consoleRequest(&identitypb.CreateProjectRequest{Name: "Acme"}, consoleTestOwner))
			require.NoError(t, err)
		}
		_, err := h.CreateProject(ctx, consoleRequest(&identitypb.CreateProjectRequest{Name: "Acme"}, consoleTestOwner))
		requireCode(t, err, connect.CodeResourceExhausted)
	})

	t.Run("a blank name is InvalidArgument", func(t *testing.T) {
		t.Parallel()
		h, _ := newConsoleHandler(true)
		_, err := h.CreateProject(ctx, consoleRequest(&identitypb.CreateProjectRequest{Name: "  "}, consoleTestOwner))
		requireCode(t, err, connect.CodeInvalidArgument)
	})

	t.Run("an unverified account is FailedPrecondition", func(t *testing.T) {
		t.Parallel()
		h, _ := newConsoleHandler(true)
		_, err := h.ListMyProjects(ctx, consoleRequest(&identitypb.ListMyProjectsRequest{}, "user-unverified"))
		requireCode(t, err, connect.CodeFailedPrecondition)
	})

	t.Run("a token of another project is PermissionDenied", func(t *testing.T) {
		t.Parallel()
		h, _ := newConsoleHandler(true)
		elsewhere := service.WithProjectScope(context.Background(), &service.ProjectScope{ProjectID: "acme-project"})
		_, err := h.ListMyProjects(elsewhere, consoleRequest(&identitypb.ListMyProjectsRequest{}, consoleTestOwner))
		requireCode(t, err, connect.CodePermissionDenied)
	})

	t.Run("settings of someone else's project", func(t *testing.T) {
		t.Parallel()
		h, store := newConsoleHandler(true)
		created, err := h.CreateProject(ctx, consoleRequest(&identitypb.CreateProjectRequest{Name: "Acme"}, consoleTestOwner))
		require.NoError(t, err)
		projectID := created.Msg.GetProject().GetProjectId()

		_, err = h.GetProjectSettings(ctx, consoleRequest(&identitypb.GetProjectSettingsRequest{ProjectId: projectID}, "user-other"))
		requireCode(t, err, connect.CodePermissionDenied)
		_, err = h.UpdateProjectSettings(ctx, consoleRequest(&identitypb.UpdateProjectSettingsRequest{
			ProjectId: projectID, SettingsJson: `{"access":{"mode":"open"}}`,
		}, "user-other"))
		requireCode(t, err, connect.CodePermissionDenied)
		assert.JSONEq(t, "{}", store.config[projectID])
	})

	t.Run("update refusals", func(t *testing.T) {
		t.Parallel()
		h, store := newConsoleHandler(true)
		created, err := h.CreateProject(ctx, consoleRequest(&identitypb.CreateProjectRequest{Name: "Acme"}, consoleTestOwner))
		require.NoError(t, err)
		projectID := created.Msg.GetProject().GetProjectId()
		update := func(settings string, version int64) error {
			_, err := h.UpdateProjectSettings(ctx, consoleRequest(&identitypb.UpdateProjectSettingsRequest{
				ProjectId: projectID, SettingsJson: settings, ExpectedVersion: version,
			}, consoleTestOwner))
			return err
		}
		requireCode(t, update(`{"access":{"mode":"open"}}`, 7), connect.CodeAborted)
		requireCode(t, update(`{"oauth":{"hub":true}}`, 0), connect.CodeInvalidArgument)
		requireCode(t, update(`{"accounts":{"domain":"example.com"}}`, 0), connect.CodeInvalidArgument)
		requireCode(t, update(`{"access":{"mode":"no-such-mode"}}`, 0), connect.CodeInvalidArgument)
		requireCode(t, update(``, 0), connect.CodeInvalidArgument)
		assert.JSONEq(t, "{}", store.config[projectID], "no refused update reached the store")
	})

	t.Run("a section the stored config spells two ways is FailedPrecondition", func(t *testing.T) {
		t.Parallel()
		h, store := newConsoleHandler(true)
		created, err := h.CreateProject(ctx, consoleRequest(&identitypb.CreateProjectRequest{Name: "Acme"}, consoleTestOwner))
		require.NoError(t, err)
		projectID := created.Msg.GetProject().GetProjectId()
		const stored = `{"Accounts":{"domain":"accounts.example.com"},"accounts":{"email_signup":"self"}}`
		store.config[projectID] = stored

		_, err = h.UpdateProjectSettings(ctx, consoleRequest(&identitypb.UpdateProjectSettingsRequest{
			ProjectId: projectID, SettingsJson: `{"accounts":{"email_signup":"admin"}}`,
		}, consoleTestOwner))
		requireCode(t, err, connect.CodeFailedPrecondition)
		assert.Equal(t, stored, store.config[projectID], "the refused write left the config as it was")
	})
}
