package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/app/ui"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/service"
)

const wiringDefaultProject = "default"

// stubProjectMemberStore satisfies service.ProjectMemberStore so
// buildProjectConsole's non-nil check passes. Its methods are never called.
type stubProjectMemberStore struct {
	service.ProjectMemberStore
}

func consoleDeps(cfg *config.Config) Deps {
	return Deps{
		Config:             cfg,
		ControlPlaneStore:  &stubControlPlaneStore{},
		ProjectMemberStore: &stubProjectMemberStore{},
	}
}

// The console is built only when it is switched on and the build has the
// control-plane stores it reads; otherwise its RPCs stay Unimplemented and
// its page is not served.
func TestBuildProjectConsole(t *testing.T) {
	logger := zap.NewNop()
	users := &stubUserDirectory{}
	on := &config.Config{ConsoleEnabled: true, ConsoleSelfServiceProjectsEnabled: true, DefaultProjectID: wiringDefaultProject}

	svc := buildProjectConsole(consoleDeps(on), nil, users, nil, logger)
	if svc == nil {
		t.Fatal("console enabled with its stores: want a service, got nil")
	}
	if !svc.SelfServiceProjects() {
		t.Error("GATEWAY_CONSOLE_SELF_SERVICE_PROJECTS_ENABLED did not reach the service")
	}

	if svc := buildProjectConsole(consoleDeps(&config.Config{DefaultProjectID: wiringDefaultProject}), nil, users, nil, logger); svc != nil {
		t.Error("console disabled: want nil")
	}
	if svc := buildProjectConsole(consoleDeps(nil), nil, users, nil, logger); svc != nil {
		t.Error("nil config: want nil")
	}
	noMembers := consoleDeps(on)
	noMembers.ProjectMemberStore = nil
	if svc := buildProjectConsole(noMembers, nil, users, nil, logger); svc != nil {
		t.Error("no project-member store (no control plane): want nil")
	}
	noConfigStore := consoleDeps(on)
	noConfigStore.ControlPlaneStore = nil
	if svc := buildProjectConsole(noConfigStore, nil, users, nil, logger); svc != nil {
		t.Error("no control-plane store: want nil")
	}
	if svc := buildProjectConsole(consoleDeps(on), nil, nil, nil, logger); svc != nil {
		t.Error("no user directory: want nil")
	}
}

// The page is mounted where the auth middleware lets an unauthenticated
// browser reach it: the two packages each name the path, and they must agree.
func TestConsolePath_MatchesTheAuthExemption(t *testing.T) {
	if ui.ConsolePath != middleware.ConsolePathPrefix {
		t.Fatalf("ui.ConsolePath = %q, middleware.ConsolePathPrefix = %q: the page would be mounted where the JWT layer refuses it",
			ui.ConsolePath, middleware.ConsolePathPrefix)
	}
}

func consoleRequest(projectID string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, ui.ConsolePath, nil)
	if projectID == "" {
		return req
	}
	return req.WithContext(service.WithProjectScope(context.Background(), &service.ProjectScope{ProjectID: projectID}))
}

// The console page answers only when the console is built, and only on a
// request that resolved to the default project: on another project's auth
// domain there is no console.
func TestMountProjectConsole(t *testing.T) {
	cfg := &config.Config{ConsoleEnabled: true, DefaultProjectID: wiringDefaultProject}
	svc := buildProjectConsole(consoleDeps(cfg), nil, &stubUserDirectory{}, nil, zap.NewNop())
	if svc == nil {
		t.Fatal("want a console service")
	}

	status := func(mux *http.ServeMux, req *http.Request) int {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}

	off := http.NewServeMux()
	mountProjectConsole(off, cfg, nil)
	if got := status(off, consoleRequest(wiringDefaultProject)); got != http.StatusNotFound {
		t.Errorf("no console service: status = %d, want 404", got)
	}

	on := http.NewServeMux()
	mountProjectConsole(on, cfg, svc)
	if got := status(on, consoleRequest(wiringDefaultProject)); got != http.StatusOK {
		t.Errorf("default project: status = %d, want 200", got)
	}
	if got := status(on, consoleRequest("acme-project")); got != http.StatusNotFound {
		t.Errorf("another project's host: status = %d, want 404", got)
	}
	// A build with no project middleware (no control plane) resolves no
	// scope; the console is never built there, but a request that carries
	// none is the default project's by definition.
	if got := status(on, consoleRequest("")); got != http.StatusOK {
		t.Errorf("no project scope: status = %d, want 200", got)
	}
}
