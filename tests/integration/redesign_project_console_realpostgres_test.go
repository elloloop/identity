//go:build integration && realpostgres

package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/app/ui"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
)

// consoleTestProjectLimit is the per-account project limit the console
// harness runs with, small enough for a test to reach.
const consoleTestProjectLimit = 2

// startConsoleHarness boots the redesign harness with the project console
// and self-service projects on. Project resolution is uncached, so a change
// an owner saves governs the very next request rather than the first one
// after the cache's lifetime.
func startConsoleHarness(t *testing.T) *RedesignHarness {
	t.Helper()
	return startRedesignHarnessWith(t, func(c *config.Config) {
		c.ConsoleEnabled = true
		c.ConsoleSelfServiceProjectsEnabled = true
		c.ConsoleMaxProjectsPerAccount = consoleTestProjectLimit
		c.ProjectResolutionCacheTTLSeconds = 0
	})
}

// consoleAccount signs up an account of the default project with a verified
// email and returns a client carrying its token, and its user id.
func consoleAccount(t *testing.T, h *RedesignHarness, label string) (identityconnectgen.IdentityServiceClient, string) {
	t.Helper()
	addr := fmt.Sprintf("%s-%d@example.com", label, time.Now().UnixNano())
	signup, err := h.Client.PasswordSignup(context.Background(), connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: addr, Password: validPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup(%s): %v", label, err)
	}
	verifyMailedEmail(t, h, h.Client, addr)
	return h.AuthedClient(signup.Msg.GetAccessToken()), signup.Msg.GetUser().GetId()
}

// TestRedesign_ProjectConsole_EndToEnd: a console account creates a project,
// which admits nobody until its owner sets an access mode through the
// console; after that an application selects the project by its publishable
// key and people sign up into it. Nobody but the project's members reaches
// its settings, and the operator's path sees what the owner stored.
func TestRedesign_ProjectConsole_EndToEnd(t *testing.T) {
	h := startConsoleHarness(t)
	ctx := context.Background()
	owner, ownerID := consoleAccount(t, h, "console-owner")

	listed, err := owner.ListMyProjects(ctx, connect.NewRequest(&identitypb.ListMyProjectsRequest{}))
	if err != nil {
		t.Fatalf("ListMyProjects: %v", err)
	}
	if len(listed.Msg.GetProjects()) != 0 || !listed.Msg.GetCanCreateProject() {
		t.Fatalf("a new console account: projects=%d can_create=%v, want none and true",
			len(listed.Msg.GetProjects()), listed.Msg.GetCanCreateProject())
	}

	created, err := owner.CreateProject(ctx, connect.NewRequest(&identitypb.CreateProjectRequest{Name: "Acme Storefront"}))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	project := created.Msg.GetProject()
	if project.GetProjectId() == "" || project.GetProjectId() == h.ProjectID {
		t.Fatalf("project id = %q, want a new project, not the default %q", project.GetProjectId(), h.ProjectID)
	}
	if project.GetName() != "Acme Storefront" || project.GetRole() != service.ProjectRoleOwner || project.GetPublishableKey() == "" {
		t.Fatalf("project = %+v, want the name, the owner role and a publishable key", project)
	}
	listed, err = owner.ListMyProjects(ctx, connect.NewRequest(&identitypb.ListMyProjectsRequest{}))
	if err != nil {
		t.Fatalf("ListMyProjects after create: %v", err)
	}
	if len(listed.Msg.GetProjects()) != 1 || listed.Msg.GetProjects()[0].GetProjectId() != project.GetProjectId() {
		t.Fatalf("listed projects = %+v, want the one just created", listed.Msg.GetProjects())
	}

	// The application's view: the publishable key selects the project.
	app := h.ClientWithHost("", map[string]string{middleware.ProjectKeyHeader: project.GetPublishableKey()})
	signupInProject := func(label string) (*connect.Response[identitypb.PasswordSignupResponse], error) {
		return app.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
			Email: fmt.Sprintf("%s-%d@example.com", label, time.Now().UnixNano()), Password: validPassword,
		}))
	}
	_, err = signupInProject("too-early")
	requireConnectCode(t, "signing up to a project with no access mode", err, connect.CodePermissionDenied)

	read, err := owner.GetProjectSettings(ctx, connect.NewRequest(&identitypb.GetProjectSettingsRequest{ProjectId: project.GetProjectId()}))
	if err != nil {
		t.Fatalf("GetProjectSettings: %v", err)
	}
	if read.Msg.GetSettingsJson() != "{}" {
		t.Fatalf("a new project's settings = %s, want {}", read.Msg.GetSettingsJson())
	}

	update := func(client identityconnectgen.IdentityServiceClient, settings string, version int64) (*connect.Response[identitypb.UpdateProjectSettingsResponse], error) {
		return client.UpdateProjectSettings(ctx, connect.NewRequest(&identitypb.UpdateProjectSettingsRequest{
			ProjectId: project.GetProjectId(), SettingsJson: settings, ExpectedVersion: version,
		}))
	}
	_, err = update(owner, `{"oauth":{"hub":true}}`, read.Msg.GetVersion())
	requireConnectCode(t, "writing an operator's section", err, connect.CodeInvalidArgument)
	_, err = update(owner, `{"accounts":{"domain":"example.com"}}`, read.Msg.GetVersion())
	requireConnectCode(t, "writing an operator's field", err, connect.CodeInvalidArgument)

	updated, err := update(owner, `{"access":{"mode":"open"},"tenants":{"self_service":true}}`, read.Msg.GetVersion())
	if err != nil {
		t.Fatalf("UpdateProjectSettings: %v", err)
	}
	if updated.Msg.GetVersion() <= read.Msg.GetVersion() {
		t.Fatalf("version %d did not advance past %d", updated.Msg.GetVersion(), read.Msg.GetVersion())
	}
	_, err = update(owner, `{"access":{"mode":"closed"}}`, read.Msg.GetVersion())
	requireConnectCode(t, "writing with the version read before the last write", err, connect.CodeAborted)

	// The owner's choice now governs the project.
	joined, err := signupInProject("customer")
	if err != nil {
		t.Fatalf("signing up to the project after its owner opened it: %v", err)
	}
	if got := decodeTokenProjectClaim(t, joined.Msg.GetAccessToken()); got != project.GetProjectId() {
		t.Fatalf("the customer signed up into project %q, want %q", got, project.GetProjectId())
	}

	// A customer of the project is not a console account: their token is the
	// new project's, and the console takes the default project's only.
	customer := identityconnectgen.NewIdentityServiceClient(&redesignHTTPClient{
		base: h.HTTP, token: joined.Msg.GetAccessToken(),
		headers: map[string]string{middleware.ProjectKeyHeader: project.GetPublishableKey()},
	}, h.BaseURL)
	_, err = customer.ListMyProjects(ctx, connect.NewRequest(&identitypb.ListMyProjectsRequest{}))
	requireConnectCode(t, "a customer's token at the console", err, connect.CodePermissionDenied)
	_, err = update(customer, `{"access":{"mode":"closed"}}`, updated.Msg.GetVersion())
	requireConnectCode(t, "a customer changing the project's settings", err, connect.CodePermissionDenied)

	// Another console account is not a member of this project.
	stranger, _ := consoleAccount(t, h, "console-stranger")
	_, err = stranger.GetProjectSettings(ctx, connect.NewRequest(&identitypb.GetProjectSettingsRequest{ProjectId: project.GetProjectId()}))
	requireConnectCode(t, "another account reading the settings", err, connect.CodePermissionDenied)
	_, err = update(stranger, `{"access":{"mode":"closed"}}`, updated.Msg.GetVersion())
	requireConnectCode(t, "another account changing the settings", err, connect.CodePermissionDenied)
	others, err := stranger.ListMyProjects(ctx, connect.NewRequest(&identitypb.ListMyProjectsRequest{}))
	if err != nil || len(others.Msg.GetProjects()) != 0 {
		t.Fatalf("another account's projects = %+v (err %v), want none", others.Msg.GetProjects(), err)
	}

	// The operator's path is unchanged and sees what the owner stored.
	operator := h.adminClient(harnessAdminSecret)
	stored, err := operator.GetProjectConfig(ctx, connect.NewRequest(&identitypb.GetProjectConfigRequest{ProjectId: project.GetProjectId()}))
	if err != nil {
		t.Fatalf("operator GetProjectConfig: %v", err)
	}
	parsed, err := service.ParseProjectConfig(stored.Msg.GetConfigJson())
	if err != nil {
		t.Fatalf("stored config does not parse: %v", err)
	}
	if parsed.Access.Mode != "open" || !parsed.Tenants.SelfService {
		t.Fatalf("stored config = %s, want the owner's access mode and tenant setting", stored.Msg.GetConfigJson())
	}

	// The limit: one more project fits, a third does not.
	if _, err := owner.CreateProject(ctx, connect.NewRequest(&identitypb.CreateProjectRequest{Name: "Acme Support"})); err != nil {
		t.Fatalf("a second project under a limit of %d: %v", consoleTestProjectLimit, err)
	}
	_, err = owner.CreateProject(ctx, connect.NewRequest(&identitypb.CreateProjectRequest{Name: "Acme Labs"}))
	requireConnectCode(t, "a project past the account's limit", err, connect.CodeResourceExhausted)

	event := waitForAuditEvent(t, h, ownerID, string(audit.EventProjectSettingsUpdated))
	if event.ActorUserID != ownerID || !event.Success || event.Details["project_id"] != project.GetProjectId() {
		t.Fatalf("project_settings_updated = %+v, want a success by the owner naming the project", event)
	}
}

// TestRedesign_ProjectConsole_UnverifiedAccountIsRefused: an account whose
// email nobody has proven holds no project.
func TestRedesign_ProjectConsole_UnverifiedAccountIsRefused(t *testing.T) {
	h := startRedesignHarnessWith(t, func(c *config.Config) {
		c.ConsoleEnabled = true
		c.ConsoleSelfServiceProjectsEnabled = true
		// Sign-up answers with a session before the email is verified, so the
		// console's own rule is what is exercised.
		c.AuthRequireVerifiedEmail = false
	})
	ctx := context.Background()
	addr := fmt.Sprintf("console-unverified-%d@example.com", time.Now().UnixNano())
	signup, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email: addr, Password: validPassword,
	}))
	if err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}
	if signup.Msg.GetAccessToken() == "" {
		t.Skip("this deployment issues no session before verification; the service-level test covers the rule")
	}
	unverified := h.AuthedClient(signup.Msg.GetAccessToken())
	_, err = unverified.CreateProject(ctx, connect.NewRequest(&identitypb.CreateProjectRequest{Name: "Acme"}))
	requireConnectCode(t, "an unverified account creating a project", err, connect.CodeFailedPrecondition)
}

// TestRedesign_ProjectConsole_OffByDefault: with the console off its RPCs
// are UNIMPLEMENTED and its page is not served.
func TestRedesign_ProjectConsole_OffByDefault(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()
	account, _ := consoleAccount(t, h, "console-off")

	_, err := account.ListMyProjects(ctx, connect.NewRequest(&identitypb.ListMyProjectsRequest{}))
	requireConnectCode(t, "ListMyProjects with the console off", err, connect.CodeUnimplemented)
	_, err = account.CreateProject(ctx, connect.NewRequest(&identitypb.CreateProjectRequest{Name: "Acme"}))
	requireConnectCode(t, "CreateProject with the console off", err, connect.CodeUnimplemented)

	if status, _ := getConsolePage(t, h); status != http.StatusNotFound {
		t.Fatalf("console page with the console off: status = %d, want 404", status)
	}
}

// TestRedesign_ProjectConsole_PageIsServedWithoutASession: a browser loads
// the page before anyone has signed in, and the page admits only its own
// inline style and script.
func TestRedesign_ProjectConsole_PageIsServedWithoutASession(t *testing.T) {
	h := startConsoleHarness(t)

	status, resp := getConsolePage(t, h)
	if status != http.StatusOK {
		t.Fatalf("console page: status = %d, want 200", status)
	}
	policy := resp.Header.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'nonce-", "connect-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(policy, want) {
			t.Errorf("Content-Security-Policy = %q, want it to contain %q", policy, want)
		}
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// getConsolePage fetches the console page with no credentials and returns
// the status and the response, its body already drained.
func getConsolePage(t *testing.T, h *RedesignHarness) (int, *http.Response) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, h.BaseURL+ui.ConsolePath, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := h.HTTP.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", ui.ConsolePath, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("read %s: %v", ui.ConsolePath, err)
	}
	return resp.StatusCode, resp
}
