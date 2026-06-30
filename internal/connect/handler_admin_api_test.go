package connect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"go.uber.org/zap"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/service"
)

const handlerAdminSecret = "handler-operator-secret"

// adminControlStore is a minimal in-memory service.ControlPlaneProjectStore
// for the admin handler tests. It records the project/credential ids it mints
// and the last auth-domain it was asked to ensure.
type adminControlStore struct {
	nextID     int
	domains    map[string]*service.AdminProjectAuthDomain // hostname → row
	configs    map[string]string                          // projectID → config_json
	lastDomain struct {
		projectID string
		hostname  string
		isPrimary bool
	}
}

func (s *adminControlStore) UpdateProjectConfig(_ context.Context, projectID, configJSON string) (string, error) {
	if s.configs == nil {
		s.configs = map[string]string{}
	}
	if configJSON == "" {
		configJSON = "{}"
	}
	s.configs[projectID] = configJSON
	return configJSON, nil
}

func (s *adminControlStore) GetProjectConfig(_ context.Context, projectID string) (string, error) {
	if cfg, ok := s.configs[projectID]; ok {
		return cfg, nil
	}
	return "{}", nil
}

// adminLoginPolicyStore is an in-memory LoginPolicyStore for the handler
// tests.
type adminLoginPolicyStore struct {
	policies map[string]*service.LoginPolicy // projectID|tenantID → policy
}

func (s *adminLoginPolicyStore) key(p, t string) string { return p + "|" + t }

func (s *adminLoginPolicyStore) UpsertLoginPolicy(_ context.Context, p *service.LoginPolicy) (string, error) {
	if s.policies == nil {
		s.policies = map[string]*service.LoginPolicy{}
	}
	if p.ID == "" {
		p.ID = "lp-1"
	}
	if p.SSOConnectionJSON == "" {
		p.SSOConnectionJSON = "{}"
	}
	cp := *p
	s.policies[s.key(p.ProjectID, p.TenantID)] = &cp
	return p.ID, nil
}

func (s *adminLoginPolicyStore) GetLoginPolicy(_ context.Context, projectID, tenantID string) (*service.LoginPolicy, error) {
	if p, ok := s.policies[s.key(projectID, tenantID)]; ok {
		cp := *p
		return &cp, nil
	}
	return nil, nil
}

func (s *adminLoginPolicyStore) DeleteLoginPolicy(_ context.Context, projectID, tenantID string) error {
	delete(s.policies, s.key(projectID, tenantID))
	return nil
}

var _ service.LoginPolicyStore = (*adminLoginPolicyStore)(nil)

// adminDNSResolver is a fixed-record TXT resolver for the handler tests.
type adminDNSResolver struct {
	txt map[string][]string
}

func (r *adminDNSResolver) LookupTXT(_ context.Context, host string) ([]string, error) {
	return r.txt[host], nil
}

func (s *adminControlStore) mint(prefix string) string {
	s.nextID++
	switch s.nextID {
	case 1:
		return prefix + "-1"
	default:
		return prefix + "-n"
	}
}

func (s *adminControlStore) CreateProject(_ context.Context, p *service.AdminProject) (string, error) {
	id := s.mint("proj")
	p.ID = id
	return id, nil
}

func (s *adminControlStore) CreateProjectCredential(_ context.Context, c *service.AdminProjectCredential) (string, error) {
	id := s.mint("cred")
	c.ID = id
	return id, nil
}

func (s *adminControlStore) EnsureAuthDomain(_ context.Context, projectID, hostname string, isPrimary bool, _ int64) error {
	s.lastDomain.projectID = projectID
	s.lastDomain.hostname = hostname
	s.lastDomain.isPrimary = isPrimary
	return nil
}

func (s *adminControlStore) CreateAuthDomain(_ context.Context, projectID, hostname string, isPrimary bool) error {
	if s.domains == nil {
		s.domains = map[string]*service.AdminProjectAuthDomain{}
	}
	s.domains[hostname] = &service.AdminProjectAuthDomain{Hostname: hostname, IsPrimary: isPrimary}
	s.lastDomain.projectID = projectID
	s.lastDomain.hostname = hostname
	s.lastDomain.isPrimary = isPrimary
	return nil
}

func (s *adminControlStore) GetAuthDomain(_ context.Context, _, hostname string) (*service.AdminProjectAuthDomain, error) {
	d := s.domains[hostname]
	if d == nil {
		return nil, nil
	}
	cp := *d
	return &cp, nil
}

func (s *adminControlStore) ListAuthDomains(_ context.Context, _ string) ([]*service.AdminProjectAuthDomain, error) {
	var out []*service.AdminProjectAuthDomain
	for _, d := range s.domains {
		cp := *d
		out = append(out, &cp)
	}
	return out, nil
}

func (s *adminControlStore) SetAuthDomainVerified(_ context.Context, _, hostname string, verifiedAtMs int64) error {
	d := s.domains[hostname]
	if d == nil {
		return service.ErrNotFound
	}
	d.VerifiedAtMs = verifiedAtMs
	return nil
}

func (s *adminControlStore) SetPrimaryAuthDomain(_ context.Context, _, hostname string) (*service.AdminProjectAuthDomain, error) {
	target := s.domains[hostname]
	if target == nil {
		return nil, service.ErrNotFound
	}
	if target.VerifiedAtMs <= 0 {
		return nil, service.ErrAuthDomainNotVerified
	}
	for _, d := range s.domains {
		d.IsPrimary = false
	}
	target.IsPrimary = true
	cp := *target
	return &cp, nil
}

var _ service.ControlPlaneProjectStore = (*adminControlStore)(nil)

// startAdminServer mounts a handler whose only wired service is the
// control-plane admin one (built with the given secret), or nil to simulate
// the no-control-plane build.
func startAdminServer(t *testing.T, svc *service.ControlPlaneAdminService) identityconnectgen.IdentityServiceClient {
	t.Helper()
	h := NewIdentityHandler(nil, nil, nil, nil, nil, nil, nil, nil, svc, nil, testConfig())
	mux := http.NewServeMux()
	path, handler := identityconnectgen.NewIdentityServiceHandler(h)
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return identityconnectgen.NewIdentityServiceClient(srv.Client(), srv.URL)
}

// connectPlatformAdminStore is a minimal in-memory service.PlatformAdminStore
// for the admin handler tests. It inserts the first admin and reports
// created=false thereafter, mirroring the store's one-time contract.
type connectPlatformAdminStore struct {
	count int
}

func (s *connectPlatformAdminStore) CreateFirstPlatformAdmin(_ context.Context, a *service.PlatformAdmin) (bool, error) {
	if s.count > 0 {
		return false, nil
	}
	s.count++
	if a.ID == "" {
		a.ID = "admin-1"
	}
	return true, nil
}

func (s *connectPlatformAdminStore) CountPlatformAdmins(_ context.Context) (int, error) {
	return s.count, nil
}

var _ service.PlatformAdminStore = (*connectPlatformAdminStore)(nil)

func newAdminControlSvc(secret string) (*service.ControlPlaneAdminService, *adminControlStore, *connectMembershipStore) {
	store := &adminControlStore{}
	members := &connectMembershipStore{}
	svc := service.NewControlPlaneAdminService(secret, store, &connectTenantStore{}, members, &adminLoginPolicyStore{}, &connectPlatformAdminStore{}, &adminDNSResolver{txt: map[string][]string{}}, nil, zap.NewNop())
	return svc, store, members
}

// withAdminSecret returns a request carrying the operator's admin secret.
func withAdminSecret[T any](msg *T, secret string) *connect.Request[T] {
	req := connect.NewRequest(msg)
	if secret != "" {
		req.Header().Set(middleware.AdminAPISecretHeader, secret)
	}
	return req
}

// ── nil service (no control plane) → Unimplemented ───────────────────────

func TestAdminRPCs_NilService_ReturnUnimplemented(t *testing.T) {
	t.Parallel()
	client := startAdminServer(t, nil)
	ctx := context.Background()

	_, err := client.AdminCreateProject(ctx, withAdminSecret(&identitypb.AdminCreateProjectRequest{StorageScopeId: "s"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeUnimplemented)

	_, err = client.AdminCreateProjectCredential(ctx, withAdminSecret(&identitypb.AdminCreateProjectCredentialRequest{ProjectId: "p"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeUnimplemented)

	_, err = client.AdminAddProjectAuthDomain(ctx, withAdminSecret(&identitypb.AdminAddProjectAuthDomainRequest{ProjectId: "p", Hostname: "h.example.com"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeUnimplemented)

	_, err = client.AdminCreateTenant(ctx, withAdminSecret(&identitypb.AdminCreateTenantRequest{ProjectId: "p"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeUnimplemented)

	_, err = client.AdminAddTenantAdmin(ctx, withAdminSecret(&identitypb.AdminAddTenantAdminRequest{ProjectId: "p", TenantId: "t", UserId: "u"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeUnimplemented)
}

// ── secret configured but unset on this build (empty secret) → Unimplemented

func TestAdminRPCs_SecretDisabled_ReturnUnimplemented(t *testing.T) {
	t.Parallel()
	svc, _, _ := newAdminControlSvc("") // empty secret disables the surface
	client := startAdminServer(t, svc)

	_, err := client.AdminCreateProject(context.Background(),
		withAdminSecret(&identitypb.AdminCreateProjectRequest{StorageScopeId: "s"}, "whatever"))
	requireCode(t, err, connect.CodeUnimplemented)
}

// ── wrong / missing secret → PermissionDenied ────────────────────────────

func TestAdminRPCs_BadSecret_Denied(t *testing.T) {
	t.Parallel()
	svc, store, _ := newAdminControlSvc(handlerAdminSecret)
	client := startAdminServer(t, svc)
	ctx := context.Background()

	// Every RPC rejects a wrong secret (exercising each handler's error path
	// through toConnectError → PermissionDenied).
	_, err := client.AdminCreateProject(ctx,
		withAdminSecret(&identitypb.AdminCreateProjectRequest{StorageScopeId: "s"}, "nope"))
	requireCode(t, err, connect.CodePermissionDenied)

	_, err = client.AdminCreateProjectCredential(ctx,
		withAdminSecret(&identitypb.AdminCreateProjectCredentialRequest{ProjectId: "p"}, "nope"))
	requireCode(t, err, connect.CodePermissionDenied)

	_, err = client.AdminAddProjectAuthDomain(ctx,
		withAdminSecret(&identitypb.AdminAddProjectAuthDomainRequest{ProjectId: "p", Hostname: "h.example.com"}, "nope"))
	requireCode(t, err, connect.CodePermissionDenied)

	_, err = client.AdminCreateTenant(ctx,
		withAdminSecret(&identitypb.AdminCreateTenantRequest{ProjectId: "p"}, "nope"))
	requireCode(t, err, connect.CodePermissionDenied)

	_, err = client.AdminAddTenantAdmin(ctx,
		withAdminSecret(&identitypb.AdminAddTenantAdminRequest{ProjectId: "p", TenantId: "t", UserId: "u"}, "nope"))
	requireCode(t, err, connect.CodePermissionDenied)

	// Missing secret header entirely is likewise denied.
	_, err = client.AdminCreateProject(ctx,
		connect.NewRequest(&identitypb.AdminCreateProjectRequest{StorageScopeId: "s"}))
	requireCode(t, err, connect.CodePermissionDenied)

	if store.nextID != 0 {
		t.Fatal("a denied call must not reach the store")
	}
}

// ── customer custom auth-domain flow through the handler ─────────────────

func TestAdminRPCs_CustomAuthDomain_Handler(t *testing.T) {
	t.Parallel()
	store := &adminControlStore{}
	dns := &adminDNSResolver{txt: map[string][]string{}}
	svc := service.NewControlPlaneAdminService(handlerAdminSecret, store, &connectTenantStore{}, &connectMembershipStore{}, &adminLoginPolicyStore{}, &connectPlatformAdminStore{}, dns, nil, zap.NewNop())
	client := startAdminServer(t, svc)
	ctx := context.Background()

	// Add a custom domain → unverified, with a TXT challenge.
	add, err := client.AddProjectAuthDomain(ctx,
		withAdminSecret(&identitypb.AddProjectAuthDomainRequest{ProjectId: "proj-1", Hostname: "auth.customer.test", IsPrimary: false}, handlerAdminSecret))
	if err != nil {
		t.Fatalf("AddProjectAuthDomain: %v", err)
	}
	if add.Msg.GetDomain().GetVerifiedAtMs() != 0 {
		t.Fatalf("custom domain must start unverified, got %d", add.Msg.GetDomain().GetVerifiedAtMs())
	}
	if add.Msg.GetTxtValue() == "" || add.Msg.GetTxtName() != "auth.customer.test" {
		t.Fatalf("challenge incomplete: %+v", add.Msg)
	}

	// Verify without the TXT published → PermissionDenied, stays unverified.
	_, err = client.VerifyProjectAuthDomain(ctx,
		withAdminSecret(&identitypb.VerifyProjectAuthDomainRequest{ProjectId: "proj-1", Hostname: "auth.customer.test"}, handlerAdminSecret))
	requireCode(t, err, connect.CodePermissionDenied)

	// Publish the challenge → verify succeeds, domain flips verified.
	dns.txt["auth.customer.test"] = []string{add.Msg.GetTxtValue()}
	ver, err := client.VerifyProjectAuthDomain(ctx,
		withAdminSecret(&identitypb.VerifyProjectAuthDomainRequest{ProjectId: "proj-1", Hostname: "auth.customer.test"}, handlerAdminSecret))
	if err != nil {
		t.Fatalf("VerifyProjectAuthDomain: %v", err)
	}
	if ver.Msg.GetDomain().GetVerifiedAtMs() <= 0 {
		t.Fatalf("verified_at_ms not stamped: %+v", ver.Msg.GetDomain())
	}

	// List returns the domain.
	list, err := client.ListProjectAuthDomains(ctx,
		withAdminSecret(&identitypb.ListProjectAuthDomainsRequest{ProjectId: "proj-1"}, handlerAdminSecret))
	if err != nil {
		t.Fatalf("ListProjectAuthDomains: %v", err)
	}
	if len(list.Msg.GetDomains()) != 1 {
		t.Fatalf("listed %d domains, want 1", len(list.Msg.GetDomains()))
	}

	// SetPrimary on the verified domain promotes it.
	sp, err := client.SetPrimaryAuthDomain(ctx,
		withAdminSecret(&identitypb.SetPrimaryAuthDomainRequest{ProjectId: "proj-1", Hostname: "auth.customer.test"}, handlerAdminSecret))
	if err != nil {
		t.Fatalf("SetPrimaryAuthDomain: %v", err)
	}
	if !sp.Msg.GetDomain().GetIsPrimary() {
		t.Fatalf("promoted domain must be primary: %+v", sp.Msg.GetDomain())
	}
}

func TestAdminRPCs_SetPrimaryAuthDomain_UnverifiedRejected_Handler(t *testing.T) {
	t.Parallel()
	store := &adminControlStore{}
	dns := &adminDNSResolver{txt: map[string][]string{}}
	svc := service.NewControlPlaneAdminService(handlerAdminSecret, store, &connectTenantStore{}, &connectMembershipStore{}, &adminLoginPolicyStore{}, &connectPlatformAdminStore{}, dns, nil, zap.NewNop())
	client := startAdminServer(t, svc)
	ctx := context.Background()

	if _, err := client.AddProjectAuthDomain(ctx,
		withAdminSecret(&identitypb.AddProjectAuthDomainRequest{ProjectId: "proj-1", Hostname: "pending.customer.test"}, handlerAdminSecret)); err != nil {
		t.Fatalf("add: %v", err)
	}
	_, err := client.SetPrimaryAuthDomain(ctx,
		withAdminSecret(&identitypb.SetPrimaryAuthDomainRequest{ProjectId: "proj-1", Hostname: "pending.customer.test"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeFailedPrecondition)
}

func TestAdminRPCs_CustomAuthDomain_NilService_Unimplemented(t *testing.T) {
	t.Parallel()
	client := startAdminServer(t, nil)
	ctx := context.Background()

	_, err := client.AddProjectAuthDomain(ctx, withAdminSecret(&identitypb.AddProjectAuthDomainRequest{ProjectId: "p", Hostname: "h.example.com"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeUnimplemented)
	_, err = client.VerifyProjectAuthDomain(ctx, withAdminSecret(&identitypb.VerifyProjectAuthDomainRequest{ProjectId: "p", Hostname: "h.example.com"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeUnimplemented)
	_, err = client.ListProjectAuthDomains(ctx, withAdminSecret(&identitypb.ListProjectAuthDomainsRequest{ProjectId: "p"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeUnimplemented)
	_, err = client.SetPrimaryAuthDomain(ctx, withAdminSecret(&identitypb.SetPrimaryAuthDomainRequest{ProjectId: "p", Hostname: "h.example.com"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeUnimplemented)
}

// ── correct secret → full provisioning flow through the handler ──────────

func TestAdminRPCs_HappyPath_Handler(t *testing.T) {
	t.Parallel()
	svc, store, members := newAdminControlSvc(handlerAdminSecret)
	client := startAdminServer(t, svc)
	ctx := context.Background()

	proj, err := client.AdminCreateProject(ctx,
		withAdminSecret(&identitypb.AdminCreateProjectRequest{Name: "Acme", StorageScopeId: "scope-1"}, handlerAdminSecret))
	if err != nil {
		t.Fatalf("AdminCreateProject: %v", err)
	}
	if proj.Msg.GetProjectId() == "" {
		t.Fatal("expected a project id")
	}

	cred, err := client.AdminCreateProjectCredential(ctx,
		withAdminSecret(&identitypb.AdminCreateProjectCredentialRequest{ProjectId: proj.Msg.GetProjectId(), Kind: service.CredentialKindSecret}, handlerAdminSecret))
	if err != nil {
		t.Fatalf("AdminCreateProjectCredential: %v", err)
	}
	if cred.Msg.GetRawKey() == "" || cred.Msg.GetPublicId() == "" || cred.Msg.GetCredentialId() == "" {
		t.Fatalf("credential response incomplete: %+v", cred.Msg)
	}

	if _, err := client.AdminAddProjectAuthDomain(ctx,
		withAdminSecret(&identitypb.AdminAddProjectAuthDomainRequest{ProjectId: proj.Msg.GetProjectId(), Hostname: "auth.acme.test", IsPrimary: true}, handlerAdminSecret)); err != nil {
		t.Fatalf("AdminAddProjectAuthDomain: %v", err)
	}
	if store.lastDomain.hostname != "auth.acme.test" || !store.lastDomain.isPrimary {
		t.Fatalf("auth domain not ensured: %+v", store.lastDomain)
	}

	if _, err := client.AdminCreateTenant(ctx,
		withAdminSecret(&identitypb.AdminCreateTenantRequest{ProjectId: proj.Msg.GetProjectId(), Name: "Acme Inc", PrimaryDomain: "acme.test"}, handlerAdminSecret)); err != nil {
		t.Fatalf("AdminCreateTenant: %v", err)
	}

	// connectTenantStore mints no id, so the admin supplies the tenant id
	// explicitly (the handler-layer assertion is the secret gate + wiring,
	// not the tenant store's id generation — that is the e2e's job).
	admin, err := client.AdminAddTenantAdmin(ctx,
		withAdminSecret(&identitypb.AdminAddTenantAdminRequest{
			ProjectId: proj.Msg.GetProjectId(),
			TenantId:  "tenant-1",
			UserId:    "user-1",
			Role:      service.RoleOwner,
		}, handlerAdminSecret))
	if err != nil {
		t.Fatalf("AdminAddTenantAdmin: %v", err)
	}
	m := admin.Msg.GetMembership()
	if m.GetUserId() != "user-1" || m.GetRole() != service.RoleOwner || m.GetSource() != service.MembershipSourceAdded {
		t.Fatalf("membership = %+v", m)
	}
	if members.upserted == nil || members.upserted.UserID != "user-1" {
		t.Fatalf("membership not upserted: %+v", members.upserted)
	}
}

// ── zero-config first-admin bootstrap through the handler ────────────────

// startBootstrapServer mounts a handler whose control-admin service is built
// with an EMPTY secret (the fresh-deployer shape) but a real platform-admin
// store, proving the bootstrap RPC works WITHOUT a configured admin secret.
func startBootstrapServer(t *testing.T) (identityconnectgen.IdentityServiceClient, *connectPlatformAdminStore) {
	t.Helper()
	admins := &connectPlatformAdminStore{}
	svc := service.NewControlPlaneAdminService("", &adminControlStore{}, &connectTenantStore{}, &connectMembershipStore{}, &adminLoginPolicyStore{}, admins, &adminDNSResolver{txt: map[string][]string{}}, nil, zap.NewNop())
	return startAdminServer(t, svc), admins
}

func TestCreateFirstPlatformAdmin_NilService_Unimplemented(t *testing.T) {
	t.Parallel()
	client := startAdminServer(t, nil)
	_, err := client.CreateFirstPlatformAdmin(context.Background(),
		connect.NewRequest(&identitypb.CreateFirstPlatformAdminRequest{Email: "ops@acme.com"}))
	requireCode(t, err, connect.CodeUnimplemented)
}

func TestCreateFirstPlatformAdmin_NoSecretRequired_HappyPath(t *testing.T) {
	t.Parallel()
	client, admins := startBootstrapServer(t)
	ctx := context.Background()

	// No admin-secret header at all — the bootstrap is intentionally ungated.
	resp, err := client.CreateFirstPlatformAdmin(ctx,
		connect.NewRequest(&identitypb.CreateFirstPlatformAdminRequest{Email: "ops@acme.com"}))
	if err != nil {
		t.Fatalf("CreateFirstPlatformAdmin: %v", err)
	}
	if resp.Msg.GetAdminId() == "" || resp.Msg.GetEmail() != "ops@acme.com" {
		t.Fatalf("response = %+v", resp.Msg)
	}
	if resp.Msg.GetGeneratedPassword() == "" {
		t.Fatal("blank password should yield a generated one in the response")
	}
	if admins.count != 1 {
		t.Fatalf("admin count = %d, want 1", admins.count)
	}
}

func TestCreateFirstPlatformAdmin_SecondCall_FailedPrecondition(t *testing.T) {
	t.Parallel()
	client, _ := startBootstrapServer(t)
	ctx := context.Background()

	if _, err := client.CreateFirstPlatformAdmin(ctx,
		connect.NewRequest(&identitypb.CreateFirstPlatformAdminRequest{Email: "first@acme.com"})); err != nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	_, err := client.CreateFirstPlatformAdmin(ctx,
		connect.NewRequest(&identitypb.CreateFirstPlatformAdminRequest{Email: "second@acme.com"}))
	requireCode(t, err, connect.CodeFailedPrecondition)
}

// ── LoginPolicy + ProjectConfig admin RPCs through the handler ───────────

func TestAdminRPCs_LoginPolicy_Handler(t *testing.T) {
	t.Parallel()
	svc, _, _ := newAdminControlSvc(handlerAdminSecret)
	client := startAdminServer(t, svc)
	ctx := context.Background()

	// Get before any policy is set → empty policy.
	got, err := client.GetLoginPolicy(ctx,
		withAdminSecret(&identitypb.GetLoginPolicyRequest{ProjectId: "p", TenantId: "t"}, handlerAdminSecret))
	if err != nil {
		t.Fatalf("GetLoginPolicy (none): %v", err)
	}
	if got.Msg.GetPolicy() != nil {
		t.Fatalf("expected nil policy, got %+v", got.Msg.GetPolicy())
	}

	// Upsert, including the per-tenant password/session governance fields —
	// they must travel through the proto, the handler, and the service without
	// being dropped (the blocker-5 regression).
	up, err := client.UpsertLoginPolicy(ctx, withAdminSecret(&identitypb.UpsertLoginPolicyRequest{
		ProjectId:                     "p",
		TenantId:                      "t",
		AllowedMethods:                "password,email_otp",
		Require_2Fa:                   true,
		PasswordMinLength:             14,
		SessionIdleTimeoutSeconds:     1800,
		SessionAbsoluteTimeoutSeconds: 43200,
	}, handlerAdminSecret))
	if err != nil {
		t.Fatalf("UpsertLoginPolicy: %v", err)
	}
	if !up.Msg.GetPolicy().GetRequire_2Fa() {
		t.Fatalf("require_2fa not echoed: %+v", up.Msg.GetPolicy())
	}
	if p := up.Msg.GetPolicy(); p.GetPasswordMinLength() != 14 ||
		p.GetSessionIdleTimeoutSeconds() != 1800 || p.GetSessionAbsoluteTimeoutSeconds() != 43200 {
		t.Fatalf("governance fields not echoed: %+v", p)
	}

	// Get reads it back, governance fields and all.
	got, err = client.GetLoginPolicy(ctx,
		withAdminSecret(&identitypb.GetLoginPolicyRequest{ProjectId: "p", TenantId: "t"}, handlerAdminSecret))
	if err != nil {
		t.Fatalf("GetLoginPolicy: %v", err)
	}
	if got.Msg.GetPolicy().GetAllowedMethods() != "password,email_otp" {
		t.Fatalf("allowed methods = %q", got.Msg.GetPolicy().GetAllowedMethods())
	}
	if p := got.Msg.GetPolicy(); p.GetPasswordMinLength() != 14 ||
		p.GetSessionIdleTimeoutSeconds() != 1800 || p.GetSessionAbsoluteTimeoutSeconds() != 43200 {
		t.Fatalf("read-back dropped governance fields: %+v", p)
	}

	// Delete clears it.
	if _, err := client.DeleteLoginPolicy(ctx,
		withAdminSecret(&identitypb.DeleteLoginPolicyRequest{ProjectId: "p", TenantId: "t"}, handlerAdminSecret)); err != nil {
		t.Fatalf("DeleteLoginPolicy: %v", err)
	}
	got, err = client.GetLoginPolicy(ctx,
		withAdminSecret(&identitypb.GetLoginPolicyRequest{ProjectId: "p", TenantId: "t"}, handlerAdminSecret))
	if err != nil {
		t.Fatalf("GetLoginPolicy (after delete): %v", err)
	}
	if got.Msg.GetPolicy() != nil {
		t.Fatalf("policy not cleared: %+v", got.Msg.GetPolicy())
	}
}

func TestAdminRPCs_ProjectConfig_Handler(t *testing.T) {
	t.Parallel()
	svc, _, _ := newAdminControlSvc(handlerAdminSecret)
	client := startAdminServer(t, svc)
	ctx := context.Background()

	const cfg = `{"cors":{"allowed_origins":["https://pro.example.com"]}}`
	up, err := client.UpsertProjectConfig(ctx,
		withAdminSecret(&identitypb.UpsertProjectConfigRequest{ProjectId: "p", ConfigJson: cfg}, handlerAdminSecret))
	if err != nil {
		t.Fatalf("UpsertProjectConfig: %v", err)
	}
	if up.Msg.GetConfigJson() != cfg {
		t.Fatalf("stored = %q", up.Msg.GetConfigJson())
	}

	got, err := client.GetProjectConfig(ctx,
		withAdminSecret(&identitypb.GetProjectConfigRequest{ProjectId: "p"}, handlerAdminSecret))
	if err != nil {
		t.Fatalf("GetProjectConfig: %v", err)
	}
	if got.Msg.GetConfigJson() != cfg {
		t.Fatalf("read = %q", got.Msg.GetConfigJson())
	}

	// Malformed config is rejected.
	_, err = client.UpsertProjectConfig(ctx,
		withAdminSecret(&identitypb.UpsertProjectConfigRequest{ProjectId: "p", ConfigJson: "{bad"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeInvalidArgument)
}

func TestAdminRPCs_PolicyConfig_NilService_Unimplemented(t *testing.T) {
	t.Parallel()
	client := startAdminServer(t, nil)
	ctx := context.Background()

	_, err := client.UpsertLoginPolicy(ctx, withAdminSecret(&identitypb.UpsertLoginPolicyRequest{ProjectId: "p", TenantId: "t"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeUnimplemented)
	_, err = client.GetLoginPolicy(ctx, withAdminSecret(&identitypb.GetLoginPolicyRequest{ProjectId: "p", TenantId: "t"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeUnimplemented)
	_, err = client.DeleteLoginPolicy(ctx, withAdminSecret(&identitypb.DeleteLoginPolicyRequest{ProjectId: "p", TenantId: "t"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeUnimplemented)
	_, err = client.UpsertProjectConfig(ctx, withAdminSecret(&identitypb.UpsertProjectConfigRequest{ProjectId: "p"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeUnimplemented)
	_, err = client.GetProjectConfig(ctx, withAdminSecret(&identitypb.GetProjectConfigRequest{ProjectId: "p"}, handlerAdminSecret))
	requireCode(t, err, connect.CodeUnimplemented)
}

func TestAdminRPCs_PolicyConfig_BadSecret_Denied(t *testing.T) {
	t.Parallel()
	svc, _, _ := newAdminControlSvc(handlerAdminSecret)
	client := startAdminServer(t, svc)
	ctx := context.Background()

	_, err := client.UpsertLoginPolicy(ctx, withAdminSecret(&identitypb.UpsertLoginPolicyRequest{ProjectId: "p", TenantId: "t"}, "nope"))
	requireCode(t, err, connect.CodePermissionDenied)
	_, err = client.UpsertProjectConfig(ctx, withAdminSecret(&identitypb.UpsertProjectConfigRequest{ProjectId: "p"}, "nope"))
	requireCode(t, err, connect.CodePermissionDenied)
}
