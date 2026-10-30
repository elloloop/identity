//go:build integration && realpostgres

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
)

const (
	hostClientCallbackHost = "auth.b.example"
	hostClientRedirectOnB  = "https://auth.b.example/oauth/callback"
	hostClientRedirectElse = "https://app.test/oauth/callback"
)

// beginGoogleClientID begins a headless Google sign-in and returns the client
// id its authorization URL carries.
func beginGoogleClientID(t *testing.T, client identityconnectgen.IdentityServiceClient, redirectURI string) string {
	t.Helper()
	begin, err := client.BeginOAuthLogin(context.Background(), connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
		Provider:    "google",
		RedirectUri: redirectURI,
	}))
	if err != nil {
		t.Fatalf("BeginOAuthLogin(%s): %v", redirectURI, err)
	}
	u, err := url.Parse(begin.Msg.GetAuthorizationUrl())
	if err != nil {
		t.Fatalf("authorization url %q: %v", begin.Msg.GetAuthorizationUrl(), err)
	}
	return u.Query().Get("client_id")
}

func setGoogleHostClient(ctx context.Context, admin identityconnectgen.IdentityServiceClient, projectID string, cfg *identitypb.ProjectOAuthProviderConfig) (*identitypb.ProjectOAuthProviderConfig, error) {
	cfg.Provider = "google"
	resp, err := admin.AdminSetProjectOAuthProvider(ctx, connect.NewRequest(&identitypb.AdminSetProjectOAuthProviderRequest{
		ProjectId: projectID,
		Config:    cfg,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg.GetConfig(), nil
}

// TestRedesign_OAuthHostClient_OwnProvider authors a client for one callback
// host over the admin API and drives sign-ins against the real server and
// store: the host's sign-ins use its client, every other host keeps the
// project's own one, the secret is stored encrypted and read back redacted,
// re-authoring the base leaves the override alone, and deleting the override
// reverts its host to the base.
func TestRedesign_OAuthHostClient_OwnProvider(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()
	admin := h.adminClient(harnessAdminSecret)
	unique := time.Now().UnixNano()

	proj, err := admin.AdminCreateProject(ctx, connect.NewRequest(&identitypb.AdminCreateProjectRequest{
		Name:           "OAuth Host Client E2E",
		StorageScopeId: fmt.Sprintf("oauth-host-client-scope-%d", unique),
	}))
	if err != nil {
		t.Fatalf("AdminCreateProject: %v", err)
	}
	projectID := proj.Msg.GetProjectId()

	if _, err := setGoogleHostClient(ctx, admin, projectID, &identitypb.ProjectOAuthProviderConfig{
		ClientId:               "base-google",
		ClientSecret:           "base-secret-plaintext",
		GoogleAuthorizationUrl: "https://accounts.example/authorize",
	}); err != nil {
		t.Fatalf("set base provider: %v", err)
	}
	const hostSecret = "host-secret-plaintext"
	set, err := setGoogleHostClient(ctx, admin, projectID, &identitypb.ProjectOAuthProviderConfig{
		CallbackHost: "Auth.B.Example.",
		ClientId:     "host-b-google",
		ClientSecret: hostSecret,
	})
	if err != nil {
		t.Fatalf("set host client: %v", err)
	}
	if set.GetCallbackHost() != hostClientCallbackHost || set.GetClientSecret() != "" || !set.GetHasClientSecret() {
		t.Fatalf("set response not normalized and redacted: %+v", set)
	}

	stored, _, err := h.Stores.controlPlane.GetProjectConfig(ctx, projectID)
	if err != nil {
		t.Fatalf("GetProjectConfig: %v", err)
	}
	if strings.Contains(stored, hostSecret) || !strings.Contains(stored, `"`+hostClientCallbackHost+`"`) {
		t.Fatalf("stored config must hold the host client with its secret encrypted, got %s", stored)
	}

	list, err := admin.AdminListProjectOAuthProviders(ctx, connect.NewRequest(&identitypb.AdminListProjectOAuthProvidersRequest{
		ProjectId: projectID,
	}))
	if err != nil {
		t.Fatalf("AdminListProjectOAuthProviders: %v", err)
	}
	if n := len(list.Msg.GetProviders()); n != 1 {
		t.Fatalf("providers = %d, want 1", n)
	}
	hc := list.Msg.GetHostClients()
	if len(hc) != 1 || hc[0].GetCallbackHost() != hostClientCallbackHost || hc[0].GetClientId() != "host-b-google" ||
		hc[0].GetClientSecret() != "" || !hc[0].GetHasClientSecret() {
		t.Fatalf("listed host clients wrong or leaky: %+v", hc)
	}

	cred, err := admin.AdminCreateProjectCredential(ctx, connect.NewRequest(&identitypb.AdminCreateProjectCredentialRequest{
		ProjectId: projectID,
		Kind:      service.CredentialKindSecret,
	}))
	if err != nil {
		t.Fatalf("AdminCreateProjectCredential: %v", err)
	}
	client := h.ClientWithHost("", map[string]string{projectKeyHeader: cred.Msg.GetPublicId()})
	if got := beginGoogleClientID(t, client, hostClientRedirectOnB); got != "host-b-google" {
		t.Fatalf("callback on the host: client_id = %q, want the host client", got)
	}
	if got := beginGoogleClientID(t, client, hostClientRedirectElse); got != "base-google" {
		t.Fatalf("callback elsewhere: client_id = %q, want the base", got)
	}

	// An override takes a client identity only.
	_, err = setGoogleHostClient(ctx, admin, projectID, &identitypb.ProjectOAuthProviderConfig{
		CallbackHost:           hostClientCallbackHost,
		ClientId:               "host-b-google",
		GoogleAuthorizationUrl: "https://elsewhere.example/authorize",
	})
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("a host client with a base setting: err = %v, want InvalidArgument", err)
	}

	// Re-authoring the base keeps the override.
	if _, err := setGoogleHostClient(ctx, admin, projectID, &identitypb.ProjectOAuthProviderConfig{
		ClientId:               "base-google-2",
		GoogleAuthorizationUrl: "https://accounts.example/authorize",
	}); err != nil {
		t.Fatalf("re-author base: %v", err)
	}
	if got := beginGoogleClientID(t, client, hostClientRedirectOnB); got != "host-b-google" {
		t.Fatalf("after re-authoring the base: client_id on the host = %q, want the host client", got)
	}
	if got := beginGoogleClientID(t, client, hostClientRedirectElse); got != "base-google-2" {
		t.Fatalf("after re-authoring the base: client_id elsewhere = %q, want the new base", got)
	}

	// Deleting the override reverts its host to the base; the base stays.
	if _, err := admin.AdminDeleteProjectOAuthProvider(ctx, connect.NewRequest(&identitypb.AdminDeleteProjectOAuthProviderRequest{
		ProjectId:    projectID,
		Provider:     "google",
		CallbackHost: hostClientCallbackHost,
	})); err != nil {
		t.Fatalf("delete host client: %v", err)
	}
	if got := beginGoogleClientID(t, client, hostClientRedirectOnB); got != "base-google-2" {
		t.Fatalf("after deleting the override: client_id on the host = %q, want the base", got)
	}
	list, err = admin.AdminListProjectOAuthProviders(ctx, connect.NewRequest(&identitypb.AdminListProjectOAuthProvidersRequest{
		ProjectId: projectID,
	}))
	if err != nil {
		t.Fatalf("AdminListProjectOAuthProviders: %v", err)
	}
	if len(list.Msg.GetProviders()) != 1 || len(list.Msg.GetHostClients()) != 0 {
		t.Fatalf("after deleting the override: providers %d, host clients %d; want 1 and 0",
			len(list.Msg.GetProviders()), len(list.Msg.GetHostClients()))
	}
}

// TestRedesign_OAuthHostClient_EnvBaseDefaultProject gives the default
// project, whose Google comes from the environment, a client for one callback
// host: the real server rebuilds the env provider with that client there and
// keeps the env client everywhere else, and a request that names no project
// (the env fallback) is unchanged.
func TestRedesign_OAuthHostClient_EnvBaseDefaultProject(t *testing.T) {
	h := startRedesignHarnessWith(t, func(cfg *config.Config) {
		cfg.GoogleClientID = "env-google"
		cfg.GoogleClientSecret = "env-google-secret"
		cfg.GoogleAuthorizationURL = "https://accounts.example/authorize"
	})
	ctx := context.Background()
	admin := h.adminClient(harnessAdminSecret)
	// The default project's overrides live in its stored config, which a
	// request carries when it resolves to the project by an auth domain (or a
	// key); the env fallback for a request naming no project carries none.
	client := h.ClientWithHost(h.BrandedAuthDomain, nil)

	if got := beginGoogleClientID(t, client, hostClientRedirectOnB); got != "env-google" {
		t.Fatalf("before any override: client_id = %q, want the env client", got)
	}
	if _, err := setGoogleHostClient(ctx, admin, h.ProjectID, &identitypb.ProjectOAuthProviderConfig{
		CallbackHost: hostClientCallbackHost,
		ClientId:     "host-b-google",
		ClientSecret: "host-secret-plaintext",
	}); err != nil {
		t.Fatalf("set host client on the default project: %v", err)
	}
	if got := beginGoogleClientID(t, client, hostClientRedirectOnB); got != "host-b-google" {
		t.Fatalf("callback on the host: client_id = %q, want the host client", got)
	}
	if got := beginGoogleClientID(t, client, hostClientRedirectElse); got != "env-google" {
		t.Fatalf("callback elsewhere: client_id = %q, want the env client", got)
	}
	if got := beginGoogleClientID(t, h.ClientWithHost("", nil), hostClientRedirectOnB); got != "env-google" {
		t.Fatalf("a request naming no project: client_id = %q, want the env client", got)
	}

	// An override never enables a provider the project has no base for.
	_, err := admin.AdminSetProjectOAuthProvider(ctx, connect.NewRequest(&identitypb.AdminSetProjectOAuthProviderRequest{
		ProjectId: h.ProjectID,
		Config: &identitypb.ProjectOAuthProviderConfig{
			Provider:     "github",
			CallbackHost: hostClientCallbackHost,
			ClientId:     "host-b-github",
			ClientSecret: "host-secret-plaintext",
		},
	}))
	if err != nil {
		t.Fatalf("set github host client: %v", err)
	}
	_, err = client.BeginOAuthLogin(ctx, connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
		Provider:    "github",
		RedirectUri: hostClientRedirectOnB,
	}))
	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("github with only a host client must stay unavailable, got err = %v", err)
	}
}
