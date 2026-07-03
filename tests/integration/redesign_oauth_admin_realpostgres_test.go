//go:build integration && realpostgres

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// TestRedesign_OAuthAdmin_AuthorAndLogin closes the loop PR A/B could only test
// by seeding config_json directly: an operator authors a project's Google
// provider through the admin API — sending the client secret in PLAINTEXT — and
// the server encrypts it, stores it, and the hosted login flow resolves the
// project and uses the authored provider end-to-end. It also asserts reads
// redact the secret and that delete removes the provider.
func TestRedesign_OAuthAdmin_AuthorAndLogin(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()
	admin := h.adminClient(harnessAdminSecret)
	unique := time.Now().UnixNano()

	projResp, err := admin.AdminCreateProject(ctx, connect.NewRequest(&identitypb.AdminCreateProjectRequest{
		Name:           "OAuth Admin E2E",
		StorageScopeId: fmt.Sprintf("oauth-admin-scope-%d", unique),
	}))
	if err != nil {
		t.Fatalf("AdminCreateProject: %v", err)
	}
	projectID := projResp.Msg.GetProjectId()

	// Author the Google provider over the admin API with a PLAINTEXT secret.
	const clientID = "authored-google-client"
	setResp, err := admin.AdminSetProjectOAuthProvider(ctx, connect.NewRequest(&identitypb.AdminSetProjectOAuthProviderRequest{
		ProjectId: projectID,
		Config: &identitypb.ProjectOAuthProviderConfig{
			Provider:               "google",
			ClientId:               clientID,
			ClientSecret:           "super-secret-plaintext",
			GoogleAuthorizationUrl: "https://accounts.example/authorize",
		},
	}))
	if err != nil {
		t.Fatalf("AdminSetProjectOAuthProvider: %v", err)
	}
	// The write response redacts the secret.
	if c := setResp.Msg.GetConfig(); c.GetClientSecret() != "" || !c.GetHasClientSecret() {
		t.Fatalf("set response not redacted: %+v", c)
	}

	// A read lists the provider with the secret redacted.
	listResp, err := admin.AdminListProjectOAuthProviders(ctx, connect.NewRequest(&identitypb.AdminListProjectOAuthProvidersRequest{
		ProjectId: projectID,
	}))
	if err != nil {
		t.Fatalf("AdminListProjectOAuthProviders: %v", err)
	}
	if n := len(listResp.Msg.GetProviders()); n != 1 {
		t.Fatalf("providers = %d, want 1", n)
	}
	if p := listResp.Msg.GetProviders()[0]; p.GetProvider() != "google" || p.GetClientSecret() != "" || !p.GetHasClientSecret() {
		t.Fatalf("listed provider wrong/leaky: %+v", p)
	}

	// Mint a credential and drive the hosted login flow for the project: the
	// authorization URL carries the authored client id, proving the resolver
	// decrypted and used the server-encrypted secret end-to-end.
	credResp, err := admin.AdminCreateProjectCredential(ctx, connect.NewRequest(&identitypb.AdminCreateProjectCredentialRequest{
		ProjectId: projectID,
		Kind:      service.CredentialKindSecret,
	}))
	if err != nil {
		t.Fatalf("AdminCreateProjectCredential: %v", err)
	}
	projectKey := credResp.Msg.GetPublicId()

	client := h.ClientWithHost("", map[string]string{projectKeyHeader: projectKey})
	begin, err := client.BeginOAuthLogin(ctx, connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
		Provider:    "google",
		RedirectUri: "https://app.test/oauth/callback",
	}))
	if err != nil {
		t.Fatalf("BeginOAuthLogin: %v", err)
	}
	if !strings.Contains(begin.Msg.GetAuthorizationUrl(), "client_id="+clientID) {
		t.Fatalf("authorization url must use the authored client id, got %q", begin.Msg.GetAuthorizationUrl())
	}

	// Delete the provider → the project can no longer begin google login.
	if _, err := admin.AdminDeleteProjectOAuthProvider(ctx, connect.NewRequest(&identitypb.AdminDeleteProjectOAuthProviderRequest{
		ProjectId: projectID,
		Provider:  "google",
	})); err != nil {
		t.Fatalf("AdminDeleteProjectOAuthProvider: %v", err)
	}
	if _, err := client.BeginOAuthLogin(ctx, connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
		Provider:    "google",
		RedirectUri: "https://app.test/oauth/callback",
	})); err == nil {
		t.Fatal("after delete, google login must be unavailable for the project")
	}
}

// TestRedesign_OAuthAdmin_GitHub_AuthorAndLogin mirrors the Google author→login
// flow for GitHub, the newest per-project provider: an operator authors a
// project's GitHub provider through the admin API (PLAINTEXT secret in), the
// server encrypts + stores it, and the hosted login flow resolves the project
// and builds the exchanger from the server-encrypted secret. GitHub is
// hosted-only, so a read redacts the secret and delete removes the provider.
func TestRedesign_OAuthAdmin_GitHub_AuthorAndLogin(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()
	admin := h.adminClient(harnessAdminSecret)
	unique := time.Now().UnixNano()

	projResp, err := admin.AdminCreateProject(ctx, connect.NewRequest(&identitypb.AdminCreateProjectRequest{
		Name:           "GitHub Admin E2E",
		StorageScopeId: fmt.Sprintf("github-admin-scope-%d", unique),
	}))
	if err != nil {
		t.Fatalf("AdminCreateProject: %v", err)
	}
	projectID := projResp.Msg.GetProjectId()

	const clientID = "authored-github-client"
	setResp, err := admin.AdminSetProjectOAuthProvider(ctx, connect.NewRequest(&identitypb.AdminSetProjectOAuthProviderRequest{
		ProjectId: projectID,
		Config: &identitypb.ProjectOAuthProviderConfig{
			Provider:     "github",
			ClientId:     clientID,
			ClientSecret: "super-secret-plaintext",
		},
	}))
	if err != nil {
		t.Fatalf("AdminSetProjectOAuthProvider: %v", err)
	}
	if c := setResp.Msg.GetConfig(); c.GetClientSecret() != "" || !c.GetHasClientSecret() {
		t.Fatalf("set response not redacted: %+v", c)
	}

	listResp, err := admin.AdminListProjectOAuthProviders(ctx, connect.NewRequest(&identitypb.AdminListProjectOAuthProvidersRequest{
		ProjectId: projectID,
	}))
	if err != nil {
		t.Fatalf("AdminListProjectOAuthProviders: %v", err)
	}
	if n := len(listResp.Msg.GetProviders()); n != 1 {
		t.Fatalf("providers = %d, want 1", n)
	}
	if p := listResp.Msg.GetProviders()[0]; p.GetProvider() != "github" || p.GetClientSecret() != "" || !p.GetHasClientSecret() {
		t.Fatalf("listed provider wrong/leaky: %+v", p)
	}

	credResp, err := admin.AdminCreateProjectCredential(ctx, connect.NewRequest(&identitypb.AdminCreateProjectCredentialRequest{
		ProjectId: projectID,
		Kind:      service.CredentialKindSecret,
	}))
	if err != nil {
		t.Fatalf("AdminCreateProjectCredential: %v", err)
	}
	projectKey := credResp.Msg.GetPublicId()

	// BeginOAuthLogin succeeds only if the resolver decrypted the server-encrypted
	// secret and built the GitHub exchanger; the auth URL carries the authored id.
	client := h.ClientWithHost("", map[string]string{projectKeyHeader: projectKey})
	begin, err := client.BeginOAuthLogin(ctx, connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
		Provider:    "github",
		RedirectUri: "https://app.test/oauth/callback",
	}))
	if err != nil {
		t.Fatalf("BeginOAuthLogin: %v", err)
	}
	if !strings.Contains(begin.Msg.GetAuthorizationUrl(), "client_id="+clientID) {
		t.Fatalf("authorization url must use the authored client id, got %q", begin.Msg.GetAuthorizationUrl())
	}

	if _, err := admin.AdminDeleteProjectOAuthProvider(ctx, connect.NewRequest(&identitypb.AdminDeleteProjectOAuthProviderRequest{
		ProjectId: projectID,
		Provider:  "github",
	})); err != nil {
		t.Fatalf("AdminDeleteProjectOAuthProvider: %v", err)
	}
	if _, err := client.BeginOAuthLogin(ctx, connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
		Provider:    "github",
		RedirectUri: "https://app.test/oauth/callback",
	})); err == nil {
		t.Fatal("after delete, github login must be unavailable for the project")
	}
}
