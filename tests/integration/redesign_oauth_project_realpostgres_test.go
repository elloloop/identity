//go:build integration && realpostgres

package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/secretcrypto"
)

// seedProjectWithGoogle creates a fresh project, sets its config_json to a
// per-project Google OAuth provider whose client secret is encrypted with the
// harness's project secrets key, and returns the project's public credential id
// (usable as X-Project-Key).
func seedProjectWithGoogle(t *testing.T, h *RedesignHarness, googleClientID string) string {
	t.Helper()
	ctx := context.Background()
	admin := h.adminClient(harnessAdminSecret)
	unique := time.Now().UnixNano()

	projResp, err := admin.AdminCreateProject(ctx, connect.NewRequest(&identitypb.AdminCreateProjectRequest{
		Name:           "OAuth " + googleClientID,
		StorageScopeId: fmt.Sprintf("oauth-scope-%s-%d", googleClientID, unique),
	}))
	if err != nil {
		t.Fatalf("AdminCreateProject: %v", err)
	}
	projectID := projResp.Msg.GetProjectId()

	credResp, err := admin.AdminCreateProjectCredential(ctx, connect.NewRequest(&identitypb.AdminCreateProjectCredentialRequest{
		ProjectId: projectID,
		Kind:      service.CredentialKindSecret,
	}))
	if err != nil {
		t.Fatalf("AdminCreateProjectCredential: %v", err)
	}

	key, err := base64.StdEncoding.DecodeString(testProjectSecretsKey)
	if err != nil {
		t.Fatalf("decode secrets key: %v", err)
	}
	enc, err := secretcrypto.Encrypt(googleClientID+"-secret", key)
	if err != nil {
		t.Fatalf("encrypt secret: %v", err)
	}
	cfgJSON := fmt.Sprintf(
		`{"oauth":{"google":{"client_id":%q,"client_secret_enc":%q,"authorization_url":"https://accounts.example/authorize"}}}`,
		googleClientID, enc,
	)
	// A freshly-created project is at config_version 0; CAS against it.
	if _, _, err := h.Stores.controlPlane.UpdateProjectConfig(ctx, projectID, 0, cfgJSON); err != nil {
		t.Fatalf("UpdateProjectConfig: %v", err)
	}
	return credResp.Msg.GetPublicId()
}

// TestRedesign_PerProjectOAuth_Isolation asserts the Firebase-project model:
// two projects each configure their OWN Google provider, and each project's
// BeginOAuthLogin produces an authorization URL carrying THAT project's
// client_id — never the other's. The default project, which configures no
// provider and has no env OAuth, cannot use Google at all.
func TestRedesign_PerProjectOAuth_Isolation(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()

	keyB := seedProjectWithGoogle(t, h, "projectB-google")
	keyC := seedProjectWithGoogle(t, h, "projectC-google")

	begin := func(projectKey string) (string, error) {
		client := h.ClientWithHost("", map[string]string{projectKeyHeader: projectKey})
		resp, err := client.BeginOAuthLogin(ctx, connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
			Provider:    "google",
			RedirectUri: "https://app.test/oauth/callback",
		}))
		if err != nil {
			return "", err
		}
		return resp.Msg.GetAuthorizationUrl(), nil
	}

	urlB, err := begin(keyB)
	if err != nil {
		t.Fatalf("project B BeginOAuthLogin: %v", err)
	}
	if !strings.Contains(urlB, "client_id=projectB-google") {
		t.Errorf("project B url must use its own client_id, got %q", urlB)
	}
	if strings.Contains(urlB, "projectC-google") {
		t.Errorf("project B url leaked project C client_id: %q", urlB)
	}

	urlC, err := begin(keyC)
	if err != nil {
		t.Fatalf("project C BeginOAuthLogin: %v", err)
	}
	if !strings.Contains(urlC, "client_id=projectC-google") {
		t.Errorf("project C url must use its own client_id, got %q", urlC)
	}

	// The default project configures no provider and has no env OAuth → disabled.
	if _, err := h.Client.BeginOAuthLogin(ctx, connect.NewRequest(&identitypb.BeginOAuthLoginRequest{
		Provider:    "google",
		RedirectUri: "https://app.test/oauth/callback",
	})); err == nil {
		t.Fatal("default project without any provider must not begin google oauth")
	}
}
