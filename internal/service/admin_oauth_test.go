package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/secretcrypto"
)

const oauthAdminSecret = "oauth-operator-secret"

// seedOAuthProject creates a project in the fake control-plane store and returns
// its id, so the OAuth admin RPCs (which read-modify-write config_json) have a
// project to write to.
func seedOAuthProject(t *testing.T, f *adminFixture) string {
	t.Helper()
	id, err := f.projects.CreateProject(context.Background(), &AdminProject{StorageScopeID: "scope-" + itoa(f.projects.nextID+1)})
	if err != nil {
		t.Fatalf("seed project: %v", err)
	}
	return id
}

func TestAdminSetProjectOAuthProvider_EncryptsAndResolves(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	const plaintext = "google-top-secret"
	view, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider:               oauthProviderGoogle,
		ClientID:               "goog-client",
		ClientSecret:           plaintext,
		GoogleAuthorizationURL: "https://accounts.example/authorize",
	})
	if err != nil {
		t.Fatalf("AdminSetProjectOAuthProvider: %v", err)
	}
	// The response redacts the secret but reports its presence.
	if !view.HasClientSecret || view.ClientID != "goog-client" {
		t.Fatalf("view = %+v", view)
	}

	stored, err := f.projects.GetProjectConfig(ctx, projectID)
	if err != nil {
		t.Fatalf("GetProjectConfig: %v", err)
	}
	// The plaintext must never appear at rest.
	if strings.Contains(stored, plaintext) {
		t.Fatalf("plaintext secret leaked into config_json: %s", stored)
	}

	// The stored ciphertext decrypts back to the plaintext with the same key.
	cfg, err := ParseProjectConfig(stored)
	if err != nil {
		t.Fatalf("ParseProjectConfig: %v", err)
	}
	if cfg.OAuth.Google == nil || cfg.OAuth.Google.ClientSecretEnc == "" {
		t.Fatalf("google secret not stored: %+v", cfg.OAuth.Google)
	}
	dec, err := secretcrypto.Decrypt(cfg.OAuth.Google.ClientSecretEnc, testAdminSecretsKey())
	if err != nil || dec != plaintext {
		t.Fatalf("decrypt = %q, %v; want %q", dec, err, plaintext)
	}

	// The resolver builds the exchanger for this project, proving it can decrypt
	// and use the authored secret end-to-end (build fails → ok=false otherwise).
	r := newOAuthResolver("default-proj", nil, zap.NewNop()).withSecrets(testAdminSecretsKey(), nil)
	rctx := WithProjectScope(ctx, &ProjectScope{ProjectID: projectID, OAuth: cfg.OAuth})
	if ex, ok := r.exchangerFor(rctx, oauthProviderGoogle); !ok || ex == nil {
		t.Fatal("resolver could not build the authored google provider")
	}

	if n := f.audit.countByEventType(string(audit.EventProjectOAuthProviderSet)); n != 1 {
		t.Fatalf("project_oauth_provider_set events = %d, want 1", n)
	}
}

func TestAdminSetProjectOAuthProvider_PreservesOtherConfigKeys(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	// Seed unrelated config (branding + cors) directly.
	const seed = `{"branding":{"product_name":"Kids"},"cors":{"allowed_origins":["https://pro.example.com"]}}`
	if _, err := f.projects.UpdateProjectConfig(ctx, projectID, seed); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	if _, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider:     oauthProviderOIDC,
		ClientID:     "oidc-client",
		ClientSecret: "oidc-secret",
		OIDCIssuer:   "https://idp.example.com",
	}); err != nil {
		t.Fatalf("set oidc: %v", err)
	}

	stored, err := f.projects.GetProjectConfig(ctx, projectID)
	if err != nil {
		t.Fatalf("GetProjectConfig: %v", err)
	}
	cfg, err := ParseProjectConfig(stored)
	if err != nil {
		t.Fatalf("ParseProjectConfig: %v", err)
	}
	// Branding and CORS survive; the oauth provider is added.
	if cfg.Branding.ProductName != "Kids" {
		t.Fatalf("branding dropped: %+v", cfg.Branding)
	}
	if len(cfg.CORS.AllowedOrigins) != 1 || cfg.CORS.AllowedOrigins[0] != "https://pro.example.com" {
		t.Fatalf("cors dropped: %+v", cfg.CORS)
	}
	if cfg.OAuth.OIDC == nil || cfg.OAuth.OIDC.ClientID != "oidc-client" {
		t.Fatalf("oidc not added: %+v", cfg.OAuth.OIDC)
	}
}

func TestAdminSetProjectOAuthProvider_EmptySecretKeepsExisting(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	if _, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider:     oauthProviderGoogle,
		ClientID:     "goog-client",
		ClientSecret: "first-secret",
	}); err != nil {
		t.Fatalf("initial set: %v", err)
	}

	// Re-set with an empty secret but a new client id + native audiences: the
	// stored secret is preserved, the other fields are replaced.
	view, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider:        oauthProviderGoogle,
		ClientID:        "goog-client-2",
		NativeAudiences: []string{"ios.aud", "android.aud"},
	})
	if err != nil {
		t.Fatalf("re-set: %v", err)
	}
	if !view.HasClientSecret || view.ClientID != "goog-client-2" || len(view.NativeAudiences) != 2 {
		t.Fatalf("view = %+v", view)
	}

	stored, _ := f.projects.GetProjectConfig(ctx, projectID)
	cfg, err := ParseProjectConfig(stored)
	if err != nil {
		t.Fatalf("ParseProjectConfig: %v", err)
	}
	dec, err := secretcrypto.Decrypt(cfg.OAuth.Google.ClientSecretEnc, testAdminSecretsKey())
	if err != nil || dec != "first-secret" {
		t.Fatalf("secret not preserved: dec=%q err=%v", dec, err)
	}
}

func TestAdminSetProjectOAuthProvider_RotatesSecret(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	set := func(secret string) {
		if _, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
			Provider: oauthProviderApple, ClientID: "svc.id", AppleTeamID: "TEAM", AppleKeyID: "KEY", ApplePrivateKey: secret,
		}); err != nil {
			t.Fatalf("set apple: %v", err)
		}
	}
	set("key-v1")
	set("key-v2")

	stored, _ := f.projects.GetProjectConfig(ctx, projectID)
	cfg, _ := ParseProjectConfig(stored)
	dec, err := secretcrypto.Decrypt(cfg.OAuth.Apple.PrivateKeyEnc, testAdminSecretsKey())
	if err != nil || dec != "key-v2" {
		t.Fatalf("rotation failed: dec=%q err=%v", dec, err)
	}
}

func TestAdminDeleteProjectOAuthProvider_RemovesOnlyThatProvider(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	mustSet := func(in *ProjectOAuthProviderInput) {
		if _, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, in); err != nil {
			t.Fatalf("set %s: %v", in.Provider, err)
		}
	}
	mustSet(&ProjectOAuthProviderInput{Provider: oauthProviderGoogle, ClientID: "g", ClientSecret: "gs"})
	mustSet(&ProjectOAuthProviderInput{Provider: oauthProviderOIDC, ClientID: "o", ClientSecret: "os", OIDCIssuer: "https://idp.example.com"})

	if err := f.svc.AdminDeleteProjectOAuthProvider(ctx, oauthAdminSecret, projectID, oauthProviderGoogle); err != nil {
		t.Fatalf("delete google: %v", err)
	}

	list, err := f.svc.AdminListProjectOAuthProviders(ctx, oauthAdminSecret, projectID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].Provider != oauthProviderOIDC {
		t.Fatalf("after delete, providers = %+v", list)
	}
	if n := f.audit.countByEventType(string(audit.EventProjectOAuthProviderRemoved)); n != 1 {
		t.Fatalf("removed events = %d, want 1", n)
	}
}

func TestAdminListProjectOAuthProviders_RedactsSecrets(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	if _, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider: oauthProviderApple, ClientID: "svc.id", AppleTeamID: "TEAM", AppleKeyID: "KEY", ApplePrivateKey: "the-key",
	}); err != nil {
		t.Fatalf("set apple: %v", err)
	}

	list, err := f.svc.AdminListProjectOAuthProviders(ctx, oauthAdminSecret, projectID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("providers = %d, want 1", len(list))
	}
	v := list[0]
	// The redacted view reports presence but carries neither plaintext nor
	// ciphertext (the view type has no field to carry either).
	if !v.HasPrivateKey || v.AppleTeamID != "TEAM" || v.AppleKeyID != "KEY" {
		t.Fatalf("view = %+v", v)
	}
}

func TestAdminSetProjectOAuthProvider_RejectsBadIssuerFormat(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	for _, bad := range []string{"https://login.test/v2.0", "https://login.test/%s/%s/v2.0", "https://login.test/%d/v2.0"} {
		_, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
			Provider:              oauthProviderMicrosoft,
			ClientID:              "ms",
			ClientSecret:          "ms-secret",
			MicrosoftIssuerFormat: bad,
		})
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("issuer_format %q: err = %v, want ErrInvalidArgument", bad, err)
		}
	}

	// A well-formed single-%s format is accepted.
	if _, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider:              oauthProviderMicrosoft,
		ClientID:              "ms",
		ClientSecret:          "ms-secret",
		MicrosoftIssuerFormat: "https://login.test/%s/v2.0",
	}); err != nil {
		t.Fatalf("good issuer_format rejected: %v", err)
	}
}

func TestAdminSetProjectOAuthProvider_RejectsMissingRequiredFields(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	// Google with a client_id but no secret and no native audiences is an
	// incomplete hosted block.
	_, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider: oauthProviderGoogle,
		ClientID: "goog-client",
	})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("incomplete google: err = %v, want ErrInvalidArgument", err)
	}

	// OIDC without issuer or discovery_url is incomplete.
	_, err = f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider: oauthProviderOIDC, ClientID: "o", ClientSecret: "os",
	})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("incomplete oidc: err = %v, want ErrInvalidArgument", err)
	}
}

func TestAdminSetProjectOAuthProvider_RejectsBadURL(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	_, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider:               oauthProviderGoogle,
		ClientID:               "g",
		ClientSecret:           "gs",
		GoogleAuthorizationURL: "http://insecure.example/authorize", // must be https
	})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("bad url: err = %v, want ErrInvalidArgument", err)
	}
}

func TestAdminSetProjectOAuthProvider_SecretWithoutKey(t *testing.T) {
	t.Parallel()
	f := newAdminFixtureWithKey(oauthAdminSecret, nil) // no secrets key configured
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	_, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider: oauthProviderGoogle, ClientID: "g", ClientSecret: "gs",
	})
	if !errors.Is(err, ErrProjectSecretsKeyMissing) {
		t.Fatalf("err = %v, want ErrProjectSecretsKeyMissing", err)
	}
}

func TestAdminSetProjectOAuthProvider_UnknownProvider(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	_, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider: "facebook", ClientID: "x", ClientSecret: "y",
	})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestAdminSetProjectOAuthProvider_UnknownProject(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	_, err := f.svc.AdminSetProjectOAuthProvider(context.Background(), oauthAdminSecret, "no-such-project", &ProjectOAuthProviderInput{
		Provider: oauthProviderGoogle, ClientID: "g", ClientSecret: "gs",
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestAdminOAuthRPCs_BadSecretDenied(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()

	if _, err := f.svc.AdminSetProjectOAuthProvider(ctx, "wrong", "p", &ProjectOAuthProviderInput{Provider: oauthProviderGoogle}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("set: err = %v, want ErrPermissionDenied", err)
	}
	if err := f.svc.AdminDeleteProjectOAuthProvider(ctx, "wrong", "p", oauthProviderGoogle); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("delete: err = %v, want ErrPermissionDenied", err)
	}
	if _, err := f.svc.AdminListProjectOAuthProviders(ctx, "wrong", "p"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("list: err = %v, want ErrPermissionDenied", err)
	}
}

func TestAdminOAuthRPCs_DisabledWhenSecretEmpty(t *testing.T) {
	t.Parallel()
	f := newAdminFixture("")
	ctx := context.Background()

	if _, err := f.svc.AdminSetProjectOAuthProvider(ctx, "anything", "p", &ProjectOAuthProviderInput{Provider: oauthProviderGoogle}); !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("set: err = %v, want ErrUnimplemented", err)
	}
	if err := f.svc.AdminDeleteProjectOAuthProvider(ctx, "anything", "p", oauthProviderGoogle); !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("delete: err = %v, want ErrUnimplemented", err)
	}
	if _, err := f.svc.AdminListProjectOAuthProviders(ctx, "anything", "p"); !errors.Is(err, ErrUnimplemented) {
		t.Fatalf("list: err = %v, want ErrUnimplemented", err)
	}
}
