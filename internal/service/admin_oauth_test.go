package service

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
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

// seedProjectConfig writes cfg into the fake control-plane store using the
// project's CURRENT config version, so a test lays down starting state without
// having to thread the optimistic-concurrency token by hand.
func seedProjectConfig(t *testing.T, f *adminFixture, projectID, cfg string) {
	t.Helper()
	_, ver, err := f.projects.GetProjectConfig(context.Background(), projectID)
	if err != nil {
		t.Fatalf("seed read version: %v", err)
	}
	if _, _, err := f.projects.UpdateProjectConfig(context.Background(), projectID, ver, cfg); err != nil {
		t.Fatalf("seed config: %v", err)
	}
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

	stored, _, err := f.projects.GetProjectConfig(ctx, projectID)
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
	seedProjectConfig(t, f, projectID, seed)

	if _, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider:     oauthProviderOIDC,
		ClientID:     "oidc-client",
		ClientSecret: "oidc-secret",
		OIDCIssuer:   "https://idp.example.com",
	}); err != nil {
		t.Fatalf("set oidc: %v", err)
	}

	stored, _, err := f.projects.GetProjectConfig(ctx, projectID)
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

	stored, _, _ := f.projects.GetProjectConfig(ctx, projectID)
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

	stored, _, _ := f.projects.GetProjectConfig(ctx, projectID)
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

// TestAdminSetProjectOAuthProvider_MicrosoftAllowedTenants_RoundTrip proves the
// nOAuth allow-list survives the write→read authoring round-trip (input →
// config_json → redacted view) and lands on the resolved provider config.
func TestAdminSetProjectOAuthProvider_MicrosoftAllowedTenants_RoundTrip(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	tenants := []string{"11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"}
	view, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider:                oauthProviderMicrosoft,
		ClientID:                "ms",
		ClientSecret:            "ms-secret",
		MicrosoftAllowedTenants: append([]string{"  "}, tenants...), // a blank entry is dropped
	})
	if err != nil {
		t.Fatalf("AdminSetProjectOAuthProvider: %v", err)
	}
	if !slices.Equal(view.MicrosoftAllowedTenants, tenants) {
		t.Fatalf("view allowed_tenants = %v, want %v", view.MicrosoftAllowedTenants, tenants)
	}

	// The list round-trips through config_json onto the typed provider.
	stored, err := f.projects.GetProjectConfig(ctx, projectID)
	if err != nil {
		t.Fatalf("GetProjectConfig: %v", err)
	}
	cfg, err := ParseProjectConfig(stored)
	if err != nil {
		t.Fatalf("ParseProjectConfig: %v", err)
	}
	if cfg.OAuth.Microsoft == nil || !slices.Equal(cfg.OAuth.Microsoft.AllowedTenants, tenants) {
		t.Fatalf("stored allowed_tenants = %+v, want %v", cfg.OAuth.Microsoft, tenants)
	}

	// A malformed entry (here a verified-domain form, which can never match a
	// token's GUID `tid`) is rejected at author time.
	if _, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider:                oauthProviderMicrosoft,
		ClientID:                "ms",
		ClientSecret:            "ms-secret",
		MicrosoftAllowedTenants: []string{"contoso.onmicrosoft.com"},
	}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("domain-form allowed_tenants: err = %v, want ErrInvalidArgument", err)
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

// OIDC is hosted-only and has no native-audience allow-list, so native_audiences
// on an oidc write must be rejected (not silently dropped). The same write
// without native_audiences succeeds.
func TestAdminSetProjectOAuthProvider_OIDCRejectsNativeAudiences(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	_, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider:        oauthProviderOIDC,
		ClientID:        "oidc-client",
		ClientSecret:    "oidc-secret",
		OIDCIssuer:      "https://idp.example.com",
		NativeAudiences: []string{"native.aud"},
	})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("oidc with native_audiences: err = %v, want ErrInvalidArgument", err)
	}

	// The same write without native_audiences succeeds.
	if _, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider:     oauthProviderOIDC,
		ClientID:     "oidc-client",
		ClientSecret: "oidc-secret",
		OIDCIssuer:   "https://idp.example.com",
	}); err != nil {
		t.Fatalf("oidc without native_audiences: %v", err)
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

// oauthSubtreeOf extracts the decoded "oauth" object from a project's stored
// config_json, so tests can assert exactly which keys survive a merge.
func oauthSubtreeOf(t *testing.T, f *adminFixture, projectID string) map[string]json.RawMessage {
	t.Helper()
	stored, _, err := f.projects.GetProjectConfig(context.Background(), projectID)
	if err != nil {
		t.Fatalf("GetProjectConfig: %v", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stored), &top); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	sub := map[string]json.RawMessage{}
	if raw, ok := top["oauth"]; ok {
		if err := json.Unmarshal(raw, &sub); err != nil {
			t.Fatalf("unmarshal oauth: %v", err)
		}
	}
	return sub
}

// A Set/Delete must byte-preserve every "oauth" key it does not touch —
// including a sibling provider with an UNKNOWN field and a wholly UNKNOWN
// provider key a newer binary may have written (forward/rollback compat).
func TestAdminOAuthProvider_PreservesUnknownOAuthKeys(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	// Seed config with: a top-level non-oauth key, a known provider carrying an
	// unknown field, a wholly-unknown provider key, and a provider to delete.
	const seed = `{"branding":{"product_name":"Kids"},"oauth":{` +
		`"google":{"client_id":"g","client_secret_enc":"ENC","future_field":"keepme"},` +
		`"future_provider":{"client_id":"fp","weird":123},` +
		`"apple":{"native_audiences":["com.x"]}}}`
	seedProjectConfig(t, f, projectID, seed)

	// Set a DIFFERENT provider and Delete ANOTHER one.
	if _, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider: oauthProviderMicrosoft, ClientID: "m", ClientSecret: "ms-secret",
	}); err != nil {
		t.Fatalf("set microsoft: %v", err)
	}
	if err := f.svc.AdminDeleteProjectOAuthProvider(ctx, oauthAdminSecret, projectID, oauthProviderApple); err != nil {
		t.Fatalf("delete apple: %v", err)
	}

	sub := oauthSubtreeOf(t, f, projectID)
	// The unknown provider key survives byte-for-byte.
	if got := string(sub["future_provider"]); got != `{"client_id":"fp","weird":123}` {
		t.Fatalf("future_provider not preserved: %s", got)
	}
	// The unknown field inside the untouched known provider survives.
	if got := string(sub["google"]); !strings.Contains(got, `"future_field":"keepme"`) {
		t.Fatalf("google unknown field dropped: %s", got)
	}
	// The edited/removed providers reflect the operations.
	if _, ok := sub["microsoft"]; !ok {
		t.Fatal("microsoft not set")
	}
	if _, ok := sub["apple"]; ok {
		t.Fatal("apple not deleted")
	}
	// The non-oauth top-level key survives.
	stored, _, _ := f.projects.GetProjectConfig(ctx, projectID)
	if !strings.Contains(stored, `"product_name":"Kids"`) {
		t.Fatalf("branding dropped: %s", stored)
	}
}

// Delete removes only the target key; it must NOT decode or validate the
// surviving providers, so a stale INVALID neighbour never blocks the deletion.
func TestAdminDeleteProjectOAuthProvider_IgnoresInvalidNeighbor(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	// A microsoft block with a malformed issuer_format (no %s) — invalid, but
	// already at rest — alongside a valid google block.
	const seed = `{"oauth":{` +
		`"google":{"client_id":"g","client_secret_enc":"ENC"},` +
		`"microsoft":{"client_id":"m","client_secret_enc":"ENC","issuer_format":"https://login.test/no-verb"}}}`
	seedProjectConfig(t, f, projectID, seed)

	if err := f.svc.AdminDeleteProjectOAuthProvider(ctx, oauthAdminSecret, projectID, oauthProviderGoogle); err != nil {
		t.Fatalf("delete google must succeed despite invalid neighbor: %v", err)
	}
	sub := oauthSubtreeOf(t, f, projectID)
	if _, ok := sub["google"]; ok {
		t.Fatal("google not deleted")
	}
	if _, ok := sub["microsoft"]; !ok {
		t.Fatal("invalid microsoft neighbor must survive the deletion")
	}
}

func TestAdminDeleteProjectOAuthProvider_MissingIsNoop(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	// Delete a provider that was never configured — no error, no oauth block.
	if err := f.svc.AdminDeleteProjectOAuthProvider(ctx, oauthAdminSecret, projectID, oauthProviderGoogle); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
	if list, err := f.svc.AdminListProjectOAuthProviders(ctx, oauthAdminSecret, projectID); err != nil || len(list) != 0 {
		t.Fatalf("list = %+v, err = %v; want empty", list, err)
	}
}

func TestAdminListProjectOAuthProviders_EmptyProject(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	projectID := seedOAuthProject(t, f)
	list, err := f.svc.AdminListProjectOAuthProviders(context.Background(), oauthAdminSecret, projectID)
	if err != nil || len(list) != 0 {
		t.Fatalf("list = %+v, err = %v; want empty", list, err)
	}
}

// Exercises the Microsoft and OIDC field mappings (buildProvider + providerView
// + decodeProvider) and a native-only Apple block, plus the sorted list order.
func TestAdminSetProjectOAuthProvider_AllProviderFields(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	ms, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider:              oauthProviderMicrosoft,
		ClientID:              "ms-client",
		ClientSecret:          "ms-secret",
		MicrosoftTenantID:     "tenant-abc",
		MicrosoftIssuerFormat: "https://login.test/%s/v2.0",
		NativeAudiences:       []string{"ms-native"},
	})
	if err != nil {
		t.Fatalf("set microsoft: %v", err)
	}
	if ms.MicrosoftTenantID != "tenant-abc" || ms.MicrosoftIssuerFormat != "https://login.test/%s/v2.0" ||
		!ms.HasClientSecret || len(ms.NativeAudiences) != 1 {
		t.Fatalf("microsoft view = %+v", ms)
	}

	oidc, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider:         oauthProviderOIDC,
		ClientID:         "oidc-client",
		ClientSecret:     "oidc-secret",
		OIDCIssuer:       "https://idp.example.com",
		OIDCDiscoveryURL: "https://idp.example.com/.well-known/openid-configuration",
		OIDCScopes:       "openid email profile",
	})
	if err != nil {
		t.Fatalf("set oidc: %v", err)
	}
	if oidc.OIDCIssuer != "https://idp.example.com" || oidc.OIDCDiscoveryURL == "" ||
		oidc.OIDCScopes != "openid email profile" || !oidc.HasClientSecret {
		t.Fatalf("oidc view = %+v", oidc)
	}

	// A native-only Apple block: no hosted credentials, so no private key stored.
	apple, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider:        oauthProviderApple,
		NativeAudiences: []string{"com.example.app"},
	})
	if err != nil {
		t.Fatalf("set apple native-only: %v", err)
	}
	if apple.HasPrivateKey || len(apple.NativeAudiences) != 1 {
		t.Fatalf("apple view = %+v", apple)
	}

	// List returns all three, ordered by provider key (apple, microsoft, oidc),
	// with secrets redacted.
	list, err := f.svc.AdminListProjectOAuthProviders(ctx, oauthAdminSecret, projectID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	gotOrder := []string{list[0].Provider, list[1].Provider, list[2].Provider}
	want := []string{oauthProviderApple, oauthProviderMicrosoft, oauthProviderOIDC}
	for i := range want {
		if gotOrder[i] != want[i] {
			t.Fatalf("list order = %v, want %v", gotOrder, want)
		}
	}
	if !list[1].HasClientSecret || list[1].MicrosoftTenantID != "tenant-abc" {
		t.Fatalf("listed microsoft not mapped/redacted: %+v", list[1])
	}
}

// A stored oauth subtree that is not a JSON object is a caller-visible config
// error rather than a silent nil.
func TestAdminOAuthProvider_MalformedStoredSubtree(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)
	seedProjectConfig(t, f, projectID, `{"oauth":["not","an","object"]}`)
	if _, err := f.svc.AdminListProjectOAuthProviders(ctx, oauthAdminSecret, projectID); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("list malformed oauth: err = %v, want ErrInvalidArgument", err)
	}
}

// Covers the argument-validation error paths of all three RPCs.
func TestAdminOAuthRPCs_ArgumentValidation(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()

	// Missing project_id on each RPC.
	if _, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, "  ", &ProjectOAuthProviderInput{Provider: oauthProviderGoogle, ClientID: "g", ClientSecret: "s"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("set missing project_id: %v", err)
	}
	if err := f.svc.AdminDeleteProjectOAuthProvider(ctx, oauthAdminSecret, "", oauthProviderGoogle); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("delete missing project_id: %v", err)
	}
	if _, err := f.svc.AdminListProjectOAuthProviders(ctx, oauthAdminSecret, ""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("list missing project_id: %v", err)
	}

	// Nil config on Set.
	if _, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, "p", nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("set nil config: %v", err)
	}

	// Unknown provider on Delete (normalize rejects it before touching config).
	if err := f.svc.AdminDeleteProjectOAuthProvider(ctx, oauthAdminSecret, "p", "facebook"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("delete unknown provider: %v", err)
	}
}

// A stored config that is not a JSON object at all is a caller-visible error.
func TestAdminOAuthProvider_MalformedStoredTopLevel(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)
	seedProjectConfig(t, f, projectID, `[1,2,3]`)
	if _, err := f.svc.AdminListProjectOAuthProviders(ctx, oauthAdminSecret, projectID); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("list malformed top-level: err = %v, want ErrInvalidArgument", err)
	}
}

// A known provider key whose stored VALUE is not a valid provider object makes
// a list fail cleanly (exercising the decodeProvider error path).
func TestAdminListProjectOAuthProviders_MalformedProviderValue(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)
	seedProjectConfig(t, f, projectID, `{"oauth":{"google":"not-an-object"}}`)
	if _, err := f.svc.AdminListProjectOAuthProviders(ctx, oauthAdminSecret, projectID); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("list malformed provider: err = %v, want ErrInvalidArgument", err)
	}
}

// Empty-secret-keeps must work for every provider, not just Google — this
// exercises the existing-secret decode branch of buildProvider per provider.
func TestAdminSetProjectOAuthProvider_EmptySecretKeepsAllProviders(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	// Microsoft: set with a secret, then re-set with empty secret + a new field.
	if _, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider: oauthProviderMicrosoft, ClientID: "m", ClientSecret: "ms-1",
	}); err != nil {
		t.Fatalf("ms set: %v", err)
	}
	if v, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider: oauthProviderMicrosoft, ClientID: "m2", MicrosoftTenantID: "t",
	}); err != nil || !v.HasClientSecret || v.ClientID != "m2" {
		t.Fatalf("ms re-set keep: v=%+v err=%v", v, err)
	}

	// OIDC: same pattern.
	if _, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider: oauthProviderOIDC, ClientID: "o", ClientSecret: "o-1", OIDCIssuer: "https://idp.example.com",
	}); err != nil {
		t.Fatalf("oidc set: %v", err)
	}
	v, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider: oauthProviderOIDC, ClientID: "o2", OIDCIssuer: "https://idp.example.com", OIDCScopes: "openid",
	})
	if err != nil || !v.HasClientSecret || v.ClientID != "o2" {
		t.Fatalf("oidc re-set keep: v=%+v err=%v", v, err)
	}
	// Confirm both secrets round-trip after the keep.
	sub := oauthSubtreeOf(t, f, projectID)
	for _, key := range []string{oauthProviderMicrosoft, oauthProviderOIDC} {
		prov, err := decodeProvider(key, sub[key])
		if err != nil {
			t.Fatalf("decode %s: %v", key, err)
		}
		if !providerView(key, prov).HasClientSecret {
			t.Fatalf("%s secret not kept", key)
		}
	}
}

// decodeProvider surfaces a malformed stored VALUE for each provider key, not
// just Google — a list over a corrupted subtree fails cleanly per provider.
func TestAdminListProjectOAuthProviders_MalformedPerProvider(t *testing.T) {
	t.Parallel()
	for _, key := range []string{oauthProviderMicrosoft, oauthProviderApple, oauthProviderOIDC} {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			f := newAdminFixture(oauthAdminSecret)
			ctx := context.Background()
			projectID := seedOAuthProject(t, f)
			seedProjectConfig(t, f, projectID, `{"oauth":{"`+key+`":42}}`)
			if _, err := f.svc.AdminListProjectOAuthProviders(ctx, oauthAdminSecret, projectID); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("list malformed %s: err = %v, want ErrInvalidArgument", key, err)
			}
		})
	}
}

// TestAdminSetProjectOAuthProvider_ConcurrentDifferentProviders_NoLostUpdate is
// the service-level regression proof for issue #313: two operators concurrently
// set DIFFERENT providers on the SAME project. The config_json write is a
// read-modify-write, so without the optimistic-concurrency CAS + retry the later
// writer would clobber the earlier one and a provider would vanish. With it,
// BOTH providers must be present afterward and each must emit exactly one audit
// event (retries re-run the merge but never double-log). Run with -race.
func TestAdminSetProjectOAuthProvider_ConcurrentDifferentProviders_NoLostUpdate(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	start := make(chan struct{})

	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, errs[0] = f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
			Provider: oauthProviderGoogle, ClientID: "goog", ClientSecret: "goog-secret",
		})
	}()
	go func() {
		defer wg.Done()
		<-start
		_, errs[1] = f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
			Provider: oauthProviderMicrosoft, ClientID: "ms", ClientSecret: "ms-secret",
		})
	}()
	close(start)
	wg.Wait()

	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("concurrent set errors: google=%v microsoft=%v", errs[0], errs[1])
	}

	// NEITHER write was lost: both providers survive in the merged config.
	stored, _, err := f.projects.GetProjectConfig(ctx, projectID)
	if err != nil {
		t.Fatalf("GetProjectConfig: %v", err)
	}
	cfg, err := ParseProjectConfig(stored)
	if err != nil {
		t.Fatalf("ParseProjectConfig: %v", err)
	}
	if cfg.OAuth.Google == nil || cfg.OAuth.Google.ClientID != "goog" {
		t.Fatalf("google provider lost to a concurrent clobber: %+v", cfg.OAuth.Google)
	}
	if cfg.OAuth.Microsoft == nil || cfg.OAuth.Microsoft.ClientID != "ms" {
		t.Fatalf("microsoft provider lost to a concurrent clobber: %+v", cfg.OAuth.Microsoft)
	}
	// Exactly two successful sets → exactly two audit events (a retried set that
	// re-ran the merge must not double-log).
	if n := f.audit.countByEventType(string(audit.EventProjectOAuthProviderSet)); n != 2 {
		t.Fatalf("project_oauth_provider_set events = %d, want 2", n)
	}
}

// TestControlPlaneStore_ConfigCAS_StaleVersionRejected proves the store contract
// every driver's fake must honour: a write carrying a version the row has moved
// past is rejected with ErrProjectConfigConflict and does not mutate the blob.
func TestControlPlaneStore_ConfigCAS_StaleVersionRejected(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	_, v0, err := f.projects.GetProjectConfig(ctx, projectID)
	if err != nil {
		t.Fatalf("GetProjectConfig: %v", err)
	}
	if _, v1, err := f.projects.UpdateProjectConfig(ctx, projectID, v0, `{"branding":{"product_name":"A"}}`); err != nil || v1 != v0+1 {
		t.Fatalf("first write: v1=%d err=%v", v1, err)
	}
	// A second write still carrying the now-stale v0 loses the CAS.
	if _, _, err := f.projects.UpdateProjectConfig(ctx, projectID, v0, `{"branding":{"product_name":"B"}}`); !errors.Is(err, ErrProjectConfigConflict) {
		t.Fatalf("stale write: err = %v, want ErrProjectConfigConflict", err)
	}
	// The blob is unchanged by the rejected write.
	stored, _, err := f.projects.GetProjectConfig(ctx, projectID)
	if err != nil {
		t.Fatalf("GetProjectConfig after stale: %v", err)
	}
	if !strings.Contains(stored, `"product_name":"A"`) {
		t.Fatalf("rejected stale write mutated the blob: %s", stored)
	}
}

// TestAdminSetProjectOAuthProvider_RetryExhaustion_Conflict proves a config
// write that keeps losing the CAS surfaces ErrProjectConfigConflict after the
// bounded retries — the retryable signal the Connect layer maps to CodeAborted.
func TestAdminSetProjectOAuthProvider_RetryExhaustion_Conflict(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	// Every UpdateProjectConfig loses its CAS, so the bounded retry loop exhausts.
	f.projects.forceConflict = true
	_, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider: oauthProviderGoogle, ClientID: "goog", ClientSecret: "goog-secret",
	})
	if !errors.Is(err, ErrProjectConfigConflict) {
		t.Fatalf("retry exhaustion: err = %v, want ErrProjectConfigConflict", err)
	}
	// A persistent conflict must NOT emit a success audit event.
	if n := f.audit.countByEventType(string(audit.EventProjectOAuthProviderSet)); n != 0 {
		t.Fatalf("project_oauth_provider_set events = %d, want 0 on exhausted conflict", n)
	}
}

// TestAdminSetProjectOAuthProvider_StoreErrorNotRetried proves the retry helper
// only retries a version conflict: any OTHER store error from the write is
// surfaced immediately (not spun on and not swallowed as a conflict).
func TestAdminSetProjectOAuthProvider_StoreErrorNotRetried(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	sentinel := errors.New("boom: transient store failure")
	f.projects.updateErr = sentinel
	_, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider: oauthProviderGoogle, ClientID: "goog", ClientSecret: "goog-secret",
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("store error: err = %v, want %v", err, sentinel)
	}
	if errors.Is(err, ErrProjectConfigConflict) {
		t.Fatal("a non-conflict store error must not be reported as a config conflict")
	}
}
