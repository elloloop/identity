package service

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/secretcrypto"
)

// storedOAuth reads the project's stored config and returns it raw and parsed,
// failing when it no longer parses (a write left the project unusable).
func storedOAuth(t *testing.T, f *adminFixture, projectID string) (string, ProjectOAuthConfig) {
	t.Helper()
	stored, _, err := f.projects.GetProjectConfig(context.Background(), projectID)
	if err != nil {
		t.Fatalf("GetProjectConfig: %v", err)
	}
	cfg, err := ParseProjectConfig(stored)
	if err != nil {
		t.Fatalf("stored config no longer parses: %v\n%s", err, stored)
	}
	return stored, cfg.OAuth
}

// TestAdminHostClient_SetListDelete authors host clients beside a base
// provider: each is encrypted at rest, listed redacted in host order, keeps
// its stored secret on an empty re-set, and is removed on its own, leaving the
// base provider, the other host clients and every unknown key alone.
func TestAdminHostClient_SetListDelete(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)
	seedProjectConfig(t, f, projectID, `{"custom":{"keep":1},"oauth":{"future":{"keep":2}}}`)

	if _, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider: oauthProviderGoogle, ClientID: "base-google", ClientSecret: "base-secret",
	}); err != nil {
		t.Fatalf("set base google: %v", err)
	}

	const hostSecret = "host-b-google-secret"
	view, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider: oauthProviderGoogle, CallbackHost: " Auth.B.Example. ", ClientID: hostBGoogle, ClientSecret: hostSecret,
	})
	if err != nil {
		t.Fatalf("set host google: %v", err)
	}
	want := ProjectOAuthProviderView{Provider: oauthProviderGoogle, CallbackHost: hostB, ClientID: hostBGoogle, HasClientSecret: true}
	if !reflect.DeepEqual(*view, want) {
		t.Fatalf("view = %+v, want %+v", *view, want)
	}
	if _, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider: oauthProviderApple, CallbackHost: hostB, ClientID: hostBAppleID,
	}); err != nil {
		t.Fatalf("set host apple: %v", err)
	}
	if _, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider: oauthProviderMicrosoft, CallbackHost: hostA, ClientID: "host-a-microsoft", ClientSecret: "host-a-secret",
	}); err != nil {
		t.Fatalf("set host microsoft: %v", err)
	}

	stored, cfg := storedOAuth(t, f, projectID)
	if strings.Contains(stored, hostSecret) {
		t.Fatalf("plaintext host secret leaked into config_json: %s", stored)
	}
	if !strings.Contains(stored, `"custom":{"keep":1}`) || !strings.Contains(stored, `"future":{"keep":2}`) {
		t.Fatalf("unknown keys were not preserved: %s", stored)
	}
	enc := cfg.Hosts[hostB][oauthProviderGoogle].ClientSecretEnc
	if dec, err := secretcrypto.Decrypt(enc, testAdminSecretsKey()); err != nil || dec != hostSecret {
		t.Fatalf("host secret decrypts to %q, %v", dec, err)
	}
	if cfg.Google == nil || cfg.Google.ClientID != "base-google" {
		t.Fatalf("the base provider changed: %+v", cfg.Google)
	}
	if n := f.audit.countByEventTypeAndDetail(string(audit.EventProjectOAuthProviderSet), "callback_host", hostB); n != 2 {
		t.Fatalf("set events naming %s = %d, want 2", hostB, n)
	}

	providers, hostClients, err := f.svc.AdminListProjectOAuthProviders(ctx, oauthAdminSecret, projectID)
	if err != nil || len(providers) != 1 || providers[0].Provider != oauthProviderGoogle || providers[0].CallbackHost != "" {
		t.Fatalf("providers = %+v, err = %v", providers, err)
	}
	var listed []string
	for _, v := range hostClients {
		listed = append(listed, v.CallbackHost+"/"+v.Provider+"/"+v.ClientID)
		if v.HasClientSecret != (v.Provider != oauthProviderApple) {
			t.Errorf("%s/%s: has_client_secret = %v", v.CallbackHost, v.Provider, v.HasClientSecret)
		}
	}
	if got, want := strings.Join(listed, " "), hostA+"/microsoft/host-a-microsoft "+hostB+"/apple/"+hostBAppleID+" "+hostB+"/google/"+hostBGoogle; got != want {
		t.Fatalf("host clients = %s, want %s", got, want)
	}

	// An empty secret keeps the stored one.
	if v, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider: oauthProviderGoogle, CallbackHost: hostB, ClientID: "host-b-google-2",
	}); err != nil || !v.HasClientSecret || v.ClientID != "host-b-google-2" {
		t.Fatalf("empty-secret keep: v = %+v, err = %v", v, err)
	}
	if _, cfg = storedOAuth(t, f, projectID); cfg.Hosts[hostB][oauthProviderGoogle].ClientSecretEnc != enc {
		t.Fatal("an empty secret must keep the stored ciphertext")
	}

	// Deleting the base provider leaves its host clients.
	if err := f.svc.AdminDeleteProjectOAuthProvider(ctx, oauthAdminSecret, projectID, oauthProviderGoogle, ""); err != nil {
		t.Fatalf("delete base google: %v", err)
	}
	if _, cfg = storedOAuth(t, f, projectID); cfg.Google != nil || len(cfg.Hosts[hostB]) != 2 {
		t.Fatalf("after deleting the base: google = %+v, hosts = %+v", cfg.Google, cfg.Hosts)
	}

	// Each host client goes on its own; an emptied host and then the hosts key go with the last.
	for _, d := range []struct{ provider, host string }{
		{oauthProviderGoogle, hostB}, {oauthProviderGoogle, hostB}, {oauthProviderApple, "AUTH.B.EXAMPLE"}, {oauthProviderMicrosoft, hostA},
	} {
		if err := f.svc.AdminDeleteProjectOAuthProvider(ctx, oauthAdminSecret, projectID, d.provider, d.host); err != nil {
			t.Fatalf("delete %s on %s: %v", d.provider, d.host, err)
		}
	}
	stored, _ = storedOAuth(t, f, projectID)
	var top struct {
		OAuth map[string]json.RawMessage `json:"oauth"`
	}
	if err := json.Unmarshal([]byte(stored), &top); err != nil {
		t.Fatalf("decode stored: %v", err)
	}
	if _, ok := top.OAuth["hosts"]; ok || string(top.OAuth["future"]) != `{"keep":2}` {
		t.Fatalf("after deleting every host client: %s", stored)
	}
	if n := f.audit.countByEventTypeAndDetail(string(audit.EventProjectOAuthProviderRemoved), "callback_host", hostB); n != 3 {
		t.Fatalf("remove events naming %s = %d, want 3", hostB, n)
	}
}

// A host client takes only a client: any other setting, an Apple secret, a
// bad host or a missing client is refused, and nothing is stored.
func TestAdminHostClient_SetRejects(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	for name, in := range map[string]ProjectOAuthProviderInput{
		"host with a scheme":     {Provider: oauthProviderGoogle, CallbackHost: "https://auth.b.example", ClientID: "g", ClientSecret: "s"},
		"host with a port":       {Provider: oauthProviderGoogle, CallbackHost: "auth.b.example:8443", ClientID: "g", ClientSecret: "s"},
		"host without a dot":     {Provider: oauthProviderGoogle, CallbackHost: "localhost", ClientID: "g", ClientSecret: "s"},
		"native audiences":       {Provider: oauthProviderGoogle, CallbackHost: hostB, ClientID: "g", ClientSecret: "s", NativeAudiences: []string{"aud"}},
		"an endpoint":            {Provider: oauthProviderGoogle, CallbackHost: hostB, ClientID: "g", ClientSecret: "s", GoogleAuthorizationURL: "https://accounts.example/authorize"},
		"a tenant":               {Provider: oauthProviderMicrosoft, CallbackHost: hostB, ClientID: "m", ClientSecret: "s", MicrosoftTenantID: "organizations"},
		"apple team":             {Provider: oauthProviderApple, CallbackHost: hostB, ClientID: "a", AppleTeamID: "TEAM"},
		"apple key":              {Provider: oauthProviderApple, CallbackHost: hostB, ClientID: "a", ApplePrivateKey: "pem"},
		"apple secret":           {Provider: oauthProviderApple, CallbackHost: hostB, ClientID: "a", ClientSecret: "s"},
		"no secret, none stored": {Provider: oauthProviderGoogle, CallbackHost: hostB, ClientID: "g"},
		"no client id":           {Provider: oauthProviderGitHub, CallbackHost: hostB, ClientSecret: "s"},
		"unknown provider":       {Provider: "facebook", CallbackHost: hostB, ClientID: "f", ClientSecret: "s"},
	} {
		if _, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &in); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: err = %v, want ErrInvalidArgument", name, err)
		}
	}
	if stored, _ := storedOAuth(t, f, projectID); strings.Contains(stored, "hosts") {
		t.Fatalf("a refused write stored something: %s", stored)
	}

	if err := f.svc.AdminDeleteProjectOAuthProvider(ctx, oauthAdminSecret, projectID, oauthProviderGoogle, "auth.b.example:8443"); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("delete with a bad host: err = %v, want ErrInvalidArgument", err)
	}
	if _, err := f.svc.AdminSetProjectOAuthProvider(ctx, "wrong", projectID, &ProjectOAuthProviderInput{
		Provider: oauthProviderGoogle, CallbackHost: hostB, ClientID: "g", ClientSecret: "s",
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("wrong secret: err = %v, want ErrPermissionDenied", err)
	}
	if err := f.svc.AdminDeleteProjectOAuthProvider(ctx, "wrong", projectID, oauthProviderGoogle, hostB); !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("delete with the wrong secret: err = %v, want ErrPermissionDenied", err)
	}
}

// A stored hosts value this binary cannot read refuses a host write and the
// list instead of overwriting or hiding it.
func TestAdminHostClient_MalformedStoredHosts(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)
	seedProjectConfig(t, f, projectID, `{"oauth":{"hosts":["not","an","object"]}}`)

	if _, err := f.svc.AdminSetProjectOAuthProvider(ctx, oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
		Provider: oauthProviderGoogle, CallbackHost: hostB, ClientID: "g", ClientSecret: "s",
	}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("set over malformed hosts: err = %v, want ErrInvalidArgument", err)
	}
	if err := f.svc.AdminDeleteProjectOAuthProvider(ctx, oauthAdminSecret, projectID, oauthProviderGoogle, hostB); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("delete over malformed hosts: err = %v, want ErrInvalidArgument", err)
	}
	if _, _, err := f.svc.AdminListProjectOAuthProviders(ctx, oauthAdminSecret, projectID); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("list over malformed hosts: err = %v, want ErrInvalidArgument", err)
	}
}
