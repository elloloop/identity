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
	view, err := f.svc.AdminSetProjectOAuthHostClient(ctx, oauthAdminSecret, projectID, &ProjectOAuthHostClientInput{
		Provider: oauthProviderGoogle, CallbackHost: " Auth.B.Example. ", ClientID: hostBGoogle, ClientSecret: hostSecret,
	})
	if err != nil {
		t.Fatalf("set host google: %v", err)
	}
	want := ProjectOAuthHostClientView{Provider: oauthProviderGoogle, CallbackHost: hostB, ClientID: hostBGoogle, HasClientSecret: true}
	if !reflect.DeepEqual(*view, want) {
		t.Fatalf("view = %+v, want %+v", *view, want)
	}
	if _, err := f.svc.AdminSetProjectOAuthHostClient(ctx, oauthAdminSecret, projectID, &ProjectOAuthHostClientInput{
		Provider: oauthProviderApple, CallbackHost: hostB, ClientID: hostBAppleID,
	}); err != nil {
		t.Fatalf("set host apple: %v", err)
	}
	if _, err := f.svc.AdminSetProjectOAuthHostClient(ctx, oauthAdminSecret, projectID, &ProjectOAuthHostClientInput{
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
	if err != nil || len(providers) != 1 || providers[0].Provider != oauthProviderGoogle || providers[0].ClientID != "base-google" {
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
	if v, err := f.svc.AdminSetProjectOAuthHostClient(ctx, oauthAdminSecret, projectID, &ProjectOAuthHostClientInput{
		Provider: oauthProviderGoogle, CallbackHost: hostB, ClientID: "host-b-google-2",
	}); err != nil || !v.HasClientSecret || v.ClientID != "host-b-google-2" {
		t.Fatalf("empty-secret keep: v = %+v, err = %v", v, err)
	}
	if _, cfg = storedOAuth(t, f, projectID); cfg.Hosts[hostB][oauthProviderGoogle].ClientSecretEnc != enc {
		t.Fatal("an empty secret must keep the stored ciphertext")
	}

	// Deleting the base provider leaves its host clients.
	if err := f.svc.AdminDeleteProjectOAuthProvider(ctx, oauthAdminSecret, projectID, oauthProviderGoogle); err != nil {
		t.Fatalf("delete base google: %v", err)
	}
	if _, cfg = storedOAuth(t, f, projectID); cfg.Google != nil || len(cfg.Hosts[hostB]) != 2 {
		t.Fatalf("after deleting the base: google = %+v, hosts = %+v", cfg.Google, cfg.Hosts)
	}

	// Each host client goes on its own; an emptied host and then the hosts key go with the last.
	for _, d := range []struct{ provider, host string }{
		{oauthProviderGoogle, hostB}, {oauthProviderGoogle, hostB}, {oauthProviderApple, "AUTH.B.EXAMPLE"}, {oauthProviderMicrosoft, hostA},
	} {
		if err := f.svc.AdminDeleteProjectOAuthHostClient(ctx, oauthAdminSecret, projectID, d.provider, d.host); err != nil {
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

// A host client with a bad host, an Apple secret or a missing client is
// refused, and nothing is stored.
func TestAdminHostClient_SetRejects(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	for name, in := range map[string]ProjectOAuthHostClientInput{
		"no host":                {Provider: oauthProviderGoogle, ClientID: "g", ClientSecret: "s"},
		"a blank host":           {Provider: oauthProviderGoogle, CallbackHost: "   ", ClientID: "g", ClientSecret: "s"},
		"host with a scheme":     {Provider: oauthProviderGoogle, CallbackHost: "https://auth.b.example", ClientID: "g", ClientSecret: "s"},
		"host with a port":       {Provider: oauthProviderGoogle, CallbackHost: "auth.b.example:8443", ClientID: "g", ClientSecret: "s"},
		"host without a dot":     {Provider: oauthProviderGoogle, CallbackHost: "localhost", ClientID: "g", ClientSecret: "s"},
		"two trailing dots":      {Provider: oauthProviderGoogle, CallbackHost: "auth.b.example..", ClientID: "g", ClientSecret: "s"},
		"only dots":              {Provider: oauthProviderGoogle, CallbackHost: "..", ClientID: "g", ClientSecret: "s"},
		"a space before the dot": {Provider: oauthProviderGoogle, CallbackHost: "auth.b.example\u00a0.", ClientID: "g", ClientSecret: "s"},
		"a query character":      {Provider: oauthProviderGoogle, CallbackHost: "auth.b?example", ClientID: "g", ClientSecret: "s"},
		"a fragment character":   {Provider: oauthProviderGoogle, CallbackHost: "auth.b#example", ClientID: "g", ClientSecret: "s"},
		"a newline":              {Provider: oauthProviderGoogle, CallbackHost: "auth.b\n.example", ClientID: "g", ClientSecret: "s"},
		"a NUL":                  {Provider: oauthProviderGoogle, CallbackHost: "auth.b\x00.example", ClientID: "g", ClientSecret: "s"},
		"an escape":              {Provider: oauthProviderGoogle, CallbackHost: "auth.b%2eexample", ClientID: "g", ClientSecret: "s"},
		"an underscore":          {Provider: oauthProviderGoogle, CallbackHost: "auth_b.example", ClientID: "g", ClientSecret: "s"},
		"a Unicode letter":       {Provider: oauthProviderGoogle, CallbackHost: "auth.b\u00e9.example", ClientID: "g", ClientSecret: "s"},
		"an empty label":         {Provider: oauthProviderGoogle, CallbackHost: "auth..b.example", ClientID: "g", ClientSecret: "s"},
		"a leading hyphen":       {Provider: oauthProviderGoogle, CallbackHost: "-auth.b.example", ClientID: "g", ClientSecret: "s"},
		"apple secret":           {Provider: oauthProviderApple, CallbackHost: hostB, ClientID: "a", ClientSecret: "s"},
		"no secret, none stored": {Provider: oauthProviderGoogle, CallbackHost: hostB, ClientID: "g"},
		"no client id":           {Provider: oauthProviderGitHub, CallbackHost: hostB, ClientSecret: "s"},
		"unknown provider":       {Provider: "facebook", CallbackHost: hostB, ClientID: "f", ClientSecret: "s"},
	} {
		if _, err := f.svc.AdminSetProjectOAuthHostClient(ctx, oauthAdminSecret, projectID, &in); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: err = %v, want ErrInvalidArgument", name, err)
		}
	}
	if _, err := f.svc.AdminSetProjectOAuthHostClient(ctx, oauthAdminSecret, projectID, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("no client: err = %v, want ErrInvalidArgument", err)
	}
	if _, err := f.svc.AdminSetProjectOAuthHostClient(ctx, oauthAdminSecret, " ", &ProjectOAuthHostClientInput{
		Provider: oauthProviderGoogle, CallbackHost: hostB, ClientID: "g", ClientSecret: "s",
	}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("no project: err = %v, want ErrInvalidArgument", err)
	}
	if stored, _ := storedOAuth(t, f, projectID); strings.Contains(stored, "hosts") {
		t.Fatalf("a refused write stored something: %s", stored)
	}

	for name, d := range map[string]struct{ project, provider, host string }{
		"a bad host":       {projectID, oauthProviderGoogle, "auth.b.example:8443"},
		"two dots":         {projectID, oauthProviderGoogle, "auth.b.example.."},
		"a NUL":            {projectID, oauthProviderGoogle, "auth.b\x00.example"},
		"no host":          {projectID, oauthProviderGoogle, ""},
		"unknown provider": {projectID, "facebook", hostB},
		"no project":       {"", oauthProviderGoogle, hostB},
	} {
		if err := f.svc.AdminDeleteProjectOAuthHostClient(ctx, oauthAdminSecret, d.project, d.provider, d.host); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("delete with %s: err = %v, want ErrInvalidArgument", name, err)
		}
	}
	if _, err := f.svc.AdminSetProjectOAuthHostClient(ctx, "wrong", projectID, &ProjectOAuthHostClientInput{
		Provider: oauthProviderGoogle, CallbackHost: hostB, ClientID: "g", ClientSecret: "s",
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("wrong secret: err = %v, want ErrPermissionDenied", err)
	}
	if err := f.svc.AdminDeleteProjectOAuthHostClient(ctx, "wrong", projectID, oauthProviderGoogle, hostB); !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("delete with the wrong secret: err = %v, want ErrPermissionDenied", err)
	}
}

// newCallbackHost accepts an LDH hostname, a punycode IDN included, in its
// normalized form, and refuses every other host by its class.
func TestNewCallbackHost(t *testing.T) {
	t.Parallel()
	label63 := strings.Repeat("a", 63)
	// Three 63-character labels and a 61-character one: 253 characters.
	host253 := strings.Join([]string{label63, label63, label63, strings.Repeat("b", 61)}, ".")
	for _, tc := range []struct{ in, want string }{
		{"auth.b.example", "auth.b.example"},
		{" Auth.B.Example. ", "auth.b.example"},
		{"auth-2.b.example", "auth-2.b.example"},
		{"xn--bcher-kva.example", "xn--bcher-kva.example"},
		{"XN--BCHER-KVA.EXAMPLE.", "xn--bcher-kva.example"},
		{"123.example", "123.example"},
		{label63 + ".example", label63 + ".example"},
		{host253, host253},
		{host253 + ".", host253},
		{"a.b.c.d.e.example", "a.b.c.d.e.example"},
	} {
		got, err := newCallbackHost(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("newCallbackHost(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	for _, tc := range []struct{ name, in string }{
		{"an empty label", "auth..example"},
		{"a leading dot", ".auth.example"},
		{"a leading hyphen", "-auth.example"},
		{"a label ending in '-'", "auth-.example"},
		{"a 64-character label", label63 + "a.example"},
		{"over 253 characters", "c" + host253},
		{"a single label", "localhost"},
		{"an underscore", "auth_b.example"},
		{"a Unicode letter", "b\u00fccher.example"},
		{"two trailing dots", "auth.example.."},
		{"a port", "auth.example:8443"},
	} {
		if got, err := newCallbackHost(tc.in); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: newCallbackHost(%q) = %q, %v; want ErrInvalidArgument", tc.name, tc.in, got, err)
		}
	}
}

// A host client on a hyphenated, numbered or punycode host is stored and
// listed under that exact host, and the stored config still parses.
func TestAdminHostClient_SetAcceptsLDHHosts(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)

	hosts := []string{"123.example", "auth-2.b.example", "xn--bcher-kva.example"}
	for _, host := range hosts {
		if _, err := f.svc.AdminSetProjectOAuthHostClient(ctx, oauthAdminSecret, projectID, &ProjectOAuthHostClientInput{
			Provider: oauthProviderGitHub, CallbackHost: host, ClientID: "gh-" + host, ClientSecret: "s",
		}); err != nil {
			t.Fatalf("set on %s: %v", host, err)
		}
	}
	_, cfg := storedOAuth(t, f, projectID)
	_, listed, err := f.svc.AdminListProjectOAuthProviders(ctx, oauthAdminSecret, projectID)
	if err != nil || len(listed) != len(hosts) {
		t.Fatalf("host clients = %+v, err = %v", listed, err)
	}
	for i, host := range hosts {
		if c, ok := cfg.hostClient(host, oauthProviderGitHub); !ok || c.ClientID != "gh-"+host {
			t.Errorf("stored client on %s = %+v, %v", host, c, ok)
		}
		if listed[i].CallbackHost != host || listed[i].ClientID != "gh-"+host {
			t.Errorf("listed[%d] = %+v, want %s", i, listed[i], host)
		}
	}
}

// A whole-config write holds each host key it adds to the host client
// write's rule, and keeps a key already stored whatever rule it was written
// under, so a config written back as read never fails on it.
func TestUpsertProjectConfig_HostKeys(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)
	client := `{"github":{"client_id":"h","client_secret_enc":"e"}}`
	withHosts := func(keys ...string) string {
		entries := make([]string, 0, len(keys))
		for _, k := range keys {
			b, err := json.Marshal(k)
			if err != nil {
				t.Fatalf("marshal %q: %v", k, err)
			}
			entries = append(entries, string(b)+":"+client)
		}
		return `{"oauth":{"hosts":{` + strings.Join(entries, ",") + `}}}`
	}

	for _, host := range []string{"auth_b.example", "auth.b?example", "auth..b.example", "-auth.b.example", "auth.b\n.example"} {
		if _, err := f.svc.UpsertProjectConfig(ctx, oauthAdminSecret, projectID, withHosts(host)); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("a new key %q: err = %v, want ErrInvalidArgument", host, err)
		}
	}
	if stored, _ := storedOAuth(t, f, projectID); strings.Contains(stored, "hosts") {
		t.Fatalf("a refused write stored something: %s", stored)
	}

	if _, err := f.svc.UpsertProjectConfig(ctx, oauthAdminSecret, projectID, withHosts("auth-2.b.example")); err != nil {
		t.Fatalf("a new LDH key: %v", err)
	}
	const wider = "auth_b.example"
	seedProjectConfig(t, f, projectID, withHosts(wider))
	if _, err := f.svc.UpsertProjectConfig(ctx, oauthAdminSecret, projectID, withHosts(wider, "xn--bcher-kva.example")); err != nil {
		t.Fatalf("a stored non-LDH key written back beside a new LDH one: %v", err)
	}
	if _, err := f.svc.UpsertProjectConfig(ctx, oauthAdminSecret, projectID, withHosts(wider, "auth.c?example")); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("a new non-LDH key beside a stored one: err = %v, want ErrInvalidArgument", err)
	}
	if _, cfg := storedOAuth(t, f, projectID); len(cfg.Hosts) != 2 {
		t.Fatalf("hosts = %v, want the stored key and the LDH one", cfg.Hosts)
	}
}

// A stored null where an object belongs (the whole config, "oauth": null,
// "hosts": null or one host's entry) reads as empty: a host write succeeds
// and leaves a config that parses.
func TestAdminHostClient_StoredNulls(t *testing.T) {
	t.Parallel()
	for _, seed := range []string{`null`, `{"oauth":null}`, `{"oauth":{"hosts":null}}`, `{"oauth":{"hosts":{"auth.b.example":null}}}`} {
		f := newAdminFixture(oauthAdminSecret)
		ctx := context.Background()
		projectID := seedOAuthProject(t, f)
		seedProjectConfig(t, f, projectID, seed)

		if _, err := f.svc.AdminSetProjectOAuthHostClient(ctx, oauthAdminSecret, projectID, &ProjectOAuthHostClientInput{
			Provider: oauthProviderGoogle, CallbackHost: hostB, ClientID: hostBGoogle, ClientSecret: "s",
		}); err != nil {
			t.Fatalf("%s: set host client: %v", seed, err)
		}
		if _, cfg := storedOAuth(t, f, projectID); cfg.Hosts[hostB][oauthProviderGoogle].ClientID != hostBGoogle {
			t.Fatalf("%s: stored hosts = %+v", seed, cfg.Hosts)
		}
	}
	for _, seed := range []string{`null`, `{"oauth":null}`} {
		f := newAdminFixture(oauthAdminSecret)
		projectID := seedOAuthProject(t, f)
		seedProjectConfig(t, f, projectID, seed)
		if _, err := f.svc.AdminSetProjectOAuthProvider(context.Background(), oauthAdminSecret, projectID, &ProjectOAuthProviderInput{
			Provider: oauthProviderGoogle, ClientID: "g", ClientSecret: "s",
		}); err != nil {
			t.Fatalf("set base over %s: %v", seed, err)
		}
	}
}

// A host write keeps what it does not read: an unknown provider entry of any
// shape under its host, and a host key this binary would not write (not an
// LDH hostname) but still loads. The delete removes such a key; the set
// refuses to write one.
func TestAdminHostClient_KeepsWhatItDoesNotRead(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)
	const wider = "auth_b.example"
	seedProjectConfig(t, f, projectID, `{"oauth":{"hosts":{"auth.b.example":{"okta":["x"]},"auth_b.example":{"google":{"client_id":"u","client_secret_enc":"e"}}}}}`)
	if _, cfg := storedOAuth(t, f, projectID); cfg.Hosts[wider][oauthProviderGoogle].ClientID != "u" {
		t.Fatalf("a stored non-LDH host key must load: %+v", cfg.Hosts)
	}

	if _, err := f.svc.AdminSetProjectOAuthHostClient(ctx, oauthAdminSecret, projectID, &ProjectOAuthHostClientInput{
		Provider: oauthProviderGoogle, CallbackHost: hostB, ClientID: hostBGoogle, ClientSecret: "s",
	}); err != nil {
		t.Fatalf("set host google: %v", err)
	}
	if stored, _ := storedOAuth(t, f, projectID); !strings.Contains(stored, `"okta":["x"]`) {
		t.Fatalf("the unknown entry under the host was not kept: %s", stored)
	}
	if _, hostClients, err := f.svc.AdminListProjectOAuthProviders(ctx, oauthAdminSecret, projectID); err != nil || len(hostClients) != 2 {
		t.Fatalf("list: %d host clients, err %v; want the two built-in ones", len(hostClients), err)
	}

	if err := f.svc.AdminDeleteProjectOAuthHostClient(ctx, oauthAdminSecret, projectID, oauthProviderGoogle, hostB); err != nil {
		t.Fatalf("delete host google: %v", err)
	}
	if stored, _ := storedOAuth(t, f, projectID); !strings.Contains(stored, `"auth.b.example":{"okta":["x"]}`) {
		t.Fatalf("the host must stay while an unknown entry remains: %s", stored)
	}

	if _, err := f.svc.AdminSetProjectOAuthHostClient(ctx, oauthAdminSecret, projectID, &ProjectOAuthHostClientInput{
		Provider: oauthProviderGoogle, CallbackHost: wider, ClientID: "w", ClientSecret: "s",
	}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("set on a non-LDH host: err = %v, want ErrInvalidArgument", err)
	}
	if err := f.svc.AdminDeleteProjectOAuthHostClient(ctx, oauthAdminSecret, projectID, oauthProviderGoogle, wider); err != nil {
		t.Fatalf("delete on a stored non-LDH host: %v", err)
	}
	if stored, _ := storedOAuth(t, f, projectID); strings.Contains(stored, wider) {
		t.Fatalf("the non-LDH host was not removed: %s", stored)
	}
}

// Deleting a host client that is not there is a no-op that still succeeds.
func TestAdminHostClient_DeleteAbsentIsANoop(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	projectID := seedOAuthProject(t, f)
	seedProjectConfig(t, f, projectID, `{"custom":{"keep":1}}`)
	if err := f.svc.AdminDeleteProjectOAuthHostClient(context.Background(), oauthAdminSecret, projectID, oauthProviderGoogle, hostB); err != nil {
		t.Fatalf("delete absent: %v", err)
	}
	if stored, _ := storedOAuth(t, f, projectID); stored != `{"custom":{"keep":1}}` {
		t.Fatalf("an absent delete changed the config: %s", stored)
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

	if _, err := f.svc.AdminSetProjectOAuthHostClient(ctx, oauthAdminSecret, projectID, &ProjectOAuthHostClientInput{
		Provider: oauthProviderGoogle, CallbackHost: hostB, ClientID: "g", ClientSecret: "s",
	}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("set over malformed hosts: err = %v, want ErrInvalidArgument", err)
	}
	if err := f.svc.AdminDeleteProjectOAuthHostClient(ctx, oauthAdminSecret, projectID, oauthProviderGoogle, hostB); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("delete over malformed hosts: err = %v, want ErrInvalidArgument", err)
	}
	if _, _, err := f.svc.AdminListProjectOAuthProviders(ctx, oauthAdminSecret, projectID); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("list over malformed hosts: err = %v, want ErrInvalidArgument", err)
	}
}
