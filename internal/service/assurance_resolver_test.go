package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/elloloop/identity/pkg/assurance/appattest"
	"github.com/elloloop/identity/pkg/secretcrypto"
)

// assuranceCtx returns a context carrying a ProjectScope with the given
// project id and assurance block — the shape the project-resolution
// middleware stamps on every served request.
func assuranceCtx(projectID string, cfg ProjectAssuranceConfig) context.Context {
	return WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: projectID,
		Assurance: cfg,
	})
}

// iosBlock is a valid per-project App Attest identity.
func iosBlock(teamID, bundleID string) ProjectAssuranceConfig {
	return ProjectAssuranceConfig{IOS: &ProjectAssuranceIOS{TeamID: teamID, BundleID: bundleID}}
}

// defaultsWithAppAttest builds env-default providers holding a real
// App Attest verifier, standing in for the deployment's configured app.
func defaultsWithAppAttest(t *testing.T) AssuranceProviders {
	t.Helper()
	v, err := appattest.New(appattest.Config{TeamID: "ENVTEAM001", BundleID: "com.example.env"})
	if err != nil {
		t.Fatalf("appattest.New: %v", err)
	}
	return AssuranceProviders{AppAttest: v}
}

func TestAssuranceResolver_DefaultProjectUsesEnvDefaults(t *testing.T) {
	defaults := defaultsWithAppAttest(t)
	r := NewAssuranceResolver("proj-default", defaults, nil, nil)

	// Explicit default project id.
	got := r.For(assuranceCtx("proj-default", ProjectAssuranceConfig{}))
	if got.AppAttest != defaults.AppAttest {
		t.Errorf("default project did not get the env defaults")
	}
	// No scope at all (direct service call) also falls back to defaults.
	if got := r.For(context.Background()); got.AppAttest != defaults.AppAttest {
		t.Errorf("scopeless context did not get the env defaults")
	}
	// An empty project id behaves the same.
	if got := r.For(assuranceCtx("", ProjectAssuranceConfig{})); got.AppAttest != defaults.AppAttest {
		t.Errorf("empty project id did not get the env defaults")
	}
}

// TestAssuranceResolver_DefaultProjectConfigWins pins the precedence fix:
// a stored assurance block on the DEFAULT project must be honoured, not
// silently shadowed by the env defaults. Before this, a validated block
// written to the default project was inert with no log line — the
// challenge RPC succeeded while the exchange returned Unimplemented
// forever.
func TestAssuranceResolver_DefaultProjectConfigWins(t *testing.T) {
	defaults := defaultsWithAppAttest(t)
	r := NewAssuranceResolver("proj-default", defaults, nil, nil)

	got := r.For(assuranceCtx("proj-default", iosBlock("TEAMOWNAAA", "com.example.own")))
	if got.AppAttest == nil {
		t.Fatal("default project's own assurance block produced no verifier")
	}
	if got.AppAttest == defaults.AppAttest {
		t.Fatal("default project's stored block was shadowed by the env defaults")
	}
}

func TestAssuranceResolver_NonDefaultProjectWithoutConfigGetsNothing(t *testing.T) {
	defaults := defaultsWithAppAttest(t)
	r := NewAssuranceResolver("proj-default", defaults, nil, nil)

	// A project that configures no assurance block must NOT inherit the
	// default project's app identity — that would let one product's
	// attestation satisfy another's.
	got := r.For(assuranceCtx("proj-other", ProjectAssuranceConfig{}))
	if got.AppAttest != nil || got.PlayIntegrity != nil {
		t.Fatalf("unconfigured project inherited providers: %+v", got)
	}
}

func TestAssuranceResolver_PerProjectIOSBuildsAndIsIsolated(t *testing.T) {
	defaults := defaultsWithAppAttest(t)
	r := NewAssuranceResolver("proj-default", defaults, nil, nil)

	got := r.For(assuranceCtx("proj-a", iosBlock("TEAMAAAAAA", "com.example.a")))
	if got.AppAttest == nil {
		t.Fatal("per-project iOS block did not build a verifier")
	}
	if got.AppAttest == defaults.AppAttest {
		t.Fatal("per-project verifier must not be the env default instance")
	}

	// A second project builds its own, distinct from the first.
	other := r.For(assuranceCtx("proj-b", iosBlock("TEAMBBBBBB", "com.example.b")))
	if other.AppAttest == nil || other.AppAttest == got.AppAttest {
		t.Fatal("projects must not share an App Attest verifier")
	}
}

func TestAssuranceResolver_CachesPerProjectAndRebuildsOnConfigChange(t *testing.T) {
	r := NewAssuranceResolver("proj-default", AssuranceProviders{}, nil, nil)

	cfg := iosBlock("TEAMAAAAAA", "com.example.a")
	first := r.For(assuranceCtx("proj-a", cfg))
	if first.AppAttest == nil {
		t.Fatal("first resolve produced no verifier")
	}
	// Same config → same hash → cached instance.
	second := r.For(assuranceCtx("proj-a", cfg))
	if second.AppAttest != first.AppAttest {
		t.Fatal("identical config must hit the cache, not rebuild")
	}

	// Changed config → new hash → rebuild, and the stale verifier must not
	// be served (a rotated bundle id has to take effect).
	changed := r.For(assuranceCtx("proj-a", iosBlock("TEAMAAAAAA", "com.example.a2")))
	if changed.AppAttest == nil {
		t.Fatal("changed config produced no verifier")
	}
	if changed.AppAttest == first.AppAttest {
		t.Fatal("config change must rebuild; the stale verifier was served")
	}
}

func TestAssuranceResolver_AndroidBuildsWithDecryptedKey(t *testing.T) {
	key := make([]byte, 32)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	saKey, err := json.Marshal(map[string]string{
		"client_email": "svc@test.iam.gserviceaccount.com",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"token_uri":    "https://oauth2.googleapis.com/token",
	})
	if err != nil {
		t.Fatalf("marshal sa key: %v", err)
	}
	enc, err := secretcrypto.Encrypt(string(saKey), key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	r := NewAssuranceResolver("proj-default", AssuranceProviders{}, key, nil)
	got := r.For(assuranceCtx("proj-a", ProjectAssuranceConfig{
		Android: &ProjectAssuranceAndroid{
			PackageName:          "com.example.a",
			CertSHA256Digests:    []string{"ZGlnZXN0"},
			ServiceAccountKeyEnc: enc,
		},
	}))
	if got.PlayIntegrity == nil {
		t.Fatal("android block with a decryptable key did not build a verifier")
	}
}

func TestAssuranceResolver_PlatformBuildFailuresAreIsolated(t *testing.T) {
	// An Android key that cannot be decrypted (wrong deployment key) must
	// not take down the sibling iOS arm.
	r := NewAssuranceResolver("proj-default", AssuranceProviders{}, make([]byte, 32), nil)
	got := r.For(assuranceCtx("proj-a", ProjectAssuranceConfig{
		IOS: &ProjectAssuranceIOS{TeamID: "TEAMAAAAAA", BundleID: "com.example.a"},
		Android: &ProjectAssuranceAndroid{
			PackageName:          "com.example.a",
			CertSHA256Digests:    []string{"ZGlnZXN0"},
			ServiceAccountKeyEnc: "not-a-valid-ciphertext",
		},
	}))
	if got.AppAttest == nil {
		t.Error("a failed Android build must not disable the iOS arm")
	}
	if got.PlayIntegrity != nil {
		t.Error("an undecryptable Android key must leave PlayIntegrity nil")
	}

	// An unusable iOS env likewise leaves the rest alone (and yields no
	// verifier rather than a partly-built one).
	got = r.For(assuranceCtx("proj-b", ProjectAssuranceConfig{
		IOS: &ProjectAssuranceIOS{TeamID: "TEAMBBBBBB", BundleID: "com.example.b", Env: "staging"},
	}))
	if got.AppAttest != nil {
		t.Error("an invalid iOS environment must not produce a verifier")
	}
}

func TestProjectAssuranceConfigHashAndIsZero(t *testing.T) {
	zero := ProjectAssuranceConfig{}
	if !zero.isZero() {
		t.Error("empty config must report isZero")
	}
	a := iosBlock("TEAMAAAAAA", "com.example.a")
	if a.isZero() {
		t.Error("configured block must not report isZero")
	}
	if a.hash() != iosBlock("TEAMAAAAAA", "com.example.a").hash() {
		t.Error("identical configs must hash equal")
	}
	if a.hash() == iosBlock("TEAMAAAAAA", "com.example.b").hash() {
		t.Error("differing configs must hash differently")
	}
}
