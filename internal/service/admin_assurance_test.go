package service

import (
	"context"
	"strings"
	"testing"

	"github.com/elloloop/identity/pkg/secretcrypto"
)

// TestAdminSetProjectAssurance covers the authoring path the per-project
// Android arm previously lacked: an operator supplies the Google
// service-account key in PLAINTEXT and the server encrypts it at rest, so
// nobody has to reimplement pkg/secretcrypto's framing outside the
// product. Mirrors AdminSetProjectOAuthProvider.
func TestAdminSetProjectAssurance(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(oauthAdminSecret)
	ctx := context.Background()
	projectID := seedOAuthProject(t, f)
	const saKey = `{"client_email":"svc@x.iam.gserviceaccount.com","private_key":"pk"}`
	seedProjectConfig(t, f, projectID, `{"branding":{"product_name":"Seeded"}}`)

	view, err := f.svc.AdminSetProjectAssurance(ctx, oauthAdminSecret, projectID, &ProjectAssuranceInput{
		IOSTeamID:                "TEAM123456",
		IOSBundleID:              "com.example.app",
		AndroidPackageName:       "com.example.app",
		AndroidCertSHA256Digests: []string{"ZGlnZXN0", "  "},
		AndroidServiceAccountKey: saKey,
	})
	if err != nil {
		t.Fatalf("AdminSetProjectAssurance: %v", err)
	}
	if !view.HasServiceAccountKey {
		t.Error("view should report a stored key")
	}
	if len(view.AndroidCertSHA256Digests) != 1 {
		t.Errorf("blank digest not trimmed: %v", view.AndroidCertSHA256Digests)
	}

	// The stored blob must hold CIPHERTEXT that decrypts back to the input,
	// never the plaintext key.
	stored, _, err := f.projects.GetProjectConfig(ctx, projectID)
	if err != nil {
		t.Fatalf("GetProjectConfig: %v", err)
	}
	if strings.Contains(stored, "private_key") {
		t.Fatal("plaintext service-account key was written to config_json")
	}
	cfg, err := ParseProjectConfig(stored)
	if err != nil {
		t.Fatalf("ParseProjectConfig: %v", err)
	}
	if cfg.Assurance.Android == nil {
		t.Fatal("android block not stored")
	}
	plain, err := secretcrypto.Decrypt(cfg.Assurance.Android.ServiceAccountKeyEnc, testAdminSecretsKey())
	if err != nil {
		t.Fatalf("stored key does not decrypt: %v", err)
	}
	if plain != saKey {
		t.Errorf("decrypted key = %q, want the supplied plaintext", plain)
	}
	// Sibling config keys survive the write.
	if cfg.Branding.ProductName != "Seeded" {
		t.Errorf("the write clobbered the project's other config keys: %+v", cfg.Branding)
	}

	t.Run("rotation without re-supplying the key keeps it", func(t *testing.T) {
		v, err := f.svc.AdminSetProjectAssurance(ctx, oauthAdminSecret, projectID, &ProjectAssuranceInput{
			AndroidPackageName:       "com.example.renamed",
			AndroidCertSHA256Digests: []string{"ZGlnZXN0"},
		})
		if err != nil {
			t.Fatalf("rotate: %v", err)
		}
		if !v.HasServiceAccountKey {
			t.Fatal("stored key was dropped when the caller supplied none")
		}
	})

	t.Run("half-specified platform fails the write", func(t *testing.T) {
		if _, err := f.svc.AdminSetProjectAssurance(ctx, oauthAdminSecret, projectID, &ProjectAssuranceInput{
			IOSTeamID: "TEAM123456", // no bundle id
		}); err == nil {
			t.Fatal("expected a validation error for a half-filled iOS block")
		}
	})

	t.Run("read view never echoes the key", func(t *testing.T) {
		v, err := f.svc.GetProjectAssurance(ctx, oauthAdminSecret, projectID)
		if err != nil {
			t.Fatalf("GetProjectAssurance: %v", err)
		}
		if !v.HasServiceAccountKey {
			t.Error("HasServiceAccountKey should be true")
		}
	})

	t.Run("empty input clears the block", func(t *testing.T) {
		if _, err := f.svc.AdminSetProjectAssurance(ctx, oauthAdminSecret, projectID, &ProjectAssuranceInput{}); err != nil {
			t.Fatalf("clear: %v", err)
		}
		v, err := f.svc.GetProjectAssurance(ctx, oauthAdminSecret, projectID)
		if err != nil {
			t.Fatalf("GetProjectAssurance: %v", err)
		}
		if v.HasServiceAccountKey || v.IOSTeamID != "" {
			t.Errorf("block not cleared: %+v", v)
		}
	})

	t.Run("wrong admin secret denied", func(t *testing.T) {
		if _, err := f.svc.AdminSetProjectAssurance(ctx, "wrong", projectID, &ProjectAssuranceInput{}); err == nil {
			t.Fatal("expected an authorization failure")
		}
	})
}
