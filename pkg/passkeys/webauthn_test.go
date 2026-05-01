package passkeys

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

// ---------------------------------------------------------------------------
// Config / constructor tests
// ---------------------------------------------------------------------------

func TestNewWebAuthnService(t *testing.T) {
	svc, err := NewWebAuthnService(Config{
		RPID:   "glassa.work",
		RPName: "Glassa Work",
		Origin: "https://glassa.work",
	})
	if err != nil {
		t.Fatalf("NewWebAuthnService returned error: %v", err)
	}
	if svc == nil {
		t.Fatal("NewWebAuthnService returned nil service")
	}
	if svc.wa == nil {
		t.Fatal("WebAuthn instance is nil")
	}
}

func TestNewWebAuthnService_InvalidConfig(t *testing.T) {
	// go-webauthn requires at least one RPOrigin; an empty Origin
	// produces an empty RPOrigins slice, which is rejected.
	_, err := NewWebAuthnService(Config{
		RPID:   "example.com",
		RPName: "Example",
		Origin: "", // no origin → validation error
	})
	if err == nil {
		t.Fatal("expected error for empty origin, got nil")
	}
}

func TestConfig_LocalhostDefaults(t *testing.T) {
	svc, err := NewWebAuthnService(Config{
		RPID:   "localhost",
		RPName: "Glassa Work (dev)",
		Origin: "http://localhost:9002",
	})
	if err != nil {
		t.Fatalf("NewWebAuthnService with localhost config failed: %v", err)
	}
	if svc == nil {
		t.Fatal("service should not be nil for localhost config")
	}
}

// ---------------------------------------------------------------------------
// Registration option generation
// ---------------------------------------------------------------------------

func TestBeginRegistration_ReturnsValidJSON(t *testing.T) {
	svc := newTestService(t)

	optJSON, challenge, err := svc.BeginRegistration(
		"user-123",
		"alice@glassa.work",
		"Alice",
		nil,
	)
	if err != nil {
		t.Fatalf("BeginRegistration error: %v", err)
	}

	// optionsJSON must be valid JSON.
	if !json.Valid([]byte(optJSON)) {
		t.Fatalf("optionsJSON is not valid JSON: %s", optJSON)
	}

	// Challenge must be non-empty base64url.
	if challenge == "" {
		t.Fatal("challenge is empty")
	}
	if strings.ContainsAny(challenge, "+/=") {
		t.Errorf("challenge contains non-base64url chars: %s", challenge)
	}

	// Verify essential fields in the JSON.
	var opts struct {
		PublicKey struct {
			RP struct {
				Name string `json:"name"`
				ID   string `json:"id"`
			} `json:"rp"`
			User struct {
				Name        string `json:"name"`
				DisplayName string `json:"displayName"`
			} `json:"user"`
			Challenge        string `json:"challenge"`
			ExcludeCredentials []any  `json:"excludeCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal([]byte(optJSON), &opts); err != nil {
		t.Fatalf("failed to unmarshal options: %v", err)
	}
	if opts.PublicKey.RP.ID != "localhost" {
		t.Errorf("RP ID = %q, want %q", opts.PublicKey.RP.ID, "localhost")
	}
	if opts.PublicKey.User.Name != "alice@glassa.work" {
		t.Errorf("user.name = %q, want %q", opts.PublicKey.User.Name, "alice@glassa.work")
	}
	if opts.PublicKey.Challenge == "" {
		t.Error("challenge in JSON is empty")
	}
}

func TestBeginRegistration_EmptyDisplayName(t *testing.T) {
	svc := newTestService(t)

	optJSON, _, err := svc.BeginRegistration(
		"user-456",
		"bob@glassa.work",
		"", // empty display name — should fall back to email
		nil,
	)
	if err != nil {
		t.Fatalf("BeginRegistration error: %v", err)
	}

	var opts struct {
		PublicKey struct {
			User struct {
				DisplayName string `json:"displayName"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal([]byte(optJSON), &opts); err != nil {
		t.Fatalf("failed to unmarshal options: %v", err)
	}
	if opts.PublicKey.User.DisplayName != "bob@glassa.work" {
		t.Errorf("displayName = %q, want %q (should fall back to email)",
			opts.PublicKey.User.DisplayName, "bob@glassa.work")
	}
}

func TestBeginRegistration_ExcludesExistingCreds(t *testing.T) {
	svc := newTestService(t)

	// base64url of some fake credential IDs.
	existing := []string{
		b64urlEncode([]byte("cred-aaa")),
		b64urlEncode([]byte("cred-bbb")),
	}

	optJSON, _, err := svc.BeginRegistration(
		"user-789",
		"carol@glassa.work",
		"Carol",
		existing,
	)
	if err != nil {
		t.Fatalf("BeginRegistration error: %v", err)
	}

	var opts struct {
		PublicKey struct {
			ExcludeCredentials []struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"excludeCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal([]byte(optJSON), &opts); err != nil {
		t.Fatalf("failed to unmarshal options: %v", err)
	}
	if len(opts.PublicKey.ExcludeCredentials) != 2 {
		t.Fatalf("excludeCredentials count = %d, want 2",
			len(opts.PublicKey.ExcludeCredentials))
	}
	for _, ec := range opts.PublicKey.ExcludeCredentials {
		if ec.Type != "public-key" {
			t.Errorf("excludeCredential type = %q, want %q", ec.Type, "public-key")
		}
	}
}

// ---------------------------------------------------------------------------
// Authentication option generation
// ---------------------------------------------------------------------------

func TestBeginAuthentication_ReturnsValidJSON(t *testing.T) {
	svc := newTestService(t)

	allowed := []string{
		b64urlEncode([]byte("cred-xxx")),
	}

	optJSON, challenge, err := svc.BeginAuthentication(allowed)
	if err != nil {
		t.Fatalf("BeginAuthentication error: %v", err)
	}
	if !json.Valid([]byte(optJSON)) {
		t.Fatalf("optionsJSON is not valid JSON: %s", optJSON)
	}
	if challenge == "" {
		t.Fatal("challenge is empty")
	}
	if strings.ContainsAny(challenge, "+/=") {
		t.Errorf("challenge contains non-base64url chars: %s", challenge)
	}

	// Verify the rpId and allowCredentials are present.
	var opts struct {
		PublicKey struct {
			RPID             string `json:"rpId"`
			AllowCredentials []struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal([]byte(optJSON), &opts); err != nil {
		t.Fatalf("failed to unmarshal options: %v", err)
	}
	if opts.PublicKey.RPID != "localhost" {
		t.Errorf("rpId = %q, want %q", opts.PublicKey.RPID, "localhost")
	}
	if len(opts.PublicKey.AllowCredentials) != 1 {
		t.Fatalf("allowCredentials count = %d, want 1",
			len(opts.PublicKey.AllowCredentials))
	}
}

func TestBeginAuthentication_EmptyAllowedCreds(t *testing.T) {
	svc := newTestService(t)

	optJSON, challenge, err := svc.BeginAuthentication(nil)
	if err != nil {
		t.Fatalf("BeginAuthentication error: %v", err)
	}
	if !json.Valid([]byte(optJSON)) {
		t.Fatalf("optionsJSON is not valid JSON: %s", optJSON)
	}
	if challenge == "" {
		t.Fatal("challenge is empty")
	}

	// With no allowed creds, allowCredentials should be empty or absent
	// (discoverable credentials flow).
	var opts struct {
		PublicKey struct {
			AllowCredentials []any `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal([]byte(optJSON), &opts); err != nil {
		t.Fatalf("failed to unmarshal options: %v", err)
	}
	if len(opts.PublicKey.AllowCredentials) != 0 {
		t.Errorf("allowCredentials should be empty for discoverable flow, got %d",
			len(opts.PublicKey.AllowCredentials))
	}
}

// ---------------------------------------------------------------------------
// ExtractCredentialID
// ---------------------------------------------------------------------------

func TestExtractCredentialID_ValidJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "id field",
			input: `{"id":"dGVzdC1jcmVk","type":"public-key"}`,
			want:  "dGVzdC1jcmVk",
		},
		{
			name:  "rawId fallback",
			input: `{"rawId":"dGVzdC1jcmVk","type":"public-key"}`,
			want:  "dGVzdC1jcmVk",
		},
		{
			name:  "id with padding stripped",
			input: `{"id":"dGVzdC1jcmVk==","type":"public-key"}`,
			want:  "dGVzdC1jcmVk",
		},
		{
			name:  "both id and rawId (id takes precedence)",
			input: `{"id":"aWQ","rawId":"cmF3SWQ","type":"public-key"}`,
			want:  "aWQ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractCredentialID(tt.input)
			if err != nil {
				t.Fatalf("ExtractCredentialID error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractCredentialID_InvalidJSON(t *testing.T) {
	_, err := ExtractCredentialID("not valid json")
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestExtractCredentialID_MissingID(t *testing.T) {
	_, err := ExtractCredentialID(`{"type":"public-key"}`)
	if err == nil {
		t.Fatal("expected error for missing id, got nil")
	}
}

// ---------------------------------------------------------------------------
// RegistrationResult fields
// ---------------------------------------------------------------------------

func TestRegistrationResult_Fields(t *testing.T) {
	r := &RegistrationResult{
		CredentialID: "dGVzdC1jcmVk",
		PublicKey:    "cHVibGljLWtleQ==",
		SignCount:    42,
		AAGUID:       "01020304-0506-0708-090a-0b0c0d0e0f10",
		Transports:   "usb,nfc",
	}

	if r.CredentialID == "" {
		t.Error("CredentialID should not be empty")
	}
	if r.PublicKey == "" {
		t.Error("PublicKey should not be empty")
	}
	if r.SignCount != 42 {
		t.Errorf("SignCount = %d, want 42", r.SignCount)
	}
	if r.AAGUID == "" {
		t.Error("AAGUID should not be empty")
	}
	if r.Transports != "usb,nfc" {
		t.Errorf("Transports = %q, want %q", r.Transports, "usb,nfc")
	}

	// Verify CredentialID is valid base64url (no padding, no +/).
	if strings.ContainsAny(r.CredentialID, "+/=") {
		t.Errorf("CredentialID contains non-base64url chars: %s", r.CredentialID)
	}
}

// ---------------------------------------------------------------------------
// WebAuthnUser interface compliance
// ---------------------------------------------------------------------------

func TestWebAuthnUser_Interface(t *testing.T) {
	u := &WebAuthnUser{
		ID:          []byte("user-id"),
		Name:        "alice@example.com",
		DisplayName: "Alice",
		Credentials: []webauthn.Credential{
			{ID: []byte("cred-1")},
		},
	}

	// Verify the interface is satisfied.
	var _ webauthn.User = u

	if string(u.WebAuthnID()) != "user-id" {
		t.Errorf("WebAuthnID = %q, want %q", string(u.WebAuthnID()), "user-id")
	}
	if u.WebAuthnName() != "alice@example.com" {
		t.Errorf("WebAuthnName = %q, want %q", u.WebAuthnName(), "alice@example.com")
	}
	if u.WebAuthnDisplayName() != "Alice" {
		t.Errorf("WebAuthnDisplayName = %q, want %q", u.WebAuthnDisplayName(), "Alice")
	}
	if len(u.WebAuthnCredentials()) != 1 {
		t.Errorf("WebAuthnCredentials count = %d, want 1", len(u.WebAuthnCredentials()))
	}
}

// ---------------------------------------------------------------------------
// Round-trip integration test (skipped without real authenticator)
// ---------------------------------------------------------------------------

func TestCompleteRegistration_Integration(t *testing.T) {
	t.Skip("requires real authenticator attestation response — run with -tags=integration and a FIDO2 device")
}

func TestCompleteAuthentication_Integration(t *testing.T) {
	t.Skip("requires real authenticator assertion response — run with -tags=integration and a FIDO2 device")
}

// ---------------------------------------------------------------------------
// b64url helper tests
// ---------------------------------------------------------------------------

func TestB64urlRoundTrip(t *testing.T) {
	data := []byte("hello-webauthn-world!")
	encoded := b64urlEncode(data)

	// Must not contain +, /, or =.
	if strings.ContainsAny(encoded, "+/=") {
		t.Errorf("b64urlEncode produced non-base64url chars: %s", encoded)
	}

	decoded, err := b64urlDecode(encoded)
	if err != nil {
		t.Fatalf("b64urlDecode error: %v", err)
	}
	if string(decoded) != string(data) {
		t.Errorf("round-trip mismatch: got %q, want %q", string(decoded), string(data))
	}
}

func TestB64urlDecode_WithPadding(t *testing.T) {
	// "test" in base64url with padding = "dGVzdA=="
	decoded, err := b64urlDecode("dGVzdA==")
	if err != nil {
		t.Fatalf("b64urlDecode error: %v", err)
	}
	if string(decoded) != "test" {
		t.Errorf("got %q, want %q", string(decoded), "test")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newTestService(t *testing.T) *WebAuthnService {
	t.Helper()
	svc, err := NewWebAuthnService(Config{
		RPID:   "localhost",
		RPName: "Test",
		Origin: "http://localhost:9002",
	})
	if err != nil {
		t.Fatalf("newTestService: %v", err)
	}
	return svc
}
