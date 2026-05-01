// Package passkeys provides WebAuthn/FIDO2 passkey registration and
// authentication using the go-webauthn library.
//
// All credential IDs are encoded as base64url (unpadded) per the WebAuthn spec.
// Public keys are stored as standard base64 (with padding) for compactness.
//
// Security:
//   - Never log public keys or credential data in full
//   - Challenge comparison is handled by go-webauthn (constant-time)
//   - Sign count verification detects cloned authenticators
package passkeys

import "github.com/go-webauthn/webauthn/webauthn"

// WebAuthnUser is a minimal implementation of the webauthn.User interface.
// It carries just enough data for the go-webauthn library to generate
// registration and authentication options.
type WebAuthnUser struct {
	ID          []byte
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

// WebAuthnID returns the user handle (opaque byte sequence).
func (u *WebAuthnUser) WebAuthnID() []byte { return u.ID }

// WebAuthnName returns the user's account identifier (typically email).
func (u *WebAuthnUser) WebAuthnName() string { return u.Name }

// WebAuthnDisplayName returns the human-friendly display name.
func (u *WebAuthnUser) WebAuthnDisplayName() string { return u.DisplayName }

// WebAuthnCredentials returns the user's registered credentials.
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }
