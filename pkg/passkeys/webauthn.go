package passkeys

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Config for the WebAuthn relying party.
type Config struct {
	RPID   string // e.g. "localhost" or "glassa.work"
	RPName string // e.g. "Glassa Work"
	Origin string // e.g. "https://glassa.work" or "http://localhost:9002"
}

// RegistrationResult holds the verified credential data after a successful
// registration ceremony. All fields are in their storage-friendly encoding.
type RegistrationResult struct {
	CredentialID string // base64url (unpadded)
	PublicKey    string // base64 (standard, with padding)
	SignCount    uint32
	AAGUID       string
	Transports   string // comma-separated
}

// WebAuthnService wraps go-webauthn for registration and authentication
// ceremonies. It is safe for concurrent use.
type WebAuthnService struct {
	wa *webauthn.WebAuthn
}

// NewWebAuthnService creates a WebAuthnService from the given Config.
// Returns an error if the configuration is invalid.
func NewWebAuthnService(cfg Config) (*WebAuthnService, error) {
	if cfg.RPID == "" {
		return nil, fmt.Errorf("passkeys: RPID is required")
	}
	if cfg.Origin == "" {
		return nil, fmt.Errorf("passkeys: Origin is required")
	}

	wconfig := &webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPName,
		RPOrigins:     []string{cfg.Origin},
	}

	wa, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("passkeys: creating webauthn instance: %w", err)
	}

	return &WebAuthnService{wa: wa}, nil
}

// b64urlEncode encodes bytes to unpadded base64url.
func b64urlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// b64urlDecode decodes a base64url string (with or without padding).
func b64urlDecode(s string) ([]byte, error) {
	// Strip any padding the caller may have included.
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}

// BeginRegistration generates PublicKeyCredentialCreationOptions for
// navigator.credentials.create().
//
// existingCredIDs contains base64url credential IDs to exclude (the user's
// already-registered devices).
//
// Returns optionsJSON (the serialized options to send to the frontend) and
// challenge (base64url for server-side storage).
func (s *WebAuthnService) BeginRegistration(
	userID, userEmail, userDisplayName string,
	existingCredIDs []string,
) (optionsJSON string, challenge string, err error) {
	displayName := userDisplayName
	if displayName == "" {
		displayName = userEmail
	}

	// Build exclude list from existing credential IDs.
	excludeCreds := make([]protocol.CredentialDescriptor, 0, len(existingCredIDs))
	for _, cidB64 := range existingCredIDs {
		raw, decErr := b64urlDecode(cidB64)
		if decErr != nil {
			return "", "", fmt.Errorf("passkeys: decoding existing credential ID %q: %w", cidB64, decErr)
		}
		excludeCreds = append(excludeCreds, protocol.CredentialDescriptor{
			Type:            protocol.PublicKeyCredentialType,
			CredentialID:    raw,
		})
	}

	user := &WebAuthnUser{
		ID:          []byte(userID),
		Name:        userEmail,
		DisplayName: displayName,
		Credentials: nil,
	}

	opts := []webauthn.RegistrationOption{
		webauthn.WithExclusions(excludeCreds),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		}),
	}

	creation, session, createErr := s.wa.BeginRegistration(user, opts...)
	if createErr != nil {
		return "", "", fmt.Errorf("passkeys: begin registration: %w", createErr)
	}

	jsonBytes, marshalErr := json.Marshal(creation)
	if marshalErr != nil {
		return "", "", fmt.Errorf("passkeys: marshalling creation options: %w", marshalErr)
	}

	// session.Challenge is already a base64url-encoded string.
	return string(jsonBytes), session.Challenge, nil
}

// CompleteRegistration verifies the attestation response from the browser
// after navigator.credentials.create() completes.
//
// credentialJSON is the JSON-serialized credential from the browser.
// expectedChallenge is the base64url challenge stored server-side during
// BeginRegistration.
//
// Returns a RegistrationResult with the verified credential data.
func (s *WebAuthnService) CompleteRegistration(
	credentialJSON string,
	expectedChallenge string,
) (result *RegistrationResult, err error) {
	// Parse the credential JSON into a parsed response.
	parsedResponse, parseErr := protocol.ParseCredentialCreationResponseBody(
		strings.NewReader(credentialJSON),
	)
	if parseErr != nil {
		return nil, fmt.Errorf("passkeys: parsing credential creation response: %w", parseErr)
	}

	// Build a synthetic session with the expected challenge so we can use
	// the library's verification. Challenge is already base64url-encoded.
	session := webauthn.SessionData{
		Challenge: expectedChallenge,
	}

	// We need a user object — the library only uses it to set credential
	// ownership, not for challenge verification.
	user := &WebAuthnUser{
		ID:   []byte("registration-user"),
		Name: "registration-user",
	}

	credential, verifyErr := s.wa.CreateCredential(user, session, parsedResponse)
	if verifyErr != nil {
		return nil, fmt.Errorf("passkeys: verifying registration: %w", verifyErr)
	}

	// Extract transports from the raw JSON (the library may not surface them
	// on the credential object reliably).
	var rawCred struct {
		Response struct {
			Transports []string `json:"transports"`
		} `json:"response"`
	}
	_ = json.Unmarshal([]byte(credentialJSON), &rawCred)
	transportsStr := strings.Join(rawCred.Response.Transports, ",")

	aaguid := ""
	if credential.Authenticator.AAGUID != nil {
		// Format as hex UUID-style string.
		a := credential.Authenticator.AAGUID
		if len(a) == 16 {
			aaguid = fmt.Sprintf(
				"%x-%x-%x-%x-%x",
				a[0:4], a[4:6], a[6:8], a[8:10], a[10:16],
			)
		} else {
			aaguid = fmt.Sprintf("%x", a)
		}
	}

	return &RegistrationResult{
		CredentialID: b64urlEncode(credential.ID),
		PublicKey:    base64.StdEncoding.EncodeToString(credential.PublicKey),
		SignCount:    credential.Authenticator.SignCount,
		AAGUID:       aaguid,
		Transports:   transportsStr,
	}, nil
}

// BeginAuthentication generates PublicKeyCredentialRequestOptions for
// navigator.credentials.get().
//
// allowedCredIDs contains base64url credential IDs the user has registered.
// If empty, the authenticator may use any discoverable (resident) credential
// — i.e. the usernameless flow.
//
// Returns optionsJSON and challenge (base64url).
func (s *WebAuthnService) BeginAuthentication(
	allowedCredIDs []string,
) (optionsJSON string, challenge string, err error) {
	opts := []webauthn.LoginOption{
		webauthn.WithUserVerification(protocol.VerificationPreferred),
	}

	var (
		assertion *protocol.CredentialAssertion
		session   *webauthn.SessionData
		loginErr  error
	)

	if len(allowedCredIDs) == 0 {
		// Discoverable credentials — no allowCredentials list (usernameless flow).
		assertion, session, loginErr = s.wa.BeginDiscoverableLogin(opts...)
	} else {
		// Build allow list and a user carrying those credentials.
		user := &WebAuthnUser{
			ID:   []byte("auth-user"),
			Name: "auth-user",
		}
		creds := make([]webauthn.Credential, 0, len(allowedCredIDs))
		for _, cidB64 := range allowedCredIDs {
			raw, decErr := b64urlDecode(cidB64)
			if decErr != nil {
				return "", "", fmt.Errorf("passkeys: decoding allowed credential ID %q: %w", cidB64, decErr)
			}
			creds = append(creds, webauthn.Credential{
				ID: raw,
			})
		}
		user.Credentials = creds

		assertion, session, loginErr = s.wa.BeginLogin(user, opts...)
	}

	if loginErr != nil {
		return "", "", fmt.Errorf("passkeys: begin authentication: %w", loginErr)
	}

	jsonBytes, marshalErr := json.Marshal(assertion)
	if marshalErr != nil {
		return "", "", fmt.Errorf("passkeys: marshalling request options: %w", marshalErr)
	}

	// session.Challenge is already a base64url-encoded string.
	return string(jsonBytes), session.Challenge, nil
}

// CompleteAuthentication verifies the assertion response from
// navigator.credentials.get().
//
// It validates the signature against the stored public key and checks the
// sign count for cloned authenticator detection.
//
// Returns the new sign count on success.
func (s *WebAuthnService) CompleteAuthentication(
	credentialJSON string,
	expectedChallenge string,
	storedPublicKeyB64 string,
	storedSignCount uint32,
	storedCredentialID string,
) (newSignCount uint32, err error) {
	credIDBytes, decErr := b64urlDecode(storedCredentialID)
	if decErr != nil {
		return 0, fmt.Errorf("passkeys: decoding stored credential ID: %w", decErr)
	}

	pubKeyBytes, decErr := base64.StdEncoding.DecodeString(storedPublicKeyB64)
	if decErr != nil {
		return 0, fmt.Errorf("passkeys: decoding stored public key: %w", decErr)
	}

	parsedResponse, parseErr := protocol.ParseCredentialRequestResponseBody(
		strings.NewReader(credentialJSON),
	)
	if parseErr != nil {
		return 0, fmt.Errorf("passkeys: parsing credential request response: %w", parseErr)
	}

	// Challenge is already base64url-encoded.
	session := webauthn.SessionData{
		Challenge: expectedChallenge,
	}

	// Build a user with the stored credential so the library can verify.
	user := &WebAuthnUser{
		ID:   []byte("auth-user"),
		Name: "auth-user",
		Credentials: []webauthn.Credential{
			{
				ID:        credIDBytes,
				PublicKey: pubKeyBytes,
				Authenticator: webauthn.Authenticator{
					SignCount: storedSignCount,
				},
			},
		},
	}

	credential, loginErr := s.wa.ValidateLogin(user, session, parsedResponse)
	if loginErr != nil {
		return 0, fmt.Errorf("passkeys: verifying authentication: %w", loginErr)
	}

	return credential.Authenticator.SignCount, nil
}

// ExtractCredentialID extracts the credential ID from a raw credential JSON
// response (from navigator.credentials.get() or .create()). The returned
// value is base64url-encoded without padding.
func ExtractCredentialID(credentialJSON string) (string, error) {
	var cred struct {
		ID    string `json:"id"`
		RawID string `json:"rawId"`
	}

	if err := json.Unmarshal([]byte(credentialJSON), &cred); err != nil {
		return "", fmt.Errorf("passkeys: parsing credential JSON: %w", err)
	}

	raw := cred.ID
	if raw == "" {
		raw = cred.RawID
	}
	if raw == "" {
		return "", fmt.Errorf("passkeys: credential JSON missing 'id' and 'rawId'")
	}

	// Normalize — strip padding if the caller included it.
	return strings.TrimRight(raw, "="), nil
}
