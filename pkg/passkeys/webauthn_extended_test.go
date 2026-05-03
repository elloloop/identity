package passkeys

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// W3C WebAuthn-3 spec test vectors
// https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-none-es256
//
// These vectors are used by go-webauthn's own test suite. They allow us to
// exercise CompleteRegistration / CompleteAuthentication without a real
// authenticator. The vectors target an RP at https://example.org with
// RPID="example.org".
// ---------------------------------------------------------------------------

const (
	// Registration (None ES256) vector.
	specRegAttestationObjectHex = "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"
	specRegClientDataJSONHex    = "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d"
	specRegCredentialIDHex      = "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4"
	specRegChallengeHex         = "00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130"

	// Authentication (None ES256) vector — uses the credential registered above.
	specLoginAuthenticatorDataHex = "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000"
	specLoginClientDataJSONHex    = "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"
	specLoginSignatureHex         = "3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87"
	specLoginCredentialIDHex      = "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4"
	specLoginChallengeHex         = "39c0e7521417ba54d43e8dc95174f423dee9bf3cd804ff6d65c857c9abf4d408"
	specLoginCredentialPubKeyHex  = "a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"
)

// newSpecVectorService returns a service configured for the spec vector RP.
func newSpecVectorService(t *testing.T) *WebAuthnService {
	t.Helper()
	svc, err := NewWebAuthnService(Config{
		RPID:   "example.org",
		RPName: "Example",
		Origin: "https://example.org",
	})
	if err != nil {
		t.Fatalf("newSpecVectorService: %v", err)
	}
	return svc
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

// buildRegistrationCredentialJSON builds a Web-style registration credential
// JSON envelope from raw attestation/client data and a credential ID.
func buildRegistrationCredentialJSON(t *testing.T, attestationObject, clientDataJSON, credentialID []byte, transports []string) string {
	t.Helper()
	id := base64.RawURLEncoding.EncodeToString(credentialID)
	resp := map[string]any{
		"attestationObject": base64.RawURLEncoding.EncodeToString(attestationObject),
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataJSON),
	}
	if transports != nil {
		resp["transports"] = transports
	}
	body := map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": resp,
	}
	out, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal credential json: %v", err)
	}
	return string(out)
}

// buildAssertionCredentialJSON builds a Web-style assertion credential JSON
// envelope from raw authenticator data, client data, signature, credential ID,
// and optional userHandle.
func buildAssertionCredentialJSON(t *testing.T, authData, clientDataJSON, signature, credentialID, userHandle []byte) string {
	t.Helper()
	id := base64.RawURLEncoding.EncodeToString(credentialID)
	resp := map[string]any{
		"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataJSON),
		"signature":         base64.RawURLEncoding.EncodeToString(signature),
	}
	if userHandle != nil {
		resp["userHandle"] = base64.RawURLEncoding.EncodeToString(userHandle)
	}
	body := map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": resp,
	}
	out, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal credential json: %v", err)
	}
	return string(out)
}

// ---------------------------------------------------------------------------
// CompleteRegistration — happy path with spec vectors
// ---------------------------------------------------------------------------

func TestCompleteRegistration_SpecVectorNoneES256(t *testing.T) {
	t.Parallel()

	svc := newSpecVectorService(t)

	attObj := mustHex(t, specRegAttestationObjectHex)
	cdj := mustHex(t, specRegClientDataJSONHex)
	credID := mustHex(t, specRegCredentialIDHex)
	challenge := base64.RawURLEncoding.EncodeToString(mustHex(t, specRegChallengeHex))

	credJSON := buildRegistrationCredentialJSON(t, attObj, cdj, credID, []string{"usb", "nfc"})

	result, err := svc.CompleteRegistration(credJSON, challenge)
	if err != nil {
		t.Fatalf("CompleteRegistration error: %v", err)
	}
	if result == nil {
		t.Fatal("nil result")
	}
	if result.CredentialID != base64.RawURLEncoding.EncodeToString(credID) {
		t.Errorf("CredentialID = %q, want %q",
			result.CredentialID, base64.RawURLEncoding.EncodeToString(credID))
	}
	if result.PublicKey == "" {
		t.Error("PublicKey is empty")
	}
	// PublicKey is standard base64; it should decode cleanly.
	if _, err := base64.StdEncoding.DecodeString(result.PublicKey); err != nil {
		t.Errorf("PublicKey not valid std-base64: %v", err)
	}
	if result.Transports != "usb,nfc" {
		t.Errorf("Transports = %q, want %q", result.Transports, "usb,nfc")
	}
	// AAGUID for the spec vector is 8446ccb9-ab1d-b374-750b-2367ff6f3a1f
	// (the bytes after the credential-id length in the auth data).
	if result.AAGUID == "" {
		t.Error("AAGUID is empty")
	}
	if !strings.Contains(result.AAGUID, "-") {
		t.Errorf("AAGUID = %q, want hyphenated UUID", result.AAGUID)
	}
}

func TestCompleteRegistration_SpecVectorNoTransports(t *testing.T) {
	t.Parallel()

	svc := newSpecVectorService(t)

	attObj := mustHex(t, specRegAttestationObjectHex)
	cdj := mustHex(t, specRegClientDataJSONHex)
	credID := mustHex(t, specRegCredentialIDHex)
	challenge := base64.RawURLEncoding.EncodeToString(mustHex(t, specRegChallengeHex))

	// No transports field at all.
	credJSON := buildRegistrationCredentialJSON(t, attObj, cdj, credID, nil)

	result, err := svc.CompleteRegistration(credJSON, challenge)
	if err != nil {
		t.Fatalf("CompleteRegistration error: %v", err)
	}
	if result.Transports != "" {
		t.Errorf("Transports = %q, want empty", result.Transports)
	}
}

// ---------------------------------------------------------------------------
// CompleteRegistration — failure paths
// ---------------------------------------------------------------------------

func TestCompleteRegistration_InvalidJSON(t *testing.T) {
	t.Parallel()

	svc := newSpecVectorService(t)

	_, err := svc.CompleteRegistration("not valid json", "challenge")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parsing credential creation response") {
		t.Errorf("error = %v, want parse error", err)
	}
}

func TestCompleteRegistration_WrongChallenge(t *testing.T) {
	t.Parallel()

	svc := newSpecVectorService(t)

	attObj := mustHex(t, specRegAttestationObjectHex)
	cdj := mustHex(t, specRegClientDataJSONHex)
	credID := mustHex(t, specRegCredentialIDHex)
	credJSON := buildRegistrationCredentialJSON(t, attObj, cdj, credID, nil)

	// Wrong challenge — verification must fail.
	wrongChallenge := base64.RawURLEncoding.EncodeToString([]byte("wrong-challenge-bytes-zzzzzzzzzz"))
	_, err := svc.CompleteRegistration(credJSON, wrongChallenge)
	if err == nil {
		t.Fatal("expected error for wrong challenge")
	}
	if !strings.Contains(err.Error(), "verifying registration") {
		t.Errorf("error = %v, want verify error", err)
	}
}

func TestCompleteRegistration_WrongOrigin(t *testing.T) {
	t.Parallel()

	// Service configured for a *different* origin than the clientDataJSON.
	svc, err := NewWebAuthnService(Config{
		RPID:   "evil.example.com",
		RPName: "Evil",
		Origin: "https://evil.example.com",
	})
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}

	attObj := mustHex(t, specRegAttestationObjectHex)
	cdj := mustHex(t, specRegClientDataJSONHex)
	credID := mustHex(t, specRegCredentialIDHex)
	challenge := base64.RawURLEncoding.EncodeToString(mustHex(t, specRegChallengeHex))
	credJSON := buildRegistrationCredentialJSON(t, attObj, cdj, credID, nil)

	_, err = svc.CompleteRegistration(credJSON, challenge)
	if err == nil {
		t.Fatal("expected error for wrong origin")
	}
}

func TestCompleteRegistration_TamperedClientDataJSON(t *testing.T) {
	t.Parallel()

	svc := newSpecVectorService(t)

	attObj := mustHex(t, specRegAttestationObjectHex)
	cdj := mustHex(t, specRegClientDataJSONHex)
	// Flip a byte in the client data — challenge hash baked into authenticator
	// data must no longer match.
	tampered := make([]byte, len(cdj))
	copy(tampered, cdj)
	tampered[10] ^= 0x01

	credID := mustHex(t, specRegCredentialIDHex)
	challenge := base64.RawURLEncoding.EncodeToString(mustHex(t, specRegChallengeHex))

	credJSON := buildRegistrationCredentialJSON(t, attObj, tampered, credID, nil)

	_, err := svc.CompleteRegistration(credJSON, challenge)
	if err == nil {
		t.Fatal("expected error for tampered clientDataJSON")
	}
}

// ---------------------------------------------------------------------------
// CompleteAuthentication — failure paths
//
// Note: a happy-path spec-vector login test is omitted intentionally. The
// W3C spec vector for login asserts an authenticator with the BackupEligible
// (BE) flag set, which go-webauthn validates against the *stored* credential's
// flags. Our wrapper does not (yet) round-trip BE state through the persisted
// credential record, so reproducing this in a unit test would require either
// patching the source to surface BE in RegistrationResult / accept it in
// CompleteAuthentication, or hand-crafting an assertion with BE=0. We rely
// instead on the failure-path tests below (which all exercise ValidateLogin
// up through signature/auth-data verification) plus an integration test
// against a real authenticator.
// ---------------------------------------------------------------------------

func TestCompleteAuthentication_BadStoredCredentialID(t *testing.T) {
	t.Parallel()

	svc := newSpecVectorService(t)

	// stored credential ID is not valid base64url.
	_, err := svc.CompleteAuthentication("{}", "chal", "cHVi", 0, "not!base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid stored credential ID")
	}
	if !strings.Contains(err.Error(), "decoding stored credential ID") {
		t.Errorf("error = %v, want decode error", err)
	}
}

func TestCompleteAuthentication_BadStoredPublicKey(t *testing.T) {
	t.Parallel()

	svc := newSpecVectorService(t)

	credID := base64.RawURLEncoding.EncodeToString([]byte("cred"))
	_, err := svc.CompleteAuthentication("{}", "chal", "!!!not-base64!!!", 0, credID)
	if err == nil {
		t.Fatal("expected error for invalid stored public key")
	}
	if !strings.Contains(err.Error(), "decoding stored public key") {
		t.Errorf("error = %v, want decode error", err)
	}
}

func TestCompleteAuthentication_InvalidJSON(t *testing.T) {
	t.Parallel()

	svc := newSpecVectorService(t)
	credID := base64.RawURLEncoding.EncodeToString([]byte("cred"))
	pubKey := base64.StdEncoding.EncodeToString([]byte("pubkey"))

	_, err := svc.CompleteAuthentication("not valid json", "chal", pubKey, 0, credID)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parsing credential request response") {
		t.Errorf("error = %v, want parse error", err)
	}
}

func TestCompleteAuthentication_WrongChallenge(t *testing.T) {
	t.Parallel()

	svc := newSpecVectorService(t)

	authData := mustHex(t, specLoginAuthenticatorDataHex)
	cdj := mustHex(t, specLoginClientDataJSONHex)
	sig := mustHex(t, specLoginSignatureHex)
	credID := mustHex(t, specLoginCredentialIDHex)
	pubKey := mustHex(t, specLoginCredentialPubKeyHex)

	credJSON := buildAssertionCredentialJSON(t, authData, cdj, sig, credID, nil)

	wrongChallenge := base64.RawURLEncoding.EncodeToString([]byte("totally-wrong-challenge-aaaaaaaa"))
	storedCredID := base64.RawURLEncoding.EncodeToString(credID)
	storedPubKey := base64.StdEncoding.EncodeToString(pubKey)

	_, err := svc.CompleteAuthentication(credJSON, wrongChallenge, storedPubKey, 0, storedCredID)
	if err == nil {
		t.Fatal("expected error for wrong challenge")
	}
	if !strings.Contains(err.Error(), "verifying authentication") {
		t.Errorf("error = %v, want verify error", err)
	}
}

func TestCompleteAuthentication_WrongPublicKey(t *testing.T) {
	t.Parallel()

	svc := newSpecVectorService(t)

	authData := mustHex(t, specLoginAuthenticatorDataHex)
	cdj := mustHex(t, specLoginClientDataJSONHex)
	sig := mustHex(t, specLoginSignatureHex)
	credID := mustHex(t, specLoginCredentialIDHex)
	challenge := base64.RawURLEncoding.EncodeToString(mustHex(t, specLoginChallengeHex))

	credJSON := buildAssertionCredentialJSON(t, authData, cdj, sig, credID, nil)

	// Use a bogus (but valid-base64) public key.
	storedCredID := base64.RawURLEncoding.EncodeToString(credID)
	bogusPubKey := base64.StdEncoding.EncodeToString([]byte("not-a-real-cose-public-key-blob!"))

	_, err := svc.CompleteAuthentication(credJSON, challenge, bogusPubKey, 0, storedCredID)
	if err == nil {
		t.Fatal("expected error for wrong public key")
	}
}

func TestCompleteAuthentication_TamperedAuthenticatorData(t *testing.T) {
	t.Parallel()

	svc := newSpecVectorService(t)

	authData := mustHex(t, specLoginAuthenticatorDataHex)
	// Flip a bit in the auth data — sig over (authData || sha256(cdj)) breaks.
	tampered := make([]byte, len(authData))
	copy(tampered, authData)
	tampered[len(tampered)-1] ^= 0x01

	cdj := mustHex(t, specLoginClientDataJSONHex)
	sig := mustHex(t, specLoginSignatureHex)
	credID := mustHex(t, specLoginCredentialIDHex)
	pubKey := mustHex(t, specLoginCredentialPubKeyHex)
	challenge := base64.RawURLEncoding.EncodeToString(mustHex(t, specLoginChallengeHex))

	credJSON := buildAssertionCredentialJSON(t, tampered, cdj, sig, credID, nil)

	storedCredID := base64.RawURLEncoding.EncodeToString(credID)
	storedPubKey := base64.StdEncoding.EncodeToString(pubKey)

	_, err := svc.CompleteAuthentication(credJSON, challenge, storedPubKey, 0, storedCredID)
	if err == nil {
		t.Fatal("expected error for tampered authenticatorData")
	}
}

func TestCompleteAuthentication_CounterRegression(t *testing.T) {
	t.Parallel()

	// The spec-vector authData has SignCount = 25. If we pass a stored
	// SignCount >= 25, the library should detect a clone (the assertion's
	// counter is not strictly greater than what we have on file).
	svc := newSpecVectorService(t)

	authData := mustHex(t, specLoginAuthenticatorDataHex)
	cdj := mustHex(t, specLoginClientDataJSONHex)
	sig := mustHex(t, specLoginSignatureHex)
	credID := mustHex(t, specLoginCredentialIDHex)
	pubKey := mustHex(t, specLoginCredentialPubKeyHex)
	challenge := base64.RawURLEncoding.EncodeToString(mustHex(t, specLoginChallengeHex))

	credJSON := buildAssertionCredentialJSON(t, authData, cdj, sig, credID, nil)

	storedCredID := base64.RawURLEncoding.EncodeToString(credID)
	storedPubKey := base64.StdEncoding.EncodeToString(pubKey)

	// Stored count = 100, authenticator presents 25. The library returns
	// the new (lower) count and (depending on version) may flag a clone.
	// We can't guarantee an error here — the library returns the cloned
	// flag on the credential rather than aborting — but the key detection
	// data is still surfaced. Either an error OR a non-incrementing count
	// is acceptable for our wrapper's purposes.
	newCount, err := svc.CompleteAuthentication(credJSON, challenge, storedPubKey, 100, storedCredID)
	if err == nil {
		// If no error, the returned count should be the authenticator-reported
		// 25 (which is < stored 100). Caller must detect regression.
		if newCount >= 100 {
			t.Errorf("expected counter regression: stored=100, new=%d", newCount)
		}
	}
}

func TestCompleteAuthentication_WrongCredentialID(t *testing.T) {
	t.Parallel()

	svc := newSpecVectorService(t)

	authData := mustHex(t, specLoginAuthenticatorDataHex)
	cdj := mustHex(t, specLoginClientDataJSONHex)
	sig := mustHex(t, specLoginSignatureHex)
	credID := mustHex(t, specLoginCredentialIDHex)
	pubKey := mustHex(t, specLoginCredentialPubKeyHex)
	challenge := base64.RawURLEncoding.EncodeToString(mustHex(t, specLoginChallengeHex))

	credJSON := buildAssertionCredentialJSON(t, authData, cdj, sig, credID, nil)

	// Stored credential ID does not match the credential in the assertion.
	differentCredID := base64.RawURLEncoding.EncodeToString([]byte("a-different-credential-id-bytes!"))
	storedPubKey := base64.StdEncoding.EncodeToString(pubKey)

	_, err := svc.CompleteAuthentication(credJSON, challenge, storedPubKey, 0, differentCredID)
	if err == nil {
		t.Fatal("expected error when stored credential ID mismatches")
	}
}

// ---------------------------------------------------------------------------
// BeginRegistration / BeginAuthentication failure paths
// ---------------------------------------------------------------------------

func TestBeginRegistration_BadExistingCredID(t *testing.T) {
	t.Parallel()

	svc := newTestService(t)

	// "***" is not valid base64url.
	_, _, err := svc.BeginRegistration("u", "u@x", "U", []string{"***not-base64***"})
	if err == nil {
		t.Fatal("expected error for invalid existing credential ID")
	}
	if !strings.Contains(err.Error(), "decoding existing credential ID") {
		t.Errorf("error = %v, want decode error", err)
	}
}

func TestBeginAuthentication_BadAllowedCredID(t *testing.T) {
	t.Parallel()

	svc := newTestService(t)

	_, _, err := svc.BeginAuthentication([]string{"!!!not-base64!!!"})
	if err == nil {
		t.Fatal("expected error for invalid allowed credential ID")
	}
	if !strings.Contains(err.Error(), "decoding allowed credential ID") {
		t.Errorf("error = %v, want decode error", err)
	}
}

// ---------------------------------------------------------------------------
// NewWebAuthnService — RPID required path
// ---------------------------------------------------------------------------

func TestNewWebAuthnService_MissingRPID(t *testing.T) {
	t.Parallel()
	_, err := NewWebAuthnService(Config{
		RPID:   "",
		RPName: "Example",
		Origin: "https://example.org",
	})
	if err == nil {
		t.Fatal("expected error for missing RPID")
	}
	if !strings.Contains(err.Error(), "RPID is required") {
		t.Errorf("error = %v, want RPID required", err)
	}
}

func TestNewWebAuthnService_MissingOrigin(t *testing.T) {
	t.Parallel()
	_, err := NewWebAuthnService(Config{
		RPID:   "example.org",
		RPName: "Example",
		Origin: "",
	})
	if err == nil {
		t.Fatal("expected error for missing origin")
	}
	if !strings.Contains(err.Error(), "Origin is required") {
		t.Errorf("error = %v, want Origin required", err)
	}
}
