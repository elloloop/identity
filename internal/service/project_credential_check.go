package service

import (
	"context"
	"crypto/subtle"
)

// Reasons recorded on a refused machine-credential presentation.
const (
	credentialRefusedSecretMismatch = "secret_mismatch"
	credentialRefusedRevoked        = "revoked"
)

// checkProjectCredential resolves a split "<public id>.<secret>" key to its
// credential when that credential is of kind. It returns a nil credential
// when no credential of kind has the public id, and the credential with a
// refusal reason when one exists but the secret is wrong or it is revoked,
// so the caller can audit that refusal under the credential's project. The
// secret is hashed before the read, so an unknown public id costs the same
// as a known one.
func checkProjectCredential(ctx context.Context, store DirectoryCredentialStore, kind, publicID, secret string) (*AdminProjectCredential, string, error) {
	presentedHash := sha256Hex(secret)
	cred, err := store.CredentialByPublicIDInActiveProject(ctx, publicID)
	if err != nil {
		return nil, "", err
	}
	if cred == nil || cred.Kind != kind {
		return nil, "", nil
	}
	switch {
	case subtle.ConstantTimeCompare([]byte(presentedHash), []byte(cred.SecretHash)) != 1:
		return cred, credentialRefusedSecretMismatch, nil
	case cred.Revoked:
		return cred, credentialRefusedRevoked, nil
	}
	return cred, "", nil
}
