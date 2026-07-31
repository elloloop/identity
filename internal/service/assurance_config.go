package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// ProjectAssuranceConfig is a project's client-attestation identity: the
// iOS and Android app builds whose hardware attestations the project
// accepts. Platforms are independent — a project may configure either,
// both, or neither. Web assurance (Turnstile/reCAPTCHA) is deployment-
// global, not per-project: the siteverify secret authenticates our
// server to the captcha provider, not one app to us.
type ProjectAssuranceConfig struct {
	IOS     *ProjectAssuranceIOS     `json:"ios,omitempty"`
	Android *ProjectAssuranceAndroid `json:"android,omitempty"`
}

// ProjectAssuranceIOS identifies the App Attest app: TeamID.BundleID is
// the App ID every attestation's RP hash must match.
type ProjectAssuranceIOS struct {
	TeamID   string `json:"team_id"`
	BundleID string `json:"bundle_id"`
	// Env selects the App Attest environment AAGUID: "production"
	// (default when empty) or "development".
	Env string `json:"env,omitempty"`
}

// ProjectAssuranceAndroid identifies the Play Integrity app and carries
// the encrypted Google service-account key used to decode verdicts.
type ProjectAssuranceAndroid struct {
	PackageName string `json:"package_name"`
	// CertSHA256Digests are allowed signing-cert digests (unpadded
	// base64url SHA-256, as Play reports them).
	CertSHA256Digests []string `json:"cert_sha256_digests"`
	// ServiceAccountKeyEnc is the service-account JSON key encrypted
	// under GATEWAY_PROJECT_SECRETS_KEY (AES-256-GCM), mirroring the
	// per-project OAuth client_secret_enc handling. Never returned
	// decrypted by any read RPC.
	ServiceAccountKeyEnc string `json:"service_account_key_enc"`
}

// validate rejects present-but-incomplete platform blocks: a half-filled
// block would produce a platform that can never verify an attestation,
// so it fails the config write instead (mirroring the OAuth-block rule).
func (a ProjectAssuranceConfig) validate() error {
	if ios := a.IOS; ios != nil {
		if ios.TeamID == "" || ios.BundleID == "" {
			return fmt.Errorf("%w: assurance.ios requires team_id and bundle_id", ErrInvalidArgument)
		}
		switch ios.Env {
		case "", "production", "development":
		default:
			return fmt.Errorf("%w: assurance.ios.env must be production or development, got %q", ErrInvalidArgument, ios.Env)
		}
	}
	if and := a.Android; and != nil {
		if and.PackageName == "" || len(and.CertSHA256Digests) == 0 || and.ServiceAccountKeyEnc == "" {
			return fmt.Errorf("%w: assurance.android requires package_name, cert_sha256_digests, and service_account_key_enc", ErrInvalidArgument)
		}
		for _, d := range and.CertSHA256Digests {
			if d == "" {
				return fmt.Errorf("%w: assurance.android.cert_sha256_digests contains an empty digest", ErrInvalidArgument)
			}
		}
	}
	return nil
}

// isZero reports whether no platform is configured.
func (a ProjectAssuranceConfig) isZero() bool { return a.IOS == nil && a.Android == nil }

// hash pins a resolver cache entry to one exact assurance config; any
// field change produces a new hash and therefore a rebuild.
//
// The struct holds only strings, string slices and pointers to the same,
// so json.Marshal cannot fail — the error is discarded rather than
// guarded with an unreachable branch.
func (a ProjectAssuranceConfig) hash() string {
	raw, _ := json.Marshal(a) //nolint:errchkjson // only strings and slices; cannot fail
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
