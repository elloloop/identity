package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ProjectAssuranceInput is the write shape for a project's assurance app
// identity. The Play service-account key arrives in PLAINTEXT and is
// encrypted server-side, mirroring how an OAuth client secret is authored
// — an operator must never have to reimplement the at-rest encryption.
// An empty key keeps whatever is already stored, so other fields can be
// rotated without re-supplying it.
type ProjectAssuranceInput struct {
	IOSTeamID   string
	IOSBundleID string
	IOSEnv      string

	AndroidPackageName       string
	AndroidCertSHA256Digests []string
	AndroidServiceAccountKey string // plaintext; empty = keep stored

	// ClearIOS / ClearAndroid remove that platform's stored block. Removal
	// is only ever explicit: a write that does not mention a platform
	// leaves it untouched, because the stored Android service-account key
	// is ciphertext the operator cannot reconstruct.
	ClearIOS     bool
	ClearAndroid bool
}

// ProjectAssuranceView is the redacted read shape: it reports WHETHER a
// service-account key is stored, never the key itself.
type ProjectAssuranceView struct {
	IOSTeamID   string
	IOSBundleID string
	IOSEnv      string

	AndroidPackageName       string
	AndroidCertSHA256Digests []string
	HasServiceAccountKey     bool
}

// AdminSetProjectAssurance writes a project's `assurance` config block,
// encrypting the supplied Play service-account key at rest. It preserves
// every OTHER key in the project's config (branding, passkey, oauth,
// access, …) and runs inside the optimistic-concurrency helper so a
// concurrent write to a sibling block cannot clobber it.
//
// The merge is PER PLATFORM: supplying any field of a platform replaces
// that platform's block; a platform the caller does not mention is left
// exactly as stored. Deletion is therefore never implicit — an iOS-only
// rotation cannot destroy the Android service-account key, which is
// ciphertext the operator cannot recover. Use ClearIOS / ClearAndroid to
// remove a platform on purpose.
func (s *ControlPlaneAdminService) AdminSetProjectAssurance(ctx context.Context, secret, projectID string, in *ProjectAssuranceInput) (*ProjectAssuranceView, error) {
	if err := s.authorize(secret); err != nil {
		return nil, err
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	if in == nil {
		return nil, fmt.Errorf("%w: missing config", ErrInvalidArgument)
	}

	var view *ProjectAssuranceView
	if _, err := s.mutateProjectConfig(ctx, projectID, func(current string) (string, error) {
		top, existing, err := decodeAssuranceSubtree(current)
		if err != nil {
			return "", err
		}

		next, err := s.buildAssurance(in, existing)
		if err != nil {
			return "", err
		}
		// Validate the assembled block before it is written, so a
		// half-specified platform fails the write rather than producing a
		// project that can never verify an attestation.
		if err := next.validate(); err != nil {
			return "", err
		}

		if next.isZero() {
			delete(top, "assurance")
		} else {
			raw, err := json.Marshal(next)
			if err != nil {
				return "", fmt.Errorf("encoding assurance config: %w", err)
			}
			top["assurance"] = json.RawMessage(raw)
		}
		encoded, err := json.Marshal(top)
		if err != nil {
			return "", fmt.Errorf("encoding project config: %w", err)
		}
		view = assuranceView(next)
		return string(encoded), nil
	}); err != nil {
		return nil, err
	}
	return view, nil
}

// GetProjectAssurance returns the project's stored assurance block in its
// redacted read shape.
func (s *ControlPlaneAdminService) GetProjectAssurance(ctx context.Context, secret, projectID string) (*ProjectAssuranceView, error) {
	if err := s.authorize(secret); err != nil {
		return nil, err
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	current, _, err := s.projects.GetProjectConfig(ctx, projectID)
	if err != nil {
		return nil, err
	}
	_, existing, err := decodeAssuranceSubtree(current)
	if err != nil {
		return nil, err
	}
	return assuranceView(existing), nil
}

// buildAssurance merges the input over the stored block, encrypting a
// newly supplied service-account key and keeping the stored ciphertext
// when the caller supplies none.
func (s *ControlPlaneAdminService) buildAssurance(in *ProjectAssuranceInput, existing ProjectAssuranceConfig) (ProjectAssuranceConfig, error) {
	// Start from what is stored: an unmentioned platform survives.
	out := existing

	switch {
	case in.ClearIOS:
		out.IOS = nil
	case in.IOSTeamID != "" || in.IOSBundleID != "" || in.IOSEnv != "":
		out.IOS = &ProjectAssuranceIOS{
			TeamID:   strings.TrimSpace(in.IOSTeamID),
			BundleID: strings.TrimSpace(in.IOSBundleID),
			Env:      strings.TrimSpace(in.IOSEnv),
		}
	}

	switch {
	case in.ClearAndroid:
		out.Android = nil
	case in.AndroidPackageName != "" || len(in.AndroidCertSHA256Digests) > 0 || in.AndroidServiceAccountKey != "":
		var keep string
		if existing.Android != nil {
			keep = existing.Android.ServiceAccountKeyEnc
		}
		enc, err := s.encryptOrKeep(in.AndroidServiceAccountKey, keep)
		if err != nil {
			return ProjectAssuranceConfig{}, err
		}
		out.Android = &ProjectAssuranceAndroid{
			PackageName:          strings.TrimSpace(in.AndroidPackageName),
			CertSHA256Digests:    trimDigests(in.AndroidCertSHA256Digests),
			ServiceAccountKeyEnc: enc,
		}
	}
	return out, nil
}

// decodeAssuranceSubtree splits a project's config into its top-level map
// and its typed `assurance` block, so a write replaces only that key.
func decodeAssuranceSubtree(current string) (map[string]json.RawMessage, ProjectAssuranceConfig, error) {
	top := map[string]json.RawMessage{}
	if strings.TrimSpace(current) != "" {
		if err := json.Unmarshal([]byte(current), &top); err != nil {
			return nil, ProjectAssuranceConfig{}, fmt.Errorf("%w: stored project config is not valid JSON: %w", ErrInvalidArgument, err)
		}
	}
	var existing ProjectAssuranceConfig
	if raw, ok := top["assurance"]; ok {
		if err := json.Unmarshal(raw, &existing); err != nil {
			return nil, ProjectAssuranceConfig{}, fmt.Errorf("%w: stored assurance config is not valid JSON: %w", ErrInvalidArgument, err)
		}
	}
	return top, existing, nil
}

// assuranceView renders the redacted read view.
func assuranceView(cfg ProjectAssuranceConfig) *ProjectAssuranceView {
	v := &ProjectAssuranceView{}
	if cfg.IOS != nil {
		v.IOSTeamID = cfg.IOS.TeamID
		v.IOSBundleID = cfg.IOS.BundleID
		v.IOSEnv = cfg.IOS.Env
	}
	if cfg.Android != nil {
		v.AndroidPackageName = cfg.Android.PackageName
		v.AndroidCertSHA256Digests = cfg.Android.CertSHA256Digests
		v.HasServiceAccountKey = cfg.Android.ServiceAccountKeyEnc != ""
	}
	return v
}

// trimDigests drops blank entries and surrounding space from a supplied
// digest list.
func trimDigests(in []string) []string {
	out := make([]string, 0, len(in))
	for _, d := range in {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	return out
}
