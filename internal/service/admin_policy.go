package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"
)

// maxConfigWriteAttempts bounds the optimistic-concurrency retries a config_json
// read-modify-write makes before surfacing the conflict. Three attempts absorb
// the realistic operator-concurrency window (a handful of admin writes racing on
// one project) without letting a pathological hot-loop spin unbounded.
const maxConfigWriteAttempts = 3

// mutateProjectConfig performs an optimistic-concurrency read-modify-write on a
// project's config_json — the single shared path every config mutator (admin
// OAuth set/delete, UpsertProjectConfig, and any future branding/passkey/cors
// mutator) routes through. It reads the current blob and version, applies mutate
// to compute the next blob, and writes it back guarded by the version it read.
// A concurrent writer that advanced the version between the read and the write
// loses the compare-and-swap; mutateProjectConfig then re-reads fresh state and
// retries, up to maxConfigWriteAttempts, before surfacing ErrProjectConfigConflict
// (which the Connect layer maps to the retryable CodeAborted).
//
// mutate may be invoked more than once, so it must derive its result purely from
// its current argument and carry no state across calls except through its return
// value. It returns the stored (normalised) blob on success.
func (s *ControlPlaneAdminService) mutateProjectConfig(ctx context.Context, projectID string, mutate func(current string) (string, error)) (string, error) {
	for attempt := 0; attempt < maxConfigWriteAttempts; attempt++ {
		current, version, err := s.projects.GetProjectConfig(ctx, projectID)
		if err != nil {
			return "", err
		}
		next, err := mutate(current)
		if err != nil {
			return "", err
		}
		stored, _, err := s.projects.UpdateProjectConfig(ctx, projectID, version, next)
		switch {
		case err == nil:
			return stored, nil
		case errors.Is(err, ErrProjectConfigConflict):
			continue
		default:
			return "", err
		}
	}
	return "", fmt.Errorf("%w: project config write contended after %d attempts", ErrProjectConfigConflict, maxConfigWriteAttempts)
}

// maxSessionTimeoutSeconds bounds the idle/absolute session timeouts an
// operator may author. The enforcement path converts these to epoch-ms by
// multiplying by msPerSecond (1000); a value near math.MaxInt64 would overflow
// int64 on that multiply and wrap negative, silently disabling the timeout.
// 100 years is far longer than any real session lifetime yet comfortably below
// math.MaxInt64/1000 (~2.9e8 years), so the *1000 conversion can never
// overflow.
const maxSessionTimeoutSeconds = 100 * 365 * 24 * 60 * 60

// This file adds the operator-authored write/read surface for the two pieces
// of governance state the login path already ENFORCES but nothing could
// author: a claimed tenant's LoginPolicy (allowed methods / SSO-required /
// require-2FA) and a project's config_json blob. Both are secret-gated
// platform-operator operations, like the rest of ControlPlaneAdminService,
// and emit an audit event on every mutation so a policy change is visible in
// the trail. They are postgres-only: a build with no governance plane wires a
// nil policies store, which makes the LoginPolicy methods return
// ErrUnimplemented (mirroring the nil-projects → Unimplemented behaviour).

// normalizeAllowedMethods validates the comma-separated AllowedMethods list,
// rejecting any unknown token and returning the canonical (trimmed,
// deduplicated, lower-cased) list. An empty list is valid and means "no
// restriction" — the login path then falls back to its safe default rather
// than locking the tenant out.
func normalizeAllowedMethods(allowed string) (string, error) {
	if strings.TrimSpace(allowed) == "" {
		return "", nil
	}
	known := map[string]struct{}{
		LoginMethodEmailOTP: {},
		LoginMethodPassword: {},
		LoginMethodOAuth:    {},
		LoginMethodPasskey:  {},
		LoginMethodSSO:      {},
	}
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, raw := range strings.Split(allowed, ",") {
		tok := strings.ToLower(strings.TrimSpace(raw))
		if tok == "" {
			continue
		}
		if _, ok := known[tok]; !ok {
			return "", fmt.Errorf("%w: unknown login method %q", ErrInvalidArgument, tok)
		}
		if _, dup := seen[tok]; dup {
			continue
		}
		seen[tok] = struct{}{}
		out = append(out, tok)
	}
	return strings.Join(out, ","), nil
}

// UpsertLoginPolicy authors (inserts or replaces) the LoginPolicy the login
// path enforces for a claimed tenant within a project. project_id and
// tenant_id are required; AllowedMethods is validated against the known
// method tokens. The mutation emits an audit event. When this build has no
// governance plane (nil policies store) it returns ErrUnimplemented.
func (s *ControlPlaneAdminService) UpsertLoginPolicy(ctx context.Context, secret string, p *LoginPolicy) (*LoginPolicy, error) {
	if err := s.authorize(secret); err != nil {
		return nil, err
	}
	if s.policies == nil {
		return nil, ErrUnimplemented
	}
	if p == nil {
		return nil, fmt.Errorf("%w: missing policy", ErrInvalidArgument)
	}
	projectID := strings.TrimSpace(p.ProjectID)
	tenantID := strings.TrimSpace(p.TenantID)
	if projectID == "" {
		return nil, fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	if tenantID == "" {
		return nil, fmt.Errorf("%w: missing tenant_id", ErrInvalidArgument)
	}
	allowed, err := normalizeAllowedMethods(p.AllowedMethods)
	if err != nil {
		return nil, err
	}
	if p.PasswordMinLength < 0 || p.SessionIdleTimeoutSeconds < 0 || p.SessionAbsoluteTimeoutSeconds < 0 {
		return nil, fmt.Errorf("%w: password/session governance values must be non-negative", ErrInvalidArgument)
	}
	// A minimum above bcrypt's max byte length would make every password both
	// too short (vs the floor) and too long (vs the bcrypt cap) at once,
	// locking the tenant out of all password signups/resets. Reject it so the
	// operator learns immediately rather than silently breaking the tenant.
	if p.PasswordMinLength > passwords.MaxPasswordLength {
		return nil, fmt.Errorf("%w: password_min_length must not exceed %d (bcrypt's maximum)", ErrInvalidArgument, passwords.MaxPasswordLength)
	}
	// Bound the timeouts so the seconds→ms (*1000) conversion in the
	// enforcement path can never overflow int64 and wrap negative.
	if p.SessionIdleTimeoutSeconds > maxSessionTimeoutSeconds || p.SessionAbsoluteTimeoutSeconds > maxSessionTimeoutSeconds {
		return nil, fmt.Errorf("%w: session timeout seconds must not exceed %d", ErrInvalidArgument, maxSessionTimeoutSeconds)
	}
	policy := &LoginPolicy{
		ProjectID:                     projectID,
		TenantID:                      tenantID,
		AllowedMethods:                allowed,
		SSORequired:                   p.SSORequired,
		SSOConnectionJSON:             strings.TrimSpace(p.SSOConnectionJSON),
		Require2FA:                    p.Require2FA,
		PasswordMinLength:             p.PasswordMinLength,
		SessionIdleTimeoutSeconds:     p.SessionIdleTimeoutSeconds,
		SessionAbsoluteTimeoutSeconds: p.SessionAbsoluteTimeoutSeconds,
	}
	if _, err := s.policies.UpsertLoginPolicy(ctx, policy); err != nil {
		return nil, err
	}
	s.audit.Log(ctx, audit.EventLoginPolicyUpserted, audit.WithSuccess(true), audit.WithDetails(map[string]any{
		"project_id":                 projectID,
		"tenant_id":                  tenantID,
		"allowed_methods":            allowed,
		"sso_required":               policy.SSORequired,
		"require_2fa":                policy.Require2FA,
		"password_min_length":        policy.PasswordMinLength,
		"session_idle_timeout_s":     policy.SessionIdleTimeoutSeconds,
		"session_absolute_timeout_s": policy.SessionAbsoluteTimeoutSeconds,
	}))
	return policy, nil
}

// GetLoginPolicy returns the LoginPolicy for (projectID, tenantID), or
// (nil, nil) when none is set. project_id and tenant_id are required.
func (s *ControlPlaneAdminService) GetLoginPolicy(ctx context.Context, secret, projectID, tenantID string) (*LoginPolicy, error) {
	if err := s.authorize(secret); err != nil {
		return nil, err
	}
	if s.policies == nil {
		return nil, ErrUnimplemented
	}
	projectID = strings.TrimSpace(projectID)
	tenantID = strings.TrimSpace(tenantID)
	if projectID == "" {
		return nil, fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	if tenantID == "" {
		return nil, fmt.Errorf("%w: missing tenant_id", ErrInvalidArgument)
	}
	return s.policies.GetLoginPolicy(ctx, projectID, tenantID)
}

// DeleteLoginPolicy clears a claimed tenant's LoginPolicy, reverting the login
// path to its safe default for that tenant. It is idempotent (deleting an
// absent policy is a no-op) and emits an audit event.
func (s *ControlPlaneAdminService) DeleteLoginPolicy(ctx context.Context, secret, projectID, tenantID string) error {
	if err := s.authorize(secret); err != nil {
		return err
	}
	if s.policies == nil {
		return ErrUnimplemented
	}
	projectID = strings.TrimSpace(projectID)
	tenantID = strings.TrimSpace(tenantID)
	if projectID == "" {
		return fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	if tenantID == "" {
		return fmt.Errorf("%w: missing tenant_id", ErrInvalidArgument)
	}
	if err := s.policies.DeleteLoginPolicy(ctx, projectID, tenantID); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.EventLoginPolicyDeleted, audit.WithSuccess(true), audit.WithDetails(map[string]any{
		"project_id": projectID,
		"tenant_id":  tenantID,
	}))
	return nil
}

// UpsertProjectConfig REPLACES a project's config_json blob and returns the
// stored (normalised) value. The blob must be a valid JSON object — it is
// validated by decoding it through ParseProjectConfig so a malformed config is
// rejected (ErrInvalidArgument) before it is persisted, never silently stored.
// The mutation emits an audit event. project_id is required; an unknown
// project surfaces ErrNotFound from the store.
func (s *ControlPlaneAdminService) UpsertProjectConfig(ctx context.Context, secret, projectID, configJSON string) (string, error) {
	if err := s.authorize(secret); err != nil {
		return "", err
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return "", fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	// Validate the blob decodes to the typed config before persisting it, so a
	// malformed config is a caller error rather than a write the login/resolver
	// path later trips over.
	if _, err := ParseProjectConfig(configJSON); err != nil {
		return "", fmt.Errorf("%w: %s", ErrInvalidArgument, err.Error())
	}
	// A whole-blob replace still routes through the optimistic-concurrency helper
	// so it is serialized against concurrent config mutators (e.g. an in-flight
	// OAuth-provider write) rather than blindly clobbering under a lost update.
	stored, err := s.mutateProjectConfig(ctx, projectID, func(string) (string, error) {
		return configJSON, nil
	})
	if err != nil {
		return "", err
	}
	s.audit.Log(ctx, audit.EventProjectConfigUpdated, audit.WithSuccess(true), audit.WithDetails(map[string]any{
		"project_id": projectID,
	}))
	return stored, nil
}

// GetProjectConfig returns a project's stored config_json ("{}" when unset).
// project_id is required; an unknown project surfaces ErrNotFound.
func (s *ControlPlaneAdminService) GetProjectConfig(ctx context.Context, secret, projectID string) (string, error) {
	if err := s.authorize(secret); err != nil {
		return "", err
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return "", fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	stored, _, err := s.projects.GetProjectConfig(ctx, projectID)
	return stored, err
}
