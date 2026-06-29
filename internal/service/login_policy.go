package service

import "context"

// LoginPolicy controls HOW the members of a claimed Tenant authenticate —
// never WHETHER. It is consulted on the login path for a user whose email
// domain belongs to a claimed tenant; an absent or empty policy fails safe
// to email-OTP so a misconfiguration never locks anyone out.
//
// Like Tenant/Domain it is per-project governance state, postgres-backed,
// and addressed by (projectID, tenantID) — at most one policy per tenant.

// Login method tokens used in LoginPolicy.AllowedMethods (a comma-separated
// list). Empty AllowedMethods means "no restriction" — the caller falls
// back to its safe default rather than locking the tenant out.
const (
	LoginMethodEmailOTP = "email_otp"
	LoginMethodPassword = "password"
	LoginMethodOAuth    = "oauth"
	LoginMethodPasskey  = "passkey"
	LoginMethodSSO      = "sso"
)

// LoginPolicy is a claimed tenant's authentication policy.
type LoginPolicy struct {
	ID        string
	ProjectID string
	TenantID  string
	// AllowedMethods is a comma-separated allow-list of login method
	// tokens (see LoginMethod*). Empty means no restriction.
	AllowedMethods string
	// SSORequired forces SSO; SSOConnectionJSON carries the connection
	// config (IdP metadata) as a JSON object.
	SSORequired       bool
	SSOConnectionJSON string
	// Require2FA forces a second factor after the primary method.
	Require2FA bool
	// PasswordMinLength is the tenant's minimum password length. 0 means
	// "use the global passwords.MinPasswordLength"; a tenant can only ever
	// raise the floor, never lower it.
	PasswordMinLength int
	// PasswordRequireClasses records that the tenant demands all four
	// character classes (upper/lower/digit/special). The global class
	// rules are always enforced; this only tightens.
	PasswordRequireClasses bool
	// SessionIdleTimeoutSeconds invalidates a session not used within this
	// many seconds (compared against the refresh token's LastUsedAt). 0
	// means "no idle timeout — global behavior".
	SessionIdleTimeoutSeconds int64
	// SessionAbsoluteTimeoutSeconds invalidates a session older than this
	// many seconds regardless of activity (compared against the refresh
	// token's CreatedAt). 0 means "no absolute timeout".
	SessionAbsoluteTimeoutSeconds int64
	CreatedAtMs                   int64
	UpdatedAtMs                   int64
}

// LoginPolicyStore persists at most one LoginPolicy per (project, tenant).
type LoginPolicyStore interface {
	// UpsertLoginPolicy inserts or replaces the policy for
	// (ProjectID, TenantID). Both are required. Returns the row id.
	UpsertLoginPolicy(ctx context.Context, p *LoginPolicy) (string, error)
	// GetLoginPolicy returns the policy for (projectID, tenantID), or
	// (nil, nil) when none is set.
	GetLoginPolicy(ctx context.Context, projectID, tenantID string) (*LoginPolicy, error)
	// DeleteLoginPolicy removes the policy for (projectID, tenantID). It is
	// idempotent: deleting an absent policy is a no-op that returns nil, so a
	// caller can clear a tenant's policy without first checking for one. Both
	// ids are required.
	DeleteLoginPolicy(ctx context.Context, projectID, tenantID string) error
}
