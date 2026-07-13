package service

import (
	"context"
	"fmt"
	"strings"
)

// ExportFormatVersion is the schema version stamped on a DataExport so a later
// importer can evolve the shape unambiguously. Bump it on any breaking change
// to the export's structure.
const ExportFormatVersion = 1

// DefaultExportMaxAuditEvents is the fallback cap on how many of the caller's
// own audit events a data export includes when the wired value is
// non-positive. It guarantees an export can never trigger an unbounded scan.
const DefaultExportMaxAuditEvents = 1000

// DataExport is the aggregated, self-describing copy of the personal data the
// identity service holds about ONE caller (GDPR Art 15 access + Art 20
// portability). It carries NO secret material — no password hash, TOTP secret,
// recovery codes, or raw/hashed tokens — only the account, auth, and security
// metadata the user is entitled to receive about themselves.
type DataExport struct {
	FormatVersion int
	ExportedAtMs  int64

	User             *User
	Sessions         []*Session
	Passkeys         []*PasskeyInfo
	LinkedIdentities []*OAuthIdentity
	TotpEnabled      bool
	AuditEvents      []*AuditEvent
}

// WithExportMaxAuditEvents wires the cap on the number of the caller's own
// audit events a data export includes and returns the service for chaining. A
// non-positive value keeps the safe default (DefaultExportMaxAuditEvents).
func (s *ProfileService) WithExportMaxAuditEvents(max int) *ProfileService {
	s.exportMaxAuditEvents = max
	return s
}

// exportAuditLimit returns the effective audit-event cap, clamping a
// non-positive configured value to the safe default.
func (s *ProfileService) exportAuditLimit() int {
	if s.exportMaxAuditEvents < 1 {
		return DefaultExportMaxAuditEvents
	}
	return s.exportMaxAuditEvents
}

// ExportMyData aggregates the caller's own data into a single structured
// export: their profile, active sessions, passkey metadata, linked provider
// identities, TOTP-enabled flag, and the audit events where they are the actor
// or the target. Every source is scoped to the caller — a second user's data
// is never included — and no secret material is read into the result.
func (s *ProfileService) ExportMyData(ctx context.Context, userID string) (*DataExport, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("%w: user_id is required", ErrInvalidArgument)
	}
	repo := s.repo(ctx)
	if repo == nil {
		return nil, ErrServiceUnavailable
	}

	user, err := repo.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("export: fetch user: %w", err)
	}
	if user == nil {
		return nil, ErrNotFound
	}

	sessions, err := s.ListMySessions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("export: list sessions: %w", err)
	}

	passkeys, err := s.ListMyPasskeys(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("export: list passkeys: %w", err)
	}

	linked, err := s.ListLinkedIdentities(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("export: list linked identities: %w", err)
	}

	totpEnabled, err := s.totpEnabled(ctx, repo, userID)
	if err != nil {
		return nil, fmt.Errorf("export: totp status: %w", err)
	}

	auditEvents, err := repo.ListAuditEventsForUser(ctx, userID, s.exportAuditLimit())
	if err != nil {
		return nil, fmt.Errorf("export: list audit events: %w", err)
	}

	// Belt-and-braces: the User domain type carries a PasswordHash field, so
	// clear it before it leaves the boundary. userToProto never maps it, but a
	// future proto field or JSON marshal must not leak it from the export.
	user.PasswordHash = ""

	return &DataExport{
		FormatVersion:    ExportFormatVersion,
		ExportedAtMs:     nowMs(),
		User:             user,
		Sessions:         sessions,
		Passkeys:         passkeys,
		LinkedIdentities: linked,
		TotpEnabled:      totpEnabled,
		AuditEvents:      auditEvents,
	}, nil
}

// totpEnabled reports whether the user has an enrolled, verified TOTP
// credential. It reads only the verified flag — the encrypted secret is never
// touched — so the export exposes TOTP status without the secret itself.
func (s *ProfileService) totpEnabled(ctx context.Context, repo Repository, userID string) (bool, error) {
	cred, err := repo.GetTotpCredential(ctx, userID)
	if err != nil {
		return false, err
	}
	return cred != nil && cred.Verified, nil
}
