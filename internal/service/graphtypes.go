package service

import (
	"context"

	"github.com/elloloop/identity/internal/graph"
)

// ── Graph node type IDs ─────────────────────────────

const (
	typeUser            = 1
	typeWorkingGroup    = 2
	typeRefreshToken    = 5
	typePasswordReset   = 19
	typePasskeyCredCred = 20
	typeAuditEvent      = 26
	typeUserInvitation  = 27
	typeAdminHelpReq    = 28
	typeOAuthIdentity   = 30
)

// ── Graph edge type IDs ─────────────────────────────
// Edge type ids are never reused: even if an edge type is retired, its id
// stays reserved so historical edges can never be misread as a new type.

const (
	edgeMemberOf   = 101
	edgeGuardianOf = 102
)

// ── User field IDs (type_id 1) ─────────────────────────────────────

const (
	ufEmail         = "1"
	ufName          = "2"
	ufRole          = "3"
	ufAvatarURL     = "4"
	ufCreatedAt     = "5"
	ufUpdatedAt     = "6"
	ufPasswordHash  = "7"
	ufTOTPRequired  = "8"
	ufStatus        = "11"
	ufRecoveryEmail = "12"
	ufInvitedBy     = "13"
	ufInvitedAt     = "14"
	ufQuotaBytes    = "15"
	ufDeactivatedAt = "16"
	ufLastLoginAt   = "17"
	// ufIsAnonymous carries the credential-less flag through the graph
	// layer. Without it userFromNode leaves User.IsAnonymous at its zero
	// value, so the admin surfaces would report every account as permanent.
	ufIsAnonymous = "20"
)

// ── WorkingGroup field IDs (type_id 2) ─────────────────────────────

const (
	gfName        = "1"
	gfDescription = "2"
	gfCreatedBy   = "3"
	gfCreatedAt   = "4"
	gfUpdatedAt   = "5"
)

// ── RefreshToken field IDs (type_id 5) ─────────────────────────────

const (
	rfTokenHash  = "1"
	rfUserID     = "2"
	rfDeviceInfo = "3"
	rfExpiresAt  = "4"
	rfCreatedAt  = "5"
	rfDeviceName = "6"
	rfIPAddress  = "7"
	rfUserAgent  = "8"
	rfLastUsedAt = "9"
	rfConsumedAt = "10"
)

// ── PasswordResetToken field IDs (type_id 19) ──────────────────────

const (
	prfTokenHash = "1"
	prfUserID    = "2"
	prfExpiresAt = "3"
	prfCreatedAt = "4"
)

// ── PasskeyCredential field IDs (type_id 20) ───────────────────────

const (
	pkfCredentialID = "1"
	pkfUserID       = "2"
	pkfDeviceName   = "5"
	pkfCreatedAt    = "8"
	pkfLastUsedAt   = "9"
)

// ── UserInvitation field IDs (type_id 27) ──────────────────────────

const (
	invTokenHash  = "1"
	invEmail      = "2"
	invUserID     = "3"
	invInvitedBy  = "4"
	invRole       = "5"
	invExpiresAt  = "6"
	invAcceptedAt = "7"
	invCreatedAt  = "8"
)

// ── AdminHelpRequest field IDs (type_id 28) ────────────────────────

const (
	hfEmail           = "1"
	hfReason          = "2"
	hfSourceIP        = "3"
	hfUserAgent       = "4"
	hfStatus          = "5"
	hfResolvedBy      = "6"
	hfResolutionNotes = "7"
	hfResolvedAt      = "8"
	hfCreatedAt       = "9"
)

// ── AuditEvent field IDs (type_id 26) ──────────────────────────────

const (
	afEventType    = "1"
	afActorUserID  = "2"
	afTargetUserID = "3"
	afIPAddress    = "4"
	afUserAgent    = "5"
	afSuccess      = "6"
	afDetails      = "7"
	afCreatedAt    = "8"
)

// ── Additional domain types not in auth.go ─────────────────────────

// Session represents an active refresh-token-backed session.
type Session struct {
	ID         string
	DeviceName string
	IPAddress  string
	UserAgent  string
	CreatedAt  int64
	LastUsedAt int64
	ExpiresAt  int64
	Current    bool
}

// Group is the domain representation of a working group (type_id 2).
type Group struct {
	ID          string
	Name        string
	Description string
	CreatedAt   int64
	UpdatedAt   int64
}

// HelpRequest is the domain representation of an admin help request
// (type_id 28).
type HelpRequest struct {
	ID              string
	Email           string
	Reason          string
	SourceIP        string
	UserAgent       string
	Status          string
	ResolvedBy      string
	ResolutionNotes string
	ResolvedAt      int64
	CreatedAt       int64
}

// AuditEvent is the domain representation of an audit event
// (type_id 26).
type AuditEvent struct {
	ID           string
	EventType    string
	ActorUserID  string
	TargetUserID string
	IPAddress    string
	UserAgent    string
	Success      bool
	Details      map[string]any
	CreatedAt    int64
}

// InviteResult is returned by AdminService.InviteUser.
type InviteResult struct {
	User              *User
	InvitationToken   string
	SetupURL          string
	TemporaryPassword string
}

// ResetPasswordResult is returned by AdminService.ResetUserPassword.
type ResetPasswordResult struct {
	TemporaryPassword string
	ResetToken        string
}

// ── DB interface ───────────────────────────────────────────────────
// Services accept this narrow interface rather than the full
// *graph.DbClient so they are testable with an in-memory fake.

// DB is the subset of the graph DB used by identity services.
type DB interface {
	GetNode(ctx context.Context, tenantID, actor string, typeID int, nodeID string) (*graph.Node, error)
	QueryNodes(ctx context.Context, tenantID, actor string, typeID int, filter map[string]any) ([]*graph.Node, error)
	ExecuteAtomic(ctx context.Context, tenantID, actor string, ops []graph.Operation) (*graph.CommitResult, error)
	GetEdgesFrom(ctx context.Context, tenantID, actor, fromNodeID string, edgeTypeID int) ([]*graph.Edge, error)
	GetEdgesTo(ctx context.Context, tenantID, actor, toNodeID string, edgeTypeID int) ([]*graph.Edge, error)
	SearchNodes(ctx context.Context, tenantID, actor string, typeID int, query string) ([]*graph.Node, error)
	// RegisterUserInTenant registers userID in the global user
	// registry and adds them as a member of tenantID with the given
	// role. Idempotent: tolerates ALREADY_EXISTS on both calls. The
	// service-layer admin path (admin.InviteUser) uses this to bring
	// new users onto v1.12+'s "actor must be a tenant member"
	// contract; the typed entRepository.CreateUser path uses the
	// equivalent SDK calls directly via its entClient seam.
	RegisterUserInTenant(ctx context.Context, tenantID, userID, email, name, role string) error
}
