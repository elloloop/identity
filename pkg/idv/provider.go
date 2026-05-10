// Package idv defines the pluggable identity-verification provider
// interface. Implementations live in sibling files (azure.go, stub.go)
// or in downstream forks — the package is intentionally narrow so a
// deployment can swap providers via config without touching the
// service layer.
//
// The service layer owns the public verification_id; providers track
// their own ProviderSessionID and never see the caller's user id
// unless an implementation chooses to forward it.
package idv

import (
	"context"
	"time"
)

// Status enumerates the lifecycle of a verification session. The
// string values are mirrored in the proto enum
// `IdentityVerificationStatus`; keep them in sync.
const (
	StatusPending  = "pending"
	StatusInReview = "in_review"
	StatusApproved = "approved"
	StatusRejected = "rejected"
	StatusExpired  = "expired"
)

// Request is the input to BeginVerification. All fields except UserID
// are optional; providers that need them (e.g. Onfido's applicant
// API) read what is present and ignore the rest.
type Request struct {
	UserID      string // local user id, used as the provider-side actor
	TenantID    string // local tenant id, for providers that scope by it
	Email       string // optional, for applicant creation
	DisplayName string // optional, for applicant creation
	RedirectURL string // optional, for hosted-flow providers
}

// Session is what a provider returns from BeginVerification. The
// caller persists ProviderSessionID alongside the locally-issued
// verification_id and returns SessionToken + ExpiresAt to the client
// so the SDK can drive document capture and liveness.
type Session struct {
	ProviderSessionID string    // provider's identifier for the check
	SessionToken      string    // opaque token the client SDK exchanges
	ExpiresAt         time.Time // when SessionToken stops accepting captures
}

// Status is the current state of a verification as reported by the
// provider. The CompletedAt zero value means the provider has not
// reached a terminal verdict yet.
type StatusResult struct {
	Status          string    // one of Status* constants
	RejectionReason string    // empty unless Status == StatusRejected
	CompletedAt     time.Time // zero if Status is pending/in_review
}

// Provider is the pluggable identity-verification backend. The
// service layer holds exactly one Provider for the lifetime of the
// process; multi-provider deployments use a Provider that dispatches
// on tenant configuration internally.
type Provider interface {
	// Name returns the provider identifier (e.g., "azure", "stub").
	// It is persisted in IdentityVerificationRecord.Provider so an
	// audit reader can tell which backend issued a session.
	Name() string

	// BeginVerification creates a new verification session.
	BeginVerification(ctx context.Context, req Request) (*Session, error)

	// GetVerification returns the current state of an existing
	// session. Sync providers (Azure Face API) query the upstream
	// service; async providers (Onfido webhooks) return their last
	// known state, which the caller's webhook handler keeps fresh.
	GetVerification(ctx context.Context, providerSessionID string) (*StatusResult, error)
}
