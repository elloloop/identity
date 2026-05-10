package connect

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity"
)

// errIDVNotWired is returned until the service-layer IDV wiring lands.
var errIDVNotWired = errors.New("identity verification is not wired in this build")

// ─── Identity Verification RPCs ─────────────────────────────────────────────
//
// These RPCs are scaffolded with the proto contract and storage layer in
// place; the service-layer wiring lands in a follow-up that introduces
// pkg/idv (provider abstraction, stub, Azure impl). Callers receive
// CodeUnimplemented until then.

// BeginIdentityVerification starts a verification session for the caller.
func (h *IdentityHandler) BeginIdentityVerification(
	_ context.Context,
	_ *connect.Request[identitypb.BeginIdentityVerificationRequest],
) (*connect.Response[identitypb.BeginIdentityVerificationResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errIDVNotWired)
}

// GetIdentityVerificationStatus returns the current status of a verification.
func (h *IdentityHandler) GetIdentityVerificationStatus(
	_ context.Context,
	_ *connect.Request[identitypb.GetIdentityVerificationStatusRequest],
) (*connect.Response[identitypb.GetIdentityVerificationStatusResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errIDVNotWired)
}
