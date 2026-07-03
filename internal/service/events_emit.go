package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/events"
)

// eventEmitter is the small surface the service layer needs to emit
// user-lifecycle events. AuthService and AdminService each hold one
// (nil ⇒ the no-op events.Discard, so existing behaviour is unchanged).
//
// Emitting is best-effort: a failed Emit is logged and never fails the
// surrounding RPC. The originating mutation has already been committed; the
// outbox-backed publisher's own retries handle delivery durability, and a
// no-op publisher never errors.

// newEventID returns a unique, opaque id used for at-least-once delivery
// idempotency. It is independent of the user id so the same user mutated
// twice produces two distinct events.
func newEventID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is unrecoverable; mirror the package's
		// existing fail-fast posture (see auth.go).
		panic("service: crypto/rand failed generating event id: " + err.Error())
	}
	return "evt_" + hex.EncodeToString(b[:])
}

// toEventUser maps a service User to the secret-free events.User payload.
func toEventUser(u *User) events.User {
	if u == nil {
		return events.User{}
	}
	return events.User{
		ID:            u.ID,
		Email:         u.Email,
		Name:          u.Name,
		Status:        u.Status,
		EmailVerified: u.EmailVerified,
	}
}

// EmitUserEvent publishes a single user-lifecycle event through pub. A nil
// pub is treated as the no-op publisher. Failures are logged, never
// returned: the caller's mutation is already durable.
//
// It is exported so the inbound SCIM server (internal/app) emits the SAME
// lifecycle events as the admin/gRPC paths through the one construction site,
// rather than reimplementing the event shape.
func EmitUserEvent(
	ctx context.Context,
	pub events.Publisher,
	logger *zap.Logger,
	projectID, tenantID string,
	t events.EventType,
	u *User,
) {
	if pub == nil {
		return
	}
	e := events.Event{
		ID:        newEventID(),
		Type:      t,
		ProjectID: projectID,
		TenantID:  tenantID,
		User:      toEventUser(u),
	}
	if err := pub.Emit(ctx, e); err != nil && logger != nil {
		logger.Warn(
			"user_lifecycle_event_emit_failed",
			zap.String("event_type", string(t)),
			zap.String("user_id", e.User.ID),
			zap.Error(err),
		)
	}
}
