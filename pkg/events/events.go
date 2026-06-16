// Package events is the pluggable user-lifecycle eventing primitive.
//
// The service layer emits a typed Event whenever a user is created,
// updated, or deactivated. By default the publisher is a no-op (Discard),
// so emitting an event has no observable effect and existing deployments
// behave exactly as before. When outbound delivery is configured
// (GATEWAY_WEBHOOKS_ENABLED), the composition root swaps in an
// outbox-backed Publisher whose background worker delivers a signed
// webhook to every matching subscription at-least-once, with retry and
// exponential backoff, recording each attempt in a transactional outbox
// so delivery is idempotent by event id.
//
// The package is intentionally narrow and self-contained — it depends on
// neither internal/service nor internal/repo — so it can be reused by the
// outbound-SCIM connector (which subscribes to the same events) and unit
// tested without a datastore. Persistence is abstracted behind OutboxStore
// so the in-memory store backs tests and a SQL-backed store can be wired
// without touching the delivery engine.
package events

import (
	"context"
	"time"
)

// EventType enumerates the user-lifecycle events the service emits. The
// string values are stable wire identifiers: they appear in the webhook
// payload's "type" field and are matched against a subscription's event
// filter, so they must never be renumbered or repurposed (append only).
type EventType string

const (
	// EventUserCreated is emitted after a new user account is persisted.
	EventUserCreated EventType = "user.created"
	// EventUserUpdated is emitted after a user's mutable profile fields
	// (name, email, status transitions other than deactivation) change.
	EventUserUpdated EventType = "user.updated"
	// EventUserDeactivated is emitted after a user is deactivated (status
	// set to a non-active value, or the account deleted). This is the
	// deprovisioning signal outbound SCIM connectors act on.
	EventUserDeactivated EventType = "user.deactivated"
)

// Valid reports whether t is one of the known event types. Unknown types
// are rejected at the Emit boundary so a typo cannot silently produce an
// undeliverable outbox row.
func (t EventType) Valid() bool {
	switch t {
	case EventUserCreated, EventUserUpdated, EventUserDeactivated:
		return true
	default:
		return false
	}
}

// User is the subset of a user record carried in a lifecycle event. It is
// deliberately small and free of secrets (no password hash, no tokens):
// downstream SaaS provisioning needs identity and status, nothing more.
type User struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name,omitempty"`
	Status        string `json:"status,omitempty"`
	EmailVerified bool   `json:"email_verified"`
}

// Event is the typed payload emitted by the service layer and delivered to
// subscribers. ID is a unique, caller-supplied identifier used for
// at-least-once idempotency: a subscriber that has already processed an ID
// can safely ignore a redelivery, and the delivery engine never enqueues
// the same (event, subscription) pair twice.
type Event struct {
	ID         string    `json:"id"`
	Type       EventType `json:"type"`
	ProjectID  string    `json:"project_id"`
	TenantID   string    `json:"tenant_id,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
	User       User      `json:"user"`
}

// Publisher is the pluggable eventing sink the service layer holds. The
// service calls Emit on every user-mutation path; the implementation
// decides what (if anything) happens. The default (Discard) does nothing.
//
// Emit must be safe for concurrent use and must not block on network I/O:
// the outbox-backed implementation only writes a durable row and lets a
// background worker handle delivery, so a slow or unreachable subscriber
// never adds latency to (or fails) the originating RPC.
type Publisher interface {
	// Emit records an event for delivery. It returns an error only when
	// the event itself is invalid or the durable write fails; a delivery
	// failure to a downstream subscriber is never surfaced here (it is
	// retried by the worker). A no-op publisher always returns nil.
	Emit(ctx context.Context, e Event) error
}

// Discard is the no-op Publisher used when outbound eventing is disabled.
// It validates nothing and stores nothing, so emitting is free.
type Discard struct{}

// Emit implements Publisher and does nothing.
func (Discard) Emit(context.Context, Event) error { return nil }

// compile-time assertion that Discard satisfies Publisher.
var _ Publisher = Discard{}
