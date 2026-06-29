package events

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// DeliveryStatus is the lifecycle of one outbox row — one (event,
// subscription) delivery attempt-set.
type DeliveryStatus string

const (
	// StatusPending means the delivery is awaiting its first attempt or a
	// retry whose NextAttemptAt has not yet arrived.
	StatusPending DeliveryStatus = "pending"
	// StatusDelivered means the subscriber acknowledged the webhook (2xx).
	StatusDelivered DeliveryStatus = "delivered"
	// StatusFailed means the delivery exhausted its retry budget and was
	// abandoned. Failures are surfaced to the operator (audit/log), never
	// silently dropped.
	StatusFailed DeliveryStatus = "failed"
)

// ErrDeliveryExists is returned by EnqueueDelivery when an outbox row for
// the same (EventID, SubscriptionID) pair already exists. It makes
// enqueueing idempotent by event id: re-emitting an event that was already
// fanned out to a subscription is a no-op rather than a duplicate.
var ErrDeliveryExists = errors.New("events: delivery already enqueued for this event/subscription")

// Subscription is a per-tenant webhook endpoint. The delivery engine fans
// an event out to every active subscription in the event's project whose
// EventTypes filter matches (an empty filter matches all types). Secret is
// the HMAC key used to sign the payload so the subscriber can verify the
// webhook originated from this server.
type Subscription struct {
	ID         string
	ProjectID  string
	TenantID   string
	URL        string
	Secret     string
	EventTypes []EventType // empty ⇒ all types
	Active     bool
}

// matches reports whether this subscription should receive e.
func (s Subscription) matches(e Event) bool {
	if !s.Active || s.ProjectID != e.ProjectID {
		return false
	}
	if s.TenantID != "" && e.TenantID != "" && s.TenantID != e.TenantID {
		return false
	}
	if len(s.EventTypes) == 0 {
		return true
	}
	for _, t := range s.EventTypes {
		if t == e.Type {
			return true
		}
	}
	return false
}

// Delivery is one durable outbox row: a single event bound to a single
// subscription, with its attempt bookkeeping. The payload is the exact
// signed bytes so a retry re-sends an identical body (and identical
// signature), which is what makes delivery idempotent by event id on the
// receiving end.
type Delivery struct {
	ID             string
	EventID        string
	SubscriptionID string
	URL            string
	Secret         string
	Payload        []byte
	Status         DeliveryStatus
	Attempts       int
	LastError      string
	NextAttemptAt  time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// OutboxStore is the persistence boundary for the delivery engine. An
// in-memory implementation (MemoryOutbox) backs tests and single-node
// runs; a SQL-backed store (postgres/sqlite) implements the same contract
// for durable, multi-replica delivery. All methods must be safe for
// concurrent use.
type OutboxStore interface {
	// EnqueueDelivery durably stores a pending delivery. It returns
	// ErrDeliveryExists when a row for the same (EventID, SubscriptionID)
	// already exists, so the caller's fan-out is idempotent.
	EnqueueDelivery(ctx context.Context, d *Delivery) error

	// ClaimDue returns up to limit pending deliveries whose NextAttemptAt
	// is at or before now, marking each claimed so a concurrent worker
	// does not pick the same row. The engine processes the returned batch
	// and reports the outcome via MarkDelivered / Reschedule / MarkFailed.
	ClaimDue(ctx context.Context, now time.Time, limit int) ([]*Delivery, error)

	// MarkDelivered records a successful delivery (2xx ack).
	MarkDelivered(ctx context.Context, id string, at time.Time) error

	// Reschedule records a failed attempt and sets the next retry time.
	Reschedule(ctx context.Context, id string, attempts int, lastErr string, nextAttemptAt time.Time) error

	// MarkFailed records a delivery that exhausted its retry budget.
	MarkFailed(ctx context.Context, id string, attempts int, lastErr string) error

	// ListActiveSubscriptions returns every active subscription in the
	// given project so the engine can fan an event out.
	ListActiveSubscriptions(ctx context.Context, projectID string) ([]Subscription, error)
}

// MemoryOutbox is an in-process OutboxStore. It is the differential
// reference the SQL stores are held to and backs unit tests + single-node
// deployments.
type MemoryOutbox struct {
	mu sync.Mutex
	// deliveries keyed by delivery ID.
	deliveries map[string]*Delivery
	// dedupe keyed by eventID + "\x00" + subscriptionID.
	dedupe map[string]string
	// claimed tracks delivery IDs currently in-flight in a worker so
	// ClaimDue does not hand the same row to two workers.
	claimed map[string]bool
	subs    map[string]Subscription
}

// NewMemoryOutbox returns an empty in-memory outbox.
func NewMemoryOutbox() *MemoryOutbox {
	return &MemoryOutbox{
		deliveries: make(map[string]*Delivery),
		dedupe:     make(map[string]string),
		claimed:    make(map[string]bool),
		subs:       make(map[string]Subscription),
	}
}

// AddSubscription registers a subscription. Provided as a test/wiring seam
// since this slice does not yet expose subscription-management RPCs.
func (m *MemoryOutbox) AddSubscription(s Subscription) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subs[s.ID] = s
}

func dedupeKey(eventID, subID string) string { return eventID + "\x00" + subID }

// EnqueueDelivery implements OutboxStore.
func (m *MemoryOutbox) EnqueueDelivery(_ context.Context, d *Delivery) error {
	if d == nil {
		return errors.New("events: EnqueueDelivery: nil delivery")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := dedupeKey(d.EventID, d.SubscriptionID)
	if _, ok := m.dedupe[key]; ok {
		return ErrDeliveryExists
	}
	cp := *d
	cp.Payload = append([]byte(nil), d.Payload...)
	m.deliveries[cp.ID] = &cp
	m.dedupe[key] = cp.ID
	return nil
}

// ClaimDue implements OutboxStore.
func (m *MemoryOutbox) ClaimDue(_ context.Context, now time.Time, limit int) ([]*Delivery, error) {
	if limit <= 0 {
		return nil, errors.New("events: ClaimDue: limit must be > 0")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	due := make([]*Delivery, 0, limit)
	for id, d := range m.deliveries {
		if d.Status != StatusPending || m.claimed[id] {
			continue
		}
		if d.NextAttemptAt.After(now) {
			continue
		}
		due = append(due, d)
	}
	// Deterministic order (oldest NextAttemptAt first) so behaviour is
	// stable and testable.
	sort.Slice(due, func(i, j int) bool {
		if due[i].NextAttemptAt.Equal(due[j].NextAttemptAt) {
			return due[i].ID < due[j].ID
		}
		return due[i].NextAttemptAt.Before(due[j].NextAttemptAt)
	})
	if len(due) > limit {
		due = due[:limit]
	}
	out := make([]*Delivery, 0, len(due))
	for _, d := range due {
		m.claimed[d.ID] = true
		cp := *d
		cp.Payload = append([]byte(nil), d.Payload...)
		out = append(out, &cp)
	}
	return out, nil
}

// MarkDelivered implements OutboxStore.
func (m *MemoryOutbox) MarkDelivered(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.deliveries[id]
	if !ok {
		return errors.New("events: MarkDelivered: unknown delivery")
	}
	d.Status = StatusDelivered
	d.UpdatedAt = at
	delete(m.claimed, id)
	return nil
}

// Reschedule implements OutboxStore.
func (m *MemoryOutbox) Reschedule(_ context.Context, id string, attempts int, lastErr string, nextAttemptAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.deliveries[id]
	if !ok {
		return errors.New("events: Reschedule: unknown delivery")
	}
	d.Status = StatusPending
	d.Attempts = attempts
	d.LastError = lastErr
	d.NextAttemptAt = nextAttemptAt
	d.UpdatedAt = nextAttemptAt
	delete(m.claimed, id)
	return nil
}

// MarkFailed implements OutboxStore.
func (m *MemoryOutbox) MarkFailed(_ context.Context, id string, attempts int, lastErr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.deliveries[id]
	if !ok {
		return errors.New("events: MarkFailed: unknown delivery")
	}
	d.Status = StatusFailed
	d.Attempts = attempts
	d.LastError = lastErr
	delete(m.claimed, id)
	return nil
}

// ListActiveSubscriptions implements OutboxStore.
func (m *MemoryOutbox) ListActiveSubscriptions(_ context.Context, projectID string) ([]Subscription, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Subscription, 0)
	for _, s := range m.subs {
		if s.Active && s.ProjectID == projectID {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Get returns a copy of a delivery by ID — a test/inspection seam.
func (m *MemoryOutbox) Get(id string) (Delivery, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.deliveries[id]
	if !ok {
		return Delivery{}, false
	}
	return *d, true
}

var _ OutboxStore = (*MemoryOutbox)(nil)
