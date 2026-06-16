package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"go.uber.org/zap"
)

// IDFunc generates a unique delivery-row id. Injectable so tests get
// deterministic ids; production uses a random generator supplied by the
// composition root.
type IDFunc func() string

// OutboxPublisher is the durable Publisher: Emit fans an event out to
// every matching active subscription by writing one pending outbox row per
// subscription, then returns. A background Worker (Run) delivers the rows.
// Because Emit only writes durable rows, a slow or down subscriber never
// adds latency to — or fails — the originating RPC.
type OutboxPublisher struct {
	store  OutboxStore
	now    func() time.Time
	newID  IDFunc
	logger *zap.Logger
}

// NewOutboxPublisher constructs an OutboxPublisher. now and newID may be
// nil, in which case time.Now and a panic-free fallback are used; logger
// may be nil (a no-op logger is substituted).
func NewOutboxPublisher(store OutboxStore, newID IDFunc, now func() time.Time, logger *zap.Logger) *OutboxPublisher {
	if now == nil {
		now = time.Now
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &OutboxPublisher{store: store, now: now, newID: newID, logger: logger}
}

// Emit implements Publisher. It validates the event, fans it out to every
// matching active subscription, and enqueues one idempotent outbox row per
// subscription. A subscription that already has a row for this event id is
// skipped (ErrDeliveryExists), so re-emitting is safe.
func (p *OutboxPublisher) Emit(ctx context.Context, e Event) error {
	if e.ID == "" {
		return errors.New("events: Emit: event id is required for idempotency")
	}
	if !e.Type.Valid() {
		return fmt.Errorf("events: Emit: unknown event type %q", e.Type)
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = p.now()
	}
	payload, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("events: Emit: marshal event: %w", err)
	}
	subs, err := p.store.ListActiveSubscriptions(ctx, e.ProjectID)
	if err != nil {
		return fmt.Errorf("events: Emit: list subscriptions: %w", err)
	}
	now := p.now()
	for _, s := range subs {
		if !s.matches(e) {
			continue
		}
		d := &Delivery{
			ID:             p.newID(),
			EventID:        e.ID,
			SubscriptionID: s.ID,
			URL:            s.URL,
			Secret:         s.Secret,
			Payload:        payload,
			Status:         StatusPending,
			NextAttemptAt:  now,
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		if err := p.store.EnqueueDelivery(ctx, d); err != nil {
			if errors.Is(err, ErrDeliveryExists) {
				continue // idempotent: already enqueued for this event
			}
			return fmt.Errorf("events: Emit: enqueue delivery: %w", err)
		}
	}
	return nil
}

var _ Publisher = (*OutboxPublisher)(nil)

// RetryPolicy bounds delivery retries. After MaxAttempts failed attempts a
// delivery is abandoned (StatusFailed) and surfaced via FailureHook. The
// backoff is exponential — BaseDelay * 2^(attempt-1) — capped at MaxDelay.
type RetryPolicy struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
}

// DefaultRetryPolicy is a conservative at-least-once policy: six attempts
// over roughly ten minutes.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{MaxAttempts: 6, BaseDelay: 2 * time.Second, MaxDelay: 5 * time.Minute}
}

// backoff returns the delay before the given (1-based) attempt's retry.
func (rp RetryPolicy) backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	// 2^(attempt-1), guarded against overflow.
	shift := attempt - 1
	if shift > 30 {
		return rp.MaxDelay
	}
	d := rp.BaseDelay * time.Duration(math.Pow(2, float64(shift)))
	if d <= 0 || d > rp.MaxDelay {
		return rp.MaxDelay
	}
	return d
}
