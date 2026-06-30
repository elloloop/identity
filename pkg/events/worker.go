package events

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// Sender delivers one signed webhook. The default httpSender POSTs the
// payload; tests inject a fake. Deliver returns nil on a 2xx acknowledgement
// and a non-nil error otherwise (so the worker retries).
type Sender interface {
	Deliver(ctx context.Context, d *Delivery) error
}

// httpSender is the production Sender. It POSTs the payload with the HMAC
// signature and event-id headers and treats any 2xx as success.
type httpSender struct {
	client *http.Client
}

// NewHTTPSender returns a Sender backed by client (or a 10s-timeout client
// when nil).
func NewHTTPSender(client *http.Client) Sender {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &httpSender{client: client}
}

// Deliver implements Sender.
func (s *httpSender) Deliver(ctx context.Context, d *Delivery) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, bytes.NewReader(d.Payload))
	if err != nil {
		return fmt.Errorf("events: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(SignatureHeader, sign(d.Secret, d.Payload))
	req.Header.Set(EventIDHeader, d.EventID)
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("events: deliver: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("events: non-2xx response: %d", resp.StatusCode)
	}
	return nil
}

// FailureHook is called once when a delivery exhausts its retry budget, so
// the composition root can surface the abandonment via audit/metrics rather
// than swallowing it. It must not block.
type FailureHook func(d *Delivery)

// Worker drains the outbox: it claims due deliveries, sends each, and
// records the outcome (delivered / rescheduled with backoff / failed). It
// is safe to run one Worker per replica against a shared durable store —
// ClaimDue prevents two workers from sending the same row.
type Worker struct {
	store    OutboxStore
	sender   Sender
	policy   RetryPolicy
	now      func() time.Time
	logger   *zap.Logger
	batch    int
	interval time.Duration
	onFail   FailureHook
}

// WorkerConfig configures a Worker. Store and Sender are required; the rest
// have sane defaults.
type WorkerConfig struct {
	Store       OutboxStore
	Sender      Sender
	Policy      RetryPolicy
	Now         func() time.Time
	Logger      *zap.Logger
	Batch       int
	Interval    time.Duration
	FailureHook FailureHook
}

// NewWorker constructs a Worker from cfg, applying defaults for unset
// fields.
func NewWorker(cfg WorkerConfig) *Worker {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}
	if cfg.Batch <= 0 {
		cfg.Batch = 50
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Second
	}
	if cfg.Policy.MaxAttempts == 0 {
		cfg.Policy = DefaultRetryPolicy()
	}
	return &Worker{
		store:    cfg.Store,
		sender:   cfg.Sender,
		policy:   cfg.Policy,
		now:      cfg.Now,
		logger:   cfg.Logger,
		batch:    cfg.Batch,
		interval: cfg.Interval,
		onFail:   cfg.FailureHook,
	}
}

// Run drains the outbox on a ticker until ctx is cancelled. It returns
// ctx.Err() on shutdown.
func (w *Worker) Run(ctx context.Context) error {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := w.ProcessOnce(ctx); err != nil {
				w.logger.Warn("events_worker_tick_error", zap.Error(err))
			}
		}
	}
}

// ProcessOnce claims one due batch and attempts each delivery. Exposed
// (and the unit of work) so tests can drive the worker deterministically
// without a ticker. It returns an error only when the store cannot be
// queried; per-delivery failures are recorded and retried, never returned.
func (w *Worker) ProcessOnce(ctx context.Context) error {
	now := w.now()
	due, err := w.store.ClaimDue(ctx, now, w.batch)
	if err != nil {
		return fmt.Errorf("events: worker: claim due: %w", err)
	}
	for _, d := range due {
		w.attempt(ctx, d)
	}
	return nil
}

func (w *Worker) attempt(ctx context.Context, d *Delivery) {
	attempt := d.Attempts + 1
	err := w.sender.Deliver(ctx, d)
	if err == nil {
		if mErr := w.store.MarkDelivered(ctx, d.ID, w.now()); mErr != nil {
			w.logger.Warn("events_mark_delivered_error", zap.String("delivery_id", d.ID), zap.Error(mErr))
		}
		return
	}
	if attempt >= w.policy.MaxAttempts {
		if mErr := w.store.MarkFailed(ctx, d.ID, attempt, err.Error()); mErr != nil {
			w.logger.Warn("events_mark_failed_error", zap.String("delivery_id", d.ID), zap.Error(mErr))
		}
		w.logger.Error(
			"events_delivery_abandoned",
			zap.String("delivery_id", d.ID),
			zap.String("event_id", d.EventID),
			zap.String("subscription_id", d.SubscriptionID),
			zap.Int("attempts", attempt),
			zap.String("last_error", err.Error()),
		)
		if w.onFail != nil {
			failed := *d
			failed.Attempts = attempt
			failed.LastError = err.Error()
			w.onFail(&failed)
		}
		return
	}
	next := w.now().Add(w.policy.backoff(attempt))
	if rErr := w.store.Reschedule(ctx, d.ID, attempt, err.Error(), next); rErr != nil {
		w.logger.Warn("events_reschedule_error", zap.String("delivery_id", d.ID), zap.Error(rErr))
	}
}
