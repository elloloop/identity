package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDiscard_EmitDoesNothing(t *testing.T) {
	if err := (Discard{}).Emit(context.Background(), Event{}); err != nil {
		t.Fatalf("Discard.Emit: %v", err)
	}
}

func TestEventType_Valid(t *testing.T) {
	for _, ty := range []EventType{EventUserCreated, EventUserUpdated, EventUserDeactivated, EventUserDeleted} {
		if !ty.Valid() {
			t.Errorf("%q should be valid", ty)
		}
	}
	if EventType("nope").Valid() {
		t.Error("unknown type should be invalid")
	}
}

// seqID returns a deterministic id generator for tests.
func seqID() IDFunc {
	var n int64
	return func() string { return fmt.Sprintf("d-%d", atomic.AddInt64(&n, 1)) }
}

func sampleEvent(id string) Event {
	return Event{
		ID:        id,
		Type:      EventUserCreated,
		ProjectID: "proj-1",
		TenantID:  "tenant-1",
		User:      User{ID: "u1", Email: "u@example.com", Status: "active"},
	}
}

func TestEmit_RejectsInvalidEvents(t *testing.T) {
	p := NewOutboxPublisher(NewMemoryOutbox(), seqID(), nil, nil)
	if err := p.Emit(context.Background(), Event{Type: EventUserCreated}); err == nil {
		t.Fatal("missing id: want error")
	}
	if err := p.Emit(context.Background(), Event{ID: "x", Type: "bogus"}); err == nil {
		t.Fatal("bad type: want error")
	}
}

func TestEmit_FanOutToMatchingSubscriptions(t *testing.T) {
	store := NewMemoryOutbox()
	store.AddSubscription(Subscription{ID: "s1", ProjectID: "proj-1", URL: "http://a", Secret: "k", Active: true})
	store.AddSubscription(Subscription{ID: "s2", ProjectID: "proj-1", URL: "http://b", Secret: "k", Active: true, EventTypes: []EventType{EventUserUpdated}})
	store.AddSubscription(Subscription{ID: "s3", ProjectID: "other", URL: "http://c", Secret: "k", Active: true})
	store.AddSubscription(Subscription{ID: "s4", ProjectID: "proj-1", URL: "http://d", Secret: "k", Active: false})

	p := NewOutboxPublisher(store, seqID(), nil, nil)
	if err := p.Emit(context.Background(), sampleEvent("ev-1")); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	// Only s1 matches: same project, no filter, active. s2 filters a
	// different type, s3 is another project, s4 is inactive.
	due, err := store.ClaimDue(context.Background(), time.Now(), 10)
	if err != nil {
		t.Fatalf("ClaimDue: %v", err)
	}
	if len(due) != 1 || due[0].SubscriptionID != "s1" {
		t.Fatalf("fan-out = %+v, want only s1", due)
	}
}

func TestEmit_IdempotentByEventID(t *testing.T) {
	store := NewMemoryOutbox()
	store.AddSubscription(Subscription{ID: "s1", ProjectID: "proj-1", URL: "http://a", Secret: "k", Active: true})
	p := NewOutboxPublisher(store, seqID(), nil, nil)

	for i := 0; i < 3; i++ {
		if err := p.Emit(context.Background(), sampleEvent("ev-dup")); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}
	due, _ := store.ClaimDue(context.Background(), time.Now(), 10)
	if len(due) != 1 {
		t.Fatalf("re-emit produced %d deliveries, want 1 (idempotent by event id)", len(due))
	}
}

func TestWorker_DeliversAndSignsPayload(t *testing.T) {
	var gotBody []byte
	var gotSig, gotEvID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSig = r.Header.Get(SignatureHeader)
		gotEvID = r.Header.Get(EventIDHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	store := NewMemoryOutbox()
	store.AddSubscription(Subscription{ID: "s1", ProjectID: "proj-1", URL: srv.URL, Secret: "topsecret", Active: true})
	p := NewOutboxPublisher(store, seqID(), nil, nil)
	if err := p.Emit(context.Background(), sampleEvent("ev-1")); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	w := NewWorker(WorkerConfig{Store: store, Sender: NewHTTPSender(srv.Client())})
	if err := w.ProcessOnce(context.Background()); err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}

	if gotEvID != "ev-1" {
		t.Fatalf("event-id header = %q", gotEvID)
	}
	if !VerifySignature("topsecret", gotBody, gotSig) {
		t.Fatal("signature does not verify against received body")
	}
	if !VerifySignature("topsecret", gotBody, gotSig) {
		t.Fatal("signature mismatch")
	}
	// wrong secret must not verify
	if VerifySignature("wrong", gotBody, gotSig) {
		t.Fatal("signature verified under wrong secret")
	}

	var ev Event
	if err := json.Unmarshal(gotBody, &ev); err != nil {
		t.Fatalf("payload not valid JSON: %v", err)
	}
	if ev.ID != "ev-1" || ev.Type != EventUserCreated || ev.User.Email != "u@example.com" {
		t.Fatalf("payload round-trip: %+v", ev)
	}

	d, _ := store.Get("d-1")
	if d.Status != StatusDelivered {
		t.Fatalf("status = %q, want delivered", d.Status)
	}
}

// flakySender fails the first failN attempts, then succeeds.
type flakySender struct {
	mu       sync.Mutex
	calls    int
	failN    int
	lastBody []byte
}

func (f *flakySender) Deliver(_ context.Context, d *Delivery) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastBody = d.Payload
	if f.calls <= f.failN {
		return errors.New("boom")
	}
	return nil
}

func TestWorker_RetryWithBackoffThenDeliver(t *testing.T) {
	store := NewMemoryOutbox()
	store.AddSubscription(Subscription{ID: "s1", ProjectID: "proj-1", URL: "http://x", Secret: "k", Active: true})

	now := time.Unix(0, 0)
	clock := &now
	nowFn := func() time.Time { return *clock }

	p := NewOutboxPublisher(store, seqID(), nowFn, nil)
	if err := p.Emit(context.Background(), sampleEvent("ev-1")); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	sender := &flakySender{failN: 2}
	w := NewWorker(WorkerConfig{
		Store:  store,
		Sender: sender,
		Now:    nowFn,
		Policy: RetryPolicy{MaxAttempts: 5, BaseDelay: time.Second, MaxDelay: time.Minute},
	})

	// Attempt 1 fails → rescheduled to now+1s.
	mustProcess(t, w)
	d, _ := store.Get("d-1")
	if d.Status != StatusPending || d.Attempts != 1 {
		t.Fatalf("after attempt 1: %+v", d)
	}
	// Not yet due — claiming at current time yields nothing.
	mustProcess(t, w)
	if d2, _ := store.Get("d-1"); d2.Attempts != 1 {
		t.Fatalf("delivery retried before NextAttemptAt: attempts=%d", d2.Attempts)
	}

	// Advance past backoff (1s) → attempt 2 fails → reschedule to +2s.
	*clock = now.Add(2 * time.Second)
	mustProcess(t, w)
	if d3, _ := store.Get("d-1"); d3.Attempts != 2 {
		t.Fatalf("after attempt 2: %+v", d3)
	}

	// Advance well past → attempt 3 succeeds.
	*clock = now.Add(time.Hour)
	mustProcess(t, w)
	d4, _ := store.Get("d-1")
	if d4.Status != StatusDelivered {
		t.Fatalf("after attempt 3: status=%q attempts=%d", d4.Status, d4.Attempts)
	}
	if sender.calls != 3 {
		t.Fatalf("sender called %d times, want 3", sender.calls)
	}
}

func TestWorker_FailsAfterMaxAttempts_SurfacesViaHook(t *testing.T) {
	store := NewMemoryOutbox()
	store.AddSubscription(Subscription{ID: "s1", ProjectID: "proj-1", URL: "http://x", Secret: "k", Active: true})

	now := time.Unix(0, 0)
	clock := &now
	nowFn := func() time.Time { return *clock }

	p := NewOutboxPublisher(store, seqID(), nowFn, nil)
	if err := p.Emit(context.Background(), sampleEvent("ev-1")); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	var failed *Delivery
	w := NewWorker(WorkerConfig{
		Store:       store,
		Sender:      &flakySender{failN: 1000},
		Now:         nowFn,
		Policy:      RetryPolicy{MaxAttempts: 3, BaseDelay: time.Second, MaxDelay: time.Minute},
		FailureHook: func(d *Delivery) { failed = d },
	})

	for i := 0; i < 3; i++ {
		*clock = now.Add(time.Duration(i+1) * time.Hour)
		mustProcess(t, w)
	}
	d, _ := store.Get("d-1")
	if d.Status != StatusFailed {
		t.Fatalf("status = %q, want failed", d.Status)
	}
	if d.Attempts != 3 {
		t.Fatalf("attempts = %d, want 3", d.Attempts)
	}
	if failed == nil || failed.ID != "d-1" || failed.LastError == "" {
		t.Fatalf("failure hook not called with the abandoned delivery: %+v", failed)
	}
}

func TestClaimDue_PreventsDoubleClaim(t *testing.T) {
	store := NewMemoryOutbox()
	store.AddSubscription(Subscription{ID: "s1", ProjectID: "proj-1", URL: "http://x", Secret: "k", Active: true})
	p := NewOutboxPublisher(store, seqID(), nil, nil)
	if err := p.Emit(context.Background(), sampleEvent("ev-1")); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	a, _ := store.ClaimDue(context.Background(), time.Now(), 10)
	b, _ := store.ClaimDue(context.Background(), time.Now(), 10)
	if len(a) != 1 || len(b) != 0 {
		t.Fatalf("double-claim: first=%d second=%d, want 1/0", len(a), len(b))
	}
}

func TestRetryPolicy_BackoffMonotonicCapped(t *testing.T) {
	rp := RetryPolicy{MaxAttempts: 10, BaseDelay: time.Second, MaxDelay: 8 * time.Second}
	got := []time.Duration{rp.backoff(1), rp.backoff(2), rp.backoff(3), rp.backoff(4), rp.backoff(50)}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("backoff(%d)=%v want %v", i+1, got[i], want[i])
		}
	}
}

func mustProcess(t *testing.T, w *Worker) {
	t.Helper()
	if err := w.ProcessOnce(context.Background()); err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
}

func TestWorker_RunDeliversThenStops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	store := NewMemoryOutbox()
	store.AddSubscription(Subscription{ID: "s1", ProjectID: "proj-1", URL: srv.URL, Secret: "k", Active: true})
	p := NewOutboxPublisher(store, seqID(), nil, nil)
	if err := p.Emit(context.Background(), sampleEvent("ev-1")); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	w := NewWorker(WorkerConfig{
		Store:    store,
		Sender:   NewHTTPSender(srv.Client()),
		Interval: 5 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	deadline := time.After(2 * time.Second)
	for {
		if d, ok := store.Get("d-1"); ok && d.Status == StatusDelivered {
			break
		}
		select {
		case <-deadline:
			cancel()
			t.Fatal("delivery not completed within deadline")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v", err)
	}
}
