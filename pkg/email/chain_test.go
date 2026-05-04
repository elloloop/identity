package email

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

type mockTransport struct {
	mu     sync.Mutex
	calls  int
	err    error
	delay  func(ctx context.Context) error
	gotMsg Message
}

func (m *mockTransport) Send(ctx context.Context, msg Message) error {
	m.mu.Lock()
	m.calls++
	m.gotMsg = msg
	m.mu.Unlock()
	if m.delay != nil {
		if err := m.delay(ctx); err != nil {
			return err
		}
	}
	return m.err
}

func validMsg() Message {
	return Message{To: "u@example.com", From: "f@example.com", Subject: "s", Text: "t"}
}

func TestChainFirstSucceeds(t *testing.T) {
	t.Parallel()

	a := &mockTransport{}
	b := &mockTransport{}
	c := NewChain(zaptest.NewLogger(t), a, b)
	if err := c.Send(context.Background(), validMsg()); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if a.calls != 1 {
		t.Errorf("a calls: got %d want 1", a.calls)
	}
	if b.calls != 0 {
		t.Errorf("b calls: got %d want 0", b.calls)
	}
}

func TestChainFallsThroughToSecond(t *testing.T) {
	t.Parallel()

	boom := errors.New("primary down")
	a := &mockTransport{err: boom}
	b := &mockTransport{}
	c := NewChain(zaptest.NewLogger(t), a, b)
	if err := c.Send(context.Background(), validMsg()); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if a.calls != 1 || b.calls != 1 {
		t.Fatalf("calls: a=%d b=%d want 1,1", a.calls, b.calls)
	}
}

func TestChainAllFailReturnsLast(t *testing.T) {
	t.Parallel()

	first := errors.New("first fail")
	last := errors.New("last fail")
	a := &mockTransport{err: first}
	b := &mockTransport{err: last}
	c := NewChain(zaptest.NewLogger(t), a, b)
	err := c.Send(context.Background(), validMsg())
	if !errors.Is(err, last) {
		t.Fatalf("expected last err, got %v", err)
	}
}

func TestChainOnAttemptHook(t *testing.T) {
	t.Parallel()

	first := errors.New("boom")
	a := &mockTransport{err: first}
	b := &mockTransport{}

	type rec struct {
		idx int
		err error
	}
	var recs []rec
	var mu sync.Mutex

	c := NewChain(zaptest.NewLogger(t), a, b)
	c.OnAttempt = func(idx int, err error) {
		mu.Lock()
		recs = append(recs, rec{idx, err})
		mu.Unlock()
	}

	if err := c.Send(context.Background(), validMsg()); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 hook fires, got %d", len(recs))
	}
	if recs[0].idx != 0 || !errors.Is(recs[0].err, first) {
		t.Errorf("rec[0]=%+v", recs[0])
	}
	if recs[1].idx != 1 || recs[1].err != nil {
		t.Errorf("rec[1]=%+v", recs[1])
	}
}

func TestChainEmpty(t *testing.T) {
	t.Parallel()
	c := NewChain(zap.NewNop())
	err := c.Send(context.Background(), validMsg())
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("expected ErrTransport, got %v", err)
	}
}

func TestChainValidatesMessage(t *testing.T) {
	t.Parallel()
	a := &mockTransport{}
	c := NewChain(zap.NewNop(), a)
	err := c.Send(context.Background(), Message{})
	if !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("expected ErrInvalidMessage, got %v", err)
	}
	if a.calls != 0 {
		t.Errorf("transport should not be called for invalid msg, calls=%d", a.calls)
	}
}

func TestChainNilLoggerSafe(t *testing.T) {
	t.Parallel()
	a := &mockTransport{}
	c := NewChain(nil, a)
	if err := c.Send(context.Background(), validMsg()); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	// confirm logger is non-nil and OnAttempt unset (no panic).
	var attempts int32
	c.OnAttempt = func(_ int, _ error) { atomic.AddInt32(&attempts, 1) }
	_ = c.Send(context.Background(), validMsg())
	if atomic.LoadInt32(&attempts) != 1 {
		t.Fatalf("attempts: got %d want 1", attempts)
	}
}
