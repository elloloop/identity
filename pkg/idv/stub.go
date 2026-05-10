package idv

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// StubProvider is an in-process Provider for tests and bring-up.
// It accepts every BeginVerification call, returns a deterministic
// SessionToken, and lets the test set the verdict that subsequent
// GetVerification calls will report.
//
// Production deployments MUST replace this with a real provider (e.g.
// AzureProvider). Wiring intentionally defaults to StubProvider only
// when no provider is configured, so a misconfigured deploy fails
// closed: signups marked verified by the stub will not pass the
// real-provider gate in any non-test environment.
type StubProvider struct {
	// Verdict controls the StatusResult returned by GetVerification
	// for sessions whose verdict has not been set explicitly. Defaults
	// to StatusApproved so tests of the happy path do not need setup.
	Verdict string

	// Clock returns the current time. Tests may override.
	Clock func() time.Time

	// SessionTTL is the lifetime applied to ExpiresAt. Defaults to 15m.
	SessionTTL time.Duration

	mu       sync.Mutex
	sessions map[string]*StatusResult
}

// NewStubProvider returns a StubProvider with sensible defaults: every
// session resolves to StatusApproved and SessionToken expires in 15m.
func NewStubProvider() *StubProvider {
	return &StubProvider{
		Verdict:    StatusApproved,
		Clock:      time.Now,
		SessionTTL: 15 * time.Minute,
		sessions:   make(map[string]*StatusResult),
	}
}

// Name implements Provider.
func (s *StubProvider) Name() string { return "stub" }

// BeginVerification implements Provider.
func (s *StubProvider) BeginVerification(_ context.Context, _ Request) (*Session, error) {
	id, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	token, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	now := s.Clock()
	ttl := s.SessionTTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	s.mu.Lock()
	s.sessions[id] = &StatusResult{Status: StatusPending}
	s.mu.Unlock()
	return &Session{
		ProviderSessionID: id,
		SessionToken:      token,
		ExpiresAt:         now.Add(ttl),
	}, nil
}

// GetVerification implements Provider. Sessions reach their configured
// Verdict on the first poll: the stub does not model a queue/delay so
// tests assert deterministic post-Begin state.
func (s *StubProvider) GetVerification(_ context.Context, providerSessionID string) (*StatusResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[providerSessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	if rec.Status == StatusPending {
		rec.Status = s.Verdict
		if rec.Status == "" {
			rec.Status = StatusApproved
		}
		rec.CompletedAt = s.Clock()
		if rec.Status == StatusRejected && rec.RejectionReason == "" {
			rec.RejectionReason = "stub: configured to reject"
		}
	}
	out := *rec
	return &out, nil
}

// SetVerdict overrides the resolved verdict for a specific session.
// Tests use this to exercise the rejection path without having to
// reconfigure the global Verdict.
func (s *StubProvider) SetVerdict(providerSessionID, status, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[providerSessionID]
	if !ok {
		return
	}
	rec.Status = status
	rec.RejectionReason = reason
	rec.CompletedAt = s.Clock()
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
