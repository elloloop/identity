package service

import (
	"sync"

	"github.com/elloloop/identity/internal/config"
)

// probeBudgetMaxSize bounds how many keys a probeBudget tracks.
const probeBudgetMaxSize = 100_000

// probeBudget caps how many answers that reveal something one key may
// collect per window: "that username is taken" per client IP, or which of a
// tenant's members hold a set of phone numbers per credential and tenant. A
// request reserves a unit BEFORE it can learn anything (reserve, one locked
// step, so parallel requests cannot all pass a check together) and may give
// it back if the answer revealed nothing (refund). Once a key's units are
// spent, every further request for it in the window is refused the same way
// whatever it asks about, so the refusal itself reveals nothing. In-memory
// and per replica, keyed on the exact string, like keyCooldown.
type probeBudget struct {
	mu       sync.Mutex
	windowMs int64
	limit    int
	spent    map[string]probeWindow
}

type probeWindow struct {
	startMs int64
	count   int
}

func newProbeBudget(windowMs int64, limit int) *probeBudget {
	return &probeBudget{windowMs: windowMs, limit: limit, spent: make(map[string]probeWindow)}
}

func (b *probeBudget) disabled(key string) bool {
	return b == nil || b.windowMs <= 0 || b.limit <= 0 || key == ""
}

// reserve takes one unit for key, or reports false when its budget for the
// current window is spent. A disabled budget and an empty key always pass.
func (b *probeBudget) reserve(key string, nowMs int64) bool {
	if b.disabled(key) {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	w, ok := b.spent[key]
	if !ok || nowMs-w.startMs >= b.windowMs {
		if !ok && len(b.spent) >= probeBudgetMaxSize {
			b.evictLocked(nowMs)
		}
		w = probeWindow{startMs: nowMs}
	}
	if w.count >= b.limit {
		return false
	}
	w.count++
	b.spent[key] = w
	return true
}

// refund gives back a unit reserve took, for an answer that revealed nothing.
func (b *probeBudget) refund(key string, nowMs int64) {
	if b.disabled(key) {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if w, ok := b.spent[key]; ok && nowMs-w.startMs < b.windowMs && w.count > 0 {
		w.count--
		b.spent[key] = w
	}
}

// evictLocked drops expired windows; if none expired it drops one arbitrary
// entry, so the map stays bounded (bounded growth over perfect fairness, as
// keyCooldown chooses).
func (b *probeBudget) evictLocked(nowMs int64) {
	for k, v := range b.spent {
		if nowMs-v.startMs >= b.windowMs {
			delete(b.spent, k)
		}
	}
	if len(b.spent) < probeBudgetMaxSize {
		return
	}
	for k := range b.spent {
		delete(b.spent, k)
		return
	}
}

// rateLimitWindowMs is the per-IP rate-limit window, falling back to one
// minute as the HTTP limiters do when GATEWAY_RATE_LIMIT_WINDOW_SECONDS is
// not positive.
func rateLimitWindowMs(cfg *config.Config) int64 {
	if cfg.RateLimitWindowSeconds <= 0 {
		return 60_000
	}
	return int64(cfg.RateLimitWindowSeconds) * 1000
}
