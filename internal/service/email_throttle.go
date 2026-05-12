package service

import "sync"

// emailSendThrottle enforces a per-recipient cooldown between transactional
// emails (password-reset, email-verification) so an unauthenticated attacker
// cannot use those endpoints to bomb a victim inbox or burn the SMTP budget.
//
// The tracker is in-memory and per-replica. At N replicas this allows up to
// N sends per cooldown window per recipient — orders of magnitude better
// than unbounded, and acceptable for launch. A shared store (Redis) is the
// natural upgrade once rate-limiting infrastructure lands.
type emailSendThrottle struct {
	mu         sync.Mutex
	lastSentMs map[string]int64
	cooldownMs int64
	maxSize    int
}

func newEmailSendThrottle(cooldownMs int64, maxSize int) *emailSendThrottle {
	if maxSize <= 0 {
		maxSize = 100_000
	}
	return &emailSendThrottle{
		lastSentMs: make(map[string]int64),
		cooldownMs: cooldownMs,
		maxSize:    maxSize,
	}
}

// allow returns true and records the send. Returns false if the recipient
// was sent to within the cooldown window. A zero or negative cooldown
// disables throttling entirely.
func (t *emailSendThrottle) allow(recipient string, nowMs int64) bool {
	if t == nil || t.cooldownMs <= 0 || recipient == "" {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if last, ok := t.lastSentMs[recipient]; ok && nowMs-last < t.cooldownMs {
		return false
	}
	if len(t.lastSentMs) >= t.maxSize {
		t.evictLocked(nowMs)
	}
	t.lastSentMs[recipient] = nowMs
	return true
}

// evictLocked drops any entries older than the cooldown window. If the map
// is still over capacity it drops one arbitrary entry — bounded growth
// matters more than perfect LRU semantics here.
func (t *emailSendThrottle) evictLocked(nowMs int64) {
	for k, v := range t.lastSentMs {
		if nowMs-v >= t.cooldownMs {
			delete(t.lastSentMs, k)
		}
	}
	if len(t.lastSentMs) < t.maxSize {
		return
	}
	for k := range t.lastSentMs {
		delete(t.lastSentMs, k)
		return
	}
}
