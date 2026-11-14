package service

import "sync"

// keyCooldown admits one event per key per cooldown window: a transactional
// email or a phone code per recipient, so an unauthenticated caller cannot
// bomb an inbox or burn the delivery budget.
//
// The tracker is in-memory and per-replica. At N replicas this allows up to
// N events per cooldown window per key — orders of magnitude better than
// unbounded. A shared store (Redis) is the natural upgrade once
// rate-limiting infrastructure lands.
type keyCooldown struct {
	mu         sync.Mutex
	lastMs     map[string]int64
	cooldownMs int64
	maxSize    int
}

func newKeyCooldown(cooldownMs int64, maxSize int) *keyCooldown {
	if maxSize <= 0 {
		maxSize = 100_000
	}
	return &keyCooldown{
		lastMs:     make(map[string]int64),
		cooldownMs: cooldownMs,
		maxSize:    maxSize,
	}
}

// allow returns true and records the event. Returns false if key was
// admitted within the cooldown window. A zero or negative cooldown disables
// the cooldown entirely.
func (t *keyCooldown) allow(key string, nowMs int64) bool {
	return t.allowAll(nowMs, key)
}

// allowAll admits one event that counts against every key: it returns true
// and records the event under each only when none was admitted within the
// cooldown window, so a refusal spends none of them. An empty key is not
// counted.
func (t *keyCooldown) allowAll(nowMs int64, keys ...string) bool {
	if t == nil || t.cooldownMs <= 0 {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, key := range keys {
		if last, ok := t.lastMs[key]; ok && key != "" && nowMs-last < t.cooldownMs {
			return false
		}
	}
	for _, key := range keys {
		if key == "" {
			continue
		}
		if len(t.lastMs) >= t.maxSize {
			t.evictLocked(nowMs)
		}
		t.lastMs[key] = nowMs
	}
	return true
}

// evictLocked drops any entries older than the cooldown window. If the map
// is still over capacity it drops one arbitrary entry — bounded growth
// matters more than perfect LRU semantics here.
func (t *keyCooldown) evictLocked(nowMs int64) {
	for k, v := range t.lastMs {
		if nowMs-v >= t.cooldownMs {
			delete(t.lastMs, k)
		}
	}
	if len(t.lastMs) < t.maxSize {
		return
	}
	for k := range t.lastMs {
		delete(t.lastMs, k)
		return
	}
}
