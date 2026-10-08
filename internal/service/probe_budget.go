package service

import "sync"

// probeBudget caps how many answers that reveal something (here: "that
// username is taken") one client IP may collect per window. Once an IP has
// spent its budget, every further request from it in the window is refused
// the same way whatever it asks about, so the refusal itself reveals nothing.
// In-memory and per replica, like emailSendThrottle.
type probeBudget struct {
	mu       sync.Mutex
	windowMs int64
	limit    int
	maxSize  int
	spent    map[string]probeWindow
}

type probeWindow struct {
	startMs int64
	count   int
}

func newProbeBudget(windowMs int64, limit int) *probeBudget {
	return &probeBudget{windowMs: windowMs, limit: limit, maxSize: 100_000, spent: make(map[string]probeWindow)}
}

// exhausted reports whether ip has spent its budget in the current window.
// A disabled budget (no window or limit) and an unknown IP are never
// exhausted.
func (b *probeBudget) exhausted(ip string, nowMs int64) bool {
	if b == nil || b.windowMs <= 0 || b.limit <= 0 || ip == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	w, ok := b.spent[ip]
	return ok && nowMs-w.startMs < b.windowMs && w.count >= b.limit
}

// spend records one revealing answer to ip.
func (b *probeBudget) spend(ip string, nowMs int64) {
	if b == nil || b.windowMs <= 0 || b.limit <= 0 || ip == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	w, ok := b.spent[ip]
	if !ok || nowMs-w.startMs >= b.windowMs {
		if len(b.spent) >= b.maxSize {
			for k, v := range b.spent {
				if nowMs-v.startMs >= b.windowMs {
					delete(b.spent, k)
				}
			}
		}
		w = probeWindow{startMs: nowMs}
	}
	w.count++
	b.spent[ip] = w
}
