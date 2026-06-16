package middleware

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// RateLimiter gates requests by a string key (typically a client IP plus a
// path bucket). The in-memory implementation is per-replica; a Redis-backed
// variant can replace it without changing call sites.
type RateLimiter interface {
	Allow(key string, now time.Time) bool
}

// FixedWindowLimiter is a bounded, fixed-window in-memory rate limiter.
// Each key gets `limit` permits per `window`. Window boundaries are aligned
// to wall-clock seconds for simplicity; that's fine for human-scale abuse.
type FixedWindowLimiter struct {
	mu      sync.Mutex
	counts  map[string]windowCount
	window  time.Duration
	limit   int
	maxSize int
}

type windowCount struct {
	startMs int64
	count   int
}

// NewFixedWindowLimiter returns a limiter with the given per-key limit
// per window. limit <= 0 disables the limiter — Allow always returns true.
func NewFixedWindowLimiter(window time.Duration, limit, maxSize int) *FixedWindowLimiter {
	if maxSize <= 0 {
		maxSize = 100_000
	}
	return &FixedWindowLimiter{
		counts:  make(map[string]windowCount),
		window:  window,
		limit:   limit,
		maxSize: maxSize,
	}
}

// Allow returns true if the key has remaining quota in the current window.
func (l *FixedWindowLimiter) Allow(key string, now time.Time) bool {
	if l == nil || l.limit <= 0 || key == "" {
		return true
	}
	nowMs := now.UnixMilli()
	windowMs := l.window.Milliseconds()
	l.mu.Lock()
	defer l.mu.Unlock()
	wc, ok := l.counts[key]
	if !ok || nowMs-wc.startMs >= windowMs {
		// New window.
		if len(l.counts) >= l.maxSize {
			l.evictLocked(nowMs, windowMs)
		}
		l.counts[key] = windowCount{startMs: nowMs, count: 1}
		return true
	}
	if wc.count >= l.limit {
		return false
	}
	wc.count++
	l.counts[key] = wc
	return true
}

func (l *FixedWindowLimiter) evictLocked(nowMs, windowMs int64) {
	for k, v := range l.counts {
		if nowMs-v.startMs >= windowMs {
			delete(l.counts, k)
		}
	}
	if len(l.counts) < l.maxSize {
		return
	}
	for k := range l.counts {
		delete(l.counts, k)
		return
	}
}

// PathLimit binds a path prefix to a RateLimiter. The middleware below
// gates each request by the first matching PathLimit entry.
type PathLimit struct {
	PathPrefix string
	Limiter    RateLimiter
	Tag        string // metric label / log field
}

// RateLimitMiddleware enforces per-IP+path quotas using the configured
// PathLimit entries. Requests whose path matches a PathLimit are checked
// against its limiter; everything else passes through.
//
// The client IP comes from ClientIPHeader (set by ClientIPMiddleware), so
// this middleware must be installed after it. Rate-limited responses
// return 429 with a Retry-After header.
func RateLimitMiddleware(limits []PathLimit, logger *zap.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, pl := range limits {
				if pl.Limiter == nil || pl.PathPrefix == "" {
					continue
				}
				if !strings.HasPrefix(r.URL.Path, pl.PathPrefix) {
					continue
				}
				clientIP := r.Header.Get(ClientIPHeader)
				if clientIP == "" {
					// Without a resolved IP we cannot rate-limit safely.
					// Fail open — the audit logger will still see the
					// path and rate from upstream observability.
					next.ServeHTTP(w, r)
					return
				}
				key := pl.Tag + "|" + clientIP
				if !pl.Limiter.Allow(key, time.Now()) {
					w.Header().Set("Retry-After", "60")
					http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
					logger.Info(
						"rate_limit_exceeded",
						zap.String("path", r.URL.Path),
						zap.String("tag", pl.Tag),
						zap.String("client_ip", clientIP),
					)
					return
				}
				break
			}
			next.ServeHTTP(w, r)
		})
	}
}
