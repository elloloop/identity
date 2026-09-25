package middleware

import (
	"math"
	"net/http"
	"strconv"
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
	// Window is the length of one quota window: the longest a refused
	// caller waits before its count resets.
	Window() time.Duration
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

// Window returns the limiter's window length; zero for a nil limiter.
func (l *FixedWindowLimiter) Window() time.Duration {
	if l == nil {
		return 0
	}
	return l.window
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

// Allow reports whether a request from clientIP has quota left on this
// limit. Without a resolved client IP the request cannot be attributed to
// a caller, so it is admitted rather than charged to a shared bucket every
// such request would exhaust together.
func (pl PathLimit) Allow(clientIP string, now time.Time) bool {
	if pl.Limiter == nil || clientIP == "" {
		return true
	}
	return pl.Limiter.Allow(pl.Tag+"|"+clientIP, now)
}

// RetryAfterSeconds is the Retry-After value, in whole seconds, a caller
// refused by this limit is told to wait: its window rounded up, and never
// less than one second so a sub-second window does not advertise "retry
// now".
func (pl PathLimit) RetryAfterSeconds() int {
	if pl.Limiter == nil {
		return 1
	}
	return max(1, int(math.Ceil(pl.Limiter.Window().Seconds())))
}

// MatchPathLimit returns the first limit in limits whose prefix matches path
// and which has a limiter. Every transport that enforces the configured
// limits selects through it, so an RPC is held to the same budget however
// it arrives.
func MatchPathLimit(limits []PathLimit, path string) (PathLimit, bool) {
	for _, pl := range limits {
		if pl.Limiter != nil && pl.PathPrefix != "" && strings.HasPrefix(path, pl.PathPrefix) {
			return pl, true
		}
	}
	return PathLimit{}, false
}

// RateLimitMiddleware enforces per-IP+path quotas using the configured
// PathLimit entries. Requests whose path matches a PathLimit are checked
// against its limiter; everything else passes through.
//
// The client IP comes from ClientIPHeader (set by ClientIPMiddleware), so
// this middleware must be installed after it. Rate-limited responses
// return 429 with a Retry-After header of the limit's window.
func RateLimitMiddleware(limits []PathLimit, logger *zap.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pl, ok := MatchPathLimit(limits, r.URL.Path)
			clientIP := r.Header.Get(ClientIPHeader)
			if !ok || pl.Allow(clientIP, time.Now()) {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Retry-After", strconv.Itoa(pl.RetryAfterSeconds()))
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			logger.Info(
				"rate_limit_exceeded",
				zap.String("path", r.URL.Path),
				zap.String("tag", pl.Tag),
				zap.String("client_ip", clientIP),
			)
		})
	}
}
