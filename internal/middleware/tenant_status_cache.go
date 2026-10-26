package middleware

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// tenantStatusMetricName is the histogram deployers wire into their
// dashboards and alerts for the selected-tenant check on the auth path.
const tenantStatusMetricName = "identity_token_tenant_lookup_duration_seconds"

// maxTenantStatusEntries bounds the cache. Only a signed token names a
// tenant, so its keys are tenants a token was minted for; the bound keeps a
// project with very many of them from growing the map without limit.
const maxTenantStatusEntries = 10000

// TenantStatusMetrics owns the histogram of selected-tenant status reads on
// the auth path: cache hits land in the sub-microsecond buckets, misses and
// errors include the repository round-trip.
type TenantStatusMetrics struct {
	lookupDuration *prometheus.HistogramVec
}

// NewTenantStatusMetrics registers the histogram with reg. nil registers it
// against a fresh isolated registry (suitable for tests).
func NewTenantStatusMetrics(reg prometheus.Registerer) (*TenantStatusMetrics, error) {
	if reg == nil {
		reg = prometheus.NewRegistry()
	}
	hist := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    tenantStatusMetricName,
		Help:    "Selected-tenant status lookup duration in seconds on the access-token check, labelled by outcome (hit/miss/error).",
		Buckets: cacheLookupBuckets,
	}, []string{"outcome"})
	if err := reg.Register(hist); err != nil {
		return nil, err
	}
	return &TenantStatusMetrics{lookupDuration: hist}, nil
}

// TenantStatusCache serves a selected tenant's status to TokenTenants from an
// in-process TTL cache over source, so a token that carries a selected tenant
// does not read the tenants table on every request.
//
// A status change is seen by this replica at the latest one TTL after it was
// written: a suspended tenant's tokens keep working for up to that long. A
// failed read is never cached, so the next request reads again. TTL = 0 is
// strict mode: every lookup reads source.
type TenantStatusCache struct {
	source     TenantLookup
	ttl        time.Duration
	metrics    *TenantStatusMetrics
	now        func() time.Time
	maxEntries int

	mu        sync.RWMutex
	entries   map[tenantStatusKey]tenantStatusEntry
	lastSweep time.Time // when store last swept expired entries; guarded by mu
}

type tenantStatusKey struct {
	project string
	tenant  string
}

type tenantStatusEntry struct {
	status   string
	deadline time.Time
}

// NewTenantStatusCache wraps source. nil source returns nil; a caller assigns
// the result to TokenTenants.Selectable only when it is non-nil.
func NewTenantStatusCache(source TenantLookup, ttl time.Duration, metrics *TenantStatusMetrics) *TenantStatusCache {
	if source == nil {
		return nil
	}
	return &TenantStatusCache{
		source:     source,
		ttl:        ttl,
		metrics:    metrics,
		now:        time.Now,
		maxEntries: maxTenantStatusEntries,
		entries:    map[tenantStatusKey]tenantStatusEntry{},
	}
}

// GetTenantStatus answers TenantLookup: a fresh cached status without I/O,
// otherwise source's answer, cached until the TTL passes when it succeeded.
func (c *TenantStatusCache) GetTenantStatus(ctx context.Context, projectID, tenantID string) (string, error) {
	start := c.now()
	if c.ttl <= 0 {
		status, err := c.source.GetTenantStatus(ctx, projectID, tenantID)
		c.observe(start, readOutcome(err))
		return status, err
	}
	key := tenantStatusKey{project: projectID, tenant: tenantID}
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if ok && start.Before(entry.deadline) {
		c.observe(start, "hit")
		return entry.status, nil
	}
	status, err := c.source.GetTenantStatus(ctx, projectID, tenantID)
	if err != nil {
		c.observe(start, "error")
		return "", err
	}
	c.store(key, tenantStatusEntry{status: status, deadline: c.now().Add(c.ttl)})
	c.observe(start, "miss")
	return status, nil
}

// store records entry under key, making room first when the cache is full.
// At most once per TTL that sweeps every expired entry; otherwise, and when
// none had expired, one arbitrary entry goes. A miss at capacity therefore
// walks the map at most once per TTL, not on every call.
func (c *TenantStatusCache) store(key tenantStatusKey, entry tenantStatusEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[key]; !ok && len(c.entries) >= c.maxEntries {
		if now := c.now(); now.Sub(c.lastSweep) >= c.ttl {
			c.lastSweep = now
			for k, e := range c.entries {
				if !now.Before(e.deadline) {
					delete(c.entries, k)
				}
			}
		}
		if len(c.entries) >= c.maxEntries {
			for k := range c.entries {
				delete(c.entries, k)
				break
			}
		}
	}
	c.entries[key] = entry
}

func readOutcome(err error) string {
	if err != nil {
		return "error"
	}
	return "miss"
}

func (c *TenantStatusCache) observe(start time.Time, outcome string) {
	if c.metrics == nil {
		return
	}
	c.metrics.lookupDuration.WithLabelValues(outcome).Observe(c.now().Sub(start).Seconds())
}
