package middleware

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// lookupSamples is how many lookups the histogram observed with outcome.
func lookupSamples(t *testing.T, reg *prometheus.Registry, outcome string) uint64 {
	t.Helper()
	families, err := reg.Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() != tenantStatusMetricName {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "outcome" && l.GetValue() == outcome {
					return m.GetHistogram().GetSampleCount()
				}
			}
		}
	}
	return 0
}

// cacheAt is a cache over source with a clock the test moves.
func cacheAt(t *testing.T, source TenantLookup, ttl time.Duration) (*TenantStatusCache, *prometheus.Registry, *time.Time) {
	t.Helper()
	reg := prometheus.NewRegistry()
	metrics, err := NewTenantStatusMetrics(reg)
	require.NoError(t, err)
	c := NewTenantStatusCache(source, ttl, metrics)
	now := time.Unix(1_900_000_000, 0)
	c.now = func() time.Time { return now }
	return c, reg, &now
}

func TestTenantStatusCache_ServesAFreshStatusWithoutReading(t *testing.T) {
	source := newTenantLookup()
	c, reg, now := cacheAt(t, source, time.Minute)
	ctx := context.Background()

	for range 3 {
		status, err := c.GetTenantStatus(ctx, ttProject, "t-claimed")
		require.NoError(t, err)
		assert.Equal(t, service.TenantStatusClaimed, status)
	}
	assert.Equal(t, 1, source.calls)
	assert.EqualValues(t, 1, lookupSamples(t, reg, "miss"))
	assert.EqualValues(t, 2, lookupSamples(t, reg, "hit"))

	// A change in the source is seen once the entry's TTL has passed.
	source.byKey[ttProject+"/t-claimed"].Status = service.TenantStatusSuspended
	*now = now.Add(time.Minute - time.Nanosecond)
	status, _ := c.GetTenantStatus(ctx, ttProject, "t-claimed")
	assert.Equal(t, service.TenantStatusClaimed, status, "still within the TTL")
	*now = now.Add(time.Nanosecond)
	status, _ = c.GetTenantStatus(ctx, ttProject, "t-claimed")
	assert.Equal(t, service.TenantStatusSuspended, status, "read again at the TTL")
	assert.Equal(t, 2, source.calls)

	// Entries are per project and tenant, and an unknown tenant's empty
	// status is cached like any other answer.
	status, _ = c.GetTenantStatus(ctx, "proj-other", "t-claimed")
	assert.Empty(t, status)
	status, _ = c.GetTenantStatus(ctx, "proj-other", "t-claimed")
	assert.Empty(t, status)
	assert.Equal(t, 3, source.calls)
}

func TestTenantStatusCache_NeverCachesAFailedRead(t *testing.T) {
	source := newTenantLookup()
	source.err = errors.New("database down")
	c, reg, _ := cacheAt(t, source, time.Minute)
	ctx := context.Background()

	for range 2 {
		_, err := c.GetTenantStatus(ctx, ttProject, "t-claimed")
		require.ErrorIs(t, err, source.err)
	}
	assert.Equal(t, 2, source.calls)
	assert.EqualValues(t, 2, lookupSamples(t, reg, "error"))

	source.err = nil
	status, err := c.GetTenantStatus(ctx, ttProject, "t-claimed")
	require.NoError(t, err)
	assert.Equal(t, service.TenantStatusClaimed, status)
}

func TestTenantStatusCache_StrictModeReadsEveryTime(t *testing.T) {
	source := newTenantLookup()
	c, reg, _ := cacheAt(t, source, 0)
	ctx := context.Background()

	for range 2 {
		status, err := c.GetTenantStatus(ctx, ttProject, "t-latent")
		require.NoError(t, err)
		assert.Equal(t, service.TenantStatusLatent, status)
	}
	assert.Equal(t, 2, source.calls)
	assert.EqualValues(t, 2, lookupSamples(t, reg, "miss"))
	source.err = errors.New("database down")
	_, err := c.GetTenantStatus(ctx, ttProject, "t-latent")
	require.Error(t, err)
	assert.EqualValues(t, 1, lookupSamples(t, reg, "error"))
	assert.Empty(t, c.entries, "strict mode stores nothing")
}

// A full cache drops the expired entries first, and one live entry only when
// none had expired; it never grows past its bound.
func TestTenantStatusCache_StaysWithinItsBound(t *testing.T) {
	source := newTenantLookup()
	c, _, now := cacheAt(t, source, time.Minute)
	c.maxEntries = 2
	ctx := context.Background()

	_, _ = c.GetTenantStatus(ctx, ttProject, "t-claimed")
	*now = now.Add(30 * time.Second)
	_, _ = c.GetTenantStatus(ctx, ttProject, "t-latent")
	*now = now.Add(31 * time.Second) // t-claimed has expired, t-latent has not
	_, _ = c.GetTenantStatus(ctx, ttProject, "t-suspended")
	require.Len(t, c.entries, 2)
	assert.NotContains(t, c.entries, tenantStatusKey{project: ttProject, tenant: "t-claimed"}, "the expired entry went")
	assert.Contains(t, c.entries, tenantStatusKey{project: ttProject, tenant: "t-latent"})

	_, _ = c.GetTenantStatus(ctx, "proj-other", "t-elsewhere")
	assert.Len(t, c.entries, 2, "with none expired, one live entry makes room")
	assert.Contains(t, c.entries, tenantStatusKey{project: "proj-other", tenant: "t-elsewhere"})

	// Refreshing a key already held never evicts another.
	*now = now.Add(2 * time.Minute)
	_, _ = c.GetTenantStatus(ctx, "proj-other", "t-elsewhere")
	assert.Len(t, c.entries, 2)
}

func TestTenantStatusCache_Construction(t *testing.T) {
	assert.Nil(t, NewTenantStatusCache(nil, time.Minute, nil), "no source, no cache")

	c := NewTenantStatusCache(newTenantLookup(), time.Minute, nil)
	status, err := c.GetTenantStatus(context.Background(), ttProject, "t-claimed")
	require.NoError(t, err, "a cache without metrics still answers")
	assert.Equal(t, service.TenantStatusClaimed, status)

	reg := prometheus.NewRegistry()
	_, err = NewTenantStatusMetrics(reg)
	require.NoError(t, err)
	_, err = NewTenantStatusMetrics(reg)
	require.Error(t, err, "the histogram registers once per registry")
	m, err := NewTenantStatusMetrics(nil)
	require.NoError(t, err)
	assert.NotNil(t, m)
}

// Through the token check: a selected tenant is read once per TTL, not on
// every request that carries it.
func TestTokenTenants_SelectedTenantReadThroughTheCache(t *testing.T) {
	signer := testSigner(t)
	for name := range tokenTenantMiddlewares(signer, TokenTenants{Default: ttDefault}) {
		t.Run(name, func(t *testing.T) {
			source := newTenantLookup()
			cache, _, _ := cacheAt(t, source, time.Minute)
			mw := tokenTenantMiddlewares(signer, TokenTenants{Default: ttDefault, Selectable: cache})[name]
			token := tenantToken(t, signer, ttProject, "t-claimed")
			for range 3 {
				cap := &tenantCapture{}
				rec := serveWithToken(mw(cap.handler()), ttPath, token)
				assert.Equal(t, http.StatusOK, rec.Code)
				assert.True(t, cap.called)
			}
			assert.Equal(t, 1, source.calls)
		})
	}
}

// BenchmarkTenantStatusCacheHit is the cost a selected-tenant token adds to
// a request once its tenant is cached.
func BenchmarkTenantStatusCacheHit(b *testing.B) {
	metrics, err := NewTenantStatusMetrics(prometheus.NewRegistry())
	if err != nil {
		b.Fatal(err)
	}
	c := NewTenantStatusCache(newTenantLookup(), time.Minute, metrics)
	ctx := context.Background()
	if _, err := c.GetTenantStatus(ctx, ttProject, "t-claimed"); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := c.GetTenantStatus(ctx, ttProject, "t-claimed"); err != nil {
				b.Error(err)
				return
			}
		}
	})
}
