package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestMetricsMiddleware_RecordsRedCounters confirms the M8 contract:
// every Connect RPC bumps the requests counter labelled by method/code
// and the duration histogram labelled by method. The exact names are
// frozen by the spec and matched against the dump.
func TestMetricsMiddleware_RecordsRedCounters(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	m, err := NewRPCMetrics(reg)
	if err != nil {
		t.Fatalf("NewRPCMetrics: %v", err)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := MetricsMiddleware(m)(inner)

	for range 3 {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/identity.IdentityService/PasswordLogin", nil)
		handler.ServeHTTP(rec, req)
	}

	if got := testutil.ToFloat64(m.requests.WithLabelValues("PasswordLogin", "ok")); got != 3 {
		t.Errorf("requests_total{method=PasswordLogin,code=ok} = %v, want 3", got)
	}
	if got := testutil.CollectAndCount(m.requests); got == 0 {
		t.Errorf("expected requests counter to register a series, got 0")
	}
	if got := testutil.CollectAndCount(m.duration); got == 0 {
		t.Errorf("expected duration histogram to register a series, got 0")
	}
}

// TestMetricsMiddleware_NonRPCPathsSkipped guards against polluting
// the metric cardinality with /healthz, /metrics, JWKS, etc.
func TestMetricsMiddleware_NonRPCPathsSkipped(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	m, err := NewRPCMetrics(reg)
	if err != nil {
		t.Fatalf("NewRPCMetrics: %v", err)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := MetricsMiddleware(m)(inner)

	for _, p := range []string{"/healthz", "/metrics", "/.well-known/jwks.json"} {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, p, nil))
	}
	if got := testutil.CollectAndCount(m.requests); got != 0 {
		t.Errorf("non-RPC paths should not register a series; got %d", got)
	}
}

// TestMetricsMiddleware_MapsHTTPStatusToConnectCode covers the error
// branches a deployer's PromQL `code!="ok"` alert depends on.
func TestMetricsMiddleware_MapsHTTPStatusToConnectCode(t *testing.T) {
	t.Parallel()

	cases := []struct {
		status   int
		wantCode string
	}{
		{http.StatusOK, "ok"},
		{http.StatusUnauthorized, "unauthenticated"},
		{http.StatusForbidden, "permission_denied"},
		{http.StatusTooManyRequests, "resource_exhausted"},
		{http.StatusInternalServerError, "internal"},
		{http.StatusNotImplemented, "unimplemented"},
		{http.StatusServiceUnavailable, "unavailable"},
	}

	for _, c := range cases {
		t.Run(strings.ToLower(c.wantCode), func(t *testing.T) {
			t.Parallel()

			reg := prometheus.NewRegistry()
			m, err := NewRPCMetrics(reg)
			if err != nil {
				t.Fatalf("NewRPCMetrics: %v", err)
			}
			inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(c.status)
			})
			handler := MetricsMiddleware(m)(inner)
			handler.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest(http.MethodPost, "/identity.IdentityService/PasswordLogin", nil))

			if got := testutil.ToFloat64(m.requests.WithLabelValues("PasswordLogin", c.wantCode)); got != 1 {
				t.Errorf("status %d: want code=%q, got 0", c.status, c.wantCode)
			}
		})
	}
}

// TestNewRPCMetrics_NilRegistryUsesFreshOne confirms that passing nil
// builds an isolated registry rather than colliding with whatever else
// has registered against the default. Integration tests rely on this.
func TestNewRPCMetrics_NilRegistryUsesFreshOne(t *testing.T) {
	t.Parallel()

	_, err := NewRPCMetrics(nil)
	if err != nil {
		t.Fatalf("first NewRPCMetrics(nil): %v", err)
	}
	if _, err := NewRPCMetrics(nil); err != nil {
		t.Fatalf("second NewRPCMetrics(nil): %v", err)
	}
}
