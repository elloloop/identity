package middleware

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metric names are fixed by the M8 spec — deployers' alerting rules
// and dashboards reference these exact identifiers.
const (
	metricRequestsTotal = "identity_rpc_requests_total"
	metricDurationSec   = "identity_rpc_duration_seconds"
)

// RPCMetrics owns the RED metric handles for the Connect handler chain.
// A single instance is registered against a prometheus.Registerer at
// boot; the HTTP middleware reads from it on every request.
type RPCMetrics struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// NewRPCMetrics constructs the metrics and registers them with reg. A
// non-nil error is returned if registration collides — typically a
// second call against the default registry within the same process.
// Pass nil to register against a fresh isolated registry (suitable for
// tests, integration harnesses, and benchmarks that want clean state);
// the production binary explicitly passes prometheus.DefaultRegisterer
// so /metrics serves the same counters that record traffic.
func NewRPCMetrics(reg prometheus.Registerer) (*RPCMetrics, error) {
	if reg == nil {
		reg = prometheus.NewRegistry()
	}
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: metricRequestsTotal,
		Help: "Total number of identity Connect RPCs handled, labelled by RPC method and Connect status code.",
	}, []string{"method", "code"})
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    metricDurationSec,
		Help:    "Identity Connect RPC handler duration in seconds, labelled by RPC method.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method"})

	for _, c := range []prometheus.Collector{requests, duration} {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}
	return &RPCMetrics{requests: requests, duration: duration}, nil
}

// MetricsMiddleware records the RED counters for each Connect RPC.
// Non-Connect paths (/metrics, /healthz, /.well-known/jwks.json) are
// passed through unmeasured — they aren't RPCs and would pollute the
// label cardinality.
func MetricsMiddleware(m *RPCMetrics) func(http.Handler) http.Handler {
	if m == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			method, ok := rpcMethodFromPath(r.URL.Path)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			start := time.Now()
			wrapped := &metricsResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(wrapped, r)

			elapsed := time.Since(start).Seconds()
			code := connectCodeFromHTTP(wrapped.statusCode, wrapped.connectCodeHeader())
			m.requests.WithLabelValues(method, code).Inc()
			m.duration.WithLabelValues(method).Observe(elapsed)
		})
	}
}

// rpcMethodFromPath returns "RpcName" for a Connect path of the form
// "/identity.IdentityService/RpcName". Returns ok=false for any other
// path (health checks, JWKS, /metrics).
func rpcMethodFromPath(path string) (string, bool) {
	const prefix = "/identity.IdentityService/"
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	method := path[len(prefix):]
	if method == "" || strings.ContainsAny(method, "/?#") {
		return "", false
	}
	return method, true
}

// connectCodeFromHTTP maps the HTTP status (with optional Connect
// code header) to the Connect status code string Prometheus is
// labelled by. Connect's wire format puts the canonical code in the
// "Connect-Status" / trailer for unary; when absent we derive a
// reasonable name from the HTTP status. "ok" labels successful
// responses to mirror gRPC convention.
func connectCodeFromHTTP(httpStatus int, connectCode string) string {
	if connectCode != "" {
		return connectCode
	}
	switch {
	case httpStatus >= 200 && httpStatus < 300:
		return "ok"
	case httpStatus == http.StatusBadRequest:
		return "invalid_argument"
	case httpStatus == http.StatusUnauthorized:
		return "unauthenticated"
	case httpStatus == http.StatusForbidden:
		return "permission_denied"
	case httpStatus == http.StatusNotFound:
		return "not_found"
	case httpStatus == http.StatusConflict:
		return "already_exists"
	case httpStatus == http.StatusTooManyRequests:
		return "resource_exhausted"
	case httpStatus == http.StatusGatewayTimeout, httpStatus == http.StatusRequestTimeout:
		return "deadline_exceeded"
	case httpStatus == http.StatusNotImplemented:
		return "unimplemented"
	case httpStatus == http.StatusServiceUnavailable:
		return "unavailable"
	case httpStatus >= 500:
		return "internal"
	default:
		return "unknown"
	}
}

// metricsResponseWriter captures the response status and any
// Connect-Status header the handler writes. The mutex guards
// concurrent reads from connectCodeHeader() against the handler's
// WriteHeader — Connect handlers themselves don't concurrently write,
// but http.ResponseWriter implementations sometimes wrap callers.
type metricsResponseWriter struct {
	http.ResponseWriter
	mu          sync.Mutex
	statusCode  int
	headerCache string
}

func (m *metricsResponseWriter) WriteHeader(code int) {
	m.mu.Lock()
	m.statusCode = code
	// Cache the Connect-Status header at WriteHeader time — handlers
	// may modify Header() before this point but not after.
	m.headerCache = m.Header().Get("Connect-Status")
	m.mu.Unlock()
	m.ResponseWriter.WriteHeader(code)
}

func (m *metricsResponseWriter) connectCodeHeader() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.headerCache != "" {
		return m.headerCache
	}
	return m.Header().Get("Connect-Status")
}
