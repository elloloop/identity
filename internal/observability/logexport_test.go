package observability

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/observability/otlplogtest"
)

// keepErrorHandler restores the process-wide OpenTelemetry error handler
// NewLogExport replaces, so one test cannot report into another's logger.
func keepErrorHandler(t *testing.T) {
	t.Helper()
	prev := otel.GetErrorHandler()
	t.Cleanup(func() { otel.SetErrorHandler(prev) })
}

// newExportLogger builds the export from cfg and a logger writing to it at
// info and above.
func newExportLogger(t *testing.T, cfg LogExportConfig, report *zap.Logger) (*LogExport, *zap.Logger) {
	t.Helper()
	keepErrorHandler(t)
	export, err := NewLogExport(context.Background(), cfg, report)
	if err != nil {
		t.Fatalf("NewLogExport(%+v): %v", cfg, err)
	}
	core, err := export.Core(zapcore.InfoLevel)
	if err != nil {
		t.Fatalf("Core: %v", err)
	}
	return export, zap.New(core)
}

func TestLogExportFromAppConfig(t *testing.T) {
	got := LogExportFromAppConfig(&config.Config{
		OTelLogsEndpoint:   "http://collector.example.test:4318",
		OTelServiceVersion: "1.2.3",
		OTelDeploymentEnv:  "staging",
	})
	want := LogExportConfig{Endpoint: "http://collector.example.test:4318", ServiceVersion: "1.2.3", DeploymentEnv: "staging"}
	if got != want {
		t.Fatalf("LogExportFromAppConfig = %+v, want %+v", got, want)
	}
}

func TestLogExport_RecordsCarryTheTraceResourceSettings(t *testing.T) {
	collector := otlplogtest.New(t)
	t.Setenv("OTEL_SERVICE_NAME", "")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "")

	export, logger := newExportLogger(t, LogExportConfig{Endpoint: collector.URL, ServiceVersion: "1.2.3", DeploymentEnv: "staging"}, zap.NewNop())
	logger.Debug("below_the_level")
	logger.Info("exported_line", zap.String("k", "v"))
	if err := export.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	got := collector.Records()
	if len(got) != 1 {
		t.Fatalf("collector received %d records (%+v), want only the info line", len(got), got)
	}
	rec := got[0]
	if rec.Body != "exported_line" || rec.Severity != "info" {
		t.Errorf("record = %q at %q, want %q at %q", rec.Body, rec.Severity, "exported_line", "info")
	}
	for key, want := range map[string]string{
		"service.name":                ServiceName,
		"service.version":             "1.2.3",
		"deployment.environment.name": "staging",
	} {
		if rec.Resource[key] != want {
			t.Errorf("%s = %q, want %q (the trace resource's value)", key, rec.Resource[key], want)
		}
	}
}

func TestLogExport_TheStandardResourceVariablesOverrideAndAdd(t *testing.T) {
	collector := otlplogtest.New(t)
	t.Setenv("OTEL_SERVICE_NAME", "identity-under-test")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment=test")

	export, logger := newExportLogger(t, LogExportConfig{Endpoint: collector.URL}, zap.NewNop())
	logger.Info("line")
	if err := export.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	got := collector.Records()
	if len(got) != 1 {
		t.Fatalf("records = %+v, want one", got)
	}
	if got[0].Resource["service.name"] != "identity-under-test" {
		t.Errorf("service.name = %q, want OTEL_SERVICE_NAME's value", got[0].Resource["service.name"])
	}
	if got[0].Resource["deployment.environment"] != "test" {
		t.Errorf("deployment.environment = %q, want OTEL_RESOURCE_ATTRIBUTES's value", got[0].Resource["deployment.environment"])
	}
}

func TestLogExport_PostsUnderTheEndpointsPath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	export, logger := newExportLogger(t, LogExportConfig{Endpoint: srv.URL + "/otlp/"}, zap.NewNop())
	logger.Info("line")
	if err := export.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if gotPath != "/otlp/v1/logs" {
		t.Fatalf("posted to %q, want /otlp/v1/logs", gotPath)
	}
}

func TestLogExport_DestinationIsSchemeAndHostOnly(t *testing.T) {
	export, _ := newExportLogger(t, LogExportConfig{Endpoint: "https://user:pw@collector.example.test:4318/otlp"}, zap.NewNop())
	t.Cleanup(func() { _ = export.Shutdown(context.Background()) })
	if got := export.Destination(); got != "https://collector.example.test:4318" {
		t.Fatalf("Destination() = %q, want scheme and host only", got)
	}
}

func TestNewLogExport_RefusesAnEndpointThatDoesNotParse(t *testing.T) {
	keepErrorHandler(t)
	export, err := NewLogExport(context.Background(), LogExportConfig{Endpoint: "http://[::1"}, zap.NewNop())
	if err == nil || export != nil {
		t.Fatalf("NewLogExport = %v, %v; want an error and no export", export, err)
	}
	if _, ok := otel.GetErrorHandler().(*exportErrorReporter); ok {
		t.Error("a refused endpoint installed the export's error reporter")
	}
}

// closedEndpoint returns the base URL of a port nothing listens on.
func closedEndpoint(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return "http://" + addr
}

func TestLogExport_AnUnreachableCollectorNeverBlocksLogging(t *testing.T) {
	reportCore, reports := observer.New(zapcore.DebugLevel)
	export, logger := newExportLogger(t, LogExportConfig{Endpoint: closedEndpoint(t)}, zap.New(reportCore))

	const lines = 20000 // well past the batch queue, so records are dropped, not waited on
	start := time.Now()
	for range lines {
		logger.Info("line_to_nowhere")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("logging %d lines took %v with the collector down, want it never to wait on the export", lines, elapsed)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = export.Shutdown(ctx) // the collector is down; the flush may fail

	// Failed exports reach the process-wide handler, which is now the
	// export's reporter: however many failures there were, one line a minute.
	otel.Handle(errors.New("another failure"))
	if n := reports.FilterMessage("otel_export_failed").Len(); n != 1 {
		t.Fatalf("export failure reported %d times within a minute, want exactly once", n)
	}
}

func TestLogExport_ShutdownGivesUpOnAHungCollector(t *testing.T) {
	release := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(hung.Close)
	t.Cleanup(func() { close(release) })

	export, logger := newExportLogger(t, LogExportConfig{Endpoint: hung.URL}, zap.NewNop())
	logger.Info("never_delivered")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := export.Shutdown(ctx); err == nil {
		t.Fatal("Shutdown against a hung collector returned nil, want the deadline error")
	}
	if elapsed := time.Since(start); elapsed > logExportShutdownBudget {
		t.Fatalf("Shutdown took %v, want it bounded by the caller's deadline", elapsed)
	}
}

func TestExportErrorReporter_ReportsAtMostOncePerInterval(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	r := &exportErrorReporter{logger: zap.New(core)}

	r.Handle(errors.New("first"))
	r.Handle(errors.New("second"))
	if n := logs.FilterMessage("otel_export_failed").Len(); n != 1 {
		t.Fatalf("reported %d times within one interval, want 1", n)
	}

	r.last.Store(time.Now().Add(-exportErrorInterval - time.Second).UnixNano())
	r.Handle(errors.New("third"))
	if n := logs.FilterMessage("otel_export_failed").Len(); n != 2 {
		t.Fatalf("reported %d times after the interval passed, want 2", n)
	}
}
