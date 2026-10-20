package observability

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/contrib/bridges/otelzap"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/elloloop/identity/internal/config"
)

// logExportShutdownBudget bounds the final flush, so a collector that is
// down cannot hold up process exit.
const logExportShutdownBudget = 5 * time.Second

// exportErrorInterval is the most often an export failure is reported.
const exportErrorInterval = time.Minute

// LogExportConfig controls the log export. It mirrors the
// GATEWAY_OTEL_LOGS_* settings and shares the trace resource's
// GATEWAY_OTEL_SERVICE_VERSION and GATEWAY_OTEL_DEPLOYMENT_ENV.
type LogExportConfig struct {
	// Endpoint is the collector's OTLP/HTTP base URL, already checked by
	// config.Config.ValidateLogExport.
	Endpoint       string
	ServiceVersion string
	DeploymentEnv  string
}

// LogExportFromAppConfig translates a *config.Config into the LogExportConfig
// NewLogExport takes.
func LogExportFromAppConfig(c *config.Config) LogExportConfig {
	return LogExportConfig{
		Endpoint:       c.OTelLogsEndpoint,
		ServiceVersion: c.OTelServiceVersion,
		DeploymentEnv:  c.OTelDeploymentEnv,
	}
}

// LogExport sends log records to an OTLP/HTTP collector beside the
// process's own log output.
type LogExport struct {
	provider    *sdklog.LoggerProvider
	destination string
}

// NewLogExport builds the log export to cfg.Endpoint, posting under /v1/logs.
// Records carry the same service.name, service.version and deployment
// environment as traces; the standard OTEL_SERVICE_NAME and
// OTEL_RESOURCE_ATTRIBUTES, which the SDK reads, override or add to them.
//
// Records are batched in a bounded queue, so the export never blocks a
// caller; when the queue is full the oldest records are dropped. Export
// failures are written to report at most once a minute. That reporting
// replaces the process-wide OpenTelemetry error handler, so it covers trace
// export failures too.
func NewLogExport(ctx context.Context, cfg LogExportConfig, report *zap.Logger) (*LogExport, error) {
	base, err := url.Parse(strings.TrimSpace(cfg.Endpoint))
	if err != nil {
		return nil, errors.New("observability: the log export endpoint does not parse as a URL")
	}
	exp, err := otlploghttp.New(ctx, otlploghttp.WithEndpointURL(base.JoinPath("v1", "logs").String()))
	if err != nil {
		return nil, fmt.Errorf("observability: build OTLP log exporter: %w", err)
	}
	res, err := resource.New(ctx,
		resource.WithTelemetrySDK(),
		resource.WithAttributes(identityAttributes(cfg.ServiceVersion, cfg.DeploymentEnv)...),
		resource.WithFromEnv(),
	)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("observability: build log resource: %w", err), exp.Shutdown(ctx))
	}
	otel.SetErrorHandler(&exportErrorReporter{logger: report})
	return &LogExport{
		provider: sdklog.NewLoggerProvider(
			sdklog.WithResource(res),
			sdklog.WithProcessor(sdklog.NewBatchProcessor(exp)),
		),
		destination: base.Scheme + "://" + base.Host,
	}, nil
}

// Destination is the collector's scheme and host, safe to log: no path,
// query or user information.
func (e *LogExport) Destination() string { return e.destination }

// Core returns a zap core that exports every entry at level or above.
func (e *LogExport) Core(level zapcore.LevelEnabler) (zapcore.Core, error) {
	return zapcore.NewIncreaseLevelCore(
		otelzap.NewCore(InstrumentationName, otelzap.WithLoggerProvider(e.provider)),
		level,
	)
}

// Shutdown flushes queued records and stops the export, waiting at most
// logExportShutdownBudget.
func (e *LogExport) Shutdown(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, logExportShutdownBudget)
	defer cancel()
	return e.provider.Shutdown(ctx)
}

// exportErrorReporter is the OpenTelemetry error handler. It writes to the
// process's own log output only, so a failing export cannot log into itself.
type exportErrorReporter struct {
	logger *zap.Logger
	last   atomic.Int64 // unix nanos of the last report
}

func (r *exportErrorReporter) Handle(err error) {
	now := time.Now()
	prev := r.last.Load()
	if prev != 0 && now.Sub(time.Unix(0, prev)) < exportErrorInterval {
		return
	}
	if !r.last.CompareAndSwap(prev, now.UnixNano()) {
		return
	}
	r.logger.Warn("otel_export_failed", zap.Error(err))
}
