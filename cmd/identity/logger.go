package main

import (
	"context"
	"errors"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/observability"
)

// samplingTick is the window zap's production sampler counts entries in.
const samplingTick = time.Second

// newLogger builds the production logger. When cfg turns the log export on
// (GATEWAY_OTEL_LOGS_ENABLED), every entry the logger keeps is written both to
// the process output and to the export, through one sampler so the two carry
// the same lines. The returned close flushes both and must run before the
// process exits; a Fatal entry runs it too.
func newLogger(ctx context.Context, cfg *config.Config) (*zap.Logger, func(), error) {
	zcfg := zap.NewProductionConfig()
	output, err := zcfg.Build()
	if err != nil {
		return nil, nil, err
	}
	if !cfg.OTelLogsEnabled {
		return output, func() { syncLogger(output) }, nil
	}
	if err := cfg.ValidateLogExport(); err != nil {
		return nil, nil, err
	}
	export, err := observability.NewLogExport(ctx, observability.LogExportFromAppConfig(cfg), output)
	if err != nil {
		return nil, nil, err
	}
	exportCore, err := export.Core(zcfg.Level)
	if err != nil {
		return nil, nil, errors.Join(err, export.Shutdown(ctx))
	}

	var logger *zap.Logger
	closeLogger := func() {
		syncLogger(logger)
		if err := export.Shutdown(context.WithoutCancel(ctx)); err != nil {
			output.Warn("log_export_shutdown_failed", zap.Error(err))
			syncLogger(output)
		}
	}
	sampling := zcfg.Sampling
	zcfg.Sampling = nil
	logger, err = zcfg.Build(
		zap.WrapCore(func(c zapcore.Core) zapcore.Core {
			return zapcore.NewSamplerWithOptions(zapcore.NewTee(c, exportCore), samplingTick, sampling.Initial, sampling.Thereafter)
		}),
		zap.WithFatalHook(flushThenExit{flush: closeLogger, exit: os.Exit}),
	)
	if err != nil {
		return nil, nil, errors.Join(err, export.Shutdown(ctx))
	}
	logger.Info("log_export_enabled", zap.String("collector", export.Destination()))
	return logger, closeLogger, nil
}

// flushThenExit is the Fatal hook while the log export is on: os.Exit skips
// deferred calls, so the export is flushed before the process exits.
type flushThenExit struct {
	flush func()
	exit  func(int)
}

func (h flushThenExit) OnWrite(*zapcore.CheckedEntry, []zapcore.Field) {
	h.flush()
	h.exit(1)
}
