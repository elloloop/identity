package sms

import (
	"context"

	"go.uber.org/zap"
)

// previewLen caps how much body content gets logged in dev mode so a
// long message doesn't dominate the log line.
const previewLen = 240

type logOnlySender struct {
	logger *zap.Logger
}

// NewLogOnly returns a Sender that logs each Send at WARN and returns
// nil. It is the disabled/dev default — installed when GATEWAY_SMS_
// ENABLED is false — so service code can always call Send without a nil
// check.
func NewLogOnly(logger *zap.Logger) Sender {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &logOnlySender{logger: logger}
}

func (l *logOnlySender) Send(_ context.Context, m Message) error {
	if err := m.Validate(); err != nil {
		return err
	}
	preview := m.Body
	if len(preview) > previewLen {
		preview = preview[:previewLen]
	}
	l.logger.Warn(
		"sms_disabled_no_sender",
		zap.String("to", m.To),
		zap.String("preview", preview),
	)
	return nil
}
