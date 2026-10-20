package sms

import (
	"context"

	"go.uber.org/zap"
)

type logOnlySender struct {
	logger *zap.Logger
}

// NewLogOnly returns a Sender that logs each Send at WARN and returns
// nil. It is the disabled/dev default — installed when GATEWAY_SMS_
// ENABLED is false — so service code can always call Send without a nil
// check. The line records that a message was dropped, never its body
// (which carries one-time codes) or the full number.
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
	l.logger.Warn(
		"sms_disabled_no_sender",
		zap.String("to", Redact(m.To)),
		zap.Int("body_bytes", len(m.Body)),
	)
	return nil
}
