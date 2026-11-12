package templatemsg

import (
	"context"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/sms"
)

type logOnlySender struct {
	logger *zap.Logger
}

// NewLogOnly returns a Sender that logs each Send at WARN and returns nil,
// delivering nothing. It is for development and tests. The line records
// that a message was dropped, with the template's name and the redacted
// number, never the params (which carry one-time codes).
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
		"template_message_dropped_no_sender",
		zap.String("to", sms.Redact(m.To)),
		zap.String("template", m.Template),
		zap.Int("params", len(m.Params)),
	)
	return nil
}
