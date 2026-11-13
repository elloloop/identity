package email

import (
	"context"

	"go.uber.org/zap"
)

type logOnlyTransport struct {
	logger *zap.Logger
}

// NewLogOnly returns a Transport that logs each Send at WARN and returns nil.
// It is the transport when no SMTP server is configured, so a nil error from
// it means nothing was sent. The line records that a message was dropped,
// with the fields ContextWithLogFields put on ctx, never its body (sign-in
// codes, magic links and reset links are bearer credentials) or the full
// address.
func NewLogOnly(logger *zap.Logger) Transport {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &logOnlyTransport{logger: logger}
}

func (l *logOnlyTransport) Send(ctx context.Context, m Message) error {
	if err := m.Validate(); err != nil {
		return err
	}
	l.logger.With(logFieldsFrom(ctx)...).Warn(
		"email_disabled_no_transport",
		zap.String("to", Redact(m.To)),
		zap.String("subject", m.Subject),
		zap.Int("text_bytes", len(m.Text)),
		zap.Int("html_bytes", len(m.HTML)),
	)
	return nil
}
