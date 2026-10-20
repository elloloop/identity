package email

import (
	"context"

	"go.uber.org/zap"
)

type logOnlyTransport struct {
	logger *zap.Logger
}

// NewLogOnly returns a Transport that logs each Send at WARN and returns nil.
// It is the transport when no SMTP server is configured, and the last link of
// an SMTP chain whose providers all failed, so it runs in production too. The
// line records that a message was dropped, never its body (sign-in codes,
// magic links and reset links are bearer credentials) or the full address.
func NewLogOnly(logger *zap.Logger) Transport {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &logOnlyTransport{logger: logger}
}

func (l *logOnlyTransport) Send(_ context.Context, m Message) error {
	if err := m.Validate(); err != nil {
		return err
	}
	l.logger.Warn(
		"email_disabled_no_transport",
		zap.String("to", Redact(m.To)),
		zap.String("subject", m.Subject),
		zap.Int("text_bytes", len(m.Text)),
		zap.Int("html_bytes", len(m.HTML)),
	)
	return nil
}
