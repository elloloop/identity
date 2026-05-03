package email

import (
	"context"

	"go.uber.org/zap"
)

// previewLen caps how much body content gets logged in dev mode. Keeps the
// log line readable and avoids dumping huge HTML payloads.
const previewLen = 240

type logOnlyTransport struct {
	logger *zap.Logger
}

// NewLogOnly returns a Transport that logs each Send at WARN and returns nil.
// Intended for local development when no SMTP server is configured.
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
	preview := m.Text
	if preview == "" {
		preview = m.HTML
	}
	if len(preview) > previewLen {
		preview = preview[:previewLen]
	}
	l.logger.Warn("email_disabled_no_transport",
		zap.String("to", m.To),
		zap.String("subject", m.Subject),
		zap.String("preview", preview),
	)
	return nil
}
