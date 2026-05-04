package email

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

// Chain is a Transport that delegates to an ordered list of inner transports,
// trying each in turn until one succeeds. Use it for primary/secondary/tertiary
// failover across providers.
type Chain struct {
	logger     *zap.Logger
	transports []Transport

	// OnAttempt, if non-nil, is invoked synchronously after each inner Send
	// with the index of the transport and the error it returned (nil on
	// success). Hook is intended for metrics; keep it cheap and non-blocking.
	OnAttempt func(idx int, err error)
}

// NewChain builds a Chain. Returns an error-on-Send transport if transports is
// empty (rather than panicking) so callers can construct a Chain from config
// without special-casing the zero-provider path.
func NewChain(logger *zap.Logger, transports ...Transport) *Chain {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Chain{logger: logger, transports: transports}
}

// Send tries each inner transport in order. Returns nil on first success.
// If all fail, returns the last error wrapped with ErrTransport.
func (c *Chain) Send(ctx context.Context, m Message) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if len(c.transports) == 0 {
		err := fmt.Errorf("%w: chain has no transports", ErrTransport)
		c.logger.Error("email_send_failed",
			zap.String("to", m.To),
			zap.String("subject", m.Subject),
			zap.Error(err),
		)
		return err
	}

	var lastErr error
	for idx, t := range c.transports {
		err := t.Send(ctx, m)
		if c.OnAttempt != nil {
			c.OnAttempt(idx, err)
		}
		if err == nil {
			c.logger.Info("email_sent",
				zap.Int("provider_idx", idx),
				zap.String("to", m.To),
				zap.String("subject", m.Subject),
			)
			return nil
		}
		c.logger.Warn("email_send_attempt_failed",
			zap.Int("provider_idx", idx),
			zap.String("to", m.To),
			zap.String("subject", m.Subject),
			zap.Error(err),
		)
		lastErr = err
	}

	c.logger.Error("email_send_failed",
		zap.String("to", m.To),
		zap.String("subject", m.Subject),
		zap.Int("attempts", len(c.transports)),
		zap.Error(lastErr),
	)
	return lastErr
}
