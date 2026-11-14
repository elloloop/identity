package service

import (
	"context"
	"crypto/subtle"
	"errors"

	"go.uber.org/zap"
)

// oneTimeCode is a stored emailed or texted code, as one guess at it sees
// it. The emailed sign-in code, the phone code and the recovery-email code
// are checked the same way, by settleGuess.
type oneTimeCode struct {
	// kind labels the code in logs ("email_login_code", "phone_code",
	// "recovery_email_code").
	kind string
	hash string
	// attempts is how many guesses the code has taken, this one included;
	// maxAttempts caps them (0 = no cap).
	attempts, maxAttempts int64
	// invalid is the code's one refusal, whatever went wrong.
	invalid error
	// consume spends the code single-use, returning invalid when it is
	// already spent.
	consume func(context.Context) error
}

// settleGuess compares guess with c in constant time and spends c: a right
// guess consumes it, so a replay racing it loses, and a wrong guess that used
// c's last attempt burns it. right reports whether the guess matched; err is
// nil only for a right guess this caller consumed, and c.invalid otherwise.
func (s *AuthService) settleGuess(ctx context.Context, c oneTimeCode, guess string, logFields ...zap.Field) (right bool, err error) {
	if subtle.ConstantTimeCompare([]byte(c.hash), []byte(sha256Hex(guess))) == 1 {
		if err := c.consume(ctx); err != nil {
			return true, c.invalid
		}
		return true, nil
	}
	if c.maxAttempts > 0 && c.attempts >= c.maxAttempts {
		if err := c.consume(ctx); err != nil && !errors.Is(err, c.invalid) {
			s.logger.Warn(c.kind+"_lock_failed", append(logFields, zap.Error(err))...)
		}
	}
	return false, c.invalid
}
