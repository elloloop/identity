package totp

import (
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyCode_InvalidBase32Secret hits the ValidateCustom error branch by
// supplying a 6-digit numeric code paired with a secret that is not valid
// base32, which makes the underlying library return an error.
func TestVerifyCode_InvalidBase32Secret(t *testing.T) {
	t.Parallel()
	// "111111111" — '1' is not valid in RFC 4648 base32 alphabet.
	assert.False(t, VerifyCode("111111111", "123456"))
}

// TestVerifyCode_DriftWindow exercises the +/-1 skew window: codes one period
// ahead and one period behind must verify, but two periods away must not.
func TestVerifyCode_DriftWindow(t *testing.T) {
	t.Parallel()
	secret, err := GenerateSecret()
	require.NoError(t, err)

	now := time.Now()
	gen := func(at time.Time) string {
		c, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{
			Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
		})
		require.NoError(t, err)
		return c
	}

	assert.True(t, VerifyCode(secret, gen(now)), "current code")
	assert.True(t, VerifyCode(secret, gen(now.Add(-30*time.Second))), "previous window")
	assert.True(t, VerifyCode(secret, gen(now.Add(30*time.Second))), "next window")

	// Two periods away should not validate (outside skew=1).
	farPast := gen(now.Add(-90 * time.Second))
	farFuture := gen(now.Add(90 * time.Second))
	// In rare cases the same digits collide; guard against false negatives.
	if farPast != gen(now) {
		assert.False(t, VerifyCode(secret, farPast), "two windows behind must fail")
	}
	if farFuture != gen(now) {
		assert.False(t, VerifyCode(secret, farFuture), "two windows ahead must fail")
	}
}

// TestVerifyCode_StripsWhitespaceAndDashes confirms the digit-only normalizer
// accepts user-typed codes with spaces or punctuation.
func TestVerifyCode_StripsWhitespaceAndDashes(t *testing.T) {
	t.Parallel()
	secret, err := GenerateSecret()
	require.NoError(t, err)

	code, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	require.Len(t, code, 6)

	// Insert a space in the middle, e.g. "123 456".
	spaced := code[:3] + " " + code[3:]
	assert.True(t, VerifyCode(secret, spaced))

	// Hyphenated.
	hyphenated := code[:3] + "-" + code[3:]
	assert.True(t, VerifyCode(secret, hyphenated))
}

// TestVerifyCode_WrongLength confirms codes with 5 or 7 digits are rejected.
func TestVerifyCode_WrongLength(t *testing.T) {
	t.Parallel()
	secret, err := GenerateSecret()
	require.NoError(t, err)

	assert.False(t, VerifyCode(secret, "12345"))
	assert.False(t, VerifyCode(secret, "1234567"))
}

// TestGenerateRecoveryCodes_NegativeN ensures n<=0 returns nil cleanly.
func TestGenerateRecoveryCodes_NegativeN(t *testing.T) {
	t.Parallel()
	assert.Nil(t, GenerateRecoveryCodes(-1))
	assert.Nil(t, GenerateRecoveryCodes(-100))
}
