// Package passwords provides bcrypt password hashing and strength validation.
//
// Security:
//   - bcrypt with cost factor 12 (tunable)
//   - Constant-time comparison (built into bcrypt)
//   - No plaintext passwords ever stored or logged
package passwords

import (
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// ProductionBcryptCost is the bcrypt work factor used in production
// (≈250 ms on modern hardware). Lowering it is a security regression; the
// strength_security_test enforces it.
const ProductionBcryptCost = 12

// bcryptCost is the work factor actually used by Hash. It defaults to the
// production value and is a var (not a const) only so tests can lower it via
// SetCostForTests for speed. Production code MUST NOT mutate it.
var bcryptCost = ProductionBcryptCost

// SetCostForTests overrides the bcrypt cost factor for the duration of a
// test binary. Call ONLY from TestMain (before any tests run) or from a
// single test that immediately defers the returned restore func. It is not
// safe for concurrent use and must never be called from production code.
// Returns a restore func that resets the original cost.
func SetCostForTests(cost int) (restore func()) {
	old := bcryptCost
	bcryptCost = cost
	return func() { bcryptCost = old }
}

var errPasswordContainsNUL = errors.New("password contains NUL byte")

// Hash hashes a plaintext password using bcrypt with cost 12.
// The returned string is suitable for storage (e.g. "$2a$12$...").
func Hash(plaintext string) (string, error) {
	if strings.ContainsRune(plaintext, '\x00') {
		return "", errPasswordContainsNUL
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

// Verify checks a plaintext password against a bcrypt hash using
// bcrypt's built-in constant-time comparison to prevent timing attacks.
// Returns true if the password matches, false otherwise.
func Verify(plaintext, hash string) bool {
	if hash == "" || strings.ContainsRune(plaintext, '\x00') {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
	return err == nil
}
