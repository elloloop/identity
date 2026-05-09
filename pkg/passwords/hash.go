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

// bcryptCost is the work factor for bcrypt hashing. 12 is a good balance of
// security and speed (≈250 ms on modern hardware).
const bcryptCost = 12

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
