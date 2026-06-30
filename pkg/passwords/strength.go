package passwords

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	// MinPasswordLength is the minimum acceptable password length.
	MinPasswordLength = 8
	// MaxPasswordLength is bcrypt's maximum password byte length.
	MaxPasswordLength = 72
)

// commonPasswords is the top-100 common passwords blocklist.
var commonPasswords = map[string]struct{}{
	"123456": {}, "password": {}, "12345678": {}, "qwerty": {}, "123456789": {},
	"12345": {}, "1234": {}, "111111": {}, "1234567": {}, "dragon": {},
	"123123": {}, "baseball": {}, "abc123": {}, "football": {}, "monkey": {},
	"letmein": {}, "696969": {}, "shadow": {}, "master": {}, "666666": {},
	"qwertyuiop": {}, "123321": {}, "mustang": {}, "1234567890": {}, "michael": {},
	"654321": {}, "pussy": {}, "superman": {}, "1qaz2wsx": {}, "7777777": {},
	"fuckyou": {}, "121212": {}, "000000": {}, "qazwsx": {}, "123qwe": {},
	"killer": {}, "trustno1": {}, "jordan": {}, "jennifer": {}, "zxcvbnm": {},
	"asdfgh": {}, "hunter": {}, "buster": {}, "soccer": {}, "harley": {},
	"batman": {}, "andrew": {}, "tigger": {}, "sunshine": {}, "iloveyou": {},
	"fuckme": {}, "charlie": {}, "robert": {}, "thomas": {}, "hockey": {},
	"ranger": {}, "daniel": {}, "starwars": {}, "klaster": {}, "112233": {},
	"george": {}, "asshole": {}, "computer": {}, "michelle": {}, "jessica": {},
	"pepper": {}, "1111": {}, "zxcvbn": {}, "555555": {}, "11111111": {},
	"131313": {}, "freedom": {}, "777777": {}, "pass": {}, "fuck": {},
	"maggie": {}, "159753": {}, "aaaaaa": {}, "ginger": {}, "princess": {},
	"joshua": {}, "cheese": {}, "amanda": {}, "summer": {}, "love": {},
	"ashley": {}, "6969": {}, "nicole": {}, "chelsea": {}, "biteme": {},
	"matthew": {}, "access": {}, "yankees": {}, "987654321": {}, "dallas": {},
	"austin": {}, "thunder": {}, "taylor": {}, "matrix": {}, "minecraft": {},
	"password1": {}, "password123": {}, "welcome": {}, "welcome1": {}, "p@ssw0rd": {},
	"admin": {}, "admin123": {}, "root": {}, "toor": {}, "changeme": {},
}

// specialChars is the set of characters considered "special" for strength validation.
const specialChars = `!@#$%^&*()_+-=[]{};':"\|,.<>/?` + "`~"

// StrengthPolicy tunes ValidateStrengthWithPolicy for a single caller —
// typically a tenant's per-org password rules. The zero value is the global
// default: MinLength falls back to MinPasswordLength and the four character
// classes (upper/lower/digit/special) are required. A tenant may only ever
// tighten the global baseline, never loosen it: MinLength below
// MinPasswordLength is clamped up to MinPasswordLength, and the global
// character-class rules are always enforced.
type StrengthPolicy struct {
	// MinLength is the tenant's minimum length. 0 means "use the global
	// MinPasswordLength"; any value below MinPasswordLength is treated as
	// MinPasswordLength (tenants tighten, never loosen).
	MinLength int
}

// effectiveMinLength returns the larger of the policy's MinLength and the
// global MinPasswordLength so a tenant can only ever raise the floor.
func (p StrengthPolicy) effectiveMinLength() int {
	if p.MinLength > MinPasswordLength {
		return p.MinLength
	}
	return MinPasswordLength
}

// ValidateStrength validates password strength against the global default
// policy and returns a list of issues. An empty slice means the password
// meets all requirements.
func ValidateStrength(password string) []string {
	return ValidateStrengthWithPolicy(password, StrengthPolicy{})
}

// ValidateStrengthWithPolicy validates password strength against a
// per-tenant StrengthPolicy and returns a list of issues. An empty slice
// means the password meets all requirements. The policy can only tighten
// the global rules (see StrengthPolicy).
func ValidateStrengthWithPolicy(password string, policy StrengthPolicy) []string {
	var issues []string

	minLen := policy.effectiveMinLength()
	if len(password) < minLen {
		issues = append(issues, fmt.Sprintf("Password must be at least %d characters", minLen))
	}

	if len(password) > MaxPasswordLength {
		issues = append(issues, fmt.Sprintf("Password must be at most %d bytes", MaxPasswordLength))
	}

	if strings.ContainsRune(password, '\x00') {
		issues = append(issues, "Password must not contain NUL bytes")
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case strings.ContainsRune(specialChars, ch):
			hasSpecial = true
		}
	}

	if !hasUpper {
		issues = append(issues, "Password must contain at least one uppercase letter")
	}

	if !hasLower {
		issues = append(issues, "Password must contain at least one lowercase letter")
	}

	if !hasDigit {
		issues = append(issues, "Password must contain at least one digit")
	}

	if !hasSpecial {
		issues = append(issues, "Password must contain at least one special character")
	}

	if _, found := commonPasswords[strings.ToLower(password)]; found {
		issues = append(issues, "Password is too common")
	}

	return issues
}
