package passwords

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	// MinPasswordLength is the minimum acceptable password length.
	MinPasswordLength = 8
	// MaxPasswordLength prevents bcrypt DoS (bcrypt truncates at 72 bytes anyway).
	MaxPasswordLength = 128
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

// ValidateStrength validates password strength and returns a list of issues.
// An empty slice means the password meets all requirements.
func ValidateStrength(password string) []string {
	var issues []string

	if len(password) < MinPasswordLength {
		issues = append(issues, fmt.Sprintf("Password must be at least %d characters", MinPasswordLength))
	}

	if len(password) > MaxPasswordLength {
		issues = append(issues, fmt.Sprintf("Password must be at most %d characters", MaxPasswordLength))
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
