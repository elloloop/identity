package passwords

import (
	"strings"
	"testing"
)

func hasLengthIssue(issues []string) bool {
	for _, i := range issues {
		if strings.Contains(i, "at least") {
			return true
		}
	}
	return false
}

func TestValidateStrengthWithPolicy_TightensMinLength(t *testing.T) {
	// 11 chars, all classes present — passes the global 8 floor.
	const pw = "Aa1!aaaaaaa"
	if got := len([]rune(pw)); got != 11 {
		t.Fatalf("fixture length = %d, want 11", got)
	}

	if issues := ValidateStrengthWithPolicy(pw, StrengthPolicy{}); len(issues) != 0 {
		t.Fatalf("global policy should accept %q, got %v", pw, issues)
	}

	issues := ValidateStrengthWithPolicy(pw, StrengthPolicy{MinLength: 12})
	if !hasLengthIssue(issues) {
		t.Fatalf("min-12 policy should reject an 11-char password, got %v", issues)
	}

	if issues := ValidateStrengthWithPolicy("Aa1!aaaaaaaa", StrengthPolicy{MinLength: 12}); len(issues) != 0 {
		t.Fatalf("min-12 policy should accept a 12-char password, got %v", issues)
	}
}

func TestValidateStrengthWithPolicy_CannotLoosenBelowGlobal(t *testing.T) {
	// A policy asking for fewer than the global minimum is clamped up to
	// the global MinPasswordLength — tenants tighten, never loosen.
	short := strings.Repeat("Aa1!", 1) // 4 chars, all classes
	issues := ValidateStrengthWithPolicy(short, StrengthPolicy{MinLength: 2})
	if !hasLengthIssue(issues) {
		t.Fatalf("a sub-global MinLength must not loosen the floor; got %v", issues)
	}
}

func TestStrengthPolicyEffectiveMinLength(t *testing.T) {
	cases := []struct {
		in, want int
	}{
		{0, MinPasswordLength},
		{MinPasswordLength - 1, MinPasswordLength},
		{MinPasswordLength, MinPasswordLength},
		{MinPasswordLength + 5, MinPasswordLength + 5},
	}
	for _, c := range cases {
		if got := (StrengthPolicy{MinLength: c.in}).effectiveMinLength(); got != c.want {
			t.Errorf("effectiveMinLength(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}
