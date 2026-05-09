package passwords

import (
	"strings"
	"testing"
)

func TestValidateStrength_Strong(t *testing.T) {
	issues := ValidateStrength("Str0ng!Pass#9")
	if len(issues) != 0 {
		t.Errorf("expected no issues for strong password, got %v", issues)
	}
}

func TestValidateStrength_RejectsNUL(t *testing.T) {
	issues := ValidateStrength("Str0ng!Pass#9\x00")
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "NUL") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected NUL issue, got %v", issues)
	}
}

func TestValidateStrength_TooShort(t *testing.T) {
	issues := ValidateStrength("Ab1!")
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "at least 8") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'at least 8 characters' issue, got %v", issues)
	}
}

func TestValidateStrength_TooLong(t *testing.T) {
	long := strings.Repeat("Aa1!", 40) // 160 chars
	issues := ValidateStrength(long)
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "at most 72") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'at most 72 bytes' issue, got %v", issues)
	}
}

func TestValidateStrength_NoUppercase(t *testing.T) {
	issues := ValidateStrength("lowercase1!")
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "uppercase") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected uppercase issue, got %v", issues)
	}
}

func TestValidateStrength_NoLowercase(t *testing.T) {
	issues := ValidateStrength("UPPERCASE1!")
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "lowercase") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected lowercase issue, got %v", issues)
	}
}

func TestValidateStrength_NoDigit(t *testing.T) {
	issues := ValidateStrength("NoDigits!Here")
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "digit") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected digit issue, got %v", issues)
	}
}

func TestValidateStrength_NoSpecial(t *testing.T) {
	issues := ValidateStrength("NoSpecial1Here")
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "special") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected special character issue, got %v", issues)
	}
}

func TestValidateStrength_CommonPassword(t *testing.T) {
	commonCases := []string{"password", "12345678", "Password", "QWERTY"}
	for _, pw := range commonCases {
		issues := ValidateStrength(pw)
		found := false
		for _, issue := range issues {
			if strings.Contains(issue, "too common") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected 'too common' issue for %q, got %v", pw, issues)
		}
	}
}

func TestValidateStrength_Empty(t *testing.T) {
	issues := ValidateStrength("")
	if len(issues) == 0 {
		t.Error("expected issues for empty password")
	}
	// Should at least flag length, uppercase, lowercase, digit, special
	if len(issues) < 5 {
		t.Errorf("expected at least 5 issues for empty password, got %d: %v", len(issues), issues)
	}
}

func TestValidateStrength_AllRulesFail(t *testing.T) {
	// "pass" is < 8 chars, no uppercase, no digit, no special, and is common
	issues := ValidateStrength("pass")
	expectedSubstrings := []string{
		"at least 8",
		"uppercase",
		"digit",
		"special",
		"too common",
	}
	for _, expected := range expectedSubstrings {
		found := false
		for _, issue := range issues {
			if strings.Contains(issue, expected) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected issue containing %q, got %v", expected, issues)
		}
	}
}

func TestValidateStrength_ExactMinLength(t *testing.T) {
	// Exactly 8 chars, meets all rules
	issues := ValidateStrength("Abcde1!x")
	for _, issue := range issues {
		if strings.Contains(issue, "at least 8") {
			t.Errorf("password of exactly 8 chars should not fail min length check, got %v", issues)
		}
	}
}

func TestValidateStrength_ExactMaxLength(t *testing.T) {
	base := "Aa1!" + strings.Repeat("x", 68)
	issues := ValidateStrength(base)
	for _, issue := range issues {
		if strings.Contains(issue, "at most 72") {
			t.Errorf("password of exactly 72 bytes should not fail max length check, got %v", issues)
		}
	}
}
