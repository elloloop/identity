package service

import "testing"

func TestParseReturnAllowlist(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		csv         string
		wantEnabled bool
		wantLen     int
	}{
		{"empty", "", false, 0},
		{"whitespace_only", "  ,  , ", false, 0},
		{"single", "https://app.example.com/", true, 1},
		{"multiple_trimmed", " https://a.test/ , https://b.test/ ", true, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := ParseReturnAllowlist(tt.csv)
			if a.Enabled() != tt.wantEnabled {
				t.Errorf("Enabled() = %v, want %v", a.Enabled(), tt.wantEnabled)
			}
			if len(a.Entries()) != tt.wantLen {
				t.Errorf("len(Entries()) = %d, want %d", len(a.Entries()), tt.wantLen)
			}
		})
	}
}

func TestReturnAllowlist_Allows(t *testing.T) {
	t.Parallel()

	a := ParseReturnAllowlist("https://app.example.com/,https://other.example.org/auth")
	tests := []struct {
		returnTo string
		want     bool
	}{
		{"https://app.example.com/", true},
		{"https://app.example.com/auth/finish?next=/home", true}, // prefix match
		{"https://other.example.org/auth", true},
		{"https://other.example.org/auth/callback", true},
		{"https://evil.example.net/", false},
		{"https://app.example.com.evil.net/", false}, // not a prefix of an entry
		{"http://app.example.com/", false},           // scheme differs
		{"", false},
		{"   ", false},
	}
	for _, tt := range tests {
		if got := a.Allows(tt.returnTo); got != tt.want {
			t.Errorf("Allows(%q) = %v, want %v", tt.returnTo, got, tt.want)
		}
	}
}

func TestReturnAllowlist_EmptyDeniesAll(t *testing.T) {
	t.Parallel()
	a := ParseReturnAllowlist("")
	if a.Allows("https://anything.test/") {
		t.Error("empty allowlist allowed a return_to")
	}
}
