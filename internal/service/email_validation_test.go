package service

import (
	"strings"
	"testing"
)

// TestValidateEmailFormat covers every guard validateEmailFormat
// enforces, plus the happy positives that exercise the parser path.
// Lives in the service package so it directly drives the unexported
// helper (the e2e tests in tests/e2e/ also pin the same behaviour
// through HTTP, but those don't contribute to internal/ coverage when
// CI runs without the e2e tag).
func TestValidateEmailFormat(t *testing.T) {
	t.Parallel()

	type tc struct {
		name    string
		addr    string
		wantErr bool
	}
	cases := []tc{
		// Reject paths.
		{name: "empty", addr: "", wantErr: true},
		{name: "just_at", addr: "@", wantErr: true},
		{name: "local_only", addr: "alice@", wantErr: true},
		{name: "domain_only", addr: "@example.com", wantErr: true},
		{name: "no_at_sign", addr: "alice.example.com", wantErr: true},
		{name: "no_tld_in_domain", addr: "alice@example", wantErr: true},
		{name: "trailing_dot_only", addr: "alice@example.", wantErr: true},
		{name: "leading_dot_local", addr: ".alice@example.com", wantErr: true},
		{name: "trailing_dot_local", addr: "alice.@example.com", wantErr: true},
		{name: "leading_dot_domain", addr: "alice@.example.com", wantErr: true},
		{name: "spaces_in_local", addr: "ali ce@example.com", wantErr: true},
		{name: "spaces_in_domain", addr: "alice@exam ple.com", wantErr: true},
		{name: "tab_anywhere", addr: "alice\t@example.com", wantErr: true},
		{name: "newline_anywhere", addr: "alice@example.com\n", wantErr: true},
		{name: "double_at", addr: "alice@@example.com", wantErr: true},
		{name: "display_name_form", addr: "Alice <a@x.com>", wantErr: true},

		// Accept paths.
		{name: "simple", addr: "alice@example.com", wantErr: false},
		{name: "with_dot_local", addr: "alice.smith@example.com", wantErr: false},
		{name: "with_plus_tag", addr: "alice+tag@example.com", wantErr: false},
		{name: "subdomain", addr: "alice@mail.example.com", wantErr: false},
		{name: "short_tld", addr: "a@b.co", wantErr: false},
		{name: "multi_label_tld", addr: "alice@example.co.uk", wantErr: false},
		{name: "long_local_part", addr: strings.Repeat("a", 60) + "@example.com", wantErr: false},
		{name: "unicode_local_part", addr: "alïce@example.com", wantErr: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			err := validateEmailFormat(c.addr)
			if c.wantErr && err == nil {
				t.Fatalf("%q: expected error, got nil", c.addr)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("%q: unexpected error: %v", c.addr, err)
			}
		})
	}
}
