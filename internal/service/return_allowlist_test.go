package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/elloloop/identity/internal/origin"
)

func mustReturnAllowlist(t *testing.T, csv string) ReturnAllowlist {
	t.Helper()
	a, err := ParseReturnAllowlist(csv)
	if err != nil {
		t.Fatalf("ParseReturnAllowlist(%q): %v", csv, err)
	}
	return a
}

func TestParseReturnAllowlist(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		csv          string
		wantEnabled  bool
		wantEntries  int
		wantPatterns int
	}{
		{"empty", "", false, 0, 0},
		{"whitespace_only", "  ,  , ", false, 0, 0},
		{"single", "https://app.example.com/", true, 1, 0},
		{"multiple_trimmed", " https://a.test/ , https://b.test/ ", true, 2, 0},
		{"pattern_only", "https://*.previews.example.app", true, 0, 1},
		{"mixed", "https://app.example.app/auth, https://*.previews.example.app/auth", true, 1, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := mustReturnAllowlist(t, tt.csv)
			if a.Enabled() != tt.wantEnabled {
				t.Errorf("Enabled() = %v, want %v", a.Enabled(), tt.wantEnabled)
			}
			if len(a.Entries()) != tt.wantEntries {
				t.Errorf("len(Entries()) = %d, want %d", len(a.Entries()), tt.wantEntries)
			}
			if len(a.Patterns()) != tt.wantPatterns {
				t.Errorf("len(Patterns()) = %d, want %d", len(a.Patterns()), tt.wantPatterns)
			}
		})
	}
}

func TestParseReturnAllowlist_EntriesAndCanonicalPatterns(t *testing.T) {
	t.Parallel()

	a := mustReturnAllowlist(t, "https://app.example.app, https://*.previews.example.app/auth")
	if got := a.Entries(); len(got) != 1 || got[0] != "https://app.example.app" {
		t.Errorf("Entries() = %v", got)
	}
	if got := a.Patterns(); len(got) != 1 || got[0] != "https://*.previews.example.app/auth" {
		t.Errorf("Patterns() = %v", got)
	}

	canonical := mustReturnAllowlist(t, "HTTPS://*.Previews.Example.app:443/auth")
	if got := canonical.Patterns(); len(got) != 1 || got[0] != "https://*.previews.example.app/auth" {
		t.Errorf("Patterns() is not canonical: %v", got)
	}
}

func TestParseReturnAllowlist_RejectsInvalidPatterns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		entry   string
		wantErr error
	}{
		{"*", origin.ErrPatternScheme},
		{"*.com", origin.ErrPatternScheme},
		{"http://*.previews.example.app", origin.ErrPatternScheme},
		{"https://*", origin.ErrPatternParentShort},
		{"https://*.app", origin.ErrPatternParentShort},
		{"https://a.*.example.app", origin.ErrPatternLabel},
		{"https://pr-*.example.app", origin.ErrPatternLabel},
		{"https://*.previews.example.app/auth/*", origin.ErrPatternLabel},
		{"https://*.*.example.app", origin.ErrPatternParentLabel},
		{"https://*.-bad.example.app", origin.ErrPatternParentLabel},
		{"https://*.vercel.app/auth", origin.ErrPatternParentPublicSuffix},
		{"https://*.pages.dev/auth", origin.ErrPatternParentPublicSuffix},
		{"https://*.co.uk", origin.ErrPatternParentPublicSuffix},
		{"https://*.0.0.1/auth", origin.ErrPatternParentNumeric},
	}
	for _, tt := range tests {
		t.Run(tt.entry, func(t *testing.T) {
			_, err := ParseReturnAllowlist("https://app.example.app," + tt.entry)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ParseReturnAllowlist(%q) error = %v, want %v", tt.entry, err, tt.wantErr)
			}
		})
	}
}

func TestParseReturnAllowlist_RejectsPatternQueryFragmentUserinfo(t *testing.T) {
	t.Parallel()

	for _, entry := range []string{
		"https://*.previews.example.app/auth?next=1",
		"https://*.previews.example.app/auth?",
		"https://*.previews.example.app/auth#frag",
		"https://user@*.previews.example.app/auth",
	} {
		if _, err := ParseReturnAllowlist(entry); err == nil {
			t.Errorf("ParseReturnAllowlist(%q) accepted an invalid pattern", entry)
		}
	}
}

func TestReturnAllowlist_Allows(t *testing.T) {
	t.Parallel()

	a := mustReturnAllowlist(t, "https://app.example.com,https://other.example.org/auth")
	tests := []struct {
		returnTo string
		want     bool
	}{
		{"https://app.example.com/", true},
		{"https://app.example.com/auth/finish?next=/home", true},
		{"https://other.example.org/auth", true},
		{"https://other.example.org/auth/callback", true},
		{"https://other.example.org/authentication", false},
		{"https://other.example.org/auth/../unrelated", false},
		{"https://evil.example.net/", false},
		{"https://app.example.com.evil.net/", false},
		{"https://app.example.com.attacker.tld/", false},
		{"https://app.example.com@evil.example.net/", false},
		{"http://app.example.com/", false},
		{`https://other.example.org/auth/..\evil`, false},
		{`https://other.example.org/auth\..\evil`, false},
		{`https://app.example.com\@evil.example.net/`, false},
		{"https://other.example.org/auth/%2e%2e/unrelated", false},
		{"https://other.example.org/auth/%2E%2E/unrelated", false},
		{"https://other.example.org/auth/\tx", false},
		{"https://other.example.org/auth/\nx", false},
		{"", false},
		{"   ", false},
	}
	for _, tt := range tests {
		if got := a.Allows(tt.returnTo); got != tt.want {
			t.Errorf("Allows(%q) = %v, want %v", tt.returnTo, got, tt.want)
		}
	}
}

func TestReturnAllowlist_AllowsPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		pattern  string
		returnTo string
		want     bool
	}{
		{"one_label_match", "https://*.previews.example.app", "https://feature-x.previews.example.app/auth/complete", true},
		{"two_label_host_rejected", "https://*.previews.example.app", "https://a.b.previews.example.app/", false},
		{"bare_parent_rejected", "https://*.previews.example.app", "https://previews.example.app/", false},
		{"http_against_https_rejected", "https://*.previews.example.app", "http://a.previews.example.app/", false},
		{"port_mismatch_rejected", "https://*.previews.example.app", "https://a.previews.example.app:8443/", false},
		{"explicit_default_port_matches", "https://*.previews.example.app", "https://a.previews.example.app:443/", true},
		{"pattern_port_matches", "https://*.previews.example.app:8443", "https://a.previews.example.app:8443/", true},
		{"pattern_port_requires_it", "https://*.previews.example.app:8443", "https://a.previews.example.app/", false},
		{"path_prefix_enforced_match", "https://*.previews.example.app/auth", "https://a.previews.example.app/auth/complete", true},
		{"path_prefix_enforced_reject", "https://*.previews.example.app/auth", "https://a.previews.example.app/other", false},
		{"path_prefix_sibling_reject", "https://*.previews.example.app/auth", "https://a.previews.example.app/authx", false},
		{"mixed_case_host", "https://*.Previews.Example.app", "https://Feature-X.PREVIEWS.example.APP/", true},
		{"sibling_domain_rejected", "https://*.previews.example.app", "https://a.previews.example.net/", false},
		{"suffix_lookalike_rejected", "https://*.previews.example.app", "https://a.evilpreviews.example.app/", false},
		{"parent_as_label_rejected", "https://*.previews.example.app", "https://a.previews.example.app.evil.example/", false},
		{"empty_label_rejected", "https://*.previews.example.app", "https://.previews.example.app/", false},
		{"underscore_label_rejected", "https://*.previews.example.app", "https://a_b.previews.example.app/", false},
		{"leading_hyphen_rejected", "https://*.previews.example.app", "https://-a.previews.example.app/", false},
		{"userinfo_rejected", "https://*.previews.example.app", "https://a.previews.example.app@evil.example/", false},
		{"trailing_dot_rejected", "https://*.previews.example.app", "https://a.previews.example.app./", false},
		{"backslash_escape_rejected", "https://*.previews.example.app/auth", `https://a.previews.example.app/auth/..\x`, false},
		{"dot_segment_escape_rejected", "https://*.previews.example.app/auth", "https://a.previews.example.app/auth/../x", false},
		{"encoded_dot_segment_escape_rejected", "https://*.previews.example.app/auth", "https://a.previews.example.app/auth/%2e%2e/x", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := mustReturnAllowlist(t, tt.pattern)
			if got := a.Allows(tt.returnTo); got != tt.want {
				t.Errorf("pattern %q Allows(%q) = %v, want %v", tt.pattern, tt.returnTo, got, tt.want)
			}
		})
	}
}

func TestReturnAllowlist_IgnoresMalformedExactEntries(t *testing.T) {
	t.Parallel()

	for _, entry := range []string{
		"https://app.example.com/callback?source=oauth",
		"https://app.example.com/callback#fragment",
		"app.example.com/callback",
		"ftp://app.example.com/callback",
	} {
		a := mustReturnAllowlist(t, entry)
		if a.Allows("https://app.example.com/callback") {
			t.Fatalf("entry %q allowed a return_to", entry)
		}
		if a.Enabled() {
			t.Errorf("entry %q: a list with no usable entry reports Enabled", entry)
		}
		if got := a.Ignored(); len(got) != 1 || got[0] != entry {
			t.Errorf("entry %q: Ignored() = %v", entry, got)
		}
	}
}

func TestReturnAllowlist_IgnoredEntriesDoNotHideUsableOnes(t *testing.T) {
	t.Parallel()

	a := mustReturnAllowlist(t, "app.example.app, https://app.example.app/auth")
	if !a.Enabled() || !a.Allows("https://app.example.app/auth/complete") {
		t.Fatal("usable entry not honoured next to an ignored one")
	}
	if got := a.Entries(); len(got) != 1 || got[0] != "https://app.example.app/auth" {
		t.Errorf("Entries() = %v", got)
	}
	if got := a.Ignored(); len(got) != 1 || got[0] != "app.example.app" {
		t.Errorf("Ignored() = %v", got)
	}
}

func TestReturnAllowlist_EmptyDeniesAll(t *testing.T) {
	t.Parallel()
	a := mustReturnAllowlist(t, "")
	if a.Allows("https://anything.test/") {
		t.Error("empty allowlist allowed a return_to")
	}
}

// TestParseReturnAllowlist_NeverEchoesCredentials pins that neither a pattern
// boot error nor an ignored entry reported for the startup warning carries a
// password from the configured value.
func TestParseReturnAllowlist_NeverEchoesCredentials(t *testing.T) {
	t.Parallel()

	const secret = "s3cret-pw"
	for _, entry := range []string{
		"https://user:" + secret + "@*.previews.example.app/auth",
		"https://user:" + secret + "@*.previews.example.app/%zz",
	} {
		_, err := ParseReturnAllowlist(entry)
		if err == nil {
			t.Fatalf("entry with userinfo accepted: %q", entry)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error leaks the password: %v", err)
		}
	}

	a := mustReturnAllowlist(t, strings.Join([]string{
		"https://user:" + secret + "@app.example.app/auth",
		"user:" + secret + "@app.example.app",
		"https://user:" + secret + "@app.example.app/%zz",
	}, ","))
	ignored := a.Ignored()
	if len(ignored) != 3 {
		t.Fatalf("Ignored() = %v, want 3 entries", ignored)
	}
	for _, e := range ignored {
		if strings.Contains(e, secret) {
			t.Errorf("ignored entry leaks the password: %q", e)
		}
	}
}
