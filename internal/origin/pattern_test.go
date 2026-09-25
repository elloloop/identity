package origin

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

func mustPattern(t *testing.T, raw string) Pattern {
	t.Helper()
	p, err := ParsePattern(mustURL(t, raw))
	if err != nil {
		t.Fatalf("ParsePattern(%q): %v", raw, err)
	}
	return p
}

func TestIsPattern(t *testing.T) {
	t.Parallel()

	for entry, want := range map[string]bool{
		"https://*.previews.example.app": true,
		"*":                              true,
		"https://app.example.app":        false,
		"":                               false,
	} {
		if got := IsPattern(entry); got != want {
			t.Errorf("IsPattern(%q) = %v, want %v", entry, got, want)
		}
	}
}

func TestParsePattern_Rejections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw     string
		wantErr error
	}{
		{"*", ErrPatternScheme},
		{"*.com", ErrPatternScheme},
		{"http://*.previews.example.app", ErrPatternScheme},
		{"wss://*.previews.example.app", ErrPatternScheme},
		{"https://*", ErrPatternParentShort},
		{"https://*.app", ErrPatternParentShort},
		{"https://a.*.example.app", ErrPatternLabel},
		{"https://pr-*.example.app", ErrPatternLabel},
		{"https://*pr.example.app", ErrPatternLabel},
		{"https://*.previews.example.app/*", ErrPatternLabel},
		{"https://*.previews.example.app/?q=*", ErrPatternLabel},
		{"https://*.*.example.app", ErrPatternParentLabel},
		{"https://*.example..app", ErrPatternParentLabel},
		{"https://*.example-.app", ErrPatternParentLabel},
		{"https://*.exa_mple.app", ErrPatternParentLabel},
		{"https://*." + strings.Repeat("a", maxLabelLen+1) + ".app", ErrPatternParentLabel},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			_, err := ParsePattern(mustURL(t, tt.raw))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ParsePattern(%q) error = %v, want %v", tt.raw, err, tt.wantErr)
			}
		})
	}
}

func TestParsePattern_Canonical(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"https://*.previews.example.app":      "https://*.previews.example.app",
		"https://*.previews.example.app/":     "https://*.previews.example.app",
		"HTTPS://*.Previews.Example.APP":      "https://*.previews.example.app",
		"https://*.previews.example.app:443":  "https://*.previews.example.app",
		"https://*.previews.example.app:8443": "https://*.previews.example.app:8443",
		"https://*.xn--bcher-kva.example":     "https://*.xn--bcher-kva.example",
	}
	for raw, want := range tests {
		if got := mustPattern(t, raw).String(); got != want {
			t.Errorf("ParsePattern(%q).String() = %q, want %q", raw, got, want)
		}
	}
}

func TestPattern_Matches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		target  string
		want    bool
	}{
		{"one_label", "https://*.previews.example.app", "https://feature-1.previews.example.app", true},
		{"one_char_label", "https://*.previews.example.app", "https://a.previews.example.app", true},
		{"max_len_label", "https://*.previews.example.app", "https://" + strings.Repeat("a", maxLabelLen) + ".previews.example.app", true},
		{"over_max_len_label", "https://*.previews.example.app", "https://" + strings.Repeat("a", maxLabelLen+1) + ".previews.example.app", false},
		{"two_labels", "https://*.previews.example.app", "https://a.b.previews.example.app", false},
		{"bare_parent", "https://*.previews.example.app", "https://previews.example.app", false},
		{"empty_label", "https://*.previews.example.app", "https://.previews.example.app", false},
		{"http_scheme", "https://*.previews.example.app", "http://a.previews.example.app", false},
		{"port_mismatch", "https://*.previews.example.app", "https://a.previews.example.app:8443", false},
		{"explicit_default_port", "https://*.previews.example.app", "https://a.previews.example.app:443", true},
		{"pattern_port", "https://*.previews.example.app:8443", "https://a.previews.example.app:8443", true},
		{"pattern_port_omitted_by_target", "https://*.previews.example.app:8443", "https://a.previews.example.app", false},
		{"mixed_case_host", "https://*.previews.example.app", "https://Feature-1.PREVIEWS.Example.app", true},
		{"suffix_lookalike", "https://*.previews.example.app", "https://a.xpreviews.example.app", false},
		{"sibling_domain", "https://*.previews.example.app", "https://a.previews.example.net", false},
		{"trailing_dot", "https://*.previews.example.app", "https://a.previews.example.app.", false},
		{"underscore", "https://*.previews.example.app", "https://a_b.previews.example.app", false},
		{"trailing_hyphen", "https://*.previews.example.app", "https://a-.previews.example.app", false},
		{"wildcard_literal", "https://*.previews.example.app", "https://*.previews.example.app", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mustPattern(t, tt.pattern).Matches(mustURL(t, tt.target)); got != tt.want {
				t.Errorf("%q.Matches(%q) = %v, want %v", tt.pattern, tt.target, got, tt.want)
			}
		})
	}
}

func TestEffectivePort(t *testing.T) {
	t.Parallel()

	for raw, want := range map[string]string{
		"https://a.example.app":      "443",
		"https://a.example.app:8443": "8443",
		"http://a.example.app":       "80",
		"http://a.example.app:8080":  "8080",
	} {
		if got := EffectivePort(mustURL(t, raw)); got != want {
			t.Errorf("EffectivePort(%q) = %q, want %q", raw, got, want)
		}
	}
}
