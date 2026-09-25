package origin

import (
	"reflect"
	"testing"
)

func TestAllowlist_Allows(t *testing.T) {
	t.Parallel()

	a := NewAllowlist(
		[]string{"https://app.example.app", "http://localhost:5173"},
		[]Pattern{mustPattern(t, "https://*.previews.example.app")},
	)
	tests := []struct {
		name   string
		origin string
		want   bool
	}{
		{"exact", "https://app.example.app", true},
		{"exact_http_localhost", "http://localhost:5173", true},
		{"exact_is_case_sensitive", "https://APP.example.app", false},
		{"pattern_one_label", "https://feature-1.previews.example.app", true},
		{"pattern_mixed_case_host", "https://Feature-1.Previews.example.app", true},
		{"pattern_two_labels", "https://a.b.previews.example.app", false},
		{"pattern_bare_parent", "https://previews.example.app", false},
		{"pattern_http", "http://a.previews.example.app", false},
		{"pattern_port_mismatch", "https://a.previews.example.app:8443", false},
		{"pattern_sibling_domain", "https://a.previews.example.net", false},
		{"pattern_with_path", "https://a.previews.example.app/", false},
		{"pattern_with_query", "https://a.previews.example.app?x=1", false},
		{"pattern_with_empty_query", "https://a.previews.example.app?", false},
		{"pattern_with_fragment", "https://a.previews.example.app#x", false},
		{"pattern_with_userinfo", "https://u@a.previews.example.app", false},
		{"null", "null", false},
		{"empty", "", false},
		{"unparseable", "https://a.previews.example.app:bad", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.Allows(tt.origin); got != tt.want {
				t.Errorf("Allows(%q) = %v, want %v", tt.origin, got, tt.want)
			}
		})
	}
}

func TestAllowlist_ZeroValueAllowsNothing(t *testing.T) {
	t.Parallel()

	var a Allowlist
	for _, o := range []string{"", "https://app.example.app", "https://a.previews.example.app"} {
		if a.Allows(o) {
			t.Errorf("zero Allowlist allowed %q", o)
		}
	}
}

func TestAllowlist_ExactAndPatterns(t *testing.T) {
	t.Parallel()

	a := NewAllowlist(
		[]string{"https://app.example.app"},
		[]Pattern{mustPattern(t, "https://*.Previews.example.app:443"), mustPattern(t, "https://*.staging.example.app:8443")},
	)
	if got, want := a.Exact(), []string{"https://app.example.app"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Exact() = %v, want %v", got, want)
	}
	want := []string{"https://*.previews.example.app", "https://*.staging.example.app:8443"}
	if got := a.Patterns(); !reflect.DeepEqual(got, want) {
		t.Errorf("Patterns() = %v, want %v", got, want)
	}
}
