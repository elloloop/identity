package origin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustAllowlist(t *testing.T, entries ...string) Allowlist {
	t.Helper()
	a, err := ValidateAllowedOrigins(entries, true)
	require.NoError(t, err)
	return a
}

func TestAllowlist_Allows(t *testing.T) {
	t.Parallel()

	a := mustAllowlist(t, "https://app.example.app", "http://localhost:5173", "https://*.previews.example.app")
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
		{"pattern_upper_scheme", "HTTPS://a.previews.example.app", false},
		{"pattern_port_mismatch", "https://a.previews.example.app:8443", false},
		{"pattern_explicit_default_port", "https://a.previews.example.app:443", true},
		{"pattern_sibling_domain", "https://a.previews.example.net", false},
		{"pattern_with_path", "https://a.previews.example.app/", false},
		{"pattern_with_query", "https://a.previews.example.app?x=1", false},
		{"pattern_with_empty_query", "https://a.previews.example.app?", false},
		{"pattern_with_fragment", "https://a.previews.example.app#x", false},
		{"pattern_with_empty_fragment", "https://a.previews.example.app#", false},
		{"pattern_with_userinfo", "https://u@a.previews.example.app", false},
		{"null", "null", false},
		{"empty", "", false},
		{"unparseable", "https://a.previews.example.app:bad", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, a.Allows(tt.origin), tt.origin)
		})
	}
}

func TestAllowlist_ZeroValueAllowsNothing(t *testing.T) {
	t.Parallel()

	var a Allowlist
	for _, o := range []string{"", "https://app.example.app", "https://a.previews.example.app"} {
		assert.False(t, a.Allows(o), o)
	}
}

func TestAllowlist_ExactAndPatterns(t *testing.T) {
	t.Parallel()

	a := mustAllowlist(t, "https://A.example.app", "https://*.Previews.example.app:443", "https://*.staging.example.app:8443")
	assert.Equal(t, []string{"https://A.example.app"}, a.Exact(), "exact entries keep their case")
	assert.Equal(t, []string{"https://*.previews.example.app", "https://*.staging.example.app:8443"}, a.Patterns(),
		"patterns are canonicalized")

	exact := a.Exact()
	exact[0] = "https://mutated.example.app"
	assert.Equal(t, []string{"https://A.example.app"}, a.Exact(), "Exact returns a copy")
}

func TestValidateAllowedOrigins_StructuredInput(t *testing.T) {
	t.Parallel()

	out, err := ValidateAllowedOrigins([]string{"https://A.example.com", " http://localhost:9002 "}, true)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://A.example.com", "http://localhost:9002"}, out.Exact())

	_, err = ValidateAllowedOrigins(nil, true)
	require.ErrorIs(t, err, ErrAllowedOriginsEmpty)

	out, err = ValidateAllowedOrigins([]string{"https://*.previews.example.app"}, true)
	require.NoError(t, err, "a pattern alone is a non-empty allow-list")
	assert.Empty(t, out.Exact())
	assert.Equal(t, []string{"https://*.previews.example.app"}, out.Patterns())
}

func TestParseAllowedOrigins_CredentialsRejections(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"*":                          "wildcard",
		"http://localhost:9002,*":    "wildcard",
		"*,http://localhost:9002":    "wildcard",
		" * ":                        "wildcard",
		"http://localhost:9002,null": "null",
		"http://localhost:9002,":     "empty origin entry",
		"http://bad host:9002":       "whitespace",
		"http://":                    "host",
	}
	for raw, wantMsg := range cases {
		t.Run(raw, func(t *testing.T) {
			_, err := ParseAllowedOrigins(raw, true)
			require.Error(t, err)
			assert.Contains(t, err.Error(), wantMsg)
		})
	}
}

func TestParseAllowedOrigins_EmptyList_Rejected(t *testing.T) {
	t.Parallel()

	_, err := ParseAllowedOrigins("", true)
	require.ErrorIs(t, err, ErrAllowedOriginsEmpty)
	_, err = ParseAllowedOrigins(",,,", false)
	require.ErrorIs(t, err, ErrAllowedOriginsEmpty)
}

func TestParseAllowedOrigins_MalformedOrigin_Rejected(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"localhost:9002",            // missing scheme
		"ftp://localhost:9002",      // wrong scheme
		"http://localhost:9002/",    // trailing slash
		"http://localhost:9002/x",   // path
		"http://localhost:9002?q=1", // query
		"http://localhost:9002?",    // empty query
		"http://localhost:9002#f",   // fragment
		"http://user@localhost",     // userinfo
		"HTTP://localhost:9002",     // uppercase scheme
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := ParseAllowedOrigins(raw, true)
			require.Error(t, err)
		})
	}
}

func TestParseAllowedOrigins_ValidList_PreservesOrderAndCase(t *testing.T) {
	t.Parallel()

	out, err := ParseAllowedOrigins("https://A.example.com,http://localhost:9002 , https://b.example.com", true)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://A.example.com", "http://localhost:9002", "https://b.example.com"}, out.Exact())
}

func TestParseAllowedOrigins_NoCredentials_AllowsEmptyEntries(t *testing.T) {
	t.Parallel()

	out, err := ParseAllowedOrigins("http://a.example.com,,http://b.example.com", false)
	require.NoError(t, err)
	assert.Equal(t, []string{"http://a.example.com", "http://b.example.com"}, out.Exact())
}

func TestParseAllowedOrigins_InvalidPattern_Rejected(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw     string
		wantErr error
		wantMsg string
	}{
		{raw: "https://*", wantErr: ErrPatternParentShort},
		{raw: "*.com", wantMsg: "scheme"},
		{raw: "http://*.previews.example.app", wantErr: ErrPatternScheme},
		{raw: "https://a.*.example.app", wantErr: ErrPatternLabel},
		{raw: "https://*.app", wantErr: ErrPatternParentShort},
		{raw: "https://pr-*.example.app", wantErr: ErrPatternLabel},
		{raw: "https://*.*.example.app", wantErr: ErrPatternParentLabel},
		{raw: "https://*.vercel.app", wantErr: ErrPatternParentPublicSuffix},
		{raw: "https://*.co.uk", wantErr: ErrPatternParentPublicSuffix},
		{raw: "https://*.previews.example.app/", wantMsg: "path not allowed"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			_, err := ParseAllowedOrigins("http://localhost:9002,"+tc.raw, true)
			require.Error(t, err)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
			}
			assert.Contains(t, err.Error(), tc.wantMsg)
		})
	}
}
