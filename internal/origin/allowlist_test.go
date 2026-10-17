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

// TestAllowlist_AppSchemeOrigin pins that an exact origin on an application's
// own scheme admits that serialized origin, byte for byte, and no look-alike.
func TestAllowlist_AppSchemeOrigin(t *testing.T) {
	t.Parallel()

	a := mustAllowlist(t, "https://app.example.app", "app://example-desktop")
	tests := []struct {
		name   string
		origin string
		want   bool
	}{
		{"exact", "app://example-desktop", true},
		{"http_entry_unchanged", "https://app.example.app", true},
		{"other_host", "app://other-desktop", false},
		{"host_suffix", "app://example-desktop.example.app", false},
		{"other_scheme", "web://example-desktop", false},
		{"https_same_host", "https://example-desktop", false},
		{"upper_scheme", "APP://example-desktop", false},
		{"upper_host", "app://Example-Desktop", false},
		{"trailing_slash", "app://example-desktop/", false},
		{"path", "app://example-desktop/index.html", false},
		{"port", "app://example-desktop:443", false},
		{"userinfo", "app://u@example-desktop", false},
		{"null", "null", false},
		{"file", "file://", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, a.Allows(tt.origin), tt.origin)
		})
	}
}

func TestValidateAllowedOrigins_AppSchemeOrigins(t *testing.T) {
	t.Parallel()

	entries := []string{"app://example-desktop", "example+shell://ui.example.test", "x-example.app://localhost", "app2://123.example-desktop", "app://example.0xg"}
	out, err := ValidateAllowedOrigins(entries, true)
	require.NoError(t, err)
	assert.Equal(t, entries, out.Exact())
	assert.Equal(t, entries, out.AppSchemeOrigins())
	assert.Empty(t, out.Patterns())
}

// TestAllowlist_AppSchemeOrigins pins that the app-scheme entries are listed
// apart from the http(s) entries and the patterns.
func TestAllowlist_AppSchemeOrigins(t *testing.T) {
	t.Parallel()

	a := mustAllowlist(t, "https://app.example.app", "app://example-desktop", "http://localhost:3000", "example+shell://ui.example.test", "https://*.previews.example.app")
	assert.Equal(t, []string{"app://example-desktop", "example+shell://ui.example.test"}, a.AppSchemeOrigins())
	assert.Nil(t, mustAllowlist(t, "https://app.example.app").AppSchemeOrigins())
}

func TestOneEditApart(t *testing.T) {
	t.Parallel()

	tests := []struct {
		a, b string
		want bool
	}{
		{"https", "htps", true},     // deletion
		{"https", "hhttps", true},   // insertion
		{"https", "https2", true},   // insertion at the end
		{"http", "shttp", true},     // insertion at the start
		{"http", "htpp", true},      // substitution
		{"https", "httsp", true},    // adjacent swap
		{"http", "thtp", true},      // adjacent swap at the start
		{"http", "http", false},     // equal
		{"http", "hxxp", false},     // two substitutions
		{"http", "ptth", false},     // reversed
		{"https", "htp", false},     // two deletions
		{"https", "hptts", false},   // a swap that is not adjacent
		{"http", "app", false},      // unrelated
		{"https", "example", false}, // unrelated, longer
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, oneEditApart(tt.a, tt.b), "%s / %s", tt.a, tt.b)
		assert.Equal(t, tt.want, oneEditApart(tt.b, tt.a), "%s / %s", tt.b, tt.a)
	}
}

// TestValidateAllowedOrigins_AppSchemeHostRejections pins the host rule's two
// sentinels: a host that is not a lower-case DNS name with no port, and one a
// browser engine would read as an IPv4 address and send rewritten.
func TestValidateAllowedOrigins_AppSchemeHostRejections(t *testing.T) {
	t.Parallel()

	cases := map[string]error{
		"app://example-desktop:8080": errAppOriginHost,
		"app://example-desktop:":     errAppOriginHost,
		"app://Example-Desktop":      errAppOriginHost,
		"app://*.example-desktop":    errAppOriginHost,
		"app://*":                    errAppOriginHost,
		"app://example-desktop.":     errAppOriginHost,
		"app://example_desktop":      errAppOriginHost,
		"app://-example-desktop":     errAppOriginHost,
		"app://-":                    errAppOriginHost,
		"app://.":                    errAppOriginHost,
		"app://[::1]":                errAppOriginHost,
		"app://1":                    errAppOriginNumericHost,
		"app://0x7f":                 errAppOriginNumericHost,
		"app://0x":                   errAppOriginNumericHost,
		"app://example.123":          errAppOriginNumericHost,
		"app2://127.0.0.1":           errAppOriginNumericHost,
	}
	for raw, want := range cases {
		t.Run(raw, func(t *testing.T) {
			_, err := ParseAllowedOrigins(raw, true)
			require.ErrorIs(t, err, want)
		})
	}
}

func TestValidateAllowedOrigins_AppSchemeRejections(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"app://":                          "host is empty",
		"app://example-desktop/":          "path not allowed",
		"app://example-desktop/index":     "path not allowed",
		"app://example-desktop?":          "query not allowed",
		"app://example-desktop?x=1":       "query not allowed",
		"app://example-desktop#f":         "fragment not allowed",
		"app://example-desktop#":          "fragment not allowed",
		"app://u@example-desktop":         "userinfo not allowed",
		"app://%65xample-desktop":         "not a valid URL",
		"APP://example-desktop":           "lower-case scheme",
		"App://example-desktop":           "lower-case scheme",
		"1app://example-desktop":          "lower-case scheme",
		"ap_p://example-desktop":          "lower-case scheme",
		"://example-desktop":              "lower-case scheme",
		"app:example-desktop":             "lower-case scheme",
		"app:/example-desktop":            "lower-case scheme",
		"blob:https://app.example.app":    "lower-case scheme",
		"file://":                         "scheme file:",
		"file:///":                        "scheme file:",
		"file://localhost":                "scheme file:",
		"data://example-desktop":          "scheme data:",
		"blob://example-desktop":          "scheme blob:",
		"javascript://example-desktop":    "scheme javascript:",
		"about://blank":                   "scheme about:",
		"filesystem://example-desktop":    "scheme filesystem:",
		"ws://example-desktop":            "scheme ws:",
		"wss://example-desktop":           "scheme wss:",
		"ftp://example-desktop":           "scheme ftp:",
		"htps://app.example.app":          "misspelling",
		"htp://app.example.app":           "misspelling",
		"hhttps://app.example.app":        "misspelling",
		"httsp://app.example.app":         "misspelling",
		"htttps://app.example.app":        "misspelling",
		"https2://app.example.app":        "misspelling",
		"httpx://app.example.app":         "misspelling",
		"app://example-desktop,":          "empty origin entry",
		"app://example-desktop,null":      "null",
		"app://example-desktop,*":         "wildcard",
		"app://example-desktop,app://x y": "whitespace",
	}
	for raw, wantMsg := range cases {
		t.Run(raw, func(t *testing.T) {
			_, err := ParseAllowedOrigins(raw, true)
			require.Error(t, err)
			assert.Contains(t, err.Error(), wantMsg)
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
		"ftp://localhost:9002",      // a scheme with a standard meaning (refusedSchemes)
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

func TestRedact(t *testing.T) {
	t.Parallel()

	const secret = "s3cret-pw"
	cases := map[string]string{
		"https://app.example.app":                         "https://app.example.app",
		"https://*.previews.example.app/auth":             "https://*.previews.example.app/auth",
		"https://user:" + secret + "@app.example.app/x":   "https://REDACTED@app.example.app/x",
		"https://" + secret + "@app.example.app":          "https://REDACTED@app.example.app",
		"https://user:" + secret + "@*.example.app":       "https://REDACTED@*.example.app",
		"user:" + secret + "@app.example.app":             redactedEntry,
		"https://user:" + secret + "@app.example.app/%zz": redactedEntry,
	}
	for in, want := range cases {
		got := Redact(in)
		assert.Equal(t, want, got, in)
		assert.NotContains(t, got, secret, in)
	}
}

// TestValidateAllowedOrigins_ErrorsNeverCarryCredentials pins that a rejected
// entry's credentials never reach the error (and so the boot log or an admin
// API response).
func TestValidateAllowedOrigins_ErrorsNeverCarryCredentials(t *testing.T) {
	t.Parallel()

	const secret = "s3cret-pw"
	for _, entry := range []string{
		"https://user:" + secret + "@app.example.app",
		"https://user:" + secret + "@*.previews.example.app",
		"https://user:" + secret + "@app.example.app/%zz",
		"https://user:" + secret + "@app.example.app/path",
		"app://user:" + secret + "@example-desktop",
		"app://user:" + secret + "@example-desktop:8080",
	} {
		_, err := ValidateAllowedOrigins([]string{entry}, true)
		require.Error(t, err, entry)
		assert.NotContains(t, err.Error(), secret, entry)
	}
}
