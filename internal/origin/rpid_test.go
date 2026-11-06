package origin

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsDNSName(t *testing.T) {
	t.Parallel()
	for host, want := range map[string]bool{
		"acme.example":                  true,
		"a-b.acme.example":              true,
		"localhost":                     true,
		"":                              false,
		"Acme.example":                  false,
		"acme.example.":                 false,
		"-acme.example":                 false,
		"acme_b.example":                false,
		"acme.example:443":              false,
		strings.Repeat("a", 64):         false,
		strings.Repeat("a.", 127):       false,
		strings.Repeat("a.", 126) + "a": true,
	} {
		assert.Equal(t, want, IsDNSName(host), "%q", host)
	}
}

func TestIsRegistrableSuffix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		rpID, hostname string
		want           bool
	}{
		{"acme.example", "acme.example", true},
		{"acme.example", "auth.acme.example", true},
		{"acme.example", "a.b.acme.example", true},
		{"localhost", "localhost", true},
		{"localhost", "app.localhost", false},
		{"acme.example", "notacme.example", false},
		{"auth.acme.example", "acme.example", false},
		{"acme.example", "widgets.example", false},
		{"co.uk", "acme.co.uk", false},
		{"Acme.example", "acme.example", false},
		{"127.0.0.1", "127.0.0.1", false},
		{"", "acme.example", false},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, IsRegistrableSuffix(tc.rpID, tc.hostname), "%q of %q", tc.rpID, tc.hostname)
	}
}

func TestIsSerializedPort(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]bool{
		"https://acme.example":       true,
		"https://acme.example:8443":  true,
		"http://localhost":           true,
		"http://localhost:3000":      true,
		"https://acme.example:80":    true,
		"http://localhost:443":       true,
		"https://acme.example:443":   false,
		"http://localhost:80":        false,
		"https://acme.example:":      false,
		"https://acme.example:0443":  false,
		"https://acme.example:99999": false,
		"https://acme.example:0":     false,
	} {
		u, err := url.Parse(raw)
		require.NoError(t, err, raw)
		assert.Equal(t, want, IsSerializedPort(u), raw)
	}
}
