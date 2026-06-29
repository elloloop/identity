package postgres

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// projectCORSOrigins is a pure function over a project's parsed config, so it
// is tested directly without a database. It is the per-request hop that turns a
// project's stored CORS config into the validated allow-list the resolver
// threads onto ResolvedProject. corsFromJSON wraps the parse the resolver does
// before calling it, so the cases keep reading off raw config_json.
func corsFromJSON(t *testing.T, configJSON string) ([]string, error) {
	t.Helper()
	cfg, err := service.ParseProjectConfig(configJSON)
	if err != nil {
		return nil, err
	}
	return projectCORSOrigins("p1", cfg)
}

func TestProjectCORSOrigins_ParsesAndValidates(t *testing.T) {
	t.Parallel()

	origins, err := corsFromJSON(t, `{"cors":{"allowed_origins":["https://app.example.com","http://localhost:5173"]}}`)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://app.example.com", "http://localhost:5173"}, origins)
}

func TestProjectCORSOrigins_EmptyConfig_NoOrigins(t *testing.T) {
	t.Parallel()

	for _, cfg := range []string{"", "{}", `{"cors":{}}`, `{"cors":{"allowed_origins":[]}}`} {
		origins, err := corsFromJSON(t, cfg)
		require.NoError(t, err, cfg)
		assert.Nil(t, origins, cfg)
	}
}

func TestProjectCORSOrigins_UnknownKeysIgnored(t *testing.T) {
	t.Parallel()

	origins, err := corsFromJSON(t, `{"login_methods":["email_otp"],"cors":{"allowed_origins":["https://app.example.com"]}}`)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://app.example.com"}, origins)
}

func TestProjectCORSOrigins_MalformedJSON_Errors(t *testing.T) {
	t.Parallel()

	_, err := corsFromJSON(t, `{"cors":`)
	require.Error(t, err)
}

func TestProjectCORSOrigins_DangerousOrigin_Rejected(t *testing.T) {
	t.Parallel()

	// Credentials are always sent, so a wildcard/malformed per-project origin
	// is a configuration error surfaced here, not served to the browser.
	cases := map[string]string{
		"wildcard":  `{"cors":{"allowed_origins":["*"]}}`,
		"null":      `{"cors":{"allowed_origins":["null"]}}`,
		"no scheme": `{"cors":{"allowed_origins":["app.example.com"]}}`,
		"has path":  `{"cors":{"allowed_origins":["https://app.example.com/x"]}}`,
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := corsFromJSON(t, cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "cors")
		})
	}
}
