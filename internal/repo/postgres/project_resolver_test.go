package postgres

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
)

// corsOriginsFromJSON mirrors the resolver's per-request hop: parse a project's
// config_json, then turn its CORS block into the validated allow-list threaded
// onto ResolvedProject. It is a pure function over the stored JSON, so it is
// tested directly without a database.
func corsOriginsFromJSON(id, configJSON string) ([]string, error) {
	cfg, err := service.ParseProjectConfig(configJSON)
	if err != nil {
		return nil, fmt.Errorf("project %q: %w", id, err)
	}
	return projectCORSOrigins(id, cfg)
}

func TestProjectCORSOrigins_ParsesAndValidates(t *testing.T) {
	t.Parallel()

	origins, err := corsOriginsFromJSON("p1", `{"cors":{"allowed_origins":["https://app.example.com","http://localhost:5173"]}}`)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://app.example.com", "http://localhost:5173"}, origins)
}

func TestProjectCORSOrigins_EmptyConfig_NoOrigins(t *testing.T) {
	t.Parallel()

	for _, cfg := range []string{"", "{}", `{"cors":{}}`, `{"cors":{"allowed_origins":[]}}`} {
		origins, err := corsOriginsFromJSON("p1", cfg)
		require.NoError(t, err, cfg)
		assert.Nil(t, origins, cfg)
	}
}

func TestProjectCORSOrigins_UnknownKeysIgnored(t *testing.T) {
	t.Parallel()

	origins, err := corsOriginsFromJSON("p1", `{"login_methods":["email_otp"],"cors":{"allowed_origins":["https://app.example.com"]}}`)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://app.example.com"}, origins)
}

func TestProjectCORSOrigins_MalformedJSON_Errors(t *testing.T) {
	t.Parallel()

	_, err := corsOriginsFromJSON("p1", `{"cors":`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `project "p1"`)
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
			_, err := corsOriginsFromJSON("p1", cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "cors")
		})
	}
}
