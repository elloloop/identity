package postgres

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// projectCORSOrigins is a pure function over a Project's config_json, so it is
// tested directly without a database. It is the per-request hop that turns a
// project's stored CORS config into the validated allow-list the resolver
// threads onto ResolvedProject.

func TestProjectCORSOrigins_ParsesAndValidates(t *testing.T) {
	t.Parallel()

	origins, err := projectCORSOrigins(&Project{
		ID:         "p1",
		ConfigJSON: `{"cors":{"allowed_origins":["https://app.example.com","http://localhost:5173"]}}`,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"https://app.example.com", "http://localhost:5173"}, origins)
}

func TestProjectCORSOrigins_EmptyConfig_NoOrigins(t *testing.T) {
	t.Parallel()

	for _, cfg := range []string{"", "{}", `{"cors":{}}`, `{"cors":{"allowed_origins":[]}}`} {
		origins, err := projectCORSOrigins(&Project{ID: "p1", ConfigJSON: cfg})
		require.NoError(t, err, cfg)
		assert.Nil(t, origins, cfg)
	}
}

func TestProjectCORSOrigins_UnknownKeysIgnored(t *testing.T) {
	t.Parallel()

	origins, err := projectCORSOrigins(&Project{
		ID:         "p1",
		ConfigJSON: `{"login_methods":["email_otp"],"cors":{"allowed_origins":["https://app.example.com"]}}`,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"https://app.example.com"}, origins)
}

func TestProjectCORSOrigins_MalformedJSON_Errors(t *testing.T) {
	t.Parallel()

	_, err := projectCORSOrigins(&Project{ID: "p1", ConfigJSON: `{"cors":`})
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
			_, err := projectCORSOrigins(&Project{ID: "p1", ConfigJSON: cfg})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "cors")
		})
	}
}
