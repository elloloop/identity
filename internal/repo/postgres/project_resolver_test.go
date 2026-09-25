package postgres

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/internal/origin"
	"github.com/elloloop/identity/internal/service"
)

// projectCORSOrigins needs no database, so it is tested on a pool-less store
// whose logger is observed. corsFromJSON wraps the config parse the resolver
// does before calling it, so the cases read off raw config_json.
func corsFromJSON(t *testing.T, configJSON string) (origin.Allowlist, *observer.ObservedLogs) {
	t.Helper()
	cfg, err := service.ParseProjectConfig(configJSON)
	require.NoError(t, err)
	core, logs := observer.New(zapcore.WarnLevel)
	s := &ProjectStore{logger: zap.New(core)}
	return s.projectCORSOrigins("p1", cfg.CORS), logs
}

func TestProjectCORSOrigins_ParsesAndValidates(t *testing.T) {
	t.Parallel()

	origins, logs := corsFromJSON(t, `{"cors":{"allowed_origins":["https://app.example.com","http://localhost:5173"]}}`)
	assert.Equal(t, []string{"https://app.example.com", "http://localhost:5173"}, origins.Exact())
	assert.Zero(t, logs.Len())
}

func TestProjectCORSOrigins_WildcardPattern(t *testing.T) {
	t.Parallel()

	origins, _ := corsFromJSON(t, `{"cors":{"allowed_origins":["https://app.example.app","https://*.previews.example.app"]}}`)
	assert.Equal(t, []string{"https://app.example.app"}, origins.Exact())
	assert.Equal(t, []string{"https://*.previews.example.app"}, origins.Patterns())
	assert.True(t, origins.Allows("https://feature-1.previews.example.app"))
	assert.False(t, origins.Allows("https://a.b.previews.example.app"))
}

func TestProjectCORSOrigins_EmptyConfig_NoOrigins(t *testing.T) {
	t.Parallel()

	for _, cfg := range []string{"", "{}", `{"cors":{}}`, `{"cors":{"allowed_origins":[]}}`} {
		origins, logs := corsFromJSON(t, cfg)
		assert.Zero(t, origins, cfg)
		assert.Zero(t, logs.Len(), cfg)
	}
}

func TestProjectCORSOrigins_UnknownKeysIgnored(t *testing.T) {
	t.Parallel()

	origins, _ := corsFromJSON(t, `{"login_methods":["email_otp"],"cors":{"allowed_origins":["https://app.example.com"]}}`)
	assert.Equal(t, []string{"https://app.example.com"}, origins.Exact())
}

// TestProjectCORSOrigins_InvalidStoredOrigin_FailsClosed pins that a stored
// per-project list the CORS rule refuses admits nothing (only the global floor
// applies) and is logged, rather than failing the whole project's resolution.
func TestProjectCORSOrigins_InvalidStoredOrigin_FailsClosed(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"wildcard":      `{"cors":{"allowed_origins":["https://app.example.com","*"]}}`,
		"null":          `{"cors":{"allowed_origins":["null"]}}`,
		"no scheme":     `{"cors":{"allowed_origins":["app.example.com"]}}`,
		"has path":      `{"cors":{"allowed_origins":["https://app.example.com/x"]}}`,
		"bad pattern":   `{"cors":{"allowed_origins":["https://*.app"]}}`,
		"public suffix": `{"cors":{"allowed_origins":["https://*.pages.dev"]}}`,
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			origins, logs := corsFromJSON(t, cfg)
			assert.Zero(t, origins)
			assert.False(t, origins.Allows("https://app.example.com"))
			entries := logs.FilterMessage("project_cors_config_invalid_failing_closed").All()
			require.Len(t, entries, 1)
			assert.Equal(t, "p1", entries[0].ContextMap()["project_id"])
		})
	}
}
