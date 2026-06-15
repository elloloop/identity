package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProjectConfig_Empty_ReturnsZero(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"", "   ", "\n\t"} {
		cfg, err := ParseProjectConfig(in)
		require.NoError(t, err)
		assert.Empty(t, cfg.CORS.AllowedOrigins)
	}
}

func TestParseProjectConfig_CORSOrigins(t *testing.T) {
	t.Parallel()

	cfg, err := ParseProjectConfig(`{"cors":{"allowed_origins":["https://a.example.com","http://localhost:3000"]}}`)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://a.example.com", "http://localhost:3000"}, cfg.CORS.AllowedOrigins)
}

func TestParseProjectConfig_UnknownKeysTolerated(t *testing.T) {
	t.Parallel()

	cfg, err := ParseProjectConfig(`{"future_knob":42,"cors":{"allowed_origins":["https://a.example.com"]}}`)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://a.example.com"}, cfg.CORS.AllowedOrigins)
}

func TestParseProjectConfig_Malformed_Errors(t *testing.T) {
	t.Parallel()

	_, err := ParseProjectConfig(`{"cors": `)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse project config")
}
