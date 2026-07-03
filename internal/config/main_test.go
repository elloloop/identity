package config

import (
	"encoding/base64"
	"os"
	"testing"
)

// TestMain sets a valid GATEWAY_PROJECT_SECRETS_KEY for the whole package so
// Load()-based "base valid config" helpers keep validating: the postgres
// default driver now requires the key (validateProjectSecrets). Tests that
// exercise the requirement itself call validateProjectSecrets directly on a
// struct-built Config, independent of this env value.
func TestMain(m *testing.M) {
	if err := os.Setenv("GATEWAY_PROJECT_SECRETS_KEY",
		base64.StdEncoding.EncodeToString(make([]byte, projectSecretsKeyBytes))); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
