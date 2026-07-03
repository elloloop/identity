package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func validSecretsKey() string {
	return base64.StdEncoding.EncodeToString(make([]byte, projectSecretsKeyBytes))
}

func TestValidateProjectSecrets_PostgresRequiresKey(t *testing.T) {
	c := &Config{RepoDriver: "postgres"}
	err := c.validateProjectSecrets()
	if err == nil || !strings.Contains(err.Error(), "GATEWAY_PROJECT_SECRETS_KEY is required") {
		t.Fatalf("postgres without key must fail, got %v", err)
	}
}

func TestValidateProjectSecrets_PostgresWithKeyOK(t *testing.T) {
	c := &Config{RepoDriver: "postgres", ProjectSecretsKey: validSecretsKey()}
	if err := c.validateProjectSecrets(); err != nil {
		t.Fatalf("postgres with a valid key must pass: %v", err)
	}
}

func TestValidateProjectSecrets_NonPostgresKeyOptional(t *testing.T) {
	for _, driver := range []string{"sqlite", "memory", ""} {
		c := &Config{RepoDriver: driver}
		if err := c.validateProjectSecrets(); err != nil {
			t.Errorf("driver %q without key must pass: %v", driver, err)
		}
	}
}

func TestValidateProjectSecrets_MalformedBase64Rejected(t *testing.T) {
	c := &Config{RepoDriver: "memory", ProjectSecretsKey: "not base64!!"}
	if err := c.validateProjectSecrets(); err == nil || !strings.Contains(err.Error(), "not valid base64") {
		t.Fatalf("malformed base64 must fail, got %v", err)
	}
}

func TestValidateProjectSecrets_WrongLengthRejected(t *testing.T) {
	c := &Config{RepoDriver: "memory", ProjectSecretsKey: base64.StdEncoding.EncodeToString(make([]byte, 16))}
	if err := c.validateProjectSecrets(); err == nil || !strings.Contains(err.Error(), "must decode to 32 bytes") {
		t.Fatalf("wrong-length key must fail, got %v", err)
	}
}
