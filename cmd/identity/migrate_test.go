package main

import (
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/identityserver"
)

func TestMigrateRequested(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{"identity"}, false},
		{[]string{"identity", "migrate"}, true},
		{[]string{"identity", "serve"}, false},
		{[]string{"identity", "migrate", "--verbose"}, true},
	}
	for _, c := range cases {
		if got := migrateRequested(c.args); got != c.want {
			t.Errorf("migrateRequested(%v) = %v, want %v", c.args, got, c.want)
		}
	}
}

// TestRunMigrate_NoDSN_Returns1 exercises the command path without a
// database: a missing Postgres DSN must yield a non-zero exit code, not a
// panic.
func TestRunMigrate_NoDSN_Returns1(t *testing.T) {
	if code := runMigrate(identityserver.Options{}, zap.NewNop()); code != 1 {
		t.Fatalf("runMigrate with no DSN: want exit code 1, got %d", code)
	}
}
