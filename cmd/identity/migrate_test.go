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

func TestUnknownSubcommand(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{"identity"}, false},
		{[]string{"identity", "migrate"}, false},
		{[]string{"identity", "serve"}, true},
		{[]string{"identity", "migate"}, true},
	}
	for _, c := range cases {
		if got := unknownSubcommand(c.args); got != c.want {
			t.Errorf("unknownSubcommand(%v) = %v, want %v", c.args, got, c.want)
		}
	}
}

// TestRunMigrate_NoDSN_Returns1 exercises the command path without a
// database: a missing Postgres DSN must yield a non-zero exit code, not a
// panic.
func TestRunMigrate_NoDSN_Returns1(t *testing.T) {
	if code := runMigrate(identityserver.Options{}, migrateCommand{}, zap.NewNop()); code != 1 {
		t.Fatalf("runMigrate with no DSN: want exit code 1, got %d", code)
	}
}

// TestRunMigrate_ForceNoDSN_Returns1: the force path fails the same way
// without a database.
func TestRunMigrate_ForceNoDSN_Returns1(t *testing.T) {
	if code := runMigrate(identityserver.Options{}, migrateCommand{forceVersion: 33}, zap.NewNop()); code != 1 {
		t.Fatalf("runMigrate force with no DSN: want exit code 1, got %d", code)
	}
}

func TestParseMigrateCommand(t *testing.T) {
	cases := []struct {
		args    []string
		want    migrateCommand
		wantErr bool
	}{
		{[]string{"identity", "migrate"}, migrateCommand{}, false},
		{[]string{"identity", "migrate", "--verbose"}, migrateCommand{}, false},
		{[]string{"identity", "migrate", "force", "33"}, migrateCommand{forceVersion: 33}, false},
		{[]string{"identity", "migrate", "force"}, migrateCommand{}, true},
		{[]string{"identity", "migrate", "force", "33", "34"}, migrateCommand{}, true},
		{[]string{"identity", "migrate", "force", "latest"}, migrateCommand{}, true},
		{[]string{"identity", "migrate", "force", "0"}, migrateCommand{}, true},
		{[]string{"identity", "migrate", "force", "-1"}, migrateCommand{}, true},
	}
	for _, c := range cases {
		got, err := parseMigrateCommand(c.args)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("parseMigrateCommand(%v) = %+v, %v; want %+v, error %t", c.args, got, err, c.want, c.wantErr)
		}
	}
}
