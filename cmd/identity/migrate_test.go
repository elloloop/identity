package main

import (
	"strings"
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
		{[]string{"identity", "migrate", "--verbose"}, migrateCommand{}, true},
		{[]string{"identity", "migrate", "--verbose", "force", "33"}, migrateCommand{}, true},
		{[]string{"identity", "migrate", "up"}, migrateCommand{}, true},
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

func TestDirtyMigrationRecovery(t *testing.T) {
	cases := []struct {
		name      string
		dirty     identityserver.DirtyMigrationError
		want      []string
		mustNotBe []string
	}{
		{
			"middle", identityserver.DirtyMigrationError{Version: 33, Known: true, Latest: 34, Previous: 32, Next: 34},
			[]string{"identity migrate force 32", "identity migrate force 34"}, []string{"schema_migrations"},
		},
		{
			"first", identityserver.DirtyMigrationError{Version: 1, Known: true, Latest: 34, First: true, Next: 2},
			[]string{"drop the schema_migrations table"}, []string{"force 0"},
		},
		{
			"newer release", identityserver.DirtyMigrationError{Version: 35, Latest: 34},
			[]string{"newer than this build", "never drop schema_migrations"}, []string{"force 34", "force 35"},
		},
	}
	for _, c := range cases {
		got := dirtyMigrationRecovery(&c.dirty)
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: %q lacks %q", c.name, got, w)
			}
		}
		for _, n := range c.mustNotBe {
			if strings.Contains(got, n) {
				t.Errorf("%s: %q must not contain %q", c.name, got, n)
			}
		}
	}
}
