package main

import (
	"context"
	"errors"
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
		{[]string{"identity", "migrate", "force", "--override", "33"}, migrateCommand{forceVersion: 33, override: true}, false},
		{[]string{"identity", "migrate", "force", "33", "--override"}, migrateCommand{}, true},
		{[]string{"identity", "migrate", "force", "--override"}, migrateCommand{}, true},
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

func TestParseRepairEmailsCommand(t *testing.T) {
	apply, err := parseRepairEmailsCommand([]string{"identity", "repair-emails"})
	if err != nil || apply {
		t.Fatalf("no argument is a dry run: apply=%v err=%v", apply, err)
	}
	apply, err = parseRepairEmailsCommand([]string{"identity", "repair-emails", "--apply"})
	if err != nil || !apply {
		t.Fatalf("--apply applies: apply=%v err=%v", apply, err)
	}
	for _, args := range [][]string{
		{"identity", "repair-emails", "--aply"},
		{"identity", "repair-emails", "--apply", "extra"},
	} {
		if _, err := parseRepairEmailsCommand(args); err == nil {
			t.Errorf("%v must be refused", args)
		}
	}
	if !repairEmailsRequested([]string{"identity", "repair-emails"}) || unknownSubcommand([]string{"identity", "repair-emails"}) {
		t.Error("repair-emails is a known subcommand")
	}
}

// TestRunRepairEmails_InitFailure_Returns1: a server New refuses to build is
// a non-zero exit, not a panic or a silent success.
func TestRunRepairEmails_InitFailure_Returns1(t *testing.T) {
	if code := runRepairEmails(identityserver.Options{}, false, zap.NewNop()); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestRepairEmailsExitCode(t *testing.T) {
	ok := &identityserver.EmailRepairReport{Items: []identityserver.EmailRepairItem{{Action: identityserver.EmailRepairSkip}}}
	failed := &identityserver.EmailRepairReport{Items: []identityserver.EmailRepairItem{{Action: identityserver.EmailRepairSkip, Error: "x"}}}
	for _, c := range []struct {
		report      *identityserver.EmailRepairReport
		undelivered int
		want        int
	}{
		{ok, 0, 0},
		{failed, 0, 1},
		{ok, 2, 1},
		{nil, 0, 1},
	} {
		if got := repairEmailsExitCode(c.report, c.undelivered); got != c.want {
			t.Errorf("repairEmailsExitCode(%+v, %d) = %d, want %d", c.report, c.undelivered, got, c.want)
		}
	}
}

type fakeRepairer struct {
	report      *identityserver.EmailRepairReport
	err         error
	undelivered int
	drained     bool
}

func (f *fakeRepairer) RepairStoredEmails(context.Context, bool) (*identityserver.EmailRepairReport, error) {
	return f.report, f.err
}

func (f *fakeRepairer) DrainEvents(context.Context) (int, error) {
	f.drained = true
	return f.undelivered, nil
}

// A run that fails part-way still delivers what its earlier merges queued.
func TestRepairAndDrain_DrainsEvenWhenTheRunFails(t *testing.T) {
	partial := &identityserver.EmailRepairReport{Applied: true, Items: []identityserver.EmailRepairItem{{Action: identityserver.EmailRepairMerge}}}
	f := &fakeRepairer{report: partial, err: errors.New("project b: unavailable")}
	if code := repairAndDrain(context.Background(), f, true, zap.NewNop()); code != 1 || !f.drained {
		t.Fatalf("code = %d, drained = %v; want 1 and drained", code, f.drained)
	}
	ok := &fakeRepairer{report: partial, undelivered: 1}
	if code := repairAndDrain(context.Background(), ok, true, zap.NewNop()); code != 1 {
		t.Fatalf("an undelivered event must fail the run, got %d", code)
	}
	ok.undelivered = 0
	if code := repairAndDrain(context.Background(), ok, true, zap.NewNop()); code != 0 {
		t.Fatalf("a clean run exits 0, got %d", code)
	}
}
