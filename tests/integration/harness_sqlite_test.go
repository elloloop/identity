//go:build integration && sqlite

package integration

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/repo"
)

// sqliteIntegrationProjectID is the boot-default project the SQLite-backed
// integration server binds to. SQLite data-plane rows carry this project id
// (the mandatory `WHERE project_id = $1` boundary) and the FK to projects(id)
// is satisfied by the seed the driver performs at Build time.
const sqliteIntegrationProjectID = "sqlite-integration"

// StartServer boots the full identity app on the pure-Go SQLite driver (an
// in-process :memory: database — no Docker, no external service), so the same
// integration suite that runs on memory/postgres/entdb also runs on SQLite.
// Selected with `-tags 'integration sqlite'`.
func StartServer(t *testing.T, opts ...HarnessOption) *Harness {
	t.Helper()

	cfg := newTestConfig()
	cfg.RepoDriver = string(repo.DriverSQLite)
	cfg.DefaultProjectID = sqliteIntegrationProjectID
	hOpts := applyHarnessOptions(cfg, opts)

	built, err := repo.Build(context.Background(), repo.Config{
		Driver:    repo.DriverSQLite,
		ProjectID: sqliteIntegrationProjectID,
		// A fresh on-disk database file per server keeps each test fully
		// isolated (a bare ":memory:" shared-cache DB would be process-global
		// and leak state across tests). The driver migrates and seeds the
		// default project on Build; t.TempDir is cleaned up automatically.
		SQLitePath: t.TempDir() + "/identity.db",
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("build sqlite repo: %v", err)
	}

	auditDB := NewRecordingDB()
	mailer := NewRecordingMailer()

	// Pass the RecordingDB as the service.DB (matching the memory harness):
	// the SQLite Repository handles all real persistence, while the entdb
	// graph surface is only used for audit writes (ExecuteAtomic) and the
	// test-only node-inspection helpers, both of which RecordingDB satisfies.
	return startHarness(t, cfg, built.Repository, auditDB, auditDB, mailer, hOpts.oauthRegistry, hOpts.idvProvider)
}
