//go:build integration && !realentdb && !realpostgres && !sqlite

package integration

import "testing"

func StartServer(t *testing.T, opts ...HarnessOption) *Harness {
	t.Helper()

	cfg := newTestConfig()
	hOpts := applyHarnessOptions(cfg, opts)

	repo := NewMemRepo()
	auditDB := NewRecordingDB()
	mailer := NewRecordingMailer()

	return startHarness(t, cfg, repo, auditDB, auditDB, mailer, hOpts.oauthRegistry, hOpts.idvProvider)
}
