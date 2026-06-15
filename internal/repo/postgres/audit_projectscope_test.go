package postgres

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
	"go.uber.org/zap"
)

// TestPostgres_AuditScopedToRequestProject_Smoke is the env-DSN form of the
// postgres audit project-scope regression (issue #21). It shares its body with
// the dockerpostgres container test below so the same assertions run both in
// CI's coverage gate (this test, which contributes coverage) and hermetically
// (the //go:build dockerpostgres twin, which spins up its own container).
func TestPostgres_AuditScopedToRequestProject_Smoke(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset — skipping postgres audit project-scope smoke test")
	}
	runAuditProjectScopeSmoke(t, dsn)
}

// runAuditProjectScopeSmoke proves that an audit event logged under a request
// scoped to one project lands under THAT project's partition and not another's,
// exercising the real postgres writer through the same wiring internal/app
// uses: an audit.Logger whose ProjectScoper rebinds the boot DB via
// service.ScopedDB (which calls pgRepository.WithProject).
//
// Before the fix the audit logger was pinned to the boot-default project, so a
// write made under a different request project landed under the boot default —
// invisible to a per-request ListAuditEvents read of the request's project.
func runAuditProjectScopeSmoke(t *testing.T, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	require.NoError(t, truncateAll(ctx, dsn))

	const defaultProj = "audit-default"
	projA := fmt.Sprintf("audit-project-a-%d", time.Now().UnixNano())
	projB := fmt.Sprintf("audit-project-b-%d", time.Now().UnixNano())

	// The boot DB binds the default project, mirroring app.New. The scoper
	// rebinds it per request via WithProject.
	bootRepo, err := New(ctx, Config{
		DSN:         dsn,
		MaxConns:    5,
		ConnTimeout: 5 * time.Second,
		AutoMigrate: true,
		ProjectID:   defaultProj,
	})
	require.NoError(t, err)
	defer bootRepo.Close()

	// Every project a data-plane write targets needs its projects(id) row (the
	// project_id FK target, migration 0015).
	seedProject(ctx, t, bootRepo, defaultProj)
	seedProject(ctx, t, bootRepo, projA)
	seedProject(ctx, t, bootRepo, projB)

	var bootDB service.DB = bootRepo
	auditLog := audit.NewLogger(bootDB, defaultProj, zap.NewNop()).
		WithProjectScoper(func(ctx context.Context) (audit.NodeWriter, string) {
			scoped, projectID := service.ScopedDB(ctx, bootDB, defaultProj)
			if scoped == nil {
				return nil, projectID
			}
			return scoped, projectID
		})

	// Log an event under a request scoped to project A (synchronous path —
	// StartAsync is not called, so the write completes before we read back).
	ctxA := service.WithProjectScope(ctx, &service.ProjectScope{ProjectID: projA})
	auditLog.Log(ctxA, audit.EventPasswordChanged, audit.WithActor("user-a"))

	// The audit row must exist in project A's partition...
	eventsA, err := bootRepo.WithProject(projA).(service.DB).
		QueryNodes(ctx, projA, "system:admin", dbTypeAuditEvent, nil)
	require.NoError(t, err)
	require.Len(t, eventsA, 1, "expected the audit event under project A")
	require.Equal(t, string(audit.EventPasswordChanged), eventsA[0].Payload[dbAfEventType])

	// ...and NOT in project B's partition, nor the boot default.
	eventsB, err := bootRepo.WithProject(projB).(service.DB).
		QueryNodes(ctx, projB, "system:admin", dbTypeAuditEvent, nil)
	require.NoError(t, err)
	require.Empty(t, eventsB, "audit event must not leak into project B")

	eventsDefault, err := bootRepo.QueryNodes(ctx, defaultProj, "system:admin", dbTypeAuditEvent, nil)
	require.NoError(t, err)
	require.Empty(t, eventsDefault, "audit event must not land under the boot-default project")
}
