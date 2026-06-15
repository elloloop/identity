package audit

import (
	"context"
	"sync"
	"testing"

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb/v2"
	"go.uber.org/zap"
)

// projectCtxKey carries a per-request project id through context in these
// tests, standing in for service.ProjectScope without importing the service
// package (pkg/audit must not depend on internal/service).
type projectCtxKey struct{}

func ctxWithProject(projectID string) context.Context {
	return context.WithValue(context.Background(), projectCtxKey{}, projectID)
}

// partitionedWriter is a NodeWriter that records, per project id (the tenant
// argument), the events written to it. A WithProject sibling shares the parent
// store so a rebound writer and the boot writer agree on what landed where —
// mirroring postgres's WithProject (filters on the bound project) and entdb's
// per-call partition argument in one fake.
type partitionedWriter struct {
	mu      sync.Mutex
	byProj  map[string][]string // projectID -> event types
	boundTo string              // "" for the boot writer; set on a WithProject sibling
	store   *partitionedWriter  // shared backing store (self for the root)
}

func newPartitionedWriter() *partitionedWriter {
	w := &partitionedWriter{byProj: map[string][]string{}}
	w.store = w
	return w
}

// WithProject returns a sibling bound to projectID. It satisfies neither
// audit's interfaces directly nor service.Repository here; the test wires it
// through a ProjectScoper, matching how internal/app rebinds the writer.
func (w *partitionedWriter) WithProject(projectID string) *partitionedWriter {
	return &partitionedWriter{boundTo: projectID, store: w.store}
}

func (w *partitionedWriter) ExecuteAtomic(
	_ context.Context,
	tenantID, _ string,
	ops []entdb.Operation,
) (*entdb.CommitResult, error) {
	// A postgres-shaped writer ignores tenantID and lands under boundTo; an
	// entdb-shaped writer lands under tenantID. The boot writer (boundTo == "")
	// lands under tenantID. Resolve the effective partition the same way a real
	// backend would: a bound writer wins, else the per-call tenant argument.
	proj := tenantID
	if w.boundTo != "" {
		proj = w.boundTo
	}
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	for _, op := range ops {
		et, _ := op.Data[fieldEventType].(string)
		w.store.byProj[proj] = append(w.store.byProj[proj], et)
	}
	return &entdb.CommitResult{Success: true, Applied: true}, nil
}

func (w *partitionedWriter) events(projectID string) []string {
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	out := make([]string, len(w.store.byProj[projectID]))
	copy(out, w.store.byProj[projectID])
	return out
}

// scoperFromContext builds a ProjectScoper that rebinds w to the project read
// from ctx (falling back to the boot default), exactly as internal/app wires
// service.ScopedDB. It models BOTH backend shapes: it both rebinds the writer
// (postgres) and passes the project id back (entdb).
func scoperFromContext(w *partitionedWriter, defaultProjectID string) ProjectScoper {
	return func(ctx context.Context) (NodeWriter, string) {
		projectID := defaultProjectID
		if p, ok := ctx.Value(projectCtxKey{}).(string); ok && p != "" {
			projectID = p
		}
		return w.WithProject(projectID), projectID
	}
}

// TestLog_ScopesWriteToRequestProject is the core regression for issue #21:
// an event logged under a request scoped to project A must land under A and
// NOT under project B. Covers the synchronous write path.
func TestLog_ScopesWriteToRequestProject(t *testing.T) {
	const (
		defaultProj = "default"
		projA       = "project-a"
		projB       = "project-b"
	)
	w := newPartitionedWriter()
	l := NewLogger(w, defaultProj, zap.NewNop()).
		WithProjectScoper(scoperFromContext(w, defaultProj))

	l.Log(ctxWithProject(projA), EventLoginSuccess, WithActor("user-a"))

	if got := w.events(projA); len(got) != 1 || got[0] != string(EventLoginSuccess) {
		t.Fatalf("project A: expected [login_success], got %v", got)
	}
	if got := w.events(projB); len(got) != 0 {
		t.Errorf("project B: expected no events, got %v", got)
	}
	if got := w.events(defaultProj); len(got) != 0 {
		t.Errorf("default project: expected no events (request resolved to A), got %v", got)
	}
}

// TestLog_AsyncScopesWriteToRequestProject proves the project is captured on
// the request goroutine and carried through the async queue to the flusher,
// so async mode does not regress to the boot-default project.
func TestLog_AsyncScopesWriteToRequestProject(t *testing.T) {
	const (
		defaultProj = "default"
		projA       = "project-a"
		projB       = "project-b"
	)
	w := newPartitionedWriter()
	l := NewLogger(w, defaultProj, zap.NewNop()).
		WithProjectScoper(scoperFromContext(w, defaultProj))
	stop := l.StartAsync(64)
	defer stop()

	l.Log(ctxWithProject(projA), EventLoginSuccess, WithActor("user-a"))
	l.Log(ctxWithProject(projB), EventLogout, WithActor("user-b"))
	stop() // drain

	if got := w.events(projA); len(got) != 1 || got[0] != string(EventLoginSuccess) {
		t.Fatalf("project A: expected [login_success], got %v", got)
	}
	if got := w.events(projB); len(got) != 1 || got[0] != string(EventLogout) {
		t.Fatalf("project B: expected [logout], got %v", got)
	}
	if got := w.events(defaultProj); len(got) != 0 {
		t.Errorf("default project: expected no events, got %v", got)
	}
}

// TestLog_FallsBackToDefaultProjectWhenUnscoped proves a request that resolved
// no project (no scope in context) still writes — under the boot default.
func TestLog_FallsBackToDefaultProjectWhenUnscoped(t *testing.T) {
	const defaultProj = "default"
	w := newPartitionedWriter()
	l := NewLogger(w, defaultProj, zap.NewNop()).
		WithProjectScoper(scoperFromContext(w, defaultProj))

	// No project in context — scoper falls back to the boot default.
	l.Log(context.Background(), EventLoginSuccess, WithActor("user-x"))

	if got := w.events(defaultProj); len(got) != 1 || got[0] != string(EventLoginSuccess) {
		t.Fatalf("default project: expected [login_success], got %v", got)
	}
}

// TestLog_NoScoperUsesBootDefault proves that without a ProjectScoper the
// logger behaves as before: writes go to the boot-default project via the
// boot writer. This preserves the zero-config single-project path.
func TestLog_NoScoperUsesBootDefault(t *testing.T) {
	const defaultProj = "default"
	w := newPartitionedWriter()
	l := NewLogger(w, defaultProj, zap.NewNop())

	// A project IS present in context, but no scoper is installed, so it is
	// ignored and the write lands under the boot default.
	l.Log(ctxWithProject("project-a"), EventLoginSuccess, WithActor("user-x"))

	if got := w.events(defaultProj); len(got) != 1 {
		t.Fatalf("default project: expected 1 event, got %v", got)
	}
	if got := w.events("project-a"); len(got) != 0 {
		t.Errorf("project-a: expected no events without a scoper, got %v", got)
	}
}

// TestResolveProject_PartialResolutionFallsBack proves the field-by-field
// fallback: a scoper that returns a project id but a nil writer keeps the
// boot writer (so the write is not dropped) while honouring the project id;
// a scoper that returns an empty project id is ignored entirely.
func TestResolveProject_PartialResolutionFallsBack(t *testing.T) {
	const defaultProj = "default"
	bootW := newPartitionedWriter()

	t.Run("nil writer keeps boot writer, honours project id", func(t *testing.T) {
		l := NewLogger(bootW, defaultProj, zap.NewNop()).
			WithProjectScoper(func(context.Context) (NodeWriter, string) {
				return nil, "project-z"
			})
		w, proj := l.resolveProject(context.Background())
		if w != NodeWriter(bootW) {
			t.Errorf("expected boot writer when scoper writer is nil")
		}
		if proj != "project-z" {
			t.Errorf("expected project-z, got %q", proj)
		}
	})

	t.Run("empty project id ignored entirely", func(t *testing.T) {
		other := newPartitionedWriter()
		l := NewLogger(bootW, defaultProj, zap.NewNop()).
			WithProjectScoper(func(context.Context) (NodeWriter, string) {
				return other, ""
			})
		w, proj := l.resolveProject(context.Background())
		if w != NodeWriter(bootW) {
			t.Errorf("expected boot writer when scoper project id is empty")
		}
		if proj != defaultProj {
			t.Errorf("expected boot default %q, got %q", defaultProj, proj)
		}
	})
}
