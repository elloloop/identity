package app

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/identity/internal/graph"
)

// stubDB is a no-op service.DB that records the last QueryNodes call.
type stubDB struct {
	lastTypeID int
	failQuery  error
}

func (s *stubDB) GetNode(_ context.Context, _, _ string, _ int, _ string) (*graph.Node, error) {
	return nil, nil
}

func (s *stubDB) QueryNodes(_ context.Context, _, _ string, typeID int, _ map[string]any) ([]*graph.Node, error) {
	s.lastTypeID = typeID
	return nil, s.failQuery
}

func (s *stubDB) ExecuteAtomic(_ context.Context, _, _ string, _ []graph.Operation) (*graph.CommitResult, error) {
	return &graph.CommitResult{Success: true, Applied: true}, nil
}

func (s *stubDB) GetEdgesFrom(_ context.Context, _, _, _ string, _ int) ([]*graph.Edge, error) {
	return nil, nil
}

func (s *stubDB) GetEdgesTo(_ context.Context, _, _, _ string, _ int) ([]*graph.Edge, error) {
	return nil, nil
}

func (s *stubDB) SearchNodes(_ context.Context, _, _ string, _ int, _ string) ([]*graph.Node, error) {
	return nil, nil
}

func (s *stubDB) RegisterUserInTenant(context.Context, string, string, string, string, string) error {
	return nil
}

func TestNewDBReadinessProbe_NilReturnsNil(t *testing.T) {
	if got := newDBReadinessProbe(nil); got != nil {
		t.Fatalf("expected nil for nil DB, got %T", got)
	}
}

func TestDBProbe_Ready_QueriesUserType(t *testing.T) {
	s := &stubDB{}
	probe := newDBReadinessProbe(s)
	if probe == nil {
		t.Fatal("probe is nil")
	}
	if err := probe.Ready(context.Background()); err != nil {
		t.Fatalf("Ready: %v", err)
	}
	if s.lastTypeID != 1 {
		t.Fatalf("lastTypeID = %d, want 1 (User)", s.lastTypeID)
	}
}

func TestDBProbe_Ready_PropagatesError(t *testing.T) {
	s := &stubDB{failQuery: errors.New("db down")}
	probe := newDBReadinessProbe(s)
	if err := probe.Ready(context.Background()); err == nil {
		t.Fatal("expected error to propagate")
	}
}
