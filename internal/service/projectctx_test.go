package service

import (
	"context"
	"testing"
)

func TestProjectScope_RoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	if got := ProjectScopeFromContext(ctx); got != nil {
		t.Fatalf("empty context: got %+v, want nil", got)
	}

	scope := &ProjectScope{ProjectID: "proj-1", StorageScopeID: "scope-1"}
	ctx = WithProjectScope(ctx, scope)

	got := ProjectScopeFromContext(ctx)
	if got == nil {
		t.Fatal("scope not found in context")
	}
	if got.ProjectID != "proj-1" || got.StorageScopeID != "scope-1" {
		t.Fatalf("round-trip mismatch: got %+v", got)
	}
}

func TestWithProjectScope_NilIsNoOp(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	if WithProjectScope(ctx, nil) != ctx {
		t.Fatal("WithProjectScope(nil) must return the same context unchanged")
	}
}
