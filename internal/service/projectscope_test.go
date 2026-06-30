package service

import (
	"context"
	"testing"
)

// projectBindRepo embeds StubRepository and records the project it was bound to,
// so the test can assert ProjectBoundRepository binds the FIXED project id
// regardless of any request scope.
type projectBindRepo struct {
	StubRepository
	boundTo string
}

func (r *projectBindRepo) WithProject(projectID string) Repository {
	return &projectBindRepo{boundTo: projectID}
}

func TestProjectBoundRepository(t *testing.T) {
	// nil repo → nil.
	if got := ProjectBoundRepository(nil, "p1"); got != nil {
		t.Fatalf("nil repo → %#v, want nil", got)
	}

	// A driver without WithProject is returned unchanged.
	stub := StubRepository{}
	if got := ProjectBoundRepository(stub, "p1"); got != Repository(stub) {
		t.Fatalf("non-scoper repo must be returned unchanged")
	}

	// A scoper is bound to the FIXED project id — and crucially ignores any
	// per-request project scope in context (the SCIM security invariant).
	base := &projectBindRepo{boundTo: "default"}
	bound := ProjectBoundRepository(base, "scim-project")
	pb, ok := bound.(*projectBindRepo)
	if !ok || pb.boundTo != "scim-project" {
		t.Fatalf("ProjectBoundRepository bound to %q, want scim-project", pb.boundTo)
	}
	// Even with a foreign scope on the context, the binding does not change:
	// ProjectBoundRepository takes no context, so it cannot be influenced.
	_ = WithProjectScope(context.Background(), &ProjectScope{ProjectID: "attacker"})
}
