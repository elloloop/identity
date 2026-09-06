//go:build integration

package integration

import (
	"testing"

	"github.com/elloloop/identity/internal/repo/conformance"
	"github.com/elloloop/identity/internal/service"
)

// TestMemRepo_Conformance runs the cross-driver Repository suite against the
// integration harness's own in-memory repository.
//
// MemRepo is a fourth hand-written Repository implementation alongside
// postgres, sqlite and internal/repo/memory. Every integration test in this
// package runs against it, so a behaviour it gets wrong is a behaviour those
// tests silently bless — and until now nothing held it to the same contract
// the three real drivers are held to. Running the suite here does not remove
// the duplication, but it removes the part that matters: the two can no
// longer diverge quietly.
func TestMemRepo_Conformance(t *testing.T) {
	conformance.RunConformance(t, conformance.Driver{
		Name: "integration-memrepo",
		NewRepo: func(t *testing.T) service.Repository {
			return NewMemRepo()
		},
	})
}
