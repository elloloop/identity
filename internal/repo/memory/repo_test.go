package memory_test

import (
	"testing"

	"github.com/elloloop/identity/internal/repo/conformance"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
)

// TestMemoryConformance runs the driver-agnostic conformance suite
// against the in-memory Repository implementation.
func TestMemoryConformance(t *testing.T) {
	t.Parallel()
	conformance.RunConformance(t, func(_ *testing.T) service.Repository {
		return memory.New()
	})
}
