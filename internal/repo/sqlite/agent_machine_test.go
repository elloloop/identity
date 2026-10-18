package sqlite

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAgentMachineMigrationRoundTrip(t *testing.T) {
	repo := newTestRepo(t, "machine-migration")
	for _, version := range []uint{24, 25, 24, 25} {
		migrateTo(t, repo.db.db, version)
		var count int
		require.NoError(t, repo.db.QueryRow(context.Background(), "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='agent_machines'").Scan(&count))
		if version == 25 {
			require.Equal(t, 1, count)
		} else {
			require.Zero(t, count)
		}
	}
}
