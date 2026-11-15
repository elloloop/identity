package conformance

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/elloloop/identity/internal/service"
	"github.com/stretchr/testify/require"
)

func runDateOfBirthPresenceConformance(t *testing.T, driver Driver) {
	t.Helper()
	t.Run(driver.Name+"/DateOfBirthPresence", func(t *testing.T) {
		ctx := context.Background()
		repo := driver.NewRepo(t)
		for i, dob := range []int64{0, -1000, 1000} {
			t.Run(strconv.FormatInt(dob, 10), func(t *testing.T) {
				input := new(dob)
				id, err := repo.CreateUser(ctx, &service.User{Email: fmt.Sprintf("presence-%d@example.test", i), Status: "active", DateOfBirthMs: input})
				require.NoError(t, err)
				*input = 999
				got, err := repo.GetUser(ctx, id)
				require.NoError(t, err)
				require.Equal(t, new(dob), got.DateOfBirthMs)
				*got.DateOfBirthMs = 888
				again, err := repo.GetUser(ctx, id)
				require.NoError(t, err)
				require.Equal(t, new(dob), again.DateOfBirthMs)
				won, err := repo.SetDateOfBirthOnce(ctx, id, 777, "", 1)
				require.NoError(t, err)
				require.False(t, won)
				unknown, err := repo.CreateUser(ctx, &service.User{Email: fmt.Sprintf("completion-%d@example.test", i), Status: service.StatusActive})
				require.NoError(t, err)
				won, err = repo.SetDateOfBirthOnce(ctx, unknown, dob, "", 2)
				require.NoError(t, err)
				require.True(t, won)
				won, err = repo.SetDateOfBirthOnce(ctx, unknown, 777, "", 3)
				require.NoError(t, err)
				require.False(t, won)
				got, err = repo.GetUser(ctx, unknown)
				require.NoError(t, err)
				require.Equal(t, new(dob), got.DateOfBirthMs)
				err = repo.UpdateUser(ctx, id, map[string]any{"date_of_birth_ms": int64(0)})
				require.NoError(t, err)
				got, err = repo.GetUser(ctx, id)
				require.NoError(t, err)
				require.Equal(t, new(int64(0)), got.DateOfBirthMs)
			})
		}
	})
}
