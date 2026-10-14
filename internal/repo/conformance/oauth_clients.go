package conformance

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/elloloop/identity/internal/service"
	"github.com/stretchr/testify/require"
)

func oauthClientRecord(id string) *service.OAuthClient {
	return &service.OAuthClient{ID: id, Kind: service.OAuthClientNativePublic, Revision: 1, CreatedAt: 100, UpdatedAt: 100, Registration: service.OAuthClientRegistration{Name: "Acme desktop", RedirectURIs: []string{"http://127.0.0.1/callback"}, Resources: []service.OAuthResourceBounds{{Resource: "urn:example:records", Scopes: []string{"read"}}}, GrantTypes: []string{"authorization_code", "refresh_token"}}}
}

func runOAuthClientsConformance(t *testing.T, driver Driver) {
	t.Helper()
	t.Run(driver.Name+"/OAuthClients", func(t *testing.T) {
		t.Run("RoundTripCASAndCopies", func(t *testing.T) {
			ctx := context.Background()
			repo := driver.NewRepo(t)
			original := oauthClientRecord("a")
			require.NoError(t, repo.CreateOAuthClient(ctx, original))
			require.ErrorIs(t, repo.CreateOAuthClient(ctx, original), service.ErrAlreadyExists)
			original.Registration.Resources[0].Scopes[0] = "write"
			got, err := repo.GetOAuthClient(ctx, "a")
			require.NoError(t, err)
			require.Equal(t, oauthClientRecord("a"), got)
			got.Registration.RedirectURIs[0] = "https://other.example.test/cb"
			stored, err := repo.GetOAuthClient(ctx, "a")
			require.NoError(t, err)
			require.Equal(t, oauthClientRecord("a"), stored)
			reg := oauthClientRecord("b").Registration
			reg.Disabled = true
			updated, err := repo.UpdateOAuthClient(ctx, "a", 1, &reg, 200)
			require.NoError(t, err)
			require.EqualValues(t, 2, updated.Revision)
			require.EqualValues(t, 100, updated.CreatedAt)
			require.EqualValues(t, 200, updated.UpdatedAt)
			require.True(t, updated.Registration.Disabled)
			stale, err := repo.UpdateOAuthClient(ctx, "a", 1, &reg, 300)
			require.NoError(t, err)
			require.Nil(t, stale)
			reg.Disabled = false
			reg.Resources[0].Scopes[0] = "wider"
			still, err := repo.GetOAuthClient(ctx, "a")
			require.NoError(t, err)
			require.True(t, still.Registration.Disabled)
			require.Equal(t, []string{"read"}, still.Registration.Resources[0].Scopes)
			updated.Registration.Resources[0].Scopes[0] = "mutated result"
			still, err = repo.GetOAuthClient(ctx, "a")
			require.NoError(t, err)
			require.Equal(t, []string{"read"}, still.Registration.Resources[0].Scopes)
			missing, err := repo.GetOAuthClient(ctx, "missing")
			require.NoError(t, err)
			require.Nil(t, missing)
			missing, err = repo.UpdateOAuthClient(ctx, "missing", 1, &reg, 300)
			require.NoError(t, err)
			require.Nil(t, missing)
			require.ErrorIs(t, repo.CreateOAuthClient(ctx, nil), service.ErrInvalidArgument)
			_, err = repo.UpdateOAuthClient(ctx, "a", 2, nil, 300)
			require.ErrorIs(t, err, service.ErrInvalidArgument)
		})
		t.Run("SortedBoundedPages", func(t *testing.T) {
			ctx := context.Background()
			repo := driver.NewRepo(t)
			for _, id := range []string{"c", "a", "b"} {
				require.NoError(t, repo.CreateOAuthClient(ctx, oauthClientRecord(id)))
			}
			first, err := repo.ListOAuthClients(ctx, "", 2)
			require.NoError(t, err)
			require.Len(t, first, 2)
			require.Equal(t, "a", first[0].ID)
			require.Equal(t, "b", first[1].ID)
			second, err := repo.ListOAuthClients(ctx, "b", 2)
			require.NoError(t, err)
			require.Len(t, second, 1)
			require.Equal(t, "c", second[0].ID)
			end, err := repo.ListOAuthClients(ctx, "c", 2)
			require.NoError(t, err)
			require.Empty(t, end)
			for _, limit := range []int{-1, 0, 101} {
				_, err = repo.ListOAuthClients(ctx, "", limit)
				require.ErrorIs(t, err, service.ErrInvalidArgument)
			}
			_, err = repo.ListOAuthClients(ctx, "bad cursor", 2)
			require.ErrorIs(t, err, service.ErrInvalidArgument)
			first[0].Registration.Resources[0].Scopes[0] = "mutated"
			got, err := repo.GetOAuthClient(ctx, "a")
			require.NoError(t, err)
			require.Equal(t, []string{"read"}, got.Registration.Resources[0].Scopes)
		})
		t.Run("ConcurrentCASHasOneWinner", func(t *testing.T) {
			ctx := context.Background()
			repo := driver.NewRepo(t)
			client := oauthClientRecord("a")
			require.NoError(t, repo.CreateOAuthClient(ctx, client))
			var group sync.WaitGroup
			var winners atomic.Int32
			failures := make(chan error, 16)
			for range 16 {
				group.Add(1)
				go func() {
					defer group.Done()
					updated, err := repo.UpdateOAuthClient(ctx, "a", 1, &client.Registration, 200)
					if err != nil {
						failures <- err
					}
					if updated != nil {
						winners.Add(1)
					}
				}()
			}
			group.Wait()
			close(failures)
			for err := range failures {
				require.NoError(t, err)
			}
			require.EqualValues(t, 1, winners.Load())
			got, err := repo.GetOAuthClient(ctx, "a")
			require.NoError(t, err)
			require.EqualValues(t, 2, got.Revision)
		})
		t.Run("ProjectIsolation", func(t *testing.T) {
			if driver.BindProject == nil {
				t.Skip("driver has no project binding")
			}
			ctx := context.Background()
			base := driver.NewRepo(t)
			one := driver.BindProject(t, base, "oauth-project-one")
			two := driver.BindProject(t, base, "oauth-project-two")
			client := oauthClientRecord("same-id")
			require.NoError(t, one.CreateOAuthClient(ctx, client))
			got, err := two.GetOAuthClient(ctx, client.ID)
			require.NoError(t, err)
			require.Nil(t, got)
			list, err := two.ListOAuthClients(ctx, "", 10)
			require.NoError(t, err)
			require.Empty(t, list)
			got, err = two.UpdateOAuthClient(ctx, client.ID, 1, &client.Registration, 200)
			require.NoError(t, err)
			require.Nil(t, got)
			other := client.Clone()
			other.Registration.Name = "Another client"
			require.NoError(t, two.CreateOAuthClient(ctx, other))
			other.Registration.Disabled = true
			_, err = two.UpdateOAuthClient(ctx, other.ID, 1, &other.Registration, 200)
			require.NoError(t, err)
			got, err = one.GetOAuthClient(ctx, client.ID)
			require.NoError(t, err)
			require.Equal(t, client, got)
		})
	})
}
