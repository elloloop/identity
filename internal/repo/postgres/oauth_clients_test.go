package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/elloloop/identity/internal/service"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestOAuthClientRowLevelSecurity(t *testing.T) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_POSTGRES_DSN unset")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, truncateAll(ctx, dsn))
	admin, err := New(ctx, Config{DSN: dsn, MaxConns: 2, ConnTimeout: 5 * time.Second, ProjectID: "oauth-rls-a"})
	require.NoError(t, err)
	defer admin.Close()
	seedProject(ctx, t, admin, "oauth-rls-a")
	seedProject(ctx, t, admin, "oauth-rls-b")
	appDSN := provisionRLSAppRole(ctx, t, dsn)
	repo, err := New(ctx, Config{DSN: appDSN, MaxConns: 2, ConnTimeout: 5 * time.Second, ProjectID: "oauth-rls-a"})
	require.NoError(t, err)
	defer repo.Close()
	client := &service.OAuthClient{ID: "native-client", Kind: service.OAuthClientNativePublic, Revision: 1, CreatedAt: 100, UpdatedAt: 100, Registration: service.OAuthClientRegistration{Name: "Acme desktop", RedirectURIs: []string{"http://127.0.0.1/callback"}, Resources: []service.OAuthResourceBounds{{Resource: "urn:example:records", Scopes: []string{"read"}}}, GrantTypes: []string{"authorization_code"}}}
	require.NoError(t, repo.CreateOAuthClient(ctx, client))
	raw, err := pgx.Connect(ctx, appDSN)
	require.NoError(t, err)
	defer func() { _ = raw.Close(ctx) }()
	var superuser, bypass bool
	require.NoError(t, raw.QueryRow(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&superuser, &bypass))
	require.False(t, superuser)
	require.False(t, bypass)
	for _, project := range []string{"", "oauth-rls-b", "oauth-rls-a"} {
		_, err := raw.Exec(ctx, `SELECT set_config('app.current_project_id',$1,false)`, project)
		require.NoError(t, err)
		var count int
		require.NoError(t, raw.QueryRow(ctx, `SELECT count(*) FROM oauth_clients`).Scan(&count))
		if project == "oauth-rls-a" {
			require.Equal(t, 1, count)
		} else {
			require.Zero(t, count)
			tag, err := raw.Exec(ctx, `UPDATE oauth_clients SET revision=revision+1`)
			require.NoError(t, err)
			require.Zero(t, tag.RowsAffected())
			_, err = raw.Exec(ctx, `INSERT INTO oauth_clients(project_id,id,kind,registration_json,revision,created_at_ms,updated_at_ms) VALUES('oauth-rls-a','injected','native_public','{}',1,100,100)`)
			require.Error(t, err, "RLS must reject writes into another project")
		}
	}
	stored, err := repo.GetOAuthClient(ctx, client.ID)
	require.NoError(t, err)
	require.EqualValues(t, 1, stored.Revision)
}
