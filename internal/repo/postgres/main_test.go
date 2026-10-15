package postgres

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	os.Exit(runPostgresTests(m.Run))
}

func runPostgresTests(run func() int) (code int) {
	dsn := os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	if dsn == "" {
		return run()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "postgres test fixture: could not connect to configured test database")
		return 1
	}
	defer func() { _ = admin.Close(context.Background()) }()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		fmt.Fprintln(os.Stderr, "postgres test fixture: could not generate isolated database name")
		return 1
	}
	nonce[6] = nonce[6]&0x0f | 0x40
	nonce[8] = nonce[8]&0x3f | 0x80
	database := fmt.Sprintf("identity_repo_%x-%x-%x-%x-%x", nonce[:4], nonce[4:6], nonce[6:8], nonce[8:10], nonce[10:])
	name := pgx.Identifier{database}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		fmt.Fprintf(os.Stderr, "postgres test fixture: cannot create isolated database (test role needs CREATEDB): %v\n", err)
		return 1
	}
	// Conformance truncates its tables. A package-local database prevents
	// that from deleting fixtures owned by concurrent coverage packages.
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP DATABASE "+name+" WITH (FORCE)"); err != nil {
			fmt.Fprintf(os.Stderr, "postgres test fixture: could not drop owned database %s: %v\n", database, err)
			if code == 0 {
				code = 1
			}
		}
	}()
	isolated, err := postgresTestDSN(dsn, database)
	if err != nil {
		fmt.Fprintln(os.Stderr, "postgres test fixture: cannot select isolated database in configured DSN")
		return 1
	}
	if err := os.Setenv("GATEWAY_TEST_POSTGRES_DSN", isolated); err != nil {
		fmt.Fprintln(os.Stderr, "postgres test fixture: cannot set process-local test DSN")
		return 1
	}
	return run()
}

func postgresTestDSN(dsn, database string) (string, error) {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "", err
		}
		q := u.Query()
		q.Del("database")
		q.Del("dbname")
		u.Path, u.RawPath, u.RawQuery = "/"+database, "", q.Encode()
		return u.String(), nil
	}
	escaped := strings.ReplaceAll(strings.ReplaceAll(database, `\`, `\\`), `'`, `\'`)
	return dsn + " dbname='" + escaped + "'", nil
}

func TestPostgresTestDSNPreservesConnectionOptions(t *testing.T) {
	for _, dsn := range []string{
		"postgres://fixture:p%40ss@db.example.test:5444/base?sslmode=require&application_name=suite&connect_timeout=7&dbname=query_base&statement_timeout=5000",
		"postgresql://fixture:p%40ss@db.example.test:5444/base?sslmode=disable&database=query_base&application_name=suite",
		"host=db.example.test port=5444 user=fixture password='p@ss word' dbname=base sslmode=require application_name=suite connect_timeout=7 statement_timeout=5000",
	} {
		before, err := pgx.ParseConfig(dsn)
		require.NoError(t, err)
		isolated, err := postgresTestDSN(dsn, "identity_repo_test-db")
		require.NoError(t, err)
		after, err := pgx.ParseConfig(isolated)
		require.NoError(t, err)
		require.Equal(t, "identity_repo_test-db", after.Database)
		require.Equal(t, before.Host, after.Host)
		require.Equal(t, before.Port, after.Port)
		require.Equal(t, before.User, after.User)
		require.Equal(t, before.Password, after.Password)
		require.Equal(t, before.RuntimeParams, after.RuntimeParams)
		require.Equal(t, before.ConnectTimeout, after.ConnectTimeout)
		if before.TLSConfig == nil {
			require.Nil(t, after.TLSConfig)
		} else {
			require.NotNil(t, after.TLSConfig)
			require.Equal(t, before.TLSConfig.ServerName, after.TLSConfig.ServerName)
			require.Equal(t, before.TLSConfig.InsecureSkipVerify, after.TLSConfig.InsecureSkipVerify)
		}
	}
}
