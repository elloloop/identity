package sqlite

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/elloloop/identity/internal/repo/conformance"
	"github.com/elloloop/identity/internal/service"
)

// newTestRepo builds a fresh, isolated in-memory SQLite repository. Each call
// gets a uniquely-named shared-cache in-memory database (so subtests never
// share state), pinned to a single connection, migrated, and bound to
// projectID with the projects(id) seed row already in place. Close is
// registered on cleanup.
func newTestRepo(t *testing.T, projectID string) *sqliteRepository {
	t.Helper()
	ctx := context.Background()
	name := fmt.Sprintf("sqlite-test-%s-%d", t.Name(), time.Now().UnixNano())
	repo, err := open(ctx, memoryDSNForName(name), true, 1, projectID)
	if err != nil {
		t.Fatalf("open in-memory sqlite: %v", err)
	}
	t.Cleanup(repo.Close)
	if err := repo.EnsureDefaultProject(ctx, projectID, projectID); err != nil {
		t.Fatalf("seed default project: %v", err)
	}
	return repo
}

// TestConformance runs the driver-agnostic Repository conformance suite
// against the pure-Go SQLite driver. It needs no external service, so unlike
// the postgres leg it always runs in CI.
func TestConformance(t *testing.T) {
	t.Parallel()
	conformance.RunConformance(t, conformance.Driver{
		Name: "sqlite",
		NewRepo: func(t *testing.T) service.Repository {
			t.Helper()
			return newTestRepo(t, "sqlite-conformance")
		},
		// Binding a project seeds its projects(id) row (the project_id FK
		// target) on the SAME backing store, then rebinds via WithProject so
		// the cross-project isolation subtest exercises the real per-request
		// scoping over one connection pool.
		BindProject: func(t *testing.T, base service.Repository, projectID string) service.Repository {
			t.Helper()
			repo := base.(*sqliteRepository)
			if err := repo.EnsureDefaultProject(context.Background(), projectID, projectID); err != nil {
				t.Fatalf("seed bound project: %v", err)
			}
			return repo.WithProject(projectID)
		},
	})
}

// TestSQLite_CaseInsensitiveEmail verifies the lower(email) unique index
// gives case-insensitive lookup + uniqueness, the SQLite analogue of the
// postgres smoke test (the conformance suite only asserts exact-match).
func TestSQLite_CaseInsensitiveEmail(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := newTestRepo(t, "sqlite-smoke")

	id, err := repo.CreateUser(ctx, &service.User{
		Email: "alice@example.com", Name: "Alice", Role: "admin", Status: "active",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if id == "" {
		t.Fatal("CreateUser returned empty id")
	}

	got, err := repo.FindUserByEmail(ctx, "Alice@Example.com")
	if err != nil {
		t.Fatalf("FindUserByEmail mixed-case: %v", err)
	}
	if got == nil || got.ID != id {
		t.Fatalf("case-insensitive lookup failed: got %#v", got)
	}

	// A second account with a case-variant of the same address must collide
	// on the lower(email) unique index -> ErrAlreadyExists.
	_, err = repo.CreateUser(ctx, &service.User{
		Email: "ALICE@example.com", Name: "Dup", Role: "member", Status: "active",
	})
	if err == nil {
		t.Fatal("expected ErrAlreadyExists on case-variant duplicate email")
	}
}

// TestSQLite_ForeignKeyCascade verifies DeleteUser cascades user-owned rows
// (FK ON DELETE CASCADE fires because foreign_keys is enabled per
// connection).
func TestSQLite_ForeignKeyCascade(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := newTestRepo(t, "sqlite-fk")

	uid, err := repo.CreateUser(ctx, &service.User{Email: "bob@example.com", Status: "active"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := repo.CreateRefreshToken(ctx, &service.RefreshTokenRecord{
		UserID: uid, TokenHash: "rt-hash", ExpiresAt: 9_999_999, CreatedAt: 1,
	}); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	if err := repo.DeleteUser(ctx, uid); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if got, _ := repo.GetUser(ctx, uid); got != nil {
		t.Fatal("user still present after DeleteUser")
	}
	if got, _ := repo.FindRefreshTokenByHash(ctx, "rt-hash"); got != nil {
		t.Fatal("refresh token not cascaded by DeleteUser")
	}
}

// TestSQLite_FileBacked exercises the on-disk path end to end (open, migrate,
// CRUD, reopen) so the file branch — not just :memory: — is covered.
func TestSQLite_FileBacked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := t.TempDir() + "/identity.db"

	repo, err := New(ctx, Config{Path: path, ProjectID: "p1"})
	if err != nil {
		t.Fatalf("New file-backed: %v", err)
	}
	if err := repo.EnsureDefaultProject(ctx, "p1", "p1"); err != nil {
		t.Fatalf("EnsureDefaultProject: %v", err)
	}
	uid, err := repo.CreateUser(ctx, &service.User{Email: "carol@example.com", Status: "active"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	repo.Close()

	// Reopen the same file: the migration is idempotent and the row persists.
	repo2, err := New(ctx, Config{Path: path, ProjectID: "p1"})
	if err != nil {
		t.Fatalf("reopen file-backed: %v", err)
	}
	defer repo2.Close()
	got, err := repo2.GetUser(ctx, uid)
	if err != nil || got == nil {
		t.Fatalf("user did not persist across reopen: got=%#v err=%v", got, err)
	}
}

// TestSQLite_EnsureDefaultProjectIdempotent confirms the boot seed is safe to
// call twice.
func TestSQLite_EnsureDefaultProjectIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := newTestRepo(t, "sqlite-seed")
	if err := repo.EnsureDefaultProject(ctx, "sqlite-seed", "seed"); err != nil {
		t.Fatalf("second EnsureDefaultProject: %v", err)
	}
}
