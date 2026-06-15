package sqlite

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// TestWrapErr covers the non-unique and nil branches of the error translator,
// plus isUniqueViolation against a non-SQLite error.
func TestWrapErr(t *testing.T) {
	if err := wrapErr("op", nil); err != nil {
		t.Fatalf("wrapErr(nil) = %v, want nil", err)
	}
	base := errors.New("boom")
	err := wrapErr("doThing", base)
	if !errors.Is(err, base) {
		t.Fatalf("wrapErr should wrap the base error: %v", err)
	}
	if errors.Is(err, service.ErrAlreadyExists) {
		t.Fatal("non-unique error must not map to ErrAlreadyExists")
	}
	if !strings.Contains(err.Error(), "doThing") {
		t.Fatalf("wrapErr should carry op name: %v", err)
	}
	if isUniqueViolation(errors.New("not a sqlite error")) {
		t.Fatal("plain error must not be a unique violation")
	}
}

// TestNullableHelpers covers the type-normalisation helpers used by the
// map-patch update methods, including their reject branches.
func TestNullableHelpers(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want int64
		ok   bool
	}{
		{int64(7), 7, true},
		{int(8), 8, true},
		{int32(9), 9, true},
		{float64(10), 10, true},
		{"x", 0, false},
	} {
		got, ok := nullableInt64(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("nullableInt64(%#v) = %d,%v want %d,%v", tc.in, got, ok, tc.want, tc.ok)
		}
	}

	if v, ok := nullableBool(true); !v || !ok {
		t.Fatalf("nullableBool(true) = %v,%v", v, ok)
	}
	if _, ok := nullableBool("nope"); ok {
		t.Fatal("nullableBool(string) should be !ok")
	}

	if v, ok := nullableString("hi"); v != "hi" || !ok {
		t.Fatalf("nullableString(\"hi\") = %q,%v", v, ok)
	}
	if _, ok := nullableString(42); ok {
		t.Fatal("nullableString(int) should be !ok")
	}
}

// TestConfigFromEnv covers the env-var reader and its envInt helper, including
// the default, valid-override, and non-numeric-fallback branches.
func TestConfigFromEnv(t *testing.T) {
	t.Setenv("GATEWAY_SQLITE_PATH", "/tmp/identity.db")
	t.Setenv("GATEWAY_SQLITE_MAX_CONNS", "9")
	cfg := ConfigFromEnv("proj-1")
	if cfg.Path != "/tmp/identity.db" {
		t.Fatalf("Path = %q", cfg.Path)
	}
	if cfg.MaxConns != 9 {
		t.Fatalf("MaxConns = %d, want 9", cfg.MaxConns)
	}
	if cfg.ProjectID != "proj-1" {
		t.Fatalf("ProjectID = %q", cfg.ProjectID)
	}

	// Non-numeric value falls back to the default.
	t.Setenv("GATEWAY_SQLITE_MAX_CONNS", "not-a-number")
	if got := ConfigFromEnv("p").MaxConns; got != DefaultMaxConns {
		t.Fatalf("MaxConns on bad input = %d, want default %d", got, DefaultMaxConns)
	}

	// Unset value falls back to the default.
	t.Setenv("GATEWAY_SQLITE_MAX_CONNS", "")
	if got := ConfigFromEnv("p").MaxConns; got != DefaultMaxConns {
		t.Fatalf("MaxConns when unset = %d, want default %d", got, DefaultMaxConns)
	}
}

// TestConfigValidate covers each validation branch.
func TestConfigValidate(t *testing.T) {
	var nilCfg *Config
	if err := nilCfg.validate(); err == nil {
		t.Fatal("nil config: want error")
	}
	if err := (&Config{Path: "", ProjectID: "p"}).validate(); err == nil {
		t.Fatal("empty path: want error")
	}
	if err := (&Config{Path: MemoryPath, ProjectID: " "}).validate(); err == nil {
		t.Fatal("blank project id: want error")
	}
	if err := (&Config{Path: MemoryPath, ProjectID: "p"}).validate(); err != nil {
		t.Fatalf("valid config: unexpected error %v", err)
	}
}

// TestConfigDSN verifies the in-memory path stays WAL-free while the on-disk
// path appends the WAL + synchronous(NORMAL) pragmas (gated to file-backed).
func TestConfigDSN(t *testing.T) {
	memCfg := &Config{Path: MemoryPath, ProjectID: "p"}
	memDSN, inMem := memCfg.dsn()
	if !inMem {
		t.Fatal(":memory: should report in-memory")
	}
	if strings.Contains(memDSN, "journal_mode(WAL)") {
		t.Fatalf("in-memory DSN must not request WAL: %q", memDSN)
	}
	if !strings.Contains(memDSN, "foreign_keys(1)") || !strings.Contains(memDSN, "busy_timeout(5000)") {
		t.Fatalf("in-memory DSN missing base pragmas: %q", memDSN)
	}

	fileCfg := &Config{Path: "/tmp/identity.db", ProjectID: "p"}
	fileDSN, inMem := fileCfg.dsn()
	if inMem {
		t.Fatal("file path should not report in-memory")
	}
	if !strings.Contains(fileDSN, "journal_mode(WAL)") {
		t.Fatalf("file DSN must request WAL: %q", fileDSN)
	}
	if !strings.Contains(fileDSN, "synchronous(NORMAL)") {
		t.Fatalf("file DSN must request synchronous(NORMAL): %q", fileDSN)
	}

	// A file::memory: form is also treated as in-memory (no WAL).
	prefixCfg := &Config{Path: "file::memory:?cache=shared", ProjectID: "p"}
	if _, inMem := prefixCfg.dsn(); !inMem {
		t.Fatal("file::memory: prefix should report in-memory")
	}
}

// TestNewRejectsInvalidConfig confirms New surfaces validation failures
// before opening a pool.
func TestNewRejectsInvalidConfig(t *testing.T) {
	if _, err := New(context.Background(), Config{Path: "", ProjectID: "p"}); err == nil {
		t.Fatal("New with empty path: want error")
	}
}

// TestOpenPingFailure covers open's ping/connect error branch: pointing the
// on-disk path at a directory makes the first PingContext fail.
func TestOpenPingFailure(t *testing.T) {
	dir := t.TempDir() // a directory, not a file — opening it as a DB fails.
	_, err := New(context.Background(), Config{Path: dir, ProjectID: "p"})
	if err == nil {
		t.Fatal("New on a directory path: want error")
	}
}

// TestMethodErrorAfterClose drives a Repository method against a closed pool so
// the wrapErr error branch (otherwise only the happy path runs) is exercised.
func TestMethodErrorAfterClose(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t, "sqlite-closed")
	repo.Close()
	if _, err := repo.GetUser(ctx, "anyone"); err == nil {
		t.Fatal("GetUser on closed pool: want error")
	}
	if _, err := repo.FindUserByEmail(ctx, "anyone@example.com"); err == nil {
		t.Fatal("FindUserByEmail on closed pool: want error")
	}
	if _, err := repo.FindRefreshTokenByHash(ctx, "h"); err == nil {
		t.Fatal("FindRefreshTokenByHash on closed pool: want error")
	}
	if err := repo.DeleteRefreshTokensForUser(ctx, "u"); err == nil {
		t.Fatal("DeleteRefreshTokensForUser on closed pool: want error")
	}
	if err := repo.RevokeSessionsForUser(ctx, "u", nowMs()); err == nil {
		t.Fatal("RevokeSessionsForUser on closed pool: want error")
	}
	if err := repo.EnsureDefaultProject(ctx, "p", "n"); err == nil {
		t.Fatal("EnsureDefaultProject on closed pool: want error")
	}
}

// TestEnsureDefaultProjectRejectsEmptyID covers the guard branch.
func TestEnsureDefaultProjectRejectsEmptyID(t *testing.T) {
	repo := newTestRepo(t, "sqlite-guard")
	err := repo.EnsureDefaultProject(context.Background(), "", "name")
	if !errors.Is(err, service.ErrInvalidArgument) {
		t.Fatalf("empty project id: err = %v, want ErrInvalidArgument", err)
	}
}

// TestDBGraphStubBehavior exercises the service.DB graph surface: reads return
// ErrServiceUnavailable, edge reads return nil, and the write paths are
// no-op successes. Mirrors the memory driver's stub contract so the two
// embedded-tier drivers stay behaviourally identical.
func TestDBGraphStubBehavior(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t, "sqlite-graph")

	if _, err := repo.GetNode(ctx, "tenant", "actor", 1, "node"); !errors.Is(err, service.ErrServiceUnavailable) {
		t.Fatalf("GetNode err = %v", err)
	}
	if _, err := repo.QueryNodes(ctx, "tenant", "actor", 1, map[string]any{"k": "v"}); !errors.Is(err, service.ErrServiceUnavailable) {
		t.Fatalf("QueryNodes err = %v", err)
	}
	if _, err := repo.SearchNodes(ctx, "tenant", "actor", 1, "query"); !errors.Is(err, service.ErrServiceUnavailable) {
		t.Fatalf("SearchNodes err = %v", err)
	}
	result, err := repo.ExecuteAtomic(ctx, "tenant", "actor", nil)
	if err != nil {
		t.Fatalf("ExecuteAtomic: %v", err)
	}
	if result == nil || !result.Success || !result.Applied {
		t.Fatalf("ExecuteAtomic result = %+v", result)
	}
	if edges, err := repo.GetEdgesFrom(ctx, "tenant", "actor", "node", 1); err != nil || edges != nil {
		t.Fatalf("GetEdgesFrom edges=%v err=%v", edges, err)
	}
	if edges, err := repo.GetEdgesTo(ctx, "tenant", "actor", "node", 1); err != nil || edges != nil {
		t.Fatalf("GetEdgesTo edges=%v err=%v", edges, err)
	}
	if err := repo.RegisterUserInTenant(ctx, "a", "b", "c", "d", "e"); err != nil {
		t.Fatalf("RegisterUserInTenant: %v", err)
	}
}

// TestInvitationFindAndUpdate covers FindInvitationByHash (hit, miss, empty
// hash) and UpdateInvitation (mapped fields, unknown fields skipped, missing
// id error, empty/no-op patches).
func TestInvitationFindAndUpdate(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t, "sqlite-inv")

	uid, err := repo.CreateUser(ctx, &service.User{Email: "inv@example.com", Status: "active"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	const insert = `
		INSERT INTO user_invitations
		  (id, project_id, token_hash, email, user_id, invited_by, role,
		   expires_at_ms, accepted_at_ms, created_at_ms)
		VALUES ($1, $2, $3, $4, '', $5, 'member', $6, 0, $7)`
	now := nowMs()
	id := newID()
	if _, err := repo.db.Exec(ctx, insert, id, repo.projectID, "inv-hash",
		"inv@example.com", uid, now+10_000, now); err != nil {
		t.Fatalf("seed invitation: %v", err)
	}

	// Empty hash short-circuits to nil.
	if got, err := repo.FindInvitationByHash(ctx, ""); err != nil || got != nil {
		t.Fatalf("FindInvitationByHash(\"\") = %v, %v", got, err)
	}
	// Miss.
	if got, err := repo.FindInvitationByHash(ctx, "nope"); err != nil || got != nil {
		t.Fatalf("FindInvitationByHash(miss) = %v, %v", got, err)
	}
	// Hit.
	inv, err := repo.FindInvitationByHash(ctx, "inv-hash")
	if err != nil || inv == nil {
		t.Fatalf("FindInvitationByHash(hit) = %v, %v", inv, err)
	}
	if inv.Email != "inv@example.com" {
		t.Fatalf("invitation email = %q", inv.Email)
	}

	// Missing node id is an error.
	if err := repo.UpdateInvitation(ctx, "", map[string]any{"user_id": uid}); err == nil {
		t.Fatal("UpdateInvitation with empty id: want error")
	}
	// Empty patch is a no-op.
	if err := repo.UpdateInvitation(ctx, id, nil); err != nil {
		t.Fatalf("UpdateInvitation(nil patch): %v", err)
	}
	// Only unknown / wrong-typed fields => no-op (no SET clause).
	if err := repo.UpdateInvitation(ctx, id, map[string]any{
		"unknown":     "x",
		"user_id":     123,       // wrong type for a string column: skipped
		"accepted_at": "not-int", // wrong type for an int column: skipped
	}); err != nil {
		t.Fatalf("UpdateInvitation(no mappable fields): %v", err)
	}
	// Real update: accept + bind the user.
	if err := repo.UpdateInvitation(ctx, id, map[string]any{
		"accepted_at": now + 1,
		"user_id":     uid,
	}); err != nil {
		t.Fatalf("UpdateInvitation(accept): %v", err)
	}
	got, err := repo.FindInvitationByHash(ctx, "inv-hash")
	if err != nil || got == nil {
		t.Fatalf("re-find after update: %v, %v", got, err)
	}
	if got.AcceptedAt != now+1 {
		t.Fatalf("AcceptedAt = %d, want %d", got.AcceptedAt, now+1)
	}
	if got.UserID != uid {
		t.Fatalf("UserID = %q, want %q", got.UserID, uid)
	}
}
