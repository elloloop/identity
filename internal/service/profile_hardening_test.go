package service

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

// TestProfileService_UpdateProfile_NilRepoStub asserts UpdateProfile
// returns ErrServiceUnavailable when no Repository is wired (the
// deployer-without-persistence path). Without this branch the call
// would NPE on a nil interface deref.
func TestProfileService_UpdateProfile_NilRepoStub(t *testing.T) {
	t.Parallel()
	svc := NewProfileService(nil, newFakeDB(), "test", audit.NewLogger(nil, "test", zap.NewNop()), zap.NewNop())
	_, err := svc.UpdateProfile(context.Background(), "u-1", "Name", "")
	if !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("nil repo: err = %v, want ErrServiceUnavailable", err)
	}
}

// TestProfileService_UpdateProfile_RefetchFallback covers the fallback
// path: UpdateUser succeeded but the post-update GetUser returned nil
// or an error. UpdateProfile must still return a usable User (the
// patched-in-memory snapshot), not a 500.
func TestProfileService_UpdateProfile_RefetchFallback(t *testing.T) {
	t.Parallel()

	bootDB := newFakeDB()
	bootDB.addUser("u-1", "rf@test.com", "Original", "member", "active")
	repo := &refetchFailRepo{
		base:  fakeRepoOverFakeDB{db: bootDB},
		state: 0,
	}
	svc := NewProfileService(repo, bootDB, "test",
		audit.NewLogger(nil, "test", zap.NewNop()), zap.NewNop())

	user, err := svc.UpdateProfile(context.Background(), "u-1", "After Update", "")
	if err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if user.Name != "After Update" {
		t.Errorf("fallback path: name = %q, want patched-in-memory %q", user.Name, "After Update")
	}
}

// refetchFailRepo embeds StubRepository (so the full Repository
// interface is satisfied without spelling every method) and overrides
// GetUser to fail on the SECOND call — the post-UpdateUser re-fetch.
// UpdateUser delegates so the first GetUser + the actual write
// behave normally.
type refetchFailRepo struct {
	StubRepository
	base  fakeRepoOverFakeDB
	state int
}

func (r *refetchFailRepo) GetUser(ctx context.Context, userID string) (*User, error) {
	r.state++
	if r.state == 2 {
		return nil, errors.New("refetch unavailable")
	}
	return r.base.GetUser(ctx, userID)
}

func (r *refetchFailRepo) UpdateUser(ctx context.Context, userID string, fields map[string]any) error {
	return r.base.UpdateUser(ctx, userID, fields)
}
