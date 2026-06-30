package app

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/scim"
)

// scimFakeRepo embeds StubRepository and overrides only the methods the SCIM
// store adapter calls, so a test can inject precise errors / values to exercise
// every error branch of repoSCIMStore directly (no HTTP round-trip).
type scimFakeRepo struct {
	service.StubRepository

	user *service.User

	errGet        error
	errCreate     error
	errUpdate     error
	errDelete     error
	errDelRefresh error
	errRevoke     error

	delRefreshCalled bool
	revokeCalled     bool
}

func (r *scimFakeRepo) GetUser(context.Context, string) (*service.User, error) {
	return r.user, r.errGet
}

func (r *scimFakeRepo) CreateUser(context.Context, *service.User) (string, error) {
	if r.errCreate != nil {
		return "", r.errCreate
	}
	return "new-id", nil
}

func (r *scimFakeRepo) UpdateUser(context.Context, string, map[string]any) error {
	return r.errUpdate
}

func (r *scimFakeRepo) DeleteUser(context.Context, string) error { return r.errDelete }

func (r *scimFakeRepo) DeleteRefreshTokensForUser(context.Context, string) error {
	r.delRefreshCalled = true
	return r.errDelRefresh
}

func (r *scimFakeRepo) RevokeSessionsForUser(context.Context, string, int64) error {
	r.revokeCalled = true
	return r.errRevoke
}

func TestMapStoreErr(t *testing.T) {
	if mapStoreErr(nil) != nil {
		t.Fatal("nil must map to nil")
	}
	if !errors.Is(mapStoreErr(service.ErrAlreadyExists), scim.ErrConflict) {
		t.Fatal("ErrAlreadyExists must map to ErrConflict")
	}
	if !errors.Is(mapStoreErr(service.ErrNotFound), scim.ErrNotFound) {
		t.Fatal("ErrNotFound must map to ErrNotFound")
	}
	sentinel := errors.New("boom")
	if got := mapStoreErr(sentinel); !errors.Is(got, sentinel) {
		t.Fatalf("unknown error must pass through, got %v", got)
	}
}

func TestRepoSCIMStore_GetUser(t *testing.T) {
	ctx := context.Background()

	// repo error → mapped through.
	s := &repoSCIMStore{repo: &scimFakeRepo{errGet: errors.New("db down")}}
	if _, err := s.GetUser(ctx, "x"); err == nil {
		t.Fatal("GetUser must surface repo error")
	}
	// nil user → ErrNotFound.
	s = &repoSCIMStore{repo: &scimFakeRepo{user: nil}}
	if _, err := s.GetUser(ctx, "x"); !errors.Is(err, scim.ErrNotFound) {
		t.Fatalf("GetUser nil user → %v, want ErrNotFound", err)
	}
}

func TestRepoSCIMStore_CreateUser_Conflict(t *testing.T) {
	s := &repoSCIMStore{repo: &scimFakeRepo{errCreate: service.ErrAlreadyExists}}
	if _, err := s.CreateUser(context.Background(), scim.User{Email: "a@b.com"}); !errors.Is(err, scim.ErrConflict) {
		t.Fatalf("CreateUser duplicate → %v, want ErrConflict", err)
	}
}

func TestRepoSCIMStore_ReplaceUser_Errors(t *testing.T) {
	ctx := context.Background()
	u := scim.User{Email: "a@b.com", Active: true}

	// GetUser error.
	s := &repoSCIMStore{repo: &scimFakeRepo{errGet: errors.New("x")}}
	if _, err := s.ReplaceUser(ctx, "id", u); err == nil {
		t.Fatal("ReplaceUser must surface GetUser error")
	}
	// not found.
	s = &repoSCIMStore{repo: &scimFakeRepo{user: nil}}
	if _, err := s.ReplaceUser(ctx, "id", u); !errors.Is(err, scim.ErrNotFound) {
		t.Fatalf("ReplaceUser missing → %v, want ErrNotFound", err)
	}
	// UpdateUser conflict.
	s = &repoSCIMStore{repo: &scimFakeRepo{user: &service.User{ID: "id"}, errUpdate: service.ErrAlreadyExists}}
	if _, err := s.ReplaceUser(ctx, "id", u); !errors.Is(err, scim.ErrConflict) {
		t.Fatalf("ReplaceUser update conflict → %v, want ErrConflict", err)
	}
	// Deactivating PUT whose revoke fails surfaces the error.
	fr := &scimFakeRepo{user: &service.User{ID: "id"}, errDelRefresh: errors.New("revoke fail")}
	s = &repoSCIMStore{repo: fr}
	if _, err := s.ReplaceUser(ctx, "id", scim.User{Email: "a@b.com", Active: false}); err == nil {
		t.Fatal("ReplaceUser deactivate must surface revoke error")
	}
	if !fr.delRefreshCalled {
		t.Fatal("ReplaceUser deactivate must attempt refresh-token revocation")
	}
}

func TestRepoSCIMStore_SetActive_RevokesAndErrors(t *testing.T) {
	ctx := context.Background()

	// Deactivation revokes both refresh tokens and sessions.
	fr := &scimFakeRepo{user: &service.User{ID: "id"}}
	s := &repoSCIMStore{repo: fr}
	if _, err := s.SetActive(ctx, "id", false); err != nil {
		t.Fatalf("SetActive deactivate: %v", err)
	}
	if !fr.delRefreshCalled || !fr.revokeCalled {
		t.Fatalf("SetActive false must revoke tokens+sessions: refresh=%v sessions=%v", fr.delRefreshCalled, fr.revokeCalled)
	}

	// Session-revocation failure surfaces.
	fr = &scimFakeRepo{user: &service.User{ID: "id"}, errRevoke: errors.New("sess fail")}
	s = &repoSCIMStore{repo: fr}
	if _, err := s.SetActive(ctx, "id", false); err == nil {
		t.Fatal("SetActive must surface session-revocation error")
	}

	// Reactivation does not revoke.
	fr = &scimFakeRepo{user: &service.User{ID: "id"}}
	s = &repoSCIMStore{repo: fr}
	if _, err := s.SetActive(ctx, "id", true); err != nil {
		t.Fatalf("SetActive activate: %v", err)
	}
	if fr.delRefreshCalled || fr.revokeCalled {
		t.Fatal("SetActive true must not revoke")
	}

	// Missing user → ErrNotFound.
	s = &repoSCIMStore{repo: &scimFakeRepo{user: nil}}
	if _, err := s.SetActive(ctx, "id", false); !errors.Is(err, scim.ErrNotFound) {
		t.Fatalf("SetActive missing → %v, want ErrNotFound", err)
	}
}

func TestRepoSCIMStore_DeleteUser(t *testing.T) {
	ctx := context.Background()

	// Missing user → ErrNotFound.
	s := &repoSCIMStore{repo: &scimFakeRepo{user: nil}}
	if err := s.DeleteUser(ctx, "id"); !errors.Is(err, scim.ErrNotFound) {
		t.Fatalf("DeleteUser missing → %v, want ErrNotFound", err)
	}
	// GetUser error.
	s = &repoSCIMStore{repo: &scimFakeRepo{errGet: errors.New("x")}}
	if err := s.DeleteUser(ctx, "id"); err == nil {
		t.Fatal("DeleteUser must surface GetUser error")
	}
	// Delete error.
	s = &repoSCIMStore{repo: &scimFakeRepo{user: &service.User{ID: "id"}, errDelete: errors.New("del fail")}}
	if err := s.DeleteUser(ctx, "id"); err == nil {
		t.Fatal("DeleteUser must surface delete error")
	}
}

func TestSplitDisplayName(t *testing.T) {
	if g, f := splitDisplayName(""); g != "" || f != "" {
		t.Fatalf("empty: %q %q", g, f)
	}
	if g, f := splitDisplayName("Solo"); g != "Solo" || f != "" {
		t.Fatalf("single: %q %q", g, f)
	}
	if g, f := splitDisplayName("Ada Lovelace"); g != "Ada" || f != "Lovelace" {
		t.Fatalf("two: %q %q", g, f)
	}
}
