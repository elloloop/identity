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
	// updateCalled / deleteCalled make "the row was not mutated" assertable.
	// A refusal that still wrote would return the same error as one that
	// did not, so asserting the error alone proves nothing.
	updateCalled bool
	deleteCalled bool
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
	r.updateCalled = true
	return r.errUpdate
}

func (r *scimFakeRepo) DeleteUser(context.Context, string) error {
	r.deleteCalled = true
	return r.errDelete
}

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

func boolPtr(b bool) *bool { return &b }

func TestRepoSCIMStore_PatchUser_RevokesAndErrors(t *testing.T) {
	ctx := context.Background()

	// Deactivation via PATCH revokes both refresh tokens and sessions.
	fr := &scimFakeRepo{user: &service.User{ID: "id"}}
	s := &repoSCIMStore{repo: fr}
	if _, err := s.PatchUser(ctx, "id", scim.UserPatch{Active: boolPtr(false)}); err != nil {
		t.Fatalf("PatchUser deactivate: %v", err)
	}
	if !fr.delRefreshCalled || !fr.revokeCalled {
		t.Fatalf("PatchUser active:false must revoke tokens+sessions: refresh=%v sessions=%v", fr.delRefreshCalled, fr.revokeCalled)
	}

	// Session-revocation failure surfaces.
	fr = &scimFakeRepo{user: &service.User{ID: "id"}, errRevoke: errors.New("sess fail")}
	s = &repoSCIMStore{repo: fr}
	if _, err := s.PatchUser(ctx, "id", scim.UserPatch{Active: boolPtr(false)}); err == nil {
		t.Fatal("PatchUser must surface session-revocation error")
	}

	// A profile-only PATCH (no active) does not revoke.
	fr = &scimFakeRepo{user: &service.User{ID: "id", Name: "Old Name"}}
	s = &repoSCIMStore{repo: fr}
	if _, err := s.PatchUser(ctx, "id", scim.UserPatch{GivenName: ptr("New")}); err != nil {
		t.Fatalf("PatchUser profile: %v", err)
	}
	if fr.delRefreshCalled || fr.revokeCalled {
		t.Fatal("PatchUser without active:false must not revoke")
	}

	// Reactivation does not revoke.
	fr = &scimFakeRepo{user: &service.User{ID: "id"}}
	s = &repoSCIMStore{repo: fr}
	if _, err := s.PatchUser(ctx, "id", scim.UserPatch{Active: boolPtr(true)}); err != nil {
		t.Fatalf("PatchUser activate: %v", err)
	}
	if fr.delRefreshCalled || fr.revokeCalled {
		t.Fatal("PatchUser active:true must not revoke")
	}

	// UpdateUser conflict (e.g. email collision) maps to ErrConflict.
	fr = &scimFakeRepo{user: &service.User{ID: "id"}, errUpdate: service.ErrAlreadyExists}
	s = &repoSCIMStore{repo: fr}
	if _, err := s.PatchUser(ctx, "id", scim.UserPatch{Email: ptr("dup@example.com")}); !errors.Is(err, scim.ErrConflict) {
		t.Fatalf("PatchUser email conflict → %v, want ErrConflict", err)
	}

	// Missing user → ErrNotFound.
	s = &repoSCIMStore{repo: &scimFakeRepo{user: nil}}
	if _, err := s.PatchUser(ctx, "id", scim.UserPatch{Active: boolPtr(false)}); !errors.Is(err, scim.ErrNotFound) {
		t.Fatalf("PatchUser missing → %v, want ErrNotFound", err)
	}
}

func ptr(s string) *string { return &s }

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

// TestRepoSCIMStore_AnonymousUsersAreNotAddressable pins that every by-id
// SCIM method treats an anonymous account as absent.
//
// They have no email, and RFC 7643 §4.1.1 makes userName REQUIRED and
// unique, which is why the list filter excludes them. The write half is the
// one that loses data: an IdP "repairing" a blank userName would give the
// account a real address while is_anonymous stayed true, making it
// email-loginable AND still matched by the retention sweep — hard-deleted
// with its sessions after the window. Asserting the error is not enough;
// these assert the row was never touched.
func TestRepoSCIMStore_AnonymousUsersAreNotAddressable(t *testing.T) {
	ctx := context.Background()
	anon := func() *service.User {
		return &service.User{ID: "anon-1", IsAnonymous: true}
	}

	t.Run("GetUser", func(t *testing.T) {
		s := &repoSCIMStore{repo: &scimFakeRepo{user: anon()}}
		if _, err := s.GetUser(ctx, "anon-1"); !errors.Is(err, scim.ErrNotFound) {
			t.Fatalf("GetUser → %v, want ErrNotFound", err)
		}
	})

	t.Run("ReplaceUser does not mutate", func(t *testing.T) {
		repo := &scimFakeRepo{user: anon()}
		s := &repoSCIMStore{repo: repo}
		_, err := s.ReplaceUser(ctx, "anon-1", scim.User{Email: "claimed@example.com", Active: true})
		if !errors.Is(err, scim.ErrNotFound) {
			t.Fatalf("ReplaceUser → %v, want ErrNotFound", err)
		}
		if repo.updateCalled {
			t.Fatal("ReplaceUser wrote to an anonymous account: it would become email-loginable while still reapable")
		}
	})

	t.Run("PatchUser does not mutate", func(t *testing.T) {
		repo := &scimFakeRepo{user: anon()}
		s := &repoSCIMStore{repo: repo}
		name := "claimed@example.com"
		_, err := s.PatchUser(ctx, "anon-1", scim.UserPatch{UserName: &name})
		if !errors.Is(err, scim.ErrNotFound) {
			t.Fatalf("PatchUser → %v, want ErrNotFound", err)
		}
		if repo.updateCalled {
			t.Fatal("PatchUser wrote to an anonymous account")
		}
	})

	t.Run("DeleteUser does not delete", func(t *testing.T) {
		repo := &scimFakeRepo{user: anon()}
		s := &repoSCIMStore{repo: repo}
		if err := s.DeleteUser(ctx, "anon-1"); !errors.Is(err, scim.ErrNotFound) {
			t.Fatalf("DeleteUser → %v, want ErrNotFound", err)
		}
		// Otherwise DELETE hard-deletes and emits user_deleted for an id
		// that PUT and PATCH answer 404 for.
		if repo.deleteCalled {
			t.Fatal("DeleteUser deleted an account the other methods report as absent")
		}
	})

	// A permanent account is unaffected — the guard must not swallow real users.
	t.Run("permanent accounts still resolve", func(t *testing.T) {
		s := &repoSCIMStore{repo: &scimFakeRepo{user: &service.User{ID: "u1", Email: "real@example.com"}}}
		if _, err := s.GetUser(ctx, "u1"); err != nil {
			t.Fatalf("GetUser on a permanent account → %v", err)
		}
	})
}
