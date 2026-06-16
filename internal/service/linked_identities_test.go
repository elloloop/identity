package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

// newTestProfileServiceWithRepo builds a ProfileService backed by the
// full in-memory fakeRepo (for users + oauth links) and a fakeDB (for
// passkeys, which live in the graph DB). The linked-identity flows touch
// both: last-credential protection counts password (repo) and passkey (db).
func newTestProfileServiceWithRepo(repo *fakeRepo, db *fakeDB) *ProfileService {
	auditLog := audit.NewLogger(nil, "test-tenant", zap.NewNop())
	return NewProfileService(repo, db, "test-tenant", auditLog, zap.NewNop())
}

func TestProfileService_ListLinkedIdentities(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestProfileServiceWithRepo(repo, newFakeDB())
	ctx := context.Background()

	u := seedUser(repo, "list@example.com", "hash", "active")
	require.NoError(t, repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID: u.ID, Provider: "google", ProviderUserID: "g-1",
		EmailAtLinkTime: "list@example.com", CreatedAt: 100,
	}))
	require.NoError(t, repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID: u.ID, Provider: "github", ProviderUserID: "gh-1",
		EmailAtLinkTime: "list@example.com", CreatedAt: 200,
	}))

	got, err := svc.ListLinkedIdentities(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, got, 2)

	// Empty user id is rejected.
	_, err = svc.ListLinkedIdentities(ctx, "")
	assert.ErrorIs(t, err, ErrInvalidArgument)
}

func TestProfileService_UnlinkIdentity_RemovesNonFinalLink(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestProfileServiceWithRepo(repo, newFakeDB())
	ctx := context.Background()

	// User with NO password and NO passkey but TWO provider links: removing
	// one is fine because another credential (the other link) remains.
	u := seedUser(repo, "two@example.com", "", "active")
	require.NoError(t, repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID: u.ID, Provider: "google", ProviderUserID: "g-1", CreatedAt: 100,
	}))
	require.NoError(t, repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID: u.ID, Provider: "github", ProviderUserID: "gh-1", CreatedAt: 200,
	}))

	require.NoError(t, svc.UnlinkIdentity(ctx, u.ID, "google", "g-1"))

	got, err := repo.ListOAuthIdentitiesForUser(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "github", got[0].Provider)
}

func TestProfileService_UnlinkIdentity_LastCredentialBlocked(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestProfileServiceWithRepo(repo, newFakeDB())
	ctx := context.Background()

	// User with NO password, NO passkey, and a SINGLE provider link.
	// Removing it would leave no way to sign in → blocked.
	u := seedUser(repo, "only@example.com", "", "active")
	require.NoError(t, repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID: u.ID, Provider: "google", ProviderUserID: "g-1", CreatedAt: 100,
	}))

	err := svc.UnlinkIdentity(ctx, u.ID, "google", "g-1")
	assert.ErrorIs(t, err, ErrLastCredential)

	// The link must survive a refused unlink.
	got, err := repo.ListOAuthIdentitiesForUser(ctx, u.ID)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

func TestProfileService_UnlinkIdentity_LastLinkAllowedWithPassword(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestProfileServiceWithRepo(repo, newFakeDB())
	ctx := context.Background()

	// Single provider link but the user also has a password: removing the
	// link is fine because the password remains as a sign-in credential.
	u := seedUser(repo, "pw@example.com", "argon2-hash", "active")
	require.NoError(t, repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID: u.ID, Provider: "google", ProviderUserID: "g-1", CreatedAt: 100,
	}))

	require.NoError(t, svc.UnlinkIdentity(ctx, u.ID, "google", "g-1"))

	got, err := repo.ListOAuthIdentitiesForUser(ctx, u.ID)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestProfileService_UnlinkIdentity_LastLinkAllowedWithPasskey(t *testing.T) {
	repo := newFakeRepo()
	db := newFakeDB()
	svc := newTestProfileServiceWithRepo(repo, db)
	ctx := context.Background()

	// Single provider link, no password, but a registered passkey: the
	// passkey is a remaining credential so the unlink is allowed.
	u := seedUser(repo, "pk@example.com", "", "active")
	db.addPasskey("pk-node", u.ID, "cred-1", "Phone")
	require.NoError(t, repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID: u.ID, Provider: "google", ProviderUserID: "g-1", CreatedAt: 100,
	}))

	require.NoError(t, svc.UnlinkIdentity(ctx, u.ID, "google", "g-1"))

	got, err := repo.ListOAuthIdentitiesForUser(ctx, u.ID)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestProfileService_UnlinkIdentity_NotFound(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestProfileServiceWithRepo(repo, newFakeDB())
	ctx := context.Background()

	u := seedUser(repo, "nf@example.com", "hash", "active")
	require.NoError(t, repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID: u.ID, Provider: "google", ProviderUserID: "g-1", CreatedAt: 100,
	}))

	// Wrong subject → ErrNotFound, not a last-credential precondition.
	err := svc.UnlinkIdentity(ctx, u.ID, "google", "does-not-exist")
	assert.ErrorIs(t, err, ErrNotFound)

	// Another user's link must not be unlinkable by this user.
	other := seedUser(repo, "other@example.com", "hash", "active")
	require.NoError(t, repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID: other.ID, Provider: "slack", ProviderUserID: "s-1", CreatedAt: 100,
	}))
	err = svc.UnlinkIdentity(ctx, u.ID, "slack", "s-1")
	assert.ErrorIs(t, err, ErrNotFound)

	// Other user's link survived.
	got, err := repo.ListOAuthIdentitiesForUser(ctx, other.ID)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

func TestProfileService_UnlinkIdentity_Validation(t *testing.T) {
	svc := newTestProfileServiceWithRepo(newFakeRepo(), newFakeDB())
	ctx := context.Background()

	assert.ErrorIs(t, svc.UnlinkIdentity(ctx, "", "google", "g-1"), ErrInvalidArgument)
	assert.ErrorIs(t, svc.UnlinkIdentity(ctx, "u1", "", "g-1"), ErrInvalidArgument)
	assert.ErrorIs(t, svc.UnlinkIdentity(ctx, "u1", "google", ""), ErrInvalidArgument)
}

func TestAuthService_LinkIdentity_AttachesVerifiedIdentity(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()

	// Authenticated user who signed up by password.
	u := seedUser(repo, "linker@example.com", "hash", "active")

	// The fake exchanger derives the subject from the email argument as
	// "sub-<email>". Drive a link for a Google identity.
	code := fakeOAuthCode("linker@example.com", "Linker", "", "google")
	oi, err := svc.LinkIdentity(ctx, u.ID, code, "google", "https://app/cb", "", "", "")
	require.NoError(t, err)
	require.NotNil(t, oi)
	assert.Equal(t, u.ID, oi.UserID)
	assert.Equal(t, "google", oi.Provider)
	assert.Equal(t, "sub-linker@example.com", oi.ProviderUserID)

	links, err := repo.ListOAuthIdentitiesForUser(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, links, 1)
}

func TestAuthService_LinkIdentity_AlreadyLinked(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()

	owner := seedUser(repo, "owner@example.com", "hash", "active")
	require.NoError(t, repo.CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID: owner.ID, Provider: "google", ProviderUserID: "sub-victim@example.com", CreatedAt: 1,
	}))

	// A different authenticated user tries to link the SAME provider
	// identity (the fake exchanger maps the code's email to the subject).
	attacker := seedUser(repo, "attacker@example.com", "hash", "active")
	code := fakeOAuthCode("victim@example.com", "Victim", "", "google")
	_, err := svc.LinkIdentity(ctx, attacker.ID, code, "google", "https://app/cb", "", "", "")
	assert.ErrorIs(t, err, ErrAlreadyExists)

	// The link still points at the original owner.
	got, err := repo.FindUserByProviderID(ctx, "google", "sub-victim@example.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, owner.ID, got.ID)
}

func TestAuthService_LinkIdentity_RequiresAuth(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()

	code := fakeOAuthCode("noauth@example.com", "NoAuth", "", "google")
	_, err := svc.LinkIdentity(ctx, "", code, "google", "https://app/cb", "", "", "")
	assert.ErrorIs(t, err, ErrUnauthenticated)
}
