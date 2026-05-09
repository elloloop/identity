// Tests covering DB error branches in admin/group/help/profile services.
package service

import (
	"context"
	"testing"

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb"
	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"

	"github.com/stretchr/testify/require"
)

func newAdminWithDB(db DB) *AdminService {
	return NewAdminService(db, "test-tenant",
		audit.NewLogger(nil, "test", zap.NewNop()),
		config.Load(), nil, zap.NewNop())
}
func newGroupWithDB(db DB) *GroupService {
	return NewGroupService(db, "test-tenant",
		audit.NewLogger(nil, "test", zap.NewNop()), zap.NewNop())
}
func newHelpWithDB(db DB) *HelpService {
	return NewHelpService(db, "test-tenant",
		audit.NewLogger(nil, "test", zap.NewNop()), zap.NewNop())
}
func newProfileWithDB(db DB) *ProfileService {
	return NewProfileService(db, "test-tenant",
		audit.NewLogger(nil, "test", zap.NewNop()), zap.NewNop())
}

// ── AdminService DB error paths ────────────────────────────────────────

func TestAdminInviteUser_DuplicateCheckQueryFails(t *testing.T) {
	db := newErrorDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	// Pass admin check (GetNode), fail QueryNodes.
	db.failQueryNodes = true
	svc := newAdminWithDB(db)

	_, err := svc.InviteUser(context.Background(), "admin-1", "x@test.com", "", "member", "", 0, false)
	require.Error(t, err)
}

func TestAdminInviteUser_CreateUserExecuteFails(t *testing.T) {
	db := newErrorDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	db.failExecuteAtomic = true
	svc := newAdminWithDB(db)

	_, err := svc.InviteUser(context.Background(), "admin-1", "x@test.com", "", "member", "", 0, false)
	require.Error(t, err)
}

func TestAdminInviteUser_CreateInvitationExecuteFails(t *testing.T) {
	db := newErrorDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	// First execute (create user) succeeds, second (create invitation) fails.
	db.failExecuteAfter = 2
	svc := newAdminWithDB(db)

	_, err := svc.InviteUser(context.Background(), "admin-1", "x@test.com", "", "member", "", 0, false)
	require.Error(t, err)
}

func TestAdminDeactivateUser_GetNodeFails(t *testing.T) {
	db := newErrorDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	db.addUser("target-1", "t@test.com", "T", "member", "active")
	// First GetNode (admin check) ok, second (target fetch) fails.
	db.failGetNodeAfter = 2
	svc := newAdminWithDB(db)

	err := svc.DeactivateUser(context.Background(), "admin-1", "target-1", "")
	require.Error(t, err)
}

func TestAdminDeactivateUser_ExecuteFails(t *testing.T) {
	db := newErrorDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	db.addUser("target-1", "t@test.com", "T", "member", "active")
	db.failExecuteAtomic = true
	svc := newAdminWithDB(db)

	err := svc.DeactivateUser(context.Background(), "admin-1", "target-1", "")
	require.Error(t, err)
}

func TestAdminReactivateUser_GetNodeFails(t *testing.T) {
	db := newErrorDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	db.addUser("target-1", "t@test.com", "T", "member", "deactivated")
	db.failGetNodeAfter = 2
	svc := newAdminWithDB(db)

	err := svc.ReactivateUser(context.Background(), "admin-1", "target-1")
	require.Error(t, err)
}

func TestAdminReactivateUser_ExecuteFails(t *testing.T) {
	db := newErrorDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	db.addUser("target-1", "t@test.com", "T", "member", "deactivated")
	db.failExecuteAtomic = true
	svc := newAdminWithDB(db)

	err := svc.ReactivateUser(context.Background(), "admin-1", "target-1")
	require.Error(t, err)
}

func TestAdminResetUserPassword_GetNodeFails(t *testing.T) {
	db := newErrorDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	db.addUser("target-1", "t@test.com", "T", "member", "active")
	db.failGetNodeAfter = 2
	svc := newAdminWithDB(db)

	_, err := svc.ResetUserPassword(context.Background(), "admin-1", "target-1", true)
	require.Error(t, err)
}

func TestAdminResetUserPassword_ExecuteFails_TempPath(t *testing.T) {
	db := newErrorDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	db.addUser("target-1", "t@test.com", "T", "member", "active")
	db.failExecuteAtomic = true
	svc := newAdminWithDB(db)

	_, err := svc.ResetUserPassword(context.Background(), "admin-1", "target-1", true)
	require.Error(t, err)
}

func TestAdminResetUserPassword_ExecuteFails_TokenPath(t *testing.T) {
	db := newErrorDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	db.addUser("target-1", "t@test.com", "T", "member", "active")
	db.failExecuteAtomic = true
	svc := newAdminWithDB(db)

	_, err := svc.ResetUserPassword(context.Background(), "admin-1", "target-1", false)
	require.Error(t, err)
}

func TestAdminSetUserQuota_GetNodeFails(t *testing.T) {
	db := newErrorDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	db.addUser("target-1", "t@test.com", "T", "member", "active")
	db.failGetNodeAfter = 2
	svc := newAdminWithDB(db)

	err := svc.SetUserQuota(context.Background(), "admin-1", "target-1", 1024)
	require.Error(t, err)
}

func TestAdminSetUserQuota_ExecuteFails(t *testing.T) {
	db := newErrorDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	db.addUser("target-1", "t@test.com", "T", "member", "active")
	db.failExecuteAtomic = true
	svc := newAdminWithDB(db)

	err := svc.SetUserQuota(context.Background(), "admin-1", "target-1", 1024)
	require.Error(t, err)
}

func TestAdminListUsers_QueryFails(t *testing.T) {
	db := newErrorDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	db.failQueryNodes = true
	svc := newAdminWithDB(db)

	_, _, _, err := svc.ListUsers(context.Background(), "admin-1", "", "", "", 50)
	require.Error(t, err)
}

func TestAdminGetUser_GetNodeFails(t *testing.T) {
	db := newErrorDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	db.failGetNodeAfter = 2
	svc := newAdminWithDB(db)

	_, err := svc.GetUser(context.Background(), "admin-1", "target")
	require.Error(t, err)
}

func TestAdminUpdateUser_ExecuteFails(t *testing.T) {
	db := newErrorDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	db.failExecuteAtomic = true
	svc := newAdminWithDB(db)

	_, err := svc.UpdateUser(context.Background(), "admin-1", "user-1", "Name", "", "")
	require.Error(t, err)
}

func TestAdminUpdateUser_RefetchFails(t *testing.T) {
	db := newErrorDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	db.addUser("user-1", "u@test.com", "U", "member", "active")
	// Fail GetNode on the refetch (3rd call: admin-check, then refetch).
	db.failGetNodeAfter = 2
	svc := newAdminWithDB(db)

	_, err := svc.UpdateUser(context.Background(), "admin-1", "user-1", "Name", "", "")
	require.Error(t, err)
}

func TestAdminUpdateUser_RefetchReturnsNil(t *testing.T) {
	// Update succeeds but the user was concurrently deleted — node nil.
	db := newErrorDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	svc := newAdminWithDB(db)

	// user-x doesn't exist; update will succeed (no-op in fake), refetch returns nil.
	_, err := svc.UpdateUser(context.Background(), "admin-1", "ghost-user", "Name", "", "")
	require.Error(t, err)
}

// ── GroupService DB errors ─────────────────────────────────────────────

func TestGroupUpdateGroup_RefetchFails(t *testing.T) {
	db := newErrorDB()
	seedGroupAdmin(db.fakeDB)
	db.addGroup("grp-1", "G", "")
	db.failGetNode = true
	svc := newGroupWithDB(db)

	_, err := svc.UpdateGroup(context.Background(), "admin-1", "grp-1", "X", "")
	require.Error(t, err)
}

func TestGroupUpdateGroup_RefetchReturnsNil(t *testing.T) {
	db := newErrorDB()
	seedGroupAdmin(db.fakeDB)
	svc := newGroupWithDB(db)

	// No group exists; update is a no-op, refetch returns nil.
	_, err := svc.UpdateGroup(context.Background(), "admin-1", "ghost", "X", "")
	require.Error(t, err)
}

func TestGroupListGroups_QueryFails(t *testing.T) {
	db := newErrorDB()
	seedGroupAdmin(db.fakeDB)
	db.failQueryNodes = true
	svc := newGroupWithDB(db)

	_, _, err := svc.ListGroups(context.Background(), "admin-1", "", 10)
	require.Error(t, err)
}

func TestGroupListMembers_GetNodeMissingUserSkipped(t *testing.T) {
	// Add an edge but no user node — GetNode returns nil; the user is skipped.
	db := newErrorDB()
	seedGroupAdmin(db.fakeDB)
	db.addGroup("grp-1", "Team", "")
	svc := newGroupWithDB(db)

	// Inject an incoming membership edge to grp-1 from a nonexistent user node.
	db.mu.Lock()
	db.edges = append(db.edges, &entdb.Edge{
		FromNodeID: "ghost-user", ToNodeID: "grp-1", EdgeTypeID: edgeMemberOf,
	})
	db.mu.Unlock()

	members, err := svc.ListGroupMembers(context.Background(), "admin-1", "grp-1")
	require.NoError(t, err)
	require.Len(t, members, 0)
}

// ── HelpService DB errors ──────────────────────────────────────────────

func TestHelpListRequests_QueryFails(t *testing.T) {
	db := newErrorDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	// Fail the second query (after admin check, the list-help-requests query).
	db.failQueryAfter = 1
	svc := newHelpWithDB(db)

	_, _, _, err := svc.ListHelpRequests(context.Background(), "admin-1", "", "", 50)
	require.Error(t, err)
}

func TestHelpResolveRequest_GetNodeFails(t *testing.T) {
	db := newErrorDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	db.failGetNodeAfter = 2
	svc := newHelpWithDB(db)

	_, err := svc.ResolveHelpRequest(context.Background(), "admin-1", "hr-1", false, "")
	require.Error(t, err)
}

func TestHelpResolveRequest_ExecuteFails(t *testing.T) {
	db := newErrorDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	db.addHelpRequest("hr-1", "h@test.com", "pending", nowMs())
	db.failExecuteAtomic = true
	svc := newHelpWithDB(db)

	_, err := svc.ResolveHelpRequest(context.Background(), "admin-1", "hr-1", false, "")
	require.Error(t, err)
}

// ── ProfileService DB errors ───────────────────────────────────────────

func TestProfileUpdateProfile_ExecuteFails(t *testing.T) {
	db := newErrorDB()
	db.addUser("user-1", "u@test.com", "U", "member", "active")
	db.failExecuteAtomic = true
	svc := newProfileWithDB(db)

	_, err := svc.UpdateProfile(context.Background(), "user-1", "Name", "")
	require.Error(t, err)
}

func TestProfileUpdateProfile_RefetchFallback(t *testing.T) {
	// Update succeeds, but GetNode on the refetch fails → fallback path.
	db := newErrorDB()
	db.addUser("user-1", "u@test.com", "U", "member", "active")
	// First GetNode (initial fetch) succeeds; second (refetch) fails.
	db.failGetNodeAfter = 2
	svc := newProfileWithDB(db)

	user, err := svc.UpdateProfile(context.Background(), "user-1", "New Name", "https://x.png")
	require.NoError(t, err)
	require.NotNil(t, user)
}

func TestProfileListSessions_QueryFails(t *testing.T) {
	db := newErrorDB()
	db.failQueryNodes = true
	svc := newProfileWithDB(db)

	_, err := svc.ListMySessions(context.Background(), "u")
	require.Error(t, err)
}

func TestProfileRevokeSession_GetNodeFails(t *testing.T) {
	db := newErrorDB()
	db.failGetNode = true
	svc := newProfileWithDB(db)

	err := svc.RevokeSession(context.Background(), "u", "sess-1")
	require.Error(t, err)
}

func TestProfileRevokeSession_ExecuteFails(t *testing.T) {
	db := newErrorDB()
	db.addRefreshToken("sess-1", "user-1", nowMs()+3600*1000)
	db.failExecuteAtomic = true
	svc := newProfileWithDB(db)

	err := svc.RevokeSession(context.Background(), "user-1", "sess-1")
	require.Error(t, err)
}

func TestProfileRevokeAllSessions_GetNodeFails(t *testing.T) {
	db := newErrorDB()
	db.failGetNode = true
	svc := newProfileWithDB(db)

	_, err := svc.RevokeAllSessions(context.Background(), "u", "p")
	require.Error(t, err)
}

func TestProfileRevokeAllSessions_QueryFails(t *testing.T) {
	db := newErrorDB()
	pwHash, _ := passwords.Hash("Str0ng!Pass")
	db.addUserWithPassword("user-1", "u@test.com", "U", "member", "active", pwHash)
	db.failQueryNodes = true
	svc := newProfileWithDB(db)

	_, err := svc.RevokeAllSessions(context.Background(), "user-1", "Str0ng!Pass")
	require.Error(t, err)
}

func TestProfileRevokeAllSessions_ExecuteFails(t *testing.T) {
	db := newErrorDB()
	pwHash, _ := passwords.Hash("Str0ng!Pass")
	db.addUserWithPassword("user-1", "u@test.com", "U", "member", "active", pwHash)
	db.addRefreshToken("sess-1", "user-1", nowMs()+3600*1000)
	db.failExecuteAtomic = true
	svc := newProfileWithDB(db)

	count, err := svc.RevokeAllSessions(context.Background(), "user-1", "Str0ng!Pass")
	require.NoError(t, err)
	require.Equal(t, 0, count)
}

func TestProfileListPasskeys_QueryFails(t *testing.T) {
	db := newErrorDB()
	db.failQueryNodes = true
	svc := newProfileWithDB(db)

	_, err := svc.ListMyPasskeys(context.Background(), "user-1")
	require.Error(t, err)
}

func TestProfileDeletePasskey_QueryFails(t *testing.T) {
	db := newErrorDB()
	db.failQueryNodes = true
	svc := newProfileWithDB(db)

	err := svc.DeletePasskey(context.Background(), "u", "cred-1")
	require.Error(t, err)
}

func TestProfileDeletePasskey_ExecuteFails(t *testing.T) {
	db := newErrorDB()
	db.addPasskey("pk-1", "user-1", "cred-1", "Key")
	db.failExecuteAtomic = true
	svc := newProfileWithDB(db)

	err := svc.DeletePasskey(context.Background(), "user-1", "cred-1")
	require.Error(t, err)
}

func TestProfileChangePassword_GetUserFails(t *testing.T) {
	db := newErrorDB()
	db.failGetNode = true
	svc := newProfileWithDB(db)

	err := svc.ChangePassword(context.Background(), "u", "old", "NewStr0ng!Pass")
	require.Error(t, err)
}

func TestProfileChangePassword_ExecuteFails(t *testing.T) {
	db := newErrorDB()
	pwHash, _ := passwords.Hash("OldStr0ng!Pass")
	db.addUserWithPassword("user-1", "u@test.com", "U", "member", "active", pwHash)
	db.failExecuteAtomic = true
	svc := newProfileWithDB(db)

	err := svc.ChangePassword(context.Background(), "user-1", "OldStr0ng!Pass", "NewStr0ng!Pass")
	require.Error(t, err)
}

func TestProfileListAuditEvents_QueryFails(t *testing.T) {
	db := newErrorDB()
	db.addUser("admin-1", "a@test.com", "A", "admin", "active")
	db.failQueryAfter = 1
	svc := newProfileWithDB(db)

	_, _, err := svc.ListAuditEvents(context.Background(), "admin-1", "", "", 0, 0, "", 50)
	require.Error(t, err)
}

func TestProfileListAuditEvents_GetActorFails(t *testing.T) {
	db := newErrorDB()
	db.failGetNode = true
	svc := newProfileWithDB(db)

	_, _, err := svc.ListAuditEvents(context.Background(), "u", "", "", 0, 0, "", 50)
	require.Error(t, err)
}
