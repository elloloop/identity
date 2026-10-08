package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/passwords"
)

const issuedPW = "Issu3d!Temp0rary"

// issuedPasswordUser seeds an account holding a password an administrator
// issued.
func issuedPasswordUser(t *testing.T, repo *fakeRepo, email string) *User {
	t.Helper()
	u := seedUser(repo, email, hashPW(t, issuedPW), StatusActive)
	u.PasswordChangeRequired = true
	return u
}

// passwordChangeTicket signs in with the issued password and returns the
// ticket the refusal carries.
func passwordChangeTicket(t *testing.T, svc *AuthService, identifier string) string {
	t.Helper()
	res, err := svc.PasswordLogin(context.Background(), identifier, issuedPW, "203.0.113.10", "agent")
	require.Nil(t, res, "no session for an issued password")
	require.ErrorIs(t, err, ErrPasswordChangeRequired)
	assert.Contains(t, err.Error(), "password_change_required", "the stable wire token leads the message")
	var pcErr *PasswordChangeRequiredError
	require.ErrorAs(t, err, &pcErr)
	_, accessErr := jwt.VerifyAccessToken(pcErr.Ticket, svc.signer, "", "", false)
	require.Error(t, accessErr, "the ticket never authenticates a request")
	claims, err := jwt.VerifyPurposeToken(pcErr.Ticket, svc.signer, "", "", false, tokenPurposePasswordChange)
	require.NoError(t, err)
	require.NotEmpty(t, claims.Sub)
	return pcErr.Ticket
}

func TestRequiredPasswordChange_RoundTrip(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	user := issuedPasswordUser(t, repo, "issued@example.com")

	// A wrong password gets the ordinary refusal: nothing tells a guesser
	// the account is waiting for a change.
	_, err := svc.PasswordLogin(ctx, "issued@example.com", "Wr0ng!Passw0rd", "203.0.113.10", "agent")
	require.ErrorIs(t, err, ErrUnauthenticated)
	require.NotErrorIs(t, err, ErrPasswordChangeRequired)

	ticket := passwordChangeTicket(t, svc, "issued@example.com")

	res, err := svc.CompleteRequiredPasswordChange(ctx, ticket, strongPW, "203.0.113.10", "agent")
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)
	require.NotEmpty(t, res.RefreshToken)
	require.False(t, res.User.PasswordChangeRequired)

	stored, _ := repo.GetUser(ctx, user.ID)
	require.False(t, stored.PasswordChangeRequired)
	require.True(t, passwords.Verify(strongPW, stored.PasswordHash))

	_, err = svc.PasswordLogin(ctx, "issued@example.com", issuedPW, "203.0.113.10", "agent")
	require.ErrorIs(t, err, ErrUnauthenticated, "the issued password no longer signs in")
	login, err := svc.PasswordLogin(ctx, "issued@example.com", strongPW, "203.0.113.10", "agent")
	require.NoError(t, err)
	require.NotEmpty(t, login.AccessToken)

	// The ticket is spent once the change is made.
	_, err = svc.CompleteRequiredPasswordChange(ctx, ticket, "An0ther!Passw0rd", "203.0.113.10", "agent")
	require.ErrorIs(t, err, ErrUnauthenticated)
}

func TestRequiredPasswordChange_Refusals(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	user := issuedPasswordUser(t, repo, "issued@example.com")
	ticket := passwordChangeTicket(t, svc, "issued@example.com")

	_, err := svc.CompleteRequiredPasswordChange(ctx, ticket, issuedPW, "203.0.113.10", "agent")
	require.ErrorIs(t, err, ErrInvalidArgument, "the issued password cannot be kept")
	_, err = svc.CompleteRequiredPasswordChange(ctx, ticket, "", "203.0.113.10", "agent")
	require.ErrorIs(t, err, ErrInvalidArgument)
	_, err = svc.CompleteRequiredPasswordChange(ctx, ticket, "short", "203.0.113.10", "agent")
	require.Error(t, err, "the password policy applies")

	// Only a password-change ticket is accepted.
	other, err := svc.mintPurposeTicket(ctx, user.ID, tokenPurposeDOBCompletion, passwordChangeTicketTTL)
	require.NoError(t, err)
	_, err = svc.CompleteRequiredPasswordChange(ctx, other, strongPW, "203.0.113.10", "agent")
	require.ErrorIs(t, err, ErrUnauthenticated)
	_, err = svc.CompleteRequiredPasswordChange(ctx, "not-a-ticket", strongPW, "203.0.113.10", "agent")
	require.ErrorIs(t, err, ErrUnauthenticated)

	// A deactivation after the ticket was minted wins over it.
	user.Status = StatusDeactivated
	_, err = svc.CompleteRequiredPasswordChange(ctx, ticket, strongPW, "203.0.113.10", "agent")
	require.Error(t, err)
	stored, _ := repo.GetUser(ctx, user.ID)
	require.True(t, stored.PasswordChangeRequired, "nothing changed on a refusal")
	require.True(t, passwords.Verify(issuedPW, stored.PasswordHash))
}

// The second factor is asked for after the change, not skipped by it.
func TestRequiredPasswordChange_SecondFactorStillRequired(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	user := issuedPasswordUser(t, repo, "issued@example.com")
	user.TotpRequired = true
	ticket := passwordChangeTicket(t, svc, "issued@example.com")

	res, err := svc.CompleteRequiredPasswordChange(context.Background(), ticket, strongPW, "203.0.113.10", "agent")
	require.NoError(t, err)
	require.True(t, res.TotpRequired)
	require.NotEmpty(t, res.LoginChallengeID)
	require.Empty(t, res.AccessToken)
	require.Empty(t, res.RefreshToken)
}

func TestRequiredPasswordChange_AdminIssuedPasswordsAreFlagged(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	db.addUser("target-1", "target@test.com", "Target", "member", "active")
	repo := newFakeRepo()
	svc := newTestAdminServiceWithRepo(db, repo)
	ctx := context.Background()

	_, err := svc.ResetUserPassword(ctx, "admin-1", "target-1", true)
	require.NoError(t, err)
	assert.Equal(t, true, db.nodes["target-1"].Payload[ufPasswordChangeRequired], "a temporary password is flagged")

	db.addUser("target-2", "target2@test.com", "Target", "member", "active")
	_, err = svc.ResetUserPassword(ctx, "admin-1", "target-2", false)
	require.NoError(t, err)
	assert.Nil(t, db.nodes["target-2"].Payload[ufPasswordChangeRequired], "a reset link lets the user choose; nothing to flag")

	inv, err := svc.InviteUser(ctx, "admin-1", "imm@test.com", "Immediate", "member", "", 0, true)
	require.NoError(t, err)
	assert.Equal(t, true, db.nodes[inv.User.ID].Payload[ufPasswordChangeRequired], "an immediate account's temporary password is flagged")

	uctx := signupScope(t, `{"access":{"mode":"open"},"accounts":{"domain":"accounts.example.com","username_signup":"admin"}}`)
	res, err := svc.CreateUsernameUser(uctx, "admin-1", "bob", "", "")
	require.NoError(t, err)
	created, _ := repo.GetUser(uctx, res.User.ID)
	require.True(t, created.PasswordChangeRequired, "a username account's issued password is flagged")
}

func TestRequiredPasswordChange_ClearedWhenTheUserSetsTheirOwn(t *testing.T) {
	db := newErrorDB()
	db.addUserWithPassword("user-1", "u@test.com", "U", "member", "active", hashPW(t, issuedPW))
	db.nodes["user-1"].Payload[ufPasswordChangeRequired] = true
	require.NoError(t, newProfileWithDB(db).ChangePassword(context.Background(), "user-1", issuedPW, strongPW))
	assert.Equal(t, false, db.nodes["user-1"].Payload[ufPasswordChangeRequired], "ChangePassword clears it")

	svc, repo, rec := newAuthSvcWithMailer(t)
	user := issuedPasswordUser(t, repo, "alice@test.com")
	token := requestAndExtractResetToken(t, svc, rec, "alice@test.com")
	require.NoError(t, svc.ConfirmPasswordReset(context.Background(), token, strongPW))
	stored, _ := repo.GetUser(context.Background(), user.ID)
	require.False(t, stored.PasswordChangeRequired, "a reset clears it")
}

func TestMergeAccounts_RefusesAnIssuedPassword(t *testing.T) {
	svc, repo, survivor, native, ctx := mergeFixture(t)
	native.PasswordChangeRequired = true
	_, err := svc.MergeAccounts(ctx, survivor.ID, "bob", accessTestPassword, "203.0.113.10", "agent", false)
	require.ErrorIs(t, err, ErrMergeRefused)
	still, _ := repo.GetUser(ctx, native.ID)
	require.Equal(t, StatusActive, still.Status)
}

// A temporary password often recovers an account someone else is signed in
// to: completing the change ends every session opened before it.
func TestRequiredPasswordChange_RevokesExistingSessions(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	ctx := context.Background()
	user := issuedPasswordUser(t, repo, "issued@example.com")
	_, err := repo.CreateRefreshToken(ctx, &RefreshTokenRecord{
		TokenHash: "earlier-session", UserID: user.ID, ExpiresAt: nowMs() + 60_000,
	})
	require.NoError(t, err)

	ticket := passwordChangeTicket(t, svc, "issued@example.com")
	res, err := svc.CompleteRequiredPasswordChange(ctx, ticket, strongPW, "203.0.113.10", "agent")
	require.NoError(t, err)

	earlier, err := repo.FindRefreshTokenByHash(ctx, "earlier-session")
	require.NoError(t, err)
	require.Nil(t, earlier, "a session opened before the change is gone")
	_, _, _, err = svc.RefreshToken(ctx, res.RefreshToken, "203.0.113.10", "agent")
	require.NoError(t, err, "the session the change opened survives it")
}

func TestRequiredPasswordChange_ClearedByAcceptingAnInvitation(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	ctx := context.Background()
	token := seedInvitedUser(t, repo, "invitee@example.com")
	invitee, err := repo.FindUserByEmail(ctx, "invitee@example.com")
	require.NoError(t, err)
	require.NoError(t, repo.UpdateUser(ctx, invitee.ID, map[string]any{"password_change_required": true}))

	_, err = svc.AcceptInvitation(ctx, token, strongPW, "Invitee", "203.0.113.10", "agent")
	require.NoError(t, err)
	stored, _ := repo.GetUser(ctx, invitee.ID)
	require.False(t, stored.PasswordChangeRequired, "the invitee chose their own password")
}
