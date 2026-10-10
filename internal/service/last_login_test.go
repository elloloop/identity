package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// Every issued sign-in records the account's last login, the ones that never
// stamped it themselves included.
func TestLastLogin_RecordedByEveryIssuedSignIn(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func(t *testing.T, svc *AuthService, user *User){
		"password": func(t *testing.T, svc *AuthService, user *User) {
			t.Helper()
			_, err := svc.PasswordLogin(ctx, user.Email, strongPW, "203.0.113.10", "agent")
			require.NoError(t, err)
		},
		"qr": func(t *testing.T, svc *AuthService, user *User) {
			t.Helper()
			init, err := svc.InitiateQrLogin(ctx, "Pixel 8", "agent", "10.0.0.1")
			require.NoError(t, err)
			_, err = svc.ApproveQrLogin(ctx, init.SessionID, true, user.ID, "ApproverAgent")
			require.NoError(t, err)
			_, err = svc.PollQrLogin(ctx, init.SessionID, init.PollSecret, "10.0.0.1", "agent")
			require.NoError(t, err)
		},
	}
	for name, signIn := range cases {
		t.Run(name, func(t *testing.T) {
			repo := newFakeRepo()
			svc := newTestAuthService(t, repo)
			user := seedUser(repo, "signed-in@example.com", hashPW(t, strongPW), StatusActive)

			signIn(t, svc, user)

			stored, err := repo.GetUser(ctx, user.ID)
			require.NoError(t, err)
			require.NotZero(t, stored.LastLoginAtMs)
		})
	}
}
