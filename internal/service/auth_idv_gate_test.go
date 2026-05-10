package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/elloloop/identity/pkg/idv"
	"github.com/elloloop/identity/pkg/passwords"
)

// seedActiveUserWithPassword stores a user with a known password so a
// PasswordLogin call can reach the IDV gate.
func seedActiveUserWithPassword(t *testing.T, repo *fakeRepo, email, password string) *User {
	t.Helper()
	hash, err := passwords.Hash(password)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	uid, err := repo.CreateUser(context.Background(), &User{
		Email:        email,
		Status:       "active",
		PasswordHash: hash,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	u, _ := repo.GetUser(context.Background(), uid)
	return u
}

func TestPasswordLogin_IDVRequired_RejectsUnverified(t *testing.T) {
	t.Parallel()

	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.IDVRequired = true
	user := seedActiveUserWithPassword(t, repo, "u@example.com", "Sup3r-Sekret-Password-1!")

	_, err := svc.PasswordLogin(context.Background(), user.Email, "Sup3r-Sekret-Password-1!", "1.1.1.1", "ua")
	if !errors.Is(err, ErrIDVRequired) {
		t.Fatalf("err = %v; want ErrIDVRequired", err)
	}
}

func TestPasswordLogin_IDVRequired_AllowsVerified(t *testing.T) {
	t.Parallel()

	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	svc.cfg.IDVRequired = true
	user := seedActiveUserWithPassword(t, repo, "u@example.com", "Sup3r-Sekret-Password-1!")
	if err := repo.SetUserIDVVerified(context.Background(), user.ID, time.Now().UnixMilli()); err != nil {
		t.Fatalf("seed verified: %v", err)
	}

	res, err := svc.PasswordLogin(context.Background(), user.Email, "Sup3r-Sekret-Password-1!", "1.1.1.1", "ua")
	if err != nil {
		t.Fatalf("PasswordLogin: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("AccessToken empty")
	}
}

func TestPasswordLogin_IDVDisabled_NoGate(t *testing.T) {
	t.Parallel()

	repo := newFakeRepo()
	svc := newTestAuthService(t, repo)
	// cfg.IDVRequired defaults to false → unverified user logs in fine.
	user := seedActiveUserWithPassword(t, repo, "u@example.com", "Sup3r-Sekret-Password-1!")

	res, err := svc.PasswordLogin(context.Background(), user.Email, "Sup3r-Sekret-Password-1!", "1.1.1.1", "ua")
	if err != nil {
		t.Fatalf("PasswordLogin: %v", err)
	}
	if res.User.IDVVerified {
		t.Fatalf("user marked verified unexpectedly: %+v", user)
	}
}

func TestIDV_Approve_FlipsUserVerifiedFlag(t *testing.T) {
	t.Parallel()

	provider := idv.NewStubProvider() // default: APPROVED on first poll
	svc, repo, uid := makeIDVService(t, provider)

	begin, err := svc.BeginIdentityVerification(context.Background(), uid)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	if u, _ := repo.GetUser(context.Background(), uid); u.IDVVerified {
		t.Fatal("user already verified before status poll")
	}

	if _, err := svc.GetIdentityVerificationStatus(context.Background(), uid, begin.VerificationID); err != nil {
		t.Fatalf("Get: %v", err)
	}

	u, _ := repo.GetUser(context.Background(), uid)
	if !u.IDVVerified || u.IDVVerifiedAt == 0 {
		t.Fatalf("user not flipped verified: %+v", u)
	}
}

func TestIDV_Reject_DoesNotFlipUserVerifiedFlag(t *testing.T) {
	t.Parallel()

	provider := idv.NewStubProvider()
	provider.Verdict = idv.StatusRejected
	svc, repo, uid := makeIDVService(t, provider)

	begin, _ := svc.BeginIdentityVerification(context.Background(), uid)
	if _, err := svc.GetIdentityVerificationStatus(context.Background(), uid, begin.VerificationID); err != nil {
		t.Fatalf("Get: %v", err)
	}

	u, _ := repo.GetUser(context.Background(), uid)
	if u.IDVVerified {
		t.Fatalf("user verified after rejection: %+v", u)
	}
}
