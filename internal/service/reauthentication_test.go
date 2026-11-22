package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

type reauthenticationFixture struct {
	service      *AuthService
	repo         *fakeRepo
	user         *User
	key          *ecdsa.PrivateKey
	credentialID string
}

func newReauthenticationFixture(t *testing.T) reauthenticationFixture {
	t.Helper()
	svc, repo, _ := newAuthSvcWithMailer(t)
	enableAgeGate(t, svc, false)
	user := seedUser(repo, "parent@example.com", "", StatusActive)
	user.DateOfBirthMs = new(svc.nowFunc().AddDate(-35, 0, 0).UnixMilli())
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	public, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: key.X.FillBytes(make([]byte, 32)), -3: key.Y.FillBytes(make([]byte, 32))})
	require.NoError(t, err)
	credentialID := base64.RawURLEncoding.EncodeToString([]byte("fixture-credential"))
	_, err = repo.CreatePasskeyCredential(context.Background(), &PasskeyCredRecord{UserID: user.ID, CredentialID: credentialID, PublicKey: base64.StdEncoding.EncodeToString(public)})
	require.NoError(t, err)
	return reauthenticationFixture{service: svc, repo: repo, user: user, key: key, credentialID: credentialID}
}

func (f reauthenticationFixture) proof(t *testing.T, action, resource string, verified bool) *PasskeyReauthentication {
	t.Helper()
	options, id, err := f.service.BeginReauthentication(context.Background(), f.user.ID, SessionSignIn{}, action, resource)
	require.NoError(t, err)
	require.Contains(t, options, `"userVerification":"required"`)
	record, err := f.repo.GetPasskeyChallenge(context.Background(), id)
	require.NoError(t, err)
	client, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": record.Challenge, "origin": f.service.cfg.PasskeyOrigin})
	require.NoError(t, err)
	rpHash := sha256.Sum256([]byte(f.service.cfg.PasskeyRPID))
	flags := byte(0x01)
	if verified {
		flags |= 0x04
	}
	authData := append(append([]byte{}, rpHash[:]...), flags, 0, 0, 0, 0)
	clientHash := sha256.Sum256(client)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, f.key, digest[:])
	require.NoError(t, err)
	b64 := base64.RawURLEncoding.EncodeToString
	assertion, err := json.Marshal(map[string]any{"id": f.credentialID, "rawId": f.credentialID, "type": "public-key", "response": map[string]any{
		"authenticatorData": b64(authData), "clientDataJSON": b64(client), "signature": b64(signature), "userHandle": b64([]byte(f.user.ID)),
	}})
	require.NoError(t, err)
	return &PasskeyReauthentication{ChallengeID: id, CredentialJSON: string(assertion)}
}

func TestReauthenticationRequiresExactBindingAndVerification(t *testing.T) {
	f := newReauthenticationFixture(t)
	ctx := context.Background()
	proof := f.proof(t, "account.pin.set", f.user.ID, true)
	for _, binding := range [][2]string{{"account.pin.reset", f.user.ID}, {"account.pin.set", "other-resource"}} {
		require.Error(t, f.service.VerifyReauthentication(ctx, f.user.ID, SessionSignIn{}, proof, binding[0], binding[1]))
	}
	require.NoError(t, f.service.VerifyReauthentication(ctx, f.user.ID, SessionSignIn{}, proof, "account.pin.set", f.user.ID))
	require.Error(t, f.service.VerifyReauthentication(ctx, f.user.ID, SessionSignIn{}, proof, "account.pin.set", f.user.ID))
	unverified := f.proof(t, "account.pin.set", f.user.ID, false)
	require.Error(t, f.service.VerifyReauthentication(ctx, f.user.ID, SessionSignIn{}, unverified, "account.pin.set", f.user.ID))
	require.Empty(t, f.repo.refreshTokens)
}

func TestReauthenticationExpiredUnknownAdultAndRemovedFactor(t *testing.T) {
	f := newReauthenticationFixture(t)
	proof := f.proof(t, "account.pin.set", f.user.ID, true)
	f.repo.passkeyChallenges[proof.ChallengeID].ExpiresAt = f.service.nowMs()
	require.Error(t, f.service.VerifyReauthentication(context.Background(), f.user.ID, SessionSignIn{}, proof, "account.pin.set", f.user.ID))
	f.user.DateOfBirthMs = nil
	_, _, err := f.service.BeginReauthentication(context.Background(), f.user.ID, SessionSignIn{}, "account.pin.set", f.user.ID)
	require.Error(t, err)
	f.user.DateOfBirthMs = new(f.service.nowFunc().AddDate(-35, 0, 0).UnixMilli())
	proof = f.proof(t, "account.pin.set", f.user.ID, true)
	require.NoError(t, f.repo.DeletePasskeyCredentialsForUser(context.Background(), f.user.ID))
	require.Error(t, f.service.VerifyReauthentication(context.Background(), f.user.ID, SessionSignIn{}, proof, "account.pin.set", f.user.ID))
}

func TestReauthenticationConcurrentConsumptionHasOneWinner(t *testing.T) {
	f := newReauthenticationFixture(t)
	proof := f.proof(t, "account.pin.set", f.user.ID, true)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if f.service.VerifyReauthentication(context.Background(), f.user.ID, SessionSignIn{}, proof, "account.pin.set", f.user.ID) == nil {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	require.Equal(t, int32(1), wins.Load())
}

func TestReauthenticationCreatesChildWithExplicitConsentAndNoPassword(t *testing.T) {
	f := newReauthenticationFixture(t)
	proof := f.proof(t, "guardian.create_child", "", true)
	child, err := f.service.CreateManagedChildAccount(context.Background(), f.user.ID, SessionSignIn{}, ManagedChildAccountRequest{
		Username: "child.example", DateOfBirthMs: new(f.service.nowFunc().AddDate(-8, 0, 0).UnixMilli()), Password: strongPW, PolicyVersion: "policy-v1", StepUpPasskey: proof,
	}, "", "")
	require.NoError(t, err)
	require.NotNil(t, child.Consent)
	require.True(t, child.Consent.SteppedUp)
	require.Contains(t, child.Consent.Factors, string(ParentalConsentFactorPasskey))
	require.Empty(t, f.user.PasswordHash)
	_, err = f.service.CreateManagedChildAccount(context.Background(), f.user.ID, SessionSignIn{}, ManagedChildAccountRequest{
		Username: "child.other", DateOfBirthMs: new(f.service.nowFunc().AddDate(-8, 0, 0).UnixMilli()), Password: strongPW, PolicyVersion: "policy-v1", StepUpPasskey: proof,
	}, "", "")
	require.Error(t, err)
}

func TestReauthenticationRejectsLoginChallengeAndDoesNotCreateSessions(t *testing.T) {
	f := newReauthenticationFixture(t)
	proof := f.proof(t, "account.pin.set", f.user.ID, true)
	_, err := f.service.CompletePasskeyLogin(context.Background(), proof.ChallengeID, proof.CredentialJSON, "", "")
	require.Error(t, err)
	record := f.repo.passkeyChallenges[proof.ChallengeID]
	record.Action = ""
	require.Error(t, f.service.VerifyReauthentication(context.Background(), f.user.ID, SessionSignIn{}, proof, "account.pin.set", f.user.ID))
	require.Empty(t, f.repo.refreshTokens)
	require.LessOrEqual(t, record.ExpiresAt-record.CreatedAt, (2 * time.Minute).Milliseconds())
}

func TestStrictProjectPasskeyRegistrationRequiresFreshTrustedSignIn(t *testing.T) {
	f := newReauthenticationFixture(t)
	ctx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: f.service.cfg.DefaultProjectID})
	f.service.WithActiveProjects(&fakeActiveProjects{active: map[string]*AdminProject{
		f.service.cfg.DefaultProjectID: {ID: f.service.cfg.DefaultProjectID, Guardian: ProjectGuardianConfig{RequireStepUp: true}},
	}})
	for _, signIn := range []SessionSignIn{
		{},
		{AuthTimeSec: f.service.nowMs()/1000 - 301},
		{AuthTimeSec: f.service.nowMs() / 1000, AMR: []string{AMRRecoveryEmail}},
		{AuthTimeSec: f.service.nowMs() / 1000, AMR: []string{AMRUnvouched}},
	} {
		_, _, err := f.service.BeginPasskeyRegistration(ctx, f.user.ID, signIn, "device", false)
		require.ErrorIs(t, err, ErrRecoveryReauthenticationRequired)
		_, _, err = f.service.CompletePasskeyRegistration(ctx, f.user.ID, signIn, "unused", "{}", "device", false, "", "")
		require.ErrorIs(t, err, ErrRecoveryReauthenticationRequired)
	}
	require.Empty(t, f.repo.passkeyChallenges)
	_, _, err := f.service.BeginPasskeyRegistration(ctx, f.user.ID, SessionSignIn{AuthTimeSec: f.service.nowMs() / 1000}, "device", false)
	require.NoError(t, err)
}

func TestStrictProjectRefreshDoesNotRenewEnrollmentFreshness(t *testing.T) {
	f := newReauthenticationFixture(t)
	f.user.PasswordHash = hashPW(t, strongPW)
	f.user.EmailVerified = true
	login, err := f.service.PasswordLogin(context.Background(), f.user.Email, strongPW, "", "")
	require.NoError(t, err)
	old := f.service.nowFunc
	f.service.nowFunc = func() time.Time { return old().Add(6 * time.Minute) }
	_, access, _, err := f.service.RefreshToken(context.Background(), login.RefreshToken, "", "", "")
	require.NoError(t, err)
	stamp := authTimeOf(t, f.service, access)
	require.Equal(t, authTimeOf(t, f.service, login.AccessToken), stamp)
	f.service.WithActiveProjects(&fakeActiveProjects{active: map[string]*AdminProject{
		f.service.cfg.DefaultProjectID: {ID: f.service.cfg.DefaultProjectID, Guardian: ProjectGuardianConfig{RequireStepUp: true}},
	}})
	_, _, err = f.service.BeginPasskeyRegistration(context.Background(), f.user.ID, SessionSignIn{AuthTimeSec: stamp}, "device", false)
	require.ErrorIs(t, err, ErrRecoveryReauthenticationRequired)
}

func TestGuardianOperationsConsumeOnlyTheirBoundPasskey(t *testing.T) {
	for _, test := range []struct {
		action string
		status string
		call   func(reauthenticationFixture, string, *PasskeyReauthentication) error
	}{
		{"guardian.grant_consent", StatusPendingParentalConsent, func(f reauthenticationFixture, child string, proof *PasskeyReauthentication) error {
			_, err := f.service.GrantParentalConsent(context.Background(), f.user.ID, SessionSignIn{}, child, "policy-v1", "", proof, "", "")
			return err
		}},
		{"guardian.view_child", StatusActive, func(f reauthenticationFixture, child string, proof *PasskeyReauthentication) error {
			_, err := f.service.GetManagedChildProfile(context.Background(), f.user.ID, SessionSignIn{}, child, "", proof, "", "")
			return err
		}},
		{"guardian.set_child_password", StatusActive, func(f reauthenticationFixture, child string, proof *PasskeyReauthentication) error {
			return f.service.SetManagedChildPassword(context.Background(), f.user.ID, SessionSignIn{}, child, strongPW, "", proof, "", "")
		}},
		{"guardian.set_child_username", StatusActive, func(f reauthenticationFixture, child string, proof *PasskeyReauthentication) error {
			_, err := f.service.SetManagedChildUsername(context.Background(), f.user.ID, SessionSignIn{}, child, "child.renamed", "", proof, "", "")
			return err
		}},
		{"guardian.revoke_child_sessions", StatusActive, func(f reauthenticationFixture, child string, proof *PasskeyReauthentication) error {
			return f.service.RevokeManagedChildSessions(context.Background(), f.user.ID, SessionSignIn{}, child, "", proof, "", "")
		}},
		{"guardian.deactivate_child", StatusActive, func(f reauthenticationFixture, child string, proof *PasskeyReauthentication) error {
			return f.service.DeactivateManagedChildAccount(context.Background(), f.user.ID, SessionSignIn{}, child, "requested", "", proof, "", "")
		}},
		{"guardian.reactivate_child", StatusDeactivated, func(f reauthenticationFixture, child string, proof *PasskeyReauthentication) error {
			return f.service.ReactivateManagedChildAccount(context.Background(), f.user.ID, SessionSignIn{}, child, "", proof, "", "")
		}},
		{"guardian.delete_child", StatusActive, func(f reauthenticationFixture, child string, proof *PasskeyReauthentication) error {
			return f.service.DeleteManagedChildAccount(context.Background(), f.user.ID, SessionSignIn{}, child, "", proof, "", "")
		}},
	} {
		t.Run(test.action, func(t *testing.T) {
			f := newReauthenticationFixture(t)
			ctx := context.Background()
			f.service.WithAccountPurger(&fakePurger{repo: f.repo})
			child := seedManagedChild(t, f.repo, "child.example", f.service.nowFunc().AddDate(-8, 0, 0).UnixMilli())
			child.Status = test.status
			seedGuardianEdge(ctx, t, f.repo, f.user.ID, child.ID)
			wrong := f.proof(t, "account.pin.set", child.ID, true)
			require.ErrorIs(t, test.call(f, child.ID, wrong), ErrParentalConsentStepUpFailed)
			proof := f.proof(t, test.action, child.ID, true)
			require.NoError(t, test.call(f, child.ID, proof))
			remaining, err := f.repo.GetPasskeyChallenge(ctx, proof.ChallengeID)
			require.NoError(t, err)
			require.Nil(t, remaining)
		})
	}
}
