package service

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passkeys"
)

const (
	reauthenticationTTL           = 2 * time.Minute
	passkeyRegistrationAuthMaxAge = 5 * time.Minute
)

func (s *AuthService) passkeyRegistrationContext(ctx context.Context, signIn SessionSignIn) (context.Context, error) {
	ctx, err := s.activeProjectPolicyContext(ctx)
	if err != nil {
		return nil, err
	}
	if scope := ProjectScopeFromContext(ctx); scope != nil && scope.Guardian.RequireStepUp {
		if signIn.mayBeRecoverySession() || !s.signedInWithin(signIn.AuthTimeSec, passkeyRegistrationAuthMaxAge) {
			return nil, ErrRecoveryReauthenticationRequired
		}
	}
	return ctx, nil
}

var reauthenticationAction = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,95}$`)

type PasskeyReauthentication struct {
	ChallengeID    string
	CredentialJSON string
}

func validateReauthenticationAction(action, resourceID string) error {
	if !reauthenticationAction.MatchString(action) || len(resourceID) > 256 || strings.ContainsAny(resourceID, "\r\n\x00") {
		return fmt.Errorf("%w: invalid reauthentication action or resource", ErrInvalidArgument)
	}
	return nil
}

func (s *AuthService) reauthenticationUser(ctx context.Context, userID string, signIn SessionSignIn) (context.Context, *User, error) {
	if userID == "" {
		return nil, nil, ErrUnauthenticated
	}
	if err := s.refuseHeldSession(ctx, userID, signIn); err != nil {
		return nil, nil, err
	}
	ctx, err := s.activeProjectPolicyContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	user, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	if user == nil || !s.isKnownAdultPerson(ctx, user) {
		return nil, nil, errGuardianAdultProfileRequired
	}
	if err := s.checkAccountStatus(ctx, user, "", "", sessionGateSignIn); err != nil {
		return nil, nil, err
	}
	return ctx, user, nil
}

func (s *AuthService) BeginReauthentication(ctx context.Context, userID string, signIn SessionSignIn, action, resourceID string) (string, string, error) {
	if err := validateReauthenticationAction(action, resourceID); err != nil {
		return "", "", err
	}
	ctx, user, err := s.reauthenticationUser(ctx, userID, signIn)
	if err != nil {
		return "", "", err
	}
	credentials, err := s.repo(ctx).ListPasskeyCredentials(ctx, user.ID)
	if err != nil {
		return "", "", err
	}
	ids := make([]string, 0, len(credentials))
	for _, credential := range credentials {
		if credential.CredentialID != "" {
			ids = append(ids, credential.CredentialID)
		}
	}
	if len(ids) == 0 {
		return "", "", ErrParentalConsentFactorMissing
	}
	rp, err := s.passkeysFor(ctx)
	if err != nil {
		return "", "", err
	}
	options, challenge, err := rp.BeginUserVerifiedAuthentication(ids)
	if err != nil {
		return "", "", err
	}
	now := s.nowMs()
	id, err := s.repo(ctx).CreatePasskeyChallenge(ctx, &PasskeyChallengeRecord{
		UserID: user.ID, Challenge: challenge, ChallengeType: "authentication", Action: action,
		ResourceID: resourceID, CreatedAt: now, ExpiresAt: now + reauthenticationTTL.Milliseconds(),
	})
	if err != nil {
		return "", "", err
	}
	return options, id, nil
}

func (s *AuthService) VerifyReauthentication(ctx context.Context, userID string, signIn SessionSignIn, proof *PasskeyReauthentication, action, resourceID string) error {
	if err := validateReauthenticationAction(action, resourceID); err != nil {
		return err
	}
	ctx, user, err := s.reauthenticationUser(ctx, userID, signIn)
	if err != nil {
		return err
	}
	return s.verifyPasskeyReauthentication(ctx, user, proof, action, resourceID)
}

func (s *AuthService) verifyPasskeyReauthentication(ctx context.Context, user *User, proof *PasskeyReauthentication, action, resourceID string) error {
	if proof == nil || proof.ChallengeID == "" || proof.CredentialJSON == "" || !s.isKnownAdultPerson(ctx, user) {
		return ErrParentalConsentStepUpFailed
	}
	if err := s.checkAccountStatus(ctx, user, "", "", sessionGateSignIn); err != nil {
		return err
	}
	repo := s.repo(ctx)
	challenge, err := repo.GetPasskeyChallenge(ctx, proof.ChallengeID)
	if err != nil {
		return err
	}
	now := s.nowMs()
	if challenge == nil || challenge.ChallengeType != "authentication" || challenge.UserID != user.ID ||
		challenge.Action != action || challenge.ResourceID != resourceID || challenge.ExpiresAt <= now ||
		challenge.CreatedAt > now || challenge.ExpiresAt-challenge.CreatedAt > reauthenticationTTL.Milliseconds() {
		return ErrParentalConsentStepUpFailed
	}
	credentialID, err := passkeys.ExtractCredentialID(proof.CredentialJSON)
	if err != nil {
		return ErrParentalConsentStepUpFailed
	}
	credential, err := repo.GetPasskeyCredentialByCredID(ctx, credentialID)
	if err != nil {
		return err
	}
	if credential == nil || credential.UserID != user.ID || credential.SignCount < 0 || credential.SignCount > math.MaxUint32 {
		return ErrParentalConsentStepUpFailed
	}
	rp, err := s.passkeysFor(ctx)
	if err != nil {
		return err
	}
	counter, err := rp.CompleteUserVerifiedAuthentication(proof.CredentialJSON, challenge.Challenge, credential.PublicKey,
		uint32(credential.SignCount), credential.CredentialID, credential.UserID, credential.BackupEligible, credential.BackupState)
	if err != nil {
		return ErrParentalConsentStepUpFailed
	}
	consumed, err := repo.ConsumeReauthenticationChallenge(ctx, challenge.NodeID, user.ID, action, resourceID, s.nowMs())
	if err != nil {
		return err
	}
	if !consumed {
		return ErrParentalConsentStepUpFailed
	}
	if err := repo.UpdatePasskeyCredential(ctx, credential.NodeID, map[string]any{"sign_count": int64(counter), "last_used_at": now}); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.EventPasskeyUsed, audit.WithActor(user.ID), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"action": action, "resource_id": resourceID, "reauthentication": true}))
	return nil
}
