package service

import (
	"context"
	"fmt"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passkeys"
)

const (
	passkeyEligibilityAction        = "identity.passkey.verify_eligibility"
	maxEligibilityCredentialIDBytes = 4096
)

func (s *AuthService) passkeyEligibilityCaller(ctx context.Context, userID string, signIn SessionSignIn) (context.Context, *User, error) {
	if userID == "" {
		return nil, nil, ErrUnauthenticated
	}
	if err := s.refuseHeldSession(ctx, userID, signIn); err != nil {
		return nil, nil, err
	}
	ctx, err := s.credentialEnrollmentContext(ctx, userID, signIn)
	if err != nil {
		return nil, nil, err
	}
	// The target key is being vouched for by an independent primary sign-in,
	// not by a key-derived session whose own eligibility is in question.
	if signIn.credentialEnrollment().PasskeyID != "" {
		return nil, nil, ErrRecoveryReauthenticationRequired
	}
	user, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	if !isActivePerson(user) {
		return nil, nil, ErrPermissionDenied
	}
	if err := s.checkAccountStatus(ctx, user, "", "", sessionGateSignIn); err != nil {
		return nil, nil, err
	}
	return ctx, user, nil
}

func validateEligibilityCredentialID(id string) error {
	if id == "" || len(id) > maxEligibilityCredentialIDBytes {
		return fmt.Errorf("%w: credential_id is required and must be bounded", ErrInvalidArgument)
	}
	return nil
}

func (s *AuthService) BeginPasskeyEligibilityVerification(ctx context.Context, userID string, signIn SessionSignIn, credentialID string) (string, string, error) {
	if err := validateEligibilityCredentialID(credentialID); err != nil {
		return "", "", err
	}
	ctx, user, err := s.passkeyEligibilityCaller(ctx, userID, signIn)
	if err != nil {
		return "", "", err
	}
	key, err := s.repo(ctx).GetPasskeyCredentialByCredID(ctx, credentialID)
	if err != nil {
		return "", "", err
	}
	if key == nil || key.UserID != user.ID {
		return "", "", ErrPermissionDenied
	}
	return s.beginBoundPasskeyChallenge(ctx, user.ID, []string{key.CredentialID}, passkeyEligibilityAction, key.CredentialID)
}

func (s *AuthService) CompletePasskeyEligibilityVerification(ctx context.Context, userID string, signIn SessionSignIn, credentialID string, proof *PasskeyReauthentication) (*PasskeyInfo, error) {
	if err := validateEligibilityCredentialID(credentialID); err != nil {
		return nil, err
	}
	ctx, user, err := s.passkeyEligibilityCaller(ctx, userID, signIn)
	if err != nil {
		return nil, err
	}
	if proof == nil {
		return nil, ErrParentalConsentStepUpFailed
	}
	key, err := s.repo(ctx).GetPasskeyCredentialByCredID(ctx, credentialID)
	if err != nil {
		return nil, err
	}
	if key == nil || key.UserID != user.ID {
		return nil, ErrPermissionDenied
	}
	asserted, err := passkeys.ExtractCredentialID(proof.CredentialJSON)
	if err != nil || asserted != credentialID {
		return nil, ErrParentalConsentStepUpFailed
	}
	verified, err := s.consumeBoundPasskeyAssertion(ctx, user, proof, passkeyEligibilityAction, credentialID, false)
	if err != nil {
		return nil, err
	}
	updated, err := s.repo(ctx).MarkPasskeyReauthenticationEligible(ctx, verified)
	if err != nil {
		return nil, err
	}
	if !updated {
		return nil, ErrParentalConsentStepUpFailed
	}
	verified.ReauthenticationEligible = true
	s.audit.Log(ctx, audit.EventPasskeyEligibilityVerified, audit.WithActor(user.ID), audit.WithSuccess(true), audit.WithDetails(map[string]any{"credential_id": credentialID}))
	return passkeyInfoFromCredential(verified), nil
}
