package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/elloloop/identity/pkg/audit"
)

// ManagedChildAuthorizationService exposes only a live authorization decision,
// never an account profile or a credential that can mint sessions.
type ManagedChildAuthorizationService struct {
	credentials DirectoryCredentialStore
	auth        *AuthService
}

// NewManagedChildAuthorizationService builds the narrow live authorization surface.
func NewManagedChildAuthorizationService(credentials DirectoryCredentialStore, auth *AuthService) *ManagedChildAuthorizationService {
	if credentials == nil {
		return nil
	}
	return &ManagedChildAuthorizationService{credentials: credentials, auth: auth}
}

// maxManagedChildAuthorizationIDBytes bounds opaque identifiers before repository reads.
const maxManagedChildAuthorizationIDBytes = 128

var errInvalidManagedChildKey = fmt.Errorf("%w: invalid managed child reader key or project", ErrUnauthenticated)

// GetManagedChildAuthorization checks one pair without returning profiles or tokens.
func (s *ManagedChildAuthorizationService) GetManagedChildAuthorization(ctx context.Context, key, childID, guardianID string) (bool, error) {
	publicID, secret, ok := strings.Cut(key, rawKeySeparator)
	if !ok || publicID == "" || secret == "" {
		return false, errInvalidManagedChildKey
	}
	cred, reason, err := checkProjectCredential(ctx, s.credentials, CredentialKindManagedChildReader, publicID, secret)
	if err != nil {
		return false, err
	}
	if cred == nil {
		return false, errInvalidManagedChildKey
	}
	scope := ProjectScopeFromContext(ctx)
	if reason == "" && (scope == nil || scope.ProjectID == "" || scope.ProjectID != cred.ProjectID) {
		reason = credentialRefusedOtherProject
	}
	if reason != "" {
		s.auth.audit.Log(WithProjectScope(ctx, &ProjectScope{ProjectID: cred.ProjectID}), audit.EventManagedChildAuthorization,
			audit.WithActor(credentialActor(cred)), audit.WithSuccess(false), audit.WithDetails(map[string]any{"reason": reason}))
		return false, errInvalidManagedChildKey
	}
	childID, guardianID = strings.TrimSpace(childID), strings.TrimSpace(guardianID)
	if childID == "" || guardianID == "" || len(childID) > maxManagedChildAuthorizationIDBytes || len(guardianID) > maxManagedChildAuthorizationIDBytes {
		return false, fmt.Errorf("%w: child_user_id and guardian_user_id must be 1..%d bytes", ErrInvalidArgument, maxManagedChildAuthorizationIDBytes)
	}
	ctx, err = s.auth.guardianContext(ctx)
	if err != nil {
		return false, err
	}
	// The resolved scope supplies age policy; the credential pins the repository.
	authorized, err := s.check(ctx, s.auth.defaultRepo.WithProject(cred.ProjectID), childID, guardianID)
	if err != nil {
		return false, err
	}
	s.auth.audit.Log(ctx, audit.EventManagedChildAuthorization, audit.WithActor(credentialActor(cred)), audit.WithTarget(childID), audit.WithSuccess(authorized))
	return authorized, nil
}

func (s *ManagedChildAuthorizationService) check(ctx context.Context, repo Repository, childID, guardianID string) (bool, error) {
	edge, err := repo.GetGuardianEdge(ctx, guardianID, childID)
	if err != nil || edge == nil {
		return false, err
	}
	users, err := repo.GetUsersByIDs(ctx, []string{childID, guardianID})
	if err != nil {
		return false, err
	}
	var child, guardian *User
	for _, user := range users {
		if user.ID == childID {
			child = user
		}
		if user.ID == guardianID {
			guardian = user
		}
	}
	if child == nil || guardian == nil || childID == guardianID || !isActivePerson(child) || !isActivePerson(guardian) {
		return false, nil
	}
	now := s.auth.nowFunc()
	childBand := s.auth.determinerForUser(ctx, child).Determine(child.DateOfBirthMs, now)
	return childBand.IsMinor && s.auth.isKnownAdultPerson(ctx, guardian), nil
}
