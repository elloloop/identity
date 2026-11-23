package service

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/elloloop/identity/pkg/agegate"
	"github.com/elloloop/identity/pkg/audit"
)

const (
	MaxAccountClassificationUsers   = 2
	maxAccountClassificationIDBytes = 128
)

type AccountClassification int

const (
	AccountClassificationDenied AccountClassification = iota
	AccountClassificationActiveKnownAdult
	AccountClassificationActiveKnownMinor
)

type ClassifiedAccount struct {
	UserID         string
	Classification AccountClassification
}

// AccountClassificationService is an ID-only standing check, not an
// authorization grant. Household, contact and consent checks remain separate.
type AccountClassificationService struct {
	credentials DirectoryCredentialStore
	auth        *AuthService
}

func NewAccountClassificationService(credentials DirectoryCredentialStore, auth *AuthService) *AccountClassificationService {
	if credentials == nil || auth == nil {
		return nil
	}
	return &AccountClassificationService{credentials: credentials, auth: auth}
}

var errInvalidAccountClassifierKey = fmt.Errorf("%w: invalid account classifier key or project", ErrUnauthenticated)

func validateAccountClassificationIDs(ids []string) error {
	if len(ids) == 0 || len(ids) > MaxAccountClassificationUsers {
		return fmt.Errorf("%w: user_ids must contain one or two exact IDs", ErrInvalidArgument)
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id == "" || len(id) > maxAccountClassificationIDBytes || strings.TrimSpace(id) != id || strings.Contains(id, "@") || strings.IndexFunc(id, unicode.IsControl) >= 0 || seen[id] {
			return fmt.Errorf("%w: user_ids must be distinct bounded account IDs", ErrInvalidArgument)
		}
		seen[id] = true
	}
	return nil
}

func (s *AccountClassificationService) ClassifyAccounts(ctx context.Context, presentedKey string, ids []string) ([]ClassifiedAccount, error) {
	if err := validateAccountClassificationIDs(ids); err != nil {
		return nil, err
	}
	publicID, secret, ok := strings.Cut(presentedKey, rawKeySeparator)
	if !ok || publicID == "" || secret == "" {
		return nil, errInvalidAccountClassifierKey
	}
	cred, reason, err := checkProjectCredential(ctx, s.credentials, CredentialKindAccountClassifier, publicID, secret)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, errInvalidAccountClassifierKey
	}
	scope := ProjectScopeFromContext(ctx)
	if reason == "" && (scope == nil || scope.ProjectID == "" || scope.ProjectID != cred.ProjectID) {
		reason = credentialRefusedOtherProject
	}
	if reason != "" {
		s.auth.audit.Log(WithProjectScope(ctx, &ProjectScope{ProjectID: cred.ProjectID}), audit.EventAccountsClassified,
			audit.WithActor(credentialActor(cred)), audit.WithSuccess(false), audit.WithDetails(map[string]any{"reason": reason}))
		return nil, errInvalidAccountClassifierKey
	}
	ctx, err = s.auth.activeProjectPolicyContext(ctx)
	if err != nil {
		return nil, err
	}
	users, err := s.auth.defaultRepo.WithProject(cred.ProjectID).GetUsersByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	classes := make(map[string]AccountClassification, len(users))
	now := s.auth.nowFunc()
	for _, user := range users {
		if !isActivePerson(user) || user.Status != StatusActive || user.Kind != UserKindPerson {
			continue
		}
		band := s.auth.determinerForUser(ctx, user).Determine(user.DateOfBirthMs, now)
		switch band.Band {
		case agegate.BandAdult:
			classes[user.ID] = AccountClassificationActiveKnownAdult
		case agegate.BandChild, agegate.BandTeen:
			classes[user.ID] = AccountClassificationActiveKnownMinor
		}
	}
	out := make([]ClassifiedAccount, len(ids))
	for i, id := range ids {
		out[i] = ClassifiedAccount{UserID: id, Classification: classes[id]}
	}
	s.auth.audit.Log(ctx, audit.EventAccountsClassified, audit.WithActor(credentialActor(cred)), audit.WithSuccess(true), audit.WithDetails(map[string]any{"requested": len(ids)}))
	return out, nil
}
