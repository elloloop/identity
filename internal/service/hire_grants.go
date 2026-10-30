package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/elloloop/identity/pkg/audit"
)

var errHireGrantCaller = fmt.Errorf("%w: only the teammate's owner or a project admin can grant its hire", ErrPermissionDenied)

// CreateHireGrant records that callerID, the person signed in to the
// request's project, hires teammateID into placementID for companyID. As for
// every action on an agent, only its owner or a project admin may, and every
// other caller is refused alike whether the id names an agent, a person or
// nothing. The exchange applies the same rule again on every token. The
// grant is single use and expires after HireGrantLifetime.
func (s *TeammateKeyService) CreateHireGrant(ctx context.Context, callerID, teammateID, placementID, companyID string) (*HireGrant, error) {
	if callerID == "" {
		return nil, ErrUnauthenticated
	}
	if !validOAuthClientID(teammateID) || !validOAuthClientID(placementID) || !validOAuthClientID(companyID) {
		return nil, ErrInvalidArgument
	}
	project := s.requestProject(ctx)
	users := s.base.WithProject(project)
	caller, err := users.GetUser(ctx, callerID)
	if errors.Is(err, ErrNotFound) || err == nil && caller == nil {
		return nil, ErrUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	refuse := func(step string) error {
		s.audit.Log(ctx, audit.EventHireGrantRefused, audit.WithActor(callerID), audit.WithTarget(teammateID), audit.WithSuccess(false), audit.WithDetails(map[string]any{"step": step, "placement_id": placementID, "company_id": companyID}))
		return errHireGrantCaller
	}
	if !isActivePerson(caller) {
		return nil, refuse("caller_not_active_person")
	}
	teammate, err := users.GetUser(ctx, teammateID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if !mayGrantHire(caller, teammate) {
		return nil, refuse("not_permitted")
	}
	now := s.now()
	grant := &HireGrant{ID: rand.Text(), OwnerUserID: caller.ID, TeammateID: teammateID, PlacementID: placementID, CompanyID: companyID, CreatedAtMs: now.UnixMilli(), ExpiresAtMs: now.Add(HireGrantLifetime).UnixMilli()}
	if err = s.repo(project).CreateHireGrant(ctx, grant); err != nil {
		return nil, err
	}
	s.audit.Log(ctx, audit.EventHireGrantCreated, audit.WithActor(caller.ID), audit.WithTarget(teammateID), audit.WithSuccess(true), audit.WithDetails(map[string]any{"placement_id": placementID, "company_id": companyID}))
	return grant, nil
}
