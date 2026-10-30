package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/elloloop/identity/pkg/audit"
)

var errHireGrantCaller = fmt.Errorf("%w: only an active person can grant a hire", ErrPermissionDenied)

// CreateHireGrant records that callerID, the person signed in to the
// request's project, hires teammateID into placementID for companyID. The
// grant is single use and expires after HireGrantLifetime.
func (s *TeammateKeyService) CreateHireGrant(ctx context.Context, callerID, teammateID, placementID, companyID string) (*HireGrant, error) {
	if callerID == "" {
		return nil, ErrUnauthenticated
	}
	if !validOAuthClientID(teammateID) || !validOAuthClientID(placementID) || !validOAuthClientID(companyID) {
		return nil, ErrInvalidArgument
	}
	project := s.requestProject(ctx)
	caller, err := s.base.WithProject(project).GetUser(ctx, callerID)
	if errors.Is(err, ErrNotFound) || err == nil && caller == nil {
		return nil, ErrUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	if !isActivePerson(caller) {
		return nil, errHireGrantCaller
	}
	if err = s.activeTeammate(ctx, project, teammateID, ErrInvalidArgument); err != nil {
		return nil, err
	}
	now := s.now()
	grant := &HireGrant{ID: rand.Text(), OwnerUserID: caller.ID, TeammateID: teammateID, PlacementID: placementID, CompanyID: companyID, CreatedAtMs: now.UnixMilli(), ExpiresAtMs: now.Add(HireGrantLifetime).UnixMilli()}
	if err = s.repo(project).CreateHireGrant(ctx, grant); err != nil {
		return nil, err
	}
	s.audit.Log(ctx, audit.EventHireGrantCreated, audit.WithActor(caller.ID), audit.WithTarget(teammateID), audit.WithSuccess(true), audit.WithDetails(map[string]any{"grant_id": grant.ID, "placement_id": placementID, "company_id": companyID}))
	return grant, nil
}
