package service

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

type resolvedProjectPolicyKey struct{}

// Admission reads the project policy even when transport routing
// used the default pin, or a native gRPC host supplied no project scope.
func (s *AuthService) activeProjectPolicyContext(ctx context.Context) (context.Context, error) {
	if s.activeProjects == nil {
		return ctx, nil
	}
	projectID := s.projectID(ctx)
	if resolved, ok := ctx.Value(resolvedProjectPolicyKey{}).(string); ok && resolved == projectID {
		return ctx, nil
	}
	project, err := s.activeProjects.ActiveProjectByID(ctx, projectID)
	if err != nil {
		s.logger.Warn("project_policy_unavailable", zap.Error(err))
		return nil, fmt.Errorf("%w: project policy unavailable", ErrUnavailable)
	}
	if project == nil || project.ID != projectID {
		return nil, fmt.Errorf("%w: project is not active", ErrPermissionDenied)
	}
	scope := ProjectScope{
		ProjectID: projectID, StorageScopeID: project.StorageScopeID,
		OAuth: project.OAuth, Access: project.Access, Products: project.Products,
		Accounts: project.Accounts, Branding: project.Branding,
	}
	if existing := ProjectScopeFromContext(ctx); existing != nil {
		scope = *existing
	}
	scope.ProjectID = projectID
	scope.Guardian = project.Guardian
	scope.AgeGate = project.AgeGate
	scope.Jurisdictions = project.Jurisdictions
	return context.WithValue(WithProjectScope(ctx, &scope), resolvedProjectPolicyKey{}, projectID), nil
}

func (s *AuthService) requiresDateOfBirth(ctx context.Context) bool {
	scope := ProjectScopeFromContext(ctx)
	return s.cfg.AgeGateRequireDOB || (scope != nil && scope.AgeGate.RequireDOB)
}

func (s *AuthService) requireAgeGateForDOB(ctx context.Context) error {
	if s.requiresDateOfBirth(ctx) && !s.ageGate.Enabled() {
		s.logger.Warn("required_dob_classification_disabled", zap.String("project_id", s.projectID(ctx)))
		return fmt.Errorf("%w: project requires date of birth but age classification is disabled", ErrUnavailable)
	}
	return nil
}
