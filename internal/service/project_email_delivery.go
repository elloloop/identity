package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/elloloop/identity/pkg/email"
)

var ErrEmailDeliveryDisabled = errors.New("email_delivery_disabled: this project does not send email")

func projectEmailDeliveryDisabled(ctx context.Context, defaultProjectID string, projects ActiveProjectStore) (bool, error) {
	if projects == nil {
		scope := ProjectScopeFromContext(ctx)
		return scope != nil && scope.EmailDelivery.Disabled, nil
	}
	projectID := requestProjectID(ctx, defaultProjectID)
	project, err := projects.ActiveProjectByID(ctx, projectID)
	if err != nil || project == nil || project.ID != projectID {
		return false, fmt.Errorf("%w: project email policy unavailable", ErrUnavailable)
	}
	return project.EmailDelivery.Disabled, nil
}

func requireProjectEmailDelivery(ctx context.Context, defaultProjectID string, projects ActiveProjectStore) error {
	disabled, err := projectEmailDeliveryDisabled(ctx, defaultProjectID, projects)
	if err != nil {
		return err
	}
	if disabled {
		return ErrEmailDeliveryDisabled
	}
	return nil
}

func (s *AuthService) ProjectEmailDeliveryDisabled(ctx context.Context) (bool, error) {
	return projectEmailDeliveryDisabled(ctx, s.cfg.DefaultProjectID, s.activeProjects)
}

func (s *AuthService) requireEmailDelivery(ctx context.Context) error {
	scope := ProjectScopeFromContext(ctx)
	if resolved, ok := ctx.Value(resolvedProjectPolicyKey{}).(string); ok && scope != nil && resolved == scope.ProjectID {
		if scope.EmailDelivery.Disabled {
			return ErrEmailDeliveryDisabled
		}
		return nil
	}
	return requireProjectEmailDelivery(ctx, s.cfg.DefaultProjectID, s.activeProjects)
}

type projectMailTransport struct {
	transport        email.Transport
	defaultProjectID string
	projects         ActiveProjectStore
}

// Policy is read at the last handoff so delayed sends cannot use a stale
// request snapshot. A failed lookup must never fall back to the shared relay.
func NewProjectMailTransport(transport email.Transport, defaultProjectID string, projects ActiveProjectStore) email.Transport {
	return projectMailTransport{transport: transport, defaultProjectID: defaultProjectID, projects: projects}
}

func (m projectMailTransport) Send(ctx context.Context, message email.Message) error {
	if err := requireProjectEmailDelivery(ctx, m.defaultProjectID, m.projects); err != nil {
		return err
	}
	return m.transport.Send(ctx, message)
}
