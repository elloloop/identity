package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/elloloop/identity/pkg/audit"
)

// OperatorCredentials is what a caller of an operator RPC presents. The
// admin secret authorizes every operator RPC on every project. A
// tenant_operator credential ("<public id>.<secret>") authorizes only the
// tenant operations, the methods that call authorizeTenantOperator
// (app.TenantOperatorProcedures names them for the rate limit), and only on
// its own project, so a service that runs a project's tenants never
// holds the admin secret. When an admin secret is presented, it alone is
// checked.
type OperatorCredentials struct {
	AdminSecret       string
	TenantOperatorKey string
}

// errTenantOperatorRefused is every refusal of a presented tenant_operator
// key: one not shaped "<public id>.<secret>", an unknown public id, another
// kind's credential, a wrong secret, a revoked credential, a suspended
// project, or another project than the credential's. The caller learns
// nothing about which.
var errTenantOperatorRefused = fmt.Errorf("%w: invalid tenant operator credential", ErrPermissionDenied)

// tenantOperator is who an authorized tenant operation acts for.
type tenantOperator struct {
	// actor is the audit actor of the operation's records: a tenant_operator
	// credential's (credentialActor), or empty for the admin secret, which
	// names nobody.
	actor string
}

// authorizeTenantOperator admits a tenant operation on projectID: the admin
// secret through authorize, or an active tenant_operator credential of
// projectID, read uncached so a revocation holds from the next call. A
// refusal of a tenant_operator credential of an active project is audited
// under that project, with the reason; an unknown public id, another kind's
// credential and a suspended project's record nothing.
// projectID must be given: a credential is never taken to name its project.
func (s *ControlPlaneAdminService) authorizeTenantOperator(ctx context.Context, caller OperatorCredentials, projectID string) (tenantOperator, error) {
	if caller.AdminSecret != "" || caller.TenantOperatorKey == "" {
		return tenantOperator{}, s.authorize(caller.AdminSecret)
	}
	publicID, secret, ok := strings.Cut(caller.TenantOperatorKey, rawKeySeparator)
	if !ok || publicID == "" || secret == "" {
		return tenantOperator{}, errTenantOperatorRefused
	}
	cred, reason, err := checkProjectCredential(ctx, s.projects, CredentialKindTenantOperator, publicID, secret)
	if err != nil {
		return tenantOperator{}, err
	}
	if cred == nil {
		return tenantOperator{}, errTenantOperatorRefused
	}
	projectID = strings.TrimSpace(projectID)
	if reason == "" && projectID != "" && projectID != cred.ProjectID {
		reason = credentialRefusedOtherProject
	}
	if reason != "" {
		s.audit.Log(WithProjectScope(ctx, &ProjectScope{ProjectID: cred.ProjectID}), audit.EventTenantOperatorRefused,
			audit.WithActor(credentialActor(cred)), audit.WithSuccess(false),
			audit.WithDetails(map[string]any{"reason": reason}))
		return tenantOperator{}, errTenantOperatorRefused
	}
	if projectID == "" {
		return tenantOperator{}, fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	return tenantOperator{actor: credentialActor(cred)}, nil
}
