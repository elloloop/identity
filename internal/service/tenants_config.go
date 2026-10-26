package service

// ProjectTenantsConfig is a project's policy for the tenants its users make
// for themselves.
type ProjectTenantsConfig struct {
	// SelfService lets a signed-in user create a tenant they own
	// (CreateTenant). Absent/false means the RPC is refused with
	// ErrSelfServiceTenantsDisabled. ListMyTenants and the tenant selection
	// on RefreshToken do not depend on it: they serve every tenant a user is
	// an active member of, however that tenant was made.
	SelfService bool `json:"self_service"`
}

// validate accepts any value: the block carries a single boolean and both
// states are meaningful. It exists so ProjectConfig.Validate has a uniform
// call for every block.
//
// There is deliberately no per-project creation limit. The limit is
// deployment-wide (GATEWAY_SELF_SERVICE_TENANTS_*), because it bounds the
// rows one account can make the operator responsible for, which is the
// operator's budget, not a project's.
func (t ProjectTenantsConfig) validate() error { return nil }
