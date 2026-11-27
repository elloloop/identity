package service

// ProjectTenantsConfig is a project's policy for the tenants its users make
// for themselves and for what its tenants' invitations may carry. Every value
// is valid, so ProjectConfig.Validate has nothing to check here.
//
// There is deliberately no per-project creation limit. The limit is
// deployment-wide (GATEWAY_SELF_SERVICE_TENANTS_*), because it bounds the
// rows one account can make the operator responsible for, which is the
// operator's budget, not a project's.
type ProjectTenantsConfig struct {
	// SelfService lets a signed-in user create a tenant they own
	// (CreateTenant). Absent/false means the RPC is refused with
	// ErrSelfServiceTenantsDisabled. ListMyTenants and the tenant selection
	// on RefreshToken do not depend on it: they serve every tenant a user is
	// an active member of, however that tenant was made.
	SelfService bool `json:"self_service"`
	// InvitationNotes lets an owner or admin of a tenant that is not
	// self-service attach a short plain-text note to an invitation
	// (CreateTenantInvitationRequest.note), which its email shows. Absent/false
	// refuses a note with ErrInvitationNoteNotAllowed.
	InvitationNotes bool `json:"invitation_notes"`
}
