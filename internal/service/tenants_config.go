package service

import "errors"

// ProjectTenantsConfig is a project's policy for the tenants its users make
// for themselves and for what its tenants' invitations may carry.
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
	// InvitationNotes lets an owner or admin of a tenant attach a short
	// plain-text note to an invitation (CreateTenantInvitationRequest.note),
	// which its email shows. Absent/false refuses a note with
	// ErrInvitationNoteNotAllowed.
	InvitationNotes bool `json:"invitation_notes"`
	// InvitationNotesSelfService extends InvitationNotes to tenants made
	// through CreateTenant. Their owners and admins are whoever signed up, not
	// people the project vetted, so a project turning it on accepts that such
	// a person may put a validated, link-free note in an email the service
	// sends under its own name. Absent/false refuses a note on such a tenant
	// with ErrInvitationNoteNotAllowed. It needs InvitationNotes.
	InvitationNotesSelfService bool `json:"invitation_notes_self_service"`
}

// validate rejects invitation_notes_self_service without invitation_notes,
// where it could never take effect.
func (t ProjectTenantsConfig) validate() error {
	if t.InvitationNotesSelfService && !t.InvitationNotes {
		return errors.New("tenants: invitation_notes_self_service needs invitation_notes")
	}
	return nil
}
