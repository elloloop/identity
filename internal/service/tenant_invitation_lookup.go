package service

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"
)

// TenantInvitationView is what GetTenantInvitation tells the holder of an
// invitation's token: enough for the page the invitation email links to to
// say who invites them where, and whether they sign up or sign in.
type TenantInvitationView struct {
	TenantID string
	// TenantName is the name the invitation email shows (tenantDisplayName).
	TenantName string
	// InviterName and InviterEmail are the inviting account's, "" once it
	// no longer exists.
	InviterName  string
	InviterEmail string
	Email        string
	Role         string
	ExpiresAtMs  int64
	// Status is the invitation's status, with a pending invitation past its
	// expiry reported as InvitationStatusExpired (invitationStatusAt).
	Status string
	// AccountExists reports whether an account of the project holds Email.
	// It is false whenever the mailer does not deliver or the invitation's
	// token did not go only into its email (TokenOnlyInEmail). It is false
	// for a managed account's set-up link.
	AccountExists bool
	// IsManagedSetup marks a managed account's set-up link; Email is then
	// the account's address.
	IsManagedSetup bool
	// AccountAddress and DisplayName describe the managed account a set-up
	// link sets up, only while the link is pending and is the account's
	// current one; DisplayName is also withheld for a tenant made through
	// self-service CreateTenant, as TenantName is.
	AccountAddress string
	DisplayName    string
}

// GetTenantInvitation describes the invitation rawToken names, to anyone who
// holds the token: no caller is required. It changes nothing: an expired
// invitation is reported expired but not marked so, and the token stays
// redeemable as it was. A token no invitation of the request's project has is
// ErrNotFound, as AcceptTenantInvitation answers it, so the response tells a
// caller without a real token nothing.
//
// Whether the invited address has an account is answered only when the
// mailer delivers and the invitation records that its token went only into
// its email (TokenOnlyInEmail). Otherwise CreateTenantInvitation may have
// handed the token to the inviter, and answering would let a tenant admin
// learn whether any address they invite has an account.
//
// A managed account's set-up link is described by describeManagedSetup.
func (s *MembershipService) GetTenantInvitation(ctx context.Context, rawToken string) (*TenantInvitationView, error) {
	projectID, err := s.requireProject(ctx)
	if err != nil {
		return nil, err
	}
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, fmt.Errorf("%w: missing token", ErrInvalidArgument)
	}
	inv, err := s.invitations.GetInvitationByTokenHash(ctx, projectID, sha256Hex(rawToken))
	if err != nil {
		return nil, err
	}
	if inv == nil {
		s.logger.Info("tenant_invitation_read_refused",
			zap.String("project_id", projectID), zap.String("reason", "not_found"))
		return nil, fmt.Errorf("%w: invitation", ErrNotFound)
	}

	tenantName, err := s.tenantDisplayName(ctx, projectID, inv.TenantID)
	if err != nil {
		return nil, err
	}
	view := &TenantInvitationView{
		TenantID:    inv.TenantID,
		TenantName:  tenantName,
		Email:       inv.Email,
		Role:        inv.Role,
		ExpiresAtMs: inv.ExpiresAtMs,
		Status:      invitationStatusAt(inv, s.nowFunc().UnixMilli()),
	}
	if inv.InvitedBy != "" {
		inviter, err := s.users.GetUserInProject(ctx, projectID, inv.InvitedBy)
		if err != nil {
			return nil, err
		}
		if inviter != nil {
			view.InviterName, view.InviterEmail = inviter.Name, inviter.Email
		}
	}
	fields := append(invitationDecisionLogFields(ctx, projectID, inv), zap.String("status", view.Status))
	if inv.IsManagedSetup() {
		if err := s.describeManagedSetup(ctx, projectID, inv, view); err != nil {
			return nil, err
		}
		s.logger.Info("tenant_invitation_read", append(fields, zap.Bool("managed_setup", true), zap.Bool("live", view.AccountAddress != ""))...)
		return view, nil
	}
	switch {
	case !s.mailerDelivers:
		fields = append(fields, zap.String("account_exists_withheld", "mail_not_delivered"))
	case !inv.TokenOnlyInEmail:
		fields = append(fields, zap.String("account_exists_withheld", "token_outside_email"))
	default:
		if s.accounts == nil {
			return nil, fmt.Errorf("%w: no account store", ErrUnavailable)
		}
		if view.AccountExists, err = addressHasAccount(ctx, s.accounts.WithProject(projectID), inv.Email); err != nil {
			return nil, err
		}
		fields = append(fields, zap.Bool("account_exists", view.AccountExists))
	}
	s.logger.Info("tenant_invitation_read", fields...)
	return view, nil
}

// invitationDecisionLogFields are the ids the line recording a decision about
// a tenant invitation carries: the project, and, unless the token named none,
// the invitation's tenant and id with the request's trace. They never carry
// the address, the token or a name.
func invitationDecisionLogFields(ctx context.Context, projectID string, inv *TenantInvitation) []zap.Field {
	fields := []zap.Field{zap.String("project_id", projectID)}
	if inv == nil {
		return fields
	}
	return append(append(fields, zap.String("tenant_id", inv.TenantID)), invitationLogFields(ctx, inv.ID)...)
}

// invitationStatusAt is inv's status at nowMs: a pending invitation whose
// expiry has passed is expired, read as AcceptTenantInvitation reads it,
// whether or not the expiry has been recorded.
func invitationStatusAt(inv *TenantInvitation, nowMs int64) string {
	if inv.Status == InvitationStatusPending && inv.ExpiresAtMs > 0 && inv.ExpiresAtMs < nowMs {
		return InvitationStatusExpired
	}
	return inv.Status
}

// addressHasAccount reports whether an account of repo's project holds email,
// as its email or as a recovery email: either way no new account can be made
// on it.
func addressHasAccount(ctx context.Context, repo Repository, email string) (bool, error) {
	if u, err := repo.FindUserByEmail(ctx, email); err != nil || u != nil {
		return u != nil, err
	}
	held, err := repo.FindRecoveryEmailHolder(ctx, email)
	return held != nil, err
}

// describeManagedSetup fills view for inv, a managed account's set-up link.
// Email stays the account's address, as stored on the link; the address is
// repeated as AccountAddress, with the account's name, only while the link
// is pending and its epoch is the account's current one, so a revoked,
// replaced or used link no longer describes the account. The address the
// link was delivered to is never answered, nor the account's id: the read is
// public to whoever holds the token. The name is withheld for a self-service
// tenant, whose names are unvetted.
func (s *MembershipService) describeManagedSetup(ctx context.Context, projectID string, inv *TenantInvitation, view *TenantInvitationView) error {
	view.IsManagedSetup = true
	if view.Status != InvitationStatusPending {
		return nil
	}
	account, err := s.users.GetUserInProject(ctx, projectID, inv.UserID)
	if err != nil {
		return err
	}
	if account == nil || account.ManagedByTenantID != inv.TenantID || account.Status != StatusInvited || account.SetupEpoch != inv.SetupEpoch {
		return nil
	}
	view.AccountAddress = account.Email
	t, err := s.tenants.GetTenant(ctx, projectID, inv.TenantID)
	if err != nil {
		return err
	}
	if t != nil && t.CreatedBy == "" {
		view.DisplayName = account.Name
	}
	return nil
}
