package service

import (
	"context"
	"fmt"
	"strings"
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
	// It is false whenever the mailer does not deliver.
	AccountExists bool
}

// GetTenantInvitation describes the invitation rawToken names, to anyone who
// holds the token: no caller is required. It changes nothing: an expired
// invitation is reported expired but not marked so, and the token stays
// redeemable as it was. A token no invitation of the request's project has is
// ErrNotFound, as AcceptTenantInvitation answers it, so the response tells a
// caller without a real token nothing.
//
// Whether the invited address has an account is answered only when the
// mailer delivers. Without one, CreateTenantInvitation hands the token to the
// inviter, and answering it would let a tenant admin learn whether any
// address they invite has an account.
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
	if s.mailerDelivers {
		if s.accounts == nil {
			return nil, fmt.Errorf("%w: no account store", ErrUnavailable)
		}
		if view.AccountExists, err = addressHasAccount(ctx, s.accounts.WithProject(projectID), inv.Email); err != nil {
			return nil, err
		}
	}
	return view, nil
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
