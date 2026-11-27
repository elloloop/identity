package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/emailaddr"
)

// ManagedAccountRequest asks CreateManagedSetupInvitation for a managed
// account of TenantID at <Username>@<Domain>, named DisplayName, whose
// set-up link goes to DeliveryEmail and grants Role.
type ManagedAccountRequest struct {
	TenantID      string
	Username      string
	Domain        string
	DisplayName   string
	DeliveryEmail string
	Role          string
}

// WithManagedSetups wires the store managed accounts' set-up links are
// written through (the postgres control plane's); without one no managed
// account can be created, and ListTenantMembers reports every member as
// having a personal account.
func (s *MembershipService) WithManagedSetups(store ManagedSetupStore) *MembershipService {
	s.managedSetups = store
	return s
}

// CreateManagedSetupInvitation creates a managed account of req.TenantID, or,
// for one of its managed accounts never set up, issues a new set-up link that
// replaces the pending one, and mails the link to req.DeliveryEmail. callerID
// must be an active owner or admin of a tenant that may be governed, asking
// from a session no recovery hold binds; an owner role, or replacing an
// owner's link, needs an owner. The server, the project and the tenant must
// admit managed accounts, and the project must hold the address
// (ErrManagedAccountsNotAdmitted); the address's domain must be verified for
// the tenant (ErrManagedDomainUnverified); the address must be free or one
// of the tenant's own accounts waiting to be set up (ErrManagedByThisTenant,
// ErrManagedAddressUnavailable). The invitation limits apply with the
// account's address as the recipient, and the delivery address is held to
// the resend cooldown and to the per-recipient cap, counted across the
// project. The link's token goes only into its email,
// so a server whose mailer does not deliver refuses with
// ErrEmailDeliveryDisabled. Every refusal is logged with its reason; the
// creation or resend is logged and audited.
func (s *MembershipService) CreateManagedSetupInvitation(ctx context.Context, callerID string, signIn SessionSignIn, req ManagedAccountRequest, ip, userAgent string) (*CreatedInvitation, error) {
	projectID, err := s.requireProject(ctx)
	tenantID := strings.TrimSpace(req.TenantID)
	fields := []zap.Field{zap.String("project_id", projectID), zap.String("tenant_id", tenantID), zap.String("inviter_id", callerID)}
	refuse := func(reason string, err error) (*CreatedInvitation, error) {
		s.logger.Info("managed_account_create_refused", append(fields, zap.String("reason", reason))...)
		return nil, err
	}
	if err != nil {
		return refuse("no_project", err)
	}
	if callerID == "" {
		return refuse("unauthenticated", ErrUnauthenticated)
	}
	if s.managedSetups == nil {
		return refuse("unavailable", ErrUnimplemented)
	}
	if err := s.refuseHeldSession(ctx, projectID, callerID, signIn); err != nil {
		return refuse("held_session", err)
	}
	if tenantID == "" {
		return refuse("invalid_argument", fmt.Errorf("%w: missing tenant_id", ErrInvalidArgument))
	}
	address, domain, err := managedAccountAddress(req.Username, req.Domain)
	if err != nil {
		return refuse("invalid_argument", err)
	}
	displayName, err := normalizeText("display_name", req.DisplayName, accountNameMaxRunes)
	if err != nil {
		return refuse("invalid_argument", err)
	}
	delivery, err := normalizeInvitationEmail(req.DeliveryEmail)
	if err != nil {
		return refuse("invalid_argument", err)
	}
	role, err := normalizeInvitationRole(req.Role)
	if err != nil {
		return refuse("invalid_argument", err)
	}
	caller, err := s.requireTenantAdmin(ctx, projectID, tenantID, callerID, signIn)
	if err != nil {
		return refuse("not_permitted", err)
	}
	if role == RoleOwner && caller.Role != RoleOwner {
		return refuse("not_permitted", fmt.Errorf("%w: only an owner may create an owner's account", ErrPermissionDenied))
	}
	scope := ProjectScopeFromContext(ctx)
	if err := requireManagedAccountsAdmitted(ctx, s.cfg, s.tenants, scope, tenantID); err != nil {
		return refuse("policy", err)
	}
	if err := refuseProjectAddress(s.cfg, scope, address, domain); err != nil {
		return refuse("policy", err)
	}
	if !s.mailerDelivers {
		return refuse("mail_not_delivered", ErrEmailDeliveryDisabled)
	}
	if err := requireProjectEmailDelivery(ctx, projectID, s.projects); err != nil {
		return refuse("mail_not_delivered", err)
	}

	rawToken := randomToken(invitationTokenBytes)
	now := s.nowFunc()
	issued, err := s.managedSetups.CreateManagedSetup(ctx, ManagedSetup{
		ProjectID: projectID, TenantID: tenantID, Address: address, Domain: domain,
		DisplayName: displayName, DeliveryEmail: delivery, Role: role, InvitedBy: callerID,
		TokenHash: sha256Hex(rawToken), ExpiresAtMs: now.Add(s.invitationTTL()).UnixMilli(),
		Limits:              s.invitationLimits(now),
		MaxPerDeliveryEmail: s.config().TenantInvitationRecipientLimit(),
	})
	if err != nil {
		return refuse(managedCreateRefusalReason(err), err)
	}

	fields = append(fields, zap.String("user_id", issued.User.ID), zap.String("invitation_id", issued.Invitation.ID),
		zap.String("role", issued.Invitation.Role), zap.String("to", redactEmail(delivery)))
	event := audit.EventManagedAccountCreated
	details := map[string]any{
		"project_id": projectID, "tenant_id": tenantID, "role": issued.Invitation.Role,
		"invitation_id": issued.Invitation.ID,
	}
	if issued.Created {
		s.logger.Info("managed_account_created", fields...)
	} else {
		deliveryChanged := issued.PreviousDeliveryEmail != "" && !emailaddr.SameMailbox(issued.PreviousDeliveryEmail, delivery)
		s.logger.Info("managed_account_setup_resent", append(fields, zap.Bool("delivery_changed", deliveryChanged))...)
		event = audit.EventManagedAccountSetupResent
		details["delivery_changed"] = deliveryChanged
	}
	if s.audit != nil {
		s.audit.Log(ctx, event,
			audit.WithActor(callerID), audit.WithTarget(issued.User.ID),
			audit.WithIP(ip), audit.WithUserAgent(userAgent),
			audit.WithSuccess(true), audit.WithDetails(details),
		)
	}

	out := &CreatedInvitation{Invitation: issued.Invitation, EmailStatus: EmailSent}
	if err := s.sendManagedSetupEmail(ctx, issued, rawToken); err != nil {
		out.EmailStatus = EmailSendFailed
	}
	return out, nil
}

// managedCreateRefusalReason names the rule CreateManagedSetup refused with.
func managedCreateRefusalReason(err error) string {
	switch {
	case errors.Is(err, ErrManagedByThisTenant):
		return "managed_by_this_tenant"
	case errors.Is(err, ErrManagedAddressUnavailable):
		return "address_unavailable"
	case errors.Is(err, ErrManagedDomainUnverified):
		return "domain_unverified"
	case errors.Is(err, ErrPermissionDenied):
		return "not_permitted"
	case isInvitationLimit(err):
		return "limited"
	default:
		return "store_error"
	}
}

// refuseManagedAddress refuses an ordinary invitation of tenantID to email
// with ErrManagedByThisTenant when email is one of the tenant's managed
// accounts: the tenant already holds that account, and an invitation would
// only reach the mailbox behind it. An address another tenant manages is
// invited as any other, so no tenant can learn which addresses others
// manage; acceptance refuses it.
func (s *MembershipService) refuseManagedAddress(ctx context.Context, projectID, tenantID, email string) error {
	if s.managedSetups == nil {
		return nil
	}
	holders, err := s.managedSetups.ManagedAddressHolders(ctx, projectID, tenantID, []string{email})
	if err != nil {
		return err
	}
	if holders[email] == ManagedAddressManagedByThis {
		return ErrManagedByThisTenant
	}
	return nil
}

// revokeManagedSetup revokes tenantID's managed set-up link invitationID
// through RevokeManagedSetup, deleting its account when it was never set up.
// handled is false when invitationID is not one of the tenant's managed
// set-up links, for the caller to revoke as an ordinary invitation.
func (s *MembershipService) revokeManagedSetup(ctx context.Context, projectID, tenantID, invitationID, callerID, ip, userAgent string) (inv *TenantInvitation, changed, handled bool, err error) {
	revoked, err := s.managedSetups.RevokeManagedSetup(ctx, projectID, tenantID, invitationID, callerID)
	if errors.Is(err, ErrNotFound) {
		return nil, false, false, nil
	}
	if err != nil {
		return nil, false, true, err
	}
	if deleted := revoked.DeletedUser; deleted != nil {
		s.logger.Info("managed_account_deleted",
			zap.String("project_id", projectID), zap.String("tenant_id", tenantID),
			zap.String("invitation_id", invitationID), zap.String("user_id", deleted.ID),
			zap.String("by", callerID))
		if s.audit != nil {
			s.audit.Log(ctx, audit.EventManagedAccountDeleted,
				audit.WithActor(callerID), audit.WithTarget(deleted.ID),
				audit.WithIP(ip), audit.WithUserAgent(userAgent),
				audit.WithSuccess(true), audit.WithDetails(map[string]any{
					"project_id": projectID, "tenant_id": tenantID, "invitation_id": invitationID,
				}),
			)
		}
	}
	return revoked.Invitation, revoked.Changed, true, nil
}

// markManagedMembers sets AccountKind on each of members: managed for an
// account tenantID manages, personal otherwise.
func (s *MembershipService) markManagedMembers(ctx context.Context, projectID, tenantID string, members []*TenantMembership) error {
	managed := map[string]bool{}
	if s.managedSetups != nil && len(members) > 0 {
		ids := make([]string, 0, len(members))
		for _, m := range members {
			ids = append(ids, m.UserID)
		}
		var err error
		if managed, err = s.managedSetups.ManagedAccountsAmong(ctx, projectID, tenantID, ids); err != nil {
			return err
		}
	}
	for _, m := range members {
		m.AccountKind = AccountKindPersonal
		if managed[m.UserID] {
			m.AccountKind = AccountKindManaged
		}
	}
	return nil
}

// sendManagedSetupEmail mails issued's set-up link, carrying rawToken, to the
// address it was issued to be delivered at, and returns why it was not sent.
func (s *MembershipService) sendManagedSetupEmail(ctx context.Context, issued *ManagedSetupIssued, rawToken string) error {
	inv := issued.Invitation
	fields := invitationLogFields(ctx, inv.ID)
	ctx = email.ContextWithLogFields(ctx, fields...)
	logger := s.logger.With(fields...)
	var brand resolvedBranding
	if s.cfg != nil {
		brand = resolveBranding(ctx, s.cfg, "")
	}
	t, err := s.tenants.GetTenant(ctx, inv.ProjectID, inv.TenantID)
	if err != nil {
		logger.Warn("managed_account_setup_tenant_lookup_failed", zap.Error(err))
		t = nil
	}
	greeting, tenantName := managedAccountGreeting(t, issued.User)
	html, text, err := email.Render(email.TemplateManagedAccountSetup, brand.templateData(map[string]any{
		"UserName":       greeting,
		"TenantName":     tenantName,
		"AccountAddress": issued.User.Email,
		"Role":           inv.Role,
		"ExpiresIn":      formatLinkLifetime(s.invitationTTL()),
		"Link":           tenantInvitationLink(ctx, s.cfg, rawToken),
	}))
	if err != nil {
		logger.Warn("managed_account_setup_render_failed", zap.String("to", redactEmail(inv.DeliveryEmail)), zap.Error(err))
		return err
	}
	msg := email.Message{
		To:      inv.DeliveryEmail,
		From:    s.cfg.SMTPFrom,
		Subject: "Set up your account",
		HTML:    html,
		Text:    text,
	}
	brand.applyTo(&msg)
	if err := s.mailer.Send(ctx, msg); err != nil {
		logger.Warn("managed_account_setup_send_failed", zap.String("to", redactEmail(inv.DeliveryEmail)), zap.Error(err))
		return err
	}
	return nil
}

// acceptManagedSetupLink answers AcceptTenantInvitation for inv, a managed
// account's set-up link: only its own account, once the link is accepted,
// gets its membership back, so a repeated accept after set-up is idempotent.
func (s *MembershipService) acceptManagedSetupLink(ctx context.Context, projectID, callerID string, inv *TenantInvitation) (*TenantMembership, error) {
	if inv.UserID != callerID || inv.Status != InvitationStatusAccepted {
		s.logAcceptRefused(ctx, projectID, callerID, inv, "managed_setup_link")
		return nil, fmt.Errorf("%w: this link sets up an account; open it to set the account's password", ErrPermissionDenied)
	}
	m, err := s.memberships.GetMembership(ctx, projectID, inv.TenantID, callerID)
	if err != nil {
		return nil, err
	}
	if m == nil {
		s.logAcceptRefused(ctx, projectID, callerID, inv, "not_a_member")
		return nil, fmt.Errorf("%w: membership", ErrNotFound)
	}
	return m, nil
}
