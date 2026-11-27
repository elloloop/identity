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

var (
	// ErrManagedResetReauthenticationRequired refuses ResetManagedAccount
	// from a session whose sign-in is older than
	// GATEWAY_ACCOUNT_MERGE_REAUTH_MAX_AGE_SECONDS. Its message leads with the
	// stable `reauthentication_required` token clients match on to sign the
	// caller in again and retry. Mapped to CodePermissionDenied.
	ErrManagedResetReauthenticationRequired = errors.New("reauthentication_required: sign in again to reset this account")
	// ErrManagedSetupNeedsMailer refuses a managed account's set-up link on a
	// server that delivers no mail: the link's token travels only in its
	// email. Mapped to CodeFailedPrecondition.
	ErrManagedSetupNeedsMailer = errors.New("a set-up link needs a mail provider to deliver it")
)

// managedResetReviewNote is what the reset's audit entry tells the responder
// to do next: whoever held the account may have used it.
const managedResetReviewNote = "review the invitations and accounts this account created"

// SessionInvalidator drops sessions from the in-process session cache, so a
// session a store transaction revoked stops working on this replica at once.
type SessionInvalidator interface {
	Invalidate(sid string)
}

// WithManagedMembers sets the store that suspends, removes and resets the
// tenant's managed accounts, and the session cache whose entries for the
// sessions they end are dropped after each commit. With no store a managed
// account's suspension, removal or reset is ErrServiceUnavailable.
func (s *MembershipService) WithManagedMembers(managed ManagedMemberStore, sessions SessionInvalidator) *MembershipService {
	s.managed, s.sessions = managed, sessions
	return s
}

// managedByTenant reports whether targetUserID's account is one tenantID
// manages, whether or not managed accounts are on: turning them off must not
// leave an existing managed account's sessions running after its suspension
// or removal. Which tenant manages an account is fixed when the account is
// created, so the store's transaction finds what this read found.
func (s *MembershipService) managedByTenant(ctx context.Context, projectID, tenantID, targetUserID string) (bool, error) {
	user, err := s.users.GetUserInProject(ctx, projectID, targetUserID)
	if err != nil {
		return false, err
	}
	if user == nil || user.ManagedByTenantID == "" || user.ManagedByTenantID != tenantID {
		return false, nil
	}
	if s.managed == nil {
		return false, fmt.Errorf("%w: managed accounts are not served by this store", ErrServiceUnavailable)
	}
	return true, nil
}

// forgetSessions drops sids from the session cache.
func (s *MembershipService) forgetSessions(sids []string) {
	if s.sessions == nil {
		return
	}
	for _, sid := range sids {
		s.sessions.Invalidate(sid)
	}
}

// removeManaged removes a managed account from the tenant that manages it:
// the account is deactivated, keeping its id and address, and signed out
// everywhere, and its agents are deactivated (ManagedMemberStore.RemoveManaged).
// Removing one with no membership is a no-op, as RemoveTenantMember's is.
func (s *MembershipService) removeManaged(ctx context.Context, callerID, projectID, tenantID, targetUserID, ip, userAgent string) error {
	change, err := s.managed.RemoveManaged(ctx, projectID, tenantID, targetUserID, callerID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	s.forgetSessions(change.RevokedSessionIDs)
	s.logManagedChange("managed_account_removed", projectID, change)
	s.auditManagedChange(ctx, audit.EventTenantMemberRemoved, callerID, change, ip, userAgent)
	return nil
}

// suspendManaged suspends a managed account's membership of the tenant that
// manages it and signs the account and its agents out everywhere, its agents
// deactivated (ManagedMemberStore.SuspendManaged).
func (s *MembershipService) suspendManaged(ctx context.Context, callerID, projectID, tenantID, targetUserID, ip, userAgent string) (*TenantMembership, error) {
	change, err := s.managed.SuspendManaged(ctx, projectID, tenantID, targetUserID, callerID)
	if err != nil {
		return nil, err
	}
	if change.Changed {
		s.forgetSessions(change.RevokedSessionIDs)
		s.logManagedChange("managed_account_suspended", projectID, change)
		s.auditManagedChange(ctx, audit.EventTenantMemberSuspended, callerID, change, ip, userAgent)
	}
	return change.Membership, nil
}

func (s *MembershipService) logManagedChange(event, projectID string, change *ManagedMemberChange) {
	s.logger.Info(event,
		zap.String("project_id", projectID), zap.String("tenant_id", change.Membership.TenantID),
		zap.String("user_id", change.Membership.UserID),
		zap.Int("sessions_ended", len(change.RevokedSessionIDs)),
		zap.Int("agents_deactivated", len(change.DeactivatedAgentIDs)))
}

// auditManagedChange records an owner or admin's change to a managed member
// as auditMemberChange does, with what it ended: the sessions and the agents.
func (s *MembershipService) auditManagedChange(ctx context.Context, event audit.EventType, callerID string, change *ManagedMemberChange, ip, userAgent string) {
	if s.audit == nil {
		return
	}
	details := memberChangeDetails(change.Membership)
	details["managed"] = true
	details["sessions_ended"] = len(change.RevokedSessionIDs)
	details["agents_deactivated"] = change.DeactivatedAgentIDs
	s.audit.Log(ctx, event,
		audit.WithActor(callerID), audit.WithTarget(change.Membership.UserID),
		audit.WithIP(ip), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true), audit.WithDetails(details),
	)
}

// ManagedAccountReset is what ResetManagedAccount did: the account's new
// set-up link and what became of the one attempt to mail it.
type ManagedAccountReset struct {
	Invitation  *TenantInvitation
	EmailStatus EmailSendStatus
}

// ResetManagedAccount takes back userID, an account tenantID manages, for its
// owners and admins when they can no longer trust it: in one store
// transaction (ManagedMemberStore.ResetManaged) the account is signed out
// everywhere, its outstanding links and codes are spent, its password,
// passkeys, provider links, recovery emails, two-step methods, backup codes
// and phone are cleared, its agents are deactivated, it becomes
// StatusInvited with its membership unchanged, and a new set-up link with the
// member's role is written for deliveryAddress. After the commit the ended
// sessions are dropped from the session cache, every address the account had
// is told, and the link is mailed to deliveryAddress.
//
// The server must enable managed accounts and the project admit them for the
// tenant (ErrManagedAccountsNotAdmitted), and the server must deliver mail
// (ErrManagedSetupNeedsMailer). callerID must be an active owner or admin of
// a tenant that may be governed, asking from a session no recovery hold binds,
// signed in within GATEWAY_ACCOUNT_MERGE_REAUTH_MAX_AGE_SECONDS
// (ErrManagedResetReauthenticationRequired); only an owner resets an owner,
// an admin may reset another admin, which the tenant's active owners are told
// of by email, and naming oneself is ErrInvalidArgument. An account the tenant does not
// manage, or one with no active or suspended membership there, is
// ErrNotFound. Resets are exempt from the resend cooldown and the
// per-recipient cap but count toward the tenant's and the caller's
// invitation caps, and the links sent to one canonical delivery address are
// capped (ErrManagedResetLimited) by GATEWAY_TENANT_INVITATION_MAX_PER_RECIPIENT
// across the project in the invitation window. Each call logs one line,
// managed_account_reset or managed_account_reset_refused with the reason, and
// a reset is audited as EventManagedAccountReset.
func (s *MembershipService) ResetManagedAccount(ctx context.Context, callerID string, signIn SessionSignIn, tenantID, userID, deliveryAddress, ip, userAgent string) (*ManagedAccountReset, error) {
	tenantID, userID = strings.TrimSpace(tenantID), strings.TrimSpace(userID)
	projectID, err := s.requireProject(ctx)
	fields := []zap.Field{
		zap.String("project_id", projectID), zap.String("tenant_id", tenantID),
		zap.String("user_id", userID), zap.String("caller_id", callerID),
	}
	refuse := func(reason string, err error) (*ManagedAccountReset, error) {
		s.logger.Info("managed_account_reset_refused", append(fields, zap.String("reason", reason), zap.Error(err))...)
		return nil, err
	}
	if err != nil {
		return refuse("no_project", err)
	}
	if callerID == "" {
		return refuse("unauthenticated", ErrUnauthenticated)
	}
	if s.managed == nil {
		return refuse("unimplemented", ErrUnimplemented)
	}
	if err := s.refuseHeldSession(ctx, projectID, callerID, signIn); err != nil {
		return refuse("held_session", err)
	}
	if !signedInWithin(s.nowFunc(), signIn.AuthTimeSec, s.config().AccountMergeReauthMaxAge()) {
		return refuse("reauthentication_required", ErrManagedResetReauthenticationRequired)
	}
	if tenantID == "" || userID == "" {
		return refuse("invalid_argument", fmt.Errorf("%w: tenant_id and user_id are required", ErrInvalidArgument))
	}
	if userID == callerID {
		return refuse("own_account", fmt.Errorf("%w: you cannot reset your own account", ErrInvalidArgument))
	}
	delivery, usable := emailaddr.Mailbox(deliveryAddress)
	if delivery == "" || !usable {
		s.logger.Info("managed_account_reset_refused", append(fields, zap.String("reason", "invalid_argument"),
			zap.String("to", redactEmail(deliveryAddress)))...)
		return nil, fmt.Errorf("%w: delivery_address is not a usable address", ErrInvalidArgument)
	}
	callerMembership, err := s.requireTenantAdmin(ctx, projectID, tenantID, callerID, signIn)
	if err != nil {
		return refuse("not_permitted", err)
	}
	if err := requireManagedAccountsAdmitted(ctx, s.config(), s.tenants, ProjectScopeFromContext(ctx), tenantID); err != nil {
		return refuse("policy", err)
	}
	if !s.mailerDelivers {
		return refuse("no_mailer", ErrManagedSetupNeedsMailer)
	}
	if err := requireProjectEmailDelivery(ctx, projectID, s.projects); err != nil {
		return refuse("email_delivery", err)
	}

	rawToken := randomToken(invitationTokenBytes)
	now := s.nowFunc()
	limits := s.invitationLimits(now)
	done, err := s.managed.ResetManaged(ctx, ManagedReset{
		ProjectID: projectID, TenantID: tenantID, UserID: userID, By: callerID,
		DeliveryEmail: delivery, TokenHash: sha256Hex(rawToken),
		ExpiresAtMs: now.Add(s.invitationTTL()).UnixMilli(), NowMs: now.UnixMilli(),
		Limits:              limits,
		MaxPerDeliveryEmail: limits.MaxPerRecipient,
	})
	switch {
	case errors.Is(err, ErrNotFound):
		return refuse("not_found", err)
	case errors.Is(err, ErrPermissionDenied):
		return refuse("not_permitted", err)
	case errors.Is(err, ErrManagedResetLimited) || isInvitationLimit(err):
		return refuse("limited", err)
	case err != nil:
		return refuse("store_error", err)
	}
	s.forgetSessions(done.RevokedSessionIDs)
	s.logger.Info("managed_account_reset", append(fields,
		zap.String("to", redactEmail(delivery)),
		zap.Int("sessions_ended", len(done.RevokedSessionIDs)),
		zap.Int("agents_deactivated", len(done.DeactivatedAgentIDs)))...)
	notifyOwners := callerMembership.Role == RoleAdmin && done.Invitation.Role == RoleAdmin
	if s.audit != nil {
		s.audit.Log(ctx, audit.EventManagedAccountReset,
			audit.WithActor(callerID), audit.WithTarget(userID),
			audit.WithIP(ip), audit.WithUserAgent(userAgent),
			audit.WithSuccess(true), audit.WithDetails(map[string]any{
				"project_id":         projectID,
				"tenant_id":          tenantID,
				"role":               done.Invitation.Role,
				"delivery_email":     redactEmail(delivery),
				"sessions_ended":     len(done.RevokedSessionIDs),
				"agents_deactivated": done.DeactivatedAgentIDs,
				"review":             managedResetReviewNote,
				"owners_notice_due":  notifyOwners,
			}),
		)
	}
	s.dispatchNotice(ctx, "managed_account_reset_notice", func(ctx context.Context) {
		s.sendResetNotices(ctx, done)
	})
	if notifyOwners {
		s.dispatchNotice(ctx, "managed_account_reset_owner_notice", func(ctx context.Context) {
			s.tellOwnersOfAdminReset(ctx, projectID, tenantID, callerID, done.User, ip, userAgent)
		})
	}
	out := &ManagedAccountReset{Invitation: done.Invitation, EmailStatus: EmailSent}
	if err := s.sendManagedSetupEmail(ctx, &ManagedSetupIssued{User: done.User, Invitation: done.Invitation}, rawToken); err != nil {
		out.EmailStatus = EmailSendFailed
	}
	return out, nil
}

// managedAccountGreeting is how an email to account, which tenant t
// manages, greets it, and the tenant name it may show: the name the
// tenant's admin typed only for a tenant an operator created (CreatedBy
// empty), whose names are vetted; for a self-service tenant, or one that
// could not be read (t nil), the address's local part and no tenant name.
func managedAccountGreeting(t *Tenant, account *User) (greeting, tenantName string) {
	if t != nil && t.CreatedBy == "" {
		return account.Name, tenantNameOf(t)
	}
	return invitationGreeting(account.Email), ""
}

// sendResetNotices tells every address the account had before its reset
// that the tenant took it back, greeting it as the set-up email does
// (managedAccountGreeting). Best-effort: a notice that cannot be rendered
// or sent is logged, and the reset stands.
func (s *MembershipService) sendResetNotices(ctx context.Context, done *ManagedResetDone) {
	const headline = "Your account was reset by your organization"
	detail := "An administrator of the organization that manages your account reset it: it was signed out everywhere, and its password, passkeys, two-step methods, recovery emails and phone were removed. The organization has sent a new set-up link."
	advice := "If you did not expect this, contact your organization's administrator."
	t, err := s.tenants.GetTenant(ctx, done.Invitation.ProjectID, done.Invitation.TenantID)
	if err != nil {
		s.logger.Warn("managed_account_reset_notice_tenant_lookup_failed",
			zap.String("user_id", done.User.ID), zap.String("tenant_id", done.Invitation.TenantID), zap.Error(err))
		t = nil
	}
	greeting, _ := managedAccountGreeting(t, done.User)
	brand := resolveBranding(ctx, s.config(), "")
	for _, addr := range done.NoticeEmails {
		html, text, err := renderAccountNotice(brand, greeting, accountNotice{headline: headline, detail: detail, advice: advice})
		if err == nil {
			msg := email.Message{To: addr, From: s.config().SMTPFrom, Subject: headline, HTML: html, Text: text}
			brand.applyTo(&msg)
			err = s.mailer.Send(ctx, msg)
		}
		if err != nil {
			s.logger.Warn("managed_account_reset_notice_failed",
				zap.String("user_id", done.User.ID), zap.String("to", redactEmail(addr)), zap.Error(err))
		}
	}
}

// activeOwners returns the accounts of tenantID's active owners that are
// active and have an address: one read of the memberships and one of the
// accounts.
func (s *MembershipService) activeOwners(ctx context.Context, projectID, tenantID string) ([]*User, error) {
	if s.accounts == nil {
		return nil, fmt.Errorf("%w: the tenant's owners cannot be read", ErrServiceUnavailable)
	}
	members, err := s.memberships.ListMembershipsForTenant(ctx, projectID, tenantID)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, m := range members {
		if m.Role == RoleOwner && m.Status == MembershipStatusActive {
			ids = append(ids, m.UserID)
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	users, err := s.accounts.WithProject(projectID).GetUsersByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	var owners []*User
	for _, u := range users {
		if u != nil && u.Email != "" && isActiveStatus(u.Status) {
			owners = append(owners, u)
		}
	}
	return owners, nil
}

// tellOwnersOfAdminReset tells every active owner of tenantID that the
// admin callerID reset the sign-in of account, another admin: one admin
// taking back another's account is a change the owners must see. The admin
// is named by address only, never by a name an admin can edit. The owners
// told, those a notice reached, are audited as
// EventManagedAccountResetOwnersNotified. Best-effort: a notice that cannot
// be rendered or sent is logged, and the reset stands.
func (s *MembershipService) tellOwnersOfAdminReset(ctx context.Context, projectID, tenantID, callerID string, account *User, ip, userAgent string) {
	owners, err := s.activeOwners(ctx, projectID, tenantID)
	if err != nil {
		s.logger.Warn("managed_account_reset_owners_unread",
			zap.String("project_id", projectID), zap.String("tenant_id", tenantID), zap.Error(err))
		return
	}
	by := "An admin"
	if caller, err := s.users.GetUserInProject(ctx, projectID, callerID); err == nil && caller != nil && caller.Email != "" {
		by = caller.Email
	}
	notice := accountNotice{
		headline: "An admin reset another admin's sign-in",
		detail:   fmt.Sprintf("%s reset %s's sign-in. That admin's account was signed out everywhere and its sign-in methods were removed until it is set up again.", by, account.Email),
		advice:   "If you did not expect this, review your organization's admins and the members they manage.",
	}
	brand := resolveBranding(ctx, s.config(), "")
	sent := 0
	for _, owner := range owners {
		html, text, err := renderAccountNotice(brand, owner.Name, notice)
		if err == nil {
			msg := email.Message{To: owner.Email, From: s.config().SMTPFrom, Subject: notice.headline, HTML: html, Text: text}
			brand.applyTo(&msg)
			err = s.mailer.Send(ctx, msg)
		}
		if err != nil {
			s.logger.Warn("managed_account_reset_owner_notice_failed",
				zap.String("user_id", account.ID), zap.String("owner_id", owner.ID), zap.Error(err))
			continue
		}
		sent++
	}
	if s.audit != nil {
		s.audit.Log(ctx, audit.EventManagedAccountResetOwnersNotified,
			audit.WithActor(callerID), audit.WithTarget(account.ID),
			audit.WithIP(ip), audit.WithUserAgent(userAgent),
			audit.WithSuccess(sent == len(owners)), audit.WithDetails(map[string]any{
				"project_id":      projectID,
				"tenant_id":       tenantID,
				"owners":          len(owners),
				"owners_notified": sent,
			}),
		)
	}
}

// noticeDispatcher runs a notice's send off the request path
// (AuthService.dispatchEmailSend).
type noticeDispatcher interface {
	dispatchEmailSend(ctx context.Context, op string, send func(context.Context))
}

// WithNoticeDispatch sets what sends the reset's notices off the request
// path; without one they are sent inline.
func (s *MembershipService) WithNoticeDispatch(d noticeDispatcher) *MembershipService {
	s.notices = d
	return s
}

// dispatchNotice runs send through the notice dispatcher, or inline without
// one.
func (s *MembershipService) dispatchNotice(ctx context.Context, op string, send func(context.Context)) {
	if s.notices == nil {
		send(ctx)
		return
	}
	s.notices.dispatchEmailSend(ctx, op, send)
}
