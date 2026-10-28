package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/emailaddr"
)

// MembershipService implements the redesign's tenant-membership and
// invitation RPCs: a tenant owner/admin invites people by email, an invited
// person redeems a token to become a member, and admins list/manage
// invitations and members.
//
// Like DomainService it is project-scoped governance: every operation
// resolves the caller's Project from the request context and rejects when
// none is present. It is available only on the postgres control-plane driver;
// memory deployments construct no MembershipService and the handler
// returns Unimplemented.

// defaultInvitationTTL is the fallback validity window for an invitation when
// config.TenantInvitationExpirySeconds is unset (7 days). Joining a team is
// less time-sensitive than a password reset, so the window is generous.
const defaultInvitationTTL = 7 * 24 * time.Hour

// invitationTokenBytes is the entropy of the raw redemption token. 32 bytes
// (256 bits) matches the password-reset / email-verification tokens.
const invitationTokenBytes = 32

var (
	// ErrInvitationLimited is returned when the tenant has already sent the
	// configured number of invitations in the current window
	// (GATEWAY_TENANT_INVITATION_MAX_PER_TENANT per
	// GATEWAY_TENANT_INVITATION_WINDOW_SECONDS). Mapped to
	// CodeResourceExhausted.
	ErrInvitationLimited = errors.New("too many invitations sent from this tenant recently; try again later")
	// ErrInvitationResendTooSoon is returned when the tenant invited the same
	// address within GATEWAY_TENANT_INVITATION_RESEND_COOLDOWN_SECONDS.
	// Mapped to CodeResourceExhausted.
	ErrInvitationResendTooSoon = errors.New("this address was invited recently; try again later")
	// ErrInviterLimited is returned when the caller has already sent the
	// configured number of invitations, from all their tenants together, in
	// the current window (GATEWAY_TENANT_INVITATION_MAX_PER_INVITER). Mapped
	// to CodeResourceExhausted.
	ErrInviterLimited = errors.New("too many invitations sent by you recently; try again later")
	// ErrInvitationRecipientLimited is returned when the tenant has already
	// sent the address the configured number of invitations in the current
	// window (GATEWAY_TENANT_INVITATION_MAX_PER_RECIPIENT). Mapped to
	// CodeResourceExhausted.
	ErrInvitationRecipientLimited = errors.New("this address has been invited too often recently; try again later")
	// ErrMemberSuspended refuses a person whose membership of the tenant an
	// owner or admin suspended (SuspendTenantMember) the ways back in that
	// would lift it: accepting an invitation to the tenant and joining it
	// by domain. Only RestoreTenantMember, or an operator's grant, lifts a
	// suspension. Mapped to CodePermissionDenied.
	ErrMemberSuspended = errors.New("your membership of this tenant is suspended; an owner or admin must restore it")
)

// UserDirectory is the narrow user-lookup boundary MembershipService needs:
// resolving the caller (to match an accepting caller's email against the
// invitation, and to judge who may create a tenant). Accounts are partitioned
// by project, so every lookup names the request's project: a caller signed
// in to one project is found there, never in the deployment's default.
// RepositoryUserDirectory adapts a Repository; injecting only this method
// keeps the service decoupled from the full repository surface and trivially
// fakeable.
type UserDirectory interface {
	GetUserInProject(ctx context.Context, projectID, userID string) (*User, error)
}

// RepositoryUserDirectory is the UserDirectory over repo, rebinding it to the
// named project on every lookup, as scopedRepository does for the request's
// project.
func RepositoryUserDirectory(repo Repository) UserDirectory {
	return repositoryUserDirectory{repo: repo}
}

type repositoryUserDirectory struct{ repo Repository }

func (d repositoryUserDirectory) GetUserInProject(ctx context.Context, projectID, userID string) (*User, error) {
	return d.repo.WithProject(projectID).GetUser(ctx, userID)
}

// MembershipService manages tenant invitations and memberships within a
// project.
type MembershipService struct {
	invitations InvitationStore
	memberships MembershipStore
	tenants     TenantStore
	users       UserDirectory
	// domains finds the tenant a caller's verified email domain lets them
	// join (WithDomains); nil leaves ListJoinableTenants and
	// JoinTenantByDomain unimplemented.
	domains DomainStore
	mailer  email.Transport
	// mailerConfigured reports whether a real outbound mail provider is wired
	// (not just the log-only fallback). When false, CreateTenantInvitation
	// returns the raw token in its response so a headless/dev deployment can
	// still complete the flow; when true the token travels only in the email.
	mailerConfigured bool
	cfg              *config.Config
	logger           *zap.Logger
	// audit records CreateTenant outcomes, ownership transfers and joins by
	// domain (WithAudit); nil records nothing.
	audit   *audit.Logger
	nowFunc func() time.Time
}

// NewMembershipService wires a MembershipService. mailer must be non-nil (the
// app builds a log-only transport when no provider is configured);
// mailerConfigured tells the service whether that transport actually
// delivers, which governs whether the raw token is returned in the RPC
// response. A nil logger defaults to a no-op.
func NewMembershipService(
	invitations InvitationStore,
	memberships MembershipStore,
	tenants TenantStore,
	users UserDirectory,
	mailer email.Transport,
	mailerConfigured bool,
	cfg *config.Config,
	logger *zap.Logger,
) *MembershipService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &MembershipService{
		invitations:      invitations,
		memberships:      memberships,
		tenants:          tenants,
		users:            users,
		mailer:           mailer,
		mailerConfigured: mailerConfigured,
		cfg:              cfg,
		logger:           logger,
		nowFunc:          time.Now,
	}
}

// CreatedInvitation is the result of CreateTenantInvitation: the stored
// invitation plus, ONLY when no mailer is configured, the raw token (so a
// headless deployment can hand it to the recipient out-of-band). When a
// mailer delivered the invitation, RawToken is empty.
type CreatedInvitation struct {
	Invitation *TenantInvitation
	RawToken   string
}

// CreateTenantInvitation invites an email address to join a tenant. callerID
// must be an active owner/admin member of the tenant. It generates a random
// token, stores its hash via InvitationStore.CreateInvitation (which
// atomically revokes any prior open invite for the same recipient), and
// best-effort dispatches a branded invitation email carrying the raw token.
//
// Every invitation sends an email, so the store refuses one past the limits
// (see invitationLimits): ErrInvitationLimited past the per-tenant cap,
// ErrInviterLimited past the caller's cap across all their tenants,
// ErrInvitationRecipientLimited past the tenant's cap for the address,
// and ErrInvitationResendTooSoon inside the per-recipient cooldown. Each
// refusal is logged.
func (s *MembershipService) CreateTenantInvitation(ctx context.Context, callerID, tenantID, emailAddr, role string) (*CreatedInvitation, error) {
	projectID, err := s.requireProject(ctx)
	if err != nil {
		return nil, err
	}
	if callerID == "" {
		return nil, ErrUnauthenticated
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("%w: missing tenant_id", ErrInvalidArgument)
	}
	normEmail, err := normalizeInvitationEmail(emailAddr)
	if err != nil {
		return nil, err
	}
	role, err = normalizeInvitationRole(role)
	if err != nil {
		return nil, err
	}

	if _, err := s.requireTenantAdmin(ctx, projectID, tenantID, callerID); err != nil {
		return nil, err
	}

	rawToken := randomToken(invitationTokenBytes)
	now := s.nowFunc()
	expiresAtMs := now.Add(s.invitationTTL()).UnixMilli()

	inv := &TenantInvitation{
		ProjectID:   projectID,
		TenantID:    tenantID,
		TokenHash:   sha256Hex(rawToken),
		Email:       normEmail,
		InvitedBy:   callerID,
		Role:        role,
		ExpiresAtMs: expiresAtMs,
		CreatedAtMs: now.UnixMilli(),
	}
	id, err := s.invitations.CreateInvitation(ctx, inv, s.invitationLimits(now))
	if err != nil {
		if isInvitationLimit(err) {
			// Refusals are what an operator watches for abuse, so each is
			// recorded; the recipient only redacted.
			s.logger.Info("tenant_invitation_limited",
				zap.String("project_id", projectID), zap.String("tenant_id", tenantID),
				zap.String("inviter_id", callerID), zap.String("to", redactEmail(normEmail)),
				zap.Error(err))
		}
		return nil, err
	}
	inv.ID = id

	out := &CreatedInvitation{Invitation: inv}
	if s.mailerConfigured {
		// The token belongs in the recipient's inbox, not the API response.
		s.sendInvitationEmail(ctx, inv, rawToken)
	} else {
		// No delivery channel — surface the token so the caller can hand it
		// over out-of-band. Still best-effort log-send so it appears in logs.
		s.sendInvitationEmail(ctx, inv, rawToken)
		out.RawToken = rawToken
	}
	return out, nil
}

// AcceptTenantInvitation redeems a raw invitation token for the authenticated
// caller. It validates the token (must be pending and unexpired), enforces
// that the caller's account email equals the invitation email, then grants
// an active invited-source membership at the invitation's role and marks the
// invitation accepted. Accepting never lowers a role: a caller who already
// holds an active membership at that role or a higher one keeps it unchanged,
// so an invitation cannot demote an owner, the last one included.
//
// Email-match policy: a leaked token must not let the wrong account join. The
// caller is looked up and their email compared to the invitation email, both
// canonicalized as sign-in canonicalizes an address (emailaddr.Canonicalize); a
// mismatch is PermissionDenied, and an unverified email is
// ErrEmailVerificationRequired. A suspended tenant admits nobody
// (requireGovernableTenant), and a caller whose membership of the tenant is
// suspended is ErrMemberSuspended (MembershipStore.GrantMembership); the
// invitation stays pending through each. An
// expired invitation is marked expired and rejected; an
// unknown/revoked/already-accepted token is rejected without mutation.
func (s *MembershipService) AcceptTenantInvitation(ctx context.Context, callerID, rawToken string) (*TenantMembership, error) {
	projectID, err := s.requireProject(ctx)
	if err != nil {
		return nil, err
	}
	if callerID == "" {
		return nil, ErrUnauthenticated
	}
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, fmt.Errorf("%w: missing token", ErrInvalidArgument)
	}

	inv, err := s.invitations.GetInvitationByTokenHash(ctx, projectID, sha256Hex(rawToken))
	if err != nil {
		return nil, err
	}
	// Unknown token is NotFound — but we don't distinguish it from a wrong
	// project, so the redeemer learns nothing about other projects' tokens.
	if inv == nil {
		return nil, fmt.Errorf("%w: invitation", ErrNotFound)
	}

	if inv.Status != InvitationStatusPending {
		// Already accepted / revoked / expired: not redeemable. Don't leak
		// which — PermissionDenied for any non-pending state.
		return nil, fmt.Errorf("%w: invitation is not pending", ErrPermissionDenied)
	}
	if inv.ExpiresAtMs > 0 && inv.ExpiresAtMs < s.nowFunc().UnixMilli() {
		// Record the expiry so a later list/read reflects reality, then reject.
		if setErr := s.invitations.SetInvitationStatus(ctx, projectID, inv.ID, InvitationStatusExpired, 0); setErr != nil {
			s.logger.Warn("invitation_mark_expired_failed", zap.String("invitation_id", inv.ID), zap.Error(setErr))
		}
		return nil, fmt.Errorf("%w: invitation expired", ErrPermissionDenied)
	}

	// Email-match: the caller's account email must equal the invitation
	// email, so a leaked token cannot grant access to a different account.
	caller, err := s.users.GetUserInProject(ctx, projectID, callerID)
	if err != nil {
		return nil, err
	}
	if caller == nil {
		return nil, fmt.Errorf("%w: caller", ErrNotFound)
	}
	if !emailaddr.SameMailbox(caller.Email, inv.Email) {
		return nil, fmt.Errorf("%w: invitation was issued to a different email", ErrPermissionDenied)
	}
	// Holding the token proves nothing about the address: without a mailer
	// the inviter is handed it. The invitation stays pending meanwhile.
	if !caller.EmailVerified {
		return nil, fmt.Errorf("%w: verify your email before accepting an invitation", ErrEmailVerificationRequired)
	}
	if err := requireGovernableTenant(ctx, s.tenants, projectID, inv.TenantID); err != nil {
		return nil, err
	}

	m, _, err := s.memberships.GrantMembership(ctx, &TenantMembership{
		ProjectID: projectID,
		TenantID:  inv.TenantID,
		UserID:    callerID,
		Source:    MembershipSourceInvited,
		Role:      inv.Role,
		Status:    MembershipStatusActive,
	})
	if err != nil {
		return nil, err
	}
	if err := s.invitations.SetInvitationStatus(ctx, projectID, inv.ID, InvitationStatusAccepted, s.nowFunc().UnixMilli()); err != nil {
		return nil, err
	}
	return m, nil
}

// ListTenantInvitations returns every invitation in a tenant, newest first.
// callerID must be an active owner/admin member of the tenant.
func (s *MembershipService) ListTenantInvitations(ctx context.Context, callerID, tenantID string) ([]*TenantInvitation, error) {
	projectID, err := s.requireProject(ctx)
	if err != nil {
		return nil, err
	}
	if callerID == "" {
		return nil, ErrUnauthenticated
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("%w: missing tenant_id", ErrInvalidArgument)
	}
	if _, err := s.requireTenantAdmin(ctx, projectID, tenantID, callerID); err != nil {
		return nil, err
	}
	return s.invitations.ListInvitationsForTenant(ctx, projectID, tenantID)
}

// ListTenantMembers returns every membership in a tenant. callerID must be an
// active owner/admin member of the tenant.
func (s *MembershipService) ListTenantMembers(ctx context.Context, callerID, tenantID string) ([]*TenantMembership, error) {
	projectID, err := s.requireProject(ctx)
	if err != nil {
		return nil, err
	}
	if callerID == "" {
		return nil, ErrUnauthenticated
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("%w: missing tenant_id", ErrInvalidArgument)
	}
	if _, err := s.requireTenantAdmin(ctx, projectID, tenantID, callerID); err != nil {
		return nil, err
	}
	return s.memberships.ListMembershipsForTenant(ctx, projectID, tenantID)
}

// RemoveTenantMember removes a user's membership from a tenant. callerID must
// be an active owner/admin member of the tenant.
//
// The removal is recorded, so the user cannot join again through their
// email's domain (JoinTenantByDomain) until a membership from another
// source, such as an invitation they accept, lets them back in; an owner
// or admin removing themselves is recorded too. A removal is audited as
// EventTenantMemberRemoved; removing a membership that does not exist
// records nothing.
//
// A tenant is never left without an owner: removing its last active owner
// is ErrLastOwner (the caller may remove members, so ErrPermissionDenied
// would be wrong). Removing a non-owner, or an owner while another active
// owner remains, is allowed, including an owner removing themselves. The
// store checks and removes in one step (MembershipStore.RemoveMembership),
// so a concurrent removal or ownership transfer cannot slip between them.
func (s *MembershipService) RemoveTenantMember(ctx context.Context, callerID, tenantID, targetUserID, ip, userAgent string) error {
	projectID, tenantID, targetUserID, err := s.memberChangeRef(ctx, callerID, tenantID, targetUserID)
	if err != nil {
		return err
	}
	if _, err := s.requireTenantAdmin(ctx, projectID, tenantID, callerID); err != nil {
		return err
	}

	removed, err := s.memberships.RemoveMembership(ctx, projectID, tenantID, targetUserID)
	if err != nil || removed == nil {
		// Removing a membership that does not exist is a no-op.
		return err
	}
	s.auditMemberChange(ctx, audit.EventTenantMemberRemoved, callerID, removed, ip, userAgent)
	return nil
}

// SuspendTenantMember stops targetUserID acting in the tenant without
// removing them: their membership keeps its role and source at status
// MembershipStatusSuspended. Every read that lets a member act asks for an
// active membership, so while it is suspended they cannot select the tenant
// on a refresh, do not see it in ListMyTenants and cannot administer it; an
// access token already issued for the tenant is not revoked and lasts until
// it expires. Neither an invitation they accept nor joining by domain lifts
// it (ErrMemberSuspended), and the email leaving the domain does not end it
// (migration 0053). callerID must be an active owner or admin of a tenant
// that may be governed (authorizeTenantAdmin); an admin may suspend an
// owner, as an admin may remove one.
//
// Suspending oneself is ErrInvalidArgument: a caller who means to leave
// removes themselves. Suspending the tenant's last active owner is
// ErrLastOwner, decided where the write is (MembershipStore.SuspendMembership).
// A target that is not an active or suspended member is ErrNotFound.
// Suspending a suspended member returns the membership unchanged and records
// nothing; a suspension is audited as EventTenantMemberSuspended.
func (s *MembershipService) SuspendTenantMember(ctx context.Context, callerID, tenantID, targetUserID, ip, userAgent string) (*TenantMembership, error) {
	projectID, tenantID, targetUserID, err := s.memberChangeRef(ctx, callerID, tenantID, targetUserID)
	if err != nil {
		return nil, err
	}
	if _, err := s.requireTenantAdmin(ctx, projectID, tenantID, callerID); err != nil {
		return nil, err
	}
	if targetUserID == callerID {
		return nil, fmt.Errorf("%w: you cannot suspend yourself; remove yourself to leave the tenant", ErrInvalidArgument)
	}
	m, changed, err := s.memberships.SuspendMembership(ctx, projectID, tenantID, targetUserID)
	if err != nil {
		return nil, err
	}
	if changed {
		s.auditMemberChange(ctx, audit.EventTenantMemberSuspended, callerID, m, ip, userAgent)
	}
	return m, nil
}

// RestoreTenantMember lifts targetUserID's suspension in the tenant: the
// membership is active again with the role and source it had. A membership
// through the email's domain whose email is not on a domain the tenant has
// verified when it is restored ends instead (MembershipStatusInactive).
// callerID must be an active owner or admin of a tenant that may be
// governed, and still be one where the restore is written
// (MembershipStore.RestoreMembership), so one suspended while the call is in
// flight is ErrPermissionDenied and lifts nothing. Naming oneself is
// ErrInvalidArgument: a caller who may restore is not suspended. A target
// that is not an active or suspended member is ErrNotFound. Restoring an
// active member returns the membership unchanged and records nothing; a
// restore is audited as EventTenantMemberRestored, with the status it left.
func (s *MembershipService) RestoreTenantMember(ctx context.Context, callerID, tenantID, targetUserID, ip, userAgent string) (*TenantMembership, error) {
	projectID, tenantID, targetUserID, err := s.memberChangeRef(ctx, callerID, tenantID, targetUserID)
	if err != nil {
		return nil, err
	}
	if _, err := s.requireTenantAdmin(ctx, projectID, tenantID, callerID); err != nil {
		return nil, err
	}
	if targetUserID == callerID {
		return nil, fmt.Errorf("%w: you cannot restore yourself", ErrInvalidArgument)
	}
	m, changed, err := s.memberships.RestoreMembership(ctx, projectID, tenantID, targetUserID, callerID)
	if err != nil {
		return nil, err
	}
	if changed {
		s.auditMemberChange(ctx, audit.EventTenantMemberRestored, callerID, m, ip, userAgent)
	}
	return m, nil
}

// memberChangeRef checks an owner or admin's request to change a member:
// it needs the request's project, a caller, and a tenant and a member id,
// which it trims. It returns the project and the trimmed ids.
func (s *MembershipService) memberChangeRef(ctx context.Context, callerID, tenantID, targetUserID string) (projectID, tenant, target string, err error) {
	projectID, err = s.requireProject(ctx)
	if err != nil {
		return "", "", "", err
	}
	if callerID == "" {
		return "", "", "", ErrUnauthenticated
	}
	tenant, target = strings.TrimSpace(tenantID), strings.TrimSpace(targetUserID)
	if tenant == "" {
		return "", "", "", fmt.Errorf("%w: missing tenant_id", ErrInvalidArgument)
	}
	if target == "" {
		return "", "", "", fmt.Errorf("%w: missing user_id", ErrInvalidArgument)
	}
	return projectID, tenant, target, nil
}

// auditMemberChange records an owner or admin's change to member m: actor
// callerID, target the member, with memberChangeDetails of the membership
// the change left, or, for a removal, removed.
func (s *MembershipService) auditMemberChange(ctx context.Context, event audit.EventType, callerID string, m *TenantMembership, ip, userAgent string) {
	if s.audit == nil {
		return
	}
	s.audit.Log(ctx, event,
		audit.WithActor(callerID), audit.WithTarget(m.UserID),
		audit.WithIP(ip), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true), audit.WithDetails(memberChangeDetails(m)),
	)
}

// memberChangeDetails is what the audit trail keeps of a change to
// membership m: the project and tenant ids, and its role, source and status.
func memberChangeDetails(m *TenantMembership) map[string]any {
	return map[string]any{
		"project_id": m.ProjectID,
		"tenant_id":  m.TenantID,
		"role":       m.Role,
		"source":     m.Source,
		"status":     m.Status,
	}
}

// sendInvitationEmail renders and best-effort dispatches the branded tenant
// invitation email carrying the raw token. Failures are logged, never
// propagated — a mail outage must not fail the RPC (the invitation is already
// persisted).
func (s *MembershipService) sendInvitationEmail(ctx context.Context, inv *TenantInvitation, rawToken string) {
	if s.mailer == nil {
		return
	}
	link := tenantInvitationLink(ctx, s.cfg, rawToken)
	var brand resolvedBranding
	if s.cfg != nil {
		brand = resolveBranding(ctx, s.cfg, "")
	}
	html, text, err := email.Render(email.TemplateTenantInvitation, brand.templateData(map[string]any{
		"UserName":    invitationGreeting(inv.Email),
		"InviterName": "A tenant administrator",
		"TenantName":  s.tenantDisplayName(ctx, inv.ProjectID, inv.TenantID),
		"Role":        inv.Role,
		"ExpiresIn":   formatExpiresIn(s.invitationTTL()),
		"Link":        link,
	}))
	if err != nil {
		s.logger.Warn("tenant_invitation_render_failed", zap.String("to", redactEmail(inv.Email)), zap.Error(err))
		return
	}
	from := ""
	if s.cfg != nil {
		from = s.cfg.SMTPFrom
	}
	msg := email.Message{
		To:      inv.Email,
		From:    from,
		Subject: "You're invited to join a team",
		HTML:    html,
		Text:    text,
	}
	brand.applyTo(&msg)
	if err := s.mailer.Send(ctx, msg); err != nil {
		s.logger.Warn("tenant_invitation_send_failed", zap.String("to", redactEmail(inv.Email)), zap.Error(err))
	}
}

// tenantDisplayName is the tenant name an invitation email shows: the name
// of an operator-made or auto-formed tenant, else its primary domain, or ""
// (the email then invites to "a team"). A self-service tenant's name is
// whatever its creator typed, unvetted, so it never appears: otherwise
// anyone could create a tenant named after a company and have the service
// send its invitations. Lookup failures are non-fatal and yield "".
func (s *MembershipService) tenantDisplayName(ctx context.Context, projectID, tenantID string) string {
	t, err := s.tenants.GetTenant(ctx, projectID, tenantID)
	if err != nil || t == nil || t.CreatedBy != "" {
		return ""
	}
	if n := strings.TrimSpace(t.Name); n != "" {
		return n
	}
	return strings.TrimSpace(t.PrimaryDomain)
}

// invitationTTL returns the configured invitation validity window, defaulting
// to defaultInvitationTTL when unset.
func (s *MembershipService) invitationTTL() time.Duration {
	if s.cfg != nil && s.cfg.TenantInvitationExpirySeconds > 0 {
		return time.Duration(s.cfg.TenantInvitationExpirySeconds) * time.Second
	}
	return defaultInvitationTTL
}

// invitationLimits is the per-tenant, per-inviter and per-recipient caps and
// the per-recipient cooldown a create at now is held to, from the
// deployment's configuration (the defaults when none is wired).
func (s *MembershipService) invitationLimits(now time.Time) InvitationLimits {
	cfg := s.config()
	return InvitationLimits{
		MaxPerTenant:          cfg.TenantInvitationLimit(),
		WindowStartMs:         now.Add(-cfg.TenantInvitationWindow()).UnixMilli(),
		ResendCooldownStartMs: now.Add(-cfg.TenantInvitationResendCooldown()).UnixMilli(),
		MaxPerInviter:         cfg.TenantInvitationInviterLimit(),
		MaxPerRecipient:       cfg.TenantInvitationRecipientLimit(),
	}
}

// isInvitationLimit reports whether err is one of the refusals
// InvitationStore.CreateInvitation answers past a limit.
func isInvitationLimit(err error) bool {
	return errors.Is(err, ErrInvitationLimited) || errors.Is(err, ErrInvitationResendTooSoon) ||
		errors.Is(err, ErrInviterLimited) || errors.Is(err, ErrInvitationRecipientLimited)
}

// requireProject resolves the caller's project, rejecting when none is in the
// request context.
func (s *MembershipService) requireProject(ctx context.Context) (string, error) {
	if scope := ProjectScopeFromContext(ctx); scope != nil && scope.ProjectID != "" {
		return scope.ProjectID, nil
	}
	return "", fmt.Errorf("%w: no project in request scope", ErrPermissionDenied)
}

// requireTenantAdmin is authorizeTenantAdmin over this service's stores.
func (s *MembershipService) requireTenantAdmin(ctx context.Context, projectID, tenantID, callerID string) (*TenantMembership, error) {
	return authorizeTenantAdmin(ctx, s.memberships, s.tenants, projectID, tenantID, callerID)
}

// authorizeTenantAdmin is the rule every tenant-admin RPC of both the
// membership and the domain service applies: it returns the caller's
// membership when that is an active owner/admin one and the tenant may be
// governed (requireGovernableTenant), and refuses with ErrPermissionDenied
// otherwise. Only an admin learns that a tenant is suspended.
func authorizeTenantAdmin(ctx context.Context, memberships MembershipStore, tenants TenantStore, projectID, tenantID, callerID string) (*TenantMembership, error) {
	m, err := memberships.GetMembership(ctx, projectID, tenantID, callerID)
	if err != nil {
		return nil, err
	}
	if m == nil || m.Status != MembershipStatusActive || !isAdminRole(m.Role) {
		return nil, ErrPermissionDenied
	}
	if err := requireGovernableTenant(ctx, tenants, projectID, tenantID); err != nil {
		return nil, err
	}
	return m, nil
}

// requireGovernableTenant refuses, with ErrPermissionDenied, a tenant that is
// neither claimed nor latent. A suspended tenant is stopped: its admins may
// not invite, list or remove members, or register, list or verify domains,
// and no invitation to it may be accepted, until an operator sets it back.
func requireGovernableTenant(ctx context.Context, tenants TenantStore, projectID, tenantID string) error {
	status, err := tenants.GetTenantStatus(ctx, projectID, tenantID)
	if err != nil {
		return err
	}
	switch status {
	case TenantStatusClaimed, TenantStatusLatent:
		return nil
	case TenantStatusSuspended:
		return fmt.Errorf("%w: the tenant is suspended", ErrPermissionDenied)
	default:
		return ErrPermissionDenied
	}
}

// normalizeInvitationEmail canonicalizes an invitation email as sign-up
// canonicalizes an account's, rejecting a blank one or one that is not a
// usable mailbox (emailaddr.Mailbox). Full RFC validation lives upstream; this
// is the minimal sanity gate the store and email-match rely on.
func normalizeInvitationEmail(emailAddr string) (string, error) {
	e, usable := emailaddr.Mailbox(emailAddr)
	if e == "" {
		return "", fmt.Errorf("%w: missing email", ErrInvalidArgument)
	}
	if !usable {
		return "", fmt.Errorf("%w: invalid email %q", ErrInvalidArgument, emailAddr)
	}
	return e, nil
}

// normalizeInvitationRole defaults a blank role to member and rejects an
// unknown one. Only the three known roles may be granted via an invitation.
func normalizeInvitationRole(role string) (string, error) {
	switch r := strings.TrimSpace(strings.ToLower(role)); r {
	case "":
		return RoleMember, nil
	case RoleMember, RoleAdmin, RoleOwner:
		return r, nil
	default:
		return "", fmt.Errorf("%w: role %q (want %q, %q or %q)",
			ErrInvalidArgument, role, RoleMember, RoleAdmin, RoleOwner)
	}
}

// invitationGreeting derives a friendly greeting name from the recipient
// email's local-part, so the email has a sensible salutation without knowing
// the (possibly not-yet-existent) recipient's display name.
func invitationGreeting(emailAddr string) string {
	if i := strings.Index(emailAddr, "@"); i > 0 {
		return emailAddr[:i]
	}
	return "there"
}
