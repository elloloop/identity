package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/email"
)

// MembershipService implements the redesign's tenant-membership and
// invitation RPCs: a tenant owner/admin invites people by email, an invited
// person redeems a token to become a member, and admins list/manage
// invitations and members.
//
// Like DomainService it is project-scoped governance: every operation
// resolves the caller's Project from the request context and rejects when
// none is present. It is available only on the postgres control-plane driver;
// entdb/memory deployments construct no MembershipService and the handler
// returns Unimplemented.

// defaultInvitationTTL is the fallback validity window for an invitation when
// config.TenantInvitationExpirySeconds is unset (7 days). Joining a team is
// less time-sensitive than a password reset, so the window is generous.
const defaultInvitationTTL = 7 * 24 * time.Hour

// invitationTokenBytes is the entropy of the raw redemption token. 32 bytes
// (256 bits) matches the password-reset / email-verification tokens.
const invitationTokenBytes = 32

// UserDirectory is the narrow user-lookup boundary MembershipService needs:
// resolving the accepting caller so its account email can be matched against
// the invitation. service.Repository satisfies it; injecting only this method
// keeps the service decoupled from the full repository surface and trivially
// fakeable. The redesign's governance plane is a single postgres control
// database, so the boot-time repository is the correct (and only) handle —
// there is no per-tenant repo sharding in redesign mode.
type UserDirectory interface {
	GetUser(ctx context.Context, userID string) (*User, error)
}

// MembershipService manages tenant invitations and memberships within a
// project.
type MembershipService struct {
	invitations InvitationStore
	memberships MembershipStore
	tenants     TenantStore
	users       UserDirectory
	mailer      email.Transport
	// mailerConfigured reports whether a real outbound mail provider is wired
	// (not just the log-only fallback). When false, CreateTenantInvitation
	// returns the raw token in its response so a headless/dev deployment can
	// still complete the flow; when true the token travels only in the email.
	mailerConfigured bool
	cfg              *config.Config
	logger           *zap.Logger
	nowFunc          func() time.Time
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
	id, err := s.invitations.CreateInvitation(ctx, inv)
	if err != nil {
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
// that the caller's account email equals the invitation email, then upserts
// an active invited-source membership at the invitation's role and marks the
// invitation accepted.
//
// Email-match policy: a leaked token must not let the wrong account join. The
// caller is looked up and their email compared (case-insensitively) to the
// invitation email; a mismatch is PermissionDenied. An expired invitation is
// marked expired and rejected; an unknown/revoked/already-accepted token is
// rejected without mutation.
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
	caller, err := s.users.GetUser(ctx, callerID)
	if err != nil {
		return nil, err
	}
	if caller == nil {
		return nil, fmt.Errorf("%w: caller", ErrNotFound)
	}
	if !strings.EqualFold(strings.TrimSpace(caller.Email), inv.Email) {
		return nil, fmt.Errorf("%w: invitation was issued to a different email", ErrPermissionDenied)
	}

	m := &TenantMembership{
		ProjectID: projectID,
		TenantID:  inv.TenantID,
		UserID:    callerID,
		Source:    MembershipSourceInvited,
		Role:      inv.Role,
		Status:    MembershipStatusActive,
	}
	if _, err := s.memberships.UpsertMembership(ctx, m); err != nil {
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
// Last-owner guard: a tenant must never be left ownerless. Removing the only
// remaining active owner is rejected with FailedPrecondition-style
// ErrInvalidArgument-adjacent semantics — here ErrPermissionDenied is wrong
// (the caller IS permitted to remove members), so we surface a dedicated
// guard error. The rule: if the target is an active owner and is the last
// active owner of the tenant, the removal is refused. Removing a non-owner,
// or an owner while other active owners remain, is allowed (including an
// owner removing themselves, as long as another owner survives).
func (s *MembershipService) RemoveTenantMember(ctx context.Context, callerID, tenantID, targetUserID string) error {
	projectID, err := s.requireProject(ctx)
	if err != nil {
		return err
	}
	if callerID == "" {
		return ErrUnauthenticated
	}
	tenantID = strings.TrimSpace(tenantID)
	targetUserID = strings.TrimSpace(targetUserID)
	if tenantID == "" {
		return fmt.Errorf("%w: missing tenant_id", ErrInvalidArgument)
	}
	if targetUserID == "" {
		return fmt.Errorf("%w: missing user_id", ErrInvalidArgument)
	}
	if _, err := s.requireTenantAdmin(ctx, projectID, tenantID, callerID); err != nil {
		return err
	}

	target, err := s.memberships.GetMembership(ctx, projectID, tenantID, targetUserID)
	if err != nil {
		return err
	}
	if target == nil {
		// Idempotent: nothing to remove.
		return nil
	}

	if err := s.guardLastOwner(ctx, projectID, tenantID, target); err != nil {
		return err
	}
	return s.memberships.RemoveMembership(ctx, projectID, tenantID, targetUserID)
}

// guardLastOwner refuses to remove the last active owner of a tenant, which
// would strand it ownerless. It is a no-op when the target is not an active
// owner.
func (s *MembershipService) guardLastOwner(ctx context.Context, projectID, tenantID string, target *TenantMembership) error {
	if target.Role != RoleOwner || target.Status != MembershipStatusActive {
		return nil
	}
	members, err := s.memberships.ListMembershipsForTenant(ctx, projectID, tenantID)
	if err != nil {
		return err
	}
	otherOwners := 0
	for _, m := range members {
		if m.UserID == target.UserID {
			continue
		}
		if m.Role == RoleOwner && m.Status == MembershipStatusActive {
			otherOwners++
		}
	}
	if otherOwners == 0 {
		return fmt.Errorf("%w: cannot remove the last owner of a tenant", ErrLastOwner)
	}
	return nil
}

// sendInvitationEmail renders and best-effort dispatches the branded tenant
// invitation email carrying the raw token. Failures are logged, never
// propagated — a mail outage must not fail the RPC (the invitation is already
// persisted).
func (s *MembershipService) sendInvitationEmail(ctx context.Context, inv *TenantInvitation, rawToken string) {
	if s.mailer == nil {
		return
	}
	link := fmt.Sprintf("%s/auth/accept-invitation?token=%s", s.appBaseURL(ctx), rawToken)
	html, text, err := email.Render(email.TemplateTenantInvitation, map[string]any{
		"UserName":    invitationGreeting(inv.Email),
		"InviterName": "A tenant administrator",
		"TenantName":  s.tenantDisplayName(ctx, inv.ProjectID, inv.TenantID),
		"Role":        inv.Role,
		"ExpiresIn":   formatExpiresIn(s.invitationTTL()),
		"Link":        link,
	})
	if err != nil {
		s.logger.Warn("tenant_invitation_render_failed", zap.String("to", redactEmail(inv.Email)), zap.Error(err))
		return
	}
	from := ""
	if s.cfg != nil {
		from = s.cfg.SMTPFrom
	}
	if err := s.mailer.Send(ctx, email.Message{
		To:      inv.Email,
		From:    from,
		Subject: "You're invited to join a team",
		HTML:    html,
		Text:    text,
	}); err != nil {
		s.logger.Warn("tenant_invitation_send_failed", zap.String("to", redactEmail(inv.Email)), zap.Error(err))
	}
}

// tenantDisplayName resolves a human-friendly tenant name for the email,
// falling back to its primary domain or a generic label. Lookup failures are
// non-fatal — they just yield the generic label.
func (s *MembershipService) tenantDisplayName(ctx context.Context, projectID, tenantID string) string {
	const generic = "the team"
	t, err := s.tenants.GetTenant(ctx, projectID, tenantID)
	if err != nil || t == nil {
		return generic
	}
	if n := strings.TrimSpace(t.Name); n != "" {
		return n
	}
	if d := strings.TrimSpace(t.PrimaryDomain); d != "" {
		return d
	}
	return generic
}

// appBaseURL returns the public app base URL for the request's project, with
// any trailing slash trimmed, so callers can concatenate "/auth/foo". It
// mirrors AuthService.appBaseURL: a branded primary auth-domain when the
// request resolved to one, else the configured GATEWAY_APP_BASE_URL, else a
// localhost dev default.
func (s *MembershipService) appBaseURL(ctx context.Context) string {
	if scope := ProjectScopeFromContext(ctx); scope != nil && scope.PrimaryAuthDomain != "" {
		return "https://" + scope.PrimaryAuthDomain
	}
	if s.cfg != nil {
		if u := strings.TrimRight(s.cfg.AppBaseURL, "/"); u != "" {
			return u
		}
	}
	return "http://localhost:9002"
}

// invitationTTL returns the configured invitation validity window, defaulting
// to defaultInvitationTTL when unset.
func (s *MembershipService) invitationTTL() time.Duration {
	if s.cfg != nil && s.cfg.TenantInvitationExpirySeconds > 0 {
		return time.Duration(s.cfg.TenantInvitationExpirySeconds) * time.Second
	}
	return defaultInvitationTTL
}

// requireProject resolves the caller's project, rejecting when none is in the
// request context.
func (s *MembershipService) requireProject(ctx context.Context) (string, error) {
	if scope := ProjectScopeFromContext(ctx); scope != nil && scope.ProjectID != "" {
		return scope.ProjectID, nil
	}
	return "", fmt.Errorf("%w: no project in request scope", ErrPermissionDenied)
}

// requireTenantAdmin returns the caller's membership when it is an active
// owner/admin of the tenant, or ErrPermissionDenied otherwise. It mirrors
// DomainService.requireTenantAdmin (same isAdminRole rule).
func (s *MembershipService) requireTenantAdmin(ctx context.Context, projectID, tenantID, callerID string) (*TenantMembership, error) {
	m, err := s.memberships.GetMembership(ctx, projectID, tenantID, callerID)
	if err != nil {
		return nil, err
	}
	if m == nil || m.Status != MembershipStatusActive || !isAdminRole(m.Role) {
		return nil, ErrPermissionDenied
	}
	return m, nil
}

// normalizeInvitationEmail trims and lower-cases an invitation email,
// rejecting a blank one or one without an '@'. Full RFC validation lives
// upstream; this is the minimal sanity gate the store and email-match rely on.
func normalizeInvitationEmail(emailAddr string) (string, error) {
	e := strings.ToLower(strings.TrimSpace(emailAddr))
	if e == "" {
		return "", fmt.Errorf("%w: missing email", ErrInvalidArgument)
	}
	if i := strings.Index(e, "@"); i <= 0 || i == len(e)-1 {
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
