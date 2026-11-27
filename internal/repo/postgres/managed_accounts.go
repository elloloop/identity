package postgres

import (
	"context"
	"crypto/subtle"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/elloloop/identity/internal/service"
)

// Managed accounts (service.ManagedSetupStore, service.ManagedMemberStore).
// Each write is one transaction bound to its project (bindProject), since
// users, sessions, refresh tokens and the credential tables are under
// row-level security and these stores' pool is bound to the server's own
// project. Every one takes its locks in the order service documents: the
// membership's advisory lock, the account's users row (then its agents'
// rows), the domain row and then the tenants row FOR SHARE where read, the
// tenant's memberships in one ordered pass, then the tenant_invitations
// rows.

var (
	_ service.ManagedSetupStore  = (*InvitationStore)(nil)
	_ service.ManagedMemberStore = (*MembershipStore)(nil)
)

// bindProject binds tx's row-level security to projectID until tx ends, as
// migration 0046's functions bind themselves.
func bindProject(ctx context.Context, tx pgx.Tx, projectID string) error {
	_, err := tx.Exec(ctx, `SELECT set_config($1, $2, true)`, rlsGUC, projectID)
	return err
}

// refuseManagedElsewhere refuses, with service.ErrManagedElsewhere, a
// membership of userID in tenantID when the account is managed by another
// tenant; tenantID "" is a tenant being created, which manages no account.
// A managed account belongs to its tenant only. managed_by_tenant_id is fixed
// when the account is created, so the read needs no lock and runs on its own
// connection bound to projectID.
func refuseManagedElsewhere(ctx context.Context, pool *tracedPool, op, projectID, tenantID, userID string) error {
	managedBy, err := managingTenant(ctx, pool, op, projectID, userID)
	if err != nil {
		return err
	}
	if managedBy != "" && managedBy != tenantID {
		return service.ErrManagedElsewhere
	}
	return nil
}

// managingTenant returns the tenant that manages userID's account, "" for a
// personal account or none.
func managingTenant(ctx context.Context, pool *tracedPool, op, projectID, userID string) (string, error) {
	var managedBy string
	err := pool.forProject(projectID).QueryRow(ctx, `SELECT managed_by_tenant_id FROM users
		WHERE project_id = $1 AND id = $2`, projectID, userID).Scan(&managedBy)
	if noRows(err) {
		return "", nil
	}
	if err != nil {
		return "", wrapPgErr(op+"(managed)", err)
	}
	return managedBy, nil
}

// lockUserRow returns userID's account in projectID with its row held FOR
// UPDATE until tx ends, or nil when there is none. tx must be bound to
// projectID.
func lockUserRow(ctx context.Context, tx pgx.Tx, projectID, userID string) (*service.User, error) {
	u, err := scanUser(tx.QueryRow(ctx, `SELECT `+userColumns+`
		FROM users WHERE project_id = $1 AND id = $2
		FOR UPDATE`, projectID, userID))
	if noRows(err) {
		return nil, nil
	}
	return u, err
}

// lockAgentRows holds the rows of ownerID's agent accounts FOR UPDATE, in id
// order, and returns their ids.
func lockAgentRows(ctx context.Context, tx pgx.Tx, projectID, ownerID string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT id FROM users
		WHERE project_id = $1 AND owner_user_id <> '' AND owner_user_id = $2 AND kind = $3
		ORDER BY id
		FOR UPDATE`, projectID, ownerID, service.UserKindAgent)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// domainVerifiedFor reports whether domain is verified for tenantID, holding
// the domain's row FOR SHARE until tx ends so it cannot change before tx
// commits.
func domainVerifiedFor(ctx context.Context, tx pgx.Tx, projectID, tenantID, domain string) (bool, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT id FROM domains
		WHERE project_id = $1 AND tenant_id = $2 AND lower(domain) = lower($3) AND status = 'verified'
		LIMIT 1
		FOR SHARE`, projectID, tenantID, domain).Scan(&id)
	if noRows(err) {
		return false, nil
	}
	return err == nil, err
}

// addressDomain is the domain of a canonical address.
func addressDomain(address string) string {
	_, domain, _ := strings.Cut(address, "@")
	return domain
}

// signOutEverywhere revokes every active session of userIDs, deletes their
// refresh tokens and pending sign-in challenges, expires their approved QR
// hand-offs and spends their unredeemed OAuth one-time codes, so no sign-in
// already under way completes. Returns the revoked sessions' ids.
func signOutEverywhere(ctx context.Context, tx pgx.Tx, projectID string, userIDs []string, nowMs int64) ([]string, error) {
	rows, err := tx.Query(ctx, `UPDATE sessions SET revoked_at_ms = $3
		WHERE project_id = $1 AND user_id = ANY($2) AND revoked_at_ms = 0
		RETURNING sid`, projectID, userIDs, nowMs)
	if err != nil {
		return nil, err
	}
	sids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM refresh_tokens WHERE project_id = $1 AND user_id = ANY($2)`, projectID, userIDs); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE qr_login_sessions SET status = 'expired', updated_at_ms = $3
		WHERE project_id = $1 AND user_id = ANY($2) AND status = 'approved'`, projectID, userIDs, nowMs); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE oauth_one_time_codes SET consumed_at_ms = $3
		WHERE project_id = $1 AND user_id = ANY($2) AND consumed_at_ms = 0`, projectID, userIDs, nowMs); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM login_challenges WHERE project_id = $1 AND user_id = ANY($2)`, projectID, userIDs); err != nil {
		return nil, err
	}
	slices.Sort(sids)
	return sids, nil
}

// deactivateAgents deactivates the agent accounts agentIDs that are not
// deactivated yet and returns those it changed.
func deactivateAgents(ctx context.Context, tx pgx.Tx, projectID string, agentIDs []string, nowMs int64) ([]string, error) {
	if len(agentIDs) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `UPDATE users SET status = $3, deactivated_at_ms = $4, updated_at_ms = $4
		WHERE project_id = $1 AND id = ANY($2) AND status <> $3
		RETURNING id`, projectID, agentIDs, service.StatusDeactivated, nowMs)
	if err != nil {
		return nil, err
	}
	changed, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	slices.Sort(changed)
	return changed, nil
}

// revokePendingSetupLinks revokes every pending set-up link of userID.
func revokePendingSetupLinks(ctx context.Context, tx pgx.Tx, projectID, userID string) error {
	_, err := tx.Exec(ctx, `UPDATE tenant_invitations SET status = 'revoked'
		WHERE project_id = $1 AND user_id = $2 AND status = 'pending'`, projectID, userID)
	return err
}

// setupLink is a managed account's set-up link that issueSetupLink writes.
type setupLink struct {
	inv service.TenantInvitation
	// limits apply as CreateInvitation applies them; with
	// recipientLimits false the resend cooldown and the per-recipient cap do
	// not.
	limits          service.InvitationLimits
	recipientLimits bool
	// maxPerDeliveryEmail caps the links sent to inv.DeliveryEmail across the
	// project in the limits' window; zero applies no cap.
	maxPerDeliveryEmail int
}

// issueSetupLink inserts link as the account's only pending set-up link: it
// applies the limits, revokes every pending link of the account and any
// pending invitation to its address in the tenant, and inserts the new one.
// It runs last in a managed write, after the account's and the memberships'
// locks. Returns the invitation and where the newest link it revoked was
// sent, "" for none.
func issueSetupLink(ctx context.Context, tx pgx.Tx, op string, link setupLink) (*service.TenantInvitation, string, error) {
	inv := link.inv
	if link.limits.MaxPerTenant <= 0 {
		return nil, "", fmt.Errorf("%w: max_per_tenant must be positive", service.ErrInvalidArgument)
	}
	if err := lockInvitationWriters(ctx, tx, op, inv.ProjectID, inv.TenantID, inv.InvitedBy); err != nil {
		return nil, "", err
	}
	recipientKey := ""
	if link.recipientLimits {
		recipientKey = service.FoldEmail(inv.Email)
	}
	if err := checkInvitationLimits(ctx, tx, op, inv.ProjectID, inv.TenantID, inv.InvitedBy, recipientKey, link.limits); err != nil {
		return nil, "", err
	}
	if link.maxPerDeliveryEmail > 0 {
		var sent int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM tenant_invitations
			WHERE project_id = $1 AND user_id <> '' AND lower(delivery_email COLLATE "C") = $2 AND created_at_ms >= $3`,
			inv.ProjectID, service.FoldEmail(inv.DeliveryEmail), link.limits.WindowStartMs).Scan(&sent); err != nil {
			return nil, "", wrapPgErr(op+"(delivery count)", err)
		}
		if sent >= link.maxPerDeliveryEmail {
			return nil, "", service.ErrManagedResetLimited
		}
	}
	var previousDelivery string
	rows, err := tx.Query(ctx, `UPDATE tenant_invitations SET status = 'revoked'
		WHERE project_id = $1 AND status = 'pending'
		  AND (user_id = $2 OR (tenant_id = $3 AND lower(email COLLATE "C") = $4))
		RETURNING delivery_email, created_at_ms`,
		inv.ProjectID, inv.UserID, inv.TenantID, service.FoldEmail(inv.Email))
	if err != nil {
		return nil, "", wrapPgErr(op+"(revoke)", err)
	}
	var newest int64 = -1
	for rows.Next() {
		var delivery string
		var createdAt int64
		if err := rows.Scan(&delivery, &createdAt); err != nil {
			rows.Close()
			return nil, "", wrapPgErr(op+"(revoke)", err)
		}
		if createdAt > newest {
			newest, previousDelivery = createdAt, delivery
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, "", wrapPgErr(op+"(revoke)", err)
	}
	if inv.ID == "" {
		inv.ID = newID()
	}
	if inv.CreatedAtMs == 0 {
		inv.CreatedAtMs = nowMs()
	}
	issued, err := scanInvitation(tx.QueryRow(ctx, `
		INSERT INTO tenant_invitations (
			id, project_id, tenant_id, token_hash, email, invited_by, role,
			status, expires_at_ms, accepted_at_ms, created_at_ms, token_only_in_email,
			user_id, delivery_email, setup_epoch
		) VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8, 0, $9, $10, $11, $12, $13)
		RETURNING `+invitationColumns,
		inv.ID, inv.ProjectID, inv.TenantID, inv.TokenHash, inv.Email, inv.InvitedBy, inv.Role,
		inv.ExpiresAtMs, inv.CreatedAtMs, inv.TokenOnlyInEmail,
		inv.UserID, inv.DeliveryEmail, inv.SetupEpoch))
	if err != nil {
		return nil, "", wrapPgErr(op+"(insert)", err)
	}
	return issued, previousDelivery, nil
}

// governorOf returns by's membership among held when it is an active owner
// or admin one, else service.ErrPermissionDenied.
func governorOf(held map[string]*service.TenantMembership, by string) (*service.TenantMembership, error) {
	m := held[by]
	if by == "" || m == nil || m.Status != service.MembershipStatusActive || (m.Role != service.RoleOwner && m.Role != service.RoleAdmin) {
		return nil, fmt.Errorf("%w: only an active owner or admin of the tenant may do this", service.ErrPermissionDenied)
	}
	return m, nil
}

// ── ManagedSetupStore ───────────────────────────────────────────────────

// managedSetupRole checks setup's required fields and returns the role its
// link grants: setup.Role, member by default, and only member, admin or
// owner.
func managedSetupRole(setup service.ManagedSetup) (string, error) {
	if setup.ProjectID == "" || setup.TenantID == "" || setup.Address == "" || setup.Domain == "" ||
		setup.DeliveryEmail == "" || setup.InvitedBy == "" || setup.TokenHash == "" || setup.ExpiresAtMs == 0 {
		return "", fmt.Errorf("%w: project, tenant, address, domain, delivery email, inviter, token hash and expiry are required", service.ErrInvalidArgument)
	}
	if !strings.EqualFold(addressDomain(setup.Address), setup.Domain) {
		return "", fmt.Errorf("%w: the address is not on the domain", service.ErrInvalidArgument)
	}
	switch setup.Role {
	case "":
		return service.RoleMember, nil
	case service.RoleMember, service.RoleAdmin, service.RoleOwner:
		return setup.Role, nil
	}
	return "", fmt.Errorf("%w: role %q", service.ErrInvalidArgument, setup.Role)
}

// CreateManagedSetup implements service.ManagedSetupStore. The address's
// lock (addressLockKey), which every write of an account's email or a
// recovery email takes, comes before the users row, so no account or
// recovery email can take the address between the check and the insert.
func (s *InvitationStore) CreateManagedSetup(ctx context.Context, setup service.ManagedSetup) (*service.ManagedSetupIssued, error) {
	const op = "CreateManagedSetup"
	role, err := managedSetupRole(setup)
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, wrapPgErr(op, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := bindProject(ctx, tx, setup.ProjectID); err != nil {
		return nil, wrapPgErr(op+"(bind)", err)
	}
	if err := lockXact(ctx, tx, op, addressLockKey(setup.ProjectID, setup.Address)); err != nil {
		return nil, err
	}
	account, holderRefusal, err := lockAddressHolder(ctx, tx, setup)
	if err != nil {
		return nil, err
	}
	verified, err := domainVerifiedFor(ctx, tx, setup.ProjectID, setup.TenantID, setup.Domain)
	if err != nil {
		return nil, wrapPgErr(op+"(domain)", err)
	}
	if !verified {
		return nil, service.ErrManagedDomainUnverified
	}
	claimed, err := tenantClaimed(ctx, tx, setup.ProjectID, setup.TenantID)
	if err != nil {
		return nil, wrapPgErr(op+"(tenant)", err)
	}
	if !claimed {
		return nil, fmt.Errorf("%w: the tenant cannot take members", service.ErrPermissionDenied)
	}
	held, err := lockGovernorsAnd(ctx, tx, setup.ProjectID, setup.TenantID, setup.InvitedBy)
	if err != nil {
		return nil, wrapPgErr(op+"(lock)", err)
	}
	inviter, err := governorOf(held, setup.InvitedBy)
	if err != nil {
		return nil, err
	}
	if holderRefusal != nil {
		return nil, holderRefusal
	}
	now := nowMs()
	created := account == nil
	if created {
		if account, err = createManagedAccount(ctx, tx, setup, now); err != nil {
			return nil, err
		}
	}
	var replacesOwnerLink bool
	if !created {
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenant_invitations
			WHERE project_id = $1 AND user_id = $2 AND status = 'pending' AND role = 'owner')`,
			setup.ProjectID, account.ID).Scan(&replacesOwnerLink); err != nil {
			return nil, wrapPgErr(op+"(pending role)", err)
		}
	}
	if (role == service.RoleOwner || replacesOwnerLink) && inviter.Role != service.RoleOwner {
		return nil, fmt.Errorf("%w: only an owner may issue an owner's set-up link", service.ErrPermissionDenied)
	}
	if !created {
		if account, err = scanUser(tx.QueryRow(ctx, `UPDATE users SET setup_epoch = setup_epoch + 1, updated_at_ms = $3
			WHERE project_id = $1 AND id = $2
			RETURNING `+userColumns, setup.ProjectID, account.ID, now)); err != nil {
			return nil, wrapPgErr(op+"(epoch)", err)
		}
	}
	issued, previousDelivery, err := issueSetupLink(ctx, tx, op, setupLink{
		inv: service.TenantInvitation{
			ProjectID: setup.ProjectID, TenantID: setup.TenantID, TokenHash: setup.TokenHash,
			Email: setup.Address, InvitedBy: setup.InvitedBy, Role: role, ExpiresAtMs: setup.ExpiresAtMs,
			TokenOnlyInEmail: true, UserID: account.ID, DeliveryEmail: setup.DeliveryEmail,
			SetupEpoch: account.SetupEpoch,
		},
		limits:              setup.Limits,
		recipientLimits:     true,
		maxPerDeliveryEmail: setup.MaxPerDeliveryEmail,
	})
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, wrapPgErr(op+"(commit)", err)
	}
	return &service.ManagedSetupIssued{User: account, Invitation: issued, Created: created, PreviousDeliveryEmail: previousDelivery}, nil
}

// lockAddressHolder returns the managed account of setup.TenantID at
// setup.Address that may be sent a new link, its row held FOR UPDATE, or nil
// when nothing holds the address. Any other holder is a refusal, returned
// apart from err so the caller says it only once the domain and the inviter
// have passed, and nobody learns who holds an address they could not use:
// service.ErrManagedByThisTenant for one of the tenant's accounts past
// set-up, service.ErrManagedAddressUnavailable for anything outside it. It
// must run under the address's lock.
func lockAddressHolder(ctx context.Context, tx pgx.Tx, setup service.ManagedSetup) (account *service.User, refusal, err error) {
	const op = "CreateManagedSetup(holder)"
	fold := service.FoldEmail(setup.Address)
	account, err = scanUser(tx.QueryRow(ctx, `SELECT `+userColumns+`
		FROM users WHERE project_id = $1 AND email <> '' AND email_fold = $2
		FOR UPDATE`, setup.ProjectID, fold))
	switch {
	case noRows(err):
		var recovery bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_recovery_emails WHERE project_id = $1 AND email_fold = $2)`,
			setup.ProjectID, fold).Scan(&recovery); err != nil {
			return nil, nil, wrapPgErr(op, err)
		}
		if recovery {
			return nil, service.ErrManagedAddressUnavailable, nil
		}
		return nil, nil, nil
	case err != nil:
		return nil, nil, wrapPgErr(op, err)
	case account.ManagedByTenantID != setup.TenantID:
		return nil, service.ErrManagedAddressUnavailable, nil
	case account.Status != service.StatusInvited || account.SetUpAtMs != 0:
		return nil, service.ErrManagedByThisTenant, nil
	}
	return account, nil, nil
}

// createManagedAccount inserts setup's account: invited, never set up, at
// set-up epoch 1, managed by setup.TenantID.
func createManagedAccount(ctx context.Context, tx pgx.Tx, setup service.ManagedSetup, now int64) (*service.User, error) {
	account := &service.User{
		Email: setup.Address, Name: setup.DisplayName, Status: service.StatusInvited,
		Kind: service.UserKindPerson, ManagedByTenantID: setup.TenantID, SetupEpoch: 1,
		CreatedAt: time.UnixMilli(now),
	}
	id, role, status := defaultNewUserFields(account)
	if _, err := tx.Exec(ctx, insertUserQuery, insertUserArgs(setup.ProjectID, id, role, status, account)...); err != nil {
		return nil, wrapPgErr("CreateManagedSetup(create account)", err)
	}
	created, err := scanUser(tx.QueryRow(ctx, `UPDATE users SET invited_by = $3, invited_at_ms = $4
		WHERE project_id = $1 AND id = $2
		RETURNING `+userColumns, setup.ProjectID, id, setup.InvitedBy, now))
	if err != nil {
		return nil, wrapPgErr("CreateManagedSetup(create account)", err)
	}
	return created, nil
}

// managedSetupLink reads tenantID's invitation invitationID (any tenant when
// tenantID is ""), unlocked, to learn whose link it is: the locks are then
// taken in order and the link read again under its own. Returns nil for none
// or for an ordinary invitation.
func managedSetupLink(ctx context.Context, tx pgx.Tx, projectID, tenantID, invitationID string) (*service.TenantInvitation, error) {
	inv, err := scanInvitation(tx.QueryRow(ctx, `SELECT `+invitationColumns+`
		FROM tenant_invitations
		WHERE project_id = $1 AND id = $2 AND ($3 = '' OR tenant_id = $3)`, projectID, invitationID, tenantID))
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !inv.IsManagedSetup() {
		return nil, nil
	}
	return inv, nil
}

// lockInvitationRow re-reads invitation id FOR UPDATE.
func lockInvitationRow(ctx context.Context, tx pgx.Tx, projectID, id string) (*service.TenantInvitation, error) {
	return scanInvitation(tx.QueryRow(ctx, `SELECT `+invitationColumns+`
		FROM tenant_invitations WHERE project_id = $1 AND id = $2
		FOR UPDATE`, projectID, id))
}

// tenantClaimed reports whether tenantID is a claimed tenant of projectID,
// holding its row FOR SHARE so its status cannot change before tx ends.
func tenantClaimed(ctx context.Context, tx pgx.Tx, projectID, tenantID string) (bool, error) {
	var claimed bool
	err := tx.QueryRow(ctx, `SELECT status = $3 FROM tenants WHERE project_id = $1 AND id = $2 FOR SHARE`,
		projectID, tenantID, service.TenantStatusClaimed).Scan(&claimed)
	if noRows(err) {
		return false, nil
	}
	return claimed, err
}

// hasGovernorBesides reports whether tenantID has an active owner or admin
// other than userID. It must run after the membership pass, which holds those
// memberships, so it reads them as they stand.
func hasGovernorBesides(ctx context.Context, tx pgx.Tx, projectID, tenantID, userID string) (bool, error) {
	var governed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM tenant_memberships
			WHERE project_id = $1 AND tenant_id = $2 AND user_id <> $3
			  AND status = 'active' AND role IN ('owner', 'admin'))`, projectID, tenantID, userID).Scan(&governed)
	return governed, err
}

// issuerStillMayIssue refuses a set-up link whose issuer is no longer an
// active owner or admin of its tenant, as an ordinary invitation's open read
// refuses one, and an owner-role grant whose issuer is no longer an owner. A
// grant is the link's role only where the account holds no membership yet.
func issuerStillMayIssue(held map[string]*service.TenantMembership, link *service.TenantInvitation, accountID string) error {
	issuer, err := governorOf(held, link.InvitedBy)
	if err != nil {
		return fmt.Errorf("%w: the link's issuer may no longer invite", service.ErrPermissionDenied)
	}
	grantsLinkRole := held[accountID] == nil
	if grantsLinkRole && link.Role == service.RoleOwner && issuer.Role != service.RoleOwner {
		return fmt.Errorf("%w: the link's issuer is no longer an owner", service.ErrPermissionDenied)
	}
	return nil
}

// setUpState is what CompleteManagedSetup read under its locks, besides the
// link and the account.
type setUpState struct {
	now            int64
	domainVerified bool
	governed       bool
	removed        bool
}

// setUpRefusal says why link cannot set account up now, or nil.
func setUpRefusal(link *service.TenantInvitation, account *service.User, st setUpState) error {
	switch {
	case link.Status == service.InvitationStatusAccepted:
		return service.ErrInvitationUsed
	case link.Status == service.InvitationStatusExpired,
		link.Status == service.InvitationStatusPending && link.ExpiresAtMs != 0 && link.ExpiresAtMs < st.now:
		return service.ErrInvitationExpired
	case link.Status != service.InvitationStatusPending,
		account == nil,
		account.Status != service.StatusInvited,
		account.ManagedByTenantID != link.TenantID,
		account.SetupEpoch != link.SetupEpoch:
		return service.ErrManagedSetupStale
	case !st.domainVerified:
		return service.ErrManagedDomainUnverified
	case !st.governed:
		return fmt.Errorf("%w: the tenant cannot take members", service.ErrPermissionDenied)
	case st.removed:
		return service.ErrRemovedFromTenant
	}
	return nil
}

// keepOrGrantMembership leaves an active or suspended membership as it is,
// makes one that has ended active again with its own role, and grants an
// account with none the link's role.
func keepOrGrantMembership(ctx context.Context, tx pgx.Tx, op string, link *service.TenantInvitation, held *service.TenantMembership) (*service.TenantMembership, error) {
	if held != nil && (held.Status == service.MembershipStatusActive || held.Status == service.MembershipStatusSuspended) {
		return held, nil
	}
	role := link.Role
	if held != nil {
		role = held.Role
	}
	if err := clearRemoval(ctx, tx, op, link.ProjectID, link.TenantID, link.UserID, service.MembershipSourceInvited); err != nil {
		return nil, err
	}
	granted, _, err := grantIn(ctx, tx, op, link.ProjectID, link.TenantID, link.UserID, service.MembershipSourceInvited, role)
	return granted, err
}

// CompleteManagedSetup implements service.ManagedSetupStore.
func (s *InvitationStore) CompleteManagedSetup(ctx context.Context, c service.ManagedSetupCompletion) (*service.ManagedSetupCompleted, error) {
	const op = "CompleteManagedSetup"
	if c.ProjectID == "" || c.InvitationID == "" || c.TokenHash == "" || c.PasswordHash == "" {
		return nil, fmt.Errorf("%w: project, invitation, token hash and password hash are required", service.ErrInvalidArgument)
	}
	now := c.NowMs
	if now == 0 {
		now = nowMs()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, wrapPgErr(op, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := bindProject(ctx, tx, c.ProjectID); err != nil {
		return nil, wrapPgErr(op+"(bind)", err)
	}
	link, err := managedSetupLink(ctx, tx, c.ProjectID, "", c.InvitationID)
	if err != nil {
		return nil, wrapPgErr(op+"(read)", err)
	}
	if link == nil || subtle.ConstantTimeCompare([]byte(link.TokenHash), []byte(c.TokenHash)) != 1 {
		return nil, fmt.Errorf("%w: set-up link", service.ErrNotFound)
	}
	if err := lockMembership(ctx, tx, op, c.ProjectID, link.TenantID, link.UserID); err != nil {
		return nil, err
	}
	account, err := lockUserRow(ctx, tx, c.ProjectID, link.UserID)
	if err != nil {
		return nil, wrapPgErr(op+"(account)", err)
	}
	verified := false
	if account != nil {
		if verified, err = domainVerifiedFor(ctx, tx, c.ProjectID, link.TenantID, addressDomain(account.Email)); err != nil {
			return nil, wrapPgErr(op+"(domain)", err)
		}
	}
	claimed, err := tenantClaimed(ctx, tx, c.ProjectID, link.TenantID)
	if err != nil {
		return nil, wrapPgErr(op+"(tenant)", err)
	}
	held, err := lockGovernorsAnd(ctx, tx, c.ProjectID, link.TenantID, link.UserID, link.InvitedBy)
	if err != nil {
		return nil, wrapPgErr(op+"(lock)", err)
	}
	governed, err := hasGovernorBesides(ctx, tx, c.ProjectID, link.TenantID, link.UserID)
	if err != nil {
		return nil, wrapPgErr(op+"(governors)", err)
	}
	governed = governed && claimed
	removed, err := isRemoved(ctx, tx, c.ProjectID, link.TenantID, link.UserID)
	if err != nil {
		return nil, wrapPgErr(op+"(removal)", err)
	}
	if link, err = lockInvitationRow(ctx, tx, c.ProjectID, link.ID); err != nil {
		return nil, wrapPgErr(op+"(lock link)", err)
	}
	if err := setUpRefusal(link, account, setUpState{now: now, domainVerified: verified, governed: governed, removed: removed}); err != nil {
		return nil, err
	}
	if err := issuerStillMayIssue(held, link, account.ID); err != nil {
		return nil, err
	}
	firstSetUp := account.SetUpAtMs == 0
	if account, err = scanUser(tx.QueryRow(ctx, `UPDATE users SET
			password_hash = $3, password_change_required = FALSE, status = $4,
			email_verified = TRUE,
			email_verified_at_ms = CASE WHEN email_verified_at_ms = 0 THEN $5 ELSE email_verified_at_ms END,
			set_up_at_ms = CASE WHEN set_up_at_ms = 0 THEN $5 ELSE set_up_at_ms END,
			failed_login_count = 0, locked_until_ms = 0, updated_at_ms = $5
		WHERE project_id = $1 AND id = $2
		RETURNING `+userColumns, c.ProjectID, account.ID, c.PasswordHash, service.StatusActive, now)); err != nil {
		return nil, wrapPgErr(op+"(account)", err)
	}
	membership, err := keepOrGrantMembership(ctx, tx, op, link, held[account.ID])
	if err != nil {
		return nil, err
	}
	accepted, err := scanInvitation(tx.QueryRow(ctx, `UPDATE tenant_invitations SET status = 'accepted', accepted_at_ms = $3
		WHERE project_id = $1 AND id = $2 AND status = 'pending' AND setup_epoch = $4
		RETURNING `+invitationColumns, c.ProjectID, link.ID, now, link.SetupEpoch))
	if noRows(err) {
		return nil, service.ErrManagedSetupStale
	}
	if err != nil {
		return nil, wrapPgErr(op+"(accept)", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, wrapPgErr(op+"(commit)", err)
	}
	return &service.ManagedSetupCompleted{User: account, Membership: membership, Invitation: accepted, FirstSetUp: firstSetUp}, nil
}

// RevokeManagedSetup implements service.ManagedSetupStore.
func (s *InvitationStore) RevokeManagedSetup(ctx context.Context, projectID, tenantID, invitationID, by string) (*service.ManagedSetupRevoked, error) {
	const op = "RevokeManagedSetup"
	if projectID == "" || tenantID == "" || invitationID == "" || by == "" {
		return nil, fmt.Errorf("%w: project_id, tenant_id, invitation_id and by are required", service.ErrInvalidArgument)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, wrapPgErr(op, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := bindProject(ctx, tx, projectID); err != nil {
		return nil, wrapPgErr(op+"(bind)", err)
	}
	link, err := managedSetupLink(ctx, tx, projectID, tenantID, invitationID)
	if err != nil {
		return nil, wrapPgErr(op+"(read)", err)
	}
	if link == nil {
		return nil, fmt.Errorf("%w: set-up link", service.ErrNotFound)
	}
	if err := lockMembership(ctx, tx, op, projectID, tenantID, link.UserID); err != nil {
		return nil, err
	}
	account, err := lockUserRow(ctx, tx, projectID, link.UserID)
	if err != nil {
		return nil, wrapPgErr(op+"(account)", err)
	}
	held, err := lockGovernorsAnd(ctx, tx, projectID, tenantID, link.UserID, by)
	if err != nil {
		return nil, wrapPgErr(op+"(lock)", err)
	}
	if _, err := governorOf(held, by); err != nil {
		return nil, err
	}
	if link, err = lockInvitationRow(ctx, tx, projectID, link.ID); err != nil {
		return nil, wrapPgErr(op+"(lock link)", err)
	}
	out := &service.ManagedSetupRevoked{Invitation: link}
	switch link.Status {
	case service.InvitationStatusAccepted:
		return nil, fmt.Errorf("%w: remove the member instead", service.ErrInvitationUsed)
	case service.InvitationStatusPending:
		if out.Invitation, err = scanInvitation(tx.QueryRow(ctx, `UPDATE tenant_invitations SET status = 'revoked'
			WHERE project_id = $1 AND id = $2
			RETURNING `+invitationColumns, projectID, link.ID)); err != nil {
			return nil, wrapPgErr(op+"(revoke)", err)
		}
		out.Changed = true
	}
	if account != nil && account.ManagedByTenantID == tenantID && account.Status == service.StatusInvited && account.SetUpAtMs == 0 {
		if err := revokePendingSetupLinks(ctx, tx, projectID, account.ID); err != nil {
			return nil, wrapPgErr(op+"(revoke others)", err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM users WHERE project_id = $1 AND id = $2`, projectID, account.ID); err != nil {
			return nil, wrapPgErr(op+"(delete account)", err)
		}
		out.DeletedUser = account
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, wrapPgErr(op+"(commit)", err)
	}
	return out, nil
}

// ManagedAddressHolders implements service.ManagedSetupStore.
func (s *InvitationStore) ManagedAddressHolders(ctx context.Context, projectID, tenantID string, addresses []string) (map[string]string, error) {
	const op = "ManagedAddressHolders"
	if projectID == "" || tenantID == "" {
		return nil, fmt.Errorf("%w: project_id and tenant_id are required", service.ErrInvalidArgument)
	}
	out := make(map[string]string, len(addresses))
	byFold := make(map[string][]string, len(addresses))
	folds := make([]string, 0, len(addresses))
	for _, a := range addresses {
		out[a] = service.ManagedAddressFree
		f := service.FoldEmail(a)
		if _, seen := byFold[f]; !seen {
			folds = append(folds, f)
		}
		byFold[f] = append(byFold[f], a)
	}
	if len(folds) == 0 {
		return out, nil
	}
	pool := s.pool.forProject(projectID)
	domainRows, err := pool.Query(ctx, `SELECT lower(domain) FROM domains
		WHERE project_id = $1 AND tenant_id = $2 AND status = 'verified'`, projectID, tenantID)
	if err != nil {
		return nil, wrapPgErr(op+"(domains)", err)
	}
	verified, err := pgx.CollectRows(domainRows, pgx.RowTo[string])
	if err != nil {
		return nil, wrapPgErr(op+"(domains)", err)
	}
	folds = slices.DeleteFunc(folds, func(f string) bool {
		if slices.Contains(verified, strings.ToLower(addressDomain(f))) {
			return false
		}
		for _, a := range byFold[f] {
			out[a] = service.ManagedAddressDomainUnverified
		}
		return true
	})
	if len(folds) == 0 {
		return out, nil
	}
	rows, err := pool.Query(ctx, `
		SELECT email_fold, managed_by_tenant_id = $3 FROM users
		WHERE project_id = $1 AND email <> '' AND email_fold = ANY($2::text[])
		UNION ALL
		SELECT email_fold, FALSE FROM user_recovery_emails
		WHERE project_id = $1 AND email_fold = ANY($2::text[])`, projectID, folds, tenantID)
	if err != nil {
		return nil, wrapPgErr(op, err)
	}
	defer rows.Close()
	for rows.Next() {
		var fold string
		var managedHere bool
		if err := rows.Scan(&fold, &managedHere); err != nil {
			return nil, wrapPgErr(op+"(scan)", err)
		}
		holder := service.ManagedAddressHeldOutsideTheTenant
		if managedHere {
			holder = service.ManagedAddressManagedByThis
		}
		for _, a := range byFold[fold] {
			if out[a] != service.ManagedAddressHeldOutsideTheTenant {
				out[a] = holder
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr(op+"(rows)", err)
	}
	return out, nil
}

// ── ManagedMemberStore ──────────────────────────────────────────────────

// lockedManagedMember takes a managed write's locks on userID, an account
// tenantID manages, up to and including the membership pass: the
// membership's lock, the account's row, its agents' rows, then the tenant's
// governors with userID and by (lockGovernorsAnd). It refuses an account
// tenantID does not manage with service.ErrNotFound and a by who is not an
// active owner or admin with service.ErrPermissionDenied.
func lockedManagedMember(ctx context.Context, tx pgx.Tx, op, projectID, tenantID, userID, by string) (account *service.User, agents []string, held map[string]*service.TenantMembership, err error) {
	if err := bindProject(ctx, tx, projectID); err != nil {
		return nil, nil, nil, wrapPgErr(op+"(bind)", err)
	}
	if err := lockMembership(ctx, tx, op, projectID, tenantID, userID); err != nil {
		return nil, nil, nil, err
	}
	if account, err = lockUserRow(ctx, tx, projectID, userID); err != nil {
		return nil, nil, nil, wrapPgErr(op+"(account)", err)
	}
	if account == nil || account.ManagedByTenantID != tenantID {
		return nil, nil, nil, fmt.Errorf("%w: the account is not one the tenant manages", service.ErrNotFound)
	}
	if agents, err = lockAgentRows(ctx, tx, projectID, userID); err != nil {
		return nil, nil, nil, wrapPgErr(op+"(agents)", err)
	}
	if held, err = lockGovernorsAnd(ctx, tx, projectID, tenantID, userID, by); err != nil {
		return nil, nil, nil, wrapPgErr(op+"(lock)", err)
	}
	if _, err := governorOf(held, by); err != nil {
		return nil, nil, nil, err
	}
	return account, agents, held, nil
}

// signOutAccountAndAgents revokes the sessions and refresh tokens of the
// account and its agents and deactivates the agents.
func signOutAccountAndAgents(ctx context.Context, tx pgx.Tx, op, projectID, userID string, agents []string, now int64, change *service.ManagedMemberChange) error {
	sids, err := signOutEverywhere(ctx, tx, projectID, append([]string{userID}, agents...), now)
	if err != nil {
		return wrapPgErr(op+"(sign out)", err)
	}
	deactivated, err := deactivateAgents(ctx, tx, projectID, agents, now)
	if err != nil {
		return wrapPgErr(op+"(agents)", err)
	}
	change.RevokedSessionIDs, change.DeactivatedAgentIDs = sids, deactivated
	return nil
}

// SuspendManaged implements service.ManagedMemberStore.
func (s *MembershipStore) SuspendManaged(ctx context.Context, projectID, tenantID, userID, by string) (*service.ManagedMemberChange, error) {
	const op = "SuspendManaged"
	if projectID == "" || tenantID == "" || userID == "" || by == "" {
		return nil, fmt.Errorf("%w: project_id, tenant_id, user_id and by are required", service.ErrInvalidArgument)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, wrapPgErr(op, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, agents, held, err := lockedManagedMember(ctx, tx, op, projectID, tenantID, userID, by)
	if err != nil {
		return nil, err
	}
	target := held[userID]
	switch {
	case target == nil:
		return nil, fmt.Errorf("%w: the user is not a member of the tenant", service.ErrNotFound)
	case target.Status == service.MembershipStatusSuspended:
		return &service.ManagedMemberChange{Membership: target}, nil
	case target.Status != service.MembershipStatusActive:
		return nil, fmt.Errorf("%w: the user is not an active member of the tenant", service.ErrNotFound)
	}
	if err := keepAnOwner(ctx, tx, op, target, "suspend"); err != nil {
		return nil, err
	}
	now := nowMs()
	change := &service.ManagedMemberChange{Changed: true}
	if change.Membership, err = scanMembership(tx.QueryRow(ctx, `
		UPDATE tenant_memberships SET status = 'suspended', updated_at_ms = $4
		WHERE project_id = $1 AND tenant_id = $2 AND user_id = $3
		RETURNING `+membershipColumns, projectID, tenantID, userID, now)); err != nil {
		return nil, wrapPgErr(op, err)
	}
	if err := signOutAccountAndAgents(ctx, tx, op, projectID, userID, agents, now, change); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, wrapPgErr(op+"(commit)", err)
	}
	return change, nil
}

// RemoveManaged implements service.ManagedMemberStore.
func (s *MembershipStore) RemoveManaged(ctx context.Context, projectID, tenantID, userID, by string) (*service.ManagedMemberChange, error) {
	const op = "RemoveManaged"
	if projectID == "" || tenantID == "" || userID == "" || by == "" {
		return nil, fmt.Errorf("%w: project_id, tenant_id, user_id and by are required", service.ErrInvalidArgument)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, wrapPgErr(op, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, agents, held, err := lockedManagedMember(ctx, tx, op, projectID, tenantID, userID, by)
	if err != nil {
		return nil, err
	}
	target := held[userID]
	if target == nil {
		return nil, fmt.Errorf("%w: the user is not a member of the tenant", service.ErrNotFound)
	}
	if err := keepAnOwner(ctx, tx, op, target, "remove"); err != nil {
		return nil, err
	}
	now := nowMs()
	if _, err := tx.Exec(ctx, `DELETE FROM tenant_memberships
		WHERE project_id = $1 AND tenant_id = $2 AND user_id = $3`, projectID, tenantID, userID); err != nil {
		return nil, wrapPgErr(op, err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO tenant_member_removals (
			project_id, tenant_id, user_id, removed_at_ms
		) VALUES ($1, $2, $3, $4)
		ON CONFLICT (project_id, tenant_id, user_id) DO UPDATE SET
			removed_at_ms = EXCLUDED.removed_at_ms`, projectID, tenantID, userID, now); err != nil {
		return nil, wrapPgErr(op+"(record)", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET status = $3, deactivated_at_ms = $4, updated_at_ms = $4
		WHERE project_id = $1 AND id = $2`, projectID, userID, service.StatusDeactivated, now); err != nil {
		return nil, wrapPgErr(op+"(deactivate)", err)
	}
	change := &service.ManagedMemberChange{Membership: target, Changed: true}
	if err := signOutAccountAndAgents(ctx, tx, op, projectID, userID, agents, now, change); err != nil {
		return nil, err
	}
	if err := revokePendingSetupLinks(ctx, tx, projectID, userID); err != nil {
		return nil, wrapPgErr(op+"(links)", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, wrapPgErr(op+"(commit)", err)
	}
	return change, nil
}

// noticeEmails returns every address account has: its email and its
// recovery emails, each once.
func noticeEmails(ctx context.Context, tx pgx.Tx, projectID string, account *service.User) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT email FROM user_recovery_emails
		WHERE project_id = $1 AND user_id = $2 ORDER BY email`, projectID, account.ID)
	if err != nil {
		return nil, err
	}
	recovery, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, e := range append([]string{account.Email, account.RecoveryEmail}, recovery...) {
		f := service.FoldEmail(e)
		if e == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, e)
	}
	return out, nil
}

// clearCredentials consumes every outstanding sign-in, reset and
// verification link or code of the account (addressed by user or, for the
// email-keyed ones, by any of addresses) and deletes every credential
// attached to it: passkeys, provider links, recovery emails, TOTP, backup
// codes and its phone claim.
func clearCredentials(ctx context.Context, tx pgx.Tx, projectID, userID string, addresses []string, now int64) error {
	folds := make([]string, len(addresses))
	for i, a := range addresses {
		folds[i] = service.FoldEmail(a)
	}
	for _, table := range []string{"password_reset_tokens", "email_verification_tokens", "email_change_tokens", "recovery_email_codes", "phone_verification_codes"} {
		if _, err := tx.Exec(ctx, `UPDATE `+table+` SET consumed_at_ms = $3
			WHERE project_id = $1 AND user_id = $2 AND consumed_at_ms = 0`, projectID, userID, now); err != nil {
			return fmt.Errorf("%s: %w", table, err)
		}
	}
	for _, table := range []string{"magic_link_tokens", "email_login_codes"} {
		if _, err := tx.Exec(ctx, `UPDATE `+table+` SET consumed_at_ms = $3
			WHERE project_id = $1 AND lower(email COLLATE "C") = ANY($2::text[]) AND consumed_at_ms = 0`, projectID, folds, now); err != nil {
			return fmt.Errorf("%s: %w", table, err)
		}
	}
	for _, table := range []string{"passkeys", "oauth_identities", "user_recovery_emails", "totp_secrets", "recovery_codes", "phone_number_claims"} {
		if _, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE project_id = $1 AND user_id = $2`, projectID, userID); err != nil {
			return fmt.Errorf("%s: %w", table, err)
		}
	}
	return nil
}

// ResetManaged implements service.ManagedMemberStore.
func (s *MembershipStore) ResetManaged(ctx context.Context, reset service.ManagedReset) (*service.ManagedResetDone, error) {
	const op = "ResetManaged"
	if reset.ProjectID == "" || reset.TenantID == "" || reset.UserID == "" || reset.By == "" ||
		reset.DeliveryEmail == "" || reset.TokenHash == "" || reset.ExpiresAtMs == 0 {
		return nil, fmt.Errorf("%w: project, tenant, user, by, delivery email, token hash and expiry are required", service.ErrInvalidArgument)
	}
	if reset.By == reset.UserID {
		return nil, fmt.Errorf("%w: an owner or admin cannot reset their own account", service.ErrInvalidArgument)
	}
	now := reset.NowMs
	if now == 0 {
		now = nowMs()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, wrapPgErr(op, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	account, agents, held, err := lockedManagedMember(ctx, tx, op, reset.ProjectID, reset.TenantID, reset.UserID, reset.By)
	if err != nil {
		return nil, err
	}
	target := held[reset.UserID]
	if target == nil || account.Status == service.StatusDeactivated ||
		(target.Status != service.MembershipStatusActive && target.Status != service.MembershipStatusSuspended) {
		return nil, fmt.Errorf("%w: the account has no active or suspended membership of the tenant", service.ErrNotFound)
	}
	if target.Role == service.RoleOwner && held[reset.By].Role != service.RoleOwner {
		return nil, fmt.Errorf("%w: only an owner may reset an owner", service.ErrPermissionDenied)
	}
	var elsewhere bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenant_memberships
		WHERE project_id = $1 AND user_id = $2 AND tenant_id <> $3)`, reset.ProjectID, reset.UserID, reset.TenantID).Scan(&elsewhere); err != nil {
		return nil, wrapPgErr(op+"(elsewhere)", err)
	}
	if elsewhere {
		return nil, service.ErrManagedElsewhere
	}
	notices, err := noticeEmails(ctx, tx, reset.ProjectID, account)
	if err != nil {
		return nil, wrapPgErr(op+"(notices)", err)
	}
	change := &service.ManagedMemberChange{}
	if err := signOutAccountAndAgents(ctx, tx, op, reset.ProjectID, reset.UserID, agents, now, change); err != nil {
		return nil, err
	}
	if err := clearCredentials(ctx, tx, reset.ProjectID, reset.UserID, notices, now); err != nil {
		return nil, wrapPgErr(op+"(credentials)", err)
	}
	if account, err = scanUser(tx.QueryRow(ctx, `UPDATE users SET
			status = $3, password_hash = '', password_change_required = FALSE,
			totp_required = FALSE, recovery_email = '',
			phone_number = '', phone_verified = FALSE, phone_verified_at_ms = 0,
			failed_login_count = 0, locked_until_ms = 0,
			setup_epoch = setup_epoch + 1, updated_at_ms = $4
		WHERE project_id = $1 AND id = $2
		RETURNING `+userColumns, reset.ProjectID, reset.UserID, service.StatusInvited, now)); err != nil {
		return nil, wrapPgErr(op+"(account)", err)
	}
	issued, _, err := issueSetupLink(ctx, tx, op, setupLink{
		inv: service.TenantInvitation{
			ProjectID: reset.ProjectID, TenantID: reset.TenantID, TokenHash: reset.TokenHash,
			Email: account.Email, InvitedBy: reset.By, Role: target.Role, ExpiresAtMs: reset.ExpiresAtMs,
			TokenOnlyInEmail: true, UserID: account.ID, DeliveryEmail: reset.DeliveryEmail,
			SetupEpoch: account.SetupEpoch, CreatedAtMs: now,
		},
		limits:              reset.Limits,
		maxPerDeliveryEmail: reset.MaxPerDeliveryEmail,
	})
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, wrapPgErr(op+"(commit)", err)
	}
	return &service.ManagedResetDone{
		User: account, Invitation: issued, NoticeEmails: notices,
		RevokedSessionIDs: change.RevokedSessionIDs, DeactivatedAgentIDs: change.DeactivatedAgentIDs,
	}, nil
}
