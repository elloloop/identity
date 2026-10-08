package service

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/events"
)

// AccountMerge is one merge for Repository.ApplyAccountMerge: which account
// survives, which is retired, and what moves. The flags are decided from the
// accounts as read before; the store moves the values it reads inside its
// transaction.
type AccountMerge struct {
	SurvivorID, OtherID string
	// MoveUsername, MovePassword and MoveEmail move the retired account's
	// username, password hash and email (with its verified flag) to the
	// survivor, which has none of its own.
	MoveUsername, MovePassword, MoveEmail bool
	// SwapAddress gives the survivor the retired account's account address
	// and the retired account the survivor's old one.
	SwapAddress bool
	AtMs        int64
}

// ErrMergeConflict is returned by ApplyAccountMerge when either account is no
// longer active and unmerged by the time the merge runs (a concurrent merge,
// deactivation or deletion won); nothing was written.
var ErrMergeConflict = errors.New("one of the accounts changed while merging; try again")

// ErrMergeRefused is returned when two accounts cannot be merged as they
// stand; the wrapped message says why and what to do first.
var ErrMergeRefused = errors.New("these accounts cannot be merged")

// errIDPManaged refuses a self-service merge involving an account an identity
// provider provisions (SCIM, ExternalID set): merging it away would move its
// sign-in out of the provider's control, past its deprovisioning. An admin
// can merge it (MergeUsers).
var errIDPManaged = fmt.Errorf("%w: an account your identity provider manages can only be merged by an admin", ErrMergeRefused)

// ErrAccountMergeDisabled is returned by MergeAccounts when the deployment has
// not turned self-service merging on (GATEWAY_ACCOUNT_MERGE_ENABLED).
var ErrAccountMergeDisabled = errors.New("merging accounts is not enabled on this server")

// ErrReauthenticationRequired is returned by MergeAccounts when the caller's
// session was not opened by a sign-in within
// GATEWAY_ACCOUNT_MERGE_REAUTH_MAX_AGE_SECONDS. It maps to
// CodeFailedPrecondition, and its message leads with the stable
// `reauthentication_required` token clients match on to sign the user in
// again (any method, with any second factor) and retry. The token is part of
// the wire contract — do not reword it.
var ErrReauthenticationRequired = errors.New("reauthentication_required: sign in again to merge accounts")

// Merging two accounts of one person.
//
// A merge never deletes anything. One account, the survivor, chosen by
// whoever asks (never by the server), carries on. The other is RETIRED:
// StatusDeactivated with MergedIntoUserID naming the survivor (which also
// keeps it from ever being reactivated), every session revoked, its row and
// everything stored under its id kept, and a user.merged event tells
// downstream applications to move what they hold under the retired id.
//
// Everything that lets the person sign in the way they used to moves to the
// survivor, in one transaction (Repository.ApplyAccountMerge): its linked
// provider identities always; its username, password and email
// where the survivor has none of its own; and, on request (takeAddress), its
// account address, the survivor's old address moving to the retired account
// so neither is freed for someone else. Passkeys do not move: a passkey is
// bound to the account it was registered for (its WebAuthn user handle), so
// it would not sign in to the survivor. The person registers passkeys again
// on the survivor.
//
// Refused: merging an account with itself; an account that is not active;
// an anonymous account (upgrade it instead); a managed child's account (it
// stays with its guardian), and an account that is any child's guardian
// (its children's guardian edges would point at a retired account).

// MergeAccounts merges the account identified by otherIdentifier (an email,
// or a username) into the caller's own account, survivorID. The proof that
// the caller controls the other account is the whole credential check of a
// password sign-in (verifyPasswordCredential: access gates, lockout, status,
// verified email, login policy), plus one more condition: an account that a
// second factor protects — enrolled two-step, or a policy requiring one —
// cannot be merged by its password alone. The deployment must have turned
// merging on (GATEWAY_ACCOUNT_MERGE_ENABLED).
func (s *AuthService) MergeAccounts(ctx context.Context, survivorID string, authTimeSec int64, otherIdentifier, otherPassword, ipAddr, userAgent string, takeAddress bool) (*User, error) {
	if !s.cfg.AccountMergeEnabled {
		return nil, ErrAccountMergeDisabled
	}
	if survivorID == "" {
		return nil, ErrUnauthenticated
	}
	// The account that is kept proves itself as freshly as the other one: a
	// session is not enough, a recent sign-in is. Before any password check,
	// so a stale session learns nothing about the other account.
	if !s.recentlyAuthenticated(authTimeSec) {
		return nil, ErrReauthenticationRequired
	}
	repo := s.repo(ctx)
	survivor, err := repo.GetUser(ctx, survivorID)
	if err != nil {
		return nil, err
	}
	if survivor == nil {
		return nil, ErrUnauthenticated
	}
	// The caller's own account is checked before any password is, so an
	// account that could never be a survivor gets no answer about the other
	// account's password.
	if err := checkSurvivor(ctx, repo, survivor); err != nil {
		return nil, err
	}
	if survivor.ExternalID != "" {
		return nil, errIDPManaged
	}
	other, decision, err := s.verifyPasswordCredential(ctx, otherIdentifier, otherPassword, ipAddr, userAgent)
	if err != nil {
		return nil, err
	}
	if other.ExternalID != "" {
		s.auditMerge(ctx, survivor.ID, other.ID, ipAddr, userAgent, false, "idp_managed")
		return nil, errIDPManaged
	}
	if other.TotpRequired || decision.RequireSecondFactor {
		s.auditMerge(ctx, survivor.ID, other.ID, ipAddr, userAgent, false, "second_factor_required")
		return nil, fmt.Errorf("%w: the other account requires a second factor; turn two-step verification off there first", ErrMergeRefused)
	}
	s.resetFailedLogin(ctx, other)
	merged, retired, err := mergeAccounts(ctx, repo, survivor, other, takeAddress, s.nowMs())
	if err != nil {
		s.auditMerge(ctx, survivor.ID, other.ID, ipAddr, userAgent, false, err.Error())
		return nil, err
	}
	s.auditMerge(ctx, survivor.ID, retired.ID, ipAddr, userAgent, true, "")
	notifyMerge(ctx, s.cfg, s.mailer, s.logger, other, merged)
	EmitUserEvent(ctx, s.publisher, s.logger, s.projectID(ctx), s.tenantID(ctx), events.EventUserMerged, retired)
	return merged, nil
}

func (s *AuthService) auditMerge(ctx context.Context, actorID, targetID, ipAddr, userAgent string, ok bool, reason string) {
	details := map[string]any{"survivor": actorID, "source": "self"}
	if reason != "" {
		details["reason"] = reason
	}
	s.audit.Log(ctx, audit.EventAccountMerged,
		audit.WithActor(actorID), audit.WithTarget(targetID),
		audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(ok), audit.WithDetails(details))
}

// MergeUsers is the admin form of MergeAccounts: an admin merges otherID into
// survivorID. The admin's role is the authority, so no password of either
// account is asked for, and it does not depend on the self-service switch.
func (s *AdminService) MergeUsers(ctx context.Context, actorID, survivorID, otherID string, takeAddress bool) (*User, error) {
	if _, err := s.requireAdmin(ctx, actorID); err != nil {
		return nil, err
	}
	if otherID == actorID {
		return nil, fmt.Errorf("%w: an admin cannot merge away their own account", ErrMergeRefused)
	}
	repo := s.repo(ctx)
	survivor, err := repo.GetUser(ctx, survivorID)
	if err != nil {
		return nil, err
	}
	other, err := repo.GetUser(ctx, otherID)
	if err != nil {
		return nil, err
	}
	if survivor == nil || other == nil {
		return nil, ErrNotFound
	}
	merged, retired, err := mergeAccounts(ctx, repo, survivor, other, takeAddress, nowMs())
	if err != nil {
		return nil, err
	}
	s.audit.Log(ctx, audit.EventAccountMerged,
		audit.WithActor(actorID), audit.WithTarget(retired.ID), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"survivor": survivor.ID, "source": "admin"}))
	notifyMerge(ctx, s.cfg, s.mailer, s.logger, other, merged)
	EmitUserEvent(ctx, s.publisher, s.logger, s.projectID(ctx), s.cfg.DefaultTenantID, events.EventUserMerged, retired)
	return merged, nil
}

// mergeAccounts checks the pair, applies the merge in one transaction and
// returns both accounts as stored afterwards.
func mergeAccounts(ctx context.Context, repo Repository, survivor, other *User, takeAddress bool, now int64) (*User, *User, error) {
	if err := checkMergeable(ctx, repo, survivor, other); err != nil {
		return nil, nil, err
	}
	if err := repo.ApplyAccountMerge(ctx, AccountMerge{
		SurvivorID:   survivor.ID,
		OtherID:      other.ID,
		MoveUsername: other.Username != "" && survivor.Username == "",
		// A password a second factor protected does not move: on the
		// survivor it would sign in without one.
		MovePassword: other.PasswordHash != "" && survivor.PasswordHash == "" && !other.TotpRequired,
		MoveEmail:    other.Email != "" && survivor.Email == "",
		SwapAddress:  takeAddress && other.AccountAddress != "",
		AtMs:         now,
	}); err != nil {
		return nil, nil, err
	}
	merged, err := repo.GetUser(ctx, survivor.ID)
	if err != nil {
		return nil, nil, err
	}
	retired, err := repo.GetUser(ctx, other.ID)
	if err != nil {
		return nil, nil, err
	}
	if merged == nil || retired == nil {
		return nil, nil, fmt.Errorf("merge: %w", ErrNotFound)
	}
	return merged, retired, nil
}

func checkMergeable(ctx context.Context, repo Repository, survivor, other *User) error {
	if survivor.ID == other.ID {
		return fmt.Errorf("%w: an account cannot be merged into itself", ErrMergeRefused)
	}
	if err := checkSurvivor(ctx, repo, survivor); err != nil {
		return err
	}
	if other.Status != StatusActive || other.MergedIntoUserID != "" {
		return fmt.Errorf("%w: both accounts must be active", ErrMergeRefused)
	}
	if other.IsAnonymous {
		return fmt.Errorf("%w: upgrade an anonymous account instead of merging it", ErrMergeRefused)
	}
	// A password an administrator issued would arrive on the survivor as an
	// ordinary one, skipping the change its user still owes.
	if other.PasswordChangeRequired {
		return fmt.Errorf("%w: the other account still has the password it was issued; sign in to it and choose a new one first", ErrMergeRefused)
	}
	if err := refuseManagedChild(ctx, repo, other); err != nil {
		return err
	}
	children, err := repo.ListChildrenOfGuardian(ctx, other.ID, 1, 0)
	if err != nil {
		return fmt.Errorf("check guardianship: %w", err)
	}
	if len(children) > 0 {
		return fmt.Errorf("%w: the other account is a guardian; move its children first", ErrMergeRefused)
	}
	return nil
}

// checkSurvivor refuses an account that cannot take another one in: not
// active, already merged, anonymous, or a managed child.
func checkSurvivor(ctx context.Context, repo Repository, survivor *User) error {
	if survivor.Status != StatusActive || survivor.MergedIntoUserID != "" {
		return fmt.Errorf("%w: both accounts must be active", ErrMergeRefused)
	}
	if survivor.IsAnonymous {
		return fmt.Errorf("%w: upgrade an anonymous account instead of merging into it", ErrMergeRefused)
	}
	return refuseManagedChild(ctx, repo, survivor)
}

func refuseManagedChild(ctx context.Context, repo Repository, u *User) error {
	guardians, err := repo.ListGuardiansOfChild(ctx, u.ID, 1, 0)
	if err != nil {
		return fmt.Errorf("check guardianship: %w", err)
	}
	if len(guardians) > 0 {
		return fmt.Errorf("%w: a managed child's account stays with its guardian", ErrMergeRefused)
	}
	return nil
}

// AccountMergedSubject is the subject of the merge security notice.
const AccountMergedSubject = "Two of your accounts were merged"

// notifyMerge tells the person, at every address either account had, that one
// account was merged into the other: a merge cannot be undone, so someone who
// did not ask for it must hear about it at once. Each notice names only the
// recipient's own account. It goes through the template and branding pipeline
// like every other notice. Best-effort: a failed render or send is logged and
// never undoes the merge.
func notifyMerge(ctx context.Context, cfg *config.Config, mailer email.Transport, logger *zap.Logger, retired, survivor *User) {
	if mailer == nil {
		return
	}
	brand := resolveBranding(ctx, cfg, "")
	send := func(to string, u *User, isRetired bool) {
		if to == "" {
			return
		}
		yours := u.Email
		if yours == "" {
			yours = u.Username
		}
		html, text, err := email.Render(email.TemplateAccountMerged, brand.templateData(map[string]any{
			"UserName":    displayNameOrEmail(u),
			"YourAccount": yours,
			"Retired":     isRetired,
		}))
		if err != nil {
			logger.Warn("account_merge_notice_render_failed", zap.Error(err))
			return
		}
		msg := email.Message{To: to, From: cfg.SMTPFrom, Subject: AccountMergedSubject, HTML: html, Text: text}
		brand.applyTo(&msg)
		if err := mailer.Send(ctx, msg); err != nil {
			logger.Warn("account_merge_notice_failed", zap.String("user_id", u.ID), zap.Error(err))
		}
	}
	send(retired.Email, retired, true)
	if survivor.Email != retired.Email {
		send(survivor.Email, survivor, false)
	}
}

// recentlyAuthenticated reports whether a session's sign-in (auth_time, epoch
// seconds) is within GATEWAY_ACCOUNT_MERGE_REAUTH_MAX_AGE_SECONDS of now. A
// session with no recorded sign-in time, or one in the future, is not.
func (s *AuthService) recentlyAuthenticated(authTimeSec int64) bool {
	if authTimeSec <= 0 {
		return false
	}
	age := s.nowMs() - authTimeSec*1000
	return age >= 0 && age <= s.cfg.AccountMergeReauthMaxAge().Milliseconds()
}
