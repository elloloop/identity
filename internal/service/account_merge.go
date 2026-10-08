package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/events"
	"github.com/elloloop/identity/pkg/passwords"
)

// ErrMergeRefused is returned when two accounts cannot be merged as they
// stand; the wrapped message says why and what to do first.
var ErrMergeRefused = errors.New("these accounts cannot be merged")

// Merging two accounts of one person.
//
// A merge never deletes anything. One account, the survivor, chosen by
// whoever asks (never by the server), carries on. The other is RETIRED:
// StatusDeactivated with MergedIntoUserID naming the survivor (which also
// keeps it from ever being reactivated), every session
// revoked, and it never signs in again, but its row and everything stored
// under its id stay, and a user.merged event tells downstream applications to
// move what they hold under the retired id to the survivor.
//
// The survivor takes over what lets the person sign in the way they used to:
//   - the retired account's username, when the survivor has none, so the
//     username keeps signing in (to the survivor);
//   - its password, when the survivor has none (an account made by an
//     external provider gains the password the username used);
//   - on request (takeAddress), its account address; the survivor's old
//     address then moves to the retired account, so neither is freed for
//     someone else.
//
// Refused: merging an account with itself; an account that is not active;
// an anonymous account (upgrade it instead); a managed child's account (it
// stays with its guardian), and an account that is any child's guardian
// (its children's guardian edges would point at a retired account).

// MergeAccounts merges the account identified by otherIdentifier (an email,
// or a username) into the caller's own account, survivorID. Proof that the
// caller controls the other account is its password, checked exactly as
// PasswordLogin checks it — the same uniform refusal for an unknown
// identifier or a wrong password, the same lockout. An account protected by
// two-step verification cannot be merged by password alone: turn it off
// there first.
func (s *AuthService) MergeAccounts(ctx context.Context, survivorID, otherIdentifier, otherPassword string, takeAddress bool) (*User, error) {
	if survivorID == "" {
		return nil, ErrUnauthenticated
	}
	if strings.TrimSpace(otherIdentifier) == "" || otherPassword == "" {
		return nil, fmt.Errorf("%w: the other account's identifier and password are required", ErrInvalidArgument)
	}
	repo := s.repo(ctx)
	survivor, err := repo.GetUser(ctx, survivorID)
	if err != nil {
		return nil, err
	}
	if survivor == nil {
		return nil, ErrUnauthenticated
	}
	other, err := s.lookupByIdentifier(ctx, otherIdentifier)
	if err != nil && !errors.Is(err, errNoSuchAccount) {
		return nil, err
	}
	if other == nil || other.PasswordHash == "" {
		_ = passwords.Verify(otherPassword, getDummyPasswordHash())
		return nil, fmt.Errorf("%w: invalid identifier or password", ErrUnauthenticated)
	}
	if other.LockedUntil > s.nowMs() {
		return nil, fmt.Errorf("%w: account temporarily locked due to too many failed attempts", ErrAccountLocked)
	}
	if !passwords.Verify(otherPassword, other.PasswordHash) {
		if _, _, rerr := s.recordFailedLogin(ctx, other); rerr != nil {
			s.logger.Warn("merge_failed_attempt_not_recorded", zap.String("user_id", other.ID), zap.Error(rerr))
		}
		return nil, fmt.Errorf("%w: invalid identifier or password", ErrUnauthenticated)
	}
	if other.TotpRequired {
		return nil, fmt.Errorf("%w: turn off two-step verification on the other account first", ErrMergeRefused)
	}
	merged, retired, err := mergeAccounts(ctx, repo, survivor, other, takeAddress, s.nowMs())
	if err != nil {
		return nil, err
	}
	s.audit.Log(ctx, audit.EventAccountMerged,
		audit.WithActor(survivor.ID), audit.WithTarget(retired.ID), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"survivor": survivor.ID, "source": "self"}))
	EmitUserEvent(ctx, s.publisher, s.logger, s.projectID(ctx), s.tenantID(ctx), events.EventUserMerged, retired)
	return merged, nil
}

// errNoSuchAccount is lookupByIdentifier's answer for an identifier that can
// name no account (malformed); the caller treats it like an unknown one.
var errNoSuchAccount = errors.New("identifier names no account")

// lookupByIdentifier resolves a sign-in identifier the way PasswordLogin
// does: an email (canonical form) when it contains '@', else a username.
// A well-formed identifier with no account resolves to (nil, nil).
func (s *AuthService) lookupByIdentifier(ctx context.Context, identifier string) (*User, error) {
	identifier = strings.TrimSpace(strings.ToLower(identifier))
	if strings.Contains(identifier, "@") {
		if err := validateEmailFormat(identifier); err != nil {
			return nil, fmt.Errorf("%w: %w", errNoSuchAccount, err)
		}
		cemail, usable := canonicalMailbox(identifier)
		if !usable {
			return nil, errNoSuchAccount
		}
		return s.repo(ctx).FindUserByEmail(ctx, string(cemail))
	}
	username := normalizeUsername(identifier)
	if err := validateUsernameShape(username); err != nil {
		return nil, fmt.Errorf("%w: %w", errNoSuchAccount, err)
	}
	return s.repo(ctx).FindUserByUsername(ctx, username)
}

// MergeUsers is the admin form of MergeAccounts: an admin merges otherID into
// survivorID. The admin's role is the authority, so no password of either
// account is asked for.
func (s *AdminService) MergeUsers(ctx context.Context, actorID, survivorID, otherID string, takeAddress bool) (*User, error) {
	if _, err := s.requireAdmin(ctx, actorID); err != nil {
		return nil, err
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
	EmitUserEvent(ctx, s.publisher, s.logger, s.projectID(ctx), s.cfg.DefaultTenantID, events.EventUserMerged, retired)
	return merged, nil
}

// mergeAccounts retires other into survivor (see "Merging two accounts of one
// person" above) and returns both as stored afterwards.
func mergeAccounts(ctx context.Context, repo Repository, survivor, other *User, takeAddress bool, now int64) (*User, *User, error) {
	if err := checkMergeable(ctx, repo, survivor, other); err != nil {
		return nil, nil, err
	}
	// The values the accounts hold now, kept apart from the caller's structs
	// so a rollback restores exactly them.
	before, survivorAddress := *other, survivor.AccountAddress
	retire := map[string]any{
		"status":              StatusDeactivated,
		"merged_into_user_id": survivor.ID,
		"updated_at":          now,
	}
	gain := map[string]any{"updated_at": now}
	if other.Username != "" && survivor.Username == "" {
		retire["username"] = ""
		gain["username"] = other.Username
	}
	if survivor.PasswordHash == "" && other.PasswordHash != "" {
		gain["password_hash"] = other.PasswordHash
	}
	swapAddress := takeAddress && other.AccountAddress != ""
	if swapAddress {
		retire["account_address"] = ""
		gain["account_address"] = other.AccountAddress
	}

	// Retire first: it releases the username and address the survivor takes.
	if err := repo.UpdateUser(ctx, other.ID, retire); err != nil {
		return nil, nil, fmt.Errorf("retire merged account: %w", err)
	}
	if err := repo.UpdateUser(ctx, survivor.ID, gain); err != nil {
		// Put the retired account back as it was, so a failed merge leaves
		// both accounts exactly as they were.
		restore := map[string]any{"status": before.Status, "merged_into_user_id": "", "updated_at": now}
		if _, ok := retire["username"]; ok {
			restore["username"] = before.Username
		}
		if swapAddress {
			restore["account_address"] = before.AccountAddress
		}
		if rerr := repo.UpdateUser(ctx, other.ID, restore); rerr != nil {
			return nil, nil, fmt.Errorf("merge into survivor: %w (and restoring the other account failed: %w)", err, rerr)
		}
		return nil, nil, fmt.Errorf("merge into survivor: %w", err)
	}
	if swapAddress && survivorAddress != "" {
		// The survivor's old address stays reserved on the retired account
		// rather than being freed for someone else to take.
		if err := repo.UpdateUser(ctx, other.ID, map[string]any{"account_address": survivorAddress}); err != nil {
			return nil, nil, fmt.Errorf("keep the survivor's old address: %w", err)
		}
	}
	if err := revokeAllUserSessions(ctx, repo, other.ID, now); err != nil {
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
	switch {
	case survivor.ID == other.ID:
		return fmt.Errorf("%w: an account cannot be merged into itself", ErrMergeRefused)
	case survivor.Status != StatusActive || other.Status != StatusActive:
		return fmt.Errorf("%w: both accounts must be active", ErrMergeRefused)
	case survivor.IsAnonymous || other.IsAnonymous:
		return fmt.Errorf("%w: upgrade an anonymous account instead of merging it", ErrMergeRefused)
	}
	for _, u := range []*User{survivor, other} {
		guardians, err := repo.ListGuardiansOfChild(ctx, u.ID, 1, 0)
		if err != nil {
			return fmt.Errorf("check guardianship: %w", err)
		}
		if len(guardians) > 0 {
			return fmt.Errorf("%w: a managed child's account stays with its guardian", ErrMergeRefused)
		}
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
