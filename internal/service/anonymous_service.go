package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

var (
	// ErrAnonymousDisabled: the resolved project does not offer anonymous
	// sign-in. Distinct from an access-mode denial — anonymous sign-in has
	// its own switch and is never turned on or off by `access.mode`.
	ErrAnonymousDisabled = errors.New("anonymous sign-in is not enabled for this project")

	// ErrNotAnonymous: the caller asked to upgrade an account that already
	// holds a credential. Upgrading twice would silently rebind an
	// identified account to a new credential, so it is refused.
	ErrNotAnonymous = errors.New("account is not anonymous")

	// ErrAnonymousMustUpgrade: an anonymous caller tried to attach a
	// permanent credential through a path that cannot also clear the
	// anonymous flag. See refuseAnonymousCredentialAttach.
	ErrAnonymousMustUpgrade = errors.New("anonymous accounts gain credentials through UpgradeAnonymousAccount")

	// ErrAnonymousRefreshDisabled: the project turned anonymous sign-in off
	// while this session was live. Distinct from ErrAnonymousDisabled
	// because it surfaces on RefreshToken — a shipped, implemented RPC —
	// where UNIMPLEMENTED would read as a routing fault (HTTP 404 under
	// Connect) and some SDK layers cache it as a capability probe. This is
	// an authorization outcome for one caller, not an absent capability.
	ErrAnonymousRefreshDisabled = errors.New("anonymous sign-in was disabled for this project")
)

// AnonymousPasswordCredential upgrades an anonymous account to an email +
// password login. AnonymousOAuthCredential upgrades it to a federated one;
// the server performs the provider code exchange itself, so the client is
// never trusted to assert the identity.
type AnonymousPasswordCredential struct {
	Email    string
	Password string
	Name     string
	// IPAddress / UserAgent describe the client, recorded on the refresh
	// token the upgrade issues so a promoted session is as attributable as
	// one from an ordinary login.
	IPAddress string
	UserAgent string
}

type AnonymousOAuthCredential struct {
	Provider     string
	Code         string
	RedirectURI  string
	CodeVerifier string
	State        string
	StateToken   string
	IPAddress    string
	UserAgent    string
}

// anonymousEnabled reports whether the resolved project offers anonymous
// sign-in.
//
// It reads ONLY the anonymous switch. It deliberately does not consult
// scope.Access: a project may be mode:closed — admitting no new identified
// users — and still hand out anonymous sessions, because the access mode
// governs which email-identified humans may sign up and log in, which is a
// different question. This mirrors Firebase, where anonymous auth is its own
// provider toggle and does not even fire the blocking functions that gate
// identified sign-ups. Anonymous abuse is controlled by the assurance layer
// (GATEWAY_ANONYMOUS_REQUIRE_ASSURANCE), not by the access mode.
//
// A request with no project scope (a direct service call, or a deployment
// with neither a control plane nor a default project) has no project whose
// policy could enable the feature, so it is DENIED — the inverse of the
// access guard's nil-scope pass-through, because there the absence of a
// project means "no gate to apply" while here it means "nothing turned this
// on".
func (s *AuthService) anonymousEnabled(ctx context.Context) bool {
	scope := ProjectScopeFromContext(ctx)
	return scope != nil && scope.Anonymous.Enabled
}

// SignInAnonymously creates a brand-new credential-less account and returns
// it with a token pair. Every call mints a NEW user: there is nothing to
// authenticate against, so the server cannot recognise a returning anonymous
// client — that is what the refresh token is for, and why a client must
// persist it.
//
// The account is a real user row (Firebase's model): it can own data, be
// referenced by foreign keys, and later gain a credential without changing
// id. It carries no email, which is what lets any number of them coexist in
// one project — the per-project email unique index covers non-empty
// addresses only.
func (s *AuthService) SignInAnonymously(ctx context.Context, ipAddr, userAgent string) (*LoginResult, error) {
	if !s.anonymousEnabled(ctx) {
		return nil, ErrAnonymousDisabled
	}

	now := s.nowMs()
	u := &User{
		Role:        "member",
		Status:      "active",
		IsAnonymous: true,
		// LastLoginAtMs is the retention sweep's activity clock, and creation
		// is the first activity. Leaving it zero would make every new
		// anonymous user instantly older than any cutoff and reap it on the
		// next sweep tick.
		LastLoginAtMs: now,
		CreatedAt:     s.nowFunc(),
		UpdatedAt:     s.nowFunc(),
	}
	id, err := s.repo(ctx).CreateUser(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("creating anonymous user: %w", err)
	}
	u.ID = id

	access, refresh, err := s.issueTokens(ctx, u, ipAddr, userAgent)
	if err != nil {
		return nil, err
	}

	s.audit.Log(
		ctx, audit.EventAnonymousSignIn,
		audit.WithActor(id),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"project_id": s.projectID(ctx)}),
	)
	s.logger.Info("anonymous_signin",
		zap.String("user_id", id),
		zap.String("project_id", s.projectID(ctx)))

	return &LoginResult{
		User:         u,
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}

// UpgradeAnonymousUser promotes an anonymous account to a permanent one IN
// PLACE, preserving its id. It is the server half of Firebase's
// linkWithCredential: the credential itself is attached by the caller (the
// password is hashed and stored, or the OAuth identity row is written)
// before this runs, and this makes the promotion atomic-in-intent — clearing
// is_anonymous and stamping the identifying fields in one update.
//
// Preserving the id is the entire point. Everything the client wrote against
// the anonymous id — rows in the consumer's own database, uploaded files,
// purchases — stays attached to the same subject after the upgrade, so no
// data migration is needed and no token reissue changes who the user is.
//
// It refuses an account that is not anonymous: a second upgrade would
// silently rebind an identified account to a different credential.
func (s *AuthService) UpgradeAnonymousUser(ctx context.Context, userID string, fields map[string]any) error {
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("%w: missing user ID", ErrUnauthenticated)
	}
	u, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if u == nil {
		return ErrNotFound
	}
	if !u.IsAnonymous {
		return ErrNotAnonymous
	}

	// Clearing the flag is what takes the account out of the retention
	// sweep's reach, permanently — the sweep matches on is_anonymous.
	upgrade := map[string]any{"is_anonymous": false, "updated_at": s.nowMs()}
	for k, v := range fields {
		upgrade[k] = v
	}
	if err := s.repo(ctx).UpdateUser(ctx, userID, upgrade); err != nil {
		return err
	}

	s.audit.Log(
		ctx, audit.EventAnonymousUpgraded,
		audit.WithActor(userID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"project_id": s.projectID(ctx)}),
	)
	s.logger.Info("anonymous_upgraded",
		zap.String("user_id", userID),
		zap.String("project_id", s.projectID(ctx)))
	return nil
}

// touchAnonymousActivity advances an anonymous user's activity clock on
// token refresh.
//
// An anonymous account has no login event to stamp — refresh IS its only
// recurring sign of life. Without this the retention sweep would key on a
// timestamp that never advances, and every anonymous user would be deleted
// exactly one retention window after creation no matter how actively it was
// being used, taking its refresh token (its only credential) with it.
//
// Best-effort: a failed stamp must not fail the refresh. The cost of losing
// one stamp is that the account looks idle until its next refresh.
func (s *AuthService) touchAnonymousActivity(ctx context.Context, u *User) {
	if u == nil || !u.IsAnonymous {
		return
	}
	if err := s.repo(ctx).UpdateUser(ctx, u.ID, map[string]any{"last_login_at": s.nowMs()}); err != nil {
		s.logger.Warn("anonymous_activity_stamp_failed",
			zap.String("user_id", u.ID), zap.Error(err))
	}
}

// refuseAnonymousCredentialAttach blocks a permanent credential from being
// attached to an anonymous account by any path other than
// UpgradeAnonymousAccount.
//
// The retention sweep keys on is_anonymous, and every other credential
// endpoint (LinkIdentity, passkey registration, phone verification) is
// reachable by an anonymous access token — it carries a sub and role:member
// like any other. Attaching there leaves the flag set, so the account holds
// a working credential AND stays in the sweep's reach: after the retention
// window it is hard-deleted, cascading its sessions and credentials, with no
// signal to anyone. Refusing keeps a single door through which an anonymous
// account can become permanent, which is the only place the project access
// mode has to be enforced.
//
// A lookup failure refuses too: guessing "probably not anonymous" is the
// direction that loses data.
func (s *AuthService) refuseAnonymousCredentialAttach(ctx context.Context, userID string) error {
	u, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if u != nil && u.IsAnonymous {
		return fmt.Errorf(
			"%w: attaching one here would leave the account subject to the anonymous "+
				"retention sweep despite holding a working credential", ErrAnonymousMustUpgrade)
	}
	return nil
}
