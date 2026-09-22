package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"
)

// UpgradeAnonymousWithPassword attaches an email + password credential to
// the calling anonymous account, preserving its id.
//
// It deliberately does NOT reuse PasswordSignup. Signup resolves-or-creates
// an account from an email; this promotes an account that already exists,
// and the two differ on the case that matters: if the address is already
// taken, signup's anti-enumeration behaviour is to return a decoy success,
// whereas here the caller is authenticated as the account being upgraded
// and MUST learn that the address is unavailable — otherwise it believes it
// has a permanent account it cannot log into. What is shared is the rules:
// the same format validation, canonicalization, and strength policy.
//
// The access mode is enforced with SIGNUP semantics, not login: this call
// turns an anonymous session into an email-identified account in the
// project's namespace, which is precisely the act `mode` governs. Under
// `mode: invite` the access guard denies self-signup but permits login, so
// gating on login semantics here would let SignInAnonymously (ungated by
// design) chain into a permanent, indefinitely-refreshable account on a
// project whose entire boundary is "invited users only".
//
// The cost is real and accepted: an anonymous user on a closed project
// cannot become permanent. Operators who want that data retained open the
// project, or upgrade the account administratively.
func (s *AuthService) UpgradeAnonymousWithPassword(
	ctx context.Context, userID string, cred AnonymousPasswordCredential,
) (*LoginResult, error) {
	if !s.cfg.AuthAllowLocal {
		return nil, ErrLocalAuthDisabled
	}
	// The upgrade creates a password account, so it is bound by the same
	// switch that governs creating one directly.
	if !s.cfg.PasswordSignupEnabled {
		return nil, ErrSignupDisabled
	}
	// Signup semantics include the age gate. PasswordSignup refuses a
	// missing date of birth when the deployment demands one; this arm's
	// request cannot carry a DOB at all, so on such a deployment it must
	// refuse rather than mint an active, password-loginable account with
	// date_of_birth_ms=0 that is permanently classified non-minor and can
	// never enter the parental-consent flow. Collecting a DOB on the
	// upgrade is a compatible future addition (ADR-0013 "Not shipped").
	if s.ageGate.Enabled() && s.cfg.AgeGateRequireDOB {
		return nil, fmt.Errorf("%w: this deployment requires a date of birth at signup; the anonymous upgrade cannot collect one", ErrInvalidArgument)
	}
	email := strings.TrimSpace(strings.ToLower(cred.Email))
	if err := validateEmailFormat(email); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidArgument, err.Error())
	}
	cemail := canonicalize(email)
	email = string(cemail)
	// Before any password work, and before the address probe below, so a
	// restricted project neither mints a disallowed account nor answers
	// existence questions about addresses it would refuse anyway.
	if err := s.enforceProjectAccessSignup(ctx, cemail); err != nil {
		return nil, err
	}
	if cred.Password == "" {
		return nil, fmt.Errorf("%w: password is required", ErrInvalidArgument)
	}
	if err := s.validatePasswordStrengthForEmail(ctx, email, cred.Password); err != nil {
		return nil, err
	}

	// Confirm the caller is anonymous BEFORE probing whether the address is
	// taken. The probe answers a question about OTHER accounts, and its
	// ALREADY_EXISTS is distinguishable from the not-anonymous refusal — so
	// checking it first let ANY authenticated caller walk the project's
	// registered addresses, straight around the decoy-success
	// anti-enumeration work PasswordSignup invests in. The OAuth arm already
	// ordered these correctly.
	u, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, ErrNotFound
	}
	if !u.IsAnonymous {
		return nil, ErrNotAnonymous
	}

	// Now the address. Checked before hashing (bcrypt-class work) so a taken
	// address costs nothing; the unique index remains the authority, this is
	// the friendly error.
	existing, err := s.repo(ctx).FindUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, fmt.Errorf("%w: email already registered", ErrAlreadyExists)
	}

	hash, err := passwords.Hash(cred.Password)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	if err := s.UpgradeAnonymousUser(ctx, userID, map[string]any{
		"email":         email,
		"name":          fallbackDisplayName(email, cred.Name),
		"password_hash": hash,
		// The address is unproven at this point — the user typed it. Marking
		// it verified here would hand out a verified identity for free, which
		// is precisely the property account-recovery and allowlists rely on.
		"email_verified": false,
	}); err != nil {
		return nil, s.mapUpgradeConflict(err)
	}

	// Prove the address before it buys anything. GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL
	// defaults TRUE and is this codebase's anti-pre-hijacking control:
	// PasswordSignup honours it by returning the user with no tokens, and
	// PasswordLogin refuses an unverified account. Without the same gate here
	// the upgrade was strictly more powerful than signup — an unauthenticated
	// caller could chain SignInAnonymously into a live session whose JWT
	// asserts someone else's address, with no verification mail and so no
	// signal to its owner. Same shape as signup: promoted account, no tokens.
	if s.cfg != nil && s.cfg.AuthRequireVerifiedEmail {
		if err := s.SendEmailVerification(ctx, userID); err != nil {
			s.logger.Warn("anonymous_upgrade_verification_send_failed",
				zap.String("user_id", userID), zap.Error(err))
		}
		u, err := s.repo(ctx).GetUser(ctx, userID)
		if err != nil {
			return nil, err
		}
		if u == nil {
			return nil, ErrNotFound
		}
		// The anonymous session is deliberately revoked with the promotion:
		// leaving it live would return exactly the session this gate exists
		// to withhold, just under the previous credential. Refresh tokens
		// alone do NOT end the session: under
		// GATEWAY_REVOCATION_MODE=session the access token's lifetime is
		// uncapped and it is revocable only through its Session row, and an
		// SSO session would keep offering continue-as — the shared helper
		// kills all three stores, or the caller keeps a working credential
		// against a subject that now bears the address they just claimed.
		if err := revokeDerivedSessionsForUser(ctx, s.repo(ctx), userID, s.nowMs()); err != nil {
			s.logger.Warn("anonymous_upgrade_session_revoke_failed",
				zap.String("user_id", userID), zap.Error(err))
		}
		return &LoginResult{User: u}, nil
	}

	if err := s.SendEmailVerification(ctx, userID); err != nil {
		s.logger.Warn("anonymous_upgrade_verification_send_failed",
			zap.String("user_id", userID), zap.Error(err))
	}
	return s.reissueAfterUpgrade(ctx, userID, cred.IPAddress, cred.UserAgent)
}

// UpgradeAnonymousWithOAuth attaches a federated identity to the calling
// anonymous account, preserving its id. The server performs the code
// exchange itself, exactly as OAuthLogin and LinkIdentity do.
//
// The provider identity must be unclaimed. Firebase reports this as
// credential-already-in-use, and like Firebase we do NOT merge the two
// accounts: merging would silently destroy one account's data, and choosing
// which one survives is the application's decision, not the server's.
func (s *AuthService) UpgradeAnonymousWithOAuth(
	ctx context.Context, userID string, cred AnonymousOAuthCredential,
) (*LoginResult, error) {
	// Every check that can refuse runs BEFORE anything is persisted, so a
	// rejected upgrade leaves the account exactly as it was. Deciding after
	// the link would also allow a PERMANENT account with an empty email —
	// invalid, since that is the one state the partial email index tolerates
	// multiples of, and the account would have no address despite being
	// permanent.
	u, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, ErrNotFound
	}
	if !u.IsAnonymous {
		return nil, ErrNotAnonymous
	}

	identity, err := s.verifyOAuthExchange(ctx, OAuthLoginParams{
		Code:         cred.Code,
		Provider:     cred.Provider,
		RedirectURI:  cred.RedirectURI,
		CodeVerifier: cred.CodeVerifier,
		State:        cred.State,
		StateToken:   cred.StateToken,
	})
	if err != nil {
		if errors.Is(err, errOAuthExchangeFailed) {
			// NOT errors.Unwrap: the error wraps two verbs, and Unwrap
			// returns nil for a multi-%w error — which reached the client as
			// the literal "unauthenticated: %!w(<nil>)".
			return nil, s.mapOAuthErr(err)
		}
		return nil, err
	}
	if identity.ProviderUserID == "" {
		return nil, fmt.Errorf("%w: provider returned no stable subject", ErrUnauthenticated)
	}

	email := canonicalize(strings.TrimSpace(strings.ToLower(identity.Email)))
	if email == "" {
		// A permanent account must have an address. Without one it cannot be
		// recovered, cannot be allowlisted, and occupies the empty-email slot
		// the partial index exists to keep free for anonymous users.
		return nil, fmt.Errorf("%w: provider returned no email, which a permanent account requires", ErrInvalidArgument)
	}
	// Same gate as the password path: this is what provisions an identified
	// account in the project's namespace.
	if err := s.enforceProjectAccessSignup(ctx, email); err != nil {
		return nil, err
	}
	taken, err := s.repo(ctx).FindUserByEmail(ctx, string(email))
	if err != nil {
		return nil, err
	}
	if taken != nil {
		return nil, fmt.Errorf("%w: email already registered", ErrAlreadyExists)
	}
	existing, err := s.repo(ctx).FindUserByProviderID(ctx, identity.Provider, identity.ProviderUserID)
	if err != nil {
		return nil, err
	}
	if existing != nil && existing.ID != userID {
		// Firebase's credential-already-in-use. Deliberately NOT a merge:
		// choosing which account survives is the application's decision.
		return nil, fmt.Errorf("%w: provider identity already linked", ErrAlreadyExists)
	}

	// This writes TWO rows without a transaction, so the ordering and the
	// compensation below are what keep it recoverable. If the promotion
	// failed after the link was created, the account is still anonymous but
	// already owns the identity — `existing.ID == userID` above is that
	// case, and skipping the create makes the retry succeed instead of
	// returning ALREADY_EXISTS forever against the caller's own identity.
	// Without it a single transient failure stranded the provider identity
	// on an account the sweep then reaps, and no account on the deployment
	// could ever claim that identity again without manual repair.
	if existing == nil {
		if err := s.repo(ctx).CreateOAuthIdentity(ctx, &OAuthIdentity{
			UserID:          userID,
			Provider:        identity.Provider,
			ProviderUserID:  identity.ProviderUserID,
			EmailAtLinkTime: string(email),
			CreatedAt:       s.nowMs(),
		}); err != nil {
			// Only a genuine uniqueness conflict is a racing link; anything
			// else (pool exhaustion, statement timeout) must not surface as
			// a terminal 409 the caller can never retry past.
			if errors.Is(err, ErrAlreadyExists) {
				return nil, fmt.Errorf("%w: provider identity already linked", ErrAlreadyExists)
			}
			return nil, err
		}
	}
	if err := s.UpgradeAnonymousUser(ctx, userID, map[string]any{
		"email": string(email),
		// Federated addresses are provider-verified, unlike a typed one.
		"email_verified":    true,
		"email_verified_at": s.nowMs(),
		"name":              fallbackDisplayName(string(email), identity.Name),
	}); err != nil {
		// Compensate: drop the identity we just created so the account does
		// not keep a credential while remaining anonymous (and therefore
		// reapable). Best-effort — the retry path above recovers even if
		// this fails.
		if existing == nil {
			if delErr := s.repo(ctx).DeleteOAuthIdentity(ctx, userID, identity.Provider, identity.ProviderUserID); delErr != nil {
				s.logger.Warn("anonymous_upgrade_compensation_failed",
					zap.String("user_id", userID),
					zap.String("provider", identity.Provider),
					zap.Error(delErr))
			}
		}
		return nil, s.mapUpgradeConflict(err)
	}
	s.audit.Log(
		ctx, audit.EventIdentityLinked,
		audit.WithActor(userID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{
			"provider":           identity.Provider,
			"provider_user_id":   identity.ProviderUserID,
			"source":             "anonymous_upgrade",
			"email_at_link_time": string(email),
		}),
	)
	return s.reissueAfterUpgrade(ctx, userID, cred.IPAddress, cred.UserAgent)
}

// reissueAfterUpgrade re-reads the promoted account and mints a fresh token
// pair for it.
//
// The re-read is not incidental: the caller's in-memory copy still says
// is_anonymous, and the new access token's `anonymous` claim is derived from
// the user. Reissuing is likewise mandatory rather than a convenience — the
// caller's existing access token asserts anonymous=true, so without a new
// one every downstream service would keep treating a now-permanent account
// as anonymous until that token happened to expire.
func (s *AuthService) reissueAfterUpgrade(ctx context.Context, userID, ipAddr, userAgent string) (*LoginResult, error) {
	u, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, ErrNotFound
	}
	access, refresh, err := s.issueTokens(ctx, u, ipAddr, userAgent)
	if err != nil {
		return nil, err
	}
	return &LoginResult{
		User:         u,
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}

// mapUpgradeConflict translates a unique-index violation raised by the
// promotion into the caller-facing conflict. The pre-check above narrows the
// window but cannot close it: two requests can both find an address free and
// both proceed, and the index is what actually decides.
func (s *AuthService) mapUpgradeConflict(err error) error {
	if errors.Is(err, ErrAlreadyExists) {
		return fmt.Errorf("%w: email already registered", ErrAlreadyExists)
	}
	return err
}
