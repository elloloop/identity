package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
// The access mode IS enforced, with SIGNUP semantics. An earlier version of
// this reasoned that the account already exists and is merely gaining a way
// to log back in, so the mode need not apply — that was wrong, and it was a
// full bypass of invite-only projects. Under `mode: invite` the guard denies
// self-signup but permits login, so an unauthenticated caller could chain
// SignInAnonymously (no access check, by design) into an upgrade (no check
// at all) and end with a permanent, provisioned, indefinitely-refreshable
// account on a project whose entire boundary is "invited users only".
//
// Signup semantics, not login: this call is what turns an anonymous session
// into an email-identified account in the project's namespace, which is
// precisely the act `mode` governs. The cost is real and accepted — an
// anonymous user on a closed project cannot become permanent — but the
// alternative is that the access mode means nothing. Operators who want that
// data retained should open the project, or upgrade the account
// administratively.
func (s *AuthService) UpgradeAnonymousWithPassword(
	ctx context.Context, userID string, cred AnonymousPasswordCredential,
) (*LoginResult, error) {
	if !s.cfg.AuthAllowLocal {
		return nil, ErrLocalAuthDisabled
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

	// Check the address BEFORE hashing (bcrypt-class work) and before the
	// promotion, so a taken address costs nothing and changes nothing. The
	// unique index is still the authority — this is the friendly error, not
	// the guarantee; a racing signup is caught by the index below.
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
	return s.reissueAfterUpgrade(ctx, userID)
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
	// Every check that can refuse runs BEFORE anything is persisted. An
	// earlier version linked the identity first (via LinkIdentity) and
	// decided afterwards, so a rejected upgrade still permanently mutated
	// the account — and, when the provider's address could not be adopted,
	// produced a PERMANENT account with an empty email. That state is
	// invalid: it is the one thing the partial email index tolerates
	// multiple of, so it silently blocks any future rollback of 0028, and
	// the account has no address despite being permanent.
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
			return nil, s.mapOAuthErr(errors.Unwrap(err))
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
	if existing != nil {
		// Firebase's credential-already-in-use. Deliberately NOT a merge:
		// choosing which account survives is the application's decision.
		return nil, fmt.Errorf("%w: provider identity already linked", ErrAlreadyExists)
	}

	// Everything is permitted; now mutate.
	if err := s.repo(ctx).CreateOAuthIdentity(ctx, &OAuthIdentity{
		UserID:          userID,
		Provider:        identity.Provider,
		ProviderUserID:  identity.ProviderUserID,
		EmailAtLinkTime: string(email),
		CreatedAt:       s.nowMs(),
	}); err != nil {
		// A racing link that beat us to the unique (provider, sub) pair.
		return nil, fmt.Errorf("%w: provider identity already linked", ErrAlreadyExists)
	}
	if err := s.UpgradeAnonymousUser(ctx, userID, map[string]any{
		"email": string(email),
		// Federated addresses are provider-verified, unlike a typed one.
		"email_verified":    true,
		"email_verified_at": s.nowMs(),
		"name":              fallbackDisplayName(string(email), identity.Name),
	}); err != nil {
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
	return s.reissueAfterUpgrade(ctx, userID)
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
func (s *AuthService) reissueAfterUpgrade(ctx context.Context, userID string) (*LoginResult, error) {
	u, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, ErrNotFound
	}
	access, refresh, err := s.issueTokens(ctx, u, "", "")
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
