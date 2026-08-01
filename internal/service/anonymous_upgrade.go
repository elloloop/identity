package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
// The access mode is not consulted. It governs who may sign up as a new
// identified user; this account already exists and is merely gaining a way
// to log back in. Gating it here would mean an anonymous user on a closed
// project could never become permanent, stranding the data they accrued.
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
	// LinkIdentity already owns the exchange, the unclaimed-identity check,
	// and the audit trail for attaching a provider to an authenticated user.
	// It is reused whole rather than reimplemented: the only thing an
	// anonymous upgrade adds is the promotion afterwards.
	identity, err := s.LinkIdentity(ctx, userID, cred.Code, cred.Provider,
		cred.RedirectURI, cred.CodeVerifier, cred.State, cred.StateToken)
	if err != nil {
		return nil, err
	}

	fields := map[string]any{}
	if email := strings.TrimSpace(strings.ToLower(identity.EmailAtLinkTime)); email != "" {
		// Only claim the address if it is genuinely free. A collision here
		// means the provider's email already belongs to another account: the
		// link itself is legitimate (that account has no such provider
		// identity) but adopting the address would breach the per-project
		// uniqueness index, so the upgrade completes WITHOUT an email. The
		// account is permanent and reachable via the provider either way.
		taken, lookupErr := s.repo(ctx).FindUserByEmail(ctx, email)
		if lookupErr != nil {
			return nil, lookupErr
		}
		if taken == nil {
			fields["email"] = email
			// Federated addresses are provider-verified, unlike a typed one.
			fields["email_verified"] = true
			fields["email_verified_at"] = s.nowMs()
			fields["name"] = fallbackDisplayName(email, "")
		}
	}

	if err := s.UpgradeAnonymousUser(ctx, userID, fields); err != nil {
		return nil, s.mapUpgradeConflict(err)
	}
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
