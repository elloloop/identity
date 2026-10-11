package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/oauth"
)

// LinkIdentity attaches a freshly-verified OAuth identity to an already
// authenticated user. The server performs the provider code exchange itself
// (the client is never trusted to assert the identity), exactly as OAuthLogin
// does, then persists the (provider, provider_user_id) link against userID.
//
// It differs from login-time auto-linking in two ways: it targets the
// CURRENTLY AUTHENTICATED user rather than resolving a user from the
// provider's email, and it surfaces a hard error (rather than best-effort
// logging) so the caller learns whether the link was created. If the provider
// identity is already linked — to this user or another — it returns
// ErrAlreadyExists; the caller must not be able to steal another account's
// provider identity, and a no-op re-link should not look like success.
func (s *AuthService) LinkIdentity(
	ctx context.Context,
	userID, code, provider, redirectURI, codeVerifier, state, stateToken string,
) (*OAuthIdentity, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("%w: missing user ID", ErrUnauthenticated)
	}
	// An anonymous caller must not gain a permanent credential here. The
	// retention sweep keys on is_anonymous, so a link that leaves the flag
	// set produces an account with a working provider login that the sweep
	// hard-deletes after the retention window — silently, cascading its
	// sessions. UpgradeAnonymousAccount is the one door that attaches a
	// credential AND clears the flag AND applies the project access mode;
	// everything else refuses, so there is exactly one path to guard.
	if err := s.refuseAnonymousCredentialAttach(ctx, userID); err != nil {
		return nil, err
	}
	// Read before the insert: see withdrawLinkIfAddressProven.
	holder, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if holder == nil {
		return nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}
	provider = strings.ToLower(strings.TrimSpace(provider))

	identity, err := s.verifyOAuthExchange(ctx, OAuthLoginParams{
		Code:         code,
		Provider:     provider,
		RedirectURI:  redirectURI,
		CodeVerifier: codeVerifier,
		State:        state,
		StateToken:   stateToken,
	})
	if err != nil {
		if errors.Is(err, errOAuthExchangeFailed) {
			s.audit.Log(
				ctx, audit.EventIdentityLinked,
				audit.WithActor(userID),
				audit.WithSuccess(false),
				audit.WithDetails(map[string]any{
					"provider": provider,
					"reason":   "code_exchange_failed",
				}),
			)
			return nil, s.mapOAuthErr(errors.Unwrap(err))
		}
		return nil, err
	}

	if identity.ProviderUserID == "" {
		return nil, fmt.Errorf("%w: provider returned no stable subject", ErrUnauthenticated)
	}

	email := assertedAddress(identity)
	oi := &OAuthIdentity{
		UserID:          userID,
		Provider:        identity.Provider,
		ProviderUserID:  identity.ProviderUserID,
		EmailAtLinkTime: email,
		CreatedAt:       s.nowMs(),
	}
	// The store's uniqueness on (provider, provider_user_id) is the one guard,
	// so concurrent links of one identity, to one account or to several,
	// leave exactly one. A link that already exists — including the caller's
	// own — is reported rather than swallowed, since the user asked for it.
	if err := s.repo(ctx).CreateOAuthIdentity(ctx, oi); err != nil {
		if errors.Is(err, ErrAlreadyExists) {
			return nil, fmt.Errorf("%w: provider identity already linked", ErrAlreadyExists)
		}
		return nil, err
	}
	if !holder.EmailVerified {
		if err := s.withdrawLinkIfAddressProven(ctx, oi); err != nil {
			return nil, err
		}
	}

	s.audit.Log(
		ctx, audit.EventIdentityLinked,
		audit.WithActor(userID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{
			"provider":           identity.Provider,
			"provider_user_id":   identity.ProviderUserID,
			"email_at_link_time": email,
			"source":             "self_service",
		}),
	)
	s.logger.Info(
		"identity_linked",
		zap.String("user_id", userID),
		zap.String("provider", identity.Provider),
	)
	return oi, nil
}

// attachedCredential is a credential a call has just attached to an account
// whose address was unproven when the call began: what withdraws it, and how
// a failure to withdraw it is logged (kind_withdraw_failed,
// kind_recheck_failed) and refused.
type attachedCredential struct {
	kind     string
	refusal  string
	fields   []zap.Field
	withdraw func(context.Context) error
}

// withdrawIfAddressProven withdraws c if the account's address is proven now,
// and reports whether it did. The first proof of an address voids the
// credentials attached before it, listing them once before marking the
// address verified and once after; one attached between the two escapes both
// listings. Reading the account after the attach means either the second
// listing sees the credential or this read sees the proof. A read that fails
// withdraws the credential too, so the call fails closed. An account deleted
// meanwhile takes the credential with it and is ErrNotFound.
func (s *AuthService) withdrawIfAddressProven(ctx context.Context, userID string, c attachedCredential) (bool, error) {
	account, err := s.repo(ctx).GetUser(ctx, userID)
	if err == nil && account != nil && !account.EmailVerified {
		return false, nil
	}
	fields := append([]zap.Field{zap.String("user_id", userID)}, c.fields...)
	if delErr := c.withdraw(ctx); delErr != nil && !errors.Is(delErr, ErrNotFound) {
		s.logger.Error(c.kind+"_withdraw_failed", append(fields, zap.Error(delErr))...)
		return false, fmt.Errorf("%w: %s", ErrUnavailable, c.refusal)
	}
	if err != nil {
		s.logger.Error(c.kind+"_recheck_failed", append(fields, zap.Error(err))...)
		return false, fmt.Errorf("%w: %s", ErrUnavailable, c.refusal)
	}
	if account == nil {
		return false, fmt.Errorf("%w: user not found", ErrNotFound)
	}
	return true, nil
}

// withdrawLinkIfAddressProven deletes a link just added to an account whose
// address was unproven when the call began, if it is proven now: see
// withdrawIfAddressProven.
func (s *AuthService) withdrawLinkIfAddressProven(ctx context.Context, oi *OAuthIdentity) error {
	withdrawn, err := s.withdrawIfAddressProven(ctx, oi.UserID, attachedCredential{
		kind:    "identity_link",
		refusal: "the provider could not be linked",
		fields:  []zap.Field{zap.String("provider", oi.Provider)},
		withdraw: func(ctx context.Context) error {
			return s.repo(ctx).DeleteOAuthIdentity(ctx, oi.UserID, oi.Provider, oi.ProviderUserID)
		},
	})
	if err != nil || !withdrawn {
		return err
	}
	s.audit.Log(
		ctx, audit.EventIdentityLinked,
		audit.WithActor(oi.UserID),
		audit.WithSuccess(false),
		audit.WithDetails(map[string]any{
			"provider":         oi.Provider,
			"provider_user_id": oi.ProviderUserID,
			"reason":           "address_proven_while_linking",
		}),
	)
	return fmt.Errorf("%w: the account's address was proven while linking; sign in again", ErrUnauthenticated)
}

// assertedAddress is the address a provider asserted, as a link records it.
// It is not canonicalized: whether a later proof of the account's address
// keeps the link depends on the spelling the provider proved, and a +tag
// outside Gmail is not the untagged mailbox.
func assertedAddress(identity *oauth.Identity) string {
	return strings.TrimSpace(strings.ToLower(identity.Email))
}
