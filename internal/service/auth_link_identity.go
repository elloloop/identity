package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
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
	return s.linkIdentityUnguarded(ctx, userID, code, provider, redirectURI, codeVerifier, state, stateToken)
}

// linkIdentityUnguarded is LinkIdentity without the anonymous refusal, for
// the anonymous-upgrade path which legitimately attaches a provider to an
// anonymous account and promotes it in the same operation.
func (s *AuthService) linkIdentityUnguarded(
	ctx context.Context,
	userID, code, provider, redirectURI, codeVerifier, state, stateToken string,
) (*OAuthIdentity, error) {
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

	// Reject linking a provider identity that already belongs to someone —
	// including the caller. A duplicate link is not silently swallowed here
	// (unlike the best-effort login path) because the user explicitly asked
	// to connect it and deserves to know it is already connected.
	existing, err := s.repo(ctx).FindUserByProviderID(ctx, identity.Provider, identity.ProviderUserID)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, fmt.Errorf("%w: provider identity already linked", ErrAlreadyExists)
	}

	email := strings.TrimSpace(strings.ToLower(identity.Email))
	oi := &OAuthIdentity{
		UserID:          userID,
		Provider:        identity.Provider,
		ProviderUserID:  identity.ProviderUserID,
		EmailAtLinkTime: email,
		CreatedAt:       s.nowMs(),
	}
	if err := s.repo(ctx).CreateOAuthIdentity(ctx, oi); err != nil {
		// A racing create that beat us to the unique (provider, sub) pair.
		return nil, fmt.Errorf("%w: provider identity already linked", ErrAlreadyExists)
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
