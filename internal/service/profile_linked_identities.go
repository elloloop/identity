package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/elloloop/identity/pkg/audit"
)

// ListLinkedIdentities returns the authenticated user's connected provider
// identities (the (provider, provider_user_id) links), oldest first. It is a
// read-only self-service view backing a "connected accounts" surface.
func (s *ProfileService) ListLinkedIdentities(ctx context.Context, userID string) ([]*OAuthIdentity, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("%w: user_id is required", ErrInvalidArgument)
	}
	repo := s.repo(ctx)
	if repo == nil {
		return nil, ErrServiceUnavailable
	}
	return repo.ListOAuthIdentitiesForUser(ctx, userID)
}

// UnlinkIdentity disconnects a provider identity from the authenticated user.
//
// It refuses to remove the user's LAST remaining sign-in credential: if the
// user has no password and no passkey, the final linked provider cannot be
// removed (ErrLastCredential), so a self-service unlink can never lock a user
// out of their own account. The check counts what would remain AFTER the
// removal, using the link the caller asked to drop, so removing a non-final
// link is always allowed.
func (s *ProfileService) UnlinkIdentity(ctx context.Context, userID, provider, providerUserID string) error {
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("%w: user_id is required", ErrInvalidArgument)
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	providerUserID = strings.TrimSpace(providerUserID)
	if provider == "" || providerUserID == "" {
		return fmt.Errorf("%w: provider and provider_user_id are required", ErrInvalidArgument)
	}

	repo := s.repo(ctx)
	if repo == nil {
		return ErrServiceUnavailable
	}

	links, err := repo.ListOAuthIdentitiesForUser(ctx, userID)
	if err != nil {
		return err
	}
	// Confirm the target link exists for THIS user before touching credential
	// state, so a non-existent link reports ErrNotFound rather than masquerading
	// as a last-credential precondition failure.
	found := false
	remainingLinks := 0
	for _, l := range links {
		if l.Provider == provider && l.ProviderUserID == providerUserID {
			found = true
			continue
		}
		remainingLinks++
	}
	if !found {
		return ErrNotFound
	}

	// Last-credential protection: if removing this link would leave the user
	// with no other sign-in credential, refuse. Other credentials are: any
	// remaining provider link, a password, or a passkey.
	if remainingLinks == 0 {
		hasPassword, err := s.userHasPassword(ctx, userID)
		if err != nil {
			return err
		}
		if !hasPassword {
			passkeys, err := s.ListMyPasskeys(ctx, userID)
			if err != nil {
				return err
			}
			if len(passkeys) == 0 {
				return ErrLastCredential
			}
		}
	}

	if err := repo.DeleteOAuthIdentity(ctx, userID, provider, providerUserID); err != nil {
		return err
	}

	s.audit.Log(
		ctx, audit.EventIdentityUnlinked,
		audit.WithActor(userID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{
			"provider":         provider,
			"provider_user_id": providerUserID,
		}),
	)
	return nil
}

// userHasPassword reports whether the user has a local password set. It reads
// through the Repository (which every backend implements fully) rather than
// the low-level DB node, mirroring UpdateProfile.
func (s *ProfileService) userHasPassword(ctx context.Context, userID string) (bool, error) {
	user, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return false, err
	}
	if user == nil {
		return false, ErrNotFound
	}
	return strings.TrimSpace(user.PasswordHash) != "", nil
}
