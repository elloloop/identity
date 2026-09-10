package service

import (
	"context"
	"fmt"
)

// ActionLinkState classifies an emailed action link before it is used. The
// hosted pages render it on GET so a user sees "already used" or "expired"
// before clicking, and nothing is consumed by the look. It is advisory: the
// click is authoritative, and a link that expires between the two renders
// the outcome the click reports.
type ActionLinkState string

const (
	ActionLinkReady   ActionLinkState = "ready"
	ActionLinkInvalid ActionLinkState = "invalid"
	ActionLinkUsed    ActionLinkState = "used"
	ActionLinkExpired ActionLinkState = "expired"
)

// ActionLinkPreview is the pre-click view of an emailed action link: its
// state, and the address the action concerns when the token is known. The
// address lets the page say whose email is being verified or who is about
// to be signed in, so a person handed someone else's link can tell.
type ActionLinkPreview struct {
	State ActionLinkState
	Email string
}

// linkState derives the pre-click state from a token's stamps.
func (s *AuthService) linkState(consumedAt, expiresAt int64) ActionLinkState {
	if consumedAt > 0 {
		return ActionLinkUsed
	}
	if expiresAt > 0 && expiresAt < s.nowMs() {
		return ActionLinkExpired
	}
	return ActionLinkReady
}

// PeekEmailVerification previews an email-verification link without
// consuming it. An unknown token is ActionLinkInvalid, not an error.
func (s *AuthService) PeekEmailVerification(ctx context.Context, token string) (ActionLinkPreview, error) {
	if token == "" {
		return ActionLinkPreview{State: ActionLinkInvalid}, nil
	}
	rec, err := s.repo(ctx).FindEmailVerificationTokenByHash(ctx, sha256Hex(token))
	if err != nil {
		return ActionLinkPreview{}, fmt.Errorf("looking up verification token: %w", err)
	}
	if rec == nil {
		return ActionLinkPreview{State: ActionLinkInvalid}, nil
	}
	return ActionLinkPreview{State: s.linkState(rec.ConsumedAt, rec.ExpiresAt), Email: rec.Email}, nil
}

// PeekPasswordReset previews a password-reset link without consuming it.
// The reset token stores only the user id, so the address comes from the
// account.
func (s *AuthService) PeekPasswordReset(ctx context.Context, token string) (ActionLinkPreview, error) {
	if token == "" {
		return ActionLinkPreview{State: ActionLinkInvalid}, nil
	}
	rec, err := s.repo(ctx).FindPasswordResetTokenByHash(ctx, sha256Hex(token))
	if err != nil {
		return ActionLinkPreview{}, fmt.Errorf("looking up reset token: %w", err)
	}
	if rec == nil {
		return ActionLinkPreview{State: ActionLinkInvalid}, nil
	}
	user, err := s.repo(ctx).GetUser(ctx, rec.UserID)
	if err != nil {
		return ActionLinkPreview{}, fmt.Errorf("fetching user: %w", err)
	}
	if user == nil {
		return ActionLinkPreview{State: ActionLinkInvalid}, nil
	}
	return ActionLinkPreview{State: s.linkState(rec.ConsumedAt, rec.ExpiresAt), Email: user.Email}, nil
}

// PeekEmailChange previews an email-change confirmation link without
// consuming it. The address shown is the NEW one the link confirms.
func (s *AuthService) PeekEmailChange(ctx context.Context, token string) (ActionLinkPreview, error) {
	if token == "" {
		return ActionLinkPreview{State: ActionLinkInvalid}, nil
	}
	rec, err := s.repo(ctx).FindEmailChangeTokenByHash(ctx, sha256Hex(token))
	if err != nil {
		return ActionLinkPreview{}, fmt.Errorf("looking up email change token: %w", err)
	}
	if rec == nil {
		return ActionLinkPreview{State: ActionLinkInvalid}, nil
	}
	return ActionLinkPreview{State: s.linkState(rec.ConsumedAt, rec.ExpiresAt), Email: rec.NewEmail}, nil
}

// PeekMagicLink previews a magic link without consuming it.
func (s *AuthService) PeekMagicLink(ctx context.Context, token string) (ActionLinkPreview, error) {
	if token == "" {
		return ActionLinkPreview{State: ActionLinkInvalid}, nil
	}
	rec, err := s.repo(ctx).FindMagicLinkTokenByHash(ctx, sha256Hex(token))
	if err != nil {
		return ActionLinkPreview{}, fmt.Errorf("looking up magic link token: %w", err)
	}
	if rec == nil {
		return ActionLinkPreview{State: ActionLinkInvalid}, nil
	}
	return ActionLinkPreview{State: s.linkState(rec.ConsumedAt, rec.ExpiresAt), Email: rec.Email}, nil
}

// PeekInvitation previews an invitation link without consuming it. The
// address is the invitee's, taken from the invitation or, for an invitation
// keyed only by user id, from the account it belongs to.
func (s *AuthService) PeekInvitation(ctx context.Context, token string) (ActionLinkPreview, error) {
	if token == "" {
		return ActionLinkPreview{State: ActionLinkInvalid}, nil
	}
	inv, err := s.repo(ctx).FindInvitationByHash(ctx, hashInvitationToken(token))
	if err != nil {
		return ActionLinkPreview{}, fmt.Errorf("looking up invitation: %w", err)
	}
	if inv == nil {
		return ActionLinkPreview{State: ActionLinkInvalid}, nil
	}
	preview := ActionLinkPreview{State: s.linkState(inv.AcceptedAt, inv.ExpiresAt), Email: inv.Email}
	if preview.Email == "" && inv.UserID != "" {
		user, err := s.repo(ctx).GetUser(ctx, inv.UserID)
		if err != nil {
			return ActionLinkPreview{}, fmt.Errorf("fetching invited user: %w", err)
		}
		if user != nil {
			preview.Email = user.Email
		}
	}
	return preview, nil
}

// HostedUIBranding is the product identity the hosted pages render: the
// name used in headings and button copy, and the support address in the
// footer. Resolved per request with the precedence transactional mail
// uses (project config_json branding, then GATEWAY_EMAIL_BRAND_*).
type HostedUIBranding struct {
	ProductName  string
	SupportEmail string
}

// HostedUIBranding resolves the branding the hosted pages render for the
// request's project.
func (s *AuthService) HostedUIBranding(ctx context.Context) HostedUIBranding {
	b := resolveBranding(ctx, s.cfg)
	return HostedUIBranding{ProductName: b.productName, SupportEmail: b.supportEmail}
}
