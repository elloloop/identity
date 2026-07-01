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

// NativeIDTokenVerifier verifies a native mobile-SDK ID token (Google idToken /
// Apple identityToken) server-side — signature, issuer, expiry, audience, and,
// for Apple, the nonce — returning the provider-asserted identity. It is the
// seam NativeOAuthLogin depends on instead of the concrete *oauth.NativeVerifier
// so the login flow's verification-result branches (an unverified provider
// email, a provider that returns no email) are testable without minting signed
// JWTs against a live JWKS endpoint. *oauth.NativeVerifier satisfies it.
type NativeIDTokenVerifier interface {
	Verify(ctx context.Context, provider, idToken, rawNonce, product string) (*oauth.NativeVerification, error)
}

// NativeOAuthProjectStore is the narrow control-plane lookup NativeOAuthLogin
// uses to confirm that a product→project id names a real, ACTIVE project
// before token issuance is scoped to it. It delegates to the postgres
// control-plane ProjectStore.GetProjectByID; drivers without a control plane
// inject nil and native login pins to the configured default project. A clean
// miss (no such project, or a suspended one) returns (nil, nil); only an
// infrastructure failure returns a non-nil error.
type NativeOAuthProjectStore interface {
	ActiveProjectByID(ctx context.Context, projectID string) (*AdminProject, error)
}

// NativeOAuthLoginParams are the inputs to NativeOAuthLogin. IDToken is the
// JWT a native SDK returned (Google idToken / Apple identityToken); Nonce is
// the RAW Apple nonce (empty for Google).
type NativeOAuthLoginParams struct {
	Provider  string
	IDToken   string
	Product   string
	Nonce     string
	IPAddr    string
	UserAgent string
}

// NativeOAuthLogin verifies a native mobile-SDK ID token, resolves the
// product to a project, scopes the request to it, then reuses the SAME social
// account-linking + token-issuance path as the hosted OAuthLogin.
//
// The flow is, in order: gate on the enabled flag → verify the ID token
// server-side (signature, issuer, expiry, the requested product's audience set,
// and — for Apple — the nonce) → resolve product→project and inject a
// ProjectScope → match
// (provider, sub) then email, creating the user if new → issue the token pair.
// It carries the same enumeration-safety and verified-email posture as
// OAuthLogin: a provider-verified identity proves email control, so the user
// is upserted with email_verified=true and any planted credentials are cleared.
func (s *AuthService) NativeOAuthLogin(ctx context.Context, params NativeOAuthLoginParams) (*LoginResult, error) {
	if !s.cfg.NativeOAuthEnabled || s.nativeVerifier == nil {
		return nil, fmt.Errorf("%w", ErrNativeOAuthDisabled)
	}

	provider := strings.ToLower(strings.TrimSpace(params.Provider))
	switch provider {
	case "google", "apple":
	default:
		return nil, fmt.Errorf("%w: unsupported provider %q", ErrInvalidArgument, provider)
	}
	if strings.TrimSpace(params.IDToken) == "" {
		return nil, fmt.Errorf("%w: missing id_token", ErrInvalidArgument)
	}

	// Scope the `aud` check to the requested product so a token minted for
	// another product's OAuth client id is rejected here — before any project
	// resolution or token issuance — even if its `aud` is valid globally.
	verified, err := s.nativeVerifier.Verify(ctx, provider, params.IDToken, params.Nonce, params.Product)
	if err != nil {
		s.logger.Info("native_oauth_login_failed",
			zap.String("provider", provider), zap.Error(err))
		s.audit.Log(
			ctx, audit.EventOAuthLogin,
			audit.WithIP(params.IPAddr), audit.WithUserAgent(params.UserAgent),
			audit.WithSuccess(false),
			audit.WithDetails(map[string]any{
				"provider": provider,
				"native":   true,
				"reason":   "token_verification_failed",
			}),
		)
		return nil, s.mapOAuthErr(err)
	}
	identity := verified.Identity

	// Resolve the product to a project and scope the rest of the call to it so
	// linking + token issuance write under the product's project, independent
	// of the request Host (native calls carry none).
	scope, err := s.resolveNativeProject(ctx, params.Product)
	if err != nil {
		return nil, err
	}
	ctx = WithProjectScope(ctx, scope)

	// Replay protection: a native ID token is a bearer JWT valid until its
	// `exp`, so a captured token could be redeemed more than once. Record the
	// token's replay key BEFORE issuing any session; the first redemption
	// wins, a second presentation of the SAME token hits the unique index and
	// is rejected as Unauthenticated. Scoped to the resolved project (the
	// token is bound to the product's OAuth client id), mirroring every other
	// ephemeral auth artifact.
	if err := s.recordNativeRedemption(ctx, verified); err != nil {
		if errors.Is(err, ErrNativeTokenReplayed) {
			s.logger.Info("native_oauth_login_replay",
				zap.String("provider", provider))
			s.audit.Log(
				ctx, audit.EventOAuthLogin,
				audit.WithIP(params.IPAddr), audit.WithUserAgent(params.UserAgent),
				audit.WithSuccess(false),
				audit.WithDetails(map[string]any{
					"provider": provider,
					"native":   true,
					"reason":   "token_replay",
				}),
			)
			return nil, fmt.Errorf("%w", ErrUnauthenticated)
		}
		return nil, err
	}

	email := strings.ToLower(strings.TrimSpace(identity.Email))
	if email == "" {
		return nil, fmt.Errorf("%w: provider returned no email", ErrUnauthenticated)
	}

	user, isNew, err := s.upsertOAuthUser(ctx, identity, email)
	if err != nil {
		return nil, err
	}
	if err := s.checkAccountStatus(ctx, user, params.IPAddr, params.UserAgent); err != nil {
		return nil, err
	}

	decision, err := s.enforceLoginPolicy(ctx, user.Email, LoginMethodOAuth)
	if err != nil {
		return nil, err
	}
	if user.TotpRequired || decision.RequireSecondFactor {
		return s.requireSecondFactor(ctx, user, decision.RequireSecondFactor)
	}

	s.updateLastLogin(ctx, user.ID)
	s.logger.Info(
		"native_oauth_login_success",
		zap.String("email", redactEmail(email)),
		zap.String("provider", provider),
		zap.String("project", scope.ProjectID),
		zap.String("user_id", user.ID),
	)

	accessToken, refreshToken, err := s.issueTokens(ctx, user, params.IPAddr, params.UserAgent)
	if err != nil {
		return nil, err
	}

	s.audit.Log(
		ctx, audit.EventOAuthLogin,
		audit.WithActor(user.ID), audit.WithIP(params.IPAddr), audit.WithUserAgent(params.UserAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{
			"provider": provider,
			"native":   true,
			"email":    email,
			"new_user": isNew,
			"project":  scope.ProjectID,
		}),
	)

	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}

// recordNativeRedemption records the verified token's replay key so the same
// bearer token cannot be redeemed twice. A verification with no replay key
// (only the fake verifier used in tests can produce that) skips the write —
// the concrete verifier always derives one. Returns ErrNativeTokenReplayed
// when the key was already recorded (a replay), else any infrastructure error.
func (s *AuthService) recordNativeRedemption(ctx context.Context, verified *oauth.NativeVerification) error {
	if verified.ReplayKey == "" {
		return nil
	}
	_, err := s.repo(ctx).RecordNativeTokenRedemption(ctx, &NativeTokenRedemptionRecord{
		ReplayKey: verified.ReplayKey,
		ExpiresAt: verified.ExpiresAtMs,
		CreatedAt: s.nowMs(),
	})
	return err
}

// resolveNativeProject maps a native client's product selector to the
// ProjectScope token issuance is bound to. Resolution:
//
//  1. look the product up (case-insensitively) in
//     GATEWAY_NATIVE_OAUTH_PRODUCT_PROJECTS; if mapped, use the mapped project
//     id, else treat the ORIGINAL (trimmed, case-preserved) product string AS
//     a project id — project ids are case-sensitive, so the fallback must not
//     lower-case;
//  2. with a control plane (postgres), require that project to exist and be
//     active (ProjectStore.GetProjectByID via ActiveProjectByID); an unknown
//     project is InvalidArgument;
//  3. without a control plane (memory), accept only the product that resolves
//     to cfg.DefaultProjectID — there is no other project to scope to.
//
// An empty or unresolvable product is ErrInvalidArgument.
func (s *AuthService) resolveNativeProject(ctx context.Context, product string) (*ProjectScope, error) {
	product = strings.TrimSpace(product)
	if product == "" {
		return nil, fmt.Errorf("%w: missing product", ErrInvalidArgument)
	}

	// The map key is case-insensitive (keys are stored lower-cased), but the
	// fallback project id is the verbatim product — a project id may be
	// mixed-case, and lower-casing it would never match an upper-case id.
	projectID := product
	if mapped, ok := s.nativeProductProjects[strings.ToLower(product)]; ok {
		projectID = mapped
	}

	if s.nativeProjects != nil {
		p, err := s.nativeProjects.ActiveProjectByID(ctx, projectID)
		if err != nil {
			// An infrastructure failure must not be reported as a client error;
			// surface it so the handler maps it to Internal.
			return nil, fmt.Errorf("resolve native project: %w", err)
		}
		if p == nil {
			return nil, fmt.Errorf("%w: unknown product %q", ErrInvalidArgument, product)
		}
		return &ProjectScope{ProjectID: p.ID, StorageScopeID: p.StorageScopeID}, nil
	}

	// No control plane: only the default project exists.
	if projectID != s.cfg.DefaultProjectID {
		return nil, fmt.Errorf("%w: unknown product %q", ErrInvalidArgument, product)
	}
	return &ProjectScope{ProjectID: projectID, StorageScopeID: s.cfg.DefaultTenantID}, nil
}
