package connect

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// SignInAnonymously mints a brand-new credential-less account.
//
// The endpoint is unauthenticated by nature — there is nothing to
// authenticate — which makes it the cheapest account-creation surface the
// server has. That is exactly what GATEWAY_ANONYMOUS_REQUIRE_ASSURANCE
// exists for: with it on, a caller must first prove it is a genuine app on
// genuine hardware (or a human-passed web client) before it may mint one.
func (h *IdentityHandler) SignInAnonymously(
	ctx context.Context,
	req *connect.Request[identitypb.SignInAnonymouslyRequest],
) (*connect.Response[identitypb.SignInAnonymouslyResponse], error) {
	if err := h.requireAssurance(ctx, h.anonymousRequireAssurance(), req.Header()); err != nil {
		// requireAssurance returns the bare service sentinel; every caller
		// maps it, or the Connect layer would surface CodeUnknown.
		return nil, toConnectError(err)
	}
	res, err := h.auth.SignInAnonymously(ctx, clientIP(req.Header()), req.Header().Get("User-Agent"))
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identitypb.SignInAnonymouslyResponse{
		User:         userToProto(res.User),
		AccessToken:  res.AccessToken,
		RefreshToken: res.RefreshToken,
		ExpiresIn:    res.ExpiresIn,
	}), nil
}

// UpgradeAnonymousAccount attaches a permanent credential to the CALLING
// anonymous account, preserving its id.
//
// The account comes from the access token, never from the request body:
// there is no user_id field, so one account can never upgrade another.
func (h *IdentityHandler) UpgradeAnonymousAccount(
	ctx context.Context,
	req *connect.Request[identitypb.UpgradeAnonymousAccountRequest],
) (*connect.Response[identitypb.UpgradeAnonymousAccountResponse], error) {
	userID := authenticatedUserID(req.Header())
	if userID == "" {
		return nil, toConnectError(service.ErrUnauthenticated)
	}

	var (
		res *service.LoginResult
		err error
	)
	switch cred := req.Msg.GetCredential().(type) {
	case *identitypb.UpgradeAnonymousAccountRequest_Password:
		res, err = h.auth.UpgradeAnonymousWithPassword(ctx, userID, service.AnonymousPasswordCredential{
			Email:     cred.Password.GetEmail(),
			Password:  cred.Password.GetPassword(),
			Name:      cred.Password.GetName(),
			IPAddress: clientIP(req.Header()),
			UserAgent: req.Header().Get("User-Agent"),
		})
	case *identitypb.UpgradeAnonymousAccountRequest_Oauth:
		res, err = h.auth.UpgradeAnonymousWithOAuth(ctx, userID, service.AnonymousOAuthCredential{
			Provider:     cred.Oauth.GetProvider(),
			Code:         cred.Oauth.GetCode(),
			RedirectURI:  cred.Oauth.GetRedirectUri(),
			CodeVerifier: cred.Oauth.GetCodeVerifier(),
			State:        cred.Oauth.GetState(),
			StateToken:   cred.Oauth.GetStateToken(),
			IPAddress:    clientIP(req.Header()),
			UserAgent:    req.Header().Get("User-Agent"),
		})
	default:
		// A oneof with nothing set. Refused rather than treated as a no-op
		// upgrade, which would clear is_anonymous and leave an account with
		// no credential at all — unreachable AND out of the retention
		// sweep's reach, i.e. a permanent orphan.
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("upgrade requires exactly one credential (password or oauth)"))
	}
	if err != nil {
		return nil, toConnectError(err)
	}
	// The service reissues the pair: the caller's old access token still
	// carries anonymous=true, and without a new one every downstream service
	// would keep treating a now-permanent account as anonymous.
	return connect.NewResponse(&identitypb.UpgradeAnonymousAccountResponse{
		User:         userToProto(res.User),
		AccessToken:  res.AccessToken,
		RefreshToken: res.RefreshToken,
		ExpiresIn:    res.ExpiresIn,
	}), nil
}

// anonymousRequireAssurance nil-checks cfg so requireAssurance's
// short-circuit stays reachable when a test builds a handler without one,
// matching the six per-endpoint enforce accessors.
func (h *IdentityHandler) anonymousRequireAssurance() bool {
	return h.cfg != nil && h.cfg.AnonymousRequireAssurance
}
