package app

import (
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	agentOAuthAuthorizePath  = "/oauth/authorize"
	agentOAuthTokenPath      = "/oauth/token" //nolint:gosec // A protocol route, never a credential.
	agentOAuthIntrospectPath = "/oauth/introspect"
	agentOAuthRevokePath     = "/oauth/revoke"
	agentOAuthMetadataPath   = "/.well-known/oauth-authorization-server"
	agentOAuthConsentPath    = "/auth/agent-consent"
	maxAgentOAuthFormBytes   = 65536
)

type (
	agentOAuthProtocol struct {
		op.UnimplementedServer
		service *service.AgentOAuthService
		auth    *service.AuthService
		issuer  string
	}
	nativeOAuthClient struct{ client *service.OAuthClient }
)

func (c nativeOAuthClient) GetID() string                     { return c.client.ID }
func (c nativeOAuthClient) RedirectURIs() []string            { return c.client.Registration.RedirectURIs }
func (nativeOAuthClient) PostLogoutRedirectURIs() []string    { return nil }
func (nativeOAuthClient) ApplicationType() op.ApplicationType { return op.ApplicationTypeNative }
func (nativeOAuthClient) AuthMethod() oidc.AuthMethod         { return oidc.AuthMethodNone }
func (nativeOAuthClient) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

func (c nativeOAuthClient) GrantTypes() []oidc.GrantType {
	out := make([]oidc.GrantType, 0, len(c.client.Registration.GrantTypes))
	for _, g := range c.client.Registration.GrantTypes {
		out = append(out, oidc.GrantType(g))
	}
	return out
}
func (nativeOAuthClient) LoginURL(string) string              { return agentOAuthConsentPath }
func (nativeOAuthClient) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeJWT }
func (nativeOAuthClient) IDTokenLifetime() time.Duration      { return 0 }
func (nativeOAuthClient) DevMode() bool                       { return false }

//nolint:revive // The external op.Client interface fixes this spelling.
func (nativeOAuthClient) RestrictAdditionalIdTokenScopes() func([]string) []string { return nil }

func (nativeOAuthClient) RestrictAdditionalAccessTokenScopes() func([]string) []string { return nil }

func (c nativeOAuthClient) IsScopeAllowed(scope string) bool {
	for _, resource := range c.client.Registration.Resources {
		if slices.Contains(resource.Scopes, scope) {
			return true
		}
	}
	return false
}
func (nativeOAuthClient) IDTokenUserinfoClaimsAssertion() bool { return false }
func (nativeOAuthClient) ClockSkew() time.Duration             { return 0 }

func (p *agentOAuthProtocol) VerifyAuthRequest(ctx context.Context, r *op.Request[oidc.AuthRequest]) (*op.ClientRequest[oidc.AuthRequest], error) {
	raw := r.Form
	if raw.Get("response_type") != "code" || raw.Get("code_challenge_method") != "S256" || !service.ValidS256Challenge(raw.Get("code_challenge")) || raw.Get("state") == "" {
		return nil, oidc.ErrInvalidRequest()
	}
	client, err := p.auth.OAuthProtocolClient(ctx, raw.Get("client_id"))
	if err != nil {
		return nil, oauthProtocolError(err)
	}
	scopes := strings.Split(raw.Get("scope"), " ")
	if slices.Contains(scopes, "openid") {
		return nil, oidc.ErrInvalidScope()
	}
	if err = client.ValidateOAuthRequest(raw.Get("redirect_uri"), raw.Get("resource"), scopes, service.OAuthGrantAuthorizationCode); err != nil {
		return nil, oidc.ErrInvalidRequestRedirectURI()
	}
	// Original raw bounds are validated before the library can normalize scopes.
	return &op.ClientRequest[oidc.AuthRequest]{Request: r, Client: nativeOAuthClient{client: client}}, nil
}

func (p *agentOAuthProtocol) Authorize(ctx context.Context, r *op.ClientRequest[oidc.AuthRequest]) (*op.Redirect, error) {
	request, err := p.service.Start(ctx, service.AgentOAuthStart{ClientID: r.Form.Get("client_id"), RedirectURI: r.Form.Get("redirect_uri"), Resource: r.Form.Get("resource"), Scopes: strings.Split(r.Form.Get("scope"), " "), Challenge: r.Form.Get("code_challenge"), State: r.Form.Get("state")})
	if err != nil {
		return nil, op.NewStatusError(oauthProtocolError(err), http.StatusBadRequest)
	}
	params := url.Values{"request_id": []string{request.ID}}
	if key := r.Form.Get("project_key"); key != "" {
		params.Set("project_key", key)
	}
	return op.NewRedirect(p.issuer + agentOAuthConsentPath + "?" + params.Encode()), nil
}

func (p *agentOAuthProtocol) VerifyClient(ctx context.Context, r *op.Request[op.ClientCredentials]) (op.Client, error) {
	if r.Data.ClientSecret != "" || r.Data.ClientAssertion != "" || r.Data.ClientAssertionType != "" || r.Header.Get("Authorization") != "" {
		return nil, oidc.ErrInvalidClient()
	}
	client, err := p.auth.OAuthProtocolClient(ctx, r.Data.ClientID)
	if err != nil {
		return nil, oidc.ErrInvalidClient()
	}
	return nativeOAuthClient{client: client}, nil
}

func oauthProtocolError(err error) error {
	switch {
	case errors.Is(err, service.ErrAgentOAuthGrant), errors.Is(err, service.ErrAgentOAuthRevision), errors.Is(err, service.ErrAccountNotActive), errors.Is(err, service.ErrEmailVerificationRequired), errors.Is(err, service.ErrIDVRequired), errors.Is(err, service.ErrDOBRequired), errors.Is(err, service.ErrAccessNotAllowed), errors.Is(err, service.ErrProductAgeRestricted):
		return oidc.ErrInvalidGrant()
	case errors.Is(err, service.ErrInvalidArgument):
		return oidc.ErrInvalidRequest()
	case errors.Is(err, service.ErrPermissionDenied):
		return oidc.ErrUnauthorizedClient()
	default:
		return oidc.ErrServerError()
	}
}

func oauthTokenResponse(tokens *service.AgentOAuthTokens) *op.Response {
	return op.NewResponse(&oidc.AccessTokenResponse{AccessToken: tokens.AccessToken, TokenType: "Bearer", RefreshToken: tokens.RefreshToken, ExpiresIn: tokens.ExpiresIn, Scope: oidc.SpaceDelimitedArray(strings.Split(tokens.Scope, " "))})
}

func (p *agentOAuthProtocol) CodeExchange(ctx context.Context, r *op.ClientRequest[oidc.AccessTokenRequest]) (*op.Response, error) {
	tokens, err := p.service.Redeem(ctx, r.Client.GetID(), r.Data.RedirectURI, r.Form.Get("resource"), r.Data.Code, r.Data.CodeVerifier)
	if err != nil {
		return nil, oauthProtocolError(err)
	}
	return oauthTokenResponse(tokens), nil
}

func (p *agentOAuthProtocol) RefreshToken(ctx context.Context, r *op.ClientRequest[oidc.RefreshTokenRequest]) (*op.Response, error) {
	tokens, err := p.service.Refresh(ctx, r.Client.GetID(), r.Form.Get("resource"), r.Data.RefreshToken, r.Form.Get("scope"))
	if err != nil {
		return nil, oauthProtocolError(err)
	}
	return oauthTokenResponse(tokens), nil
}

func (p *agentOAuthProtocol) Introspect(ctx context.Context, r *op.Request[op.IntrospectionRequest]) (*op.Response, error) {
	resource, err := p.service.AuthenticateResource(ctx, r.Data.ClientID, r.Data.ClientSecret)
	if err != nil {
		return nil, op.NewStatusError(oidc.ErrInvalidClient(), http.StatusUnauthorized)
	}
	result, err := p.service.Introspect(ctx, resource, r.Data.Token)
	if err != nil {
		return nil, oidc.ErrServerError()
	}
	return op.NewResponse(result), nil
}

func (p *agentOAuthProtocol) Revocation(ctx context.Context, r *op.ClientRequest[oidc.RevocationRequest]) (*op.Response, error) {
	if hint := r.Form.Get("token_type_hint"); hint != "" && hint != "refresh_token" {
		return nil, &oidc.Error{ErrorType: "unsupported_token_type"}
	}
	if err := p.service.RevokeToken(ctx, r.Client.GetID(), r.Data.Token); err != nil {
		return nil, oauthProtocolError(err)
	}
	return op.NewResponse(struct{}{}), nil
}

func (p *agentOAuthProtocol) metadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"issuer": p.issuer, "authorization_endpoint": p.issuer + agentOAuthAuthorizePath, "token_endpoint": p.issuer + agentOAuthTokenPath, "introspection_endpoint": p.issuer + agentOAuthIntrospectPath, "revocation_endpoint": p.issuer + agentOAuthRevokePath, "jwks_uri": p.issuer + "/.well-known/jwks.json", "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"none"}, "introspection_endpoint_auth_methods_supported": []string{"client_secret_basic"}, "revocation_endpoint_auth_methods_supported": []string{"none"}, "authorization_response_iss_parameter_supported": true})
}

func strictOAuthForm(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		if len(r.URL.RawQuery) > maxAgentOAuthFormBytes || len(r.Header.Values("Authorization")) > 1 {
			http.Error(w, "invalid_request", http.StatusBadRequest)
			return
		}
		allowed := map[string]bool{}
		var fields []string
		if r.URL.Path == agentOAuthAuthorizePath {
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", "GET")
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if r.ContentLength > 0 {
				http.Error(w, "invalid_request", http.StatusBadRequest)
				return
			}
			fields = []string{"client_id", "redirect_uri", "response_type", "scope", "resource", "code_challenge", "code_challenge_method", "state", "project_key"}
		} else {
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", "POST")
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || media != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
				http.Error(w, "invalid_request", http.StatusBadRequest)
				return
			}
			switch r.URL.Path {
			case agentOAuthTokenPath:
				fields = []string{"grant_type", "client_id", "code", "redirect_uri", "code_verifier", "resource", "refresh_token", "scope"}
			case agentOAuthIntrospectPath:
				fields = []string{"token", "token_type_hint"}
				if _, _, ok := r.BasicAuth(); !ok {
					w.Header().Set("WWW-Authenticate", `Basic realm="oauth-resource"`)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
			case agentOAuthRevokePath:
				fields = []string{"client_id", "token", "token_type_hint"}
			default:
				http.NotFound(w, r)
				return
			}
		}
		for _, key := range fields {
			allowed[key] = true
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxAgentOAuthFormBytes)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid_request", http.StatusBadRequest)
			return
		}
		for key, values := range r.Form {
			if !allowed[key] || len(values) != 1 {
				http.Error(w, "invalid_request", http.StatusBadRequest)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Run before project resolution, whose hosted OAuth parser otherwise reads the
// form first and would prevent a later body reader from enforcing this bound.
func agentOAuthRequestBounds(cfg *config.Config, next http.Handler) http.Handler {
	if !cfg.AgentOAuthEnabled {
		return next
	}
	bounded := strictOAuthForm(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case agentOAuthAuthorizePath, agentOAuthTokenPath, agentOAuthIntrospectPath, agentOAuthRevokePath:
			bounded.ServeHTTP(w, r)
		default:
			next.ServeHTTP(w, r)
		}
	})
}

func (p *agentOAuthProtocol) authenticateIntrospection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == agentOAuthIntrospectPath && r.Method == http.MethodPost {
			id, secret, present := r.BasicAuth()
			id, idErr := url.QueryUnescape(id)
			secret, secretErr := url.QueryUnescape(secret)
			_, err := p.service.AuthenticateResource(r.Context(), id, secret)
			if !present || idErr != nil || secretErr != nil || err != nil {
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("WWW-Authenticate", `Basic realm="oauth-resource"`)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (p *agentOAuthProtocol) register(mux *http.ServeMux) {
	endpoints := op.Endpoints{Authorization: op.NewEndpoint(agentOAuthAuthorizePath), Token: op.NewEndpoint(agentOAuthTokenPath), Introspection: op.NewEndpoint(agentOAuthIntrospectPath), Revocation: op.NewEndpoint(agentOAuthRevokePath)}
	protocol := p.authenticateIntrospection(op.RegisterServer(p, endpoints, op.WithServerCORSOptions(nil)))
	for _, path := range []string{agentOAuthAuthorizePath, agentOAuthTokenPath, agentOAuthIntrospectPath, agentOAuthRevokePath} {
		mux.Handle(path, protocol)
	}
	mux.HandleFunc(agentOAuthMetadataPath, p.metadata)
}

func sweepAgentOAuth(ctx context.Context, base service.Repository, projects service.ProjectLister, defaultProject string, beforeMs int64, limit int) error {
	ids := []string{defaultProject}
	if projects != nil {
		var err error
		ids, err = projects.ListProjectIDs(ctx)
		if err != nil {
			return err
		}
	}
	for _, id := range ids {
		store, ok := base.WithProject(id).(service.AgentOAuthRepository)
		if !ok {
			return service.ErrServiceUnavailable
		}
		if err := store.DeleteExpiredAgentAuthorizations(ctx, beforeMs, limit); err != nil {
			return err
		}
	}
	return nil
}
