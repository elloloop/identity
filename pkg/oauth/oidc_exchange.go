package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// This file is the single home for the OAuth authorization-code → token
// exchange shared by every OIDC-style Exchanger (Google, Microsoft, Apple,
// and the generic OIDC provider). The transport and error-mapping knowledge
// lives here ONCE; each provider file expresses only what is genuinely
// provider-specific (its endpoints, its client authentication, any extra
// request parameters, and its id_token claim rules).

// tokenResponse is the subset of an OAuth token-endpoint response the
// OIDC-style providers consume. Only id_token (verified downstream) and
// access_token (used for a best-effort userinfo fetch) carry meaning;
// Identity never stores provider tokens for ongoing API access, so the
// remaining fields are decoded solely so a provider-signalled error
// (error / error_description) surfaces cleanly.
type tokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// codeExchangeForm builds the RFC 6749 authorization-code grant request body
// shared by every OIDC-style provider: code, client_id, client_secret,
// redirect_uri, grant_type, and the PKCE code_verifier when present. A
// provider that needs additional parameters (e.g. Microsoft's explicit
// `scope`) sets them on the returned form before calling oidcTokenExchange.
func codeExchangeForm(clientID, clientSecret string, params ExchangeParams) url.Values {
	form := url.Values{}
	form.Set("code", params.Code)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("redirect_uri", params.RedirectURI)
	form.Set("grant_type", "authorization_code")
	if params.CodeVerifier != "" {
		form.Set("code_verifier", params.CodeVerifier)
	}
	return form
}

// oidcTokenExchange POSTs an authorization-code grant to the provider's token
// endpoint and returns the parsed token response. It is the single definition
// of the "POST the form, bound-read the body, map HTTP / JSON / provider
// errors, require an id_token" rule shared by the OIDC-style exchangers. The
// caller supplies the fully-built form (each provider owns its own client
// authentication and any extra parameters); this helper owns only the
// transport and error-mapping knowledge. Every failure wraps
// ErrCodeExchangeFailed so callers map any exchange failure to one safe error.
func oidcTokenExchange(ctx context.Context, client *http.Client, tokenURL string, form url.Values) (*tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", ErrCodeExchangeFailed, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCodeExchangeFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %w", ErrCodeExchangeFailed, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: provider HTTP %d", ErrCodeExchangeFailed, resp.StatusCode)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("%w: parse response: %w", ErrCodeExchangeFailed, err)
	}
	if tr.Error != "" {
		return nil, fmt.Errorf("%w: %s", ErrCodeExchangeFailed, tr.Error)
	}
	if tr.IDToken == "" {
		return nil, fmt.Errorf("%w: provider returned no id_token", ErrCodeExchangeFailed)
	}
	return &tr, nil
}
