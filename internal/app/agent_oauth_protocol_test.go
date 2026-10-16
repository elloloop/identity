package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
	"github.com/stretchr/testify/require"
)

func TestAgentOAuthDiscoveryAdvertisesOnlySupportedNativeProtocol(t *testing.T) {
	f := newAgentOAuthHTTPFixture(t)
	response, err := f.server.Client().Get(f.server.URL + agentOAuthMetadataPath)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
	var metadata map[string]any
	require.NoError(t, json.NewDecoder(response.Body).Decode(&metadata))
	for name, path := range map[string]string{
		"authorization_endpoint": agentOAuthAuthorizePath,
		"token_endpoint":         agentOAuthTokenPath,
		"introspection_endpoint": agentOAuthIntrospectPath,
		"revocation_endpoint":    agentOAuthRevokePath,
		"jwks_uri":               "/.well-known/jwks.json",
	} {
		require.Equal(t, f.cfg.JWTIssuer+path, metadata[name])
	}
	require.Equal(t, f.cfg.JWTIssuer, metadata["issuer"])
	require.Equal(t, []any{"code"}, metadata["response_types_supported"])
	require.Equal(t, []any{"authorization_code", "refresh_token"}, metadata["grant_types_supported"])
	require.Equal(t, []any{"S256"}, metadata["code_challenge_methods_supported"])
	require.Equal(t, []any{"none"}, metadata["token_endpoint_auth_methods_supported"])
	require.Equal(t, []any{"client_secret_basic"}, metadata["introspection_endpoint_auth_methods_supported"])
	require.Equal(t, true, metadata["authorization_response_iss_parameter_supported"])
	require.NotContains(t, metadata, "userinfo_endpoint")
	require.NotContains(t, metadata, "id_token_signing_alg_values_supported")
	req, err := http.NewRequest(http.MethodPost, f.server.URL+agentOAuthMetadataPath, nil)
	require.NoError(t, err)
	refused, err := f.server.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = refused.Body.Close() }()
	require.Equal(t, http.StatusMethodNotAllowed, refused.StatusCode)
	require.Equal(t, "GET", refused.Header.Get("Allow"))
}

func issueProtocolDelegation(t *testing.T, f *agentOAuthHTTPFixture) (string, string) {
	t.Helper()
	id, verifier := f.start(t)
	code := f.approve(t, id, f.consent(t, id).Revision)
	status, tokens := f.post(t, agentOAuthTokenPath, f.exchangeForm(code, verifier), false)
	require.Equal(t, http.StatusOK, status)
	access, ok := tokens["access_token"].(string)
	require.True(t, ok)
	refresh, ok := tokens["refresh_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, access)
	require.NotEmpty(t, refresh)
	return access, refresh
}

func TestAgentOAuthRevocationUsesOriginalClientAndTerminalRefreshFamily(t *testing.T) {
	f := newAgentOAuthHTTPFixture(t)
	access, refresh := issueProtocolDelegation(t, f)
	form := url.Values{"client_id": {f.clientID}, "token": {refresh}, "token_type_hint": {"access_token"}}
	status, refusal := f.post(t, agentOAuthRevokePath, form, false)
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "unsupported_token_type", refusal["error"])
	_, active := f.post(t, agentOAuthIntrospectPath, url.Values{"token": {access}}, true)
	require.Equal(t, true, active["active"], "unsupported revocation must not mutate the family")
	client, err := f.repo.GetOAuthClient(t.Context(), f.clientID)
	require.NoError(t, err)
	other := client.Clone()
	other.ID = "other-native-client"
	require.NoError(t, f.repo.CreateOAuthClient(t.Context(), other))
	form.Set("client_id", other.ID)
	form.Set("token_type_hint", "refresh_token")
	status, _ = f.post(t, agentOAuthRevokePath, form, false)
	require.Equal(t, http.StatusOK, status)
	_, active = f.post(t, agentOAuthIntrospectPath, url.Values{"token": {access}}, true)
	require.Equal(t, true, active["active"], "another registered client cannot revoke this family")
	form.Set("client_id", f.clientID)
	form.Set("token", "unknown-synthetic-refresh")
	status, _ = f.post(t, agentOAuthRevokePath, form, false)
	require.Equal(t, http.StatusOK, status, "unknown refresh does not disclose existence")
	form.Set("token", refresh)
	status, _ = f.post(t, agentOAuthRevokePath, form, false)
	require.Equal(t, http.StatusOK, status)
	_, inactive := f.post(t, agentOAuthIntrospectPath, url.Values{"token": {access}}, true)
	require.Equal(t, map[string]any{"active": false}, inactive)
	status, refusal = f.post(t, agentOAuthTokenPath, url.Values{"grant_type": {"refresh_token"}, "client_id": {f.clientID}, "resource": {testAgentResource}, "refresh_token": {refresh}}, false)
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "invalid_grant", refusal["error"])
}

func TestAgentOAuthDenyIsTerminalAndReturnsOriginalStateWithoutCode(t *testing.T) {
	f := newAgentOAuthHTTPFixture(t)
	id, _ := f.start(t)
	view := f.consent(t, id)
	request := connect.NewRequest(&identitypb.DecideAgentAuthorizationRequest{
		RequestId: id, ExpectedRevision: view.Revision,
		Decision: identitypb.AgentAuthorizationDecision_AGENT_AUTHORIZATION_DECISION_DENY,
	})
	request.Header().Set("Authorization", "Bearer "+f.token)
	response, err := f.client.DecideAgentAuthorization(t.Context(), request)
	require.NoError(t, err)
	callback, err := url.Parse(response.Msg.RedirectUri)
	require.NoError(t, err)
	require.Equal(t, "caller-state", callback.Query().Get("state"))
	require.Equal(t, f.cfg.JWTIssuer, callback.Query().Get("iss"))
	require.Equal(t, "access_denied", callback.Query().Get("error"))
	require.False(t, callback.Query().Has("code"))
	_, err = f.client.DecideAgentAuthorization(t.Context(), request)
	require.Equal(t, connect.CodeAborted, connect.CodeOf(err))
	stored, err := f.repo.(service.AgentOAuthRepository).GetAgentAuthorization(t.Context(), id)
	require.NoError(t, err)
	require.Equal(t, service.AgentAuthorizationDenied, stored.Decision)
	require.Empty(t, stored.CodeHash)
	require.Empty(t, stored.AgentID)
}

func TestAgentOAuthRefusesUnregisteredRequestsWithoutRedirecting(t *testing.T) {
	f := newAgentOAuthHTTPFixture(t)
	challenge := sha256.Sum256([]byte(strings.Repeat("v", 64)))
	base := url.Values{"response_type": {"code"}, "client_id": {f.clientID}, "redirect_uri": {"http://127.0.0.1:31821/callback"}, "resource": {testAgentResource}, "scope": {"files:read"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "state": {"synthetic-state"}}
	for name, mutate := range map[string]func(url.Values){
		"missing state":         func(v url.Values) { v.Del("state") },
		"plain challenge":       func(v url.Values) { v.Set("code_challenge_method", "plain") },
		"unknown client":        func(v url.Values) { v.Set("client_id", "absent-client") },
		"unregistered redirect": func(v url.Values) { v.Set("redirect_uri", "https://other.example.test/callback") },
		"unregistered scope":    func(v url.Values) { v.Set("scope", "files:write") },
	} {
		t.Run(name, func(t *testing.T) {
			query, err := url.ParseQuery(base.Encode())
			require.NoError(t, err)
			mutate(query)
			response, err := f.server.Client().Get(f.server.URL + agentOAuthAuthorizePath + "?" + query.Encode())
			require.NoError(t, err)
			defer func() { _ = response.Body.Close() }()
			require.Equal(t, http.StatusBadRequest, response.StatusCode)
			require.Empty(t, response.Header.Get("Location"))
		})
	}
}

func TestAgentOAuthPublicClientRejectsBasicSecretAndUnknownClient(t *testing.T) {
	f := newAgentOAuthHTTPFixture(t)
	id, verifier := f.start(t)
	code := f.approve(t, id, f.consent(t, id).Revision)
	for _, basic := range []bool{false, true} {
		form := f.exchangeForm(code, verifier)
		if !basic {
			form.Set("client_id", "unknown-client")
		}
		request, err := http.NewRequest(http.MethodPost, f.server.URL+agentOAuthTokenPath, strings.NewReader(form.Encode()))
		require.NoError(t, err)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if basic {
			request.SetBasicAuth(f.clientID, "synthetic-secret")
		}
		response, err := f.server.Client().Do(request)
		require.NoError(t, err)
		var failure map[string]any
		require.NoError(t, json.NewDecoder(response.Body).Decode(&failure))
		require.NoError(t, response.Body.Close())
		require.Equal(t, "invalid_client", failure["error"])
		require.NotEqual(t, http.StatusOK, response.StatusCode)
	}
	status, _ := f.post(t, agentOAuthTokenPath, f.exchangeForm(code, verifier), false)
	require.Equal(t, http.StatusOK, status, "rejected client authentication must not consume the code")
}

func TestAgentOAuthMalformedTransportCannotReachAuthorization(t *testing.T) {
	f := newAgentOAuthHTTPFixture(t)
	for _, tc := range []struct {
		path, body string
		doubleAuth bool
	}{
		{agentOAuthAuthorizePath + "?state=" + strings.Repeat("x", maxAgentOAuthFormBytes), "", false},
		{agentOAuthAuthorizePath, "state=body-is-not-an-authorization-query", false},
		{agentOAuthTokenPath, "grant_type=authorization_code", true},
	} {
		method := http.MethodGet
		if tc.doubleAuth {
			method = http.MethodPost
		}
		request, err := http.NewRequest(method, f.server.URL+tc.path, strings.NewReader(tc.body))
		require.NoError(t, err)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if tc.doubleAuth {
			request.Header.Add("Authorization", "Basic first")
			request.Header.Add("Authorization", "Basic second")
		}
		response, err := f.server.Client().Do(request)
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Equal(t, http.StatusBadRequest, response.StatusCode, string(body))
		require.Empty(t, response.Header.Get("Location"))
	}
}

func TestAgentOAuthRegisteredButUnconfiguredResourceCannotStart(t *testing.T) {
	f := newAgentOAuthHTTPFixture(t)
	client, err := f.repo.GetOAuthClient(context.Background(), f.clientID)
	require.NoError(t, err)
	client.Registration.Resources[0].Resource = "https://unconfigured.example.test"
	_, err = f.repo.UpdateOAuthClient(t.Context(), f.clientID, client.Revision, &client.Registration, time.Now().UnixMilli())
	require.NoError(t, err)
	challenge := sha256.Sum256([]byte(strings.Repeat("v", 64)))
	query := url.Values{"response_type": {"code"}, "client_id": {f.clientID}, "redirect_uri": {"http://127.0.0.1:31821/callback"}, "resource": {client.Registration.Resources[0].Resource}, "scope": {"files:read"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "state": {"synthetic-state"}}
	response, err := f.server.Client().Get(f.server.URL + agentOAuthAuthorizePath + "?" + query.Encode())
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, http.StatusBadRequest, response.StatusCode)
	require.Empty(t, response.Header.Get("Location"))
}
