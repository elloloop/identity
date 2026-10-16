package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnect "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const (
	testAgentResource  = "https://files.example.test"
	testResourceSecret = "offline-test-resource-secret-not-real"
)

type agentOAuthHTTPFixture struct {
	cfg                 *config.Config
	server              *httptest.Server
	client              identityconnect.IdentityServiceClient
	repo                service.Repository
	signer              jwt.Signer
	owner, agent, token string
	clientID            string
}

func newAgentOAuthHTTPFixture(t *testing.T) *agentOAuthHTTPFixture {
	t.Helper()
	ctx := context.Background()
	cfg := newTestConfig()
	cfg.DefaultProjectID = config.DefaultProjectIDFallback
	cfg.JWTIssuer = "https://auth.example.test"
	cfg.AgentsEnabled = true
	cfg.AgentOAuthEnabled = true
	cfg.RevocationMode = config.RevocationModeSession
	cfg.SessionCacheTTLSeconds = 60
	cfg.AgentOAuthAccessSeconds = config.DefaultAgentOAuthAccessSeconds
	cfg.AgentOAuthConsentSeconds = config.DefaultAgentOAuthConsentSeconds
	cfg.AgentOAuthRefreshIdleSeconds = config.DefaultAgentOAuthRefreshIdleSeconds
	sum := sha256.Sum256([]byte(testResourceSecret))
	cfg.AgentOAuthResourceCredentialsJSON = fmt.Sprintf(`[{"id":"files-resource","project_id":"%s","resource":"%s","secret_sha256":"%s"}]`, cfg.DefaultProjectID, testAgentResource, hex.EncodeToString(sum[:]))
	repo := memory.New()
	signer := jwttest.NewSigner(t, "delegation-test-key")
	pk, err := passkeys.NewWebAuthnService(passkeys.Config{RPID: "localhost", RPName: "Identity test", Origin: "http://localhost:9002"})
	require.NoError(t, err)
	built, err := New(Deps{Config: cfg, Logger: zap.NewNop(), Signer: signer, Repo: repo, DB: repo, Passkeys: pk, TOTPKey: []byte("01234567890123456789012345678901"), TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH")})
	require.NoError(t, err)
	server := httptest.NewServer(built.Handler)
	t.Cleanup(server.Close)
	client := identityconnect.NewIdentityServiceClient(server.Client(), server.URL)
	signed, err := client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{Email: "owner@example.com", Password: "Offline-test-Password123!"}))
	require.NoError(t, err)
	req := connect.NewRequest(&identitypb.CreateAgentRequest{Name: "Example assistant"})
	req.Header().Set("Authorization", "Bearer "+signed.Msg.AccessToken)
	agent, err := client.CreateAgent(ctx, req)
	require.NoError(t, err)
	scoped := repo.WithProject(cfg.DefaultProjectID)
	registration := &service.OAuthClient{ID: "desktop-client", Kind: service.OAuthClientNativePublic, Revision: 1, CreatedAt: 1, UpdatedAt: 1, Registration: service.OAuthClientRegistration{Name: "Example desktop", RedirectURIs: []string{"http://127.0.0.1/callback"}, Resources: []service.OAuthResourceBounds{{Resource: testAgentResource, Product: "files", Scopes: []string{"files:read"}}}, GrantTypes: []string{service.OAuthGrantAuthorizationCode, service.OAuthGrantRefreshToken}}}
	require.NoError(t, scoped.CreateOAuthClient(ctx, registration))
	return &agentOAuthHTTPFixture{cfg: cfg, server: server, client: client, repo: scoped, signer: signer, owner: signed.Msg.User.Id, agent: agent.Msg.Agent.Id, token: signed.Msg.AccessToken, clientID: registration.ID}
}

func (f *agentOAuthHTTPFixture) start(t *testing.T) (string, string) {
	t.Helper()
	verifier := strings.Repeat("v", 64)
	sum := sha256.Sum256([]byte(verifier))
	params := url.Values{"response_type": {"code"}, "client_id": {f.clientID}, "redirect_uri": {"http://127.0.0.1:31821/callback"}, "resource": {testAgentResource}, "scope": {"files:read"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "state": {"caller-state"}}
	client := *f.server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Get(f.server.URL + agentOAuthAuthorizePath + "?" + params.Encode())
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusFound, resp.StatusCode, string(body))
	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, agentOAuthConsentPath, location.Path)
	return location.Query().Get("request_id"), verifier
}

func (f *agentOAuthHTTPFixture) consent(t *testing.T, id string) *identitypb.GetAgentAuthorizationResponse {
	t.Helper()
	req := connect.NewRequest(&identitypb.GetAgentAuthorizationRequest{RequestId: id})
	req.Header().Set("Authorization", "Bearer "+f.token)
	response, err := f.client.GetAgentAuthorization(context.Background(), req)
	require.NoError(t, err)
	return response.Msg
}

func (f *agentOAuthHTTPFixture) approve(t *testing.T, id string, revision int64) string {
	t.Helper()
	req := connect.NewRequest(&identitypb.DecideAgentAuthorizationRequest{RequestId: id, ExpectedRevision: revision, Decision: identitypb.AgentAuthorizationDecision_AGENT_AUTHORIZATION_DECISION_APPROVE, AgentUserId: f.agent})
	req.Header().Set("Authorization", "Bearer "+f.token)
	response, err := f.client.DecideAgentAuthorization(context.Background(), req)
	require.NoError(t, err)
	callback, err := url.Parse(response.Msg.RedirectUri)
	require.NoError(t, err)
	require.Equal(t, "caller-state", callback.Query().Get("state"))
	require.Equal(t, "https://auth.example.test", callback.Query().Get("iss"))
	return callback.Query().Get("code")
}

func (f *agentOAuthHTTPFixture) post(t *testing.T, path string, form url.Values, basic bool) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.server.URL+path, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		req.SetBasicAuth("files-resource", testResourceSecret)
	}
	response, err := f.server.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
	var data map[string]any
	err = json.NewDecoder(response.Body).Decode(&data)
	require.NoError(t, err)
	return response.StatusCode, data
}

func (f *agentOAuthHTTPFixture) exchangeForm(code, verifier string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "client_id": {f.clientID}, "redirect_uri": {"http://127.0.0.1:31821/callback"}, "resource": {testAgentResource}, "code": {code}, "code_verifier": {verifier}}
}

func TestAgentOAuthServedJourneyAndCurrentResourceAdmission(t *testing.T) {
	f := newAgentOAuthHTTPFixture(t)
	id, verifier := f.start(t)
	view := f.consent(t, id)
	require.Len(t, view.Agents, 1)
	require.Equal(t, f.agent, view.Agents[0].Id)
	require.Equal(t, "files", view.Product)
	require.Equal(t, []string{"files:read"}, view.Scopes)
	code := f.approve(t, id, view.Revision)
	status, invalid := f.post(t, agentOAuthTokenPath, f.exchangeForm(code, strings.Repeat("w", 64)), false)
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "invalid_grant", invalid["error"])
	status, tokens := f.post(t, agentOAuthTokenPath, f.exchangeForm(code, verifier), false)
	require.Equal(t, http.StatusOK, status)
	require.NotContains(t, tokens, "id_token")
	access := tokens["access_token"].(string)
	refresh := tokens["refresh_token"].(string)
	principal, err := jwt.VerifyDelegatedAccessToken(access, f.signer, "https://auth.example.test", config.DefaultProjectIDFallback, testAgentResource)
	require.NoError(t, err)
	require.Equal(t, f.agent, principal.Sub)
	require.Equal(t, f.owner, principal.Actor.Sub)
	_, err = jwt.VerifyAccessToken(access, f.signer, "", "", false)
	require.Error(t, err, "agent OAuth token must never become a human session")
	status, active := f.post(t, agentOAuthIntrospectPath, url.Values{"token": {access}}, true)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, true, active["active"])
	require.Equal(t, f.agent, active["sub"])
	listRequest := connect.NewRequest(&identitypb.ListAgentDelegationsRequest{Limit: 1})
	listRequest.Header().Set("Authorization", "Bearer "+f.token)
	listed, err := f.client.ListAgentDelegations(context.Background(), listRequest)
	require.NoError(t, err)
	require.Len(t, listed.Msg.Delegations, 1)
	require.Equal(t, id, listed.Msg.Delegations[0].DelegationId)
	require.Equal(t, f.agent, listed.Msg.Delegations[0].AgentUserId)
	require.NotContains(t, fmt.Sprint(listed.Msg), refresh)
	listRequest.Msg.Limit = service.MaxAgentOAuthListLimit + 1
	_, err = f.client.ListAgentDelegations(context.Background(), listRequest)
	require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	// A resource makes the authoritative check for every request, even while a
	// correctly signed access token remains within its local expiry.
	req := connect.NewRequest(&identitypb.RevokeAgentDelegationRequest{DelegationId: id})
	req.Header().Set("Authorization", "Bearer "+f.token)
	_, err = f.client.RevokeAgentDelegation(context.Background(), req)
	require.NoError(t, err)
	_, inactive := f.post(t, agentOAuthIntrospectPath, url.Values{"token": {access}}, true)
	require.Equal(t, false, inactive["active"])
	require.Len(t, inactive, 1)
	status, _ = f.post(t, agentOAuthTokenPath, url.Values{"grant_type": {"refresh_token"}, "client_id": {f.clientID}, "resource": {testAgentResource}, "refresh_token": {refresh}}, false)
	require.Equal(t, http.StatusBadRequest, status)
}

func TestAgentOAuthIssuedTokenHonorsShortenedHumanSessionLifetime(t *testing.T) {
	f := newAgentOAuthHTTPFixture(t)
	id, verifier := f.start(t)
	view := f.consent(t, id)
	code := f.approve(t, id, view.GetRevision())
	f.cfg.RefreshExpirySeconds = 30
	status, response := f.post(t, agentOAuthTokenPath, f.exchangeForm(code, verifier), false)
	require.Equal(t, http.StatusOK, status)
	claims, err := jwt.VerifyDelegatedAccessToken(response["access_token"].(string), f.signer, f.cfg.JWTIssuer, f.cfg.DefaultProjectID, testAgentResource)
	require.NoError(t, err)
	require.LessOrEqual(t, claims.ExpiresAt-claims.IssuedAt, int64(30))
	require.LessOrEqual(t, response["expires_in"].(float64), float64(30))
}

func TestAgentOAuthRotationReplayAndCodeConcurrency(t *testing.T) {
	f := newAgentOAuthHTTPFixture(t)
	id, v := f.start(t)
	code := f.approve(t, id, f.consent(t, id).Revision)
	var group sync.WaitGroup
	var winners atomic.Int32
	var tokenMu sync.Mutex
	var token map[string]any
	for range 6 {
		group.Go(func() {
			req, _ := http.NewRequest(http.MethodPost, f.server.URL+agentOAuthTokenPath, strings.NewReader(f.exchangeForm(code, v).Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			res, err := f.server.Client().Do(req)
			if err != nil {
				return
			}
			defer func() { _ = res.Body.Close() }()
			if res.StatusCode == http.StatusOK {
				var got map[string]any
				if json.NewDecoder(res.Body).Decode(&got) == nil {
					winners.Add(1)
					tokenMu.Lock()
					token = got
					tokenMu.Unlock()
				}
			}
		})
	}
	group.Wait()
	require.EqualValues(t, 1, winners.Load())
	refresh := token["refresh_token"].(string)
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {f.clientID}, "resource": {testAgentResource}, "refresh_token": {refresh}}
	status, next := f.post(t, agentOAuthTokenPath, form, false)
	require.Equal(t, http.StatusOK, status)
	require.NotEqual(t, refresh, next["refresh_token"])
	status, _ = f.post(t, agentOAuthTokenPath, form, false)
	require.Equal(t, http.StatusBadRequest, status)
	_, inactive := f.post(t, agentOAuthIntrospectPath, url.Values{"token": {next["access_token"].(string)}}, true)
	require.Equal(t, false, inactive["active"])
}

func TestAgentOAuthConsentNeedsRecentLiveSIDAndRejectsSpoofedSID(t *testing.T) {
	f := newAgentOAuthHTTPFixture(t)
	id, _ := f.start(t)
	claims, err := jwt.VerifyAccessToken(f.token, f.signer, "", "", false)
	require.NoError(t, err)
	require.NotEmpty(t, claims.SID)
	require.Positive(t, claims.AuthTime)
	f.consent(t, id) // Prime ordinary middleware cache before raw authority revocation.
	legacy, err := f.signer.SignAccessToken(context.Background(), jwt.Claims{Sub: f.owner, Tenant: "tenant", Project: config.DefaultProjectIDFallback, AuthTime: time.Now().Unix()}, time.Minute)
	require.NoError(t, err)
	for _, token := range []string{legacy, f.token} {
		req := connect.NewRequest(&identitypb.GetAgentAuthorizationRequest{RequestId: id})
		req.Header().Set("Authorization", "Bearer "+token)
		req.Header().Set(middleware.AuthenticatedSessionIDHeader, claims.SID)
		if token == f.token {
			require.NoError(t, f.repo.RevokeSession(context.Background(), claims.SID, time.Now().UnixMilli()))
		}
		_, err = f.client.GetAgentAuthorization(context.Background(), req)
		require.Contains(t, []connect.Code{connect.CodeFailedPrecondition, connect.CodeUnauthenticated}, connect.CodeOf(err))
	}
}

func TestAgentOAuthStrictProtocolForms(t *testing.T) {
	f := newAgentOAuthHTTPFixture(t)
	for i, tc := range []struct {
		method, path, body, content string
		status                      int
	}{
		{"GET", agentOAuthTokenPath, "", "", 405},
		{"POST", agentOAuthAuthorizePath, "", "application/x-www-form-urlencoded", 405},
		{"POST", agentOAuthTokenPath, `{"grant_type":"authorization_code"}`, "application/json", 400},
		{"POST", agentOAuthTokenPath + "?resource=urn:other", "grant_type=authorization_code", "application/x-www-form-urlencoded", 400},
		{"POST", agentOAuthTokenPath, "grant_type=authorization_code&client_id=a&client_id=b", "application/x-www-form-urlencoded", 400},
		{"POST", agentOAuthTokenPath, "grant_type=authorization_code&resource=a&resource=b", "application/x-www-form-urlencoded", 400},
		{"POST", agentOAuthTokenPath, "grant_type=authorization_code&client_secret=guess", "application/x-www-form-urlencoded", 400},
		{"POST", agentOAuthTokenPath, "grant_type=authorization_code&code=" + strings.Repeat("a", maxAgentOAuthFormBytes), "application/x-www-form-urlencoded", 400},
		{"POST", agentOAuthIntrospectPath, "token=anything", "application/x-www-form-urlencoded", 401},
	} {
		t.Run(fmt.Sprintf("%d-%s%s", i, tc.method, tc.path), func(t *testing.T) {
			req, err := http.NewRequest(tc.method, f.server.URL+tc.path, strings.NewReader(tc.body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", tc.content)
			res, err := f.server.Client().Do(req)
			require.NoError(t, err)
			defer func() { _ = res.Body.Close() }()
			require.Equal(t, tc.status, res.StatusCode)
		})
	}
}

func TestAgentOAuthObservedPolicyRefusalNeverRevives(t *testing.T) {
	f := newAgentOAuthHTTPFixture(t)
	id, verifier := f.start(t)
	code := f.approve(t, id, f.consent(t, id).Revision)
	status, tokens := f.post(t, agentOAuthTokenPath, f.exchangeForm(code, verifier), false)
	require.Equal(t, http.StatusOK, status)
	f.cfg.AgeGateRequireDOB = true
	status, inactive := f.post(t, agentOAuthIntrospectPath, url.Values{"token": {tokens["access_token"].(string)}}, true)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, false, inactive["active"])
	f.cfg.AgeGateRequireDOB = false
	_, inactive = f.post(t, agentOAuthIntrospectPath, url.Values{"token": {tokens["access_token"].(string)}}, true)
	require.Equal(t, false, inactive["active"], "restoring policy must not restore previously refused delegation")
	stored, err := f.repo.(service.AgentOAuthRepository).GetAgentAuthorization(context.Background(), id)
	require.NoError(t, err)
	require.NotZero(t, stored.RevokedAtMs)
}

func TestAgentOAuthIntrospectionAuthenticatesResourceBeforeTokenParsing(t *testing.T) {
	f := newAgentOAuthHTTPFixture(t)
	req, err := http.NewRequest(http.MethodPost, f.server.URL+agentOAuthIntrospectPath, strings.NewReader("token="))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("files-resource", "wrong-offline-test-secret")
	response, err := f.server.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, http.StatusUnauthorized, response.StatusCode)
	require.Equal(t, `Basic realm="oauth-resource"`, response.Header.Get("WWW-Authenticate"))
}

func TestAgentOAuthRejectsOpenIDScopeEvenWhenRegistered(t *testing.T) {
	f := newAgentOAuthHTTPFixture(t)
	ctx := context.Background()
	client, err := f.repo.GetOAuthClient(ctx, f.clientID)
	require.NoError(t, err)
	client.Registration.Resources[0].Scopes = append(client.Registration.Resources[0].Scopes, "openid")
	_, err = f.repo.UpdateOAuthClient(ctx, f.clientID, client.Revision, &client.Registration, time.Now().UnixMilli())
	require.NoError(t, err)
	proof := sha256.Sum256([]byte(strings.Repeat("v", 64)))
	query := url.Values{"client_id": {f.clientID}, "response_type": {"code"}, "redirect_uri": {"http://127.0.0.1/callback"}, "scope": {"openid"}, "resource": {testAgentResource}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(proof[:])}, "state": {"request-state"}}
	response, err := f.server.Client().Get(f.server.URL + agentOAuthAuthorizePath + "?" + query.Encode())
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, http.StatusBadRequest, response.StatusCode)
	require.Empty(t, response.Header.Get("Location"))
}
