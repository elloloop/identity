//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/oauth"
	"github.com/elloloop/identity/pkg/passwords"
)

// ssoStubProvider stands in for Google in the hosted round trip: the e2e suite
// has no provider credentials, and the thing under test is what identity does
// AFTER a provider says yes, not the provider exchange itself (which
// tests/integration covers).
type ssoStubProvider struct{ email string }

func (p *ssoStubProvider) AuthorizationURL(_ context.Context, redirectURI, state, _ string) (string, error) {
	u, _ := url.Parse("https://provider.test/authorize")
	q := u.Query()
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (p *ssoStubProvider) Exchange(_ context.Context, _ oauth.ExchangeParams) (*oauth.Identity, error) {
	return &oauth.Identity{
		Provider:       "google",
		ProviderUserID: "sso-e2e-user",
		Email:          p.email,
		EmailVerified:  true,
		Name:           "SSO E2E",
	}, nil
}

// The two real TinyKite surfaces this models: the reader portal's return_to
// and the sign-in hub that draws the continue-as card.
const (
	glossPortalCallback = "https://gloss.tinykite.co/auth/callback"
	nestaWebCallback    = "https://nesta.tinykite.co/auth/callback"
	accountsHubOrigin   = "https://accounts.tinykite.co"
	accountsHubSignIn   = "https://accounts.tinykite.co/signin"
)

func startSSOServer(t *testing.T, userEmail string) *Harness {
	t.Helper()
	reg := oauth.NewRegistry()
	reg.Register("google", &ssoStubProvider{email: userEmail})

	return StartServerWith(t,
		func(cfg *config.Config) {
			cfg.OAuthAllowedReturnURLs = strings.Join([]string{
				glossPortalCallback, nestaWebCallback, accountsHubSignIn,
			}, ",")
			cfg.SSOEnabled = true
			cfg.SSOSessionTTLSeconds = 3600
			cfg.SSOContinueMode = config.SSOContinueModeTap
			cfg.SSOHubOrigins = accountsHubOrigin
		},
		func(deps *app.Deps) { deps.OAuthRegistry = reg },
	)
}

// browserClient is an HTTP client with a cookie jar that does NOT follow
// redirects — so each hop is inspectable, exactly as the real flow is a chain
// of 302s the browser walks.
func browserClient(t *testing.T, h *Harness) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{
		Jar:       jar,
		Transport: h.HTTP.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// hostedSignIn walks /oauth/start → provider → /oauth/callback with one cookie
// jar, leaving the jar holding whatever cookies the server set. It returns the
// one-time code the callback handed back to returnTo.
func hostedSignIn(t *testing.T, h *Harness, client *http.Client, returnTo string) string {
	t.Helper()

	startResp, err := client.Get(h.BaseURL + "/oauth/start/google?return_to=" + url.QueryEscape(returnTo))
	if err != nil {
		t.Fatalf("GET /oauth/start: %v", err)
	}
	defer func() { _ = startResp.Body.Close() }()
	if startResp.StatusCode != http.StatusFound {
		t.Fatalf("/oauth/start status = %d", startResp.StatusCode)
	}
	providerURL, err := url.Parse(startResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse provider redirect: %v", err)
	}
	state := providerURL.Query().Get("state")
	if state == "" {
		t.Fatal("/oauth/start produced no state")
	}

	cbResp, err := client.Get(h.BaseURL + "/oauth/callback/google?code=stub&state=" + url.QueryEscape(state))
	if err != nil {
		t.Fatalf("GET /oauth/callback: %v", err)
	}
	defer func() { _ = cbResp.Body.Close() }()
	if cbResp.StatusCode != http.StatusFound {
		t.Fatalf("/oauth/callback status = %d", cbResp.StatusCode)
	}
	loc, err := url.Parse(cbResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse callback redirect: %v", err)
	}
	if !strings.HasPrefix(cbResp.Header.Get("Location"), returnTo) {
		t.Fatalf("callback redirected to %q, want a %s URL", cbResp.Header.Get("Location"), returnTo)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("callback carried no one-time code")
	}
	return code
}

func ssoCookieFromJar(t *testing.T, h *Harness, client *http.Client) *http.Cookie {
	t.Helper()
	base, err := url.Parse(h.BaseURL)
	if err != nil {
		t.Fatalf("parse base url: %v", err)
	}
	for _, c := range client.Jar.Cookies(base) {
		if c.Name == "__Host-sso_session" {
			return c
		}
	}
	return nil
}

// TestE2E_SSO_SecondProductSkipsTheProvider is the whole feature end to end
// against a real database, over the real HTTP surface, with one browser cookie
// jar: sign in once through the gloss portal's flow, then have a second
// product (nesta web) get its own session with no provider round trip.
func TestE2E_SSO_SecondProductSkipsTheProvider(t *testing.T) {
	t.Parallel()
	const userEmail = "sso-e2e@example.com"
	h := startSSOServer(t, userEmail)
	browser := browserClient(t, h)

	// 1. Cold sign-in through the gloss portal's real return_to.
	firstCode := hostedSignIn(t, h, browser, glossPortalCallback)

	cookie := ssoCookieFromJar(t, h, browser)
	if cookie == nil {
		t.Fatal("no SSO session cookie was established by the sign-in")
	}

	// The portal redeems its code for its own pair, exactly as today.
	firstSession := redeemCode(t, h, firstCode)
	if firstSession.RefreshToken == "" {
		t.Fatal("gloss portal got no refresh token")
	}

	// 2. The hub asks who this browser is, cross-origin and with credentials.
	view := introspect(t, h, browser, accountsHubOrigin)
	if !view.Authenticated || view.Email != userEmail {
		t.Fatalf("hub introspection = %+v, want authenticated %s", view, userEmail)
	}
	if view.ContinueMode != config.SSOContinueModeTap {
		t.Fatalf("continueMode = %q, want tap", view.ContinueMode)
	}

	// 3. "Continue as" — a second product, no provider hop.
	contResp, err := browser.Get(h.BaseURL + "/oauth/continue?return_to=" + url.QueryEscape(nestaWebCallback) +
		"&fallback_to=" + url.QueryEscape(accountsHubSignIn))
	if err != nil {
		t.Fatalf("GET /oauth/continue: %v", err)
	}
	defer func() { _ = contResp.Body.Close() }()
	if contResp.StatusCode != http.StatusFound {
		t.Fatalf("/oauth/continue status = %d", contResp.StatusCode)
	}
	contLoc, err := url.Parse(contResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse continue redirect: %v", err)
	}
	if contLoc.Host != "nesta.tinykite.co" {
		t.Fatalf("continue redirected to %q", contResp.Header.Get("Location"))
	}
	secondCode := contLoc.Query().Get("code")
	if secondCode == "" {
		t.Fatal("continue carried no one-time code")
	}
	if secondCode == firstCode {
		t.Fatal("the second product was handed the first product's code")
	}

	secondSession := redeemCode(t, h, secondCode)

	// Same account, independent credentials.
	if firstSession.UserID != secondSession.UserID {
		t.Fatalf("different users: %q vs %q", firstSession.UserID, secondSession.UserID)
	}
	if firstSession.RefreshToken == secondSession.RefreshToken {
		t.Fatal("the two products share a refresh token — SSO must share an authentication, never a token pair")
	}

	// Both sessions are independently alive: rotating one does not touch the
	// other, which is what "per-product pair" has to mean in practice.
	if rotated := refreshToken(t, h, secondSession.RefreshToken); rotated == "" {
		t.Fatal("nesta's refresh failed")
	}
	if rotated := refreshToken(t, h, firstSession.RefreshToken); rotated == "" {
		t.Fatal("gloss's session was disturbed by nesta's rotation")
	}

	// 4. Sign out everywhere ends the SSO session too, so the very next
	// continue falls back to the hub instead of silently minting again.
	signOutEverywhere(t, h, firstSession.AccessToken)

	afterResp, err := browser.Get(h.BaseURL + "/oauth/continue?return_to=" + url.QueryEscape(nestaWebCallback) +
		"&fallback_to=" + url.QueryEscape(accountsHubSignIn))
	if err != nil {
		t.Fatalf("GET /oauth/continue after sign-out: %v", err)
	}
	defer func() { _ = afterResp.Body.Close() }()
	if afterResp.StatusCode != http.StatusFound {
		t.Fatalf("post-sign-out continue status = %d", afterResp.StatusCode)
	}
	afterLoc := afterResp.Header.Get("Location")
	if !strings.HasPrefix(afterLoc, accountsHubSignIn) || !strings.Contains(afterLoc, "session=expired") {
		t.Fatalf("after sign-out-everywhere the continue must fall back to the hub, got %q", afterLoc)
	}

	// And the hub now reports nobody signed in.
	if after := introspect(t, h, browser, accountsHubOrigin); after.Authenticated {
		t.Fatalf("still authenticated after sign-out-everywhere: %+v", after)
	}
}

// A product's own sign-out must NOT end the SSO session (the approved model).
func TestE2E_SSO_PerProductLogoutKeepsTheSession(t *testing.T) {
	t.Parallel()
	h := startSSOServer(t, "sso-logout-e2e@example.com")
	browser := browserClient(t, h)

	code := hostedSignIn(t, h, browser, glossPortalCallback)
	session := redeemCode(t, h, code)

	logout(t, h, session.AccessToken, session.RefreshToken)

	// The browser is still signed in for the next product.
	if view := introspect(t, h, browser, accountsHubOrigin); !view.Authenticated {
		t.Fatal("a per-product logout ended the SSO session; it must not")
	}
	resp, err := browser.Get(h.BaseURL + "/oauth/continue?return_to=" + url.QueryEscape(nestaWebCallback))
	if err != nil {
		t.Fatalf("GET /oauth/continue: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("continue after per-product logout: status = %d", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("Location"), nestaWebCallback) {
		t.Fatalf("continue went to %q", resp.Header.Get("Location"))
	}
}

// A browser with no session gets no fast path, and the endpoint discloses
// nothing to an origin that is not the configured hub.
func TestE2E_SSO_NoSessionAndForeignOrigin(t *testing.T) {
	t.Parallel()
	h := startSSOServer(t, "sso-cold-e2e@example.com")
	cold := browserClient(t, h)

	if view := introspect(t, h, cold, accountsHubOrigin); view.Authenticated {
		t.Fatalf("a fresh browser reported authenticated: %+v", view)
	}

	resp, err := cold.Get(h.BaseURL + "/oauth/continue?return_to=" + url.QueryEscape(nestaWebCallback) +
		"&fallback_to=" + url.QueryEscape(accountsHubSignIn))
	if err != nil {
		t.Fatalf("GET /oauth/continue: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "session=expired") {
		t.Fatalf("cold continue: status=%d location=%q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Now sign in, then try to read the session from a different origin.
	warm := browserClient(t, h)
	hostedSignIn(t, h, warm, glossPortalCallback)

	req, err := http.NewRequest(http.MethodGet, h.BaseURL+"/sso/session", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	base, _ := url.Parse(h.BaseURL)
	for _, c := range warm.Jar.Cookies(base) {
		req.AddCookie(c)
	}
	req.Header.Set("Origin", "https://evil.test")
	evilResp, err := warm.Do(req)
	if err != nil {
		t.Fatalf("GET /sso/session from a foreign origin: %v", err)
	}
	defer func() { _ = evilResp.Body.Close() }()
	if evilResp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign origin status = %d, want 403", evilResp.StatusCode)
	}
	if got := evilResp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("foreign origin received a CORS grant: %q", got)
	}
}

// ── helpers over the public wire ─────────────────────────────────────────

type e2eSession struct {
	UserID       string
	AccessToken  string
	RefreshToken string
}

func redeemCode(t *testing.T, h *Harness, code string) e2eSession {
	t.Helper()
	resp, status := h.rpcCall(t, "RedeemOAuthCode", map[string]any{"code": code}, "")
	if status != http.StatusOK {
		t.Fatalf("RedeemOAuthCode: status=%d body=%v", status, resp)
	}
	user, _ := resp["user"].(map[string]any)
	id, _ := user["id"].(string)
	access, _ := resp["accessToken"].(string)
	refresh, _ := resp["refreshToken"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("RedeemOAuthCode returned no token pair: %v", resp)
	}
	return e2eSession{UserID: id, AccessToken: access, RefreshToken: refresh}
}

func refreshToken(t *testing.T, h *Harness, refresh string) string {
	t.Helper()
	resp, status := h.rpcCall(t, "RefreshToken", map[string]any{"refreshToken": refresh}, "")
	if status != http.StatusOK {
		t.Fatalf("RefreshToken: status=%d body=%v", status, resp)
	}
	next, _ := resp["refreshToken"].(string)
	return next
}

func logout(t *testing.T, h *Harness, access, refresh string) {
	t.Helper()
	resp, status := h.rpcCall(t, "Logout", map[string]any{"refreshToken": refresh}, access)
	if status != http.StatusOK {
		t.Fatalf("Logout: status=%d body=%v", status, resp)
	}
}

// signOutEverywhere calls the RPC with the account's password. The e2e OAuth
// account has none, so the password is set first through the admin-free
// repository seam the harness exposes — the point under test is the
// revocation, not the credential check.
func signOutEverywhere(t *testing.T, h *Harness, access string) {
	t.Helper()
	const password = "Str0ng!SignOut1"
	user := currentUser(t, h, access)
	setUserPassword(t, h, user, password)

	resp, status := h.rpcCall(t, "SignOutEverywhere", map[string]any{"password": password}, access)
	if status != http.StatusOK {
		t.Fatalf("SignOutEverywhere: status=%d body=%v", status, resp)
	}
}

func currentUser(t *testing.T, h *Harness, access string) string {
	t.Helper()
	resp, status := h.rpcCall(t, "GetCurrentUser", map[string]any{}, access)
	if status != http.StatusOK {
		t.Fatalf("GetCurrentUser: status=%d body=%v", status, resp)
	}
	user, _ := resp["user"].(map[string]any)
	id, _ := user["id"].(string)
	if id == "" {
		t.Fatalf("GetCurrentUser returned no id: %v", resp)
	}
	return id
}

func setUserPassword(t *testing.T, h *Harness, userID, password string) {
	t.Helper()
	hash, err := passwords.Hash(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if err := h.Repo.UpdateUser(context.Background(), userID, map[string]any{"password_hash": hash}); err != nil {
		t.Fatalf("seed password: %v", err)
	}
}

type ssoView struct {
	Authenticated bool   `json:"authenticated"`
	Email         string `json:"email"`
	ContinueMode  string `json:"continueMode"`
}

func introspect(t *testing.T, h *Harness, client *http.Client, origin string) ssoView {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.BaseURL+"/sso/session", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Origin", origin)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /sso/session: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/sso/session status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != origin {
		t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, origin)
	}
	var view ssoView
	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		t.Fatalf("decode /sso/session: %v", err)
	}
	return view
}
