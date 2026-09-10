//go:build browsere2e

package browsere2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/require"
)

// Selectors for the hosted action pages (internal/app/ui/templates/action.html).
const (
	selActionSubmit  = `#submit-btn`
	selActionSuccess = `.success-message`
	selActionNotice  = `.notice-message`
	selNewPassword   = `#password`
	selConfirmPass   = `#password_confirm`

	hostedPassword    = "Sup3rSecret!pw"
	hostedNewPassword = "Br4nd-New!Passw0rd"
)

// rpc posts a Connect JSON request to the served identity and decodes the
// response, so a browser journey can be set up (sign up, request a link) and
// verified (read the user back) without driving the sign-in page for it.
func rpc(t *testing.T, baseURL, method string, body map[string]any, accessToken string) (map[string]any, int) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		baseURL+"/identity.v1.IdentityService/"+method, bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	out := map[string]any{}
	data, _ := io.ReadAll(resp.Body)
	if len(data) > 0 {
		require.NoError(t, json.Unmarshal(data, &out), "decode %s: %s", method, data)
	}
	return out, resp.StatusCode
}

func emailVerifiedOf(resp map[string]any) bool {
	user, _ := resp["user"].(map[string]any)
	if user == nil {
		return false
	}
	v, _ := user["emailVerified"].(bool)
	return v
}

// waitText blocks until the element's text contains want.
func waitText(sel, want string) chromedp.Action {
	js := fmt.Sprintf(
		`(() => { const el = document.querySelector(%q); return !!el && el.textContent.includes(%q); })()`,
		sel, want,
	)
	return chromedp.Poll(js, nil)
}

// waitLocationPrefix polls the tab's location from the Go side until it
// starts with prefix. The click that precedes it submits a form and follows
// a redirect, and an in-page poll would be torn down by that navigation
// ("Inspected target navigated or closed"); reading the location between
// attempts tolerates the transition.
func waitLocationPrefix(t *testing.T, ctx context.Context, prefix string) string {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var location string
	for time.Now().Before(deadline) {
		if err := chromedp.Run(ctx, chromedp.Location(&location)); err == nil && strings.HasPrefix(location, prefix) {
			return location
		}
		time.Sleep(100 * time.Millisecond)
	}
	var body string
	_ = chromedp.Run(ctx, chromedp.Text("body", &body, chromedp.ByQuery))
	t.Fatalf("browser never reached %s; last location %q, page reads:\n%s", prefix, location, body)
	return ""
}

// TestBrowser_HostedVerifyEmail_ClickVerifies opens the mailed verification
// link in Chrome: the page names the address and changes nothing until the
// button is clicked, after which the account reads back as verified.
func TestBrowser_HostedVerifyEmail_ClickVerifies(t *testing.T) {
	requireChrome(t)
	h := startServer(t, true)
	ctx := newBrowser(t)

	email := uniqueEmail("hosted-verify")
	signup, status := rpc(t, h.baseURL, "PasswordSignup", map[string]any{"email": email, "password": hostedPassword}, "")
	require.Equal(t, http.StatusOK, status, "signup: %v", signup)
	accessToken, _ := signup["accessToken"].(string)
	link := h.mailer.linkPath(t, "/auth/verify-email")

	var pageText string
	require.NoError(t, chromedp.Run(
		ctx,
		chromedp.Navigate(h.baseURL+link),
		chromedp.WaitVisible(selActionSubmit, chromedp.ByID),
		waitText(selActionSubmit, "Confirm email"),
		chromedp.Text("body", &pageText, chromedp.ByQuery),
	))
	require.Contains(t, pageText, email, "the page names the address being verified")

	cur, _ := rpc(t, h.baseURL, "GetCurrentUser", map[string]any{}, accessToken)
	require.False(t, emailVerifiedOf(cur), "opening the link must not verify the email")

	var banner string
	require.NoError(t, chromedp.Run(
		ctx,
		chromedp.Click(selActionSubmit, chromedp.ByID),
		chromedp.WaitVisible(selActionSuccess, chromedp.ByQuery),
		chromedp.Text(selActionSuccess, &banner, chromedp.ByQuery),
	))
	require.Contains(t, banner, "verified")

	cur, _ = rpc(t, h.baseURL, "GetCurrentUser", map[string]any{}, accessToken)
	require.True(t, emailVerifiedOf(cur), "the click verifies the email")
}

// TestBrowser_HostedMagicLink_HandsOverToApp opens the mailed magic link:
// clicking Continue lands the browser on the app's return_to carrying a
// handover code the app redeems for tokens.
func TestBrowser_HostedMagicLink_HandsOverToApp(t *testing.T) {
	requireChrome(t)
	h := startServer(t, true)
	ctx := newBrowser(t)

	// The harness leaves passwordless sign-up off, so the link must belong
	// to an existing account: a magic link for an unknown address is refused
	// (indistinguishably from a bad token) rather than creating one.
	email := uniqueEmail("hosted-magic")
	signup, status := rpc(t, h.baseURL, "PasswordSignup", map[string]any{"email": email, "password": hostedPassword}, "")
	require.Equal(t, http.StatusOK, status, "signup: %v", signup)
	// The sign-in page stands in for the app's return_to: it is on the
	// allowlisted origin and always exists.
	returnTo := h.authURL + "?welcome=1"
	resp, status := rpc(t, h.baseURL, "RequestMagicLink", map[string]any{"email": email, "returnTo": returnTo}, "")
	require.Equal(t, http.StatusOK, status, "RequestMagicLink: %v", resp)
	link := h.mailer.linkPath(t, "/auth/magic-link")

	require.NoError(t, chromedp.Run(
		ctx,
		chromedp.Navigate(h.baseURL+link),
		chromedp.WaitVisible(selActionSubmit, chromedp.ByID),
		waitText(selActionSubmit, "Continue"),
		chromedp.Click(selActionSubmit, chromedp.ByID),
	))
	// The code is appended to return_to's own query; the parameters are
	// re-encoded in sorted order, so match the path and inspect the query.
	location := waitLocationPrefix(t, ctx, h.authURL+"?")
	landed, err := url.Parse(location)
	require.NoError(t, err)
	code := landed.Query().Get("code")
	require.NotEmpty(t, code, "the redirect must carry a handover code: %s", location)
	require.Equal(t, "1", landed.Query().Get("welcome"), "return_to's own query survives")

	redeemed, status := rpc(t, h.baseURL, "RedeemOAuthCode", map[string]any{"code": code}, "")
	require.Equal(t, http.StatusOK, status, "RedeemOAuthCode: %v", redeemed)
	require.NotEmpty(t, redeemed["accessToken"])
	user, _ := redeemed["user"].(map[string]any)
	require.Equal(t, strings.ToLower(email), user["email"])

	_, status = rpc(t, h.baseURL, "RedeemOAuthCode", map[string]any{"code": code}, "")
	require.NotEqual(t, http.StatusOK, status, "the handover code is single-use")
}

// TestBrowser_HostedResetPassword_FormSetsPassword fills the hosted reset
// form and signs in with the new password afterwards.
func TestBrowser_HostedResetPassword_FormSetsPassword(t *testing.T) {
	requireChrome(t)
	h := startServer(t, true)
	ctx := newBrowser(t)

	email := uniqueEmail("hosted-reset")
	signup, status := rpc(t, h.baseURL, "PasswordSignup", map[string]any{"email": email, "password": hostedPassword}, "")
	require.Equal(t, http.StatusOK, status, "signup: %v", signup)
	resp, status := rpc(t, h.baseURL, "RequestPasswordReset", map[string]any{"email": email}, "")
	require.Equal(t, http.StatusOK, status, "RequestPasswordReset: %v", resp)
	link := h.mailer.linkPath(t, "/auth/reset-password")

	var banner string
	require.NoError(t, chromedp.Run(
		ctx,
		chromedp.Navigate(h.baseURL+link),
		chromedp.WaitVisible(selNewPassword, chromedp.ByID),
		chromedp.SendKeys(selNewPassword, hostedNewPassword, chromedp.ByID),
		chromedp.SendKeys(selConfirmPass, hostedNewPassword, chromedp.ByID),
		chromedp.Click(selActionSubmit, chromedp.ByID),
		chromedp.WaitVisible(selActionSuccess, chromedp.ByQuery),
		chromedp.Text(selActionSuccess, &banner, chromedp.ByQuery),
	))
	require.Contains(t, banner, "updated")

	login, status := rpc(t, h.baseURL, "PasswordLogin", map[string]any{"email": email, "password": hostedNewPassword}, "")
	require.Equal(t, http.StatusOK, status, "login with the new password: %v", login)
	_, status = rpc(t, h.baseURL, "PasswordLogin", map[string]any{"email": email, "password": hostedPassword}, "")
	require.NotEqual(t, http.StatusOK, status, "the old password no longer works")
}
