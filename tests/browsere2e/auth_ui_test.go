//go:build browsere2e

package browsere2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/require"
)

// browserTimeout bounds a single browser test end-to-end (container boot is
// already covered by startServer's own context).
const browserTimeout = 90 * time.Second

// selectors for the auth UI (internal/app/ui/static/index.html).
const (
	selEmail   = `#email`
	selPass    = `#password`
	selSubmit  = `#submit-btn`
	selToggle  = `#toggle-link`
	selError   = `#error-message`
	selSuccess = `#success-message`

	// Submit-button labels the page renders per mode (index.html sets these in
	// the toggle handler). Used as a barrier to confirm the form-mode toggle's
	// async click handler has run before we fill and submit.
	submitTextSignup = "Sign up"
)

// waitSubmitText returns an Action that blocks until the submit button's text
// equals want — i.e. the page's toggle handler has flipped the form mode. It
// polls in-page rather than sleeping, so it is robust on slow CI runners.
func waitSubmitText(want string) chromedp.Action {
	js := fmt.Sprintf(
		`(() => { const b = document.querySelector(%q); return !!b && b.textContent.trim() === %q; })()`,
		selSubmit, want,
	)
	return chromedp.Poll(js, nil)
}

// newBrowser opens a headless Chrome context bound to the host binary, with a
// timeout. The returned cancel funcs tear the browser down.
func newBrowser(t *testing.T) context.Context {
	t.Helper()
	execPath := requireChrome(t)

	allocCtx, allocCancel := chromedp.NewExecAllocator(
		context.Background(),
		append(
			chromedp.DefaultExecAllocatorOptions[:],
			chromedp.ExecPath(execPath),
			// Required for CI/root containers; harmless locally.
			chromedp.NoSandbox,
			// GPU is unavailable on headless CI runners; without this the first
			// renderer init can stall. (DefaultExecAllocatorOptions already sets
			// --disable-dev-shm-usage and headless.)
			chromedp.DisableGPU,
		)...,
	)
	t.Cleanup(allocCancel)

	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	t.Cleanup(browserCancel)

	ctx, timeoutCancel := context.WithTimeout(browserCtx, browserTimeout)
	t.Cleanup(timeoutCancel)

	// chromedp starts the browser lazily on the first action. Force the launch
	// here (still inside the bounded ctx) so the websocket handshake is not
	// folded into — and does not race — the first Navigate of a test. On a
	// resource-constrained CI runner the cold start right after the postgres
	// container boots is the slowest moment; isolating it makes the first
	// in-test action deterministic.
	require.NoError(t, chromedp.Run(ctx), "warm up browser")
	return ctx
}

// uniqueEmail returns a per-test address so reruns against the same container
// (and the email-canonicalization dedup) don't collide. The domain must use a
// routable TLD — the service rejects reserved TLDs like .test — so we use
// example.com (RFC 2606 reserved for documentation but treated as routable by
// the validator).
func uniqueEmail(prefix string) string {
	return fmt.Sprintf("%s-%d@example.com", prefix, time.Now().UnixNano())
}

// signupViaUI drives the page's signup form: toggle into signup mode, fill the
// fields, submit, and wait for the success banner. It asserts on the visible
// success text the page renders.
func signupViaUI(t *testing.T, ctx context.Context, email, password string) {
	t.Helper()
	err := chromedp.Run(
		ctx,
		chromedp.WaitVisible(selToggle, chromedp.ByID),
		// The page boots in login mode; the toggle switches it to signup. The
		// submit button is already visible in login mode, so WaitVisible on it
		// is not a barrier — it returns immediately and races the toggle's
		// click handler. Wait until the handler has actually flipped the form
		// into signup mode (the submit label becomes "Sign up") before filling
		// and submitting, so a slow CI runner never POSTs PasswordLogin for a
		// not-yet-created user by accident.
		chromedp.Click(selToggle, chromedp.ByID),
		chromedp.WaitVisible(selSubmit, chromedp.ByID),
		waitSubmitText(submitTextSignup),
		chromedp.SendKeys(selEmail, email, chromedp.ByID),
		chromedp.SendKeys(selPass, password, chromedp.ByID),
		chromedp.Click(selSubmit, chromedp.ByID),
	)
	require.NoError(t, err, "submit signup form")

	success, errMsg := waitForBanner(t, ctx)
	require.Empty(t, errMsg, "signup must not render an error banner")
	require.Contains(t, strings.ToLower(success), "created",
		"signup should render the account-created banner")
}

// loginViaUI drives the page's login form (its default mode) and returns the
// visible success and error banner text so the caller can assert on either.
func loginViaUI(t *testing.T, ctx context.Context, email, password string) (success, errMsg string) {
	t.Helper()
	// Submit, then wait until exactly one of the banners becomes visible. The
	// page toggles display:block on success-message or error-message; poll
	// both and return whichever appears.
	err := chromedp.Run(
		ctx,
		chromedp.WaitVisible(selSubmit, chromedp.ByID),
		chromedp.SendKeys(selEmail, email, chromedp.ByID),
		chromedp.SendKeys(selPass, password, chromedp.ByID),
		chromedp.Click(selSubmit, chromedp.ByID),
	)
	require.NoError(t, err, "submit login form")
	return waitForBanner(t, ctx)
}

// waitForBanner polls the page until exactly one of the success / error
// banners becomes visible (the page flips display:block on whichever applies)
// and returns its text. Exactly one of the returned strings is non-empty.
func waitForBanner(t *testing.T, ctx context.Context) (success, errMsg string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		var sVisible, eVisible bool
		if err := chromedp.Run(
			ctx,
			chromedp.Evaluate(bannerVisibleJS(selSuccess), &sVisible),
			chromedp.Evaluate(bannerVisibleJS(selError), &eVisible),
		); err != nil {
			t.Fatalf("poll banners: %v", err)
		}
		if sVisible {
			require.NoError(t, chromedp.Run(ctx, chromedp.Text(selSuccess, &success, chromedp.ByID)))
			return success, ""
		}
		if eVisible {
			require.NoError(t, chromedp.Run(ctx, chromedp.Text(selError, &errMsg, chromedp.ByID)))
			return "", errMsg
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("neither success nor error banner became visible after form submit")
	return "", ""
}

// bannerVisibleJS returns a JS expression that is true when the given element
// is rendered (display != none). The page flips inline display to "block".
func bannerVisibleJS(sel string) string {
	return fmt.Sprintf(
		`(() => { const el = document.querySelector(%q); return !!el && getComputedStyle(el).display !== 'none'; })()`,
		sel,
	)
}

// TestBrowser_PasswordSignupLogin_AuthenticatedCall drives the happy path
// entirely through the served UI: sign up, log in, then prove the issued
// access token authorizes a same-origin RPC (GetCurrentUser) — the
// page-issued token is used for an authenticated call that succeeds.
func TestBrowser_PasswordSignupLogin_AuthenticatedCall(t *testing.T) {
	// Skip before the (slow, Docker-dependent) container boot when no browser
	// is present, so a Chrome-less runner exits cleanly and cheaply.
	requireChrome(t)
	h := startServer(t, true /* signup enabled */)
	ctx := newBrowser(t)

	email := uniqueEmail("happy")
	const password = "Sup3rSecret!pw"

	require.NoError(t, chromedp.Run(ctx, chromedp.Navigate(h.authURL)))
	signupViaUI(t, ctx, email, password)

	// Reload to reset the form back to login mode, then log in with the same
	// credentials and assert the success banner.
	require.NoError(t, chromedp.Run(ctx, chromedp.Navigate(h.authURL)))
	success, errMsg := loginViaUI(t, ctx, email, password)
	require.Empty(t, errMsg, "login with correct password must not error")
	require.Contains(t, strings.ToLower(success), "logged in",
		"login should render the logged-in banner")

	// The page truncates the token in the DOM, so obtain a full token by
	// driving the same PasswordLogin endpoint from the page context, then use
	// it to call GetCurrentUser — an authenticated, same-origin RPC. This
	// proves the browser-obtained credential authorizes a real call.
	gotEmail := authenticatedCurrentUserEmail(t, ctx, email, password)
	require.Equal(t, email, gotEmail,
		"GetCurrentUser with the page-issued token should return the signed-up user")
}

// authenticatedCurrentUserEmail logs in via fetch from the page's own origin
// (so CORS, project resolution and the auth middleware are all exercised),
// then calls GetCurrentUser with the bearer token and returns the email the
// server reports. It runs inside the browser via chromedp.Evaluate with an
// awaited promise.
func authenticatedCurrentUserEmail(t *testing.T, ctx context.Context, email, password string) string {
	t.Helper()
	// The JS resolves to the user's email, or to "ERR:<detail>" on any failure,
	// so a server-side rejection surfaces as a readable test failure rather
	// than a bare timeout.
	js := fmt.Sprintf(`
		(async () => {
			const login = await fetch('/identity.v1.IdentityService/PasswordLogin', {
				method: 'POST',
				headers: {'Content-Type': 'application/json'},
				body: JSON.stringify({email: %q, password: %q}),
			});
			const loginBody = await login.json();
			if (!login.ok) return 'ERR:login:' + JSON.stringify(loginBody);
			const token = loginBody.accessToken || loginBody.access_token;
			if (!token) return 'ERR:no-token';
			const me = await fetch('/identity.v1.IdentityService/GetCurrentUser', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Authorization': 'Bearer ' + token,
				},
				body: JSON.stringify({}),
			});
			const meBody = await me.json();
			if (!me.ok) return 'ERR:me:' + JSON.stringify(meBody);
			const user = meBody.user || {};
			return user.email || 'ERR:no-email:' + JSON.stringify(meBody);
		})()
	`, email, password)

	var result string
	err := chromedp.Run(
		ctx,
		chromedp.Evaluate(js, &result, func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
			return p.WithAwaitPromise(true)
		}),
	)
	require.NoError(t, err, "evaluate authenticated fetch")
	require.False(t, strings.HasPrefix(result, "ERR:"),
		"authenticated call failed: %s", result)
	return result
}

// TestBrowser_WrongPassword_ShowsError covers the unhappy path: a real user
// exists, but logging in with the wrong password renders the error banner and
// no success banner.
func TestBrowser_WrongPassword_ShowsError(t *testing.T) {
	requireChrome(t)
	h := startServer(t, true)
	ctx := newBrowser(t)

	email := uniqueEmail("wrongpw")
	const password = "Sup3rSecret!pw"

	require.NoError(t, chromedp.Run(ctx, chromedp.Navigate(h.authURL)))
	signupViaUI(t, ctx, email, password)

	require.NoError(t, chromedp.Run(ctx, chromedp.Navigate(h.authURL)))
	success, errMsg := loginViaUI(t, ctx, email, "totally-wrong-password")
	require.Empty(t, success, "wrong password must not render a success banner")
	require.NotEmpty(t, errMsg, "wrong password must render an error banner")
}

// TestBrowser_SignupDisabled_HidesSignup asserts the UNHAPPY config path: when
// the server runs with PasswordSignupEnabled=false, the injected
// window.serverConfig.passwordSignupEnabled is false and the page hides the
// signup affordance (the toggle-mode block), so a user cannot switch to the
// signup form from the browser.
func TestBrowser_SignupDisabled_HidesSignup(t *testing.T) {
	requireChrome(t)
	h := startServer(t, false /* signup disabled */)
	ctx := newBrowser(t)

	require.NoError(t, chromedp.Run(ctx, chromedp.Navigate(h.authURL)))

	var signupFlag bool
	var toggleHidden bool
	err := chromedp.Run(
		ctx,
		chromedp.WaitVisible(selSubmit, chromedp.ByID),
		// Assert the server actually injected the disabled flag.
		chromedp.Evaluate(`window.serverConfig.passwordSignupEnabled === false`, &signupFlag),
		// ...and that the page acted on it by hiding the toggle-mode block.
		chromedp.Evaluate(
			`getComputedStyle(document.querySelector('.toggle-mode')).display === 'none'`,
			&toggleHidden,
		),
	)
	require.NoError(t, err)
	require.True(t, signupFlag,
		"window.serverConfig.passwordSignupEnabled should be false when signup is disabled")
	require.True(t, toggleHidden,
		"the signup toggle should be hidden when passwordSignupEnabled is false")
}
