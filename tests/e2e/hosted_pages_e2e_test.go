//go:build e2e

package e2e

import (
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// hostedLinkPath returns the path+query of the first emailed link to the
// given hosted page ("/auth/verify-email?token=…"). The mail's host is the
// configured app base URL, not the test server, so only the path is used.
func hostedLinkPath(t *testing.T, body, page string) string {
	t.Helper()
	re := regexp.MustCompile(regexp.QuoteMeta(page) + `\?token=[A-Za-z0-9_\-]+`)
	m := re.FindString(html.UnescapeString(body))
	if m == "" {
		t.Fatalf("no link to %s in mail body: %q", page, body)
	}
	return m
}

// hostedGet fetches a hosted page and returns the status, headers and the
// entity-decoded body.
func hostedGet(t *testing.T, h *Harness, path string) (int, http.Header, string) {
	t.Helper()
	resp, err := h.HTTP.Get(h.BaseURL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, html.UnescapeString(string(raw))
}

// hostedPost submits an action form the way the page's own form does and
// does NOT follow redirects, so the handover 303 can be inspected.
func hostedPost(t *testing.T, h *Harness, path string, form url.Values, headers map[string]string) (int, http.Header, string) {
	t.Helper()
	client := &http.Client{
		Transport: h.HTTP.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest(http.MethodPost, h.BaseURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, html.UnescapeString(string(raw))
}

func tokenOf(t *testing.T, linkPath string) string {
	t.Helper()
	u, err := url.Parse(linkPath)
	if err != nil {
		t.Fatalf("parse %q: %v", linkPath, err)
	}
	return u.Query().Get("token")
}

// emailVerified reads user.emailVerified from an RPC response. protojson
// omits a false boolean, so absence reads as false.
func emailVerified(resp map[string]any) bool {
	user, _ := resp["user"].(map[string]any)
	if user == nil {
		return false
	}
	verified, _ := user["emailVerified"].(bool)
	return verified
}

func mustContain(t *testing.T, body string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q\n---\n%s", want, body)
		}
	}
}

// TestE2E_HostedPages_VerifyEmail: the emailed verification link lands on
// the hosted page; opening it changes nothing, clicking verifies, clicking
// again reports the link as used.
func TestE2E_HostedPages_VerifyEmail(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	addr := "hosted-verify@example.com"
	at, _, _ := h.Signup(t, addr, goodPassword)

	link := hostedLinkPath(t, h.Mailer.Latest().Text, "/auth/verify-email")

	status, hdr, body := hostedGet(t, h, link)
	if status != http.StatusOK {
		t.Fatalf("GET %s = %d\n%s", link, status, body)
	}
	mustContain(t, body, "Verify your email", addr, "Confirm email", `name="token"`)
	for name, want := range map[string]string{
		"Cache-Control":   "no-store",
		"Referrer-Policy": "no-referrer",
		"X-Frame-Options": "DENY",
	} {
		if got := hdr.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if csp := hdr.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "script-src") {
		t.Errorf("unexpected CSP on an action page: %q", csp)
	}

	// The look consumed nothing.
	cur, _ := h.rpcCall(t, "GetCurrentUser", map[string]any{}, at)
	if emailVerified(cur) {
		t.Fatalf("GET must not verify the email: %v", cur)
	}

	status, _, body = hostedPost(t, h, "/auth/verify-email", url.Values{"token": {tokenOf(t, link)}}, nil)
	if status != http.StatusOK {
		t.Fatalf("POST = %d\n%s", status, body)
	}
	mustContain(t, body, "Your email address is verified", `href="/auth/"`)

	cur, _ = h.rpcCall(t, "GetCurrentUser", map[string]any{}, at)
	if !emailVerified(cur) {
		t.Fatalf("click must verify the email: %v", cur)
	}

	status, _, body = hostedPost(t, h, "/auth/verify-email", url.Values{"token": {tokenOf(t, link)}}, nil)
	if status != http.StatusOK {
		t.Fatalf("second POST = %d", status)
	}
	mustContain(t, body, "already been used")
}

// TestE2E_HostedPages_ResetPassword: the reset form validates before it
// spends the token, then sets the password the user can sign in with.
func TestE2E_HostedPages_ResetPassword(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	addr := "hosted-reset@example.com"
	h.Signup(t, addr, goodPassword)

	if resp, status := h.rpcCall(t, "RequestPasswordReset", map[string]any{"email": addr}, ""); status != http.StatusOK {
		t.Fatalf("RequestPasswordReset = %d %v", status, resp)
	}
	resetMail := h.Mailer.FindContaining("/auth/reset-password")
	if resetMail == nil {
		t.Fatal("no reset mail recorded")
	}
	link := hostedLinkPath(t, resetMail.Text, "/auth/reset-password")
	token := tokenOf(t, link)

	status, _, body := hostedGet(t, h, link)
	if status != http.StatusOK {
		t.Fatalf("GET = %d", status)
	}
	mustContain(t, body, "Choose a new password", addr, `name="password_confirm"`)

	const newPassword = "Br4nd-New!Passw0rd"
	status, _, body = hostedPost(t, h, "/auth/reset-password", url.Values{
		"token": {token}, "password": {newPassword}, "password_confirm": {"different"},
	}, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("mismatch POST = %d\n%s", status, body)
	}
	mustContain(t, body, "don't match", "<form")

	status, _, body = hostedPost(t, h, "/auth/reset-password", url.Values{
		"token": {token}, "password": {"short"}, "password_confirm": {"short"},
	}, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("weak POST = %d\n%s", status, body)
	}
	mustContain(t, body, "Password must", "<form")

	status, _, body = hostedPost(t, h, "/auth/reset-password", url.Values{
		"token": {token}, "password": {newPassword}, "password_confirm": {newPassword},
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("POST = %d\n%s", status, body)
	}
	mustContain(t, body, "Your password has been updated")

	h.Login(t, addr, newPassword)
	if _, status := h.rpcCall(t, "PasswordLogin", map[string]any{"email": addr, "password": goodPassword}, ""); status == http.StatusOK {
		t.Fatal("old password must no longer work")
	}
}

// TestE2E_HostedPages_ConfirmEmailChange: the link mailed to the NEW address
// lands on the hosted page and, once clicked, moves the account to it.
func TestE2E_HostedPages_ConfirmEmailChange(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	oldAddr, newAddr := "hosted-old@example.com", "hosted-new@example.com"
	at, _, _ := h.Signup(t, oldAddr, goodPassword)

	if resp, status := h.rpcCall(t, "RequestEmailChange", map[string]any{
		"newEmail": newAddr, "currentPassword": goodPassword,
	}, at); status != http.StatusOK {
		t.Fatalf("RequestEmailChange = %d %v", status, resp)
	}
	verifyMail := h.Mailer.FindContaining("/auth/confirm-email-change")
	if verifyMail == nil || verifyMail.To != newAddr {
		t.Fatalf("confirmation mail not sent to the new address: %+v", verifyMail)
	}
	link := hostedLinkPath(t, verifyMail.Text, "/auth/confirm-email-change")

	status, _, body := hostedGet(t, h, link)
	if status != http.StatusOK {
		t.Fatalf("GET = %d", status)
	}
	mustContain(t, body, "Confirm your new email", newAddr, "Confirm new email")

	status, _, body = hostedPost(t, h, "/auth/confirm-email-change", url.Values{"token": {tokenOf(t, link)}}, nil)
	if status != http.StatusOK {
		t.Fatalf("POST = %d\n%s", status, body)
	}
	mustContain(t, body, "Your email address has been updated")

	h.Login(t, newAddr, goodPassword)
}

// TestE2E_HostedPages_MagicLinkHandsOverWithCode: the hosted magic-link page
// redirects to the link's return_to with a single-use code the app redeems
// for tokens through RedeemOAuthCode; the link and the code are each spent
// once.
func TestE2E_HostedPages_MagicLinkHandsOverWithCode(t *testing.T) {
	t.Parallel()
	h := StartServer(t)
	addr := "hosted-magic@example.com"
	const returnTo = "http://localhost/welcome?next=/home"

	if resp, status := h.rpcCall(t, "RequestMagicLink", map[string]any{"email": addr, "returnTo": returnTo}, ""); status != http.StatusOK {
		t.Fatalf("RequestMagicLink = %d %v", status, resp)
	}
	link := hostedLinkPath(t, h.Mailer.Latest().Text, "/auth/magic-link")

	status, hdr, body := hostedGet(t, h, link)
	if status != http.StatusOK {
		t.Fatalf("GET = %d", status)
	}
	mustContain(t, body, "Sign in", addr, "Continue")
	if csp := hdr.Get("Content-Security-Policy"); strings.Contains(csp, "form-action") {
		t.Errorf("the redirecting page must not pin form-action: %q", csp)
	}

	status, hdr, body = hostedPost(t, h, "/auth/magic-link", url.Values{"token": {tokenOf(t, link)}}, nil)
	if status != http.StatusSeeOther {
		t.Fatalf("POST = %d\n%s", status, body)
	}
	loc, err := url.Parse(hdr.Get("Location"))
	if err != nil || loc.Scheme+"://"+loc.Host+loc.Path != "http://localhost/welcome" {
		t.Fatalf("Location = %q, want the return_to", hdr.Get("Location"))
	}
	if loc.Query().Get("next") != "/home" {
		t.Errorf("return_to query not preserved: %q", loc.RawQuery)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("redirect carried no handover code")
	}

	redeemed, status := h.rpcCall(t, "RedeemOAuthCode", map[string]any{"code": code}, "")
	if status != http.StatusOK {
		t.Fatalf("RedeemOAuthCode = %d %v", status, redeemed)
	}
	at, _ := redeemed["accessToken"].(string)
	user, _ := redeemed["user"].(map[string]any)
	if at == "" || user == nil || user["email"] != addr || !emailVerified(redeemed) {
		t.Fatalf("redeem did not sign the user in: %v", redeemed)
	}
	if _, status := h.rpcCall(t, "RedeemOAuthCode", map[string]any{"code": code}, ""); status == http.StatusOK {
		t.Fatal("handover code must be single-use")
	}

	status, _, body = hostedPost(t, h, "/auth/magic-link", url.Values{"token": {tokenOf(t, link)}}, nil)
	if status != http.StatusOK {
		t.Fatalf("replay POST = %d", status)
	}
	mustContain(t, body, "already been used")
}

// TestE2E_HostedPages_AcceptInvitation: an admin's invitation link lands on
// the hosted page, where the invitee picks a name and password and is then
// able to sign in. Invitations run through the graph store, so this case
// runs on the postgres gate.
func TestE2E_HostedPages_AcceptInvitation(t *testing.T) {
	requireGraphDB(t)
	t.Parallel()
	h := StartServer(t)

	adminEmail := "hosted-admin@example.com"
	h.SeedUser(t, adminEmail, "Admin", "admin", "active", goodPassword)
	at, _ := h.Login(t, adminEmail, goodPassword)

	invitee := "hosted-invitee@example.com"
	resp, status := h.rpcCall(t, "InviteUser", map[string]any{"email": invitee, "name": "Invitee", "role": "member"}, at)
	if status != http.StatusOK {
		t.Fatalf("InviteUser = %d %v", status, resp)
	}
	setupURL, _ := resp["setupUrl"].(string)
	link := hostedLinkPath(t, setupURL, "/auth/accept-invitation")

	status, _, body := hostedGet(t, h, link)
	if status != http.StatusOK {
		t.Fatalf("GET = %d", status)
	}
	mustContain(t, body, "Set up your account", invitee, `name="name"`, `name="password"`)

	const password = "Inv1ted!Passw0rd"
	status, _, body = hostedPost(t, h, "/auth/accept-invitation", url.Values{
		"token": {tokenOf(t, link)}, "name": {"Invitee Person"}, "password": {password}, "password_confirm": {password},
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("POST = %d\n%s", status, body)
	}
	mustContain(t, body, "Your account is ready")

	h.Login(t, invitee, password)

	status, _, body = hostedPost(t, h, "/auth/accept-invitation", url.Values{
		"token": {tokenOf(t, link)}, "password": {password}, "password_confirm": {password},
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("replay POST = %d", status)
	}
	mustContain(t, body, "already been accepted")
}

// TestE2E_HostedPages_Guards: an unknown or missing link renders its state
// without error, a browser-marked cross-site POST is refused, and paths
// under /auth/ that are not pages 404.
func TestE2E_HostedPages_Guards(t *testing.T) {
	t.Parallel()
	h := StartServer(t)

	status, _, body := hostedGet(t, h, "/auth/verify-email?token=not-a-real-token")
	if status != http.StatusOK {
		t.Fatalf("unknown token GET = %d", status)
	}
	mustContain(t, body, "isn't valid")

	status, _, body = hostedGet(t, h, "/auth/reset-password")
	if status != http.StatusOK {
		t.Fatalf("missing token GET = %d", status)
	}
	mustContain(t, body, "isn't valid")

	status, _, body = hostedPost(t, h, "/auth/magic-link", url.Values{"token": {"x"}}, map[string]string{"Sec-Fetch-Site": "cross-site"})
	if status != http.StatusForbidden {
		t.Fatalf("cross-site POST = %d\n%s", status, body)
	}

	if status, _, _ := hostedGet(t, h, "/auth/not-a-page"); status != http.StatusNotFound {
		t.Fatalf("GET /auth/not-a-page = %d, want 404", status)
	}
}
