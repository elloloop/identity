package ui

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/service"
)

// maxActionFormBytes bounds an action-page form body: a token, at most two
// passwords and a name.
const maxActionFormBytes = 64 << 10

// Page states beyond the link preview's own. The preview states
// (service.ActionLinkReady / Invalid / Used / Expired) render as-is.
const (
	// stateDone: the click succeeded and the page reports it.
	stateDone = "done"
	// stateInfo: a live link on a page that has nothing to consume — it
	// tells the user what the link is and where to go next.
	stateInfo = "info"
	// statePending: the account behind the link has not accepted its
	// invitation yet, so nothing else can happen to it.
	statePending = "pending"
	// stateRefused: the project's policy or the account's status refused
	// the action; the link itself was fine.
	stateRefused = "refused"
	// stateError: the server could not complete the request.
	stateError = "error"
)

// actionText is the copy of one action page. {email} is the address the
// link concerns, {detail} what else the preview named (falling back to
// text.DetailFallback), and {to_product} expands to " to <Product>" when the
// project has a product name, else to "".
type actionText struct {
	Heading string
	Intro   string
	Submit  string
	Done    string
	Used    string
	Expired string
	Invalid string
	// Next labels the onward link shown under every non-form state.
	Next string
	// DetailFallback stands in for {detail} when the preview names nothing.
	DetailFallback string
}

// actionInput is what a submitted action form carries, plus the caller
// context the service records.
type actionInput struct {
	token     string
	password  string
	name      string
	ipAddr    string
	userAgent string
}

// actionResult is what a successful click produced: a redirect target for
// the handover flow, or nothing, in which case the page renders its done
// state.
type actionResult struct {
	redirectURL string
}

// actionKind describes one emailed-link page: its route, its copy, what its
// form asks for, and the service calls behind the look (peek) and the click
// (act).
type actionKind struct {
	path        string
	text        actionText
	askName     bool
	askPassword bool
	// redirects reports whether a successful POST leaves this origin; see
	// pagePolicy.formAction.
	redirects bool
	// informational marks a page that only looks: a live link renders its
	// intro and the onward link, and there is no POST.
	informational bool
	peek          func(ctx context.Context, src Sources, token string) (service.ActionLinkPreview, error)
	act           func(ctx context.Context, src Sources, in actionInput) (actionResult, error)
}

// ActionPaths lists every hosted action page path, for wiring and logs.
func ActionPaths() []string {
	kinds := actionKinds()
	paths := make([]string, 0, len(kinds))
	for _, k := range kinds {
		paths = append(paths, k.path)
	}
	return paths
}

// actionKinds is the table of hosted action pages. The paths are the ones
// identity's own emails already link to ({base}/auth/<action>?token=…).
func actionKinds() []actionKind {
	const notYouHint = " If you didn't request this, you can ignore the email."
	return []actionKind{
		{
			path: service.HostedVerifyEmailPath,
			text: actionText{
				Heading: "Verify your email",
				Intro:   "Confirm that {email} is your email address{to_product}.",
				Submit:  "Confirm email",
				Done:    "Your email address is verified. You can close this page or sign in.",
				Used:    "This link has already been used. If you verified your email, you're all set.",
				Expired: "This verification link has expired. Request a new one from the app you signed up in.",
				Invalid: "This verification link isn't valid. Make sure you opened the full link from the email.",
				Next:    "Sign in",
			},
			peek: func(ctx context.Context, src Sources, token string) (service.ActionLinkPreview, error) {
				return src.Auth.PeekEmailVerification(ctx, token)
			},
			act: func(ctx context.Context, src Sources, in actionInput) (actionResult, error) {
				_, err := src.Auth.VerifyEmail(ctx, in.token)
				return actionResult{}, err
			},
		},
		{
			path: service.HostedResetPasswordPath,
			text: actionText{
				Heading: "Choose a new password",
				Intro:   "Set a new password for {email}." + notYouHint,
				Submit:  "Update password",
				Done:    "Your password has been updated. You've been signed out everywhere; sign in with your new password.",
				Used:    "This reset link has already been used. If you didn't change your password, request a new link from your app.",
				Expired: "This reset link has expired. Request a new one from your app.",
				Invalid: "This reset link isn't valid. Make sure you opened the full link from the email.",
				Next:    "Sign in",
			},
			askPassword: true,
			peek: func(ctx context.Context, src Sources, token string) (service.ActionLinkPreview, error) {
				return src.Auth.PeekPasswordReset(ctx, token)
			},
			act: func(ctx context.Context, src Sources, in actionInput) (actionResult, error) {
				return actionResult{}, src.Auth.ConfirmPasswordReset(ctx, in.token, in.password)
			},
		},
		{
			path: service.HostedConfirmEmailChangePath,
			text: actionText{
				Heading: "Confirm your new email",
				Intro:   "Confirm that {email} is now your email address{to_product}.",
				Submit:  "Confirm new email",
				Done:    "Your email address has been updated. You've been signed out everywhere; sign in with your new address.",
				Used:    "This link has already been used. If you changed your email, you're all set.",
				Expired: "This confirmation link has expired. Request the change again from your account settings.",
				Invalid: "This confirmation link isn't valid. Make sure you opened the full link from the email.",
				Next:    "Sign in",
			},
			peek: func(ctx context.Context, src Sources, token string) (service.ActionLinkPreview, error) {
				return src.Auth.PeekEmailChange(ctx, token)
			},
			act: func(ctx context.Context, src Sources, in actionInput) (actionResult, error) {
				_, err := src.Auth.ConfirmEmailChange(ctx, in.token)
				return actionResult{}, err
			},
		},
		{
			path: service.HostedMagicLinkPath,
			text: actionText{
				Heading: "Sign in{to_product}",
				Intro:   "Continue to sign in as {email}.",
				Submit:  "Continue",
				Used:    "This sign-in link has already been used. Request a new one from your app.",
				Expired: "This sign-in link has expired. Request a new one from your app.",
				Invalid: "This sign-in link isn't valid. Make sure you opened the full link from the email.",
				Next:    "Back to sign in",
			},
			redirects: true,
			peek: func(ctx context.Context, src Sources, token string) (service.ActionLinkPreview, error) {
				return src.Auth.PeekMagicLink(ctx, token)
			},
			act: func(ctx context.Context, src Sources, in actionInput) (actionResult, error) {
				handover, err := src.Auth.RedeemMagicLinkForHandover(ctx, in.token, in.ipAddr, in.userAgent)
				if err != nil {
					return actionResult{}, err
				}
				if handover == nil || handover.RedirectURL == "" {
					return actionResult{}, errors.New("magic link handover returned no redirect")
				}
				return actionResult{redirectURL: handover.RedirectURL}, nil
			},
		},
		{
			path: service.HostedAcceptInvitationPath,
			text: actionText{
				Heading: "Set up your account",
				Intro:   "You've been invited{to_product} as {email}. Choose a password to finish setting up.",
				Submit:  "Create account",
				Done:    "Your account is ready. Sign in to get started.",
				Used:    "This invitation has already been accepted. Sign in to continue.",
				Expired: "This invitation has expired. Ask the person who invited you to send a new one.",
				Invalid: "This invitation link isn't valid. Make sure you opened the full link from the email.",
				Next:    "Sign in",
			},
			askName:     true,
			askPassword: true,
			peek: func(ctx context.Context, src Sources, token string) (service.ActionLinkPreview, error) {
				return src.Auth.PeekInvitation(ctx, token)
			},
			act: func(ctx context.Context, src Sources, in actionInput) (actionResult, error) {
				_, err := src.Auth.RedeemInvitation(ctx, in.token, in.password, in.name)
				return actionResult{}, err
			},
		},
		{
			// A tenant-membership invitation is accepted by a signed-in caller
			// whose address matches (AcceptTenantInvitation), so this page
			// cannot complete it: it says what the link is and sends the
			// invitee to sign in.
			path: service.HostedJoinTeamPath,
			text: actionText{
				Heading:        "Join {detail}",
				DetailFallback: "your team",
				Intro:          "You've been invited to join {detail}{to_product} as {email}. Sign in with that address to accept the invitation.",
				Used:           "This invitation has already been accepted. Sign in to continue.",
				Expired:        "This invitation has expired. Ask the person who invited you to send a new one.",
				Invalid:        "This invitation link isn't valid. Make sure you opened the full link from the email.",
				Next:           "Sign in",
			},
			informational: true,
			peek: func(ctx context.Context, src Sources, token string) (service.ActionLinkPreview, error) {
				if src.Teams == nil {
					return service.ActionLinkPreview{State: service.ActionLinkInvalid}, nil
				}
				return src.Teams.PeekTenantInvitation(ctx, token)
			},
		},
	}
}

// actionPage is the template data for an action page.
type actionPage struct {
	Nonce        string
	Title        string
	Heading      string
	Intro        string
	Email        string
	State        string
	Message      string
	Error        string
	Token        string
	Name         string
	FormAction   string
	AskName      bool
	AskPassword  bool
	Submit       string
	Next         string
	SignInURL    string
	SupportEmail string

	text actionText
}

func (h *handler) serveAction(w http.ResponseWriter, r *http.Request, kind actionKind) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		h.serveActionGet(w, r, kind)
	case http.MethodPost:
		if kind.informational {
			w.Header().Set("Allow", "GET, HEAD")
			h.plainError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		h.serveActionPost(w, r, kind)
	default:
		allow := "GET, HEAD, POST"
		if kind.informational {
			allow = "GET, HEAD"
		}
		w.Header().Set("Allow", allow)
		h.plainError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// serveActionGet renders the page for the link the user opened. It only
// looks: the token is previewed, never consumed, so a mail scanner or a
// preview fetch cannot spend it.
func (h *handler) serveActionGet(w http.ResponseWriter, r *http.Request, kind actionKind) {
	token := r.URL.Query().Get("token")
	preview, err := kind.peek(r.Context(), h.src, token)
	if err != nil {
		h.logger.Error("hosted_action_peek_failed", zap.String("page", kind.path), zap.Error(err))
		page := h.newActionPage(r, kind, token, service.ActionLinkPreview{})
		page.setState(stateError)
		h.renderAction(w, r, kind, page, http.StatusInternalServerError)
		return
	}
	page := h.newActionPage(r, kind, token, preview)
	if kind.informational && preview.State == service.ActionLinkReady {
		page.setState(stateInfo)
	} else {
		page.setState(string(preview.State))
	}
	h.renderAction(w, r, kind, page, http.StatusOK)
}

// serveActionPost is the click: the one request that consumes the token.
func (h *handler) serveActionPost(w http.ResponseWriter, r *http.Request, kind actionKind) {
	if err := h.crossOrigin.Check(r); err != nil {
		// Request metadata only — enough to tell a proxy that strips
		// Sec-Fetch-* or rewrites Host apart from a real cross-site post.
		h.logger.Info("hosted_action_cross_origin_rejected",
			zap.String("page", kind.path),
			zap.String("host", r.Host),
			zap.String("sec_fetch_site", r.Header.Get("Sec-Fetch-Site")),
			zap.String("origin", r.Header.Get("Origin")),
			zap.Error(err))
		page := h.newActionPage(r, kind, "", service.ActionLinkPreview{})
		page.setState(stateRefused)
		page.Message = "This request didn't come from this site's own page. Open the link from your email again."
		h.renderAction(w, r, kind, page, http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxActionFormBytes)
	if err := r.ParseForm(); err != nil {
		h.plainError(w, http.StatusBadRequest, "bad request")
		return
	}
	token := r.PostForm.Get("token")
	preview, err := kind.peek(r.Context(), h.src, token)
	if err != nil {
		h.logger.Error("hosted_action_peek_failed", zap.String("page", kind.path), zap.Error(err))
		page := h.newActionPage(r, kind, token, service.ActionLinkPreview{})
		page.setState(stateError)
		h.renderAction(w, r, kind, page, http.StatusInternalServerError)
		return
	}
	page := h.newActionPage(r, kind, token, preview)
	page.Name = strings.TrimSpace(r.PostForm.Get("name"))
	if preview.State != service.ActionLinkReady {
		// A click on a page rendered before the link expired or was used
		// elsewhere: report the state, consume nothing.
		page.setState(string(preview.State))
		h.renderAction(w, r, kind, page, http.StatusOK)
		return
	}

	in := actionInput{
		token:     token,
		name:      page.Name,
		ipAddr:    middleware.ClientIPFromContext(r.Context()),
		userAgent: r.UserAgent(),
	}
	if kind.askPassword {
		in.password = r.PostForm.Get("password")
		if msg := passwordFormError(in.password, r.PostForm.Get("password_confirm")); msg != "" {
			page.setState(string(service.ActionLinkReady))
			page.Error = msg
			h.renderAction(w, r, kind, page, http.StatusBadRequest)
			return
		}
	}

	result, err := kind.act(r.Context(), h.src, in)
	if err != nil {
		status := h.applyActionError(page, kind, err)
		h.renderAction(w, r, kind, page, status)
		return
	}
	if result.redirectURL != "" {
		// The target is the link's stored return_to, allowlist-checked when
		// the link was requested and again before it was consumed; it is
		// not request input. The redirect carries the single-use code, so
		// it gets the same no-store / no-referrer headers as a page.
		nonce, err := newNonce()
		if err != nil {
			h.plainError(w, http.StatusInternalServerError, "internal error")
			return
		}
		setSecurityHeaders(w.Header(), pagePolicy{nonce: nonce})
		http.Redirect(w, r, result.redirectURL, http.StatusSeeOther)
		return
	}
	h.logger.Info("hosted_action_completed", zap.String("page", kind.path))
	page.setState(stateDone)
	h.renderAction(w, r, kind, page, http.StatusOK)
}

// passwordFormError validates the two password fields before the service is
// asked to spend the token on them, so a typo re-renders the form with the
// link still live.
func passwordFormError(password, confirm string) string {
	if password == "" {
		return "Enter a password."
	}
	if password != confirm {
		return "The two passwords don't match."
	}
	return ""
}

// applyActionError maps a service error to what the page says and the status
// it says it with. Link outcomes (expired, used, invalid) are ordinary page
// states; a policy refusal names itself without detail; a bad password
// re-renders the form with the requirement that failed; anything else is a
// server error the operator hears about in the log, not the user.
func (h *handler) applyActionError(page *actionPage, kind actionKind, err error) int {
	switch {
	case errors.Is(err, service.ErrTokenExpired), errors.Is(err, service.ErrInvitationExpired):
		page.setState(string(service.ActionLinkExpired))
		return http.StatusOK
	case errors.Is(err, service.ErrInvitationUsed):
		page.setState(string(service.ActionLinkUsed))
		return http.StatusOK
	case errors.Is(err, service.ErrMagicLinkInvalid),
		errors.Is(err, service.ErrUnauthenticated),
		errors.Is(err, service.ErrNotFound),
		errors.Is(err, service.ErrInvalidArgument):
		page.setState(string(service.ActionLinkInvalid))
		return http.StatusOK
	case errors.Is(err, service.ErrWeakPassword):
		page.setState(string(service.ActionLinkReady))
		page.Error = passwordRequirements(err)
		return http.StatusBadRequest
	case errors.Is(err, service.ErrInvitationPending):
		// The account exists but has not accepted its invitation, so no
		// other link can act on it yet.
		h.logger.Info("hosted_action_refused", zap.String("page", kind.path), zap.Error(err))
		page.setState(statePending)
		return http.StatusForbidden
	case errors.Is(err, service.ErrAlreadyExists):
		page.setState(string(service.ActionLinkReady))
		page.Error = "That email address is already in use by another account."
		return http.StatusConflict
	case errors.Is(err, service.ErrAccessNotAllowed),
		errors.Is(err, service.ErrSignupByInvitationOnly),
		errors.Is(err, service.ErrAccountNotActive),
		errors.Is(err, service.ErrAccountLocked),
		errors.Is(err, service.ErrSSORequired),
		errors.Is(err, service.ErrPermissionDenied),
		errors.Is(err, service.ErrIDVRequired),
		errors.Is(err, service.ErrParentalConsentRequired):
		h.logger.Info("hosted_action_refused", zap.String("page", kind.path), zap.Error(err))
		page.setState(stateRefused)
		return http.StatusForbidden
	}
	h.logger.Error("hosted_action_failed", zap.String("page", kind.path), zap.Error(err))
	page.setState(stateError)
	return http.StatusInternalServerError
}

// passwordRequirements turns the service's weak-password error into the
// sentence the form shows: the requirements that failed, read from the
// typed error rather than parsed out of its message.
func passwordRequirements(err error) string {
	var weak *service.WeakPasswordError
	if errors.As(err, &weak) && len(weak.Issues) > 0 {
		return strings.Join(weak.Issues, ". ") + "."
	}
	return "This password doesn't meet the requirements."
}

// newActionPage builds the page data shared by every state of an action
// page for this request: branding, copy with the address and product filled
// in, and the URLs the form and the onward link use.
func (h *handler) newActionPage(r *http.Request, kind actionKind, token string, preview service.ActionLinkPreview) *actionPage {
	brand := h.src.Auth.HostedUIBranding(r.Context())
	toProduct := ""
	if brand.ProductName != "" {
		toProduct = " to " + brand.ProductName
	}
	detail := preview.Detail
	if detail == "" {
		detail = kind.text.DetailFallback
	}
	fill := strings.NewReplacer("{email}", preview.Email, "{to_product}", toProduct, "{detail}", detail)

	// A hub-served page carries the project in its query; the form and the
	// onward link keep it so the POST and the sign-in page resolve the same
	// project (the middleware reads project_key from the query on /auth/*).
	scope := url.Values{}
	if key := r.URL.Query().Get(middleware.ProjectKeyParam); key != "" {
		scope.Set(middleware.ProjectKeyParam, key)
	}
	withScope := func(path string) string {
		if len(scope) == 0 {
			return path
		}
		return path + "?" + scope.Encode()
	}

	heading := fill.Replace(kind.text.Heading)
	return &actionPage{
		Title:        heading,
		Heading:      heading,
		Intro:        fill.Replace(kind.text.Intro),
		Email:        preview.Email,
		Token:        token,
		FormAction:   withScope(kind.path),
		AskName:      kind.askName,
		AskPassword:  kind.askPassword,
		Submit:       kind.text.Submit,
		Next:         kind.text.Next,
		SignInURL:    withScope(loginPath),
		SupportEmail: brand.SupportEmail,
		text:         kind.text,
	}
}

// setState selects the copy for a state.
func (p *actionPage) setState(state string) {
	p.State = state
	switch state {
	case string(service.ActionLinkReady):
		p.Message = ""
	case stateDone:
		p.Message = p.text.Done
	case stateInfo:
		p.Message = p.Intro
	case statePending:
		p.Message = "This account hasn't accepted its invitation yet. Open the invitation email and set up the account first."
	case string(service.ActionLinkUsed):
		p.Message = p.text.Used
	case string(service.ActionLinkExpired):
		p.Message = p.text.Expired
	case string(service.ActionLinkInvalid):
		p.Message = p.text.Invalid
	case stateRefused:
		p.Message = "This account can't be used here right now. Contact support if you think this is a mistake."
	default:
		p.State = stateError
		p.Message = "Something went wrong on our side. Try again in a moment."
	}
}

func (h *handler) renderAction(w http.ResponseWriter, r *http.Request, kind actionKind, page *actionPage, status int) {
	nonce, err := newNonce()
	if err != nil {
		h.plainError(w, http.StatusInternalServerError, "internal error")
		return
	}
	policy := pagePolicy{nonce: nonce, formAction: !kind.redirects}
	if r.Method == http.MethodHead {
		// Only the status and headers reach the client; skip the render.
		setSecurityHeaders(w.Header(), policy)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		return
	}
	page.Nonce = nonce
	var buf bytes.Buffer
	if err := h.action.ExecuteTemplate(&buf, "layout.html", page); err != nil {
		h.logger.Error("hosted_action_render_failed", zap.String("page", kind.path), zap.Error(err))
		h.plainError(w, http.StatusInternalServerError, "internal error")
		return
	}
	setSecurityHeaders(w.Header(), policy)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}
