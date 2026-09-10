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
	// stateRefused: the project's policy or the account's status refused
	// the action; the link itself was fine.
	stateRefused = "refused"
	// stateError: the server could not complete the request.
	stateError = "error"
)

// actionText is the copy of one action page. {email} is the address the
// link concerns and {to_product} expands to " to <Product>" when the project
// has a product name, else to "".
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
	peek      func(ctx context.Context, svc Service, token string) (service.ActionLinkPreview, error)
	act       func(ctx context.Context, svc Service, in actionInput) (actionResult, error)
}

// actionKinds is the table of hosted action pages. The paths are the ones
// identity's own emails already link to ({base}/auth/<action>?token=…).
func actionKinds() []actionKind {
	const notYouHint = " If you didn't request this, you can ignore the email."
	return []actionKind{
		{
			path: "/auth/verify-email",
			text: actionText{
				Heading: "Verify your email",
				Intro:   "Confirm that {email} is your email address{to_product}.",
				Submit:  "Confirm email",
				Done:    "Your email address is verified. You can close this page or sign in.",
				Used:    "This link has already been used. If you verified your email, you're all set.",
				Expired: "This verification link has expired. Sign in to request a new one.",
				Invalid: "This verification link isn't valid. Make sure you opened the full link from the email.",
				Next:    "Sign in",
			},
			peek: func(ctx context.Context, svc Service, token string) (service.ActionLinkPreview, error) {
				return svc.PeekEmailVerification(ctx, token)
			},
			act: func(ctx context.Context, svc Service, in actionInput) (actionResult, error) {
				_, err := svc.VerifyEmail(ctx, in.token)
				return actionResult{}, err
			},
		},
		{
			path: "/auth/reset-password",
			text: actionText{
				Heading: "Choose a new password",
				Intro:   "Set a new password for {email}." + notYouHint,
				Submit:  "Update password",
				Done:    "Your password has been updated. You've been signed out everywhere; sign in with your new password.",
				Used:    "This reset link has already been used. If you didn't change your password, request a new link.",
				Expired: "This reset link has expired. Request a new one from the sign-in page.",
				Invalid: "This reset link isn't valid. Make sure you opened the full link from the email.",
				Next:    "Sign in",
			},
			askPassword: true,
			peek: func(ctx context.Context, svc Service, token string) (service.ActionLinkPreview, error) {
				return svc.PeekPasswordReset(ctx, token)
			},
			act: func(ctx context.Context, svc Service, in actionInput) (actionResult, error) {
				return actionResult{}, svc.ConfirmPasswordReset(ctx, in.token, in.password)
			},
		},
		{
			path: "/auth/confirm-email-change",
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
			peek: func(ctx context.Context, svc Service, token string) (service.ActionLinkPreview, error) {
				return svc.PeekEmailChange(ctx, token)
			},
			act: func(ctx context.Context, svc Service, in actionInput) (actionResult, error) {
				_, err := svc.ConfirmEmailChange(ctx, in.token)
				return actionResult{}, err
			},
		},
		{
			path: "/auth/magic-link",
			text: actionText{
				Heading: "Sign in{to_product}",
				Intro:   "Continue to sign in as {email}.",
				Submit:  "Continue",
				Used:    "This sign-in link has already been used. Request a new one.",
				Expired: "This sign-in link has expired. Request a new one.",
				Invalid: "This sign-in link isn't valid. Make sure you opened the full link from the email.",
				Next:    "Back to sign in",
			},
			redirects: true,
			peek: func(ctx context.Context, svc Service, token string) (service.ActionLinkPreview, error) {
				return svc.PeekMagicLink(ctx, token)
			},
			act: func(ctx context.Context, svc Service, in actionInput) (actionResult, error) {
				handover, err := svc.RedeemMagicLinkForHandover(ctx, in.token, in.ipAddr, in.userAgent)
				if err != nil {
					return actionResult{}, err
				}
				return actionResult{redirectURL: handover.RedirectURL}, nil
			},
		},
		{
			path: "/auth/accept-invitation",
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
			peek: func(ctx context.Context, svc Service, token string) (service.ActionLinkPreview, error) {
				return svc.PeekInvitation(ctx, token)
			},
			act: func(ctx context.Context, svc Service, in actionInput) (actionResult, error) {
				_, err := svc.RedeemInvitation(ctx, in.token, in.password, in.name)
				return actionResult{}, err
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
		h.serveActionPost(w, r, kind)
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// serveActionGet renders the page for the link the user opened. It only
// looks: the token is previewed, never consumed, so a mail scanner or a
// preview fetch cannot spend it.
func (h *handler) serveActionGet(w http.ResponseWriter, r *http.Request, kind actionKind) {
	token := r.URL.Query().Get("token")
	preview, err := kind.peek(r.Context(), h.svc, token)
	if err != nil {
		h.logger.Error("hosted_action_peek_failed", zap.String("page", kind.path), zap.Error(err))
		page := h.newActionPage(r, kind, token, "")
		page.setState(stateError)
		h.renderAction(w, r, kind, page, http.StatusInternalServerError)
		return
	}
	page := h.newActionPage(r, kind, token, preview.Email)
	page.setState(string(preview.State))
	h.renderAction(w, r, kind, page, http.StatusOK)
}

// serveActionPost is the click: the one request that consumes the token.
func (h *handler) serveActionPost(w http.ResponseWriter, r *http.Request, kind actionKind) {
	if err := h.crossOrigin.Check(r); err != nil {
		h.logger.Info("hosted_action_cross_origin_rejected", zap.String("page", kind.path))
		page := h.newActionPage(r, kind, "", "")
		page.setState(stateRefused)
		page.Message = "This request didn't come from this site's own page. Open the link from your email again."
		h.renderAction(w, r, kind, page, http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxActionFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	token := r.PostForm.Get("token")
	preview, err := kind.peek(r.Context(), h.svc, token)
	if err != nil {
		h.logger.Error("hosted_action_peek_failed", zap.String("page", kind.path), zap.Error(err))
		page := h.newActionPage(r, kind, token, "")
		page.setState(stateError)
		h.renderAction(w, r, kind, page, http.StatusInternalServerError)
		return
	}
	page := h.newActionPage(r, kind, token, preview.Email)
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

	result, err := kind.act(r.Context(), h.svc, in)
	if err != nil {
		status := h.applyActionError(page, kind, err)
		h.renderAction(w, r, kind, page, status)
		return
	}
	if result.redirectURL != "" {
		// The target is the link's stored return_to, allowlist-checked when
		// the link was requested and again when it was consumed; it is not
		// request input.
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
		page.Error = passwordIssues(err)
		return http.StatusBadRequest
	case errors.Is(err, service.ErrAlreadyExists):
		page.setState(string(service.ActionLinkReady))
		page.Error = "That email address is already in use by another account."
		return http.StatusConflict
	case errors.Is(err, service.ErrAccessNotAllowed),
		errors.Is(err, service.ErrSignupByInvitationOnly),
		errors.Is(err, service.ErrAccountNotActive),
		errors.Is(err, service.ErrAccountLocked),
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

// passwordIssues turns the service's weak-password error into the sentence
// the form shows: the requirement list after the sentinel's prefix, which is
// what the RPC surface already returns to API clients.
func passwordIssues(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, ": "); i >= 0 && i+2 < len(msg) {
		return msg[i+2:]
	}
	return "This password doesn't meet the requirements."
}

// newActionPage builds the page data shared by every state of an action
// page for this request: branding, copy with the address and product filled
// in, and the URLs the form and the onward link use.
func (h *handler) newActionPage(r *http.Request, kind actionKind, token, email string) *actionPage {
	brand := h.svc.HostedUIBranding(r.Context())
	toProduct := ""
	if brand.ProductName != "" {
		toProduct = " to " + brand.ProductName
	}
	fill := strings.NewReplacer("{email}", email, "{to_product}", toProduct)

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
		Email:        email,
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
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	page.Nonce = nonce
	var buf bytes.Buffer
	if err := h.action.ExecuteTemplate(&buf, "layout.html", page); err != nil {
		h.logger.Error("hosted_action_render_failed", zap.String("page", kind.path), zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	setSecurityHeaders(w.Header(), pagePolicy{nonce: nonce, formAction: !kind.redirects})
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(buf.Bytes())
}
