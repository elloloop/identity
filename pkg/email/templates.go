package email

import (
	"bytes"
	"embed"
	"fmt"
	htmltpl "html/template"
	"strings"
	texttpl "text/template"
)

//go:embed templates/*.html templates/*.txt
var templateFS embed.FS

// Known template names. Keep this list in sync with templates/.
const (
	TemplatePasswordReset     = "password_reset"
	TemplateEmailVerification = "email_verification"
	TemplateInvitation        = "invitation"
	// TemplateEmailChangeVerify is sent to the *new* address with the
	// verification link to confirm the email change.
	TemplateEmailChangeVerify = "email_change_verify"
	// TemplateEmailChangeNotice is sent to the *old* address as a
	// security notice that an email change has been requested.
	TemplateEmailChangeNotice = "email_change_notice"
	// TemplateEmailLoginCode carries the 6-digit OTP for passwordless
	// email login.
	TemplateEmailLoginCode = "email_login_code"
	// TemplateMagicLink carries the clickable single-use sign-in link for
	// passwordless email login.
	TemplateMagicLink = "magic_link"
)

// Render returns the HTML and plain-text bodies for the given template name,
// with data substituted. The HTML side uses html/template (auto-escaping); the
// text side uses text/template.
//
// Returns a wrapped error if the template is unknown or if execution fails.
func Render(name string, data any) (html, text string, err error) {
	htmlPath := "templates/" + name + ".html"
	textPath := "templates/" + name + ".txt"

	htmlSrc, err := templateFS.ReadFile(htmlPath)
	if err != nil {
		return "", "", fmt.Errorf("email: unknown template %q: %w", name, err)
	}
	textSrc, err := templateFS.ReadFile(textPath)
	if err != nil {
		return "", "", fmt.Errorf("email: unknown template %q: %w", name, err)
	}

	htmlT, err := htmltpl.New(name + ".html").Parse(string(htmlSrc))
	if err != nil {
		return "", "", fmt.Errorf("email: parse html template %q: %w", name, err)
	}
	textT, err := texttpl.New(name + ".txt").Parse(string(textSrc))
	if err != nil {
		return "", "", fmt.Errorf("email: parse text template %q: %w", name, err)
	}

	var hb, tb bytes.Buffer
	if err := htmlT.Execute(&hb, data); err != nil {
		return "", "", fmt.Errorf("email: render html template %q: %w", name, err)
	}
	if err := textT.Execute(&tb, data); err != nil {
		return "", "", fmt.Errorf("email: render text template %q: %w", name, err)
	}
	return hb.String(), strings.TrimRight(tb.String(), "\n") + "\n", nil
}
