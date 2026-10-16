package ui

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/elloloop/identity/internal/config"
)

//go:generate pnpm --dir ../../../examples/agent-delegation/consent build
//go:embed agent_assets/consent.html
var agentConsentFS embed.FS

// AgentConsentHandler serves the human review screen. Authentication is kept
// in page memory; project-scoped RPCs independently enforce the live session.
func AgentConsentHandler(cfg *config.Config, options OptionsSource) http.Handler {
	page, err := agentConsentFS.ReadFile("agent_assets/consent.html")
	if err != nil {
		panic(err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		opts := options.HostedUIOptions(r.Context())
		settings := configData{
			PasswordLoginEnabled: opts.PasswordLoginEnabled,
			UsernameLoginEnabled: opts.UsernameLoginEnabled,
			CaptchaProvider:      captchaUIProvider(cfg),
			CaptchaSiteKey:       captchaUISiteKey(cfg),
			CaptchaEnforceLogin:  cfg.AssuranceEnabled && cfg.AssuranceEnforcePasswordLogin,
		}
		data, err := json.Marshal(settings)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		nonceBytes := make([]byte, 24)
		if _, err := rand.Read(nonceBytes); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		nonce := base64.RawStdEncoding.EncodeToString(nonceBytes)
		body := strings.Replace(string(page), "<!--IDENTITY_AGENT_CONFIG-->", `<script type="application/json" id="agent-config">`+string(data)+`</script>`, 1)
		body = strings.ReplaceAll(body, "<script", `<script nonce="`+nonce+`"`)
		csp := "default-src 'none'; script-src 'nonce-" + nonce + "'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
		if settings.CaptchaProvider == config.AssuranceWebProviderTurnstile && settings.CaptchaEnforceLogin {
			csp = "default-src 'none'; script-src 'nonce-" + nonce + "' https://challenges.cloudflare.com; style-src 'unsafe-inline'; connect-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
		}
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(body))
	})
}
