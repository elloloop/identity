package ui

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
)

func TestAgentConsentHandlerUsesPrivatePerRequestConfiguration(t *testing.T) {
	h := AgentConsentHandler(&config.Config{}, scopeOptions{}, service.ReturnAllowlist{})
	for _, project := range []string{"proj-google", "default"} {
		req := httptest.NewRequest(http.MethodGet, "/auth/agent-consent?request_id=private-request", nil)
		req = req.WithContext(service.WithProjectScope(req.Context(), &service.ProjectScope{ProjectID: project}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("unsafe response: status %d, headers %v", rec.Code, rec.Header())
		}
		want := `"passwordLoginEnabled":true`
		if project == "proj-google" {
			want = `"passwordLoginEnabled":false`
		}
		if !strings.Contains(rec.Body.String(), want) || strings.Contains(rec.Body.String(), "private-request") {
			t.Fatal("request configuration missing or request identifier reflected into HTML")
		}
		csp := rec.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "script-src 'unsafe-inline'") {
			t.Fatalf("unsafe CSP: %s", csp)
		}
		nonce := regexp.MustCompile(`nonce="([^"]+)"`).FindStringSubmatch(rec.Body.String())
		if len(nonce) != 2 || !strings.Contains(csp, "'nonce-"+nonce[1]+"'") {
			t.Fatal("executable scripts need matching unpredictable CSP nonce")
		}
	}
}

func TestAgentConsentConfigurationEscapesOperatorText(t *testing.T) {
	cfg := &config.Config{AssuranceEnabled: true, AssuranceWebProvider: config.AssuranceWebProviderTurnstile, AssuranceTurnstileSiteKey: `</script><script>alert(1)</script>`, AssuranceEnforcePasswordLogin: true}
	h := AgentConsentHandler(cfg, allEnabled(), service.ReturnAllowlist{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/agent-consent", nil))
	if strings.Contains(rec.Body.String(), `</script><script>alert(1)</script>`) || !strings.Contains(rec.Body.String(), `\u003c/script\u003e`) {
		t.Fatal("operator text must stay inside inert JSON")
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-src https://challenges.cloudflare.com") {
		t.Fatal("configured CAPTCHA needs its narrowly allowed frame origin")
	}
}

func TestAgentConsentHandlerRejectsMutation(t *testing.T) {
	rec := httptest.NewRecorder()
	AgentConsentHandler(&config.Config{}, allEnabled(), service.ReturnAllowlist{}).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/agent-consent", nil))
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodGet {
		t.Fatal("consent HTML must never accept a mutation")
	}
}

func TestAgentConsentOAuthReturnPolicyAndScopedProviders(t *testing.T) {
	allow, err := service.ParseReturnAllowlist("https://auth.example.test/auth/agent-consent")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, address, forwardedHost, forwardedProto string
		enabled                                      bool
	}{
		{name: "direct TLS", address: "https://auth.example.test/auth/agent-consent", enabled: true},
		{name: "Azure forwarded", address: "http://internal.example.test/auth/agent-consent", forwardedHost: "auth.example.test", forwardedProto: "https", enabled: true},
		{name: "other project host", address: "https://other.example.test/auth/agent-consent"},
		{name: "HTTP not allowed", address: "http://auth.example.test/auth/agent-consent"},
		{name: "ambiguous scheme", address: "http://auth.example.test/auth/agent-consent", forwardedProto: "https,http"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := stubOptions{opts: service.HostedUIOptions{OAuthProviders: []service.HostedUIProvider{{Key: "google", StartOrigin: "https://hub.example.test", NeedsProjectKey: true}}}}
			r := httptest.NewRequest(http.MethodGet, tc.address, nil)
			if tc.forwardedHost != "" {
				r.Header.Set("X-Forwarded-Host", tc.forwardedHost)
			}
			if tc.forwardedProto != "" {
				r.Header.Set("X-Forwarded-Proto", tc.forwardedProto)
			}
			w := httptest.NewRecorder()
			AgentConsentHandler(&config.Config{}, opts, allow).ServeHTTP(w, r)
			want := `"hostedOAuthEnabled":false`
			if tc.enabled {
				want = `"hostedOAuthEnabled":true`
			}
			if !strings.Contains(w.Body.String(), want) || !strings.Contains(w.Body.String(), `"startOrigin":"https://hub.example.test","needsProjectKey":true`) {
				t.Fatal("wrong return policy or scoped provider projection")
			}
		})
	}
}
