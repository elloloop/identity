package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/origin"
	"github.com/elloloop/identity/internal/service"
)

// withProjectOrigins returns a request whose context carries a ProjectScope
// with the given per-project CORS allow-list, as the project resolver would.
func withProjectOrigins(t *testing.T, req *http.Request, origins ...string) *http.Request {
	t.Helper()
	allow, err := ValidateAllowedOrigins(origins, true)
	require.NoError(t, err)
	ctx := service.WithProjectScope(req.Context(), &service.ProjectScope{
		ProjectID:          "proj-A",
		CORSAllowedOrigins: allow,
	})
	return req.WithContext(ctx)
}

func nopHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func mustParse(t *testing.T, raw string) origin.Allowlist {
	t.Helper()
	out, err := ParseAllowedOrigins(raw, true)
	require.NoError(t, err)
	return out
}

func TestCORS_AllowedOrigin_SetsHeaders(t *testing.T) {
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002,http://localhost:3000"))(nopHandler())

	req := httptest.NewRequest(http.MethodPost, "/identity.v1.IdentityService/GetCurrentUser", nil)
	req.Header.Set("Origin", "http://localhost:9002")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, "http://localhost:9002", rec.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", rec.Header().Get("Access-Control-Allow-Credentials"))
	assert.Equal(t, "grpc-status,grpc-message", rec.Header().Get("Access-Control-Expose-Headers"))
}

func TestCORS_DisallowedOrigin_NoHeaders(t *testing.T) {
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())

	req := httptest.NewRequest(http.MethodPost, "/identity.v1.IdentityService/GetCurrentUser", nil)
	req.Header.Set("Origin", "http://evil.example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"))
	assert.Empty(t, rec.Header().Get("Access-Control-Expose-Headers"))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCORS_OriginCaseMismatch_Rejected(t *testing.T) {
	cases := []struct{ name, origin string }{
		{"uppercase host", "http://LOCALHOST:9002"},
		{"mixed case host", "http://LocalHost:9002"},
		{"uppercase scheme", "HTTP://localhost:9002"},
	}
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.Header.Set("Origin", tc.origin)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
		})
	}
}

func TestCORS_PortDifference_Rejected(t *testing.T) {
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Origin", "http://localhost:9003")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_Preflight_Returns204(t *testing.T) {
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())
	req := httptest.NewRequest(http.MethodOptions, "/identity.v1.IdentityService/GetCurrentUser", nil)
	req.Header.Set("Origin", "http://localhost:9002")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "http://localhost:9002", rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_Preflight_SetsAllowMethods(t *testing.T) {
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())
	req := httptest.NewRequest(http.MethodOptions, "/identity.v1.IdentityService/GetCurrentUser", nil)
	req.Header.Set("Origin", "http://localhost:9002")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, "POST, OPTIONS", rec.Header().Get("Access-Control-Allow-Methods"))
	assert.Contains(t, rec.Header().Get("Access-Control-Allow-Headers"), "authorization")
	assert.Equal(t, "86400", rec.Header().Get("Access-Control-Max-Age"))
}

func TestCORS_Preflight_AllowsGrpcWebRequestHeaders(t *testing.T) {
	// Regression: browser gRPC-Web clients (grpc-dart, grpc-web js) send
	// x-user-agent, x-grpc-web and grpc-timeout on the actual request, so a
	// preflight naming them must be permitted or every gRPC-Web call from a
	// browser fails CORS even when the origin is allowed.
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())
	req := httptest.NewRequest(http.MethodOptions, "/identity.v1.IdentityService/PasswordSignup", nil)
	req.Header.Set("Origin", "http://localhost:9002")
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Access-Control-Request-Headers", "content-type, x-user-agent, x-grpc-web, grpc-timeout")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	allowed := rec.Header().Get("Access-Control-Allow-Headers")
	for _, header := range []string{"x-user-agent", "x-grpc-web", "grpc-timeout"} {
		assert.Contains(t, allowed, header)
	}
}

func TestCORS_Preflight_AllowsProjectKeyHeader(t *testing.T) {
	// Regression: a browser SPA selecting a non-default control-plane project
	// sends the publishable key as x-project-key; the preflight must permit it or
	// the cross-origin call fails CORS even when the origin is allowed.
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())
	req := httptest.NewRequest(http.MethodOptions, "/identity.v1.IdentityService/RequestEmailLoginCode", nil)
	req.Header.Set("Origin", "http://localhost:9002")
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Access-Control-Request-Headers", "content-type, x-project-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Contains(t, rec.Header().Get("Access-Control-Allow-Headers"), "x-project-key")
}

func TestCORS_Preflight_AllowsProductHeader(t *testing.T) {
	// Regression: a browser SPA names the product it is authenticating for with
	// x-product, which the per-product age guardrails gate on. Without it in the
	// preflight allow-list every SPA silently falls back to the deployment
	// default product, whatever origin allow-listing says.
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())
	req := httptest.NewRequest(http.MethodOptions, "/identity.v1.IdentityService/PasswordLogin", nil)
	req.Header.Set("Origin", "http://localhost:9002")
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Access-Control-Request-Headers", "content-type, x-product")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Contains(t, rec.Header().Get("Access-Control-Allow-Headers"), "x-product")
}

func TestCORS_Preflight_AllowsAssuranceTokenHeader(t *testing.T) {
	// Regression: the client-assurance token moved from a request BODY field
	// (captcha_token, which had no preflight implications) to the
	// X-Assurance-Token header. Without it in the allow-list, a cross-origin
	// SPA can complete the exchange and then never attach the token — every
	// gated auth endpoint fails CORS with no server-side signal.
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())
	req := httptest.NewRequest(http.MethodOptions, "/identity.v1.IdentityService/PasswordLogin", nil)
	req.Header.Set("Origin", "http://localhost:9002")
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Access-Control-Request-Headers", "content-type, x-assurance-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Contains(t, rec.Header().Get("Access-Control-Allow-Headers"), "x-assurance-token")
}

func TestCORS_Preflight_DisallowedOrigin_StillReturns204(t *testing.T) {
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())
	req := httptest.NewRequest(http.MethodOptions, "/some-path", nil)
	req.Header.Set("Origin", "http://evil.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_NoOriginHeader_PassesThroughUnchanged(t *testing.T) {
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())
	req := httptest.NewRequest(http.MethodPost, "/some-path", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ── per-project CORS (layered on the global floor) ─────────────────────

func TestCORS_ProjectOrigin_Allowed_GlobalFloorPreserved(t *testing.T) {
	// Global floor allows localhost; project A additionally allows its own
	// app origin. Both must be accepted on a request resolved to project A.
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())

	for _, origin := range []string{"http://localhost:9002", "https://app-a.example.com"} {
		req := httptest.NewRequest(http.MethodPost, "/identity.v1.IdentityService/GetCurrentUser", nil)
		req.Header.Set("Origin", origin)
		req = withProjectOrigins(t, req, "https://app-a.example.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, origin, rec.Header().Get("Access-Control-Allow-Origin"), origin)
		assert.Equal(t, "true", rec.Header().Get("Access-Control-Allow-Credentials"), origin)
	}
}

func TestCORS_ProjectOrigin_OtherProjectOrigin_Rejected(t *testing.T) {
	// An origin configured for a DIFFERENT project (not in scope) is not
	// allowed: only the resolved project's list plus the global floor apply.
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())

	req := httptest.NewRequest(http.MethodPost, "/identity.v1.IdentityService/GetCurrentUser", nil)
	req.Header.Set("Origin", "https://app-b.example.com")
	req = withProjectOrigins(t, req, "https://app-a.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_NoProjectScope_OnlyGlobalFloorApplies(t *testing.T) {
	// An unresolved request (no ProjectScope in context) falls back to the
	// global allow-list — the project origin is not magically allowed.
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())

	allowed := httptest.NewRequest(http.MethodPost, "/", nil)
	allowed.Header.Set("Origin", "http://localhost:9002")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, allowed)
	assert.Equal(t, "http://localhost:9002", rec.Header().Get("Access-Control-Allow-Origin"))

	denied := httptest.NewRequest(http.MethodPost, "/", nil)
	denied.Header.Set("Origin", "https://app-a.example.com")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, denied)
	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_ProjectOrigin_Preflight_Returns204WithHeaders(t *testing.T) {
	// The OPTIONS preflight resolves the project by Host (ahead of auth), so
	// a project origin must be echoed on the preflight too.
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())

	req := httptest.NewRequest(http.MethodOptions, "/identity.v1.IdentityService/GetCurrentUser", nil)
	req.Header.Set("Origin", "https://app-a.example.com")
	req = withProjectOrigins(t, req, "https://app-a.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "https://app-a.example.com", rec.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "POST, OPTIONS", rec.Header().Get("Access-Control-Allow-Methods"))
}

func TestValidateAllowedOrigins_StructuredInput(t *testing.T) {
	out, err := ValidateAllowedOrigins([]string{"https://A.example.com", " http://localhost:9002 "}, true)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://A.example.com", "http://localhost:9002"}, out.Exact())

	_, err = ValidateAllowedOrigins([]string{"*"}, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wildcard")

	_, err = ValidateAllowedOrigins(nil, true)
	require.ErrorIs(t, err, ErrAllowedOriginsEmpty)
}

func TestParseAllowedOrigins_WildcardWithCredentials_Rejected(t *testing.T) {
	cases := []string{"*", "http://localhost:9002,*", "*,http://localhost:9002", " * "}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			_, err := ParseAllowedOrigins(raw, true)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "wildcard")
		})
	}
}

func TestParseAllowedOrigins_NullOriginWithCredentials_Rejected(t *testing.T) {
	_, err := ParseAllowedOrigins("http://localhost:9002,null", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "null")
}

func TestParseAllowedOrigins_EmptyEntryWithCredentials_Rejected(t *testing.T) {
	_, err := ParseAllowedOrigins("http://localhost:9002,", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty origin entry")
}

func TestParseAllowedOrigins_EmptyList_Rejected(t *testing.T) {
	_, err := ParseAllowedOrigins("", true)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAllowedOriginsEmpty))
}

func TestParseAllowedOrigins_MalformedOrigin_Rejected(t *testing.T) {
	cases := []string{
		"localhost:9002",            // missing scheme
		"ftp://localhost:9002",      // wrong scheme
		"http://localhost:9002/",    // trailing slash
		"http://localhost:9002/x",   // path
		"http://localhost:9002?q=1", // query
		"http://localhost:9002#f",   // fragment
		"http://user@localhost",     // userinfo
		"HTTP://localhost:9002",     // uppercase scheme
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			_, err := ParseAllowedOrigins(raw, true)
			require.Error(t, err)
		})
	}
}

func TestParseAllowedOrigins_ValidList_PreservesOrderAndCase(t *testing.T) {
	out, err := ParseAllowedOrigins("https://A.example.com,http://localhost:9002 , https://b.example.com", true)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://A.example.com", "http://localhost:9002", "https://b.example.com"}, out.Exact())
}

// ── Coverage for non-credentialed and edge paths ───────────────────────

func TestParseAllowedOrigins_NoCredentials_AllowsEmptyEntries(t *testing.T) {
	out, err := ParseAllowedOrigins("http://a.example.com,,http://b.example.com", false)
	require.NoError(t, err)
	assert.Equal(t, []string{"http://a.example.com", "http://b.example.com"}, out.Exact())
}

func TestParseAllowedOrigins_NoCredentials_OnlyEmpty_ReturnsErr(t *testing.T) {
	_, err := ParseAllowedOrigins(",,,", false)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAllowedOriginsEmpty))
}

func TestParseAllowedOrigins_WhitespaceInsideOrigin_Rejected(t *testing.T) {
	_, err := ParseAllowedOrigins("http://bad host:9002", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "whitespace")
}

func TestParseAllowedOrigins_HostEmpty_Rejected(t *testing.T) {
	_, err := ParseAllowedOrigins("http://", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "host")
}

func TestCORS_PreflightWithoutOrigin_Returns204(t *testing.T) {
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

// ── Vary and one-label wildcard patterns ───────────────────────────────

func TestCORS_VaryOrigin_OnEveryResponse(t *testing.T) {
	handler := CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())
	for _, tc := range []struct{ name, method, origin string }{
		{"allowed", http.MethodPost, "http://localhost:9002"},
		{"disallowed", http.MethodPost, "https://evil.example.app"},
		{"preflight", http.MethodOptions, "http://localhost:9002"},
		{"no_origin", http.MethodPost, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, []string{"Origin"}, rec.Header().Values("Vary"))
		})
	}
}

func TestCORS_PatternOrigin(t *testing.T) {
	const pattern = "https://*.previews.example.app"
	cases := []struct {
		name, origin string
		want         bool
	}{
		{"one_label", "https://feature-1.previews.example.app", true},
		{"two_labels", "https://a.b.previews.example.app", false},
		{"bare_parent", "https://previews.example.app", false},
		{"http", "http://feature-1.previews.example.app", false},
		{"port_mismatch", "https://feature-1.previews.example.app:8443", false},
		{"sibling_domain", "https://feature-1.previews.example.net", false},
		{"mixed_case_host", "https://Feature-1.Previews.example.app", true},
	}
	scopes := map[string]func(*testing.T, *http.Request) (*http.Request, http.Handler){
		"global": func(t *testing.T, r *http.Request) (*http.Request, http.Handler) {
			t.Helper()
			return r, CORSMiddleware(mustParse(t, "http://localhost:9002,"+pattern))(nopHandler())
		},
		"project": func(t *testing.T, r *http.Request) (*http.Request, http.Handler) {
			t.Helper()
			return withProjectOrigins(t, r, pattern), CORSMiddleware(mustParse(t, "http://localhost:9002"))(nopHandler())
		},
	}
	for scopeName, build := range scopes {
		for _, method := range []string{http.MethodOptions, http.MethodPost} {
			for _, tc := range cases {
				t.Run(scopeName+"/"+method+"/"+tc.name, func(t *testing.T) {
					req := httptest.NewRequest(method, "/identity.v1.IdentityService/RedeemOAuthCode", nil)
					req.Header.Set("Origin", tc.origin)
					req, handler := build(t, req)
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)
					if !tc.want {
						assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
						assert.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"))
						return
					}
					assert.Equal(t, tc.origin, rec.Header().Get("Access-Control-Allow-Origin"), "echoes the concrete origin, never the pattern")
					assert.Equal(t, "true", rec.Header().Get("Access-Control-Allow-Credentials"))
					assert.Equal(t, []string{"Origin"}, rec.Header().Values("Vary"))
				})
			}
		}
	}
}

func TestValidateAllowedOrigins_Patterns(t *testing.T) {
	out, err := ValidateAllowedOrigins([]string{"https://app.example.app", "https://*.previews.example.app"}, true)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://app.example.app"}, out.Exact())
	assert.Equal(t, []string{"https://*.previews.example.app"}, out.Patterns())

	out, err = ValidateAllowedOrigins([]string{"https://*.previews.example.app"}, true)
	require.NoError(t, err, "a pattern alone is a non-empty allow-list")
	assert.Empty(t, out.Exact())
}

func TestParseAllowedOrigins_InvalidPattern_Rejected(t *testing.T) {
	cases := []struct {
		raw     string
		wantErr error
		wantMsg string
	}{
		{raw: "*", wantMsg: "wildcard"},
		{raw: "https://*", wantErr: origin.ErrPatternParentShort},
		{raw: "*.com", wantMsg: "scheme"},
		{raw: "http://*.previews.example.app", wantErr: origin.ErrPatternScheme},
		{raw: "https://a.*.example.app", wantErr: origin.ErrPatternLabel},
		{raw: "https://*.app", wantErr: origin.ErrPatternParentShort},
		{raw: "https://pr-*.example.app", wantErr: origin.ErrPatternLabel},
		{raw: "https://*.*.example.app", wantErr: origin.ErrPatternParentLabel},
		{raw: "https://*.previews.example.app/", wantMsg: "path not allowed"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			_, err := ParseAllowedOrigins("http://localhost:9002,"+tc.raw, true)
			require.Error(t, err)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
			}
			assert.Contains(t, err.Error(), tc.wantMsg)
		})
	}
}
