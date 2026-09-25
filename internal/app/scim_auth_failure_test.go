package app

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/pkg/audit"
)

// Graph data keys the audit logger writes (pkg/audit, unexported), read back
// to assert what a refused SCIM request recorded.
const (
	fieldActor     = "2"
	fieldIPAddress = "4"
	fieldUserAgent = "5"
	fieldSuccess   = "6"
	fieldDetails   = "7"
)

// A refused SCIM request leaves a warning log line and a scim_auth_failed
// audit entry under the SCIM project, carrying why it was refused and who
// sent it — never the token it presented.
func TestSCIM_FailedAuthIsLoggedAndAudited(t *testing.T) {
	const (
		clientIP  = "203.0.113.7"
		userAgent = "probe/1.0"
		wrong     = "not-the-scim-token-but-long-enough"
	)
	for _, tc := range []struct {
		name          string
		authorization string
		reason        string
	}{
		{"no header", "", scimRefusedMissingToken},
		{"empty bearer", "Bearer ", scimRefusedMissingToken},
		{"other scheme", "Basic " + testSCIMToken, scimRefusedMissingToken},
		{"wrong token", "Bearer " + wrong, scimRefusedInvalidToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zapcore.InfoLevel)
			h, _, _, aud := newSCIMObservedHandlerLogging(t, zap.New(core))

			req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
			if tc.authorization != "" {
				req.Header.Set("Authorization", tc.authorization)
			}
			req.Header.Set(middleware.ClientIPHeader, clientIP)
			req.Header.Set("User-Agent", userAgent)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}

			writes := aud.all()
			if len(writes) != 1 || writes[0].eventType != string(audit.EventSCIMAuthFailed) {
				t.Fatalf("audit writes = %+v, want one %s", writes, audit.EventSCIMAuthFailed)
			}
			w := writes[0]
			if w.projectID != testSCIMProjectID {
				t.Fatalf("audit landed under project %q, want %q", w.projectID, testSCIMProjectID)
			}
			if w.data[fieldActor] != scimAuditActor || w.data[fieldIPAddress] != clientIP ||
				w.data[fieldUserAgent] != userAgent || w.data[fieldSuccess] != false {
				t.Fatalf("audit entry = %+v, want actor %q, ip %q, user agent %q, success=false",
					w.data, scimAuditActor, clientIP, userAgent)
			}
			details, _ := w.data[fieldDetails].(string)
			if !strings.Contains(details, strconv.Quote(tc.reason)) {
				t.Fatalf("audit details = %s, want reason %q", details, tc.reason)
			}

			entries := logs.FilterMessage("scim_auth_failed").All()
			if len(entries) != 1 || entries[0].Level != zapcore.WarnLevel {
				t.Fatalf("log entries = %+v, want one scim_auth_failed warning", entries)
			}
			fields := entries[0].ContextMap()
			if fields["reason"] != tc.reason || fields["client_ip"] != clientIP {
				t.Fatalf("log fields = %v, want reason %q and client_ip %q", fields, tc.reason, clientIP)
			}

			for _, trace := range []string{details, strings.Join(logFieldValues(entries[0]), " ")} {
				if strings.Contains(trace, wrong) || strings.Contains(trace, testSCIMToken) {
					t.Fatalf("a token leaked into the trail: %s", trace)
				}
			}
		})
	}
}

func logFieldValues(e observer.LoggedEntry) []string {
	var out []string
	for _, v := range e.ContextMap() {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// An authenticated request records no refusal.
func TestSCIM_SuccessfulAuthRecordsNoRefusal(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	h, _, _, aud := newSCIMObservedHandlerLogging(t, zap.New(core))
	if rec := scimReq(t, h, http.MethodGet, "/scim/v2/Users", testSCIMToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	for _, w := range aud.all() {
		if w.eventType == string(audit.EventSCIMAuthFailed) {
			t.Fatalf("an authenticated request recorded %s", w.eventType)
		}
	}
	if n := logs.FilterMessage("scim_auth_failed").Len(); n != 0 {
		t.Fatalf("an authenticated request logged %d scim_auth_failed lines", n)
	}
}

// Through the full chain the SCIM path is throttled per client IP before the
// bearer check, so a caller guessing the token is refused with 429 and a
// Retry-After of the configured window once its quota is spent.
func TestSCIM_ThrottledThroughFullChain(t *testing.T) {
	cfg := newTestConfig()
	cfg.SCIMEnabled = true
	cfg.SCIMBearerToken = strings.Repeat("s", config.MinSCIMBearerTokenLength)
	cfg.SCIMProjectID = testSCIMProjectID
	cfg.RateLimitSCIMPerIP = 2
	cfg.RateLimitWindowSeconds = 45
	handler, _, stop := buildTestApp(t, cfg)
	defer stop()

	for i := range 2 {
		if rec := scimReq(t, handler, http.MethodGet, "/scim/v2/Users", "wrong-token", ""); rec.Code != http.StatusUnauthorized {
			t.Fatalf("guess %d: status = %d, want 401", i+1, rec.Code)
		}
	}
	rec := scimReq(t, handler, http.MethodGet, "/scim/v2/Users", cfg.SCIMBearerToken, "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over quota: status = %d, want 429 even with the right token", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "45" {
		t.Fatalf("Retry-After = %q, want the 45 s window", got)
	}
}
