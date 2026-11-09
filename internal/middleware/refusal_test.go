package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/internal/observability"
	"github.com/elloloop/identity/internal/service"
	jwtpkg "github.com/elloloop/identity/pkg/jwt"
)

func assertTokenNeverLogged(t *testing.T, entries []observer.LoggedEntry, secret string) {
	t.Helper()
	if secret == "" {
		return
	}
	for _, entry := range entries {
		assert.NotContains(t, entry.Message, secret, "log message must never contain raw token")
		for k, v := range entry.ContextMap() {
			assert.NotContains(t, fmt.Sprint(v), secret, "log field %s must never contain raw token", k)
		}
	}
}

func TestAuthRefusal_ReasonCodesAndStructuredFields(t *testing.T) {
	t.Parallel()

	signer := testSigner(t)
	wrongSigner := testSigner(t)
	now := time.Now()

	baseClaims := jwtpkg.Claims{
		Sub:      "user-42",
		Project:  "proj-token",
		Tenant:   "t-claimed",
		SID:      "sid-42",
		Issuer:   "https://issuer.example.com",
		Audience: []string{"https://api.example.com"},
		AuthTime: now.Add(-5 * time.Minute).Unix(),
	}

	validTok, err := signer.SignAccessToken(context.Background(), baseClaims, 15*time.Minute)
	require.NoError(t, err)

	wrongSigTok, err := wrongSigner.SignAccessToken(context.Background(), baseClaims, 15*time.Minute)
	require.NoError(t, err)

	expiredTok, err := signer.SignAccessToken(context.Background(), baseClaims, -2*time.Minute)
	require.NoError(t, err)

	purposeClaims := baseClaims
	purposeClaims.Purpose = "dob_completion"
	purposeTok, err := signer.SignAccessToken(context.Background(), purposeClaims, 15*time.Minute)
	require.NoError(t, err)

	suspendedClaims := baseClaims
	suspendedClaims.Tenant = "t-suspended"
	suspendedTok, err := signer.SignAccessToken(context.Background(), suspendedClaims, 15*time.Minute)
	require.NoError(t, err)

	const malformedTok = "not-a-valid-jwt-secret-value-xyz987"

	cases := []struct {
		name            string
		token           string
		expectedIssuer  string
		expectedAud     string
		requireAud      bool
		lookupErr       error
		wantStatus      int
		wantReason      string
		wantPeekedClaim bool
	}{
		{
			name:       "missing_bearer",
			token:      "",
			wantStatus: http.StatusUnauthorized,
			wantReason: ReasonMissingBearer,
		},
		{
			name:       "token_malformed",
			token:      malformedTok,
			wantStatus: http.StatusUnauthorized,
			wantReason: ReasonTokenMalformed,
		},
		{
			name:            "token_signature",
			token:           wrongSigTok,
			wantStatus:      http.StatusUnauthorized,
			wantReason:      ReasonTokenSignature,
			wantPeekedClaim: true,
		},
		{
			name:            "token_expired",
			token:           expiredTok,
			wantStatus:      http.StatusUnauthorized,
			wantReason:      ReasonTokenExpired,
			wantPeekedClaim: true,
		},
		{
			name:            "token_issuer",
			token:           validTok,
			expectedIssuer:  "https://other-issuer.example.com",
			wantStatus:      http.StatusUnauthorized,
			wantReason:      ReasonTokenIssuer,
			wantPeekedClaim: true,
		},
		{
			name:            "token_audience",
			token:           validTok,
			expectedAud:     "https://other-aud.example.com",
			requireAud:      true,
			wantStatus:      http.StatusUnauthorized,
			wantReason:      ReasonTokenAudience,
			wantPeekedClaim: true,
		},
		{
			name:            "token_purpose_rejected",
			token:           purposeTok,
			wantStatus:      http.StatusUnauthorized,
			wantReason:      ReasonTokenPurposeRejected,
			wantPeekedClaim: true,
		},
		{
			name:            "token_tenant_rejected",
			token:           suspendedTok,
			wantStatus:      http.StatusUnauthorized,
			wantReason:      ReasonTokenTenantRejected,
			wantPeekedClaim: true,
		},
		{
			name:            "token_tenant_lookup",
			token:           validTok,
			lookupErr:       errors.New("db timeout"),
			wantStatus:      http.StatusServiceUnavailable,
			wantReason:      ReasonTokenTenantLookup,
			wantPeekedClaim: true,
		},
	}

	for _, mode := range []string{"ttl", "session"} {
		for _, tc := range cases {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				core, logs := observer.New(zapcore.InfoLevel)
				logger := zap.New(core)

				lookup := newTenantLookup()
				lookup.byKey["proj-token/t-claimed"] = &service.Tenant{
					ID: "t-claimed", ProjectID: "proj-token", Status: service.TenantStatusClaimed,
				}
				lookup.byKey["proj-token/t-suspended"] = &service.Tenant{
					ID: "t-suspended", ProjectID: "proj-token", Status: service.TenantStatusSuspended,
				}
				lookup.err = tc.lookupErr

				tenants := TokenTenants{
					Default:        ttDefault,
					Selectable:     lookup,
					ExpectedIssuer: tc.expectedIssuer,
					Logger:         logger,
				}

				var authMW func(http.Handler) http.Handler
				if mode == "session" {
					src := newStubLookup()
					src.project("proj-host").put(&service.SessionRecord{SID: "sid-42", UserID: "user-42"})
					authMW = SessionAuthMiddleware(signer, tenants, tc.expectedAud, tc.requireAud, NewSessionCache(src, 0, nil))
				} else {
					authMW = AuthMiddleware(signer, tenants, tc.expectedAud, tc.requireAud)
				}

				inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
				})
				chain := LoggingMiddleware(logger)(
					NewProjectResolver(DefaultProject{ProjectID: "proj-host", StorageScopeID: ttDefault}, nil, logger)(
						authMW(inner),
					),
				)

				req := httptest.NewRequest(http.MethodPost, "/identity.v1.IdentityService/GetProfile", nil)
				req.Host = "auth.example.com:8443"
				req.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
				if tc.token != "" {
					req.Header.Set("Authorization", "Bearer "+tc.token)
				}
				rec := httptest.NewRecorder()
				chain.ServeHTTP(rec, req)

				require.Equal(t, tc.wantStatus, rec.Code)
				assertTokenNeverLogged(t, logs.All(), tc.token)

				refusals := logs.FilterMessage("auth_refused").All()
				require.Len(t, refusals, 1)
				rf := refusals[0].ContextMap()
				assert.Equal(t, tc.wantReason, rf["reason"])
				assert.Equal(t, "auth.example.com", rf["host"])
				assert.Equal(t, "proj-host", rf["request_project_id"])
				assert.Equal(t, "/identity.v1.IdentityService/GetProfile", rf["path"])
				assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", rf[observability.TraceIDLogField])

				reqLogs := logs.FilterMessage("request").All()
				require.Len(t, reqLogs, 1)
				qf := reqLogs[0].ContextMap()
				assert.Equal(t, tc.wantReason, qf["reason"])
				assert.Equal(t, "auth.example.com", qf["host"])
				assert.Equal(t, "proj-host", qf["request_project_id"])
				assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", qf[observability.TraceIDLogField])

				if tc.wantPeekedClaim {
					assert.Equal(t, "proj-token", rf["project_id"])
					assert.Equal(t, "user-42", rf["user_id"])
					assert.Equal(t, "sid-42", rf["session_id"])
					assert.Equal(t, "https://issuer.example.com", rf["issuer"])
					assert.Contains(t, rf, "auth_time_age_s")
					assert.Contains(t, rf, "expiry_age_s")
					assert.Equal(t, "proj-token", qf["project_id"])
					assert.Equal(t, "user-42", qf["user_id"])
					assert.Equal(t, "sid-42", qf["session_id"])
				}
			})
		}
	}
}

func TestSessionAuthRefusal_SessionRevokedAndLookupFailed(t *testing.T) {
	t.Parallel()

	signer := testSigner(t)
	tok, err := signer.SignAccessToken(context.Background(), jwtpkg.Claims{
		Sub:     "user-sess",
		Project: "proj-a",
		Tenant:  ttDefault,
		SID:     "sid-revoked",
	}, 15*time.Minute)
	require.NoError(t, err)

	t.Run("session_revoked", func(t *testing.T) {
		t.Parallel()
		core, logs := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)

		src := newStubLookup()
		src.project("proj-a").put(&service.SessionRecord{SID: "sid-revoked", UserID: "user-sess", RevokedAtMs: 100})
		mw := SessionAuthMiddleware(signer, TokenTenants{Default: ttDefault, Logger: logger}, "", false, NewSessionCache(src, 0, nil))
		chain := LoggingMiddleware(logger)(
			NewProjectResolver(DefaultProject{ProjectID: "proj-a", StorageScopeID: ttDefault}, nil, logger)(
				mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })),
			),
		)

		req := httptest.NewRequest(http.MethodPost, "/identity.v1.IdentityService/GetProfile", nil)
		req.Host = "auth.example.com"
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)

		require.Equal(t, http.StatusUnauthorized, rec.Code)
		assertTokenNeverLogged(t, logs.All(), tok)

		refusals := logs.FilterMessage("auth_refused").All()
		require.Len(t, refusals, 1)
		rf := refusals[0].ContextMap()
		assert.Equal(t, ReasonSessionRevoked, rf["reason"])
		assert.Equal(t, "auth.example.com", rf["host"])
		assert.Equal(t, "proj-a", rf["request_project_id"])
		assert.Equal(t, "proj-a", rf["project_id"])
		assert.Equal(t, "user-sess", rf["user_id"])
		assert.Equal(t, "sid-revoked", rf["session_id"])
	})

	t.Run("session_lookup_failed", func(t *testing.T) {
		t.Parallel()
		core, logs := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)

		src := newStubLookup()
		src.project("proj-a").err = errors.New("repo down")
		mw := SessionAuthMiddleware(signer, TokenTenants{Default: ttDefault, Logger: logger}, "", false, NewSessionCache(src, 0, nil))
		chain := LoggingMiddleware(logger)(
			NewProjectResolver(DefaultProject{ProjectID: "proj-a", StorageScopeID: ttDefault}, nil, logger)(
				mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })),
			),
		)

		req := httptest.NewRequest(http.MethodPost, "/identity.v1.IdentityService/GetProfile", nil)
		req.Host = "auth.example.com"
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)

		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assertTokenNeverLogged(t, logs.All(), tok)

		refusals := logs.FilterMessage("auth_refused").All()
		require.Len(t, refusals, 1)
		rf := refusals[0].ContextMap()
		assert.Equal(t, ReasonSessionLookupFailed, rf["reason"])
		assert.Equal(t, "auth.example.com", rf["host"])
		assert.Equal(t, "proj-a", rf["request_project_id"])
		assert.Equal(t, "proj-a", rf["project_id"])
	})
}

func TestProjectScopeGuard_LogsTokenProjectMismatchWithHostAndRequestProject(t *testing.T) {
	t.Parallel()

	signer := testSigner(t)
	tok, err := signer.SignAccessToken(context.Background(), jwtpkg.Claims{
		Sub:     "user-cross",
		Project: "proj-alpha",
		Tenant:  ttDefault,
		SID:     "sid-cross",
	}, 15*time.Minute)
	require.NoError(t, err)

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	var chain http.Handler = inner
	chain = NewProjectScopeGuard()(chain)
	chain = AuthMiddleware(signer, TokenTenants{Default: ttDefault, Logger: logger}, "", false)(chain)
	chain = NewProjectResolver(DefaultProject{ProjectID: "proj-beta", StorageScopeID: ttDefault}, nil, logger)(chain)
	chain = LoggingMiddleware(logger)(chain)

	req := httptest.NewRequest(http.MethodPost, "/identity.v1.IdentityService/GetProfile", nil)
	req.Host = "beta.example.com"
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
	assertTokenNeverLogged(t, logs.All(), tok)

	refusals := logs.FilterMessage("auth_refused").All()
	require.Len(t, refusals, 1)
	rf := refusals[0].ContextMap()
	assert.Equal(t, ReasonTokenProjectMismatch, rf["reason"])
	assert.Equal(t, "beta.example.com", rf["host"])
	assert.Equal(t, "proj-beta", rf["request_project_id"])
	assert.Equal(t, "proj-alpha", rf["project_id"])
	assert.Equal(t, ttDefault, rf["tenant_id"])
	assert.Equal(t, "user-cross", rf["user_id"])
	assert.Equal(t, "sid-cross", rf["session_id"])

	reqLogs := logs.FilterMessage("request").All()
	require.Len(t, reqLogs, 1)
	qf := reqLogs[0].ContextMap()
	assert.Equal(t, ReasonTokenProjectMismatch, qf["reason"])
	assert.Equal(t, "beta.example.com", qf["host"])
	assert.Equal(t, "proj-beta", qf["request_project_id"])
	assert.Equal(t, "proj-alpha", qf["project_id"])
	assert.Equal(t, "user-cross", qf["user_id"])
}
