package service

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestRefreshTokenRefusals_ReasonCodesAndNoSecretsLogged(t *testing.T) {
	t.Parallel()

	t.Run("refresh_token_invalid", func(t *testing.T) {
		t.Parallel()
		f := newSelectionFixture(t)
		core, logs := observer.New(zapcore.WarnLevel)
		f.svc.logger = zap.New(core)
		ctx := WithRequestHost(WithProjectScope(t.Context(), &ProjectScope{
			ProjectID: f.project(),
			Access:    ProjectAccessConfig{Mode: AccessModeOpen},
		}), "auth.example.com")

		_, _, _, err := f.svc.RefreshToken(ctx, "", "", "203.0.113.10", "agent")
		require.ErrorIs(t, err, ErrUnauthenticated)
		fields := assertLastRPCRefusal(t, logs, ReasonRefreshTokenInvalid)
		assert.Equal(t, "auth.example.com", fields["host"])
		assert.Equal(t, f.project(), fields["request_project_id"])

		rawInvalid := "rt-secret-unknown-token-value-12345"
		_, _, _, err = f.svc.RefreshToken(ctx, rawInvalid, "", "203.0.113.10", "agent")
		require.ErrorIs(t, err, ErrUnauthenticated)
		fields = assertLastRPCRefusal(t, logs, ReasonRefreshTokenInvalid)
		assert.Equal(t, "auth.example.com", fields["host"])
		assert.Equal(t, f.project(), fields["request_project_id"])
		for k, v := range fields {
			assert.NotContains(t, fmt.Sprint(v), rawInvalid, "field %s must not contain raw refresh token", k)
		}
	})

	t.Run("refresh_token_expired", func(t *testing.T) {
		t.Parallel()
		f := newSelectionFixture(t)
		core, logs := observer.New(zapcore.WarnLevel)
		f.svc.logger = zap.New(core)
		ctx := WithRequestHost(WithProjectScope(t.Context(), &ProjectScope{
			ProjectID: f.project(),
			Access:    ProjectAccessConfig{Mode: AccessModeOpen},
		}), "auth.example.com")

		rec, err := f.repo.FindRefreshTokenByHashIncludingConsumed(ctx, hashRefreshToken(f.refresh))
		require.NoError(t, err)
		require.NotNil(t, rec)
		f.svc.nowFunc = func() time.Time { return time.UnixMilli(rec.ExpiresAt + 45_000) }

		_, _, _, err = f.svc.RefreshToken(ctx, f.refresh, "", "203.0.113.10", "agent")
		require.ErrorIs(t, err, ErrTokenExpired)

		fields := assertLastRPCRefusal(t, logs, ReasonRefreshTokenExpired)
		assert.Equal(t, "auth.example.com", fields["host"])
		assert.Equal(t, f.project(), fields["request_project_id"])
		assert.Equal(t, f.user.ID, fields["user_id"])
		assert.GreaterOrEqual(t, fields["expiry_age_s"], int64(44))
		for k, v := range fields {
			assert.NotContains(t, fmt.Sprint(v), f.refresh, "field %s must not contain raw refresh token", k)
		}
	})

	t.Run("refresh_session_revoked", func(t *testing.T) {
		t.Parallel()
		f := newSelectionFixture(t)
		core, logs := observer.New(zapcore.WarnLevel)
		f.svc.logger = zap.New(core)
		ctx := WithRequestHost(WithProjectScope(t.Context(), &ProjectScope{
			ProjectID: f.project(),
			Access:    ProjectAccessConfig{Mode: AccessModeOpen},
		}), "auth.example.com")

		oldRefresh := f.refresh
		_, _, rotated, err := f.svc.RefreshToken(ctx, oldRefresh, "", "203.0.113.10", "agent")
		require.NoError(t, err)
		require.NotEmpty(t, rotated)

		// Replaying the consumed refresh token revokes the session and logs refresh_session_revoked.
		_, _, _, err = f.svc.RefreshToken(ctx, oldRefresh, "", "203.0.113.10", "agent")
		require.ErrorIs(t, err, ErrUnauthenticated)

		fields := assertLastRPCRefusal(t, logs, ReasonRefreshSessionRevoked)
		assert.Equal(t, "auth.example.com", fields["host"])
		assert.Equal(t, f.project(), fields["request_project_id"])
		assert.Equal(t, f.user.ID, fields["user_id"])
		for k, v := range fields {
			assert.NotContains(t, fmt.Sprint(v), oldRefresh, "field %s must not contain raw refresh token", k)
			assert.NotContains(t, fmt.Sprint(v), rotated, "field %s must not contain rotated refresh token", k)
		}
	})

	t.Run("not_a_member", func(t *testing.T) {
		t.Parallel()
		f := newSelectionFixture(t)
		core, logs := observer.New(zapcore.WarnLevel)
		f.svc.logger = zap.New(core)
		ctx := WithRequestHost(WithProjectScope(t.Context(), &ProjectScope{
			ProjectID: f.project(),
			Access:    ProjectAccessConfig{Mode: AccessModeOpen},
		}), "auth.example.com")

		_, _, _, err := f.svc.RefreshToken(ctx, f.refresh, "t-acme", "203.0.113.10", "agent")
		require.ErrorIs(t, err, ErrPermissionDenied)

		fields := assertLastRPCRefusal(t, logs, ReasonNotAMember)
		assert.Equal(t, "auth.example.com", fields["host"])
		assert.Equal(t, f.project(), fields["request_project_id"])
		assert.Equal(t, "t-acme", fields["tenant_id"])
		assert.Equal(t, f.user.ID, fields["user_id"])
		for k, v := range fields {
			assert.NotContains(t, fmt.Sprint(v), f.refresh, "field %s must not contain raw refresh token", k)
		}
	})

	t.Run("tenant_suspended", func(t *testing.T) {
		t.Parallel()
		f := newSelectionFixture(t)
		f.seedTenant(t, "t-suspended", TenantStatusSuspended, MembershipStatusActive)
		core, logs := observer.New(zapcore.WarnLevel)
		f.svc.logger = zap.New(core)
		ctx := WithRequestHost(WithProjectScope(t.Context(), &ProjectScope{
			ProjectID: f.project(),
			Access:    ProjectAccessConfig{Mode: AccessModeOpen},
		}), "auth.example.com")

		_, _, _, err := f.svc.RefreshToken(ctx, f.refresh, "t-suspended", "203.0.113.10", "agent")
		require.ErrorIs(t, err, ErrPermissionDenied)

		fields := assertLastRPCRefusal(t, logs, ReasonTenantSuspended)
		assert.Equal(t, "auth.example.com", fields["host"])
		assert.Equal(t, f.project(), fields["request_project_id"])
		assert.Equal(t, "t-suspended", fields["tenant_id"])
		assert.Equal(t, f.user.ID, fields["user_id"])
		for k, v := range fields {
			assert.NotContains(t, fmt.Sprint(v), f.refresh, "field %s must not contain raw refresh token", k)
		}
	})

	t.Run("tenant_selection_disabled", func(t *testing.T) {
		t.Parallel()
		f := newSelectionFixture(t)
		f.svc.WithTenantSelection(nil)
		core, logs := observer.New(zapcore.WarnLevel)
		f.svc.logger = zap.New(core)
		ctx := WithRequestHost(WithProjectScope(t.Context(), &ProjectScope{
			ProjectID: f.project(),
			Access:    ProjectAccessConfig{Mode: AccessModeOpen},
		}), "auth.example.com")

		_, _, _, err := f.svc.RefreshToken(ctx, f.refresh, "t-acme", "203.0.113.10", "agent")
		require.ErrorIs(t, err, ErrTenantSelectionDisabled)

		fields := assertLastRPCRefusal(t, logs, ReasonTenantSelectionDisabled)
		assert.Equal(t, "auth.example.com", fields["host"])
		assert.Equal(t, f.project(), fields["request_project_id"])
		assert.Equal(t, "t-acme", fields["tenant_id"])
		assert.Equal(t, f.user.ID, fields["user_id"])
		for k, v := range fields {
			assert.NotContains(t, fmt.Sprint(v), f.refresh, "field %s must not contain raw refresh token", k)
		}
	})
}

func TestMergeAccountsRefusals_ReasonCodesAndNoSecretsLogged(t *testing.T) {
	t.Parallel()

	t.Run("sign_in_not_recent", func(t *testing.T) {
		t.Parallel()
		svc, _, survivor, _, baseCtx := mergeFixture(t)
		core, logs := observer.New(zapcore.WarnLevel)
		svc.logger = zap.New(core)
		ctx := WithRequestHost(baseCtx, "auth.example.com")

		staleAuthTime := svc.nowMs()/1000 - int64(svc.cfg.AccountMergeReauthMaxAge().Seconds()) - 120
		_, err := svc.MergeAccounts(ctx, survivor.ID, staleAuthTime, "bob", accessTestPassword, "203.0.113.10", "agent", false)
		require.ErrorIs(t, err, ErrReauthenticationRequired)

		fields := assertLastRPCRefusal(t, logs, ReasonSignInNotRecent)
		assert.Equal(t, "auth.example.com", fields["host"])
		assert.Equal(t, svc.projectID(ctx), fields["request_project_id"])
		assert.Equal(t, survivor.ID, fields["user_id"])
		assert.Equal(t, int64(svc.cfg.AccountMergeReauthMaxAge().Seconds()), fields["max_age_s"])
		assert.Greater(t, fields["auth_time_age_s"], fields["max_age_s"])
		for k, v := range fields {
			assert.NotContains(t, fmt.Sprint(v), accessTestPassword, "field %s must not contain password", k)
		}
	})

	t.Run("merge_same_user", func(t *testing.T) {
		t.Parallel()
		svc, _, _, native, baseCtx := mergeFixture(t)
		core, logs := observer.New(zapcore.WarnLevel)
		svc.logger = zap.New(core)
		ctx := WithRequestHost(baseCtx, "auth.example.com")

		_, err := svc.MergeAccounts(ctx, native.ID, freshAuth(svc), "bob", accessTestPassword, "203.0.113.10", "agent", false)
		require.ErrorIs(t, err, ErrMergeRefused)

		fields := assertLastRPCRefusal(t, logs, ReasonMergeSameUser)
		assert.Equal(t, "auth.example.com", fields["host"])
		assert.Equal(t, svc.projectID(ctx), fields["request_project_id"])
		assert.Equal(t, native.ID, fields["user_id"])
		for k, v := range fields {
			assert.NotContains(t, fmt.Sprint(v), accessTestPassword, "field %s must not contain password", k)
		}
	})

	t.Run("merge_target_invalid", func(t *testing.T) {
		t.Parallel()
		svc, _, survivor, native, baseCtx := mergeFixture(t)
		core, logs := observer.New(zapcore.WarnLevel)
		svc.logger = zap.New(core)
		ctx := WithRequestHost(baseCtx, "auth.example.com")

		wrongPassword := "Wr0ng!Passw0rdSecret"
		_, err := svc.MergeAccounts(ctx, survivor.ID, freshAuth(svc), "bob", wrongPassword, "203.0.113.10", "agent", false)
		require.ErrorIs(t, err, ErrUnauthenticated)

		fields := assertLastRPCRefusal(t, logs, ReasonMergeTargetInvalid)
		assert.Equal(t, "auth.example.com", fields["host"])
		assert.Equal(t, svc.projectID(ctx), fields["request_project_id"])
		assert.Equal(t, survivor.ID, fields["user_id"])
		for k, v := range fields {
			assert.NotContains(t, fmt.Sprint(v), wrongPassword, "field %s must not contain password", k)
		}

		native.TotpRequired = true
		_, err = svc.MergeAccounts(ctx, survivor.ID, freshAuth(svc), "bob", accessTestPassword, "203.0.113.10", "agent", false)
		require.ErrorIs(t, err, ErrMergeRefused)
		fields = assertLastRPCRefusal(t, logs, ReasonMergeTargetInvalid)
		assert.Equal(t, survivor.ID, fields["user_id"])
		for k, v := range fields {
			assert.NotContains(t, fmt.Sprint(v), accessTestPassword, "field %s must not contain password", k)
		}
	})
}
