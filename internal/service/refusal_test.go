package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/internal/observability"
)

func TestRecordRefusal_PopulatesHolderAndEmitsStructuredWarning(t *testing.T) {
	t.Parallel()

	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	ctx, span := tp.Tracer("test").Start(context.Background(), "rpc")
	defer span.End()

	core, logs := observer.New(zapcore.WarnLevel)
	logger := zap.New(core)

	info := &RefusalInfo{
		Logger:     logger,
		Path:       "/identity.v1.IdentityService/RegisterAgentMachine",
		RemoteAddr: "192.0.2.10:54321",
	}
	ctx = WithRefusalInfo(ctx, info)
	ctx = WithRequestHost(ctx, "auth.example.com")
	ctx = WithProjectScope(ctx, &ProjectScope{ProjectID: "proj-host"})

	RecordRefusal(ctx, nil, "rpc_refused", "sign_in_not_recent",
		zap.String("project_id", "proj-token"),
		zap.String("tenant_id", "tenant-a"),
		zap.String("user_id", "user-123"),
		zap.String("session_id", "sid-456"),
		zap.Int64("auth_time_age_s", 1800),
		zap.Int64("max_age_s", 900),
	)

	assert.Equal(t, "sign_in_not_recent", info.Reason)
	assert.Equal(t, "auth.example.com", info.Host)
	assert.Equal(t, "proj-host", info.RequestProjectID)
	assert.Equal(t, "proj-token", info.ProjectID)
	assert.Equal(t, "tenant-a", info.TenantID)
	assert.Equal(t, "user-123", info.UserID)
	assert.Equal(t, "sid-456", info.SessionID)
	assert.Equal(t, span.SpanContext().TraceID().String(), info.TraceID)

	entries := logs.FilterMessage("rpc_refused").All()
	require.Len(t, entries, 1)
	fields := entries[0].ContextMap()
	assert.Equal(t, "sign_in_not_recent", fields["reason"])
	assert.Equal(t, "auth.example.com", fields["host"])
	assert.Equal(t, "proj-host", fields["request_project_id"])
	assert.Equal(t, "/identity.v1.IdentityService/RegisterAgentMachine", fields["path"])
	assert.Equal(t, "192.0.2.10:54321", fields["remote_addr"])
	assert.Equal(t, "proj-token", fields["project_id"])
	assert.Equal(t, "tenant-a", fields["tenant_id"])
	assert.Equal(t, "user-123", fields["user_id"])
	assert.Equal(t, "sid-456", fields["session_id"])
	assert.EqualValues(t, 1800, fields["auth_time_age_s"])
	assert.EqualValues(t, 900, fields["max_age_s"])
	assert.Equal(t, span.SpanContext().TraceID().String(), fields[observability.TraceIDLogField])
}

func TestWithRefusalInfo_NilIsNoOp(t *testing.T) {
	t.Parallel()

	ctx := WithRefusalInfo(context.Background(), nil)
	assert.Nil(t, RefusalInfoFromContext(ctx))
}
