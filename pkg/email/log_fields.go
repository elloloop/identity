package email

import (
	"context"
	"slices"

	"go.uber.org/zap"
)

type logFieldsKey struct{}

// ContextWithLogFields returns ctx carrying fields that every line a Chain or
// LogOnly transport logs for a Send under ctx includes, so a caller can tie
// those lines to its own record. Fields already on ctx are kept.
func ContextWithLogFields(ctx context.Context, fields ...zap.Field) context.Context {
	return context.WithValue(ctx, logFieldsKey{}, slices.Concat(logFieldsFrom(ctx), fields))
}

func logFieldsFrom(ctx context.Context) []zap.Field {
	fields, _ := ctx.Value(logFieldsKey{}).([]zap.Field)
	return fields
}
