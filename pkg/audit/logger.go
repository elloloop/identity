// Package audit provides best-effort audit event logging to EntDB.
//
// Audit writes MUST NOT block the user flow or propagate errors — an
// EntDB outage must not break login. All failures are caught and logged
// via zap, never returned to callers.
//
// Usage:
//
//	l := audit.NewLogger(writer, "tenant-1", zapLogger)
//	l.Log(ctx, audit.EventLoginSuccess,
//	    audit.WithActor("user-42"),
//	    audit.WithIP("10.0.0.1"),
//	    audit.WithUserAgent("Mozilla/5.0"),
//	    audit.WithDetails(map[string]any{"method": "password"}),
//	)
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb"
	"go.uber.org/zap"
)

// auditEventTypeID is the EntDB type_id for AuditEvent nodes (schema.yaml).
const auditEventTypeID = 26

// AuditEvent field IDs from schema.yaml (type_id 26).
// Data keys on the wire are field IDs as decimal strings.
const (
	fieldEventType    = "1" // enum (string on the wire)
	fieldActorUserID  = "2" // str
	fieldTargetUserID = "3" // str
	fieldIPAddress    = "4" // str
	fieldUserAgent    = "5" // str
	fieldSuccess      = "6" // bool
	fieldDetails      = "7" // str (JSON-encoded)
	fieldCreatedAt    = "8" // timestamp (ms)
)

// NodeWriter is the subset of EntDB operations needed by the audit
// logger. Accepting an interface rather than *entdb.DbClient makes
// the logger testable without a live gRPC connection.
type NodeWriter interface {
	ExecuteAtomic(
		ctx context.Context,
		tenantID, actor, idempotencyKey string,
		ops []entdb.Operation,
	) (*entdb.CommitResult, error)
}

// EventType enumerates all auditable events. Values MUST stay in sync
// with schema.yaml AuditEvent enum_values.
type EventType string

const (
	EventLoginSuccess       EventType = "login_success"
	EventLoginFailure       EventType = "login_failure"
	EventLoginLocked        EventType = "login_locked"   // login attempt while account is in lockout window
	EventAccountLocked      EventType = "account_locked" // threshold tripped, lockout window opened
	EventLogout             EventType = "logout"
	EventPasswordChanged    EventType = "password_changed"
	EventPasswordReset      EventType = "password_reset"
	EventTotpEnabled        EventType = "totp_enabled"
	EventTotpDisabled       EventType = "totp_disabled"
	EventTotpVerified       EventType = "totp_verified"
	EventPasskeyAdded       EventType = "passkey_added"
	EventPasskeyRemoved     EventType = "passkey_removed"
	EventPasskeyUsed        EventType = "passkey_used"
	EventSessionRevoked     EventType = "session_revoked"
	EventUserInvited        EventType = "user_invited"
	EventUserDeactivated    EventType = "user_deactivated"
	EventUserReactivated    EventType = "user_reactivated"
	EventAdminResetPassword EventType = "admin_reset_password"
	EventOAuthLogin         EventType = "oauth_login"
	EventQrLoginApproved    EventType = "qr_login_approved"
	EventQrLoginRejected    EventType = "qr_login_rejected"
	EventAdminHelpRequested EventType = "admin_help_requested"
	EventAdminHelpResolved  EventType = "admin_help_resolved"
)

// validEventTypes is the canonical set of known event type strings.
var validEventTypes = map[EventType]struct{}{
	EventLoginSuccess:       {},
	EventLoginFailure:       {},
	EventLoginLocked:        {},
	EventAccountLocked:      {},
	EventLogout:             {},
	EventPasswordChanged:    {},
	EventPasswordReset:      {},
	EventTotpEnabled:        {},
	EventTotpDisabled:       {},
	EventTotpVerified:       {},
	EventPasskeyAdded:       {},
	EventPasskeyRemoved:     {},
	EventPasskeyUsed:        {},
	EventSessionRevoked:     {},
	EventUserInvited:        {},
	EventUserDeactivated:    {},
	EventUserReactivated:    {},
	EventAdminResetPassword: {},
	EventOAuthLogin:         {},
	EventQrLoginApproved:    {},
	EventQrLoginRejected:    {},
	EventAdminHelpRequested: {},
	EventAdminHelpResolved:  {},
}

// eventConfig holds the optional parameters for a single audit log call.
type eventConfig struct {
	actorUserID  string
	targetUserID string
	ipAddress    string
	userAgent    string
	success      bool
	details      map[string]any
}

// Option configures a single Log call.
type Option func(*eventConfig)

// WithActor sets the actor (initiating user) for the audit event.
func WithActor(userID string) Option {
	return func(c *eventConfig) { c.actorUserID = userID }
}

// WithTarget sets the target user for the audit event. When omitted,
// defaults to the actor (the event is about the actor themselves).
func WithTarget(userID string) Option {
	return func(c *eventConfig) { c.targetUserID = userID }
}

// WithIP sets the client IP address.
func WithIP(ip string) Option {
	return func(c *eventConfig) { c.ipAddress = ip }
}

// WithUserAgent sets the client User-Agent header value.
func WithUserAgent(ua string) Option {
	return func(c *eventConfig) { c.userAgent = ua }
}

// WithSuccess sets whether the audited action succeeded.
func WithSuccess(success bool) Option {
	return func(c *eventConfig) { c.success = success }
}

// WithDetails attaches arbitrary key-value metadata to the event.
func WithDetails(details map[string]any) Option {
	return func(c *eventConfig) { c.details = details }
}

// Logger writes audit events to EntDB. All methods are best-effort.
type Logger struct {
	writer   NodeWriter
	tenantID string
	logger   *zap.Logger
	// nowFunc is overridable for testing.
	nowFunc func() time.Time
}

// NewLogger creates an audit Logger.
//
// A nil writer is tolerated — Log calls will be silently dropped with
// a warning, matching the best-effort contract.
func NewLogger(writer NodeWriter, tenantID string, logger *zap.Logger) *Logger {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Logger{
		writer:   writer,
		tenantID: tenantID,
		logger:   logger,
		nowFunc:  time.Now,
	}
}

// Log writes an audit event to EntDB. It never returns an error and
// never panics — failures are logged via zap and silently dropped.
func (l *Logger) Log(ctx context.Context, event EventType, opts ...Option) {
	// Recover from any panic — audit writes must never crash the caller.
	defer func() {
		if r := recover(); r != nil {
			l.logger.Error(
				"audit_log_panic",
				zap.String("event_type", string(event)),
				zap.Any("panic", r),
			)
		}
	}()

	if l.writer == nil {
		l.logger.Warn(
			"audit_log_skipped_nil_client",
			zap.String("event_type", string(event)),
		)
		return
	}

	// Warn on unknown event types but still write (defensive, don't break callers).
	if _, ok := validEventTypes[event]; !ok {
		l.logger.Warn(
			"audit_unknown_event_type",
			zap.String("event_type", string(event)),
		)
	}

	cfg := eventConfig{
		success: true, // default to true, matching Python
	}
	for _, o := range opts {
		o(&cfg)
	}

	// target defaults to actor when unset (event is about the actor themselves).
	targetUserID := cfg.targetUserID
	if targetUserID == "" {
		targetUserID = cfg.actorUserID
	}

	// Encode details as sorted JSON string, matching Python's sort_keys=True.
	detailsJSON := "{}"
	if len(cfg.details) > 0 {
		detailsJSON = sortedJSON(cfg.details)
	}

	nowMs := l.nowFunc().UnixMilli()

	// Build the raw operation. Data keys are field IDs (decimal strings)
	// as required by the EntDB wire format.
	data := map[string]any{
		fieldEventType:    string(event),
		fieldActorUserID:  cfg.actorUserID,
		fieldTargetUserID: targetUserID,
		fieldIPAddress:    cfg.ipAddress,
		fieldUserAgent:    cfg.userAgent,
		fieldSuccess:      cfg.success,
		fieldDetails:      detailsJSON,
		fieldCreatedAt:    nowMs,
	}

	ops := []entdb.Operation{
		{
			Type:   entdb.OpCreateNode,
			TypeID: auditEventTypeID,
			Data:   data,
		},
	}

	_, err := l.writer.ExecuteAtomic(ctx, l.tenantID, "user:system", "", ops)
	if err != nil {
		l.logger.Error(
			"audit_log_failed",
			zap.String("event_type", string(event)),
			zap.Error(err),
		)
	}
}

// sortedJSON encodes a map to JSON with keys sorted, matching the
// Python audit logger's sort_keys=True behaviour. Falls back to "{}"
// on encoding errors.
func sortedJSON(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	ordered := make([]byte, 0, 64)
	ordered = append(ordered, '{')
	for i, k := range keys {
		if i > 0 {
			ordered = append(ordered, ',')
		}
		kb, _ := json.Marshal(k)
		ordered = append(ordered, kb...)
		ordered = append(ordered, ':')
		vb, err := json.Marshal(m[k])
		if err != nil {
			vb = []byte(fmt.Sprintf("%q", fmt.Sprint(m[k])))
		}
		ordered = append(ordered, vb...)
	}
	ordered = append(ordered, '}')
	return string(ordered)
}
