// Package audit provides best-effort audit event logging to the datastore.
//
// Audit writes MUST NOT block the user flow or propagate errors — an
// A datastore outage must not break login. All failures are caught and logged
// via zap, never returned to callers.
//
// Usage:
//
//	l := audit.NewLogger(writer, "default-project", zapLogger)
//	l.Log(ctx, audit.EventLoginSuccess,
//	    audit.WithActor("user-42"),
//	    audit.WithIP("10.0.0.1"),
//	    audit.WithUserAgent("Mozilla/5.0"),
//	    audit.WithDetails(map[string]any{"method": "password"}),
//	)
//
// In a multi-project deployment, install a ProjectScoper via WithProjectScoper
// so each write lands under the project the request resolved to (ADR-0002)
// rather than the boot default.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elloloop/identity/internal/graph"
	"go.uber.org/zap"
)

// auditEventTypeID is the graph type_id for AuditEvent nodes.
const auditEventTypeID = 26

// auditWriteActor is the system actor recorded for audit-event writes. Audit
// rows are written by the service itself, not on behalf of the acting user
// (the acting user is captured in the actor/target fields), so every write
// uses this fixed system identity.
const auditWriteActor = "system:admin"

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

// NodeWriter is the subset of datastore operations needed by the audit
// logger. Accepting an interface rather than *graph.DbClient makes
// the logger testable without a live gRPC connection.
type NodeWriter interface {
	ExecuteAtomic(
		ctx context.Context,
		tenantID, actor string,
		ops []graph.Operation,
	) (*graph.CommitResult, error)
}

// ProjectScoper resolves the project an audit write must land under, from
// the request context. It returns the project-bound writer and the project
// id (ADR-0002: the Project is the data-plane shard). The two outputs cover
// both backend shapes the identity service ships:
//
//   - the graph DB keys on the per-call tenant argument, so the returned project id
//     becomes that argument and selects the partition;
//   - postgres ignores that argument and filters on the project its writer was
//     bound to, so the returned writer is the project-bound sibling.
//
// internal/app wires this to service.ScopedDB so an audit write lands under
// the SAME project the request resolved to. When no scoper is injected the
// logger falls back to its boot-default writer and project, preserving the
// zero-config single-project behaviour.
type ProjectScoper func(ctx context.Context) (writer NodeWriter, projectID string)

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
	EventUserDeleted        EventType = "user_deleted"
	EventAdminResetPassword EventType = "admin_reset_password"
	EventOAuthLogin         EventType = "oauth_login"
	EventQrLoginApproved    EventType = "qr_login_approved"
	EventQrLoginRejected    EventType = "qr_login_rejected"
	EventAdminHelpRequested EventType = "admin_help_requested"
	EventAdminHelpResolved  EventType = "admin_help_resolved"

	EventPhoneVerificationRequested EventType = "phone_verification_requested"
	EventPhoneVerified              EventType = "phone_verified"

	// EventPlatformAdminBootstrapBlocked records a first-admin bootstrap
	// attempt that arrived AFTER the platform_admins table was no longer
	// empty (the bootstrap is permanently closed → FailedPrecondition). It
	// makes a closed-bootstrap probe against the ungated endpoint visible.
	EventPlatformAdminBootstrapBlocked EventType = "platform_admin_bootstrap_blocked"

	// RBAC role-management events (custom scoped roles + assignments).
	EventRoleCreated  EventType = "role_created"
	EventRoleDeleted  EventType = "role_deleted"
	EventRoleAssigned EventType = "role_assigned"
	EventRoleRevoked  EventType = "role_revoked"
)

// validEventTypes is the canonical set of known event type strings.
var validEventTypes = map[EventType]struct{}{
	EventLoginSuccess:                  {},
	EventLoginFailure:                  {},
	EventLoginLocked:                   {},
	EventAccountLocked:                 {},
	EventLogout:                        {},
	EventPasswordChanged:               {},
	EventPasswordReset:                 {},
	EventTotpEnabled:                   {},
	EventTotpDisabled:                  {},
	EventTotpVerified:                  {},
	EventPasskeyAdded:                  {},
	EventPasskeyRemoved:                {},
	EventPasskeyUsed:                   {},
	EventSessionRevoked:                {},
	EventUserInvited:                   {},
	EventUserDeactivated:               {},
	EventUserReactivated:               {},
	EventUserDeleted:                   {},
	EventAdminResetPassword:            {},
	EventOAuthLogin:                    {},
	EventQrLoginApproved:               {},
	EventQrLoginRejected:               {},
	EventAdminHelpRequested:            {},
	EventAdminHelpResolved:             {},
	EventPhoneVerificationRequested:    {},
	EventPhoneVerified:                 {},
	EventPlatformAdminBootstrapBlocked: {},
	EventRoleCreated:                   {},
	EventRoleDeleted:                   {},
	EventRoleAssigned:                  {},
	EventRoleRevoked:                   {},
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

// Logger writes audit events to the datastore. All methods are best-effort.
//
// By default, Log writes synchronously on the caller's goroutine. Call
// StartAsync to move writes to a background goroutine with a bounded
// queue, so the auth hot path is not gated on datastore latency. Drops
// when the queue is full are counted and visible via DroppedCount.
type Logger struct {
	// writer and defaultProjectID are the boot-default binding: the writer
	// bound to defaultProjectID's storage partition. They are used verbatim
	// when no per-request ProjectScoper is injected, and as the fallback the
	// scoper itself returns for requests that resolved no project.
	writer           NodeWriter
	defaultProjectID string
	logger           *zap.Logger
	// scoper, when non-nil, resolves the per-request project (writer + id) at
	// Log time so a write lands under the request's project, not the boot
	// default. nil in zero-config / tests that don't exercise multi-project.
	scoper ProjectScoper
	// nowFunc is overridable for testing.
	nowFunc func() time.Time

	// Async machinery. queueLive is true while the flusher goroutine
	// is running and the queue is accepting new items. After Close it
	// flips back to false and Log returns to sync writes.
	queueLive  atomic.Bool
	queue      chan asyncOp
	done       chan struct{}
	dropped    atomic.Uint64
	startStop  sync.Mutex
	flushersWG sync.WaitGroup
}

// asyncOp is the value enqueued by Log when async mode is enabled. The
// project (writer + id) is resolved at Log time and carried on the op so the
// background flusher writes under the request's project, not a per-logger
// field — the resolution must happen on the request goroutine that still
// holds the project scope, before the context is detached for the queue.
type asyncOp struct {
	ctx       context.Context
	writer    NodeWriter
	projectID string
	ops       []graph.Operation
	event     EventType
}

// NewLogger creates an audit Logger.
//
// A nil writer is tolerated — Log calls will be silently dropped with
// a warning, matching the best-effort contract. defaultProjectID is the
// boot-default storage partition (ADR-0002); per-request scoping is layered
// on via WithProjectScoper.
func NewLogger(writer NodeWriter, defaultProjectID string, logger *zap.Logger) *Logger {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Logger{
		writer:           writer,
		defaultProjectID: defaultProjectID,
		logger:           logger,
		nowFunc:          time.Now,
	}
}

// WithProjectScoper installs the per-request project resolver and returns the
// receiver for chaining. internal/app calls it once at boot. Passing nil is a
// no-op, leaving the logger on its boot-default binding.
func (l *Logger) WithProjectScoper(scoper ProjectScoper) *Logger {
	l.scoper = scoper
	return l
}

// resolveProject returns the writer + project id an event logged under ctx
// must use: the injected scoper's result when present and non-empty, else the
// boot-default binding. A scoper that yields an empty project id or nil writer
// falls back to the boot default field-by-field so a partial resolution never
// produces an unpartitioned write.
func (l *Logger) resolveProject(ctx context.Context) (NodeWriter, string) {
	writer, projectID := l.writer, l.defaultProjectID
	if l.scoper != nil {
		if w, p := l.scoper(ctx); p != "" {
			projectID = p
			if w != nil {
				writer = w
			}
		}
	}
	return writer, projectID
}

// Log writes an audit event to the datastore. It never returns an error and
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

	// Resolve the request's project (writer + id) up front, on the calling
	// goroutine that still holds the project scope — the async queue detaches
	// the context, so resolution must not be deferred to the flusher.
	writer, projectID := l.resolveProject(ctx)
	if writer == nil {
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
	// as required by the graph wire format.
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

	ops := []graph.Operation{
		{
			Type:   graph.OpCreateNode,
			TypeID: auditEventTypeID,
			Data:   data,
		},
	}

	if l.queueLive.Load() {
		l.enqueueAsync(ctx, writer, projectID, event, ops)
		return
	}

	_, err := writer.ExecuteAtomic(ctx, projectID, auditWriteActor, ops)
	if err != nil {
		l.logger.Error(
			"audit_log_failed",
			zap.String("event_type", string(event)),
			zap.Error(err),
		)
	}
}

// StartAsync switches Log into async mode: writes are enqueued on a
// bounded channel and drained by a background goroutine. queueSize must
// be > 0. Calling StartAsync more than once is a no-op. The returned
// Close func stops the flusher and drains pending writes; safe to call
// multiple times.
func (l *Logger) StartAsync(queueSize int) func() {
	l.startStop.Lock()
	defer l.startStop.Unlock()
	if l.queueLive.Load() {
		return l.closeFn()
	}
	if queueSize <= 0 {
		queueSize = 1024
	}
	l.queue = make(chan asyncOp, queueSize)
	l.done = make(chan struct{})
	l.queueLive.Store(true)
	l.flushersWG.Add(1)
	go l.flush()
	return l.closeFn()
}

// DroppedCount returns the cumulative number of audit events dropped
// because the async queue was full. Useful for tests and Prometheus
// exporters.
func (l *Logger) DroppedCount() uint64 {
	return l.dropped.Load()
}

func (l *Logger) closeFn() func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			// queueLive=false redirects new Log calls to sync mode
			// before we signal the flusher to drain.
			if !l.queueLive.Swap(false) {
				return
			}
			close(l.done)
			l.flushersWG.Wait()
		})
	}
}

func (l *Logger) enqueueAsync(ctx context.Context, writer NodeWriter, projectID string, event EventType, ops []graph.Operation) {
	op := asyncOp{
		ctx:       context.WithoutCancel(ctx),
		writer:    writer,
		projectID: projectID,
		ops:       ops,
		event:     event,
	}
	select {
	case l.queue <- op:
	default:
		// Queue full: drop and surface. We DON'T block the caller —
		// that's the whole point of async mode.
		n := l.dropped.Add(1)
		if n == 1 || n%1000 == 0 {
			l.logger.Warn(
				"audit_log_dropped_queue_full",
				zap.String("event_type", string(event)),
				zap.Uint64("total_dropped", n),
			)
		}
	}
}

func (l *Logger) flush() {
	defer l.flushersWG.Done()
	for {
		select {
		case op, ok := <-l.queue:
			if !ok {
				return
			}
			l.writeOne(op)
		case <-l.done:
			// Drain remaining items, then exit.
			for {
				select {
				case op := <-l.queue:
					l.writeOne(op)
				default:
					return
				}
			}
		}
	}
}

func (l *Logger) writeOne(op asyncOp) {
	defer func() {
		if r := recover(); r != nil {
			l.logger.Error(
				"audit_log_async_panic",
				zap.String("event_type", string(op.event)),
				zap.Any("panic", r),
			)
		}
	}()
	_, err := op.writer.ExecuteAtomic(op.ctx, op.projectID, auditWriteActor, op.ops)
	if err != nil {
		l.logger.Error(
			"audit_log_async_failed",
			zap.String("event_type", string(op.event)),
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
