package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
)

// managedHelpWindow is how far back a managed account's help requests are
// counted: one notice per account, and the tenant's and each source's caps,
// per day.
const managedHelpWindow = 24 * time.Hour

// Outcomes of ManagedHelpStore.RecordManagedHelp.
const (
	// ManagedHelpNotify: the notice is recorded and goes to the recipients.
	ManagedHelpNotify = "notify"
	// ManagedHelpDuplicate: the account's tenant was told within the window.
	ManagedHelpDuplicate = "duplicate"
	// ManagedHelpTenantLimited: the tenant was sent its cap of notices in
	// the window.
	ManagedHelpTenantLimited = "tenant_limited"
	// ManagedHelpSourceLimited: requests from the source caused their cap of
	// the tenant's notices in the window.
	ManagedHelpSourceLimited = "source_limited"
)

// ManagedHelpRequest asks ManagedHelpStore.RecordManagedHelp to record a
// help request for the managed account at Address.
type ManagedHelpRequest struct {
	ProjectID string
	// Address is the address asked about, in canonical form.
	Address string
	// SourceKey stands for the client the request came from; the store keeps
	// it to count the requests from one source.
	SourceKey string
	NowMs     int64
	// SinceMs starts the window the account's earlier notice, and the caps,
	// are counted over.
	SinceMs            int64
	MaxPerTenant       int
	MaxPerTenantSource int
}

// ManagedHelpRecorded is what RecordManagedHelp decided.
type ManagedHelpRecorded struct {
	// Account is the managed account at the address.
	Account *User
	// TenantID is the tenant that manages it.
	TenantID string
	// Outcome is ManagedHelpNotify, ManagedHelpDuplicate,
	// ManagedHelpTenantLimited or ManagedHelpSourceLimited.
	Outcome string
	// Recipients are the tenant's active owners and admins, active accounts
	// with an address other than Account, when Outcome is ManagedHelpNotify.
	Recipients []*User
}

// ManagedHelpStore records help requests about managed accounts, for the
// tenants that manage them. Only the postgres control-plane driver has one.
type ManagedHelpStore interface {
	// RecordManagedHelp finds the managed account at req.Address and, when
	// its membership of the tenant that manages it is active or suspended,
	// decides in one transaction, serialised per tenant, whether its tenant
	// is told: not when it was told about the account since req.SinceMs, nor
	// past the tenant's cap or the source's. Only a notice that goes out is
	// recorded. An address that is no such account is ErrNotFound.
	RecordManagedHelp(ctx context.Context, req ManagedHelpRequest) (*ManagedHelpRecorded, error)
}

// AdminHelpRouter decides where a help request goes (WithAdminHelpRouter).
type AdminHelpRouter interface {
	// RouteAdminHelp takes a request about address from sourceIP and
	// userAgent; for anything it does not route itself it calls ordinary,
	// which files the request for the project's admins.
	RouteAdminHelp(ctx context.Context, address, sourceIP, userAgent string, ordinary func(context.Context))
}

// WithManagedHelp sets the store help requests about managed accounts are
// recorded in; nil sends every request to the project's admins.
func (s *AuthService) WithManagedHelp(store ManagedHelpStore) *AuthService {
	s.managedHelp = store
	return s
}

// RouteAdminHelp implements AdminHelpRouter. Where managed accounts are
// enabled, a request is looked up off the request path (dispatchEmailSend),
// so neither the answer nor its timing says whether the address is a managed
// account: a request about an active or suspended managed account goes to
// the owners and admins of the tenant that manages it (RecordManagedHelp
// decides whether they are told) and never to the project's admins, and any
// other request is filed as ordinary files it. The notice carries nothing
// the caller wrote, nor their IP address or user agent, which only the audit
// entry keeps. Where managed accounts are off, or the project sends no
// email, ordinary files every request at once, as it always has.
func (s *AuthService) RouteAdminHelp(ctx context.Context, address, sourceIP, userAgent string, ordinary func(context.Context)) {
	if !s.cfg.ManagedAccountsEnabled || s.managedHelp == nil {
		ordinary(ctx)
		return
	}
	if err := requireProjectEmailDelivery(ctx, s.cfg.DefaultProjectID, s.activeProjects); err != nil {
		ordinary(ctx)
		return
	}
	s.dispatchEmailSend(ctx, "admin_help", func(ctx context.Context) {
		s.routeAdminHelpNow(ctx, address, sourceIP, userAgent, ordinary)
	})
}

// routeAdminHelpNow is the body of RouteAdminHelp's dispatch.
func (s *AuthService) routeAdminHelpNow(ctx context.Context, address, sourceIP, userAgent string, ordinary func(context.Context)) {
	addr, usable := canonicalMailbox(address)
	if !usable {
		ordinary(ctx)
		return
	}
	now := s.nowMs()
	projectID := requestProjectID(ctx, s.cfg.DefaultProjectID)
	rec, err := s.managedHelp.RecordManagedHelp(ctx, ManagedHelpRequest{
		ProjectID: projectID, Address: string(addr), SourceKey: sha256Hex(sourceIP), NowMs: now,
		SinceMs:            now - managedHelpWindow.Milliseconds(),
		MaxPerTenant:       s.cfg.ManagedHelpTenantLimit(),
		MaxPerTenantSource: s.cfg.ManagedHelpSourceLimit(),
	})
	if errors.Is(err, ErrNotFound) {
		ordinary(ctx)
		return
	}
	if err != nil {
		s.logger.Error("managed_account_help_failed", zap.String("project_id", projectID), zap.Error(err))
		return
	}
	fields := []zap.Field{
		zap.String("project_id", projectID), zap.String("tenant_id", rec.TenantID),
		zap.String("user_id", rec.Account.ID), zap.String("outcome", rec.Outcome),
	}
	if rec.Outcome != ManagedHelpNotify {
		s.logger.Info("managed_account_help_not_sent", fields...)
		if rec.Outcome != ManagedHelpDuplicate {
			s.auditManagedHelp(ctx, rec, false, sourceIP, userAgent)
		}
		return
	}
	sent := s.sendManagedHelpNotices(ctx, rec)
	s.logger.Info("managed_account_help_requested", append(fields, zap.Int("recipients", len(rec.Recipients)), zap.Int("sent", sent))...)
	s.auditManagedHelp(ctx, rec, true, sourceIP, userAgent)
}

// sendManagedHelpNotices tells each recipient that someone asked for help
// signing in to rec.Account, and returns how many notices went out.
func (s *AuthService) sendManagedHelpNotices(ctx context.Context, rec *ManagedHelpRecorded) int {
	notice := accountNotice{
		headline: "Someone asked for help signing in",
		detail:   fmt.Sprintf("Someone asked for help signing in to %s, an account your organization manages.", rec.Account.Email),
		advice:   "If they should have access, reset the account from your organization's member list. If you did not expect this, you can ignore this message.",
	}
	brand := resolveBranding(ctx, s.cfg, "")
	sent := 0
	for _, to := range rec.Recipients {
		html, text, err := renderAccountNotice(brand, displayNameOrEmail(to), notice)
		if err == nil {
			msg := email.Message{To: to.Email, From: s.cfg.SMTPFrom, Subject: notice.headline, HTML: html, Text: text}
			brand.applyTo(&msg)
			err = s.mailer.Send(ctx, msg)
		}
		if err != nil {
			s.logger.Warn("managed_account_help_send_failed",
				zap.String("tenant_id", rec.TenantID), zap.String("recipient_id", to.ID), zap.Error(err))
			continue
		}
		sent++
	}
	return sent
}

// auditManagedHelp records a managed account's help request that told its
// tenant (ok) or was refused by a cap.
func (s *AuthService) auditManagedHelp(ctx context.Context, rec *ManagedHelpRecorded, ok bool, sourceIP, userAgent string) {
	s.audit.Log(ctx, audit.EventManagedAccountHelpRequested,
		audit.WithTarget(rec.Account.ID),
		audit.WithIP(sourceIP), audit.WithUserAgent(userAgent),
		audit.WithSuccess(ok), audit.WithDetails(map[string]any{
			"tenant_id":  rec.TenantID,
			"outcome":    rec.Outcome,
			"recipients": len(rec.Recipients),
		}),
	)
}
