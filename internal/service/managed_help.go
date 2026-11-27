package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
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
	// ManagedHelpNoRecipients: the tenant has no active owner or admin to
	// tell; nothing is recorded, and the request goes to the project's
	// admins.
	ManagedHelpNoRecipients = "no_recipients"
)

// ManagedHelpRequest asks ManagedHelpStore.RecordManagedHelp to record a
// help request for the managed account at Address.
type ManagedHelpRequest struct {
	ProjectID string
	// Address is the address asked about, in canonical form.
	Address string
	// SourceKey stands for the client the request came from
	// (managedHelpSourceKey); the store keeps it to count the requests from
	// one source.
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
	// ManagedHelpTenantLimited, ManagedHelpSourceLimited or
	// ManagedHelpNoRecipients.
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
	// is told: not when it has no active owner or admin to tell
	// (ManagedHelpNoRecipients, which uses no cap), nor when it was told
	// about the account since req.SinceMs, nor past the tenant's cap or the
	// source's. Only a notice that goes out is recorded. An address that is
	// no such account is ErrNotFound.
	RecordManagedHelp(ctx context.Context, req ManagedHelpRequest) (*ManagedHelpRecorded, error)
}

// AdminHelpRouter decides where a help request goes (WithAdminHelpRouter).
type AdminHelpRouter interface {
	// RouteAdminHelp takes a request about address, with the caller's
	// reason, from sourceIP and userAgent; for anything it does not route
	// itself it calls ordinary, which files the request for the project's
	// admins.
	RouteAdminHelp(ctx context.Context, address, reason, sourceIP, userAgent string, ordinary func(context.Context))
}

// WithManagedHelp sets the store help requests about managed accounts are
// recorded in; nil sends every request to the project's admins.
func (s *AuthService) WithManagedHelp(store ManagedHelpStore) *AuthService {
	s.managedHelp = store
	return s
}

// WithManagedHelpMetrics counts, as
// identity_managed_help_limited_total{outcome}, the help requests about a
// managed account that a daily cap kept from its tenant (outcome
// tenant_limited or source_limited), registered with reg (nil registers
// with a fresh registry, for tests). A rising count is a tenant being
// flooded with requests, or one locked-out member asking again and again.
func (s *AuthService) WithManagedHelpMetrics(reg prometheus.Registerer) (*AuthService, error) {
	if reg == nil {
		reg = prometheus.NewRegistry()
	}
	limited := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "identity_managed_help_limited_total",
		Help: "Help requests about a managed account that a daily cap kept from its tenant, labelled by outcome.",
	}, []string{"outcome"})
	if err := reg.Register(limited); err != nil {
		return nil, fmt.Errorf("managed help metrics: %w", err)
	}
	s.managedHelpLimited = limited
	return s, nil
}

// RouteAdminHelp implements AdminHelpRouter. Where managed accounts are
// enabled, a request is looked up off the request path (dispatchEmailSend),
// so neither the answer nor its timing says whether the address is a managed
// account: a request about an active or suspended managed account goes to
// the owners and admins of the tenant that manages it (RecordManagedHelp
// decides whether they are told), not to the project's admins, unless the
// tenant has no active owner or admin to tell, the lookup cannot run (a
// dropped dispatch) or managed accounts are off; those, and any other
// request, are filed as ordinary files it. A store error files nothing. The notice carries nothing the caller wrote,
// nor their IP address or user agent; the audit entry keeps those and the
// reason. Where managed accounts are off, or the project sends no email,
// ordinary files every request at once, as it always has; a dispatch that is
// dropped files it too.
func (s *AuthService) RouteAdminHelp(ctx context.Context, address, reason, sourceIP, userAgent string, ordinary func(context.Context)) {
	if !s.cfg.ManagedAccountsEnabled || s.managedHelp == nil {
		ordinary(ctx)
		return
	}
	if err := requireProjectEmailDelivery(ctx, s.cfg.DefaultProjectID, s.activeProjects); errors.Is(err, ErrEmailDeliveryDisabled) {
		ordinary(ctx)
		return
	}
	s.dispatchEmailSendOr(ctx, "admin_help", func(ctx context.Context) {
		s.routeAdminHelpNow(ctx, address, reason, sourceIP, userAgent, ordinary)
	}, ordinary)
}

// routeAdminHelpNow is the body of RouteAdminHelp's dispatch.
func (s *AuthService) routeAdminHelpNow(ctx context.Context, address, reason, sourceIP, userAgent string, ordinary func(context.Context)) {
	addr, usable := canonicalMailbox(address)
	if !usable {
		ordinary(ctx)
		return
	}
	now := s.nowMs()
	projectID := requestProjectID(ctx, s.cfg.DefaultProjectID)
	rec, err := s.managedHelp.RecordManagedHelp(ctx, ManagedHelpRequest{
		ProjectID: projectID, Address: string(addr), SourceKey: s.managedHelpSourceKey(sourceIP), NowMs: now,
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
	switch rec.Outcome {
	case ManagedHelpNoRecipients:
		s.logger.Info("managed_account_help_not_sent", fields...)
		ordinary(ctx)
		return
	case ManagedHelpNotify:
	default:
		s.logger.Info("managed_account_help_not_sent", fields...)
		if rec.Outcome != ManagedHelpDuplicate {
			s.auditManagedHelp(ctx, rec, false, reason, sourceIP, userAgent)
			if s.managedHelpLimited != nil {
				s.managedHelpLimited.WithLabelValues(rec.Outcome).Inc()
			}
		}
		return
	}
	sent := s.sendManagedHelpNotices(ctx, rec)
	s.logger.Info("managed_account_help_requested", append(fields, zap.Int("recipients", len(rec.Recipients)), zap.Int("sent", sent))...)
	s.auditManagedHelp(ctx, rec, true, reason, sourceIP, userAgent)
}

// managedHelpSourceLabel separates the key managedHelpSourceKey derives from
// the server secret from every other use of that secret.
const managedHelpSourceLabel = "identity/managed-help-source/v1"

// managedHelpSourceKey stands for the client a help request came from: an
// HMAC of its address, an IPv6 address taken as its /64 so one host cannot
// spread its requests over its prefix, under a key derived from the server's
// TOTP recovery pepper, a secret every server holds. The store keeps this
// key, never the address, and one cannot be turned back into the other
// without the secret.
func (s *AuthService) managedHelpSourceKey(sourceIP string) string {
	derive := hmac.New(sha256.New, s.totpRecoveryPepper)
	derive.Write([]byte(managedHelpSourceLabel))
	mac := hmac.New(sha256.New, derive.Sum(nil))
	mac.Write([]byte(normalizeHelpSource(sourceIP)))
	return hex.EncodeToString(mac.Sum(nil))
}

// normalizeHelpSource is the part of a client address a help request is
// counted against: an IPv4 address whole, an IPv6 address as its /64, and
// anything that does not parse as it came.
func normalizeHelpSource(sourceIP string) string {
	addr, err := netip.ParseAddr(sourceIP)
	if err != nil {
		return sourceIP
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.WithZone("").Prefix(64)
	if err != nil {
		return sourceIP
	}
	return prefix.String()
}

// sendManagedHelpNotices tells each recipient that someone asked for help
// signing in to rec.Account, and returns how many notices went out.
func (s *AuthService) sendManagedHelpNotices(ctx context.Context, rec *ManagedHelpRecorded) int {
	notice := managedHelpNotice(s.cfg, rec)
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

// managedHelpNotice is the notice a tenant's owners and admins get about
// rec's account: named by its stored display name and address, never by
// anything the caller wrote, with a button to the tenant's members page
// when GATEWAY_TENANT_MEMBERS_PAGE_URL is set.
func managedHelpNotice(cfg *config.Config, rec *ManagedHelpRecorded) accountNotice {
	name, who := rec.Account.Email, rec.Account.Email
	if n := strings.TrimSpace(rec.Account.Name); n != "" {
		name, who = n, fmt.Sprintf("%s (%s)", n, rec.Account.Email)
	}
	return accountNotice{
		headline:    name + " asked for help signing in",
		detail:      who + " asked for help signing in.",
		advice:      "If you know it was them, reset their sign-in from Members: it signs them out, clears their password and two-step verification, and sends a new set-up link to an address you choose. If it was not them, do nothing; no other request about this account is sent for 24 hours. You get this because you are an owner or admin of the organization that manages the account.",
		buttonLabel: "Open Members",
		buttonURL:   tenantMembersLink(cfg, rec.TenantID),
	}
}

// auditManagedHelp records a managed account's help request that told its
// tenant (ok) or was refused by a cap, with the caller's reason as
// RequestAdminHelp truncated it.
func (s *AuthService) auditManagedHelp(ctx context.Context, rec *ManagedHelpRecorded, ok bool, reason, sourceIP, userAgent string) {
	s.audit.Log(ctx, audit.EventManagedAccountHelpRequested,
		audit.WithTarget(rec.Account.ID),
		audit.WithIP(sourceIP), audit.WithUserAgent(userAgent),
		audit.WithSuccess(ok), audit.WithDetails(map[string]any{
			"tenant_id":  rec.TenantID,
			"outcome":    rec.Outcome,
			"recipients": len(rec.Recipients),
			"reason":     reason,
		}),
	)
}
