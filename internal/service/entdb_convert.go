package service

import (
	"time"

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb"
)

// ── Node-to-domain converters ──────────────────────────────────────

func userFromNode(n *entdb.Node) *User {
	if n == nil {
		return nil
	}
	p := n.Payload
	return &User{
		ID:            n.NodeID,
		Email:         pstr(p, ufEmail),
		Name:          pstr(p, ufName),
		Role:          pstrOr(p, ufRole, "member"),
		AvatarURL:     pstr(p, ufAvatarURL),
		Status:        pstrOr(p, ufStatus, "active"),
		RecoveryEmail: pstr(p, ufRecoveryEmail),
		QuotaBytes:    pi64(p, ufQuotaBytes),
		TotpRequired:  pbool(p, ufTOTPRequired),
		LastLoginAtMs: pi64(p, ufLastLoginAt),
		CreatedAt:     time.UnixMilli(pi64(p, ufCreatedAt)),
		UpdatedAt:     time.UnixMilli(pi64(p, ufUpdatedAt)),
		PasswordHash:  pstr(p, ufPasswordHash),
	}
}

func groupFromNode(n *entdb.Node) *Group {
	if n == nil {
		return nil
	}
	p := n.Payload
	return &Group{
		ID:          n.NodeID,
		Name:        pstr(p, gfName),
		Description: pstr(p, gfDescription),
		CreatedAt:   pi64(p, gfCreatedAt),
		UpdatedAt:   pi64(p, gfUpdatedAt),
	}
}

func helpRequestFromNode(n *entdb.Node) *HelpRequest {
	if n == nil {
		return nil
	}
	p := n.Payload
	return &HelpRequest{
		ID:              n.NodeID,
		Email:           pstr(p, hfEmail),
		Reason:          pstr(p, hfReason),
		SourceIP:        pstr(p, hfSourceIP),
		UserAgent:       pstr(p, hfUserAgent),
		Status:          pstrOr(p, hfStatus, "pending"),
		ResolvedBy:      pstr(p, hfResolvedBy),
		ResolutionNotes: pstr(p, hfResolutionNotes),
		ResolvedAt:      pi64(p, hfResolvedAt),
		CreatedAt:       pi64(p, hfCreatedAt),
	}
}

func sessionFromNode(n *entdb.Node) *Session {
	if n == nil {
		return nil
	}
	p := n.Payload
	return &Session{
		ID:         n.NodeID,
		DeviceName: pstr(p, rfDeviceName),
		IPAddress:  pstr(p, rfIPAddress),
		UserAgent:  pstr(p, rfUserAgent),
		CreatedAt:  pi64(p, rfCreatedAt),
		LastUsedAt: pi64(p, rfLastUsedAt),
		ExpiresAt:  pi64(p, rfExpiresAt),
	}
}

func passkeyInfoFromNode(n *entdb.Node) *PasskeyInfo {
	if n == nil {
		return nil
	}
	p := n.Payload
	return &PasskeyInfo{
		CredentialID: pstr(p, pkfCredentialID),
		DeviceName:   pstr(p, pkfDeviceName),
		CreatedAt:    time.UnixMilli(pi64(p, pkfCreatedAt)),
		LastUsedAt:   time.UnixMilli(pi64(p, pkfLastUsedAt)),
	}
}

// ── Payload helpers ────────────────────────────────────────────────
// These use "p" prefix to avoid colliding with any existing helpers
// in auth.go.

func pstr(p map[string]any, key string) string {
	if v, ok := p[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func pstrOr(p map[string]any, key, def string) string {
	s := pstr(p, key)
	if s == "" {
		return def
	}
	return s
}

func pi64(p map[string]any, key string) int64 {
	v, ok := p[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case int64:
		return n
	case float64:
		return int64(n)
	case int:
		return int64(n)
	}
	return 0
}

func pbool(p map[string]any, key string) bool {
	v, ok := p[key]
	if !ok {
		return false
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

func nowMs() int64 {
	return time.Now().UnixMilli()
}

func actorStr(userID string) string {
	return "user:" + userID
}

// tenantAdminActor is the actor used by service-layer admin and
// bookkeeping operations that need tenant-wide visibility (e.g.
// uniqueness checks across users, listing groups across users,
// admin-driven user invites).
//
// `system:admin` is the upstream tenant-shard-db tenant-admin
// namespace. Unlike a user actor it has tenant-wide read/write and
// does not need to be a registered user in the global registry. The
// older form `"user:system"` had no such privileges under v1.12+'s
// actor-scoped visibility model — it would silently return zero rows
// for any cross-user query and ACCESS_DENIED for any write under a
// tenant it was not a member of.
const tenantAdminActor = "system:admin"
