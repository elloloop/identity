package connect

import (
	"encoding/json"
	"math"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func intToProtoInt32(n int) int32 {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	if n < math.MinInt32 {
		return math.MinInt32
	}
	return int32(n) // #nosec G115 -- bounds checked above.
}

// ─── Domain → Proto converters ──────────────────────────────────────────────
//
// These functions convert service-layer domain types to proto messages.
// They are nil-safe: a nil input returns nil.
//
// Note on timestamps: the AuthService User type uses time.Time for
// CreatedAt/UpdatedAt while other service types (Session, Group, etc.)
// use int64 epoch milliseconds. The converters handle both representations
// and will be unified when the type discrepancy in the service layer is
// reconciled. For now, converters use time.Time since auth.go's User is
// the authoritative definition (most complete, with PasswordHash, etc.).

func userToProto(u *service.User) *identitypb.User {
	if u == nil {
		return nil
	}
	pb := &identitypb.User{
		Id:               u.ID,
		Email:            u.Email,
		Name:             u.Name,
		AvatarUrl:        u.AvatarURL,
		Role:             u.Role,
		TotpRequired:     u.TotpRequired,
		Status:           userStatusToProto(u.Status),
		RecoveryEmail:    u.RecoveryEmail,
		QuotaBytes:       u.QuotaBytes,
		LastLoginAtMs:    u.LastLoginAtMs,
		EmailVerified:    u.EmailVerified,
		EmailVerifiedAt:  u.EmailVerifiedAt,
		IdvVerified:      u.IDVVerified,
		IdvVerifiedAt:    u.IDVVerifiedAt,
		PhoneNumber:      u.PhoneNumber,
		PhoneVerified:    u.PhoneVerified,
		PhoneVerifiedAt:  u.PhoneVerifiedAt,
		FailedLoginCount: intToProtoInt32(u.FailedLoginCount),
		LockedUntil:      u.LockedUntil,
		DateOfBirthMs:    u.DateOfBirthMs,
		IsMinor:          u.IsMinor,
		AgeBand:          ageBandToProto(u.AgeBand),
		ExternalId:       u.ExternalID,
		IsAnonymous:      u.IsAnonymous,
	}
	if !u.CreatedAt.IsZero() {
		pb.CreatedAt = timestamppb.New(u.CreatedAt)
	}
	if !u.UpdatedAt.IsZero() {
		pb.UpdatedAt = timestamppb.New(u.UpdatedAt)
	}
	return pb
}

func userStatusToProto(s string) identitypb.UserStatus {
	switch s {
	case "active":
		return identitypb.UserStatus_USER_STATUS_ACTIVE
	case "invited":
		return identitypb.UserStatus_USER_STATUS_INVITED
	case "deactivated":
		return identitypb.UserStatus_USER_STATUS_DEACTIVATED
	case "suspended":
		return identitypb.UserStatus_USER_STATUS_SUSPENDED
	case "pending_parental_consent":
		return identitypb.UserStatus_USER_STATUS_PENDING_PARENTAL_CONSENT
	case "pending_deletion":
		return identitypb.UserStatus_USER_STATUS_PENDING_DELETION
	default:
		return identitypb.UserStatus_USER_STATUS_UNSPECIFIED
	}
}

func protoToUserStatusString(s identitypb.UserStatus) string {
	switch s {
	case identitypb.UserStatus_USER_STATUS_ACTIVE:
		return "active"
	case identitypb.UserStatus_USER_STATUS_INVITED:
		return "invited"
	case identitypb.UserStatus_USER_STATUS_DEACTIVATED:
		return "deactivated"
	case identitypb.UserStatus_USER_STATUS_SUSPENDED:
		return "suspended"
	case identitypb.UserStatus_USER_STATUS_PENDING_PARENTAL_CONSENT:
		return "pending_parental_consent"
	case identitypb.UserStatus_USER_STATUS_PENDING_DELETION:
		return "pending_deletion"
	default:
		return ""
	}
}

func ageBandToProto(b string) identitypb.AgeBand {
	switch b {
	case "CHILD":
		return identitypb.AgeBand_AGE_BAND_CHILD
	case "TEEN":
		return identitypb.AgeBand_AGE_BAND_TEEN
	case "ADULT":
		return identitypb.AgeBand_AGE_BAND_ADULT
	default:
		return identitypb.AgeBand_AGE_BAND_UNSPECIFIED
	}
}

func groupToProto(g *service.Group) *identitypb.Group {
	if g == nil {
		return nil
	}
	return &identitypb.Group{
		Id:          g.ID,
		Name:        g.Name,
		Description: g.Description,
		CreatedAt:   msToTimestamp(g.CreatedAt),
		UpdatedAt:   msToTimestamp(g.UpdatedAt),
	}
}

func sessionToProto(s *service.Session) *identitypb.Session {
	if s == nil {
		return nil
	}
	return &identitypb.Session{
		SessionId:  s.ID,
		DeviceName: s.DeviceName,
		IpAddress:  s.IPAddress,
		UserAgent:  s.UserAgent,
		Current:    s.Current,
		CreatedAt:  msToTimestamp(s.CreatedAt),
		LastUsedAt: msToTimestamp(s.LastUsedAt),
		ExpiresAt:  msToTimestamp(s.ExpiresAt),
	}
}

func passkeyToProto(p *service.PasskeyInfo) *identitypb.PasskeyCredentialInfo {
	if p == nil {
		return nil
	}
	pb := &identitypb.PasskeyCredentialInfo{
		CredentialId: p.CredentialID,
		DeviceName:   p.DeviceName,
	}
	if !p.CreatedAt.IsZero() {
		pb.CreatedAt = timestamppb.New(p.CreatedAt)
	}
	if !p.LastUsedAt.IsZero() {
		pb.LastUsedAt = timestamppb.New(p.LastUsedAt)
	}
	return pb
}

func helpRequestToProto(h *service.HelpRequest) *identitypb.AdminHelpRequest {
	if h == nil {
		return nil
	}
	return &identitypb.AdminHelpRequest{
		Id:              h.ID,
		Email:           h.Email,
		Reason:          h.Reason,
		SourceIp:        h.SourceIP,
		UserAgent:       h.UserAgent,
		Status:          helpRequestStatusToProto(h.Status),
		ResolvedBy:      h.ResolvedBy,
		ResolutionNotes: h.ResolutionNotes,
		ResolvedAt:      msToTimestamp(h.ResolvedAt),
		CreatedAt:       msToTimestamp(h.CreatedAt),
	}
}

func helpRequestStatusToProto(s string) identitypb.HelpRequestStatus {
	switch s {
	case "pending":
		return identitypb.HelpRequestStatus_HELP_REQUEST_STATUS_PENDING
	case "resolved":
		return identitypb.HelpRequestStatus_HELP_REQUEST_STATUS_RESOLVED
	case "rejected":
		return identitypb.HelpRequestStatus_HELP_REQUEST_STATUS_REJECTED
	default:
		return identitypb.HelpRequestStatus_HELP_REQUEST_STATUS_UNSPECIFIED
	}
}

func protoToHelpRequestStatusString(s identitypb.HelpRequestStatus) string {
	switch s {
	case identitypb.HelpRequestStatus_HELP_REQUEST_STATUS_PENDING:
		return "pending"
	case identitypb.HelpRequestStatus_HELP_REQUEST_STATUS_RESOLVED:
		return "resolved"
	case identitypb.HelpRequestStatus_HELP_REQUEST_STATUS_REJECTED:
		return "rejected"
	default:
		return ""
	}
}

func auditEventToProto(e *service.AuditEvent) *identitypb.AuditEvent {
	if e == nil {
		return nil
	}
	// Details is map[string]any in the service layer; encode as JSON string for proto.
	detailsJSON := ""
	if len(e.Details) > 0 {
		b, err := json.Marshal(e.Details)
		if err == nil {
			detailsJSON = string(b)
		}
	}
	return &identitypb.AuditEvent{
		Id:           e.ID,
		EventType:    e.EventType,
		ActorUserId:  e.ActorUserID,
		TargetUserId: e.TargetUserID,
		IpAddress:    e.IPAddress,
		UserAgent:    e.UserAgent,
		Success:      e.Success,
		Details:      detailsJSON,
		CreatedAt:    msToTimestamp(e.CreatedAt),
	}
}

func qrLoginStatusToProto(s string) identitypb.QrLoginStatus {
	switch s {
	case "pending":
		return identitypb.QrLoginStatus_QR_LOGIN_STATUS_PENDING
	case "approved":
		return identitypb.QrLoginStatus_QR_LOGIN_STATUS_APPROVED
	case "rejected":
		return identitypb.QrLoginStatus_QR_LOGIN_STATUS_REJECTED
	case "expired":
		return identitypb.QrLoginStatus_QR_LOGIN_STATUS_EXPIRED
	case "consumed":
		return identitypb.QrLoginStatus_QR_LOGIN_STATUS_CONSUMED
	default:
		return identitypb.QrLoginStatus_QR_LOGIN_STATUS_UNSPECIFIED
	}
}

// msToTimestamp converts epoch milliseconds to a proto Timestamp.
// Returns nil for zero or negative values.
func msToTimestamp(ms int64) *timestamppb.Timestamp {
	if ms <= 0 {
		return nil
	}
	sec := ms / 1000
	nsec := (ms % 1000) * 1_000_000
	return &timestamppb.Timestamp{
		Seconds: sec,
		Nanos:   int32(nsec),
	}
}

// ─── Slice converters ───────────────────────────────────────────────────────

func usersToProto(users []*service.User) []*identitypb.User {
	out := make([]*identitypb.User, len(users))
	for i, u := range users {
		out[i] = userToProto(u)
	}
	return out
}

func groupsToProto(groups []*service.Group) []*identitypb.Group {
	out := make([]*identitypb.Group, len(groups))
	for i, g := range groups {
		out[i] = groupToProto(g)
	}
	return out
}

func sessionsToProto(sessions []*service.Session) []*identitypb.Session {
	out := make([]*identitypb.Session, len(sessions))
	for i, s := range sessions {
		out[i] = sessionToProto(s)
	}
	return out
}

func passkeysToProto(pks []*service.PasskeyInfo) []*identitypb.PasskeyCredentialInfo {
	out := make([]*identitypb.PasskeyCredentialInfo, len(pks))
	for i, p := range pks {
		out[i] = passkeyToProto(p)
	}
	return out
}

func helpRequestsToProto(reqs []*service.HelpRequest) []*identitypb.AdminHelpRequest {
	out := make([]*identitypb.AdminHelpRequest, len(reqs))
	for i, r := range reqs {
		out[i] = helpRequestToProto(r)
	}
	return out
}

func auditEventsToProto(events []*service.AuditEvent) []*identitypb.AuditEvent {
	out := make([]*identitypb.AuditEvent, len(events))
	for i, e := range events {
		out[i] = auditEventToProto(e)
	}
	return out
}
