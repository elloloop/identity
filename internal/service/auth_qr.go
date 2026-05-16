package service

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

// InitiateQrLoginResult is the value returned by InitiateQrLogin.
type InitiateQrLoginResult struct {
	SessionID  string
	QRURL      string
	PollSecret string
	ExpiresIn  int32
}

// ── InitiateQrLogin ────────────────────────────────────────────────────

// InitiateQrLogin creates a new QR login session for an unauthenticated device.
// The returned PollSecret is shown only to the initiating device and must be
// presented on every PollQrLogin call; it is NEVER embedded in the QR URL.
func (s *AuthService) InitiateQrLogin(ctx context.Context, deviceInfo, userAgent, ipAddr string) (*InitiateQrLoginResult, error) {
	sessionID := generateSessionID()
	pollSecret := randomToken(32)
	now := s.nowMs()
	expiresIn := secondsToInt32(s.cfg.QRLoginExpirySeconds)
	expiresAt := now + int64(expiresIn)*1000

	_, err := s.repo.CreateQrLoginSession(ctx, &QrLoginSessionRecord{
		SessionID:          sessionID,
		Status:             "pending",
		NewDeviceInfo:      deviceInfo,
		NewDeviceIP:        ipAddr,
		NewDeviceUserAgent: truncate(userAgent, 512),
		PollSecretHash:     sha256Hex(pollSecret),
		ExpiresAt:          expiresAt,
		CreatedAt:          now,
		UpdatedAt:          now,
	})
	if err != nil {
		return nil, fmt.Errorf("creating QR login session: %w", err)
	}

	qrURL := strings.TrimRight(s.cfg.QRLoginBaseURL, "/") + "/qr-login/" + sessionID
	s.logger.Info(
		"qr_login_initiated",
		zap.String("device_info", deviceInfo),
		zap.Int32("expires_in", expiresIn),
	)
	return &InitiateQrLoginResult{
		SessionID:  sessionID,
		QRURL:      qrURL,
		PollSecret: pollSecret,
		ExpiresIn:  expiresIn,
	}, nil
}

// ── GetQrLoginSession ──────────────────────────────────────────────────

// GetQrLoginSession returns display-safe details of a QR login session.
func (s *AuthService) GetQrLoginSession(ctx context.Context, sessionID string) (*QrSessionInfo, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("%w: session_id is required", ErrInvalidArgument)
	}

	session, err := s.repo.FindQrLoginSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, fmt.Errorf("%w: QR login session not found", ErrNotFound)
	}

	status := session.Status
	now := s.nowMs()
	if status == "pending" && session.ExpiresAt < now {
		_ = s.repo.UpdateQrLoginSession(ctx, session.NodeID, map[string]any{
			"status": "expired", "updated_at": now,
		})
		status = "expired"
	}

	return &QrSessionInfo{
		Status:        status,
		NewDeviceInfo: session.NewDeviceInfo,
		NewDeviceIP:   session.NewDeviceIP,
		ExpiresAt:     msToTime(session.ExpiresAt),
	}, nil
}

// ── ApproveQrLogin ─────────────────────────────────────────────────────

// ApproveQrLogin approves or rejects a QR login session. Returns the new status.
func (s *AuthService) ApproveQrLogin(ctx context.Context, sessionID string, approve bool, userID, userAgent string) (string, error) {
	if sessionID == "" {
		return "", fmt.Errorf("%w: session_id is required", ErrInvalidArgument)
	}

	session, err := s.repo.FindQrLoginSession(ctx, sessionID)
	if err != nil {
		return "", err
	}
	if session == nil {
		return "", fmt.Errorf("%w: QR login session not found", ErrNotFound)
	}

	now := s.nowMs()
	if session.ExpiresAt < now {
		if session.Status == "pending" {
			_ = s.repo.UpdateQrLoginSession(ctx, session.NodeID, map[string]any{
				"status": "expired", "updated_at": now,
			})
		}
		return "", ErrQrLoginExpired
	}

	if session.Status != "pending" {
		return "", fmt.Errorf("%w: status=%s", ErrQrLoginNotPending, session.Status)
	}

	var newStatus string
	if approve {
		newStatus = "approved"
		err = s.repo.UpdateQrLoginSession(ctx, session.NodeID, map[string]any{
			"status":               "approved",
			"user_id":              userID,
			"approved_device_info": truncate(userAgent, 512),
			"updated_at":           now,
		})
		s.audit.Log(
			ctx, audit.EventQrLoginApproved,
			audit.WithActor(userID),
			audit.WithSuccess(true),
		)
	} else {
		newStatus = "rejected"
		err = s.repo.UpdateQrLoginSession(ctx, session.NodeID, map[string]any{
			"status":     "rejected",
			"updated_at": now,
		})
		s.audit.Log(
			ctx, audit.EventQrLoginRejected,
			audit.WithActor(userID),
			audit.WithSuccess(true),
		)
	}
	if err != nil {
		return "", fmt.Errorf("updating QR login session: %w", err)
	}

	s.logger.Info(
		"qr_login_decision",
		zap.String("user_id", userID),
		zap.Bool("approved", approve),
	)
	return newStatus, nil
}

// ── PollQrLogin ────────────────────────────────────────────────────────

// PollQrLogin polls a QR login session. When approved, atomically
// consumes the session and issues tokens. Returns (status, user,
// accessToken, refreshToken, error). pollSecret must match the value
// returned by InitiateQrLogin; otherwise the session appears "expired"
// to the caller — a stolen QR URL alone is useless.
//
// Multi-replica correctness: the approved→consumed transition runs
// through the repository's ConsumeQrLoginSession compare-and-set
// primitive BEFORE tokens are minted, so only one of N concurrent
// pollers against the same approved session can complete the flow.
// The loser sees status="consumed" on the next poll cycle.
func (s *AuthService) PollQrLogin(ctx context.Context, sessionID, pollSecret, ipAddr, userAgent string) (*PollQrResult, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("%w: session_id is required", ErrInvalidArgument)
	}
	if pollSecret == "" {
		return &PollQrResult{Status: "expired"}, nil
	}

	session, err := s.repo.FindQrLoginSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if session == nil {
		// Do not distinguish "never existed" from "expired" -- both
		// look the same to a brute-force attacker.
		return &PollQrResult{Status: "expired"}, nil
	}

	if subtle.ConstantTimeCompare([]byte(sha256Hex(pollSecret)), []byte(session.PollSecretHash)) != 1 {
		return &PollQrResult{Status: "expired"}, nil
	}

	now := s.nowMs()
	status := session.Status

	// Expiry check for pending sessions.
	if status == "pending" && session.ExpiresAt < now {
		_ = s.repo.UpdateQrLoginSession(ctx, session.NodeID, map[string]any{
			"status": "expired", "updated_at": now,
		})
		return &PollQrResult{Status: "expired"}, nil
	}

	switch status {
	case "pending":
		return &PollQrResult{Status: "pending"}, nil
	case "rejected":
		return &PollQrResult{Status: "rejected"}, nil
	case "consumed":
		return &PollQrResult{Status: "consumed"}, nil
	case "expired":
		return &PollQrResult{Status: "expired"}, nil
	}

	// status == "approved" -- consume atomically, then mint tokens.
	if session.UserID == "" {
		s.logger.Error("qr_login_approved_without_user", zap.String("node_id", session.NodeID))
		return nil, errors.New("approved session has no user")
	}

	// Serialize approved→consumed at the repository layer. Two replicas
	// observing the same approved session race here; exactly one wins
	// and proceeds to mint tokens. The loser sees ErrQrLoginNotPending
	// and surfaces "consumed" — the same shape another caller would see
	// after the winner committed.
	if err := s.repo.ConsumeQrLoginSession(ctx, session.NodeID, now); err != nil {
		if errors.Is(err, ErrQrLoginNotPending) {
			return &PollQrResult{Status: "consumed"}, nil
		}
		return nil, fmt.Errorf("consuming QR login session: %w", err)
	}

	user, err := s.repo.GetUser(ctx, session.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}

	accessToken, refreshToken, err := s.issueTokens(ctx, user, ipAddr, userAgent)
	if err != nil {
		return nil, err
	}

	s.logger.Info("qr_login_completed", zap.String("user_id", user.ID))

	return &PollQrResult{
		Status:       "approved",
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}
