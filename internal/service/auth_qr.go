package service

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

// ── InitiateQrLogin ────────────────────────────────────────────────────

// InitiateQrLogin creates a new QR login session for an unauthenticated device.
// Returns (sessionID, qrURL, expiresIn, error).
func (s *AuthService) InitiateQrLogin(ctx context.Context, deviceInfo, userAgent, ipAddr string) (string, string, int32, error) {
	sessionID := generateSessionID()
	now := s.nowMs()
	expiresIn := secondsToInt32(s.cfg.QRLoginExpirySeconds)
	expiresAt := now + int64(expiresIn)*1000

	_, err := s.repo.CreateQrLoginSession(ctx, &QrLoginSessionRecord{
		SessionID:          sessionID,
		Status:             "pending",
		NewDeviceInfo:      deviceInfo,
		NewDeviceIP:        ipAddr,
		NewDeviceUserAgent: truncate(userAgent, 512),
		ExpiresAt:          expiresAt,
		CreatedAt:          now,
		UpdatedAt:          now,
	})
	if err != nil {
		return "", "", 0, fmt.Errorf("creating QR login session: %w", err)
	}

	qrURL := strings.TrimRight(s.cfg.QRLoginBaseURL, "/") + "/qr-login/" + sessionID
	s.logger.Info("qr_login_initiated",
		zap.String("device_info", deviceInfo),
		zap.Int32("expires_in", expiresIn),
	)
	return sessionID, qrURL, expiresIn, nil
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
		s.audit.Log(ctx, audit.EventQrLoginApproved,
			audit.WithActor(userID),
			audit.WithSuccess(true),
		)
	} else {
		newStatus = "rejected"
		err = s.repo.UpdateQrLoginSession(ctx, session.NodeID, map[string]any{
			"status":     "rejected",
			"updated_at": now,
		})
		s.audit.Log(ctx, audit.EventQrLoginRejected,
			audit.WithActor(userID),
			audit.WithSuccess(true),
		)
	}
	if err != nil {
		return "", fmt.Errorf("updating QR login session: %w", err)
	}

	s.logger.Info("qr_login_decision",
		zap.String("user_id", userID),
		zap.Bool("approved", approve),
	)
	return newStatus, nil
}

// ── PollQrLogin ────────────────────────────────────────────────────────

// PollQrLogin polls a QR login session. When approved, issues tokens and
// marks the session consumed. Returns (status, user, accessToken, refreshToken, error).
func (s *AuthService) PollQrLogin(ctx context.Context, sessionID, ipAddr, userAgent string) (*PollQrResult, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("%w: session_id is required", ErrInvalidArgument)
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

	// status == "approved" -- mint tokens and consume the session.
	if session.UserID == "" {
		s.logger.Error("qr_login_approved_without_user", zap.String("node_id", session.NodeID))
		return nil, fmt.Errorf("approved session has no user")
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

	// Mark consumed after issuing tokens.
	_ = s.repo.UpdateQrLoginSession(ctx, session.NodeID, map[string]any{
		"status": "consumed", "updated_at": now,
	})

	s.logger.Info("qr_login_completed", zap.String("user_id", user.ID))

	return &PollQrResult{
		Status:       "approved",
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}
