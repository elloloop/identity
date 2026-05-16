package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb"
)

// SetUserQuota updates the storage quota for a user.
func (s *AdminService) SetUserQuota(ctx context.Context, actorID, targetUserID string, quotaBytes int64) error {
	if _, err := s.requireAdmin(ctx, actorID); err != nil {
		return err
	}
	if targetUserID == "" {
		return errors.New("user_id is required")
	}
	if quotaBytes < 0 {
		return errors.New("quota_bytes must be non-negative")
	}

	node, err := s.db.GetNode(ctx, s.tenantID, actorStr(targetUserID), typeUser, targetUserID)
	if err != nil {
		return fmt.Errorf("fetch user: %w", err)
	}
	if node == nil {
		return errors.New("user not found")
	}

	op := entdb.Operation{
		Type: entdb.OpUpdateNode, TypeID: typeUser, NodeID: targetUserID,
		Patch: map[string]any{ufQuotaBytes: quotaBytes, ufUpdatedAt: nowMs()},
	}
	if _, err := s.db.ExecuteAtomic(ctx, s.tenantID, actorStr(actorID), []entdb.Operation{op}); err != nil {
		return fmt.Errorf("set quota: %w", err)
	}
	return nil
}

// ListUsers returns a paginated list of users, optionally filtered by
// status and/or search substring.
func (s *AdminService) ListUsers(
	ctx context.Context, actorID, statusFilter, search, cursor string, limit int,
) ([]*User, string, int, error) {
	if _, err := s.requireAdmin(ctx, actorID); err != nil {
		return nil, "", 0, err
	}

	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	offset := 0
	if cursor != "" {
		if parsed, err := strconv.Atoi(cursor); err == nil {
			offset = parsed
		}
	}

	nodes, err := s.db.QueryNodes(ctx, s.tenantID, tenantAdminActor, typeUser, nil)
	if err != nil {
		return nil, "", 0, fmt.Errorf("list users: %w", err)
	}

	searchLower := strings.TrimSpace(strings.ToLower(search))
	var filtered []*entdb.Node
	for _, n := range nodes {
		u := userFromNode(n)
		if statusFilter != "" && !strings.EqualFold(u.Status, statusFilter) {
			continue
		}
		if searchLower != "" {
			hay := strings.ToLower(u.Email + " " + u.Name)
			if !strings.Contains(hay, searchLower) {
				continue
			}
		}
		filtered = append(filtered, n)
	}

	totalCount := len(filtered)
	end := offset + limit
	if end > totalCount {
		end = totalCount
	}
	var page []*entdb.Node
	if offset < totalCount {
		page = filtered[offset:end]
	}
	nextCursor := ""
	if end < totalCount {
		nextCursor = strconv.Itoa(end)
	}

	users := make([]*User, 0, len(page))
	for _, n := range page {
		users = append(users, userFromNode(n))
	}
	return users, nextCursor, totalCount, nil
}

// GetUser returns a single user by ID.
func (s *AdminService) GetUser(ctx context.Context, actorID, userID string) (*User, error) {
	if _, err := s.requireAdmin(ctx, actorID); err != nil {
		return nil, err
	}
	node, err := s.db.GetNode(ctx, s.tenantID, actorStr(userID), typeUser, userID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	if node == nil {
		return nil, errors.New("user not found")
	}
	return userFromNode(node), nil
}

// UpdateUser patches name, role, and/or avatar_url for a user.
func (s *AdminService) UpdateUser(ctx context.Context, actorID, userID, name, role, avatarURL string) (*User, error) {
	if _, err := s.requireAdmin(ctx, actorID); err != nil {
		return nil, err
	}
	if userID == "" {
		return nil, errors.New("user_id is required")
	}

	patch := map[string]any{ufUpdatedAt: nowMs()}
	if name != "" {
		patch[ufName] = name
	}
	if role != "" {
		patch[ufRole] = strings.ToLower(role)
	}
	if avatarURL != "" {
		patch[ufAvatarURL] = avatarURL
	}

	op := entdb.Operation{Type: entdb.OpUpdateNode, TypeID: typeUser, NodeID: userID, Patch: patch}
	if _, err := s.db.ExecuteAtomic(ctx, s.tenantID, actorStr(actorID), []entdb.Operation{op}); err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}

	// Re-fetch to return the updated user.
	node, err := s.db.GetNode(ctx, s.tenantID, actorStr(userID), typeUser, userID)
	if err != nil {
		return nil, fmt.Errorf("re-fetch user: %w", err)
	}
	if node == nil {
		return nil, errors.New("user not found after update")
	}
	return userFromNode(node), nil
}

// ── Helpers ────────────────────────────────────────────────────────

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func randomToken(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func generateTempPassword() string {
	// 16-char password: upper, lower, digit, special + 12 random.
	const (
		upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lower   = "abcdefghijklmnopqrstuvwxyz"
		digits  = "0123456789"
		special = "!@#$%^&*_-+="
		all     = upper + lower + digits
	)
	b := make([]byte, 16)
	_, _ = rand.Read(b)

	chars := make([]byte, 16)
	chars[0] = upper[int(b[0])%len(upper)]
	chars[1] = lower[int(b[1])%len(lower)]
	chars[2] = digits[int(b[2])%len(digits)]
	chars[3] = special[int(b[3])%len(special)]
	for i := 4; i < 16; i++ {
		chars[i] = all[int(b[i])%len(all)]
	}

	// Fisher-Yates shuffle.
	rb := make([]byte, 16)
	_, _ = rand.Read(rb)
	for i := len(chars) - 1; i > 0; i-- {
		j := int(rb[i]) % (i + 1)
		chars[i], chars[j] = chars[j], chars[i]
	}
	return string(chars)
}
