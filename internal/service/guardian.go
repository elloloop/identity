package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/elloloop/identity/pkg/audit"
)

// ── Guardian edges ──────────────────────────────────────────────────────
//
// A guardian edge is the authorization fact that one account (the guardian)
// manages another (the child). It is stored relationally in guardian_edges
// (edge type id 102 is reserved in graphtypes.go against a later move into
// the graph, but nothing writes a graph edge today). Edges are created when
// verifiable parental consent is granted (GrantParentalConsent upserts the
// edge in the same write sequence as the consent record) and backfilled by
// migration for consents granted before the edge model existed; they are
// removed when the consent is revoked.
//
// Unlike the parental-consent record — an audit/compliance artifact that
// deliberately survives account deletion — an edge is LIVE authorization
// state: it carries users foreign keys with ON DELETE CASCADE, so it dies
// with either account it references.

// GuardianEdge is one (guardian -> child) authorization fact in the account
// graph.
type GuardianEdge struct {
	// ProjectID is the storage shard (ADR-0002): the per-request project.
	ProjectID      string
	GuardianUserID string
	ChildUserID    string
	// CreatedAtMs is the epoch-ms instant the edge was first created; an
	// idempotent re-upsert preserves it.
	CreatedAtMs int64
}

// ListManagedChildren returns the child accounts guardianUserID holds a
// guardian edge to, with each child's age band stamped via
// determinerForUser. An edge whose child account has been deleted is
// skipped (the FK cascade should already have removed it; the skip keeps a
// stale row from erroring the listing).
func (s *AuthService) ListManagedChildren(ctx context.Context, guardianUserID string) ([]*User, error) {
	if guardianUserID == "" {
		return nil, ErrUnauthenticated
	}
	repo := s.repo(ctx)
	edges, err := repo.ListChildrenOfGuardian(ctx, guardianUserID)
	if err != nil {
		return nil, fmt.Errorf("list children of guardian: %w", err)
	}
	children := make([]*User, 0, len(edges))
	for _, e := range edges {
		child, err := repo.GetUser(ctx, e.ChildUserID)
		if err != nil {
			return nil, fmt.Errorf("fetch managed child: %w", err)
		}
		if child == nil {
			continue
		}
		s.stampAgeBand(ctx, child)
		children = append(children, child)
	}
	return children, nil
}

// GetGuardians returns the guardian accounts of childUserID. The caller must
// be a project admin or hold a guardian edge to the child; any other caller
// gets the same ErrPermissionDenied whether or not the child account exists,
// so the surface discloses nothing about account existence.
func (s *AuthService) GetGuardians(ctx context.Context, callerUserID, childUserID string, callerIsAdmin bool) ([]*User, error) {
	if callerUserID == "" {
		return nil, ErrUnauthenticated
	}
	childUserID = strings.TrimSpace(childUserID)
	if childUserID == "" {
		return nil, fmt.Errorf("%w: child_user_id is required", ErrInvalidArgument)
	}
	repo := s.repo(ctx)
	if !callerIsAdmin {
		// The denial is account-agnostic: the edge lookup keys on
		// (caller, child) and does not touch the users table, so a stranger
		// probing a nonexistent child id gets the identical denial — and the
		// lookup neither confirms nor denies that the account exists.
		edge, err := repo.GetGuardianEdge(ctx, callerUserID, childUserID)
		if err != nil {
			return nil, fmt.Errorf("check guardian edge: %w", err)
		}
		if edge == nil {
			return nil, fmt.Errorf("%w: caller is not a guardian of this account", ErrPermissionDenied)
		}
	}
	edges, err := repo.ListGuardiansOfChild(ctx, childUserID)
	if err != nil {
		return nil, fmt.Errorf("list guardians of child: %w", err)
	}
	guardians := make([]*User, 0, len(edges))
	for _, e := range edges {
		guardian, err := repo.GetUser(ctx, e.GuardianUserID)
		if err != nil {
			return nil, fmt.Errorf("fetch guardian: %w", err)
		}
		if guardian == nil {
			continue
		}
		s.stampAgeBand(ctx, guardian)
		guardians = append(guardians, guardian)
	}
	return guardians, nil
}

// upsertGuardianEdge records the (consenting adult -> child) edge and audits
// it. It is idempotent, and it must run BEFORE the child's status flip to
// active: an active child always has both the consent record and the edge
// that authorizes managing it.
func (s *AuthService) upsertGuardianEdge(ctx context.Context, guardianUserID, childUserID, ip, userAgent string) error {
	if err := s.repo(ctx).UpsertGuardianEdge(ctx, &GuardianEdge{
		GuardianUserID: guardianUserID,
		ChildUserID:    childUserID,
		CreatedAtMs:    s.nowMs(),
	}); err != nil {
		return fmt.Errorf("record guardian edge: %w", err)
	}
	s.audit.Log(
		ctx, audit.EventGuardianEdgeCreated,
		audit.WithActor(guardianUserID), audit.WithTarget(childUserID),
		audit.WithIP(ip), audit.WithUserAgent(userAgent), audit.WithSuccess(true),
	)
	return nil
}
