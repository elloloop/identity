package service

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/elloloop/identity/pkg/agegate"
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

// summarizeManagedAccount returns the SAFE projection of an account for a
// listing: identity and classification only. The full record — email,
// recovery email, phone, date of birth, login state — is reachable only
// through GetManagedChildProfile, which demands a step-up re-auth.
//
// The listings answer "who do I manage / who manages this child", a question
// a session alone may answer. Reading the account itself is a separate
// question with a higher bar, and returning the whole record here would have
// handed a stolen session every child's PII without one.
func (s *AuthService) summarizeManagedAccount(ctx context.Context, u *User) *User {
	summary := &User{
		ID:        u.ID,
		Username:  u.Username,
		Name:      u.Name,
		AvatarURL: u.AvatarURL,
		Role:      u.Role,
		Status:    u.Status,
		Market:    u.Market,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
	// Band and is_minor are the point of the listing (a parent needs to see
	// which of their children are still managed), so they are derived from
	// the real DOB — without carrying the DOB itself.
	dec := s.determinerForUser(ctx, u).Determine(u.DateOfBirthMs, s.nowFunc())
	summary.AgeBand = string(dec.Band)
	summary.IsMinor = dec.IsMinor
	return summary
}

// Paging bounds for the guardian listings. A guardian's edge set is small in
// practice, but "small in practice" is not a bound: the response is capped so
// no single call can return an unbounded number of accounts.
const (
	defaultGuardianPageSize = 50
	maxGuardianPageSize     = 200
)

// guardianPage clamps a requested page size and decodes the opaque cursor
// (an offset). A malformed cursor starts from the beginning rather than
// erroring — it is a pagination hint, not a credential.
func guardianPage(limit int32, cursor string) (size, offset int) {
	size = int(limit)
	if size <= 0 {
		size = defaultGuardianPageSize
	}
	if size > maxGuardianPageSize {
		size = maxGuardianPageSize
	}
	if cursor != "" {
		if n, err := strconv.Atoi(cursor); err == nil && n > 0 {
			offset = n
		}
	}
	return size, offset
}

// nextGuardianCursor returns the cursor for the following page, or "" when
// the page just returned was the last.
func nextGuardianCursor(offset, consumed, total int) string {
	if offset+consumed >= total {
		return ""
	}
	return strconv.Itoa(offset + consumed)
}

// hydrateManagedAccounts turns a page of edge ids into account summaries in
// ONE query. The per-edge GetUser this replaces made a listing cost 1+N round
// trips, with N attacker-influenced through account creation.
//
// Accounts that no longer exist are skipped (the FK cascade should have
// removed the edge; the skip keeps a stale row from erroring the listing),
// When dropAdults is set — the CHILD listing — accounts that have aged past
// the adult threshold are skipped too: the edge survives as consent history
// but confers nothing, and a listing that kept showing them would be the one
// place a former guardian could still read an adult's account. The GUARDIAN
// listing passes false, obviously: guardians are adults.
func (s *AuthService) hydrateManagedAccounts(ctx context.Context, ids []string, dropAdults bool) ([]*User, error) {
	if len(ids) == 0 {
		return []*User{}, nil
	}
	found, err := s.repo(ctx).GetUsersByIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("fetch managed accounts: %w", err)
	}
	byID := make(map[string]*User, len(found))
	for _, u := range found {
		byID[u.ID] = u
	}
	out := make([]*User, 0, len(ids))
	for _, id := range ids {
		u, ok := byID[id]
		if !ok {
			continue
		}
		summary := s.summarizeManagedAccount(ctx, u)
		if dropAdults && summary.AgeBand == string(agegate.BandAdult) {
			continue
		}
		out = append(out, summary)
	}
	return out, nil
}

// ListManagedChildren returns one page of the child accounts guardianUserID
// holds a guardian edge to, as SUMMARIES (see summarizeManagedAccount) rather
// than full records. It returns the page and the cursor for the next one
// ("" when the page is the last).
//
// The edge read itself is not paged: it is a single indexed lookup returning
// narrow rows, and it is the per-edge account fetch that made the listing
// expensive. Paging is applied to the accounts, which are what the response
// carries and what costs a query to hydrate.
func (s *AuthService) ListManagedChildren(
	ctx context.Context, guardianUserID string, limit int32, cursor string,
) ([]*User, string, error) {
	if guardianUserID == "" {
		return nil, "", ErrUnauthenticated
	}
	edges, err := s.repo(ctx).ListChildrenOfGuardian(ctx, guardianUserID)
	if err != nil {
		return nil, "", fmt.Errorf("list children of guardian: %w", err)
	}
	size, offset := guardianPage(limit, cursor)
	if offset >= len(edges) {
		return []*User{}, "", nil
	}
	page := edges[offset:]
	if len(page) > size {
		page = page[:size]
	}
	ids := make([]string, 0, len(page))
	for _, e := range page {
		ids = append(ids, e.ChildUserID)
	}
	children, err := s.hydrateManagedAccounts(ctx, ids, true)
	if err != nil {
		return nil, "", err
	}
	return children, nextGuardianCursor(offset, len(page), len(edges)), nil
}

// GetGuardians returns the guardian accounts of childUserID. The caller must
// be a project admin or hold a guardian edge to the child; any other caller
// gets the same ErrPermissionDenied whether or not the child account exists,
// so the surface discloses nothing about account existence.
func (s *AuthService) GetGuardians(
	ctx context.Context, callerUserID, childUserID string, callerIsAdmin bool, limit int32, cursor string,
) ([]*User, string, error) {
	if callerUserID == "" {
		return nil, "", ErrUnauthenticated
	}
	childUserID = strings.TrimSpace(childUserID)
	if childUserID == "" {
		return nil, "", fmt.Errorf("%w: child_user_id is required", ErrInvalidArgument)
	}
	repo := s.repo(ctx)
	if !callerIsAdmin {
		// The denial is account-agnostic: the edge lookup keys on
		// (caller, child) and does not touch the users table, so a stranger
		// probing a nonexistent child id gets the identical denial — and the
		// lookup neither confirms nor denies that the account exists.
		edge, err := repo.GetGuardianEdge(ctx, callerUserID, childUserID)
		if err != nil {
			return nil, "", fmt.Errorf("check guardian edge: %w", err)
		}
		if edge == nil {
			return nil, "", fmt.Errorf("%w: caller is not a guardian of this account", ErrPermissionDenied)
		}
	}
	edges, err := repo.ListGuardiansOfChild(ctx, childUserID)
	if err != nil {
		return nil, "", fmt.Errorf("list guardians of child: %w", err)
	}
	size, offset := guardianPage(limit, cursor)
	if offset >= len(edges) {
		return []*User{}, "", nil
	}
	page := edges[offset:]
	if len(page) > size {
		page = page[:size]
	}
	ids := make([]string, 0, len(page))
	for _, e := range page {
		ids = append(ids, e.GuardianUserID)
	}
	// Summaries here too: this listing hands one guardian the records of
	// their CO-guardians, who have not agreed to share contact details with
	// each other. dropAdults is false — guardians are adults by definition.
	guardians, err := s.hydrateManagedAccounts(ctx, ids, false)
	if err != nil {
		return nil, "", err
	}
	return guardians, nextGuardianCursor(offset, len(page), len(edges)), nil
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
