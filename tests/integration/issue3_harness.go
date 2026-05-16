//go:build integration && !realentdb && !realpostgres

package integration

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb"

	identityconnectgen "github.com/elloloop/identity/gen/go/identity/identityconnect"
	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/passkeys"
)

const (
	issue3TypeUser           = 1
	issue3TypeWorkingGroup   = 2
	issue3TypePasswordReset  = 19
	issue3TypeAuditEvent     = 26
	issue3TypeUserInvitation = 27

	issue3EdgeMemberOf = 101

	issue3UfEmail         = "1"
	issue3UfName          = "2"
	issue3UfRole          = "3"
	issue3UfAvatarURL     = "4"
	issue3UfCreatedAt     = "5"
	issue3UfUpdatedAt     = "6"
	issue3UfPasswordHash  = "7"
	issue3UfStatus        = "11"
	issue3UfRecoveryEmail = "12"
	issue3UfInvitedBy     = "13"
	issue3UfInvitedAt     = "14"
	issue3UfQuotaBytes    = "15"
	issue3UfDeactivatedAt = "16"
	issue3UfLastLoginAt   = "17"

	issue3GfName        = "1"
	issue3GfDescription = "2"
	issue3GfCreatedBy   = "3"
	issue3GfCreatedAt   = "4"
	issue3GfUpdatedAt   = "5"

	issue3PrfTokenHash = "1"
	issue3PrfUserID    = "2"
	issue3PrfExpiresAt = "3"
	issue3PrfCreatedAt = "4"

	issue3InvTokenHash  = "1"
	issue3InvEmail      = "2"
	issue3InvUserID     = "3"
	issue3InvInvitedBy  = "4"
	issue3InvRole       = "5"
	issue3InvExpiresAt  = "6"
	issue3InvAcceptedAt = "7"
	issue3InvCreatedAt  = "8"
)

type issue3DB struct {
	repo  *MemRepo
	audit *RecordingDB

	mu     sync.Mutex
	groups map[string]*entdb.Node
	edges  []*entdb.Edge
}

func newIssue3DB(repo *MemRepo, audit *RecordingDB) *issue3DB {
	return &issue3DB{
		repo:   repo,
		audit:  audit,
		groups: make(map[string]*entdb.Node),
	}
}

func StartIssue3Server(t *testing.T) *issue3Harness {
	t.Helper()

	cfg := newIssue3TestConfig()
	cfg.PasswordResetExpirySeconds = 3600

	signingKey, err := jwt.GenerateKey("issue-3-test-kid")
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	keyRing, err := jwt.NewKeyRing([]jwt.SigningKey{signingKey})
	if err != nil {
		t.Fatalf("build key ring: %v", err)
	}

	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   cfg.PasskeyRPID,
		RPName: cfg.PasskeyRPName,
		Origin: cfg.PasskeyOrigin,
	})
	if err != nil {
		t.Fatalf("init webauthn: %v", err)
	}

	repo := NewMemRepo()
	auditDB := NewRecordingDB()
	db := newIssue3DB(repo, auditDB)
	mailer := NewRecordingMailer()

	handler, stop, err := app.New(app.Deps{
		Config:             cfg,
		Logger:             zap.NewNop(),
		KeyRing:            keyRing,
		Repo:               repo,
		DB:                 db,
		Passkeys:           pkSvc,
		TOTPKey:            []byte("01234567890123456789012345678901"),
		TOTPRecoveryPepper: []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		EmailTransport:     mailer,
	})
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	t.Cleanup(stop)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	httpClient := srv.Client()
	client := identityconnectgen.NewIdentityServiceClient(httpClient, srv.URL)

	return &issue3Harness{
		BaseURL: srv.URL,
		Client:  client,
		HTTP:    httpClient,
		Repo:    repo,
	}
}

func (d *issue3DB) GetNode(_ context.Context, _, _ string, typeID int, nodeID string) (*entdb.Node, error) {
	switch typeID {
	case issue3TypeUser:
		d.repo.mu.Lock()
		defer d.repo.mu.Unlock()
		u := d.repo.users[nodeID]
		if u == nil {
			return nil, nil
		}
		return issue3UserNode(u), nil
	case issue3TypeWorkingGroup:
		d.mu.Lock()
		defer d.mu.Unlock()
		n := d.groups[nodeID]
		if n == nil {
			return nil, nil
		}
		return issue3CloneNode(n), nil
	case issue3TypeUserInvitation:
		d.repo.mu.Lock()
		defer d.repo.mu.Unlock()
		inv := d.repo.invitations[nodeID]
		if inv == nil {
			return nil, nil
		}
		return issue3InvitationNode(inv), nil
	case issue3TypePasswordReset:
		d.repo.mu.Lock()
		defer d.repo.mu.Unlock()
		reset := d.repo.passwordResets[nodeID]
		if reset == nil {
			return nil, nil
		}
		return issue3PasswordResetNode(reset), nil
	default:
		return nil, nil
	}
}

func (d *issue3DB) QueryNodes(_ context.Context, _, _ string, typeID int, filter map[string]any) ([]*entdb.Node, error) {
	switch typeID {
	case issue3TypeUser:
		d.repo.mu.Lock()
		defer d.repo.mu.Unlock()
		var out []*entdb.Node
		for _, u := range d.repo.users {
			n := issue3UserNode(u)
			if issue3MatchFilter(n.Payload, filter) {
				out = append(out, n)
			}
		}
		return out, nil
	case issue3TypeWorkingGroup:
		d.mu.Lock()
		defer d.mu.Unlock()
		var out []*entdb.Node
		for _, n := range d.groups {
			if issue3MatchFilter(n.Payload, filter) {
				out = append(out, issue3CloneNode(n))
			}
		}
		return out, nil
	case issue3TypeUserInvitation:
		d.repo.mu.Lock()
		defer d.repo.mu.Unlock()
		var out []*entdb.Node
		for _, inv := range d.repo.invitations {
			n := issue3InvitationNode(inv)
			if issue3MatchFilter(n.Payload, filter) {
				out = append(out, n)
			}
		}
		return out, nil
	default:
		return nil, nil
	}
}

func (d *issue3DB) ExecuteAtomic(ctx context.Context, tenantID, actor string, ops []entdb.Operation) (*entdb.CommitResult, error) {
	if issue3IsAuditWrite(ops) {
		return d.audit.ExecuteAtomic(ctx, tenantID, actor, ops)
	}

	var createdIDs []string
	for _, op := range ops {
		switch op.Type {
		case entdb.OpCreateNode:
			createdID, err := d.createNode(op)
			if err != nil {
				return nil, err
			}
			if createdID != "" {
				createdIDs = append(createdIDs, createdID)
			}
		case entdb.OpUpdateNode:
			if err := d.updateNode(op); err != nil {
				return nil, err
			}
		case entdb.OpDeleteNode:
			if err := d.deleteNode(op); err != nil {
				return nil, err
			}
		case entdb.OpCreateEdge:
			d.mu.Lock()
			d.edges = append(d.edges, &entdb.Edge{
				EdgeTypeID: op.EdgeTypeID,
				FromNodeID: op.FromNodeID,
				ToNodeID:   op.ToNodeID,
			})
			d.mu.Unlock()
		case entdb.OpDeleteEdge:
			d.mu.Lock()
			keep := d.edges[:0]
			for _, e := range d.edges {
				if e.EdgeTypeID == op.EdgeTypeID && e.FromNodeID == op.FromNodeID && e.ToNodeID == op.ToNodeID {
					continue
				}
				keep = append(keep, e)
			}
			d.edges = keep
			d.mu.Unlock()
		}
	}

	return &entdb.CommitResult{
		Success:        true,
		Applied:        true,
		CreatedNodeIDs: createdIDs,
	}, nil
}

func (d *issue3DB) GetEdgesFrom(_ context.Context, _, _ string, fromNodeID string, edgeTypeID int) ([]*entdb.Edge, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var out []*entdb.Edge
	for _, e := range d.edges {
		if e.EdgeTypeID == edgeTypeID && e.FromNodeID == fromNodeID {
			out = append(out, &entdb.Edge{
				EdgeTypeID: e.EdgeTypeID,
				FromNodeID: e.FromNodeID,
				ToNodeID:   e.ToNodeID,
			})
		}
	}
	return out, nil
}

func (d *issue3DB) GetEdgesTo(_ context.Context, _, _ string, toNodeID string, edgeTypeID int) ([]*entdb.Edge, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var out []*entdb.Edge
	for _, e := range d.edges {
		if e.EdgeTypeID == edgeTypeID && e.ToNodeID == toNodeID {
			out = append(out, &entdb.Edge{
				EdgeTypeID: e.EdgeTypeID,
				FromNodeID: e.FromNodeID,
				ToNodeID:   e.ToNodeID,
			})
		}
	}
	return out, nil
}

func (d *issue3DB) SearchNodes(_ context.Context, _, _ string, typeID int, query string) ([]*entdb.Node, error) {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil, nil
	}

	switch typeID {
	case issue3TypeUser:
		d.repo.mu.Lock()
		defer d.repo.mu.Unlock()
		var out []*entdb.Node
		for _, u := range d.repo.users {
			n := issue3UserNode(u)
			if issue3MatchesQuery(n.Payload, q) {
				out = append(out, n)
			}
		}
		return out, nil
	case issue3TypeWorkingGroup:
		d.mu.Lock()
		defer d.mu.Unlock()
		var out []*entdb.Node
		for _, n := range d.groups {
			if issue3MatchesQuery(n.Payload, q) {
				out = append(out, issue3CloneNode(n))
			}
		}
		return out, nil
	default:
		return nil, nil
	}
}

// RegisterUserInTenant is a no-op on the issue3 fake. The fake's
// single in-memory store has no global-registry / membership model
// to enforce.
func (d *issue3DB) RegisterUserInTenant(_ context.Context, _, _, _, _, _ string) error {
	return nil
}

func (d *issue3DB) createNode(op entdb.Operation) (string, error) {
	switch op.TypeID {
	case issue3TypeUser:
		d.repo.mu.Lock()
		defer d.repo.mu.Unlock()
		id := d.repo.nextID()
		d.repo.users[id] = &service.User{
			ID:            id,
			Email:         strings.ToLower(issue3String(op.Data[issue3UfEmail])),
			Name:          issue3String(op.Data[issue3UfName]),
			Role:          issue3String(op.Data[issue3UfRole]),
			AvatarURL:     issue3String(op.Data[issue3UfAvatarURL]),
			Status:        issue3String(op.Data[issue3UfStatus]),
			RecoveryEmail: strings.ToLower(issue3String(op.Data[issue3UfRecoveryEmail])),
			QuotaBytes:    issue3Int64(op.Data[issue3UfQuotaBytes]),
			PasswordHash:  issue3String(op.Data[issue3UfPasswordHash]),
			CreatedAt:     time.UnixMilli(issue3Int64(op.Data[issue3UfCreatedAt])),
			UpdatedAt:     time.UnixMilli(issue3Int64(op.Data[issue3UfUpdatedAt])),
			LastLoginAtMs: issue3Int64(op.Data[issue3UfLastLoginAt]),
		}
		return id, nil
	case issue3TypeUserInvitation:
		d.repo.mu.Lock()
		defer d.repo.mu.Unlock()
		id := d.repo.nextID()
		d.repo.invitations[id] = &service.InvitationRecord{
			NodeID:     id,
			TokenHash:  issue3String(op.Data[issue3InvTokenHash]),
			Email:      strings.ToLower(issue3String(op.Data[issue3InvEmail])),
			UserID:     issue3String(op.Data[issue3InvUserID]),
			InvitedBy:  issue3String(op.Data[issue3InvInvitedBy]),
			Role:       issue3String(op.Data[issue3InvRole]),
			ExpiresAt:  issue3Int64(op.Data[issue3InvExpiresAt]),
			AcceptedAt: issue3Int64(op.Data[issue3InvAcceptedAt]),
			CreatedAt:  issue3Int64(op.Data[issue3InvCreatedAt]),
		}
		return id, nil
	case issue3TypePasswordReset:
		d.repo.mu.Lock()
		defer d.repo.mu.Unlock()
		id := d.repo.nextID()
		d.repo.passwordResets[id] = &service.PasswordResetToken{
			NodeID:    id,
			TokenHash: issue3String(op.Data[issue3PrfTokenHash]),
			UserID:    issue3String(op.Data[issue3PrfUserID]),
			ExpiresAt: issue3Int64(op.Data[issue3PrfExpiresAt]),
			CreatedAt: issue3Int64(op.Data[issue3PrfCreatedAt]),
		}
		return id, nil
	case issue3TypeWorkingGroup:
		d.repo.mu.Lock()
		id := d.repo.nextID()
		d.repo.mu.Unlock()

		d.mu.Lock()
		d.groups[id] = &entdb.Node{
			NodeID: id,
			TypeID: issue3TypeWorkingGroup,
			Payload: map[string]any{
				issue3GfName:        issue3String(op.Data[issue3GfName]),
				issue3GfDescription: issue3String(op.Data[issue3GfDescription]),
				issue3GfCreatedBy:   issue3String(op.Data[issue3GfCreatedBy]),
				issue3GfCreatedAt:   issue3Int64(op.Data[issue3GfCreatedAt]),
				issue3GfUpdatedAt:   issue3Int64(op.Data[issue3GfUpdatedAt]),
			},
		}
		d.mu.Unlock()
		return id, nil
	default:
		return "", nil
	}
}

func (d *issue3DB) updateNode(op entdb.Operation) error {
	switch op.TypeID {
	case issue3TypeUser:
		d.repo.mu.Lock()
		defer d.repo.mu.Unlock()
		u := d.repo.users[op.NodeID]
		if u == nil {
			return nil
		}
		for k, v := range op.Patch {
			switch k {
			case issue3UfEmail:
				u.Email = strings.ToLower(issue3String(v))
			case issue3UfName:
				u.Name = issue3String(v)
			case issue3UfRole:
				u.Role = issue3String(v)
			case issue3UfAvatarURL:
				u.AvatarURL = issue3String(v)
			case issue3UfPasswordHash:
				u.PasswordHash = issue3String(v)
			case issue3UfStatus:
				u.Status = issue3String(v)
			case issue3UfRecoveryEmail:
				u.RecoveryEmail = strings.ToLower(issue3String(v))
			case issue3UfQuotaBytes:
				u.QuotaBytes = issue3Int64(v)
			case issue3UfUpdatedAt:
				u.UpdatedAt = time.UnixMilli(issue3Int64(v))
			case issue3UfLastLoginAt:
				u.LastLoginAtMs = issue3Int64(v)
			}
		}
	case issue3TypeUserInvitation:
		d.repo.mu.Lock()
		defer d.repo.mu.Unlock()
		inv := d.repo.invitations[op.NodeID]
		if inv == nil {
			return nil
		}
		for k, v := range op.Patch {
			switch k {
			case issue3InvAcceptedAt:
				inv.AcceptedAt = issue3Int64(v)
			}
		}
	case issue3TypeWorkingGroup:
		d.mu.Lock()
		defer d.mu.Unlock()
		n := d.groups[op.NodeID]
		if n == nil {
			return nil
		}
		for k, v := range op.Patch {
			n.Payload[k] = v
		}
	}
	return nil
}

func (d *issue3DB) deleteNode(op entdb.Operation) error {
	if op.TypeID != issue3TypeWorkingGroup {
		return nil
	}

	d.mu.Lock()
	delete(d.groups, op.NodeID)
	keep := d.edges[:0]
	for _, e := range d.edges {
		if e.FromNodeID == op.NodeID || e.ToNodeID == op.NodeID {
			continue
		}
		keep = append(keep, e)
	}
	d.edges = keep
	d.mu.Unlock()
	return nil
}

func issue3IsAuditWrite(ops []entdb.Operation) bool {
	if len(ops) == 0 {
		return false
	}
	for _, op := range ops {
		if op.Type != entdb.OpCreateNode || op.TypeID != issue3TypeAuditEvent {
			return false
		}
	}
	return true
}

func issue3UserNode(u *service.User) *entdb.Node {
	payload := map[string]any{
		issue3UfEmail:         u.Email,
		issue3UfName:          u.Name,
		issue3UfRole:          u.Role,
		issue3UfAvatarURL:     u.AvatarURL,
		issue3UfCreatedAt:     u.CreatedAt.UnixMilli(),
		issue3UfUpdatedAt:     u.UpdatedAt.UnixMilli(),
		issue3UfPasswordHash:  u.PasswordHash,
		issue3UfStatus:        u.Status,
		issue3UfRecoveryEmail: u.RecoveryEmail,
		issue3UfQuotaBytes:    u.QuotaBytes,
		issue3UfLastLoginAt:   u.LastLoginAtMs,
	}
	return &entdb.Node{NodeID: u.ID, TypeID: issue3TypeUser, Payload: payload}
}

func issue3InvitationNode(inv *service.InvitationRecord) *entdb.Node {
	return &entdb.Node{
		NodeID: inv.NodeID,
		TypeID: issue3TypeUserInvitation,
		Payload: map[string]any{
			issue3InvTokenHash:  inv.TokenHash,
			issue3InvEmail:      inv.Email,
			issue3InvUserID:     inv.UserID,
			issue3InvInvitedBy:  inv.InvitedBy,
			issue3InvRole:       inv.Role,
			issue3InvExpiresAt:  inv.ExpiresAt,
			issue3InvAcceptedAt: inv.AcceptedAt,
			issue3InvCreatedAt:  inv.CreatedAt,
		},
	}
}

func issue3PasswordResetNode(reset *service.PasswordResetToken) *entdb.Node {
	return &entdb.Node{
		NodeID: reset.NodeID,
		TypeID: issue3TypePasswordReset,
		Payload: map[string]any{
			issue3PrfTokenHash: reset.TokenHash,
			issue3PrfUserID:    reset.UserID,
			issue3PrfExpiresAt: reset.ExpiresAt,
			issue3PrfCreatedAt: reset.CreatedAt,
		},
	}
}

func issue3CloneNode(n *entdb.Node) *entdb.Node {
	if n == nil {
		return nil
	}
	return &entdb.Node{
		NodeID:  n.NodeID,
		TypeID:  n.TypeID,
		Payload: issue3CopyMap(n.Payload),
	}
}

func issue3CopyMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func issue3MatchFilter(payload map[string]any, filter map[string]any) bool {
	if filter == nil {
		return true
	}
	for k, v := range filter {
		if fmt.Sprint(payload[k]) != fmt.Sprint(v) {
			return false
		}
	}
	return true
}

func issue3MatchesQuery(payload map[string]any, q string) bool {
	for _, v := range payload {
		if s, ok := v.(string); ok && strings.Contains(strings.ToLower(s), q) {
			return true
		}
	}
	return false
}

func issue3String(v any) string {
	s, _ := v.(string)
	return s
}

func issue3Int64(v any) int64 {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int32:
		return int64(x)
	case int64:
		return x
	case uint32:
		return int64(x)
	case uint64:
		return int64(x)
	case float64:
		return int64(x)
	default:
		return 0
	}
}

var _ service.DB = (*issue3DB)(nil)
