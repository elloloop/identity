package memory

import (
	"context"
	"fmt"
	"sort"

	"github.com/elloloop/identity/internal/service"
)

// ── RBAC: custom roles + per-user role assignments ─────────────────────

func (r *Repo) CreateRole(_ context.Context, rec *service.RoleRecord) (string, error) {
	if rec == nil {
		return "", fmt.Errorf("memory: CreateRole: nil record")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.roles {
		if existing.Name == rec.Name {
			return "", fmt.Errorf("%w: role %q", service.ErrAlreadyExists, rec.Name)
		}
	}
	id := r.nextID()
	cp := *rec
	cp.NodeID = id
	cp.Permissions = append([]string(nil), rec.Permissions...)
	r.roles[id] = &cp
	rec.NodeID = id
	return id, nil
}

func (r *Repo) GetRoleByName(_ context.Context, name string) (*service.RoleRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, role := range r.roles {
		if role.Name == name {
			cp := *role
			cp.Permissions = append([]string(nil), role.Permissions...)
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *Repo) ListRoles(_ context.Context) ([]*service.RoleRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*service.RoleRecord, 0, len(r.roles))
	for _, role := range r.roles {
		cp := *role
		cp.Permissions = append([]string(nil), role.Permissions...)
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (r *Repo) DeleteRole(_ context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, role := range r.roles {
		if role.Name == name {
			delete(r.roles, id)
		}
	}
	// Cascade: drop assignments pointing at the deleted role.
	for id, a := range r.roleAssignments {
		if a.RoleName == name {
			delete(r.roleAssignments, id)
		}
	}
	return nil
}

func (r *Repo) SetUserRoleAssignment(_ context.Context, userID, roleName string, atMs int64) error {
	if userID == "" {
		return fmt.Errorf("%w: user_id is required", service.ErrInvalidArgument)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.roleAssignments {
		if a.UserID == userID {
			a.RoleName = roleName
			a.CreatedAt = atMs
			return nil
		}
	}
	id := r.nextID()
	r.roleAssignments[id] = &service.RoleAssignmentRecord{
		NodeID:    id,
		UserID:    userID,
		RoleName:  roleName,
		CreatedAt: atMs,
	}
	return nil
}

func (r *Repo) GetUserRoleAssignment(_ context.Context, userID string) (*service.RoleAssignmentRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.roleAssignments {
		if a.UserID == userID {
			cp := *a
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *Repo) DeleteUserRoleAssignment(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, a := range r.roleAssignments {
		if a.UserID == userID {
			delete(r.roleAssignments, id)
		}
	}
	return nil
}
