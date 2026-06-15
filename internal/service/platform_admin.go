package service

import "context"

// This file defines the platform-admin entity and its store interface. A
// PlatformAdmin is a control-plane OPERATOR account: the human(s) who own a
// whole deployment and call the Admin* RPCs. It is platform-global (not
// project- or tenant-scoped), backed by the platform_admins table from
// migration 0013, and exists only on the postgres control-plane driver.

// PlatformAdmin status — an active operator may sign in; a suspended one is
// retained for audit but cannot.
const (
	PlatformAdminStatusActive    = "active"
	PlatformAdminStatusSuspended = "suspended"
)

// PlatformAdmin is a control-plane operator account. Email is unique
// (case-insensitive); only PasswordHash — never a raw password — is stored.
type PlatformAdmin struct {
	ID            string
	Email         string
	PasswordHash  string
	TOTPRequired  bool
	Status        string
	CreatedAtMs   int64
	LastLoginAtMs int64
}

// PlatformAdminStore persists PlatformAdmins. It exists only on the postgres
// control-plane driver; the memory driver has no platform_admins table, so the
// admin service is constructed without it and the bootstrap RPC returns
// Unimplemented.
type PlatformAdminStore interface {
	// CreateFirstPlatformAdmin inserts a the first platform admin ATOMICALLY
	// and ONLY while the table is empty. It is the storage primitive behind
	// the zero-config bootstrap: the emptiness check and the insert happen in
	// one serialized transaction so two concurrent bootstraps create exactly
	// one admin.
	//
	// It returns (created=true, nil) when this call inserted the admin, and
	// (created=false, nil) when an admin already existed (the table was not
	// empty) — the bootstrap is then permanently closed. A blank id is
	// generated and written back to a.ID on success. Any other failure (e.g.
	// a duplicate-email race) is returned as an error.
	CreateFirstPlatformAdmin(ctx context.Context, a *PlatformAdmin) (created bool, err error)

	// CountPlatformAdmins returns the number of platform admins. It backs the
	// store conformance assertions; the bootstrap itself relies on the atomic
	// CreateFirstPlatformAdmin, not a read-then-write.
	CountPlatformAdmins(ctx context.Context) (int, error)
}
