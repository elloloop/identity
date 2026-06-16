// Package scim implements the inbound (server) side of SCIM 2.0
// (RFC 7643 schema, RFC 7644 protocol) for the /scim/v2 surface: an
// external IdP (Okta, Entra ID, Google Workspace) lifecycle-manages users
// in a project by POST/GET/PUT/PATCH/DELETE-ing the /Users resource and the
// discovery endpoints (/ServiceProviderConfig, /Schemas, /ResourceTypes).
//
// The package is deliberately transport- and storage-agnostic: it depends
// only on the Store interface (a thin slice of the host's user repository)
// so it can be unit-tested with an in-memory fake and mounted by the host
// over its own project-scoped repository. The host gates the whole surface
// behind config + a bearer token and resolves the project before calling in;
// this package never sees credentials or projects.
package scim

import (
	"context"
	"errors"
	"strings"
	"time"
)

// SchemaUser is the SCIM core User schema URN (RFC 7643 §8.7.1).
const SchemaUser = "urn:ietf:params:scim:schemas:core:2.0:User"

// SchemaListResponse, SchemaError, SchemaPatchOp, SchemaServiceProviderConfig,
// SchemaResourceType, and SchemaSchema are the SCIM message schema URNs.
const (
	SchemaListResponse          = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaError                 = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaPatchOp               = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaServiceProviderConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	SchemaResourceTypeURN       = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SchemaSchemaURN             = "urn:ietf:params:scim:schemas:core:2.0:Schema"
	resourceTypeUser            = "User"
	userResourceLocationPrefix  = "/scim/v2/Users/"
)

// User is the host's representation of a user, mapped to/from the SCIM core
// User schema by this package. It is intentionally a small value type so the
// Store contract does not leak the host's full domain model.
type User struct {
	ID         string
	ExternalID string
	UserName   string // SCIM userName — mapped to the host email
	Email      string
	GivenName  string
	FamilyName string
	Active     bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Store is the slice of the host's user repository the SCIM provider needs.
// All methods operate within whatever project/tenant scope the host bound
// before constructing the provider. Implementations MUST return ErrNotFound
// for a missing user and ErrConflict when a uniqueness constraint (userName
// or externalId) would be violated, so the provider can map them to the
// correct SCIM HTTP status (404 / 409).
type Store interface {
	CreateUser(ctx context.Context, u User) (User, error)
	GetUser(ctx context.Context, id string) (User, error)
	ReplaceUser(ctx context.Context, id string, u User) (User, error)
	// SetActive flips the account's active state. active=false maps to the
	// host's deactivation path (which also revokes sessions); active=true
	// reactivates. It returns the updated user.
	SetActive(ctx context.Context, id string, active bool) (User, error)
	DeleteUser(ctx context.Context, id string) error
	// ListUsers returns users matching filter (zero value = all), ordered
	// stably, plus the total number of matches (for SCIM totalResults).
	ListUsers(ctx context.Context, filter ListFilter) (users []User, total int, err error)
}

// ListFilter narrows a ListUsers query. The provider parses the subset of
// the SCIM filter grammar enterprises actually send (userName eq, email eq,
// externalId eq) into this struct; an unsupported filter is rejected before
// it reaches the Store.
type ListFilter struct {
	UserName   string
	Email      string
	ExternalID string
	StartIndex int // 1-based (SCIM); the provider converts to a 0-based offset
	Count      int
}

// Sentinel errors a Store returns; the provider maps them to SCIM HTTP
// statuses.
var (
	ErrNotFound = errors.New("scim: resource not found")
	ErrConflict = errors.New("scim: uniqueness conflict")
)

// splitName splits a SCIM formatted/display name into given/family parts on
// the first space. SCIM clients commonly send name.givenName + name.familyName
// directly, but when only a single display string is provided this keeps the
// mapping lossless-enough for round-tripping.
func splitName(full string) (given, family string) {
	full = strings.TrimSpace(full)
	if full == "" {
		return "", ""
	}
	if i := strings.LastIndex(full, " "); i >= 0 {
		return strings.TrimSpace(full[:i]), strings.TrimSpace(full[i+1:])
	}
	return full, ""
}

// fullName joins given + family into a display name, collapsing empties.
func fullName(given, family string) string {
	return strings.TrimSpace(strings.TrimSpace(given) + " " + strings.TrimSpace(family))
}
