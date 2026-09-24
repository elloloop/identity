package service

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

// MaxDirectoryLookupEmails bounds one LookupUsers batch. A consumer resolving
// a larger roster pages through it; the bound keeps one call to one indexed
// query of bounded size.
const MaxDirectoryLookupEmails = 100

// directoryAuditActorPrefix prefixes the credential id recorded as the actor
// of a directory lookup: the caller is a machine credential, not a user.
const directoryAuditActorPrefix = "credential:"

// Reasons recorded on a refused directory-credential presentation.
const (
	directoryRefusedSecretMismatch = "secret_mismatch"
	directoryRefusedWrongKind      = "wrong_kind"
	directoryRefusedRevoked        = "revoked"
)

// DirectoryCredentialStore is the read side of the control-plane credential
// registry the directory lookup authenticates against. The postgres
// ProjectStore satisfies it; drivers without a control plane have no
// credentials, and the app wires no DirectoryService for them.
type DirectoryCredentialStore interface {
	// ProjectCredentialByPublicID returns the credential whose public id is
	// publicID — revoked or not, with Revoked set accordingly — when its
	// project is ACTIVE. It returns (nil, nil) when no credential has that
	// public id or its project is suspended; only an infrastructure failure
	// is an error.
	ProjectCredentialByPublicID(ctx context.Context, publicID string) (*AdminProjectCredential, error)
}

// DirectoryUser is the minimal profile a directory lookup discloses: enough to
// address and render a colleague, nothing about how they sign in.
type DirectoryUser struct {
	ID        string
	Email     string
	Name      string
	AvatarURL string
}

// DirectoryService answers read-only directory lookups for services. Its
// caller is a directory_reader project credential, not a user: the credential
// is the whole authorization, it is bound to exactly one project, and the
// only thing it can do is resolve email addresses to active accounts in that
// project. It has no write path at all.
type DirectoryService struct {
	credentials DirectoryCredentialStore
	users       Repository
	audit       *audit.Logger
}

// NewDirectoryService wires the lookup over the control-plane credential
// store and the boot-default user repository, which every lookup rebinds to
// the credential's project. A nil auditLog defaults to a no-op logger.
func NewDirectoryService(credentials DirectoryCredentialStore, users Repository, auditLog *audit.Logger) *DirectoryService {
	if auditLog == nil {
		auditLog = audit.NewLogger(nil, "", zap.NewNop())
	}
	return &DirectoryService{credentials: credentials, users: users, audit: auditLog}
}

// LookupUsers resolves emails to the ACTIVE accounts they name in the project
// presentedKey belongs to, in request order. Addresses match exactly,
// ignoring case; an address naming no active account is simply absent.
//
// The request's own project scope (Host, X-Project-Key) is ignored: the
// credential selects the project, so it can never read another project's
// users, whichever auth-domain it is presented against.
func (s *DirectoryService) LookupUsers(ctx context.Context, presentedKey string, emails []string) ([]DirectoryUser, error) {
	cred, err := s.authenticate(ctx, presentedKey)
	if err != nil {
		return nil, err
	}
	ctx = WithProjectScope(ctx, &ProjectScope{ProjectID: cred.ProjectID})

	wanted, err := directoryLookupEmails(emails)
	if err != nil {
		return nil, err
	}
	found, err := ProjectBoundRepository(s.users, cred.ProjectID).FindUsersByEmails(ctx, wanted)
	if err != nil {
		return nil, err
	}
	out := activeDirectoryUsersInOrder(wanted, found)

	s.audit.Log(ctx, audit.EventDirectoryLookup,
		audit.WithActor(directoryAuditActorPrefix+cred.ID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{
			"requested": len(wanted),
			"matched":   len(out),
		}),
	)
	return out, nil
}

// authenticate resolves presentedKey ("<public id>.<secret>") to an active
// directory_reader credential. Every refusal is the same ErrUnauthenticated,
// so a caller learns nothing about which part was wrong; a refusal against a
// credential that exists is audited under its project with the reason.
func (s *DirectoryService) authenticate(ctx context.Context, presentedKey string) (*AdminProjectCredential, error) {
	refused := fmt.Errorf("%w: invalid directory key", ErrUnauthenticated)
	publicID, secret, ok := strings.Cut(presentedKey, rawKeySeparator)
	if !ok || publicID == "" || secret == "" {
		return nil, refused
	}
	cred, err := s.credentials.ProjectCredentialByPublicID(ctx, publicID)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, refused
	}

	reason := ""
	switch {
	case subtle.ConstantTimeCompare([]byte(sha256Hex(secret)), []byte(cred.SecretHash)) != 1:
		reason = directoryRefusedSecretMismatch
	case cred.Kind != CredentialKindDirectoryReader:
		reason = directoryRefusedWrongKind
	case cred.Revoked:
		reason = directoryRefusedRevoked
	}
	if reason != "" {
		s.audit.Log(WithProjectScope(ctx, &ProjectScope{ProjectID: cred.ProjectID}), audit.EventDirectoryLookup,
			audit.WithActor(directoryAuditActorPrefix+cred.ID),
			audit.WithSuccess(false),
			audit.WithDetails(map[string]any{"reason": reason}),
		)
		return nil, refused
	}
	return cred, nil
}

// directoryLookupEmails validates a lookup batch and returns its addresses
// trimmed and de-duplicated (ignoring case), first occurrence first.
func directoryLookupEmails(emails []string) ([]string, error) {
	if len(emails) == 0 {
		return nil, fmt.Errorf("%w: at least one email is required", ErrInvalidArgument)
	}
	if len(emails) > MaxDirectoryLookupEmails {
		return nil, fmt.Errorf("%w: at most %d emails per lookup, got %d",
			ErrInvalidArgument, MaxDirectoryLookupEmails, len(emails))
	}
	seen := make(map[string]bool, len(emails))
	out := make([]string, 0, len(emails))
	for _, e := range emails {
		e = strings.TrimSpace(e)
		if e == "" {
			return nil, fmt.Errorf("%w: empty email in lookup", ErrInvalidArgument)
		}
		key := strings.ToLower(e)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, e)
	}
	return out, nil
}

// activeDirectoryUsersInOrder keeps the active accounts among found and orders
// them by the address that requested them.
func activeDirectoryUsersInOrder(wanted []string, found []*User) []DirectoryUser {
	byEmail := make(map[string]*User, len(found))
	for _, u := range found {
		if isActiveDirectoryAccount(u) {
			byEmail[strings.ToLower(u.Email)] = u
		}
	}
	out := make([]DirectoryUser, 0, len(byEmail))
	for _, e := range wanted {
		u, ok := byEmail[strings.ToLower(e)]
		if !ok {
			continue
		}
		out = append(out, DirectoryUser{ID: u.ID, Email: u.Email, Name: u.Name, AvatarURL: u.AvatarURL})
	}
	return out
}

// isActiveDirectoryAccount reports whether u is a live, credentialed member of
// the project. A blank status is a legacy active row, as on the login path.
func isActiveDirectoryAccount(u *User) bool {
	if u == nil || u.IsAnonymous || u.Email == "" {
		return false
	}
	status := strings.ToLower(u.Status)
	return status == "" || status == StatusActive
}
