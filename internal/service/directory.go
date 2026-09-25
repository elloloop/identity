package service

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

// MaxDirectoryLookupEmails bounds one LookupUsers batch. More addresses take
// more calls; the bound keeps one call to one indexed query of bounded size.
const MaxDirectoryLookupEmails = 100

// MaxDirectoryLookupEmailLength bounds one address in a lookup batch, in
// bytes: a 64-octet local part, "@" and a 255-octet domain, the most RFC 5321
// allows each part.
const MaxDirectoryLookupEmailLength = 320

// directoryAuditActorPrefix prefixes the credential id recorded as the actor
// of a directory lookup: the caller is a machine credential, not a user.
const directoryAuditActorPrefix = "credential:"

// Reasons recorded on a refused directory-credential presentation.
const (
	directoryRefusedSecretMismatch = "secret_mismatch"
	directoryRefusedRevoked        = "revoked"
)

// DirectoryCredentialStore is the read side of the control-plane credential
// registry the directory lookup authenticates against. The postgres
// ProjectStore satisfies it; drivers without a control plane have no
// credentials, and the app wires no DirectoryService for them.
type DirectoryCredentialStore interface {
	// CredentialByPublicIDInActiveProject returns the credential whose public
	// id is publicID — revoked or not, with Revoked set accordingly — when
	// its project is ACTIVE. It returns (nil, nil) when no credential has
	// that public id or its project is suspended; only an infrastructure
	// failure is an error.
	CredentialByPublicIDInActiveProject(ctx context.Context, publicID string) (*AdminProjectCredential, error)
}

// DirectoryUser is the minimal profile a directory lookup discloses: the
// account's id, address, display name and avatar, nothing about how it signs
// in.
type DirectoryUser struct {
	ID        string
	Email     string
	Name      string
	AvatarURL string
	// EmailVerified reports whether the account's owner proved the address.
	// Always true when the deployment requires verified email, since an
	// unverified account is then not returned at all.
	EmailVerified bool
	// RequestedEmail is the requested address (trimmed, otherwise as sent)
	// that found the account — the first of them when several canonicalize
	// to it. Email is the address on file, which can differ from it in case,
	// a "+tag" or Gmail dots, so callers pair results with requests by this.
	RequestedEmail string
}

// directoryAddress is one requested address: as sent (trimmed), and in the
// canonical form it is looked up by.
type directoryAddress struct {
	requested string
	canonical string
}

// DirectoryService answers read-only directory lookups for services. Its
// caller is a directory_reader project credential, not a user: the credential
// is the whole authorization, it is bound to exactly one project, and the
// only thing it can do is resolve email addresses to active accounts in that
// project. It has no write path at all.
type DirectoryService struct {
	credentials DirectoryCredentialStore
	users       Repository
	// requireVerifiedEmail is GATEWAY_AUTH_REQUIRE_VERIFIED_EMAIL. When set,
	// an account whose owner has not proven its address is not returned:
	// without that, whoever signed up with an address first would be
	// returned as its owner.
	requireVerifiedEmail bool
	audit                *audit.Logger
}

// NewDirectoryService wires the lookup over the control-plane credential
// store and the boot-default user repository, which every lookup rebinds to
// the credential's project. A nil auditLog defaults to a no-op logger.
func NewDirectoryService(credentials DirectoryCredentialStore, users Repository, requireVerifiedEmail bool, auditLog *audit.Logger) *DirectoryService {
	if auditLog == nil {
		auditLog = audit.NewLogger(nil, "", zap.NewNop())
	}
	return &DirectoryService{credentials: credentials, users: users, requireVerifiedEmail: requireVerifiedEmail, audit: auditLog}
}

// LookupUsers resolves emails to the ACTIVE accounts they name in the project
// presentedKey belongs to, in request order. Each address is canonicalized
// as sign-in canonicalizes the address it is given (CanonicalizeEmail), so
// the lookup finds exactly the account sign-in with that address would; an
// address naming no active account — or, when verified email is required,
// only an unverified one — is simply absent.
//
// The request's own project scope (Host, X-Project-Key) is ignored: the
// credential selects the project, so it can never read another project's
// users, whichever auth-domain it is presented against.
func (s *DirectoryService) LookupUsers(ctx context.Context, presentedKey string, emails []string) ([]DirectoryUser, error) {
	publicID, secret, err := splitDirectoryKey(presentedKey)
	if err != nil {
		return nil, err
	}
	// The batch is checked before the credential is read, so a malformed
	// request costs no control-plane query. Its bounds are public, so a
	// caller without a valid key learns nothing from them.
	wanted, err := directoryLookupEmails(emails)
	if err != nil {
		return nil, err
	}
	cred, err := s.authenticate(ctx, publicID, secret)
	if err != nil {
		return nil, err
	}
	ctx = WithProjectScope(ctx, &ProjectScope{ProjectID: cred.ProjectID})

	canonical := make([]string, len(wanted))
	for i, a := range wanted {
		canonical[i] = a.canonical
	}
	found, err := s.users.WithProject(cred.ProjectID).FindUsersByEmails(ctx, canonical)
	if err != nil {
		return nil, err
	}
	out := s.directoryUsersInOrder(wanted, found)

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

// errInvalidDirectoryKey is every refusal of a presented directory key — one
// not shaped "<public id>.<secret>", an unknown public id, another kind's
// credential, a wrong secret, a revoked credential or a suspended project —
// so a caller learns nothing about which part was wrong.
var errInvalidDirectoryKey = fmt.Errorf("%w: invalid directory key", ErrUnauthenticated)

// splitDirectoryKey splits a presented key into its public id and secret,
// refusing one that is not shaped "<public id>.<secret>" before anything is
// read.
func splitDirectoryKey(presentedKey string) (publicID, secret string, err error) {
	publicID, secret, ok := strings.Cut(presentedKey, rawKeySeparator)
	if !ok || publicID == "" || secret == "" {
		return "", "", errInvalidDirectoryKey
	}
	return publicID, secret, nil
}

// authenticate resolves a split directory key (splitDirectoryKey) to an
// active directory_reader credential; every refusal is errInvalidDirectoryKey.
// A refusal against a directory_reader credential that exists is audited
// under its project with the reason; any other kind's public id is public by
// design (a publishable key ships in clients), so presenting one records
// nothing.
func (s *DirectoryService) authenticate(ctx context.Context, publicID, secret string) (*AdminProjectCredential, error) {
	// Hashed before the read, so a public id that names no credential costs
	// the same hash as one that does and the refusal's timing does not tell
	// them apart.
	presentedHash := sha256Hex(secret)
	cred, err := s.credentials.CredentialByPublicIDInActiveProject(ctx, publicID)
	if err != nil {
		return nil, err
	}
	if cred == nil || cred.Kind != CredentialKindDirectoryReader {
		return nil, errInvalidDirectoryKey
	}

	reason := ""
	switch {
	case subtle.ConstantTimeCompare([]byte(presentedHash), []byte(cred.SecretHash)) != 1:
		reason = directoryRefusedSecretMismatch
	case cred.Revoked:
		reason = directoryRefusedRevoked
	}
	if reason == "" {
		return cred, nil
	}
	s.audit.Log(WithProjectScope(ctx, &ProjectScope{ProjectID: cred.ProjectID}), audit.EventDirectoryLookup,
		audit.WithActor(directoryAuditActorPrefix+cred.ID),
		audit.WithSuccess(false),
		audit.WithDetails(map[string]any{"reason": reason}),
	)
	return nil, errInvalidDirectoryKey
}

// directoryLookupEmails validates a lookup batch and returns its addresses
// de-duplicated by canonical form, first occurrence first.
func directoryLookupEmails(emails []string) ([]directoryAddress, error) {
	if len(emails) == 0 {
		return nil, fmt.Errorf("%w: at least one email is required", ErrInvalidArgument)
	}
	if len(emails) > MaxDirectoryLookupEmails {
		return nil, fmt.Errorf("%w: at most %d emails per lookup, got %d",
			ErrInvalidArgument, MaxDirectoryLookupEmails, len(emails))
	}
	seen := make(map[string]bool, len(emails))
	out := make([]directoryAddress, 0, len(emails))
	for _, e := range emails {
		e = strings.TrimSpace(e)
		if e == "" {
			return nil, fmt.Errorf("%w: empty email in lookup", ErrInvalidArgument)
		}
		if len(e) > MaxDirectoryLookupEmailLength {
			return nil, fmt.Errorf("%w: an email in the lookup is longer than %d bytes",
				ErrInvalidArgument, MaxDirectoryLookupEmailLength)
		}
		canonical := CanonicalizeEmail(e)
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		out = append(out, directoryAddress{requested: e, canonical: canonical})
	}
	return out, nil
}

// directoryUsersInOrder keeps the accounts among found a lookup may return and
// orders them by the address that requested them. It pairs them under
// FoldEmail, the rule the repository matched them by, so no account the
// repository returned for a requested address can fail to pair with it.
func (s *DirectoryService) directoryUsersInOrder(wanted []directoryAddress, found []*User) []DirectoryUser {
	byEmail := make(map[string]*User, len(found))
	for _, u := range found {
		if isActiveDirectoryAccount(u) && (u.EmailVerified || !s.requireVerifiedEmail) {
			byEmail[FoldEmail(u.Email)] = u
		}
	}
	out := make([]DirectoryUser, 0, len(byEmail))
	for _, a := range wanted {
		u, ok := byEmail[FoldEmail(a.canonical)]
		if !ok {
			continue
		}
		out = append(out, DirectoryUser{
			ID: u.ID, Email: u.Email, Name: u.Name, AvatarURL: u.AvatarURL, EmailVerified: u.EmailVerified,
			RequestedEmail: a.requested,
		})
	}
	return out
}

// isActiveDirectoryAccount reports whether u is a live, credentialed member of
// the project.
func isActiveDirectoryAccount(u *User) bool {
	return u != nil && !u.IsAnonymous && u.Email != "" && isActiveStatus(u.Status)
}
