package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"go.uber.org/zap"
	"golang.org/x/net/idna"

	"github.com/elloloop/identity/internal/config"
)

// ProjectAccountsConfig is a project's account-domain policy, parsed from
// config_json `accounts` — or, for the env default project, assembled from
// GATEWAY_DEFAULT_EMAIL_DOMAIN.
//
// When Domain is set, every permanent account in the project is given an
// ACCOUNT ADDRESS on that domain: an address the project itself owns,
// independent of whichever external mailbox (if any) the person signed up
// with. A project that runs mail for its domain can deliver to it; one that
// does not still gets a stable, project-unique handle for each account. The
// address is assigned once. Changing the project's domain later leaves it as
// it was; it follows a change of the identifier it came from (a confirmed
// email change, a guardian's rename), so it never goes on spelling out a name
// or mailbox the person gave up. The address is a handle, not an identity:
// a released address can later be issued to another account, so relying
// parties key on the user id.
type ProjectAccountsConfig struct {
	// Domain is the domain account addresses are issued on, e.g.
	// "accounts.example.com". Empty (the default) issues none.
	Domain string `json:"domain"`
}

// NewDefaultProjectAccounts builds the env-configured default project's
// account policy, validated and canonicalized by the same rules as the
// config_json path.
func NewDefaultProjectAccounts(cfg *config.Config) (ProjectAccountsConfig, error) {
	a := ProjectAccountsConfig{Domain: cfg.DefaultEmailDomain}
	if err := a.validate(); err != nil {
		return ProjectAccountsConfig{}, err
	}
	return a.canonicalized(), nil
}

// validate rejects a domain that could never form a deliverable address, so
// a typo fails the config write (and project resolution) instead of minting
// addresses nobody can use. The rule is the one the access deny-lists use for
// a bare domain name: LDH labels of 1-63 characters, no leading or trailing
// hyphen, at least two labels.
func (a ProjectAccountsConfig) validate() error {
	if strings.TrimSpace(a.Domain) == "" {
		return nil
	}
	// An address is at most 254 characters (RFC 5321), and its local part may
	// take 64 of them plus the '@'.
	if d := canonicalAccountDomain(a.Domain); !isBareDomainName(d) || len(d) > maxAccountDomain {
		return fmt.Errorf("accounts.domain %q: want a fully qualified domain name such as accounts.example.com", a.Domain)
	}
	return nil
}

// canonicalized returns the domain in the one spelling every address issued
// on it shares.
func (a ProjectAccountsConfig) canonicalized() ProjectAccountsConfig {
	return ProjectAccountsConfig{Domain: canonicalAccountDomain(a.Domain)}
}

// canonicalAccountDomain lower-cases and trims a domain, drops a trailing
// dot and punycodes IDN labels. Unlike canonicalizeDomain it folds no
// provider aliases: this is the project's own domain, not one to match a
// login address against.
func canonicalAccountDomain(domain string) string {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if ascii, err := idna.Lookup.ToASCII(d); err == nil {
		d = ascii
	}
	return d
}

// maxAccountDomain bounds the account domain so that every address issued on
// it fits RFC 5321's 254-character path: 254 - 64 (local part) - 1 ('@').
const maxAccountDomain = 189

// maxAddressLocalPart is RFC 5321's limit on the part of an address before
// the '@'.
const maxAddressLocalPart = 64

// maxAddressAttempts bounds the clash-resolution walk: the plain local part,
// then -2 … -maxAddressAttempts.
const maxAddressAttempts = 20

// accountAddressLocalPart derives the local part of an account's address
// from the identifier the account signed up with:
//
//   - a username is used as it is ("bob" → "bob"), so a username account's
//     address is exactly <username>@<domain>;
//   - an email address keeps its whole spelling, with the '@' written as
//     "-at-" ("bob@mail.example" → "bob-at-mail.example"), so two people
//     with the same name at different providers get different addresses,
//     and a native <username>@<domain> address stays free for the person to
//     claim later. An email on the account domain is no exception: the plain
//     namespace is the usernames'.
//
// Every character outside a-z, 0-9, '.', '_' and '-' becomes '-' — '+'
// included, since mail systems that use subaddressing would deliver
// "bob+news-at-…" to "bob" — runs
// of '.' collapse to one, and leading or trailing '.' are dropped, so the
// result is always a valid dot-atom. An empty result means the account has no
// identifier to derive from (an anonymous account), and gets no address.
func accountAddressLocalPart(u *User) string {
	var src string
	switch {
	case u.Username != "":
		src = u.Username
	case u.Email != "":
		// Always the -at- form, even for an email on the account domain:
		// usernames own the plain namespace, so a username and an email can
		// never claim the same address, whichever comes first. The split is
		// at the last '@', as the canonicalizer splits.
		at := strings.LastIndexByte(u.Email, '@')
		src = u.Email[:at] + addressSeparator + u.Email[at+1:]
	default:
		return ""
	}
	var b strings.Builder
	for _, r := range strings.ToLower(src) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		case r == '.':
			if s := b.String(); s != "" && !strings.HasSuffix(s, ".") {
				b.WriteByte('.')
			}
		default:
			b.WriteByte('-')
		}
	}
	return strings.TrimRight(b.String(), ".")
}

// fitAddressLocalPart returns local with the attempt's clash suffix ("" for
// the first attempt, "-2", "-3", … after), shortened when needed so the whole
// local part fits maxAddressLocalPart. A shortened local part keeps its first
// characters and ends in eight hex digits of the full local part's SHA-256,
// so two long identifiers that share a prefix still get different addresses,
// and the same identifier always gets the same one.
func fitAddressLocalPart(local string, attempt int) string {
	suffix := ""
	if attempt > 1 {
		suffix = "-" + strconv.Itoa(attempt)
	}
	if len(local)+len(suffix) <= maxAddressLocalPart {
		return local + suffix
	}
	sum := sha256.Sum256([]byte(local))
	tag := "-" + hex.EncodeToString(sum[:4])
	keep := maxAddressLocalPart - len(tag) - len(suffix)
	head := strings.TrimRight(local[:keep], ".")
	return head + tag + suffix
}

// ensureAccountAddress gives u an account address on the project's domain
// when the project issues them and u has none yet. It runs where accounts are
// created and where sessions are issued, so an account created before the
// project configured a domain receives its address at its next sign-in.
//
// The write is a compare-and-set on the empty address, so it never replaces
// an address the account already holds. A clash with another account moves
// on to the next suffix; if all of them are taken, a final suffix derived
// from the account's id, which no other account can derive, ends the walk.
// Any other failure is logged and left for the next sign-in to retry:
// assigning an address is never a reason to refuse a sign-in.
func ensureAccountAddress(ctx context.Context, repo Repository, logger *zap.Logger, u *User) {
	if u == nil || u.ID == "" || u.AccountAddress != "" {
		return
	}
	scope := ProjectScopeFromContext(ctx)
	local := addressableLocalPart(scope, u)
	if local == "" {
		return
	}
	idForm := idFormLocalPart(u, local)
	candidates := make([]string, 0, maxAddressAttempts+1)
	// A local part that is a role name, or a legacy username that spells
	// another person's email-derived address, never takes its plain form or
	// a -N neighbour: it goes straight to the id form, which no other account
	// can derive.
	if !plainFormUnsafe(u, local) {
		for attempt := 1; attempt <= maxAddressAttempts; attempt++ {
			candidates = append(candidates, fitAddressLocalPart(local, attempt))
		}
	}
	candidates = append(candidates, idForm)
	for _, candidate := range candidates {
		held, err := repo.AssignAccountAddress(ctx, u.ID, candidate+"@"+scope.Accounts.Domain)
		if err == nil {
			u.AccountAddress = held
			if held == candidate+"@"+scope.Accounts.Domain {
				logger.Info("account_address_assigned", zap.String("project_id", scope.ProjectID), zap.String("user_id", u.ID))
			}
			return
		}
		if !errors.Is(err, ErrAlreadyExists) {
			logger.Warn("account_address_assign_failed", zap.String("project_id", scope.ProjectID), zap.String("user_id", u.ID), zap.Error(err))
			return
		}
	}
	logger.Warn("account_address_exhausted", zap.String("project_id", scope.ProjectID), zap.String("user_id", u.ID))
}

// addressableLocalPart returns the local part u's address would take in
// scope, or "" when u gets no address there: the project issues none, the
// account is anonymous, or the address would spell an email nobody has yet
// proven they own. An address that spells an email is issued only once that
// email is verified, so an unverified sign-up never puts someone else's
// mailbox name on the project's domain.
func addressableLocalPart(scope *ProjectScope, u *User) string {
	if scope == nil || scope.Accounts.Domain == "" || u.IsAnonymous {
		return ""
	}
	if u.Username == "" && !u.EmailVerified {
		return ""
	}
	local := accountAddressLocalPart(u)
	// A legacy username the derivation had to change ("bob." → "bob") would
	// otherwise take another username's address; plainFormUnsafe sends it to
	// the id form, and one that derives to nothing still gets that form.
	if u.Username != "" && local == "" {
		return unnamedLocalPart
	}
	return local
}

// unnamedLocalPart stands in for a legacy username that derives to nothing
// (one made only of dots); plainFormUnsafe sends it to the id form.
const unnamedLocalPart = "user"

// addressSeparator is how an email account's local part spells the '@' of
// its email. New usernames may not contain it (validateUsernameFormat), which
// keeps username addresses and email addresses apart.
const addressSeparator = "-at-"

// reservedLocalParts are the local parts that speak for a domain itself: the
// RFC 2142 role mailboxes, the addresses certificate authorities accept for
// domain validation, and common system names. No account is issued them, so
// no ordinary account receives mail meant for the domain's operators.
var reservedLocalParts = map[string]bool{
	"abuse": true, "admin": true, "administrator": true, "ftp": true,
	"hostmaster": true, "info": true, "mailer-daemon": true, "marketing": true,
	"news": true, "noc": true, "no-reply": true, "noreply": true,
	"postmaster": true, "root": true, "sales": true, "security": true,
	"ssl-admin": true, "support": true, "usenet": true, "uucp": true,
	"webmaster": true, "www": true,
}

// plainFormUnsafe reports whether local must not be issued as it stands: it
// is a reserved role name, or it comes from a username (one stored before
// today's username rules) that contains the email separator and so could
// take an address another person's email derives to.
func plainFormUnsafe(u *User, local string) bool {
	if reservedLocalParts[local] {
		return true
	}
	if u.Username == "" {
		return false
	}
	return strings.Contains(local, addressSeparator) || local != u.Username
}

// idFormLocalPart is the last-resort local part: local tagged with a hash of
// the account's id.
func idFormLocalPart(u *User, local string) string {
	sum := sha256.Sum256([]byte(u.ID))
	return fitAddressLocalPart(local+"-"+hex.EncodeToString(sum[:4]), 1)
}

// predictedAccountAddress is the address a new account like u is issued when
// nothing else holds it. The duplicate-signup decoy carries it, so a decoy
// and a genuine new account return the same fields.
func predictedAccountAddress(ctx context.Context, u *User) string {
	scope := ProjectScopeFromContext(ctx)
	local := addressableLocalPart(scope, u)
	if local == "" {
		return ""
	}
	if plainFormUnsafe(u, local) {
		return idFormLocalPart(u, local) + "@" + scope.Accounts.Domain
	}
	return fitAddressLocalPart(local, 1) + "@" + scope.Accounts.Domain
}

// ReissueAddressAfterEmailChange is the one rule for every path that changes
// an account's email (a confirmed self-service change, a SCIM write): an
// email account's address follows its email; a username account's address
// does not, because it came from the username.
func ReissueAddressAfterEmailChange(ctx context.Context, repo Repository, logger *zap.Logger, u *User) {
	if u == nil || u.Username != "" {
		return
	}
	reissueAccountAddress(ctx, repo, logger, u)
}

// reissueAccountAddress re-derives an account's address after the identifier
// it came from changed: a confirmed email change for an email account, a
// rename for a username account. An address that kept spelling the old
// identifier would go on showing it (often a real name, or a mailbox the
// person gave up) to everyone the account is visible to. Callers pass only
// accounts whose address came from the identifier that changed: a username
// account's address does not follow its email.
//
// A project that no longer issues addresses keeps the one it issued. The
// release and the new assignment are two writes; if the second fails the
// account is left without an address until its next sign-in issues one.
func reissueAccountAddress(ctx context.Context, repo Repository, logger *zap.Logger, u *User) {
	if u == nil || u.AccountAddress == "" {
		return
	}
	if scope := ProjectScopeFromContext(ctx); scope == nil || scope.Accounts.Domain == "" {
		return
	}
	if err := repo.UpdateUser(ctx, u.ID, map[string]any{"account_address": ""}); err != nil {
		logger.Warn("account_address_release_failed", zap.String("user_id", u.ID), zap.Error(err))
		return
	}
	u.AccountAddress = ""
	ensureAccountAddress(ctx, repo, logger, u)
}
