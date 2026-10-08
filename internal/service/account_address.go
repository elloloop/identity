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
// it was; an address derived from an email follows a confirmed change of
// that email, so it never goes on spelling out an address the person gave up.
// The address is a handle, not an identity: an address released by an email
// change can later be issued to another account, so relying parties key on
// the user id.
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
//     with the same name at different providers never collide, and a native
//     <username>@<domain> address stays free for the person to claim later.
//
// Every character outside a-z, 0-9, '.', '_', '+' and '-' becomes '-', runs
// of '.' collapse to one, and leading or trailing '.' are dropped, so the
// result is always a valid dot-atom. An empty result means the account has no
// identifier to derive from (an anonymous account), and gets no address.
func accountAddressLocalPart(u *User) string {
	var src string
	switch {
	case u.Username != "":
		src = u.Username
	case u.Email != "":
		src = strings.Replace(u.Email, "@", "-at-", 1)
	default:
		return ""
	}
	var b strings.Builder
	for _, r := range strings.ToLower(src) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '+', r == '-':
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
	if u == nil || u.ID == "" || u.AccountAddress != "" || u.IsAnonymous {
		return
	}
	scope := ProjectScopeFromContext(ctx)
	if scope == nil || scope.Accounts.Domain == "" {
		return
	}
	local := accountAddressLocalPart(u)
	if local == "" {
		return
	}
	candidates := make([]string, 0, maxAddressAttempts+1)
	for attempt := 1; attempt <= maxAddressAttempts; attempt++ {
		candidates = append(candidates, fitAddressLocalPart(local, attempt))
	}
	sum := sha256.Sum256([]byte(u.ID))
	candidates = append(candidates, fitAddressLocalPart(local+"-"+hex.EncodeToString(sum[:4]), 1))
	for _, candidate := range candidates {
		held, err := repo.AssignAccountAddress(ctx, u.ID, candidate+"@"+scope.Accounts.Domain)
		if err == nil {
			u.AccountAddress = held
			if held != "" {
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

// reissueEmailAddress re-derives the account address of an account whose
// address came from its email, after the email changed: an address that
// kept spelling out the old email would go on showing it to everyone the
// account is visible to. An address that came from a username is the
// account's own handle and stays.
//
// A project that no longer issues addresses keeps the one it issued. The
// release and the new assignment are two writes; if the second fails the
// account is left without an address until its next sign-in issues one.
func reissueEmailAddress(ctx context.Context, repo Repository, logger *zap.Logger, u *User) {
	if u == nil || u.Username != "" || u.AccountAddress == "" {
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
