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
// address is assigned once and never rewritten — changing the account's email
// or the project's domain later leaves an assigned address as it was.
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
// addresses nobody can use.
func (a ProjectAccountsConfig) validate() error {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(a.Domain)), ".")
	if d == "" {
		return nil
	}
	ascii, err := idna.Lookup.ToASCII(d)
	if err != nil {
		return fmt.Errorf("accounts.domain %q: %w", a.Domain, err)
	}
	if len(ascii) > 253 || !strings.Contains(ascii, ".") {
		return fmt.Errorf("accounts.domain %q: want a fully qualified domain name such as accounts.example.com", a.Domain)
	}
	return nil
}

// canonicalized returns the domain lower-cased, trimmed, without a trailing
// dot and IDN-punycoded, so every address issued on it has one spelling.
func (a ProjectAccountsConfig) canonicalized() ProjectAccountsConfig {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(a.Domain)), ".")
	if ascii, err := idna.Lookup.ToASCII(d); err == nil {
		d = ascii
	}
	return ProjectAccountsConfig{Domain: d}
}

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
// when the project issues them and u has none yet. It is called where
// accounts are created and where a session is issued, so an account created
// before the project configured a domain receives its address at its next
// sign-in.
//
// A clash with another account's address moves on to the next suffix; any
// other failure is logged and left for the next sign-in to retry. Assigning an
// address is never a reason to refuse a sign-in.
func ensureAccountAddress(ctx context.Context, repo Repository, logger *zap.Logger, u *User) {
	if u == nil || u.AccountAddress != "" || u.IsAnonymous {
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
	for attempt := 1; attempt <= maxAddressAttempts; attempt++ {
		addr := fitAddressLocalPart(local, attempt) + "@" + scope.Accounts.Domain
		err := repo.UpdateUser(ctx, u.ID, map[string]any{"account_address": addr})
		if err == nil {
			u.AccountAddress = addr
			return
		}
		if !errors.Is(err, ErrAlreadyExists) {
			logger.Warn("account_address_assign_failed", zap.String("user_id", u.ID), zap.Error(err))
			return
		}
	}
	logger.Warn("account_address_exhausted", zap.String("user_id", u.ID), zap.Int("attempts", maxAddressAttempts))
}
