package service

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
)

func TestAccountAddressLocalPart(t *testing.T) {
	cases := []struct {
		name string
		user User
		want string
	}{
		{"username as is", User{Username: "bob"}, "bob"},
		{"username wins over email", User{Username: "bob", Email: "bob@mail.example"}, "bob"},
		{"email keeps its provider", User{Email: "bob@mail.example"}, "bob-at-mail.example"},
		{"upper case folds", User{Email: "Bob@Mail.Example"}, "bob-at-mail.example"},
		{"plus and underscore kept", User{Email: "bob_x+tag@mail.example"}, "bob_x+tag-at-mail.example"},
		{"other characters become hyphens", User{Email: "bob!o'k@mail.example"}, "bob-o-k-at-mail.example"},
		{"dot runs collapse", User{Username: "a..b"}, "a.b"},
		{"leading and trailing dots dropped", User{Username: ".bob."}, "bob"},
		{"no identifier", User{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, accountAddressLocalPart(&tc.user))
		})
	}
}

func TestFitAddressLocalPart(t *testing.T) {
	require.Equal(t, "bob", fitAddressLocalPart("bob", 1))
	require.Equal(t, "bob-2", fitAddressLocalPart("bob", 2))
	require.Equal(t, "bob-20", fitAddressLocalPart("bob", 20))

	long := strings.Repeat("a", 70) + "-at-mail.example"
	got := fitAddressLocalPart(long, 1)
	require.Len(t, got, maxAddressLocalPart)
	require.Equal(t, got, fitAddressLocalPart(long, 1), "deterministic")
	require.NotEqual(t, got, fitAddressLocalPart(strings.Repeat("a", 70)+"-at-other.example", 1),
		"two long identifiers sharing a prefix differ")
	require.LessOrEqual(t, len(fitAddressLocalPart(long, 17)), maxAddressLocalPart)
	require.True(t, strings.HasSuffix(fitAddressLocalPart(long, 17), "-17"))

	// Exactly at the limit is kept whole.
	exact := strings.Repeat("b", maxAddressLocalPart)
	require.Equal(t, exact, fitAddressLocalPart(exact, 1))

	// A cut that lands on a dot never leaves "..": the dot is trimmed.
	dotted := strings.Repeat("c", 54) + "." + strings.Repeat("d", 20)
	require.NotContains(t, fitAddressLocalPart(dotted, 1), ".-")
}

func TestProjectAccountsConfig(t *testing.T) {
	cfg, err := ParseProjectConfig(`{"accounts":{"domain":" Accounts.Example.COM. "}}`)
	require.NoError(t, err)
	require.Equal(t, "accounts.example.com", cfg.Accounts.Domain)

	cfg, err = ParseProjectConfig(`{"accounts":{"domain":"bücher.example"}}`)
	require.NoError(t, err)
	require.Equal(t, "xn--bcher-kva.example", cfg.Accounts.Domain)

	cfg, err = ParseProjectConfig(`{}`)
	require.NoError(t, err)
	require.Empty(t, cfg.Accounts.Domain)

	for _, bad := range []string{"localhost", "-bad-.example", "a b.example"} {
		_, err := ParseProjectConfig(`{"accounts":{"domain":"` + bad + `"}}`)
		require.Error(t, err, bad)
	}

	def, err := NewDefaultProjectAccounts(&config.Config{DefaultEmailDomain: "Accounts.Example.com"})
	require.NoError(t, err)
	require.Equal(t, "accounts.example.com", def.Domain)
	_, err = NewDefaultProjectAccounts(&config.Config{DefaultEmailDomain: "nodot"})
	require.Error(t, err)
}

func accountsScope(t *testing.T, domain string) context.Context {
	t.Helper()
	cfg, err := ParseProjectConfig(`{"access":{"mode":"open"},"accounts":{"domain":"` + domain + `"}}`)
	require.NoError(t, err)
	return WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: "project-a", Access: cfg.Access, Accounts: cfg.Accounts,
	})
}

func TestAccountAddress_IssuedAtSignup(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	ctx := accountsScope(t, "accounts.example.com")

	_, err := svc.PasswordSignup(ctx, "bob@mail.example.com", accessTestPassword, "Bob", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)
	u, err := repo.FindUserByEmail(ctx, "bob@mail.example.com")
	require.NoError(t, err)
	require.Equal(t, "bob-at-mail.example.com@accounts.example.com", u.AccountAddress)
}

func TestAccountAddress_NoneWithoutDomain(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	ctx := accessScope(t, `{"access":{"mode":"open"}}`)

	_, err := svc.PasswordSignup(ctx, "bob@mail.example.com", accessTestPassword, "Bob", "", 0, "", EmailLinkParams{})
	require.NoError(t, err)
	u, err := repo.FindUserByEmail(ctx, "bob@mail.example.com")
	require.NoError(t, err)
	require.Empty(t, u.AccountAddress)
}

func TestAccountAddress_BackfilledAtNextSignIn(t *testing.T) {
	svc, repo, _ := newAuthSvcWithMailer(t)
	existing := seedUser(repo, "early@mail.example.com", hashPW(t, accessTestPassword), "active")
	require.Empty(t, existing.AccountAddress)

	ctx := accountsScope(t, "accounts.example.com")
	_, err := svc.PasswordLogin(ctx, "early@mail.example.com", accessTestPassword, "1.2.3.4", "agent")
	require.NoError(t, err)
	u, err := repo.GetUser(ctx, existing.ID)
	require.NoError(t, err)
	require.Equal(t, "early-at-mail.example.com@accounts.example.com", u.AccountAddress)

	// Never rewritten: a later sign-in under another domain keeps it.
	other := accountsScope(t, "elsewhere.example.com")
	_, err = svc.PasswordLogin(other, "early@mail.example.com", accessTestPassword, "1.2.3.4", "agent")
	require.NoError(t, err)
	u, err = repo.GetUser(ctx, existing.ID)
	require.NoError(t, err)
	require.Equal(t, "early-at-mail.example.com@accounts.example.com", u.AccountAddress)
}

func TestAccountAddress_ClashTakesNextSuffix(t *testing.T) {
	repo := newFakeRepo()
	ctx := accountsScope(t, "accounts.example.com")
	// A username that spells the same local part as the email below.
	taken := seedUser(repo, "", "", "active")
	require.NoError(t, repo.UpdateUser(ctx, taken.ID, map[string]any{
		"account_address": "bob-at-mail.example.com@accounts.example.com",
	}))

	u := seedUser(repo, "bob@mail.example.com", "", "active")
	ensureAccountAddress(ctx, repo, zap.NewNop(), u)
	require.Equal(t, "bob-at-mail.example.com-2@accounts.example.com", u.AccountAddress)
	stored, err := repo.GetUser(ctx, u.ID)
	require.NoError(t, err)
	require.Equal(t, u.AccountAddress, stored.AccountAddress)
}

func TestAccountAddress_SkipsAnonymousAndFailuresDoNotBlock(t *testing.T) {
	repo := newFakeRepo()
	ctx := accountsScope(t, "accounts.example.com")

	anon := &User{ID: "anon", IsAnonymous: true}
	ensureAccountAddress(ctx, repo, zap.NewNop(), anon)
	require.Empty(t, anon.AccountAddress)

	u := seedUser(repo, "bob@mail.example.com", "", "active")
	repo.updateUserErr = context.DeadlineExceeded
	ensureAccountAddress(ctx, repo, zap.NewNop(), u)
	require.Empty(t, u.AccountAddress, "a store failure leaves the address for the next sign-in")
}

func TestAccountAddress_Username(t *testing.T) {
	repo := newFakeRepo()
	ctx := accountsScope(t, "accounts.example.com")
	u := seedUser(repo, "", "", "active")
	u.Username = "bob"
	ensureAccountAddress(ctx, repo, zap.NewNop(), u)
	require.Equal(t, "bob@accounts.example.com", u.AccountAddress)
}
