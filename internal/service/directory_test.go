package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/graph"
	"github.com/elloloop/identity/pkg/audit"
)

// projectFakeRepos is a Repository whose WithProject binding hands out one
// fakeRepo per project, so the directory lookup's project pinning is
// observable: a lookup that read the wrong project would find the wrong rows.
type projectFakeRepos struct {
	*fakeRepo
	byProject map[string]*fakeRepo
}

func newProjectFakeRepos() *projectFakeRepos {
	return &projectFakeRepos{fakeRepo: newFakeRepo(), byProject: map[string]*fakeRepo{}}
}

func (p *projectFakeRepos) WithProject(projectID string) Repository {
	return p.project(projectID)
}

func (p *projectFakeRepos) project(projectID string) *fakeRepo {
	r, ok := p.byProject[projectID]
	if !ok {
		r = newFakeRepo()
		p.byProject[projectID] = r
	}
	return r
}

// projectAuditWriter records each audit event with the project it was written
// under, so a test can prove a lookup is audited in the credential's project.
type projectAuditWriter struct {
	mu      sync.Mutex
	entries []projectAuditEntry
}

type projectAuditEntry struct {
	project string
	event   string
	actor   string
	details map[string]any
}

func (w *projectAuditWriter) ExecuteAtomic(_ context.Context, projectID, _ string, ops []graph.Operation) (*graph.CommitResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, op := range ops {
		et, ok := op.Data["1"].(string)
		if !ok {
			continue
		}
		actor, _ := op.Data["2"].(string)
		raw, _ := op.Data["7"].(string)
		var details map[string]any
		_ = json.Unmarshal([]byte(raw), &details)
		w.entries = append(w.entries, projectAuditEntry{project: projectID, event: et, actor: actor, details: details})
	}
	return &graph.CommitResult{}, nil
}

func (w *projectAuditWriter) byEvent(event string) []projectAuditEntry {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []projectAuditEntry
	for _, e := range w.entries {
		if e.event == event {
			out = append(out, e)
		}
	}
	return out
}

const (
	dirTestSecret   = "operator-secret"
	dirTestProjectA = "proj-a"
	dirTestProjectB = "proj-b"
)

type directoryFixture struct {
	admin *ControlPlaneAdminService
	store *fakeControlPlaneStore
	repos *projectFakeRepos
	audit *projectAuditWriter
	svc   *DirectoryService
}

// newDirectoryFixture wires the lookup as a deployment with verified email
// required (the default) does.
func newDirectoryFixture(t *testing.T) *directoryFixture {
	t.Helper()
	return newDirectoryFixtureWith(t, true)
}

func newDirectoryFixtureWith(t *testing.T, requireVerifiedEmail bool) *directoryFixture {
	t.Helper()
	store := newFakeControlPlaneStore()
	writer := &projectAuditWriter{}
	auditLog := audit.NewLogger(writer, "boot-project", zap.NewNop()).
		WithProjectScoper(func(ctx context.Context) (audit.NodeWriter, string) {
			if scope := ProjectScopeFromContext(ctx); scope != nil {
				return writer, scope.ProjectID
			}
			return writer, "boot-project"
		})
	repos := newProjectFakeRepos()
	return &directoryFixture{
		admin: NewControlPlaneAdminService(dirTestSecret, false, nil, store, newFakeTenantStore(), newFakeMembershipStore(),
			newFakeLoginPolicyStore(), newFakePlatformAdminStore(), &fakeDNSResolver{}, auditLog, zap.NewNop()),
		store: store,
		repos: repos,
		audit: writer,
		svc:   NewDirectoryService(store, repos, requireVerifiedEmail, auditLog),
	}
}

func (f *directoryFixture) mint(t *testing.T, projectID, kind string) *MintedCredential {
	t.Helper()
	minted, err := f.admin.AdminCreateProjectCredential(context.Background(), dirTestSecret, projectID, kind)
	if err != nil {
		t.Fatalf("mint %s credential: %v", kind, err)
	}
	return minted
}

func (f *directoryFixture) seed(t *testing.T, projectID string, u *User) string {
	t.Helper()
	id, err := f.repos.project(projectID).CreateUser(context.Background(), u)
	if err != nil {
		t.Fatalf("seed %q: %v", u.Email, err)
	}
	return id
}

func directoryIDs(users []DirectoryUser) []string {
	ids := make([]string, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.ID)
	}
	return ids
}

func TestDirectoryLookup_ReturnsActiveAccountsInRequestOrder(t *testing.T) {
	f := newDirectoryFixture(t)
	key := f.mint(t, dirTestProjectA, CredentialKindDirectoryReader).RawKey

	alice := f.seed(t, dirTestProjectA, &User{
		Email: "alice@corp.test", Name: "Alice", AvatarURL: "https://cdn.test/a.png", Status: StatusActive,
		PhoneNumber: "+15550100", PasswordHash: "hash", TotpRequired: true, Role: "admin", EmailVerified: true,
	})
	bob := f.seed(t, dirTestProjectA, &User{Email: "bob@corp.test", Name: "Bob", Status: StatusActive, EmailVerified: true})
	legacy := f.seed(t, dirTestProjectA, &User{Email: "legacy@corp.test", Name: "Legacy", EmailVerified: true}) // blank status = legacy active
	for _, status := range []string{StatusDeactivated, "suspended", "invited", StatusPendingDeletion, StatusPendingParentalConsent} {
		f.seed(t, dirTestProjectA, &User{Email: status + "@corp.test", Status: status, EmailVerified: true})
	}
	f.seed(t, dirTestProjectA, &User{IsAnonymous: true, Status: StatusActive, EmailVerified: true})

	got, err := f.svc.LookupUsers(context.Background(), key, []string{
		"bob@corp.test", "ALICE@corp.test", "legacy@corp.test", "nobody@corp.test",
		StatusDeactivated + "@corp.test", "suspended@corp.test", "invited@corp.test",
		StatusPendingDeletion + "@corp.test", StatusPendingParentalConsent + "@corp.test",
	})
	if err != nil {
		t.Fatalf("LookupUsers: %v", err)
	}
	want := []DirectoryUser{
		{ID: bob, Email: "bob@corp.test", Name: "Bob", EmailVerified: true, RequestedEmails: []string{"bob@corp.test"}},
		{ID: alice, Email: "alice@corp.test", Name: "Alice", AvatarURL: "https://cdn.test/a.png", EmailVerified: true, RequestedEmails: []string{"ALICE@corp.test"}},
		{ID: legacy, Email: "legacy@corp.test", Name: "Legacy", EmailVerified: true, RequestedEmails: []string{"legacy@corp.test"}},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("LookupUsers =\n  %+v\nwant\n  %+v", got, want)
	}
}

func TestDirectoryLookup_ExactMatchOnly(t *testing.T) {
	f := newDirectoryFixture(t)
	key := f.mint(t, dirTestProjectA, CredentialKindDirectoryReader).RawKey
	f.seed(t, dirTestProjectA, &User{Email: "alice@corp.test", Status: StatusActive, EmailVerified: true})

	for _, probe := range []string{"alice", "corp.test", "@corp.test", "lice@corp.test", "alice@corp", "alice@corp.test.evil", "%", "*"} {
		got, err := f.svc.LookupUsers(context.Background(), key, []string{probe})
		if err != nil {
			t.Fatalf("LookupUsers(%q): %v", probe, err)
		}
		if len(got) != 0 {
			t.Fatalf("LookupUsers(%q) = %+v, want no match (exact match only)", probe, got)
		}
	}
	// Surrounding whitespace is not part of an address.
	got, err := f.svc.LookupUsers(context.Background(), key, []string{"  alice@corp.test "})
	if err != nil || len(got) != 1 {
		t.Fatalf("trimmed lookup = %+v %v, want the one account", got, err)
	}
}

func TestDirectoryLookup_ScopedToTheCredentialsProject(t *testing.T) {
	f := newDirectoryFixture(t)
	keyA := f.mint(t, dirTestProjectA, CredentialKindDirectoryReader).RawKey
	keyB := f.mint(t, dirTestProjectB, CredentialKindDirectoryReader).RawKey
	inA := f.seed(t, dirTestProjectA, &User{Email: "shared@corp.test", Status: StatusActive, EmailVerified: true})
	inB := f.seed(t, dirTestProjectB, &User{Email: "shared@corp.test", Status: StatusActive, EmailVerified: true})
	f.seed(t, dirTestProjectB, &User{Email: "only-b@corp.test", Status: StatusActive, EmailVerified: true})

	// The request arrived resolved to project B (its Host / X-Project-Key),
	// yet credential A still reads only project A.
	ctxB := WithProjectScope(context.Background(), &ProjectScope{ProjectID: dirTestProjectB})
	got, err := f.svc.LookupUsers(ctxB, keyA, []string{"shared@corp.test", "only-b@corp.test"})
	if err != nil {
		t.Fatalf("LookupUsers A: %v", err)
	}
	if ids := directoryIDs(got); len(ids) != 1 || ids[0] != inA {
		t.Fatalf("credential A saw %v, want only project A's account %q", ids, inA)
	}

	got, err = f.svc.LookupUsers(context.Background(), keyB, []string{"shared@corp.test"})
	if err != nil {
		t.Fatalf("LookupUsers B: %v", err)
	}
	if ids := directoryIDs(got); len(ids) != 1 || ids[0] != inB {
		t.Fatalf("credential B saw %v, want project B's account %q", ids, inB)
	}

	// The lookup is audited under the credential's project, not the request's.
	lookups := f.audit.byEvent(string(audit.EventDirectoryLookup))
	if len(lookups) != 2 || lookups[0].project != dirTestProjectA || lookups[1].project != dirTestProjectB {
		t.Fatalf("directory_lookup audit projects = %+v, want [%s %s]", lookups, dirTestProjectA, dirTestProjectB)
	}
}

func TestDirectoryLookup_RefusesEveryOtherPresentation(t *testing.T) {
	f := newDirectoryFixture(t)
	good := f.mint(t, dirTestProjectA, CredentialKindDirectoryReader)
	publicID, _, _ := strings.Cut(good.RawKey, rawKeySeparator)
	secretKind := f.mint(t, dirTestProjectA, CredentialKindSecret)
	publishable := f.mint(t, dirTestProjectA, CredentialKindPublishable)
	revoked := f.mint(t, dirTestProjectA, CredentialKindDirectoryReader)
	if err := f.admin.AdminRevokeProjectCredential(context.Background(), dirTestSecret, dirTestProjectA, revoked.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	suspended := f.mint(t, "proj-suspended", CredentialKindDirectoryReader)
	f.store.suspended["proj-suspended"] = true
	f.seed(t, dirTestProjectA, &User{Email: "alice@corp.test", Status: StatusActive, EmailVerified: true})

	cases := []struct {
		name   string
		key    string
		reason string // the audited refusal reason; "" = not audited
	}{
		{"missing", "", ""},
		{"no separator", publicID, ""},
		{"empty secret", publicID + rawKeySeparator, ""},
		{"empty public id", rawKeySeparator + "secret", ""},
		{"unknown public id", "dk_unknown" + rawKeySeparator + "secret", ""},
		{"wrong secret", publicID + rawKeySeparator + "not-the-secret", directoryRefusedSecretMismatch},
		// Other kinds' public ids are public by design; presenting one must
		// not let anyone write audit rows.
		{"secret-kind credential", secretKind.RawKey, ""},
		{"publishable credential", publishable.PublicID + rawKeySeparator + "anything", ""},
		{"revoked credential", revoked.RawKey, directoryRefusedRevoked},
		{"suspended project", suspended.RawKey, ""},
		{"a user JWT", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1In0.sig", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(f.audit.byEvent(string(audit.EventDirectoryLookup)))
			got, err := f.svc.LookupUsers(context.Background(), tc.key, []string{"alice@corp.test"})
			if !errors.Is(err, ErrUnauthenticated) || got != nil {
				t.Fatalf("LookupUsers = %+v, %v; want nil, ErrUnauthenticated", got, err)
			}
			after := f.audit.byEvent(string(audit.EventDirectoryLookup))
			if tc.reason == "" {
				if len(after) != before {
					t.Fatalf("refusal that must not be audited was: %+v", after[before:])
				}
				return
			}
			if len(after) != before+1 {
				t.Fatalf("refusal of a real credential was not audited")
			}
			entry := after[len(after)-1]
			if entry.details["reason"] != tc.reason || entry.project != dirTestProjectA ||
				!strings.HasPrefix(entry.actor, directoryAuditActorPrefix) {
				t.Fatalf("refusal audit = %+v, want reason %q under %s by a credential", entry, tc.reason, dirTestProjectA)
			}
		})
	}
}

// The batch is checked before the credential store is read, so a malformed
// batch costs no control-plane query. A key that is not even shaped like one
// is refused first; the batch bounds are public, so a caller whose key is
// merely wrong learns nothing from them.
func TestDirectoryLookup_ValidatesTheBatchBeforeReadingTheCredential(t *testing.T) {
	f := newDirectoryFixture(t)
	key := f.mint(t, dirTestProjectA, CredentialKindDirectoryReader).RawKey

	tooMany := make([]string, MaxDirectoryLookupEmails+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("u%d@corp.test", i)
	}
	const domain = "@corp.test"
	longest := strings.Repeat("a", MaxDirectoryLookupEmailLength-len(domain)) + domain
	for name, emails := range map[string][]string{
		"empty":          nil,
		"blank entry":    {"alice@corp.test", "   "},
		"over limit":     tooMany,
		"overlong entry": {"alice@corp.test", "a" + longest},
	} {
		if _, err := f.svc.LookupUsers(context.Background(), key, emails); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("%s: err = %v, want ErrInvalidArgument", name, err)
		}
		if _, err := f.svc.LookupUsers(context.Background(), "", emails); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("%s without a key: err = %v, want ErrUnauthenticated", name, err)
		}
		// A store that fails every read proves the batch was refused first.
		f.store.lookupErr = errors.New("credential store must not be read")
		if _, err := f.svc.LookupUsers(context.Background(), key, emails); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("%s with the store failing: err = %v, want ErrInvalidArgument before any read", name, err)
		}
		f.store.lookupErr = nil
	}

	// An address of exactly the maximum length is accepted.
	if _, err := f.svc.LookupUsers(context.Background(), key, []string{longest}); err != nil {
		t.Fatalf("address of the maximum length: %v", err)
	}

	// Exactly the limit is accepted, and case-duplicates collapse to one.
	alice := f.seed(t, dirTestProjectA, &User{Email: "alice@corp.test", Status: StatusActive, EmailVerified: true})
	atLimit := make([]string, 0, MaxDirectoryLookupEmails)
	atLimit = append(atLimit, tooMany[:MaxDirectoryLookupEmails-2]...)
	atLimit = append(atLimit, "alice@corp.test", "Alice@Corp.Test")
	got, err := f.svc.LookupUsers(context.Background(), key, atLimit)
	if err != nil {
		t.Fatalf("batch at the limit: %v", err)
	}
	if ids := directoryIDs(got); len(ids) != 1 || ids[0] != alice {
		t.Fatalf("batch at the limit = %v, want [%s] once", ids, alice)
	}
}

// A lookup canonicalizes each address as sign-in does, so it finds exactly
// the account sign-in with that address would: case (Unicode included), a
// plus tag, Gmail dots and a trailing FQDN dot do not make a different
// address. Once canonical, the stored address is compared under FoldEmail,
// so an account whose stored address was never canonicalized (non-ASCII
// capitals) is not found — nor can sign-in reach it.
func TestDirectoryLookup_CanonicalizesAsSignInDoes(t *testing.T) {
	f := newDirectoryFixture(t)
	key := f.mint(t, dirTestProjectA, CredentialKindDirectoryReader).RawKey
	emile := f.seed(t, dirTestProjectA, &User{Email: "émile@corp.test", Status: StatusActive, EmailVerified: true})
	alice := f.seed(t, dirTestProjectA, &User{Email: "alicesmith@gmail.com", Status: StatusActive, EmailVerified: true})
	kate := f.seed(t, dirTestProjectA, &User{Email: "kate@corp.test", Status: StatusActive, EmailVerified: true})
	f.seed(t, dirTestProjectA, &User{Email: "Ëlise@corp.test", Status: StatusActive, EmailVerified: true})

	for _, tc := range []struct {
		emails []string
		want   []string
	}{
		{[]string{"ÉMILE@CORP.TEST", "émile@corp.test"}, []string{emile}}, // one address, asked twice
		{[]string{"Alice.Smith+news@googlemail.com"}, []string{alice}},
		{[]string{"KATE+x@corp.test.", "zzz@corp.test"}, []string{kate}},
		{[]string{"\u212aate@corp.test"}, []string{kate}}, // sign-in lowers KELVIN SIGN to "k" too
		{[]string{"Ëlise@corp.test"}, nil},
	} {
		got, err := f.svc.LookupUsers(context.Background(), key, tc.emails)
		if err != nil {
			t.Fatalf("LookupUsers(%q): %v", tc.emails, err)
		}
		if ids := directoryIDs(got); fmt.Sprint(ids) != fmt.Sprint(tc.want) {
			t.Fatalf("LookupUsers(%q) = %v, want %v", tc.emails, ids, tc.want)
		}
	}
}

// Each entry lists every requested spelling that found it, so a caller can
// pair results with requests even when the address on file is spelled
// differently, and no request for the mailbox reads as a miss.
func TestDirectoryLookup_NamesEveryRequestedSpelling(t *testing.T) {
	f := newDirectoryFixture(t)
	key := f.mint(t, dirTestProjectA, CredentialKindDirectoryReader).RawKey
	bob := f.seed(t, dirTestProjectA, &User{Email: "bob@corp.com", Status: StatusActive, EmailVerified: true})
	alice := f.seed(t, dirTestProjectA, &User{Email: "alicesmith@gmail.com", Status: StatusActive, EmailVerified: true})

	got, err := f.svc.LookupUsers(context.Background(), key, []string{
		"bob+jira@corp.com", "  Alice.Smith+news@googlemail.com ", "bob@corp.com", "bob+jira@corp.com", "alicesmith@gmail.com",
	})
	if err != nil {
		t.Fatalf("LookupUsers: %v", err)
	}
	want := []DirectoryUser{
		{ID: bob, Email: "bob@corp.com", EmailVerified: true, RequestedEmails: []string{"bob+jira@corp.com", "bob@corp.com"}},
		{ID: alice, Email: "alicesmith@gmail.com", EmailVerified: true, RequestedEmails: []string{"Alice.Smith+news@googlemail.com", "alicesmith@gmail.com"}},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("LookupUsers =\n  %+v\nwant\n  %+v", got, want)
	}
}

func TestDirectoryLookup_AuditsCountsNotAddresses(t *testing.T) {
	f := newDirectoryFixture(t)
	minted := f.mint(t, dirTestProjectA, CredentialKindDirectoryReader)
	f.seed(t, dirTestProjectA, &User{Email: "alice@corp.test", Status: StatusActive, EmailVerified: true})

	if _, err := f.svc.LookupUsers(context.Background(), minted.RawKey, []string{"alice@corp.test", "ghost@corp.test"}); err != nil {
		t.Fatalf("LookupUsers: %v", err)
	}
	lookups := f.audit.byEvent(string(audit.EventDirectoryLookup))
	if len(lookups) != 1 {
		t.Fatalf("directory_lookup events = %d, want 1", len(lookups))
	}
	e := lookups[0]
	if e.actor != directoryAuditActorPrefix+minted.ID {
		t.Fatalf("actor = %q, want the credential", e.actor)
	}
	if e.details["requested"] != float64(2) || e.details["matched"] != float64(1) {
		t.Fatalf("details = %v, want requested=2 matched=1", e.details)
	}
	raw := fmt.Sprint(e.details)
	if strings.Contains(raw, "@") || strings.Contains(raw, minted.RawKey) {
		t.Fatalf("audit details leak an address or the key: %v", e.details)
	}
}

func TestDirectoryLookup_SurfacesStoreFailures(t *testing.T) {
	f := newDirectoryFixture(t)
	key := f.mint(t, dirTestProjectA, CredentialKindDirectoryReader).RawKey
	boom := errors.New("db down")

	f.repos.project(dirTestProjectA).findUsersByEmailsErr = boom
	if _, err := f.svc.LookupUsers(context.Background(), key, []string{"a@corp.test"}); !errors.Is(err, boom) {
		t.Fatalf("repo failure: err = %v, want it surfaced", err)
	}

	f.store.lookupErr = boom
	if _, err := f.svc.LookupUsers(context.Background(), key, []string{"a@corp.test"}); !errors.Is(err, boom) {
		t.Fatalf("credential-store failure: err = %v, want it surfaced", err)
	}
}

// Whoever signs up with an address first holds an unverified account for it.
// While verified email is required (the default) the lookup must not present
// that account as the address's owner; once the owner proves the address it
// is returned. With the requirement off, both are returned and flagged.
func TestDirectoryLookup_RequireVerifiedEmail(t *testing.T) {
	for _, required := range []bool{true, false} {
		t.Run(fmt.Sprintf("required=%t", required), func(t *testing.T) {
			f := newDirectoryFixtureWith(t, required)
			key := f.mint(t, dirTestProjectA, CredentialKindDirectoryReader).RawKey
			claimed := f.seed(t, dirTestProjectA, &User{Email: "claimed@corp.test", Name: "Claimed", Status: StatusActive})
			proven := f.seed(t, dirTestProjectA, &User{Email: "proven@corp.test", Name: "Proven", Status: StatusActive, EmailVerified: true})
			lookup := func() []DirectoryUser {
				t.Helper()
				got, err := f.svc.LookupUsers(context.Background(), key, []string{"claimed@corp.test", "proven@corp.test"})
				if err != nil {
					t.Fatalf("LookupUsers: %v", err)
				}
				return got
			}

			want := []DirectoryUser{{ID: proven, Email: "proven@corp.test", Name: "Proven", EmailVerified: true, RequestedEmails: []string{"proven@corp.test"}}}
			if !required {
				want = append([]DirectoryUser{{ID: claimed, Email: "claimed@corp.test", Name: "Claimed", RequestedEmails: []string{"claimed@corp.test"}}}, want...)
			}
			if got := lookup(); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("before verification: LookupUsers = %+v, want %+v", got, want)
			}

			if err := f.repos.project(dirTestProjectA).SetUserEmailVerified(context.Background(), claimed, 1); err != nil {
				t.Fatalf("verify: %v", err)
			}
			want = []DirectoryUser{
				{ID: claimed, Email: "claimed@corp.test", Name: "Claimed", EmailVerified: true, RequestedEmails: []string{"claimed@corp.test"}},
				{ID: proven, Email: "proven@corp.test", Name: "Proven", EmailVerified: true, RequestedEmails: []string{"proven@corp.test"}},
			}
			if got := lookup(); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("after verification: LookupUsers = %+v, want %+v", got, want)
			}
		})
	}
}

// Minting and revoking are recorded in the credential's project, where its
// lookups are recorded, whatever project the admin call's Host resolved to.
func TestDirectoryCredentialAdminAudit_LoggedInTheCredentialsProject(t *testing.T) {
	f := newDirectoryFixture(t)
	hostCtx := WithProjectScope(context.Background(), &ProjectScope{ProjectID: dirTestProjectB})

	minted, err := f.admin.AdminCreateProjectCredential(hostCtx, dirTestSecret, dirTestProjectA, CredentialKindDirectoryReader)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := f.admin.AdminRevokeProjectCredential(hostCtx, dirTestSecret, dirTestProjectA, minted.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	for _, event := range []audit.EventType{audit.EventProjectCredentialCreated, audit.EventProjectCredentialRevoked} {
		entries := f.audit.byEvent(string(event))
		if len(entries) != 1 || entries[0].project != dirTestProjectA {
			t.Fatalf("%s audit = %+v, want one row in %s", event, entries, dirTestProjectA)
		}
	}
}

func TestIsActiveDirectoryAccount(t *testing.T) {
	for name, tc := range map[string]struct {
		u    *User
		want bool
	}{
		"nil":               {nil, false},
		"anonymous":         {&User{IsAnonymous: true, Email: "a@corp.test", Status: StatusActive}, false},
		"no email":          {&User{Status: StatusActive}, false},
		"active":            {&User{Email: "a@corp.test", Status: StatusActive}, true},
		"active, uppercase": {&User{Email: "a@corp.test", Status: "ACTIVE"}, true},
		"legacy blank":      {&User{Email: "a@corp.test"}, true},
		"deactivated":       {&User{Email: "a@corp.test", Status: StatusDeactivated}, false},
	} {
		if got := isActiveDirectoryAccount(tc.u); got != tc.want {
			t.Errorf("%s: isActiveDirectoryAccount = %v, want %v", name, got, tc.want)
		}
	}
}
