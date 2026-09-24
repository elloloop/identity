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

func newDirectoryFixture(t *testing.T) *directoryFixture {
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
		svc:   NewDirectoryService(store, repos, auditLog),
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
	bob := f.seed(t, dirTestProjectA, &User{Email: "bob@corp.test", Name: "Bob", Status: StatusActive})
	legacy := f.seed(t, dirTestProjectA, &User{Email: "legacy@corp.test", Name: "Legacy"}) // blank status = legacy active
	for _, status := range []string{StatusDeactivated, "suspended", "invited", StatusPendingDeletion, StatusPendingParentalConsent} {
		f.seed(t, dirTestProjectA, &User{Email: status + "@corp.test", Status: status})
	}
	f.seed(t, dirTestProjectA, &User{IsAnonymous: true, Status: StatusActive})

	got, err := f.svc.LookupUsers(context.Background(), key, []string{
		"bob@corp.test", "ALICE@corp.test", "legacy@corp.test", "nobody@corp.test",
		StatusDeactivated + "@corp.test", "suspended@corp.test", "invited@corp.test",
		StatusPendingDeletion + "@corp.test", StatusPendingParentalConsent + "@corp.test",
	})
	if err != nil {
		t.Fatalf("LookupUsers: %v", err)
	}
	want := []DirectoryUser{
		{ID: bob, Email: "bob@corp.test", Name: "Bob"},
		{ID: alice, Email: "alice@corp.test", Name: "Alice", AvatarURL: "https://cdn.test/a.png", EmailVerified: true},
		{ID: legacy, Email: "legacy@corp.test", Name: "Legacy"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("LookupUsers =\n  %+v\nwant\n  %+v", got, want)
	}
}

func TestDirectoryLookup_ExactMatchOnly(t *testing.T) {
	f := newDirectoryFixture(t)
	key := f.mint(t, dirTestProjectA, CredentialKindDirectoryReader).RawKey
	f.seed(t, dirTestProjectA, &User{Email: "alice@corp.test", Status: StatusActive})

	for _, probe := range []string{"alice", "corp.test", "@corp.test", "lice@corp.test", "alice@corp", "alice@corp.test.", "%", "*"} {
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
	inA := f.seed(t, dirTestProjectA, &User{Email: "shared@corp.test", Status: StatusActive})
	inB := f.seed(t, dirTestProjectB, &User{Email: "shared@corp.test", Status: StatusActive})
	f.seed(t, dirTestProjectB, &User{Email: "only-b@corp.test", Status: StatusActive})

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
	f.seed(t, dirTestProjectA, &User{Email: "alice@corp.test", Status: StatusActive})

	cases := []struct {
		name   string
		key    string
		reason string // the audited refusal reason; "" = nothing to attribute it to
	}{
		{"missing", "", ""},
		{"no separator", publicID, ""},
		{"empty secret", publicID + rawKeySeparator, ""},
		{"empty public id", rawKeySeparator + "secret", ""},
		{"unknown public id", "dk_unknown" + rawKeySeparator + "secret", ""},
		{"wrong secret", publicID + rawKeySeparator + "not-the-secret", directoryRefusedSecretMismatch},
		{"secret-kind credential", secretKind.RawKey, directoryRefusedWrongKind},
		{"publishable credential", publishable.PublicID + rawKeySeparator + "anything", directoryRefusedSecretMismatch},
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
					t.Fatalf("refusal with nothing to attribute it to was audited: %+v", after[before:])
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

func TestDirectoryLookup_ValidatesTheBatchAfterAuthenticating(t *testing.T) {
	f := newDirectoryFixture(t)
	key := f.mint(t, dirTestProjectA, CredentialKindDirectoryReader).RawKey

	tooMany := make([]string, MaxDirectoryLookupEmails+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("u%d@corp.test", i)
	}
	for name, emails := range map[string][]string{
		"empty":       nil,
		"blank entry": {"alice@corp.test", "   "},
		"over limit":  tooMany,
	} {
		if _, err := f.svc.LookupUsers(context.Background(), key, emails); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("%s: err = %v, want ErrInvalidArgument", name, err)
		}
		// An unauthenticated caller learns nothing about input validation.
		if _, err := f.svc.LookupUsers(context.Background(), "", emails); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("%s without a key: err = %v, want ErrUnauthenticated", name, err)
		}
	}

	// Exactly the limit is accepted, and case-duplicates collapse to one.
	alice := f.seed(t, dirTestProjectA, &User{Email: "alice@corp.test", Status: StatusActive})
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

func TestDirectoryLookup_AuditsCountsNotAddresses(t *testing.T) {
	f := newDirectoryFixture(t)
	minted := f.mint(t, dirTestProjectA, CredentialKindDirectoryReader)
	f.seed(t, dirTestProjectA, &User{Email: "alice@corp.test", Status: StatusActive})

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
