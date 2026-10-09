package identityserver_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/elloloop/identity/identityserver"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
)

// TestRepairStoredEmails drives the repair through the library surface over
// the memory driver, which has no control plane: it covers the default
// project.
func TestRepairStoredEmails(t *testing.T) {
	t.Parallel()
	const projectID = "repair-test"
	base := memory.New()
	srv := newTestServerWith(t,
		func(c *config.Config) { c.DefaultProjectID = projectID },
		func(o *identityserver.Options) { o.Repo, o.DB = base, base })
	repo := base.WithProject(projectID)
	ctx := context.Background()
	id, err := repo.CreateUser(ctx, &service.User{Email: "first.last+news@gmail.com", Status: service.StatusActive})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	dry, err := srv.RepairStoredEmails(ctx, false)
	if err != nil || dry.Applied || dry.Count(identityserver.EmailRepairRewrite) != 1 || dry.Items[0].UserID != id {
		t.Fatalf("dry run: %+v, %v", dry, err)
	}
	applied, err := srv.RepairStoredEmails(ctx, true)
	if err != nil || !applied.Applied || applied.Failed() != 0 {
		t.Fatalf("apply: %+v, %v", applied, err)
	}
	u, err := repo.GetUser(ctx, id)
	if err != nil || u.Email != "firstlast@gmail.com" {
		t.Fatalf("stored email = %q, %v", u.Email, err)
	}
	again, err := srv.RepairStoredEmails(ctx, true)
	if err != nil || len(again.Items) != 0 {
		t.Fatalf("second run: %+v, %v", again, err)
	}
}

func TestRepairStoredEmails_RefusesAServerNewDidNotBuild(t *testing.T) {
	t.Parallel()
	if _, err := (&identityserver.Server{}).RepairStoredEmails(context.Background(), false); err == nil {
		t.Fatal("a zero Server must refuse")
	}
}

// hookedRepairServer builds a server with webhooks to a receiver answering
// status, over a memory store holding one mergeable pair of one Gmail
// mailbox, and returns it with the retired account's id.
func hookedRepairServer(t *testing.T, status int, record func(body string)) (*identityserver.Server, string) {
	t.Helper()
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		record(string(b))
		w.WriteHeader(status)
	}))
	t.Cleanup(hook.Close)

	const projectID = "repair-hook-test"
	base := memory.New()
	srv := newTestServerWith(t,
		func(c *config.Config) {
			c.DefaultProjectID = projectID
			c.WebhooksEnabled = true
			c.WebhooksMaxAttempts = 1
			c.WebhooksBackoffBaseSeconds = 1
			c.WebhooksBackoffMaxSeconds = 1
			c.WebhooksWorkerIntervalSeconds = 3600 // only the drain delivers here
			c.WebhooksBatchSize = 10
			c.WebhookSubscriptions = `[{"url":"` + hook.URL + `","secret":"s","event_types":["user.merged"]}]`
		},
		func(o *identityserver.Options) { o.Repo, o.DB = base, base })
	repo := base.WithProject(projectID)
	ctx := context.Background()
	keep, err := repo.CreateUser(ctx, &service.User{Email: "first.last@gmail.com", Status: service.StatusActive, EmailVerified: true})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := repo.CreateOAuthIdentity(ctx, &service.OAuthIdentity{UserID: keep, Provider: "google", ProviderUserID: "g-1", CreatedAt: 1}); err != nil {
		t.Fatalf("CreateOAuthIdentity: %v", err)
	}
	gone, err := repo.CreateUser(ctx, &service.User{Email: "firstlast@gmail.com", Status: service.StatusActive, EmailVerified: true})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	report, err := srv.RepairStoredEmails(ctx, true)
	if err != nil || report.Count(identityserver.EmailRepairMerge) != 1 || report.Failed() != 0 {
		t.Fatalf("repair: %+v, %v", report, err)
	}
	return srv, gone
}

// A repair's merges reach the applications: DrainEvents delivers the
// user.merged events the run queued before the process would exit.
func TestRepairStoredEmails_DeliversUserMergedOnDrain(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var bodies []string
	srv, gone := hookedRepairServer(t, http.StatusOK, func(b string) {
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
	})
	undelivered, err := srv.DrainEvents(context.Background())
	if err != nil || undelivered != 0 {
		t.Fatalf("DrainEvents: %d undelivered, %v", undelivered, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 || !strings.Contains(bodies[0], "user.merged") || !strings.Contains(bodies[0], gone) {
		t.Fatalf("webhook bodies = %v, want one user.merged for %s", bodies, gone)
	}
}

// An event the receiver refused until the worker gave up is undelivered, not
// done.
func TestDrainEvents_CountsAbandonedDeliveries(t *testing.T) {
	t.Parallel()
	srv, _ := hookedRepairServer(t, http.StatusInternalServerError, func(string) {})
	undelivered, err := srv.DrainEvents(context.Background())
	if err != nil || undelivered != 1 {
		t.Fatalf("DrainEvents = %d, %v; want 1 abandoned delivery", undelivered, err)
	}
}
