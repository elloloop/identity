package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/events"
)

const seedDefaultProject = "default"

// TestSeedWebhookSubscriptions_DefaultsProjectAndActivates proves a config
// entry with no project is scoped to the default project and returned as an
// active subscription, while an explicit project is honoured.
func TestSeedWebhookSubscriptions_DefaultsProjectAndActivates(t *testing.T) {
	subs := []config.WebhookSubscription{
		{URL: "https://a.example.com/hook", Secret: "k1", EventTypes: []events.EventType{events.EventUserDeleted}},
		{URL: "https://b.example.com/hook", Secret: "k2", ProjectID: "proj-2"},
	}
	outbox := events.NewMemoryOutbox()
	seedWebhookSubscriptions(outbox, subs, seedDefaultProject, zap.NewNop())

	defaultSubs, err := outbox.ListActiveSubscriptions(context.Background(), seedDefaultProject)
	if err != nil {
		t.Fatalf("ListActiveSubscriptions(default): %v", err)
	}
	if len(defaultSubs) != 1 {
		t.Fatalf("want 1 subscription under default project, got %d", len(defaultSubs))
	}
	got := defaultSubs[0]
	if got.URL != "https://a.example.com/hook" || got.Secret != "k1" || !got.Active {
		t.Errorf("seeded subscription = %+v", got)
	}
	if got.ProjectID != seedDefaultProject {
		t.Errorf("project_id = %q, want %q", got.ProjectID, seedDefaultProject)
	}

	otherSubs, err := outbox.ListActiveSubscriptions(context.Background(), "proj-2")
	if err != nil {
		t.Fatalf("ListActiveSubscriptions(proj-2): %v", err)
	}
	if len(otherSubs) != 1 || otherSubs[0].URL != "https://b.example.com/hook" {
		t.Fatalf("explicit-project subscription not seeded: %+v", otherSubs)
	}
}

// TestSeedWebhookSubscriptions_EmptyWarns proves that enabling webhooks with
// no subscriptions is inert but loudly logged rather than silently accepted.
func TestSeedWebhookSubscriptions_EmptyWarns(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	outbox := events.NewMemoryOutbox()

	seedWebhookSubscriptions(outbox, nil, seedDefaultProject, zap.New(core))

	if entries := logs.FilterMessage("webhooks_enabled_without_subscriptions").All(); len(entries) != 1 {
		t.Fatalf("want 1 warning log, got %d", len(entries))
	}
	subs, err := outbox.ListActiveSubscriptions(context.Background(), seedDefaultProject)
	if err != nil {
		t.Fatalf("ListActiveSubscriptions: %v", err)
	}
	if len(subs) != 0 {
		t.Fatalf("want no subscriptions seeded, got %d", len(subs))
	}
}

// TestSeedWebhookSubscriptions_DoesNotLogSecret guards the secret-redaction
// contract: the seed log line must never contain the HMAC secret.
func TestSeedWebhookSubscriptions_DoesNotLogSecret(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	outbox := events.NewMemoryOutbox()
	const secret = "top-secret-hmac-key"

	seedWebhookSubscriptions(
		outbox,
		[]config.WebhookSubscription{{URL: "https://a.example.com/hook", Secret: secret}},
		seedDefaultProject,
		zap.New(core),
	)

	for _, entry := range logs.All() {
		if entry.ContextMap()["secret"] != nil {
			t.Fatal("seed log must not carry a secret field")
		}
		for _, field := range entry.ContextMap() {
			if s, ok := field.(string); ok && s == secret {
				t.Fatalf("seed log leaked the secret value in field %v", entry.ContextMap())
			}
		}
	}
}

func TestWebhookSubscriptionID_StableAndProjectScoped(t *testing.T) {
	a := webhookSubscriptionID("proj-1", "https://a.example.com")
	if a != webhookSubscriptionID("proj-1", "https://a.example.com") {
		t.Fatal("id must be stable for the same project+url")
	}
	if a == webhookSubscriptionID("proj-2", "https://a.example.com") {
		t.Fatal("different projects must yield different ids")
	}
	if a == webhookSubscriptionID("proj-1", "https://b.example.com") {
		t.Fatal("different urls must yield different ids")
	}
}

// TestSeededSubscriptionDeliversSignedUserDeleted is the end-to-end proof:
// a subscription declared in config, seeded into the outbox, receives a
// signed user.deleted webhook whose body verifies against the configured
// secret — the exact path a downstream relay consumer relies on.
func TestSeededSubscriptionDeliversSignedUserDeleted(t *testing.T) {
	const secret = "relay-shared-secret"

	var gotBody []byte
	var gotSig, gotEventID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSig = r.Header.Get(events.SignatureHeader)
		gotEventID = r.Header.Get(events.EventIDHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// srv.URL is a loopback http:// address, so it passes config validation.
	cfg := &config.Config{
		WebhooksEnabled:               true,
		WebhooksMaxAttempts:           3,
		WebhooksBackoffBaseSeconds:    1,
		WebhooksBackoffMaxSeconds:     30,
		WebhooksWorkerIntervalSeconds: 1,
		WebhooksBatchSize:             10,
		WebhookSubscriptions: `[{"url":"` + srv.URL +
			`","secret":"` + secret + `","event_types":["user.deleted"]}]`,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config should validate: %v", err)
	}
	parsed, err := cfg.WebhookSubscriptionList()
	if err != nil {
		t.Fatalf("WebhookSubscriptionList: %v", err)
	}

	outbox := events.NewMemoryOutbox()
	seedWebhookSubscriptions(outbox, parsed, seedDefaultProject, zap.NewNop())

	publisher := events.NewOutboxPublisher(outbox, randomEventID, time.Now, zap.NewNop())
	event := events.Event{
		ID:        "evt_user_deleted_1",
		Type:      events.EventUserDeleted,
		ProjectID: seedDefaultProject,
		TenantID:  "local",
		User:      events.User{ID: "user-123", Email: "gone@example.com", Status: "deactivated"},
	}
	if err := publisher.Emit(context.Background(), event); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	worker := events.NewWorker(events.WorkerConfig{
		Store:  outbox,
		Sender: events.NewHTTPSender(nil),
		Logger: zap.NewNop(),
	})
	if err := worker.ProcessOnce(context.Background()); err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}

	if len(gotBody) == 0 {
		t.Fatal("subscriber received no webhook body")
	}
	if gotEventID != event.ID {
		t.Errorf("event id header = %q, want %q", gotEventID, event.ID)
	}
	if !events.VerifySignature(secret, gotBody, gotSig) {
		t.Fatal("delivered body did not verify against the configured secret")
	}
	if events.VerifySignature("wrong-secret", gotBody, gotSig) {
		t.Fatal("signature verified against the wrong secret")
	}
}
