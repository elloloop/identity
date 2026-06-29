package service

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/pkg/events"
)

// capturePublisher records emitted events for assertions.
type capturePublisher struct {
	mu     sync.Mutex
	events []events.Event
	err    error
}

func (c *capturePublisher) Emit(_ context.Context, e events.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.events = append(c.events, e)
	return nil
}

func (c *capturePublisher) all() []events.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]events.Event(nil), c.events...)
}

func TestPasswordSignup_EmitsUserCreatedEvent(t *testing.T) {
	repo := newFakeRepo()
	pub := &capturePublisher{}
	svc := newTestAuthService(t, repo).WithEventPublisher(pub)

	_, err := svc.PasswordSignup(context.Background(), "alice@example.com", strongPW, "Alice", "", 0)
	require.NoError(t, err)

	got := pub.all()
	require.Len(t, got, 1)
	require.Equal(t, events.EventUserCreated, got[0].Type)
	require.Equal(t, "alice@example.com", got[0].User.Email)
	require.NotEmpty(t, got[0].ID, "event id must be set for idempotency")
	require.NotEmpty(t, got[0].User.ID)
}

func TestPasswordSignup_NilPublisher_NoPanic(t *testing.T) {
	repo := newFakeRepo()
	svc := newTestAuthService(t, repo) // no publisher wired

	_, err := svc.PasswordSignup(context.Background(), "bob@example.com", strongPW, "Bob", "", 0)
	require.NoError(t, err)
}

func TestPasswordSignup_PublisherError_DoesNotFailRPC(t *testing.T) {
	repo := newFakeRepo()
	pub := &capturePublisher{err: errors.New("publish boom")}
	svc := newTestAuthService(t, repo).WithEventPublisher(pub)

	// A publisher failure is best-effort: the signup still succeeds.
	res, err := svc.PasswordSignup(context.Background(), "carol@example.com", strongPW, "Carol", "", 0)
	require.NoError(t, err)
	require.NotNil(t, res)
}

func TestAdminDeactivateUser_EmitsDeactivatedEvent(t *testing.T) {
	db := newFakeDB()
	db.addUser("admin-1", "admin@test.com", "Admin", "admin", "active")
	db.addUser("target-1", "target@test.com", "Target", "member", "active")
	pub := &capturePublisher{}
	svc := newTestAdminService(db).WithEventPublisher(pub)

	require.NoError(t, svc.DeactivateUser(context.Background(), "admin-1", "target-1", "leaving"))

	got := pub.all()
	require.Len(t, got, 1)
	require.Equal(t, events.EventUserDeactivated, got[0].Type)
	require.Equal(t, "target-1", got[0].User.ID)
	require.Equal(t, "deactivated", got[0].User.Status)
	require.NotEmpty(t, got[0].ID)
}

func TestToEventUser_OmitsSecrets(t *testing.T) {
	u := &User{ID: "u1", Email: "e@x.com", Name: "N", Status: "active", PasswordHash: "secret"}
	got := toEventUser(u)
	require.Equal(t, "u1", got.ID)
	require.Equal(t, "e@x.com", got.Email)
	// events.User has no password field — the secret cannot leak by
	// construction; assert the mapped fields are exactly the safe subset.
	require.Equal(t, "active", got.Status)
}
