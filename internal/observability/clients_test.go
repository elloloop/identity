package observability

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/idv"
	"github.com/elloloop/identity/pkg/oauth"
)

// fakeIDV is a minimal idv.Provider used to assert WrapIDVProvider
// passes through both Name() and the two methods plus surfaces errors.
type fakeIDV struct {
	begin func(context.Context, idv.Request) (*idv.Session, error)
	get   func(context.Context, string) (*idv.StatusResult, error)
}

func (f *fakeIDV) Name() string { return "fake" }
func (f *fakeIDV) BeginVerification(ctx context.Context, r idv.Request) (*idv.Session, error) {
	return f.begin(ctx, r)
}

func (f *fakeIDV) GetVerification(ctx context.Context, id string) (*idv.StatusResult, error) {
	return f.get(ctx, id)
}

func TestWrapIDVProvider_PassesThrough(t *testing.T) {
	t.Parallel()

	if got := WrapIDVProvider(nil); got != nil {
		t.Errorf("WrapIDVProvider(nil) = %v, want nil", got)
	}

	want := &idv.Session{ProviderSessionID: "sess"}
	errBoom := errors.New("boom")
	wrapped := WrapIDVProvider(&fakeIDV{
		begin: func(_ context.Context, r idv.Request) (*idv.Session, error) {
			if r.UserID != "u" {
				t.Errorf("begin: r.UserID = %q, want u", r.UserID)
			}
			return want, nil
		},
		get: func(_ context.Context, id string) (*idv.StatusResult, error) {
			if id != "s" {
				t.Errorf("get: id = %q, want s", id)
			}
			return nil, errBoom
		},
	})
	if wrapped.Name() != "fake" {
		t.Errorf("Name() = %q, want fake", wrapped.Name())
	}
	got, err := wrapped.BeginVerification(context.Background(), idv.Request{UserID: "u"})
	if err != nil || got != want {
		t.Errorf("BeginVerification: %v %v", got, err)
	}
	if _, err := wrapped.GetVerification(context.Background(), "s"); !errors.Is(err, errBoom) {
		t.Errorf("GetVerification err = %v, want %v", err, errBoom)
	}
}

// fakeExchanger implements oauth.Exchanger only. Asserts the
// non-Authorizer branch of WrapOAuthExchanger.
type fakeExchanger struct {
	id *oauth.Identity
}

func (f *fakeExchanger) Exchange(context.Context, string, string) (*oauth.Identity, error) {
	return f.id, nil
}

// fakeExchAuth implements both Exchanger and Authorizer to drive the
// type-asserting branch the service layer depends on.
type fakeExchAuth struct {
	*fakeExchanger
	url string
}

func (f *fakeExchAuth) AuthorizationURL(context.Context, string, string, string) (string, error) {
	return f.url, nil
}

func TestWrapOAuthExchanger(t *testing.T) {
	t.Parallel()

	if got := WrapOAuthExchanger("p", nil); got != nil {
		t.Errorf("WrapOAuthExchanger(nil) = %v, want nil", got)
	}

	plain := &fakeExchanger{id: &oauth.Identity{Email: "x@y"}}
	wrapped := WrapOAuthExchanger("google", plain)
	if _, ok := wrapped.(oauth.Authorizer); ok {
		t.Errorf("plain exchanger wrapper should not satisfy Authorizer")
	}
	id, err := wrapped.Exchange(context.Background(), "code", "https://r")
	if err != nil || id.Email != "x@y" {
		t.Errorf("Exchange: %v %v", id, err)
	}

	full := &fakeExchAuth{fakeExchanger: &fakeExchanger{id: &oauth.Identity{Email: "z"}}, url: "https://auth"}
	wrapped2 := WrapOAuthExchanger("google", full)
	a, ok := wrapped2.(oauth.Authorizer)
	if !ok {
		t.Fatalf("full exchanger wrapper should satisfy Authorizer")
	}
	url, err := a.AuthorizationURL(context.Background(), "r", "s", "c")
	if err != nil || url != "https://auth" {
		t.Errorf("AuthorizationURL: %v %v", url, err)
	}
}

type fakeMailer struct {
	last email.Message
	err  error
}

func (f *fakeMailer) Send(_ context.Context, m email.Message) error {
	f.last = m
	return f.err
}

func TestWrapMailer(t *testing.T) {
	t.Parallel()

	if got := WrapMailer(nil); got != nil {
		t.Errorf("WrapMailer(nil) = %v, want nil", got)
	}

	f := &fakeMailer{}
	wrapped := WrapMailer(f)
	msg := email.Message{To: "user@example.com", Subject: "subj", Text: "b"}
	if err := wrapped.Send(context.Background(), msg); err != nil {
		t.Errorf("Send: %v", err)
	}
	if f.last.Subject != "subj" {
		t.Errorf("inner Send not invoked correctly: %+v", f.last)
	}
}
