package oauth

import (
	"context"
	"testing"
)

type stubExchanger struct{ name string }

func (s stubExchanger) Exchange(_ context.Context, _ ExchangeParams) (*Identity, error) {
	return &Identity{Provider: s.name, Email: "x@x", EmailVerified: true}, nil
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	if _, ok := r.Get("google"); ok {
		t.Fatal("empty registry should not have google")
	}
	r.Register("google", stubExchanger{name: "google"})
	r.Register("github", stubExchanger{name: "github"})

	if r.Len() != 2 {
		t.Errorf("Len = %d, want 2", r.Len())
	}
	got, ok := r.Get("google")
	if !ok {
		t.Fatal("google not found")
	}
	if got.(stubExchanger).name != "google" {
		t.Errorf("wrong exchanger")
	}
	provs := r.Providers()
	if len(provs) != 2 || provs[0] != "github" || provs[1] != "google" {
		t.Errorf("Providers = %v", provs)
	}
}

func TestRegistry_RegisterNilUnregisters(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	r.Register("google", stubExchanger{name: "google"})
	r.Register("google", nil)
	if _, ok := r.Get("google"); ok {
		t.Fatal("expected google to be unregistered after nil register")
	}
}

func TestRegistry_NilSafe(t *testing.T) {
	t.Parallel()
	var r *Registry
	if _, ok := r.Get("google"); ok {
		t.Fatal("nil registry must report missing")
	}
	r.Register("google", stubExchanger{}) // should not panic
	if r.Len() != 0 {
		t.Errorf("Len = %d", r.Len())
	}
	if r.Providers() != nil {
		t.Error("nil registry Providers should be nil")
	}
}
