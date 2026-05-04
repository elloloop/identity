package oauth

import "sync"

// Registry maps provider keys ("google", "microsoft", "github") to
// their Exchanger implementations. The service layer looks up the
// Exchanger for the provider named in the OAuthLoginRequest.
//
// A nil *Registry is valid and reports every provider as missing.
// This lets the service treat "OAuth login disabled" as a registry
// without any registered providers (or no registry at all).
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Exchanger
}

// NewRegistry returns an empty registry. Callers populate it with
// Register.
func NewRegistry() *Registry {
	return &Registry{providers: make(map[string]Exchanger)}
}

// Register associates the given Exchanger with a provider key. Calling
// Register with the same key twice replaces the previous entry. A nil
// Exchanger is treated as "unregister" so callers can disable a
// provider at runtime.
func (r *Registry) Register(provider string, e Exchanger) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.providers == nil {
		r.providers = make(map[string]Exchanger)
	}
	if e == nil {
		delete(r.providers, provider)
		return
	}
	r.providers[provider] = e
}

// Get returns the Exchanger for the given provider key. The second
// return value is false if no Exchanger is registered.
func (r *Registry) Get(provider string) (Exchanger, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.providers[provider]
	return e, ok
}

// Providers returns the sorted list of currently-registered provider
// keys. Useful for startup logging.
func (r *Registry) Providers() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.providers))
	for k := range r.providers {
		out = append(out, k)
	}
	// Stable order without importing sort: providers are few; bubble.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// Len reports how many providers are registered.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.providers)
}
