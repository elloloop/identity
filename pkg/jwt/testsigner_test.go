package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	jwtoken "github.com/lestrrat-go/jwx/v2/jwt"
)

// memSigner is a minimal in-memory [Signer] used by the package-level
// tests. It is NOT exported; production code wires the file-backed or
// KMS-backed implementation from the sibling packages.
type memSigner struct {
	keys      []*memKey
	byKID     map[string]*memKey
	activeKID string
}

type memKey struct {
	pub PublicKey
	jwk jwk.Key
}

func newMemSigner(tb testing.TB, kid string) *memSigner {
	tb.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("rsa.GenerateKey: %v", err)
	}
	signKey, err := jwk.FromRaw(priv)
	if err != nil {
		tb.Fatalf("jwk.FromRaw: %v", err)
	}
	_ = signKey.Set(jwk.KeyIDKey, kid)
	_ = signKey.Set(jwk.AlgorithmKey, jwa.RS256)

	mk := &memKey{
		pub: PublicKey{KID: kid, Key: &priv.PublicKey},
		jwk: signKey,
	}
	return &memSigner{
		keys:      []*memKey{mk},
		byKID:     map[string]*memKey{kid: mk},
		activeKID: kid,
	}
}

func (m *memSigner) addKey(tb testing.TB, kid string) *memKey {
	tb.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("rsa.GenerateKey: %v", err)
	}
	signKey, err := jwk.FromRaw(priv)
	if err != nil {
		tb.Fatalf("jwk.FromRaw: %v", err)
	}
	_ = signKey.Set(jwk.KeyIDKey, kid)
	_ = signKey.Set(jwk.AlgorithmKey, jwa.RS256)

	mk := &memKey{
		pub: PublicKey{KID: kid, Key: &priv.PublicKey},
		jwk: signKey,
	}
	m.keys = append(m.keys, mk)
	m.byKID[kid] = mk
	return mk
}

func (m *memSigner) setActive(kid string) {
	if _, ok := m.byKID[kid]; !ok {
		panic("memSigner: unknown kid " + kid)
	}
	m.activeKID = kid
}

func (m *memSigner) dropKey(kid string) {
	delete(m.byKID, kid)
	out := m.keys[:0]
	for _, k := range m.keys {
		if k.pub.KID != kid {
			out = append(out, k)
		}
	}
	m.keys = out
}

func (m *memSigner) ActiveKID() string { return m.activeKID }

func (m *memSigner) Keys() []PublicKey {
	out := make([]PublicKey, 0, len(m.keys))
	for _, k := range m.keys {
		out = append(out, k.pub)
	}
	return out
}

func (m *memSigner) Get(kid string) (*rsa.PublicKey, bool) {
	k, ok := m.byKID[kid]
	if !ok {
		return nil, false
	}
	return k.pub.Key, true
}

func (m *memSigner) SignAccessToken(ctx context.Context, c Claims, expiry time.Duration) (string, error) {
	return m.SignClaims(ctx, c.ClaimsMap(time.Now().UTC(), expiry))
}

func (m *memSigner) SignClaims(ctx context.Context, claims map[string]any) (string, error) {
	return m.signClaims(ctx, claims, "JWT")
}

func (m *memSigner) SignTeammateAccessToken(ctx context.Context, claims TeammateAccessClaims) (string, error) {
	claimMap, err := claims.ClaimsMap()
	if err != nil {
		return "", err
	}
	return m.signClaims(ctx, claimMap, DelegatedAccessTokenType)
}

func (m *memSigner) SignDelegatedAccessToken(ctx context.Context, claims DelegatedAccessClaims) (string, error) {
	claimMap, err := claims.ClaimsMap()
	if err != nil {
		return "", err
	}
	return m.signClaims(ctx, claimMap, DelegatedAccessTokenType)
}

func (m *memSigner) signClaims(_ context.Context, claims map[string]any, profile string) (string, error) {
	k, ok := m.byKID[m.activeKID]
	if !ok {
		return "", fmt.Errorf("memSigner: active kid %q not present", m.activeKID)
	}
	b := jwtoken.NewBuilder()
	for n, v := range claims {
		b = b.Claim(n, v)
	}
	tok, err := b.Build()
	if err != nil {
		return "", err
	}
	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, profile); err != nil {
		return "", err
	}
	signed, err := jwtoken.Sign(tok, jwtoken.WithKey(jwa.RS256, k.jwk, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}
