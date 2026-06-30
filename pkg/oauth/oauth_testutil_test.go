package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// testKey is an RSA key + matching JWK Set + kid the test fakeServers
// use to sign ID tokens and serve JWKS.
type testKey struct {
	Priv    *rsa.PrivateKey
	JWKSet  jwk.Set
	KID     string
	JWKJSON []byte
}

func newTestKey(tb testing.TB, kid string) *testKey {
	tb.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("rsa generate: %v", err)
	}
	pubKey, err := jwk.FromRaw(priv.Public())
	if err != nil {
		tb.Fatalf("jwk from raw: %v", err)
	}
	if err := pubKey.Set(jwk.KeyIDKey, kid); err != nil {
		tb.Fatalf("set kid: %v", err)
	}
	if err := pubKey.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		tb.Fatalf("set alg: %v", err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(pubKey); err != nil {
		tb.Fatalf("add key: %v", err)
	}
	jwksJSON, err := json.Marshal(set)
	if err != nil {
		tb.Fatalf("marshal jwks: %v", err)
	}
	return &testKey{Priv: priv, JWKSet: set, KID: kid, JWKJSON: jwksJSON}
}

// signIDToken signs a set of claims with this key and returns the
// compact JWS.
func (k *testKey) signIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	tok := jwt.New()
	for kk, vv := range claims {
		// Special-case the registered claim names so jwx interprets
		// time/audience correctly.
		switch kk {
		case "iss":
			_ = tok.Set(jwt.IssuerKey, vv)
		case "sub":
			_ = tok.Set(jwt.SubjectKey, vv)
		case "aud":
			_ = tok.Set(jwt.AudienceKey, vv)
		case "exp":
			_ = tok.Set(jwt.ExpirationKey, vv)
		case "iat":
			_ = tok.Set(jwt.IssuedAtKey, vv)
		default:
			_ = tok.Set(kk, vv)
		}
	}
	signKey, err := jwk.FromRaw(k.Priv)
	if err != nil {
		t.Fatalf("priv jwk: %v", err)
	}
	if err := signKey.Set(jwk.KeyIDKey, k.KID); err != nil {
		t.Fatalf("kid: %v", err)
	}
	if err := signKey.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("alg: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, signKey))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return string(signed)
}

// signRawJWS signs an arbitrary JSON payload as a compact JWS,
// independent of jwx's claim-aware Sign. Useful for testing alg /
// kid edge cases.
func (k *testKey) signRawJWS(t *testing.T, payload []byte) string {
	t.Helper()
	signKey, err := jwk.FromRaw(k.Priv)
	if err != nil {
		t.Fatalf("priv jwk: %v", err)
	}
	_ = signKey.Set(jwk.KeyIDKey, k.KID)
	_ = signKey.Set(jwk.AlgorithmKey, jwa.RS256)
	signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256, signKey))
	if err != nil {
		t.Fatalf("jws sign: %v", err)
	}
	return string(signed)
}

// fakeProvider is a lightweight stub for an OAuth provider's token
// endpoint and JWKS endpoint. The test sets idTokenFor / acceptCode /
// userInfo per scenario.
type fakeProvider struct {
	srv *httptest.Server
	mux *http.ServeMux

	tokenCalls atomic.Int32
	jwksCalls  atomic.Int32
	userCalls  atomic.Int32
	emailCalls atomic.Int32

	// tokenHandler optionally overrides the default handler.
	tokenHandler http.HandlerFunc
	jwksHandler  http.HandlerFunc
	userHandler  http.HandlerFunc
	emailHandler http.HandlerFunc
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	fp := &fakeProvider{srv: srv, mux: mux}

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		fp.tokenCalls.Add(1)
		if fp.tokenHandler != nil {
			fp.tokenHandler(w, r)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		fp.jwksCalls.Add(1)
		if fp.jwksHandler != nil {
			fp.jwksHandler(w, r)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		fp.userCalls.Add(1)
		if fp.userHandler != nil {
			fp.userHandler(w, r)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		fp.emailCalls.Add(1)
		if fp.emailHandler != nil {
			fp.emailHandler(w, r)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	return fp
}

func (fp *fakeProvider) URL(path string) string { return fp.srv.URL + path }

// jsonHandler returns a handler that responds 200 with the given JSON
// body.
func jsonHandler(body any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}
}

// rawHandler returns a handler that writes the supplied raw bytes.
func rawHandler(status int, contentType string, body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}
}

// nowFunc returns a clock-stop-time function fixed at t.
func nowFunc(at time.Time) func() time.Time {
	return func() time.Time { return at }
}
