package playintegrity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestTokenSource builds a tokenSource pointed at tokenURL with a fresh
// service-account key. It lives here rather than reusing the external test
// package's helper because these tests exercise the unexported single-flight
// machinery directly.
func newTestTokenSource(t *testing.T, tokenURL string) *tokenSource {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	sa, err := json.Marshal(map[string]string{
		"client_email": "svc@test-project.iam.gserviceaccount.com",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"token_uri":    tokenURL,
	})
	if err != nil {
		t.Fatalf("marshal sa: %v", err)
	}
	ts, err := newTokenSource(sa, tokenURL, &http.Client{Timeout: 5 * time.Second}, time.Now)
	if err != nil {
		t.Fatalf("newTokenSource: %v", err)
	}
	return ts
}

// TestTokenSource_FailingExchangeIsNotSerialised is the regression guard for
// a real defect: the exchange ran while ts.mu was held, so concurrent
// callers queued on the mutex, and because nothing was cached on failure
// each one went on to run its own full attempt. During a Google
// token-endpoint outage the Nth caller paid ~N × the client timeout.
//
// The exchange now runs outside the lock, single-flighted, with the failure
// negative-cached — so N concurrent callers cost ONE upstream attempt.
func TestTokenSource_FailingExchangeIsNotSerialised(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		// Slow enough that every racer is queued behind the leader.
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ts := newTestTokenSource(t, srv.URL)

	const racers = 8
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ts.get(context.Background()); err == nil {
				t.Error("a failing token endpoint returned no error")
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	if got := attempts.Load(); got != 1 {
		t.Errorf("%d upstream attempts for %d concurrent callers, want 1 — the exchange is not single-flighted", got, racers)
	}
	// Serialised behaviour would be ~racers × 150ms; single-flighted is ~150ms.
	if budget := 150 * time.Millisecond * 3; elapsed > budget {
		t.Errorf("elapsed %v > %v — callers appear to be serialised behind the exchange", elapsed, budget)
	}
}

// A caller whose context is already cancelled must not occupy a place in the
// queue: sync.Mutex.Lock is not context-aware, so waiting on the mutex meant
// a request the client had abandoned still blocked the ones behind it.
func TestTokenSource_WaiterHonoursContextCancellation(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	defer close(release)

	ts := newTestTokenSource(t, srv.URL)

	// Leader: blocks in the exchange until release.
	go func() { _, _ = ts.get(context.Background()) }()
	// Give the leader time to claim ts.inflight.
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { _, err := ts.get(ctx); done <- err }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a cancelled waiter returned success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a cancelled waiter stayed blocked behind the in-flight exchange")
	}
}
